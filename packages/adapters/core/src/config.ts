import { verifyAdapterConfig } from '@vera/decision-token';
import { type ActionClass, type AdapterConfig, AdapterConfigSchema } from '@vera/schemas';
import type { VeraClient } from './client.js';

/**
 * The signed class table and fail-mode table (SR-07, threats T19/T12).
 *
 * Two of the adapter's decisions cannot be left to local configuration: what class a tool call is,
 * and what may proceed when VERA is unreachable. Both were editable on the machine where the agent
 * runs — which is also the machine an attacker controls in every threat this system exists for.
 *
 * So the table is signed by the tenant and verified here. The rule that makes it worth anything:
 * **a bundle that does not verify is not used at all.** Not partially, not "the safe parts". The
 * fallback is the built-in table below, never the contents of a file on disk, because a file on disk
 * is precisely what an attacker can write.
 */

/**
 * What the adapter believes when it has never successfully talked to VERA. Deliberately dull: no
 * tool overrides, and only genuinely read-only classes may proceed while VERA is unreachable.
 */
export const BUILT_IN_CONFIG: AdapterConfig = AdapterConfigSchema.parse({
  version: 0,
  tool_classes: {},
  tool_class_patterns: [],
  fail_open_classes: ['file.read', 'vcs.read', 'http.read', 'db.read', 'search'],
  hold_seconds: 300,
  poll_interval_ms: 2000,
});

export type ConfigSource = 'verified' | 'cached' | 'builtin';

export interface ResolvedConfig {
  config: AdapterConfig;
  source: ConfigSource;
  /** Why the adapter is on this source — surfaced so a stale or refused table is visible, not silent. */
  reason?: string;
  expiresAt?: Date;
}

/** Where a verified bundle is kept between runs. The stored value is the JWS, never the parsed config. */
export interface ConfigCache {
  read(): Promise<string | undefined>;
  write(bundle: string): Promise<void>;
}

export interface ConfigStoreOptions {
  client: VeraClient;
  tenant: string;
  aud: string;
  cache?: ConfigCache;
  now?: () => number;
  log?: (line: string) => void;
}

export class SignedConfigStore {
  private memo: { resolved: ResolvedConfig; at: number } | undefined;
  private readonly now: () => number;

  constructor(private readonly opts: ConfigStoreOptions) {
    this.now = opts.now ?? (() => Date.now());
  }

  /**
   * Resolve the table to obey right now: a freshly verified bundle when VERA is reachable, the last
   * verified one while it is not, and the built-in table if neither survives verification.
   */
  async resolve(): Promise<ResolvedConfig> {
    // A verified bundle is re-used for a minute so a burst of tool calls does not re-verify each time.
    if (this.memo && this.now() - this.memo.at < 60_000 && this.memo.resolved.source === 'verified') {
      return this.memo.resolved;
    }

    let fetched: string | undefined;
    let fetchError: string | undefined;
    try {
      fetched = (await this.opts.client.adapterConfig()).bundle;
    } catch (e) {
      fetchError = e instanceof Error ? e.message : String(e);
    }

    if (fetched) {
      const verified = await this.verify(fetched);
      if (verified) {
        await this.opts.cache?.write(fetched).catch(() => {});
        const resolved: ResolvedConfig = {
          config: verified.config,
          source: 'verified',
          expiresAt: verified.expiresAt,
        };
        this.memo = { resolved, at: this.now() };
        return resolved;
      }
      // VERA answered with something that does not verify. That is worse than silence: either the
      // endpoint is not VERA, or a key was revoked. Do not fall back to a cached table either.
      this.opts.log?.('VERA returned an adapter config that does not verify — using built-in defaults');
      return { config: BUILT_IN_CONFIG, source: 'builtin', reason: 'served bundle failed verification' };
    }

    const cached = await this.opts.cache?.read().catch(() => undefined);
    if (cached) {
      const verified = await this.verify(cached);
      if (verified) {
        return {
          config: verified.config,
          source: 'cached',
          reason: `VERA unreachable (${fetchError ?? 'unknown'}); using the last table it signed`,
          expiresAt: verified.expiresAt,
        };
      }
      this.opts.log?.(
        'the cached adapter config no longer verifies (expired, revoked key, or edited) — using built-in defaults',
      );
    }

    return {
      config: BUILT_IN_CONFIG,
      source: 'builtin',
      reason: fetchError ?? 'no verified table available',
    };
  }

  private async verify(bundle: string) {
    let jwks: Awaited<ReturnType<VeraClient['jwks']>>;
    try {
      jwks = await this.opts.client.jwks();
    } catch {
      return undefined;
    }
    const r = await verifyAdapterConfig(bundle, jwks, {
      tenant: this.opts.tenant,
      aud: this.opts.aud,
      now: new Date(this.now()),
    });
    if (!r.ok) {
      this.opts.log?.(`adapter config rejected: ${r.code}${r.detail ? ` (${r.detail})` : ''}`);
      return undefined;
    }
    return r;
  }
}

/**
 * Apply the signed overrides to a tool name. Exact names win over patterns; a pattern that does not
 * compile is skipped rather than breaking classification.
 */
export function classFromConfig(config: AdapterConfig, toolName: string): ActionClass | undefined {
  const exact = config.tool_classes[toolName];
  if (exact) return exact;
  for (const rule of config.tool_class_patterns) {
    try {
      if (new RegExp(rule.pattern).test(toolName)) return rule.class;
    } catch {
      // a malformed tenant pattern must not stop the adapter deciding
    }
  }
  return undefined;
}

/** May this class proceed on the adapter's own authority while VERA is unreachable? (SR-08) */
export function mayFailOpen(config: AdapterConfig, cls: ActionClass): boolean {
  return config.fail_open_classes.includes(cls);
}
