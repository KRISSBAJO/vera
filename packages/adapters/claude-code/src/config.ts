import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { z } from 'zod';

export const AdapterConfigSchema = z.object({
  endpoint: z.string().url(),
  apiKey: z.string().startsWith('vera_sk_'),
  /** Tenant (org) id — needed to fetch the JWKS and to verify the `tenant` claim. */
  org: z.string().min(1),
  /** Receiver id this adapter verifies tokens for (`aud`). Must match the API key's registered receiver. */
  aud: z.string().min(1),
  /** Asserted identity of the person at the keyboard; VERA marks it asserted (SR-09). */
  actingFor: z.string().email().optional(),
  /** Baseline environment for this machine. */
  environment: z.string().default('development'),
  /** How long `vera-hook pre` waits for a human on REVIEW before falling back. Keep below the hook timeout. */
  holdSeconds: z.number().int().min(0).max(590).default(300),
  /** What to answer when the hold expires: `ask` (interactive terminal) or `defer` (Agent SDK, -p mode). */
  onHoldExpiry: z.enum(['ask', 'defer']).default('ask'),
  pollIntervalMs: z.number().int().min(200).default(2000),
  requestTimeoutMs: z.number().int().min(200).default(2500),
});
export type AdapterConfig = z.infer<typeof AdapterConfigSchema>;

export const veraHome = () => process.env.VERA_HOME ?? join(homedir(), '.vera');
export const configPath = () => process.env.VERA_CONFIG ?? join(veraHome(), 'config.json');
export const statePath = (toolUseId: string) =>
  join(veraHome(), 'state', `${toolUseId.replace(/[^\w.-]/g, '_')}.json`);
export const degradedQueuePath = () => join(veraHome(), 'degraded-queue.jsonl');
/** Recent decisions, so `vera-hook wrong last` has something to point at. No argument values are stored. */
export const journalPath = () => join(veraHome(), 'decisions.jsonl');

export function loadConfig(): AdapterConfig {
  const path = configPath();
  const fromFile = existsSync(path)
    ? (JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>)
    : {};
  const env = process.env;
  return AdapterConfigSchema.parse({
    ...fromFile,
    ...(env.VERA_ENDPOINT ? { endpoint: env.VERA_ENDPOINT } : {}),
    ...(env.VERA_API_KEY ? { apiKey: env.VERA_API_KEY } : {}),
    ...(env.VERA_ORG ? { org: env.VERA_ORG } : {}),
    ...(env.VERA_AUD ? { aud: env.VERA_AUD } : {}),
    ...(env.VERA_ACTING_FOR ? { actingFor: env.VERA_ACTING_FOR } : {}),
  });
}

export function saveConfig(cfg: AdapterConfig): string {
  const path = configPath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Windows: ACLs, not modes. The file lives under the user's profile.
  }
  return path;
}

/** The hooks block to merge into a Claude Code settings.json (ADR-0002). */
export function hooksSettings(command = 'vera-hook'): Record<string, unknown> {
  return {
    hooks: {
      PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: `${command} pre`, timeout: 360 }] }],
      PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: `${command} post`, timeout: 10 }] }],
    },
  };
}

/** Merge the hooks block into an existing settings file without disturbing other keys. */
export function mergeHooksInto(settingsPath: string, command = 'vera-hook'): void {
  const existing = existsSync(settingsPath)
    ? (JSON.parse(readFileSync(settingsPath, 'utf8')) as Record<string, unknown>)
    : {};
  const hooks = (existing.hooks as Record<string, unknown[]> | undefined) ?? {};
  const ours = hooksSettings(command).hooks as Record<string, unknown[]>;
  const isOurs = (h: unknown) => JSON.stringify(h).includes(`${command} `);
  for (const event of Object.keys(ours)) {
    const kept = (hooks[event] ?? []).filter((h) => !isOurs(h));
    hooks[event] = [...kept, ...(ours[event] ?? [])];
  }
  mkdirSync(dirname(settingsPath), { recursive: true });
  writeFileSync(settingsPath, `${JSON.stringify({ ...existing, hooks }, null, 2)}\n`);
}
