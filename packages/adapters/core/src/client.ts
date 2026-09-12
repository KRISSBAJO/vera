import type { DecideRequest, DecideResponse, TenantJwks } from '@vera/schemas';
import { DecideResponseSchema, TenantJwksSchema } from '@vera/schemas';
import { z } from 'zod';

/**
 * The endpoint could not be reached, or answered 5xx. Adapters treat this as degraded mode: read-only
 * actions may proceed, consequential ones must fall back to a human (SR-08).
 */
export class VeraUnreachable extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VeraUnreachable';
  }
}

/** VERA answered, and the answer was no (bad key, revoked key, malformed request). Never degraded mode. */
export class VeraRejected extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = 'VeraRejected';
  }
}

export const DecisionStatusSchema = DecideResponseSchema.extend({
  review_status: z.enum(['none', 'pending', 'approved', 'rejected', 'expired']),
});
export type DecisionStatus = z.infer<typeof DecisionStatusSchema>;

export interface ClientOptions {
  endpoint: string;
  apiKey: string;
  org: string;
  requestTimeoutMs: number;
  fetch?: typeof fetch;
}

/**
 * Thin HTTP client. Network failures, timeouts, and 5xx become `VeraUnreachable`; 4xx become
 * `VeraRejected`. Nothing else escapes, so an adapter always has a decision to make rather than a
 * crash — a crashed hook fails open in the runtimes we plug into.
 */
export class VeraClient {
  private jwksCache: { value: TenantJwks; fetchedAt: number } | undefined;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly opts: ClientOptions) {
    this.fetchImpl = opts.fetch ?? fetch;
  }

  private async call(method: 'GET' | 'POST', path: string, body?: unknown, auth = true): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.requestTimeoutMs);
    try {
      const res = await this.fetchImpl(`${this.opts.endpoint}${path}`, {
        method,
        headers: {
          'content-type': 'application/json',
          ...(auth ? { authorization: `Bearer ${this.opts.apiKey}` } : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: controller.signal,
      });
      const text = await res.text();
      const json = text ? (JSON.parse(text) as unknown) : {};
      if (res.status >= 500) throw new VeraUnreachable(`VERA returned ${res.status}`);
      if (res.status >= 400) {
        const err = (json as { error?: { code?: string; message?: string } }).error;
        throw new VeraRejected(res.status, err?.code ?? `HTTP_${res.status}`, err?.message);
      }
      return json;
    } catch (e) {
      if (e instanceof VeraRejected || e instanceof VeraUnreachable) throw e;
      throw new VeraUnreachable(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
    } finally {
      clearTimeout(timer);
    }
  }

  async decide(body: DecideRequest): Promise<DecideResponse> {
    return DecideResponseSchema.parse(await this.call('POST', '/v1/decide', body));
  }

  async getDecision(id: string): Promise<DecisionStatus> {
    return DecisionStatusSchema.parse(await this.call('GET', `/v1/decisions/${encodeURIComponent(id)}`));
  }

  async outcome(
    id: string,
    kind: 'executed' | 'failed' | 'hash_mismatch',
    data: Record<string, unknown> = {},
  ): Promise<void> {
    await this.call('POST', `/v1/decisions/${encodeURIComponent(id)}/outcome`, { kind, data });
  }

  /** The tenant-signed class and fail-mode tables (SR-07). Verified before use, never trusted raw. */
  async adapterConfig(): Promise<{ bundle: string }> {
    const r = (await this.call('GET', '/v1/adapter-config')) as { bundle?: unknown };
    if (typeof r.bundle !== 'string') throw new VeraUnreachable('adapter config response had no bundle');
    return { bundle: r.bundle };
  }

  /** Tenant JWKS, cached for 10 minutes. After the first fetch, token verification is offline. */
  async jwks(): Promise<TenantJwks> {
    if (this.jwksCache && Date.now() - this.jwksCache.fetchedAt < 10 * 60 * 1000) return this.jwksCache.value;
    const value = TenantJwksSchema.parse(
      await this.call(
        'GET',
        `/.well-known/vera/${encodeURIComponent(this.opts.org)}/jwks.json`,
        undefined,
        false,
      ),
    );
    this.jwksCache = { value, fetchedAt: Date.now() };
    return value;
  }
}
