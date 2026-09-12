import { actionHash } from '@vera/canon';
import {
  buildTenantJwks,
  generateTenantKey,
  issueDecisionToken,
  localSigner,
  type TenantSigningKey,
} from '@vera/decision-token';
import type { DecideResponse } from '@vera/schemas';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  type AdapterDeps,
  resolveDecision,
  VeraClient,
  VeraRejected,
  VeraUnreachable,
  verifyToken,
} from './index.js';

const ORG = 'org_test';
const AUD = 'adapter:test';
const HASH = actionHash({
  class: 'db.ddl',
  tool: 'Bash',
  arguments: { command: 'ALTER TABLE x DROP COLUMN y' },
  environment: 'production',
});
const OTHER_HASH = actionHash({
  class: 'db.ddl',
  tool: 'Bash',
  arguments: { command: 'DROP TABLE users' },
  environment: 'production',
});

let key: TenantSigningKey;
let foreign: TenantSigningKey;

const mint = async (
  over: Partial<Parameters<typeof issueDecisionToken>[0]> = {},
  signWith?: TenantSigningKey,
) =>
  issueDecisionToken(
    {
      iss: `https://vera.test/t/${ORG}`,
      sub: 'dec_1',
      aud: AUD,
      tenant: ORG,
      decision: 'ALLOW',
      action_hash: HASH,
      actor: 'claude-code',
      policy_set_version: 'ps_1',
      ...over,
    },
    localSigner(signWith ?? key),
  );

/** A VeraClient backed by scripted responses, so the hold loop can be driven deterministically. */
function scriptedClient(script: { jwks?: () => unknown; statuses?: unknown[]; failStatusWith?: Error }) {
  let i = 0;
  const fetchImpl = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes('jwks.json')) return json(script.jwks ? script.jwks() : buildTenantJwks([key]));
    if (url.includes('/v1/decisions/')) {
      if (script.failStatusWith) throw script.failStatusWith;
      const next = script.statuses?.[Math.min(i, (script.statuses?.length ?? 1) - 1)];
      i += 1;
      return json(next ?? {});
    }
    return json({});
  }) as typeof fetch;
  return new VeraClient({
    endpoint: 'http://vera.test',
    apiKey: 'vera_sk_x',
    org: ORG,
    requestTimeoutMs: 500,
    fetch: fetchImpl,
  });
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function deps(client: VeraClient, over: Partial<AdapterDeps> = {}): AdapterDeps & { logs: string[] } {
  const logs: string[] = [];
  return { client, sleep: async () => {}, now: () => Date.now(), log: (l) => logs.push(l), logs, ...over };
}

const response = (over: Partial<DecideResponse> = {}): DecideResponse => ({
  decision_id: 'dec_1',
  decision: 'ALLOW',
  risk: { score: 0, calibrated: false },
  confidence: 0.9,
  reason_codes: [],
  evidence: [],
  required_actions: [],
  action_hash: HASH,
  policy_set_version: 'ps_1',
  supersedes: null,
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  decision_token: null,
  ...over,
});

const status = (over: Record<string, unknown>) => ({ ...response(), review_status: 'pending', ...over });
const hold = { holdSeconds: 10, pollIntervalMs: 1 };
const ctx = { org: ORG, aud: AUD };

beforeAll(async () => {
  key = await generateTenantKey('k_main');
  foreign = await generateTenantKey('k_foreign');
});

describe('verifyToken (SR-19: adapters verify, never issue)', () => {
  it('accepts a token minted for this tenant, receiver, and action', async () => {
    expect(await verifyToken(deps(scriptedClient({})), ctx, await mint(), HASH)).toEqual({ ok: true });
  });

  it('refuses a missing token, another tenant, another receiver, another action, and a foreign key', async () => {
    const d = deps(scriptedClient({}));
    expect(await verifyToken(d, ctx, null, HASH)).toMatchObject({ ok: false, code: 'TOKEN.MALFORMED' });
    expect(await verifyToken(d, ctx, await mint(), OTHER_HASH)).toMatchObject({
      ok: false,
      code: 'TOKEN.HASH_MISMATCH',
    });
    expect(await verifyToken(d, { ...ctx, aud: 'adapter:someone-else' }, await mint(), HASH)).toMatchObject({
      ok: false,
      code: 'TOKEN.AUDIENCE_MISMATCH',
    });
    expect(await verifyToken(d, { ...ctx, org: 'org_other' }, await mint(), HASH)).toMatchObject({
      ok: false,
      code: 'TOKEN.TENANT_MISMATCH',
    });
    expect(await verifyToken(d, ctx, await mint({}, foreign), HASH)).toMatchObject({
      ok: false,
      code: 'TOKEN.BAD_SIGNATURE',
    });
  });

  it('refuses a revoked key even though it is still published', async () => {
    const client = scriptedClient({ jwks: () => buildTenantJwks([key], ['k_main']) });
    expect(await verifyToken(deps(client), ctx, await mint(), HASH)).toMatchObject({
      ok: false,
      code: 'TOKEN.REVOKED_KEY',
    });
  });

  it('refuses an expired token, using the adapter clock', async () => {
    const token = await mint({ ttlSeconds: 60 });
    const late = deps(scriptedClient({}), { now: () => Date.now() + 120_000 });
    expect(await verifyToken(late, ctx, token, HASH)).toMatchObject({ ok: false, code: 'TOKEN.EXPIRED' });
  });

  it('refuses when the JWKS cannot be fetched — unverifiable is not approved', async () => {
    const client = new VeraClient({
      endpoint: 'http://vera.test',
      apiKey: 'k',
      org: ORG,
      requestTimeoutMs: 200,
      fetch: (async () => {
        throw new Error('network down');
      }) as typeof fetch,
    });
    expect(await verifyToken(deps(client), ctx, await mint(), HASH)).toMatchObject({ ok: false });
  });
});

describe('resolveDecision', () => {
  it('ALLOW with a valid token resolves to allow, quoting the policy set', async () => {
    const r = await resolveDecision(
      response({ decision_token: await mint() }),
      deps(scriptedClient({})),
      ctx,
      HASH,
      hold,
    );
    expect(r).toMatchObject({ kind: 'allow', decisionId: 'dec_1' });
    expect(r.reason).toContain('ps_1');
  });

  it('ALLOW whose token does not verify is refused — the signature is the authority, not the HTTP response', async () => {
    const r = await resolveDecision(
      response({ decision_token: await mint({}, foreign) }),
      deps(scriptedClient({})),
      ctx,
      HASH,
      hold,
    );
    expect(r).toMatchObject({ kind: 'deny' });
    expect(r.reason).toContain('did not verify');
  });

  it('a response whose action hash differs from ours is refused before anything else', async () => {
    const r = await resolveDecision(
      response({ action_hash: OTHER_HASH, decision_token: await mint() }),
      deps(scriptedClient({})),
      ctx,
      HASH,
      hold,
    );
    expect(r).toMatchObject({ kind: 'deny' });
    expect(r.reason).toContain('canonicalization mismatch');
  });

  it('BLOCK names the policy and never produces a token', async () => {
    const res = response({
      decision: 'BLOCK',
      reason_codes: [{ code: 'POLICY.DENY', severity: 'high', policy_id: 'no-force-push-to-default' }],
    });
    const r = await resolveDecision(res, deps(scriptedClient({})), ctx, HASH, hold);
    expect(r).toMatchObject({ kind: 'deny' });
    expect(r.reason).toContain('no-force-push-to-default');
  });

  it('info-level codes are left out of the reason line, so the operator sees what mattered', async () => {
    const res = response({
      decision: 'BLOCK',
      reason_codes: [
        { code: 'IDENTITY.ASSERTED', severity: 'info' },
        { code: 'BASELINE.INSUFFICIENT_HISTORY', severity: 'info' },
        { code: 'POLICY.DEFAULT_DENY', severity: 'high' },
      ],
    });
    const r = await resolveDecision(res, deps(scriptedClient({})), ctx, HASH, hold);
    expect(r.reason).toContain('POLICY.DEFAULT_DENY');
    expect(r.reason).not.toContain('IDENTITY.ASSERTED');
  });
});

describe('resolveDecision: the REVIEW hold', () => {
  const review = () =>
    response({
      decision: 'REVIEW',
      required_actions: ['HUMAN_APPROVAL'],
      review: { url: 'http://vera.test/r/dec_1', routed_to: ['role:reviewer'], sod: 'x', quorum: 1 },
    });

  it('waits, then allows once a reviewer approves and the approval token verifies', async () => {
    const token = await mint({ decision: 'REVIEW', approver: ['ops@logaxp.com'] });
    const client = scriptedClient({
      statuses: [status({}), status({}), status({ review_status: 'approved', decision_token: token })],
    });
    const d = deps(client);
    const r = await resolveDecision(review(), d, ctx, HASH, hold);
    expect(r).toMatchObject({ kind: 'allow' });
    expect(d.logs[0]).toContain('waiting for approval');
  });

  it('an approval token for a different action is refused', async () => {
    const token = await mint({ decision: 'REVIEW', action_hash: OTHER_HASH, approver: ['ops@logaxp.com'] });
    const client = scriptedClient({
      statuses: [status({ review_status: 'approved', decision_token: token })],
    });
    const r = await resolveDecision(review(), deps(client), ctx, HASH, hold);
    expect(r).toMatchObject({ kind: 'deny' });
    expect(r.reason).toContain('did not verify');
  });

  it('a rejection is a deny', async () => {
    const client = scriptedClient({ statuses: [status({ review_status: 'rejected' })] });
    expect(await resolveDecision(review(), deps(client), ctx, HASH, hold)).toMatchObject({ kind: 'deny' });
  });

  it('an expired review stops the wait as undecided — never allow', async () => {
    const client = scriptedClient({ statuses: [status({ review_status: 'expired' })] });
    expect(await resolveDecision(review(), deps(client), ctx, HASH, hold)).toMatchObject({
      kind: 'undecided',
    });
  });

  it('a hold that runs out is undecided, and says no token was issued', async () => {
    const client = scriptedClient({ statuses: [status({})] });
    let clock = 0;
    const d = deps(client, { now: () => (clock += 400) });
    const r = await resolveDecision(review(), d, ctx, HASH, { holdSeconds: 1, pollIntervalMs: 1 });
    expect(r).toMatchObject({ kind: 'undecided' });
    expect(r.reason).toContain('SYSTEM.HOLD_EXPIRED');
  });

  it('keeps polling through a transient error but stops on a refusal', async () => {
    const transient = scriptedClient({ failStatusWith: new Error('ECONNRESET') });
    let clock = 0;
    const r = await resolveDecision(review(), deps(transient, { now: () => (clock += 300) }), ctx, HASH, {
      holdSeconds: 1,
      pollIntervalMs: 1,
    });
    expect(r).toMatchObject({ kind: 'undecided' }); // it waited rather than giving up at the first blip

    const refused = new VeraClient({
      endpoint: 'http://vera.test',
      apiKey: 'k',
      org: ORG,
      requestTimeoutMs: 200,
      fetch: (async (input: string | URL) =>
        String(input).includes('jwks')
          ? json(buildTenantJwks([key]))
          : json({ error: { code: 'API_KEY_REQUIRED' } }, 401)) as typeof fetch,
    });
    expect(await resolveDecision(review(), deps(refused), ctx, HASH, hold)).toMatchObject({
      kind: 'undecided',
    });
  });
});

describe('VeraClient error classification', () => {
  const clientWith = (fetchImpl: typeof fetch) =>
    new VeraClient({
      endpoint: 'http://vera.test',
      apiKey: 'k',
      org: ORG,
      requestTimeoutMs: 300,
      fetch: fetchImpl,
    });

  it('4xx is a refusal (never degraded mode) and carries the code', async () => {
    const client = clientWith((async () =>
      json({ error: { code: 'API_KEY_REQUIRED', message: 'no' } }, 401)) as typeof fetch);
    const err = await client.decide({} as never).catch((e) => e);
    expect(err).toBeInstanceOf(VeraRejected);
    expect(err.code).toBe('API_KEY_REQUIRED');
  });

  it('5xx, network failure, and timeout are all unreachable', async () => {
    const server = clientWith((async () => json({}, 503)) as typeof fetch);
    await expect(server.decide({} as never)).rejects.toBeInstanceOf(VeraUnreachable);

    const down = clientWith((async () => {
      throw new Error('ECONNREFUSED');
    }) as typeof fetch);
    await expect(down.decide({} as never)).rejects.toBeInstanceOf(VeraUnreachable);

    const slow = clientWith((async (_i: unknown, init?: RequestInit) => {
      await new Promise((_r, rej) =>
        init?.signal?.addEventListener('abort', () => rej(new Error('aborted'))),
      );
      return json({});
    }) as typeof fetch);
    await expect(slow.decide({} as never)).rejects.toBeInstanceOf(VeraUnreachable);
  });

  it('caches the JWKS so verification is offline after the first fetch', async () => {
    let fetches = 0;
    const client = clientWith((async () => {
      fetches += 1;
      return json(buildTenantJwks([key]));
    }) as typeof fetch);
    await client.jwks();
    await client.jwks();
    expect(fetches).toBe(1);
  });
});
