import { randomBytes } from 'node:crypto';
import { actionHash } from '@vera/canon';
import { createDb, schema, type VeraDb } from '@vera/db';
import { verifyDecisionToken } from '@vera/decision-token';
import type { DecideRequest, TenantJwks } from '@vera/schemas';
import { kidForKeyArn } from '@vera/signer-kms';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { decodeProtectedHeader } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { addReviewer, type BootstrapResult, bootstrapTenant } from './bootstrap.js';
import { adoptKmsKey } from './keys.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:keys-test';

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;
let reviewerOnly: { userId: string; reviewerToken: string };

const asKey = (t: string) => ({ authorization: `Bearer ${t}` });

let n = 0;
function request(): DecideRequest {
  n += 1;
  return {
    request_id: `req_${n}`,
    idempotency_key: `keys-${n}-${randomBytes(4).toString('hex')}`,
    actor: { type: 'ai_agent', id: 'claude-code' },
    action: {
      type: 'tool_call',
      tool: 'Bash',
      class: 'vcs.push',
      arguments: { command: `git push origin feature/${n}` },
      environment: 'production',
    },
    target: { kind: 'repository', id: 'logaxp/hearken', default_branch: 'main' },
    context: { branch: `feature/${n}` },
  };
}

const hashOf = (b: DecideRequest) =>
  actionHash({
    class: b.action.class,
    tool: b.action.tool,
    arguments: b.action.arguments,
    target: { kind: 'repository', id: 'logaxp/hearken' },
    environment: 'production',
  });

/** Decide, and hand back the token plus the hash it is bound to. */
async function allowed() {
  const body = request();
  const d = (
    await app.inject({ method: 'POST', url: '/v1/decide', headers: asKey(boot.apiKey), payload: body })
  ).json();
  expect(d.decision).toBe('ALLOW');
  return { token: d.decision_token as string, hash: hashOf(body) };
}

const jwks = async (): Promise<TenantJwks> =>
  (await app.inject({ method: 'GET', url: `/.well-known/vera/${boot.orgId}/jwks.json` })).json();

const verify = async (token: string, hash: string) =>
  verifyDecisionToken(token, await jwks(), { tenant: boot.orgId, aud: AUD, action_hash: hash });

const rotate = (token = boot.reviewerToken) =>
  app.inject({ method: 'POST', url: '/v1/keys/rotate', headers: asKey(token) });
const revoke = (kid: string, reason = 'suspected compromise', token = boot.reviewerToken) =>
  app.inject({ method: 'POST', url: `/v1/keys/${kid}/revoke`, headers: asKey(token), payload: { reason } });
const listKeys = (token = boot.reviewerToken) =>
  app.inject({ method: 'GET', url: '/v1/keys', headers: asKey(token) });

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  const masterKey = randomBytes(32);
  app = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test' });
  boot = await bootstrapTenant(vera, masterKey, {
    orgName: 'KeyCo',
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  });
  reviewerOnly = await addReviewer(vera, boot.orgId, 'ops@logaxp.com');
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('KMS custody (ADR-0005)', () => {
  const ARN = 'arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555';

  /** A tenant of its own, so retiring its key does not disturb the rest of this file. */
  async function kmsTenant() {
    const t = await bootstrapTenant(vera, randomBytes(32), {
      orgName: `KmsCo-${randomBytes(3).toString('hex')}`,
      adminEmail: 'kriss@logaxp.com',
      receiverAud: AUD,
    });
    const publicJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'x'.repeat(43),
      kid: kidForKeyArn(ARN),
      use: 'sig',
      alg: 'EdDSA',
    };
    const r = await vera.withTenant(t.orgId, (tx) =>
      adoptKmsKey(tx, t.orgId, { kid: kidForKeyArn(ARN), keyArn: ARN, publicJwk }, 'cli'),
    );
    return { ...t, adopted: r };
  }

  it('adopting a KMS key retires the local one rather than replacing it, so tokens in flight still verify', async () => {
    const t = await kmsTenant();
    expect(t.adopted.retired).toBe(t.kid);
    const keys = (await listKeys(t.reviewerToken)).json().keys as { kid: string; status: string }[];
    expect(keys).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kid: t.adopted.kid, status: 'active' }),
        expect.objectContaining({ kid: t.kid, status: 'retiring' }),
      ]),
    );
  });

  it('the retired local key stays in the JWKS — revoking is a separate, deliberate act', async () => {
    const t = await kmsTenant();
    const published = (
      await app.inject({ method: 'GET', url: `/.well-known/vera/${t.orgId}/jwks.json` })
    ).json() as TenantJwks;
    const kids = published.keys.map((k) => (k as { kid: string }).kid);
    expect(kids).toContain(t.kid);
    expect(kids).toContain(t.adopted.kid);
    expect(published.revoked).not.toContain(t.kid);
  });

  it('no private key is stored for a KMS-held key — that is the whole point', async () => {
    const t = await kmsTenant();
    const [row] = await vera.withTenant(t.orgId, (tx) =>
      tx
        .select({ sealed: schema.signingKeys.privateJwkSealed, arn: schema.signingKeys.kmsKeyArn })
        .from(schema.signingKeys)
        .where(and(eq(schema.signingKeys.orgId, t.orgId), eq(schema.signingKeys.status, 'active'))),
    );
    expect(row.sealed).toBeNull();
    expect(row.arn).toBe(ARN);
  });

  it('a key can only be held one way: the database rejects both custody modes at once, and neither', async () => {
    const t = await kmsTenant();
    const insert = (values: Record<string, unknown>) =>
      vera.withTenant(t.orgId, (tx) =>
        tx.insert(schema.signingKeys).values({
          id: `sk_${randomBytes(4).toString('hex')}`,
          orgId: t.orgId,
          kid: `k_${randomBytes(3).toString('hex')}`,
          publicJwk: {},
          status: 'retiring',
          ...values,
        } as never),
      );
    // Drizzle wraps the driver error, so the constraint name is on the cause. Assert on that rather
    // than the wrapper: the point is that *this* constraint fired, not merely that something failed.
    const violation = async (values: Record<string, unknown>) => {
      try {
        await insert(values);
      } catch (err) {
        return `${(err as Error).message} ${(err as { cause?: Error }).cause?.message ?? ''}`;
      }
      throw new Error('insert was accepted, but exactly one custody mode must be set');
    };
    expect(await violation({ privateJwkSealed: 'sealed', kmsKeyArn: ARN })).toMatch(
      'signing_keys_one_custody',
    );
    expect(await violation({})).toMatch('signing_keys_one_custody');
  });

  it('signing refuses rather than falling back to a local key when KMS is not configured', async () => {
    const t = await kmsTenant();
    // This app has no `kms` in its context — the deployment lost its KMS configuration. A fallback
    // here would silently downgrade the custody the tenant was promised (T14).
    const res = await app.inject({
      method: 'POST',
      url: '/v1/decide',
      headers: asKey(t.apiKey),
      payload: request(),
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(500);
    expect(res.body).not.toContain('decision_token');
  });

  it('adoption is in the audit trail, by ARN — which names the key without revealing anything secret', async () => {
    const t = await kmsTenant();
    const events = (
      await app.inject({ method: 'GET', url: '/v1/audit-events?limit=50', headers: asKey(t.reviewerToken) })
    ).json().events as { kind: string; payload: Record<string, unknown> }[];
    const adopted = events.find((e) => e.kind === 'signing_key.kms_adopted');
    expect(adopted?.payload).toMatchObject({ key_arn: ARN, new_kid: t.adopted.kid, retired_kid: t.kid });
  });
});

describe('who may touch the keys', () => {
  it('a reviewer without the admin role cannot rotate or revoke — revocation invalidates live approvals', async () => {
    expect((await rotate(reviewerOnly.reviewerToken)).statusCode).toBe(403);
    // A real reason, so this tests the role check rather than the schema.
    expect((await revoke(boot.kid, 'trying it on', reviewerOnly.reviewerToken)).statusCode).toBe(403);
    expect((await listKeys(reviewerOnly.reviewerToken)).statusCode).toBe(403);
  });

  it('an API key cannot manage keys at all', async () => {
    expect((await rotate(boot.apiKey)).statusCode).toBe(401);
  });
});

describe('rotation keeps agents running (the overlap window)', () => {
  it('a token issued before rotation still verifies after it', async () => {
    const before = await allowed();
    expect((await verify(before.token, before.hash)).ok).toBe(true);

    const r = await rotate();
    expect(r.statusCode).toBe(200);
    const { kid: newKid, retired } = r.json();
    expect(retired).toBe(boot.kid);
    expect(newKid).not.toBe(boot.kid);

    // The whole point of `retiring`: work already in flight does not break.
    expect((await verify(before.token, before.hash)).ok).toBe(true);
  });

  it('new tokens are signed with the new key', async () => {
    const after = await allowed();
    const header = decodeProtectedHeader(after.token);
    const keys = (await listKeys()).json().keys as { kid: string; status: string }[];
    const active = keys.find((k) => k.status === 'active');
    expect(header.kid).toBe(active?.kid);
    expect((await verify(after.token, after.hash)).ok).toBe(true);
  });

  it('exactly one key is active; the previous one is retiring and still published', async () => {
    const keys = (await listKeys()).json().keys as { kid: string; status: string }[];
    expect(keys.filter((k) => k.status === 'active')).toHaveLength(1);
    expect(keys.filter((k) => k.status === 'retiring').map((k) => k.kid)).toContain(boot.kid);
    const published = (await jwks()).keys.map((k) => k.kid);
    expect(published).toContain(boot.kid);
  });
});

describe('revocation is abrupt, and that is the point', () => {
  it('every token the revoked key signed stops verifying immediately, approved or not', async () => {
    const doomed = await allowed();
    expect((await verify(doomed.token, doomed.hash)).ok).toBe(true);
    const signingKid = decodeProtectedHeader(doomed.token).kid as string;

    const r = await revoke(signingKid, 'laptop with the key was stolen');
    expect(r.statusCode).toBe(200);
    const body = r.json();
    expect(body.revoked).toBe(signingKid);
    expect(body.tokens_invalidated).toBeGreaterThan(0);
    expect(body.note).toContain('stopped verifying immediately');

    const after = await verify(doomed.token, doomed.hash);
    expect(after).toMatchObject({ ok: false, code: 'TOKEN.REVOKED_KEY' });
  });

  it('revoking the active key mints a replacement, so the tenant can still decide', async () => {
    const keys = (await listKeys()).json().keys as { kid: string; status: string }[];
    const active = keys.find((k) => k.status === 'active');
    expect(active).toBeDefined();

    const fresh = await allowed();
    expect((await verify(fresh.token, fresh.hash)).ok).toBe(true);
  });

  it('a revoked key is published as revoked rather than quietly dropped', async () => {
    const j = await jwks();
    expect(j.revoked.length).toBeGreaterThan(0);
    // A receiver can tell "withdrawn" from "never heard of it" — one is an incident, the other a stale cache.
    expect(j.keys.map((k) => k.kid)).not.toContain(j.revoked[0]);
  });

  it('revoking twice is refused rather than silently repeated', async () => {
    const j = await jwks();
    const already = j.revoked[0] as string;
    const r = await revoke(already, 'again');
    expect(r.statusCode).toBe(409);
    expect(r.json().error.code).toBe('KEY_ALREADY_REVOKED');
  });

  it('revoking a key that does not exist is a 404, not a silent success', async () => {
    expect((await revoke('k_not_a_real_key')).statusCode).toBe(404);
  });

  it('a reason is required — an incident response should say what happened', async () => {
    const j = await jwks();
    const active = (await listKeys()).json().keys.find((k: { status: string }) => k.status === 'active');
    const r = await app.inject({
      method: 'POST',
      url: `/v1/keys/${active.kid}/revoke`,
      headers: asKey(boot.reviewerToken),
      payload: {},
    });
    expect(r.statusCode).toBe(400);
    expect(j).toBeDefined();
  });
});

describe('SR-11 signature accounting', () => {
  it('every token VERA signed has exactly one matching audit event', async () => {
    const { parity } = (await listKeys()).json();
    expect(parity.balanced).toBe(true);
    expect(parity.tokens_issued).toBe(parity.signatures_audited);
    expect(parity.tokens_issued).toBeGreaterThan(0);
    expect(parity.note).toContain('matching audit event');
  });

  it('the audit records which key signed what, and rotations and revocations by whom', async () => {
    const events = (
      await app.inject({
        method: 'GET',
        url: '/v1/audit-events?limit=500',
        headers: asKey(boot.reviewerToken),
      })
    ).json().events;
    const kinds = events.map((e: { kind: string }) => e.kind);
    expect(kinds).toEqual(
      expect.arrayContaining(['token.issued', 'signing_key.rotated', 'signing_key.revoked']),
    );

    const issued = events.find((e: { kind: string }) => e.kind === 'token.issued');
    expect(issued.payload).toHaveProperty('kid');
    expect(issued.payload).toHaveProperty('jti');

    const revoked = events.find((e: { kind: string }) => e.kind === 'signing_key.revoked');
    expect(revoked.payload).toMatchObject({ reason: 'laptop with the key was stolen' });
    expect(revoked.actor).toBe(`user:${boot.userId}`);
  });

  it('key usage is attributable: each key reports how many tokens it signed', async () => {
    const keys = (await listKeys()).json().keys as { kid: string; tokens_signed: number }[];
    expect(keys.some((k) => k.tokens_signed > 0)).toBe(true);
  });
});
