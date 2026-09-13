import { randomBytes } from 'node:crypto';
import { actionHash } from '@vera/canon';
import { createDb, type VeraDb, verifyChain } from '@vera/db';
import { verifyDecisionToken } from '@vera/decision-token';
import type { DecideRequest, TenantJwks } from '@vera/schemas';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { addReviewer, type BootstrapResult, bootstrapTenant } from './bootstrap.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:test-laptop';
const masterKey = randomBytes(32);

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;
let ops: { userId: string; reviewerToken: string };
let jwks: TenantJwks;

let seq = 0;
function request(
  over: Partial<DecideRequest> & { action?: Partial<DecideRequest['action']> } = {},
): DecideRequest {
  seq += 1;
  return {
    request_id: `req_${seq}`,
    idempotency_key: `idem-${seq}-${randomBytes(4).toString('hex')}`,
    actor: { type: 'ai_agent', id: 'claude-code', runtime: 'claude-code@test' },
    acting_for: { type: 'user', id: 'kriss@logaxp.com', trust: 'asserted' },
    target: { kind: 'repository', id: 'logaxp/hearken', default_branch: 'main' },
    context: { branch: 'feature/x' },
    ...over,
    action: {
      type: 'tool_call',
      tool: 'Bash',
      class: 'vcs.push',
      arguments: { command: 'git push origin feature/x' },
      environment: 'production',
      ...over.action,
    },
  };
}

const asKey = (token: string) => ({ authorization: `Bearer ${token}` });
const decide = (body: DecideRequest, token = boot.apiKey) =>
  app.inject({ method: 'POST', url: '/v1/decide', headers: asKey(token), payload: body });
const hashOf = (b: DecideRequest) =>
  actionHash({
    class: b.action.class,
    tool: b.action.tool,
    arguments: b.action.arguments,
    target: b.target ? { kind: b.target.kind, id: b.target.id } : undefined,
    environment: b.action.environment,
  });

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  app = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test' });
  boot = await bootstrapTenant(vera, masterKey, {
    orgName: 'LogaXP',
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  });
  ops = await addReviewer(vera, boot.orgId, 'ops@logaxp.com');
  const res = await app.inject({ method: 'GET', url: `/.well-known/vera/${boot.orgId}/jwks.json` });
  jwks = res.json();
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('authentication', () => {
  it('rejects missing and wrong-kind credentials', async () => {
    expect((await app.inject({ method: 'POST', url: '/v1/decide', payload: request() })).statusCode).toBe(
      401,
    );
    expect((await decide(request(), boot.reviewerToken)).statusCode).toBe(401);
    const r = await app.inject({
      method: 'POST',
      url: '/v1/decisions/dec_x/approve',
      headers: asKey(boot.apiKey),
      payload: {},
    });
    expect(r.statusCode).toBe(401);
  });

  it('rejects a malformed body with 400 and a schema error', async () => {
    const r = await app.inject({
      method: 'POST',
      url: '/v1/decide',
      headers: asKey(boot.apiKey),
      payload: { nope: true },
    });
    expect(r.statusCode).toBe(400);
    expect(r.json().error.code).toBe('VALIDATION_FAILED');
  });

  it('publishes a tenant JWKS with one active Ed25519 key', () => {
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: 'OKP', crv: 'Ed25519', kid: boot.kid });
    expect(jwks.revoked).toEqual([]);
  });
});

describe('ALLOW path', () => {
  it('push to a feature branch → ALLOW with a token the receiver can verify offline', async () => {
    const body = request();
    const r = await decide(body);
    expect(r.statusCode).toBe(200);
    const d = r.json();
    expect(d.decision).toBe('ALLOW');
    expect(d.policy_set_version).toBe('ps_1');
    expect(d.action_hash).toBe(hashOf(body));
    const v = await verifyDecisionToken(d.decision_token, jwks, {
      tenant: boot.orgId,
      aud: AUD,
      action_hash: hashOf(body),
      issuer: `http://vera.test/t/${boot.orgId}`,
    });
    expect(v.ok).toBe(true);
    if (v.ok)
      expect(v.claims).toMatchObject({
        sub: d.decision_id,
        decision: 'ALLOW',
        actor: 'claude-code',
        acting_for: 'kriss@logaxp.com',
      });
  });

  it('SR-13: replaying the idempotency key returns the same decision and token; a different body is a 409', async () => {
    const body = request();
    const first = (await decide(body)).json();
    const again = (await decide(body)).json();
    expect(again.decision_id).toBe(first.decision_id);
    expect(again.decision_token).toBe(first.decision_token);
    const mutated = {
      ...body,
      action: { ...body.action, arguments: { command: 'git push --force origin main' } },
    };
    const r = await decide(mutated);
    expect(r.statusCode).toBe(409);
    expect(r.json().error.code).toBe('IDEMPOTENCY_MISMATCH');
  });

  it('SR-10: a token is single-use; a second consume is a 409; a wrong hash is a 403', async () => {
    const body = request();
    const d = (await decide(body)).json();
    const consume = (payload: object) =>
      app.inject({ method: 'POST', url: '/v1/tokens/consume', headers: asKey(boot.apiKey), payload });
    expect((await consume({ token: d.decision_token, aud: AUD, action_hash: hashOf(body) })).statusCode).toBe(
      200,
    );
    const replay = await consume({ token: d.decision_token, aud: AUD, action_hash: hashOf(body) });
    expect(replay.statusCode).toBe(409);
    expect(replay.json().error.code).toBe('TOKEN.ALREADY_CONSUMED');
    const wrong = await consume({
      token: d.decision_token,
      aud: AUD,
      action_hash: `sha256:${'a'.repeat(64)}`,
    });
    expect(wrong.statusCode).toBe(403);
    expect(wrong.json().error.code).toBe('TOKEN.HASH_MISMATCH');
  });
});

describe('BLOCK path', () => {
  it('force-push to main → BLOCK, no token, POLICY.DENY names the policy', async () => {
    const r = await decide(
      request({
        context: { branch: 'main' },
        action: { arguments: { command: 'git push --force origin main', force: true } },
      }),
    );
    const d = r.json();
    expect(d.decision).toBe('BLOCK');
    expect(d.decision_token).toBeNull();
    expect(d.reason_codes).toContainEqual({
      code: 'POLICY.DENY',
      severity: 'high',
      policy_id: 'no-force-push-to-default',
    });
  });
});

describe('REVIEW path', () => {
  const ddl = () =>
    request({
      target: { kind: 'database', id: 'prod-postgres', sensitivity: 'high' },
      action: { class: 'db.ddl', arguments: { command: 'ALTER TABLE users DROP COLUMN legacy_id' } },
    });
  const approve = (id: string, token: string, verdict: 'approve' | 'reject' = 'approve') =>
    app.inject({
      method: 'POST',
      url: `/v1/decisions/${id}/${verdict}`,
      headers: asKey(token),
      payload: { rationale: 'checked' },
    });
  const status = (id: string) =>
    app.inject({ method: 'GET', url: `/v1/decisions/${id}`, headers: asKey(boot.apiKey) });

  it('production DDL → REVIEW with routing, prerequisite and identity codes, and no token yet', async () => {
    const d = (await decide(ddl())).json();
    expect(d.decision).toBe('REVIEW');
    expect(d.required_actions).toEqual(['HUMAN_APPROVAL']);
    expect(d.review).toMatchObject({
      url: `http://vera.test/r/${d.decision_id}`,
      quorum: 1,
      sod: 'actor_acting_for_and_key_owner_excluded',
    });
    const codes = d.reason_codes.map((c: { code: string }) => c.code);
    expect(codes).toEqual(
      expect.arrayContaining([
        'POLICY.REQUIRE_REVIEW',
        'PREREQ.BACKUP_NOT_VERIFIED',
        'IDENTITY.ASSERTED',
        'ACTION.SENSITIVE_RESOURCE',
      ]),
    );
    expect(d.decision_token).toBeNull();
    expect((await status(d.decision_id)).json().review_status).toBe('pending');
  });

  it('SR-09: the key owner cannot approve their own action; a second reviewer can; the receiver then gets the token', async () => {
    const body = ddl();
    const d = (await decide(body)).json();

    const self = await approve(d.decision_id, boot.reviewerToken);
    expect(self.statusCode).toBe(403);
    expect(self.json().error.code).toBe('POLICY.SOD_VIOLATION');

    const other = await approve(d.decision_id, ops.reviewerToken);
    expect(other.statusCode).toBe(200);
    expect(other.json()).toMatchObject({
      review_status: 'approved',
      approvals: 1,
      quorum: 1,
      token_issued: true,
    });
    expect(other.json()).not.toHaveProperty('decision_token');

    const polled = (await status(d.decision_id)).json();
    expect(polled.review_status).toBe('approved');
    expect(typeof polled.decision_token).toBe('string');
    const v = await verifyDecisionToken(polled.decision_token, jwks, {
      tenant: boot.orgId,
      aud: AUD,
      action_hash: hashOf(body),
    });
    expect(v.ok).toBe(true);
    if (v.ok)
      expect(v.claims).toMatchObject({
        decision: 'REVIEW',
        approver: ['ops@logaxp.com'],
        sub: d.decision_id,
      });

    // T02: the approval is bound to the exact action — a changed command fails verification.
    const changed = { ...body, action: { ...body.action, arguments: { command: 'DROP TABLE users' } } };
    const bad = await verifyDecisionToken(polled.decision_token, jwks, {
      tenant: boot.orgId,
      aud: AUD,
      action_hash: hashOf(changed),
    });
    expect(bad).toMatchObject({ ok: false, code: 'TOKEN.HASH_MISMATCH' });

    expect((await approve(d.decision_id, ops.reviewerToken)).json().error.code).toBe('REVIEW_NOT_PENDING');
  });

  it('a rejection resolves the review and never issues a token', async () => {
    const d = (await decide(ddl())).json();
    const r = await approve(d.decision_id, ops.reviewerToken, 'reject');
    expect(r.json()).toMatchObject({ review_status: 'rejected', token_issued: false });
    const polled = (await status(d.decision_id)).json();
    expect(polled.review_status).toBe('rejected');
    expect(polled.decision_token).toBeNull();
  });

  it('outcomes are recorded as asserted', async () => {
    const d = (await decide(request())).json();
    const r = await app.inject({
      method: 'POST',
      url: `/v1/decisions/${d.decision_id}/outcome`,
      headers: asKey(boot.apiKey),
      payload: { kind: 'executed', data: { exit_code: 0 } },
    });
    expect(r.statusCode).toBe(200);
  });
});

describe('SR-16 audit', () => {
  it('every step above is in the tenant chain, readable by a reviewer, and the chain verifies', async () => {
    const r = await app.inject({
      method: 'GET',
      url: '/v1/audit-events?limit=500',
      headers: asKey(boot.reviewerToken),
    });
    expect(r.statusCode).toBe(200);
    const kinds = r.json().events.map((e: { kind: string }) => e.kind);
    expect(kinds).toEqual(
      expect.arrayContaining([
        'tenant.bootstrapped',
        'decision.issued',
        'request.idempotency_mismatch',
        'review.sod_violation',
        'review.approved',
        'review.reject',
        'token.consumed',
        'token.replayed',
        'token.rejected',
        'outcome.recorded',
      ]),
    );
    const v = await vera.withTenant(boot.orgId, (tx) => verifyChain(tx, boot.orgId));
    expect(v.ok).toBe(true);
    expect(v.length).toBeGreaterThanOrEqual(kinds.length);
  });

  it('an API key cannot read audit events', async () => {
    expect(
      (await app.inject({ method: 'GET', url: '/v1/audit-events', headers: asKey(boot.apiKey) })).statusCode,
    ).toBe(401);
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
describe('wrong verdicts (the dogfood loop)', () => {
  const report = async () =>
    (await app.inject({ method: 'GET', url: '/v1/reports/wrong-verdicts?days=1', headers: asKey(ops.reviewerToken) })).json();

  it('a false negative outranks any number of false positives', async () => {
    // Two REVIEWs a human found tiresome, one ALLOW a human wanted to see.
    const tiresome = async () =>
      (
        await decide(
          request({
            target: { kind: 'database', id: 'prod-postgres', environment: 'production' },
            action: {
              type: 'tool_call',
              tool: 'Bash',
              class: 'db.ddl',
              arguments: { command: 'psql -c "ALTER TABLE t ADD COLUMN c int"' },
              environment: 'production',
            },
          }),
        )
      ).json();
    const a = await tiresome();
    const b = await tiresome();
    const c = (await decide(request())).json(); // feature-branch push → ALLOW
    expect([a.decision, b.decision, c.decision]).toEqual(['REVIEW', 'REVIEW', 'ALLOW']);

    const mark = (id: string, kind: string, should: string, note: string) =>
      app.inject({
        method: 'POST',
        url: `/v1/decisions/${id}/outcome`,
        headers: asKey(boot.apiKey),
        payload: { kind, data: { should_have_been: should, note } },
      });
    expect((await mark(a.decision_id, 'false_positive', 'ALLOW', 'additive column, reviewed in PR')).statusCode).toBe(200);
    expect((await mark(b.decision_id, 'false_positive', 'ALLOW', 'same')).statusCode).toBe(200);
    expect((await mark(c.decision_id, 'false_negative', 'REVIEW', 'this branch deploys to a preview env')).statusCode).toBe(200);

    const r = await report();
    expect(r.total).toBe(3);
    expect(r.false_positives).toBe(2);
    expect(r.false_negatives).toBe(1);
    expect(r.by_transition).toEqual({ 'REVIEW→ALLOW': 2, 'ALLOW→REVIEW': 1 });
    // Newest first, and the false negative carries its note.
    expect(r.items[0]).toMatchObject({ direction: 'false_negative', decided: 'ALLOW', should_have_been: 'REVIEW' });
    expect(r.items[0].note).toContain('preview env');
    // The policy behind the two false positives is named, so someone knows what to loosen.
    expect(r.policies.map((p: { policy_id: string }) => p.policy_id)).toContain('prod-ddl-requires-review');
    // Ranking: whatever sat on the false negative sorts above the tiresome pair, regardless of count.
    expect(r.codes[0].false_negatives).toBe(1);
  });

  it('an entry without a target verdict is ignored rather than guessed at', async () => {
    const d = (await decide(request())).json();
    await app.inject({
      method: 'POST',
      url: `/v1/decisions/${d.decision_id}/outcome`,
      headers: asKey(boot.apiKey),
      payload: { kind: 'false_positive', data: { note: 'meh' } },
    });
    const r = await report();
    expect(r.items.map((i: { decision_id: string }) => i.decision_id)).not.toContain(d.decision_id);
  });

  it('an API key cannot read the report — it is a reviewer view', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/reports/wrong-verdicts', headers: asKey(boot.apiKey) });
    expect(res.statusCode).toBe(401);
  });
});
