import { randomBytes } from 'node:crypto';
import { createDb, type VeraDb } from '@vera/db';
import type { DecideRequest } from '@vera/schemas';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { addReviewer, type BootstrapResult, bootstrapTenant } from './bootstrap.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:baseline-test';

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;
let ops: { userId: string; reviewerToken: string };

const asKey = (t: string) => ({ authorization: `Bearer ${t}` });

let n = 0;
function request(
  over: Partial<DecideRequest> & { action?: Partial<DecideRequest['action']> } = {},
): DecideRequest {
  n += 1;
  return {
    request_id: `req_${n}`,
    idempotency_key: `bl-${n}-${randomBytes(4).toString('hex')}`,
    actor: { type: 'ai_agent', id: 'claude-code' },
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

const decide = (body: DecideRequest) =>
  app.inject({ method: 'POST', url: '/v1/decide', headers: asKey(boot.apiKey), payload: body });
/** Asserts the call succeeded: a silently failing outcome would make every baseline test pass vacuously. */
async function outcome(id: string, kind: string) {
  const r = await app.inject({
    method: 'POST',
    url: `/v1/decisions/${id}/outcome`,
    headers: asKey(boot.apiKey),
    payload: { kind, data: {} },
  });
  if (r.statusCode !== 200) throw new Error(`outcome ${kind} failed: ${r.statusCode} ${r.body}`);
  return r;
}
const codesOf = (body: { reason_codes: { code: string; detail?: string }[] }) =>
  body.reason_codes.map((c) => c.code);
const detailOf = (body: { reason_codes: { code: string; detail?: string }[] }, code: string) =>
  body.reason_codes.find((c) => c.code === code)?.detail;

/** One full round trip that trains the baseline: decide, then report that it executed. */
async function performed(body: DecideRequest) {
  const d = (await decide(body)).json();
  await outcome(d.decision_id, 'executed');
  return d;
}

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  const masterKey = randomBytes(32);
  // maxAge 0: every outcome rebuilds the rollup, so the test sees history as it accumulates.
  app = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test', baselineSnapshotMaxAgeMs: 0 });
  boot = await bootstrapTenant(vera, masterKey, {
    orgName: 'BaselineCo',
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  });
  ops = await addReviewer(vera, boot.orgId, 'ops@logaxp.com');
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('cold start', () => {
  it('an org with no history says INSUFFICIENT_HISTORY and nothing else from the baseline', async () => {
    const d = (await decide(request())).json();
    expect(codesOf(d)).toContain('BASELINE.INSUFFICIENT_HISTORY');
    expect(codesOf(d).filter((c) => c.startsWith('BASELINE.'))).toEqual(['BASELINE.INSUFFICIENT_HISTORY']);
    expect(detailOf(d, 'BASELINE.INSUFFICIENT_HISTORY')).toContain('10 needed');
    expect(d.decision).toBe('ALLOW');
  });
});

describe('history accumulates only from what actually happened (SR-20)', () => {
  it('after enough executed actions the baseline stops saying it has nothing', async () => {
    for (let i = 0; i < 12; i += 1) await performed(request());
    const d = (await decide(request())).json();
    expect(codesOf(d)).not.toContain('BASELINE.INSUFFICIENT_HISTORY');
    // Nothing novel about this actor, class, or target any more. A burst code is expected and correct:
    // a test that fires twelve pushes in a few seconds *is* an actor bursting.
    expect(codesOf(d).filter((c) => c.startsWith('BASELINE.') && c !== 'BASELINE.FREQUENCY_SPIKE')).toEqual(
      [],
    );
    expect(d.baseline_snapshot_id).toMatch(/^bs_/);
  });

  it('a new actor doing a familiar class is flagged as novel, with the org history quoted', async () => {
    const d = (await decide(request({ actor: { type: 'ai_agent', id: 'some-other-agent' } }))).json();
    expect(codesOf(d)).toContain('BASELINE.ACTOR_ACTION_NOVEL');
    expect(detailOf(d, 'BASELINE.ACTOR_ACTION_NOVEL')).toMatch(/org history: \d+/);
  });

  it('a familiar actor touching a new target is flagged, but not as actor-novel', async () => {
    const d = (
      await decide(
        request({ target: { kind: 'repository', id: 'logaxp/brand-new-repo', default_branch: 'main' } }),
      )
    ).json();
    expect(codesOf(d)).toContain('BASELINE.TARGET_NOVEL');
    expect(codesOf(d)).not.toContain('BASELINE.ACTOR_ACTION_NOVEL');
  });

  it('a decision that was never executed does not train the baseline', async () => {
    const fresh = 'never-executed-agent';
    await decide(request({ actor: { type: 'ai_agent', id: fresh } })); // decided, no outcome reported
    const again = (await decide(request({ actor: { type: 'ai_agent', id: fresh } }))).json();
    expect(codesOf(again)).toContain('BASELINE.ACTOR_ACTION_NOVEL');
  });

  it('a BLOCKed action does not train the baseline', async () => {
    const blocker = 'force-pusher';
    const blocked = (
      await decide(
        request({
          actor: { type: 'ai_agent', id: blocker },
          context: { branch: 'main' },
          action: { arguments: { command: 'git push --force origin main', force: true } },
        }),
      )
    ).json();
    expect(blocked.decision).toBe('BLOCK');
    await outcome(blocked.decision_id, 'executed'); // even a lying outcome report cannot train it
    const next = (await decide(request({ actor: { type: 'ai_agent', id: blocker } }))).json();
    expect(codesOf(next)).toContain('BASELINE.ACTOR_ACTION_NOVEL');
  });

  it('a reverted action is retracted from history', async () => {
    const agent = 'reverter';
    const d = await performed(request({ actor: { type: 'ai_agent', id: agent } }));
    const before = (await decide(request({ actor: { type: 'ai_agent', id: agent } }))).json();
    expect(codesOf(before)).not.toContain('BASELINE.ACTOR_ACTION_NOVEL');

    await outcome(d.decision_id, 'reverted');
    const after = (await decide(request({ actor: { type: 'ai_agent', id: agent } }))).json();
    expect(codesOf(after)).toContain('BASELINE.ACTOR_ACTION_NOVEL');
  });

  it('a hash mismatch retracts it too — what executed was not what was decided (T02)', async () => {
    const agent = 'smuggler';
    const d = await performed(request({ actor: { type: 'ai_agent', id: agent } }));
    await outcome(d.decision_id, 'hash_mismatch');
    const after = (await decide(request({ actor: { type: 'ai_agent', id: agent } }))).json();
    expect(codesOf(after)).toContain('BASELINE.ACTOR_ACTION_NOVEL');
  });
});

describe('bursts (threat T06)', () => {
  it('flags an actor whose last hour dwarfs its daily average, quoting both numbers', async () => {
    const burst = 'busy-agent';
    for (let i = 0; i < 8; i += 1) await performed(request({ actor: { type: 'ai_agent', id: burst } }));
    const d = (await decide(request({ actor: { type: 'ai_agent', id: burst } }))).json();
    const spike = detailOf(d, 'BASELINE.FREQUENCY_SPIKE');
    expect(spike).toMatch(/actions by this actor in the last hour/);
  });
});

describe('SR-20: baselines can only add severity', () => {
  it('every baseline code is info, low, or medium — never high', async () => {
    const d = (await decide(request({ actor: { type: 'ai_agent', id: 'yet-another-agent' } }))).json();
    const baseline = d.reason_codes.filter((c: { code: string }) => c.code.startsWith('BASELINE.'));
    expect(baseline.length).toBeGreaterThan(0);
    expect(baseline.every((c: { severity: string }) => c.severity !== 'high')).toBe(true);
  });

  it('a novel action that policy allows is still allowed — history alone never blocks', async () => {
    const d = (
      await decide(request({ actor: { type: 'ai_agent', id: `novel-${randomBytes(3).toString('hex')}` } }))
    ).json();
    expect(codesOf(d)).toContain('BASELINE.ACTOR_ACTION_NOVEL');
    expect(d.decision).toBe('ALLOW');
  });
});

describe('reviewer-facing reports', () => {
  it('GET /v1/baselines shows the raw counts a reviewer can check', async () => {
    const r = await app.inject({
      method: 'GET',
      url: '/v1/baselines?class=vcs.push',
      headers: asKey(ops.reviewerToken),
    });
    expect(r.statusCode).toBe(200);
    const rows = r.json().baselines as { actor_id: string; observations: number }[];
    const main = rows.find((x) => x.actor_id === 'claude-code');
    expect(main?.observations).toBeGreaterThanOrEqual(12);
  });

  it('an API key cannot read baselines', async () => {
    expect(
      (await app.inject({ method: 'GET', url: '/v1/baselines', headers: asKey(boot.apiKey) })).statusCode,
    ).toBe(401);
  });

  it('the precision report counts reviews per policy and never applies its own advice', async () => {
    const ddl = () =>
      request({
        target: { kind: 'database', id: 'prod-postgres', sensitivity: 'high' },
        action: { class: 'db.ddl', arguments: { command: 'ALTER TABLE users DROP COLUMN x' } },
      });
    const first = (await decide(ddl())).json();
    expect(first.decision).toBe('REVIEW');
    await app.inject({
      method: 'POST',
      url: `/v1/decisions/${first.decision_id}/approve`,
      headers: asKey(ops.reviewerToken),
      payload: {},
    });
    const second = (await decide(ddl())).json();
    await app.inject({
      method: 'POST',
      url: `/v1/decisions/${second.decision_id}/reject`,
      headers: asKey(ops.reviewerToken),
      payload: {},
    });

    const r = await app.inject({
      method: 'GET',
      url: '/v1/reports/policy-precision?days=1',
      headers: asKey(ops.reviewerToken),
    });
    expect(r.statusCode).toBe(200);
    const report = r.json();
    const rule = report.policies.find(
      (p: { policy_id: string }) => p.policy_id === 'prod-ddl-requires-review',
    );
    expect(rule).toMatchObject({ reviews: 2, approved: 1, rejected: 1, approval_rate: 0.5 });
    expect(rule.recommendation).toBeNull(); // too few reviews to advise anything
    expect(report.totals.review).toBeGreaterThanOrEqual(2);
    expect(report.note).toContain('never applied automatically');
  });
});
