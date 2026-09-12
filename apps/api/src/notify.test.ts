import { randomBytes } from 'node:crypto';
import { createDb, type VeraDb } from '@vera/db';
import type { Notifier, ReviewNotification } from '@vera/notify-slack';
import type { DecideRequest } from '@vera/schemas';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { type BootstrapResult, bootstrapTenant } from './bootstrap.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:notify-test';

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;

/** What the notifier saw, and — for the ordering test — whether the decision was readable by then. */
let sent: { n: ReviewNotification; decisionVisible: boolean }[] = [];
let failNext = false;

const notifier: Notifier = {
  async notifyReview(n) {
    // If the notification fires inside the transaction that created the decision, this read cannot
    // see it. Capturing it here is what makes the after-commit ordering testable at all.
    const res = await app.inject({
      method: 'GET',
      url: `/v1/decisions/${n.decisionId}`,
      headers: { authorization: `Bearer ${boot.apiKey}` },
    });
    sent.push({ n, decisionVisible: res.statusCode === 200 });
    if (failNext) throw new Error('slack exploded');
    return { ok: true, ts: '1789.0001' };
  },
};

let n = 0;
function request(
  over: Partial<DecideRequest> & { action?: Partial<DecideRequest['action']> } = {},
): DecideRequest {
  n += 1;
  return {
    request_id: `req_${n}`,
    idempotency_key: `notify-${n}-${randomBytes(4).toString('hex')}`,
    actor: { type: 'ai_agent', id: 'claude-code', runtime: 'claude-code@test' },
    acting_for: { type: 'user', id: 'kriss@logaxp.com', trust: 'asserted' },
    target: { kind: 'database', id: 'prod-postgres', sensitivity: 'high' },
    ...over,
    action: {
      type: 'tool_call',
      tool: 'Bash',
      class: 'db.ddl',
      arguments: { command: 'ALTER TABLE users DROP COLUMN legacy_id' },
      environment: 'production',
      ...over.action,
    },
  } as DecideRequest;
}

const decide = (body: DecideRequest) =>
  app.inject({
    method: 'POST',
    url: '/v1/decide',
    headers: { authorization: `Bearer ${boot.apiKey}` },
    payload: body,
  });

/**
 * The notification is deliberately fired without being awaited, so tests have to wait for it. Poll
 * for the condition rather than sleeping a guessed interval: a fixed sleep that is occasionally too
 * short does not fail here, it leaks the notification into the *next* test.
 */
async function waitForNotifications(count: number, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (sent.length < count && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
}

/** For asserting that nothing is sent: there is no event to wait for, so allow a generous quiet period. */
const quietPeriod = () => new Promise((r) => setTimeout(r, 300));

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  const masterKey = randomBytes(32);
  app = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test', notifier });
  boot = await bootstrapTenant(vera, masterKey, {
    orgName: `NotifyCo-${randomBytes(3).toString('hex')}`,
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  });
});

beforeEach(() => {
  sent = [];
  failNext = false;
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('a reviewer is told, with the right facts', () => {
  it('a REVIEW notifies once, carrying the routing and the link — and nothing else does', async () => {
    const d = (await decide(request())).json();
    expect(d.decision).toBe('REVIEW');
    await waitForNotifications(1);
    expect(sent).toHaveLength(1);
    expect(sent[0].n).toMatchObject({
      decisionId: d.decision_id,
      url: `http://vera.test/r/${d.decision_id}`,
      actionClass: 'db.ddl',
      environment: 'production',
      target: 'database:prod-postgres',
      actor: 'claude-code',
      actingFor: 'kriss@logaxp.com',
      summary: 'ALTER TABLE users DROP COLUMN legacy_id',
    });
    expect(sent[0].n.reasonCodes).toContain('POLICY.REQUIRE_REVIEW');
  });

  it('an ALLOW notifies nobody — notifying on every decision is how a channel becomes noise', async () => {
    const d = (
      await decide(
        request({
          target: { kind: 'repository', id: 'logaxp/hearken', default_branch: 'main' },
          action: { class: 'file.read', arguments: { path: 'README.md' }, environment: 'development' },
        }),
      )
    ).json();
    expect(d.decision).toBe('ALLOW');
    await quietPeriod();
    expect(sent).toHaveLength(0);
  });
});

describe('what the notification is allowed to contain', () => {
  it('carries the masked argument, not the credential in it (SR-15)', async () => {
    // Assembled at runtime: a secret-shaped literal in a source file is the thing scanners exist to
    // catch, and ours would be right to.
    const password = ['Pg', 'Sup3r', 'S3cret', 'Value1'].join('');
    const d = (
      await decide(
        request({
          action: {
            class: 'db.ddl',
            arguments: { command: `PGPASSWORD=${password} psql -c "ALTER TABLE users DROP COLUMN x"` },
          },
        }),
      )
    ).json();
    expect(d.decision).toBe('REVIEW');
    await waitForNotifications(1);
    expect(sent).toHaveLength(1);
    expect(sent[0].n.summary).not.toContain(password);
    expect(sent[0].n.redactedCount).toBeGreaterThan(0);
  });

  it('never carries a decision token — that would hand approval authority to the channel', async () => {
    await decide(request());
    await waitForNotifications(1);
    expect(JSON.stringify(sent[0].n)).not.toMatch(/\bey[A-Za-z0-9_-]{8,}\./);
  });
});

describe('Slack never gets in the way of a decision', () => {
  it('fires only after the decision is committed and readable', async () => {
    await decide(request());
    await waitForNotifications(1);
    expect(sent).toHaveLength(1);
    expect(sent[0].decisionVisible).toBe(true);
  });

  it('a notifier that throws does not cost the agent its verdict', async () => {
    failNext = true;
    const res = await decide(request());
    expect(res.statusCode).toBe(200);
    expect(res.json().decision).toBe('REVIEW');
    await waitForNotifications(1);
    // It was still attempted; the failure was swallowed on the way out, not before the attempt.
    expect(sent).toHaveLength(1);
  });

  it('the decision is returned without waiting for the notification round trip', async () => {
    const before = sent.length;
    const res = await decide(request());
    // The response is already in hand while the notification is still in flight.
    expect(res.statusCode).toBe(200);
    expect(sent).toHaveLength(before);
    await waitForNotifications(before + 1);
    expect(sent).toHaveLength(before + 1);
  });
});
