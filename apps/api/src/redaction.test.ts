import { randomBytes } from 'node:crypto';
import { actionHash } from '@vera/canon';
import { createDb, schema, type VeraDb } from '@vera/db';
import type { DecideRequest } from '@vera/schemas';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { addReviewer, type BootstrapResult, bootstrapTenant } from './bootstrap.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:redaction-test';
const SECRET = 's3cr3t-p4ssw0rd-do-not-store';

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;
let ops: { userId: string; reviewerToken: string };

const asKey = (t: string) => ({ authorization: `Bearer ${t}` });

let n = 0;
function request(command: string, over: Partial<DecideRequest> = {}): DecideRequest {
  n += 1;
  return {
    request_id: `req_${n}`,
    idempotency_key: `red-${n}-${randomBytes(4).toString('hex')}`,
    actor: { type: 'ai_agent', id: 'claude-code' },
    acting_for: { type: 'user', id: 'kriss@logaxp.com', trust: 'asserted' },
    target: { kind: 'database', id: 'prod-postgres', sensitivity: 'high' },
    context: { branch: 'main' },
    ...over,
    action: {
      type: 'tool_call',
      tool: 'Bash',
      class: 'db.ddl',
      arguments: { command },
      environment: 'production',
    },
  };
}

const decide = (body: DecideRequest) =>
  app.inject({ method: 'POST', url: '/v1/decide', headers: asKey(boot.apiKey), payload: body });

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  app = await buildApp({ vera, masterKey: randomBytes(32), publicUrl: 'http://vera.test' });
  boot = await bootstrapTenant(vera, randomBytes(32), {
    orgName: 'RedactCo',
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  }).catch(async () => {
    throw new Error('bootstrap');
  });
  ops = await addReviewer(vera, boot.orgId, 'ops@logaxp.com');
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('SR-15 / T18: VERA must not become the breach', () => {
  const command = `psql postgres://app:${SECRET}@db.internal/prod -c "ALTER TABLE users DROP COLUMN legacy_id"`;

  it('the secret never reaches the database in clear text', async () => {
    const body = request(command);
    const d = (await decide(body)).json();

    const rows = await vera.withTenant(boot.orgId, (tx) =>
      tx.select().from(schema.actionRequests).where(eq(schema.actionRequests.requestId, body.request_id)),
    );
    const stored = rows[0];
    expect(stored).toBeDefined();
    const storedJson = JSON.stringify(stored?.action);
    expect(storedJson).not.toContain(SECRET);
    expect(storedJson).toContain('[redacted:connection-string-password]');
    // The rest of the command survives, so the reviewer can still see what it does.
    expect(storedJson).toContain('ALTER TABLE users DROP COLUMN legacy_id');
    expect(storedJson).toContain('db.internal/prod');
    expect(d.decision).toBe('REVIEW');
  });

  it('the hash still covers the RAW action, so the token binds what will actually execute', async () => {
    const body = request(command);
    const d = (await decide(body)).json();
    const rawHash = actionHash({
      class: body.action.class,
      tool: body.action.tool,
      arguments: body.action.arguments,
      target: { kind: 'database', id: 'prod-postgres' },
      environment: 'production',
    });
    expect(d.action_hash).toBe(rawHash);
  });

  it('the raw action is kept sealed — not readable from the row', async () => {
    const body = request(command);
    await decide(body);
    const rows = await vera.withTenant(boot.orgId, (tx) =>
      tx.select().from(schema.actionRequests).where(eq(schema.actionRequests.requestId, body.request_id)),
    );
    const sealed = rows[0]?.actionRawSealed;
    expect(sealed).toBeTruthy();
    expect(sealed).not.toContain(SECRET);
    expect(sealed?.startsWith('v1.')).toBe(true);
    expect(rows[0]?.redactionFindings).toHaveLength(1);
  });

  it('the reviewer view shows the masked command and what was removed, never the value', async () => {
    const body = request(command);
    const d = (await decide(body)).json();
    const r = await app.inject({
      method: 'GET',
      url: `/v1/reviews/${d.decision_id}`,
      headers: asKey(ops.reviewerToken),
    });
    expect(r.statusCode).toBe(200);
    const view = r.json();
    expect(JSON.stringify(view.action)).not.toContain(SECRET);
    expect(view.redaction[0]).toMatchObject({
      rule: 'connection-string-password',
      path: 'arguments.command',
    });
    expect(JSON.stringify(view.redaction)).not.toContain(SECRET);
    expect(view.has_raw).toBe(true);
  });

  it('a clean command stores nothing sealed — sealing is for secrets, not for everything', async () => {
    const body = request('ALTER TABLE users ADD COLUMN nickname text');
    await decide(body);
    const rows = await vera.withTenant(boot.orgId, (tx) =>
      tx.select().from(schema.actionRequests).where(eq(schema.actionRequests.requestId, body.request_id)),
    );
    expect(rows[0]?.actionRawSealed).toBeNull();
    expect(rows[0]?.redactionFindings).toEqual([]);
  });

  it('redaction is recorded in the audit chain, with findings but no values', async () => {
    const events = (
      await app.inject({
        method: 'GET',
        url: '/v1/audit-events?limit=500',
        headers: asKey(boot.reviewerToken),
      })
    ).json().events;
    const redacted = events.filter((e: { kind: string }) => e.kind === 'request.redacted');
    expect(redacted.length).toBeGreaterThan(0);
    expect(JSON.stringify(redacted)).not.toContain(SECRET);
  });
});

describe('revealing the raw action is a deliberate, named act', () => {
  it('returns the original only with a stated reason, and writes who looked and why', async () => {
    const body = request(`psql postgres://app:${SECRET}@db/prod -c "select 1"`);
    const d = (await decide(body)).json();

    const noReason = await app.inject({
      method: 'POST',
      url: `/v1/decisions/${d.decision_id}/reveal`,
      headers: asKey(ops.reviewerToken),
      payload: {},
    });
    expect(noReason.statusCode).toBe(400);

    const r = await app.inject({
      method: 'POST',
      url: `/v1/decisions/${d.decision_id}/reveal`,
      headers: asKey(ops.reviewerToken),
      payload: { reason: 'confirming the host before approving' },
    });
    expect(r.statusCode).toBe(200);
    expect(JSON.stringify(r.json().action)).toContain(SECRET);

    const events = (
      await app.inject({
        method: 'GET',
        url: '/v1/audit-events?limit=500',
        headers: asKey(boot.reviewerToken),
      })
    ).json().events;
    const reveal = events.filter((e: { kind: string }) => e.kind === 'request.raw_revealed').at(-1);
    expect(reveal.payload).toMatchObject({
      decision_id: d.decision_id,
      reason: 'confirming the host before approving',
    });
    expect(reveal.actor).toBe(`user:${ops.userId}`);
    expect(JSON.stringify(reveal)).not.toContain(SECRET);
  });

  it('an API key cannot reveal anything', async () => {
    const d = (await decide(request(`psql postgres://app:${SECRET}@db/prod -c "select 1"`))).json();
    const r = await app.inject({
      method: 'POST',
      url: `/v1/decisions/${d.decision_id}/reveal`,
      headers: asKey(boot.apiKey),
      payload: { reason: 'x' },
    });
    expect(r.statusCode).toBe(401);
  });

  it('nothing to reveal when nothing was redacted', async () => {
    const d = (await decide(request('ALTER TABLE t ADD COLUMN c int'))).json();
    const r = await app.inject({
      method: 'POST',
      url: `/v1/decisions/${d.decision_id}/reveal`,
      headers: asKey(ops.reviewerToken),
      payload: { reason: 'curious' },
    });
    expect(r.statusCode).toBe(404);
  });
});

describe('the review queue', () => {
  it('lists pending reviews with the facts needed to triage, and flags SoD before you open one', async () => {
    const r = await app.inject({
      method: 'GET',
      url: '/v1/reviews?status=pending',
      headers: asKey(ops.reviewerToken),
    });
    expect(r.statusCode).toBe(200);
    const items = r.json().reviews;
    expect(items.length).toBeGreaterThan(0);
    expect(items[0]).toMatchObject({
      action_class: 'db.ddl',
      tool: 'Bash',
      target: 'prod-postgres',
      environment: 'production',
      quorum: 1,
      sod_blocked: false,
    });
    expect(items[0].top_reason).toMatch(/^(POLICY|PREREQ)\./);
    expect(JSON.stringify(items)).not.toContain(SECRET);
  });

  it('the key owner sees sod_blocked before wasting a click', async () => {
    const r = await app.inject({
      method: 'GET',
      url: '/v1/reviews?status=pending',
      headers: asKey(boot.reviewerToken),
    });
    expect(r.json().reviews.every((i: { sod_blocked: boolean }) => i.sod_blocked)).toBe(true);
  });

  it('reason codes arrive with the guidance a reviewer should act on', async () => {
    const items = (
      await app.inject({
        method: 'GET',
        url: '/v1/reviews?status=pending',
        headers: asKey(ops.reviewerToken),
      })
    ).json().reviews;
    const view = (
      await app.inject({
        method: 'GET',
        url: `/v1/reviews/${items[0].decision_id}`,
        headers: asKey(ops.reviewerToken),
      })
    ).json();
    const prereq = view.reason_codes.find((c: { code: string }) => c.code.startsWith('PREREQ.'));
    expect(prereq.guidance).toBeTruthy();
    expect(prereq.description).toBeTruthy();
  });
});
