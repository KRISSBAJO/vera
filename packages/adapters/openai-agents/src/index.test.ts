import { randomBytes } from 'node:crypto';
import { addReviewer, type BootstrapResult, bootstrapTenant, buildApp } from '@vera/api';
import { createDb, type VeraDb } from '@vera/db';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createVeraGuard, type ToolLike, VeraDenied, type VeraGuard, VeraUndecided } from './index.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:openai-runner';

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;
let ops: { userId: string; reviewerToken: string };
let endpoint: string;
let guard: VeraGuard;
let logs: string[];

/** A tool that records what it was called with, so "did it run?" is answerable. */
function spyTool(
  name: string,
  impl?: (args: Record<string, unknown>) => unknown,
): ToolLike & { calls: Record<string, unknown>[] } {
  const calls: Record<string, unknown>[] = [];
  return {
    name,
    calls,
    execute: async (args: Record<string, unknown>) => {
      calls.push(args);
      return impl ? impl(args) : `${name} ok`;
    },
  };
}

const makeGuard = (over: Partial<Parameters<typeof createVeraGuard>[0]> = {}) => {
  logs = [];
  return createVeraGuard({
    endpoint,
    apiKey: boot.apiKey,
    org: boot.orgId,
    aud: AUD,
    actingFor: 'kriss@logaxp.com',
    agentId: 'finance-agent',
    environment: 'production',
    holdSeconds: 5,
    pollIntervalMs: 200,
    requestTimeoutMs: 2000,
    log: (l) => logs.push(l),
    ...over,
  });
};

const auditKinds = async () => {
  const r = await app.inject({
    method: 'GET',
    url: '/v1/audit-events?limit=500',
    headers: { authorization: `Bearer ${boot.reviewerToken}` },
  });
  return r.json().events as { kind: string; payload: Record<string, unknown> }[];
};

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  const masterKey = randomBytes(32);
  app = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test' });
  endpoint = await app.listen({ port: 0, host: '127.0.0.1' });
  boot = await bootstrapTenant(vera, masterKey, {
    orgName: 'OpenAICo',
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  });
  ops = await addReviewer(vera, boot.orgId, 'ops@logaxp.com');
  guard = makeGuard();
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('protect: the enforcing path', () => {
  it('runs a permitted tool and reports the outcome', async () => {
    const tool = spyTool('write_file');
    const safe = guard.protect(tool, { class: 'file.write' });
    await expect(safe.execute({ path: 'notes.md', content: 'hi' })).resolves.toBe('write_file ok');
    expect(tool.calls).toHaveLength(1);
    expect(logs.some((l) => l.startsWith('VERA ALLOW'))).toBe(true);

    const outcome = (await auditKinds()).filter((e) => e.kind === 'outcome.recorded').at(-1);
    expect(outcome?.payload).toMatchObject({ kind: 'executed', trust: 'asserted' });
  });

  it('refuses a tool no policy permits, and the tool never runs', async () => {
    const tool = spyTool('charge_card');
    const safe = guard.protect(tool, {
      class: 'payment.create',
      target: () => ({ kind: 'vendor', id: 'ABC Supplies', sensitivity: 'high' }),
    });
    await expect(safe.execute({ amount: 48700 })).rejects.toThrow(VeraDenied);
    expect(tool.calls).toHaveLength(0);
  });

  it('carries the reason and decision id on the refusal, so the agent can explain itself', async () => {
    const safe = guard.protect(spyTool('charge_card'), { class: 'payment.create' });
    const err = await safe.execute({ amount: 10 }).catch((e: VeraDenied) => e);
    expect(err).toBeInstanceOf(VeraDenied);
    expect((err as VeraDenied).message).toContain('POLICY.DEFAULT_DENY');
    expect((err as VeraDenied).decisionId).toMatch(/^dec_/);
  });

  it('a failing tool reports `failed` and rethrows the original error', async () => {
    const tool: ToolLike = {
      name: 'write_file',
      execute: async () => {
        throw new Error('disk full');
      },
    };
    const safe = guard.protect(tool, { class: 'file.write' });
    await expect(safe.execute({ path: 'x' })).rejects.toThrow('disk full');
    const outcome = (await auditKinds()).filter((e) => e.kind === 'outcome.recorded').at(-1);
    expect(outcome?.payload).toMatchObject({ kind: 'failed' });
  });

  it('T02: a tool that mutates its arguments is reported as a hash mismatch', async () => {
    const tool: ToolLike = {
      name: 'write_file',
      execute: async (args: Record<string, unknown>) => {
        args.path = '/etc/passwd';
        return 'done';
      },
    };
    const safe = guard.protect(tool, { class: 'file.write' });
    await safe.execute({ path: 'notes.md' });
    const outcome = (await auditKinds()).filter((e) => e.kind === 'outcome.recorded').at(-1);
    expect(outcome?.payload).toMatchObject({ kind: 'hash_mismatch' });
  });
});

describe('protect: review', () => {
  const ddlTool = () => spyTool('run_sql');
  const spec = {
    class: 'db.ddl' as const,
    target: () => ({ kind: 'database', id: 'prod-postgres', sensitivity: 'high' as const }),
  };

  it('holds for a human, then runs once a reviewer approves', async () => {
    const tool = ddlTool();
    const safe = guard.protect(tool, spec);
    const running = safe.execute({ statement: 'ALTER TABLE users DROP COLUMN legacy_id' });

    await new Promise((r) => setTimeout(r, 400));
    const decisionId = logs.find((l) => l.startsWith('VERA REVIEW'))?.match(/dec_\w+/)?.[0];
    expect(decisionId).toBeDefined();
    const approve = await app.inject({
      method: 'POST',
      url: `/v1/decisions/${decisionId}/approve`,
      headers: { authorization: `Bearer ${ops.reviewerToken}` },
      payload: { rationale: 'backup taken' },
    });
    expect(approve.statusCode).toBe(200);

    await expect(running).resolves.toBe('run_sql ok');
    expect(tool.calls).toHaveLength(1);
  });

  it('a rejection means the tool never runs', async () => {
    const tool = ddlTool();
    const safe = guard.protect(tool, spec);
    const running = safe.execute({ statement: 'DROP TABLE users' });

    await new Promise((r) => setTimeout(r, 400));
    const decisionId = logs
      .filter((l) => l.startsWith('VERA REVIEW'))
      .at(-1)
      ?.match(/dec_\w+/)?.[0];
    await app.inject({
      method: 'POST',
      url: `/v1/decisions/${decisionId}/reject`,
      headers: { authorization: `Bearer ${ops.reviewerToken}` },
      payload: {},
    });

    await expect(running).rejects.toThrow(VeraDenied);
    expect(tool.calls).toHaveLength(0);
  });

  it('an unanswered review is VeraUndecided, never a silent allow', async () => {
    const impatient = makeGuard({ holdSeconds: 1, pollIntervalMs: 200 });
    const tool = ddlTool();
    const safe = impatient.protect(tool, spec);
    const err = await safe.execute({ statement: 'TRUNCATE TABLE sessions' }).catch((e: Error) => e);
    expect(err).toBeInstanceOf(VeraUndecided);
    expect((err as Error).message).toContain('SYSTEM.HOLD_EXPIRED');
    expect(tool.calls).toHaveLength(0);
  });
});

describe('needsApproval', () => {
  it('is false for a permitted action and true for one that needs a human', async () => {
    const g = makeGuard();
    const write = g.needsApproval('write_file', { class: 'file.write' });
    expect(await write(null, { path: 'a.md' })).toBe(false);

    const sql = g.needsApproval('run_sql', {
      class: 'db.ddl',
      target: () => ({ kind: 'database', id: 'prod-postgres' }),
    });
    const g2 = makeGuard({ holdSeconds: 0 });
    const sqlFast = g2.needsApproval('run_sql', {
      class: 'db.ddl',
      target: () => ({ kind: 'database', id: 'prod-postgres' }),
    });
    expect(await sqlFast(null, { statement: 'ALTER TABLE x ADD COLUMN y int' })).toBe(true);
    expect(typeof sql).toBe('function');
  });

  it('answers "ask a human" when VERA cannot be reached', async () => {
    const offline = makeGuard({ endpoint: 'http://127.0.0.1:1', requestTimeoutMs: 400 });
    const check = offline.needsApproval('write_file', { class: 'file.write' });
    expect(await check(null, { path: 'a.md' })).toBe(true);
  });
});

describe('SR-08 degraded mode', () => {
  const offline = () => makeGuard({ endpoint: 'http://127.0.0.1:1', requestTimeoutMs: 400 });

  it('read-only work continues', async () => {
    const tool = spyTool('read_file');
    const safe = offline().protect(tool, { class: 'file.read' });
    await expect(safe.execute({ path: 'README.md' })).resolves.toBe('read_file ok');
    expect(logs.some((l) => l.includes('SYSTEM.DEGRADED_MODE'))).toBe(true);
  });

  it('consequential work stops', async () => {
    const tool = spyTool('run_sql');
    const safe = offline().protect(tool, { class: 'db.ddl' });
    await expect(safe.execute({ statement: 'DROP TABLE users' })).rejects.toThrow(/fail closed/);
    expect(tool.calls).toHaveLength(0);
  });

  it('a bad API key is a refusal, not degraded mode', async () => {
    const bad = makeGuard({ apiKey: 'vera_sk_nope' });
    const tool = spyTool('read_file');
    await expect(bad.protect(tool, { class: 'file.read' }).execute({ path: 'x' })).rejects.toThrow(
      VeraDenied,
    );
    expect(tool.calls).toHaveLength(0);
  });
});

describe('idempotency', () => {
  it('the same call twice resolves to the same decision instead of asking twice', async () => {
    const g = makeGuard();
    const spec = { class: 'file.write' as const };
    const a = await g.resolve('write_file', { path: 'same.md' }, spec, 'run-1');
    const b = await g.resolve('write_file', { path: 'same.md' }, spec, 'run-1');
    expect(a.kind).toBe('allow');
    expect(b.decisionId).toBe(a.decisionId);
  });

  it('different arguments are a different decision', async () => {
    const g = makeGuard();
    const spec = { class: 'file.write' as const };
    const a = await g.resolve('write_file', { path: 'one.md' }, spec, 'run-2');
    const b = await g.resolve('write_file', { path: 'two.md' }, spec, 'run-2');
    expect(b.decisionId).not.toBe(a.decisionId);
  });
});
