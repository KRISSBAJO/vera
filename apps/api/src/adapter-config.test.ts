import { randomBytes } from 'node:crypto';
import { createDb, type VeraDb } from '@vera/db';
import { verifyAdapterConfig } from '@vera/decision-token';
import type { TenantJwks } from '@vera/schemas';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { addReviewer, type BootstrapResult, bootstrapTenant } from './bootstrap.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:config-test';

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;
let reviewerOnly: { userId: string; reviewerToken: string };

const asKey = (t: string) => ({ authorization: `Bearer ${t}` });
const fetchConfig = (token = boot.apiKey) =>
  app.inject({ method: 'GET', url: '/v1/adapter-config', headers: asKey(token) });
const putConfig = (body: unknown, token = boot.reviewerToken) =>
  app.inject({ method: 'PUT', url: '/v1/adapter-config', headers: asKey(token), payload: body });
const jwks = async (): Promise<TenantJwks> =>
  (await app.inject({ method: 'GET', url: `/.well-known/vera/${boot.orgId}/jwks.json` })).json();

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  const masterKey = randomBytes(32);
  app = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test' });
  boot = await bootstrapTenant(vera, masterKey, {
    orgName: 'ConfigCo',
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  });
  reviewerOnly = await addReviewer(vera, boot.orgId, 'ops@logaxp.com');
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('the table VERA serves is signed and verifiable', () => {
  it('an adapter can verify the bundle against the tenant JWKS', async () => {
    const r = await fetchConfig();
    expect(r.statusCode).toBe(200);
    const { bundle, config } = r.json();

    const v = await verifyAdapterConfig(bundle, await jwks(), { tenant: boot.orgId, aud: AUD });
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.config).toEqual(config);
  });

  it('the bundle is bound to the receiver, so one adapter cannot use another one’s table', async () => {
    const { bundle } = (await fetchConfig()).json();
    const v = await verifyAdapterConfig(bundle, await jwks(), { tenant: boot.orgId, aud: 'adapter:not-me' });
    expect(v).toMatchObject({ ok: false, code: 'CONFIG.AUDIENCE_MISMATCH' });
  });

  it('the default table lets only read-only classes fail open', async () => {
    const { config } = (await fetchConfig()).json();
    expect(config.fail_open_classes).toEqual(['file.read', 'vcs.read', 'http.read', 'db.read', 'search']);
    expect(config.tool_classes).toEqual({});
  });
});

describe('T12: configuration cannot weaken policy', () => {
  it('refuses to sign a table that lets a consequential class fail open', async () => {
    const r = await putConfig({ fail_open_classes: ['file.read', 'deploy.production'] });
    expect(r.statusCode).toBe(403);
    expect(r.json().error.code).toBe('UNSAFE_FAIL_OPEN');
    expect(r.json().error.message).toContain('An unreachable VERA is not an approval');
  });

  it('the refusal names every offending class, not just the first', async () => {
    const r = await putConfig({ fail_open_classes: ['db.ddl', 'payment.create'] });
    expect(r.json().error.message).toContain('db.ddl');
    expect(r.json().error.message).toContain('payment.create');
  });

  it('the stored table is unchanged after a refused write', async () => {
    const { config } = (await fetchConfig()).json();
    expect(config.fail_open_classes).not.toContain('deploy.production');
  });
});

describe('who may change the table', () => {
  it('a reviewer without the admin role cannot', async () => {
    expect((await putConfig({ hold_seconds: 60 }, reviewerOnly.reviewerToken)).statusCode).toBe(403);
  });

  it('an API key can read the table but not write it', async () => {
    expect((await fetchConfig()).statusCode).toBe(200);
    expect((await putConfig({ hold_seconds: 60 }, boot.apiKey)).statusCode).toBe(401);
  });
});

describe('updating the table', () => {
  it('an admin can classify a tool, and the version increments', async () => {
    const before = (await fetchConfig()).json().config.version;
    const r = await putConfig({
      tool_classes: { deploy_service: 'deploy.production' },
      tool_class_patterns: [{ pattern: '^mcp__stripe__', class: 'payment.create' }],
    });
    expect(r.statusCode).toBe(200);
    expect(r.json().version).toBe(before + 1);
    expect(r.json().tool_classes.deploy_service).toBe('deploy.production');
  });

  it('the new table is what gets signed and served', async () => {
    const { bundle, config } = (await fetchConfig()).json();
    expect(config.tool_classes.deploy_service).toBe('deploy.production');
    const v = await verifyAdapterConfig(bundle, await jwks(), { tenant: boot.orgId, aud: AUD });
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.config.tool_class_patterns[0]?.pattern).toBe('^mcp__stripe__');
  });

  it('a change is audited with what it altered, and by whom', async () => {
    const events = (
      await app.inject({
        method: 'GET',
        url: '/v1/audit-events?limit=500',
        headers: asKey(boot.reviewerToken),
      })
    ).json().events;
    const updated = events.filter((e: { kind: string }) => e.kind === 'adapter_config.updated').at(-1);
    expect(updated.actor).toBe(`user:${boot.userId}`);
    expect(updated.payload).toMatchObject({ tool_classes: 1, patterns: 1 });
  });

  it('an unknown action class is rejected by the schema', async () => {
    const r = await putConfig({ tool_classes: { x: 'not.a.real.class' } });
    expect(r.statusCode).toBe(400);
  });
});
