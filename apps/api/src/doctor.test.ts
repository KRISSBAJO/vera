import { randomBytes } from 'node:crypto';
import { createDb, type VeraDb } from '@vera/db';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bootstrapTenant } from './bootstrap.js';
import type { ApiConfig } from './config.js';
import {
  type Check,
  checkEvidence,
  checkKms,
  checkNotifications,
  checkRlsRole,
  checkSchema,
  checkTenants,
  formatChecks,
} from './doctor.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';

let app: VeraDb;
let admin: VeraDb;

const config = (kms?: ApiConfig['kms']): ApiConfig =>
  ({
    databaseUrl: appUrl,
    migrationDatabaseUrl: migrationUrl,
    masterKey: randomBytes(32),
    publicUrl: 'http://vera.test',
    port: 4000,
    kms,
  }) as ApiConfig;

beforeAll(async () => {
  admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  app = createDb(appUrl, { max: 2 });
});

afterAll(async () => {
  await app.close();
  await admin.close();
});

describe('the check that matters most: does row-level security actually apply', () => {
  it('passes for the app role', async () => {
    const c = await checkRlsRole(app);
    expect(c.level).toBe('ok');
    expect(c.detail).toContain('vera_app');
  });

  it('fails for the migration superuser, and says what it means rather than just naming a flag', async () => {
    const c = await checkRlsRole(admin);
    expect(c.level).toBe('fail');
    expect(c.detail).toMatch(/superuser/);
    // The point of the check is the consequence, not the flag.
    expect(c.detail).toMatch(/tenant/i);
    expect(c.detail).toContain('vera_app');
  });
});

describe('schema and tenants', () => {
  it('sees the applied migrations', async () => {
    expect((await checkSchema(app)).level).toBe('ok');
  });

  it('reports a freshly bootstrapped tenant as ready, and counts its KMS keys as zero', async () => {
    const boot = await bootstrapTenant(app, randomBytes(32), {
      orgName: `DoctorCo-${randomBytes(3).toString('hex')}`,
      adminEmail: 'kriss@logaxp.com',
      receiverAud: 'adapter:doctor-test',
    });
    const survey = await checkTenants(app);
    const mine = survey.checks.filter((c) => c.name === `tenant ${boot.orgId}`);
    expect(mine.some((c) => c.level === 'ok' && c.detail.includes('ps_1'))).toBe(true);
    expect(mine.some((c) => c.level === 'ok' && c.detail.includes('development-grade'))).toBe(true);
  });

  it('warns when a tenant has too few reviewers for separation of duties to be satisfiable', async () => {
    const boot = await bootstrapTenant(app, randomBytes(32), {
      orgName: `SoloCo-${randomBytes(3).toString('hex')}`,
      adminEmail: 'solo@logaxp.com',
      receiverAud: 'adapter:doctor-solo',
    });
    const survey = await checkTenants(app);
    const mine = survey.checks.filter((c) => c.name === `tenant ${boot.orgId}`);
    const warning = mine.find((c) => c.level === 'warn');
    expect(warning?.detail).toMatch(/expire/);
  });
});

describe('KMS custody reporting', () => {
  it('fails loudly when tenants sign through KMS but the process has no KMS config', () => {
    const c = checkKms(3, config(undefined));
    expect(c.level).toBe('fail');
    expect(c.detail).toContain('cannot sign');
    // It must not suggest a fallback exists.
    expect(c.detail).toMatch(/refuses rather than falling back/);
  });

  it('warns, not fails, when KMS is merely unused — local custody is a downgrade, not an outage', () => {
    expect(checkKms(0, config(undefined)).level).toBe('warn');
    expect(checkKms(0, config({ region: 'us-east-1' })).level).toBe('warn');
    expect(checkKms(0, config({ region: 'us-east-1' })).detail).toContain('register-kms-key');
  });

  it('is satisfied when both sides agree', () => {
    const c = checkKms(2, config({ region: 'us-east-1' }));
    expect(c).toMatchObject({ level: 'ok' });
    expect(c.detail).toContain('us-east-1');
  });
});

describe('integrations', () => {
  it('treats a half-configured Slack as a failure, not a warning — it silently notifies nobody', () => {
    expect(checkNotifications({ SLACK_BOT_TOKEN: 'x' } as NodeJS.ProcessEnv).level).toBe('fail');
    expect(checkNotifications({ SLACK_REVIEW_CHANNEL: 'C1' } as NodeJS.ProcessEnv).level).toBe('fail');
    expect(checkNotifications({} as NodeJS.ProcessEnv).level).toBe('warn');
    expect(
      checkNotifications({ SLACK_BOT_TOKEN: 'x', SLACK_REVIEW_CHANNEL: 'C1' } as NodeJS.ProcessEnv).level,
    ).toBe('ok');
  });

  it('explains what an absent evidence provider costs, in reason-code terms', () => {
    const c = checkEvidence({} as NodeJS.ProcessEnv);
    expect(c.level).toBe('warn');
    expect(c.detail).toContain('EVIDENCE.MISSING');
  });
});

describe('the report', () => {
  const checks: Check[] = [
    { name: 'a', level: 'ok', detail: 'fine' },
    { name: 'bbb', level: 'warn', detail: 'hmm' },
    { name: 'cc', level: 'fail', detail: 'broken' },
  ];

  it('says plainly whether VERA is usable, and aligns for scanning', () => {
    const out = formatChecks(checks);
    expect(out).toContain('1 failure(s), 1 warning(s). VERA is not ready.');
    expect(out).toContain('[FAIL]');
    // Names are padded to a common width so the details line up.
    expect(out).toMatch(/\[ ok \]\s+a\s{3}\s*fine/);
  });

  it('does not call a run with warnings a pass', () => {
    expect(formatChecks(checks.slice(0, 2))).toContain('read the warnings before trusting it');
    expect(formatChecks(checks.slice(0, 1))).toContain('All checks passed.');
  });
});
