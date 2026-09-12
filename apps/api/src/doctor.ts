import { schema, type VeraDb } from '@vera/db';
import { and, count, eq, sql } from 'drizzle-orm';
import type { ApiConfig } from './config.js';

const { organizations, signingKeys, policySets, apiKeys, users } = schema;

/**
 * Operator preflight (deliverable 6).
 *
 * These check the failures that are otherwise silent until the worst possible moment: row-level
 * security not applying because the app connects as a superuser, a tenant with no active policy set,
 * a key held in KMS that this process cannot reach. Each says what is wrong *and* what it means, so
 * an operator can act without reading our source.
 */

export type Level = 'ok' | 'warn' | 'fail';

export interface Check {
  name: string;
  level: Level;
  detail: string;
}

/** Map with a bounded number in flight, preserving input order in the result. */
async function mapConcurrent<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i] as T);
    }
  });
  await Promise.all(workers);
  return out;
}

const ok = (name: string, detail: string): Check => ({ name, level: 'ok', detail });
const warn = (name: string, detail: string): Check => ({ name, level: 'warn', detail });
const fail = (name: string, detail: string): Check => ({ name, level: 'fail', detail });

/**
 * Whether the connected role can ignore row-level security. If it can, tenant isolation is theatre —
 * every policy still exists and none of them apply. This is first because it is the check that has
 * actually caught a real misconfiguration.
 */
export async function checkRlsRole(vera: VeraDb): Promise<Check> {
  const rows = (await vera.db.execute(
    sql`select current_user::text as who, rolsuper as superuser, rolbypassrls as bypassrls
          from pg_roles where rolname = current_user`,
  )) as unknown as { who: string; superuser: boolean; bypassrls: boolean }[];
  const row = rows[0];
  if (!row) return fail('database role', 'could not determine the connected role');
  if (row.superuser || row.bypassrls) {
    return fail(
      'database role',
      `connected as "${row.who}", which ${row.superuser ? 'is a superuser' : 'has BYPASSRLS'}. ` +
        'Row-level security does not apply to this role, so one tenant can read another tenant’s ' +
        'decisions. Point DATABASE_URL at the vera_app role.',
    );
  }
  return ok('database role', `"${row.who}" — no superuser, no BYPASSRLS, so RLS applies`);
}

/** Migrations applied, asked by looking for something only the newest one creates. */
export async function checkSchema(vera: VeraDb): Promise<Check> {
  const rows = (await vera.db.execute(
    sql`select count(*)::int as n from information_schema.columns
         where table_name = 'signing_keys' and column_name = 'kms_key_arn'`,
  )) as unknown as { n: number }[];
  return rows[0]?.n
    ? ok('schema', 'migrations applied through 0007')
    : fail('schema', 'the newest migration is missing — run: vera-api migrate');
}

export interface TenantSurvey {
  checks: Check[];
  /** How many active keys are held in KMS. Counted here because only this pass can see the rows. */
  kmsKeys: number;
}

export async function checkTenants(vera: VeraDb): Promise<TenantSurvey> {
  const orgs = await vera.withAuthLookup((tx) =>
    tx.select({ id: organizations.id, name: organizations.name }).from(organizations),
  );
  if (orgs.length === 0) {
    return {
      checks: [warn('tenants', 'none yet — run: vera-api bootstrap --org "…" --email you@…')],
      kmsKeys: 0,
    };
  }
  const checks: Check[] = [ok('tenants', `${orgs.length} organisation(s)`)];
  let kmsKeys = 0;

  // One transaction per tenant, several at a time.
  //
  // The tempting version is four grouped queries over every tenant at once. It cannot work, and the
  // reason is the point of the system: `vera.auth_lookup` — the cross-tenant escape hatch — is
  // granted only on `organizations`, `api_keys` and `reviewer_sessions`, the three tables that must
  // be read before the tenant is known. `policy_sets`, `signing_keys` and `users` are strictly
  // tenant-scoped, so a grouped query over them returns nothing at all and every tenant looks
  // unconfigured. Widening the escape to make an operator tool faster would trade real tenant
  // isolation for a preflight's convenience, which is a bad bargain at any speed. Concurrency gets
  // the latency back without giving anything up.
  const surveyed = await mapConcurrent(orgs, 8, (org) =>
    vera.withTenant(org.id, async (tx) => {
      const [ps] = await tx
        .select({ version: policySets.version })
        .from(policySets)
        .where(and(eq(policySets.orgId, org.id), eq(policySets.status, 'active')))
        .limit(1);
      const [key] = await tx
        .select({ kid: signingKeys.kid, kms: signingKeys.kmsKeyArn })
        .from(signingKeys)
        .where(and(eq(signingKeys.orgId, org.id), eq(signingKeys.status, 'active')))
        .limit(1);
      const [reviewers] = await tx.select({ n: count() }).from(users).where(eq(users.orgId, org.id));
      const [keyCount] = await tx.select({ n: count() }).from(apiKeys).where(eq(apiKeys.orgId, org.id));
      return { org, ps, key, reviewers: reviewers?.n ?? 0, keys: keyCount?.n ?? 0 };
    }),
  );

  for (const found of surveyed) {
    const org = found.org;
    const label = `tenant ${org.id}`;
    if (!found.ps) {
      checks.push(
        fail(label, 'no active policy set — every decision fails. Run: vera-api activate-policies'),
      );
      continue;
    }
    if (!found.key) {
      checks.push(fail(label, 'no active signing key — nothing can be signed'));
      continue;
    }
    if (found.key.kms) kmsKeys += 1;
    const custody = found.key.kms ? `KMS ${found.key.kms}` : 'local (development-grade, ADR-0005)';
    checks.push(
      ok(
        label,
        `${org.name} · ps_${found.ps.version} · key ${found.key.kid} · custody ${custody} · ` +
          `${found.reviewers} reviewer(s) · ${found.keys} API key(s)`,
      ),
    );
    if (found.reviewers < 2) {
      checks.push(
        warn(
          label,
          `only ${found.reviewers} reviewer(s). Separation of duties excludes whoever requested the ` +
            'action from approving it, so a REVIEW raised by your only reviewer has nobody left to ' +
            'approve it and will expire.',
        ),
      );
    }
  }
  return { checks, kmsKeys };
}

/**
 * KMS is configured in one place and recorded in another; a mismatch only shows up at signing time.
 *
 * `usingKms` is counted during the tenant survey rather than by a `select count(*)` here, because a
 * query outside `withTenant` or `withAuthLookup` sets neither setting row-level security reads, so it
 * is correctly filtered to nothing — which reads as "no tenant uses KMS" however many do. The first
 * version of this function had exactly that bug, and our own RLS is what exposed it.
 */
export function checkKms(usingKms: number, config: ApiConfig): Check {
  if (usingKms === 0) {
    return config.kms
      ? warn('KMS', 'configured, but no tenant uses it — run: vera-api register-kms-key --org-id … --arn …')
      : warn('KMS', 'not configured; private keys are sealed in this database (development-grade, ADR-0005)');
  }
  if (!config.kms) {
    return fail(
      'KMS',
      `${usingKms} tenant(s) sign through KMS but this process has no KMS configuration, so they ` +
        'cannot sign at all. VERA refuses rather than falling back to a local key.',
    );
  }
  return ok('KMS', `${usingKms} tenant(s) signing in ${config.kms.region}`);
}

export function checkNotifications(env: NodeJS.ProcessEnv): Check {
  const token = Boolean(env.SLACK_BOT_TOKEN);
  const channel = Boolean(env.SLACK_REVIEW_CHANNEL);
  if (token && channel) return ok('Slack', 'review notifications enabled');
  if (!token && !channel) {
    return warn('Slack', 'not configured — a reviewer learns about a decision only by opening the dashboard');
  }
  return fail(
    'Slack',
    `half configured (${token ? 'token but no channel' : 'channel but no token'}) — notifications are off`,
  );
}

export function checkEvidence(env: NodeJS.ProcessEnv): Check {
  return env.GITHUB_APP_ID && env.GITHUB_APP_INSTALLATION_ID && env.GITHUB_APP_PRIVATE_KEY_PATH
    ? ok('evidence: GitHub', 'PR approval and CI status can be verified rather than asserted')
    : warn(
        'evidence: GitHub',
        'not configured. Policies requiring a merged PR or green checks will see EVIDENCE.MISSING, ' +
          'because VERA does not take the agent’s word for a prerequisite.',
      );
}

export async function runDoctor(vera: VeraDb, config: ApiConfig, env: NodeJS.ProcessEnv): Promise<Check[]> {
  const checks: Check[] = [await checkRlsRole(vera)];
  const schemaCheck = await checkSchema(vera);
  checks.push(schemaCheck);
  // Everything below reads tables the migrations create. Asking anyway would produce noise, not news.
  if (schemaCheck.level === 'ok') {
    const survey = await checkTenants(vera);
    checks.push(...survey.checks, checkKms(survey.kmsKeys, config));
  }
  checks.push(checkNotifications(env), checkEvidence(env));
  return checks;
}

const MARK: Record<Level, string> = { ok: ' ok ', warn: 'warn', fail: 'FAIL' };

export function formatChecks(checks: Check[]): string {
  const width = Math.max(...checks.map((c) => c.name.length));
  const lines = checks.map((c) => `  [${MARK[c.level]}]  ${c.name.padEnd(width)}  ${c.detail}`);
  const failures = checks.filter((c) => c.level === 'fail').length;
  const warnings = checks.filter((c) => c.level === 'warn').length;
  const summary =
    failures > 0
      ? `${failures} failure(s), ${warnings} warning(s). VERA is not ready.`
      : warnings > 0
        ? `No failures, ${warnings} warning(s). VERA will run — read the warnings before trusting it.`
        : 'All checks passed.';
  return `${lines.join('\n')}\n\n  ${summary}`;
}
