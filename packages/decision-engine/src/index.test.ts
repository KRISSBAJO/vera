import { compilePolicySet, POLICY_PACK_1 } from '@vera/policy-engine';
import type { DecideRequest, Evidence } from '@vera/schemas';
import { describe, expect, it } from 'vitest';
import { type DecideInput, decide, projectEvidence } from './index.js';

const set = compilePolicySet(POLICY_PACK_1);
const now = new Date('2026-09-11T06:14:00Z');

function req(over: Partial<DecideRequest> & { action?: Partial<DecideRequest['action']> }): DecideRequest {
  return {
    request_id: 'req_1',
    idempotency_key: 'k',
    actor: { type: 'ai_agent', id: 'claude-code' },
    acting_for: { type: 'user', id: 'kriss@logaxp.com', trust: 'asserted' },
    target: { kind: 'repository', id: 'logaxp/hearken', default_branch: 'main' },
    context: { branch: 'feature/x' },
    ...over,
    action: {
      type: 'tool_call',
      tool: 'Bash',
      class: 'vcs.push',
      arguments: {},
      environment: 'production',
      ...over.action,
    },
  };
}

function run(request: DecideRequest, over: Partial<DecideInput> = {}) {
  return decide({
    request,
    tenant: { id: 'org_1', timezone: 'America/New_York' },
    policySet: set,
    policySetVersion: 'ps_1',
    verifiedEvidence: [],
    keyOwner: { id: 'usr_kriss', kind: 'user' },
    now,
    ...over,
  });
}

const codesOf = (r: ReturnType<typeof decide>) => r.reasonCodes.map((c) => c.code);

describe('Appendix C through the whole engine', () => {
  it('push to a feature branch → ALLOW, 10-minute expiry, no review', () => {
    const r = run(req({ action: { arguments: { command: 'git push origin feature/x' } } }));
    expect(r.decision).toBe('ALLOW');
    expect(r.review).toBeUndefined();
    expect(r.requiredActions).toEqual([]);
    expect(r.expiresAt.getTime() - now.getTime()).toBe(10 * 60 * 1000);
    expect(r.policyOutcome).toBe('ALLOW');
  });

  it('force-push to main → BLOCK naming the forbid policy', () => {
    const r = run(
      req({
        context: { branch: 'main' },
        action: { arguments: { command: 'git push --force origin main', force: true } },
      }),
    );
    expect(r.decision).toBe('BLOCK');
    expect(r.reasonCodes).toContainEqual({
      code: 'POLICY.DENY',
      severity: 'high',
      policy_id: 'no-force-push-to-default',
    });
    expect(r.expiresAt.getTime()).toBe(now.getTime());
  });

  it('prod deploy with migration, no verified backup → REVIEW routed with SoD exclusions', () => {
    const verified: Evidence[] = [
      {
        id: 'ev_1',
        type: 'github.pr',
        source: 'github',
        trust: 'verified',
        observed_at: now.toISOString(),
        data: { approved: true, checks: 'success', contains_migration: true },
      },
    ];
    const r = run(req({ action: { class: 'deploy.production', tool: 'deploy', arguments: {} } }), {
      verifiedEvidence: verified,
    });
    expect(r.decision).toBe('REVIEW');
    expect(codesOf(r)).toContain('PREREQ.BACKUP_NOT_VERIFIED');
    expect(codesOf(r)).not.toContain('PREREQ.MISSING_APPROVAL');
    expect(r.review?.excluded).toContain('usr_kriss');
  });

  it('prod deploy with no verified evidence at all → every prerequisite is named, not assumed', () => {
    const r = run(req({ action: { class: 'deploy.production', tool: 'deploy', arguments: {} } }));
    expect(r.decision).toBe('BLOCK'); // NO_MATCH → tenant default
    expect(codesOf(r)).toEqual(
      expect.arrayContaining(['PREREQ.MISSING_APPROVAL', 'PREREQ.TESTS_NOT_PASSED', 'POLICY.DEFAULT_DENY']),
    );
  });
});

describe('SR-01 asserted evidence', () => {
  const prReq = req({ action: { class: 'deploy.production', tool: 'deploy', arguments: {} } });
  const verifiedPr: Evidence = {
    id: 'ev_1',
    type: 'github.pr',
    source: 'github',
    trust: 'verified',
    observed_at: now.toISOString(),
    data: { approved: true, checks: 'success', contains_migration: true },
  };

  it('an adapter-asserted backup does not clear the prerequisite', () => {
    const r = run(
      {
        ...prReq,
        evidence: [
          {
            id: 'ev_2',
            type: 'ops.backup',
            source: 'adapter',
            trust: 'asserted',
            observed_at: now.toISOString(),
            data: { verified: true },
          },
        ],
      },
      { verifiedEvidence: [verifiedPr] },
    );
    expect(r.decision).toBe('REVIEW');
    expect(codesOf(r)).toContain('EVIDENCE.ASSERTED');
    expect(r.evidence.map((e) => e.trust)).toEqual(['verified', 'asserted']);
  });

  it('a VERIFIED backup does', () => {
    const backup: Evidence = {
      id: 'ev_2',
      type: 'ops.backup',
      source: 'backup-system',
      trust: 'verified',
      observed_at: now.toISOString(),
      data: { verified: true },
    };
    const r = run(prReq, { verifiedEvidence: [verifiedPr, backup] });
    expect(r.decision).toBe('ALLOW');
  });

  it('request evidence is forced to asserted even if the caller lies about trust', () => {
    const r = run(
      {
        ...prReq,
        evidence: [
          {
            id: 'ev_2',
            type: 'ops.backup',
            source: 'adapter',
            trust: 'verified' as never,
            observed_at: now.toISOString(),
            data: { verified: true },
          },
        ],
      },
      { verifiedEvidence: [verifiedPr] },
    );
    expect(r.decision).toBe('REVIEW');
  });

  it('projectEvidence ANDs conflicting flags and reads direct flag names', () => {
    expect(projectEvidence([verifiedPr])).toEqual({
      pr_approved: true,
      tests_passed: true,
      contains_migration: true,
    });
    const conflicting: Evidence[] = [
      { ...verifiedPr, data: { approved: true } },
      { ...verifiedPr, id: 'ev_x', type: 'other', data: { pr_approved: false } },
    ];
    expect(projectEvidence(conflicting).pr_approved).toBe(false);
  });
});

describe('aggregation and defaults', () => {
  it('NO_MATCH on a consequential class → BLOCK by default, REVIEW if the tenant says so', () => {
    const r = run(req({ action: { class: 'payment.create', tool: 'stripe', arguments: { amount: 100 } } }));
    expect(r.decision).toBe('BLOCK');
    expect(codesOf(r)).toContain('POLICY.DEFAULT_DENY');
    const soft = run(
      req({ action: { class: 'payment.create', tool: 'stripe', arguments: { amount: 100 } } }),
      {
        tenant: { id: 'org_1', timezone: 'UTC', noMatch: { consequential: 'REVIEW' } },
      },
    );
    expect(soft.decision).toBe('REVIEW');
  });

  it('two medium codes turn a policy ALLOW into REVIEW (destructive hint + sensitive resource)', () => {
    const r = run(
      req({
        target: { kind: 'vault', id: 'prod-secrets', sensitivity: 'high' },
        action: { class: 'secret.read', tool: 'vault', arguments: {}, hints: { destructive: true } },
      }),
    );
    expect(r.policyOutcome).toBe('ALLOW');
    expect(r.decision).toBe('REVIEW');
  });

  it('one medium code alone does not', () => {
    const r = run(
      req({
        target: { kind: 'vault', id: 'prod-secrets', sensitivity: 'high' },
        action: { class: 'secret.read', tool: 'vault', arguments: {} },
      }),
    );
    expect(r.decision).toBe('ALLOW');
  });

  it('shell with indirect input in production → REVIEW with ACTION.INDIRECT_INPUT naming the construct', () => {
    const r = run(
      req({
        target: { kind: 'database', id: 'prod-postgres' },
        action: { class: 'shell.exec', arguments: { command: 'psql $PROD_URL -c "select 1"' } },
      }),
    );
    expect(r.decision).toBe('REVIEW');
    const c = r.reasonCodes.find((x) => x.code === 'ACTION.INDIRECT_INPUT');
    expect(c?.detail).toContain('variable expansion');
  });

  it('risk score sums severity weights and caps at 100; info codes weigh nothing', () => {
    const allow = run(req({ action: { arguments: { command: 'git push origin feature/x' } } }));
    expect(allow.riskScore).toBe(0);
    const block = run(req({ context: { branch: 'main' }, action: { arguments: { force: true } } }));
    expect(block.riskScore).toBe(45);
    const heavy = run(
      req({
        target: { kind: 'db', id: 'x', sensitivity: 'high' },
        action: {
          class: 'shell.exec',
          arguments: { command: 'rm -rf $(cat t)' },
          hints: { destructive: true },
        },
      }),
    );
    expect(heavy.riskScore).toBe(100);
  });

  it('confidence reflects asserted identity and missing evidence', () => {
    const r = run(req({ action: { arguments: {} } }));
    expect(r.confidence).toBe(0.9);
  });
});

describe('SR-09 routing', () => {
  it('excludes actor, acting_for, and key owner; quorum 1 for a user key', () => {
    const r = run(
      req({
        target: { kind: 'database', id: 'prod-postgres' },
        action: { class: 'db.ddl', arguments: { command: 'ALTER TABLE x DROP COLUMN y' } },
      }),
    );
    expect(r.decision).toBe('REVIEW');
    expect(r.review).toEqual({
      routed_to: ['role:reviewer'],
      sod: 'actor_acting_for_and_key_owner_excluded',
      quorum: 1,
      excluded: ['claude-code', 'kriss@logaxp.com', 'usr_kriss'],
    });
    expect(r.expiresAt.getTime() - now.getTime()).toBe(15 * 60 * 1000);
  });

  it('a service-account key needs quorum 2 (ADR-0003)', () => {
    const r = run(
      req({ target: { kind: 'database', id: 'prod-postgres' }, action: { class: 'db.ddl', arguments: {} } }),
      {
        keyOwner: { id: 'svc_ci', kind: 'service' },
      },
    );
    expect(r.review?.quorum).toBe(2);
  });
});
