import { describe, expect, it } from 'vitest';
import {
  type CompiledPolicySet,
  cedarVersion,
  compilePolicySet,
  type EvaluationInput,
  evaluate,
  POLICY_PACK_1,
} from './index.js';

const agent = { type: 'Agent' as const, id: 'claude-code' };
const prodRepo = {
  kind: 'repository',
  id: 'logaxp/hearken',
  environment: 'production',
  branch: 'main',
  default_branch: 'main',
};
const featureBranch = { ...prodRepo, branch: 'feature/x' };
const prodDb = { kind: 'database', id: 'prod-postgres', environment: 'production', sensitivity: 'high' };
const stagingDb = { ...prodDb, id: 'staging-postgres', environment: 'staging' };

function run(
  set: CompiledPolicySet,
  partial: Omit<EvaluationInput, 'principal' | 'context'> & { context?: Partial<EvaluationInput['context']> },
) {
  return evaluate(set, {
    principal: agent,
    action: partial.action,
    resource: partial.resource,
    context: { args: {}, indirect_input: false, ...partial.context },
  });
}

describe('Cedar spike — the least-proven dependency (ADR-0001)', () => {
  it('loads the WASM and reports a version', () => {
    expect(cedarVersion()).toMatch(/^\d+\.\d+/);
  });

  it('compiles Policy Pack 1: every policy has an @id, annotations are readable, strict validation passes', () => {
    const set = compilePolicySet(POLICY_PACK_1);
    const ids = Object.keys(set.policies);
    expect(ids).toContain('no-force-push-to-default');
    expect(set.policies['no-force-push-to-default']?.effect).toBe('forbid');
    expect(set.policies['prod-ddl-requires-review']?.veraEffect).toBe('review');
    expect(set.policies['vcs-push-non-force']?.veraEffect).toBeUndefined();
    expect(ids.length).toBeGreaterThanOrEqual(18);
  });

  it('diagnostics.reason reports our @id values, not policy0/policy1', () => {
    const set = compilePolicySet(POLICY_PACK_1);
    const r = run(set, { action: 'vcs.push', resource: featureBranch, args: {} } as never);
    expect(r.determining).toEqual(['vcs-push-non-force']);
  });
});

describe('Policy Pack 1 — brief Appendix C', () => {
  const set = compilePolicySet(POLICY_PACK_1);

  it('git push to a feature branch → ALLOW', () => {
    const r = run(set, { action: 'vcs.push', resource: featureBranch });
    expect(r.outcome).toBe('ALLOW');
    expect(r.reasonCodes).toEqual([]);
  });

  it('git push --force to the default branch → BLOCK with POLICY.DENY naming the policy', () => {
    const r = run(set, { action: 'vcs.push', resource: prodRepo, context: { args: { force: true } } });
    expect(r.outcome).toBe('BLOCK');
    expect(r.reasonCodes).toEqual([
      { code: 'POLICY.DENY', severity: 'high', policy_id: 'no-force-push-to-default' },
    ]);
  });

  it('git push --force to a feature branch → REVIEW (most-restrictive-wins over nothing else)', () => {
    const r = run(set, { action: 'vcs.push', resource: featureBranch, context: { args: { force: true } } });
    expect(r.outcome).toBe('REVIEW');
    expect(r.determining).toEqual(['force-push-non-default-requires-review']);
  });

  it('production deploy, PR approved, tests green, no migration → ALLOW', () => {
    const r = run(set, {
      action: 'deploy.production',
      resource: prodRepo,
      context: { evidence: { pr_approved: true, tests_passed: true, contains_migration: false } },
    });
    expect(r.outcome).toBe('ALLOW');
    expect(r.determining).toEqual(['prod-deploy-clean']);
  });

  it('production deploy with migration and no verified backup → REVIEW', () => {
    const r = run(set, {
      action: 'deploy.production',
      resource: prodRepo,
      context: { evidence: { pr_approved: true, tests_passed: true, contains_migration: true } },
    });
    expect(r.outcome).toBe('REVIEW');
    expect(r.reasonCodes).toEqual([
      { code: 'POLICY.REQUIRE_REVIEW', severity: 'high', policy_id: 'prod-deploy-needs-backup-if-migration' },
    ]);
  });

  it('SR-01: an adapter-asserted backup does not clear the prerequisite', () => {
    const r = run(set, {
      action: 'deploy.production',
      resource: prodRepo,
      context: {
        evidence: { pr_approved: true, tests_passed: true, contains_migration: true },
        asserted: { backup_verified: true },
      },
    });
    expect(r.outcome).toBe('REVIEW');
  });

  it('production deploy with migration and a VERIFIED backup → ALLOW', () => {
    const r = run(set, {
      action: 'deploy.production',
      resource: prodRepo,
      context: {
        evidence: { pr_approved: true, tests_passed: true, contains_migration: true, backup_verified: true },
      },
    });
    expect(r.outcome).toBe('ALLOW');
    expect(r.determining).toEqual(['prod-deploy-migration-with-verified-backup']);
  });

  it('production deploy with no evidence at all → NO_MATCH (tenant default applies; never ALLOW)', () => {
    const r = run(set, { action: 'deploy.production', resource: prodRepo });
    expect(r.outcome).toBe('NO_MATCH');
  });

  it('DDL against production → REVIEW; DDL against staging → ALLOW', () => {
    expect(run(set, { action: 'db.ddl', resource: prodDb }).outcome).toBe('REVIEW');
    expect(run(set, { action: 'db.ddl', resource: stagingDb }).outcome).toBe('ALLOW');
  });

  it('shell in production with indirect input → REVIEW citing both shell policies', () => {
    const r = run(set, {
      action: 'shell.exec',
      resource: prodDb,
      context: { args: { command: 'psql $PROD_URL' }, indirect_input: true },
    });
    expect(r.outcome).toBe('REVIEW');
    expect(r.determining.sort()).toEqual([
      'prod-shell-indirect-input-requires-review',
      'prod-shell-unclassified-requires-review',
    ]);
  });

  it('read-only classes → ALLOW', () => {
    for (const action of ['file.read', 'vcs.read', 'db.read', 'search'] as const) {
      expect(run(set, { action, resource: prodDb }).outcome).toBe('ALLOW');
    }
  });

  it('unknown.consequential → NO_MATCH (nobody wrote a permit for it)', () => {
    expect(run(set, { action: 'unknown.consequential', resource: prodDb }).outcome).toBe('NO_MATCH');
  });

  it('undeclared or mistyped arguments are invisible to policy, not a validation failure', () => {
    const r = run(set, {
      action: 'vcs.push',
      resource: featureBranch,
      context: { args: { force: 'yes', weird_key: { nested: true }, timeout: 1.5 } as never },
    });
    // `force: 'yes'` is not a Boolean, so it is dropped: the non-force permit applies.
    expect(r.outcome).toBe('ALLOW');
    expect(r.errors).toEqual([]);
  });
});

describe('three-outcome mapping edge cases', () => {
  it('A9: a plain permit and a review permit both matching → REVIEW', () => {
    const set = compilePolicySet(`
      @id("plain") permit(principal, action == VERA::Action::"file.write", resource);
      @id("careful") @vera_effect("review") permit(principal, action == VERA::Action::"file.write", resource);
    `);
    const r = run(set, { action: 'file.write', resource: prodDb });
    expect(r.outcome).toBe('REVIEW');
    expect(r.determining.sort()).toEqual(['careful', 'plain']);
  });

  it('forbid beats every permit', () => {
    const set = compilePolicySet(`
      @id("plain") permit(principal, action == VERA::Action::"file.write", resource);
      @id("never") forbid(principal, action == VERA::Action::"file.write", resource);
    `);
    const r = run(set, { action: 'file.write', resource: prodDb });
    expect(r.outcome).toBe('BLOCK');
    expect(r.determining).toEqual(['never']);
  });

  it('refuses a policy without @id', () => {
    expect(() => compilePolicySet(`permit(principal, action, resource);`)).toThrow(/without @id/);
  });

  it('refuses duplicate ids and unknown @vera_effect values', () => {
    expect(() =>
      compilePolicySet(`
        @id("a") permit(principal, action == VERA::Action::"file.write", resource);
        @id("a") permit(principal, action == VERA::Action::"file.read", resource);
      `),
    ).toThrow(/duplicate/);
    expect(() =>
      compilePolicySet(
        `@id("a") @vera_effect("allow") permit(principal, action == VERA::Action::"file.write", resource);`,
      ),
    ).toThrow(/unknown @vera_effect/);
  });

  it('refuses policies that do not validate against the schema (typo in an attribute)', () => {
    expect(() =>
      compilePolicySet(
        `@id("typo") permit(principal, action == VERA::Action::"db.ddl", resource) when { resource.enviroment == "production" };`,
      ),
    ).toThrow(/validate/);
  });

  it('refuses a policy set that does not parse', () => {
    expect(() => compilePolicySet(`@id("x") permit(principal action resource)`)).toThrow(/parse/);
  });
});
