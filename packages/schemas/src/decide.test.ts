import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  DecideRequestSchema,
  DecideResponseSchema,
  isConsequential,
  REASON_CODES,
  ReasonCodeSchema,
  responseInvariantViolations,
} from './index.js';

// The brief §6.1 example, post-A1: evidence from the adapter is asserted and claims a verified backup.
const exampleRequest = {
  request_id: 'req_01J8ZK0000000000000000001',
  idempotency_key: 'claude-code:sess_9f1:call_42',
  actor: { type: 'ai_agent', id: 'claude-code', runtime: 'claude-agent-sdk@1.x', session_id: 'sess_9f1' },
  acting_for: { type: 'user', id: 'kriss@logaxp.com', trust: 'asserted' },
  action: {
    type: 'tool_call',
    tool: 'Bash',
    class: 'db.ddl',
    arguments: { command: 'psql $PROD_URL -c "ALTER TABLE users DROP COLUMN legacy_id"' },
    environment: 'production',
    hints: { destructive: true, idempotent: false, open_world: false },
  },
  target: { kind: 'database', id: 'prod-postgres', sensitivity: 'high' },
  context: {
    repo: 'logaxp/hearken',
    branch: 'main',
    cwd: '/srv/hearken',
    local_time: '2026-09-11T02:14:00-04:00',
  },
  evidence: [
    {
      id: 'ev_2',
      type: 'ops.backup',
      source: 'adapter',
      trust: 'asserted',
      observed_at: '2026-09-10T23:00:00Z',
      data: { verified: true },
    },
  ],
} as const;

const exampleResponse = {
  decision_id: 'dec_01J8ZK0000000000000000001',
  decision: 'REVIEW',
  risk: { score: 78, calibrated: false },
  confidence: 0.93,
  reason_codes: [
    { code: 'POLICY.REQUIRE_REVIEW', policy_id: 'pol_prod_ddl@v3', severity: 'high' },
    {
      code: 'PREREQ.BACKUP_NOT_VERIFIED',
      severity: 'high',
      detail: 'adapter-asserted ev_2 does not satisfy the prerequisite',
    },
    { code: 'BASELINE.ACTOR_ACTION_NOVEL', severity: 'medium' },
    { code: 'IDENTITY.ASSERTED', severity: 'info' },
  ],
  evidence: [
    {
      id: 'ev_1',
      type: 'github.pr',
      source: 'github',
      trust: 'verified',
      observed_at: '2026-09-11T06:10:02Z',
      data: { number: 812, approved: true },
    },
    {
      id: 'ev_2',
      type: 'ops.backup',
      source: 'adapter',
      trust: 'asserted',
      observed_at: '2026-09-10T23:00:00Z',
      data: { verified: true },
    },
  ],
  required_actions: ['HUMAN_APPROVAL'],
  review: {
    url: 'https://vera.example/r/dec_01J8ZK',
    routed_to: ['role:platform-admin'],
    sod: 'actor_acting_for_and_key_owner_excluded',
    quorum: 1,
  },
  action_hash: `sha256:${'4f9c'.repeat(16)}`,
  policy_set_version: 'ps_17',
  baseline_snapshot_id: 'bs_2026-09-11T06',
  supersedes: null,
  expires_at: '2026-09-11T06:40:02Z',
  decision_token: null,
} as const;

describe('DecideRequest', () => {
  it('accepts the brief example', () => {
    expect(DecideRequestSchema.safeParse(exampleRequest).success).toBe(true);
  });

  it('SR-01: rejects evidence that claims to be verified on the request', () => {
    const r = DecideRequestSchema.safeParse({
      ...exampleRequest,
      evidence: [{ ...exampleRequest.evidence[0], trust: 'verified' }],
    });
    expect(r.success).toBe(false);
  });

  it('SR-09: rejects acting_for that claims to be verified on the request', () => {
    const r = DecideRequestSchema.safeParse({
      ...exampleRequest,
      acting_for: { type: 'user', id: 'x', trust: 'verified' },
    });
    expect(r.success).toBe(false);
  });

  it('rejects an unknown action class', () => {
    const r = DecideRequestSchema.safeParse({
      ...exampleRequest,
      action: { ...exampleRequest.action, class: 'db.explode' },
    });
    expect(r.success).toBe(false);
  });

  it('keeps unknown target attributes (loose object) but requires kind and id', () => {
    const ok = DecideRequestSchema.safeParse({
      ...exampleRequest,
      target: { kind: 'database', id: 'x', region: 'eu-west-1' },
    });
    expect(ok.success).toBe(true);
    const bad = DecideRequestSchema.safeParse({ ...exampleRequest, target: { kind: 'database' } });
    expect(bad.success).toBe(false);
  });
});

describe('DecideResponse', () => {
  it('accepts the brief example and satisfies invariants', () => {
    const parsed = DecideResponseSchema.parse(exampleResponse);
    expect(responseInvariantViolations(parsed)).toEqual([]);
  });

  it('flags an ALLOW without a token', () => {
    const parsed = DecideResponseSchema.parse({
      ...exampleResponse,
      decision: 'ALLOW',
      review: undefined,
      required_actions: [],
    });
    expect(responseInvariantViolations(parsed)).toContain('ALLOW must carry a decision_token');
  });

  it('flags a BLOCK with no high-severity reason', () => {
    const parsed = DecideResponseSchema.parse({
      ...exampleResponse,
      decision: 'BLOCK',
      review: undefined,
      required_actions: [],
      reason_codes: [{ code: 'BASELINE.TIME_ANOMALY', severity: 'low' }],
    });
    expect(responseInvariantViolations(parsed)).toContain(
      'BLOCK must cite at least one high-severity reason',
    );
  });

  it('rejects an unknown reason code', () => {
    expect(ReasonCodeSchema.safeParse('POLICY.WHATEVER').success).toBe(false);
  });

  it('rejects a malformed action_hash', () => {
    expect(DecideResponseSchema.safeParse({ ...exampleResponse, action_hash: 'sha256:abc' }).success).toBe(
      false,
    );
  });
});

describe('registry', () => {
  it('every reason code has a category matching its prefix and non-empty guidance', () => {
    for (const [code, def] of Object.entries(REASON_CODES)) {
      expect(code.startsWith(`${def.category}.`)).toBe(true);
      expect(def.guidance.length).toBeGreaterThan(10);
    }
  });

  it('read-only classes are the only non-consequential ones', () => {
    expect(isConsequential('file.read')).toBe(false);
    expect(isConsequential('unknown.consequential')).toBe(true);
    expect(isConsequential('deploy.production')).toBe(true);
  });

  it('exports JSON Schema without throwing', () => {
    const json = z.toJSONSchema(DecideRequestSchema, { target: 'draft-2020-12', io: 'input' });
    expect(json).toHaveProperty('properties');
  });
});
