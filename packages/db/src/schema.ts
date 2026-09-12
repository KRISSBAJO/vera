import { sql } from 'drizzle-orm';
import {
  bigserial,
  doublePrecision,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

/**
 * VERA domain model (brief §9). Every tenant-scoped table carries org_id; row-level security is applied by
 * the custom migration in ./drizzle (Drizzle cannot express FORCE ROW LEVEL SECURITY or the audit trigger).
 *
 * Ids are prefixed opaque strings (org_, usr_, key_, ses_, agt_, sk_, ps_, req_, dec_, rev_, apr_, out_).
 */

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });
const createdAt = () => ts('created_at').notNull().defaultNow();

export interface RedactionPattern {
  name: string;
  pattern: string;
  flags?: string;
}

export interface OrgDefaults {
  /** Tenant-specific secret shapes, applied before the built-in rules (SR-15). */
  redaction_patterns?: RedactionPattern[];
  /** Signed and served to adapters; never editable on the adapter's machine (SR-07). */
  adapter_config?: Record<string, unknown>;
  /** Verdict when no policy matches, per class group (brief §7.1). */
  no_match?: { consequential?: 'BLOCK' | 'REVIEW'; read_only?: 'ALLOW' | 'REVIEW' };
  /** Severity → risk-score weight. Part of policy_set_version for reproducibility (brief §7.4). */
  weights?: { info?: number; low?: number; medium?: number; high?: number };
  token_ttl_seconds?: { allow?: number; approval?: number };
  review_hold_seconds?: number;
}

export const organizations = pgTable('organizations', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  timezone: text('timezone').notNull().default('UTC'),
  defaults: jsonb('defaults').$type<OrgDefaults>().notNull().default({}),
  createdAt: createdAt(),
});

export const users = pgTable(
  'users',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    email: text('email').notNull(),
    name: text('name').notNull(),
    roles: text('roles').array().notNull().default(sql`'{}'::text[]`),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('users_org_email').on(t.orgId, t.email)],
);

/** Per-user (or per-service-account) keys, scope `decide` only (ADR-0003). */
export const apiKeys = pgTable(
  'api_keys',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    ownerUserId: text('owner_user_id')
      .notNull()
      .references(() => users.id),
    kind: text('kind', { enum: ['user', 'service'] })
      .notNull()
      .default('user'),
    keyHash: text('key_hash').notNull(),
    prefix: text('prefix').notNull(),
    scope: text('scope', { enum: ['decide'] })
      .notNull()
      .default('decide'),
    /** `aud` claim for tokens issued to requests made with this key. */
    receiverAud: text('receiver_aud').notNull(),
    createdAt: createdAt(),
    lastUsedAt: ts('last_used_at'),
    revokedAt: ts('revoked_at'),
  },
  (t) => [uniqueIndex('api_keys_hash').on(t.keyHash)],
);

/** Reviewer sessions: the only credential that can approve, reject, or administer (ADR-0003 §4). */
export const reviewerSessions = pgTable(
  'reviewer_sessions',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    userId: text('user_id')
      .notNull()
      .references(() => users.id),
    tokenHash: text('token_hash').notNull(),
    expiresAt: ts('expires_at').notNull(),
    createdAt: createdAt(),
    revokedAt: ts('revoked_at'),
  },
  (t) => [uniqueIndex('reviewer_sessions_hash').on(t.tokenHash)],
);

export const agents = pgTable(
  'agents',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    externalId: text('external_id').notNull(),
    runtime: text('runtime'),
    ownerUserId: text('owner_user_id').references(() => users.id),
    createdAt: createdAt(),
    lastSeenAt: ts('last_seen_at'),
  },
  (t) => [uniqueIndex('agents_org_external').on(t.orgId, t.externalId)],
);

export const signingKeys = pgTable(
  'signing_keys',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    kid: text('kid').notNull(),
    publicJwk: jsonb('public_jwk').$type<Record<string, unknown>>().notNull(),
    /**
     * Custody is one of two mutually exclusive things, enforced by the `signing_keys_one_custody`
     * CHECK in migration 0007:
     *  - `privateJwkSealed`: AES-256-GCM sealed private JWK, held by us (development).
     *  - `kmsKeyArn`: the private half lives in KMS and we never see it (production, ADR-0005).
     */
    privateJwkSealed: text('private_jwk_sealed'),
    kmsKeyArn: text('kms_key_arn'),
    status: text('status', { enum: ['active', 'retiring', 'revoked'] })
      .notNull()
      .default('active'),
    createdAt: createdAt(),
    rotatedAt: ts('rotated_at'),
  },
  (t) => [uniqueIndex('signing_keys_org_kid').on(t.orgId, t.kid)],
);

export const policySets = pgTable(
  'policy_sets',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    version: integer('version').notNull(),
    /** Cedar policy-set text. Compiled and validated on activation. */
    policies: text('policies').notNull(),
    /** Aggregation weights frozen with this version (reproducibility). */
    weights: jsonb('weights').$type<Record<string, number>>().notNull().default({}),
    status: text('status', { enum: ['draft', 'active', 'retired'] })
      .notNull()
      .default('draft'),
    activatedBy: text('activated_by').references(() => users.id),
    activatedAt: ts('activated_at'),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('policy_sets_org_version').on(t.orgId, t.version),
    index('policy_sets_org_status').on(t.orgId, t.status),
  ],
);

export const actionRequests = pgTable(
  'action_requests',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    requestId: text('request_id').notNull(),
    idempotencyKey: text('idempotency_key').notNull(),
    /** sha256 of the canonical request body; a replay with a different body is a 409 (SR-13). */
    bodyHash: text('body_hash').notNull(),
    apiKeyId: text('api_key_id')
      .notNull()
      .references(() => apiKeys.id),
    actor: jsonb('actor').$type<Record<string, unknown>>().notNull(),
    actingFor: jsonb('acting_for').$type<Record<string, unknown>>(),
    /** REDACTED (SR-15). This is what reviewers, reports and any model ever see. */
    action: jsonb('action').$type<Record<string, unknown>>().notNull(),
    /** The raw action, sealed. Revealing it is a step-up, audited action. */
    actionRawSealed: text('action_raw_sealed'),
    /** What redaction removed: rule, path, length. Never the value. */
    redactionFindings: jsonb('redaction_findings').$type<unknown[]>().notNull().default([]),
    target: jsonb('target').$type<Record<string, unknown>>(),
    context: jsonb('context').$type<Record<string, unknown>>(),
    evidence: jsonb('evidence').$type<unknown[]>().notNull().default([]),
    actionHash: text('action_hash').notNull(),
    receivedAt: ts('received_at').notNull().defaultNow(),
  },
  (t) => [uniqueIndex('action_requests_org_idem').on(t.orgId, t.idempotencyKey)],
);

export const decisions = pgTable(
  'decisions',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    actionRequestId: text('action_request_id')
      .notNull()
      .references(() => actionRequests.id),
    decision: text('decision', { enum: ['ALLOW', 'REVIEW', 'BLOCK'] }).notNull(),
    riskScore: integer('risk_score').notNull(),
    confidence: integer('confidence_pct').notNull(),
    reasonCodes: jsonb('reason_codes').$type<unknown[]>().notNull(),
    evidence: jsonb('evidence').$type<unknown[]>().notNull().default([]),
    requiredActions: jsonb('required_actions').$type<string[]>().notNull().default([]),
    review: jsonb('review').$type<Record<string, unknown>>(),
    actionHash: text('action_hash').notNull(),
    policySetVersion: text('policy_set_version').notNull(),
    baselineSnapshotId: text('baseline_snapshot_id'),
    supersedes: text('supersedes'),
    expiresAt: ts('expires_at').notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    index('decisions_org_created').on(t.orgId, t.createdAt),
    uniqueIndex('decisions_request').on(t.actionRequestId),
  ],
);

export const reviews = pgTable(
  'reviews',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    decisionId: text('decision_id')
      .notNull()
      .references(() => decisions.id),
    routedTo: jsonb('routed_to').$type<string[]>().notNull(),
    quorum: integer('quorum').notNull().default(1),
    /** Principal ids that may not approve (actor, acting_for, key owner, policy authors). */
    excluded: jsonb('excluded').$type<string[]>().notNull().default([]),
    status: text('status', { enum: ['pending', 'approved', 'rejected', 'expired'] })
      .notNull()
      .default('pending'),
    expiresAt: ts('expires_at').notNull(),
    resolvedAt: ts('resolved_at'),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('reviews_decision').on(t.decisionId),
    index('reviews_org_status').on(t.orgId, t.status),
  ],
);

export const approvals = pgTable('approvals', {
  id: text('id').primaryKey(),
  orgId: text('org_id')
    .notNull()
    .references(() => organizations.id),
  reviewId: text('review_id')
    .notNull()
    .references(() => reviews.id),
  userId: text('user_id')
    .notNull()
    .references(() => users.id),
  verdict: text('verdict', { enum: ['approve', 'reject'] }).notNull(),
  rationale: text('rationale'),
  createdAt: createdAt(),
});

export const decisionTokens = pgTable(
  'decision_tokens',
  {
    /** The token's jti. */
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    decisionId: text('decision_id')
      .notNull()
      .references(() => decisions.id),
    aud: text('aud').notNull(),
    actionHash: text('action_hash').notNull(),
    /** Which key signed it — so revoking a key can say exactly how many tokens it just invalidated. */
    signingKid: text('signing_kid'),
    /** The token itself, sealed under the master key, so the receiver can collect it by polling. Never logged. */
    tokenSealed: text('token_sealed'),
    expiresAt: ts('expires_at').notNull(),
    consumedAt: ts('consumed_at'),
    createdAt: createdAt(),
  },
  (t) => [index('decision_tokens_decision').on(t.decisionId)],
);

export const outcomes = pgTable('outcomes', {
  id: text('id').primaryKey(),
  orgId: text('org_id')
    .notNull()
    .references(() => organizations.id),
  decisionId: text('decision_id')
    .notNull()
    .references(() => decisions.id),
  source: text('source').notNull(),
  trust: text('trust', { enum: ['verified', 'asserted'] }).notNull(),
  kind: text('kind', {
    enum: ['executed', 'failed', 'reverted', 'incident', 'false_positive', 'hash_mismatch'],
  }).notNull(),
  data: jsonb('data').$type<Record<string, unknown>>().notNull().default({}),
  createdAt: createdAt(),
});

/**
 * One row per action that actually happened and stuck: ALLOWed or approved, executed, not reverted
 * (SR-20, threat T09). Attempted, blocked, and rejected actions never train the baseline. Times are
 * server receive times projected into the tenant's timezone (SR-06) — never the adapter's clock.
 */
export const baselineObservations = pgTable(
  'baseline_observations',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    decisionId: text('decision_id')
      .notNull()
      .references(() => decisions.id),
    actorId: text('actor_id').notNull(),
    actionClass: text('action_class').notNull(),
    targetId: text('target_id').notNull(),
    occurredAt: ts('occurred_at').notNull(),
    localHour: integer('local_hour').notNull(),
    localDow: integer('local_dow').notNull(),
    /** First numeric argument that carries size (amount, count, …); null when the action has none. */
    magnitude: doublePrecision('magnitude'),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('baseline_observations_decision').on(t.decisionId),
    index('baseline_observations_lookup').on(t.orgId, t.actionClass, t.actorId, t.occurredAt),
    index('baseline_observations_recent').on(t.orgId, t.actorId, t.occurredAt),
  ],
);

/** A materialised generation of the rollups. Decisions reference one so they stay reproducible (A10, A11). */
export const baselineSnapshots = pgTable(
  'baseline_snapshots',
  {
    id: text('id').primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    computedAt: ts('computed_at').notNull().defaultNow(),
    observationCount: integer('observation_count').notNull().default(0),
  },
  (t) => [index('baseline_snapshots_org_computed').on(t.orgId, t.computedAt)],
);

export type BaselineScope = 'actor_class_target' | 'actor_class' | 'org_class';

/** Rollups per scope. `key` is the scope's composite key, joined with   to avoid collisions. */
export const baselineStats = pgTable(
  'baseline_stats',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    snapshotId: text('snapshot_id')
      .notNull()
      .references(() => baselineSnapshots.id),
    scope: text('scope', { enum: ['actor_class_target', 'actor_class', 'org_class'] }).notNull(),
    key: text('key').notNull(),
    count: integer('count').notNull(),
    firstSeen: ts('first_seen').notNull(),
    lastSeen: ts('last_seen').notNull(),
    /** 24 counts, index = hour of day in the tenant's timezone. */
    hourHistogram: jsonb('hour_histogram').$type<number[]>().notNull(),
    distinctTargets: integer('distinct_targets').notNull().default(0),
    magnitudeN: integer('magnitude_n').notNull().default(0),
    magnitudeP50: doublePrecision('magnitude_p50'),
    magnitudeP95: doublePrecision('magnitude_p95'),
    magnitudeMax: doublePrecision('magnitude_max'),
  },
  (t) => [uniqueIndex('baseline_stats_lookup').on(t.snapshotId, t.scope, t.key)],
);

/** Append-only, hash-chained per tenant (SR-16). UPDATE/DELETE are refused by trigger. */
export const auditEvents = pgTable(
  'audit_events',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    orgId: text('org_id')
      .notNull()
      .references(() => organizations.id),
    seq: integer('seq').notNull(),
    kind: text('kind').notNull(),
    actor: text('actor').notNull(),
    payload: jsonb('payload').$type<Record<string, unknown>>().notNull(),
    prevHash: text('prev_hash').notNull(),
    hash: text('hash').notNull(),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('audit_events_org_seq').on(t.orgId, t.seq)],
);

export const TENANT_TABLES = [
  'users',
  'api_keys',
  'reviewer_sessions',
  'agents',
  'signing_keys',
  'policy_sets',
  'action_requests',
  'decisions',
  'reviews',
  'approvals',
  'decision_tokens',
  'outcomes',
  'baseline_observations',
  'baseline_snapshots',
  'baseline_stats',
  'audit_events',
] as const;
