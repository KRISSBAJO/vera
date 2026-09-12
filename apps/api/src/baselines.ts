import { type BaselineLookup, localParts, magnitudeOf, type ScopeStats } from '@vera/baseline-engine';
import { newId, schema, type Tx } from '@vera/db';
import { and, eq, inArray, sql } from 'drizzle-orm';

const {
  baselineObservations,
  baselineSnapshots,
  baselineStats,
  decisions,
  actionRequests,
  reviews,
  outcomes,
  organizations,
} = schema;

/** How long a rollup generation is reused before the next outcome triggers a rebuild. */
export const SNAPSHOT_MAX_AGE_MS = 10 * 60 * 1000;
/** Observations older than this do not shape the baseline: an org's habits from last spring are not today's. */
const WINDOW_DAYS = 90;
/** Unit separator. NOT NUL: Postgres text cannot hold 0x00, and a key built with one is rejected. */
const SEP = '\u001f';

// ---------- recording (SR-20) ----------

/**
 * Record an observation for a decision whose action actually happened and stuck.
 *
 * Qualifies only when: the verdict was ALLOW or an approved REVIEW, the outcome is `executed`, and no
 * revert or incident has been reported. Attempted, blocked, rejected, and reverted actions never train
 * the baseline — otherwise an attacker could teach VERA that their behaviour is normal simply by
 * trying it often enough (threat T09).
 */
export async function recordObservation(tx: Tx, orgId: string, decisionId: string): Promise<boolean> {
  const [row] = await tx
    .select({
      decision: decisions.decision,
      actionHash: decisions.actionHash,
      createdAt: decisions.createdAt,
      action: actionRequests.action,
      actor: actionRequests.actor,
      target: actionRequests.target,
      reviewStatus: reviews.status,
      timezone: organizations.timezone,
    })
    .from(decisions)
    .innerJoin(actionRequests, eq(actionRequests.id, decisions.actionRequestId))
    .innerJoin(organizations, eq(organizations.id, decisions.orgId))
    .leftJoin(reviews, eq(reviews.decisionId, decisions.id))
    .where(and(eq(decisions.orgId, orgId), eq(decisions.id, decisionId)))
    .limit(1);
  if (!row) return false;

  const allowed = row.decision === 'ALLOW' || (row.decision === 'REVIEW' && row.reviewStatus === 'approved');
  if (!allowed) return false;

  const kinds = await tx
    .select({ kind: outcomes.kind })
    .from(outcomes)
    .where(and(eq(outcomes.orgId, orgId), eq(outcomes.decisionId, decisionId)));
  const seen = new Set(kinds.map((k) => k.kind));
  if (!seen.has('executed')) return false;
  if (seen.has('reverted') || seen.has('incident') || seen.has('hash_mismatch')) return false;

  const action = row.action as { class: string; arguments: Record<string, unknown> };
  const actor = row.actor as { id: string };
  const target = row.target as { id?: string } | null;
  const occurredAt = row.createdAt;
  const { hour, dow } = localParts(occurredAt, row.timezone);

  await tx
    .insert(baselineObservations)
    .values({
      id: newId('obs'),
      orgId,
      decisionId,
      actorId: actor.id,
      actionClass: action.class,
      targetId: target?.id ?? '-',
      occurredAt,
      localHour: hour,
      localDow: dow,
      magnitude: magnitudeOf(action.arguments ?? {}),
    })
    .onConflictDoNothing();
  return true;
}

/**
 * A later revert, incident, or hash mismatch retracts the observation: what was undone, or what turned
 * out not to be what was decided, is not how this organisation behaves. Returns whether anything was
 * actually removed, so the caller knows to rebuild.
 */
export async function retractObservation(tx: Tx, orgId: string, decisionId: string): Promise<boolean> {
  const removed = await tx
    .delete(baselineObservations)
    .where(and(eq(baselineObservations.orgId, orgId), eq(baselineObservations.decisionId, decisionId)))
    .returning({ id: baselineObservations.id });
  return removed.length > 0;
}

// ---------- rollups ----------

/** 24 `count(*) FILTER (WHERE local_hour = h)` columns; explicit beats clever here, and it is one pass. */
const hourColumns = sql.raw(
  Array.from({ length: 24 }, (_, h) => `count(*) FILTER (WHERE local_hour = ${h})::int AS h${h}`).join(', '),
);

interface RollupRow {
  actor_id: string;
  action_class: string;
  target_id: string;
  count: number;
  first_seen: string;
  last_seen: string;
  distinct_targets: number;
  magnitude_n: number;
  magnitude_p50: number | null;
  magnitude_p95: number | null;
  magnitude_max: number | null;
  [hour: string]: unknown;
}

/**
 * Materialise a new rollup generation for the tenant. Decisions reference the snapshot id, so the
 * numbers behind a reason code can always be re-read exactly as they were (A10, A11) — and `/decide`
 * only ever reads, never computes.
 *
 * `percentile_disc` is nearest-rank, matching `percentile()` in the engine; interpolation would make
 * the SQL and the TypeScript disagree about the same data.
 */
export async function rebuildSnapshot(tx: Tx, orgId: string): Promise<{ id: string; observations: number }> {
  const snapshotId = newId('bs');
  // Group on real columns and build the composite key in TypeScript. Concatenating with a bound
  // separator makes the SELECT and GROUP BY expressions carry different placeholders, and Postgres
  // then rejects them as different expressions.
  const scopes = [
    {
      scope: 'actor_class_target' as const,
      cols: sql.raw('actor_id, action_class, target_id'),
      key: (r: RollupRow) => [r.actor_id, r.action_class, r.target_id].join(SEP),
    },
    {
      scope: 'actor_class' as const,
      cols: sql.raw('actor_id, action_class'),
      key: (r: RollupRow) => [r.actor_id, r.action_class].join(SEP),
    },
    { scope: 'org_class' as const, cols: sql.raw('action_class'), key: (r: RollupRow) => r.action_class },
  ];

  await tx
    .insert(baselineSnapshots)
    .values({ id: snapshotId, orgId, computedAt: new Date(), observationCount: 0 });

  let total = 0;
  for (const { scope, cols, key } of scopes) {
    const rows = await tx.execute<RollupRow>(sql`
      SELECT ${cols},
             count(*)::int AS count,
             min(occurred_at) AS first_seen,
             max(occurred_at) AS last_seen,
             count(DISTINCT target_id)::int AS distinct_targets,
             count(magnitude)::int AS magnitude_n,
             percentile_disc(0.5) WITHIN GROUP (ORDER BY magnitude) AS magnitude_p50,
             percentile_disc(0.95) WITHIN GROUP (ORDER BY magnitude) AS magnitude_p95,
             max(magnitude) AS magnitude_max,
             ${hourColumns}
      FROM baseline_observations
      WHERE org_id = ${orgId} AND occurred_at > now() - ${`${WINDOW_DAYS} days`}::interval
      GROUP BY ${cols}
    `);
    const values = [...rows].map((r) => ({
      orgId,
      snapshotId,
      scope,
      key: key(r),
      count: r.count,
      firstSeen: new Date(r.first_seen),
      lastSeen: new Date(r.last_seen),
      hourHistogram: Array.from({ length: 24 }, (_, h) => Number(r[`h${h}`] ?? 0)),
      distinctTargets: r.distinct_targets,
      magnitudeN: r.magnitude_n,
      magnitudeP50: r.magnitude_p50,
      magnitudeP95: r.magnitude_p95,
      magnitudeMax: r.magnitude_max,
    }));
    if (values.length > 0) await tx.insert(baselineStats).values(values);
    if (scope === 'org_class') total = values.reduce((s, v) => s + v.count, 0);
  }

  await tx
    .update(baselineSnapshots)
    .set({ observationCount: total })
    .where(eq(baselineSnapshots.id, snapshotId));
  return { id: snapshotId, observations: total };
}

/** Rebuild only when the newest generation has gone stale. Called off the decision path, after an outcome. */
export async function rebuildSnapshotIfStale(
  tx: Tx,
  orgId: string,
  maxAgeMs = SNAPSHOT_MAX_AGE_MS,
): Promise<string | null> {
  const [latest] = await tx
    .select({ id: baselineSnapshots.id, computedAt: baselineSnapshots.computedAt })
    .from(baselineSnapshots)
    .where(eq(baselineSnapshots.orgId, orgId))
    .orderBy(sql`${baselineSnapshots.computedAt} DESC`)
    .limit(1);
  if (latest && Date.now() - latest.computedAt.getTime() < maxAgeMs) return null;
  const { id } = await rebuildSnapshot(tx, orgId);
  return id;
}

// ---------- lookup ----------

const toStats = (r: typeof baselineStats.$inferSelect): ScopeStats => ({
  count: r.count,
  firstSeen: r.firstSeen,
  lastSeen: r.lastSeen,
  hourHistogram: r.hourHistogram,
  distinctTargets: r.distinctTargets,
  magnitudeN: r.magnitudeN,
  magnitudeP50: r.magnitudeP50,
  magnitudeP95: r.magnitudeP95,
  magnitudeMax: r.magnitudeMax,
});

/**
 * Read the three scopes for one action from the newest snapshot, plus live recent counts for burst
 * detection (a snapshot is too coarse to see the last hour).
 */
export async function lookupBaselines(
  tx: Tx,
  orgId: string,
  actor: { id: string },
  actionClass: string,
  targetId: string,
): Promise<BaselineLookup> {
  const [latest] = await tx
    .select({ id: baselineSnapshots.id })
    .from(baselineSnapshots)
    .where(eq(baselineSnapshots.orgId, orgId))
    .orderBy(sql`${baselineSnapshots.computedAt} DESC`)
    .limit(1);

  const recentRows = await tx.execute<{ last_hour: number; last_24h: number }>(sql`
    SELECT count(*) FILTER (WHERE occurred_at > now() - interval '1 hour')::int AS last_hour,
           count(*) FILTER (WHERE occurred_at > now() - interval '24 hours')::int AS last_24h
    FROM baseline_observations
    WHERE org_id = ${orgId} AND actor_id = ${actor.id}
  `);
  const recentRow = [...recentRows][0];
  const recent = { lastHour: Number(recentRow?.last_hour ?? 0), last24h: Number(recentRow?.last_24h ?? 0) };

  if (!latest) return { snapshotId: null, recent };

  const keys = [
    `${actor.id}${SEP}${actionClass}${SEP}${targetId}`,
    `${actor.id}${SEP}${actionClass}`,
    actionClass,
  ];
  const rows = await tx
    .select()
    .from(baselineStats)
    .where(and(eq(baselineStats.snapshotId, latest.id), inArray(baselineStats.key, keys)));

  const byScope = new Map(rows.map((r) => [r.scope, r]));
  const pick = (scope: 'actor_class_target' | 'actor_class' | 'org_class', key: string) => {
    const r = byScope.get(scope);
    return r && r.key === key ? toStats(r) : undefined;
  };
  return {
    snapshotId: latest.id,
    actorClassTarget: pick('actor_class_target', keys[0] as string),
    actorClass: pick('actor_class', keys[1] as string),
    orgClass: pick('org_class', keys[2] as string),
    recent,
  };
}
