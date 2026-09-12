import { schema, type Tx } from '@vera/db';
import { and, eq, gte, sql } from 'drizzle-orm';

const { decisions, reviews, outcomes } = schema;

/**
 * The outcome loop (brief §8, gap B). V1 reports and *recommends*; it never moves a threshold by itself.
 *
 * The product's promise is that the more you run through VERA, the fewer approvals you need — so the
 * numbers that matter are per-rule: how often a rule stopped something a human then waved through, and
 * how long people spent on it. A rule with 40 reviews and 40 unchanged approvals is not protecting
 * anyone; it is manufacturing approval fatigue, and the report says so with the evidence.
 *
 * Every recommendation carries the trust mix of the outcomes behind it (SR-21): a suggestion built on
 * adapter-asserted outcomes is labelled as such, because the agent being governed reported them.
 */

export interface PolicyPrecision {
  policy_id: string;
  reviews: number;
  approved: number;
  rejected: number;
  expired: number;
  pending: number;
  /** approved / (approved + rejected) — the share of interruptions that turned out to be fine. */
  approval_rate: number | null;
  median_seconds_to_decision: number | null;
  outcome_trust: { verified: number; asserted: number };
  recommendation: string | null;
}

export interface PrecisionReport {
  window_days: number;
  generated_at: string;
  totals: {
    decisions: number;
    allow: number;
    review: number;
    block: number;
    review_rate: number;
    allow_reverted: number;
    median_seconds_to_decision: number | null;
  };
  policies: PolicyPrecision[];
  note: string;
}

const median = (xs: number[]): number | null => {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2
    ? (s[mid] as number)
    : Math.round((((s[mid - 1] as number) + (s[mid] as number)) / 2) * 10) / 10;
};

const MIN_FOR_RECOMMENDATION = 20;

export async function policyPrecision(tx: Tx, orgId: string, windowDays: number): Promise<PrecisionReport> {
  const since = new Date(Date.now() - windowDays * 24 * 3600 * 1000);

  const rows = await tx
    .select({
      decisionId: decisions.id,
      decision: decisions.decision,
      reasonCodes: decisions.reasonCodes,
      createdAt: decisions.createdAt,
      reviewStatus: reviews.status,
      resolvedAt: reviews.resolvedAt,
    })
    .from(decisions)
    .leftJoin(reviews, eq(reviews.decisionId, decisions.id))
    .where(and(eq(decisions.orgId, orgId), gte(decisions.createdAt, since)));

  const outcomeRows = await tx
    .select({ decisionId: outcomes.decisionId, kind: outcomes.kind, trust: outcomes.trust })
    .from(outcomes)
    .where(and(eq(outcomes.orgId, orgId), gte(outcomes.createdAt, since)));

  const outcomesByDecision = new Map<string, { kind: string; trust: string }[]>();
  for (const o of outcomeRows) {
    const list = outcomesByDecision.get(o.decisionId) ?? [];
    list.push({ kind: o.kind, trust: o.trust });
    outcomesByDecision.set(o.decisionId, list);
  }

  interface Acc {
    reviews: number;
    approved: number;
    rejected: number;
    expired: number;
    pending: number;
    seconds: number[];
    verified: number;
    asserted: number;
  }
  const byPolicy = new Map<string, Acc>();
  const acc = (id: string): Acc => {
    let a = byPolicy.get(id);
    if (!a) {
      a = {
        reviews: 0,
        approved: 0,
        rejected: 0,
        expired: 0,
        pending: 0,
        seconds: [],
        verified: 0,
        asserted: 0,
      };
      byPolicy.set(id, a);
    }
    return a;
  };

  const totals = { decisions: 0, allow: 0, review: 0, block: 0, allow_reverted: 0 };
  const allSeconds: number[] = [];

  for (const r of rows) {
    totals.decisions += 1;
    if (r.decision === 'ALLOW') {
      totals.allow += 1;
      if ((outcomesByDecision.get(r.decisionId) ?? []).some((o) => o.kind === 'reverted'))
        totals.allow_reverted += 1;
      continue;
    }
    if (r.decision === 'BLOCK') {
      totals.block += 1;
      continue;
    }
    totals.review += 1;

    const seconds = r.resolvedAt
      ? Math.max(0, Math.round((r.resolvedAt.getTime() - r.createdAt.getTime()) / 1000))
      : null;
    if (seconds !== null) allSeconds.push(seconds);

    const codes = (r.reasonCodes as { code: string; policy_id?: string }[]) ?? [];
    const policyIds = [
      ...new Set(
        codes
          .filter((c) => c.code === 'POLICY.REQUIRE_REVIEW' && c.policy_id)
          .map((c) => c.policy_id as string),
      ),
    ];
    // A REVIEW with no policy behind it was raised by severity aggregation; attribute it honestly.
    const attributed = policyIds.length > 0 ? policyIds : ['(severity aggregation)'];
    const trust = outcomesByDecision.get(r.decisionId) ?? [];

    for (const id of attributed) {
      const a = acc(id);
      a.reviews += 1;
      if (r.reviewStatus === 'approved') a.approved += 1;
      else if (r.reviewStatus === 'rejected') a.rejected += 1;
      else if (r.reviewStatus === 'expired') a.expired += 1;
      else a.pending += 1;
      if (seconds !== null) a.seconds.push(seconds);
      for (const o of trust) {
        if (o.trust === 'verified') a.verified += 1;
        else a.asserted += 1;
      }
    }
  }

  const policies: PolicyPrecision[] = [...byPolicy.entries()]
    .map(([policy_id, a]) => {
      const decided = a.approved + a.rejected;
      const approval_rate = decided > 0 ? Math.round((a.approved / decided) * 100) / 100 : null;
      let recommendation: string | null = null;
      if (a.reviews >= MIN_FOR_RECOMMENDATION && a.rejected === 0 && approval_rate === 1) {
        const basis =
          a.verified > 0
            ? `${a.verified} verified and ${a.asserted} asserted outcome(s)`
            : `${a.asserted} asserted outcome(s) only`;
        recommendation =
          `${a.reviews} reviews, all approved, none rejected (median ${median(a.seconds) ?? '?'}s of reviewer time). ` +
          `Consider narrowing "${policy_id}" — for example requiring review only when verified evidence is missing — and add a test for the case you still want held. ` +
          `Basis: ${basis}; activate as a new policy-set version after review.`;
      } else if (a.reviews >= MIN_FOR_RECOMMENDATION && approval_rate !== null && approval_rate < 0.5) {
        recommendation = `${a.reviews} reviews, only ${Math.round(approval_rate * 100)}% approved. This rule is catching real problems — consider making it a forbid so the agent stops asking.`;
      }
      return {
        policy_id,
        reviews: a.reviews,
        approved: a.approved,
        rejected: a.rejected,
        expired: a.expired,
        pending: a.pending,
        approval_rate,
        median_seconds_to_decision: median(a.seconds),
        outcome_trust: { verified: a.verified, asserted: a.asserted },
        recommendation,
      };
    })
    .sort((x, y) => y.reviews - x.reviews);

  return {
    window_days: windowDays,
    generated_at: new Date().toISOString(),
    totals: {
      ...totals,
      review_rate: totals.decisions > 0 ? Math.round((totals.review / totals.decisions) * 1000) / 1000 : 0,
      median_seconds_to_decision: median(allSeconds),
    },
    policies,
    note: 'Recommendations are never applied automatically. Activate a new policy-set version to change behaviour (brief §8).',
  };
}

/** Raw counts behind the BASELINE.* codes, so a reviewer can check VERA's arithmetic (brief §6.4). */
export async function baselineExplain(
  tx: Tx,
  orgId: string,
  actorId: string | undefined,
  actionClass: string | undefined,
) {
  const filters = [sql`org_id = ${orgId}`];
  if (actorId) filters.push(sql`actor_id = ${actorId}`);
  if (actionClass) filters.push(sql`action_class = ${actionClass}`);
  const where = sql.join(filters, sql` AND `);
  const rows = await tx.execute<{
    actor_id: string;
    action_class: string;
    observations: number;
    distinct_targets: number;
    first_seen: string;
    last_seen: string;
    magnitude_p50: number | null;
    magnitude_p95: number | null;
  }>(sql`
    SELECT actor_id, action_class,
           count(*)::int AS observations,
           count(DISTINCT target_id)::int AS distinct_targets,
           min(occurred_at) AS first_seen,
           max(occurred_at) AS last_seen,
           percentile_disc(0.5) WITHIN GROUP (ORDER BY magnitude) AS magnitude_p50,
           percentile_disc(0.95) WITHIN GROUP (ORDER BY magnitude) AS magnitude_p95
    FROM baseline_observations
    WHERE ${where}
    GROUP BY actor_id, action_class
    ORDER BY observations DESC
    LIMIT 200
  `);
  return [...rows].map((r) => ({
    actor_id: r.actor_id,
    action_class: r.action_class,
    observations: Number(r.observations),
    distinct_targets: Number(r.distinct_targets),
    first_seen: new Date(r.first_seen).toISOString(),
    last_seen: new Date(r.last_seen).toISOString(),
    magnitude_p50: r.magnitude_p50,
    magnitude_p95: r.magnitude_p95,
  }));
}
