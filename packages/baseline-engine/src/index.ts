import type { ReasonCodeEntry } from '@vera/schemas';

/**
 * Baselines (brief §7.2, gap A). Deterministic statistics over what this organisation has actually
 * done — no ML, no opaque score. Every code carries the numbers that produced it, so a reviewer can
 * disagree with the arithmetic rather than with a black box.
 *
 * Three invariants, all load-bearing:
 *   1. Baselines only ADD severity. They never clear a prerequisite, satisfy a policy, or lower a
 *      verdict (SR-20). The worst a wrong baseline can do is cost an approval.
 *   2. With too little history the engine says INSUFFICIENT_HISTORY and stays quiet, rather than
 *      treating "never seen" as "suspicious" on day one (the cold-start honesty rule).
 *   3. Times are server receive times in the tenant's timezone (SR-06); the adapter's clock is
 *      display-only.
 */

export const SCOPES = ['actor_class_target', 'actor_class', 'org_class'] as const;
export type BaselineScope = (typeof SCOPES)[number];

export interface ScopeStats {
  count: number;
  firstSeen: Date;
  lastSeen: Date;
  /** 24 counts indexed by hour of day in the tenant's timezone. */
  hourHistogram: number[];
  distinctTargets: number;
  magnitudeN: number;
  magnitudeP50: number | null;
  magnitudeP95: number | null;
  magnitudeMax: number | null;
}

export interface BaselineLookup {
  snapshotId: string | null;
  actorClassTarget?: ScopeStats | undefined;
  actorClass?: ScopeStats | undefined;
  orgClass?: ScopeStats | undefined;
  /** Live counts, not from the snapshot: actions by this actor in the last hour and 24 hours. */
  recent: { lastHour: number; last24h: number };
}

export interface BaselineInput {
  /** Hour of day (0–23) in the tenant's timezone, from the server's receive time. */
  localHour: number;
  /** Size of this action, when it has one (amount, row count, file count). */
  magnitude: number | null;
  lookup: BaselineLookup;
  thresholds?: Partial<BaselineThresholds>;
}

export interface BaselineThresholds {
  /** Below this many observations in a scope, that scope's codes are suppressed. */
  minObservations: number;
  /** Hours whose share of the histogram is below this are "outside the usual window". */
  hourTailShare: number;
  /** magnitude > p95 × this ⇒ deviation. */
  magnitudeMultiple: number;
  /** last hour > (24h mean) × this ⇒ spike. */
  spikeMultiple: number;
  /** A spike needs at least this many actions in the last hour, so 1-vs-0 is not a "3× spike". */
  spikeMinCount: number;
}

export const DEFAULT_THRESHOLDS: BaselineThresholds = {
  minObservations: 10,
  hourTailShare: 0.02,
  magnitudeMultiple: 2,
  spikeMultiple: 3,
  spikeMinCount: 5,
};

const round = (n: number, places = 2) => Number(n.toFixed(places));

/** Hours that together hold the central mass of the histogram; the rest are the tails. */
export function usualHours(histogram: number[], tailShare: number): Set<number> {
  const total = histogram.reduce((a, b) => a + b, 0);
  if (total === 0) return new Set();
  const usual = new Set<number>();
  for (let h = 0; h < 24; h += 1) if ((histogram[h] ?? 0) / total > tailShare) usual.add(h);
  return usual;
}

/**
 * Evaluate the baseline codes for one action. Pure: the caller supplies the stats and the clock, so
 * the same inputs always produce the same codes, and a decision can be replayed from its snapshot.
 */
export function evaluateBaselines(input: BaselineInput): ReasonCodeEntry[] {
  const t = { ...DEFAULT_THRESHOLDS, ...input.thresholds };
  const { actorClassTarget, actorClass, orgClass, recent } = input.lookup;
  const codes: ReasonCodeEntry[] = [];

  const orgCount = orgClass?.count ?? 0;
  const actorCount = actorClass?.count ?? 0;

  // Cold start: say so, and stay quiet. "Never seen before" is not evidence of anything when the
  // organisation has barely used VERA.
  if (orgCount < t.minObservations) {
    return [
      {
        code: 'BASELINE.INSUFFICIENT_HISTORY',
        severity: 'info',
        detail: `${orgCount} prior observation(s) of this action class in this org; ${t.minObservations} needed before baselines speak`,
      },
    ];
  }

  // Novelty. Target novelty only counts once the actor has a habit to be novel against.
  if (actorCount === 0) {
    codes.push({
      code: 'BASELINE.ACTOR_ACTION_NOVEL',
      severity: 'medium',
      detail: `first time this actor performs this action class (org history: ${orgCount})`,
    });
  } else if ((actorClassTarget?.count ?? 0) === 0) {
    codes.push({
      code: 'BASELINE.TARGET_NOVEL',
      severity: 'medium',
      detail: `this actor has performed this class ${actorCount}× but never against this target (${actorClassTarget === undefined ? 'no prior' : '0'} prior)`,
    });
  }

  // Time of day, measured against the org's own rhythm for this class.
  if (orgClass && orgCount >= t.minObservations) {
    const usual = usualHours(orgClass.hourHistogram, t.hourTailShare);
    if (usual.size > 0 && !usual.has(input.localHour)) {
      const window = [...usual].sort((a, b) => a - b);
      codes.push({
        code: 'BASELINE.TIME_ANOMALY',
        severity: 'low',
        detail: `${String(input.localHour).padStart(2, '0')}:00 tenant-local; this org runs ${
          orgClass.count
        } of these in hours ${window[0]}–${window.at(-1)}`,
      });
    }
  }

  // Magnitude, against the actor's own distribution for this class.
  const magStats = actorClass && actorClass.magnitudeN >= t.minObservations ? actorClass : undefined;
  if (input.magnitude !== null && magStats?.magnitudeP95 != null) {
    const limit = magStats.magnitudeP95 * t.magnitudeMultiple;
    if (input.magnitude > limit) {
      codes.push({
        code: 'BASELINE.MAGNITUDE_DEVIATION',
        severity: 'medium',
        detail: `${round(input.magnitude)} is ${round(input.magnitude / (magStats.magnitudeP95 || 1), 1)}× this actor's p95 of ${round(magStats.magnitudeP95)} (n=${magStats.magnitudeN}, p50 ${round(magStats.magnitudeP50 ?? 0)})`,
      });
    }
  }

  // Burst detection. Bursts precede both mistakes and attacks, and they are how approval fatigue is
  // manufactured (threat T06).
  const hourlyMean = recent.last24h / 24;
  if (
    recent.lastHour >= t.spikeMinCount &&
    hourlyMean > 0 &&
    recent.lastHour > hourlyMean * t.spikeMultiple
  ) {
    codes.push({
      code: 'BASELINE.FREQUENCY_SPIKE',
      severity: 'medium',
      detail: `${recent.lastHour} actions by this actor in the last hour vs a 24h average of ${round(hourlyMean, 1)}/hour`,
    });
  }

  return codes;
}

/**
 * The magnitude of an action, if it has one. Only declared numeric arguments count, so a random
 * numeric field cannot silently become the thing VERA measures.
 */
export const MAGNITUDE_ARGS = ['amount', 'count'] as const;

export function magnitudeOf(args: Record<string, unknown>): number | null {
  for (const key of MAGNITUDE_ARGS) {
    const v = args[key];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
  }
  return null;
}

/** Hour of day and day of week for a moment, in an IANA timezone. Falls back to UTC on a bad zone. */
export function localParts(at: Date, timeZone: string): { hour: number; dow: number } {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hour: 'numeric',
      hour12: false,
      weekday: 'short',
    }).formatToParts(at);
    const hour = Number(parts.find((p) => p.type === 'hour')?.value ?? '0') % 24;
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const dow = Math.max(0, days.indexOf(parts.find((p) => p.type === 'weekday')?.value ?? 'Sun'));
    return { hour, dow };
  } catch {
    return { hour: at.getUTCHours(), dow: at.getUTCDay() };
  }
}

/** Percentile of a sorted array, nearest-rank. Exported so the worker and tests agree exactly. */
export function percentile(sorted: readonly number[], p: number): number | null {
  if (sorted.length === 0) return null;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))] ?? null;
}
