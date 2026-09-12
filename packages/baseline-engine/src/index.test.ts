import { describe, expect, it } from 'vitest';
import {
  DEFAULT_THRESHOLDS,
  evaluateBaselines,
  localParts,
  magnitudeOf,
  percentile,
  type ScopeStats,
  usualHours,
} from './index.js';

const stats = (over: Partial<ScopeStats> = {}): ScopeStats => ({
  count: 100,
  firstSeen: new Date('2026-06-01T00:00:00Z'),
  lastSeen: new Date('2026-09-10T00:00:00Z'),
  // Office hours 9–18.
  hourHistogram: Array.from({ length: 24 }, (_, h) => (h >= 9 && h <= 18 ? 10 : 0)),
  distinctTargets: 4,
  magnitudeN: 0,
  magnitudeP50: null,
  magnitudeP95: null,
  magnitudeMax: null,
  ...over,
});

const evaluate = (over: Partial<Parameters<typeof evaluateBaselines>[0]> = {}) =>
  evaluateBaselines({
    localHour: 14,
    magnitude: null,
    lookup: {
      snapshotId: 'bs_1',
      orgClass: stats(),
      actorClass: stats({ count: 40 }),
      actorClassTarget: stats({ count: 12 }),
      recent: { lastHour: 1, last24h: 12 },
    },
    ...over,
  });

const codes = (r: ReturnType<typeof evaluateBaselines>) => r.map((c) => c.code);

describe('cold start is stated, not guessed', () => {
  it('says INSUFFICIENT_HISTORY and nothing else below the minimum', () => {
    const r = evaluate({
      lookup: { snapshotId: null, orgClass: stats({ count: 3 }), recent: { lastHour: 0, last24h: 0 } },
      localHour: 3,
      magnitude: 999999,
    });
    expect(codes(r)).toEqual(['BASELINE.INSUFFICIENT_HISTORY']);
    expect(r[0]?.severity).toBe('info');
    expect(r[0]?.detail).toContain('3 prior observation');
  });

  it('an org with no history at all is silent too', () => {
    const r = evaluate({ lookup: { snapshotId: null, recent: { lastHour: 0, last24h: 0 } } });
    expect(codes(r)).toEqual(['BASELINE.INSUFFICIENT_HISTORY']);
  });

  it('SR-20: baselines only ever emit info/low/medium — never a high that could carry a verdict alone', () => {
    const everything = evaluate({
      localHour: 3,
      magnitude: 10_000,
      lookup: {
        snapshotId: 'bs_1',
        orgClass: stats(),
        actorClass: stats({ count: 0, magnitudeN: 20, magnitudeP50: 10, magnitudeP95: 100 }),
        recent: { lastHour: 30, last24h: 40 },
      },
    });
    expect(everything.every((c) => c.severity !== 'high')).toBe(true);
    expect(everything.length).toBeGreaterThan(2);
  });
});

describe('novelty', () => {
  it('flags an actor doing this class for the first time', () => {
    const r = evaluate({
      lookup: {
        snapshotId: 'bs_1',
        orgClass: stats(),
        actorClass: stats({ count: 0 }),
        recent: { lastHour: 0, last24h: 0 },
      },
    });
    expect(codes(r)).toContain('BASELINE.ACTOR_ACTION_NOVEL');
    expect(r.find((c) => c.code === 'BASELINE.ACTOR_ACTION_NOVEL')?.detail).toContain('org history: 100');
  });

  it('flags a new target once the actor has a habit, and does not double-report with actor novelty', () => {
    const r = evaluate({
      lookup: {
        snapshotId: 'bs_1',
        orgClass: stats(),
        actorClass: stats({ count: 40 }),
        actorClassTarget: stats({ count: 0 }),
        recent: { lastHour: 0, last24h: 0 },
      },
    });
    expect(codes(r)).toContain('BASELINE.TARGET_NOVEL');
    expect(codes(r)).not.toContain('BASELINE.ACTOR_ACTION_NOVEL');
  });

  it('says nothing when both the actor and the target are familiar', () => {
    expect(codes(evaluate())).toEqual([]);
  });
});

describe('time of day', () => {
  it('flags 02:00 against an office-hours org and names the window', () => {
    const r = evaluate({ localHour: 2 });
    const c = r.find((x) => x.code === 'BASELINE.TIME_ANOMALY');
    expect(c?.severity).toBe('low');
    expect(c?.detail).toContain('02:00 tenant-local');
    expect(c?.detail).toContain('hours 9–18');
  });

  it('does not flag an hour inside the window', () => {
    expect(codes(evaluate({ localHour: 10 }))).not.toContain('BASELINE.TIME_ANOMALY');
  });

  it('says nothing about time for a round-the-clock org', () => {
    const flat = stats({ hourHistogram: Array.from({ length: 24 }, () => 10) });
    expect(
      codes(
        evaluate({
          localHour: 3,
          lookup: {
            snapshotId: 'bs_1',
            orgClass: flat,
            actorClass: stats({ count: 40 }),
            actorClassTarget: stats({ count: 5 }),
            recent: { lastHour: 0, last24h: 0 },
          },
        }),
      ),
    ).not.toContain('BASELINE.TIME_ANOMALY');
  });

  it('usualHours drops the thin tails only', () => {
    const h = Array.from({ length: 24 }, (_, i) => (i === 3 ? 1 : i >= 9 && i <= 17 ? 100 : 0));
    const usual = usualHours(h, 0.02);
    expect(usual.has(3)).toBe(false);
    expect(usual.has(12)).toBe(true);
  });
});

describe('magnitude', () => {
  const withMag = (magnitudeN: number) => ({
    snapshotId: 'bs_1',
    orgClass: stats(),
    actorClass: stats({ count: 40, magnitudeN, magnitudeP50: 100, magnitudeP95: 500 }),
    actorClassTarget: stats({ count: 12 }),
    recent: { lastHour: 0, last24h: 0 },
  });

  it('flags an amount far above the actor p95 and shows the arithmetic', () => {
    const c = evaluate({ magnitude: 4800, lookup: withMag(20) }).find(
      (x) => x.code === 'BASELINE.MAGNITUDE_DEVIATION',
    );
    expect(c?.detail).toBe("4800 is 9.6× this actor's p95 of 500 (n=20, p50 100)");
  });

  it('does not flag within the multiple, or when there is too little magnitude history', () => {
    expect(codes(evaluate({ magnitude: 900, lookup: withMag(20) }))).not.toContain(
      'BASELINE.MAGNITUDE_DEVIATION',
    );
    expect(codes(evaluate({ magnitude: 999999, lookup: withMag(3) }))).not.toContain(
      'BASELINE.MAGNITUDE_DEVIATION',
    );
  });
});

describe('frequency (threat T06: manufactured approval fatigue)', () => {
  const recent = (lastHour: number, last24h: number) => ({
    snapshotId: 'bs_1',
    orgClass: stats(),
    actorClass: stats({ count: 40 }),
    actorClassTarget: stats({ count: 12 }),
    recent: { lastHour, last24h },
  });

  it('flags a burst against the 24h average', () => {
    const c = evaluate({ lookup: recent(30, 48) }).find((x) => x.code === 'BASELINE.FREQUENCY_SPIKE');
    expect(c?.detail).toBe('30 actions by this actor in the last hour vs a 24h average of 2/hour');
  });

  it('does not call a handful of actions a spike', () => {
    expect(codes(evaluate({ lookup: recent(4, 4) }))).not.toContain('BASELINE.FREQUENCY_SPIKE');
    expect(codes(evaluate({ lookup: recent(1, 0) }))).not.toContain('BASELINE.FREQUENCY_SPIKE');
  });

  it('does not flag steady heavy use', () => {
    expect(codes(evaluate({ lookup: recent(20, 480) }))).not.toContain('BASELINE.FREQUENCY_SPIKE');
  });
});

describe('helpers', () => {
  it('magnitudeOf reads only declared numeric arguments', () => {
    expect(magnitudeOf({ amount: 4800 })).toBe(4800);
    expect(magnitudeOf({ count: 12 })).toBe(12);
    expect(magnitudeOf({ amount: 'lots', rows: 99 })).toBeNull();
    expect(magnitudeOf({})).toBeNull();
  });

  it('localParts projects into the tenant timezone (SR-06)', () => {
    const at = new Date('2026-09-11T06:14:00Z'); // 02:14 in New York
    expect(localParts(at, 'America/New_York')).toEqual({ hour: 2, dow: 5 });
    expect(localParts(at, 'UTC').hour).toBe(6);
    expect(localParts(at, 'Not/AZone').hour).toBe(6);
  });

  it('percentile is nearest-rank and handles the empty case', () => {
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50)).toBe(5);
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95)).toBe(10);
    expect(percentile([], 95)).toBeNull();
  });

  it('the default minimum is the documented 10', () => {
    expect(DEFAULT_THRESHOLDS.minObservations).toBe(10);
  });
});
