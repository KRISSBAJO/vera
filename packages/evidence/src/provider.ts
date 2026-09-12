import type { DecideRequest, Evidence } from '@vera/schemas';

/**
 * The Proof engine interface (brief §7.3). A provider fetches or computes facts with VERA's own
 * credentials; everything it returns is `trust: verified`. Providers run under a budget; one that
 * does not answer in time is recorded as missing (EVIDENCE.MISSING) — the decision never waits.
 */
export interface EvidenceProvider {
  readonly name: string;
  applies(request: DecideRequest): boolean;
  provide(request: DecideRequest, signal: AbortSignal): Promise<Evidence[]>;
}

export interface MissingEvidence {
  provider: string;
  reason: string;
}

export interface GatherResult {
  evidence: Evidence[];
  missing: MissingEvidence[];
}

export async function gatherEvidence(
  providers: readonly EvidenceProvider[],
  request: DecideRequest,
  opts: { budgetMs: number },
): Promise<GatherResult> {
  const applicable = providers.filter((p) => p.applies(request));
  const results = await Promise.all(
    applicable.map(async (p): Promise<{ evidence: Evidence[] } | { missing: MissingEvidence }> => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), opts.budgetMs);
      try {
        const evidence = await p.provide(request, controller.signal);
        return { evidence: evidence.map((e) => ({ ...e, trust: 'verified' as const })) };
      } catch (e) {
        const reason = controller.signal.aborted
          ? `timed out after ${opts.budgetMs}ms`
          : e instanceof Error
            ? e.message
            : String(e);
        return { missing: { provider: p.name, reason } };
      } finally {
        clearTimeout(timer);
      }
    }),
  );
  const evidence: Evidence[] = [];
  const missing: MissingEvidence[] = [];
  for (const r of results) {
    if ('evidence' in r) evidence.push(...r.evidence);
    else missing.push(r.missing);
  }
  return { evidence, missing };
}
