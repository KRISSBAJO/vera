import { verifyDecisionToken } from '@vera/decision-token';
import type { DecideResponse } from '@vera/schemas';
import { type DecisionStatus, type VeraClient, VeraRejected } from './client.js';

export * from './client.js';

/**
 * The part of an adapter that is identical in every runtime: ask VERA, verify what comes back, and —
 * when a human is needed — wait for them. Runtime-specific code maps the result onto whatever that
 * runtime understands (a hook decision, a thrown error, an interruption).
 *
 * Adapters verify tokens; they never hold signing material (SR-19). A token that does not verify is
 * refused even when VERA said ALLOW: the signature, not the HTTP response, is the authority.
 */

export interface VerifyContext {
  org: string;
  aud: string;
}

export interface AdapterDeps {
  client: VeraClient;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  log?: (line: string) => void;
}

export type TokenCheck = { ok: true } | { ok: false; code: string };

export async function verifyToken(
  deps: AdapterDeps,
  ctx: VerifyContext,
  token: string | null,
  actionHash: string,
): Promise<TokenCheck> {
  if (!token) return { ok: false, code: 'TOKEN.MALFORMED' };
  let jwks: Awaited<ReturnType<VeraClient['jwks']>>;
  try {
    jwks = await deps.client.jwks();
  } catch (e) {
    return { ok: false, code: `JWKS_UNAVAILABLE (${e instanceof Error ? e.message : e})` };
  }
  const v = await verifyDecisionToken(token, jwks, {
    tenant: ctx.org,
    aud: ctx.aud,
    action_hash: actionHash,
    now: new Date(deps.now()),
  });
  return v.ok ? { ok: true } : { ok: false, code: v.code };
}

export type Resolution =
  /** Proceed: a token was verified against the tenant's JWKS for exactly this action. */
  | { kind: 'allow'; decisionId: string; reason: string }
  /** Do not proceed: policy said no, a reviewer said no, or a token failed to verify. */
  | { kind: 'deny'; decisionId: string | null; reason: string }
  /** VERA could not decide in time; the runtime's own human must. No token was issued. */
  | { kind: 'undecided'; decisionId: string; reason: string };

export interface HoldOptions {
  holdSeconds: number;
  pollIntervalMs: number;
}

const codesLine = (r: Pick<DecideResponse, 'reason_codes'>) =>
  r.reason_codes
    .filter((c) => !c.code.startsWith('BASELINE.INSUFFICIENT') && c.severity !== 'info')
    .map((c) => (c.policy_id ? `${c.code}(${c.policy_id})` : c.code))
    .join(', ');

/**
 * Turn a decide response into a resolution, holding for a human when the verdict is REVIEW.
 *
 * The hold is bounded by the caller's window, which must sit inside whatever timeout the runtime
 * imposes. On expiry the answer is `undecided`, never `allow`: a review nobody answered is not an
 * approval, and the audit trail records that the keyboard decided, not VERA.
 */
export async function resolveDecision(
  res: DecideResponse,
  deps: AdapterDeps,
  ctx: VerifyContext,
  actionHash: string,
  hold: HoldOptions,
): Promise<Resolution> {
  if (res.action_hash !== actionHash) {
    return {
      kind: 'deny',
      decisionId: res.decision_id,
      reason:
        "VERA's action hash differs from this adapter's (canonicalization mismatch) — refusing (TOKEN.HASH_MISMATCH)",
    };
  }

  if (res.decision === 'BLOCK') {
    return {
      kind: 'deny',
      decisionId: res.decision_id,
      reason: `VERA BLOCK ${res.decision_id}: ${codesLine(res)}`,
    };
  }

  if (res.decision === 'ALLOW') {
    const check = await verifyToken(deps, ctx, res.decision_token, actionHash);
    if (!check.ok) {
      return {
        kind: 'deny',
        decisionId: res.decision_id,
        reason: `VERA ALLOW ${res.decision_id} but the token did not verify (${check.code}) — refusing`,
      };
    }
    const codes = codesLine(res);
    return {
      kind: 'allow',
      decisionId: res.decision_id,
      reason: `VERA ALLOW ${res.decision_id} (${res.policy_set_version})${codes ? ` — ${codes}` : ''}`,
    };
  }

  deps.log?.(
    `VERA REVIEW ${res.decision_id}: ${codesLine(res)}\n  waiting for approval: ${res.review?.url ?? ''}`,
  );
  const deadline = deps.now() + hold.holdSeconds * 1000;
  let last: DecisionStatus | undefined;
  while (deps.now() < deadline) {
    try {
      last = await deps.client.getDecision(res.decision_id);
    } catch (e) {
      if (e instanceof VeraRejected) break;
      // transient: keep polling until the deadline
    }
    if (last?.review_status === 'approved' && last.decision_token) {
      const check = await verifyToken(deps, ctx, last.decision_token, actionHash);
      return check.ok
        ? {
            kind: 'allow',
            decisionId: res.decision_id,
            reason: `VERA REVIEW ${res.decision_id} approved — token verified`,
          }
        : {
            kind: 'deny',
            decisionId: res.decision_id,
            reason: `approved, but the token did not verify (${check.code}) — refusing`,
          };
    }
    if (last?.review_status === 'rejected') {
      return {
        kind: 'deny',
        decisionId: res.decision_id,
        reason: `VERA REVIEW ${res.decision_id} rejected by a reviewer`,
      };
    }
    if (last?.review_status === 'expired') break;
    await deps.sleep(hold.pollIntervalMs);
  }
  return {
    kind: 'undecided',
    decisionId: res.decision_id,
    reason: `VERA REVIEW ${res.decision_id} not resolved within ${hold.holdSeconds}s (SYSTEM.HOLD_EXPIRED); no token issued`,
  };
}
