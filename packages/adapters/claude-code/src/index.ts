import { actionHash } from '@vera/canon';
import { verifyDecisionToken } from '@vera/decision-token';
import { type DecideRequest, isConsequential } from '@vera/schemas';
import { type Classified, classify, type GitFacts } from './classify.js';
import { type DecisionStatus, type VeraClient, VeraRejected, VeraUnreachable } from './client.js';
import type { AdapterConfig } from './config.js';
import {
  type PostToolUseInput,
  type PostToolUseOutput,
  type PreToolUseInput,
  type PreToolUseOutput,
  preOutput,
} from './hook-types.js';

export * from './classify.js';
export * from './client.js';
export * from './config.js';
export * from './hook-types.js';

/** What `pre` remembers for `post`: enough to recompute the hash and report the outcome. */
export interface HookState {
  decision_id: string;
  action_hash: string;
  decision: 'ALLOW' | 'REVIEW' | 'BLOCK' | 'DEGRADED';
  class: string;
  answered: 'allow' | 'deny' | 'ask' | 'defer';
}

export interface StateStore {
  save(toolUseId: string, state: HookState): Promise<void>;
  load(toolUseId: string): Promise<HookState | undefined>;
}

export interface DegradedEvent {
  at: string;
  tool_use_id: string;
  class: string;
  action_hash: string;
  answered: 'allow' | 'ask';
  reason: string;
}

export interface HookDeps {
  client: VeraClient;
  state: StateStore;
  git: (cwd: string) => GitFacts | undefined;
  /** Degraded-mode events are queued locally until an endpoint exists to report them (ADR-0002). */
  queueDegraded: (event: DegradedEvent) => Promise<void>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  log: (line: string) => void;
}

export function buildRequest(input: PreToolUseInput, c: Classified, cfg: AdapterConfig): DecideRequest {
  return {
    request_id: input.tool_use_id,
    idempotency_key: `claude-code:${input.session_id}:${input.tool_use_id}`,
    actor: { type: 'ai_agent', id: 'claude-code', runtime: 'claude-code', session_id: input.session_id },
    ...(cfg.actingFor
      ? { acting_for: { type: 'user' as const, id: cfg.actingFor, trust: 'asserted' as const } }
      : {}),
    action: {
      type: 'tool_call',
      tool: input.tool_name,
      class: c.class,
      arguments: c.arguments,
      environment: c.environment,
      hints: c.hints,
    },
    target: c.target,
    context: { cwd: input.cwd, ...c.context },
  };
}

export function hashOf(c: Classified, tool: string): string {
  return actionHash({
    class: c.class,
    tool,
    arguments: c.arguments,
    target: { kind: c.target.kind, id: c.target.id },
    environment: c.environment,
  });
}

const codesLine = (r: { reason_codes: { code: string; policy_id?: string | undefined }[] }) =>
  r.reason_codes
    .filter((c) => !c.code.startsWith('BASELINE.INSUFFICIENT') && !c.code.startsWith('IDENTITY.'))
    .map((c) => (c.policy_id ? `${c.code}(${c.policy_id})` : c.code))
    .join(', ');

/**
 * PreToolUse (ADR-0002). Every path answers; nothing here may throw to the CLI, because a crashed hook
 * fails open in Claude Code. Order: classify → decide → ALLOW (verify token) / BLOCK / REVIEW (hold).
 */
export async function runPre(
  input: PreToolUseInput,
  cfg: AdapterConfig,
  deps: HookDeps,
): Promise<PreToolUseOutput> {
  const c = classify(input.tool_name, input.tool_input, {
    cwd: input.cwd,
    environment: cfg.environment,
    git: deps.git(input.cwd),
  });
  const hash = hashOf(c, input.tool_name);
  const request = buildRequest(input, c, cfg);
  const remember = (decision: HookState['decision'], answered: HookState['answered'], decisionId = '-') =>
    deps.state.save(input.tool_use_id, {
      decision_id: decisionId,
      action_hash: hash,
      decision,
      class: c.class,
      answered,
    });

  let res: Awaited<ReturnType<VeraClient['decide']>>;
  try {
    res = await deps.client.decide(request);
  } catch (e) {
    if (e instanceof VeraRejected) {
      await remember('BLOCK', 'deny');
      return preOutput(
        'deny',
        `VERA refused the request: ${e.code}${e.message && e.message !== e.code ? ` — ${e.message}` : ''}`,
      );
    }
    // Unreachable: signed safe-default table (SR-08). Read-only → allow and queue; consequential → ask.
    const reason = e instanceof VeraUnreachable ? e.message : String(e);
    const answered = isConsequential(c.class) ? 'ask' : 'allow';
    await deps.queueDegraded({
      at: new Date(deps.now()).toISOString(),
      tool_use_id: input.tool_use_id,
      class: c.class,
      action_hash: hash,
      answered,
      reason,
    });
    await remember('DEGRADED', answered);
    return answered === 'allow'
      ? preOutput(
          'allow',
          `VERA unreachable (${reason}); ${c.class} is read-only — allowed in degraded mode (SYSTEM.DEGRADED_MODE)`,
        )
      : preOutput(
          'ask',
          `VERA unreachable (${reason}); ${c.class} is consequential — a human must decide (fail closed)`,
          `VERA is unreachable. This ${c.class} action was not decided by VERA.`,
        );
  }

  if (res.action_hash !== hash) {
    await remember('BLOCK', 'deny', res.decision_id);
    return preOutput(
      'deny',
      `VERA's action hash differs from the adapter's (canonicalization mismatch) — refusing (TOKEN.HASH_MISMATCH)`,
    );
  }

  if (res.decision === 'BLOCK') {
    await remember('BLOCK', 'deny', res.decision_id);
    return preOutput('deny', `VERA BLOCK ${res.decision_id}: ${codesLine(res)}`);
  }

  if (res.decision === 'ALLOW') {
    const ok = await verifyToken(deps, cfg, res.decision_token, hash);
    if (!ok.ok) {
      await remember('BLOCK', 'deny', res.decision_id);
      return preOutput(
        'deny',
        `VERA ALLOW ${res.decision_id} but the token did not verify (${ok.code}) — refusing`,
      );
    }
    await remember('ALLOW', 'allow', res.decision_id);
    return preOutput(
      'allow',
      `VERA ALLOW ${res.decision_id} (${res.policy_set_version})${codesLine(res) ? ` — ${codesLine(res)}` : ''}`,
    );
  }

  // REVIEW: hold while a human decides, polling GET /v1/decisions/:id.
  deps.log(
    `VERA REVIEW ${res.decision_id}: ${codesLine(res)}\n  waiting for approval: ${res.review?.url ?? ''}`,
  );
  const deadline = deps.now() + cfg.holdSeconds * 1000;
  let last: DecisionStatus | undefined;
  while (deps.now() < deadline) {
    try {
      last = await deps.client.getDecision(res.decision_id);
    } catch (e) {
      if (e instanceof VeraRejected) break;
      // transient: keep polling until the deadline
    }
    if (last?.review_status === 'approved' && last.decision_token) {
      const ok = await verifyToken(deps, cfg, last.decision_token, hash);
      if (!ok.ok) {
        await remember('BLOCK', 'deny', res.decision_id);
        return preOutput('deny', `approved, but the token did not verify (${ok.code}) — refusing`);
      }
      await remember('REVIEW', 'allow', res.decision_id);
      return preOutput('allow', `VERA REVIEW ${res.decision_id} approved — token verified`);
    }
    if (last?.review_status === 'rejected') {
      await remember('REVIEW', 'deny', res.decision_id);
      return preOutput('deny', `VERA REVIEW ${res.decision_id} rejected by a reviewer`);
    }
    if (last?.review_status === 'expired') break;
    await deps.sleep(cfg.pollIntervalMs);
  }
  await remember('REVIEW', cfg.onHoldExpiry, res.decision_id);
  return preOutput(
    cfg.onHoldExpiry,
    `VERA REVIEW ${res.decision_id} not resolved within ${cfg.holdSeconds}s (SYSTEM.HOLD_EXPIRED); no token issued`,
    `VERA review ${res.decision_id} is still pending: ${res.review?.url ?? ''}. Whatever you decide here is recorded as a keyboard decision, not a VERA one.`,
  );
}

async function verifyToken(deps: HookDeps, cfg: AdapterConfig, token: string | null, hash: string) {
  if (!token) return { ok: false as const, code: 'TOKEN.MALFORMED' };
  let jwks: Awaited<ReturnType<VeraClient['jwks']>>;
  try {
    jwks = await deps.client.jwks();
  } catch (e) {
    return { ok: false as const, code: `JWKS_UNAVAILABLE (${e instanceof Error ? e.message : e})` };
  }
  const v = await verifyDecisionToken(token, jwks, {
    tenant: cfg.org,
    aud: cfg.aud,
    action_hash: hash,
    now: new Date(deps.now()),
  });
  return v.ok ? { ok: true as const } : { ok: false as const, code: v.code };
}

/**
 * PostToolUse: recompute the hash from the executed tool_input; a mismatch is reported as a bypass
 * attempt (T02). Outcomes are asserted (SR-21). Never blocks, never throws.
 */
export async function runPost(
  input: PostToolUseInput,
  cfg: AdapterConfig,
  deps: HookDeps,
): Promise<PostToolUseOutput> {
  const state = await deps.state.load(input.tool_use_id);
  if (!state || state.decision_id === '-') return {};
  const c = classify(input.tool_name, input.tool_input, {
    cwd: input.cwd,
    environment: cfg.environment,
    git: deps.git(input.cwd),
  });
  const hash = hashOf(c, input.tool_name);
  const failed = looksFailed(input.tool_response ?? input.tool_output);
  try {
    if (hash !== state.action_hash)
      await deps.client.outcome(state.decision_id, 'hash_mismatch', {
        decided: state.action_hash,
        executed: hash,
      });
    else if (state.answered === 'allow')
      await deps.client.outcome(state.decision_id, failed ? 'failed' : 'executed', { tool: input.tool_name });
  } catch {
    // best effort; the API's own audit already has the decision
  }
  return {};
}

function looksFailed(response: unknown): boolean {
  if (response && typeof response === 'object') {
    const r = response as Record<string, unknown>;
    if (r.is_error === true || r.error) return true;
    if (typeof r.exit_code === 'number' && r.exit_code !== 0) return true;
  }
  return false;
}
