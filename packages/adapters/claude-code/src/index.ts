import {
  BUILT_IN_CONFIG,
  classFromConfig,
  mayFailOpen,
  resolveDecision,
  type SignedConfigStore,
} from '@vera/adapter-core';
import { actionHash } from '@vera/canon';
import { type DecideRequest, isConsequential } from '@vera/schemas';
import { type Classified, classify, type GitFacts } from './classify.js';
import { type VeraClient, VeraRejected, VeraUnreachable } from './client.js';
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

/**
 * One line per decision in ~/.vera/decisions.jsonl. Enough to recognise "the kubectl thing a minute
 * ago" and nothing more: the program name, never its arguments — a journal on the developer's disk
 * must not be a second, unredacted copy of every command an agent tried to run.
 */
export interface JournalEntry {
  at: string;
  decision_id: string;
  verdict: 'ALLOW' | 'REVIEW' | 'BLOCK';
  answered: HookState['answered'];
  class: string;
  tool: string;
  /** e.g. `git`, `kubectl`, `psql` — the first token of a shell command; the tool name otherwise. */
  program: string;
}

/**
 * Shell words that are never the program a human would recognise a command by.
 *
 * Two kinds. A segment that *opens* with one of SKIP_SEGMENT is uninteresting as a whole (`for f in
 * a b` names a variable, not a program; `cd /repo` names a directory; `echo "x"` names its text).
 * SKIP_TOKEN words are prefixes to look past inside a segment (`do cat`, `sudo systemctl`).
 */
const SKIP_SEGMENT = new Set([
  'for', 'while', 'until', 'if', 'elif', 'case', 'select',
  'cd', 'pushd', 'popd', 'export', 'set', 'unset', 'source', '.', 'echo', 'printf', 'test', '[', '[[',
  'true', 'false', 'read', 'local', 'declare', 'typeset', 'let', 'return', 'exit', 'break', 'continue',
]);
const SKIP_TOKEN = new Set([
  'do', 'done', 'then', 'else', 'fi', 'esac', 'in',
  'time', 'sudo', 'doas', 'env', 'nohup', 'exec', 'command', 'builtin', 'eval', 'nice', 'ionice',
  'sh', 'bash', 'zsh', 'dash', '-c',
]);

const clean = (raw: string) => raw.replace(/^[\s"'`]+|[\s"'`]+$/g, '');
const isAssignment = (t: string) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(t);

export function programOf(toolName: string, toolInput: Record<string, unknown>): string {
  const cmd = typeof toolInput.command === 'string' ? toolInput.command.trim() : '';
  if (!cmd) return toolName;
  // A journal entry that says `for` or `f` tells nobody which command it was; `kubectl` does.
  for (const segment of cmd.split(/\s*(?:;|&&|\|\||\||&|\(|\)|\n)\s*/)) {
    const tokens = segment.split(/\s+/).map(clean).filter(Boolean);
    // Leading assignments (`PGPASSWORD=…`) do not decide what kind of segment this is.
    let i = 0;
    while (i < tokens.length && isAssignment(tokens[i] as string)) i += 1;
    const head = tokens[i];
    if (!head || SKIP_SEGMENT.has(head)) continue;
    for (const t of tokens.slice(i)) {
      if (SKIP_TOKEN.has(t) || isAssignment(t) || t.startsWith('-') || t.startsWith('$')) continue;
      if (SKIP_SEGMENT.has(t)) break; // e.g. `sudo cd /x` — nothing to name here
      return t.split('/').at(-1) ?? t;
    }
  }
  return toolName;
}

export interface HookDeps {
  /** Append to the local decision journal. Optional: tests and embedders may not want a file. */
  journal?: (entry: JournalEntry) => Promise<void>;
  client: VeraClient;
  /**
   * The tenant-signed class and fail-mode tables (SR-07). Absent means the adapter falls back to its
   * built-in conservative defaults — which is what happens on a machine that has never reached VERA.
   */
  configStore?: SignedConfigStore;
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
  // The signed table comes first: an operator's classification beats the built-in heuristics, and the
  // heuristics only fill the gaps. Neither can be edited on this machine (threat T19).
  const resolved = (await deps.configStore?.resolve()) ?? {
    config: BUILT_IN_CONFIG,
    source: 'builtin' as const,
  };
  const signedClass = classFromConfig(resolved.config, input.tool_name);
  const c = classify(input.tool_name, input.tool_input, {
    cwd: input.cwd,
    environment: cfg.environment,
    git: deps.git(input.cwd),
    ...(signedClass ? { forcedClass: signedClass } : {}),
  });
  const hash = hashOf(c, input.tool_name);
  const request = buildRequest(input, c, cfg);
  const remember = async (
    decision: HookState['decision'],
    answered: HookState['answered'],
    decisionId = '-',
  ) => {
    await deps.state.save(input.tool_use_id, {
      decision_id: decisionId,
      action_hash: hash,
      decision,
      class: c.class,
      answered,
    });
    // Only decisions VERA actually made are journaled; degraded-mode answers have their own queue.
    if (decisionId !== '-' && decision !== 'DEGRADED' && deps.journal) {
      try {
        await deps.journal({
          at: new Date(deps.now()).toISOString(),
          decision_id: decisionId,
          verdict: decision,
          answered,
          class: c.class,
          tool: input.tool_name,
          program: programOf(input.tool_name, input.tool_input),
        });
      } catch {
        // the journal is a convenience; it must never change a decision
      }
    }
  };

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
    // Unreachable: the signed fail-mode table decides, not this machine's opinion (SR-08, T12).
    // With no verified table, the built-in one applies — read-only classes only.
    const reason = e instanceof VeraUnreachable ? e.message : String(e);
    const answered = mayFailOpen(resolved.config, c.class) ? 'allow' : 'ask';
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
          `VERA unreachable (${reason}); ${c.class} may fail open per the ${resolved.source} table — allowed in degraded mode (SYSTEM.DEGRADED_MODE)`,
        )
      : preOutput(
          'ask',
          `VERA unreachable (${reason}); ${c.class} is consequential — a human must decide (fail closed)`,
          `VERA is unreachable. This ${c.class} action was not decided by VERA.`,
        );
  }

  // Ask, verify, and — on REVIEW — hold for a human. The flow itself lives in @vera/adapter-core so
  // every adapter verifies tokens the same way; only the mapping onto hook decisions is local.
  const resolution = await resolveDecision(
    res,
    { client: deps.client, sleep: deps.sleep, now: deps.now, log: deps.log },
    { org: cfg.org, aud: cfg.aud },
    hash,
    { holdSeconds: cfg.holdSeconds, pollIntervalMs: cfg.pollIntervalMs },
  );

  if (resolution.kind === 'allow') {
    await remember(res.decision === 'ALLOW' ? 'ALLOW' : 'REVIEW', 'allow', res.decision_id);
    return preOutput('allow', resolution.reason);
  }
  if (resolution.kind === 'deny') {
    await remember(res.decision === 'REVIEW' ? 'REVIEW' : 'BLOCK', 'deny', res.decision_id);
    return preOutput('deny', resolution.reason);
  }
  await remember('REVIEW', cfg.onHoldExpiry, res.decision_id);
  return preOutput(
    cfg.onHoldExpiry,
    resolution.reason,
    `VERA review ${res.decision_id} is still pending: ${res.review?.url ?? ''}. Whatever you decide here is recorded as a keyboard decision, not a VERA one.`,
  );
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
