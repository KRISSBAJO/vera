import {
  type AdapterDeps,
  type Resolution,
  resolveDecision,
  VeraClient,
  VeraRejected,
  VeraUnreachable,
} from '@vera/adapter-core';
import { actionHash } from '@vera/canon';
import { type ActionClass, type DecideRequest, isConsequential } from '@vera/schemas';

/**
 * VERA for the OpenAI Agents SDK.
 *
 * Two integration points, and the difference matters:
 *
 *   `protect(tool, spec)` — the enforcing path. VERA decides, the token is verified, and only then does
 *   the tool run. Use this for anything consequential.
 *
 *   `needsApproval(spec)` — a convenience for the SDK's own interruption flow, which asks a boolean
 *   question ("should a human confirm this?"). It answers honestly, but a boolean cannot carry a signed
 *   decision, so on its own it is advisory. Pair it with `protect` when the action matters.
 *
 * The package is structurally typed against the SDK rather than importing it, so it does not pin the
 * agent framework's version — the shape below is all it needs.
 */

/** The shape of an Agents SDK tool that this adapter can wrap. */
export interface ToolLike<Args = Record<string, unknown>, Result = unknown> {
  name: string;
  execute: (args: Args, context?: unknown) => Promise<Result> | Result;
  [key: string]: unknown;
}

export interface GuardConfig {
  endpoint: string;
  apiKey: string;
  /** Tenant id — used for the JWKS path and checked against the token's `tenant` claim. */
  org: string;
  /** Receiver id this adapter verifies tokens for; must match the API key's registered receiver. */
  aud: string;
  /** Identity of the person the agent acts for. VERA records it as asserted (SR-09). */
  actingFor?: string;
  /** Stable id for this agent, recorded as the actor. */
  agentId?: string;
  environment?: string;
  /** How long to wait for a human on REVIEW. Keep it inside the caller's own timeouts. */
  holdSeconds?: number;
  pollIntervalMs?: number;
  requestTimeoutMs?: number;
  fetch?: typeof fetch;
  log?: (line: string) => void;
}

/** What kind of action a tool performs. Everything unmapped is treated as consequential (SR-03). */
export interface ActionSpec<Args = Record<string, unknown>> {
  class: ActionClass;
  target?: (args: Args) => { kind: string; id: string; sensitivity?: 'low' | 'medium' | 'high' };
  environment?: string | ((args: Args) => string | undefined);
  hints?: { destructive?: boolean; idempotent?: boolean; read_only?: boolean };
  /** Narrow what VERA sees and hashes. Default: the whole argument object. */
  arguments?: (args: Args) => Record<string, unknown>;
}

/** VERA refused, or a reviewer did. Nothing ran. */
export class VeraDenied extends Error {
  constructor(
    public readonly decisionId: string | null,
    message: string,
  ) {
    super(message);
    this.name = 'VeraDenied';
  }
}

/** The review was never answered inside the hold window. Nothing ran, and no token was issued. */
export class VeraUndecided extends Error {
  constructor(
    public readonly decisionId: string,
    message: string,
  ) {
    super(message);
    this.name = 'VeraUndecided';
  }
}

export interface VeraGuard {
  protect<A extends Record<string, unknown>, R>(tool: ToolLike<A, R>, spec: ActionSpec<A>): ToolLike<A, R>;
  needsApproval<A extends Record<string, unknown>>(
    toolName: string,
    spec: ActionSpec<A>,
  ): (context: unknown, args: A) => Promise<boolean>;
  /** Ask without executing — for a custom integration that wants the resolution itself. */
  resolve<A extends Record<string, unknown>>(
    toolName: string,
    args: A,
    spec: ActionSpec<A>,
    runId?: string,
  ): Promise<Resolution>;
}

export function createVeraGuard(config: GuardConfig): VeraGuard {
  const client = new VeraClient({
    endpoint: config.endpoint,
    apiKey: config.apiKey,
    org: config.org,
    requestTimeoutMs: config.requestTimeoutMs ?? 2500,
    ...(config.fetch ? { fetch: config.fetch } : {}),
  });
  const deps: AdapterDeps = {
    client,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => Date.now(),
    ...(config.log ? { log: config.log } : {}),
  };
  const ctx = { org: config.org, aud: config.aud };
  const hold = { holdSeconds: config.holdSeconds ?? 300, pollIntervalMs: config.pollIntervalMs ?? 2000 };
  const agentId = config.agentId ?? 'openai-agent';

  function describe<A extends Record<string, unknown>>(toolName: string, args: A, spec: ActionSpec<A>) {
    const argumentsForVera = spec.arguments ? spec.arguments(args) : args;
    const environment =
      (typeof spec.environment === 'function' ? spec.environment(args) : spec.environment) ??
      config.environment ??
      'development';
    const target = spec.target?.(args) ?? { kind: 'tool', id: toolName };
    const hash = actionHash({
      class: spec.class,
      tool: toolName,
      arguments: argumentsForVera,
      target: { kind: target.kind, id: target.id },
      environment,
    });
    return { argumentsForVera, environment, target, hash };
  }

  /**
   * The idempotency key is derived from the action hash, so `needsApproval` and `protect` on the same
   * call resolve to the same decision instead of asking twice — and a retried call with identical
   * arguments reuses the approval rather than interrupting a human again.
   */
  async function decideOnce<A extends Record<string, unknown>>(
    toolName: string,
    args: A,
    spec: ActionSpec<A>,
    runId?: string,
  ) {
    const { argumentsForVera, environment, target, hash } = describe(toolName, args, spec);
    const request: DecideRequest = {
      request_id: `${runId ?? 'run'}:${hash.slice(7, 23)}`,
      idempotency_key: `openai-agents:${runId ?? 'run'}:${hash}`,
      actor: { type: 'ai_agent', id: agentId, runtime: 'openai-agents' },
      ...(config.actingFor
        ? { acting_for: { type: 'user' as const, id: config.actingFor, trust: 'asserted' as const } }
        : {}),
      action: {
        type: 'tool_call',
        tool: toolName,
        class: spec.class,
        arguments: argumentsForVera,
        environment,
        ...(spec.hints ? { hints: spec.hints } : {}),
      },
      target,
    };
    const res = await client.decide(request);
    return { resolution: await resolveDecision(res, deps, ctx, hash, hold), hash };
  }

  return {
    async resolve(toolName, args, spec, runId) {
      return (await decideOnce(toolName, args, spec, runId)).resolution;
    },

    needsApproval(toolName, spec) {
      return async (_context, args) => {
        try {
          const { resolution } = await decideOnce(toolName, args, spec);
          return resolution.kind !== 'allow';
        } catch {
          // Unknown means ask: an adapter that cannot reach VERA must not quietly answer "no approval
          // needed" for an action nobody has checked.
          return true;
        }
      };
    },

    protect(tool, spec) {
      return {
        ...tool,
        execute: async (args, context) => {
          let decided: Awaited<ReturnType<typeof decideOnce>>;
          try {
            decided = await decideOnce(tool.name, args, spec);
          } catch (e) {
            if (e instanceof VeraRejected) throw new VeraDenied(null, `VERA refused the request: ${e.code}`);
            // Degraded mode (SR-08): read-only work continues, consequential work stops. Silence is not
            // consent, and an unreachable VERA is not an approval.
            const reason = e instanceof VeraUnreachable ? e.message : String(e);
            if (isConsequential(spec.class))
              throw new VeraDenied(
                null,
                `VERA unreachable (${reason}); ${spec.class} is consequential — refusing (fail closed)`,
              );
            config.log?.(
              `VERA unreachable (${reason}); ${spec.class} is read-only — proceeding in degraded mode (SYSTEM.DEGRADED_MODE)`,
            );
            return tool.execute(args, context);
          }

          const { resolution, hash } = decided;
          if (resolution.kind === 'deny') throw new VeraDenied(resolution.decisionId, resolution.reason);
          if (resolution.kind === 'undecided')
            throw new VeraUndecided(resolution.decisionId, resolution.reason);

          config.log?.(resolution.reason);
          try {
            const result = await tool.execute(args, context);
            // Recompute from the arguments as executed: a tool that mutated them did not run what was
            // approved, and that is a bypass, not a success (threat T02).
            const after = describe(tool.name, args, spec).hash;
            await client
              .outcome(
                resolution.decisionId,
                after === hash ? 'executed' : 'hash_mismatch',
                after === hash ? { tool: tool.name } : { decided: hash, executed: after },
              )
              .catch(() => {});
            return result;
          } catch (e) {
            await client
              .outcome(resolution.decisionId, 'failed', {
                tool: tool.name,
                error: e instanceof Error ? e.message : String(e),
              })
              .catch(() => {});
            throw e;
          }
        },
      };
    },
  };
}
