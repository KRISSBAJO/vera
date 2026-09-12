import type { SchemaJson } from '@cedar-policy/cedar-wasm/nodejs';
import { ACTION_CLASSES } from '@vera/schemas';

/**
 * The Cedar schema VERA evaluates against (brief §7.1).
 *
 * Principals: User, Agent. Resource: the action target. One Cedar action per VERA action class.
 *
 * Every record is CLOSED. Cedar's `additionalAttributes` (open records) is experimental and not enabled
 * in the WASM build, and a closed schema is the safer design anyway: a policy can only reference an
 * attribute the validator knows about, so a typo fails at activation, not silently at runtime. The
 * engine projects incoming context down to these declared keys (undeclared tool arguments are still
 * part of the action hash — they are just invisible to policy).
 *
 * Context shape — this is where SR-01 is enforced structurally:
 *   context.evidence   — facts VERA fetched or computed itself (trust = verified). Policies may rely on it.
 *   context.asserted   — facts the runtime claimed (trust = asserted). Policies may *raise* concern from it,
 *                        but Policy Pack 1 never clears a prerequisite from it, and the engine never puts an
 *                        asserted fact under `evidence`.
 *   context.args       — declared, policy-visible tool arguments.
 *   context.baseline   — flags from the baseline engine.
 *   context.indirect_input — from @vera/canon analyzeShell.
 */
const optional = (type: string) => ({ type, required: false });

/** Policy-visible argument attributes. Tenants will extend this via the class table in a later deliverable. */
export const ARG_ATTRIBUTES = {
  command: optional('String'),
  force: optional('Boolean'),
  branch: optional('String'),
  path: optional('String'),
  url: optional('String'),
  method: optional('String'),
  amount: optional('Long'),
  count: optional('Long'),
  recipient: optional('String'),
} as const;

export const EVIDENCE_ATTRIBUTES = {
  pr_approved: optional('Boolean'),
  tests_passed: optional('Boolean'),
  contains_migration: optional('Boolean'),
  backup_verified: optional('Boolean'),
  rollback_plan: optional('Boolean'),
  staging_deployed: optional('Boolean'),
} as const;

export const BASELINE_ATTRIBUTES = {
  actor_action_novel: optional('Boolean'),
  target_novel: optional('Boolean'),
  time_anomaly: optional('Boolean'),
  magnitude_deviation: optional('Boolean'),
  frequency_spike: optional('Boolean'),
  insufficient_history: optional('Boolean'),
} as const;

export const HINT_ATTRIBUTES = {
  destructive: optional('Boolean'),
  idempotent: optional('Boolean'),
  open_world: optional('Boolean'),
  read_only: optional('Boolean'),
} as const;

export type DeclaredType = 'String' | 'Boolean' | 'Long';

const typesOf = (attrs: Record<string, { type: string }>): Record<string, DeclaredType> =>
  Object.fromEntries(Object.entries(attrs).map(([k, v]) => [k, v.type as DeclaredType]));

/** Section → attribute → declared Cedar type. The engine projects incoming context through this. */
export const DECLARED_ATTRIBUTES = {
  args: typesOf(ARG_ATTRIBUTES),
  evidence: typesOf(EVIDENCE_ATTRIBUTES),
  asserted: typesOf(EVIDENCE_ATTRIBUTES),
  baseline: typesOf(BASELINE_ATTRIBUTES),
  hints: typesOf(HINT_ATTRIBUTES),
} as const;

const record = (attributes: Record<string, unknown>) => ({ type: 'Record', attributes });

const contextType = record({
  args: record(ARG_ATTRIBUTES),
  evidence: record(EVIDENCE_ATTRIBUTES),
  asserted: record(EVIDENCE_ATTRIBUTES),
  baseline: record(BASELINE_ATTRIBUTES),
  hints: record(HINT_ATTRIBUTES),
  indirect_input: { type: 'Boolean' },
  /**
   * True when a policy-visible argument the adapter sent contradicts VERA's own reading of the
   * command. Sits beside `indirect_input` rather than inside `args` because, like it, the service
   * derived it — nothing in here came from the runtime.
   */
  argument_mismatch: { type: 'Boolean' },
});

const resourceShape = record({
  kind: { type: 'String' },
  id: { type: 'String' },
  environment: optional('String'),
  sensitivity: optional('String'),
  branch: optional('String'),
  default_branch: optional('String'),
});

export const VERA_NAMESPACE = 'VERA';

export const veraSchema: SchemaJson<string> = {
  [VERA_NAMESPACE]: {
    entityTypes: {
      User: {
        shape: record({
          id: { type: 'String' },
          roles: { type: 'Set', element: { type: 'String' }, required: false },
        }),
      },
      Agent: { shape: record({ id: { type: 'String' }, runtime: optional('String') }) },
      Resource: { shape: resourceShape },
    },
    actions: Object.fromEntries(
      ACTION_CLASSES.map((cls) => [
        cls,
        {
          appliesTo: { principalTypes: ['User', 'Agent'], resourceTypes: ['Resource'], context: contextType },
        },
      ]),
    ),
  },
} as unknown as SchemaJson<string>;
