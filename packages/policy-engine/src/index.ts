import type {
  AuthorizationCall,
  CedarValueJson,
  DetailedError,
  EntityJson,
  PolicyJson,
} from '@cedar-policy/cedar-wasm/nodejs';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import type { ActionClass, Decision, ReasonCodeEntry } from '@vera/schemas';
import { DECLARED_ATTRIBUTES, VERA_NAMESPACE, veraSchema } from './schema.js';

export { POLICY_PACK_1, POLICY_PACK_1_VERSION } from './policy-pack-1.js';
export {
  ARG_ATTRIBUTES,
  DECLARED_ATTRIBUTES,
  EVIDENCE_ATTRIBUTES,
  VERA_NAMESPACE,
  veraSchema,
} from './schema.js';

// ---------- compiling a policy set ----------

export type VeraEffect = 'review';

export interface CompiledPolicy {
  id: string;
  effect: 'permit' | 'forbid';
  veraEffect?: VeraEffect;
  text: string;
  json: PolicyJson;
}

export interface CompiledPolicySet {
  /** Keyed by @id — this is what Cedar reports in diagnostics.reason. */
  policies: Record<string, CompiledPolicy>;
  /** Passed to Cedar verbatim; ids are ours, not policy0/policy1. */
  staticPolicies: Record<string, string>;
}

export class PolicyCompileError extends Error {
  constructor(
    message: string,
    public readonly errors: DetailedError[],
  ) {
    super(message);
    this.name = 'PolicyCompileError';
  }
}

const describe = (errors: DetailedError[]) => errors.map((e) => e.message).join('; ');

/**
 * Parse a policy-set text, split it into policies, read each policy's annotations, validate the set
 * against the VERA schema in strict mode, and key everything by @id. Refuses:
 *   - parse failures, validation errors
 *   - a policy without @id, duplicate ids, or a @vera_effect other than "review"
 *   - @vera_effect on a forbid (meaningless; forbid is always BLOCK)
 */
export function compilePolicySet(text: string): CompiledPolicySet {
  const parts = cedar.policySetTextToParts(text);
  if (parts.type === 'failure')
    throw new PolicyCompileError(`policy set does not parse: ${describe(parts.errors)}`, parts.errors);
  if (parts.policy_templates.length > 0)
    throw new PolicyCompileError('templates are not supported in V1', []);

  const policies: Record<string, CompiledPolicy> = {};
  for (const policyText of parts.policies) {
    const json = cedar.policyToJson(policyText);
    if (json.type === 'failure')
      throw new PolicyCompileError(`policy does not convert: ${describe(json.errors)}`, json.errors);
    const annotations = json.json.annotations ?? {};
    const id = annotations.id;
    if (!id) throw new PolicyCompileError(`policy without @id: ${policyText.slice(0, 80)}…`, []);
    if (policies[id]) throw new PolicyCompileError(`duplicate policy id "${id}"`, []);
    const veraEffect = annotations.vera_effect;
    if (veraEffect !== undefined && veraEffect !== 'review')
      throw new PolicyCompileError(`policy "${id}": unknown @vera_effect("${veraEffect}")`, []);
    if (veraEffect && json.json.effect === 'forbid')
      throw new PolicyCompileError(`policy "${id}": @vera_effect on a forbid is meaningless`, []);
    policies[id] = {
      id,
      effect: json.json.effect,
      text: policyText,
      json: json.json,
      ...(veraEffect ? { veraEffect } : {}),
    };
  }

  const staticPolicies = Object.fromEntries(Object.values(policies).map((p) => [p.id, p.text]));
  const validation = cedar.validate({
    validationSettings: { mode: 'strict' },
    schema: veraSchema,
    policies: { staticPolicies },
  });
  if (validation.type === 'failure')
    throw new PolicyCompileError(`validation failed: ${describe(validation.errors)}`, validation.errors);
  if (validation.validationErrors.length > 0)
    throw new PolicyCompileError(
      `policies do not validate against the VERA schema: ${validation.validationErrors.map((e) => `${e.policyId}: ${e.error.message}`).join('; ')}`,
      validation.validationErrors.map((e) => e.error),
    );
  return { policies, staticPolicies };
}

// ---------- evaluating ----------

export interface PrincipalInput {
  type: 'User' | 'Agent';
  id: string;
  attrs?: Record<string, CedarValueJson>;
}

export interface ResourceInput {
  kind: string;
  id: string;
  environment?: string;
  sensitivity?: string;
  branch?: string;
  default_branch?: string;
}

export interface EvaluationInput {
  principal: PrincipalInput;
  action: ActionClass;
  resource: ResourceInput;
  context: {
    args: Record<string, CedarValueJson>;
    evidence?: Record<string, CedarValueJson>;
    asserted?: Record<string, CedarValueJson>;
    baseline?: Record<string, CedarValueJson>;
    hints?: Record<string, CedarValueJson>;
    indirect_input: boolean;
  };
}

export type PolicyOutcome = 'ALLOW' | 'REVIEW' | 'BLOCK' | 'NO_MATCH';

export interface PolicyEvaluation {
  /** NO_MATCH means no policy matched; the caller applies the tenant default (POLICY.DEFAULT_DENY). */
  outcome: PolicyOutcome;
  /** Ids of the policies that determined the Cedar decision. */
  determining: string[];
  reasonCodes: ReasonCodeEntry[];
  /** Cedar evaluation errors (e.g. a policy that threw on a missing attribute). Non-empty ⇒ fail closed. */
  errors: { policyId: string; message: string }[];
}

function stripUndefined<T extends Record<string, unknown>>(o: T): Record<string, CedarValueJson> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Record<
    string,
    CedarValueJson
  >;
}

/**
 * Keep only the attributes the schema declares. Undeclared keys are invisible to policy (they remain in
 * the action hash). Values whose JS type cannot map to the declared Cedar type are dropped too, so a
 * malformed runtime value can never make the request fail validation and fall into fail-closed by
 * accident — it simply is not there, and `has` returns false.
 */
export function projectContext(
  section: keyof typeof DECLARED_ATTRIBUTES,
  values: Record<string, unknown> | undefined,
): Record<string, CedarValueJson> {
  if (!values) return {};
  const out: Record<string, CedarValueJson> = {};
  for (const [key, type] of Object.entries(DECLARED_ATTRIBUTES[section])) {
    const v = values[key];
    if (v === undefined || v === null) continue;
    if (type === 'String' && typeof v === 'string') out[key] = v;
    else if (type === 'Boolean' && typeof v === 'boolean') out[key] = v;
    else if (type === 'Long' && typeof v === 'number' && Number.isSafeInteger(v)) out[key] = v;
  }
  return out;
}

/**
 * Evaluate one action against a compiled policy set and map Cedar's two outcomes onto VERA's three.
 * Most-restrictive-wins (A9): forbid ⇒ BLOCK; any review-annotated permit among the determining
 * policies ⇒ REVIEW; otherwise ALLOW. Cedar errors never produce ALLOW: an allow with errors becomes
 * REVIEW with SYSTEM.FAIL_CLOSED, because an errored forbid would have been silently skipped.
 */
export function evaluate(set: CompiledPolicySet, input: EvaluationInput): PolicyEvaluation {
  const principalType = `${VERA_NAMESPACE}::${input.principal.type}`;
  const principal = { type: principalType, id: input.principal.id };
  const resource = { type: `${VERA_NAMESPACE}::Resource`, id: input.resource.id };
  const entities: EntityJson[] = [
    { uid: principal, attrs: { id: input.principal.id, ...(input.principal.attrs ?? {}) }, parents: [] },
    { uid: resource, attrs: stripUndefined({ ...input.resource }), parents: [] },
  ];
  const call: AuthorizationCall = {
    principal,
    action: { type: `${VERA_NAMESPACE}::Action`, id: input.action },
    resource,
    context: {
      args: projectContext('args', input.context.args),
      evidence: projectContext('evidence', input.context.evidence),
      asserted: projectContext('asserted', input.context.asserted),
      baseline: projectContext('baseline', input.context.baseline),
      hints: projectContext('hints', input.context.hints),
      indirect_input: input.context.indirect_input,
    },
    schema: veraSchema,
    validateRequest: true,
    policies: { staticPolicies: set.staticPolicies },
    entities,
  };

  const answer = cedar.isAuthorized(call);
  if (answer.type === 'failure') {
    // The request itself was malformed (bad entity, schema mismatch). Fail closed and say why.
    return {
      outcome: 'BLOCK',
      determining: [],
      reasonCodes: [{ code: 'SYSTEM.FAIL_CLOSED', severity: 'high', detail: describe(answer.errors) }],
      errors: answer.errors.map((e) => ({ policyId: '-', message: e.message })),
    };
  }

  const { decision, diagnostics } = answer.response;
  const determining = diagnostics.reason;
  const errors = diagnostics.errors.map((e) => ({ policyId: e.policyId, message: e.error.message }));
  const reasonCodes: ReasonCodeEntry[] = [];

  if (decision === 'deny') {
    if (determining.length === 0) return { outcome: 'NO_MATCH', determining, reasonCodes, errors };
    for (const id of determining) reasonCodes.push({ code: 'POLICY.DENY', severity: 'high', policy_id: id });
    return { outcome: 'BLOCK', determining, reasonCodes, errors };
  }

  const reviewIds = determining.filter((id) => set.policies[id]?.veraEffect === 'review');
  for (const id of reviewIds)
    reasonCodes.push({ code: 'POLICY.REQUIRE_REVIEW', severity: 'high', policy_id: id });
  if (errors.length > 0)
    reasonCodes.push({
      code: 'SYSTEM.FAIL_CLOSED',
      severity: 'high',
      detail: `cedar errors: ${errors.map((e) => e.policyId).join(', ')}`,
    });

  const outcome: PolicyOutcome = reviewIds.length > 0 || errors.length > 0 ? 'REVIEW' : 'ALLOW';
  return { outcome, determining, reasonCodes, errors };
}

export function cedarVersion(): string {
  return cedar.getCedarVersion();
}

export type { Decision };
