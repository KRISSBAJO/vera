import { analyzeShell } from '@vera/canon';
import { type CompiledPolicySet, evaluate } from '@vera/policy-engine';
import {
  type DecideRequest,
  type Decision,
  type Evidence,
  isConsequential,
  type ReasonCodeEntry,
  type Severity,
} from '@vera/schemas';
import { projectEvidence } from './evidence.js';

export { projectEvidence } from './evidence.js';

// ---------- inputs ----------

export interface TenantConfig {
  id: string;
  timezone: string;
  noMatch?: { consequential?: 'BLOCK' | 'REVIEW'; readOnly?: 'ALLOW' | 'REVIEW' };
  weights?: Partial<Record<Severity, number>>;
  tokenTtlSeconds?: { allow?: number; approval?: number };
  reviewHoldSeconds?: number;
}

export interface DecideInput {
  request: DecideRequest;
  tenant: TenantConfig;
  policySet: CompiledPolicySet;
  policySetVersion: string;
  /** Evidence VERA fetched or computed itself. Request evidence is always asserted (SR-01). */
  verifiedEvidence: readonly Evidence[];
  /** Providers that applied but did not answer in budget (EVIDENCE.MISSING; absence is never safe). */
  missingEvidence?: readonly { provider: string; reason: string }[];
  keyOwner: { id: string; kind: 'user' | 'service' };
  now: Date;
}

export interface ReviewRouting {
  routed_to: string[];
  sod: string;
  quorum: number;
  /** Principal ids that may not approve (SR-09). */
  excluded: string[];
}

export interface DecideOutput {
  decision: Decision;
  riskScore: number;
  confidence: number;
  reasonCodes: ReasonCodeEntry[];
  evidence: Evidence[];
  requiredActions: ('HUMAN_APPROVAL' | 'REMEDIATION')[];
  review?: ReviewRouting;
  expiresAt: Date;
  /** What the policy layer alone said, before aggregation. Stored for reproducibility and reporting. */
  policyOutcome: 'ALLOW' | 'REVIEW' | 'BLOCK' | 'NO_MATCH';
}

const DEFAULT_WEIGHTS: Record<Severity, number> = { info: 0, low: 10, medium: 25, high: 45 };
export const DEFAULT_REVIEW_HOLD_SECONDS = 15 * 60;
const DEFAULT_ALLOW_TTL = 10 * 60;

// ---------- the decision ----------

/**
 * Aggregation (brief §7.4): policy BLOCK ⇒ BLOCK. Else REVIEW if the policy layer said REVIEW, or the
 * tenant default for NO_MATCH says so, or any high-severity code exists, or two or more medium codes.
 * Baselines add severity only; they never lower a verdict (SR-20). `info` codes never affect the verdict.
 */
export function decide(input: DecideInput): DecideOutput {
  const { request, tenant, now } = input;
  const codes: ReasonCodeEntry[] = [];
  const action = request.action;
  const args = action.arguments;

  // --- evidence: verified from VERA, asserted from the request; never merged (SR-01) ---
  const asserted: Evidence[] = (request.evidence ?? []).map((e) => ({ ...e, trust: 'asserted' as const }));
  const verified: Evidence[] = input.verifiedEvidence.map((e) => ({ ...e, trust: 'verified' as const }));
  const evidence = [...verified, ...asserted];
  if (verified.length > 0) codes.push({ code: 'EVIDENCE.VERIFIED', severity: 'info' });
  if (asserted.length > 0)
    codes.push({
      code: 'EVIDENCE.ASSERTED',
      severity: 'info',
      detail: `${asserted.length} runtime-asserted item(s); cannot satisfy prerequisites`,
    });
  for (const m of input.missingEvidence ?? [])
    codes.push({ code: 'EVIDENCE.MISSING', severity: 'medium', detail: `${m.provider}: ${m.reason}` });

  // --- action analysis ---
  const command = typeof args.command === 'string' ? args.command : undefined;
  const shell = command ? analyzeShell(command) : { indirect: false, constructs: [] };
  const isProd = action.environment === 'production';
  if (shell.indirect)
    codes.push({
      code: 'ACTION.INDIRECT_INPUT',
      severity: 'medium',
      detail: `resolved at runtime: ${shell.constructs.join(', ')}`,
    });
  if (action.class === 'shell.exec')
    codes.push({ code: 'ACTION.UNCLASSIFIED_SHELL', severity: isProd ? 'medium' : 'low' });
  if (action.hints?.destructive) codes.push({ code: 'ACTION.DESTRUCTIVE_HINT', severity: 'medium' });
  if (request.target?.sensitivity === 'high')
    codes.push({ code: 'ACTION.SENSITIVE_RESOURCE', severity: 'medium' });

  // --- prerequisites: derived from VERIFIED evidence only (SR-01). Absence is stated, never assumed safe. ---
  const flags = projectEvidence(verified);
  if (action.class === 'deploy.production') {
    if (flags.pr_approved !== true)
      codes.push({ code: 'PREREQ.MISSING_APPROVAL', severity: 'high', detail: 'no verified PR approval' });
    if (flags.tests_passed !== true)
      codes.push({
        code: 'PREREQ.TESTS_NOT_PASSED',
        severity: 'high',
        detail: 'no verified passing CI status',
      });
    if (flags.contains_migration === true && flags.backup_verified !== true)
      codes.push({
        code: 'PREREQ.BACKUP_NOT_VERIFIED',
        severity: 'high',
        detail: 'migration present; no verified backup evidence',
      });
  }
  if (action.class === 'db.ddl' && isProd && flags.backup_verified !== true)
    codes.push({
      code: 'PREREQ.BACKUP_NOT_VERIFIED',
      severity: 'high',
      detail: 'production DDL; no verified backup evidence',
    });

  // --- identity (A2, SR-09) ---
  codes.push({
    code: 'IDENTITY.ASSERTED',
    severity: 'info',
    detail: request.acting_for
      ? `acting_for ${request.acting_for.id} asserted by adapter`
      : 'no acting_for supplied',
  });

  // --- baselines: not built yet (deliverable 4). Say so rather than pretend (BASELINE.INSUFFICIENT_HISTORY). ---
  codes.push({
    code: 'BASELINE.INSUFFICIENT_HISTORY',
    severity: 'info',
    detail: 'baseline engine not yet active',
  });

  // --- policy ---
  const policy = evaluate(input.policySet, {
    principal: { type: request.actor.type === 'ai_agent' ? 'Agent' : 'User', id: request.actor.id },
    action: action.class,
    resource: {
      kind: request.target?.kind ?? 'unknown',
      id: request.target?.id ?? '-',
      ...(action.environment ? { environment: action.environment } : {}),
      ...(request.target?.sensitivity ? { sensitivity: request.target.sensitivity } : {}),
      ...(typeof request.context?.branch === 'string' ? { branch: request.context.branch } : {}),
      ...(typeof request.target?.default_branch === 'string'
        ? { default_branch: request.target.default_branch }
        : {}),
    },
    context: {
      args: args as Record<string, never>,
      evidence: projectEvidence(verified),
      asserted: projectEvidence(asserted),
      hints: action.hints ?? {},
      indirect_input: shell.indirect,
    },
  });
  codes.push(...policy.reasonCodes);

  let noMatchVerdict: Decision | undefined;
  if (policy.outcome === 'NO_MATCH') {
    noMatchVerdict = isConsequential(action.class)
      ? (tenant.noMatch?.consequential ?? 'BLOCK')
      : (tenant.noMatch?.readOnly ?? 'ALLOW');
    if (noMatchVerdict !== 'ALLOW')
      codes.push({
        code: 'POLICY.DEFAULT_DENY',
        severity: 'high',
        detail: `no policy matched ${action.class}; tenant default ${noMatchVerdict}`,
      });
  }

  // --- aggregate ---
  const highs = codes.filter((c) => c.severity === 'high').length;
  const mediums = codes.filter((c) => c.severity === 'medium').length;
  let decision: Decision;
  if (policy.outcome === 'BLOCK' || noMatchVerdict === 'BLOCK') decision = 'BLOCK';
  else if (policy.outcome === 'REVIEW' || noMatchVerdict === 'REVIEW' || highs > 0 || mediums >= 2)
    decision = 'REVIEW';
  else decision = 'ALLOW';

  const weights = { ...DEFAULT_WEIGHTS, ...tenant.weights };
  const riskScore = Math.min(
    100,
    codes.reduce((s, c) => s + (weights[c.severity] ?? 0), 0),
  );
  const missing = codes.filter((c) => c.code === 'EVIDENCE.MISSING').length;
  const confidence = Math.max(0.3, Math.round((1 - 0.15 * missing - 0.1) * 100) / 100); // −0.1: identity is asserted in V1

  // --- routing (SR-09, ADR-0003) ---
  let review: ReviewRouting | undefined;
  const requiredActions: DecideOutput['requiredActions'] = [];
  if (decision === 'REVIEW') {
    requiredActions.push('HUMAN_APPROVAL');
    const excluded = [request.actor.id, request.acting_for?.id, input.keyOwner.id].filter(
      (x): x is string => !!x,
    );
    const quorum = input.keyOwner.kind === 'service' ? 2 : 1;
    review = {
      routed_to: ['role:reviewer'],
      sod: 'actor_acting_for_and_key_owner_excluded',
      quorum,
      excluded: [...new Set(excluded)],
    };
  }

  const ttl =
    decision === 'ALLOW'
      ? (tenant.tokenTtlSeconds?.allow ?? DEFAULT_ALLOW_TTL)
      : decision === 'REVIEW'
        ? (tenant.reviewHoldSeconds ?? DEFAULT_REVIEW_HOLD_SECONDS)
        : 0;

  return {
    decision,
    riskScore,
    confidence,
    reasonCodes: codes,
    evidence,
    requiredActions,
    ...(review ? { review } : {}),
    expiresAt: new Date(now.getTime() + ttl * 1000),
    policyOutcome: policy.outcome,
  };
}
