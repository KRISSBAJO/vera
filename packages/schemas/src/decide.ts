import { z } from 'zod';
import { ActionClassSchema } from './action-classes.js';
import { ReasonCodeSchema, SeveritySchema } from './reason-codes.js';

// ---------- shared primitives ----------

/** Prefixed identifiers: req_, dec_, ev_, ps_, bs_ … Keep them opaque strings with a sane length bound. */
const Id = z.string().min(1).max(200);
const IsoDateTime = z.iso.datetime({ offset: true });
export const ActionHashSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, 'action_hash must be sha256:<64 hex>');

export const TrustSchema = z.enum(['verified', 'asserted']);
export type Trust = z.infer<typeof TrustSchema>;

export const DecisionSchema = z.enum(['ALLOW', 'REVIEW', 'BLOCK']);
export type Decision = z.infer<typeof DecisionSchema>;

export const SensitivitySchema = z.enum(['low', 'medium', 'high']);

// ---------- principals ----------

export const ActorSchema = z.object({
  type: z.enum(['ai_agent', 'user', 'service']),
  id: Id,
  runtime: z.string().max(200).optional(),
  session_id: z.string().max(200).optional(),
});
export type Actor = z.infer<typeof ActorSchema>;

/** On the wire from an adapter, acting_for is always asserted (A2, SR-09). VERA may upgrade it to verified. */
export const ActingForSchema = z.object({
  type: z.enum(['user', 'service']),
  id: Id,
  trust: TrustSchema,
});
export const RequestActingForSchema = ActingForSchema.extend({ trust: z.literal('asserted') });
export type ActingFor = z.infer<typeof ActingForSchema>;

// ---------- the action ----------

export const ActionHintsSchema = z.object({
  destructive: z.boolean().optional(),
  idempotent: z.boolean().optional(),
  open_world: z.boolean().optional(),
  read_only: z.boolean().optional(),
});

export const ActionSchema = z.object({
  type: z.literal('tool_call'),
  tool: z.string().min(1).max(300),
  class: ActionClassSchema,
  arguments: z.record(z.string(), z.unknown()),
  environment: z.string().max(100).optional(),
  hints: ActionHintsSchema.optional(),
});
export type Action = z.infer<typeof ActionSchema>;

/** kind + id are part of the action hash; everything else is descriptive and may be enriched by VERA. */
export const TargetSchema = z.looseObject({
  kind: z.string().min(1).max(100),
  id: z.string().min(1).max(500),
  sensitivity: SensitivitySchema.optional(),
});
export type Target = z.infer<typeof TargetSchema>;

export const ContextSchema = z.looseObject({
  repo: z.string().max(300).optional(),
  branch: z.string().max(300).optional(),
  cwd: z.string().max(1000).optional(),
  /** Display only. Never used for time features (SR-06). */
  local_time: IsoDateTime.optional(),
});

// ---------- evidence ----------

export const EvidenceSchema = z.object({
  id: Id,
  type: z.string().min(1).max(100),
  source: z.string().min(1).max(100),
  trust: TrustSchema,
  observed_at: IsoDateTime,
  confidence: z.number().min(0).max(1).optional(),
  ttl_seconds: z.number().int().positive().optional(),
  data: z.record(z.string(), z.unknown()),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

/** Evidence supplied by the runtime is always asserted (A1, SR-01). */
export const RequestEvidenceSchema = EvidenceSchema.extend({ trust: z.literal('asserted') });

// ---------- POST /v1/decide ----------

export const DecideRequestSchema = z.object({
  request_id: Id,
  idempotency_key: z.string().min(1).max(300),
  actor: ActorSchema,
  acting_for: RequestActingForSchema.optional(),
  action: ActionSchema,
  target: TargetSchema.optional(),
  context: ContextSchema.optional(),
  evidence: z.array(RequestEvidenceSchema).max(50).optional(),
  /** Receiver identity that will verify the token (`aud` claim). Defaults to the API key's registered receiver. */
  receiver: z.object({ aud: z.string().min(1).max(200) }).optional(),
});
export type DecideRequest = z.infer<typeof DecideRequestSchema>;

export const ReasonCodeEntrySchema = z.object({
  code: ReasonCodeSchema,
  severity: SeveritySchema,
  policy_id: z.string().max(200).optional(),
  evidence_ref: Id.optional(),
  detail: z.string().max(2000).optional(),
});
export type ReasonCodeEntry = z.infer<typeof ReasonCodeEntrySchema>;

export const RequiredActionSchema = z.enum(['HUMAN_APPROVAL', 'REMEDIATION']);

export const ReviewInfoSchema = z.object({
  url: z.string().url(),
  routed_to: z.array(z.string().max(200)).min(1),
  sod: z.string().max(200),
  quorum: z.number().int().min(1),
});

export const DecideResponseSchema = z.object({
  decision_id: Id,
  decision: DecisionSchema,
  risk: z.object({ score: z.number().min(0).max(100), calibrated: z.boolean() }),
  confidence: z.number().min(0).max(1),
  reason_codes: z.array(ReasonCodeEntrySchema),
  evidence: z.array(EvidenceSchema),
  required_actions: z.array(RequiredActionSchema),
  review: ReviewInfoSchema.optional(),
  action_hash: ActionHashSchema,
  policy_set_version: Id,
  baseline_snapshot_id: Id.optional(),
  supersedes: Id.nullable(),
  expires_at: IsoDateTime,
  decision_token: z.string().nullable(),
});
export type DecideResponse = z.infer<typeof DecideResponseSchema>;

/**
 * Invariants a valid response must satisfy beyond field shapes. Enforced by the server before sending
 * and by tests; adapters may re-check them.
 */
export function responseInvariantViolations(r: DecideResponse): string[] {
  const v: string[] = [];
  if (r.decision === 'ALLOW' && !r.decision_token) v.push('ALLOW must carry a decision_token');
  if (r.decision !== 'ALLOW' && r.decision_token) v.push('only ALLOW carries a decision_token at issue time');
  if (r.decision === 'REVIEW' && !r.review) v.push('REVIEW must carry review routing');
  if (r.decision === 'REVIEW' && !r.required_actions.includes('HUMAN_APPROVAL'))
    v.push('REVIEW must require HUMAN_APPROVAL');
  if (r.decision === 'BLOCK' && !r.reason_codes.some((c) => c.severity === 'high'))
    v.push('BLOCK must cite at least one high-severity reason');
  return v;
}
