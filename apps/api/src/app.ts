import { createHash } from 'node:crypto';
import swagger from '@fastify/swagger';
import { evaluateBaselines, localParts, magnitudeOf } from '@vera/baseline-engine';
import { actionHash } from '@vera/canon';
import { appendAudit, newId, schema, seal, type Tx, unseal, type VeraDb } from '@vera/db';
import { decide, type TenantConfig } from '@vera/decision-engine';
import { verifyDecisionToken } from '@vera/decision-token';
import { type EvidenceProvider, gatherEvidence } from '@vera/evidence';
import { redact, rulesFor, tenantRules } from '@vera/redaction';
import {
  DecideRequestSchema,
  type DecideResponse,
  DecideResponseSchema,
  REASON_CODES,
  responseInvariantViolations,
} from '@vera/schemas';
import canonicalize from 'canonicalize';
import { and, asc, desc, eq, gt, isNull } from 'drizzle-orm';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  hasZodFastifySchemaValidationErrors,
  jsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { decodeJwt } from 'jose';
import { z } from 'zod';
import { requireApiKey, requireReviewer } from './auth.js';
import {
  lookupBaselines,
  rebuildSnapshot,
  rebuildSnapshotIfStale,
  recordObservation,
  retractObservation,
} from './baselines.js';
import { conflict, forbidden, HttpError, notFound } from './errors.js';
import { listKeys, revokeKey, rotateKey, signingParity } from './keys.js';
import { baselineExplain, policyPrecision } from './reports.js';
import {
  activePolicySet,
  issueAndRecordToken,
  liveTokenFor,
  type ServiceContext,
  tenantJwks,
} from './services.js';

const {
  organizations,
  users,
  apiKeys,
  actionRequests,
  decisions,
  reviews,
  approvals,
  decisionTokens,
  outcomes,
  auditEvents,
} = schema;

export interface AppDeps extends ServiceContext {
  vera: VeraDb;
  logger?: boolean;
  /** Evidence providers (Proof engine). Each runs under `evidenceBudgetMs`; late ones are EVIDENCE.MISSING. */
  evidenceProviders?: EvidenceProvider[];
  evidenceBudgetMs?: number;
  /** How stale a baseline rollup may get before the next outcome rebuilds it. */
  baselineSnapshotMaxAgeMs?: number;
}

const ErrorSchema = z.object({
  error: z.object({ code: z.string(), message: z.string(), details: z.unknown().optional() }),
});

/**
 * A refusal that must leave an audit event even though the transaction it happened in rolls back
 * (SoD violations, token replays, idempotency mismatches). `withTenantAudited` writes the event in a
 * fresh transaction after the rollback, then rethrows (SR-16).
 */
class AuditedRefusal extends HttpError {
  constructor(
    status: number,
    code: string,
    public readonly audit: { kind: string; actor: string; payload: Record<string, unknown> },
    message?: string,
  ) {
    super(status, code, message);
  }
}

export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  const { vera } = deps;

  const withTenantAudited = async <T>(orgId: string, fn: (tx: Tx) => Promise<T>): Promise<T> => {
    try {
      return await vera.withTenant(orgId, fn);
    } catch (e) {
      if (e instanceof AuditedRefusal)
        await vera.withTenant(orgId, (tx) =>
          appendAudit(tx, orgId, e.audit.kind, e.audit.actor, e.audit.payload),
        );
      throw e;
    }
  };
  const app = Fastify({ logger: deps.logger ?? false }).withTypeProvider<ZodTypeProvider>();
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'VERA API',
        version: '0.1.0',
        description: 'A signed decision service for consequential AI-agent actions.',
      },
    },
    transform: jsonSchemaTransform,
  });

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError)
      return reply
        .status(err.status)
        .send({ error: { code: err.code, message: err.message, details: err.details } });
    if (hasZodFastifySchemaValidationErrors(err))
      return reply.status(400).send({
        error: {
          code: 'VALIDATION_FAILED',
          message: 'request does not match schema',
          details: err.validation,
        },
      });
    app.log.error(err);
    return reply.status(500).send({ error: { code: 'INTERNAL', message: 'internal error' } });
  });

  app.get('/openapi.json', async () => app.swagger());
  app.get('/healthz', async () => ({ ok: true }));

  // ---------- JWKS (public) ----------
  app.get(
    '/.well-known/vera/:orgId/jwks.json',
    { schema: { params: z.object({ orgId: z.string() }) } },
    async (req) => {
      return vera.withTenant(req.params.orgId, (tx) => tenantJwks(tx, req.params.orgId));
    },
  );

  // ---------- POST /v1/decide ----------
  app.post(
    '/v1/decide',
    {
      onRequest: requireApiKey(vera),
      schema: { body: DecideRequestSchema, response: { 200: DecideResponseSchema, 409: ErrorSchema } },
    },
    async (req) => {
      const key = req.key!;
      const body = req.body;
      const now = new Date();
      const bodyHash = createHash('sha256')
        .update(canonicalize(body) ?? '', 'utf8')
        .digest('hex');

      return withTenantAudited(key.orgId, async (tx) => {
        // SR-13: same idempotency key ⇒ same decision; different body ⇒ 409.
        const [existing] = await tx
          .select({ id: actionRequests.id, bodyHash: actionRequests.bodyHash })
          .from(actionRequests)
          .where(
            and(eq(actionRequests.orgId, key.orgId), eq(actionRequests.idempotencyKey, body.idempotency_key)),
          )
          .limit(1);
        if (existing) {
          if (existing.bodyHash !== bodyHash)
            throw new AuditedRefusal(
              409,
              'IDEMPOTENCY_MISMATCH',
              {
                kind: 'request.idempotency_mismatch',
                actor: `key:${key.keyId}`,
                payload: { idempotency_key: body.idempotency_key, request_id: body.request_id },
              },
              'idempotency key reused with a different body',
            );
          const prior = await loadDecisionResponse(tx, key.orgId, existing.id, key.receiverAud, deps);
          if (!prior) throw notFound('decision');
          return prior;
        }

        const [org] = await tx.select().from(organizations).where(eq(organizations.id, key.orgId)).limit(1);
        if (!org) throw notFound('organization');
        const tenant: TenantConfig = {
          id: org.id,
          timezone: org.timezone,
          ...(org.defaults.no_match
            ? {
                noMatch: {
                  consequential: org.defaults.no_match.consequential,
                  readOnly: org.defaults.no_match.read_only,
                },
              }
            : {}),
          ...(org.defaults.weights ? { weights: org.defaults.weights } : {}),
          ...(org.defaults.token_ttl_seconds ? { tokenTtlSeconds: org.defaults.token_ttl_seconds } : {}),
          ...(org.defaults.review_hold_seconds
            ? { reviewHoldSeconds: org.defaults.review_hold_seconds }
            : {}),
        };
        const ps = await activePolicySet(tx, key.orgId);

        const hash = actionHash({
          class: body.action.class,
          tool: body.action.tool,
          arguments: body.action.arguments,
          target: body.target ? { kind: body.target.kind, id: body.target.id } : undefined,
          environment: body.action.environment,
        });

        // Redact AFTER hashing (SR-15, threat T18): the hash must cover what the adapter will actually
        // execute, while everything persisted — and therefore everything a reviewer or a model ever
        // sees — is the masked form. The raw action is sealed and revealed only by a step-up action.
        const redactionRules = rulesFor(tenantRules(org.defaults.redaction_patterns));
        const redactedAction = redact(body.action, redactionRules);
        const redactedContext = redact(body.context ?? null, redactionRules);
        const redactedEvidence = redact(body.evidence ?? [], redactionRules);

        const requestRowId = newId('req');
        await tx.insert(actionRequests).values({
          id: requestRowId,
          orgId: key.orgId,
          requestId: body.request_id,
          idempotencyKey: body.idempotency_key,
          bodyHash,
          apiKeyId: key.keyId,
          actor: body.actor,
          actingFor: body.acting_for ?? null,
          action: redactedAction.value,
          actionRawSealed: redactedAction.redacted ? seal(JSON.stringify(body.action), deps.masterKey) : null,
          redactionFindings: redactedAction.findings,
          target: body.target ?? null,
          context: redactedContext.value,
          evidence: redactedEvidence.value,
          actionHash: hash,
          receivedAt: now,
        });
        if (redactedAction.redacted)
          await appendAudit(tx, key.orgId, 'request.redacted', `key:${key.keyId}`, {
            request_id: body.request_id,
            findings: redactedAction.findings,
          });
        await tx.update(apiKeys).set({ lastUsedAt: now }).where(eq(apiKeys.id, key.keyId));

        // Proof: facts fetched with VERA's own credentials, gathered before the row is written so the
        // stored decision is reproducible from what was known at the time.
        const gathered = await gatherEvidence(deps.evidenceProviders ?? [], body, {
          budgetMs: deps.evidenceBudgetMs ?? 1500,
        });

        // Baselines: what this organisation has actually done before. Read from the newest materialised
        // snapshot (never computed here — that is what keeps the p95 budget and reproducibility).
        const lookup = await lookupBaselines(
          tx,
          key.orgId,
          body.actor,
          body.action.class,
          body.target?.id ?? '-',
        );
        const baselineCodes = evaluateBaselines({
          localHour: localParts(now, org.timezone).hour,
          magnitude: magnitudeOf(body.action.arguments),
          lookup,
        });

        const out = decide({
          request: body,
          tenant,
          policySet: ps.compiled,
          policySetVersion: ps.version,
          verifiedEvidence: gathered.evidence,
          missingEvidence: gathered.missing,
          baselineCodes,
          keyOwner: { id: key.ownerUserId, kind: key.ownerKind },
          now,
        });

        const decisionId = newId('dec');
        await tx.insert(decisions).values({
          id: decisionId,
          orgId: key.orgId,
          actionRequestId: requestRowId,
          decision: out.decision,
          riskScore: out.riskScore,
          confidence: Math.round(out.confidence * 100),
          reasonCodes: out.reasonCodes,
          evidence: out.evidence,
          requiredActions: out.requiredActions,
          review: out.review ? { ...out.review } : null,
          actionHash: hash,
          policySetVersion: ps.version,
          baselineSnapshotId: lookup.snapshotId,
          supersedes: null,
          expiresAt: out.expiresAt,
          createdAt: now,
        });

        let token: string | null = null;
        if (out.decision === 'ALLOW') {
          token = await issueAndRecordToken(tx, deps, {
            orgId: key.orgId,
            decisionId,
            decision: 'ALLOW',
            actionHash: hash,
            aud: key.receiverAud,
            actor: body.actor.id,
            actingFor: body.acting_for?.id,
            policySetVersion: ps.version,
            ttlSeconds: tenant.tokenTtlSeconds?.allow,
            auditActor: `key:${key.keyId}`,
          });
        }
        let reviewUrl: string | undefined;
        if (out.decision === 'REVIEW' && out.review) {
          const reviewId = newId('rev');
          await tx.insert(reviews).values({
            id: reviewId,
            orgId: key.orgId,
            decisionId,
            routedTo: out.review.routed_to,
            quorum: out.review.quorum,
            excluded: out.review.excluded,
            expiresAt: out.expiresAt,
          });
          reviewUrl = `${deps.publicUrl}/r/${decisionId}`;
        }

        await appendAudit(tx, key.orgId, 'decision.issued', `key:${key.keyId}`, {
          decision_id: decisionId,
          decision: out.decision,
          action_class: body.action.class,
          action_hash: hash,
          policy_set_version: ps.version,
          policy_outcome: out.policyOutcome,
          reason_codes: out.reasonCodes.map((c) => c.code),
          actor: body.actor.id,
          acting_for: body.acting_for?.id ?? null,
        });

        const response: DecideResponse = {
          decision_id: decisionId,
          decision: out.decision,
          risk: { score: out.riskScore, calibrated: false },
          confidence: out.confidence,
          reason_codes: out.reasonCodes,
          evidence: out.evidence,
          required_actions: out.requiredActions,
          ...(out.review && reviewUrl
            ? {
                review: {
                  url: reviewUrl,
                  routed_to: out.review.routed_to,
                  sod: out.review.sod,
                  quorum: out.review.quorum,
                },
              }
            : {}),
          action_hash: hash,
          policy_set_version: ps.version,
          ...(lookup.snapshotId ? { baseline_snapshot_id: lookup.snapshotId } : {}),
          supersedes: null,
          expires_at: out.expiresAt.toISOString(),
          decision_token: token,
        };
        const violations = responseInvariantViolations(response);
        if (violations.length > 0) throw new HttpError(500, 'INVARIANT_VIOLATION', violations.join('; '));
        return response;
      });
    },
  );

  // ---------- GET /v1/decisions/:id (adapter long-polls this while a REVIEW is pending) ----------
  const DecisionStatusSchema = DecideResponseSchema.extend({
    review_status: z.enum(['none', 'pending', 'approved', 'rejected', 'expired']),
  });
  app.get(
    '/v1/decisions/:id',
    {
      onRequest: requireApiKey(vera),
      schema: { params: z.object({ id: z.string() }), response: { 200: DecisionStatusSchema } },
    },
    async (req) => {
      const key = req.key!;
      const found = await vera.withTenant(key.orgId, async (tx) => {
        const [d] = await tx
          .select({ requestId: decisions.actionRequestId })
          .from(decisions)
          .where(eq(decisions.id, req.params.id))
          .limit(1);
        if (!d) return null;
        return loadDecisionResponse(tx, key.orgId, d.requestId, key.receiverAud, deps);
      });
      if (!found) throw notFound('decision');
      return found;
    },
  );

  // ---------- review: approve / reject (reviewer session only) ----------
  const ReviewBody = z.object({ rationale: z.string().max(2000).optional() });
  /** Reviewers never receive the token; the receiver collects it by polling GET /v1/decisions/:id. */
  const ReviewResult = z.object({
    decision_id: z.string(),
    review_status: z.enum(['pending', 'approved', 'rejected']),
    approvals: z.number().int(),
    quorum: z.number().int(),
    token_issued: z.boolean(),
  });

  for (const verdict of ['approve', 'reject'] as const) {
    app.post(
      `/v1/decisions/:id/${verdict}`,
      {
        onRequest: requireReviewer(vera),
        schema: {
          params: z.object({ id: z.string() }),
          body: ReviewBody,
          response: { 200: ReviewResult, 403: ErrorSchema },
        },
      },
      async (req) => {
        const reviewer = req.reviewer!;
        return withTenantAudited(reviewer.orgId, async (tx) => {
          const [row] = await tx
            .select({ review: reviews, decision: decisions, request: actionRequests, reviewerUser: users })
            .from(reviews)
            .innerJoin(decisions, eq(decisions.id, reviews.decisionId))
            .innerJoin(actionRequests, eq(actionRequests.id, decisions.actionRequestId))
            .innerJoin(users, eq(users.id, reviewer.userId))
            .where(eq(reviews.decisionId, req.params.id))
            .limit(1);
          if (!row) throw notFound('review');
          const { review, decision, request, reviewerUser } = row;
          if (review.status !== 'pending') throw conflict('REVIEW_NOT_PENDING', `review is ${review.status}`);
          if (review.expiresAt < new Date()) {
            await tx
              .update(reviews)
              .set({ status: 'expired', resolvedAt: new Date() })
              .where(eq(reviews.id, review.id));
            throw conflict('REVIEW_EXPIRED');
          }
          if (!reviewerUser.roles.includes('reviewer')) throw forbidden('NOT_A_REVIEWER');

          // SR-09: actor, acting_for, and the key owner may not approve their own action.
          const identities = [reviewerUser.id, reviewerUser.email];
          if (review.excluded.some((x) => identities.includes(x)))
            throw new AuditedRefusal(
              403,
              'POLICY.SOD_VIOLATION',
              {
                kind: 'review.sod_violation',
                actor: `user:${reviewer.userId}`,
                payload: { decision_id: decision.id, verdict },
              },
              'you are the actor, the acting-for principal, or the owner of the key that made this request',
            );
          const prior = await tx
            .select({ userId: approvals.userId })
            .from(approvals)
            .where(eq(approvals.reviewId, review.id));
          if (prior.some((a) => a.userId === reviewer.userId)) throw conflict('ALREADY_REVIEWED');

          await tx.insert(approvals).values({
            id: newId('apr'),
            orgId: reviewer.orgId,
            reviewId: review.id,
            userId: reviewer.userId,
            verdict,
            rationale: req.body.rationale ?? null,
          });
          await appendAudit(tx, reviewer.orgId, `review.${verdict}`, `user:${reviewer.userId}`, {
            decision_id: decision.id,
            rationale: req.body.rationale ?? null,
          });

          if (verdict === 'reject') {
            await tx
              .update(reviews)
              .set({ status: 'rejected', resolvedAt: new Date() })
              .where(eq(reviews.id, review.id));
            return {
              decision_id: decision.id,
              review_status: 'rejected' as const,
              approvals: prior.length,
              quorum: review.quorum,
              token_issued: false,
            };
          }

          const approverRows = await tx
            .select({ email: users.email })
            .from(approvals)
            .innerJoin(users, eq(users.id, approvals.userId))
            .where(and(eq(approvals.reviewId, review.id), eq(approvals.verdict, 'approve')));
          const count = approverRows.length;
          if (count < review.quorum)
            return {
              decision_id: decision.id,
              review_status: 'pending' as const,
              approvals: count,
              quorum: review.quorum,
              token_issued: false,
            };

          await tx
            .update(reviews)
            .set({ status: 'approved', resolvedAt: new Date() })
            .where(eq(reviews.id, review.id));
          const [keyRow] = await tx
            .select({ aud: apiKeys.receiverAud })
            .from(apiKeys)
            .where(eq(apiKeys.id, request.apiKeyId))
            .limit(1);
          const actingFor = request.actingFor as { id?: string } | null;
          await issueAndRecordToken(tx, deps, {
            orgId: reviewer.orgId,
            decisionId: decision.id,
            decision: 'REVIEW',
            actionHash: decision.actionHash,
            aud: keyRow?.aud ?? 'unknown',
            actor: String((request.actor as { id: string }).id),
            actingFor: actingFor?.id,
            approver: approverRows.map((a) => a.email),
            policySetVersion: decision.policySetVersion,
            auditActor: `user:${reviewer.userId}`,
          });
          await appendAudit(tx, reviewer.orgId, 'review.approved', `user:${reviewer.userId}`, {
            decision_id: decision.id,
            approvers: approverRows.map((a) => a.email),
            action_hash: decision.actionHash,
          });
          return {
            decision_id: decision.id,
            review_status: 'approved' as const,
            approvals: count,
            quorum: review.quorum,
            token_issued: true,
          };
        });
      },
    );
  }

  // ---------- POST /v1/tokens/consume ----------
  const ConsumeBody = z.object({ token: z.string(), aud: z.string(), action_hash: z.string() });
  app.post(
    '/v1/tokens/consume',
    {
      onRequest: requireApiKey(vera),
      schema: {
        body: ConsumeBody,
        response: { 200: z.object({ consumed: z.literal(true), jti: z.string() }), 409: ErrorSchema },
      },
    },
    async (req) => {
      const key = req.key!;
      const claims = decodeJwt(req.body.token);
      if (claims.tenant !== key.orgId) throw forbidden('TOKEN.TENANT_MISMATCH');
      return withTenantAudited(key.orgId, async (tx) => {
        const jwks = await tenantJwks(tx, key.orgId);
        const v = await verifyDecisionToken(req.body.token, jwks, {
          tenant: key.orgId,
          aud: req.body.aud,
          action_hash: req.body.action_hash,
        });
        if (!v.ok)
          throw new AuditedRefusal(
            v.code === 'TOKEN.EXPIRED' ? 410 : 403,
            v.code,
            {
              kind: 'token.rejected',
              actor: `key:${key.keyId}`,
              payload: { code: v.code, detail: v.detail ?? null },
            },
            v.detail,
          );
        const updated = await tx
          .update(decisionTokens)
          .set({ consumedAt: new Date() })
          .where(and(eq(decisionTokens.id, v.claims.jti), isNull(decisionTokens.consumedAt)))
          .returning({ id: decisionTokens.id });
        if (updated.length === 0)
          throw new AuditedRefusal(409, 'TOKEN.ALREADY_CONSUMED', {
            kind: 'token.replayed',
            actor: `key:${key.keyId}`,
            payload: { jti: v.claims.jti, decision_id: v.claims.sub },
          });
        await appendAudit(tx, key.orgId, 'token.consumed', `key:${key.keyId}`, {
          jti: v.claims.jti,
          decision_id: v.claims.sub,
        });
        return { consumed: true as const, jti: v.claims.jti };
      });
    },
  );

  // ---------- POST /v1/decisions/:id/outcome (adapter-reported: asserted) ----------
  const OutcomeBody = z.object({
    kind: z.enum(['executed', 'failed', 'reverted', 'incident', 'false_positive', 'hash_mismatch']),
    data: z.record(z.string(), z.unknown()).default({}),
  });
  app.post(
    '/v1/decisions/:id/outcome',
    {
      onRequest: requireApiKey(vera),
      schema: {
        params: z.object({ id: z.string() }),
        body: OutcomeBody,
        response: { 200: z.object({ recorded: z.literal(true) }) },
      },
    },
    async (req) => {
      const key = req.key!;
      await vera.withTenant(key.orgId, async (tx) => {
        const [d] = await tx
          .select({ id: decisions.id })
          .from(decisions)
          .where(eq(decisions.id, req.params.id))
          .limit(1);
        if (!d) throw notFound('decision');
        await tx.insert(outcomes).values({
          id: newId('out'),
          orgId: key.orgId,
          decisionId: d.id,
          source: 'adapter',
          trust: 'asserted',
          kind: req.body.kind,
          data: req.body.data,
        });
        await appendAudit(tx, key.orgId, 'outcome.recorded', `key:${key.keyId}`, {
          decision_id: d.id,
          kind: req.body.kind,
          trust: 'asserted',
        });

        // The outcome loop feeds the baseline (SR-20): what executed and stuck becomes history; what was
        // reverted, or executed something other than what was decided, is retracted from it.
        let touchedHistory = false;
        if (['reverted', 'incident', 'hash_mismatch'].includes(req.body.kind)) {
          // Rebuild immediately: a retraction that only lands in the next scheduled rollup would leave
          // VERA treating a reverted action as normal behaviour until something else happened to
          // trigger one.
          touchedHistory = await retractObservation(tx, key.orgId, d.id);
          if (touchedHistory) {
            const snapshot = await rebuildSnapshot(tx, key.orgId);
            await appendAudit(tx, key.orgId, 'baseline.observation_retracted', `key:${key.keyId}`, {
              decision_id: d.id,
              kind: req.body.kind,
              snapshot_id: snapshot.id,
            });
          }
        } else if (req.body.kind === 'executed') {
          touchedHistory = await recordObservation(tx, key.orgId, d.id);
          if (touchedHistory) {
            const snapshot = await rebuildSnapshotIfStale(tx, key.orgId, deps.baselineSnapshotMaxAgeMs);
            if (snapshot)
              await appendAudit(tx, key.orgId, 'baseline.snapshot_rebuilt', 'system', {
                snapshot_id: snapshot,
              });
          }
        }
      });
      return { recorded: true as const };
    },
  );

  /** Key management is an owner's job, not a reviewer's: revoking a key invalidates live approvals. */
  const assertAdmin = async (tx: Tx, reviewer: { orgId: string; userId: string }) => {
    const [me] = await tx.select().from(users).where(eq(users.id, reviewer.userId)).limit(1);
    if (!me?.roles.includes('admin')) throw forbidden('ADMIN_REQUIRED', 'this needs an administrator');
    return me;
  };

  // ---------- signing keys (SR-11, threat T14) ----------
  const KeySchema = z.object({
    kid: z.string(),
    status: z.enum(['active', 'retiring', 'revoked']),
    created_at: z.string(),
    rotated_at: z.string().nullable(),
    tokens_signed: z.number(),
  });

  app.get(
    '/v1/keys',
    {
      onRequest: requireReviewer(vera),
      schema: {
        response: {
          200: z.object({
            keys: z.array(KeySchema),
            parity: z.object({
              tokens_issued: z.number(),
              signatures_audited: z.number(),
              balanced: z.boolean(),
              note: z.string(),
            }),
          }),
        },
      },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      return vera.withTenant(reviewer.orgId, async (tx) => {
        await assertAdmin(tx, reviewer);
        return { keys: await listKeys(tx, reviewer.orgId), parity: await signingParity(tx, reviewer.orgId) };
      });
    },
  );

  app.post(
    '/v1/keys/rotate',
    {
      onRequest: requireReviewer(vera),
      schema: {
        response: { 200: z.object({ kid: z.string(), retired: z.string().nullable(), note: z.string() }) },
      },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      return vera.withTenant(reviewer.orgId, async (tx) => {
        await assertAdmin(tx, reviewer);
        const r = await rotateKey(tx, reviewer.orgId, deps.masterKey, `user:${reviewer.userId}`);
        return {
          ...r,
          note: r.retired
            ? `New tokens are signed with ${r.kid}. ${r.retired} still verifies until its last token expires, so nothing in flight breaks.`
            : `New tokens are signed with ${r.kid}.`,
        };
      });
    },
  );

  app.post(
    '/v1/keys/:kid/revoke',
    {
      onRequest: requireReviewer(vera),
      schema: {
        params: z.object({ kid: z.string() }),
        body: z.object({ reason: z.string().min(3).max(500) }),
        response: {
          200: z.object({
            revoked: z.string(),
            replacement: z.string().nullable(),
            tokens_invalidated: z.number(),
            note: z.string(),
          }),
        },
      },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      return vera.withTenant(reviewer.orgId, async (tx) => {
        await assertAdmin(tx, reviewer);
        const r = await revokeKey(
          tx,
          reviewer.orgId,
          req.params.kid,
          deps.masterKey,
          `user:${reviewer.userId}`,
          req.body.reason,
        );
        return {
          revoked: r.revoked,
          replacement: r.replacement,
          tokens_invalidated: r.tokensInvalidated,
          note: `${r.tokensInvalidated} token(s) signed by ${r.revoked} stopped verifying immediately, approved or not.${r.replacement ? ` New signing key: ${r.replacement}.` : ''}`,
        };
      });
    },
  );

  // ---------- the review queue (reviewer session) ----------
  const QueueItem = z.object({
    decision_id: z.string(),
    created_at: z.string(),
    expires_at: z.string(),
    status: z.enum(['pending', 'approved', 'rejected', 'expired']),
    actor: z.string(),
    acting_for: z.string().nullable(),
    action_class: z.string(),
    tool: z.string(),
    target: z.string(),
    environment: z.string().nullable(),
    risk: z.number(),
    top_reason: z.string().nullable(),
    quorum: z.number(),
    approvals: z.number(),
    /** Whether THIS reviewer is barred from deciding it (SR-09) — shown before they open it. */
    sod_blocked: z.boolean(),
  });

  app.get(
    '/v1/reviews',
    {
      onRequest: requireReviewer(vera),
      schema: {
        querystring: z.object({
          status: z.enum(['pending', 'approved', 'rejected', 'expired', 'all']).default('pending'),
          limit: z.coerce.number().int().min(1).max(200).default(50),
        }),
        response: { 200: z.object({ reviews: z.array(QueueItem) }) },
      },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      return vera.withTenant(reviewer.orgId, async (tx) => {
        const [me] = await tx.select().from(users).where(eq(users.id, reviewer.userId)).limit(1);
        const rows = await tx
          .select({ review: reviews, decision: decisions, request: actionRequests })
          .from(reviews)
          .innerJoin(decisions, eq(decisions.id, reviews.decisionId))
          .innerJoin(actionRequests, eq(actionRequests.id, decisions.actionRequestId))
          .where(
            req.query.status === 'all'
              ? eq(reviews.orgId, reviewer.orgId)
              : and(eq(reviews.orgId, reviewer.orgId), eq(reviews.status, req.query.status)),
          )
          .orderBy(desc(reviews.createdAt))
          .limit(req.query.limit);

        const counts = new Map<string, number>();
        if (rows.length > 0) {
          const approved = await tx
            .select({ reviewId: approvals.reviewId })
            .from(approvals)
            .where(and(eq(approvals.orgId, reviewer.orgId), eq(approvals.verdict, 'approve')));
          for (const a of approved) counts.set(a.reviewId, (counts.get(a.reviewId) ?? 0) + 1);
        }

        const identities = [me?.id, me?.email].filter((x): x is string => !!x);
        return {
          reviews: rows.map(({ review, decision, request }) => {
            const action = request.action as { class: string; tool: string; environment?: string };
            const target = request.target as { id?: string } | null;
            const codes = decision.reasonCodes as { code: string; severity: string }[];
            const top =
              codes.find((c) => c.severity === 'high') ?? codes.find((c) => c.severity === 'medium');
            return {
              decision_id: decision.id,
              created_at: decision.createdAt.toISOString(),
              expires_at: review.expiresAt.toISOString(),
              status: review.status,
              actor: String((request.actor as { id: string }).id),
              acting_for: (request.actingFor as { id?: string } | null)?.id ?? null,
              action_class: action.class,
              tool: action.tool,
              target: target?.id ?? '-',
              environment: action.environment ?? null,
              risk: decision.riskScore,
              top_reason: top?.code ?? null,
              quorum: review.quorum,
              approvals: counts.get(review.id) ?? 0,
              sod_blocked: review.excluded.some((x) => identities.includes(x)),
            };
          }),
        };
      });
    },
  );

  app.get(
    '/v1/reviews/:id',
    { onRequest: requireReviewer(vera), schema: { params: z.object({ id: z.string() }) } },
    async (req) => {
      const reviewer = req.reviewer!;
      const found = await vera.withTenant(reviewer.orgId, async (tx) => {
        const [row] = await tx
          .select({ review: reviews, decision: decisions, request: actionRequests })
          .from(decisions)
          .innerJoin(actionRequests, eq(actionRequests.id, decisions.actionRequestId))
          .leftJoin(reviews, eq(reviews.decisionId, decisions.id))
          .where(and(eq(decisions.orgId, reviewer.orgId), eq(decisions.id, req.params.id)))
          .limit(1);
        if (!row) return null;
        const [me] = await tx.select().from(users).where(eq(users.id, reviewer.userId)).limit(1);
        const priorApprovals = row.review
          ? await tx
              .select({
                verdict: approvals.verdict,
                rationale: approvals.rationale,
                at: approvals.createdAt,
                email: users.email,
              })
              .from(approvals)
              .innerJoin(users, eq(users.id, approvals.userId))
              .where(eq(approvals.reviewId, row.review.id))
          : [];
        const identities = [me?.id, me?.email].filter((x): x is string => !!x);
        const codes = row.decision.reasonCodes as {
          code: string;
          severity: string;
          policy_id?: string;
          detail?: string;
        }[];
        return {
          decision_id: row.decision.id,
          decision: row.decision.decision,
          created_at: row.decision.createdAt.toISOString(),
          expires_at: row.decision.expiresAt.toISOString(),
          risk: { score: row.decision.riskScore, calibrated: false },
          confidence: row.decision.confidence / 100,
          policy_set_version: row.decision.policySetVersion,
          baseline_snapshot_id: row.decision.baselineSnapshotId,
          actor: row.request.actor,
          acting_for: row.request.actingFor,
          /** Redacted (SR-15). `redaction` says what was removed. */
          action: row.request.action,
          redaction: row.request.redactionFindings,
          has_raw: row.request.actionRawSealed !== null,
          target: row.request.target,
          context: row.request.context,
          evidence: row.decision.evidence,
          reason_codes: codes.map((c) => {
            const def = REASON_CODES[c.code as keyof typeof REASON_CODES];
            return { ...c, description: def?.description ?? null, guidance: def?.guidance ?? null };
          }),
          review: row.review
            ? {
                status: row.review.status,
                quorum: row.review.quorum,
                routed_to: row.review.routedTo,
                excluded: row.review.excluded,
                sod_blocked: row.review.excluded.some((x) => identities.includes(x)),
                approvals: priorApprovals.map((a) => ({
                  by: a.email,
                  verdict: a.verdict,
                  rationale: a.rationale,
                  at: a.at.toISOString(),
                })),
              }
            : null,
        };
      });
      if (!found) throw notFound('decision');
      return found;
    },
  );

  /**
   * Reveal the raw, unredacted action. Separate endpoint, separate audit event, and the reviewer must
   * say why — so looking at a customer's secret is a deliberate act with a name attached (SR-15).
   */
  app.post(
    '/v1/decisions/:id/reveal',
    {
      onRequest: requireReviewer(vera),
      schema: {
        params: z.object({ id: z.string() }),
        body: z.object({ reason: z.string().min(3).max(500) }),
        response: { 200: z.object({ action: z.record(z.string(), z.unknown()) }), 404: ErrorSchema },
      },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      const action = await vera.withTenant(reviewer.orgId, async (tx) => {
        const [row] = await tx
          .select({ sealed: actionRequests.actionRawSealed, requestId: actionRequests.requestId })
          .from(decisions)
          .innerJoin(actionRequests, eq(actionRequests.id, decisions.actionRequestId))
          .where(and(eq(decisions.orgId, reviewer.orgId), eq(decisions.id, req.params.id)))
          .limit(1);
        if (!row?.sealed) return null;
        await appendAudit(tx, reviewer.orgId, 'request.raw_revealed', `user:${reviewer.userId}`, {
          decision_id: req.params.id,
          request_id: row.requestId,
          reason: req.body.reason,
        });
        return JSON.parse(unseal(row.sealed, deps.masterKey)) as Record<string, unknown>;
      });
      if (!action) throw notFound('raw action (nothing was redacted, or the decision does not exist)');
      return { action };
    },
  );

  // ---------- GET /v1/baselines (reviewer session) — the numbers behind BASELINE.* codes ----------
  app.get(
    '/v1/baselines',
    {
      onRequest: requireReviewer(vera),
      schema: {
        querystring: z.object({ actor: z.string().optional(), class: z.string().optional() }),
        response: {
          200: z.object({
            baselines: z.array(
              z.object({
                actor_id: z.string(),
                action_class: z.string(),
                observations: z.number(),
                distinct_targets: z.number(),
                first_seen: z.string(),
                last_seen: z.string(),
                magnitude_p50: z.number().nullable(),
                magnitude_p95: z.number().nullable(),
              }),
            ),
          }),
        },
      },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      const baselines = await vera.withTenant(reviewer.orgId, (tx) =>
        baselineExplain(tx, reviewer.orgId, req.query.actor, req.query.class),
      );
      return { baselines };
    },
  );

  // ---------- GET /v1/reports/policy-precision (reviewer session) — the outcome loop ----------
  app.get(
    '/v1/reports/policy-precision',
    {
      onRequest: requireReviewer(vera),
      schema: { querystring: z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }) },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      return vera.withTenant(reviewer.orgId, (tx) => policyPrecision(tx, reviewer.orgId, req.query.days));
    },
  );

  // ---------- GET /v1/audit-events (reviewer session) ----------
  const AuditEventSchema = z.object({
    seq: z.number(),
    kind: z.string(),
    actor: z.string(),
    payload: z.record(z.string(), z.unknown()),
    prev_hash: z.string(),
    hash: z.string(),
    created_at: z.string(),
  });
  app.get(
    '/v1/audit-events',
    {
      onRequest: requireReviewer(vera),
      schema: {
        querystring: z.object({
          after: z.coerce.number().int().default(0),
          limit: z.coerce.number().int().min(1).max(500).default(100),
        }),
        response: { 200: z.object({ events: z.array(AuditEventSchema) }) },
      },
    },
    async (req) => {
      const reviewer = req.reviewer!;
      const rows = await vera.withTenant(reviewer.orgId, (tx) =>
        tx
          .select()
          .from(auditEvents)
          .where(and(eq(auditEvents.orgId, reviewer.orgId), gt(auditEvents.seq, req.query.after)))
          .orderBy(asc(auditEvents.seq))
          .limit(req.query.limit),
      );
      return {
        events: rows.map((r) => ({
          seq: r.seq,
          kind: r.kind,
          actor: r.actor,
          payload: r.payload,
          prev_hash: r.prevHash,
          hash: r.hash,
          created_at: r.createdAt.toISOString(),
        })),
      };
    },
  );

  return app;
}

/** Rebuild a DecideResponse (+ review status) from stored rows. Used for idempotent replays and polling. */
async function loadDecisionResponse(
  tx: Tx,
  orgId: string,
  requestRowId: string,
  aud: string,
  deps: ServiceContext,
) {
  const [row] = await tx
    .select({ d: decisions, r: reviews })
    .from(decisions)
    .leftJoin(reviews, eq(reviews.decisionId, decisions.id))
    .where(and(eq(decisions.orgId, orgId), eq(decisions.actionRequestId, requestRowId)))
    .limit(1);
  if (!row) return null;
  const { d, r } = row;
  // The newest live token for this receiver — the ALLOW token, or the approval token once issued.
  // Only the receiver whose aud matches ever sees it; reviewers never do.
  const token = await liveTokenFor(tx, deps, d.id, aud);
  const review = d.review as { routed_to: string[]; sod: string; quorum: number } | null;
  return {
    decision_id: d.id,
    decision: d.decision,
    risk: { score: d.riskScore, calibrated: false },
    confidence: d.confidence / 100,
    reason_codes: d.reasonCodes as DecideResponse['reason_codes'],
    evidence: d.evidence as DecideResponse['evidence'],
    required_actions: d.requiredActions as DecideResponse['required_actions'],
    ...(review
      ? {
          review: {
            url: `${deps.publicUrl}/r/${d.id}`,
            routed_to: review.routed_to,
            sod: review.sod,
            quorum: review.quorum,
          },
        }
      : {}),
    action_hash: d.actionHash,
    policy_set_version: d.policySetVersion,
    ...(d.baselineSnapshotId ? { baseline_snapshot_id: d.baselineSnapshotId } : {}),
    supersedes: d.supersedes,
    expires_at: d.expiresAt.toISOString(),
    decision_token: token,
    review_status: r ? r.status : ('none' as const),
  };
}
