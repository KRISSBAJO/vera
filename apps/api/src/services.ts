import { appendAudit, newId, schema, seal, type Tx, unseal } from '@vera/db';
import { importTenantKey, issueDecisionToken, localSigner, type Signer } from '@vera/decision-token';
import { type CompiledPolicySet, compilePolicySet } from '@vera/policy-engine';
import { TenantJwksSchema } from '@vera/schemas';
import { and, desc, eq, gt, inArray, isNull } from 'drizzle-orm';
import { decodeJwt } from 'jose';
import { notFound } from './errors.js';

const { policySets, signingKeys, decisionTokens } = schema;

export interface ServiceContext {
  masterKey: Buffer;
  publicUrl: string;
}

// ---------- policy sets ----------

const compiledCache = new Map<string, CompiledPolicySet>();

/** The tenant's active policy set, compiled once per (org, version). */
export async function activePolicySet(
  tx: Tx,
  orgId: string,
): Promise<{ compiled: CompiledPolicySet; version: string; weights: Record<string, number> }> {
  const [row] = await tx
    .select({
      id: policySets.id,
      version: policySets.version,
      policies: policySets.policies,
      weights: policySets.weights,
    })
    .from(policySets)
    .where(and(eq(policySets.orgId, orgId), eq(policySets.status, 'active')))
    .limit(1);
  if (!row) throw notFound('active policy set');
  const version = `ps_${row.version}`;
  const cacheKey = `${orgId}:${row.id}`;
  let compiled = compiledCache.get(cacheKey);
  if (!compiled) {
    compiled = compilePolicySet(row.policies);
    compiledCache.set(cacheKey, compiled);
  }
  return { compiled, version, weights: row.weights };
}

// ---------- signing ----------

const signerCache = new Map<string, Signer>();

/** Active signing key for the tenant, unsealed once and cached by kid. Production swaps this for a KMS Signer (ADR-0001). */
export async function tenantSigner(tx: Tx, ctx: ServiceContext, orgId: string): Promise<Signer> {
  const [row] = await tx
    .select({ kid: signingKeys.kid, publicJwk: signingKeys.publicJwk, sealed: signingKeys.privateJwkSealed })
    .from(signingKeys)
    .where(and(eq(signingKeys.orgId, orgId), eq(signingKeys.status, 'active')))
    .limit(1);
  if (!row) throw notFound('active signing key');
  const cacheKey = `${orgId}:${row.kid}`;
  let signer = signerCache.get(cacheKey);
  if (!signer) {
    const privateJwk = JSON.parse(unseal(row.sealed, ctx.masterKey)) as Record<string, unknown>;
    const key = await importTenantKey(privateJwk, row.publicJwk);
    signer = localSigner(key);
    signerCache.set(cacheKey, signer);
  }
  return signer;
}

export async function tenantJwks(tx: Tx, orgId: string) {
  const rows = await tx
    .select({ kid: signingKeys.kid, publicJwk: signingKeys.publicJwk, status: signingKeys.status })
    .from(signingKeys)
    .where(and(eq(signingKeys.orgId, orgId), inArray(signingKeys.status, ['active', 'retiring', 'revoked'])));
  return TenantJwksSchema.parse({
    keys: rows.filter((r) => r.status !== 'revoked').map((r) => r.publicJwk),
    revoked: rows.filter((r) => r.status === 'revoked').map((r) => r.kid),
  });
}

export const issuerFor = (ctx: ServiceContext, orgId: string) => `${ctx.publicUrl}/t/${orgId}`;

export interface IssueParams {
  orgId: string;
  decisionId: string;
  decision: 'ALLOW' | 'REVIEW';
  actionHash: string;
  aud: string;
  actor: string;
  actingFor?: string | undefined;
  approver?: string[] | undefined;
  policySetVersion: string;
  ttlSeconds?: number | undefined;
  /** Who caused the signature, for the 1:1 audit parity check (SR-11). */
  auditActor: string;
}

/** Issue a decision token and record its jti for single-use enforcement (SR-10). */
export async function issueAndRecordToken(tx: Tx, ctx: ServiceContext, p: IssueParams): Promise<string> {
  const signer = await tenantSigner(tx, ctx, p.orgId);
  const jti = newId('jti');
  const token = await issueDecisionToken(
    {
      iss: issuerFor(ctx, p.orgId),
      sub: p.decisionId,
      jti,
      aud: p.aud,
      tenant: p.orgId,
      decision: p.decision,
      action_hash: p.actionHash,
      actor: p.actor,
      ...(p.actingFor ? { acting_for: p.actingFor } : {}),
      ...(p.approver ? { approver: p.approver } : {}),
      policy_set_version: p.policySetVersion,
      ...(p.ttlSeconds !== undefined ? { ttlSeconds: p.ttlSeconds } : {}),
    },
    signer,
  );
  const exp = decodeJwt(token).exp ?? 0;
  await tx.insert(decisionTokens).values({
    id: jti,
    orgId: p.orgId,
    decisionId: p.decisionId,
    aud: p.aud,
    actionHash: p.actionHash,
    signingKid: signer.kid,
    tokenSealed: seal(token, ctx.masterKey),
    expiresAt: new Date(exp * 1000),
  });
  // SR-11: one audit event per signature, so `signingParity` can prove nothing signed off-path.
  await appendAudit(tx, p.orgId, 'token.issued', p.auditActor, {
    jti,
    decision_id: p.decisionId,
    kid: signer.kid,
    aud: p.aud,
    expires_at: new Date(exp * 1000).toISOString(),
  });
  return token;
}

/** The newest live (unconsumed, unexpired) token for a decision and receiver, or null. */
export async function liveTokenFor(
  tx: Tx,
  ctx: ServiceContext,
  decisionId: string,
  aud: string,
): Promise<string | null> {
  const [row] = await tx
    .select({ sealed: decisionTokens.tokenSealed })
    .from(decisionTokens)
    .where(
      and(
        eq(decisionTokens.decisionId, decisionId),
        eq(decisionTokens.aud, aud),
        isNull(decisionTokens.consumedAt),
        gt(decisionTokens.expiresAt, new Date()),
      ),
    )
    .orderBy(desc(decisionTokens.createdAt))
    .limit(1);
  return row?.sealed ? unseal(row.sealed, ctx.masterKey) : null;
}
