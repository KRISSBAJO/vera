import { appendAudit, newId, schema, seal, type Tx } from '@vera/db';
import { exportPrivateJwk, generateTenantKey } from '@vera/decision-token';
import { and, count, eq } from 'drizzle-orm';
import { conflict, notFound } from './errors.js';

const { signingKeys, decisionTokens, auditEvents } = schema;

/**
 * Key lifecycle (SR-11, threat T14).
 *
 * A valid signature *is* an approval, so the signing key is the most valuable thing VERA holds. Three
 * states, and the difference between the last two is the whole point:
 *
 *   active    — signs new tokens. Exactly one per tenant.
 *   retiring  — signs nothing, but still verifies. Tokens minted seconds before a rotation have to
 *               keep working until they expire, or rotation would break every agent mid-flight.
 *   revoked   — verifies nothing, immediately. Published in the JWKS `revoked` list rather than
 *               silently dropped, so a receiver can tell "this key was withdrawn" from "I have never
 *               heard of this key" — one is an incident, the other is a stale cache.
 *
 * Rotation is routine and safe. Revocation is an incident response and deliberately abrupt: it
 * invalidates every token that key ever signed, including ones a human approved a minute ago.
 */

export interface KeyRow {
  kid: string;
  status: 'active' | 'retiring' | 'revoked';
  created_at: string;
  rotated_at: string | null;
  tokens_signed: number;
}

export async function listKeys(tx: Tx, orgId: string): Promise<KeyRow[]> {
  const rows = await tx.select().from(signingKeys).where(eq(signingKeys.orgId, orgId));
  const counts = await tx
    .select({ kid: decisionTokens.signingKid, n: count() })
    .from(decisionTokens)
    .where(eq(decisionTokens.orgId, orgId))
    .groupBy(decisionTokens.signingKid);
  const byKid = new Map(counts.map((c) => [c.kid, Number(c.n)]));
  return rows
    .map((r) => ({
      kid: r.kid,
      status: r.status,
      created_at: r.createdAt.toISOString(),
      rotated_at: r.rotatedAt?.toISOString() ?? null,
      tokens_signed: byKid.get(r.kid) ?? 0,
    }))
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
}

/**
 * Mint a new active key and move the current one to `retiring`. Tokens already in flight keep
 * verifying until they expire; nothing new is signed with the old key.
 */
export async function rotateKey(
  tx: Tx,
  orgId: string,
  masterKey: Buffer,
  actor: string,
): Promise<{ kid: string; retired: string | null }> {
  const [current] = await tx
    .select({ id: signingKeys.id, kid: signingKeys.kid })
    .from(signingKeys)
    .where(and(eq(signingKeys.orgId, orgId), eq(signingKeys.status, 'active')))
    .limit(1);

  const key = await generateTenantKey();
  const privateJwk = await exportPrivateJwk(key);

  if (current) {
    await tx
      .update(signingKeys)
      .set({ status: 'retiring', rotatedAt: new Date() })
      .where(eq(signingKeys.id, current.id));
  }
  await tx.insert(signingKeys).values({
    id: newId('sk'),
    orgId,
    kid: key.kid,
    publicJwk: key.publicJwk,
    privateJwkSealed: seal(JSON.stringify(privateJwk), masterKey),
    status: 'active',
  });

  await appendAudit(tx, orgId, 'signing_key.rotated', actor, {
    new_kid: key.kid,
    retired_kid: current?.kid ?? null,
  });
  return { kid: key.kid, retired: current?.kid ?? null };
}

/**
 * Withdraw a key immediately. Every token it signed stops verifying, whether or not it has expired
 * and whether or not a human approved it — that is what makes this incident response rather than
 * housekeeping.
 *
 * Revoking the active key leaves the tenant unable to sign, so a replacement is minted in the same
 * transaction. Refusing to revoke without a replacement would be worse: it would mean the fastest
 * response to a stolen key is unavailable exactly when it is needed.
 */
export async function revokeKey(
  tx: Tx,
  orgId: string,
  kid: string,
  masterKey: Buffer,
  actor: string,
  reason: string,
): Promise<{ revoked: string; replacement: string | null; tokensInvalidated: number }> {
  const [key] = await tx
    .select()
    .from(signingKeys)
    .where(and(eq(signingKeys.orgId, orgId), eq(signingKeys.kid, kid)))
    .limit(1);
  if (!key) throw notFound(`signing key ${kid}`);
  if (key.status === 'revoked') throw conflict('KEY_ALREADY_REVOKED', `${kid} was already revoked`);

  const signed = await tx
    .select({ n: count() })
    .from(decisionTokens)
    .where(and(eq(decisionTokens.orgId, orgId), eq(decisionTokens.signingKid, kid)));
  const n = signed[0]?.n ?? 0;

  await tx
    .update(signingKeys)
    .set({ status: 'revoked', rotatedAt: new Date() })
    .where(eq(signingKeys.id, key.id));

  let replacement: string | null = null;
  if (key.status === 'active') {
    const fresh = await generateTenantKey();
    const privateJwk = await exportPrivateJwk(fresh);
    await tx.insert(signingKeys).values({
      id: newId('sk'),
      orgId,
      kid: fresh.kid,
      publicJwk: fresh.publicJwk,
      privateJwkSealed: seal(JSON.stringify(privateJwk), masterKey),
      status: 'active',
    });
    replacement = fresh.kid;
  }

  await appendAudit(tx, orgId, 'signing_key.revoked', actor, {
    kid,
    reason,
    was: key.status,
    replacement,
    tokens_invalidated: Number(n),
  });
  return { revoked: kid, replacement, tokensInvalidated: Number(n) };
}

export interface SigningParity {
  tokens_issued: number;
  signatures_audited: number;
  balanced: boolean;
  note: string;
}

/**
 * SR-11: every signature must be accounted for. If VERA signed more often than it recorded issuing a
 * token, something is signing that is not the decision path — which is exactly what a stolen key, or
 * a code path that forgot to write its audit event, looks like from the outside.
 */
export async function signingParity(tx: Tx, orgId: string): Promise<SigningParity> {
  const tokenRows = await tx
    .select({ n: count() })
    .from(decisionTokens)
    .where(eq(decisionTokens.orgId, orgId));
  const tokens = tokenRows[0]?.n ?? 0;
  const auditRows = await tx
    .select({ n: count() })
    .from(auditEvents)
    .where(and(eq(auditEvents.orgId, orgId), eq(auditEvents.kind, 'token.issued')));
  const audited = auditRows[0]?.n ?? 0;
  const balanced = Number(tokens) === Number(audited);
  return {
    tokens_issued: Number(tokens),
    signatures_audited: Number(audited),
    balanced,
    note: balanced
      ? 'Every token VERA signed has a matching audit event.'
      : 'These must match. A gap means something signed outside the decision path, or an audit write was lost — investigate before trusting any token from this tenant.',
  };
}
