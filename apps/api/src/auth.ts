import { hashSecret, schema, type VeraDb } from '@vera/db';
import { and, eq, gt, isNull } from 'drizzle-orm';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { unauthorized } from './errors.js';

const { apiKeys, reviewerSessions } = schema;

/** The principal behind an API key: scope `decide` only (ADR-0003). */
export interface KeyPrincipal {
  kind: 'api_key';
  orgId: string;
  keyId: string;
  ownerUserId: string;
  ownerKind: 'user' | 'service';
  receiverAud: string;
}

/** A reviewer session: the only credential that may approve, reject, or read audit (ADR-0003 §4). */
export interface ReviewerPrincipal {
  kind: 'reviewer';
  orgId: string;
  userId: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    key?: KeyPrincipal;
    reviewer?: ReviewerPrincipal;
  }
}

function bearer(req: FastifyRequest): string | undefined {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return undefined;
  return h.slice(7).trim();
}

/**
 * Credential lookup happens before the tenant is known, so it uses the auth-lookup carve-out; the
 * tenant for everything that follows comes from the credential row, never from the request (SR-14).
 */
export async function authenticateApiKey(
  vera: VeraDb,
  secret: string | undefined,
): Promise<KeyPrincipal | null> {
  if (!secret?.startsWith('vera_sk_')) return null;
  const hash = hashSecret(secret);
  const [row] = await vera.withAuthLookup((tx) =>
    tx
      .select({
        orgId: apiKeys.orgId,
        keyId: apiKeys.id,
        ownerUserId: apiKeys.ownerUserId,
        ownerKind: apiKeys.kind,
        receiverAud: apiKeys.receiverAud,
      })
      .from(apiKeys)
      .where(and(eq(apiKeys.keyHash, hash), isNull(apiKeys.revokedAt)))
      .limit(1),
  );
  return row ? { kind: 'api_key', ...row } : null;
}

export async function authenticateReviewer(
  vera: VeraDb,
  secret: string | undefined,
): Promise<ReviewerPrincipal | null> {
  if (!secret?.startsWith('vera_rs_')) return null;
  const hash = hashSecret(secret);
  const [row] = await vera.withAuthLookup((tx) =>
    tx
      .select({ orgId: reviewerSessions.orgId, userId: reviewerSessions.userId })
      .from(reviewerSessions)
      .where(
        and(
          eq(reviewerSessions.tokenHash, hash),
          isNull(reviewerSessions.revokedAt),
          gt(reviewerSessions.expiresAt, new Date()),
        ),
      )
      .limit(1),
  );
  return row ? { kind: 'reviewer', ...row } : null;
}

/**
 * These are registered as `onRequest` hooks, not `preHandler`: Fastify validates the body before
 * preHandler runs, which would let an unauthenticated caller probe request schemas and learn what
 * VERA accepts. Authentication answers first; only then does the request get parsed.
 */
export function requireApiKey(vera: VeraDb) {
  return async (req: FastifyRequest, _reply: FastifyReply) => {
    const key = await authenticateApiKey(vera, bearer(req));
    if (!key) throw unauthorized('API_KEY_REQUIRED');
    req.key = key;
  };
}

export function requireReviewer(vera: VeraDb) {
  return async (req: FastifyRequest, _reply: FastifyReply) => {
    const reviewer = await authenticateReviewer(vera, bearer(req));
    if (!reviewer) throw unauthorized('REVIEWER_SESSION_REQUIRED');
    req.reviewer = reviewer;
  };
}
