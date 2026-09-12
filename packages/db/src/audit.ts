import { createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import { asc, desc, eq, sql } from 'drizzle-orm';
import type { Tx } from './client.js';
import { auditEvents } from './schema.js';

const GENESIS = 'genesis';

export function auditHash(
  prevHash: string,
  seq: number,
  kind: string,
  actor: string,
  payload: Record<string, unknown>,
): string {
  const body = canonicalize(payload) ?? '{}';
  return createHash('sha256').update(`${prevHash}\n${seq}\n${kind}\n${actor}\n${body}`, 'utf8').digest('hex');
}

/**
 * Append one event to the tenant's chain. Serialised per tenant with an advisory lock so `seq` and
 * `prev_hash` are always consistent under concurrency. Must run inside `withTenant`.
 */
export async function appendAudit(
  tx: Tx,
  orgId: string,
  kind: string,
  actor: string,
  payload: Record<string, unknown>,
): Promise<{ seq: number; hash: string }> {
  await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${orgId}))`);
  const [last] = await tx
    .select({ seq: auditEvents.seq, hash: auditEvents.hash })
    .from(auditEvents)
    .where(eq(auditEvents.orgId, orgId))
    .orderBy(desc(auditEvents.seq))
    .limit(1);
  const seq = (last?.seq ?? 0) + 1;
  const prevHash = last?.hash ?? GENESIS;
  const hash = auditHash(prevHash, seq, kind, actor, payload);
  await tx.insert(auditEvents).values({ orgId, seq, kind, actor, payload, prevHash, hash });
  return { seq, hash };
}

export interface ChainVerification {
  ok: boolean;
  length: number;
  head: string | null;
  /** First sequence number where the chain breaks, if any. */
  brokenAt?: number;
}

/** Recompute the whole chain. Used by tools/verify-chain and the SR-16 test. */
export async function verifyChain(tx: Tx, orgId: string): Promise<ChainVerification> {
  const rows = await tx
    .select()
    .from(auditEvents)
    .where(eq(auditEvents.orgId, orgId))
    .orderBy(asc(auditEvents.seq));
  let prev = GENESIS;
  let expectedSeq = 1;
  for (const r of rows) {
    if (
      r.seq !== expectedSeq ||
      r.prevHash !== prev ||
      auditHash(prev, r.seq, r.kind, r.actor, r.payload) !== r.hash
    ) {
      return { ok: false, length: rows.length, head: rows.at(-1)?.hash ?? null, brokenAt: r.seq };
    }
    prev = r.hash;
    expectedSeq += 1;
  }
  return { ok: true, length: rows.length, head: rows.at(-1)?.hash ?? null };
}
