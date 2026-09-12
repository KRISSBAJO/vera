import { appendAudit, newId, schema, type VeraDb } from '@vera/db';
import { compilePolicySet } from '@vera/policy-engine';
import { and, desc, eq } from 'drizzle-orm';

const { policySets } = schema;

/**
 * Activate a new policy-set version for a tenant: compile (refuses anything that does not validate),
 * insert as version max+1, retire the previous active set, audit. The dashboard's policy editor will
 * call the same function; until then `vera-api activate-policies` does.
 */
export async function activatePolicySet(
  vera: VeraDb,
  orgId: string,
  text: string,
  activatedBy: string | null,
  note: string,
): Promise<{ id: string; version: number; policies: number; retired: number | null }> {
  const compiled = compilePolicySet(text);
  return vera.withTenant(orgId, async (tx) => {
    const [latest] = await tx
      .select({ version: policySets.version })
      .from(policySets)
      .where(eq(policySets.orgId, orgId))
      .orderBy(desc(policySets.version))
      .limit(1);
    const [active] = await tx
      .select({ id: policySets.id, version: policySets.version })
      .from(policySets)
      .where(and(eq(policySets.orgId, orgId), eq(policySets.status, 'active')))
      .limit(1);
    const version = (latest?.version ?? 0) + 1;
    const id = newId('ps');
    if (active) await tx.update(policySets).set({ status: 'retired' }).where(eq(policySets.id, active.id));
    await tx.insert(policySets).values({
      id,
      orgId,
      version,
      policies: text,
      status: 'active',
      activatedBy,
      activatedAt: new Date(),
    });
    await appendAudit(tx, orgId, 'policy_set.activated', activatedBy ? `user:${activatedBy}` : 'system', {
      policy_set: `ps_${version}`,
      retired: active ? `ps_${active.version}` : null,
      policies: Object.keys(compiled.policies),
      note,
    });
    return { id, version, policies: Object.keys(compiled.policies).length, retired: active?.version ?? null };
  });
}
