import { randomBytes } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { appendAudit, verifyChain } from './audit.js';
import { createDb, type VeraDb } from './client.js';
import { actionRequests, apiKeys, auditEvents, organizations, users } from './schema.js';
import { hashSecret, newId, newSecret, seal, unseal } from './seal.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';

/** Drizzle wraps Postgres errors ("Failed query: …"); the database's own message is in `cause`. */
async function rejectsWith(promise: Promise<unknown>, pattern: RegExp): Promise<void> {
  try {
    await promise;
  } catch (e) {
    const err = e as Error & { cause?: Error };
    const message = `${err.message}\n${err.cause?.message ?? ''}`;
    if (!pattern.test(message)) throw new Error(`rejected, but not with ${pattern}: ${message}`);
    return;
  }
  throw new Error(`expected rejection matching ${pattern}, but the promise resolved`);
}

let vera: VeraDb;
const orgA = newId('org');
const orgB = newId('org');
const userA = newId('usr');
const userB = newId('usr');

async function createOrg(orgId: string, userId: string, email: string) {
  await vera.withTenant(orgId, async (tx) => {
    await tx.insert(organizations).values({ id: orgId, name: orgId });
    await tx.insert(users).values({ id: userId, orgId, email, name: email });
  });
}

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  await createOrg(orgA, userA, 'a@example.com');
  await createOrg(orgB, userB, 'b@example.com');
});

afterAll(async () => {
  await vera.close();
});

describe('SR-14 tenant isolation', () => {
  it('a tenant sees only its own rows', async () => {
    const seenByA = await vera.withTenant(orgA, (tx) => tx.select({ id: users.id }).from(users));
    expect(seenByA.map((u) => u.id)).toEqual([userA]);
    const seenByB = await vera.withTenant(orgB, (tx) => tx.select({ id: users.id }).from(users));
    expect(seenByB.map((u) => u.id)).toEqual([userB]);
  });

  it('without a tenant context nothing is visible, even to the table owner (FORCE RLS)', async () => {
    const rows = await vera.db.select({ id: users.id }).from(users);
    expect(rows).toEqual([]);
    const orgs = await vera.db.select({ id: organizations.id }).from(organizations);
    expect(orgs).toEqual([]);
  });

  it('a tenant cannot read another tenant by id, nor write into it', async () => {
    const crossRead = await vera.withTenant(orgA, (tx) => tx.select().from(users).where(eq(users.id, userB)));
    expect(crossRead).toEqual([]);
    await rejectsWith(
      vera.withTenant(orgA, (tx) =>
        tx.insert(users).values({ id: newId('usr'), orgId: orgB, email: 'x@b', name: 'x' }),
      ),
      /row-level security/,
    );
  });

  it('auth lookup can find a key by hash without a tenant, but cannot write', async () => {
    const { secret, hash, display } = newSecret('vera_sk');
    await vera.withTenant(orgA, (tx) =>
      tx
        .insert(apiKeys)
        .values({
          id: newId('key'),
          orgId: orgA,
          ownerUserId: userA,
          keyHash: hash,
          prefix: display,
          receiverAud: 'adapter:test',
        }),
    );
    const found = await vera.withAuthLookup((tx) =>
      tx
        .select({ orgId: apiKeys.orgId })
        .from(apiKeys)
        .where(eq(apiKeys.keyHash, hashSecret(secret))),
    );
    expect(found).toEqual([{ orgId: orgA }]);
    await rejectsWith(
      vera.withAuthLookup((tx) =>
        tx
          .insert(apiKeys)
          .values({
            id: newId('key'),
            orgId: orgA,
            ownerUserId: userA,
            keyHash: 'x',
            prefix: 'x',
            receiverAud: 'x',
          }),
      ),
      /row-level security/,
    );
  });

  it('SR-13 idempotency keys are unique per tenant', async () => {
    const keyId = newId('key');
    await vera.withTenant(orgA, (tx) =>
      tx
        .insert(apiKeys)
        .values({
          id: keyId,
          orgId: orgA,
          ownerUserId: userA,
          keyHash: newSecret('vera_sk').hash,
          prefix: 'x',
          receiverAud: 'x',
        }),
    );
    const row = {
      orgId: orgA,
      requestId: 'req_1',
      idempotencyKey: 'idem-1',
      bodyHash: 'h',
      apiKeyId: keyId,
      actor: { id: 'a' },
      action: { tool: 'Bash' },
      actionHash: `sha256:${'0'.repeat(64)}`,
    };
    await vera.withTenant(orgA, (tx) => tx.insert(actionRequests).values({ ...row, id: newId('req') }));
    await rejectsWith(
      vera.withTenant(orgA, (tx) => tx.insert(actionRequests).values({ ...row, id: newId('req') })),
      /unique|duplicate/,
    );
    // Same key in another tenant is fine.
    await vera.withTenant(orgB, async (tx) => {
      const keyB = newId('key');
      await tx
        .insert(apiKeys)
        .values({
          id: keyB,
          orgId: orgB,
          ownerUserId: userB,
          keyHash: newSecret('vera_sk').hash,
          prefix: 'x',
          receiverAud: 'x',
        });
      await tx.insert(actionRequests).values({ ...row, id: newId('req'), orgId: orgB, apiKeyId: keyB });
    });
  });
});

describe('SR-16 audit chain', () => {
  it('appends a verifiable chain and refuses mutation', async () => {
    await vera.withTenant(orgA, async (tx) => {
      await appendAudit(tx, orgA, 'test.one', 'system', { n: 1 });
      await appendAudit(tx, orgA, 'test.two', 'system', { n: 2, nested: { b: 1, a: 2 } });
      await appendAudit(tx, orgA, 'test.three', 'system', {});
    });
    const v = await vera.withTenant(orgA, (tx) => verifyChain(tx, orgA));
    expect(v).toMatchObject({ ok: true, length: 3 });

    await rejectsWith(
      vera.withTenant(orgA, (tx) =>
        tx.update(auditEvents).set({ kind: 'tampered' }).where(eq(auditEvents.orgId, orgA)),
      ),
      /append-only/,
    );
    await rejectsWith(
      vera.withTenant(orgA, (tx) => tx.delete(auditEvents).where(eq(auditEvents.orgId, orgA))),
      /append-only/,
    );
  });

  it('detects a forged link (wrong prev_hash) at the exact sequence number', async () => {
    await vera.withTenant(orgB, async (tx) => {
      await appendAudit(tx, orgB, 'ok', 'system', {});
      await tx
        .insert(auditEvents)
        .values({
          orgId: orgB,
          seq: 2,
          kind: 'forged',
          actor: 'x',
          payload: {},
          prevHash: 'not-the-real-one',
          hash: 'whatever',
        });
    });
    const v = await vera.withTenant(orgB, (tx) => verifyChain(tx, orgB));
    expect(v).toMatchObject({ ok: false, brokenAt: 2 });
  });

  it('chains are per tenant and serialised under concurrency', async () => {
    await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        vera.withTenant(orgA, (tx) => appendAudit(tx, orgA, 'concurrent', 'system', { i })),
      ),
    );
    const v = await vera.withTenant(orgA, (tx) => verifyChain(tx, orgA));
    expect(v).toMatchObject({ ok: true, length: 11 });
    const seqs = await vera.withTenant(orgA, (tx) =>
      tx.select({ seq: auditEvents.seq }).from(auditEvents).where(eq(auditEvents.orgId, orgA)),
    );
    expect(new Set(seqs.map((s) => s.seq)).size).toBe(11);
  });
});

describe('sealing', () => {
  it('round-trips under the master key and fails under another', () => {
    const k1 = randomBytes(32);
    const k2 = randomBytes(32);
    const sealed = seal('{"kty":"OKP"}', k1);
    expect(unseal(sealed, k1)).toBe('{"kty":"OKP"}');
    expect(() => unseal(sealed, k2)).toThrow();
    expect(sealed).not.toContain('OKP');
  });

  it('set_config is transaction-local: the tenant does not leak to the next transaction', async () => {
    await vera.withTenant(orgA, (tx) => tx.execute(sql`select 1`));
    const rows = await vera.db.select({ id: users.id }).from(users);
    expect(rows).toEqual([]);
  });
});
