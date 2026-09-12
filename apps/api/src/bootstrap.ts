import { appendAudit, newId, newSecret, schema, seal, type VeraDb } from '@vera/db';
import { exportPrivateJwk, generateTenantKey } from '@vera/decision-token';
import { compilePolicySet, POLICY_PACK_1 } from '@vera/policy-engine';

const { organizations, users, apiKeys, reviewerSessions, signingKeys, policySets } = schema;

export interface BootstrapParams {
  orgName: string;
  timezone?: string;
  adminEmail: string;
  adminName?: string;
  receiverAud?: string;
}

export interface BootstrapResult {
  orgId: string;
  userId: string;
  kid: string;
  policySetVersion: string;
  /** Shown once. Stored only as hashes. */
  apiKey: string;
  reviewerToken: string;
}

/**
 * Create a tenant with one admin user, a signing key, a per-user API key, a reviewer session, and
 * Policy Pack 1 activated. Used by `vera-api bootstrap` and by the integration tests.
 */
export async function bootstrapTenant(
  vera: VeraDb,
  masterKey: Buffer,
  p: BootstrapParams,
): Promise<BootstrapResult> {
  compilePolicySet(POLICY_PACK_1); // refuse to bootstrap with a policy pack that does not compile
  const orgId = newId('org');
  const userId = newId('usr');
  const key = await generateTenantKey();
  const privateJwk = await exportPrivateJwk(key);
  const api = newSecret('vera_sk');
  const session = newSecret('vera_rs');

  await vera.withTenant(orgId, async (tx) => {
    await tx.insert(organizations).values({ id: orgId, name: p.orgName, timezone: p.timezone ?? 'UTC' });
    await tx
      .insert(users)
      .values({
        id: userId,
        orgId,
        email: p.adminEmail,
        name: p.adminName ?? p.adminEmail,
        roles: ['admin', 'reviewer'],
      });
    await tx.insert(signingKeys).values({
      id: newId('sk'),
      orgId,
      kid: key.kid,
      publicJwk: key.publicJwk,
      privateJwkSealed: seal(JSON.stringify(privateJwk), masterKey),
    });
    await tx.insert(apiKeys).values({
      id: newId('key'),
      orgId,
      ownerUserId: userId,
      keyHash: api.hash,
      prefix: api.display,
      receiverAud: p.receiverAud ?? `adapter:${p.adminEmail}`,
    });
    await tx.insert(reviewerSessions).values({
      id: newId('ses'),
      orgId,
      userId,
      tokenHash: session.hash,
      expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000),
    });
    await tx.insert(policySets).values({
      id: newId('ps'),
      orgId,
      version: 1,
      policies: POLICY_PACK_1,
      status: 'active',
      activatedBy: userId,
      activatedAt: new Date(),
    });
    await appendAudit(tx, orgId, 'tenant.bootstrapped', `user:${userId}`, {
      org: p.orgName,
      admin: p.adminEmail,
      kid: key.kid,
      policy_set: 'ps_1',
    });
  });

  return {
    orgId,
    userId,
    kid: key.kid,
    policySetVersion: 'ps_1',
    apiKey: api.secret,
    reviewerToken: session.secret,
  };
}

/** Add a user with a reviewer session (tests, and `vera-api add-user`). */
export async function addReviewer(
  vera: VeraDb,
  orgId: string,
  email: string,
  name = email,
): Promise<{ userId: string; reviewerToken: string }> {
  const userId = newId('usr');
  const session = newSecret('vera_rs');
  await vera.withTenant(orgId, async (tx) => {
    await tx.insert(users).values({ id: userId, orgId, email, name, roles: ['reviewer'] });
    await tx
      .insert(reviewerSessions)
      .values({
        id: newId('ses'),
        orgId,
        userId,
        tokenHash: session.hash,
        expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000),
      });
    await appendAudit(tx, orgId, 'user.created', 'system', { user_id: userId, email, roles: ['reviewer'] });
  });
  return { userId, reviewerToken: session.secret };
}
