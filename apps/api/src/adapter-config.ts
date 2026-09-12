import { appendAudit, schema, type Tx } from '@vera/db';
import { issueAdapterConfig } from '@vera/decision-token';
import { type AdapterConfig, AdapterConfigSchema, isConsequential } from '@vera/schemas';
import { eq } from 'drizzle-orm';
import { forbidden, notFound } from './errors.js';
import { issuerFor, type ServiceContext, tenantSigner } from './services.js';

const { organizations } = schema;

/**
 * The adapter's class table and fail-mode table, signed by the tenant (SR-07, threats T19/T12).
 *
 * The defaults below are deliberately dull: no tool overrides, and only genuinely read-only classes
 * permitted to proceed when VERA is unreachable. A tenant extends this through the API; nobody edits
 * it on the machine where the agent runs.
 */
export const DEFAULT_ADAPTER_CONFIG: AdapterConfig = AdapterConfigSchema.parse({
  version: 1,
  tool_classes: {},
  tool_class_patterns: [],
  fail_open_classes: ['file.read', 'vcs.read', 'http.read', 'db.read', 'search'],
  hold_seconds: 300,
  poll_interval_ms: 2000,
});

/**
 * Configuration must never be able to weaken policy. A tenant that could add `deploy.production` to
 * `fail_open_classes` would have created a one-line bypass: block the endpoint, and the deploy
 * proceeds unreviewed. The server refuses to sign such a bundle at all, so the refusal happens once,
 * centrally, rather than being enforced by every adapter's good behaviour.
 */
export function assertFailOpenIsSafe(config: AdapterConfig): void {
  const unsafe = config.fail_open_classes.filter((c) => isConsequential(c));
  if (unsafe.length > 0) {
    throw forbidden(
      'UNSAFE_FAIL_OPEN',
      `${unsafe.join(', ')} ${unsafe.length === 1 ? 'is' : 'are'} consequential and cannot fail open. An unreachable VERA is not an approval.`,
    );
  }
}

export async function getAdapterConfig(tx: Tx, orgId: string): Promise<AdapterConfig> {
  const [org] = await tx.select().from(organizations).where(eq(organizations.id, orgId)).limit(1);
  if (!org) throw notFound('organization');
  const stored = org.defaults.adapter_config;
  if (!stored) return DEFAULT_ADAPTER_CONFIG;
  const parsed = AdapterConfigSchema.safeParse(stored);
  // A stored bundle that no longer parses (a schema change, a bad write) falls back to the safe
  // defaults rather than being served half-understood.
  return parsed.success ? parsed.data : DEFAULT_ADAPTER_CONFIG;
}

export async function setAdapterConfig(
  tx: Tx,
  orgId: string,
  next: unknown,
  actor: string,
): Promise<AdapterConfig> {
  const [org] = await tx.select().from(organizations).where(eq(organizations.id, orgId)).limit(1);
  if (!org) throw notFound('organization');
  const current = await getAdapterConfig(tx, orgId);
  const parsed = AdapterConfigSchema.parse({ ...(next as object), version: current.version + 1 });
  assertFailOpenIsSafe(parsed);

  await tx
    .update(organizations)
    .set({ defaults: { ...org.defaults, adapter_config: parsed } })
    .where(eq(organizations.id, orgId));
  await appendAudit(tx, orgId, 'adapter_config.updated', actor, {
    version: parsed.version,
    tool_classes: Object.keys(parsed.tool_classes).length,
    patterns: parsed.tool_class_patterns.length,
    fail_open_classes: parsed.fail_open_classes,
  });
  return parsed;
}

/** Sign the current table for one receiver. Verified by the adapter against the tenant JWKS. */
export async function signAdapterConfig(
  tx: Tx,
  ctx: ServiceContext,
  orgId: string,
  aud: string,
): Promise<{ bundle: string; config: AdapterConfig }> {
  const config = await getAdapterConfig(tx, orgId);
  assertFailOpenIsSafe(config);
  const signer = await tenantSigner(tx, ctx, orgId);
  const bundle = await issueAdapterConfig({ iss: issuerFor(ctx, orgId), aud, tenant: orgId, config }, signer);
  return { bundle, config };
}
