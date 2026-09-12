import { z } from 'zod';
import { ActionClassSchema } from './action-classes.js';

/**
 * The configuration an adapter is allowed to act on, signed by the tenant (SR-07, threats T19/T12).
 *
 * Two of the adapter's decisions are security-critical and both were local config until now:
 *
 *   - which action class a tool call is. Reclassify `deploy.production` as `file.read` and policy
 *     never sees it as consequential.
 *   - which classes may be allowed when VERA is unreachable. Add a consequential class to that list
 *     and an attacker can simply block the endpoint and proceed.
 *
 * A developer can edit a file on their own machine; a compromised agent can write files too. So the
 * table is fetched from VERA, signed with the tenant key, and verified before use. An unsigned,
 * foreign, or expired table is refused outright — the adapter falls back to its built-in conservative
 * defaults rather than to whatever is on disk.
 */

/** Distinct from the decision-token typ, so neither can ever be replayed as the other. */
export const ADAPTER_CONFIG_TYP = 'vera-adapter-config+jwt';

export const ToolClassRuleSchema = z.object({
  /** Anchored regular expression matched against the full tool name. */
  pattern: z.string().min(1).max(400),
  class: ActionClassSchema,
});
export type ToolClassRule = z.infer<typeof ToolClassRuleSchema>;

export const AdapterConfigSchema = z.object({
  version: z.number().int().nonnegative(),
  /** Exact tool name → class. Checked before the patterns. */
  tool_classes: z.record(z.string().min(1).max(300), ActionClassSchema).default({}),
  /** Ordered; first match wins. Applied after exact names, before the adapter's built-in heuristics. */
  tool_class_patterns: z.array(ToolClassRuleSchema).max(200).default([]),
  /**
   * Classes the adapter may allow on its own when VERA cannot be reached. Anything absent fails
   * closed. The server refuses to sign a bundle that puts a consequential class in here (SR-08).
   */
  fail_open_classes: z.array(ActionClassSchema).max(50).default([]),
  /** How long the adapter may hold a REVIEW waiting for a human. */
  hold_seconds: z.number().int().min(0).max(590).default(300),
  poll_interval_ms: z.number().int().min(200).max(30_000).default(2000),
});
export type AdapterConfig = z.infer<typeof AdapterConfigSchema>;

export const AdapterConfigClaimsSchema = z.object({
  iss: z.string().url(),
  aud: z.string().min(1).max(200),
  tenant: z.string().min(1).max(200),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().nonnegative(),
  config: AdapterConfigSchema,
});
export type AdapterConfigClaims = z.infer<typeof AdapterConfigClaimsSchema>;

/** A bundle is short-lived so a revoked key or a policy change reaches adapters quickly. */
export const DEFAULT_CONFIG_TTL_SECONDS = 60 * 60;
