import { z } from 'zod';
import { ActionHashSchema, DecisionSchema } from './decide.js';

/** JOSE header `typ` for VERA decision tokens. Receivers must reject any other typ. */
export const DECISION_TOKEN_TYP = 'vera-decision+jwt';

/** Default lifetimes (brief §6.3, SR-10). Tenants may shorten, never lengthen. */
export const DEFAULT_ALLOW_TTL_SECONDS = 10 * 60;
export const DEFAULT_APPROVAL_TTL_SECONDS = 15 * 60;

/**
 * Claims of a signed decision token. `iat`/`exp` are NumericDate (seconds) per RFC 7519.
 * A token binds tenant + audience + exact action hash + single-use id; any change to the action yields a
 * different hash and therefore a useless token (gap D).
 */
export const DecisionTokenClaimsSchema = z.object({
  iss: z.string().url(),
  sub: z.string().min(1).max(200),
  jti: z.string().min(16).max(200),
  aud: z.string().min(1).max(200),
  tenant: z.string().min(1).max(200),
  decision: DecisionSchema.exclude(['BLOCK']),
  action_hash: ActionHashSchema,
  actor: z.string().min(1).max(200),
  acting_for: z.string().min(1).max(200).optional(),
  approver: z.array(z.string().min(1).max(200)).min(1).optional(),
  policy_set_version: z.string().min(1).max(200),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().nonnegative(),
  single_use: z.literal(true),
});
export type DecisionTokenClaims = z.infer<typeof DecisionTokenClaimsSchema>;

/** A JWKS with VERA's `revoked` extension: kids that must be rejected even if the key is still listed. */
export const TenantJwksSchema = z.object({
  keys: z.array(
    z.looseObject({
      kid: z.string().min(1),
      kty: z.literal('OKP'),
      crv: z.literal('Ed25519'),
      x: z.string().min(1),
      use: z.literal('sig').optional(),
      alg: z.literal('EdDSA').optional(),
    }),
  ),
  revoked: z.array(z.string()).default([]),
});
export type TenantJwks = z.infer<typeof TenantJwksSchema>;
