import { randomUUID } from 'node:crypto';
import {
  ADAPTER_CONFIG_TYP,
  type AdapterConfig,
  AdapterConfigClaimsSchema,
  DECISION_TOKEN_TYP,
  DEFAULT_ALLOW_TTL_SECONDS,
  DEFAULT_APPROVAL_TTL_SECONDS,
  DEFAULT_CONFIG_TTL_SECONDS,
  type DecisionTokenClaims,
  DecisionTokenClaimsSchema,
  type TenantJwks,
  TenantJwksSchema,
} from '@vera/schemas';
import {
  type CryptoKey,
  createLocalJWKSet,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  errors as joseErrors,
  jwtVerify,
  CompactSign,
} from 'jose';

// ---------- keys ----------

export interface TenantSigningKey {
  kid: string;
  /** Private key. In production this lives in a KMS behind `Signer`; this shape is for development and tests. */
  privateKey: CryptoKey;
  publicJwk: Record<string, unknown>;
}

/** Ed25519 key pair with a public JWK ready for the tenant JWKS. */
export async function generateTenantKey(kid: string = `k_${randomUUID()}`): Promise<TenantSigningKey> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid, use: 'sig', alg: 'EdDSA' };
  return { kid, privateKey, publicJwk };
}

/** Export a private key as JWK for encrypted on-disk storage in development. Never used in production. */
export async function exportPrivateJwk(key: TenantSigningKey): Promise<Record<string, unknown>> {
  return { ...(await exportJWK(key.privateKey)), kid: key.kid };
}

export async function importTenantKey(
  privateJwk: Record<string, unknown>,
  publicJwk: Record<string, unknown>,
): Promise<TenantSigningKey> {
  const kid = String(privateJwk.kid ?? publicJwk.kid);
  const privateKey = (await importJWK(privateJwk as Parameters<typeof importJWK>[0], 'EdDSA')) as CryptoKey;
  return { kid, privateKey, publicJwk: { ...publicJwk, kid } };
}

/** Build the tenant JWKS document. Revoked kids stay listed (so old tokens are identifiable) but must be rejected. */
export function buildTenantJwks(
  keys: ReadonlyArray<Pick<TenantSigningKey, 'publicJwk'>>,
  revoked: ReadonlyArray<string> = [],
): TenantJwks {
  return TenantJwksSchema.parse({ keys: keys.map((k) => k.publicJwk), revoked: [...revoked] });
}

// ---------- issuing ----------

/**
 * The signing boundary (ADR-0005). Nothing else in the codebase touches private key material.
 *
 * The interface takes a header and a payload rather than a pre-built signer object, because a remote
 * signer — KMS, an HSM — can only be handed bytes to sign. That shape is what lets `kmsSigner` be a
 * true drop-in: the key never exists outside the HSM, and no call site changes.
 */
export interface JwsHeader {
  alg: 'EdDSA';
  kid: string;
  typ: string;
}

export interface Signer {
  readonly kid: string;
  /** Produce a compact JWS over the protected header and payload. */
  signCompact(header: JwsHeader, payload: Record<string, unknown>): Promise<string>;
}

/** Development signer: the private key is in this process. Production uses `kmsSigner` instead. */
export function localSigner(key: TenantSigningKey): Signer {
  return {
    kid: key.kid,
    signCompact: (header, payload) =>
      new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader({ ...header })
        .sign(key.privateKey),
  };
}

const sign = (signer: Signer, typ: string, payload: Record<string, unknown>) =>
  signer.signCompact({ alg: 'EdDSA', kid: signer.kid, typ }, payload);

export type IssueInput = Omit<DecisionTokenClaims, 'jti' | 'iat' | 'exp' | 'single_use'> & {
  jti?: string;
  ttlSeconds?: number;
  now?: Date;
};

/**
 * Issue a decision token. `ttlSeconds` may only shorten the default for the decision kind (SR-10):
 * ALLOW → 10 min, approval (REVIEW resolved by humans, `approver` present) → 15 min.
 */
export async function issueDecisionToken(input: IssueInput, signer: Signer): Promise<string> {
  const { ttlSeconds, now, jti, ...claims } = input;
  const maxTtl = claims.approver ? DEFAULT_APPROVAL_TTL_SECONDS : DEFAULT_ALLOW_TTL_SECONDS;
  const ttl = ttlSeconds === undefined ? maxTtl : Math.min(Math.max(1, Math.floor(ttlSeconds)), maxTtl);
  const iat = Math.floor((now ?? new Date()).getTime() / 1000);
  const full: DecisionTokenClaims = DecisionTokenClaimsSchema.parse({
    ...claims,
    jti: jti ?? randomUUID(),
    iat,
    exp: iat + ttl,
    single_use: true,
  });
  return sign(signer, DECISION_TOKEN_TYP, full);
}

// ---------- verifying ----------

export type TokenFailureCode =
  | 'TOKEN.MALFORMED'
  | 'TOKEN.BAD_SIGNATURE'
  | 'TOKEN.REVOKED_KEY'
  | 'TOKEN.EXPIRED'
  | 'TOKEN.AUDIENCE_MISMATCH'
  | 'TOKEN.TENANT_MISMATCH'
  | 'TOKEN.HASH_MISMATCH';

export interface VerifyExpectation {
  tenant: string;
  aud: string;
  /** The hash the receiver computed from the action it is about to execute. */
  action_hash: string;
  issuer?: string;
  now?: Date;
}

export type VerifyResult =
  | { ok: true; claims: DecisionTokenClaims; kid: string }
  | { ok: false; code: TokenFailureCode; detail?: string };

/**
 * Verify a decision token against the tenant JWKS and the receiver's own view of the action.
 * Checks, in order: typ + kid present → kid not revoked → signature and exp → claims schema → aud → tenant → action_hash.
 * Every failure maps to a reason code from the registry so receivers can report it.
 */
export async function verifyDecisionToken(
  token: string,
  jwks: TenantJwks,
  expect: VerifyExpectation,
): Promise<VerifyResult> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return { ok: false, code: 'TOKEN.MALFORMED', detail: 'not a JWS' };
  }
  if (header.typ !== DECISION_TOKEN_TYP)
    return { ok: false, code: 'TOKEN.MALFORMED', detail: `typ ${String(header.typ)}` };
  if (!header.kid) return { ok: false, code: 'TOKEN.MALFORMED', detail: 'missing kid' };
  if (jwks.revoked.includes(header.kid)) return { ok: false, code: 'TOKEN.REVOKED_KEY', detail: header.kid };

  const keySet = createLocalJWKSet({ keys: jwks.keys as Parameters<typeof createLocalJWKSet>[0]['keys'] });
  let payload: unknown;
  try {
    const nowSec = expect.now ? Math.floor(expect.now.getTime() / 1000) : undefined;
    const result = await jwtVerify(token, keySet, {
      algorithms: ['EdDSA'],
      typ: DECISION_TOKEN_TYP,
      ...(expect.issuer ? { issuer: expect.issuer } : {}),
      ...(nowSec !== undefined ? { currentDate: new Date(nowSec * 1000) } : {}),
    });
    payload = result.payload;
  } catch (e) {
    if (e instanceof joseErrors.JWTExpired) return { ok: false, code: 'TOKEN.EXPIRED' };
    if (e instanceof joseErrors.JWTClaimValidationFailed && e.claim === 'iss')
      return { ok: false, code: 'TOKEN.MALFORMED', detail: 'issuer' };
    return { ok: false, code: 'TOKEN.BAD_SIGNATURE', detail: e instanceof Error ? e.name : 'unknown' };
  }

  const parsed = DecisionTokenClaimsSchema.safeParse(payload);
  if (!parsed.success) return { ok: false, code: 'TOKEN.MALFORMED', detail: 'claims' };
  const claims = parsed.data;
  if (claims.aud !== expect.aud) return { ok: false, code: 'TOKEN.AUDIENCE_MISMATCH' };
  if (claims.tenant !== expect.tenant) return { ok: false, code: 'TOKEN.TENANT_MISMATCH' };
  if (claims.action_hash !== expect.action_hash) return { ok: false, code: 'TOKEN.HASH_MISMATCH' };
  return { ok: true, claims, kid: header.kid };
}

// ---------- signed adapter configuration (SR-07, threats T19/T12) ----------

/**
 * The class table and fail-mode table an adapter is allowed to obey. Signed with the same tenant key
 * as decisions but under a distinct `typ`, so a decision token can never be presented as a config
 * bundle, nor the reverse.
 */
export async function issueAdapterConfig(
  input: { iss: string; aud: string; tenant: string; config: AdapterConfig; ttlSeconds?: number; now?: Date },
  signer: Signer,
): Promise<string> {
  const iat = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const ttl = Math.min(Math.max(60, input.ttlSeconds ?? DEFAULT_CONFIG_TTL_SECONDS), 24 * 60 * 60);
  const claims = AdapterConfigClaimsSchema.parse({
    iss: input.iss,
    aud: input.aud,
    tenant: input.tenant,
    iat,
    exp: iat + ttl,
    config: input.config,
  });
  // Every claim goes in the payload: verification re-parses it against the same schema, so a claim
  // left out here fails as malformed on every read.
  return sign(signer, ADAPTER_CONFIG_TYP, claims);
}

export type ConfigVerifyResult =
  | { ok: true; config: AdapterConfig; expiresAt: Date }
  | {
      ok: false;
      code:
        | 'CONFIG.MALFORMED'
        | 'CONFIG.BAD_SIGNATURE'
        | 'CONFIG.REVOKED_KEY'
        | 'CONFIG.EXPIRED'
        | 'CONFIG.TENANT_MISMATCH'
        | 'CONFIG.AUDIENCE_MISMATCH';
      detail?: string;
    };

/**
 * Verify a config bundle. A bundle that fails for any reason is refused rather than partially
 * honoured — the caller falls back to built-in conservative defaults, never to unverified content.
 */
export async function verifyAdapterConfig(
  bundle: string,
  jwks: TenantJwks,
  expect: { tenant: string; aud: string; now?: Date },
): Promise<ConfigVerifyResult> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(bundle);
  } catch {
    return { ok: false, code: 'CONFIG.MALFORMED', detail: 'not a JWS' };
  }
  if (header.typ !== ADAPTER_CONFIG_TYP)
    return { ok: false, code: 'CONFIG.MALFORMED', detail: `typ ${String(header.typ)}` };
  if (!header.kid) return { ok: false, code: 'CONFIG.MALFORMED', detail: 'missing kid' };
  if (jwks.revoked.includes(header.kid)) return { ok: false, code: 'CONFIG.REVOKED_KEY', detail: header.kid };

  const keySet = createLocalJWKSet({ keys: jwks.keys as Parameters<typeof createLocalJWKSet>[0]['keys'] });
  let payload: unknown;
  try {
    const result = await jwtVerify(bundle, keySet, {
      algorithms: ['EdDSA'],
      typ: ADAPTER_CONFIG_TYP,
      ...(expect.now ? { currentDate: expect.now } : {}),
    });
    payload = result.payload;
  } catch (e) {
    if (e instanceof joseErrors.JWTExpired) return { ok: false, code: 'CONFIG.EXPIRED' };
    return { ok: false, code: 'CONFIG.BAD_SIGNATURE', detail: e instanceof Error ? e.name : 'unknown' };
  }

  const parsed = AdapterConfigClaimsSchema.safeParse(payload);
  if (!parsed.success) return { ok: false, code: 'CONFIG.MALFORMED', detail: 'claims' };
  if (parsed.data.tenant !== expect.tenant) return { ok: false, code: 'CONFIG.TENANT_MISMATCH' };
  if (parsed.data.aud !== expect.aud) return { ok: false, code: 'CONFIG.AUDIENCE_MISMATCH' };
  return { ok: true, config: parsed.data.config, expiresAt: new Date(parsed.data.exp * 1000) };
}

// ---------- single use ----------

export type ConsumeResult = 'consumed' | 'already_consumed';

/** Online single-use enforcement (POST /v1/tokens/consume). The server backs this with Postgres; adapters may use memory. */
export interface SingleUseRegistry {
  consume(jti: string, exp: number): Promise<ConsumeResult>;
}

export class InMemorySingleUse implements SingleUseRegistry {
  private readonly seen = new Map<string, number>();
  async consume(jti: string, exp: number): Promise<ConsumeResult> {
    const now = Math.floor(Date.now() / 1000);
    for (const [k, e] of this.seen) if (e < now) this.seen.delete(k);
    if (this.seen.has(jti)) return 'already_consumed';
    this.seen.set(jti, exp);
    return 'consumed';
  }
}
