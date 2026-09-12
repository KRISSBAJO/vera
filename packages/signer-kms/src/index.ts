import { createPublicKey } from 'node:crypto';
import { GetPublicKeyCommand, type KMSClient, SignCommand } from '@aws-sdk/client-kms';
import type { JwsHeader, Signer } from '@vera/decision-token';
import { exportJWK } from 'jose';

/**
 * A `Signer` backed by AWS KMS (ADR-0005, threat T14, SR-11).
 *
 * The point of this file is what it *cannot* do. There is no code path here that returns, exports, or
 * even observes a private key — `SignCommand` sends bytes to KMS and gets a signature back. Compare
 * `localSigner`, where the key is unsealed into process memory and `exportPrivateJwk` exists. That is
 * the difference between development custody and production custody, and it is why this package
 * closes accepted risk #8 rather than merely relocating it.
 *
 * The key must be `ECC_NIST_EDWARDS25519` (KMS gained EdDSA support in November 2025), which is what
 * makes this a drop-in: the token format stays Ed25519 and no verifier changes.
 */

/** KMS signs bytes; a JWS is `base64url(header).base64url(payload).base64url(signature)`. */
const b64url = (input: string | Uint8Array): string =>
  Buffer.from(typeof input === 'string' ? new TextEncoder().encode(input) : input).toString('base64url');

export interface KmsSignerOptions {
  client: KMSClient;
  /** Key ARN or id. The ARN is preferred: it pins the account and region. */
  keyArn: string;
  /** The `kid` published in the JWKS and stamped on every token. */
  kid: string;
}

/** Ed25519 signatures are 64 bytes (RFC 8032). Anything else is not a signature we can put in a JWS. */
const ED25519_SIGNATURE_BYTES = 64;

export function kmsSigner(opts: KmsSignerOptions): Signer {
  return {
    kid: opts.kid,
    async signCompact(header: JwsHeader, payload: Record<string, unknown>): Promise<string> {
      const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
      const res = await opts.client.send(
        new SignCommand({
          KeyId: opts.keyArn,
          Message: new TextEncoder().encode(signingInput),
          // RAW: KMS hashes the message itself. Ed25519ph (the DIGEST variant) is a different
          // algorithm and would produce signatures no JOSE verifier accepts.
          MessageType: 'RAW',
          SigningAlgorithm: 'ED25519_SHA_512',
        }),
      );
      const signature = res.Signature;
      if (!signature) throw new Error('KMS returned no signature');
      // Fail loudly rather than emitting a JWS nobody can verify. If KMS ever wrapped the signature
      // (DER, as it does for ECDSA), silently passing it through would produce tokens that fail
      // verification everywhere — a confusing, system-wide outage instead of one clear error.
      if (signature.length !== ED25519_SIGNATURE_BYTES) {
        throw new Error(
          `KMS returned a ${signature.length}-byte signature; JWS EdDSA requires exactly ${ED25519_SIGNATURE_BYTES}. Is the key spec ECC_NIST_EDWARDS25519?`,
        );
      }
      return `${signingInput}.${b64url(signature)}`;
    },
  };
}

/**
 * Fetch the public half from KMS as a JWK for the tenant JWKS.
 *
 * KMS returns DER-encoded SubjectPublicKeyInfo; node:crypto parses it and jose converts it to the
 * `{kty: OKP, crv: Ed25519, x}` form verifiers expect.
 */
export async function kmsPublicJwk(opts: KmsSignerOptions): Promise<Record<string, unknown>> {
  const res = await opts.client.send(new GetPublicKeyCommand({ KeyId: opts.keyArn }));
  if (!res.PublicKey) throw new Error('KMS returned no public key');
  if (res.KeySpec && res.KeySpec !== 'ECC_NIST_EDWARDS25519') {
    throw new Error(`KMS key ${opts.keyArn} is ${res.KeySpec}; VERA signs with ECC_NIST_EDWARDS25519`);
  }
  const key = createPublicKey({ key: Buffer.from(res.PublicKey), format: 'der', type: 'spki' });
  const jwk = await exportJWK(key);
  return { ...jwk, kid: opts.kid, use: 'sig', alg: 'EdDSA' };
}

/**
 * A stable `kid` derived from the key ARN. Traceable back to the exact KMS key without exposing
 * anything secret, and stable across restarts — a random kid would orphan every live token on deploy.
 */
export function kidForKeyArn(keyArn: string): string {
  const id = keyArn.split('/').at(-1) ?? keyArn;
  return `kms_${id}`;
}
