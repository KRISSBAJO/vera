import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import type { KMSClient } from '@aws-sdk/client-kms';
import {
  issueAdapterConfig,
  issueDecisionToken,
  verifyAdapterConfig,
  verifyDecisionToken,
} from '@vera/decision-token';
import { AdapterConfigSchema, type TenantJwks } from '@vera/schemas';
import { compactVerify, exportJWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { kidForKeyArn, kmsPublicJwk, kmsSigner } from './index.js';

// AWS's documented placeholder account id — a test has no business carrying a real one.
const KEY_ARN = 'arn:aws:kms:us-east-1:111122223333:key/2bae56fd-bdb4-4dd8-9409-e89fcdebe84e';
const KID = kidForKeyArn(KEY_ARN);

let privatePem: string;
let publicDer: Buffer;
let publicJwk: Record<string, unknown>;

/**
 * A KMS stand-in that signs with a real Ed25519 key. This proves the part that is ours — compact JWS
 * assembly and signature placement — against a real verifier, without needing AWS in the loop.
 */
function fakeKms(
  over: { signature?: Uint8Array; keySpec?: string; omitSignature?: boolean } = {},
): KMSClient {
  return {
    async send(command: { constructor: { name: string }; input: Record<string, unknown> }) {
      const name = command.constructor.name;
      if (name === 'SignCommand') {
        expect(command.input.MessageType).toBe('RAW');
        expect(command.input.SigningAlgorithm).toBe('ED25519_SHA_512');
        expect(command.input.KeyId).toBe(KEY_ARN);
        if (over.omitSignature) return {};
        if (over.signature) return { Signature: over.signature };
        const message = Buffer.from(command.input.Message as Uint8Array);
        return { Signature: new Uint8Array(nodeSign(null, message, createPrivateKey(privatePem))) };
      }
      if (name === 'GetPublicKeyCommand') {
        return { PublicKey: new Uint8Array(publicDer), KeySpec: over.keySpec ?? 'ECC_NIST_EDWARDS25519' };
      }
      throw new Error(`unexpected command ${name}`);
    },
  } as unknown as KMSClient;
}

const signer = (over?: Parameters<typeof fakeKms>[0]) =>
  kmsSigner({ client: fakeKms(over), keyArn: KEY_ARN, kid: KID });

beforeAll(async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'der' },
  });
  privatePem = privateKey;
  publicDer = publicKey;
  publicJwk = {
    ...(await exportJWK(createPublicKey({ key: publicDer, format: 'der', type: 'spki' }))),
    kid: KID,
    use: 'sig',
    alg: 'EdDSA',
  };
});

const jwks = (revoked: string[] = []): TenantJwks => ({ keys: [publicJwk as never], revoked });

describe('the JWS a KMS signature produces is a real one', () => {
  it('produces a compact JWS that verifies against the KMS public key', async () => {
    const jws = await signer().signCompact(
      { alg: 'EdDSA', kid: KID, typ: 'vera-decision+jwt' },
      { hello: 'world' },
    );
    expect(jws.split('.')).toHaveLength(3);
    const { payload, protectedHeader } = await compactVerify(
      jws,
      createPublicKey({ key: publicDer, format: 'der', type: 'spki' }),
    );
    expect(JSON.parse(new TextDecoder().decode(payload))).toEqual({ hello: 'world' });
    expect(protectedHeader).toMatchObject({ alg: 'EdDSA', kid: KID, typ: 'vera-decision+jwt' });
  });

  it('a decision token signed by KMS verifies exactly like a locally signed one', async () => {
    const token = await issueDecisionToken(
      {
        iss: 'https://vera.test/t/acme',
        sub: 'dec_1',
        aud: 'adapter:laptop',
        tenant: 'acme',
        decision: 'ALLOW',
        action_hash: `sha256:${'a'.repeat(64)}`,
        actor: 'claude-code',
        policy_set_version: 'ps_1',
      },
      signer(),
    );
    const v = await verifyDecisionToken(token, jwks(), {
      tenant: 'acme',
      aud: 'adapter:laptop',
      action_hash: `sha256:${'a'.repeat(64)}`,
    });
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.kid).toBe(KID);
  });

  it('an adapter config bundle signed by KMS verifies too', async () => {
    const bundle = await issueAdapterConfig(
      {
        iss: 'https://vera.test/t/acme',
        aud: 'adapter:laptop',
        tenant: 'acme',
        config: AdapterConfigSchema.parse({ version: 2, fail_open_classes: ['file.read'] }),
      },
      signer(),
    );
    const v = await verifyAdapterConfig(bundle, jwks(), { tenant: 'acme', aud: 'adapter:laptop' });
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.config.version).toBe(2);
  });

  it('a token signed by KMS is refused once its kid is revoked', async () => {
    const token = await issueDecisionToken(
      {
        iss: 'https://vera.test/t/acme',
        sub: 'dec_1',
        aud: 'adapter:laptop',
        tenant: 'acme',
        decision: 'ALLOW',
        action_hash: `sha256:${'b'.repeat(64)}`,
        actor: 'claude-code',
        policy_set_version: 'ps_1',
      },
      signer(),
    );
    const v = await verifyDecisionToken(token, jwks([KID]), {
      tenant: 'acme',
      aud: 'adapter:laptop',
      action_hash: `sha256:${'b'.repeat(64)}`,
    });
    expect(v).toMatchObject({ ok: false, code: 'TOKEN.REVOKED_KEY' });
  });
});

describe('it fails loudly rather than emitting something unverifiable', () => {
  it('refuses a signature that is not 64 bytes — a DER-wrapped one would break every verifier', async () => {
    const derish = new Uint8Array(70).fill(3);
    await expect(
      signer({ signature: derish }).signCompact({ alg: 'EdDSA', kid: KID, typ: 't' }, {}),
    ).rejects.toThrow(/70-byte signature.*requires exactly 64.*ECC_NIST_EDWARDS25519/s);
  });

  it('refuses when KMS returns no signature at all', async () => {
    await expect(
      signer({ omitSignature: true }).signCompact({ alg: 'EdDSA', kid: KID, typ: 't' }, {}),
    ).rejects.toThrow(/no signature/);
  });
});

describe('the public half', () => {
  it('comes back as an Ed25519 JWK ready for the tenant JWKS', async () => {
    const jwk = await kmsPublicJwk({ client: fakeKms(), keyArn: KEY_ARN, kid: KID });
    expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', kid: KID, use: 'sig', alg: 'EdDSA' });
    expect(typeof jwk.x).toBe('string');
    // The public half is public; there must be no private component anywhere near it.
    expect(jwk).not.toHaveProperty('d');
  });

  it('refuses a key of the wrong spec rather than producing tokens nothing can verify', async () => {
    await expect(
      kmsPublicJwk({ client: fakeKms({ keySpec: 'ECC_NIST_P256' }), keyArn: KEY_ARN, kid: KID }),
    ).rejects.toThrow(/ECC_NIST_P256.*ECC_NIST_EDWARDS25519/);
  });
});

describe('the kid', () => {
  it('is derived from the key ARN, so it is stable across restarts and traceable to the key', () => {
    expect(kidForKeyArn(KEY_ARN)).toBe('kms_2bae56fd-bdb4-4dd8-9409-e89fcdebe84e');
    expect(kidForKeyArn(KEY_ARN)).toBe(kidForKeyArn(KEY_ARN));
  });

  it('tolerates a bare key id', () => {
    expect(kidForKeyArn('2bae56fd')).toBe('kms_2bae56fd');
  });
});

describe('what this package cannot do', () => {
  it('exposes no way to obtain a private key — that is the whole point (ADR-0005)', async () => {
    const mod = await import('./index.js');
    const names = Object.keys(mod).join(' ');
    expect(names).not.toMatch(/private|export.*key|unseal/i);
    expect(Object.keys(mod).sort()).toEqual(['kidForKeyArn', 'kmsPublicJwk', 'kmsSigner']);
  });
});
