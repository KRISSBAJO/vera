#!/usr/bin/env node
/**
 * Live check against the real KMS key: fetch the public half, sign a decision token, verify it.
 *
 * The unit tests prove our JWS assembly against a local Ed25519 key. This proves the remaining
 * assumptions, which are the ones only AWS can answer: that ED25519_SHA_512 over a RAW message
 * produces a bare 64-byte signature (not DER-wrapped, as KMS does for ECDSA), that the SPKI public
 * key converts to a JWK verifiers accept, and that the IAM policy actually permits Sign and
 * GetPublicKey on this ARN and nothing broader.
 *
 *   node apps/api/scripts/kms-smoke.mjs
 *
 * Reads VERA_KMS_* from the repo-root .env directly. Nothing secret is printed.
 */
import { readFileSync } from 'node:fs';
import { KMSClient } from '@aws-sdk/client-kms';
import { actionHash } from '@vera/canon';
import { issueDecisionToken, verifyDecisionToken } from '@vera/decision-token';
import { kidForKeyArn, kmsPublicJwk, kmsSigner } from '@vera/signer-kms';

const env = Object.fromEntries(
  readFileSync(new URL('../../../.env', import.meta.url), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l && !l.startsWith('#') && l.includes('='))
    .map((l) => {
      const i = l.indexOf('=');
      return [
        l.slice(0, i).trim(),
        l
          .slice(i + 1)
          .trim()
          .replace(/^["']|["']$/g, ''),
      ];
    }),
);

const region = env.VERA_KMS_REGION;
const keyArn = env.VERA_KMS_KEY_ARN;
const accessKeyId = env.VERA_KMS_ACCESS_KEY_ID;
const secretAccessKey = env.VERA_KMS_SECRET_ACCESS_KEY;

const missing = Object.entries({
  VERA_KMS_REGION: region,
  VERA_KMS_KEY_ARN: keyArn,
  VERA_KMS_ACCESS_KEY_ID: accessKeyId,
  VERA_KMS_SECRET_ACCESS_KEY: secretAccessKey,
})
  .filter(([, v]) => !v)
  .map(([k]) => k);
if (missing.length) {
  console.error(`missing in .env: ${missing.join(', ')}`);
  process.exit(2);
}

const step = (n, msg) => console.log(`  ${n}. ${msg}`);
console.log(`\nKMS smoke test — ${keyArn}\n`);

const client = new KMSClient({ region, credentials: { accessKeyId, secretAccessKey } });
const kid = kidForKeyArn(keyArn);

const publicJwk = await kmsPublicJwk({ client, keyArn, kid });
step(1, `GetPublicKey  → ${publicJwk.kty}/${publicJwk.crv}, kid ${kid}`);
if (publicJwk.d) throw new Error('a private component came back from GetPublicKey — stop and investigate');

const action = {
  class: 'deploy.production',
  tool: 'Bash',
  arguments: { command: 'kubectl apply -f prod.yaml' },
  target: { kind: 'service', id: 'vera-api' },
  environment: 'production',
};
const hash = actionHash(action);

const token = await issueDecisionToken(
  {
    iss: 'https://vera.test/t/smoke',
    sub: 'dec_smoke',
    aud: 'adapter:smoke',
    tenant: 'smoke',
    decision: 'ALLOW',
    action_hash: hash,
    actor: 'kms-smoke',
    policy_set_version: 'ps_1',
  },
  kmsSigner({ client, keyArn, kid }),
);
step(2, `Sign          → ${token.length}-char JWS, bound to ${hash.slice(0, 20)}…`);

const ok = await verifyDecisionToken(
  token,
  { keys: [publicJwk], revoked: [] },
  {
    tenant: 'smoke',
    aud: 'adapter:smoke',
    action_hash: hash,
  },
);
if (!ok.ok) throw new Error(`verification failed: ${ok.code}`);
step(3, `Verify        → ok, kid ${ok.kid}`);

// The binding is the product, not the signature: a token must not verify against a different action.
const tampered = await verifyDecisionToken(
  token,
  { keys: [publicJwk], revoked: [] },
  {
    tenant: 'smoke',
    aud: 'adapter:smoke',
    action_hash: actionHash({ ...action, arguments: { command: 'kubectl delete -f prod.yaml' } }),
  },
);
if (tampered.ok) throw new Error('a token verified against an action it was not issued for');
step(4, `Rebind        → refused (${tampered.code}) when the command changes`);

console.log(`\n  PASS — the private half never left KMS.\n`);
