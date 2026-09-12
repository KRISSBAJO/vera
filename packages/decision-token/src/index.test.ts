import { actionHash } from '@vera/canon';
import { DEFAULT_ALLOW_TTL_SECONDS, DEFAULT_APPROVAL_TTL_SECONDS } from '@vera/schemas';
import { decodeJwt } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  buildTenantJwks,
  exportPrivateJwk,
  generateTenantKey,
  InMemorySingleUse,
  importTenantKey,
  issueDecisionToken,
  localSigner,
  type TenantSigningKey,
  verifyDecisionToken,
} from './index.js';

const hash = actionHash({
  class: 'vcs.push',
  tool: 'Bash',
  arguments: { command: 'git push origin feature/x' },
  environment: 'production',
});
const otherHash = actionHash({
  class: 'vcs.push',
  tool: 'Bash',
  arguments: { command: 'git push --force origin main' },
  environment: 'production',
});

const base = {
  iss: 'https://vera.example/t/acme',
  sub: 'dec_01J8ZK0000000000000000001',
  aud: 'adapter:kriss-laptop',
  tenant: 'acme',
  decision: 'ALLOW' as const,
  action_hash: hash,
  actor: 'claude-code',
  acting_for: 'kriss@logaxp.com',
  policy_set_version: 'ps_17',
};
const expectation = { tenant: 'acme', aud: 'adapter:kriss-laptop', action_hash: hash, issuer: base.iss };

let keyA: TenantSigningKey;
let keyB: TenantSigningKey;
let foreign: TenantSigningKey;

beforeAll(async () => {
  keyA = await generateTenantKey('k_a');
  keyB = await generateTenantKey('k_b');
  foreign = await generateTenantKey('k_foreign');
});

describe('SR-10 issue and verify', () => {
  it('round-trips an ALLOW token', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA]), expectation);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.kid).toBe('k_a');
      expect(r.claims.single_use).toBe(true);
      expect(r.claims.exp - r.claims.iat).toBe(DEFAULT_ALLOW_TTL_SECONDS);
    }
  });

  it('approval tokens carry approvers and use the approval TTL', async () => {
    const token = await issueDecisionToken(
      { ...base, decision: 'REVIEW', approver: ['ops@acme.com'] },
      localSigner(keyA),
    );
    const claims = decodeJwt(token);
    expect(claims.exp! - claims.iat!).toBe(DEFAULT_APPROVAL_TTL_SECONDS);
    expect(claims.approver).toEqual(['ops@acme.com']);
  });

  it('ttlSeconds can shorten but never lengthen the default', async () => {
    const short = decodeJwt(await issueDecisionToken({ ...base, ttlSeconds: 60 }, localSigner(keyA)));
    expect(short.exp! - short.iat!).toBe(60);
    const long = decodeJwt(await issueDecisionToken({ ...base, ttlSeconds: 86400 }, localSigner(keyA)));
    expect(long.exp! - long.iat!).toBe(DEFAULT_ALLOW_TTL_SECONDS);
  });

  it('refuses to issue a BLOCK token', async () => {
    await expect(
      issueDecisionToken({ ...base, decision: 'BLOCK' as never }, localSigner(keyA)),
    ).rejects.toThrow();
  });

  it('T02/T13: fails with TOKEN.HASH_MISMATCH when the executed action differs', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA]), {
      ...expectation,
      action_hash: otherHash,
    });
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.HASH_MISMATCH' });
  });

  it('T13: fails with TOKEN.AUDIENCE_MISMATCH for another receiver', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA]), {
      ...expectation,
      aud: 'adapter:someone-else',
    });
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.AUDIENCE_MISMATCH' });
  });

  it('T17: fails with TOKEN.TENANT_MISMATCH when the tenant claim differs', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA]), { ...expectation, tenant: 'other' });
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.TENANT_MISMATCH' });
  });

  it('T17: a token signed by another tenant key fails signature against this JWKS', async () => {
    const token = await issueDecisionToken(base, localSigner(foreign));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA, keyB]), expectation);
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.BAD_SIGNATURE' });
  });

  it('T13: fails with TOKEN.EXPIRED after exp', async () => {
    const token = await issueDecisionToken({ ...base, ttlSeconds: 60 }, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA]), {
      ...expectation,
      now: new Date(Date.now() + 120_000),
    });
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.EXPIRED' });
  });

  it('T13: tampering with the payload breaks the signature', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const [h, p, s] = token.split('.') as [string, string, string];
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    payload.action_hash = otherHash;
    const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
    const r = await verifyDecisionToken(tampered, buildTenantJwks([keyA]), {
      ...expectation,
      action_hash: otherHash,
    });
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.BAD_SIGNATURE' });
  });

  it('rejects tokens with the wrong typ or no kid as malformed', async () => {
    const r1 = await verifyDecisionToken('not.a.jwt', buildTenantJwks([keyA]), expectation);
    expect(r1).toMatchObject({ ok: false, code: 'TOKEN.MALFORMED' });
    const r2 = await verifyDecisionToken('garbage', buildTenantJwks([keyA]), expectation);
    expect(r2).toMatchObject({ ok: false, code: 'TOKEN.MALFORMED' });
  });
});

describe('SR-11 rotation and revocation', () => {
  it('tokens signed by the old key verify during the overlap window', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA, keyB]), expectation);
    expect(r.ok).toBe(true);
  });

  it('tokens signed by a revoked key fail with TOKEN.REVOKED_KEY even though the key is still listed', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA, keyB], ['k_a']), expectation);
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.REVOKED_KEY' });
  });

  it('tokens signed by a key no longer in the JWKS fail signature', async () => {
    const token = await issueDecisionToken(base, localSigner(keyA));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyB]), expectation);
    expect(r).toMatchObject({ ok: false, code: 'TOKEN.BAD_SIGNATURE' });
  });

  it('keys survive export/import for development storage', async () => {
    const priv = await exportPrivateJwk(keyA);
    const restored = await importTenantKey(priv, keyA.publicJwk);
    const token = await issueDecisionToken(base, localSigner(restored));
    const r = await verifyDecisionToken(token, buildTenantJwks([keyA]), expectation);
    expect(r.ok).toBe(true);
  });
});

describe('SR-10 single use', () => {
  it('second consume of the same jti reports already_consumed', async () => {
    const reg = new InMemorySingleUse();
    const exp = Math.floor(Date.now() / 1000) + 60;
    expect(await reg.consume('jti-1', exp)).toBe('consumed');
    expect(await reg.consume('jti-1', exp)).toBe('already_consumed');
    expect(await reg.consume('jti-2', exp)).toBe('consumed');
  });
});
