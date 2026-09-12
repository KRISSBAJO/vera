import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';

/**
 * Development-only sealing of tenant private signing keys at rest (AES-256-GCM under a master key from
 * the environment). Production replaces this with a KMS behind the `Signer` interface (ADR-0001, SR-11).
 */
export function masterKeyFromEnv(value: string | undefined): Buffer {
  if (!value) throw new Error('VERA_MASTER_KEY is not set (32 random bytes, base64)');
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('VERA_MASTER_KEY must decode to exactly 32 bytes');
  return key;
}

export function seal(plaintext: string, masterKey: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${Buffer.concat([iv, tag, ct]).toString('base64')}`;
}

export function unseal(sealed: string, masterKey: Buffer): string {
  if (!sealed.startsWith('v1.')) throw new Error('unknown sealed format');
  const buf = Buffer.from(sealed.slice(3), 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

// ---------- ids and secrets ----------

export function newId(prefix: string): string {
  return `${prefix}_${randomUUID().replace(/-/g, '')}`;
}

/** API keys and reviewer-session tokens: random secret, stored only as a hash. */
export function newSecret(prefix: 'vera_sk' | 'vera_rs'): { secret: string; hash: string; display: string } {
  const secret = `${prefix}_${randomBytes(24).toString('base64url')}`;
  return { secret, hash: hashSecret(secret), display: `${secret.slice(0, 12)}…` };
}

export function hashSecret(secret: string): string {
  return createHash('sha256').update(secret, 'utf8').digest('hex');
}
