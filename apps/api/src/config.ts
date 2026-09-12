import { masterKeyFromEnv } from '@vera/db';

export interface KmsConfig {
  region: string;
  /**
   * Explicit credentials, or `undefined` to use the ambient AWS credential chain.
   *
   * The chain is opt-in via `VERA_KMS_USE_AMBIENT_CREDENTIALS` and never the fallback. Deployment
   * environments routinely carry broad `AWS_*` credentials for unrelated services; silently falling
   * back to them would mean VERA signs under whatever identity happened to be lying around, which is
   * the opposite of the least-privilege signing identity ADR-0005 asks for. Absent credentials must
   * be an error, not an upgrade in authority.
   */
  credentials?: { accessKeyId: string; secretAccessKey: string } | undefined;
}

export interface ApiConfig {
  databaseUrl: string;
  migrationDatabaseUrl: string;
  masterKey: Buffer;
  publicUrl: string;
  port: number;
  /** Present only when KMS signing is configured; tenants without a `kms_key_arn` never touch it. */
  kms?: KmsConfig | undefined;
}

export function loadKmsConfig(env: NodeJS.ProcessEnv = process.env): KmsConfig | undefined {
  const region = env.VERA_KMS_REGION?.trim();
  if (!region) return undefined;
  const accessKeyId = env.VERA_KMS_ACCESS_KEY_ID?.trim();
  const secretAccessKey = env.VERA_KMS_SECRET_ACCESS_KEY?.trim();
  if (accessKeyId && secretAccessKey) return { region, credentials: { accessKeyId, secretAccessKey } };
  if (accessKeyId || secretAccessKey) {
    throw new Error('VERA_KMS_ACCESS_KEY_ID and VERA_KMS_SECRET_ACCESS_KEY must be set together');
  }
  if (env.VERA_KMS_USE_AMBIENT_CREDENTIALS === 'true') return { region, credentials: undefined };
  throw new Error(
    'VERA_KMS_REGION is set but no credentials are: set VERA_KMS_ACCESS_KEY_ID and VERA_KMS_SECRET_ACCESS_KEY, ' +
      'or VERA_KMS_USE_AMBIENT_CREDENTIALS=true to use an instance role. VERA will not fall back to ambient AWS credentials on its own.',
  );
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ApiConfig {
  const databaseUrl = env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
  return {
    databaseUrl,
    migrationDatabaseUrl: env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera',
    masterKey: masterKeyFromEnv(env.VERA_MASTER_KEY),
    publicUrl: (env.VERA_PUBLIC_URL ?? 'http://localhost:4000').replace(/\/$/, ''),
    port: Number(env.PORT ?? 4000),
    kms: loadKmsConfig(env),
  };
}
