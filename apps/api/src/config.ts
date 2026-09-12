import { masterKeyFromEnv } from '@vera/db';

export interface ApiConfig {
  databaseUrl: string;
  migrationDatabaseUrl: string;
  masterKey: Buffer;
  publicUrl: string;
  port: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ApiConfig {
  const databaseUrl = env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
  return {
    databaseUrl,
    migrationDatabaseUrl: env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera',
    masterKey: masterKeyFromEnv(env.VERA_MASTER_KEY),
    publicUrl: (env.VERA_PUBLIC_URL ?? 'http://localhost:4000').replace(/\/$/, ''),
    port: Number(env.PORT ?? 4000),
  };
}
