import { sql } from 'drizzle-orm';
import { drizzle, type PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import * as schema from './schema.js';

export type Db = PostgresJsDatabase<typeof schema>;
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];

export interface VeraDb {
  db: Db;
  /**
   * Run `fn` in a transaction scoped to one tenant. Every RLS policy reads `vera.tenant_id`, which is
   * set LOCAL to this transaction and never derived from request data (SR-14).
   */
  withTenant<T>(orgId: string, fn: (tx: Tx) => Promise<T>): Promise<T>;
  /**
   * Run `fn` in a transaction that can see across tenants, because the tenant is not known yet.
   *
   * This is the one deliberate hole in tenant isolation, so its callers are listed rather than left
   * to convention, and the list is meant to stay this short:
   *  - `auth.ts`: API-key and reviewer-session lookup by secret hash, which decides *which* tenant.
   *  - `doctor.ts`: the operator preflight, which reports on every tenant by design.
   *
   * Anything that already knows its tenant must use `withTenant` instead.
   */
  withAuthLookup<T>(fn: (tx: Tx) => Promise<T>): Promise<T>;
  migrate(): Promise<void>;
  close(): Promise<void>;
}

export function createDb(url: string, opts: { max?: number } = {}): VeraDb {
  const client = postgres(url, { max: opts.max ?? 10, onnotice: () => {} });
  const db = drizzle(client, { schema });
  return {
    db,
    withTenant: (orgId, fn) =>
      db.transaction(async (tx) => {
        await tx.execute(sql`select set_config('vera.tenant_id', ${orgId}, true)`);
        return fn(tx);
      }),
    withAuthLookup: (fn) =>
      db.transaction(async (tx) => {
        await tx.execute(sql`select set_config('vera.auth_lookup', '1', true)`);
        return fn(tx);
      }),
    migrate: () =>
      migrate(db, {
        migrationsFolder: new URL('../drizzle', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'),
      }),
    close: () => client.end(),
  };
}
