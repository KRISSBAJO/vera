#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { createDb } from '@vera/db';
import { addReviewer, bootstrapTenant } from './bootstrap.js';
import { loadConfig } from './config.js';

const usage = `vera-api <command>

  migrate                                   apply migrations (uses MIGRATION_DATABASE_URL)
  bootstrap --org <name> --email <admin>    create a tenant with Policy Pack 1 active; prints secrets once
            [--timezone <tz>] [--aud <receiver aud>]
  add-user  --org-id <id> --email <email>   add a reviewer with a session token; prints the token once
  serve                                     start the API (same as: node dist/server.js)
`;

const [command, ...rest] = process.argv.slice(2);
const { values } = parseArgs({
  args: rest,
  options: {
    org: { type: 'string' },
    'org-id': { type: 'string' },
    email: { type: 'string' },
    timezone: { type: 'string' },
    aud: { type: 'string' },
  },
  allowPositionals: true,
});

const need = (v: string | undefined, name: string): string => {
  if (!v) {
    console.error(`missing --${name}\n\n${usage}`);
    process.exit(2);
  }
  return v;
};

switch (command) {
  case 'migrate': {
    const config = loadConfig();
    const admin = createDb(config.migrationDatabaseUrl, { max: 1 });
    await admin.migrate();
    await admin.close();
    console.log('migrations applied');
    break;
  }
  case 'bootstrap': {
    const config = loadConfig();
    const vera = createDb(config.databaseUrl, { max: 2 });
    const r = await bootstrapTenant(vera, config.masterKey, {
      orgName: need(values.org, 'org'),
      adminEmail: need(values.email, 'email'),
      ...(values.timezone ? { timezone: values.timezone } : {}),
      ...(values.aud ? { receiverAud: values.aud } : {}),
    });
    await vera.close();
    console.log(`
Tenant created. These secrets are shown ONCE and stored only as hashes.

  org_id          ${r.orgId}
  admin user_id   ${r.userId}
  signing kid     ${r.kid}
  policy set      ${r.policySetVersion} (Policy Pack 1, active)

  API key (adapter, scope decide):   ${r.apiKey}
  reviewer session (approve/reject): ${r.reviewerToken}

  JWKS: ${config.publicUrl}/.well-known/vera/${r.orgId}/jwks.json
`);
    break;
  }
  case 'add-user': {
    const config = loadConfig();
    const vera = createDb(config.databaseUrl, { max: 2 });
    const r = await addReviewer(vera, need(values['org-id'], 'org-id'), need(values.email, 'email'));
    await vera.close();
    console.log(`\n  user_id          ${r.userId}\n  reviewer session ${r.reviewerToken}\n`);
    break;
  }
  case 'serve':
    await import('./server.js');
    break;
  default:
    console.error(usage);
    process.exit(command ? 2 : 0);
}
