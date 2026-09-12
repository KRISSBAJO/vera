import { readFileSync } from 'node:fs';
import { createDb } from '@vera/db';
import { githubProviderFromEnv } from '@vera/evidence';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const vera = createDb(config.databaseUrl);

const github = githubProviderFromEnv(process.env, (p) => readFileSync(p, 'utf8'));
const evidenceProviders = github ? [github] : [];

const app = await buildApp({
  vera,
  masterKey: config.masterKey,
  publicUrl: config.publicUrl,
  kms: config.kms,
  logger: true,
  evidenceProviders,
  evidenceBudgetMs: Number(process.env.VERA_EVIDENCE_BUDGET_MS ?? 1500),
});
app.log.info({ providers: evidenceProviders.map((p) => p.name) }, 'evidence providers');

const shutdown = async () => {
  await app.close();
  await vera.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ port: config.port, host: '0.0.0.0' });
