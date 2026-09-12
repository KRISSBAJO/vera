import { readFileSync } from 'node:fs';
import { createDb } from '@vera/db';
import { githubProviderFromEnv } from '@vera/evidence';
import { slackNotifier } from '@vera/notify-slack';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const vera = createDb(config.databaseUrl);

const github = githubProviderFromEnv(process.env, (p) => readFileSync(p, 'utf8'));
const evidenceProviders = github ? [github] : [];

// Both parts or neither: a token with no channel would post nowhere and a channel with no token
// cannot post, and either half alone is more likely a half-finished .env than an intention.
const slack =
  process.env.SLACK_BOT_TOKEN && process.env.SLACK_REVIEW_CHANNEL
    ? slackNotifier({
        token: process.env.SLACK_BOT_TOKEN,
        channel: process.env.SLACK_REVIEW_CHANNEL,
      })
    : undefined;

const app = await buildApp({
  vera,
  masterKey: config.masterKey,
  publicUrl: config.publicUrl,
  kms: config.kms,
  logger: true,
  evidenceProviders,
  evidenceBudgetMs: Number(process.env.VERA_EVIDENCE_BUDGET_MS ?? 1500),
  ...(slack ? { notifier: slack } : {}),
});
app.log.info(
  { providers: evidenceProviders.map((p) => p.name), slack: Boolean(slack) },
  'evidence providers',
);

const shutdown = async () => {
  await app.close();
  await vera.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ port: config.port, host: '0.0.0.0' });
