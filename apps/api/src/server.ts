import { createDb } from '@vera/db';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const vera = createDb(config.databaseUrl);
const app = await buildApp({ vera, masterKey: config.masterKey, publicUrl: config.publicUrl, logger: true });

const shutdown = async () => {
  await app.close();
  await vera.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ port: config.port, host: '0.0.0.0' });
