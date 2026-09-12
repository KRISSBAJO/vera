// Writes JSON Schema for every wire object into ./json-schema. Generated, never hand-edited.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { DecideRequestSchema, DecideResponseSchema } from '../src/decide.js';
import { REASON_CODES } from '../src/reason-codes.js';
import { DecisionTokenClaimsSchema, TenantJwksSchema } from '../src/token.js';

const out = join(import.meta.dirname, '..', 'json-schema');
mkdirSync(out, { recursive: true });

const entries: Record<string, z.ZodType> = {
  'decide-request': DecideRequestSchema,
  'decide-response': DecideResponseSchema,
  'decision-token-claims': DecisionTokenClaimsSchema,
  'tenant-jwks': TenantJwksSchema,
};

for (const [name, schema] of Object.entries(entries)) {
  const json = z.toJSONSchema(schema, { target: 'draft-2020-12', io: 'input' });
  writeFileSync(
    join(out, `${name}.schema.json`),
    `${JSON.stringify({ $id: `https://vera.dev/schemas/${name}`, ...json }, null, 2)}\n`,
  );
}
writeFileSync(join(out, 'reason-codes.json'), `${JSON.stringify(REASON_CODES, null, 2)}\n`);
console.log(`wrote ${Object.keys(entries).length + 1} files to ${out}`);
