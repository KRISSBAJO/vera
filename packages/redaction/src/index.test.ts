import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES, redact, redactString, rulesFor, tenantRules } from './index.js';

const mask = (s: string) => redactString(s).value;
const rules = (s: string) => redactString(s).findings.map((f) => f.rule);

/**
 * Vendor-shaped fixtures are assembled at runtime, never written as literals.
 *
 * The first push of this file was rejected by GitHub's own secret scanning: a test *about* finding
 * credentials was full of strings that look exactly like credentials. Constructing them from parts
 * keeps the runtime value identical — the regexes are still genuinely exercised — while the source
 * contains nothing a scanner, or a person skimming a diff, could mistake for a live key.
 */
const join = (...parts: string[]) => parts.join('');
const FAKE = {
  anthropic: join('sk-', 'ant-', 'api03-', 'AbCdEfGhIjKlMnOpQrStUv'),
  github: join('ghp', '_', 'aBcDeFgHiJkLmNoPqRsTuVwXyZ012345'),
  stripe: join('sk', '_live_', '51H8xKzAbCdEfGhIjKlMnOp'),
  slack: join('xoxb', '-123456789012-abcdefghijklmnop'),
  aws: join('AKIA', 'IOSFODNN7EXAMPLE'),
  jwt: join('eyJ', 'hbGciOiJIUzI1NiJ9', '.', 'eyJzdWIiOiIxIn0', '.', 'abcdefghijk'),
  /** Google keys are the prefix plus exactly 35 characters; the pattern is anchored on that length. */
  google: join('AIza', 'SyB', 'c'.repeat(32)),
} as const;

describe('credentials that actually appear in tool arguments', () => {
  // The property that matters is that the secret is gone — not which rule caught it. Several rules
  // legitimately overlap (a Bearer token is also a JWT), and asserting the winner would make the
  // test brittle about something nobody depends on.
  it.each([
    ['psql postgres://app:s3cr3tp4ss@db.internal/prod', 's3cr3tp4ss'],
    ['PGPASSWORD=hunter2 psql -h db', 'hunter2'],
    [`curl -H "Authorization: Bearer ${FAKE.jwt}" https://api`, FAKE.jwt],
    [`aws configure set aws_access_key_id ${FAKE.aws}`, FAKE.aws],
    [`gh auth login --with-token ${FAKE.github}`, FAKE.github],
    [`stripe listen --api-key ${FAKE.stripe}`, FAKE.stripe],
    [`export ANTHROPIC_API_KEY=${FAKE.anthropic}`, FAKE.anthropic],
    [`slack post --token ${FAKE.slack}`, FAKE.slack],
    [`gcloud config set api_key ${FAKE.google}`, FAKE.google],
    ['curl -d "{\\"secret\\": \\"p@ssw0rd-value\\"}" https://api', 'p@ssw0rd-value'],
    ['deploy --password mySecret123', 'mySecret123'],
  ])('removes the credential from %s', (command, secret) => {
    const out = mask(command);
    expect(out).not.toContain(secret);
    expect(out).toContain('[redacted:');
    expect(rules(command).length).toBeGreaterThan(0);
  });

  it('keeps the shape of a connection string so the reviewer still sees user, host and database', () => {
    const out = mask('psql postgres://app:s3cr3tp4ss@db.internal/prod');
    expect(out).toBe('psql postgres://app:[redacted:connection-string-password]@db.internal/prod');
    expect(out).toContain('db.internal/prod');
    expect(out).not.toContain('s3cr3tp4ss');
  });

  it('masks the value but keeps the variable name, which is information the reviewer needs', () => {
    expect(mask('PGPASSWORD=hunter2 psql -h db')).toBe('PGPASSWORD=[redacted:secret-assignment] psql -h db');
  });

  it('names what it removed rather than printing anonymous asterisks', () => {
    expect(mask(`credential ${FAKE.aws}`)).toContain('aws-access-key-id');
  });

  it('removes an entire private key block', () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEow...lots of base64...\n-----END RSA PRIVATE KEY-----`;
    const out = mask(`cat <<EOF > key.pem\n${pem}\nEOF`);
    expect(out).toContain('[redacted:private-key]');
    expect(out).not.toContain('MIIEow');
  });
});

describe('what it must not mask', () => {
  it.each([
    'git push origin feature/x',
    'npm run build && npm test',
    'psql -h db.internal -c "select count(*) from users"',
    'kubectl apply -f deployment.yaml',
    'echo "the order number is 1234567890123"',
    'rm -rf ./dist',
  ])('leaves %s alone', (command) => {
    expect(mask(command)).toBe(command);
    expect(rules(command)).toEqual([]);
  });

  it('does not treat a long non-card digit string as a card number (Luhn)', () => {
    expect(mask('id 1234567890123')).toBe('id 1234567890123');
    expect(mask('card 4242424242424242')).toContain('[redacted:card-number]');
  });

  it('does not re-redact something already masked', () => {
    const once = mask('PGPASSWORD=hunter2');
    expect(mask(once)).toBe(once);
  });
});

describe('walking a whole argument object', () => {
  const args = {
    command: 'psql postgres://app:s3cr3t@db/prod -c "select 1"',
    env: { PGPASSWORD: 'hunter2', PATH: '/usr/bin' },
    files: ['README.md', FAKE.aws],
    retries: 3,
    dryRun: false,
    note: null,
  };

  it('masks strings anywhere in the structure and leaves other types untouched', () => {
    const r = redact(args);
    expect(r.redacted).toBe(true);
    expect(JSON.stringify(r.value)).not.toContain('s3cr3t');
    expect(JSON.stringify(r.value)).not.toContain(FAKE.aws);
    expect(r.value.retries).toBe(3);
    expect(r.value.dryRun).toBe(false);
    expect(r.value.note).toBeNull();
    expect(r.value.env.PATH).toBe('/usr/bin');
  });

  it('key names survive, their values do not — the structured case no textual rule can see', () => {
    const r = redact({
      password: 'hunter2',
      env: { PGPASSWORD: 'p', PATH: '/usr/bin' },
      client_secret: 'abc',
    });
    expect(Object.keys(r.value)).toEqual(['password', 'env', 'client_secret']);
    expect(r.value.password).toBe('[redacted:secret-key]');
    expect(r.value.env.PGPASSWORD).toBe('[redacted:secret-key]');
    expect(r.value.client_secret).toBe('[redacted:secret-key]');
    expect(r.value.env.PATH).toBe('/usr/bin');
  });

  it('a secret-named key masks its value whatever the value looks like', () => {
    // Nothing about "correct-horse-battery-staple" matches a credential pattern; the key is the tell.
    expect(redact({ api_key: 'correct-horse-battery-staple' }).value.api_key).toBe('[redacted:secret-key]');
  });

  it('masks every element of a secret-named array', () => {
    const r = redact({ tokens: ['aaa', 'bbb'] });
    expect(r.value.tokens).toEqual(['[redacted:secret-key]', '[redacted:secret-key]']);
  });

  it('reports where each secret was and how much was removed, without the value', () => {
    const r = redact(args);
    const paths = r.findings.map((f) => f.path);
    expect(paths).toContain('command');
    expect(paths).toContain('env.PGPASSWORD');
    expect(paths).toContain('files[1]');
    expect(r.findings.find((f) => f.path === 'env.PGPASSWORD')?.rule).toBe('secret-key');
    expect(r.findings.every((f) => f.length > 0)).toBe(true);
    expect(JSON.stringify(r.findings)).not.toContain('hunter2');
  });

  it('a clean object comes back unchanged and reports nothing', () => {
    const clean = { command: 'git status', count: 2 };
    const r = redact(clean);
    expect(r.value).toEqual(clean);
    expect(r.redacted).toBe(false);
  });

  it('handles deep nesting and arrays of objects', () => {
    const r = redact({ steps: [{ run: 'export TOKEN=abc123def456' }, { run: 'echo done' }] });
    expect(JSON.stringify(r.value)).not.toContain('abc123def456');
    expect(r.findings[0]?.path).toBe('steps[0].run');
  });
});

describe('tenant patterns', () => {
  it('a tenant can add its own secret shape, and it wins over the generic rules', () => {
    const custom = tenantRules([{ name: 'logaxp-internal', pattern: 'LGX-[0-9]{8}' }]);
    const r = redactString('deploy with LGX-12345678', rulesFor(custom));
    expect(r.value).toBe('deploy with [redacted:logaxp-internal]');
  });

  it('a pattern that does not compile is skipped rather than breaking the decision', () => {
    const compiled = tenantRules([
      { name: 'broken', pattern: '([unclosed' },
      { name: 'fine', pattern: 'SECRET-[0-9]+' },
    ]);
    expect(compiled.map((r) => r.name)).toEqual(['fine']);
  });

  it('a tenant pattern without the global flag still replaces every occurrence', () => {
    const custom = tenantRules([{ name: 'x', pattern: 'AAA' }]);
    expect(redactString('AAA and AAA', rulesFor(custom)).value).toBe('[redacted:x] and [redacted:x]');
  });
});

describe('the rule set itself', () => {
  it('every rule has a unique name and a global regex, so replacement is exhaustive', () => {
    const names = DEFAULT_RULES.map((r) => r.name);
    expect(new Set(names).size).toBe(names.length);
    expect(DEFAULT_RULES.every((r) => r.pattern.flags.includes('g'))).toBe(true);
  });
});
