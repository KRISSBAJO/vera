import { randomBytes } from 'node:crypto';
import { addReviewer, type BootstrapResult, bootstrapTenant, buildApp } from '@vera/api';
import { createDb, type VeraDb } from '@vera/db';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type AdapterConfig,
  AdapterConfigSchema,
  classify,
  type HookDeps,
  type HookState,
  runPost,
  runPre,
  VeraClient,
  type JournalEntry,
  programOf,
} from './index.js';

const appUrl = process.env.DATABASE_URL ?? 'postgres://vera_app:vera_app@localhost:55432/vera';
const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? 'postgres://vera:vera@localhost:55432/vera';
const AUD = 'adapter:kriss-laptop';

let vera: VeraDb;
let app: FastifyInstance;
let boot: BootstrapResult;
let ops: { userId: string; reviewerToken: string };
let endpoint: string;
let cfg: AdapterConfig;
let masterKey: Buffer;

const git = () => ({ remote: 'github.com/logaxp/hearken', branch: 'feature/x', defaultBranch: 'main' });

function makeDeps(over: Partial<HookDeps> & { endpoint?: string } = {}) {
  const states = new Map<string, HookState>();
  const degraded: unknown[] = [];
  const logs: string[] = [];
  const deps: HookDeps & { states: typeof states; degraded: unknown[]; logs: string[] } = {
    client: new VeraClient({
      endpoint: over.endpoint ?? endpoint,
      apiKey: cfg.apiKey,
      org: cfg.org,
      requestTimeoutMs: 1500,
    }),
    state: { save: async (id, s) => void states.set(id, s), load: async (id) => states.get(id) },
    git,
    queueDegraded: async (e) => void degraded.push(e),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => Date.now(),
    log: (l) => void logs.push(l),
    states,
    degraded,
    logs,
    ...over,
  };
  return deps;
}

let n = 0;
const pre = (tool: string, input: Record<string, unknown>) => {
  n += 1;
  return {
    hook_event_name: 'PreToolUse' as const,
    tool_name: tool,
    tool_input: input,
    tool_use_id: `toolu_${n}_${randomBytes(3).toString('hex')}`,
    session_id: 'sess_test',
    cwd: 'C:/Users/kriss/hearken',
    permission_mode: 'default',
  };
};

beforeAll(async () => {
  const admin = createDb(migrationUrl, { max: 1 });
  await admin.migrate();
  await admin.close();
  vera = createDb(appUrl, { max: 4 });
  masterKey = randomBytes(32);
  app = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test' });
  const address = await app.listen({ port: 0, host: '127.0.0.1' });
  endpoint = address;
  boot = await bootstrapTenant(vera, masterKey, {
    orgName: 'LogaXP',
    adminEmail: 'kriss@logaxp.com',
    receiverAud: AUD,
  });
  ops = await addReviewer(vera, boot.orgId, 'ops@logaxp.com');
  cfg = AdapterConfigSchema.parse({
    endpoint,
    apiKey: boot.apiKey,
    org: boot.orgId,
    aud: AUD,
    actingFor: 'kriss@logaxp.com',
    holdSeconds: 5,
    pollIntervalMs: 200,
    requestTimeoutMs: 1500,
  });
});

afterAll(async () => {
  await app.close();
  await vera.close();
});

describe('classification (deterministic; SR-03 conservative)', () => {
  const opts = { cwd: 'C:/Users/kriss/hearken', environment: 'development', git: git() };
  it.each([
    ['Read', { file_path: 'a.ts' }, 'file.read'],
    ['Grep', { pattern: 'x' }, 'file.read'],
    ['Write', { file_path: 'a.ts', content: '' }, 'file.write'],
    ['WebFetch', { url: 'https://x' }, 'http.read'],
    ['mcp__github__list_issues', {}, 'http.read'],
    ['mcp__stripe__create_refund', {}, 'unknown.consequential'],
    ['SomethingNew', {}, 'unknown.consequential'],
  ])('%s → %s', (tool, input, cls) => {
    expect(classify(tool, input as Record<string, unknown>, opts).class).toBe(cls as never);
  });

  it.each([
    ['git status', 'vcs.read'],
    ['ls -la | grep foo', 'vcs.read'],
    ['git push origin feature/x', 'vcs.push'],
    ['git push --force origin main', 'vcs.push'],
    ['psql -h db.prod.internal -c "ALTER TABLE users DROP COLUMN legacy_id"', 'db.ddl'],
    ['psql -c "select count(*) from users"', 'db.read'],
    ['psql -c "delete from sessions where expired"', 'db.write'],
    ['kubectl apply -f prod.yaml', 'deploy.production'],
    ['vercel deploy', 'deploy.staging'],
    ['npm publish', 'deploy.production'],
    ['terraform destroy', 'infra.change'],
    ['curl -X POST https://api.example.com/x -d "{}"', 'http.mutation'],
    ['curl https://api.example.com/x', 'http.read'],
    ['vault kv get secret/prod/db', 'secret.read'],
    ['npm test', 'shell.exec'],
    ['rm -rf ./dist', 'shell.exec'],
    ['echo hi > file', 'shell.exec'],
  ])('bash: %s → %s', (command, cls) => {
    expect(classify('Bash', { command }, opts).class).toBe(cls as never);
  });

  // Windows dogfood, 2026-09-11: a Get-ChildItem through the PowerShell tool was BLOCKed as
  // unknown.consequential, because only `Bash` was recognised as a shell.
  it.each([
    ['Get-ChildItem "$env:USERPROFILE\\Downloads\\*.pem"', 'vcs.read'],
    ['Get-Content package.json | Select-Object -First 5', 'vcs.read'],
    ['Test-Path C:/Users/kriss/vera', 'vcs.read'],
    ['Remove-Item -Recurse -Force dist', 'shell.exec'],
    ['Set-Content secrets.txt "x"', 'shell.exec'],
  ])('powershell: %s → %s', (command, cls) => {
    expect(classify('PowerShell', { command }, opts).class).toBe(cls as never);
  });

  it('classifies every shell tool by its command, not its name', () => {
    for (const tool of ['Bash', 'PowerShell', 'Shell', 'Terminal']) {
      expect(classify(tool, { command: 'git push --force origin main' }, opts).class).toBe('vcs.push');
    }
  });

  it('derives force/branch for pushes, production for prod-looking commands, destructive hints', () => {
    const push = classify('Bash', { command: 'git push --force origin main' }, opts);
    expect(push.arguments).toMatchObject({ force: true, branch: 'main' });
    expect(push.target).toMatchObject({
      kind: 'repository',
      id: 'github.com/logaxp/hearken',
      default_branch: 'main',
    });
    expect(push.hints.destructive).toBe(true);
    const ddl = classify('Bash', { command: 'psql $PROD_URL -c "DROP TABLE users"' }, opts);
    expect(ddl.environment).toBe('production');
    expect(ddl.hints.destructive).toBe(true);
    expect(classify('Bash', { command: 'rm -rf /' }, opts).hints.destructive).toBe(true);
    expect(classify('Bash', { command: 'npm test' }, opts).environment).toBe('development');
  });
});

describe('hook contract (ADR-0002, A17)', () => {
  it('answers with the documented output shape and only the four permission decisions', async () => {
    const out = await runPre(pre('Read', { file_path: 'README.md' }), cfg, makeDeps());
    expect(out.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(['allow', 'deny', 'ask', 'defer']).toContain(out.hookSpecificOutput.permissionDecision);
    expect(typeof out.hookSpecificOutput.permissionDecisionReason).toBe('string');
  });
});

describe('end to end against the real API', () => {
  it('feature-branch push → ALLOW; token verified against the tenant JWKS; post reports executed', async () => {
    const deps = makeDeps();
    const input = pre('Bash', { command: 'git push origin feature/x' });
    const out = await runPre(input, cfg, deps);
    expect(out.hookSpecificOutput.permissionDecision).toBe('allow');
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/^VERA ALLOW dec_/);
    const state = deps.states.get(input.tool_use_id);
    expect(state).toMatchObject({ decision: 'ALLOW', answered: 'allow' });

    await runPost({ ...input, hook_event_name: 'PostToolUse', tool_response: { exit_code: 0 } }, cfg, deps);
    const audit = await app.inject({
      method: 'GET',
      url: '/v1/audit-events?limit=500',
      headers: { authorization: `Bearer ${boot.reviewerToken}` },
    });
    const outcome = audit
      .json()
      .events.find(
        (e: { kind: string; payload: { decision_id: string } }) =>
          e.kind === 'outcome.recorded' && e.payload.decision_id === state?.decision_id,
      );
    expect(outcome?.payload).toMatchObject({ kind: 'executed', trust: 'asserted' });
  });

  it('force-push to main → deny with the policy named', async () => {
    const out = await runPre(pre('Bash', { command: 'git push --force origin main' }), cfg, makeDeps());
    expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain('no-force-push-to-default');
  });

  it('read-only tools are allowed without ceremony', async () => {
    const out = await runPre(pre('Grep', { pattern: 'TODO' }), cfg, makeDeps());
    expect(out.hookSpecificOutput.permissionDecision).toBe('allow');
  });

  it('T02: post recomputes the hash; an executed command that differs is reported as hash_mismatch', async () => {
    const deps = makeDeps();
    const input = pre('Bash', { command: 'git push origin feature/x' });
    await runPre(input, cfg, deps);
    await runPost(
      {
        ...input,
        hook_event_name: 'PostToolUse',
        tool_input: { command: 'git push origin feature/x && rm -rf /' },
      },
      cfg,
      deps,
    );
    const audit = await app.inject({
      method: 'GET',
      url: '/v1/audit-events?limit=500',
      headers: { authorization: `Bearer ${boot.reviewerToken}` },
    });
    const id = deps.states.get(input.tool_use_id)?.decision_id;
    const mismatch = audit
      .json()
      .events.find(
        (e: { kind: string; payload: { decision_id: string; kind: string } }) =>
          e.kind === 'outcome.recorded' && e.payload.decision_id === id && e.payload.kind === 'hash_mismatch',
      );
    expect(mismatch).toBeDefined();
  });

  it('production DDL → REVIEW: holds, a reviewer approves, the adapter verifies the approval token and allows', async () => {
    const deps = makeDeps();
    const input = pre('Bash', {
      command: 'psql -h db.prod.internal -c "ALTER TABLE users DROP COLUMN legacy_id"',
    });
    const holding = runPre(input, cfg, deps);
    // Approve from "elsewhere" once the review exists.
    await new Promise((r) => setTimeout(r, 400));
    const line = deps.logs.find((l) => l.startsWith('VERA REVIEW'));
    const decisionId = line?.match(/dec_\w+/)?.[0];
    expect(decisionId).toBeDefined();
    const approve = await app.inject({
      method: 'POST',
      url: `/v1/decisions/${decisionId}/approve`,
      headers: { authorization: `Bearer ${ops.reviewerToken}` },
      payload: { rationale: 'backup taken' },
    });
    expect(approve.statusCode).toBe(200);
    const out = await holding;
    expect(out.hookSpecificOutput.permissionDecision).toBe('allow');
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain('approved — token verified');
  });

  it('REVIEW rejected → deny', async () => {
    const deps = makeDeps();
    const holding = runPre(
      pre('Bash', { command: 'psql -h db.prod.internal -c "ALTER TABLE users DROP COLUMN legacy_id"' }),
      cfg,
      deps,
    );
    await new Promise((r) => setTimeout(r, 400));
    const decisionId = deps.logs.find((l) => l.startsWith('VERA REVIEW'))?.match(/dec_\w+/)?.[0];
    await app.inject({
      method: 'POST',
      url: `/v1/decisions/${decisionId}/reject`,
      headers: { authorization: `Bearer ${ops.reviewerToken}` },
      payload: {},
    });
    expect((await holding).hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('REVIEW unresolved within the hold → ask (interactive) or defer (SDK), never allow', async () => {
    const short = { ...cfg, holdSeconds: 1, pollIntervalMs: 200 };
    const out = await runPre(
      pre('Bash', { command: 'psql -h db.prod.internal -c "ALTER TABLE users DROP COLUMN legacy_id"' }),
      short,
      makeDeps(),
    );
    expect(out.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain('SYSTEM.HOLD_EXPIRED');
    const sdk = await runPre(
      pre('Bash', { command: 'psql -h db.prod.internal -c "DROP TABLE users"' }),
      { ...short, onHoldExpiry: 'defer' },
      makeDeps(),
    );
    expect(sdk.hookSpecificOutput.permissionDecision).toBe('defer');
  });
});

describe('SR-08 degraded mode (VERA unreachable)', () => {
  const dead = 'http://127.0.0.1:1';
  it('read-only → allow, queued as SYSTEM.DEGRADED_MODE; consequential → ask, never allow', async () => {
    const deps = makeDeps({ endpoint: dead });
    const read = await runPre(
      pre('Read', { file_path: 'x' }),
      { ...cfg, endpoint: dead, requestTimeoutMs: 500 },
      deps,
    );
    expect(read.hookSpecificOutput.permissionDecision).toBe('allow');
    expect(read.hookSpecificOutput.permissionDecisionReason).toContain('SYSTEM.DEGRADED_MODE');
    const push = await runPre(
      pre('Bash', { command: 'git push origin feature/x' }),
      { ...cfg, endpoint: dead, requestTimeoutMs: 500 },
      deps,
    );
    expect(push.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(deps.degraded).toHaveLength(2);
  });

  it('a revoked or wrong API key is a refusal (deny), not degraded mode', async () => {
    const bad = { ...cfg, apiKey: 'vera_sk_not_a_real_key' };
    const deps = makeDeps({
      client: new VeraClient({ endpoint, apiKey: bad.apiKey, org: cfg.org, requestTimeoutMs: 1500 }),
    });
    const out = await runPre(pre('Bash', { command: 'git push origin feature/x' }), bad, deps);
    expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain('API_KEY_REQUIRED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
describe('the decision journal (dogfood loop)', () => {
  it('records every decision VERA made — program name only, never the arguments', async () => {
    const entries: JournalEntry[] = [];
    const deps = makeDeps({ journal: async (e) => void entries.push(e) });
    const secret = ['hunter', '2', 'abc'].join('');
    await runPre(pre('Bash', { command: `PGPASSWORD=${secret} psql -h prod -c "SELECT 1"` }), cfg, deps);
    await runPre(pre('Bash', { command: 'git push origin feature/journal' }), cfg, deps);

    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ tool: 'Bash', program: 'psql' });
    expect(entries[1]).toMatchObject({ tool: 'Bash', program: 'git', verdict: 'ALLOW', answered: 'allow' });
    for (const e of entries) {
      expect(e.decision_id).toMatch(/^dec_/);
      expect(JSON.stringify(e)).not.toContain(secret);
      expect(JSON.stringify(e)).not.toContain('SELECT');
    }
  });

  it('does not journal degraded-mode answers — those were not VERA decisions', async () => {
    const entries: JournalEntry[] = [];
    const deps = makeDeps({ endpoint: 'http://127.0.0.1:1', journal: async (e) => void entries.push(e) });
    await runPre(pre('Read', { file_path: '/tmp/x' }), cfg, deps);
    expect(deps.degraded).toHaveLength(1);
    expect(entries).toHaveLength(0);
  });

  it('a journal that throws never changes the decision', async () => {
    const deps = makeDeps({
      journal: async () => {
        throw new Error('disk full');
      },
    });
    const out = await runPre(pre('Bash', { command: 'git push origin feature/journal-2' }), cfg, deps);
    expect(out.hookSpecificOutput.permissionDecision).toBe('allow');
  });

  it('programOf skips leading env assignments and falls back to the tool name', () => {
    expect(programOf('Bash', { command: 'FOO=1 BAR=2 kubectl apply -f x' })).toBe('kubectl');
    expect(programOf('Bash', { command: '  git   push' })).toBe('git');
    expect(programOf('Bash', { command: 'ONLY=assignment' })).toBe('Bash');
    // Compound and wrapped commands: the journal names what a human would call it.
    expect(programOf('Bash', { command: 'for f in a b; do cat "$f"; done' })).toBe('cat');
    expect(programOf('Bash', { command: 'cd /repo && git push origin main' })).toBe('git');
    expect(programOf('Bash', { command: 'sudo systemctl restart nginx' })).toBe('systemctl');
    expect(programOf('Bash', { command: 'echo "x" | psql -h prod' })).toBe('psql');
    expect(programOf('Bash', { command: '/usr/local/bin/kubectl apply -f x' })).toBe('kubectl');
    expect(programOf('Bash', { command: 'if [ -f x ]; then rm x; fi' })).toBe('rm');
    expect(programOf('Write', { file_path: '/x' })).toBe('Write');
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
describe('SR-23 rate limited (VERA says slow down)', () => {
  it('a 429 is handled like an outage, not a refusal: read-only continues, consequential asks, both queued', async () => {
    // A second app with a two-per-minute limit, so the third decide from this key is a real 429.
    const small = await buildApp({ vera, masterKey, publicUrl: 'http://vera.test', rateLimit: { decidePerMinute: 2 } });
    const smallEndpoint = await small.listen({ port: 0, host: '127.0.0.1' });
    try {
      const deps = makeDeps({ endpoint: smallEndpoint });
      const c = { ...cfg, endpoint: smallEndpoint };
      await runPre(pre('Read', { file_path: 'a' }), c, deps);
      await runPre(pre('Read', { file_path: 'b' }), c, deps);
      expect(deps.degraded).toHaveLength(0);

      const read = await runPre(pre('Read', { file_path: 'c' }), c, deps);
      expect(read.hookSpecificOutput.permissionDecision).toBe('allow');
      expect(read.hookSpecificOutput.permissionDecisionReason).toMatch(/rate-limiting/);
      expect(read.hookSpecificOutput.permissionDecisionReason).toContain('SYSTEM.DEGRADED_MODE');

      const push = await runPre(pre('Bash', { command: 'git push origin feature/throttled' }), c, deps);
      expect(push.hookSpecificOutput.permissionDecision).toBe('ask');
      expect(push.hookSpecificOutput.permissionDecisionReason).not.toMatch(/refused/);

      expect(deps.degraded).toHaveLength(2);
      for (const d of deps.degraded as { reason: string }[]) expect(d.reason).toMatch(/rate limited/);
    } finally {
      await small.close();
    }
  });
});
