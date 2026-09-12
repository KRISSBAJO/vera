import type { DecideRequest } from '@vera/schemas';
import { exportPKCS8, generateKeyPair, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import { type EvidenceProvider, gatherEvidence, githubProvider, repoOf } from './index.js';

const request = (over: Partial<DecideRequest> = {}): DecideRequest => ({
  request_id: 'r',
  idempotency_key: 'k',
  actor: { type: 'ai_agent', id: 'claude-code' },
  action: {
    type: 'tool_call',
    tool: 'deploy',
    class: 'deploy.production',
    arguments: {},
    environment: 'production',
  },
  target: { kind: 'repository', id: 'github.com/logaxp/hearken' },
  context: { branch: 'feature/x' },
  ...over,
});

type Route = (url: string, init?: RequestInit) => { status?: number; body: unknown } | undefined;
function fakeFetch(route: Route, calls: { url: string; auth?: string }[] = []): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const headers = init?.headers as Record<string, string> | undefined;
    calls.push({ url, ...(headers?.authorization ? { auth: headers.authorization } : {}) });
    const r = route(url, init);
    if (!r) return new Response('{}', { status: 404 });
    return new Response(JSON.stringify(r.body), {
      status: r.status ?? 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}

const prFixture =
  (over: Partial<{ reviews: unknown[]; runs: unknown[]; status: unknown; files: unknown[] }> = {}): Route =>
  (url) => {
    if (url.includes('/pulls?'))
      return {
        body: [
          {
            number: 812,
            head: { sha: 'abc123' },
            user: { login: 'kriss' },
            html_url: 'https://github.com/logaxp/hearken/pull/812',
          },
        ],
      };
    if (url.endsWith('/pulls/812/reviews?per_page=100'))
      return {
        body: over.reviews ?? [
          { user: { login: 'ops' }, state: 'APPROVED', submitted_at: '2026-09-11T01:00:00Z' },
        ],
      };
    if (url.includes('/commits/abc123/check-runs'))
      return {
        body: { total_count: 1, check_runs: over.runs ?? [{ status: 'completed', conclusion: 'success' }] },
      };
    if (url.endsWith('/commits/abc123/status'))
      return { body: over.status ?? { state: 'success', total_count: 1 } };
    if (url.includes('/pulls/812/files')) return { body: over.files ?? [{ filename: 'src/app.ts' }] };
    return undefined;
  };

describe('repoOf', () => {
  it('reads owner/repo from context.repo or a github target id', () => {
    expect(repoOf(request({ context: { repo: 'logaxp/hearken', branch: 'x' } }))).toEqual({
      owner: 'logaxp',
      repo: 'hearken',
    });
    expect(repoOf(request())).toEqual({ owner: 'logaxp', repo: 'hearken' });
    expect(repoOf(request({ target: { kind: 'workspace', id: 'vera' }, context: {} }))).toBeNull();
  });
});

describe('github provider (token auth)', () => {
  const provider = (route: Route, calls: { url: string; auth?: string }[] = []) =>
    githubProvider({
      auth: { kind: 'token', token: 'ghp_test' },
      fetch: fakeFetch(route, calls),
      now: () => new Date('2026-09-11T06:00:00Z'),
    });

  it('applies only to repo actions with a branch', () => {
    const p = provider(prFixture());
    expect(p.applies(request())).toBe(true);
    expect(
      p.applies(request({ action: { type: 'tool_call', tool: 'Bash', class: 'shell.exec', arguments: {} } })),
    ).toBe(false);
    expect(p.applies(request({ context: {} }))).toBe(false);
  });

  it('reports an approved PR with green checks and no migration as verified github.pr evidence', async () => {
    const calls: { url: string; auth?: string }[] = [];
    const [ev] = await provider(prFixture(), calls).provide(request(), new AbortController().signal);
    expect(ev).toMatchObject({
      type: 'github.pr',
      source: 'github',
      trust: 'verified',
      data: { number: 812, approved: true, checks: 'success', contains_migration: false },
    });
    expect(calls.every((c) => c.auth === 'Bearer ghp_test')).toBe(true);
    expect(calls[0]?.url).toContain('head=logaxp%3Afeature%2Fx');
  });

  it('detects migrations from changed files', async () => {
    const [ev] = await provider(
      prFixture({ files: [{ filename: 'packages/db/drizzle/0003_x.sql' }] }),
    ).provide(request(), new AbortController().signal);
    expect(ev?.data.contains_migration).toBe(true);
  });

  it('a later CHANGES_REQUESTED overrides an earlier APPROVED from the same reviewer; author self-approval does not count', async () => {
    const reviews = [
      { user: { login: 'ops' }, state: 'APPROVED', submitted_at: '2026-09-11T01:00:00Z' },
      { user: { login: 'ops' }, state: 'CHANGES_REQUESTED', submitted_at: '2026-09-11T02:00:00Z' },
      { user: { login: 'kriss' }, state: 'APPROVED', submitted_at: '2026-09-11T03:00:00Z' },
    ];
    const [ev] = await provider(prFixture({ reviews })).provide(request(), new AbortController().signal);
    expect(ev?.data.approved).toBe(false);
  });

  it('checks: failure beats everything; pending when incomplete; none when nothing reported', async () => {
    const failed = await provider(
      prFixture({ runs: [{ status: 'completed', conclusion: 'failure' }] }),
    ).provide(request(), new AbortController().signal);
    expect(failed[0]?.data.checks).toBe('failure');
    const pending = await provider(
      prFixture({ runs: [{ status: 'in_progress', conclusion: null }] }),
    ).provide(request(), new AbortController().signal);
    expect(pending[0]?.data.checks).toBe('pending');
    const none = await provider(
      prFixture({ runs: [], status: { state: 'pending', total_count: 0 } }),
    ).provide(request(), new AbortController().signal);
    expect(none[0]?.data.checks).toBe('none');
  });

  it('no open PR ⇒ no evidence (absence is stated by the engine, never assumed safe)', async () => {
    const p = provider((url) => (url.includes('/pulls?') ? { body: [] } : undefined));
    expect(await p.provide(request(), new AbortController().signal)).toEqual([]);
  });
});

describe('github provider (app auth)', () => {
  it('mints an installation token with an RS256 app JWT and caches it', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
    const pem = await exportPKCS8(privateKey);
    const calls: { url: string; auth?: string }[] = [];
    let mints = 0;
    const route: Route = (url) => {
      if (url.endsWith('/app/installations/42/access_tokens')) {
        mints += 1;
        return {
          status: 201,
          body: { token: `ghs_inst_${mints}`, expires_at: new Date(Date.now() + 3600_000).toISOString() },
        };
      }
      return prFixture()(url);
    };
    const p = githubProvider({
      auth: { kind: 'app', appId: '12345', privateKeyPem: pem, installationId: '42' },
      fetch: fakeFetch(route, calls),
    });
    await p.provide(request(), new AbortController().signal);
    await p.provide(request(), new AbortController().signal);
    expect(mints).toBe(1);
    const mint = calls.find((c) => c.url.endsWith('/access_tokens'));
    const jwt = mint?.auth?.replace('Bearer ', '') ?? '';
    const { payload } = await jwtVerify(jwt, publicKey, { issuer: '12345' });
    expect(payload.exp! - payload.iat!).toBe(9 * 60);
    expect(calls.filter((c) => c.url.includes('/repos/')).every((c) => c.auth === 'Bearer ghs_inst_1')).toBe(
      true,
    );
  });
});

describe('gatherEvidence budget', () => {
  it('a slow provider is reported as missing; a fast one still delivers; results are forced to verified', async () => {
    const slow: EvidenceProvider = {
      name: 'slow',
      applies: () => true,
      provide: (_r, signal) =>
        new Promise((_res, rej) => signal.addEventListener('abort', () => rej(new Error('aborted')))),
    };
    const fast: EvidenceProvider = {
      name: 'fast',
      applies: () => true,
      provide: async () => [
        {
          id: 'e',
          type: 'x',
          source: 'fast',
          trust: 'asserted',
          observed_at: new Date().toISOString(),
          data: {},
        },
      ],
    };
    const r = await gatherEvidence([slow, fast], request(), { budgetMs: 50 });
    expect(r.missing).toEqual([{ provider: 'slow', reason: 'timed out after 50ms' }]);
    expect(r.evidence[0]?.trust).toBe('verified');
  });

  it('a throwing provider is missing with its message; non-applicable providers are skipped', async () => {
    const boom: EvidenceProvider = {
      name: 'boom',
      applies: () => true,
      provide: async () => {
        throw new Error('HTTP 500');
      },
    };
    const na: EvidenceProvider = {
      name: 'na',
      applies: () => false,
      provide: async () => {
        throw new Error('never');
      },
    };
    const r = await gatherEvidence([boom, na], request(), { budgetMs: 50 });
    expect(r.missing).toEqual([{ provider: 'boom', reason: 'HTTP 500' }]);
  });
});
