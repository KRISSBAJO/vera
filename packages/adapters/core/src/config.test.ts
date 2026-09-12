import {
  buildTenantJwks,
  generateTenantKey,
  issueAdapterConfig,
  localSigner,
  type TenantSigningKey,
} from '@vera/decision-token';
import { AdapterConfigSchema } from '@vera/schemas';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  BUILT_IN_CONFIG,
  type ConfigCache,
  classFromConfig,
  mayFailOpen,
  SignedConfigStore,
  VeraClient,
} from './index.js';

const ORG = 'org_cfg';
const AUD = 'adapter:laptop';

let key: TenantSigningKey;
let foreign: TenantSigningKey;

const table = (over: Partial<Record<string, unknown>> = {}) =>
  AdapterConfigSchema.parse({
    version: 3,
    tool_classes: { deploy_service: 'deploy.production', read_docs: 'file.read' },
    tool_class_patterns: [{ pattern: '^mcp__stripe__', class: 'payment.create' }],
    fail_open_classes: ['file.read', 'search'],
    hold_seconds: 120,
    poll_interval_ms: 500,
    ...over,
  });

const mint = async (
  over: {
    config?: ReturnType<typeof table>;
    tenant?: string;
    aud?: string;
    ttlSeconds?: number;
    now?: Date;
  } = {},
  signWith?: TenantSigningKey,
) =>
  issueAdapterConfig(
    {
      iss: `https://vera.test/t/${ORG}`,
      aud: over.aud ?? AUD,
      tenant: over.tenant ?? ORG,
      config: over.config ?? table(),
      ...(over.ttlSeconds !== undefined ? { ttlSeconds: over.ttlSeconds } : {}),
      ...(over.now ? { now: over.now } : {}),
    },
    localSigner(signWith ?? key),
  );

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** A client whose /v1/adapter-config and JWKS responses are scripted. */
function client(opts: { bundle?: string | (() => never); jwks?: () => unknown; fail?: boolean }) {
  const fetchImpl = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes('jwks.json')) return json(opts.jwks ? opts.jwks() : buildTenantJwks([key]));
    if (url.includes('/v1/adapter-config')) {
      if (opts.fail) return json({ error: { code: 'BOOM' } }, 503);
      return json({ bundle: typeof opts.bundle === 'function' ? opts.bundle() : opts.bundle });
    }
    return json({});
  }) as typeof fetch;
  return new VeraClient({
    endpoint: 'http://vera.test',
    apiKey: 'vera_sk_x',
    org: ORG,
    requestTimeoutMs: 500,
    fetch: fetchImpl,
  });
}

function memoryCache(initial?: string): ConfigCache & { value: string | undefined } {
  const box = {
    value: initial,
    async read() {
      return box.value;
    },
    async write(bundle: string) {
      box.value = bundle;
    },
  };
  return box;
}

const store = (c: VeraClient, cache?: ConfigCache, now?: () => number) =>
  new SignedConfigStore({
    client: c,
    tenant: ORG,
    aud: AUD,
    ...(cache ? { cache } : {}),
    ...(now ? { now } : {}),
  });

beforeAll(async () => {
  key = await generateTenantKey('k_cfg');
  foreign = await generateTenantKey('k_attacker');
});

describe('a verified table is obeyed', () => {
  it('uses what the tenant signed', async () => {
    const r = await store(client({ bundle: await mint() })).resolve();
    expect(r.source).toBe('verified');
    expect(r.config.version).toBe(3);
    expect(r.config.fail_open_classes).toEqual(['file.read', 'search']);
  });

  it('caches the bundle so a later run survives VERA being down', async () => {
    const cache = memoryCache();
    await store(client({ bundle: await mint() }), cache).resolve();
    expect(cache.value).toBeTruthy();

    const offline = await store(client({ fail: true }), cache).resolve();
    expect(offline.source).toBe('cached');
    expect(offline.config.version).toBe(3);
    expect(offline.reason).toContain('VERA unreachable');
  });
});

describe('T19: a table this machine could have edited is refused', () => {
  it('falls back to built-in defaults when the cached bundle was tampered with', async () => {
    const good = await mint();
    const [h, p, s] = good.split('.') as [string, string, string];
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    // The edit an attacker actually wants: let production deploys through when VERA is unreachable.
    payload.config.fail_open_classes = ['deploy.production', 'db.ddl'];
    const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;

    const r = await store(client({ fail: true }), memoryCache(forged)).resolve();
    expect(r.source).toBe('builtin');
    expect(mayFailOpen(r.config, 'deploy.production')).toBe(false);
    expect(mayFailOpen(r.config, 'db.ddl')).toBe(false);
  });

  it('a bundle signed by someone else is not a table', async () => {
    const r = await store(client({ bundle: await mint({}, foreign) })).resolve();
    expect(r.source).toBe('builtin');
    expect(r.reason).toContain('failed verification');
  });

  it('a bundle for another tenant or another receiver is refused', async () => {
    expect((await store(client({ bundle: await mint({ tenant: 'org_other' }) })).resolve()).source).toBe(
      'builtin',
    );
    expect(
      (await store(client({ bundle: await mint({ aud: 'adapter:someone-else' }) })).resolve()).source,
    ).toBe('builtin');
  });

  it('an expired cached table is refused rather than obeyed forever', async () => {
    const old = await mint({ ttlSeconds: 60 });
    const later = () => Date.now() + 10 * 60_000;
    const r = await store(client({ fail: true }), memoryCache(old), later).resolve();
    expect(r.source).toBe('builtin');
  });

  it('a revoked key means the table it signed is no longer a table', async () => {
    const bundle = await mint();
    const revoked = client({ bundle, jwks: () => buildTenantJwks([key], ['k_cfg']) });
    expect((await store(revoked).resolve()).source).toBe('builtin');
  });

  it('a decision token cannot be presented as a config bundle', async () => {
    const { issueDecisionToken } = await import('@vera/decision-token');
    const notATable = await issueDecisionToken(
      {
        iss: `https://vera.test/t/${ORG}`,
        sub: 'dec_1',
        aud: AUD,
        tenant: ORG,
        decision: 'ALLOW',
        action_hash: `sha256:${'0'.repeat(64)}`,
        actor: 'claude-code',
        policy_set_version: 'ps_1',
      },
      localSigner(key),
    );
    const r = await store(client({ bundle: notATable })).resolve();
    expect(r.source).toBe('builtin');
  });

  it('garbage is refused without throwing', async () => {
    expect((await store(client({ bundle: 'not-a-jws' })).resolve()).source).toBe('builtin');
  });
});

describe('the built-in fallback is the conservative one', () => {
  it('permits only genuinely read-only classes to fail open', async () => {
    for (const cls of ['file.read', 'vcs.read', 'http.read', 'db.read', 'search'] as const) {
      expect(mayFailOpen(BUILT_IN_CONFIG, cls)).toBe(true);
    }
    for (const cls of [
      'deploy.production',
      'db.ddl',
      'shell.exec',
      'payment.create',
      'unknown.consequential',
    ] as const) {
      expect(mayFailOpen(BUILT_IN_CONFIG, cls)).toBe(false);
    }
  });

  it('overrides nothing — an unverified machine gets the heuristics, not an attacker’s opinion', () => {
    expect(BUILT_IN_CONFIG.tool_classes).toEqual({});
    expect(BUILT_IN_CONFIG.tool_class_patterns).toEqual([]);
    expect(classFromConfig(BUILT_IN_CONFIG, 'anything')).toBeUndefined();
  });
});

describe('applying the table to a tool name', () => {
  const t = table();

  it('an exact name wins', () => {
    expect(classFromConfig(t, 'deploy_service')).toBe('deploy.production');
    expect(classFromConfig(t, 'read_docs')).toBe('file.read');
  });

  it('patterns match MCP tools; first match wins', () => {
    expect(classFromConfig(t, 'mcp__stripe__create_refund')).toBe('payment.create');
    expect(classFromConfig(t, 'mcp__github__list_issues')).toBeUndefined();
  });

  it('a pattern that does not compile is skipped, not fatal', () => {
    const broken = table({
      tool_class_patterns: [
        { pattern: '([unclosed', class: 'file.read' },
        { pattern: '^ok_', class: 'db.read' },
      ],
    });
    expect(classFromConfig(broken, 'ok_tool')).toBe('db.read');
  });
});
