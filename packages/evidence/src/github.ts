import { createPrivateKey } from 'node:crypto';
import type { DecideRequest, Evidence } from '@vera/schemas';
import { SignJWT } from 'jose';
import type { EvidenceProvider } from './provider.js';

/**
 * GitHub evidence: for an action on a repository branch, find the open PR for that branch and report
 * verified facts Policy Pack 1 reads — `pr_approved`, `tests_passed` (checks + statuses), and
 * `contains_migration` (from the PR's changed files).
 *
 * Auth: a GitHub App (preferred; JWT → installation token, cached) or a plain token (local dogfood).
 * Permissions needed, all read-only: Pull requests, Checks, Commit statuses, Contents, Metadata.
 */
export type GitHubAuth =
  | { kind: 'token'; token: string }
  | { kind: 'app'; appId: string; privateKeyPem: string; installationId: string };

export interface GitHubProviderOptions {
  auth: GitHubAuth;
  apiBase?: string;
  fetch?: typeof fetch;
  now?: () => Date;
}

const MIGRATION_PATH =
  /(^|\/)(migrations?|db\/migrate|prisma\/migrations|drizzle|alembic\/versions|flyway|liquibase)\//i;
const APPLICABLE = new Set(['deploy.production', 'deploy.staging', 'vcs.push', 'vcs.merge']);

/** `owner/repo` from context.repo, or from a target id like `github.com/owner/repo`. */
export function repoOf(request: DecideRequest): { owner: string; repo: string } | null {
  const candidates = [request.context?.repo, request.target?.id].filter(
    (v): v is string => typeof v === 'string',
  );
  for (const c of candidates) {
    const m = c.match(/(?:github\.com[/:])?([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
    if (m?.[1] && m[2] && !c.includes(' ')) return { owner: m[1], repo: m[2] };
  }
  return null;
}

export function githubProvider(opts: GitHubProviderOptions): EvidenceProvider {
  const apiBase = (opts.apiBase ?? 'https://api.github.com').replace(/\/$/, '');
  const fetchImpl = opts.fetch ?? fetch;
  const now = opts.now ?? (() => new Date());
  let installationToken: { token: string; expiresAt: number } | undefined;

  async function bearer(signal: AbortSignal): Promise<string> {
    if (opts.auth.kind === 'token') return opts.auth.token;
    if (installationToken && installationToken.expiresAt - Date.now() > 60_000)
      return installationToken.token;
    // GitHub hands out PKCS#1 ("BEGIN RSA PRIVATE KEY"); jose's importPKCS8 only accepts PKCS#8.
    // node:crypto reads both, so the key works whichever format the customer downloaded.
    const key = createPrivateKey(opts.auth.privateKeyPem);
    const iat = Math.floor(now().getTime() / 1000) - 30;
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(opts.auth.appId)
      .setIssuedAt(iat)
      .setExpirationTime(iat + 9 * 60)
      .sign(key);
    const res = await fetchImpl(`${apiBase}/app/installations/${opts.auth.installationId}/access_tokens`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
      },
      signal,
    });
    if (!res.ok) throw new Error(`installation token: HTTP ${res.status}`);
    const body = (await res.json()) as { token: string; expires_at: string };
    installationToken = { token: body.token, expiresAt: Date.parse(body.expires_at) };
    return body.token;
  }

  async function get<T>(path: string, signal: AbortSignal): Promise<T> {
    const res = await fetchImpl(`${apiBase}${path}`, {
      headers: {
        authorization: `Bearer ${await bearer(signal)}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
      },
      signal,
    });
    if (!res.ok) throw new Error(`GitHub ${path}: HTTP ${res.status}`);
    return (await res.json()) as T;
  }

  return {
    name: 'github',
    applies: (request) =>
      APPLICABLE.has(request.action.class) &&
      repoOf(request) !== null &&
      typeof request.context?.branch === 'string',
    async provide(request, signal): Promise<Evidence[]> {
      const { owner, repo } = repoOf(request) as { owner: string; repo: string };
      const branch = request.context?.branch as string;
      const base = `/repos/${owner}/${repo}`;
      const prs = await get<
        { number: number; head: { sha: string }; user: { login: string }; html_url: string }[]
      >(`${base}/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}&per_page=1`, signal);
      const pr = prs[0];
      if (!pr) return []; // no PR ⇒ no approval evidence ⇒ PREREQ.MISSING_APPROVAL stays (absence is stated)

      const [reviews, checkRuns, status, files] = await Promise.all([
        get<{ user: { login: string }; state: string; submitted_at: string }[]>(
          `${base}/pulls/${pr.number}/reviews?per_page=100`,
          signal,
        ),
        get<{ total_count: number; check_runs: { status: string; conclusion: string | null }[] }>(
          `${base}/commits/${pr.head.sha}/check-runs?per_page=100`,
          signal,
        ),
        get<{ state: string; total_count: number }>(`${base}/commits/${pr.head.sha}/status`, signal),
        get<{ filename: string }[]>(`${base}/pulls/${pr.number}/files?per_page=100`, signal),
      ]);

      // Latest review per reviewer (excluding the author); approved iff ≥1 APPROVED and no CHANGES_REQUESTED.
      const latest = new Map<string, string>();
      for (const r of [...reviews].sort((a, b) => a.submitted_at.localeCompare(b.submitted_at))) {
        if (r.user.login === pr.user.login) continue;
        if (['APPROVED', 'CHANGES_REQUESTED'].includes(r.state)) latest.set(r.user.login, r.state);
      }
      const states = [...latest.values()];
      const approved = states.includes('APPROVED') && !states.includes('CHANGES_REQUESTED');

      const runs = checkRuns.check_runs;
      const runsDone = runs.length > 0 && runs.every((r) => r.status === 'completed');
      const runsOk =
        runsDone && runs.every((r) => ['success', 'neutral', 'skipped'].includes(r.conclusion ?? ''));
      const statusOk = status.total_count === 0 || status.state === 'success';
      const anyFailure =
        runs.some((r) =>
          ['failure', 'timed_out', 'cancelled', 'action_required'].includes(r.conclusion ?? ''),
        ) || status.state === 'failure';
      const checks = anyFailure
        ? 'failure'
        : runs.length === 0 && status.total_count === 0
          ? 'none'
          : runsOk && statusOk
            ? 'success'
            : 'pending';

      return [
        {
          id: `ev_gh_pr_${pr.number}`,
          type: 'github.pr',
          source: 'github',
          trust: 'verified',
          observed_at: now().toISOString(),
          confidence: 1,
          ttl_seconds: 120,
          data: {
            number: pr.number,
            url: pr.html_url,
            head_sha: pr.head.sha,
            approved,
            reviewers: Object.fromEntries(latest),
            checks,
            contains_migration: files.some((f) => MIGRATION_PATH.test(f.filename)),
          },
        },
      ];
    },
  };
}

/** Build the provider from environment variables; null when nothing is configured. */
export function githubProviderFromEnv(
  env: NodeJS.ProcessEnv,
  readFile: (path: string) => string,
): EvidenceProvider | null {
  if (env.GITHUB_APP_ID && env.GITHUB_APP_PRIVATE_KEY_PATH && env.GITHUB_APP_INSTALLATION_ID) {
    return githubProvider({
      auth: {
        kind: 'app',
        appId: env.GITHUB_APP_ID,
        privateKeyPem: readFile(env.GITHUB_APP_PRIVATE_KEY_PATH),
        installationId: env.GITHUB_APP_INSTALLATION_ID,
      },
    });
  }
  if (env.GITHUB_TOKEN) return githubProvider({ auth: { kind: 'token', token: env.GITHUB_TOKEN } });
  return null;
}
