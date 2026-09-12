import type { ActionClass } from '@vera/schemas';

/**
 * Tool call → VERA action (class, arguments, hints, target, environment).
 *
 * Deterministic: PostToolUse re-runs the same function on the same tool_input to recompute the action
 * hash, so nothing here may depend on time or randomness. Git facts (remote, branch) are injected and
 * are only used for target id / context, never for the hash-relevant arguments.
 *
 * Conservative by design (SR-03): anything unrecognised is `unknown.consequential`; shell commands
 * that look like anything but a read stay `shell.exec`; a more specific class is assigned only on
 * clear evidence. The tenant-signed class table (ADR-0002) will refine this in a later deliverable.
 */

export interface GitFacts {
  remote?: string | undefined;
  branch?: string | undefined;
  defaultBranch?: string | undefined;
}

export interface Classified {
  class: ActionClass;
  /** tool_input plus deterministic derived keys (force, branch) that Policy Pack 1 reads. */
  arguments: Record<string, unknown>;
  hints: { destructive?: boolean; read_only?: boolean; idempotent?: boolean };
  target: { kind: string; id: string; sensitivity?: 'low' | 'medium' | 'high'; default_branch?: string };
  environment: string;
  context: { branch?: string };
}

export interface ClassifyOptions {
  cwd: string;
  /** Baseline environment for this machine (config). Commands that clearly target production override it. */
  environment: string;
  git?: GitFacts;
}

const READ_TOOLS = new Set(['Read', 'Glob', 'Grep', 'LS', 'NotebookRead', 'TodoRead']);
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const HTTP_READ_TOOLS = new Set(['WebFetch', 'WebSearch']);
const HARMLESS_TOOLS = new Set([
  'TodoWrite',
  'Task',
  'AskUserQuestion',
  'EnterPlanMode',
  'ExitPlanMode',
  'Skill',
]);

// `_` is a word character to \b, so `$PROD_URL` and `db_prod` need explicit separators.
const PROD_HINT = /(^|[^a-z])(prod|production|live)([^a-z]|$)/i;
const DDL = /\b(alter|drop|create|truncate|rename)\s+(table|schema|database|index|column|type|extension)\b/i;
const DML = /\b(insert\s+into|update\s+\w+\s+set|delete\s+from|merge\s+into|upsert)\b/i;
const SQL_CLIENT = /\b(psql|mysql|mariadb|sqlite3|mongosh|redis-cli)\b/;
const DESTRUCTIVE_SHELL =
  /\b(rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|mkfs|dd\s+if=|shred|chmod\s+-R\s+777|:\(\)\s*\{)/;
const READ_ONLY_SHELL =
  /^\s*(ls|cat|head|tail|less|more|wc|grep|rg|find|fd|pwd|echo|printf|which|type|env|printenv|stat|file|du|df|tree|jq|yq|sort|uniq|diff|node\s+-v|npm\s+-v|pnpm\s+-v|python\d?\s+--version|git\s+(status|log|diff|show|branch|remote|rev-parse|ls-files|describe|blame|stash\s+list))\b/;
const DEPLOY =
  /\b(vercel\s+(deploy|--prod)|netlify\s+deploy|fly\s+deploy|heroku\s+(release|container:release)|kubectl\s+(apply|rollout|set\s+image)|helm\s+(install|upgrade)|terraform\s+apply|pulumi\s+up|aws\s+(cloudformation|ecs|lambda\s+update)|gcloud\s+(run\s+deploy|app\s+deploy)|serverless\s+deploy|cdk\s+deploy)\b/;
const INFRA =
  /\b(kubectl\s+(delete|drain|cordon)|terraform\s+destroy|docker\s+(rm|rmi|system\s+prune)|aws\s+\w+\s+delete|gcloud\s+\w+\s+delete)\b/;
const HTTP_MUTATION =
  /\bcurl\b[^|]*\s-X\s*(POST|PUT|PATCH|DELETE)\b|\bcurl\b[^|]*\s(-d|--data|--data-binary|--json)\b|\bhttp\s+(POST|PUT|PATCH|DELETE)\b/i;
const HTTP_READ = /^\s*(curl|wget|http)\b/;
const SECRET_READ =
  /\b(vault\s+(read|kv\s+get)|aws\s+secretsmanager\s+get-secret-value|gcloud\s+secrets\s+versions\s+access|op\s+(read|item\s+get)|doppler\s+secrets|cat\s+[^|]*\.(env|pem|key)\b)/;
const PUBLISH =
  /\b(npm\s+publish|pnpm\s+publish|yarn\s+publish|cargo\s+publish|gem\s+push|twine\s+upload|docker\s+push|gh\s+release\s+create)\b/;

function gitPush(
  command: string,
  git: GitFacts | undefined,
): { force: boolean; branch: string | undefined } | null {
  const m = command.match(/\bgit\s+push\b(.*)/);
  if (!m) return null;
  const rest = m[1] ?? '';
  const force = /(\s|^)(-f|--force|--force-with-lease(=\S*)?)(\s|$)/.test(rest) || /\s\+\S+/.test(rest);
  // Last positional token is the refspec: `branch`, `src:dst`, or just the remote.
  const tokens = rest
    .trim()
    .split(/\s+/)
    .filter((t) => t && !t.startsWith('-'));
  const last = tokens.at(-1)?.replace(/^\+/, '');
  const dst = last?.includes(':') ? last.split(':').at(-1) : last;
  const looksLikeRemoteOnly = !dst || tokens.length < 2 || /^(origin|upstream)$/.test(dst);
  return { force, branch: looksLikeRemoteOnly ? git?.branch : dst };
}

export function classify(
  toolName: string,
  toolInput: Record<string, unknown>,
  opts: ClassifyOptions,
): Classified {
  const git = opts.git;
  const repoId = git?.remote ?? opts.cwd.replace(/\\/g, '/').split('/').filter(Boolean).at(-1) ?? 'workspace';
  const base = (cls: ActionClass, over: Partial<Classified> = {}): Classified => ({
    class: cls,
    arguments: toolInput,
    hints: {},
    target: { kind: 'workspace', id: repoId },
    environment: opts.environment,
    context: git?.branch ? { branch: git.branch } : {},
    ...over,
  });

  if (READ_TOOLS.has(toolName)) return base('file.read', { hints: { read_only: true } });
  if (HTTP_READ_TOOLS.has(toolName)) return base('http.read', { hints: { read_only: true } });
  if (HARMLESS_TOOLS.has(toolName)) return base('search', { hints: { read_only: true } });
  if (WRITE_TOOLS.has(toolName)) {
    const path = typeof toolInput.file_path === 'string' ? toolInput.file_path : undefined;
    return base('file.write', { arguments: { ...toolInput, ...(path ? { path } : {}) } });
  }

  if (toolName.startsWith('mcp__')) {
    const tool = toolName.split('__').at(-1) ?? '';
    const readish = /(^|_)(read|list|get|search|fetch|query|describe|show|view)($|_)/.test(tool);
    return base(readish ? 'http.read' : 'unknown.consequential', {
      hints: { read_only: readish },
      target: { kind: 'mcp', id: toolName },
    });
  }

  if (toolName === 'Bash') {
    const command = typeof toolInput.command === 'string' ? toolInput.command : '';
    const prod = PROD_HINT.test(command);
    const environment = prod ? 'production' : opts.environment;

    const push = gitPush(command, git);
    if (push) {
      return base('vcs.push', {
        arguments: { ...toolInput, force: push.force, ...(push.branch ? { branch: push.branch } : {}) },
        hints: push.force ? { destructive: true } : {},
        target: { kind: 'repository', id: repoId, default_branch: git?.defaultBranch ?? 'main' },
        environment: 'production', // a push leaves the machine; treat the remote as production
        context: push.branch ? { branch: push.branch } : {},
      });
    }
    if (
      /\bgit\s+(merge|rebase|reset\s+--hard|checkout\s+--|restore\s+--staged|branch\s+-D|tag\s+-d)\b/.test(
        command,
      )
    )
      return base('vcs.merge', {
        hints: { destructive: /reset\s+--hard|branch\s+-D|checkout\s+--/.test(command) },
      });
    if (
      READ_ONLY_SHELL.test(command) &&
      !/[|;&>]/.test(command.replace(/\|\s*(grep|head|tail|wc|sort|uniq|jq|less|cat)\b.*/g, ''))
    )
      return base('vcs.read', { hints: { read_only: true } });
    if (SQL_CLIENT.test(command) || DDL.test(command) || DML.test(command)) {
      const dbTarget = {
        kind: 'database',
        id: (command.match(/(?:-h|--host)[=\s]+(\S+)/)?.[1] ??
          command.match(/postgres(?:ql)?:\/\/[^/\s]+\/([\w-]+)/)?.[1] ??
          'unknown') as string,
        sensitivity: (prod ? 'high' : 'medium') as 'high' | 'medium',
      };
      if (DDL.test(command))
        return base('db.ddl', {
          hints: { destructive: /\b(drop|truncate)\b/i.test(command) },
          target: dbTarget,
          environment,
        });
      if (DML.test(command))
        return base('db.write', {
          hints: { destructive: /\bdelete\s+from\b/i.test(command) },
          target: dbTarget,
          environment,
        });
      return base('db.read', { hints: { read_only: true }, target: dbTarget, environment });
    }
    if (SECRET_READ.test(command))
      return base('secret.read', {
        target: { kind: 'secret-store', id: 'local', sensitivity: 'high' },
        environment,
      });
    if (DEPLOY.test(command) || PUBLISH.test(command))
      return base(prod || PUBLISH.test(command) ? 'deploy.production' : 'deploy.staging', {
        hints: { idempotent: false },
        target: { kind: 'deployment', id: repoId, sensitivity: 'high' },
        environment: prod || PUBLISH.test(command) ? 'production' : environment,
      });
    if (INFRA.test(command))
      return base('infra.change', {
        hints: { destructive: true },
        target: { kind: 'infrastructure', id: 'unknown', sensitivity: 'high' },
        environment,
      });
    if (HTTP_MUTATION.test(command))
      return base('http.mutation', {
        target: { kind: 'http', id: command.match(/https?:\/\/[^\s'"]+/)?.[0] ?? 'unknown' },
        environment,
      });
    if (HTTP_READ.test(command))
      return base('http.read', {
        hints: { read_only: true },
        target: { kind: 'http', id: command.match(/https?:\/\/[^\s'"]+/)?.[0] ?? 'unknown' },
        environment,
      });
    return base('shell.exec', { hints: { destructive: DESTRUCTIVE_SHELL.test(command) }, environment });
  }

  return base('unknown.consequential');
}
