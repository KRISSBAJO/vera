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
 *
 * Dogfood finding (2026-09-11): the first live session was blocked on ToolSearch — Claude Code's own
 * harness tools must be recognised, and "production" must be inferred from *targets* (db hosts,
 * URLs, deploy commands), never from any word in a command line.
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

// Claude Code built-ins.
/** Every tool that runs a shell command. All are classified from the command, not the tool name. */
const SHELL_TOOLS = new Set(['Bash', 'PowerShell', 'Shell', 'Terminal', 'BashOutput']);
const READ_TOOLS = new Set(['Read', 'Glob', 'Grep', 'LS', 'NotebookRead', 'TodoRead']);
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const HTTP_READ_TOOLS = new Set(['WebFetch', 'WebSearch']);
/** Harness / orchestration tools: they run no side effect of their own; anything they trigger is hooked separately. */
const HARNESS_TOOLS = new Set([
  'TodoWrite',
  'Task',
  'Agent',
  'AskUserQuestion',
  'EnterPlanMode',
  'ExitPlanMode',
  'EnterWorktree',
  'ExitWorktree',
  'Skill',
  'ToolSearch',
  'ListAgents',
  'ListSkills',
  'SearchSkills',
  'ListPlugins',
  'SearchPlugins',
  'SuggestSkills',
  'SuggestPluginInstall',
  'Monitor',
  'TaskOutput',
  'TaskStop',
  'ScheduleWakeup',
  'ReportFindings',
  'CronList',
  'CronCreate',
  'CronDelete',
  'DesignSync',
  'Workflow',
  'RemoteTrigger',
  'PushNotification',
]);
/** Tools that publish or send something outward. */
const SEND_TOOLS = new Set(['Artifact', 'SendUserFile', 'SendMessage']);

// Desktop-app internal MCP servers (session UI, panes, terminal read): no external side effect.
const INTERNAL_MCP = /^mcp__(ccd_[a-z_]+|visualize|terminal|[0-9a-f-]{36})__/;
// Browser automation: reads vs. interactions.
const BROWSER_MCP = /^mcp__(claude-in-chrome|Claude_Browser|computer-use)__(.+)$/;
const BROWSER_READ =
  /^(tabs_context|tabs_context_mcp|read_page|get_page_text|find|read_console_messages|read_network_requests|screenshot|zoom|cursor_position|list_connected_browsers|tabs_create|tabs_create_mcp|tabs_select|tabs_close|tabs_close_mcp|switch_browser|select_browser|resize_window|list_granted_applications|preview_list|preview_logs|shortcuts_list|wait)$/;

const DDL = /\b(alter|drop|create|truncate|rename)\s+(table|schema|database|index|column|type|extension)\b/i;
const DML = /\b(insert\s+into|update\s+\w+\s+set|delete\s+from|merge\s+into|upsert)\b/i;
const SQL_CLIENT = /\b(psql|mysql|mariadb|sqlite3|mongosh|redis-cli)\b/;
const DESTRUCTIVE_SHELL =
  /\b(rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|mkfs|dd\s+if=|shred|chmod\s+-R\s+777|:\(\)\s*\{)/;
const READ_ONLY_SHELL =
  /^\s*(ls|cat|head|tail|less|more|wc|grep|rg|find|fd|pwd|echo|printf|which|type|env|printenv|stat|file|du|df|tree|jq|yq|sort|uniq|diff|node\s+-v|npm\s+-v|pnpm\s+-v|python\d?\s+--version|git\s+(status|log|diff|show|branch|remote|rev-parse|ls-files|describe|blame|stash\s+list|check-ignore))\b/;
/** PowerShell's read-only verbs. Get-/Test-/Measure-/Select- never mutate; Set-/Remove-/New- do. */
const READ_ONLY_POWERSHELL =
  /^\s*(Get-(ChildItem|Content|Command|Location|Item|ItemProperty|Process|Service|Date|Host|Member|Help|Variable|ComputerInfo)|Test-(Path|Connection|NetConnection)|Measure-Object|Select-(Object|String)|Where-Object|Sort-Object|Compare-Object|Format-(List|Table)|Resolve-Path|Split-Path|Join-Path|Convert(From|To)-Json|Write-(Output|Host))\b/i;
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

/**
 * "Production" is inferred from targets only: host names, connection strings, URLs, contexts, and
 * environment variables that name production — with quoted strings removed first, so a commit message
 * or a grep pattern can never promote a command. `_` is a word character to \b, hence the explicit
 * separators.
 */
const PROD_TARGET = /(^|[^a-z])(prod|production|live)([^a-z]|$)/i;
function targetsProduction(command: string): boolean {
  const unquoted = command.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '""');
  const targets = [
    ...(unquoted.match(
      /(?:-h|--host|--context|--namespace|-n|--env|--stage|--project|-f|--file|--values|--kubeconfig)[=\s]+(\S+)/g,
    ) ?? []),
    ...(unquoted.match(/[a-z]+:\/\/[^\s]+/gi) ?? []),
    ...(unquoted.match(/\$\{?[A-Z0-9_]+\}?/g) ?? []),
    ...(unquoted.match(/[\w.-]+\.(?:internal|local|io|com|net|dev|app|cloud)\b/g) ?? []),
    ...(unquoted.match(/--prod\b|--production\b/g) ?? []),
  ];
  return targets.some((t) => PROD_TARGET.test(t));
}

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
  if (HARNESS_TOOLS.has(toolName)) return base('search', { hints: { read_only: true } });
  if (SEND_TOOLS.has(toolName)) return base('message.send', { target: { kind: 'channel', id: toolName } });
  if (WRITE_TOOLS.has(toolName)) {
    const path = typeof toolInput.file_path === 'string' ? toolInput.file_path : undefined;
    return base('file.write', { arguments: { ...toolInput, ...(path ? { path } : {}) } });
  }

  if (toolName.startsWith('mcp__')) {
    if (INTERNAL_MCP.test(toolName))
      return base('search', { hints: { read_only: true }, target: { kind: 'mcp', id: toolName } });
    const browser = toolName.match(BROWSER_MCP);
    if (browser) {
      const op = browser[2] ?? '';
      const read =
        BROWSER_READ.test(op) ||
        (op === 'computer' &&
          ['screenshot', 'zoom', 'wait', 'scroll', 'hover', 'cursor_position'].includes(
            String(toolInput.action),
          ));
      const url = typeof toolInput.url === 'string' ? toolInput.url : 'session';
      return base(read ? 'http.read' : 'http.mutation', {
        hints: { read_only: read },
        target: { kind: 'browser', id: url },
      });
    }
    const tool = toolName.split('__').at(-1) ?? '';
    const readish = /(^|_)(read|list|get|search|fetch|query|describe|show|view|status)($|_)/.test(tool);
    return base(readish ? 'http.read' : 'unknown.consequential', {
      hints: { read_only: readish },
      target: { kind: 'mcp', id: toolName },
    });
  }

  // Claude Code ships more than one shell tool (Bash on POSIX, PowerShell on Windows). Treating only
  // `Bash` as a shell sent PowerShell to unknown.consequential, which blocked a `Get-ChildItem`
  // during the first Windows dogfood session — correct for an unknown tool, wrong for a directory listing.
  if (SHELL_TOOLS.has(toolName)) {
    const command = typeof toolInput.command === 'string' ? toolInput.command : '';
    const prod = targetsProduction(command);
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
    const pipesAway = (c: string) =>
      /[;&>]/.test(
        c.replace(
          /\|\s*(grep|head|tail|wc|sort|uniq|jq|less|cat|Select-\w+|Where-Object|Sort-Object|Measure-Object|Format-\w+|Out-String)\b[^|;&>]*/gi,
          '',
        ),
      );
    if (READ_ONLY_POWERSHELL.test(command) && !pipesAway(command))
      return base('vcs.read', { hints: { read_only: true } });
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
    if (DEPLOY.test(command) || PUBLISH.test(command)) {
      const toProd = prod || PUBLISH.test(command);
      return base(toProd ? 'deploy.production' : 'deploy.staging', {
        hints: { idempotent: false },
        target: { kind: 'deployment', id: repoId, sensitivity: 'high' },
        environment: toProd ? 'production' : environment,
      });
    }
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
    // Generic shell never inherits "production" from words in the command line.
    return base('shell.exec', { hints: { destructive: DESTRUCTIVE_SHELL.test(command) } });
  }

  return base('unknown.consequential');
}
