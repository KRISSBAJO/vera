#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  AdapterConfigSchema,
  configPath,
  type DegradedEvent,
  degradedQueuePath,
  type GitFacts,
  type HookDeps,
  type HookState,
  hooksSettings,
  loadConfig,
  mergeHooksInto,
  PostToolUseInputSchema,
  PreToolUseInputSchema,
  preOutput,
  runPost,
  runPre,
  saveConfig,
  statePath,
  VeraClient,
  veraHome,
} from './index.js';

const usage = `vera-hook <command>

  pre                 PreToolUse hook: reads hook JSON on stdin, prints the decision JSON
  post                PostToolUse hook: reports the outcome, recomputes the action hash
  init --endpoint <url> --api-key <vera_sk_…> --org <org_id> --aud <receiver>
       [--acting-for <email>] [--environment development] [--settings <path/to/settings.json>]
                      writes ~/.vera/config.json (0600); with --settings, merges the hooks block into that file
  status              shows config location, endpoint, and queued degraded-mode events
`;

function git(cwd: string): GitFacts | undefined {
  const run = (...args: string[]) => {
    try {
      return (
        execFileSync('git', args, { cwd, timeout: 800, stdio: ['ignore', 'pipe', 'ignore'] })
          .toString()
          .trim() || undefined
      );
    } catch {
      return undefined;
    }
  };
  const inside = run('rev-parse', '--is-inside-work-tree');
  if (inside !== 'true') return undefined;
  const remote = run('remote', 'get-url', 'origin')
    ?.replace(/^git@([^:]+):/, '$1/')
    .replace(/^https?:\/\//, '')
    .replace(/\.git$/, '');
  const branch = run('rev-parse', '--abbrev-ref', 'HEAD');
  const head = run('symbolic-ref', '--short', 'refs/remotes/origin/HEAD');
  return { remote, branch, defaultBranch: head?.replace(/^origin\//, '') ?? 'main' };
}

const fileState = {
  async save(toolUseId: string, state: HookState) {
    const p = statePath(toolUseId);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(state));
  },
  async load(toolUseId: string) {
    const p = statePath(toolUseId);
    return existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')) as HookState) : undefined;
  },
};

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function deps(cfg: ReturnType<typeof loadConfig>): HookDeps {
  return {
    client: new VeraClient({
      endpoint: cfg.endpoint,
      apiKey: cfg.apiKey,
      org: cfg.org,
      requestTimeoutMs: cfg.requestTimeoutMs,
    }),
    state: fileState,
    git,
    queueDegraded: async (event: DegradedEvent) => {
      mkdirSync(veraHome(), { recursive: true });
      appendFileSync(degradedQueuePath(), `${JSON.stringify(event)}\n`);
    },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => Date.now(),
    log: (line) => process.stderr.write(`${line}\n`),
  };
}

const [command, ...rest] = process.argv.slice(2);

switch (command) {
  case 'pre': {
    // A thrown error here would fail open in Claude Code. Every failure becomes an explicit `ask`.
    try {
      const input = PreToolUseInputSchema.parse(JSON.parse(await readStdin()));
      const cfg = loadConfig();
      const out = await runPre(input, cfg, deps(cfg));
      process.stdout.write(JSON.stringify(out));
    } catch (e) {
      process.stdout.write(
        JSON.stringify(
          preOutput(
            'ask',
            `vera-hook could not decide (${e instanceof Error ? e.message : e}); a human must`,
          ),
        ),
      );
    }
    break;
  }
  case 'post': {
    try {
      const input = PostToolUseInputSchema.parse(JSON.parse(await readStdin()));
      const cfg = loadConfig();
      await runPost(input, cfg, deps(cfg));
    } catch {
      // never block on post
    }
    process.stdout.write('{}');
    break;
  }
  case 'init': {
    const { values } = parseArgs({
      args: rest,
      options: {
        endpoint: { type: 'string' },
        'api-key': { type: 'string' },
        org: { type: 'string' },
        aud: { type: 'string' },
        'acting-for': { type: 'string' },
        environment: { type: 'string' },
        settings: { type: 'string' },
        /** How Claude Code should invoke this hook; defaults to `vera-hook` on PATH. */
        command: { type: 'string' },
      },
    });
    const hookCommand = values.command ?? 'vera-hook';
    const cfg = AdapterConfigSchema.parse({
      endpoint: values.endpoint,
      apiKey: values['api-key'],
      org: values.org,
      aud: values.aud,
      ...(values['acting-for'] ? { actingFor: values['acting-for'] } : {}),
      ...(values.environment ? { environment: values.environment } : {}),
    });
    const path = saveConfig(cfg);
    console.log(`wrote ${path}`);
    if (values.settings) {
      mergeHooksInto(values.settings, hookCommand);
      console.log(`merged hooks into ${values.settings} (command: ${hookCommand})`);
    } else {
      console.log(
        `\nAdd to your Claude Code settings.json (or rerun with --settings <path>):\n${JSON.stringify(hooksSettings(hookCommand), null, 2)}`,
      );
    }
    break;
  }
  case 'status': {
    const cfg = loadConfig();
    const q = existsSync(degradedQueuePath())
      ? readFileSync(degradedQueuePath(), 'utf8').split('\n').filter(Boolean).length
      : 0;
    console.log(
      `config     ${configPath()}\nendpoint   ${cfg.endpoint}\norg        ${cfg.org}\naud        ${cfg.aud}\nacting_for ${cfg.actingFor ?? '(none)'}\nhold       ${cfg.holdSeconds}s → ${cfg.onHoldExpiry}\nqueued degraded events: ${q}${q ? ` (${join(veraHome(), 'degraded-queue.jsonl')})` : ''}`,
    );
    break;
  }
  default:
    console.error(usage);
    process.exit(command ? 2 : 0);
}
