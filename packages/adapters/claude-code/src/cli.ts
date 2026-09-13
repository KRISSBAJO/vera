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
  type JournalEntry,
  journalPath,
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
  recent [--n 10]     the last decisions VERA made for this machine, newest first
  wrong <id|last> --should ALLOW|REVIEW|BLOCK [--why "…"]
                      tell VERA a verdict was wrong. This is the dogfood loop: every entry ends up in
                      GET /v1/reports/wrong-verdicts, grouped by the policy and reason codes behind it
`;

const JOURNAL_MAX = 500;

function readJournal(): JournalEntry[] {
  if (!existsSync(journalPath())) return [];
  return readFileSync(journalPath(), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as JournalEntry);
}

async function appendJournal(entry: JournalEntry): Promise<void> {
  mkdirSync(veraHome(), { recursive: true });
  appendFileSync(journalPath(), `${JSON.stringify(entry)}\n`);
  // Keep the file bounded without a second process: rewrite only when it has grown well past the cap.
  const lines = readFileSync(journalPath(), 'utf8').split('\n').filter(Boolean);
  if (lines.length > JOURNAL_MAX * 1.5) writeFileSync(journalPath(), `${lines.slice(-JOURNAL_MAX).join('\n')}\n`);
}

const RANK: Record<string, number> = { ALLOW: 0, REVIEW: 1, BLOCK: 2 };
const ago = (iso: string) => {
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
};

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
    journal: appendJournal,
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
  case 'recent': {
    const { values } = parseArgs({ args: rest, options: { n: { type: 'string' } } });
    const n = Math.max(1, Number(values.n ?? 10));
    const entries = readJournal().slice(-n).reverse();
    if (entries.length === 0) {
      console.log(`no decisions journaled yet (${journalPath()})`);
      break;
    }
    for (const e of entries) {
      console.log(
        `${e.decision_id}  ${e.verdict.padEnd(6)}  ${ago(e.at).padStart(7)}  ${e.class.padEnd(18)}  ${e.program}`,
      );
    }
    break;
  }
  case 'wrong': {
    const { values, positionals } = parseArgs({
      args: rest,
      options: { should: { type: 'string' }, why: { type: 'string' } },
      allowPositionals: true,
    });
    const should = values.should?.toUpperCase();
    if (!should || !(should in RANK)) {
      console.error(`--should must be ALLOW, REVIEW or BLOCK\n\n${usage}`);
      process.exit(2);
    }
    const ref = positionals[0] ?? 'last';
    const journal = readJournal();
    const entry = ref === 'last' ? journal.at(-1) : journal.find((e) => e.decision_id === ref);
    if (!entry) {
      console.error(
        ref === 'last' ? `nothing in the journal yet (${journalPath()})` : `${ref} is not in the local journal; run \`vera-hook recent\``,
      );
      process.exit(1);
    }
    if (entry.verdict === should) {
      console.error(`${entry.decision_id} was already ${should} — that is not a wrong verdict`);
      process.exit(1);
    }
    // Looser than a human wanted is a false negative; stricter is a false positive. The distinction is
    // the whole point of the report: one false negative is a policy gap, ten false positives are fatigue.
    const kind = RANK[should]! > RANK[entry.verdict]! ? 'false_negative' : 'false_positive';
    const cfg = loadConfig();
    await deps(cfg).client.outcome(entry.decision_id, kind, {
      should_have_been: should,
      decided: entry.verdict,
      note: values.why ?? null,
      class: entry.class,
      program: entry.program,
    });
    console.log(
      `recorded ${kind.replace('_', ' ')}: ${entry.decision_id} was ${entry.verdict}, should have been ${should}${values.why ? ` — ${values.why}` : ''}`,
    );
    break;
  }
  default:
    console.error(usage);
    process.exit(command ? 2 : 0);
}
