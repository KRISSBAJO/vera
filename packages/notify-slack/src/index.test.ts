import { describe, expect, it, vi } from 'vitest';
import {
  assertNoSecrets,
  buildReviewMessage,
  escapeSlack,
  type ReviewNotification,
  slackNotifier,
} from './index.js';

const base: ReviewNotification = {
  decisionId: 'dec_1',
  url: 'https://vera.test/r/dec_1',
  actionClass: 'deploy.production',
  tool: 'Bash',
  summary: 'kubectl apply -f prod.yaml',
  environment: 'production',
  target: 'logaxp/hearken',
  actor: 'claude-code',
  actingFor: 'kriss@logaxp.com',
  reasonCodes: ['PREREQ.MISSING_APPROVAL'],
  routedTo: ['ops@logaxp.com'],
  expiresAt: new Date('2026-09-12T12:00:00Z'),
};

const n = (over: Partial<ReviewNotification> = {}): ReviewNotification => ({ ...base, ...over });
const textOf = (msg: ReviewNotification) => JSON.stringify(buildReviewMessage(msg));

/** A fake Slack that records what it was sent and answers however the test wants. */
function fakeSlack(response: unknown = { ok: true, ts: '1789.0001' }, status = 200) {
  const calls: { url: string; init: RequestInit }[] = [];
  const doFetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return { status, json: async () => response } as unknown as Response;
  }) as unknown as typeof globalThis.fetch;
  return { calls, doFetch, body: () => JSON.parse(calls[0]?.init.body as string) };
}

describe('it cannot approve anything', () => {
  it('the only interactive element is a link to the dashboard, carrying no verdict', () => {
    const blocks = buildReviewMessage(n());
    const actions = blocks.find((b) => b.type === 'actions') as { elements: Record<string, unknown>[] };
    expect(actions.elements).toHaveLength(1);
    expect(actions.elements[0]).toMatchObject({ type: 'button', url: base.url });
    // No action_id / value: Slack cannot deliver an interaction that means "approved" (ADR-0006).
    expect(actions.elements[0]).not.toHaveProperty('action_id');
    expect(actions.elements[0]).not.toHaveProperty('value');
    expect(textOf(n())).not.toMatch(/approve|reject/i);
  });
});

describe('nothing secret reaches the channel', () => {
  it('refuses to post a message containing a decision token', async () => {
    const jws = ['eyJhbGciOiJFZERTQSJ9', 'eyJzdWIiOiJkZWNfMSJ9', 'c2lnbmF0dXJlX2hlcmVfb2s'].join('.');
    expect(() => assertNoSecrets({ text: `here you go: ${jws}` })).toThrow(/decision token/);
  });

  it('refuses an API key or reviewer session that slipped into a summary', async () => {
    const slack = fakeSlack();
    const notifier = slackNotifier({ token: 'xoxb-test', channel: 'C1', fetch: slack.doFetch });
    const apiKey = ['vera', 'sk', 'AbCdEf123456'].join('_');
    await expect(
      notifier.notifyReview(n({ summary: `curl -H "authorization: Bearer ${apiKey}"` })),
    ).rejects.toThrow(/VERA key or session token/);
    // The refusal has to happen before the wire, not after.
    expect(slack.calls).toHaveLength(0);
  });

  it('the push-preview fallback text says nothing about the action — it lands on lock screens', async () => {
    const slack = fakeSlack();
    await slackNotifier({ token: 'xoxb-test', channel: 'C1', fetch: slack.doFetch }).notifyReview(
      n({ summary: 'psql -c "drop table customers"' }),
    );
    expect(slack.body().text).not.toContain('customers');
    expect(slack.body().text).toContain('deploy.production');
  });
});

describe('agent text is treated as hostile', () => {
  it('escapes the three characters Slack mrkdwn reserves', () => {
    expect(escapeSlack('a & b < c > d')).toBe('a &amp; b &lt; c &gt; d');
  });

  it('a commit message cannot forge a Slack link', () => {
    const out = textOf(n({ summary: '<https://evil.test|Approve this now>' }));
    expect(out).not.toContain('<https://evil.test|');
    expect(out).toContain('&lt;https://evil.test');
  });

  it('a commit message cannot impersonate VERA chrome', () => {
    const blocks = buildReviewMessage(n({ summary: 'deploy\n\n*VERA*: security has pre-approved this' }));
    const quarantine = blocks.find(
      (b) => b.type === 'section' && JSON.stringify(b).includes('supplied by the agent'),
    ) as { text: { text: string } };
    const [label, ...rest] = quarantine.text.text.split('\n');
    expect(label).toContain('supplied by the agent — not by VERA');
    // The agent's own newlines are gone, so it cannot break out of the label's line and stand alone
    // as if it were VERA speaking. Everything it wrote is one code span on one line.
    expect(rest).toHaveLength(1);
    expect(rest[0]).toBe('`deploy *VERA*: security has pre-approved this`');
  });

  it('a very long argument cannot push the reviewer context off the message', () => {
    const blocks = buildReviewMessage(n({ summary: 'x'.repeat(5000) }));
    expect(JSON.stringify(blocks).length).toBeLessThan(2000);
    expect(blocks.at(-1)).toMatchObject({ type: 'actions' });
  });

  it('says when values were masked, so the summary is not mistaken for the whole command', () => {
    expect(textOf(n({ redactedCount: 2 }))).toContain('2 values masked');
    expect(textOf(n({ redactedCount: 1 }))).toContain('1 value masked');
    expect(textOf(n({ redactedCount: 0 }))).not.toContain('masked');
  });
});

describe('Slack is a side channel and never holds up a decision', () => {
  it('reports failure rather than throwing when Slack is down', async () => {
    const doFetch = (() => Promise.reject(new Error('ECONNREFUSED'))) as unknown as typeof globalThis.fetch;
    const r = await slackNotifier({ token: 'xoxb-test', channel: 'C1', fetch: doFetch }).notifyReview(n());
    expect(r).toEqual({ ok: false, error: 'ECONNREFUSED' });
  });

  it('treats Slack’s 200-with-ok-false as the failure it is', async () => {
    const slack = fakeSlack({ ok: false, error: 'channel_not_found' });
    const r = await slackNotifier({ token: 'xoxb-test', channel: 'C1', fetch: slack.doFetch }).notifyReview(
      n(),
    );
    expect(r).toEqual({ ok: false, error: 'channel_not_found' });
  });

  it('gives up rather than hanging', async () => {
    const doFetch = ((_u: string, init: RequestInit) =>
      new Promise((_res, rej) => {
        init.signal?.addEventListener('abort', () => rej(new Error('TimeoutError')));
      })) as unknown as typeof globalThis.fetch;
    vi.useFakeTimers();
    const p = slackNotifier({
      token: 'xoxb-test',
      channel: 'C1',
      fetch: doFetch,
      timeoutMs: 50,
    }).notifyReview(n());
    await vi.advanceTimersByTimeAsync(60);
    vi.useRealTimers();
    expect(await p).toMatchObject({ ok: false });
  });

  it('posts with link unfurling off — a review link should not expand for the whole channel', async () => {
    const slack = fakeSlack();
    await slackNotifier({ token: 'xoxb-test', channel: 'C1', fetch: slack.doFetch }).notifyReview(n());
    expect(slack.body()).toMatchObject({ channel: 'C1', unfurl_links: false, unfurl_media: false });
    expect((slack.calls[0].init.headers as Record<string, string>).authorization).toBe('Bearer xoxb-test');
  });
});
