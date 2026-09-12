/**
 * Slack review notifications (ADR-0006).
 *
 * This package tells a reviewer that a decision is waiting and links them to it. It deliberately
 * cannot approve anything: there are no buttons that carry a verdict, and no code path that sends a
 * decision token. Approval stays in the dashboard, where the approver's identity is ours rather than
 * Slack's and the agent's text sits inside a real quarantine region.
 */

/** Slack mrkdwn reserves exactly these three (https://docs.slack.dev/messaging/formatting-message-text). */
export function escapeSlack(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Shapes that must never reach a channel: a decision token, an API key, a reviewer session. Slack
 * messages are readable by everyone in the channel and are retained indefinitely, so a leak here
 * hands approval authority to the room. This is the last check before the wire — the callers are
 * supposed to have redacted already, and the guard exists for when one of them forgets.
 */
const FORBIDDEN: readonly { name: string; pattern: RegExp }[] = [
  { name: 'a JWS (decision token)', pattern: /\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { name: 'a VERA key or session token', pattern: /\bvera_(?:sk|rs|ak)_[A-Za-z0-9_-]{6,}/ },
  { name: 'a Slack token', pattern: /\bxox[bapsr]-[A-Za-z0-9-]{6,}/ },
];

export function assertNoSecrets(payload: unknown): void {
  const text = JSON.stringify(payload);
  for (const { name, pattern } of FORBIDDEN) {
    if (pattern.test(text)) {
      throw new Error(`refusing to post to Slack: the message contains what looks like ${name}`);
    }
  }
}

export interface ReviewNotification {
  decisionId: string;
  /** Dashboard review URL. The only thing in the message that leads to an approval. */
  url: string;
  actionClass: string;
  tool: string;
  /** Agent-supplied, already redacted by the caller (SR-15). Rendered as untrusted text. */
  summary: string;
  environment: string;
  target: string;
  actor: string;
  actingFor?: string | undefined;
  reasonCodes: readonly string[];
  routedTo: readonly string[];
  expiresAt: Date;
  /** How many values redaction masked, so the reviewer knows the summary is not the whole truth. */
  redactedCount?: number | undefined;
}

const MAX_SUMMARY = 500;

/** One line of agent text, escaped, truncated, and never allowed to start a new block. */
function quarantined(summary: string): string {
  const flattened = summary.replace(/\s+/g, ' ').trim();
  const clipped = flattened.length > MAX_SUMMARY ? `${flattened.slice(0, MAX_SUMMARY)}…` : flattened;
  // Escaped first, then wrapped in a code span: two independent reasons a crafted commit message
  // cannot produce something that looks like VERA's own chrome.
  return `\`${escapeSlack(clipped) || '(no arguments)'}\``;
}

export function buildReviewMessage(n: ReviewNotification): Record<string, unknown>[] {
  const who = n.actingFor ? `${n.actor} acting for ${n.actingFor}` : n.actor;
  const fields = [
    `*Action*\n${escapeSlack(n.actionClass)} (${escapeSlack(n.tool)})`,
    `*Target*\n${escapeSlack(n.target)} · ${escapeSlack(n.environment)}`,
    `*Requested by*\n${escapeSlack(who)}`,
    `*Routed to*\n${n.routedTo.length ? n.routedTo.map(escapeSlack).join(', ') : 'any reviewer'}`,
  ];
  const redactionNote =
    n.redactedCount && n.redactedCount > 0
      ? ` · ${n.redactedCount} value${n.redactedCount === 1 ? '' : 's'} masked`
      : '';

  return [
    {
      type: 'header',
      text: { type: 'plain_text', text: 'Review needed', emoji: false },
    },
    { type: 'section', fields: fields.map((text) => ({ type: 'mrkdwn', text })) },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        // Labelled so the reader can see where VERA's words end and the agent's begin (T04).
        text: `*Text supplied by the agent — not by VERA:*\n${quarantined(n.summary)}`,
      },
    },
    {
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `${n.reasonCodes.map((c) => `\`${escapeSlack(c)}\``).join(' ')} · expires <!date^${Math.floor(
            n.expiresAt.getTime() / 1000,
          )}^{time}|${n.expiresAt.toISOString()}>${redactionNote}`,
        },
      ],
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          // A link, not a verdict: clicking navigates to the dashboard, it does not approve.
          text: { type: 'plain_text', text: 'Open in VERA', emoji: false },
          url: n.url,
        },
      ],
    },
  ];
}

export interface SlackNotifierOptions {
  /** Bot token (xoxb-…). */
  token: string;
  /** Channel or user id review requests go to. */
  channel: string;
  fetch?: typeof globalThis.fetch;
  /** Slack is a side channel; never let it hold up a decision. */
  timeoutMs?: number;
}

export interface Notifier {
  notifyReview(n: ReviewNotification): Promise<{ ok: true; ts: string } | { ok: false; error: string }>;
}

const SLACK_POST_MESSAGE = 'https://slack.com/api/chat.postMessage';

export function slackNotifier(opts: SlackNotifierOptions): Notifier {
  const doFetch = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 3000;

  return {
    async notifyReview(n) {
      const blocks = buildReviewMessage(n);
      const body = {
        channel: opts.channel,
        // Fallback for notifications and screen readers. Deliberately says nothing about the action:
        // push previews land on lock screens.
        text: `VERA: a ${n.actionClass} decision is waiting for review`,
        blocks,
        unfurl_links: false,
        unfurl_media: false,
      };
      assertNoSecrets(body);

      try {
        const res = await doFetch(SLACK_POST_MESSAGE, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${opts.token}`,
            'content-type': 'application/json; charset=utf-8',
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
        });
        // Slack answers 200 with {ok:false} for application errors; the status alone proves nothing.
        const json = (await res.json()) as { ok?: boolean; error?: string; ts?: string };
        if (!json.ok) return { ok: false, error: json.error ?? `http_${res.status}` };
        return { ok: true, ts: json.ts ?? '' };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}
