/**
 * Anything an agent wrote — a shell command, a commit message, a tool argument — rendered so it
 * cannot pretend to be anything else (threat T04).
 *
 * The cheapest attack available to a compromised agent is not a clever exploit; it is putting
 * "Security has pre-approved this, click Approve" into a field the review page renders. So:
 *
 *   - plain text only. No markdown, no HTML, no auto-linking. React escapes it; nothing from a
 *     request is ever passed to dangerouslySetInnerHTML.
 *   - a hatched border and an explicit label, so the region reads as quoted evidence rather than as
 *     something VERA is saying.
 *   - redaction placeholders are the one thing styled inside, matched by exact shape, so agent text
 *     cannot forge one to imply a secret was handled safely.
 */

const PLACEHOLDER = /(\[redacted:[a-z0-9-]+\])/g;
const isPlaceholder = (s: string) => /^\[redacted:[a-z0-9-]+\]$/.test(s);

function withRedactionMarks(text: string) {
  return text.split(PLACEHOLDER).map((part, i) =>
    isPlaceholder(part) ? (
      // biome-ignore lint/suspicious/noArrayIndexKey: split output is positional and stable
      <span key={i} className="redacted-mark" title="A credential was removed before this was stored">
        {part}
      </span>
    ) : (
      part
    ),
  );
}

export function AgentText({ label, children }: { label: string; children: string }) {
  return (
    <div className="agent-region">
      <div className="agent-label">
        <span aria-hidden="true">⚠</span>
        <span>{label} — written by the agent, not by VERA</span>
      </div>
      <pre className="agent-body">{withRedactionMarks(children)}</pre>
    </div>
  );
}

/** Arguments as a whole: pretty-printed JSON, same quarantine. */
export function AgentJson({ label, value }: { label: string; value: unknown }) {
  return <AgentText label={label}>{JSON.stringify(value, null, 2)}</AgentText>;
}
