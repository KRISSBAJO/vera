# ADR-0006 — Slack carries notifications, not approvals (for now)

**Status:** accepted · 12 September 2026
**Context:** The brief (§13, and the `.env` placeholders) scopes the Slack app as "review notifications **and low/medium-sensitivity approvals**." Building it forced the question of whether the approval half should ship. This ADR narrows that scope deliberately, as the standing rules require.

App registered: `A0C287H4CMN` in workspace TD-Pipeline. Bot scopes `chat:write`, `users:read`, `users:read.email` — nothing that reads channel history, files, or message content.

## Decision

**Slack tells a reviewer that a decision is waiting and links them to it. The approval itself happens in the dashboard.**

Socket Mode is enabled on the app anyway, so the approval path stays open without a public URL when we come back to it.

## Why not approve in Slack

The tempting version — two buttons in a channel — optimises for exactly the failure this product exists to prevent.

1. **It is the approval-fatigue affordance (T06).** A button in a busy channel is designed to be pressed without reading. The dashboard deliberately costs more: the reviewer sees the quarantined agent text and types a rationale before the verdict is accepted. Approval fatigue is not a UX annoyance here, it is the primary way a review layer becomes theatre, and §19 of the brief measures us on it. Moving approvals to a button would improve our latency metric by degrading the thing latency is a proxy for.

2. **The approver identity would be asserted, not verified (the load-bearing distinction).** A Slack interaction gives a Slack user id; making it a VERA reviewer means trusting `users:read.email`. Workspace admins can change a member's email and can invite guests. That is a *stronger* assertion than an agent's self-report, but it is still Slack's word, and an approval is the one place in this system where identity must be ours. SoD routing (§12) is meaningless if the approver identity can be rearranged by a workspace admin.

3. **Slack has no quarantine region (T04).** A review request contains attacker-influenced text — commit messages, tool arguments. The dashboard renders it inside a marked quarantine block behind a strict CSP. Block Kit has neither, and a crafted commit message that reads like VERA's own chrome ("`VERA: pre-approved by security`") is far more convincing next to real VERA chrome in Slack than it is inside a box labelled "text supplied by the agent — not VERA."

4. **The audience is wider than the reviewer set.** Everyone in the channel sees the action. Redaction (SR-15) runs first, but redaction is a mitigation for the arguments we recognise, not a reason to widen who sees them.

## What we send

Redacted action summary, verdict, reason codes, and a link. Never the decision token, never an unredacted argument, never the approval itself. A notification that leaked a token would hand approval authority to the channel.

Agent-supplied text is escaped for Slack mrkdwn (`&`, `<`, `>`) and rendered in its own labelled block, so that even without a real quarantine the reader can see where VERA's words end.

## Consequences

- A pilot gets the latency benefit — reviewers learn about decisions where they already are — without moving the authority.
- Approval latency will be worse than a button-in-Slack product. That is the trade, and §19 should report it honestly rather than hiding it.
- Revisit when there is an identity story that does not bottom out in `users:read.email`: Slack OIDC into the dashboard session, so the click happens in Slack but the authority is still ours.
- `users:read`/`users:read.email` are requested now because routing a notification to the right reviewer needs them. If the approval path is never built, they should be dropped.
