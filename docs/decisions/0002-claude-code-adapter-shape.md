# ADR-0002 — Shape of the Claude Code adapter

**Status:** accepted · 11 September 2026
**Context:** the threat model's open question 1 asked whether a Claude Code `PreToolUse` hook can hold a tool call for an out-of-band human approval. The current hook documentation (code.claude.com/docs/en/hooks, hooks-guide, managed-settings, agent-sdk/hooks) was checked on 11 September 2026. Findings that matter, with what each one forces:

| Finding | Consequence for VERA |
|---|---|
| `PreToolUse` hooks have a **default timeout of 600 s** (`"timeout"` overridable per hook). On timeout the tool call is **not executed** and Claude receives a "hook didn't respond" result. | A hook *can* hold a call for minutes. REVIEW can be resolved in-session: the adapter long-polls VERA up to a tenant-configured hold (default 5 min, < the hook timeout) and answers when a human decides. Timeout is fail-closed by construction. |
| `permissionDecision` accepts `allow`, `deny`, `ask`, and `defer` (`defer` only in non-interactive `-p` / Agent SDK mode, where it exits the session so the wrapper can collect input and resume). | Interactive sessions: REVIEW → hold, then `allow` (with token) or `deny`; if the hold expires, `ask` (human in the terminal decides, VERA records it as `SYSTEM.HOLD_EXPIRED` and no token is issued). Non-interactive: REVIEW → `defer`; the SDK wrapper resumes once VERA's callback arrives. |
| On hook **error or non-2xx**, the docs say status codes alone cannot block — the action proceeds. **Hooks fail open.** | The hook URL must **never point at VERA directly**. A VERA outage would silently allow everything (violates SR-08). The hook must be a **local command hook** (`type: command`) — a small CLI, `vera-hook`, that owns the safe-default table and calls VERA. When VERA is unreachable it answers from the signed table: consequential → `ask`, read-only → `allow` + queued `SYSTEM.DEGRADED_MODE`. |
| `PostToolUse` receives `tool_input` as **originally sent by Claude**, not the `updatedInput` a PreToolUse hook may have substituted. | V1 adapters never use `updatedInput`. Post-execution hash comparison (T02) hashes the original input, which is what was decided on. If a later version rewrites input, it must store both hashes. |
| `managed-settings.json` supports `allowManagedHooksOnly: true`, which blocks user, project, local, and plugin hooks. | This is the enforcement story for T01. Ship a managed-settings template; document that without it the hook is advisory. |
| MCP tools match as `mcp__<server>__<tool>`; matchers accept regex (`^mcp__`). | Class table keys are tool-name patterns; default matcher for the hook is `.*` with classification inside the adapter, not in the matcher. |
| Agent SDK (TS ≥ 0.3.233): `canUseTool(toolName, toolInput) → { approved, reason }`, and hooks can be registered programmatically; `PreToolUse` runs before `canUseTool`. | The SDK adapter is the same core as the CLI adapter, registered as a `HookCallback`; `canUseTool` is not used for decisions (it cannot carry a token). |
| Unconfirmed: maximum hook timeout; whether non-2xx is always fail-open. | Treat both conservatively: never rely on a hold longer than 600 s; never rely on an HTTP error to block. |

## Decision

1. The Claude Code adapter is a **command hook**: a Node CLI (`@vera/adapter-claude-code`, binary `vera-hook`) configured as

   ```json
   { "hooks": { "PreToolUse": [ { "matcher": ".*", "hooks": [ { "type": "command", "command": "vera-hook pre", "timeout": 360 } ] } ],
                "PostToolUse": [ { "matcher": ".*", "hooks": [ { "type": "command", "command": "vera-hook post", "timeout": 10 } ] } ] } }
   ```

   It reads the hook JSON from stdin, classifies the tool call using the tenant-signed class table, calls `POST /v1/decide` with a short timeout (2 s), and:
   - `ALLOW` → verifies the returned token (hash, tenant, aud, exp) and answers `allow`;
   - `BLOCK` → answers `deny` with the reason codes in `permissionDecisionReason`;
   - `REVIEW` → long-polls `GET /v1/decisions/{id}` until approved/rejected or the hold expires; answers `allow` (with verified token), `deny`, or `ask` (interactive) / `defer` (non-interactive) on expiry;
   - VERA unreachable → answers from the signed safe-default table and queues a degraded-mode report.

2. `vera-hook post` recomputes `action_hash` from `tool_input` and reports `TOKEN.HASH_MISMATCH` if it differs from the decided hash for that `tool_use_id`; it also reports the outcome (`executed` / `failed`) as **asserted**.

3. The adapter depends only on `@vera/schemas`, `@vera/canon`, `@vera/decision-token`, and `jose` (ADR-0001), and has no signing capability.

4. A **contract test** in the adapter package pins the hook input/output shapes above; a change in Claude Code's hook format fails the build rather than the customer (A17).

## Consequences

- REVIEW latency is bounded by the hook timeout; approvals slower than the hold fall back to the terminal prompt and produce no token. That is acceptable for V1 and honest: VERA either decided, or a human at the keyboard did, and audit says which.
- The adapter is a real process on the developer's machine, so it needs a config file (`~/.vera/config.json`: endpoint, key, tenant, aud) and a first-run command (`vera-hook init`).
- Open question 1 in `threat-model.md` is closed by this record.
