# VERA — Product & Build Brief v2

**Working concept:** a signed decision service for consequential AI-agent actions.
**Date:** 11 September 2026 (v2.1 — assumption fixes from `boundary-and-assumptions.md` applied)
**Status:** build spec. Supersedes the v1 Codex brief. Written for Claude Code to build from, with a validation gate before serious code.
**Companion files:** `competitive-scan-2026-09.md` (75-source landscape scan; every claim in §2 traces to it) · `threat-model.md` (T01–T25, SR-01–SR-22) · `boundary-and-assumptions.md` (A1–A17) · `decisions/` (architecture decision records).

---

## 0. What changed from v1, and why

| v1 said | v2 says | Why |
|---|---|---|
| VERA sits in the execution path as a proxy/gateway ("Agent → VERA → Tool") | VERA is a **decision service** consumed *through* existing choke points (SDK hooks, gateways, GitHub deployment rules) | ≥20 MCP gateways exist, several OSS, plus AWS AgentCore, Cloudflare, Snowflake. Being in the path is necessary for data but no longer differentiating. |
| First wedge: "Production Action Guard" via GitHub + one CI/CD | First wedge: **consequential tool calls made by coding agents** (Claude Code / Claude Agent SDK first, OpenAI Agents SDK second). GitHub deployment protection becomes one adapter, not the product. | Deploy gating is a solved commodity (GitHub Environments, OPA, Sentinel, Spacelift). Coding-agent runtimes expose native hooks → zero-integration distribution and immediate dogfooding. |
| Invent a policy DSL | **Cedar** | AWS AgentCore and Docker both chose Cedar. Don't invent vocabulary the market already learned. |
| `risk_score` 0–100 as a headline output | Reason codes are the primary output; score is present but explicitly `calibrated: false` in V1 | No calibration data exists yet. A number without calibration is theatre. |
| Moat = "Action Graph" | Moat = four concrete things nobody ships together: **org behavioral baselines feeding the decision, outcome feedback, payload-bound signed expiring decision tokens, second-party (SoD-aware) review routing** | These are the empirically open gaps (scan §10, A/B/D/F). The graph is the storage; these are the product. |
| "Approvals must be bound to the payload" (stated, unspecified) | Specified: JCS canonical hash + EdDSA JWS + per-tenant JWKS + one-shot `jti` | Only Docker (in-session) and Google AP2 (cards only) do this. It is buildable and verifiable by third parties. |
| No validation step | **Day-10 gate**: 12 interviews before the vertical slice is finished; day-30 and day-90 kill/pivot criteria | The v1 conversation set a "20–30 users" rule and then skipped it. |
| Codex builds the whole monorepo | Claude Code builds one vertical slice first, dogfooded on LogaXP's own agent workflows, then widens | Reviewing 20 decisions beats reviewing 20,000 lines. |

Everything from v1 that was already right is kept: deterministic-first, LLM never the sole authority, reproducible decisions, explicit absence-of-evidence, tenant isolation from day one, fail-open/fail-closed per integration.

---

## 1. Thesis

Every agent runtime can now *pause and ask a human*. None of them can say **when** asking is worth it, **who** should answer, **what evidence** the answer should rest on, or **prove afterwards** that the thing executed was the thing approved. The result is approval fatigue on one side and silent over-permissioning on the other.

VERA answers one question at the moment of action — *given this org's history, this policy set, and this evidence, should this specific action happen?* — and returns a **signed, payload-bound, expiring decision** with **stable reason codes**. The more actions an org runs through VERA, the fewer approvals it needs and the more each remaining approval is worth reading.

Identity says who may act. Authorization says what they may do. VERA says whether *this one* should proceed.

---

## 2. Market reality (September 2026)

Condensed from the scan. Full tables and sources in the companion file.

**Dead ends — do not build the pitch on these**

1. *"An MCP proxy that enforces policy."* Cloudflare (Portals/Gateway/WriteGuard), Docker MCP Gateway, Runlayer ($42M), Obot, Lunar MCPX, Kong AI Gateway 2.0, agentgateway (LF), AWS AgentCore Gateway + Cedar Policy, Snowflake Cortex AI Gateway (ex-Natoma), TrueFoundry, Permit.io, Pomerium, Teleport, Aembit, MintMCP, Preloop (OSS), Peta, Willow.
2. *"Pause a tool call for human approval."* Native in Claude Code / Claude Agent SDK (`PreToolUse` and `PermissionRequest` hooks incl. HTTP handlers), OpenAI Agents SDK (`needsApproval` + serializable interruptions), Codex CLI, LangGraph `interrupt()`, Microsoft Agent Framework, Cloudflare Agents SDK. Gateway-side in TrueFoundry, Docker (Cedar `@requireApproval` + elicitation + digest binding), Preloop, Peta, Permit, Delinea, Onyx.
3. *"Deterministic policy-as-code for agents."* Cedar (AWS, Docker), Rego (Permit, Spacelift, Topaz), YAML (Cerbos), Polar (Oso), Colang (NeMo), Starlark (Codex).
4. *"Prompt-injection / exfil / tool-poisoning detection."* Bought by PANW (Protect AI + Portkey), Cisco (Robust Intelligence, Astrix), Check Point (Lakera), F5 (CalypsoAI), SentinelOne (Prompt Security), Proofpoint (Acuvity), Cato (Aim), CrowdStrike (SGNL), Snyk (Invariant). Plus Zenity ($125M C), Noma ($100M B), HiddenLayer ($100M B), Straiker, AIR Security ($50M seed), Sweet.
5. *"Vendor bank-account fraud."* Trustpair, nsKnox, Ramp, BILL, Medius — with Nacha 2026 rules as a tailwind. They own the validated account-pair data and the ERP integrations.
6. *"Agent identity."* Auth0 for AI Agents (Token Vault, CIBA async approval), WorkOS, Okta Agent SSO / XAA, Microsoft Entra Agent ID + Agent 365, Descope, Arcade ($60M A), Oasis ($120M B), Neo ($100M).

**Open — where the scan found nobody or almost nobody**

| Gap | Closest | Why still open |
|---|---|---|
| **A. Org-specific behavioral baselines that change the decision** | Zenity, Noma (attack-pattern anomaly alerts); Claude auto mode (classifier, no org history, 17% FNR) | Nobody uses "this actor has never done this to this target / this is 4.8× the org's p95" as a *business* prior that raises or lowers the review threshold. No gateway uses history at all. |
| **B. Outcome feedback loop** | Orako (remembers prior answers); gotoHuman ("training dataset") | Nothing closes the loop from what happened after (reverted, incident, false positive) back to the ALLOW/REVIEW/BLOCK boundary. Approval fatigue is universally acknowledged and nobody attacks it with data. |
| **C. Evidence-backed reason codes** | Cerbos deny reasons; Noma review context | No structured, auditor-grade, machine-readable reason set (cf. card-network decline codes). Reviewers everywhere see "agent X wants to call Y" plus raw args. |
| **D. Payload-bound, expiring, signed decision receipt a downstream system can verify offline** | Docker (digest-bound, in-session only); Pipelock (Ed25519 receipts, egress only); Google AP2 (signed mandates, cards only); TrueFoundry explicitly *not* arg-bound | Nobody combines argument binding + TTL/one-shot + third-party-verifiable signature + webhook delivery for general tool calls. |
| **F. Second-party reviewer semantics (SoD, n-of-m, no self-approval)** | GitHub Environments, Spacelift (for infra only) | Every agent-native product asks the *operator* — the wrong reviewer for consequential business actions. |

**Named threats, ranked:** (1) Anthropic/OpenAI shipping a hosted approval queue + org policy on top of their hooks; (2) Cloudflare extending WriteGuard tiers into approvals + scoring on its traffic corpus; (3) Onyx (Bessemer, $153M, already routes to humans and reads reasoning) moving down-market to a developer API; (4) Preloop commoditizing proxy + approval at $0.

**Positioning implication.** VERA is the *decision* that the crowded layer calls. It plugs in as a Claude Code HTTP hook, an OpenAI `needsApproval` function, a Cedar/OPA external data source, a gateway policy plugin, and a GitHub custom deployment protection rule. It competes on A–D and F, not on being a proxy.

---

## 3. Product definition

**VERA is:** a multi-tenant HTTP service exposing `POST /v1/decide`, a human review queue with SoD-aware routing, a per-org baseline store, an outcome ledger, a signed decision-token issuer, and a small set of open-source adapters that connect existing agent runtimes to it.

**VERA is not:** a proxy or gateway, an identity provider, an OAuth server, an injection/exfil detector, a bank-account validator, a SIEM, a consumer scam app.

**Proof (v1's investigation engine)** survives as the **Evidence Provider interface**: a pluggable way to attach sourced, timestamped, confidence-scored facts to a decision. V1 providers are GitHub (PR/CI/review state), git metadata, and VERA's own baselines. Later providers (domain age, company registry, bank validation) are *partners called through the interface*, not built.

**The four things VERA does that the layer beneath it doesn't:**

1. **Decide with history.** Deterministic per-org baselines (novelty, time, magnitude, frequency) are inputs to the verdict, not just alerts.
2. **Learn from outcomes — honestly.** Outcomes (executed / reverted / incident / false-positive) compute per-rule precision and produce *human-activated* tuning recommendations. No silent threshold drift in V1.
3. **Sign what was approved.** Every ALLOW and every approved REVIEW yields a JWS bound to the canonical action hash, with TTL and one-shot `jti`, verifiable against the tenant's JWKS by anyone downstream.
4. **Route to the right human.** Reviewer selection by role, amount, resource class, n-of-m, and separation of duties (actor and `acting_for` excluded).

---

## 4. First wedge

**First customer:** engineering teams of 5–50 running coding agents (Claude Code, Codex, Cursor, custom Claude Agent SDK / OpenAI Agents SDK agents) with real tool access — shell, git push, deploys, DB access, production APIs via MCP. Buyer is the platform / dev-productivity lead, not the CISO.

**First use case:** *consequential tool calls by coding agents* — production deploys, destructive shell/DB commands, secret access, force-pushes, external API mutations. Policy Pack 1 covers exactly this.

**Why this and not the finance story:** the finance story is the best *demo*, but it collides with regulator-aligned incumbents who own the data. The coding-agent wedge has native hooks (no integration to sell), an observable outcome signal (reverts, rollbacks, incidents), a buyer who feels approval fatigue daily, and it is **dogfoodable on LogaXP's own repos on day 11**. Policy Pack 2 (business actions: refunds, credits, vendor changes, bulk emails — the second-party-reviewer case, gap F) follows once the engine is proven, using the same adapters.

**Where VERA sits:**

```
Claude Code / Agent SDK ──PreToolUse HTTP hook──┐
OpenAI Agents SDK ─────needsApproval(fn)────────┤
GitHub Environment ────deployment protection────┼──▶  POST /v1/decide  ──▶ ALLOW  + signed token
MCP gateway (TrueFoundry/Preloop/agentgateway) ─┤                        ──▶ REVIEW → queue → approve → signed token → callback
Any service ───────────direct SDK call──────────┘                        ──▶ BLOCK + reason codes
```

The adapter decides fail mode per action class when VERA is unreachable (§12).

---

## 5. Adapters (V1: two; V2: four)

| Adapter | Mechanism | Status |
|---|---|---|
| **Claude Code / Claude Agent SDK** | **Command hook** (`vera-hook`, a local CLI) on `PreToolUse` / `PostToolUse` — never an HTTP hook pointed at VERA, because hook errors fail open. Calls `/v1/decide`; `ALLOW` → `allow` with verified token; `BLOCK` → `deny`; `REVIEW` → holds (long-polls) up to a tenant hold window inside the hook's timeout, then `allow`/`deny`, or `ask` (interactive) / `defer` (SDK) on expiry. VERA unreachable → signed safe-default table. Details and the hook facts behind them: `decisions/0002-claude-code-adapter-shape.md`. | Day 11–30 |
| **OpenAI Agents SDK** | `needsApproval: async (ctx, args) => decide(...)`; on `REVIEW` the run returns `interruptions` + serialized state; VERA callback resumes. | Day 31–50 |
| **GitHub custom deployment protection rule** | GitHub App receives `deployment_protection_rule` webhook → `/v1/decide` with PR/CI/review evidence → approve/reject via API. | Day 71–90 |
| **Generic gateway plugin** | HTTP policy hook for TrueFoundry / Preloop / agentgateway; Cedar external entities for AgentCore. | Post-90 |

All adapters are open source (Apache-2.0), tiny, and stateless. They normalize the runtime's tool call into the VERA `action` shape (§6.2) and carry the `decision_token` back.

---

## 6. Decision contract

### 6.1 `POST /v1/decide` — request

```json
{
  "request_id": "req_01J8ZK…",
  "idempotency_key": "claude-code:sess_9f1:call_42",
  "actor":      { "type": "ai_agent", "id": "claude-code", "runtime": "claude-agent-sdk@1.x", "session_id": "sess_9f1" },
  "acting_for": { "type": "user", "id": "kriss@logaxp.com", "trust": "asserted" },
  "action": {
    "type": "tool_call",
    "tool": "Bash",
    "class": "shell.exec",
    "arguments": { "command": "psql $PROD_URL -c \"ALTER TABLE users DROP COLUMN legacy_id\"" },
    "environment": "production",
    "hints": { "destructive": true, "idempotent": false, "open_world": false }
  },
  "target":  { "kind": "database", "id": "prod-postgres", "sensitivity": "high" },
  "context": { "repo": "logaxp/hearken", "branch": "main", "cwd": "/srv/hearken", "local_time": "2026-09-11T02:14:00-04:00" },
  "evidence": [
    { "id": "ev_2", "type": "ops.backup", "source": "adapter", "trust": "asserted", "observed_at": "2026-09-10T23:00:00Z",
      "data": { "verified": true } }
  ]
}
```

Rules:

- `action.class` is from a controlled taxonomy (`shell.exec`, `vcs.push`, `deploy.production`, `db.write`, `db.ddl`, `secret.read`, `http.mutation`, `message.send`, `payment.create`, …). Tool → class tables are **tenant configuration served and signed by VERA**, not editable by the agent process; unknown tools map to `unknown.consequential`; shell classification can raise a class but an unrecognised shell string is `shell.exec` + `ACTION.UNCLASSIFIED_SHELL` (SR-03, SR-07).
- Everything the runtime sends is **asserted**. `acting_for.trust` and `evidence[].trust` are always `asserted` on the request; VERA sets `verified` only on facts it fetched with its own credentials (GitHub App) or computed (baselines). Asserted evidence may add reason codes; it can never clear a `PREREQ.*` code — in the example above, the adapter's `verified: true` claim about the backup does **not** satisfy `PREREQ.BACKUP_NOT_VERIFIED` (SR-01). VERA-fetched evidence appears in the response, not the request.
- `context.local_time` is display-only. Time features use server receive time converted with the `acting_for` principal's tenant-configured timezone (SR-06).
- `arguments` are stored redacted per tenant rules before any rendered view is persisted and before any external model call (SR-15). Missing fields are stored as missing — never defaulted to safe values.

### 6.2 Response

```json
{
  "decision_id": "dec_01J8ZK…",
  "decision": "REVIEW",
  "risk": { "score": 78, "calibrated": false },
  "confidence": 0.93,
  "reason_codes": [
    { "code": "POLICY.REQUIRE_REVIEW", "policy_id": "pol_prod_ddl@v3", "severity": "high" },
    { "code": "PREREQ.BACKUP_NOT_VERIFIED", "severity": "high",
      "detail": "no verified backup evidence; adapter-asserted ev_2 does not satisfy the prerequisite" },
    { "code": "BASELINE.ACTOR_ACTION_NOVEL", "severity": "medium",
      "detail": "first db.ddl against prod-postgres by this actor (org history: 0 in 90d)" },
    { "code": "BASELINE.TIME_ANOMALY", "severity": "low",
      "detail": "02:14 tenant-local (server time); org p05–p95 window for deploy/db actions is 09:00–19:30" },
    { "code": "IDENTITY.ASSERTED", "severity": "info", "detail": "acting_for not verified by an identity provider" }
  ],
  "evidence": [
    { "id": "ev_1", "type": "github.pr", "source": "github", "trust": "verified", "observed_at": "2026-09-11T06:10:02Z",
      "data": { "number": 812, "approved": true, "checks": "success", "contains_migration": true } },
    { "id": "ev_2", "type": "ops.backup", "source": "adapter", "trust": "asserted", "observed_at": "2026-09-10T23:00:00Z",
      "data": { "verified": true } }
  ],
  "required_actions": ["HUMAN_APPROVAL"],
  "review": { "url": "https://vera.example/r/dec_01J8ZK…", "routed_to": ["role:platform-admin"], "sod": "actor_acting_for_and_key_owner_excluded", "quorum": 1 },
  "action_hash": "sha256:4f9c…",
  "policy_set_version": "ps_17",
  "baseline_snapshot_id": "bs_2026-09-11T06",
  "supersedes": null,
  "expires_at": "2026-09-11T06:40:02Z",
  "decision_token": null
}
```

`decision_token` is present immediately on `ALLOW`; on `REVIEW` it is issued at approval and delivered by callback. `confidence` is about evidence completeness and freshness, not about risk. Every response is reproducible from the stored request + `policy_set_version` + `baseline_snapshot_id`. A decision is immutable once issued: if asynchronous enrichment later changes the picture, VERA issues a **new** decision whose `supersedes` names the original; the original stays as issued (A8).

### 6.3 Signed decision token (gap D)

- **Canonicalization:** `action_hash = SHA-256( JCS(RFC 8785) of { class, tool, normalized_arguments, target, environment } )`. Normalization rules are versioned and published; adapters compute the same hash locally for verification.
- **Format:** JWS, `alg: EdDSA` (Ed25519). Claims: `iss` (tenant issuer URL), `sub` (`decision_id`), `jti` (one-shot nonce), `aud` (receiver id declared by the adapter), `tenant`, `decision`, `action_hash`, `actor`, `acting_for`, `approver` (for approvals; array for n-of-m), `policy_set_version`, `iat`, `exp`, `single_use: true`.
- **TTL:** default 10 minutes for ALLOW tokens, 15 minutes for approval tokens; tenant-configurable downward only (SR-10).
- **Verification:** per-tenant JWKS at `/.well-known/vera/{tenant}/jwks.json`; keys rotate with overlap and the JWKS carries a `revoked` list. Receivers check `aud`, `tenant`, `exp`, recompute `action_hash` from the action they are about to execute, and reject on mismatch (`TOKEN.HASH_MISMATCH`), expiry, or replayed `jti` (`TOKEN.ALREADY_CONSUMED`; VERA exposes `POST /v1/tokens/consume` for online single-use enforcement; offline receivers rely on `exp`).
- **Adapters verify, never issue.** No adapter holds signing material (SR-19).
- **Material change = new decision.** Any change to the canonical action after approval yields a different hash; the old token is useless. This is the property TrueFoundry-style time-boxed grants lack.

### 6.4 Supporting endpoints

```
POST /v1/decide
GET  /v1/decisions/{id}            POST /v1/decisions/{id}/approve   POST /v1/decisions/{id}/reject
GET  /v1/decisions?…               POST /v1/decisions/{id}/outcome
POST /v1/tokens/consume            GET  /.well-known/vera/{tenant}/jwks.json
POST /v1/policies  GET /v1/policies  PATCH /v1/policies/{id}  POST /v1/policies/{id}/test  POST /v1/policies/{id}/activate
POST /v1/agents    GET /v1/agents
POST /v1/webhooks  GET /v1/audit-events
GET  /v1/baselines?actor=&class=&target=      (read-only; explains BASELINE.* codes)
```

### 6.5 Reason-code registry v0 (gap C)

Namespaced, stable, versioned, documented with "what a reviewer should check":

- `POLICY.DENY`, `POLICY.REQUIRE_REVIEW`, `POLICY.ENV_RESTRICTED`, `POLICY.LIMIT_EXCEEDED`, `POLICY.SOD_VIOLATION`, `POLICY.DEFAULT_DENY`
- `BASELINE.ACTOR_ACTION_NOVEL`, `BASELINE.TARGET_NOVEL`, `BASELINE.TIME_ANOMALY`, `BASELINE.MAGNITUDE_DEVIATION`, `BASELINE.FREQUENCY_SPIKE`, `BASELINE.INSUFFICIENT_HISTORY`
- `PREREQ.MISSING_APPROVAL`, `PREREQ.TESTS_NOT_PASSED`, `PREREQ.BACKUP_NOT_VERIFIED`, `PREREQ.NO_ROLLBACK_PLAN`, `PREREQ.STAGING_NOT_DEPLOYED`
- `EVIDENCE.MISSING`, `EVIDENCE.STALE`, `EVIDENCE.CONTRADICTED`, `EVIDENCE.VERIFIED`, `EVIDENCE.ASSERTED`, `EVIDENCE.PROBABILISTIC`
- `ACTION.DESTRUCTIVE_HINT`, `ACTION.IRREVERSIBLE`, `ACTION.SENSITIVE_RESOURCE`, `ACTION.BULK`, `ACTION.INDIRECT_INPUT`, `ACTION.UNCLASSIFIED_SHELL`
- `IDENTITY.ASSERTED`
- `TOKEN.HASH_MISMATCH`, `TOKEN.ALREADY_CONSUMED`
- `SYSTEM.FAIL_CLOSED`, `SYSTEM.EVALUATOR_TIMEOUT`, `SYSTEM.DEGRADED_MODE`

Severity levels: `info`, `low`, `medium`, `high`. `info` codes never affect the verdict; they exist so the reviewer and the audit trail see them.

Adding a code is a versioned change with a migration note. Codes never change meaning.

---

## 7. Engines

### 7.1 Policy engine — Cedar

- Policies are Cedar. Tenants get a schema (`Principal` = user/agent, `Action` = `action.class`, `Resource` = target with attributes, `Context` = normalized args, evidence flags, baseline flags).
- Three outcomes from a two-outcome language: `forbid` → **BLOCK**; `permit` annotated `@vera_effect("review")` → **REVIEW**; unannotated `permit` → **ALLOW**; no match → tenant default (`BLOCK` for consequential classes, `REVIEW` otherwise). Cedar diagnostics (`reason` policy ids) become `POLICY.*` reason codes with `policy_id@version`.
- **Precedence is most-restrictive-wins:** any matching `forbid` → BLOCK; otherwise any matching review-annotated `permit` → REVIEW, even if a plain `permit` also matches; ALLOW only when every matching permit is unannotated (A9).
- Policies are versioned, activated explicitly, and carry **test cases** (`POST /v1/policies/{id}/test` runs stored example requests and asserts outcomes). A policy with no passing tests cannot be activated.
- Natural language → Cedar draft is an LLM feature that produces a *proposed* policy with generated test cases; a human activates.
- Policy evaluation is independent of the baseline engine: a hard `forbid` blocks regardless of history; baselines can produce REVIEW with no policy hit.

Example (Policy Pack 1):

```cedar
@id("prod-ddl-requires-review")
@vera_effect("review")
permit(principal, action == Action::"db.ddl", resource)
when { resource.environment == "production" };

@id("no-force-push-to-default")
forbid(principal, action == Action::"vcs.push", resource)
when { context.args.force == true && resource.branch == resource.default_branch };

@id("prod-deploy-needs-backup-if-migration")
@vera_effect("review")
permit(principal, action == Action::"deploy.production", resource)
when { context.evidence.contains_migration == true && !(context.evidence.backup_verified == true) };
```

### 7.2 Baseline engine — deterministic statistics (gap A)

Per `(tenant, actor, action.class, target.id)` and rolled up to `(tenant, action.class)` and `(tenant, actor)`:

- counts and `first_seen` / `last_seen` (90-day and all-time)
- hour-of-day / day-of-week histogram (server receive time in the `acting_for` principal's tenant-configured timezone — never the adapter's `local_time`)
- magnitude distribution for numeric args (`amount`, row counts, file counts): p50 / p95 / max
- distinct-target cardinality and recent frequency (sliding 1h / 24h)

Evaluators emit `BASELINE.*` codes with severity from tenant-configurable thresholds (defaults: novel = 0 prior; time anomaly = outside p05–p95; magnitude = > 2× p95 with n ≥ 10; spike = > 3× 24h mean). With n < 10 the engine emits `BASELINE.INSUFFICIENT_HISTORY` and *does not* raise severity — cold start is explicit, never pretended.

Baselines are built **only from actions that were ALLOWed or approved and reached outcome `executed` without a revert or incident** — attempted, blocked, or rejected actions never train them (SR-20, threat T09). Baselines can only add severity; they never satisfy a policy REVIEW, clear a prerequisite, or lower a verdict. Rollups are materialised by workers into Postgres `BaselineSnapshot` rows; `/decide` reads a snapshot, never computes one, which is what makes the 150 ms budget and reproducibility both hold (A10, A11).

No ML in V1. Every code is explainable with the numbers that produced it, and `GET /v1/baselines` shows them.

### 7.3 Evidence providers (Proof)

Interface: `provide(request) → Evidence[]` with `source`, `trust`, `observed_at`, `confidence`, `ttl`. `trust` is `verified` when VERA fetched or computed the fact itself and `asserted` when the runtime supplied it; **only `verified` evidence can clear a `PREREQ.*` code**, and the Cedar schema exposes `evidence.<name>.trust` so Policy Pack 1 can require it (SR-01). Providers run with a per-call budget; slow providers time out and the decision records `EVIDENCE.MISSING` rather than waiting. V1 verified providers: GitHub PR/CI/review state (GitHub App, read-only), git metadata fetched from GitHub, VERA baselines. Adapter-supplied markers (backup, rollback plan) are recorded as asserted. Partner providers later (domain age, company registry, Trustpair-class bank validation) via the same interface.

### 7.4 Decision aggregation

Order: policy `forbid` → BLOCK (stop). Else collect policy REVIEW effects, prerequisite failures, baseline codes, evidence-status codes. `REVIEW` if any high-severity code or ≥ 2 medium. `ALLOW` otherwise. `risk.score` is a logged, weighted sum of severities — stored, shown, and marked uncalibrated until §8 produces calibration data. Aggregation weights are per-tenant config and are part of `policy_set_version` so decisions stay reproducible.

### 7.5 Review routing (gap F)

Routing rules per tenant: by `action.class`, `target.sensitivity`, magnitude threshold → required roles, quorum (n-of-m), and SoD. SoD excludes the `actor`, the asserted `acting_for` identity, **the principal who owns the API key that made the request**, and the author of any policy that produced a REVIEW effect. API keys are per-user — there are no shared team keys (ADR-0003) — so the key owner is the person at the keyboard and SoD holds without an identity provider. Requests made with a service-account key (CI, deployment agents) require quorum ≥ 2 for consequential classes because nobody is at the keyboard (SR-09, threat T07). A spike of review requests from one actor raises quorum for high-sensitivity targets automatically (SR-22). Reviewers get: the action (with redaction), each reason code with its "check this" guidance, the evidence with freshness, baseline numbers, and one-click approve / reject / approve-with-condition (e.g. "create backup first" → new decision required). Channels: web queue, Slack (notification + action buttons calling the API), email fallback. Expiry and escalation timers are first-class (the gap every SDK doc admits).

---

## 8. Outcome loop — the honest version (gap B)

Outcomes are captured three ways: adapter auto-report (hook `PostToolUse` → executed / failed; git revert / deploy rollback detection within a window), reviewer tagging at decision time (false positive / needed / fraud-attempt), and `POST /v1/decisions/{id}/outcome` from integrations.

V1 uses outcomes for **reporting and recommendations only**:

- per-rule precision: REVIEW → approved-without-change rate; REVIEW → rejected rate; ALLOW → reverted rate
- "This rule produced 41 REVIEWs, 40 approved unchanged, median 6 min reviewer time. Suggested: auto-ALLOW when `evidence.tests == success && baseline.n ≥ 20`" — a human activates it as a new policy version with tests.

Silent automatic threshold adjustment is out of scope until outcome volume supports a measured calibration curve; when it arrives it must be per-tenant and reversible.

---

## 9. Domain model

`Organization` (tenant, timezone, defaults) · `User` · `ApiKey` (hashed, scope, owning principal) · `Agent` (machine principal, runtime, owner) · `ActionRequest` (normalized action + context + hash; `acting_for` with trust) · `Evidence` (source, **trust**, observed_at, confidence, ttl, data) · `Policy` (Cedar text, version, tests, status) · `PolicySet` (activated policies + aggregation weights, versioned) · `BaselineSnapshot` (materialised in Postgres; id referenced by decision) · `Decision` (verdict, codes, score, confidence, expires_at, policy_set_version, baseline_snapshot_id, supersedes) · `Review` (routed_to, quorum, SoD result, approvals[]) · `DecisionToken` (jti, aud, action_hash, exp, consumed_at) · `Outcome` (source, trust, kind) · `AuditEvent` (append-only, hash-chained per tenant, signed chain heads delivered to the tenant).

Every table carries `tenant_id`; row-level security in Postgres enforces it; there is no cross-tenant query path.

---

## 10. Security and threat model (summary — full threat model is the first build deliverable)

VERA is a high-value target: compromise it and you approve anything. Non-negotiables:

- Tenant isolation via Postgres RLS + per-tenant signing keys in a KMS; tenant A cannot read, influence, or verify against tenant B.
- Signing keys never leave the KMS; JWKS rotation with overlap; token `jti` replay protection.
- Idempotency keys on `/decide`; signed + timestamped webhooks with replay windows; adapters verify VERA's signature on callbacks.
- Redaction of `arguments` per tenant rules *before* storage of the rendered view and before any external model call; raw args encrypted at rest, retention configurable.
- Least-privilege admin roles; policy changes and approvals are audited with actor identity; approving is itself an action VERA can evaluate (no self-approval, quorum).
- Rate limits and abuse controls per API key; API keys are hashed; short-lived tokens for the dashboard.
- Explicit fail mode per action class (§12); SDK adapters ship with a *safe default table* (consequential classes fail-closed to `ask`).
- No model training on customer data. Ever, without a signed opt-in.

Threat model must cover: malicious agent crafting requests to look benign (hash canonicalization attacks, argument smuggling, unicode normalization), reviewer phishing via evidence rendering, replay of decision tokens across tenants/actions, adapter bypass (VERA can only govern what routes through it — say so in docs), and VERA outage as a denial-of-service on the customer's agents.

---

## 11. Architecture and stack

TypeScript end to end. Fastify API, PostgreSQL (RLS), Redis (short-lived coordination, baseline counters), BullMQ (evidence enrichment, webhooks, outcome detection), Cedar via `@cedar-policy/cedar-wasm`, EdDSA via `jose`, Next.js dashboard. pnpm + Turborepo monorepo:

```
apps/api                      Fastify: /v1/*, JWKS, webhooks
apps/dashboard                Next.js: review queue, decisions explorer, policies, agents, audit
workers/enrichment            evidence providers, baselines rollup, outcome detection, webhook delivery
packages/schemas              zod schemas for every wire object; JSON Schema exported; action-class taxonomy
packages/canon                JCS canonicalization + action_hash (shared with adapters; property-tested)
packages/decision-token       JWS issue/verify, JWKS
packages/policy-engine        Cedar wrapper, three-outcome mapping, policy tests runner
packages/baseline-engine      statistics + BASELINE.* evaluators
packages/decision-engine      aggregation, reason-code registry
packages/evidence             provider interface + github, git, adapter-supplied providers
packages/review-routing       roles, quorum, SoD
packages/redaction            secret-pattern + tenant-pattern redaction, run before storage and before any LLM call
packages/audit                hash-chained append-only events
tools/verify-chain            CLI a tenant can run against exported audit events + signed chain heads
packages/adapters/claude-code Apache-2.0
packages/adapters/openai-agents
packages/adapters/github-deployment-rule
infra                         docker-compose (dev), Terraform (later)
docs                          API reference, reason codes, normalization rules, threat model
tests                         e2e: ALLOW / REVIEW / BLOCK / expiry / replay / idempotency / tenant isolation / fail modes
```

Clean boundaries and auditable semantics matter more than framework choice; nothing above is load-bearing except Postgres RLS, Cedar, and the token format.

---

## 12. Latency and failure modes

- Budget: **p95 ≤ 150 ms** for the synchronous `/decide` path (policy + baseline snapshot + cached evidence). Evidence providers that cannot answer within a per-provider budget (default 300 ms) are recorded as `EVIDENCE.MISSING`; enrichment continues asynchronously and may produce a **new decision** (`supersedes` set) that resolves a REVIEW to ALLOW via callback — never a silent downgrade, and never a mutation of the issued decision.
- Claude Code hooks have a bounded timeout; the adapter must return before it. On VERA unreachable, the adapter consults its safe-default table — **fetched from VERA and signed with the tenant key; an unsigned or foreign table is refused** (SR-07): read-only classes → `allow` (queued as `SYSTEM.DEGRADED_MODE`), consequential classes → `ask` (fail-closed to the human), never silent allow.
- Every degraded decision is reported to VERA when connectivity returns and appears in audit.

---

## 13. LLM boundaries

Allowed: natural language → Cedar draft (+ generated tests; human activates); reviewer-facing summaries rendered *from* structured facts; argument normalization for unstructured tools, always tagged `EVIDENCE.PROBABILISTIC` with provenance.
Forbidden: an LLM as the deciding authority for any consequential class; LLM output altering a hash, a policy version, or an approval. Any design that violates this is a build-blocking defect.

---

## 14. Dashboard (minimal, V1)

Review queue (the product surface reviewers live in) · Decision detail (action, redacted args, reason codes with guidance, evidence + freshness, baseline numbers, policy hits, token status, outcome) · Decisions explorer (filter by actor/class/target/verdict/code) · Policies (Cedar editor, tests, versions, activate/deactivate, NL draft) · Agents (identity, runtime, owner, last seen, recent verdict mix) · Audit (chronological, hash-chain verified) · Settings (API keys, webhooks, fail modes, redaction rules, routing rules, retention, JWKS).

Overview charts come last. Approval-fatigue metrics (§17) are the one chart that matters.

---

## 15. 90-day plan with gates

**Days 1–10 — Validate + foundations (parallel).**
Interviews: 12 conversations using Appendix A. Build: threat model doc; zod schemas + action-class taxonomy; canonicalization spec + property tests; reason-code registry v0; tenant/auth model with RLS; decision-token package; monorepo + CI.
**Gate 10:** ≥ 5 of 12 teams have agents with production-affecting tools *and* their approval story is "ask the operator" or "nothing" *and* at least 3 say they'd try a hook. Fail → switch Policy Pack 1 to business actions (second-party review) before continuing.

**Days 11–30 — Vertical slice.**
Claude Code HTTP `PreToolUse` adapter → `/decide` → Cedar (Policy Pack 1) + baseline evaluators → ALLOW / REVIEW / BLOCK → web + Slack review queue with SoD → approval bound to `action_hash` → signed token → callback → adapter resumes. Dogfood on LogaXP repos (Hearken, taskBricks, loga-dash) with real agent sessions.
**Gate 30:** end-to-end on own workflows daily; p95 ALLOW ≤ 150 ms; every decision reproducible; false-REVIEW rate measured on ≥ 200 real calls; **and** the adversarial suite passes — evasion corpus (SR-03), injection-rendering test (SR-04), spoofed-evidence test (SR-01), spoofed-time test (SR-06), self-approval refusal (SR-09). Dogfooding exercises the happy path; these exercise the adversary (A16).

**Days 31–50 — History + second runtime.**
Baseline rollups and all `BASELINE.*` codes; outcome capture (PostToolUse, revert/rollback detection, reviewer tags); per-rule precision report; recommendation generator; OpenAI Agents SDK adapter.

**Days 51–70 — Hardening + dashboard v0.**
Tenant-isolation tests; replay/idempotency; JWKS rotation; fail-mode tests; rate limits; audit-chain verification; observability (traces per decision); dashboard sections in §14.

**Days 71–90 — Design partners.**
Hosted sandbox; 3–5 teams from the interviews; GitHub deployment-protection adapter; policy templates; API/SDK docs; reason-code reference; measure §17.
**Gate 90:** ≥ 2 partners with weekly real agent actions through VERA; review rate declining month-over-month on ≥ 1; reviewers rate reason codes "useful" ≥ 70%. Fail → reassess wedge with the data, not the story.

---

## 16. V1 acceptance criteria

1. A Claude Code session cannot execute a Policy Pack 1 consequential action without a VERA decision (or an explicit, audited degraded-mode allow).
2. Deterministic safe action → ALLOW with a valid signed token in ≤ 150 ms p95.
3. Configured `forbid` → BLOCK with `POLICY.*` code naming `policy_id@version`.
4. Novel / off-hours / oversized action with no policy hit → REVIEW with `BASELINE.*` codes and the numbers behind them.
5. Reviewer approves; token is bound to `action_hash`; a materially changed action fails verification; expired or replayed `jti` fails.
6. Approval by `actor`, `acting_for`, or policy author is refused (`POLICY.SOD_VIOLATION`).
7. Every decision is reproducible from stored request + `policy_set_version` + `baseline_snapshot_id`.
8. Tenant A cannot read, verify against, or influence tenant B (tested).
9. VERA unreachable → consequential classes fail to `ask`; read-only classes allow with `SYSTEM.DEGRADED_MODE`; both audited on reconnect.
10. Outcome report shows per-rule precision and at least one human-activatable recommendation.
11. A policy without passing tests cannot be activated.
12. Every security requirement SR-01 … SR-22 in `threat-model.md` §6 has a passing test named after it.

---

## 17. Metrics

Approval-fatigue metrics (the product): REVIEW rate per org over time · median and p95 reviewer decision time · % REVIEWs approved unchanged (per rule) · % reviews rated "useful reason codes" · ALLOW → reverted rate · recommendations activated.
Operational: `/decide` p50/p95/p99 · verdict distribution · evidence-provider timeout rate · webhook reliability · degraded-mode count · token verification failures · outcome capture rate · protected consequential actions per week.

---

## 18. Commercial hypothesis (test, don't finalize)

- Adapters, schemas, canonicalization, and reason-code registry: **Apache-2.0** (standards want to be free; that is how a token format gets receivers).
- Server: source-available, self-host allowed for evaluation and small teams.
- Hosted: free up to N protected consequential actions/month; then priced per **protected consequential action** (aligned with value) plus reviewer seats; enterprise tier for SSO, retention, private deploy, audit export.
- Do not price on `/decide` calls — read-only ALLOWs are worth nothing to the buyer.

---

## 19. Risks and hedges

| Risk | Hedge |
|---|---|
| Anthropic / OpenAI ship a hosted approval queue on their hooks | Multi-runtime by day 50; moat is org history + verifiable token + SoD routing, not the queue; be the decision *their* queue calls. The Claude Code hook contract is an external dependency Anthropic controls: pin the version, keep a contract test against it (A17). |
| Cloudflare WriteGuard adds approvals + scoring on its corpus | Not competing on path placement; Cloudflare's decision is per-tool tier, not per-org history. Publish the token format so a Cloudflare receiver can verify VERA decisions. |
| Onyx moves down-market | Developer-first, self-serve, transparent reason codes, OSS adapters. Onyx is a CISO platform; keep the buyer different. |
| Preloop commoditizes proxy + approval at $0 | Ship a Preloop policy plugin; they have no history/outcomes/token. Partner, don't fight. |
| Customers refuse a new service in the critical path | Adapter fail-mode table; local ALLOW cache for policy-only decisions; self-host option. |
| False BLOCK causes an outage / false ALLOW causes loss | Every policy has tests; baselines can only REVIEW, never BLOCK; degraded mode audited; outcome loop measures both errors. |
| Cold start: no history means no moat on day one | Day-one value is Policy Pack 1 + prerequisite/evidence codes + SoD queue + signed token — none need history. Baselines are honest about `INSUFFICIENT_HISTORY`. |
| Hash canonicalization bugs make tokens meaningless | `packages/canon` is property-tested and shared with adapters; normalization rules are versioned and published; mismatch fails closed. |
| Enterprise buyers treat VERA as security infra → long cycles | Sell to platform / dev-productivity leads on approval fatigue; security is a feature they get. |
| Naming: "VERA" and "Proof" are common marks | Working names only. Trademark / domain / app-store clearance before any public launch; budget a rename. |

---

## 20. Explicitly not building in V1

Proxy or gateway · identity provider / OAuth · injection, exfil, or tool-poisoning detection · bank-account validation data · consumer scam app · SIEM · deepfake detection · proprietary ML risk model · more than two runtime adapters · financial transaction execution · anything that makes an LLM the deciding authority.

---

## 21. Build instructions (for Claude Code)

Deliver in this order; stop for review after each numbered item.

1. **Written restatement + threat model.** One page restating the product boundary in the builder's own words; the threat model from §10 as `docs/threat-model.md`; a list of ambiguous or unsafe assumptions found in this brief.
2. **Contracts before code.** `packages/schemas` (zod + exported JSON Schema for request, response, token claims, reason codes, action-class taxonomy), `packages/canon` with property tests, `packages/decision-token` with issue/verify tests and JWKS rotation test. No API, no UI yet.
3. **Vertical slice** exactly as §15 days 11–30, dogfooded on a real LogaXP repo. Tests for ALLOW, REVIEW, BLOCK, expiry, replay, idempotency, tenant isolation, fail-open/fail-closed, SoD refusal, hash mismatch.
4. **Baselines + outcomes + second adapter.**
5. **Hardening + dashboard v0.**
6. **Design-partner packaging.**

Standing rules: deterministic policy evaluation stays independently testable and separate from baseline scoring; every decision is auditable and reproducible; tenant isolation is in the data model from the first migration; flag — do not implement — any design where an LLM is the sole authority for a consequential action; do not add financial transactions, consumer Proof, or additional adapters without an explicit scope decision recorded in `docs/decisions/`.

---

## Appendix A — Validation interview script (12 conversations, days 1–10)

Target: engineering / platform leads at teams of 5–50 running coding agents or internal agents with tool access. 25 minutes. Record answers verbatim; score at the end, not during.

1. Which agents run in your org today with access to anything beyond reading code? (List runtimes and tools.)
2. Walk me through the last time an agent did something consequential — deployed, pushed, changed data, sent something. What happened before it executed?
3. When an agent asks for approval today, who answers, how long does it take, and how often do they actually read it?
4. Roughly how many approvals per developer per day? What fraction are "obviously fine"? *(Fatigue signal.)*
5. Has an agent ever done something you had to undo? What was it, and what would have caught it?
6. Who *should* approve a production deploy or a data change by an agent — the developer running it, or someone else? Does that happen today? *(SoD signal.)*
7. If a vendor or auditor asked "prove this specific action was approved as executed," what could you show them? *(Token signal.)*
8. What do you do when the approval tooling is down — does the agent stop, or proceed?
9. Would you install an HTTP hook in Claude Code / an approval function in your agent SDK that calls an external service before consequential actions? What would stop you? *(Path and fail-mode objections.)*
10. If approvals dropped 60% over three months without loosening policy, what is that worth per month? *(Pricing anchor — do not lead.)*
11. Who else in your org would need to say yes? *(Buyer map.)*
12. Who else should I talk to?

Scoring (pass ≥ 5 of 12): consequential agent actions exist (Q1–2) **and** approval story is operator-or-nothing (Q3, Q6) **and** would try a hook (Q9). Record Q5 answers — they become Policy Pack 1 test cases. Record Q10 answers — they become the pricing hypothesis.

## Appendix B — Competitive scan

Full report with ~75 sources: `VERA_Competitive_Scan_2026-09.md`. Sections: MCP gateways (20+), agent identity/authorization (15), HITL tooling (13), runtime guardrails (17), agentic commerce (7), AP fraud (6), infra policy gates, native platform features, gaps.

## Appendix C — Example decisions Policy Pack 1 must handle

| Action | Expected | Codes |
|---|---|---|
| `git push origin feature/x` | ALLOW | — |
| `git push --force origin main` | BLOCK | `POLICY.DENY` (`no-force-push-to-default`) |
| Deploy to production, PR approved, tests green, no migration | ALLOW | `EVIDENCE.VERIFIED` |
| Deploy to production with migration, backup not verified | REVIEW | `POLICY.REQUIRE_REVIEW`, `PREREQ.BACKUP_NOT_VERIFIED` |
| `DROP TABLE` against prod at 02:14 by an actor with no prior DDL | REVIEW (or BLOCK if tenant sets DDL forbid) | `POLICY.REQUIRE_REVIEW`, `BASELINE.ACTOR_ACTION_NOVEL`, `BASELINE.TIME_ANOMALY` |
| Read a secret the actor reads daily | ALLOW | — |
| Read a secret for a new target, 40 reads in 10 minutes | REVIEW | `BASELINE.TARGET_NOVEL`, `BASELINE.FREQUENCY_SPIKE` |
| Approve own REVIEW as `acting_for` | Refused | `POLICY.SOD_VIOLATION` |
| Re-submit approved action with changed `command` | Token verification fails | hash mismatch |
| VERA unreachable, `deploy.production` | Adapter → `ask` | `SYSTEM.DEGRADED_MODE` (reported on reconnect) |
