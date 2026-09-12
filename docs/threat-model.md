# VERA Threat Model

**Version:** 0.1 · 11 September 2026 · Status: draft for review (build deliverable 1 of 6, see `brief-v2.md` §21)
**Scope:** the V1 system as specified in `brief-v2.md` — decision API, review queue, baselines, outcome ledger, signed decision tokens, Claude Code and OpenAI adapters, dashboard, GitHub evidence provider.

The central fact of this model: **the thing VERA governs is itself the primary adversary.** A coding agent under prompt injection, a misbehaving model, or a developer who wants to skip review all present to VERA as "the actor". Every input that arrives from the agent's runtime — arguments, context, evidence, timestamps, identity claims — is attacker-controlled until proven otherwise. The design consequence runs through every section below: VERA may *record* what the runtime asserts, but it may only *rely on* what it fetched or computed itself.

---

## 1. System model and trust boundaries

```
 CUSTOMER RUNTIME (untrusted)                 VERA (trusted core)                       THIRD PARTIES
┌──────────────────────────────┐   B1   ┌──────────────────────────────────┐   B4   ┌──────────────────┐
│ Agent (Claude Code / SDK)    │ ─────▶ │ apps/api  /v1/decide  /approve   │ ─────▶ │ GitHub API       │
│   └ adapter (OSS, in-proc)   │ ◀───── │   policy · baseline · aggregate  │ ◀───── │ (evidence)       │
│ Tool / shell / MCP server    │ token  │   token issuer ──▶ KMS (keys)    │        └──────────────────┘
│ CI job (GitHub Action)       │        │ workers: enrich · outcomes · hooks│   B5   ┌──────────────────┐
└──────────────────────────────┘        │ Postgres (RLS) · Redis · queue   │ ─────▶ │ LLM API          │
                                        └──────────────┬───────────────────┘        │ (drafts, summary)│
 REVIEWERS (semi-trusted humans)               B2      │                            └──────────────────┘
┌──────────────────────────────┐        ┌──────────────▼───────────────────┐   B6   ┌──────────────────┐
│ Dashboard (browser)          │ ◀────▶ │ apps/dashboard · review queue    │ ─────▶ │ Slack / email    │
│ Slack app · email            │   B3   │ JWKS /.well-known/vera/{tenant}  │        │ (notify + act)   │
└──────────────────────────────┘        └──────────────────────────────────┘        └──────────────────┘
                                                 B7: tenant ↔ tenant (inside the same database)
```

| Boundary | Crosses | Trust assumption |
|---|---|---|
| **B1** runtime → API | decide requests, outcome reports, token consumption | Authenticated by API key; **content untrusted** |
| **B2** reviewer browser → dashboard | approvals, policy edits, settings | Authenticated user; privileged; phishable |
| **B3** Slack/email → API | interactive approvals | Channel-signed; identity mapping is the weak link |
| **B4** VERA → GitHub | evidence fetches with a GitHub App token | Trusted source; token must be read-only and scoped |
| **B5** VERA → LLM API | redacted text for drafts/summaries | Output is untrusted text; never a decision input |
| **B6** VERA → Slack/email | notifications with decision links | Delivery is best-effort; content must not be sufficient to approve |
| **B7** tenant ↔ tenant | shared Postgres, Redis, queue, KMS | Isolation is enforced, not assumed |

---

## 2. Assets, ranked by blast radius

| # | Asset | Why it matters | If compromised |
|---|---|---|---|
| A1 | **Tenant signing keys** | A valid EdDSA signature *is* an approval | Attacker forges ALLOW tokens for any action; every downstream verifier trusts them |
| A2 | **Active policy set** | Deterministic authority for BLOCK/REVIEW | A `permit` for everything silently disables VERA while audit looks healthy |
| A3 | **Approval records + audit chain** | Proof of who approved what, as executed | Repudiation; inability to answer an auditor; hidden tampering |
| A4 | **Decision inputs (arguments, context)** | Shell commands and args routinely contain secrets, DB URLs, customer data | Secret leakage via VERA — VERA becomes the breach |
| A5 | **API keys (decide scope)** | Live in developer machines and CI | Fabricated decisions/outcomes for that tenant; baseline poisoning |
| A6 | **Reviewer sessions** | Human approval authority | Attacker approves their own actions |
| A7 | **Evidence-provider credentials** (GitHub App) | Fetch trusted facts | Spoofed evidence; read access to private repos |
| A8 | **Baselines and outcome ledger** | Inputs to severity and to tuning recommendations | Slow poisoning that makes attacks look normal |
| A9 | **Adapter packages (npm)** | Run inside every customer's agent process | Supply-chain compromise of every customer at once |

---

## 3. Adversaries

| Adversary | Position | Goal | Capability |
|---|---|---|---|
| **Compromised agent** (prompt-injected, jailbroken, or simply wrong) | Inside B1 with a valid API key | Execute a consequential action without a real review; exfiltrate | Controls every field of the decide request; can call tools directly if the adapter is bypassable; can retry indefinitely |
| **Developer bypassing review** | Same as above, plus can edit adapter config | Skip approvals that slow them down | Disables hooks, edits class tables, sets fail-open |
| **Malicious tenant** | Own tenant, valid credentials | Read or influence another tenant | Crafts IDs, tokens, JWKS lookups aimed at other tenants |
| **Compromised reviewer** (phished or insider) | B2/B3 | Approve attacker's actions; loosen policy | Approves, edits policy, changes routing |
| **Network attacker** | Between any boundary | Replay, forge callbacks, steal tokens | Observes and replays traffic; cannot break TLS |
| **Compromised evidence source** | B4 | Make prerequisites appear met | Returns false "tests passed / backup verified" |
| **VERA operator insider** | Inside the trusted core | Tamper with audit, read tenant data | DB and KMS access unless constrained |
| **Supply-chain attacker** | Adapter or dependency | Everything above, everywhere | Ships a malicious adapter version |

---

## 4. Threats and mitigations

Format: **ID — title.** Attack → impact → mitigations (V1 required unless marked *later*) → proving test. Likelihood/impact are the author's estimate for V1's wedge (coding agents).

### 4.1 Governing an adversary (the threats unique to VERA)

**T01 — Adapter bypass.** The agent executes a tool without the hook firing: hooks disabled in user settings, a different runtime, a subprocess that spawns its own shell, a tool VERA doesn't know about. → Consequential action with no decision. *Likelihood: high. Impact: high.*
- VERA can only govern what routes through it. **Say this in the docs and the dashboard**; never imply otherwise.
- For Claude Code: ship a managed-settings template (enterprise `managed-settings.json`) that pins the hook so user settings cannot remove it; document that without managed settings the hook is advisory.
- **Reconciliation** *(later, days 31–50)*: compare observed side effects (git pushes, deployments via GitHub events) against decisions; report `unattested actions` per actor. Turns silent bypass into a visible metric.
- Unknown tools default to the consequential class (see T03).
- Test: hook removed → reconciliation report shows the push as unattested within one sync cycle.

**T02 — Canonicalization and argument smuggling.** Approve one thing, execute another that hashes the same or is judged the same: JSON key order and number formatting (`1` vs `1.0`), unicode normalization and homoglyphs, trailing whitespace, shell constructs (`$PROD_URL`, backticks, `$(…)`, heredocs) whose meaning is resolved at execution, path aliasing (`./a/../b`). → A REVIEW-bound token authorizes something else. *Likelihood: medium. Impact: high.*
- `packages/canon`: RFC 8785 JCS over a fixed field set; **no semantic normalization of shell strings** — hash the exact bytes the tool will receive; NFC-normalize only field *names*, never values.
- Adapters recompute `action_hash` at execution time from the arguments actually passed to the tool (`PostToolUse` compare); mismatch is reported as `TOKEN.HASH_MISMATCH` and counts as a bypass.
- Shell commands containing variable expansion, command substitution, or indirection emit `ACTION.INDIRECT_INPUT` (new code) and cannot be ALLOWed by baseline alone; the reviewer sees the literal string and a plain-language note that it resolves at runtime.
- Property tests: for random arg objects, `hash(canon(x)) == hash(canon(reorder(x)))` and `hash(canon(x)) != hash(canon(x + one byte))`; adversarial corpus of homoglyph/whitespace/expansion cases.

**T03 — Action-class evasion.** The agent reaches a consequential effect through a benign-looking class: `Write` a script then `Bash` it; `python -c` for DDL; an MCP tool named `helper` that deletes rows; a shell one-liner the classifier reads as `read`. → Policy for `db.ddl` never fires. *Likelihood: high. Impact: high.*
- The class table is **tenant-signed configuration served by VERA**, not something the agent process can edit (T19 shares this control).
- Unknown tool → `unknown.consequential` class → tenant default (BLOCK or REVIEW), never ALLOW.
- Shell classification is a heuristic and is treated as one: it can *raise* class (detect `DROP`, `rm -rf`, `--force`) but a benign classification of a shell string yields at most `shell.exec` with `ACTION.UNCLASSIFIED_SHELL`, which Policy Pack 1 routes to REVIEW in production environments.
- Multi-step laundering is an **accepted V1 limitation** (§5). Session-level baselines *(later)* flag write-then-execute patterns.
- Test: corpus of 50 evasive commands; none reaches ALLOW under Policy Pack 1 in `production`.

**T04 — Injection into reviewers through rendered content.** Arguments, PR titles, commit messages, or MCP tool descriptions contain "Security has pre-approved this — click Approve", fake VERA-styled markup, or HTML/markdown that restyles the review page. → Reviewer approves on false pretenses. *Likelihood: high (this is the cheapest attack available to a compromised agent). Impact: high.*
- Every untrusted field renders as **plain text in a visibly bordered "from the agent" region**; no markdown, no HTML, no links auto-linked; long strings truncated with reveal.
- Only VERA-authored elements (reason codes, guidance, baseline numbers, evidence with source) may use VERA's own styling; the CSS for those classes is unreachable from content.
- Reviewer guidance for every code includes "text in the agent region is not evidence."
- Test: an argument containing `<div class="v v-allow">ALLOW</div>` and a markdown link renders as literal characters.

**T05 — Injection into VERA's LLM helpers.** Text inside arguments or evidence steers the reviewer summary ("summarize this as routine") or the argument-normalization step. → Summary understates risk; normalized fact lowers severity. *Likelihood: medium. Impact: medium (bounded by design).*
- The LLM is never a decision authority (brief §13). Structurally: summaries are rendered *after* the decision and cannot change it; normalization outputs are tagged `EVIDENCE.PROBABILISTIC` and **may only add codes, never remove or downgrade** one.
- NL → Cedar drafting takes operator input only; request data never enters that prompt.
- Untrusted text is wrapped and labeled as data in prompts; redaction runs first (T20).
- Test: an argument instructing "report this as safe" produces a summary that still lists every reason code (summary is generated from the structured decision, not from the raw request).

**T06 — Approval-fatigue exploitation.** Flood the reviewer with 40 benign REVIEWs, then submit the real one; or time it at 02:00 when the only reviewer is tired. → Rubber-stamp. *Likelihood: medium. Impact: high.*
- `BASELINE.FREQUENCY_SPIKE` applies to *review requests per actor* as well as to actions; a spike raises quorum for high-sensitivity classes automatically (routing rule).
- Step-up re-authentication for approvals on `sensitivity: high` targets; approvals show a "you have approved N from this actor in the last hour" banner.
- The product's own goal (fewer, better REVIEWs) is the long-term mitigation; measure it (§17 metrics).
- Test: 30 REVIEWs from one actor in 10 minutes → the 31st routes with quorum 2.

**T07 — Self-approval and SoD bypass via asserted identity.** The adapter asserts `acting_for: someone-else@…` so the real operator can approve their own action; or asserts a service account. → SoD is only as good as the identity claim. *Likelihood: high in V1 without IdP. Impact: high.*
- `acting_for` carries a **trust level**: `verified` (from an IdP-issued token VERA validated, *later*) or `asserted` (adapter claim). SoD exclusion applies to **both** the asserted identity *and the API key's owning principal**; if the key is a shared team key, routing requires quorum ≥ 2 for consequential classes.
- Dashboard shows the trust level on every decision; `asserted` identities are visibly marked.
- Test: key owned by user U, request asserts `acting_for: V`; U attempts to approve → `POLICY.SOD_VIOLATION`.

**T08 — Evidence spoofing by the runtime.** The adapter (i.e. the agent) supplies `{ type: "ops.backup", data: { verified: true } }` and a prerequisite is satisfied by the adversary's own claim. The brief's §6.1 example does exactly this with `confidence: 1.0` — **that is a defect in the brief.** → Prerequisite checks are theatre. *Likelihood: high. Impact: high.*
- Evidence carries `trust: verified | asserted`. `verified` means VERA fetched it from a provider using VERA's own credentials (GitHub App) or computed it (baselines). Adapter-supplied evidence is always `asserted`.
- `PREREQ.*` codes can only be *cleared* by `verified` evidence. Asserted evidence may add codes (raise concern) but never satisfy a prerequisite. Policy Pack 1 encodes this; the Cedar schema exposes `evidence.<name>.trust`.
- The brief's example is corrected in `boundary-and-assumptions.md` (A1).
- Test: request asserts `backup.verified = true` with no provider confirmation → `PREREQ.BACKUP_NOT_VERIFIED` still present.

**T09 — Baseline poisoning (grooming).** Over weeks, the agent performs many small versions of an action so the eventual large one falls inside p95; or deliberately triggers spikes so thresholds get raised by an operator. → `BASELINE.*` goes quiet. *Likelihood: low–medium. Impact: medium.*
- Baselines are computed **only from actions that reached outcome `executed` without revert or incident** and that were ALLOWed or approved — attempted actions do not train the baseline.
- Baselines can only add severity; they can never satisfy a policy REVIEW or clear a prerequisite. Loosening happens only via a human-activated policy version (brief §8).
- Drift report *(later)*: p95 moving > 50 % in 30 days for an actor/class is itself a reviewable event.
- Accepted residual risk: slow grooming within the p95 band (§5).

**T10 — Outcome-ledger poisoning.** Fake `outcome: executed, reverted: false` reports make a rule look precise, so the recommendation engine proposes auto-ALLOW. → Policy loosens on false data. *Likelihood: medium. Impact: medium.*
- Outcomes carry `source` and trust like evidence; adapter-reported outcomes are `asserted`; GitHub-observed reverts/rollbacks are `verified`.
- Recommendations display the trust mix of the outcomes behind them and require human activation with tests (brief §8, §7.1).
- Test: a recommendation built from 100 % asserted outcomes is labeled as such and cannot be activated without acknowledging it.

**T11 — Time claims.** `context.local_time` is adapter-supplied; the agent sets it to 14:00 to dodge `BASELINE.TIME_ANOMALY`. *Likelihood: high (trivial). Impact: low–medium.*
- Time-of-day features use **server receive time** converted with the `acting_for` principal's configured timezone (tenant setting), never the adapter's claim. `local_time` is stored for display only.
- Test: request claims 14:00, server time is 02:14 tenant-local → time anomaly still fires.

**T12 — Fail-open manipulation.** The agent host blocks VERA's endpoint (firewall, DNS) to force the adapter into degraded mode, or edits the local safe-default table to mark `deploy.production` as read-only. *Likelihood: medium. Impact: high.*
- The safe-default table is fetched from VERA and **signed with the tenant key**; the adapter verifies the signature and refuses an unsigned or foreign table; the table is cached with a bounded TTL.
- Consequential classes never fail open (brief §12); degraded-mode allows for read-only classes are queued and reported on reconnect; a tenant alert fires when degraded events exceed a threshold.
- Test: endpoint unreachable, `deploy.production` → adapter returns `ask`; `file.read` → `allow` + queued `SYSTEM.DEGRADED_MODE` event that appears in audit after reconnect.

### 4.2 Tokens, keys and callbacks

**T13 — Decision-token replay and cross-binding.** Reuse an ALLOW token for a second execution, a different action, a different tenant, or after expiry; harvest tokens from logs. *Likelihood: medium. Impact: high.*
- Claims bind `tenant`, `action_hash`, `jti`, `exp`, `aud` (adapter/receiver id). Verifiers check all five. Default TTL: 10 min for ALLOW, 15 min for approvals, tenant-configurable downward.
- `POST /v1/tokens/consume` marks `jti` used; online receivers call it; offline receivers rely on `exp`. VERA never logs token bodies; adapters are told not to.
- Test: same token presented twice to consume → second returns `TOKEN.ALREADY_CONSUMED`; token with tenant A key presented under tenant B → signature fails (different JWKS).

**T14 — Signing-key compromise.** Keys exported from the process, an insider signs arbitrary tokens, or a key is used past rotation. *Likelihood: low. Impact: catastrophic.*
- Keys are generated and held in a KMS; the API holds only a signing handle; no export path exists in code.
- Per-tenant keys with `kid`; rotation with overlap window; JWKS served with a short cache TTL and a `revoked` list; every signing operation is an audit event with decision id; anomaly alert on signing volume vs decision volume (they must match 1:1).
- Test: audit count of signatures equals count of issued tokens over a test run; a revoked `kid` fails verification within cache TTL.

**T15 — Forged approval callback.** Attacker POSTs "approved" to the adapter's callback URL. *Likelihood: medium. Impact: high.*
- The callback carries no authority of its own: the adapter proceeds only on a **valid decision token** verified against JWKS. Callback payload signature and timestamp window are belt-and-braces.
- Test: callback with a well-formed but unsigned token → adapter stays in `ask`.

**T16 — Idempotency abuse.** Replay a `request_id` / idempotency key with a different body to retrieve a prior ALLOW. *Likelihood: medium. Impact: high.*
- Idempotency records store `body_hash`; a replay with a different hash returns `409 IDEMPOTENCY_MISMATCH` and is audited.
- Test: same key, mutated body → 409.

### 4.3 Multi-tenancy and data

**T17 — Cross-tenant read or influence.** Crafted IDs, JWKS lookups, queue jobs, or Redis keys reach another tenant. *Likelihood: medium. Impact: high.*
- `tenant_id` is derived from the authenticated API key or session — never from the request body. Postgres RLS on every table with `SET LOCAL vera.tenant_id` per request; workers set the same context per job; Redis keys and queue payloads are tenant-prefixed and validated on dequeue.
- No admin "all tenants" query path in the API; operator tooling goes through a separate, audited role.
- Test suite: for every endpoint, tenant A with tenant B's IDs → 404 (not 403, to avoid existence leaks); JWKS of A cannot verify B's tokens.

**T18 — Sensitive data in arguments.** Shell commands with `PGPASSWORD=…`, URLs with tokens, customer PII in tool args are stored, shown to reviewers, sent to the LLM, kept for years. *Likelihood: certain. Impact: high.*
- Redaction pipeline runs **before** the rendered view is stored and before any B5 call: secret-pattern scanning (keys, JWTs, connection strings, card numbers) plus tenant-defined patterns; raw arguments encrypted at rest with a per-tenant data key; reviewer "reveal raw" is a step-up, audited action.
- Retention is per tenant with a hard default (90 days raw, 1 year rendered/audit); deletion is real, not a flag.
- Test: an argument containing a known secret pattern is redacted in the review UI, in the LLM prompt log, and in webhooks.

**T19 — Adapter configuration tampering.** Class tables, fail-mode tables, endpoint URLs edited by the developer or the agent (which can write files). *Likelihood: high. Impact: high.*
- All adapter behavior tables come from VERA and are tenant-signed (shares mitigation with T12); the adapter's only local config is the endpoint and key; an agent editing the adapter package itself is T01 territory and shows up in reconciliation.

**T20 — Operator insider tampering with audit.** DB access used to delete or alter decisions or approvals. *Likelihood: low. Impact: high (trust of the whole product).*
- Audit events are append-only (DB role without UPDATE/DELETE), hash-chained per tenant; the chain head is periodically **signed and delivered to the tenant** (webhook + downloadable) so a tenant can verify continuity independently of VERA.
- Test: `verify-chain` tool detects a deleted or altered row.

### 4.4 Humans, channels and the dashboard

**T21 — Reviewer phishing and session theft.** Fake VERA login page; stolen session cookie; approval link in email replayed by an attacker. *Likelihood: medium. Impact: high.*
- Dashboard: short-lived sessions, SSO *(later)*, step-up (re-auth or WebAuthn) for high-sensitivity approvals and for policy activation; approval links are one-time, bound to the reviewer, and land on an authenticated page — the link never approves by itself.
- Slack: interactive payloads verified with Slack's signing secret and mapped to a VERA user via a one-time link flow; Slack approval allowed only for `sensitivity ≤ medium` unless the tenant opts up.

**T22 — Policy tampering.** A compromised reviewer or admin activates `permit(principal, action, resource);`. *Likelihood: low–medium. Impact: catastrophic and quiet.*
- Activation requires passing tests; tenant option for two-person activation; every decision records `policy_set_version`, and a version change generates a diff notification to all admins; a "coverage" check warns when a new version ALLOWs a Policy Pack test case that previously REVIEWed.
- Test: activating a version that flips `prod-ddl-requires-review` to ALLOW triggers the coverage warning and requires acknowledgement.

**T23 — Dashboard web-app class threats.** XSS from rendered arguments (see T04), CSRF on approve, IDOR on decision ids, privilege escalation between reviewer and admin roles.
- Standard controls: strict CSP with no inline scripts, output encoding by default, same-site cookies + CSRF tokens, authorization on every object fetch (tenant + role), RBAC with `reviewer`, `policy-admin`, `owner` roles; role changes audited.

### 4.5 Supply chain and availability

**T24 — Malicious adapter release.** A compromised npm account ships an adapter that reports ALLOW locally. *Likelihood: low. Impact: catastrophic.*
- npm provenance (Sigstore) on every release; 2FA-required publishing; minimal dependencies (the adapter is < 500 lines with `jose` as its only runtime dependency); pinned lockfiles; the adapter *cannot* produce a valid token — it only verifies — so a malicious adapter degrades to T01 (bypass), which reconciliation surfaces.

**T25 — VERA as a denial-of-service on the customer.** VERA outage, or per-tenant rate limits, stall every governed agent. *Likelihood: medium. Impact: medium–high.*
- SLO for `/decide` availability; adapter degraded mode (T12); per-tenant quotas with burst rather than hard cut-offs; rate-limit responses are distinguishable from outages so the adapter can back off instead of failing over.
- Chaos test: API down 5 minutes → read-only work continues, consequential actions wait for a human, nothing executes unattested.

---

## 5. Accepted risks and known limits (V1)

State these to design partners in writing.

1. **VERA governs only what routes through it.** Bypass is detectable (reconciliation, *later*) but not preventable without managed runtime settings or gateway placement.
2. **Multi-step laundering** — splitting a consequential action into innocuous steps — is not detected in V1.
3. **Shell semantics are not modeled.** Classification is heuristic; the fallback is conservative (REVIEW in production), which costs approvals, not safety.
4. **Slow baseline grooming** within the p95 band is possible; baselines never override policy, so the cost is a lost anomaly signal, not a bypass.
5. **Identity is asserted until an IdP integration exists.** SoD holds against the key owner and the asserted identity; shared keys degrade to quorum.
6. **Offline token receivers** cannot enforce single use; they get expiry only.
7. **The LLM helpers can be wrong.** They are designed so that wrong is harmless to the decision; they can still mislead a reviewer's *reading*, which is why the structured facts are always shown alongside.

---

## 6. Security requirements derived from this model

These become acceptance tests; the ID appears in the test name.

| ID | Requirement | Threats | Proving test |
|---|---|---|---|
| SR-01 | Adapter-supplied evidence is `asserted` and cannot clear a `PREREQ.*` code | T08 | asserted `backup.verified` leaves the code |
| SR-02 | `action_hash` is JCS over a fixed field set with byte-exact values; adapters recompute at execution | T02 | property tests + post-exec mismatch event |
| SR-03 | Unknown tools and unclassified shell in production cannot ALLOW | T03 | evasion corpus |
| SR-04 | Untrusted fields render as plain text in a labeled region | T04, T23 | markup-in-argument test |
| SR-05 | LLM outputs can add codes but never remove or downgrade | T05 | steering-text test |
| SR-06 | Time features use server time + tenant timezone | T11 | spoofed `local_time` test |
| SR-07 | Safe-default and class tables are tenant-signed and verified by adapters | T12, T19 | unsigned table refused |
| SR-08 | Consequential classes never fail open; degraded allows are reported | T12, T25 | outage chaos test |
| SR-09 | SoD excludes asserted identity **and** key owner; shared keys require quorum | T07 | self-approval refused |
| SR-10 | Tokens bind tenant, hash, jti, exp, aud; single use enforced online | T13 | replay and cross-tenant tests |
| SR-11 | Keys live in KMS; signatures are audited 1:1 with tokens; rotation with revocation | T14 | count parity + revoked kid |
| SR-12 | Callbacks carry no authority; adapters act only on verified tokens | T15 | unsigned callback ignored |
| SR-13 | Idempotency binds body hash | T16 | mutated replay → 409 |
| SR-14 | tenant_id from credentials only; RLS everywhere incl. workers; 404 on foreign ids | T17 | per-endpoint isolation suite |
| SR-15 | Redaction before storage of rendered view and before any LLM call; raw encrypted; reveal is step-up + audited | T18 | secret-pattern test |
| SR-16 | Audit is append-only, hash-chained, with tenant-verifiable signed heads | T20 | verify-chain detects tampering |
| SR-17 | Approval links never approve alone; Slack approvals capped by sensitivity; step-up for high | T21 | link replay test |
| SR-18 | Policy activation requires tests; version diffs notify; coverage regression warns | T22 | flip-to-ALLOW warning |
| SR-19 | Adapters verify only, never issue; published with provenance | T24 | adapter has no signing path |
| SR-20 | Baselines train only on executed, non-reverted, approved actions; add severity only | T09 | attempted-but-blocked action does not change counts |
| SR-21 | Outcomes and recommendations carry trust provenance; activation is human | T10 | asserted-only recommendation labeled |
| SR-22 | Review-request spikes raise quorum for high sensitivity | T06 | 30-in-10-min test |

---

## 7. Open questions to settle before contracts (deliverable 2)

1. **Claude Code hook semantics for REVIEW.** Confirm against current docs whether a `PreToolUse` HTTP handler can return a deferred/pending state and how long it may hold; if not, the adapter must return `ask` and let the human answer in-session while VERA records the decision — which changes the token flow (token issued on VERA approval, in-session ask becomes the fallback).
2. **Per-tenant KMS keys vs. one key with per-tenant `kid`.** Per-tenant keys are cleaner for isolation (T14, T17) but cost more at scale; decide the V1 default and the migration path.
3. **`aud` for tokens.** Adapter instance id, tenant, or receiver-declared? Affects offline verification.
4. **Indirect shell input.** Whether `ACTION.INDIRECT_INPUT` should be REVIEW or BLOCK in production by default in Policy Pack 1.
5. **Reconciliation data source for the GitHub wedge.** GitHub App webhooks (push, deployment) are enough for V1; decide whether to require the App install at onboarding.
6. **Shared team keys.** Allow at all in V1, or force per-user keys via the dashboard from day one (simpler SoD, harder onboarding)?

New reason codes introduced by this document, to be added to the registry: `ACTION.INDIRECT_INPUT`, `ACTION.UNCLASSIFIED_SHELL`, `TOKEN.HASH_MISMATCH`, `TOKEN.ALREADY_CONSUMED`, `IDENTITY.ASSERTED`, `EVIDENCE.ASSERTED`.
