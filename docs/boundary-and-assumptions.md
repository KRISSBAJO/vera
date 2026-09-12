# VERA — Product Boundary and Unsafe Assumptions

**Build deliverable 1 (with `threat-model.md`)** · 11 September 2026 · draft for review

## 1. The boundary, restated

VERA is a service that other systems ask one question: *should this specific action happen right now?* The asker is an adapter running inside an agent runtime (Claude Code first), a CI job, or a gateway. The answer is one of three words — ALLOW, REVIEW, BLOCK — plus the reasons, in a fixed vocabulary, and, for anything allowed or approved, a signed token that says exactly which action was approved and for how long.

VERA decides using three things it controls and one it doesn't. It controls the tenant's policies (Cedar, versioned, tested), the tenant's history (what this actor has done before, computed from actions that actually happened), and evidence it fetched itself (GitHub PR and check state). It does not control anything the agent sent: arguments, context, claimed identity, claimed evidence, claimed time. Those are recorded and shown, never relied on.

When VERA says REVIEW, it picks the humans who may answer — never the person whose action it is — shows them the reasons and the evidence with its source, and turns their yes into the same kind of signed token. Afterwards it records what happened, and uses that record to *propose* changes to policy that a human must activate.

VERA is not in the execution path and does not want to be. It is not an identity provider, not a gateway, not an injection detector, not a fraud database. It plugs into the things that already are.

The one-line test for scope: **if a feature would make VERA the thing that executes, authenticates, or detects attacks, it is out of scope; if it would make VERA's answer more accurate, more explainable, or more verifiable, it is in.**

## 2. Ambiguous or unsafe assumptions found in the brief

Each item names the brief section, the problem, and the resolution carried into the threat model and contracts.

| # | Where | Assumption | Why it's unsafe or ambiguous | Resolution |
|---|---|---|---|---|
| A1 | §6.1 example | Adapter-supplied `ops.backup { verified: false }` evidence with `confidence: 1.0` from `source: "adapter"` | The same channel could supply `verified: true`. Prerequisites satisfied by the governed party's own claim are theatre. | Evidence gets a `trust` field (`verified` / `asserted`); only `verified` clears `PREREQ.*` (threat T08, SR-01). Example to be corrected in the schema docs. |
| A2 | §6.1, §7.5 | `acting_for` is supplied by the adapter and SoD relies on it | The agent can name anyone. | SoD excludes both the asserted identity and the API-key owner; shared keys force quorum; identity trust level shown (T07, SR-09). |
| A3 | §6.1, §7.2 | `context.local_time` feeds `BASELINE.TIME_ANOMALY` | Adapter-controlled. | Server receive time + tenant timezone (T11, SR-06). |
| A4 | §6.1, §7.1 | Tool → `action.class` mapping is deterministic and reliable | For shell and generic MCP tools it is a heuristic; evasion is easy. | Unknown → consequential; unclassified shell in production → REVIEW; tables tenant-signed (T03, T19, SR-03, SR-07). |
| A5 | §5, §12 | Claude Code `PreToolUse` HTTP hook can return a deferred state and wait for an out-of-band approval | Not verified against current hook docs; may only support allow/deny/ask within a bounded timeout. | Open question 1 in the threat model; verify before contracts. If unsupported, REVIEW = `ask` in-session + VERA-issued token on approval, with the in-session answer as fallback. |
| A6 | §7.4, §8 | Baselines "can only REVIEW, never BLOCK" and outcomes "recommend only" | Consistent, but the brief doesn't say baselines can never *lower* a verdict either. | Explicit: baselines add severity only; loosening is only via an activated policy version (SR-20). |
| A7 | §6.3 | Token TTL unspecified | Unbounded tokens are replayable. | Defaults 10 min (ALLOW) / 15 min (approval), tenant-configurable downward; `aud` claim added (T13, SR-10). |
| A8 | §12 | Async enrichment can "upgrade a REVIEW to ALLOW via callback" | A decision that changes after issuance breaks reproducibility and confuses audit. | An upgrade is a **new decision** referencing the original (`supersedes`), with its own token; the original stays as issued. |
| A9 | §7.1 | Cedar three-outcome mapping when a plain `permit` and a `@vera_effect("review")` `permit` both match | Ambiguous precedence. | Most restrictive wins: any matching review-annotated permit → REVIEW; any forbid → BLOCK. |
| A10 | §7.2, §9 | Baseline counters in Redis | Redis is not a source of truth; reproducibility needs a persisted `baseline_snapshot_id`. | Redis caches; Postgres holds snapshots (or the event log they derive from). |
| A11 | §12 | p95 ≤ 150 ms with RLS + Cedar WASM + baseline lookups | Plausible only if baselines are precomputed per (actor, class, target). | Baseline rollups are materialized by workers; `/decide` reads, never computes. |
| A12 | §5 | OpenAI Agents SDK `needsApproval` + serializable interruptions; GitHub custom deployment protection rules | API details and availability must be re-verified at build time; the deployment-rule feature was in public preview per the scan. | Verify during their build windows; neither is in the day-30 slice. |
| A13 | §6.3, §10 | Per-tenant signing keys in a KMS | Right for isolation; cost and key-count at scale are unaddressed. | Open question 2; V1 default per-tenant, revisit at 1,000 tenants. |
| A14 | §6.4 | `POST /v1/tokens/consume` enforces single use | Only for receivers that call it; the agent host is not obliged to. | Documented as online-only guarantee (accepted risk 6). |
| A15 | §14, §7.5 | Slack approvals are equivalent to web approvals | Slack identity mapping and workspace compromise make them weaker. | Slack approvals capped at `sensitivity ≤ medium` by default; step-up on web for high (T21, SR-17). |
| A16 | §15 day 11–30 | Dogfooding on LogaXP repos exercises the adversarial cases | It exercises the happy path; nothing in a normal workday looks like T02–T05. | The evasion corpus and injection tests in the threat model are required for the day-30 gate, not just live usage. |
| A17 | §2, §19 | Anthropic shipping a hosted queue is threat #1 | True, and the brief's hedge assumes VERA can be "the decision their queue calls" — that requires a stable public hook contract that Anthropic controls. | Keep the OpenAI adapter on the day-50 schedule; treat the Claude Code hook contract as an external dependency with a version pin and a contract test. |

## 3. What changes in the brief because of this

- §6.1/6.2 request and response schemas gain `evidence[].trust`, `acting_for.trust`, `token.aud`, and `supersedes`.
- §6.5 registry gains `ACTION.INDIRECT_INPUT`, `ACTION.UNCLASSIFIED_SHELL`, `TOKEN.HASH_MISMATCH`, `TOKEN.ALREADY_CONSUMED`, `IDENTITY.ASSERTED`, `EVIDENCE.ASSERTED`.
- §7.1 states the most-restrictive precedence rule.
- §11 monorepo gains `packages/redaction` (T18) and a `tools/verify-chain` CLI (T20).
- §16 acceptance criteria absorb SR-01…SR-22 by reference.
- §15 day-30 gate adds: evasion corpus, injection rendering test, spoofed-evidence test pass.

These edits are applied to `brief-v2.md` once you've reviewed this document — not before, so the diff is reviewable.
