# ADR-0004 — Cedar context is closed; only declared attributes are policy-visible

**Status:** accepted · 11 September 2026
**Context:** the Cedar spike that opens deliverable 3 (ADR-0001 called Cedar the least-proven dependency). Findings from `@cedar-policy/cedar-wasm` 4.12.0:

| Checked | Result |
|---|---|
| `@id("…")` annotation becomes the policy id reported in `diagnostics.reason` | Confirmed (we also key `staticPolicies` by id ourselves, so this holds regardless of Cedar's default naming) |
| Custom annotations (`@vera_effect("review")`) readable via `policyToJson` | Confirmed |
| Strict validation against a JSON schema catches a misspelled attribute at compile time | Confirmed |
| Cedar's forbid-overrides-permit + our review-annotation mapping give ALLOW / REVIEW / BLOCK / NO_MATCH deterministically | Confirmed, including the A9 case (plain permit + review permit ⇒ REVIEW) |
| Open records (`additionalAttributes: true`) for dynamic tool arguments | **Rejected by the WASM build** — "experimental `partial-validate` feature is not enabled" |

## Decision

1. Every record in the VERA Cedar schema is **closed**. The policy-visible attributes are declared in `packages/policy-engine/src/schema.ts` (`ARG_ATTRIBUTES`, `EVIDENCE_ATTRIBUTES`, `BASELINE_ATTRIBUTES`, `HINT_ATTRIBUTES`) with explicit Cedar types.
2. The engine **projects** incoming context onto the declared attributes before evaluation (`projectContext`). Undeclared keys are dropped; a declared key whose runtime value does not match its declared type is dropped too, so a malformed value can never turn into a request-validation failure — `has` simply returns false.
3. Undeclared tool arguments remain part of the **action hash** (`@vera/canon`); they are invisible to policy, not to the token.
4. Tenants extend the declared argument set through the class-table configuration in a later deliverable; the schema is regenerated per tenant from that table and policies are re-validated on activation.
5. `context.evidence` receives only verified facts; `context.asserted` receives runtime claims. Policy Pack 1 never clears a prerequisite from `asserted`. This is SR-01 enforced by schema shape, not by author discipline.
6. Cedar evaluation **errors never yield ALLOW**: an allow with diagnostics errors becomes REVIEW with `SYSTEM.FAIL_CLOSED`, because an errored `forbid` would have been silently skipped.

## Consequences

- A policy author cannot reference an attribute the validator does not know about; typos fail at activation, not in production. This is a feature.
- "Any argument is available to policy" is not a promise VERA makes. The class table is the place to declare what a tenant's policies may see.
- If Cedar later stabilises open records, this ADR can be revisited; nothing in the API contract depends on it.
