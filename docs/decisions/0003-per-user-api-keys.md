# ADR-0003 — Per-user API keys from day one; no shared team keys in V1

**Status:** accepted · 11 September 2026
**Context:** threat-model open question 6. Separation of duties (SR-09) needs to know *who* is behind a request. Until an identity-provider integration exists, `acting_for` is an adapter assertion; the only identity VERA can actually trust is the owner of the API key that made the call.

## Decision

1. Every API key belongs to exactly one principal (a user or a named service account). There is no "team key".
2. `vera-hook init` creates the developer's own key through the dashboard (or a one-time enrolment link) and stores it in `~/.vera/config.json` with `0600` permissions. Onboarding cost: one command per developer.
3. SoD excludes the key owner, the asserted `acting_for`, and the actor from approving. Because keys are per-user, the key owner *is* the person at the keyboard, so self-approval is refused without an IdP.
4. Keys are scoped: `decide` (call `/v1/decide`, report outcomes, consume tokens) is the only scope an adapter gets. Approving, editing policy, and administration require a dashboard session, never an API key.
5. Service accounts (CI runners, deployment agents) get their own keys with a named human owner recorded; requests from a service key route with quorum ≥ 2 for consequential classes, since no individual is at the keyboard.
6. Key rotation and revocation are self-service in the dashboard and audited; a revoked key fails closed at the adapter (which then behaves as "VERA unreachable" for that key).

## Consequences

- A team of 12 developers has 12 keys. That is the point: audit says which person's key was used, and SoD has something real to check.
- The `quorum ≥ 2 for shared keys` rule in brief §7.5 becomes `quorum ≥ 2 for service-account keys`; the brief is updated accordingly.
- A later IdP integration upgrades `acting_for` to `verified` and can bind keys to SSO identities, but nothing in V1 waits for it.
