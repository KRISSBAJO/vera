# VERA

A signed decision service for consequential AI-agent actions. Working name; not cleared for trademark.

## Documents

| File | What it is |
|---|---|
| `docs/brief-v2.md` | Product and build spec (September 2026). Start here. |
| `docs/competitive-scan-2026-09.md` | Landscape scan behind the brief's §2 — ~75 sources. |
| `docs/threat-model.md` | Build deliverable 1: trust boundaries, threats T01–T25, security requirements SR-01–SR-22, accepted risks, open questions. |
| `docs/boundary-and-assumptions.md` | Build deliverable 1: the product boundary restated, and 17 unsafe or ambiguous assumptions found in the brief with resolutions. |
| `docs/decisions/` | Architecture decision records: 0001 tech stack, 0002 Claude Code adapter shape. |
| `docs/word/` | Word exports of the above, generated from the markdown — never edited by hand. |

## Code

| Package | What it is |
|---|---|
| `packages/schemas` | zod schemas for every wire object; reason-code registry; action-class taxonomy; `pnpm export` writes JSON Schema to `json-schema/`. |
| `packages/canon` | Canonical action form and `action_hash` (RFC 8785 + SHA-256); shell indirect-input analysis. Shared byte-for-byte with adapters. |
| `packages/decision-token` | Issue/verify EdDSA decision tokens bound to an action hash; tenant JWKS with revocation; single-use registry. |

```bash
corepack pnpm install
corepack pnpm turbo run build test
```

## Build order (from `brief-v2.md` §21)

1. Threat model + boundary restatement + assumptions — done (v2.1 of the brief applies its fixes)
2. Contracts: schemas, canonicalization, decision token — **done, awaiting review** (62 tests)
3. Vertical slice: Claude Code hook → `/v1/decide` → review queue → signed token → callback
4. Baselines, outcomes, second adapter
5. Hardening, dashboard v0
6. Design-partner packaging

Days 1–10 also run the validation interviews (brief Appendix A); the day-10 gate decides whether Policy Pack 1 stays on coding agents.
