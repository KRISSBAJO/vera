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
| `packages/policy-engine` | Cedar: compile a policy set keyed by `@id`, validate strictly against the VERA schema, evaluate with closed-record context projection, map to ALLOW / REVIEW / BLOCK / NO_MATCH. Ships Policy Pack 1. |
| `packages/db` | Postgres schema (Drizzle) + migrations with FORCE row-level security, tenant-scoped client, hash-chained append-only audit, key sealing. |
| `packages/decision-engine` | Request + policy set + evidence → verdict, reason codes, risk score, review routing with SoD, expiry. |
| `packages/baseline-engine` | Per-organisation behavioural baselines: novelty, time-of-day, magnitude, bursts. Deterministic, explainable, add-severity-only. |
| `packages/evidence` | Evidence providers (Proof): facts VERA fetches itself, under a budget. GitHub PR approval, checks, migrations. |
| `apps/api` | Fastify: `/v1/decide`, `/v1/decisions/:id` (+ approve / reject / outcome), `/v1/tokens/consume`, `/v1/audit-events`, tenant JWKS, `/openapi.json`. CLI: `migrate`, `bootstrap`, `add-user`, `serve`. |
| `packages/adapters/claude-code` | `vera-hook`: the Claude Code command hook (ADR-0002). `pre` asks VERA and verifies tokens; `post` recomputes the hash and reports outcomes; `init` writes config and hooks; `status`. Apache-2.0. |

## Put it in front of Claude Code

```bash
corepack pnpm --filter @vera/api cli bootstrap --org "LogaXP" --email you@example.com --aud adapter:my-laptop
node packages/adapters/claude-code/dist/cli.js init \
  --endpoint http://localhost:4000 --api-key vera_sk_… --org org_… --aud adapter:my-laptop \
  --acting-for you@example.com --settings .claude/settings.local.json
```

Restart Claude Code in that project; hooks are loaded at session start. Approve or reject a REVIEW with the reviewer session token:

```bash
curl -X POST http://localhost:4000/v1/decisions/dec_…/approve -H "Authorization: Bearer vera_rs_…" -H "content-type: application/json" -d '{"rationale":"checked"}'
```

## Run it locally

```bash
corepack pnpm install
docker compose -f infra/docker-compose.yml up -d        # Postgres on 55432 (app role vera_app), Redis on 6380
cp .env.example .env                                     # then set VERA_MASTER_KEY=$(openssl rand -base64 32)
corepack pnpm turbo run build
corepack pnpm --filter @vera/api cli migrate
corepack pnpm --filter @vera/api cli bootstrap --org "LogaXP" --email you@example.com
corepack pnpm --filter @vera/api dev                     # http://localhost:4000, OpenAPI at /openapi.json
```

Tests run against the Docker Postgres: `corepack pnpm turbo run test`.

## Build order (from `brief-v2.md` §21)

1. Threat model + boundary restatement + assumptions — done (v2.1 of the brief applies its fixes)
2. Contracts: schemas, canonicalization, decision token — done (62 tests)
3. Vertical slice: Claude Code hook → `/v1/decide` → review queue → signed token → callback — **done** (Cedar spike, database with RLS, decision engine, API, GitHub evidence provider, `vera-hook` adapter; 168 tests). First dogfood session ran on this repo and produced Policy Pack 1 v2 and the harness-tool classifier fixes.
4. Baselines, outcomes, second adapter — **baselines and the outcome loop done** (`packages/baseline-engine`, `GET /v1/baselines`, `GET /v1/reports/policy-precision`). Remaining: the OpenAI Agents SDK adapter.
5. Hardening, dashboard v0
6. Design-partner packaging

Days 1–10 also run the validation interviews (brief Appendix A); the day-10 gate decides whether Policy Pack 1 stays on coding agents.
