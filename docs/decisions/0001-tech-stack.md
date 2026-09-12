# ADR-0001 — Technology stack for V1

**Status:** accepted · 11 September 2026
**Context:** brief-v2 §11 names a pragmatic stack; this record pins the choices, versions, and the alternatives rejected so nobody re-litigates them mid-build.

## Decisions

| Layer | Choice | Version (Sept 2026) | Why this and not the obvious alternative |
|---|---|---|---|
| Language | **TypeScript**, strict, ESM everywhere | 7.0 | One language across API, workers, dashboard, and the adapters that run inside customers' Node agents. Python was the alternative; it would split the adapter and server codebases. |
| Runtime | **Node.js 22 LTS** | 22.x | Matches Claude Code / Agent SDK runtime, so adapters have no extra dependency. |
| Package manager / monorepo | **pnpm workspaces + Turborepo** | pnpm 10, turbo 2.10 | Strict node_modules (no phantom deps — matters for the adapter's supply-chain story), task caching. |
| Schemas | **zod 4** with built-in `z.toJSONSchema` | 4.6 | Single source of truth for TS types, runtime validation, and published JSON Schema / OpenAPI. zod 4's native JSON Schema export removes `zod-to-json-schema`. |
| Canonicalization | **`canonicalize`** (RFC 8785 JCS) + `node:crypto` SHA-256 | 5.0 | The only spec'd JSON canonical form; adapters in other languages can match it. |
| Tokens | **`jose`**, EdDSA / Ed25519, JWS compact | 6.2 | Audited, zero-dependency, WebCrypto-based; works in Node, browsers, and edge runtimes so any receiver can verify. |
| Policy | **Cedar** via `@cedar-policy/cedar-wasm` | 4.12 | Chosen by AWS AgentCore and Docker — the vocabulary agent teams are already learning. Deterministic, analyzable, has a schema and a validator. OPA/Rego rejected: Turing-complete-ish, harder to validate, no schema. Inventing a DSL rejected outright. |
| API | **Fastify 5** + `fastify-type-provider-zod` + `@fastify/swagger` | 5.12 / 7.0 / 9.8 | Mature Node server, zod-typed routes, OpenAPI generated from the same schemas. Hono considered (lighter, edge-ready) — rejected because V1 is a stateful Node service with Postgres transactions per request, where Fastify's plugin/lifecycle model fits better. |
| Database | **PostgreSQL 16** with **row-level security**; **Drizzle ORM** + `postgres` driver; `drizzle-kit` migrations | 0.45 / 3.4 | RLS is the tenant-isolation mechanism (SR-14) and needs `SET LOCAL` per transaction; Drizzle exposes raw transactions cleanly. Prisma rejected: its connection/transaction model fights RLS. |
| Cache / coordination | **Redis** via `ioredis` | 6.0 | Idempotency records, rate limits, hot baseline reads. Never the source of truth (A10). |
| Queue | **BullMQ** | 6.3 | Evidence enrichment, outcome detection, webhook delivery, baseline rollups. Redis-backed, so no extra infrastructure. |
| Dashboard | **Next.js 16** (React) | 16.3 | Review queue and admin UI. Only started at deliverable 5; nothing in the core depends on it. |
| Tests | **Vitest 5** + **fast-check 4** | 5.0 / 4.10 | Property tests are mandatory for canonicalization (SR-02); Vitest runs TS directly. |
| Lint / format | **Biome** | 2.5 | One tool, fast, no ESLint config sprawl. |
| Logging | **pino** | 10.3 | Structured logs with redaction paths (SR-15 applies to logs too). |
| Local infra | **Docker Compose** (Postgres 16, Redis 7) | — | Both already installed on the build machine. |
| Secrets / signing | **KMS-held Ed25519 keys** in production; in development, keys generated in-process and stored encrypted on disk behind the same `Signer` interface | — | SR-11. The interface is defined in `packages/decision-token`; the KMS implementation lands in deliverable 5 (hardening). |

## Layout

```
apps/api                      Fastify
apps/dashboard                Next.js (deliverable 5)
workers/enrichment            BullMQ workers
packages/schemas              zod + JSON Schema        ← deliverable 2
packages/canon                JCS + action_hash        ← deliverable 2
packages/decision-token       issue/verify/JWKS        ← deliverable 2
packages/policy-engine        Cedar wrapper
packages/baseline-engine
packages/decision-engine
packages/evidence
packages/review-routing
packages/redaction
packages/audit
packages/adapters/claude-code
packages/adapters/openai-agents
packages/adapters/github-deployment-rule
tools/verify-chain
infra                         docker-compose, later Terraform
docs                          brief, threat model, decisions, reason codes
```

## Rules that follow from this

- Adapters may depend only on `@vera/schemas`, `@vera/canon`, `@vera/decision-token`, and `jose`. Nothing else. They verify tokens; they never hold signing material.
- Every wire object has exactly one definition, in `packages/schemas`; JSON Schema and OpenAPI are generated from it, never hand-written.
- `packages/canon` is shared byte-for-byte between server and adapters; a change to its normalization rules bumps `CANON_VERSION`, which is part of the hash input.
- No package may import from `apps/*`.

## Consequences

- TypeScript 7 is new (the native compiler). If it causes friction, pinning to 5.9 is a one-line change and nothing in the code depends on 7-only features.
- Cedar's WASM package is the least-proven dependency here; deliverable 3 starts with a spike that loads it, evaluates Policy Pack 1, and reads diagnostics, before anything is built on top.
