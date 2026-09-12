# VERA design-partner pilot

**For:** an engineering or platform lead running coding agents with tool access.
**Length:** 30 days. **Cost:** nothing. **What we want:** your refusals, not your praise.

This document is deliberately blunt about what VERA does not do and what is not production-ready. A pilot that starts with an accurate picture is the only kind worth running, and the failure mode we most want to avoid is you trusting this more than it has earned.

---

## 1. What VERA is

Authentication says *who you are*. Authorization says *what you may do*. Neither answers **should this specific action happen right now** — and that is the question an agent with shell access raises a hundred times a day.

VERA answers it, in one of three ways:

| Verdict | Meaning |
|---|---|
| **ALLOW** | Proceed. Carries a signed token bound to this exact action. |
| **REVIEW** | A human decides. The agent holds, then proceeds or stops. |
| **BLOCK** | No. |

The product is not the verdict, it is the **signed decision token**: an Ed25519 JWS bound to a hash of the exact action — the exact command, the exact target. The receiver verifies it offline. If the agent changes so much as a flag between asking and executing, the token stops matching and the action is refused. That is what lets you answer "prove this specific action was approved *as executed*" with something other than a screenshot.

### The distinction everything rests on

Every fact VERA uses is either **verified** (VERA fetched it itself) or **asserted** (something told VERA). An agent saying "the tests passed" is asserted, forever. Only a fact VERA checked — a GitHub PR's real approval state, its real check runs — can satisfy a prerequisite. This is the difference between a policy engine and a permission slip the agent fills in for itself.

## 2. What VERA is not

- **Not a sandbox.** It decides; it does not contain. An agent that ignores the adapter is not stopped by VERA.
- **Not a runtime guarantee.** The Claude Code adapter is a command hook. Hooks can be disabled, and a determined user on their own laptop can remove it. VERA raises the cost of an unreviewed action and makes it *visible*; it does not make it impossible.
- **Not an LLM judge.** No model decides anything consequential. Policy evaluation is Cedar — deterministic, replayable, independently testable. Models draft policies and summarise for reviewers; they are never the authority.
- **Not a secrets manager, not a CI gate, not an MCP proxy.**
- **Not a compliance certification.** It produces evidence a person can use. It does not make you compliant with anything.

## 3. What you install

Three things, in about twenty minutes:

1. **The service** — one `docker compose` command: API, review dashboard, Postgres, Redis.
2. **An adapter** in whichever runtime you use:
   - Claude Code / Claude Agent SDK: `vera-hook` on `PreToolUse` / `PostToolUse`.
   - OpenAI Agents SDK: `createVeraGuard()` wrapping the tools you choose.
3. **Policy Pack 1** — a starting policy set for coding agents: production deploys, force pushes, destructive database work, secret access, outbound sends. Expect to change it in week one; that is the point.

Everything runs **in your infrastructure**. No decision, argument, or repository content reaches us.

## 4. What VERA stores, and where it goes

In your Postgres, nothing leaves it:

| Data | Why | Retention |
|---|---|---|
| Action requests (tool, arguments, target, environment) | The thing being decided | Yours to set; nothing is deleted automatically |
| Decisions, reason codes, risk scores | Reproducing why | as above |
| Approvals — who, when, what rationale | The audit answer | as above |
| Hash-chained audit events | Tamper evidence | append-only; the database refuses updates and deletes |
| Behavioural baselines | Novelty and time-of-day signals | rolling |

**Credentials in tool arguments are masked before storage** (`PGPASSWORD=…`, API keys, private key blocks, and structured `{env: {SECRET: …}}` shapes). The raw argument is sealed with AES-256-GCM and can be revealed by an admin — and that reveal is itself an audit event. Redaction is pattern-based: assume it catches the common shapes and not every shape.

**Outbound network calls, all optional, all off unless you configure them:**

| To | What is sent | Turn it off by |
|---|---|---|
| GitHub | PR/check queries for the repos you install the App on | not installing the App |
| Slack | A redacted one-line summary and a link | leaving `SLACK_BOT_TOKEN` unset |
| AWS KMS | Bytes to be signed | leaving `VERA_KMS_*` unset |

No telemetry. No phone-home. We learn what happened in your pilot because you tell us.

## 5. What happens when it breaks

The honest part.

| Failure | What happens |
|---|---|
| VERA unreachable | The adapter uses a **signed** class table: read-only classes proceed, consequential ones do not. The table is signed by your tenant key, so a stolen laptop cannot widen it. |
| VERA slow | Adapters have a budget and fall back to the same table. |
| Postgres down | VERA returns errors; adapters treat that as unreachable. |
| A reviewer never answers | The REVIEW expires. Expiry is a refusal, not an approval. |
| Evidence provider down | Prerequisites that needed it are `EVIDENCE.MISSING`, which does not satisfy them. Actions requiring verified evidence will not proceed. |
| Slack down | Nothing, except that reviewers must open the dashboard. A decision is never blocked by a notification. |

**Fail-open is a configuration you choose per action class, not a thing that happens to you.** The default is closed for anything consequential.

## 6. What is not production-ready

Read this section twice.

1. **Key custody is per-key.** A tenant registered against an AWS KMS key has production-grade custody: the private half never reaches the process and no export path exists in code. A tenant on the default local signer does not — an operator with database access *and* `VERA_MASTER_KEY` can extract a signing key. Run `vera-api doctor`; it tells you which you have. **The KMS path has not yet been exercised against a live key** — it is unit-tested against a real Ed25519 key, but the AWS round trip has not been run.
2. **Slack cannot approve, deliberately.** It notifies and links. See ADR-0006 for why we think a button in a channel would make the product worse.
3. **The adapter surface is two runtimes.** Claude Code and the OpenAI Agents SDK. Anything else needs the HTTP API directly.
4. **No SSO.** Reviewer sessions are bearer tokens. Fine for a pilot, not for a company.
5. **Single region, single instance.** No HA story yet.
6. **Policy authoring is Cedar text.** There is no policy UI.
7. **The threat model lists 8 accepted risks** (`docs/threat-model.md` §5). They are accepted, not solved. If any is unacceptable to you, that is exactly the feedback we want and it should probably stop the pilot.

## 7. What we ask of you

- **One repository or one agent workflow.** Not your whole org.
- **Two named reviewers minimum.** Separation of duties excludes whoever requested an action from approving it, so a single reviewer means their own requests can never be approved. `doctor` warns about this.
- **Thirty minutes in week one** to cut Policy Pack 1 down to what you actually care about.
- **Tell us every time VERA was wrong.** A REVIEW that was obviously fine is a false positive and is a bug. So is anything it let through that you would have wanted to see.
- **One 30-minute conversation at day 15 and day 30.**

## 8. How we will both know if it worked

Agreed at the start, measured from your own data, reported whether or not they flatter us:

| Question | Measure | What good looks like |
|---|---|---|
| Did it stop anything real? | Actions blocked or rejected that you agree should not have run | ≥ 1, with a story attached |
| Did it get in the way? | Share of REVIEWs the reviewer marked "obviously fine" | falling, week over week |
| Is review still real? | Median time-to-decision, and the share decided in under 10 seconds | fast is good; *everything* under 10 s means nobody is reading |
| Did it reduce load? | Approvals per developer per day vs. your baseline | down, without loosening policy |
| Can you prove an action? | Pick any past action; produce the signed token and its approval | yes, in under a minute |

`GET /v1/reports/policy-precision` produces the first three from your own decisions.

**A pilot where VERA blocked nothing and annoyed nobody is a failure, not a success.** It means the policy set was not aimed at anything.

## 9. Getting started

```bash
cp .env.example .env
# set VERA_MASTER_KEY, POSTGRES_PASSWORD, VERA_APP_PASSWORD — e.g. openssl rand -base64 32
docker compose -f infra/docker-compose.pilot.yml up -d --build
docker compose -f infra/docker-compose.pilot.yml run --rm api node dist/cli.js \
  bootstrap --org "Your Company" --email you@example.com --aud adapter:your-laptop
docker compose -f infra/docker-compose.pilot.yml run --rm api node dist/cli.js doctor
```

`bootstrap` prints an API key and a reviewer session token **once**. `doctor` tells you what is configured, what is missing, and what each gap costs you. Then point an adapter at it — `README.md` has the two-line version for Claude Code.

## 10. What happens at the end

The pilot stops, or it does not. There is no auto-renewal and nothing to cancel. The data is in your Postgres either way; we never had a copy.

If it stops, we would like a half hour on why. That is more useful to us than a pilot that quietly continues.
