/**
 * Policy Pack 1 — consequential tool calls by coding agents (brief §4, Appendix C).
 *
 * Conventions:
 *   @id("…")                 stable policy id; appears in diagnostics and in POLICY.* reason codes as policy_id
 *   @vera_effect("review")   a matching permit means REVIEW, not ALLOW (brief §7.1, most-restrictive-wins)
 *   forbid                   BLOCK
 *
 * Only `context.evidence` (verified) can satisfy a prerequisite. `context.asserted` is never consulted to
 * clear one — see schema.ts.
 *
 * v2 (2026-09-11, first dogfood session): added non-production permits for http.mutation and
 * message.send, and a production REVIEW for both. Without them a coding agent on a laptop could not
 * click a browser button or publish an artifact — every such call fell to POLICY.DEFAULT_DENY.
 *
 * v3 (2026-09-12): added `argument-mismatch-requires-review`, after finding that the force-push
 * rules below turned on `context.args.force` — a boolean the adapter derived and asserted. The
 * service now derives it too and its own reading wins, so those rules are sound again; this policy
 * covers the remaining question of an adapter that described the action differently from how the
 * action reads.
 *
 * v4 (2026-09-12, hostile-client suite): added `class-mismatch-requires-review`. A client speaking
 * the protocol directly could label `rm -rf /var/lib/postgresql/data` as `file.read` and be permitted
 * outright, because the read-only permits below never look at the command. Found by tests that lie,
 * not by tests that use the adapter.
 */
export const POLICY_PACK_1_VERSION = 4;

export const POLICY_PACK_1 = `
// ---- integrity of the request itself ----

// REVIEW rather than BLOCK, deliberately. VERA already used its own reading of the command, so the
// decision is made on the truth either way; what remains is a runtime that disagreed with it. That is
// what evasion looks like, but it is also what an out-of-date adapter looks like, and forbidding
// outright would take a fleet offline on a version skew — which is how a security control gets
// switched off. A human sees both readings and decides. Most-restrictive-wins still applies, so an
// action another policy forbids stays BLOCK.
@id("argument-mismatch-requires-review")
@vera_effect("review")
permit(principal, action, resource)
when { context.argument_mismatch == true };

// A read-only class was claimed for a command that plainly does something. Read-only classes are
// permitted outright below, so without this the class is simply a free pass: label 'rm -rf' as
// 'file.read' and nothing else in the pack ever looks at it.
@id("class-mismatch-requires-review")
@vera_effect("review")
permit(principal, action, resource)
when { context.class_mismatch == true };


// ---- version control ----

@id("vcs-push-non-force")
permit(principal, action == VERA::Action::"vcs.push", resource)
unless { context.args has force && context.args.force == true };

@id("no-force-push-to-default")
forbid(principal, action == VERA::Action::"vcs.push", resource)
when {
  context.args has force && context.args.force == true &&
  resource has branch && resource has default_branch &&
  resource.branch == resource.default_branch
};

@id("force-push-non-default-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"vcs.push", resource)
when { context.args has force && context.args.force == true };

@id("vcs-merge-allowed")
permit(principal, action == VERA::Action::"vcs.merge", resource);

// ---- production deployment ----

@id("prod-deploy-clean")
permit(principal, action == VERA::Action::"deploy.production", resource)
when {
  context.evidence has pr_approved && context.evidence.pr_approved &&
  context.evidence has tests_passed && context.evidence.tests_passed &&
  !(context.evidence has contains_migration && context.evidence.contains_migration)
};

@id("prod-deploy-needs-backup-if-migration")
@vera_effect("review")
permit(principal, action == VERA::Action::"deploy.production", resource)
when {
  context.evidence has contains_migration && context.evidence.contains_migration &&
  !(context.evidence has backup_verified && context.evidence.backup_verified)
};

@id("prod-deploy-migration-with-verified-backup")
permit(principal, action == VERA::Action::"deploy.production", resource)
when {
  context.evidence has contains_migration && context.evidence.contains_migration &&
  context.evidence has backup_verified && context.evidence.backup_verified &&
  context.evidence has pr_approved && context.evidence.pr_approved &&
  context.evidence has tests_passed && context.evidence.tests_passed
};

@id("staging-deploy-allowed")
permit(principal, action == VERA::Action::"deploy.staging", resource);

// ---- database ----

@id("prod-ddl-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"db.ddl", resource)
when { resource has environment && resource.environment == "production" };

@id("non-prod-ddl-allowed")
permit(principal, action == VERA::Action::"db.ddl", resource)
unless { resource has environment && resource.environment == "production" };

@id("prod-db-write-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"db.write", resource)
when { resource has environment && resource.environment == "production" };

@id("non-prod-db-write-allowed")
permit(principal, action == VERA::Action::"db.write", resource)
unless { resource has environment && resource.environment == "production" };

// ---- shell ----

@id("prod-shell-indirect-input-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"shell.exec", resource)
when { resource has environment && resource.environment == "production" && context.indirect_input };

@id("prod-shell-unclassified-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"shell.exec", resource)
when { resource has environment && resource.environment == "production" };

@id("non-prod-shell-allowed")
permit(principal, action == VERA::Action::"shell.exec", resource)
unless { resource has environment && resource.environment == "production" };

// ---- outbound: HTTP mutations and messages ----

@id("non-prod-http-mutation-allowed")
permit(principal, action == VERA::Action::"http.mutation", resource)
unless { resource has environment && resource.environment == "production" };

@id("prod-http-mutation-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"http.mutation", resource)
when { resource has environment && resource.environment == "production" };

@id("non-prod-message-send-allowed")
permit(principal, action == VERA::Action::"message.send", resource)
unless { resource has environment && resource.environment == "production" };

@id("prod-message-send-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"message.send", resource)
when { resource has environment && resource.environment == "production" };

// ---- secrets ----

@id("secret-read-allowed")
permit(principal, action == VERA::Action::"secret.read", resource);

@id("secret-write-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"secret.write", resource);

// ---- infrastructure ----

@id("infra-change-requires-review")
@vera_effect("review")
permit(principal, action == VERA::Action::"infra.change", resource);

// ---- read-only ----

@id("read-only-allowed")
permit(
  principal,
  action in [VERA::Action::"file.read", VERA::Action::"vcs.read", VERA::Action::"http.read", VERA::Action::"db.read", VERA::Action::"search"],
  resource
);

@id("file-write-allowed")
permit(principal, action == VERA::Action::"file.write", resource);
`;
