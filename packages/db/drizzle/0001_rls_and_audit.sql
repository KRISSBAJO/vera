-- Tenant isolation (SR-14, threat T17).
-- Every tenant-scoped table is filtered by vera.tenant_id, which the application sets LOCAL per
-- transaction from the authenticated credential — never from request data. FORCE applies the policy to
-- the table owner as well, so no role short of BYPASSRLS can see across tenants.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users','agents','signing_keys','policy_sets','action_requests','decisions',
    'reviews','approvals','decision_tokens','outcomes','audit_events'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (org_id = current_setting(''vera.tenant_id'', true)) '
      'WITH CHECK (org_id = current_setting(''vera.tenant_id'', true))', t);
  END LOOP;
END $$;
--> statement-breakpoint
-- Credential tables are looked up by secret hash *before* the tenant is known. The auth-lookup flag is
-- set LOCAL only inside VeraDb.withAuthLookup, which does nothing else. Writes still require the tenant.
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY tenant_isolation ON api_keys
  USING (org_id = current_setting('vera.tenant_id', true) OR current_setting('vera.auth_lookup', true) = '1')
  WITH CHECK (org_id = current_setting('vera.tenant_id', true));
--> statement-breakpoint
ALTER TABLE reviewer_sessions ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE reviewer_sessions FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY tenant_isolation ON reviewer_sessions
  USING (org_id = current_setting('vera.tenant_id', true) OR current_setting('vera.auth_lookup', true) = '1')
  WITH CHECK (org_id = current_setting('vera.tenant_id', true));
--> statement-breakpoint
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY tenant_isolation ON organizations
  USING (id = current_setting('vera.tenant_id', true) OR current_setting('vera.auth_lookup', true) = '1')
  WITH CHECK (id = current_setting('vera.tenant_id', true));
--> statement-breakpoint
-- Audit is append-only (SR-16, threat T20). The chain hash is computed in the application; the database
-- refuses any mutation so an operator with DB access cannot rewrite history without leaving a gap.
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END $$;
--> statement-breakpoint
CREATE TRIGGER audit_events_no_mutation
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
--> statement-breakpoint
CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();
