-- Tenant isolation for the baseline tables (SR-14). Same policy as 0001; new tables need it explicitly,
-- and a missing policy here would leak one organisation's behavioural history to another.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['baseline_observations','baseline_snapshots','baseline_stats'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (org_id = current_setting(''vera.tenant_id'', true)) '
      'WITH CHECK (org_id = current_setting(''vera.tenant_id'', true))', t);
  END LOOP;
END $$;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON baseline_observations, baseline_snapshots, baseline_stats TO vera_app;
--> statement-breakpoint
GRANT USAGE, SELECT ON SEQUENCE baseline_stats_id_seq TO vera_app;
