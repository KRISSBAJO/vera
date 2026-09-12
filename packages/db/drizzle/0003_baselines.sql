CREATE TABLE "baseline_observations" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"decision_id" text NOT NULL,
	"actor_id" text NOT NULL,
	"action_class" text NOT NULL,
	"target_id" text NOT NULL,
	"occurred_at" timestamp with time zone NOT NULL,
	"local_hour" integer NOT NULL,
	"local_dow" integer NOT NULL,
	"magnitude" double precision,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "baseline_snapshots" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"computed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"observation_count" integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "baseline_stats" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"snapshot_id" text NOT NULL,
	"scope" text NOT NULL,
	"key" text NOT NULL,
	"count" integer NOT NULL,
	"first_seen" timestamp with time zone NOT NULL,
	"last_seen" timestamp with time zone NOT NULL,
	"hour_histogram" jsonb NOT NULL,
	"distinct_targets" integer DEFAULT 0 NOT NULL,
	"magnitude_n" integer DEFAULT 0 NOT NULL,
	"magnitude_p50" double precision,
	"magnitude_p95" double precision,
	"magnitude_max" double precision
);
--> statement-breakpoint
ALTER TABLE "baseline_observations" ADD CONSTRAINT "baseline_observations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "baseline_observations" ADD CONSTRAINT "baseline_observations_decision_id_decisions_id_fk" FOREIGN KEY ("decision_id") REFERENCES "public"."decisions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "baseline_snapshots" ADD CONSTRAINT "baseline_snapshots_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "baseline_stats" ADD CONSTRAINT "baseline_stats_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "baseline_stats" ADD CONSTRAINT "baseline_stats_snapshot_id_baseline_snapshots_id_fk" FOREIGN KEY ("snapshot_id") REFERENCES "public"."baseline_snapshots"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "baseline_observations_decision" ON "baseline_observations" USING btree ("decision_id");--> statement-breakpoint
CREATE INDEX "baseline_observations_lookup" ON "baseline_observations" USING btree ("org_id","action_class","actor_id","occurred_at");--> statement-breakpoint
CREATE INDEX "baseline_observations_recent" ON "baseline_observations" USING btree ("org_id","actor_id","occurred_at");--> statement-breakpoint
CREATE INDEX "baseline_snapshots_org_computed" ON "baseline_snapshots" USING btree ("org_id","computed_at");--> statement-breakpoint
CREATE UNIQUE INDEX "baseline_stats_lookup" ON "baseline_stats" USING btree ("snapshot_id","scope","key");