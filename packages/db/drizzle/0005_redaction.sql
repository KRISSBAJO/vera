ALTER TABLE "action_requests" ADD COLUMN "action_raw_sealed" text;--> statement-breakpoint
ALTER TABLE "action_requests" ADD COLUMN "redaction_findings" jsonb DEFAULT '[]'::jsonb NOT NULL;