-- KMS custody for signing keys (ADR-0005, threat T14, accepted risk #8).
--
-- A key is held one of two ways: sealed in our own database (development) or in KMS, where we never
-- see the private half (production). The CHECK makes that a schema invariant rather than a runtime
-- convention: exactly one custody mode, never both and never neither. Without it a row with both
-- columns set would silently pick one at signing time, and a row with neither would fail only when
-- someone tried to sign — the worst moment to discover it.
ALTER TABLE "signing_keys" ADD COLUMN "kms_key_arn" text;
--> statement-breakpoint
ALTER TABLE "signing_keys" ALTER COLUMN "private_jwk_sealed" DROP NOT NULL;
--> statement-breakpoint
ALTER TABLE "signing_keys" ADD CONSTRAINT "signing_keys_one_custody" CHECK (
  ("private_jwk_sealed" IS NOT NULL) <> ("kms_key_arn" IS NOT NULL)
);
