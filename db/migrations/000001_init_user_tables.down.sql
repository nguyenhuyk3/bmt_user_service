-- Drop foreign keys for user_infos and user_actions
ALTER TABLE "user_infos" DROP CONSTRAINT IF EXISTS "user_infos_account_email_fkey";
ALTER TABLE "user_actions" DROP CONSTRAINT IF EXISTS "user_actions_account_email_fkey";

-- Drop indexes
DROP INDEX IF EXISTS "accounts_email_idx";
DROP INDEX IF EXISTS "user_infos_account_email_idx";
DROP INDEX IF EXISTS "user_actions_account_email_idx";

-- Drop tables
DROP TABLE IF EXISTS "user_actions";
DROP TABLE IF EXISTS "user_infos";
DROP TABLE IF EXISTS "accounts";

-- Drop types
DROP TYPE IF EXISTS "roles";
DROP TYPE IF EXISTS "sex";
