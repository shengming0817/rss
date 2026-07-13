-- 0058_harden_secret_refs_append_only.sql
--
-- `secret_refs` is a versioned append-only coordinate log. The serving role may read and append
-- versions, but mutation and physical deletion are not part of the repository contract.
-- PostgreSQL owns both invariants so a future adapter path cannot bypass them. Historical rows are
-- preflighted before the brief ACCESS EXCLUSIVE lock needed to install a NOT VALID constraint;
-- 0059 validates it in a separate migration/transaction without holding that install lock. Because
-- SQLx stops at the first failed pending migration, invalid history must be inventoried and repaired
-- out of band, under review, before deploying the binary that contains this migration.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM secret_refs WHERE version <= 0) THEN
        RAISE EXCEPTION 'secret_refs contains non-positive historical versions'
            USING HINT = 'stop deployment; complete a reviewed out-of-band preflight/repair before deploying the binary that contains 0058, then retry; no later migration can run first';
    END IF;
END
$$;

ALTER TABLE secret_refs
    ADD CONSTRAINT secret_refs_version_positive CHECK (version > 0) NOT VALID;

REVOKE UPDATE, DELETE ON secret_refs FROM rss_app;
