-- Harden dead_letter with typed tenant envelope + RLS.
--
-- Historical rows are allowed to remain while new writes are forced through a
-- tenant-scoped application path: NOT VALID skips historical validation but
-- still enforces the CHECK for new/updated rows. Historical tenant_id NULL rows
-- are intentionally invisible to tenant-scoped rss_app sessions under FORCE RLS;
-- break-glass owner/superuser audit is the only supported legacy inspection path.

ALTER TABLE dead_letter
    ADD COLUMN tenant_id uuid,
    ADD COLUMN message_id text NOT NULL DEFAULT '';

ALTER TABLE dead_letter
    ADD CONSTRAINT chk_dead_letter_tenant_required CHECK (tenant_id IS NOT NULL) NOT VALID;

CREATE INDEX idx_dead_letter_tenant_last_attempt
    ON dead_letter (tenant_id, last_attempt_at DESC);

CREATE INDEX idx_dead_letter_tenant_message
    ON dead_letter (tenant_id, message_id);

ALTER TABLE dead_letter ENABLE ROW LEVEL SECURITY;
ALTER TABLE dead_letter FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON dead_letter
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT ON dead_letter TO rss_app;
