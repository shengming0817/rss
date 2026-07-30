-- 0080_pin_saga_definition_identity.sql
--
-- A saga instance must pin the exact generated definition that created it.  Legacy rows only
-- contain owner + contract_id, so their version/schema/action identity cannot be proven.  Refuse
-- the migration instead of binding those rows to whichever definition happens to be current.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM saga_instances LIMIT 1) THEN
        RAISE EXCEPTION
            'cannot pin exact saga definition identity for existing saga_instances rows';
    END IF;
END
$$;

ALTER TABLE saga_instances
    ADD COLUMN definition_version text NOT NULL,
    ADD COLUMN definition_schema_digest text NOT NULL,
    ADD COLUMN action_registry_generation text NOT NULL,
    ADD CONSTRAINT saga_instances_definition_version_valid
        CHECK (definition_version ~ '^v[1-9][0-9]*$'),
    ADD CONSTRAINT saga_instances_definition_schema_digest_valid
        CHECK (definition_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD CONSTRAINT saga_instances_action_registry_generation_valid
        CHECK (action_registry_generation ~ '^sha256:[0-9a-f]{64}$');

-- Exact definition identity and ownership are immutable after registration.  Replace the broad
-- pre-0080 table UPDATE grant with the exact lease/status columns used by the adapter.
REVOKE UPDATE ON saga_instances FROM rss_app;
GRANT UPDATE (
    status,
    lease_token,
    holder_id,
    epoch,
    acquired_at,
    expires_at,
    heartbeat_at,
    updated_at
) ON saga_instances TO rss_app;
