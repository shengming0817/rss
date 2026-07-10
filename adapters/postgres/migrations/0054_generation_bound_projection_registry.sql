-- 0054_generation_bound_projection_registry.sql
--
-- Projection input bindings are deployment-generation scoped and additive. A newly starting
-- deployment can register its complete generated set without deleting bindings still used by an
-- older deployment. Retirement is an explicit, exact-generation maintenance operation.

ALTER TABLE projection_input_bindings
    ADD COLUMN generation text;

UPDATE projection_input_bindings
SET generation = 'legacy:v1';

ALTER TABLE projection_input_bindings
    ALTER COLUMN generation SET NOT NULL,
    DROP CONSTRAINT projection_input_bindings_pkey,
    ADD CONSTRAINT projection_input_bindings_pkey PRIMARY KEY (generation,
        contract_id, contract_version, schema_hash, topic),
    ADD CONSTRAINT chk_projection_input_generation
        CHECK (generation = 'legacy:v1' OR generation ~ '^sha256:[0-9a-f]{64}$');

GRANT INSERT, DELETE ON projection_input_bindings TO rss_projection_events_runtime;

CREATE OR REPLACE FUNCTION rss_guard_projection_input_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('rss.projection_registry_retire_generation', true)
        IS DISTINCT FROM OLD.generation
    THEN
        RAISE EXCEPTION 'projection input bindings may only be retired by exact generation'
            USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_projection_input_generation_delete
BEFORE DELETE ON projection_input_bindings
FOR EACH ROW EXECUTE FUNCTION rss_guard_projection_input_delete();

CREATE OR REPLACE FUNCTION rss_register_projection_input_binding(
    p_generation text,
    p_contract_id text,
    p_contract_version text,
    p_schema_hash text,
    p_topic text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_generation IS NULL OR p_generation !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid projection input generation' USING ERRCODE = '22023';
    END IF;

    INSERT INTO projection_input_bindings (
        generation, contract_id, contract_version, schema_hash, topic
    ) VALUES (
        p_generation, p_contract_id, p_contract_version, p_schema_hash, p_topic
    )
    ON CONFLICT (generation, contract_id, contract_version, schema_hash, topic) DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION rss_retire_projection_input_generation(p_generation text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    deleted_count bigint;
BEGIN
    IF p_generation IS NULL OR btrim(p_generation) = '' THEN
        RAISE EXCEPTION 'projection input generation is required' USING ERRCODE = '22023';
    END IF;

    PERFORM set_config('rss.projection_registry_retire_generation', p_generation, true);
    DELETE FROM projection_input_bindings
    WHERE generation = p_generation;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    PERFORM set_config('rss.projection_registry_retire_generation', '', true);
    RETURN deleted_count;
END;
$$;

ALTER FUNCTION rss_register_projection_input_binding(text, text, text, text, text)
    OWNER TO rss_projection_events_runtime;
ALTER FUNCTION rss_retire_projection_input_generation(text)
    OWNER TO rss_projection_events_runtime;
ALTER FUNCTION rss_guard_projection_input_delete() OWNER TO rss_projection_events_runtime;

REVOKE ALL ON FUNCTION rss_register_projection_input_binding(text, text, text, text, text)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_retire_projection_input_generation(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_guard_projection_input_delete() FROM PUBLIC;

-- Startup uses the migrator connection. The serving role cannot register or retire bindings.
REVOKE EXECUTE ON FUNCTION rss_register_projection_input_binding(text, text, text, text, text)
    FROM rss_app;
REVOKE EXECUTE ON FUNCTION rss_retire_projection_input_generation(text) FROM rss_app;
DO $$
DECLARE
    migration_role name := current_user;
BEGIN
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION rss_register_projection_input_binding(text, text, text, text, text) TO %I',
        migration_role
    );
END
$$;

REVOKE SELECT, INSERT, UPDATE, DELETE ON projection_input_bindings FROM PUBLIC;
REVOKE SELECT, INSERT, UPDATE, DELETE ON projection_input_bindings FROM rss_app;
REVOKE UPDATE ON projection_input_bindings FROM rss_projection_events_runtime;
