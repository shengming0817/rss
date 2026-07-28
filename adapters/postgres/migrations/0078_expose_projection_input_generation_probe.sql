-- Serving binaries must prove that their generated projection input generation is registered
-- exactly, without receiving direct access to the additive registry table.
CREATE FUNCTION rss_read_projection_input_generation(p_generation text)
RETURNS TABLE (
    contract_id text,
    contract_version text,
    schema_hash text,
    topic text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT binding.contract_id,
           binding.contract_version,
           binding.schema_hash,
           binding.topic
    FROM public.projection_input_bindings AS binding
    WHERE binding.generation = p_generation
    ORDER BY binding.contract_id,
             binding.contract_version,
             binding.schema_hash,
             binding.topic
$$;

ALTER FUNCTION rss_read_projection_input_generation(text)
    OWNER TO rss_projection_events_runtime;
REVOKE ALL ON FUNCTION rss_read_projection_input_generation(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_read_projection_input_generation(text) TO rss_app;
