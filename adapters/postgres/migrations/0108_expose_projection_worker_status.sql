-- #1993 Extend the worker-owned tenant observation with the durable quarantine reason.
-- The function remains the sole read capability; no table grant is added.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DROP FUNCTION public.rss_projection_worker_observe_tenant(
    uuid, text, text, text, text, text
);

CREATE FUNCTION public.rss_projection_worker_observe_tenant(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS TABLE (
    source_high_water bigint,
    checkpoint_offset_lsn bigint,
    checkpoint_updated_at_epoch_micros bigint,
    projection_dlq_backlog bigint,
    quarantine_reason text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR pg_catalog.current_setting('rss.tenant_id', true) IS DISTINCT FROM p_tenant_id::text THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT public.rss_projection_worker_source_high_water(
               p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
               p_definition_schema_digest, p_input_generation),
           checkpoint.offset_lsn,
           (pg_catalog.date_part('epoch', checkpoint.updated_at) * 1000000)::bigint,
           COALESCE((
               SELECT pg_catalog.count(*)::bigint
               FROM public.dead_letter AS dead_letter
               WHERE dead_letter.tenant_id = p_tenant_id
                 AND dead_letter.source_kind = public.rss_projection_dead_letter_source_kind()
                 AND dead_letter.consumer_group =
                     p_projection_id || '@' || p_target_generation || ':shadow'
           ), 0),
           quarantine.reason
    FROM (SELECT 1) AS singleton
    LEFT JOIN public.checkpoint AS checkpoint
      ON checkpoint.owner = 'projection:' || p_tenant_id::text
     AND checkpoint.checkpoint_id = p_projection_id || '@' || p_target_generation || ':shadow'
    LEFT JOIN public.projection_worker_tenant_quarantine AS quarantine
      ON quarantine.tenant_scope_id = p_tenant_id
     AND quarantine.projection_id = p_projection_id
     AND quarantine.target_generation = p_target_generation
     AND quarantine.state = 'quarantined';
END;
$function$;

ALTER FUNCTION public.rss_projection_worker_observe_tenant(
    uuid, text, text, text, text, text
) OWNER TO rss_projection_worker_owner;

REVOKE ALL ON FUNCTION public.rss_projection_worker_observe_tenant(
    uuid, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;

GRANT EXECUTE ON FUNCTION public.rss_projection_worker_observe_tenant(
    uuid, text, text, text, text, text
) TO rss_projection_worker;
