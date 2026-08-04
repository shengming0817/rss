-- #2010 Projection correctness residuals: hard-cut operator audit correlation IDs and
-- add a tenant-scoped worker observation fixed function for lag/freshness/DLQ gauges.
--
-- Do not edit 0085/0097. Drop the 7-arg audit overload entirely; create the sole 9-arg
-- signature. Observation is function-only for rss_projection_worker (no direct table grants).

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DROP FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text
);

CREATE FUNCTION public.rss_projection_operator_record_audit(
    p_occurred_at_secs bigint,
    p_occurred_at_nanos integer,
    p_operator_subject text,
    p_resource_id text,
    p_action text,
    p_outcome text,
    p_failure_reason text,
    p_request_id text,
    p_correlation_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_occurred_at_secs < 0
        OR p_occurred_at_nanos < 0 OR p_occurred_at_nanos >= 1000000000
        OR p_operator_subject IS NULL OR p_operator_subject = ''
        OR p_resource_id IS NULL OR p_resource_id = ''
        OR p_action IS NULL OR p_action !~ '^projection\.[a-z]+\.(start|finish)$'
        OR p_outcome NOT IN ('success', 'failure')
        OR ((p_outcome = 'failure') IS DISTINCT FROM (p_failure_reason IS NOT NULL))
        OR NOT public.rss_is_canonical_non_nil_uuid(p_request_id)
        OR NOT public.rss_is_canonical_non_nil_uuid(p_correlation_id)
    THEN
        RAISE EXCEPTION 'invalid projection operator audit record' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.auth_audit_events (
        occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
        resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id
    ) VALUES (
        p_occurred_at_secs, p_occurred_at_nanos, p_operator_subject, 'service', NULL,
        'projection.maintenance', p_resource_id, p_action, p_outcome, p_failure_reason,
        p_request_id, p_correlation_id
    );
END;
$$;

ALTER FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text, text, text
) OWNER TO rss_projection_operator_owner;

GRANT EXECUTE ON FUNCTION public.rss_is_canonical_non_nil_uuid(text)
    TO rss_projection_operator_owner;

REVOKE ALL ON FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_worker;

GRANT EXECUTE ON FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text, text, text
) TO rss_projection_operator;

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
    projection_dlq_backlog bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_high_water bigint;
    v_checkpoint_offset bigint;
    v_checkpoint_updated_at_epoch_micros bigint;
    v_dlq_backlog bigint;
BEGIN
    -- Scope identity matches 0098 worker source/checkpoint single source
    -- (plan + active pointer + session tenant fail-closed).
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR pg_catalog.current_setting('rss.tenant_id', true) IS DISTINCT FROM p_tenant_id::text THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;

    v_high_water := public.rss_projection_worker_source_high_water(
        p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
        p_definition_schema_digest, p_input_generation
    );

    SELECT checkpoint.offset_lsn,
           (pg_catalog.date_part('epoch', checkpoint.updated_at) * 1000000)::bigint
      INTO v_checkpoint_offset, v_checkpoint_updated_at_epoch_micros
    FROM public.checkpoint AS checkpoint
    WHERE checkpoint.owner = 'projection:' || p_tenant_id::text
      AND checkpoint.checkpoint_id = p_projection_id || '@' || p_target_generation || ':shadow';

    SELECT pg_catalog.count(*)::bigint INTO v_dlq_backlog
    FROM public.dead_letter AS dead_letter
    WHERE dead_letter.tenant_id = p_tenant_id
      AND dead_letter.source_kind = public.rss_projection_dead_letter_source_kind()
      AND dead_letter.consumer_group =
          p_projection_id || '@' || p_target_generation || ':shadow';

    source_high_water := v_high_water;
    checkpoint_offset_lsn := v_checkpoint_offset;
    checkpoint_updated_at_epoch_micros := v_checkpoint_updated_at_epoch_micros;
    projection_dlq_backlog := COALESCE(v_dlq_backlog, 0);
    RETURN NEXT;
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
