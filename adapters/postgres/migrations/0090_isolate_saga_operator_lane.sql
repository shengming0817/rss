-- 0090_isolate_saga_operator_lane.sql
--
-- The Saga CLI uses a function-only credential. It must never open a migrator/owner pool or gain
-- raw relation authority merely to consume service-token replay protection and append its audit.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_saga_operator_owner') THEN
        CREATE ROLE rss_saga_operator_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_saga_operator') THEN
        CREATE ROLE rss_saga_operator
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
END
$$;

ALTER ROLE rss_saga_operator_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_saga_operator SET search_path = pg_catalog, public;

DO $$
DECLARE
    checked_role oid;
BEGIN
    FOREACH checked_role IN ARRAY ARRAY[
        'rss_saga_operator_owner'::regrole::oid,
        'rss_saga_operator'::regrole::oid
    ] LOOP
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = checked_role OR membership.roleid = checked_role
        ) THEN
            RAISE EXCEPTION 'Saga operator roles must have no memberships';
        END IF;
    END LOOP;
END
$$;

CREATE FUNCTION public.rss_saga_operator_record_audit(
    p_occurred_at_secs bigint,
    p_occurred_at_nanos integer,
    p_operator_subject text,
    p_target_tenant uuid,
    p_resource_id text,
    p_action text,
    p_outcome text,
    p_failure_reason text,
    p_start_audit_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_occurred_at_secs < 0
        OR p_occurred_at_nanos < 0 OR p_occurred_at_nanos >= 1000000000
        OR p_operator_subject IS NULL
        OR pg_catalog.octet_length(p_operator_subject) NOT BETWEEN 1 AND 128
        OR p_target_tenant IS NULL
        OR p_target_tenant = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_resource_id IS NULL OR p_resource_id = ''
        OR p_action NOT IN (
            'saga.operator.status.start', 'saga.operator.status.finish',
            'saga.operator.retry-compensation.start',
            'saga.operator.retry-compensation.finish',
            'saga.operator.repair.start', 'saga.operator.repair.finish',
            'saga.operator.terminate.start', 'saga.operator.terminate.finish'
        )
        OR p_outcome NOT IN ('success', 'failure')
        OR ((p_outcome = 'failure') IS DISTINCT FROM (p_failure_reason IS NOT NULL))
        OR p_start_audit_id IS NULL
        OR pg_catalog.octet_length(p_start_audit_id) NOT BETWEEN 1 AND 128
    THEN
        RAISE EXCEPTION 'invalid Saga operator audit record' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.auth_audit_events (
        occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
        resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id
    ) VALUES (
        p_occurred_at_secs, p_occurred_at_nanos, p_operator_subject, 'service', p_target_tenant,
        'saga.operator', p_resource_id, p_action, p_outcome, p_failure_reason,
        p_start_audit_id, NULL
    );
END;
$$;

ALTER FUNCTION public.rss_saga_operator_record_audit(
    bigint, integer, text, uuid, text, text, text, text, text
) OWNER TO rss_saga_operator_owner;
REVOKE ALL ON FUNCTION public.rss_saga_operator_record_audit(
    bigint, integer, text, uuid, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM rss_saga_operator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM rss_saga_operator;
GRANT SELECT ON TABLE public._sqlx_migrations TO rss_saga_operator;
GRANT INSERT ON TABLE public.auth_audit_events TO rss_saga_operator_owner;
GRANT USAGE, SELECT ON SEQUENCE public.auth_audit_events_id_seq TO rss_saga_operator_owner;
GRANT USAGE ON SCHEMA public TO rss_saga_operator_owner;
GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_check_and_record(bytea, timestamptz)
    TO rss_saga_operator;
GRANT EXECUTE ON FUNCTION public.rss_saga_operator_record_audit(
    bigint, integer, text, uuid, text, text, text, text, text
) TO rss_saga_operator;
REVOKE EXECUTE ON FUNCTION public.rss_saga_retry_compensation(
    uuid, text, text, bigint, text, integer, bytea, text, text, text, text
) FROM rss_app, rss_app_read;
REVOKE EXECUTE ON FUNCTION public.rss_saga_terminate(
    uuid, text, text, text, text, text, text
) FROM rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_saga_retry_compensation(
    uuid, text, text, bigint, text, integer, bytea, text, text, text, text
) TO rss_saga_operator;
GRANT EXECUTE ON FUNCTION public.rss_saga_terminate(
    uuid, text, text, text, text, text, text
) TO rss_saga_operator;
GRANT USAGE ON SCHEMA public TO rss_saga_operator;
