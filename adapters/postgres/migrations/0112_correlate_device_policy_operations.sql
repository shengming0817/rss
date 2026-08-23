-- 0112_correlate_device_policy_operations.sql
--
-- Hard-cut Draft device-policy acceptance to transport-verified request/correlation evidence.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.device_certificate_desired_states,
    public.device_certificate_policy_operations,
    public.device_certificate_policy_authorization_policies,
    public.device_certificate_desired_generation_lineage,
    public.device_certificate_conditions,
    public.reconcile_targets,
    public.reconcile_leases
IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE migration_head bigint;
BEGIN
    SELECT max(version) INTO migration_head FROM public._sqlx_migrations;
    IF migration_head IS DISTINCT FROM 111 THEN
        RAISE EXCEPTION USING ERRCODE='55000',
            MESSAGE='0112 requires migration ledger head 0111';
    END IF;
    IF EXISTS (SELECT 1 FROM public.device_certificate_policy_operations) THEN
        RAISE EXCEPTION USING ERRCODE='55000',
            MESSAGE='0112 requires empty Draft device-policy operation state';
    END IF;
END;
$$;

ALTER TABLE public.device_certificate_policy_operations
    ADD COLUMN request_id text NOT NULL,
    ADD COLUMN correlation_id text NOT NULL,
    ADD CONSTRAINT device_certificate_policy_operations_request_id_bounded
        CHECK (request_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    ADD CONSTRAINT device_certificate_policy_operations_correlation_id_bounded
        CHECK (correlation_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    ADD CONSTRAINT device_certificate_policy_operations_user_only
        CHECK (principal_kind = 'user');

DROP FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[],
    text,text,text,text,bytea,bigint,text[],bigint[]);

CREATE FUNCTION public.rss_accept_device_certificate_desired(
    p_tenant_id uuid, p_device_id uuid, p_idempotency_key uuid, p_request_digest bytea,
    p_expected_generation bigint, p_next_generation bigint, p_validity_seconds integer,
    p_renew_before_seconds integer, p_client_auth boolean, p_server_auth boolean, p_sans text[],
    p_principal_kind text, p_principal_id text, p_contract_id text, p_permission text,
    p_obligation_fingerprint bytea, p_evaluated_at_micros bigint,
    p_policy_ids text[], p_policy_versions bigint[], p_request_id text, p_correlation_id text
)
RETURNS TABLE (
    outcome text, actual_generation bigint, authorization_receipt_id text,
    target_id text, wake_version bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    operation_digest bytea;
    operation_generation bigint;
    operation_receipt_id uuid;
    new_receipt_id uuid;
    authority_target_id uuid;
    authority_disabled_reason text;
    authority_has_lease boolean := false;
    desired_generation bigint := 0;
    next_wake bigint;
    policy_index integer;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='tenant authority mismatch'; END IF;
    IF p_next_generation <> p_expected_generation + 1
       OR pg_catalog.cardinality(p_policy_ids) IS DISTINCT FROM pg_catalog.cardinality(p_policy_versions)
       OR pg_catalog.cardinality(p_policy_ids) < 1
       OR p_principal_kind <> 'user'
       OR p_request_id !~ '^[A-Za-z0-9._-]{1,128}$'
       OR p_correlation_id !~ '^[A-Za-z0-9._-]{1,128}$'
    THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid device-policy receipt projection'; END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        p_tenant_id::text || ':' || p_device_id::text || ':' || p_idempotency_key::text, 0));
    SELECT operation.request_digest, operation.accepted_generation,
           operation.authorization_receipt_id
      INTO operation_digest, operation_generation, operation_receipt_id
    FROM public.device_certificate_policy_operations operation
    WHERE operation.tenant_id=p_tenant_id AND operation.device_id=p_device_id
      AND operation.idempotency_key=p_idempotency_key;
    IF FOUND THEN
        IF operation_digest=p_request_digest THEN
            RETURN QUERY SELECT 'replayed',operation_generation,operation_receipt_id::text,
                NULL::text,NULL::bigint;
        ELSE
            RETURN QUERY SELECT 'idempotency_conflict',operation_generation,operation_receipt_id::text,
                NULL::text,NULL::bigint;
        END IF;
        RETURN;
    END IF;

    SELECT target.target_id,target.disabled_reason
      INTO authority_target_id,authority_disabled_reason
    FROM public.reconcile_targets target
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
    FOR UPDATE;
    IF FOUND THEN
        SELECT true INTO authority_has_lease FROM public.reconcile_leases lease
        WHERE lease.tenant_id=p_tenant_id AND lease.target_id=authority_target_id FOR UPDATE;
        authority_has_lease:=COALESCE(authority_has_lease,false);
    END IF;
    SELECT desired.generation INTO desired_generation
    FROM public.device_certificate_desired_states desired
    WHERE desired.tenant_id=p_tenant_id AND desired.device_id=p_device_id FOR UPDATE;
    desired_generation:=COALESCE(desired_generation,0);
    IF desired_generation<>p_expected_generation THEN
        RETURN QUERY SELECT 'generation_conflict',desired_generation,NULL::text,NULL::text,NULL::bigint;
        RETURN;
    END IF;
    IF authority_target_id IS NULL OR NOT authority_has_lease THEN
        RETURN QUERY SELECT 'missing_enrollment',desired_generation,NULL::text,NULL::text,NULL::bigint;
        RETURN;
    END IF;
    IF authority_disabled_reason IS NOT NULL THEN
        RETURN QUERY SELECT 'quarantined',desired_generation,NULL::text,NULL::text,NULL::bigint;
        RETURN;
    END IF;

    new_receipt_id := pg_catalog.gen_random_uuid();
    INSERT INTO public.device_certificate_policy_operations
      (tenant_id,device_id,idempotency_key,request_digest,accepted_generation,
       accepted_condition,authorization_receipt_id,principal_kind,principal_id,
       contract_id,permission,obligation_fingerprint,evaluated_at,request_id,correlation_id)
    VALUES (p_tenant_id,p_device_id,p_idempotency_key,p_request_digest,p_next_generation,
      'reconciling',new_receipt_id,p_principal_kind,p_principal_id,p_contract_id,p_permission,
      p_obligation_fingerprint,
      TIMESTAMPTZ 'epoch' + p_evaluated_at_micros * INTERVAL '1 microsecond',
      p_request_id,p_correlation_id);
    FOR policy_index IN 1..pg_catalog.cardinality(p_policy_ids) LOOP
        INSERT INTO public.device_certificate_policy_authorization_policies
          (tenant_id,device_id,authorization_receipt_id,policy_ordinal,policy_id,policy_version)
        VALUES (p_tenant_id,p_device_id,new_receipt_id,policy_index,
          p_policy_ids[policy_index],p_policy_versions[policy_index]);
    END LOOP;
    INSERT INTO public.device_certificate_desired_generation_lineage
      (tenant_id,device_id,generation,authorization_receipt_id)
    VALUES (p_tenant_id,p_device_id,p_next_generation,new_receipt_id);

    IF p_expected_generation=0 THEN
        INSERT INTO public.device_certificate_desired_states
          (tenant_id,device_id,generation,authorization_receipt_id,validity_seconds,
           renew_before_seconds,client_auth,server_auth,sans)
        VALUES (p_tenant_id,p_device_id,p_next_generation,new_receipt_id,p_validity_seconds,
          p_renew_before_seconds,p_client_auth,p_server_auth,p_sans);
    ELSE
        UPDATE public.device_certificate_desired_states desired SET
          generation=p_next_generation,authorization_receipt_id=new_receipt_id,
          validity_seconds=p_validity_seconds,renew_before_seconds=p_renew_before_seconds,
          client_auth=p_client_auth,server_auth=p_server_auth,sans=p_sans,
          deletion_requested_at=NULL,finalizer_present=true
        WHERE desired.tenant_id=p_tenant_id AND desired.device_id=p_device_id
          AND desired.generation=p_expected_generation;
    END IF;
    UPDATE public.reconcile_targets target SET status='active',disabled_reason=NULL,
      next_run_at=pg_catalog.clock_timestamp(),wake_version=target.wake_version+1,
      updated_at=pg_catalog.clock_timestamp()
    WHERE target.tenant_id=p_tenant_id AND target.target_id=authority_target_id
    RETURNING target.wake_version INTO next_wake;
    INSERT INTO public.device_certificate_conditions
      (tenant_id,device_id,condition_type,status,reason,observed_generation)
    VALUES
      (p_tenant_id,p_device_id,'Ready','False','AwaitingDevice',p_next_generation),
      (p_tenant_id,p_device_id,'Reconciling','True','DesiredAccepted',p_next_generation),
      (p_tenant_id,p_device_id,'PendingDevice','False','AwaitingDevice',p_next_generation),
      (p_tenant_id,p_device_id,'Degraded','False','ArtifactUnavailable',p_next_generation),
      (p_tenant_id,p_device_id,'Quarantined','False','ProtocolViolation',p_next_generation),
      (p_tenant_id,p_device_id,'Deleting','False','DeletionPending',p_next_generation)
    ON CONFLICT (tenant_id,device_id,condition_type) DO UPDATE SET
      status=EXCLUDED.status,reason=EXCLUDED.reason,
      observed_generation=EXCLUDED.observed_generation;
    RETURN QUERY SELECT 'accepted',p_next_generation,new_receipt_id::text,
        authority_target_id::text,next_wake;
END;
$$;

ALTER FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[],
    text,text,text,text,bytea,bigint,text[],bigint[],text,text)
OWNER TO rss_device_certificate_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[],
    text,text,text,text,bytea,bigint,text[],bigint[],text,text)
FROM PUBLIC, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[],
    text,text,text,text,bytea,bigint,text[],bigint[],text,text)
TO rss_app;

DO $$
BEGIN
    IF (SELECT count(*) FROM pg_catalog.pg_proc
        WHERE pronamespace='public'::regnamespace
          AND proname='rss_accept_device_certificate_desired') <> 1
    THEN RAISE EXCEPTION USING ERRCODE='55000',
        MESSAGE='0112 requires exactly one desired-policy accept function'; END IF;
END;
$$;
