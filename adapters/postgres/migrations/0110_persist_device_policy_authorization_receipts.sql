-- 0110_persist_device_policy_authorization_receipts.sql
--
-- Hard-cut the device-policy idempotency ledger into the durable authorization-receipt
-- authority and bind every desired generation, including automatic rotations, to that receipt.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.device_certificate_desired_states,
    public.device_certificate_policy_operations,
    public.device_certificate_conditions,
    public.reconcile_targets,
    public.reconcile_leases,
    public.reconcile_attempts
IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    migration_head bigint;
BEGIN
    SELECT max(version) INTO migration_head FROM public._sqlx_migrations;
    IF migration_head IS DISTINCT FROM 109 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = '0110 requires migration ledger head 0109';
    END IF;
    IF EXISTS (SELECT 1 FROM public.device_certificate_desired_states)
       OR EXISTS (SELECT 1 FROM public.device_certificate_policy_operations)
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = '0110 requires empty legacy device-certificate desired and operation state';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM public.reconcile_leases AS lease
        JOIN public.reconcile_targets AS target
          ON target.tenant_id = lease.tenant_id AND target.target_id = lease.target_id
        WHERE lease.state = 'held'
          AND target.reconciler_id = 'identity.device-certificate'
          AND target.resource_kind = 'device-certificate'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = '0110 requires every device-certificate reconcile lease to be free';
    END IF;
END;
$$;

ALTER TABLE public.device_certificate_policy_operations
    DROP CONSTRAINT device_certificate_policy_operations_desired_fk,
    ADD COLUMN authorization_receipt_id uuid NOT NULL,
    ADD COLUMN principal_kind text NOT NULL,
    ADD COLUMN principal_id text NOT NULL,
    ADD COLUMN contract_id text NOT NULL,
    ADD COLUMN permission text NOT NULL,
    ADD COLUMN obligation_fingerprint bytea NOT NULL,
    ADD COLUMN evaluated_at timestamptz NOT NULL,
    ADD CONSTRAINT device_certificate_policy_operations_receipt_non_nil
        CHECK (authorization_receipt_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    ADD CONSTRAINT device_certificate_policy_operations_principal_kind_closed
        CHECK (principal_kind IN ('user','device','admin','super_admin','service')),
    ADD CONSTRAINT device_certificate_policy_operations_principal_id_bounded
        CHECK (pg_catalog.octet_length(principal_id) BETWEEN 1 AND 256
            AND principal_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT device_certificate_policy_operations_contract_exact
        CHECK (contract_id = 'identity.device-certificate-policy-put'),
    ADD CONSTRAINT device_certificate_policy_operations_permission_exact
        CHECK (permission = 'identity:device-certificate-policy:write'),
    ADD CONSTRAINT device_certificate_policy_operations_obligation_sha256
        CHECK (pg_catalog.octet_length(obligation_fingerprint) = 32),
    ADD CONSTRAINT device_certificate_policy_operations_receipt_unique
        UNIQUE (tenant_id, device_id, authorization_receipt_id),
    ADD CONSTRAINT device_certificate_policy_operations_generation_unique
        UNIQUE (tenant_id, device_id, accepted_generation);

CREATE TABLE public.device_certificate_policy_authorization_policies (
    tenant_id                uuid    NOT NULL,
    device_id                uuid    NOT NULL,
    authorization_receipt_id uuid    NOT NULL,
    policy_ordinal           integer NOT NULL,
    policy_id                text    NOT NULL,
    policy_version           bigint  NOT NULL,
    PRIMARY KEY (tenant_id, device_id, authorization_receipt_id, policy_ordinal),
    CONSTRAINT device_certificate_policy_authorization_policies_receipt_fk
        FOREIGN KEY (tenant_id, device_id, authorization_receipt_id)
        REFERENCES public.device_certificate_policy_operations
            (tenant_id, device_id, authorization_receipt_id),
    CONSTRAINT device_certificate_policy_authorization_policies_identity_unique
        UNIQUE (tenant_id, device_id, authorization_receipt_id, policy_id),
    CONSTRAINT device_certificate_policy_authorization_policies_ordinal_positive
        CHECK (policy_ordinal > 0),
    CONSTRAINT device_certificate_policy_authorization_policies_id_bounded
        CHECK (pg_catalog.octet_length(policy_id) BETWEEN 1 AND 256
            AND policy_id !~ '[[:cntrl:]]'),
    CONSTRAINT device_certificate_policy_authorization_policies_version_positive
        CHECK (policy_version BETWEEN 1 AND 4294967295)
);

CREATE TABLE public.device_certificate_desired_generation_lineage (
    tenant_id                uuid   NOT NULL,
    device_id                uuid   NOT NULL,
    generation               bigint NOT NULL,
    authorization_receipt_id uuid   NOT NULL,
    PRIMARY KEY (tenant_id, device_id, generation),
    CONSTRAINT device_certificate_desired_generation_lineage_identity_unique
        UNIQUE (tenant_id, device_id, generation, authorization_receipt_id),
    CONSTRAINT device_certificate_desired_generation_lineage_receipt_fk
        FOREIGN KEY (tenant_id, device_id, authorization_receipt_id)
        REFERENCES public.device_certificate_policy_operations
            (tenant_id, device_id, authorization_receipt_id),
    CONSTRAINT device_certificate_desired_generation_lineage_generation_positive
        CHECK (generation > 0)
);

ALTER TABLE public.device_certificate_desired_states
    ADD COLUMN authorization_receipt_id uuid NOT NULL,
    ADD CONSTRAINT device_certificate_desired_states_lineage_fk
        FOREIGN KEY (tenant_id, device_id, generation, authorization_receipt_id)
        REFERENCES public.device_certificate_desired_generation_lineage
            (tenant_id, device_id, generation, authorization_receipt_id);

ALTER TABLE public.device_certificate_policy_authorization_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_certificate_policy_authorization_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_certificate_policy_authorization_policies
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE public.device_certificate_desired_generation_lineage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_certificate_desired_generation_lineage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_certificate_desired_generation_lineage
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE public.device_certificate_policy_operations,
    public.device_certificate_policy_authorization_policies,
    public.device_certificate_desired_generation_lineage
FROM PUBLIC, rss_app, rss_app_read;

GRANT SELECT ON TABLE public.device_certificate_desired_generation_lineage
TO rss_app, rss_app_read;

GRANT SELECT, INSERT ON TABLE public.device_certificate_policy_operations,
    public.device_certificate_policy_authorization_policies,
    public.device_certificate_desired_generation_lineage
TO rss_device_certificate_funnel_owner;
GRANT UPDATE (authorization_receipt_id) ON public.device_certificate_desired_states
TO rss_device_certificate_funnel_owner;

CREATE FUNCTION public.rss_validate_device_policy_authorization_policies()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    policy_count bigint;
    first_ordinal integer;
    last_ordinal integer;
    ordered boolean;
BEGIN
    SELECT count(*), min(policy_ordinal), max(policy_ordinal),
        COALESCE(bool_and(previous_id IS NULL OR previous_id COLLATE "C" < policy_id COLLATE "C"), false)
      INTO policy_count, first_ordinal, last_ordinal, ordered
    FROM (
        SELECT policy_ordinal, policy_id,
            lag(policy_id) OVER (ORDER BY policy_ordinal) AS previous_id
        FROM public.device_certificate_policy_authorization_policies
        WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id
          AND authorization_receipt_id = NEW.authorization_receipt_id
    ) AS policies;
    IF policy_count < 1 OR first_ordinal <> 1
       OR last_ordinal <> policy_count OR NOT ordered
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'device-policy authorization policies must be nonempty, dense, sorted, and unique';
    END IF;
    RETURN NULL;
END;
$$;

ALTER FUNCTION public.rss_validate_device_policy_authorization_policies()
OWNER TO rss_device_certificate_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_validate_device_policy_authorization_policies()
FROM PUBLIC, rss_app, rss_app_read;

CREATE CONSTRAINT TRIGGER device_policy_authorization_policies_complete
AFTER INSERT ON public.device_certificate_policy_operations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.rss_validate_device_policy_authorization_policies();

DROP FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[]);

CREATE FUNCTION public.rss_accept_device_certificate_desired(
    p_tenant_id uuid, p_device_id uuid, p_idempotency_key uuid, p_request_digest bytea,
    p_expected_generation bigint, p_next_generation bigint, p_validity_seconds integer,
    p_renew_before_seconds integer, p_client_auth boolean, p_server_auth boolean, p_sans text[],
    p_principal_kind text, p_principal_id text, p_contract_id text, p_permission text,
    p_obligation_fingerprint bytea, p_evaluated_at_micros bigint,
    p_policy_ids text[], p_policy_versions bigint[]
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
       OR p_principal_kind = 'anonymous'
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
       contract_id,permission,obligation_fingerprint,evaluated_at)
    VALUES (p_tenant_id,p_device_id,p_idempotency_key,p_request_digest,p_next_generation,
      'reconciling',new_receipt_id,p_principal_kind,p_principal_id,p_contract_id,p_permission,
      p_obligation_fingerprint,
      TIMESTAMPTZ 'epoch' + p_evaluated_at_micros * INTERVAL '1 microsecond');
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

CREATE OR REPLACE FUNCTION public.rss_rotate_device_certificate_generation(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint
)
RETURNS TABLE (next_generation bigint, target_id text, wake_version bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_target_id uuid;
    current_receipt_id uuid;
    next_value bigint;
    next_wake bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('rss.tenant_id',true),'')::uuid
    THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='tenant authority mismatch'; END IF;
    SELECT target.target_id,desired.authorization_receipt_id
      INTO authority_target_id,current_receipt_id FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id,target_id)
    JOIN public.reconcile_leases lease USING (tenant_id,target_id)
    JOIN public.device_certificate_desired_states desired ON desired.tenant_id=target.tenant_id
      AND desired.device_id::text=target.resource_id
    JOIN public.device_certificate_desired_generation_lineage lineage
      ON lineage.tenant_id=desired.tenant_id AND lineage.device_id=desired.device_id
      AND lineage.generation=desired.generation
      AND lineage.authorization_receipt_id=desired.authorization_receipt_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held' AND lease.expires_at>pg_catalog.clock_timestamp()
      AND desired.generation=p_generation FOR UPDATE OF target,lease,desired;
    IF NOT FOUND OR p_generation=9223372036854775807 THEN RETURN; END IF;
    next_value:=p_generation+1;
    INSERT INTO public.device_certificate_desired_generation_lineage
      (tenant_id,device_id,generation,authorization_receipt_id)
    VALUES (p_tenant_id,p_device_id,next_value,current_receipt_id);
    UPDATE public.device_certificate_desired_states SET generation=next_value,
      authorization_receipt_id=current_receipt_id,deletion_requested_at=NULL,finalizer_present=true
    WHERE tenant_id=p_tenant_id AND device_id=p_device_id AND generation=p_generation;
    INSERT INTO public.device_certificate_conditions
      (tenant_id,device_id,condition_type,status,reason,observed_generation)
    VALUES
      (p_tenant_id,p_device_id,'Ready','False','AwaitingDevice',next_value),
      (p_tenant_id,p_device_id,'Reconciling','True','DesiredAccepted',next_value),
      (p_tenant_id,p_device_id,'PendingDevice','False','AwaitingDevice',next_value),
      (p_tenant_id,p_device_id,'Degraded','False','ArtifactUnavailable',next_value),
      (p_tenant_id,p_device_id,'Quarantined','False','ProtocolViolation',next_value),
      (p_tenant_id,p_device_id,'Deleting','False','DeletionPending',next_value)
    ON CONFLICT (tenant_id,device_id,condition_type) DO UPDATE SET
      status=EXCLUDED.status,reason=EXCLUDED.reason,
      observed_generation=EXCLUDED.observed_generation;
    UPDATE public.reconcile_targets SET wake_version=reconcile_targets.wake_version+1,
      next_run_at=pg_catalog.clock_timestamp(),updated_at=pg_catalog.clock_timestamp()
    WHERE tenant_id=p_tenant_id AND reconcile_targets.target_id=authority_target_id
    RETURNING reconcile_targets.wake_version INTO next_wake;
    RETURN QUERY SELECT next_value,authority_target_id::text,next_wake;
END;
$$;

ALTER FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[],
    text,text,text,text,bytea,bigint,text[],bigint[])
OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_rotate_device_certificate_generation(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint)
OWNER TO rss_device_certificate_funnel_owner;

REVOKE ALL ON FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[],
    text,text,text,text,bytea,bigint,text[],bigint[])
FROM PUBLIC, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_accept_device_certificate_desired(
    uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[],
    text,text,text,text,bytea,bigint,text[],bigint[])
TO rss_app;

REVOKE ALL ON FUNCTION public.rss_rotate_device_certificate_generation(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint)
FROM PUBLIC, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_rotate_device_certificate_generation(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint)
TO rss_app;

-- Postflight: there must be exactly one accept signature and no direct serving access to the
-- sensitive authorization ledger or its normalized policy basis.
DO $$
BEGIN
    IF (SELECT count(*) FROM pg_catalog.pg_proc
        WHERE pronamespace='public'::regnamespace
          AND proname='rss_accept_device_certificate_desired') <> 1
    THEN
        RAISE EXCEPTION USING ERRCODE='55000',
            MESSAGE='0110 requires exactly one device-policy accept funnel';
    END IF;
    IF has_table_privilege('rss_app','public.device_certificate_policy_operations','SELECT')
       OR has_table_privilege('rss_app_read','public.device_certificate_policy_operations','SELECT')
       OR has_table_privilege('rss_app','public.device_certificate_policy_authorization_policies','SELECT')
       OR has_table_privilege('rss_app_read','public.device_certificate_policy_authorization_policies','SELECT')
    THEN
        RAISE EXCEPTION USING ERRCODE='55000',
            MESSAGE='0110 sensitive authorization ledger privileges are not closed';
    END IF;
END;
$$;
