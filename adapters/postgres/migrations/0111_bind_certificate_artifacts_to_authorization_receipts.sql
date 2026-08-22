-- 0111_bind_certificate_artifacts_to_authorization_receipts.sql
--
-- Bind every durable certificate artifact receipt to the exact desired-generation
-- authorization receipt that permitted its production mint.
--
-- ref: hashicorp/vault api-docs/secret/pki#sign-certificate

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.device_certificate_authorized_artifacts,
    public.device_certificate_desired_states,
    public.device_certificate_desired_generation_lineage,
    public.reconcile_targets,
    public.reconcile_leases,
    public.reconcile_attempts
IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    migration_head bigint;
BEGIN
    SELECT max(version) INTO migration_head FROM public._sqlx_migrations;
    IF migration_head IS DISTINCT FROM 110 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = '0111 requires migration ledger head 0110';
    END IF;
END;
$$;

ALTER TABLE public.device_certificate_authorized_artifacts
    ADD COLUMN authorization_receipt_id uuid;

UPDATE public.device_certificate_authorized_artifacts AS artifact
SET authorization_receipt_id = lineage.authorization_receipt_id
FROM public.device_certificate_desired_generation_lineage AS lineage
WHERE lineage.tenant_id = artifact.tenant_id
  AND lineage.device_id = artifact.device_id
  AND lineage.generation = artifact.generation;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.device_certificate_authorized_artifacts
        WHERE authorization_receipt_id IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = '0111 cannot bind an artifact without desired-generation receipt lineage';
    END IF;
END;
$$;

ALTER TABLE public.device_certificate_authorized_artifacts
    ALTER COLUMN authorization_receipt_id SET NOT NULL,
    ADD CONSTRAINT device_certificate_authorized_artifacts_receipt_non_nil
        CHECK (authorization_receipt_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    ADD CONSTRAINT device_certificate_authorized_artifacts_lineage_fk
        FOREIGN KEY (tenant_id, device_id, generation, authorization_receipt_id)
        REFERENCES public.device_certificate_desired_generation_lineage
            (tenant_id, device_id, generation, authorization_receipt_id);

DROP FUNCTION public.rss_append_device_certificate_artifact_draft(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint
);
DROP FUNCTION public.rss_append_device_certificate_artifact_production(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint
);
DROP FUNCTION public.rss_append_device_certificate_artifact_core(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint,text
);

-- Private shared core. The typed entry points below choose eligibility; the caller must also
-- present the exact current desired-generation receipt lineage.
CREATE FUNCTION public.rss_append_device_certificate_artifact_core(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint,
    p_authorization_receipt_id uuid, p_policy_hash bytea,
    p_public_key_digest bytea, p_expected_state_hash bytea, p_artifact_digest bytea,
    p_artifact_id text, p_serial bytea, p_not_after_epoch_seconds bigint,
    p_artifact_eligibility text
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE existing public.device_certificate_authorized_artifacts%ROWTYPE;
BEGIN
    IF p_artifact_eligibility NOT IN ('draft', 'production')
       OR p_authorization_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid artifact authority';
    END IF;
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    PERFORM 1 FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id, target_id)
    JOIN public.reconcile_leases lease USING (tenant_id, target_id)
    JOIN public.device_certificate_desired_states desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id::text=target.resource_id
    JOIN public.device_certificate_desired_generation_lineage lineage
      ON lineage.tenant_id=desired.tenant_id AND lineage.device_id=desired.device_id
     AND lineage.generation=desired.generation
     AND lineage.authorization_receipt_id=desired.authorization_receipt_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp() AND desired.generation=p_generation
      AND desired.authorization_receipt_id=p_authorization_receipt_id
      AND lineage.authorization_receipt_id=p_authorization_receipt_id
    FOR UPDATE OF target, lease, desired;
    IF NOT FOUND THEN RETURN 'stale_fence'; END IF;

    INSERT INTO public.device_certificate_authorized_artifacts
        (tenant_id, device_id, generation, authorization_receipt_id, artifact_eligibility,
         policy_hash, public_key_digest, expected_state_hash, artifact_digest, artifact_id,
         serial, not_after)
    VALUES (p_tenant_id, p_device_id, p_generation, p_authorization_receipt_id,
        p_artifact_eligibility, p_policy_hash, p_public_key_digest, p_expected_state_hash,
        p_artifact_digest, p_artifact_id, p_serial,
        TIMESTAMPTZ 'epoch' + p_not_after_epoch_seconds * INTERVAL '1 second')
    ON CONFLICT DO NOTHING;
    IF FOUND THEN RETURN 'appended'; END IF;
    SELECT * INTO existing FROM public.device_certificate_authorized_artifacts
    WHERE tenant_id=p_tenant_id AND device_id=p_device_id AND generation=p_generation;
    IF (existing.authorization_receipt_id, existing.artifact_eligibility, existing.policy_hash,
        existing.public_key_digest, existing.expected_state_hash, existing.artifact_digest,
        existing.artifact_id, existing.serial,
        pg_catalog.floor(extract(epoch FROM existing.not_after))::bigint)
       IS NOT DISTINCT FROM
       (p_authorization_receipt_id, p_artifact_eligibility, p_policy_hash,
        p_public_key_digest, p_expected_state_hash, p_artifact_digest, p_artifact_id,
        p_serial, p_not_after_epoch_seconds)
    THEN RETURN 'replayed'; END IF;
    RETURN 'conflict';
END;
$$;

CREATE FUNCTION public.rss_append_device_certificate_artifact_draft(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint,
    p_authorization_receipt_id uuid, p_policy_hash bytea,
    p_public_key_digest bytea, p_expected_state_hash bytea, p_artifact_digest bytea,
    p_artifact_id text, p_serial bytea, p_not_after_epoch_seconds bigint
)
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.rss_append_device_certificate_artifact_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,p_generation,
        p_authorization_receipt_id,p_policy_hash,p_public_key_digest,p_expected_state_hash,
        p_artifact_digest,p_artifact_id,p_serial,p_not_after_epoch_seconds,'draft')
$$;

CREATE FUNCTION public.rss_append_device_certificate_artifact_production(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint,
    p_authorization_receipt_id uuid, p_policy_hash bytea,
    p_public_key_digest bytea, p_expected_state_hash bytea, p_artifact_digest bytea,
    p_artifact_id text, p_serial bytea, p_not_after_epoch_seconds bigint
)
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.rss_append_device_certificate_artifact_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,p_generation,
        p_authorization_receipt_id,p_policy_hash,p_public_key_digest,p_expected_state_hash,
        p_artifact_digest,p_artifact_id,p_serial,p_not_after_epoch_seconds,'production')
$$;

ALTER FUNCTION public.rss_append_device_certificate_artifact_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,uuid,bytea,bytea,bytea,bytea,text,bytea,bigint,text)
OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_append_device_certificate_artifact_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,uuid,bytea,bytea,bytea,bytea,text,bytea,bigint)
OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_append_device_certificate_artifact_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint,uuid,bytea,bytea,bytea,bytea,text,bytea,bigint)
OWNER TO rss_device_certificate_funnel_owner;

REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,uuid,bytea,bytea,bytea,bytea,text,bytea,bigint,text)
FROM PUBLIC, rss_app, rss_app_read;
REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,uuid,bytea,bytea,bytea,bytea,text,bytea,bigint)
FROM PUBLIC, rss_app_read;
REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint,uuid,bytea,bytea,bytea,bytea,text,bytea,bigint)
FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_append_device_certificate_artifact_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,uuid,bytea,bytea,bytea,bytea,text,bytea,bigint)
TO rss_app;
