-- 0092_persist_device_certificate_artifacts.sql
--
-- Durable certificate authorization evidence and the certificate-specific deletion finalizer.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.device_certificate_desired_states,
    public.device_certificate_conditions, public.reconcile_targets,
    public.reconcile_leases, public.reconcile_attempts,
    public.reconcile_attempt_results, public.certificate_revocations
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
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
            MESSAGE = '0092 requires every device-certificate reconcile lease to be free';
    END IF;
END;
$$;

ALTER TABLE public.device_certificate_conditions
    DROP CONSTRAINT device_certificate_conditions_ready_not_true,
    ADD CONSTRAINT device_certificate_conditions_ready_closed
        CHECK (
            condition_type <> 'Ready'
            OR ((status = 'True') =
                (reason = 'StateMatches' AND observed_generation IS NOT NULL))
        );

ALTER TABLE public.device_certificate_desired_states
    ADD COLUMN deletion_requested_at timestamptz,
    ADD COLUMN finalizer_present boolean NOT NULL DEFAULT true,
    ADD CONSTRAINT device_certificate_desired_deletion_state_closed
        CHECK (finalizer_present OR deletion_requested_at IS NOT NULL);

CREATE OR REPLACE FUNCTION public.rss_device_certificate_desired_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    encoded bytea;
    item text;
    previous text;
    character_index integer;
    codepoint integer;
    first_codepoint integer;
    last_codepoint integer;
    policy_unchanged boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.generation <> 1 OR NEW.deletion_requested_at IS NOT NULL
            OR NOT NEW.finalizer_present
        THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'initial device certificate desired state must be active generation one';
        END IF;
        NEW.created_at := pg_catalog.clock_timestamp();
    ELSE
        IF NEW.tenant_id <> OLD.tenant_id OR NEW.device_id <> OLD.device_id
            OR NEW.created_at <> OLD.created_at
        THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'device certificate desired identity is immutable';
        END IF;
        policy_unchanged := (NEW.validity_seconds, NEW.renew_before_seconds,
            NEW.client_auth, NEW.server_auth, NEW.sans)
            IS NOT DISTINCT FROM (OLD.validity_seconds, OLD.renew_before_seconds,
            OLD.client_auth, OLD.server_auth, OLD.sans);
        IF NEW.generation = OLD.generation THEN
            IF NOT policy_unchanged OR NOT (
                (OLD.deletion_requested_at IS NULL AND OLD.finalizer_present
                    AND NEW.deletion_requested_at IS NOT NULL AND NEW.finalizer_present)
                OR (OLD.deletion_requested_at IS NOT NULL AND OLD.finalizer_present
                    AND NEW.deletion_requested_at = OLD.deletion_requested_at
                    AND NOT NEW.finalizer_present)
            ) THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'same-generation desired update is not a deletion transition';
            END IF;
        ELSIF NEW.generation = OLD.generation + 1 THEN
            IF NEW.deletion_requested_at IS NOT NULL OR NOT NEW.finalizer_present THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'new desired generation must restore the active finalizer state';
            END IF;
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'device certificate desired generation must advance exactly once';
        END IF;
    END IF;

    IF pg_catalog.cardinality(NEW.sans) NOT BETWEEN 0 AND 32 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'device certificate SAN count is outside bounds';
    END IF;
    previous := NULL;
    FOREACH item IN ARRAY NEW.sans LOOP
        IF item IS NULL OR pg_catalog.char_length(item) NOT BETWEEN 1 AND 253 THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'device certificate SAN length is outside bounds';
        END IF;
        first_codepoint := pg_catalog.ascii(pg_catalog.substr(item, 1, 1));
        last_codepoint := pg_catalog.ascii(pg_catalog.substr(item, pg_catalog.char_length(item), 1));
        IF first_codepoint IN (9,10,11,12,13,32,133,160,5760,8232,8233,8239,8287,12288)
            OR first_codepoint BETWEEN 8192 AND 8202
            OR last_codepoint IN (9,10,11,12,13,32,133,160,5760,8232,8233,8239,8287,12288)
            OR last_codepoint BETWEEN 8192 AND 8202
        THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'device certificate SAN must be trimmed';
        END IF;
        FOR character_index IN 1..pg_catalog.char_length(item) LOOP
            codepoint := pg_catalog.ascii(pg_catalog.substr(item, character_index, 1));
            IF codepoint BETWEEN 0 AND 31 OR codepoint BETWEEN 127 AND 159 THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'device certificate SAN must not contain control characters';
            END IF;
        END LOOP;
        IF previous IS NOT NULL AND previous COLLATE "C" >= item COLLATE "C" THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'device certificate SANs must be C-sorted and unique';
        END IF;
        previous := item;
    END LOOP;

    encoded := pg_catalog.convert_to('rss.deviceloop.device-certificate-policy.v1', 'UTF8')
        || pg_catalog.decode('00', 'hex');
    encoded := encoded || pg_catalog.int4send(NEW.validity_seconds)
        || pg_catalog.int4send(NEW.renew_before_seconds)
        || pg_catalog.int4send(NEW.client_auth::integer + NEW.server_auth::integer);
    IF NEW.client_auth THEN
        item := 'clientAuth';
        encoded := encoded || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(item, 'UTF8')))
            || pg_catalog.convert_to(item, 'UTF8');
    END IF;
    IF NEW.server_auth THEN
        item := 'serverAuth';
        encoded := encoded || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(item, 'UTF8')))
            || pg_catalog.convert_to(item, 'UTF8');
    END IF;
    encoded := encoded || pg_catalog.int4send(pg_catalog.cardinality(NEW.sans));
    FOREACH item IN ARRAY NEW.sans LOOP
        encoded := encoded || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(item, 'UTF8')))
            || pg_catalog.convert_to(item, 'UTF8');
    END LOOP;
    NEW.policy_hash := pg_catalog.sha256(encoded);
    NEW.updated_at := pg_catalog.clock_timestamp();
    IF TG_OP = 'INSERT' THEN NEW.created_at := NEW.updated_at; END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE public.device_certificate_authorized_artifacts (
    tenant_id            uuid        NOT NULL,
    device_id            uuid        NOT NULL,
    generation           bigint      NOT NULL,
    policy_hash          bytea       NOT NULL,
    public_key_digest    bytea       NOT NULL,
    expected_state_hash  bytea       NOT NULL,
    artifact_digest      bytea       NOT NULL,
    artifact_id          text        NOT NULL,
    serial               bytea       NOT NULL,
    not_after            timestamptz NOT NULL,
    authorized_at        timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id, device_id, generation),
    CONSTRAINT device_certificate_artifacts_desired_fk FOREIGN KEY (tenant_id, device_id)
        REFERENCES public.device_certificate_desired_states (tenant_id, device_id),
    CONSTRAINT device_certificate_artifacts_generation_positive CHECK (generation > 0),
    CONSTRAINT device_certificate_artifacts_policy_hash_sha256 CHECK (pg_catalog.octet_length(policy_hash) = 32),
    CONSTRAINT device_certificate_artifacts_public_key_sha256 CHECK (pg_catalog.octet_length(public_key_digest) = 32),
    CONSTRAINT device_certificate_artifacts_state_hash_sha256 CHECK (pg_catalog.octet_length(expected_state_hash) = 32),
    CONSTRAINT device_certificate_artifacts_digest_sha256 CHECK (pg_catalog.octet_length(artifact_digest) = 32),
    CONSTRAINT device_certificate_artifacts_id_bounded CHECK (pg_catalog.octet_length(artifact_id) BETWEEN 16 AND 256),
    CONSTRAINT device_certificate_artifacts_serial_bounded CHECK (pg_catalog.octet_length(serial) BETWEEN 1 AND 20),
    CONSTRAINT device_certificate_artifacts_time_order CHECK (authorized_at < not_after)
);

CREATE INDEX device_certificate_artifacts_terminal_evidence_idx
    ON public.device_certificate_authorized_artifacts (tenant_id, device_id, not_after, serial);

ALTER TABLE public.device_certificate_authorized_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_certificate_authorized_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_certificate_authorized_artifacts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE public.device_certificate_authorized_artifacts
    FROM PUBLIC, rss_app, rss_app_read;
GRANT SELECT ON TABLE public.device_certificate_authorized_artifacts TO rss_app, rss_app_read;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON public.device_certificate_authorized_artifacts FROM rss_app, rss_app_read;

-- The serving role cannot directly author terminal evidence. A fixed NOLOGIN/NOBYPASSRLS role
-- owns the certificate-specific funnels; FORCE RLS and the explicit tenant setting still apply.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'rss_device_certificate_funnel_owner'
    ) THEN
        CREATE ROLE rss_device_certificate_funnel_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
            NOREPLICATION NOINHERIT;
    END IF;
END
$$;

ALTER ROLE rss_device_certificate_funnel_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    NOREPLICATION NOINHERIT;

DO $$
DECLARE
    funnel_owner_oid oid;
BEGIN
    SELECT role.oid INTO STRICT funnel_owner_oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'rss_device_certificate_funnel_owner';
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = funnel_owner_oid
           OR membership.member = funnel_owner_oid
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'rss_device_certificate_funnel_owner must have no role memberships';
    END IF;
END
$$;

GRANT SELECT ON TABLE public.reconcile_targets, public.reconcile_leases,
    public.reconcile_attempts, public.reconcile_actions, public.reconcile_attempt_results,
    public.device_commands,
    public.outbox, public.command_journal, public.device_certificate_desired_states,
    public.device_certificate_reported_states, public.device_certificate_conditions,
    public.device_certificate_authorized_artifacts, public.certificate_revocations,
    public.device_certificate_policy_operations
TO rss_device_certificate_funnel_owner;
GRANT INSERT ON TABLE public.device_certificate_authorized_artifacts
TO rss_device_certificate_funnel_owner;
-- PostgreSQL row-lock clauses require UPDATE privilege even though the immutable receipt funnel
-- exposes no UPDATE statement. This is granted only to the NOLOGIN function owner.
GRANT UPDATE ON TABLE public.device_certificate_authorized_artifacts,
    public.device_certificate_reported_states, public.device_commands, public.outbox
TO rss_device_certificate_funnel_owner;
GRANT INSERT (tenant_id, device_id, condition_type, status, reason, observed_generation),
    UPDATE (status, reason, observed_generation)
ON public.device_certificate_conditions TO rss_device_certificate_funnel_owner;
GRANT UPDATE (generation, deletion_requested_at, finalizer_present)
ON public.device_certificate_desired_states TO rss_device_certificate_funnel_owner;
GRANT UPDATE (wake_version, next_run_at, updated_at)
ON public.reconcile_targets TO rss_device_certificate_funnel_owner;
GRANT UPDATE (status, disabled_reason, failure_streak, last_result, updated_at)
ON public.reconcile_targets TO rss_device_certificate_funnel_owner;
GRANT UPDATE (state, lease_token, holder_id, acquired_at, expires_at, heartbeat_at, updated_at)
ON public.reconcile_leases TO rss_device_certificate_funnel_owner;
GRANT INSERT ON public.reconcile_attempt_results TO rss_device_certificate_funnel_owner;
GRANT INSERT ON public.device_certificate_desired_states,
    public.device_certificate_policy_operations TO rss_device_certificate_funnel_owner;
GRANT UPDATE (generation, validity_seconds, renew_before_seconds, client_auth, server_auth,
    sans, deletion_requested_at, finalizer_present)
ON public.device_certificate_desired_states TO rss_device_certificate_funnel_owner;

CREATE FUNCTION public.rss_serialize_device_certificate_terminal_evidence()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        NEW.tenant_id::text || ':' || NEW.device_id::text || ':' ||
        pg_catalog.encode(NEW.serial, 'hex'), 1901));
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.rss_serialize_device_certificate_terminal_evidence()
OWNER TO rss_device_certificate_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_serialize_device_certificate_terminal_evidence()
FROM PUBLIC,rss_app,rss_app_read;
CREATE TRIGGER device_certificate_revocation_serializes_ready
BEFORE INSERT OR UPDATE ON public.certificate_revocations
FOR EACH ROW EXECUTE FUNCTION public.rss_serialize_device_certificate_terminal_evidence();
CREATE FUNCTION public.rss_invalidate_device_certificate_ready()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_TABLE_NAME='device_certificate_reported_states' THEN
        UPDATE public.device_certificate_conditions condition
        SET status='False', reason='StateDrift', observed_generation=NEW.observed_generation
        WHERE condition.tenant_id=NEW.tenant_id AND condition.device_id=NEW.device_id
          AND condition.condition_type='Ready' AND condition.status='True'
          AND ((TG_OP='UPDATE' AND
            (OLD.observed_generation,OLD.fence_epoch,OLD.state_hash,OLD.artifact_digest,
             OLD.report_envelope_id,OLD.device_sequence,OLD.expires_at,OLD.device_observed_at,
             OLD.received_at)
            IS DISTINCT FROM
            (NEW.observed_generation,NEW.fence_epoch,NEW.state_hash,NEW.artifact_digest,
             NEW.report_envelope_id,NEW.device_sequence,NEW.expires_at,NEW.device_observed_at,
             NEW.received_at))
            OR NOT (condition.observed_generation=NEW.observed_generation
              AND EXISTS (SELECT 1 FROM public.device_certificate_authorized_artifacts artifact
              WHERE artifact.tenant_id=NEW.tenant_id AND artifact.device_id=NEW.device_id
                AND artifact.generation=NEW.observed_generation
                AND artifact.expected_state_hash=NEW.state_hash
                AND artifact.artifact_digest=NEW.artifact_digest)));
    ELSIF TG_TABLE_NAME='device_commands' THEN
        IF NEW.state NOT IN ('received','applied') THEN
            UPDATE public.device_certificate_conditions condition
            SET status='False', reason='StateDrift', observed_generation=NEW.generation
            WHERE condition.tenant_id=NEW.tenant_id AND condition.device_id=NEW.device_id
              AND condition.condition_type='Ready' AND condition.status='True'
              AND condition.observed_generation=NEW.generation;
        END IF;
    ELSIF TG_TABLE_NAME='outbox' THEN
        UPDATE public.device_certificate_conditions condition
        SET status='False', reason='StateDrift', observed_generation=command.generation
        FROM public.device_commands command
        WHERE command.tenant_id=NEW.tenant_id AND command.command_id=NEW.event_id
          AND condition.tenant_id=command.tenant_id AND condition.device_id=command.device_id
          AND condition.condition_type='Ready' AND condition.status='True'
          AND condition.observed_generation=command.generation;
    ELSE
        UPDATE public.device_certificate_conditions condition
        SET status='False', reason='StateDrift', observed_generation=artifact.generation
        FROM public.device_certificate_authorized_artifacts artifact
        WHERE artifact.tenant_id=NEW.tenant_id AND artifact.device_id=NEW.device_id
          AND artifact.serial=NEW.serial AND artifact.not_after=NEW.not_after
          AND condition.tenant_id=artifact.tenant_id AND condition.device_id=artifact.device_id
          AND condition.condition_type='Ready' AND condition.status='True'
          AND condition.observed_generation=artifact.generation;
    END IF;
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.rss_invalidate_device_certificate_ready()
OWNER TO rss_device_certificate_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_invalidate_device_certificate_ready()
FROM PUBLIC,rss_app,rss_app_read;
CREATE TRIGGER device_certificate_report_invalidates_ready
AFTER INSERT OR UPDATE ON public.device_certificate_reported_states
FOR EACH ROW EXECUTE FUNCTION public.rss_invalidate_device_certificate_ready();
CREATE TRIGGER device_certificate_revocation_invalidates_ready
AFTER INSERT OR UPDATE ON public.certificate_revocations
FOR EACH ROW EXECUTE FUNCTION public.rss_invalidate_device_certificate_ready();
CREATE TRIGGER device_certificate_command_invalidates_ready
AFTER UPDATE ON public.device_commands
FOR EACH ROW EXECUTE FUNCTION public.rss_invalidate_device_certificate_ready();
CREATE TRIGGER device_certificate_outbox_invalidates_ready
AFTER UPDATE ON public.outbox
FOR EACH ROW EXECUTE FUNCTION public.rss_invalidate_device_certificate_ready();

CREATE FUNCTION public.rss_append_device_certificate_artifact(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint, p_policy_hash bytea,
    p_public_key_digest bytea, p_expected_state_hash bytea, p_artifact_digest bytea,
    p_artifact_id text, p_serial bytea, p_not_after_epoch_seconds bigint
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE existing public.device_certificate_authorized_artifacts%ROWTYPE;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    PERFORM 1 FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id, target_id)
    JOIN public.reconcile_leases lease USING (tenant_id, target_id)
    JOIN public.device_certificate_desired_states desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp() AND desired.generation=p_generation
    FOR UPDATE OF target, lease, desired;
    IF NOT FOUND THEN RETURN 'stale_fence'; END IF;

    INSERT INTO public.device_certificate_authorized_artifacts
        (tenant_id, device_id, generation, policy_hash, public_key_digest,
         expected_state_hash, artifact_digest, artifact_id, serial, not_after)
    VALUES (p_tenant_id, p_device_id, p_generation, p_policy_hash, p_public_key_digest,
        p_expected_state_hash, p_artifact_digest, p_artifact_id, p_serial,
        TIMESTAMPTZ 'epoch' + p_not_after_epoch_seconds * INTERVAL '1 second')
    ON CONFLICT DO NOTHING;
    IF FOUND THEN RETURN 'appended'; END IF;
    SELECT * INTO existing FROM public.device_certificate_authorized_artifacts
    WHERE tenant_id=p_tenant_id AND device_id=p_device_id AND generation=p_generation;
    IF (existing.policy_hash, existing.public_key_digest, existing.expected_state_hash,
        existing.artifact_digest, existing.artifact_id, existing.serial,
        pg_catalog.floor(extract(epoch FROM existing.not_after))::bigint)
       IS NOT DISTINCT FROM
       (p_policy_hash, p_public_key_digest, p_expected_state_hash, p_artifact_digest,
        p_artifact_id, p_serial, p_not_after_epoch_seconds)
    THEN RETURN 'replayed'; END IF;
    RETURN 'conflict';
END;
$$;

CREATE FUNCTION public.rss_write_device_certificate_conditions(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint,
    p_condition_types text[], p_statuses text[], p_reasons text[],
    p_observed_generations bigint[]
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    item_index integer;
    pending_true boolean := false;
    degraded_true boolean := false;
    quarantined_true boolean := false;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
       OR pg_catalog.cardinality(p_condition_types) NOT IN (1,6)
       OR pg_catalog.cardinality(p_statuses)<>pg_catalog.cardinality(p_condition_types)
       OR pg_catalog.cardinality(p_reasons)<>pg_catalog.cardinality(p_condition_types)
       OR pg_catalog.cardinality(p_observed_generations)<>pg_catalog.cardinality(p_condition_types)
       OR (pg_catalog.cardinality(p_condition_types)=1
           AND (
             p_condition_types IS DISTINCT FROM ARRAY['Ready']::text[]
             OR p_statuses IS DISTINCT FROM ARRAY['False']::text[]
             OR p_reasons IS DISTINCT FROM ARRAY['StateDrift']::text[]
             OR p_observed_generations IS DISTINCT FROM ARRAY[p_generation]::bigint[]
           ))
       OR (pg_catalog.cardinality(p_condition_types)=6
           AND (
             p_condition_types IS DISTINCT FROM ARRAY[
               'Ready','Reconciling','PendingDevice','Degraded','Quarantined','Deleting'
             ]::text[]
             OR p_observed_generations IS DISTINCT FROM ARRAY[
               p_generation,p_generation,p_generation,
               p_generation,p_generation,p_generation
             ]::bigint[]
             OR p_statuses IS DISTINCT FROM ARRAY[
               'False','True','True','False','False','False'
             ]::text[]
             AND p_statuses IS DISTINCT FROM ARRAY[
               'False','False','False','True','False','False'
             ]::text[]
             AND p_statuses IS DISTINCT FROM ARRAY[
               'False','False','False','False','True','False'
             ]::text[]
           ))
    THEN RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'invalid ordinary condition authority';
    END IF;
    PERFORM 1 FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id, target_id)
    JOIN public.reconcile_leases lease USING (tenant_id, target_id)
    JOIN public.device_certificate_desired_states desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp() AND desired.generation=p_generation
      AND desired.deletion_requested_at IS NULL AND desired.finalizer_present
    FOR UPDATE OF target, lease, desired;
    IF NOT FOUND THEN RETURN false; END IF;
    FOR item_index IN 1..pg_catalog.cardinality(p_condition_types) LOOP
        INSERT INTO public.device_certificate_conditions
            (tenant_id,device_id,condition_type,status,reason,observed_generation)
        VALUES (p_tenant_id,p_device_id,p_condition_types[item_index],p_statuses[item_index],
            p_reasons[item_index],p_observed_generations[item_index])
        ON CONFLICT (tenant_id,device_id,condition_type) DO UPDATE SET
            status=EXCLUDED.status,reason=EXCLUDED.reason,
            observed_generation=EXCLUDED.observed_generation;
        pending_true:=pending_true OR
            (p_condition_types[item_index]='PendingDevice' AND p_statuses[item_index]='True');
        degraded_true:=degraded_true OR
            (p_condition_types[item_index]='Degraded' AND p_statuses[item_index]='True');
        quarantined_true:=quarantined_true OR
            (p_condition_types[item_index]='Quarantined' AND p_statuses[item_index]='True');
    END LOOP;
    IF pending_true OR degraded_true OR quarantined_true THEN
        UPDATE public.device_certificate_conditions condition
        SET status='False',
            reason=CASE WHEN condition.condition_type='Ready' AND condition.reason='StateMatches'
                THEN 'StateDrift' ELSE condition.reason END,
            observed_generation=p_generation
        WHERE condition.tenant_id=p_tenant_id AND condition.device_id=p_device_id
          AND condition.condition_type='Ready';
    END IF;
    IF degraded_true OR quarantined_true THEN
        UPDATE public.device_certificate_conditions condition
        SET status='False',observed_generation=p_generation
        WHERE condition.tenant_id=p_tenant_id AND condition.device_id=p_device_id
          AND condition.condition_type='PendingDevice';
    END IF;
    IF pending_true OR quarantined_true THEN
        UPDATE public.device_certificate_conditions condition
        SET status='False',observed_generation=p_generation
        WHERE condition.tenant_id=p_tenant_id AND condition.device_id=p_device_id
          AND condition.condition_type='Degraded';
    END IF;
    RETURN true;
END;
$$;

CREATE FUNCTION public.rss_accept_device_certificate_desired(
    p_tenant_id uuid, p_device_id uuid, p_idempotency_key uuid, p_request_digest bytea,
    p_expected_generation bigint, p_next_generation bigint, p_validity_seconds integer,
    p_renew_before_seconds integer, p_client_auth boolean, p_server_auth boolean, p_sans text[]
)
RETURNS TABLE (outcome text, actual_generation bigint, target_id text, wake_version bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    operation_digest bytea;
    operation_generation bigint;
    authority_target_id uuid;
    authority_disabled_reason text;
    authority_has_lease boolean := false;
    desired_generation bigint := 0;
    next_wake bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='tenant authority mismatch'; END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        p_tenant_id::text || ':' || p_device_id::text || ':' || p_idempotency_key::text, 0));
    SELECT operation.request_digest,operation.accepted_generation
      INTO operation_digest,operation_generation
    FROM public.device_certificate_policy_operations operation
    WHERE operation.tenant_id=p_tenant_id AND operation.device_id=p_device_id
      AND operation.idempotency_key=p_idempotency_key;
    IF FOUND THEN
        IF operation_digest=p_request_digest THEN
            RETURN QUERY SELECT 'replayed',operation_generation,NULL::text,NULL::bigint;
        ELSE
            RETURN QUERY SELECT 'idempotency_conflict',operation_generation,NULL::text,NULL::bigint;
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
        RETURN QUERY SELECT 'generation_conflict',desired_generation,NULL::text,NULL::bigint;
        RETURN;
    END IF;
    IF authority_target_id IS NULL OR NOT authority_has_lease THEN
        RETURN QUERY SELECT 'missing_enrollment',desired_generation,NULL::text,NULL::bigint;
        RETURN;
    END IF;
    IF authority_disabled_reason IS NOT NULL THEN
        RETURN QUERY SELECT 'quarantined',desired_generation,NULL::text,NULL::bigint;
        RETURN;
    END IF;

    IF p_expected_generation=0 THEN
        INSERT INTO public.device_certificate_desired_states
          (tenant_id,device_id,generation,validity_seconds,renew_before_seconds,
           client_auth,server_auth,sans)
        VALUES (p_tenant_id,p_device_id,p_next_generation,p_validity_seconds,
          p_renew_before_seconds,p_client_auth,p_server_auth,p_sans);
    ELSE
        UPDATE public.device_certificate_desired_states desired SET
          generation=p_next_generation,validity_seconds=p_validity_seconds,
          renew_before_seconds=p_renew_before_seconds,client_auth=p_client_auth,
          server_auth=p_server_auth,sans=p_sans,deletion_requested_at=NULL,
          finalizer_present=true
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
    INSERT INTO public.device_certificate_policy_operations
      (tenant_id,device_id,idempotency_key,request_digest,accepted_generation,accepted_condition)
    VALUES (p_tenant_id,p_device_id,p_idempotency_key,p_request_digest,p_next_generation,'reconciling');
    RETURN QUERY SELECT 'accepted',p_next_generation,authority_target_id::text,next_wake;
END;
$$;

CREATE FUNCTION public.rss_mark_device_certificate_ready(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint, p_command_epoch bigint,
    p_intent_digest bytea,
    p_artifact_id text, p_artifact_digest bytea, p_policy_hash bytea,
    p_state_hash bytea, p_report_envelope_id text, p_device_sequence bigint,
    p_report_received_at_micros bigint,
    p_serial bytea, p_not_after_epoch_seconds bigint, p_authoritative_epoch_seconds bigint,
    p_proof_renew_at_epoch_seconds bigint
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_target_id uuid;
    durable_renew_before_seconds integer;
    command_payload bytea;
    command_deadline_epoch_seconds bigint;
    payload_json jsonb;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    -- This lock is also acquired by the BEFORE revocation trigger. Whichever transaction wins is
    -- observed by the loser before Ready can be committed.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        p_tenant_id::text || ':' || p_device_id::text || ':' ||
        pg_catalog.encode(p_serial, 'hex'), 1901));
    SELECT target.target_id, desired.renew_before_seconds
      INTO authority_target_id, durable_renew_before_seconds
    FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id, target_id)
    JOIN public.reconcile_leases lease USING (tenant_id, target_id)
    JOIN public.device_certificate_desired_states desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp() AND desired.generation=p_generation
      AND desired.policy_hash=p_policy_hash AND desired.deletion_requested_at IS NULL
      AND desired.finalizer_present
    FOR UPDATE OF target, lease, desired;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM 1 FROM public.device_certificate_authorized_artifacts artifact
    JOIN public.device_certificate_reported_states reported
      ON reported.tenant_id=artifact.tenant_id AND reported.device_id=artifact.device_id
    WHERE artifact.tenant_id=p_tenant_id AND artifact.device_id=p_device_id
      AND artifact.generation=p_generation AND artifact.policy_hash=p_policy_hash
      AND artifact.artifact_id=p_artifact_id AND artifact.artifact_digest=p_artifact_digest
      AND artifact.expected_state_hash=p_state_hash AND artifact.serial=p_serial
      AND artifact.not_after=TIMESTAMPTZ 'epoch' + p_not_after_epoch_seconds*INTERVAL '1 second'
      AND reported.observed_generation=p_generation AND reported.fence_epoch=p_command_epoch
      AND reported.state_hash=p_state_hash AND reported.artifact_digest=p_artifact_digest
      AND reported.report_envelope_id=p_report_envelope_id
      AND reported.device_sequence=p_device_sequence
      AND pg_catalog.floor(extract(epoch FROM reported.received_at)*1000000)::bigint
          =p_report_received_at_micros
      AND p_authoritative_epoch_seconds<p_not_after_epoch_seconds
      AND TIMESTAMPTZ 'epoch'+p_proof_renew_at_epoch_seconds*INTERVAL '1 second'
          = artifact.not_after-pg_catalog.make_interval(secs=>durable_renew_before_seconds)
      AND TIMESTAMPTZ 'epoch'+p_authoritative_epoch_seconds*INTERVAL '1 second'
          < artifact.not_after-pg_catalog.make_interval(secs=>durable_renew_before_seconds)
      AND pg_catalog.clock_timestamp()<artifact.not_after
      AND pg_catalog.clock_timestamp()
          < artifact.not_after-pg_catalog.make_interval(secs=>durable_renew_before_seconds)
      AND NOT EXISTS (SELECT 1 FROM public.certificate_revocations revocation
          WHERE revocation.tenant_id=artifact.tenant_id AND revocation.device_id=artifact.device_id
            AND revocation.serial=artifact.serial AND revocation.not_after=artifact.not_after)
    FOR UPDATE OF artifact, reported;
    IF NOT FOUND THEN RETURN false; END IF;

    SELECT outbox.payload, pg_catalog.floor(extract(epoch FROM command.deadline))::bigint
      INTO command_payload, command_deadline_epoch_seconds
    FROM public.device_commands command
    JOIN public.outbox outbox ON outbox.tenant_id=command.tenant_id
      AND outbox.event_id=command.command_id
    JOIN public.command_journal journal ON journal.tenant_id=command.tenant_id
      AND journal.command_id=command.command_id AND journal.outbox_event_id=outbox.event_id
    JOIN public.reconcile_attempts command_attempt ON command_attempt.tenant_id=command.tenant_id
      AND command_attempt.attempt_id::text=outbox.causation_id
      AND command_attempt.target_id=authority_target_id
    JOIN public.reconcile_actions action ON action.tenant_id=command_attempt.tenant_id
      AND action.attempt_id=command_attempt.attempt_id AND action.target_id=command_attempt.target_id
      AND action.action_kind IN ('create','update') AND action.result_label='recorded'
    WHERE command.tenant_id=p_tenant_id AND command.device_id=p_device_id
      AND command.generation=p_generation AND command.fence_epoch=p_command_epoch
      AND command.intent_digest=p_intent_digest AND command.state IN ('received','applied')
      AND outbox.domain='identity' AND outbox.topic='identity.commands.apply-device-certificate'
      AND outbox.contract_id='identity.apply-device-certificate' AND outbox.contract_version='v1'
      AND outbox.schema_hash='sha256:b5e4a88a6b3b5c11dc928d5d723fe615a23e9560808164d66c260dc8ff415365'
      AND journal.topic=outbox.topic AND journal.contract_id=outbox.contract_id
      AND journal.contract_version=outbox.contract_version AND journal.schema_hash=outbox.schema_hash
      AND outbox.metadata->>'tenantId'=p_tenant_id::text
      AND outbox.metadata->>'subjectId'=p_device_id::text
      AND outbox.metadata#>>'{actor,kind}'='service'
      AND outbox.metadata#>>'{actor,id}'='rss.reconcile.device-certificate.v1'
      AND outbox.metadata#>>'{actor,scope}'='all'
    FOR UPDATE OF command,outbox;
    IF NOT FOUND THEN RETURN false; END IF;

    BEGIN
        payload_json := pg_catalog.convert_from(command_payload, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    IF NOT (
        pg_catalog.jsonb_typeof(payload_json)='object'
        AND payload_json->>'deviceId'=p_device_id::text
        AND payload_json->>'desiredGeneration'=p_generation::text
        AND payload_json->>'fenceEpoch'=p_command_epoch::text
        AND payload_json->>'intentDigest'='sha256:'||pg_catalog.encode(p_intent_digest,'hex')
        AND payload_json->>'artifactId'=p_artifact_id
        AND payload_json->>'artifactDigest'='sha256:'||pg_catalog.encode(p_artifact_digest,'hex')
        AND payload_json->>'policyHash'='sha256:'||pg_catalog.encode(p_policy_hash,'hex')
        AND payload_json->>'deadlineEpochSeconds'=command_deadline_epoch_seconds::text
    ) IS TRUE THEN RETURN false; END IF;

    INSERT INTO public.device_certificate_conditions
        (tenant_id,device_id,condition_type,status,reason,observed_generation)
    VALUES
      (p_tenant_id,p_device_id,'Ready','True','StateMatches',p_generation),
      (p_tenant_id,p_device_id,'Reconciling','False','DeviceReported',p_generation),
      (p_tenant_id,p_device_id,'PendingDevice','False','AwaitingDevice',p_generation),
      (p_tenant_id,p_device_id,'Degraded','False','ArtifactUnavailable',p_generation),
      (p_tenant_id,p_device_id,'Quarantined','False','ProtocolViolation',p_generation),
      (p_tenant_id,p_device_id,'Deleting','False','DeletionPending',p_generation)
    ON CONFLICT (tenant_id,device_id,condition_type) DO UPDATE SET
      status=EXCLUDED.status,reason=EXCLUDED.reason,
      observed_generation=EXCLUDED.observed_generation;
    RETURN true;
END;
$$;

CREATE FUNCTION public.rss_rotate_device_certificate_generation(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint
)
RETURNS TABLE (next_generation bigint, target_id text, wake_version bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE authority_target_id uuid; next_value bigint; next_wake bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('rss.tenant_id',true),'')::uuid
    THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='tenant authority mismatch'; END IF;
    SELECT target.target_id INTO authority_target_id FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id,target_id)
    JOIN public.reconcile_leases lease USING (tenant_id,target_id)
    JOIN public.device_certificate_desired_states desired ON desired.tenant_id=target.tenant_id
      AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held' AND lease.expires_at>pg_catalog.clock_timestamp()
      AND desired.generation=p_generation FOR UPDATE OF target,lease,desired;
    IF NOT FOUND OR p_generation=9223372036854775807 THEN RETURN; END IF;
    next_value:=p_generation+1;
    UPDATE public.device_certificate_desired_states SET generation=next_value,
      deletion_requested_at=NULL,finalizer_present=true
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

CREATE FUNCTION public.rss_request_device_certificate_deletion(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint
)
RETURNS TABLE (outcome text, target_id text, wake_version bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE authority_target_id uuid; already_requested boolean; next_wake bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('rss.tenant_id',true),'')::uuid
    THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='tenant authority mismatch'; END IF;
    SELECT target.target_id,desired.deletion_requested_at IS NOT NULL
      INTO authority_target_id,already_requested FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id,target_id)
    JOIN public.reconcile_leases lease USING (tenant_id,target_id)
    JOIN public.device_certificate_desired_states desired ON desired.tenant_id=target.tenant_id
      AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held' AND lease.expires_at>pg_catalog.clock_timestamp()
      AND desired.generation=p_generation FOR UPDATE OF target,lease,desired;
    IF NOT FOUND THEN RETURN QUERY SELECT 'stale_fence',NULL::text,NULL::bigint; RETURN; END IF;
    IF already_requested THEN
      RETURN QUERY SELECT 'replayed',authority_target_id::text,p_wake_version; RETURN;
    END IF;
    UPDATE public.device_certificate_desired_states SET deletion_requested_at=pg_catalog.clock_timestamp()
    WHERE tenant_id=p_tenant_id AND device_id=p_device_id AND generation=p_generation;
    INSERT INTO public.device_certificate_conditions
      (tenant_id,device_id,condition_type,status,reason,observed_generation)
    VALUES
      (p_tenant_id,p_device_id,'Ready','False','StateDrift',p_generation),
      (p_tenant_id,p_device_id,'Reconciling','False','StateDrift',p_generation),
      (p_tenant_id,p_device_id,'PendingDevice','False','AwaitingDevice',p_generation),
      (p_tenant_id,p_device_id,'Degraded','False','ArtifactUnavailable',p_generation),
      (p_tenant_id,p_device_id,'Quarantined','False','ProtocolViolation',p_generation),
      (p_tenant_id,p_device_id,'Deleting','True','DeletionPending',p_generation)
    ON CONFLICT (tenant_id,device_id,condition_type) DO UPDATE SET
      status=EXCLUDED.status,reason=EXCLUDED.reason,
      observed_generation=EXCLUDED.observed_generation;
    UPDATE public.reconcile_targets SET wake_version=reconcile_targets.wake_version+1,
      next_run_at=pg_catalog.clock_timestamp(),updated_at=pg_catalog.clock_timestamp()
    WHERE tenant_id=p_tenant_id AND reconcile_targets.target_id=authority_target_id
    RETURNING reconcile_targets.wake_version INTO next_wake;
    RETURN QUERY SELECT 'requested',authority_target_id::text,next_wake;
END;
$$;

CREATE FUNCTION public.rss_complete_device_certificate_deletion(
    p_tenant_id uuid, p_attempt_id uuid, p_target_id uuid,
    p_lease_token uuid, p_epoch bigint
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE claimed_wake bigint; device text; v_generation bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('rss.tenant_id',true),'')::uuid
    THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='tenant authority mismatch'; END IF;
    SELECT attempt.claimed_wake_version,target.resource_id
      INTO claimed_wake,device
    FROM public.reconcile_attempts attempt
    JOIN public.reconcile_targets target USING (tenant_id,target_id)
    JOIN public.reconcile_leases lease USING (tenant_id,target_id)
    WHERE attempt.tenant_id=p_tenant_id AND attempt.attempt_id=p_attempt_id
      AND attempt.target_id=p_target_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate'
      AND target.wake_version=attempt.claimed_wake_version
      AND lease.lease_token=p_lease_token AND lease.epoch=p_epoch
      AND lease.state='held' AND lease.expires_at>pg_catalog.clock_timestamp()
      AND NOT EXISTS (SELECT 1 FROM public.reconcile_attempt_results result
        WHERE result.tenant_id=attempt.tenant_id AND result.attempt_id=attempt.attempt_id)
    FOR UPDATE OF target,lease;
    IF NOT FOUND THEN RETURN 'lost'; END IF;
    SELECT desired.generation INTO v_generation
    FROM public.device_certificate_desired_states desired
    WHERE desired.tenant_id=p_tenant_id AND desired.device_id=device::uuid
      AND desired.deletion_requested_at IS NOT NULL AND desired.finalizer_present
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'lost'; END IF;
    IF EXISTS (SELECT 1 FROM public.device_certificate_authorized_artifacts artifact
      WHERE artifact.tenant_id=p_tenant_id AND artifact.device_id=device::uuid
        AND artifact.not_after>pg_catalog.clock_timestamp()
        AND NOT EXISTS (SELECT 1 FROM public.certificate_revocations revocation
          WHERE revocation.tenant_id=artifact.tenant_id AND revocation.device_id=artifact.device_id
            AND revocation.serial=artifact.serial AND revocation.not_after=artifact.not_after))
    THEN RETURN 'evidence_pending'; END IF;
    INSERT INTO public.device_certificate_conditions
      (tenant_id,device_id,condition_type,status,reason,observed_generation)
    VALUES
      (p_tenant_id,device::uuid,'Ready','False','StateDrift',v_generation),
      (p_tenant_id,device::uuid,'Reconciling','False','StateDrift',v_generation),
      (p_tenant_id,device::uuid,'PendingDevice','False','AwaitingDevice',v_generation),
      (p_tenant_id,device::uuid,'Degraded','False','ArtifactUnavailable',v_generation),
      (p_tenant_id,device::uuid,'Quarantined','False','ProtocolViolation',v_generation),
      (p_tenant_id,device::uuid,'Deleting','True','DeletionComplete',v_generation)
    ON CONFLICT (tenant_id,device_id,condition_type) DO UPDATE SET
      status=EXCLUDED.status,reason=EXCLUDED.reason,
      observed_generation=EXCLUDED.observed_generation;
    UPDATE public.device_certificate_desired_states desired SET finalizer_present=false
    WHERE desired.tenant_id=p_tenant_id AND desired.device_id=device::uuid
      AND desired.generation=v_generation
      AND desired.deletion_requested_at IS NOT NULL AND desired.finalizer_present;
    UPDATE public.reconcile_targets SET status='disabled',disabled_reason=NULL,
      failure_streak=0,last_result='settled',updated_at=pg_catalog.clock_timestamp()
    WHERE tenant_id=p_tenant_id AND target_id=p_target_id AND wake_version=claimed_wake;
    INSERT INTO public.reconcile_attempt_results
      (tenant_id,attempt_id,target_id,result_label,requeue_after_ms,error_kind)
    VALUES (p_tenant_id,p_attempt_id,p_target_id,'settled',NULL,NULL);
    UPDATE public.reconcile_leases SET state='free',lease_token=NULL,holder_id=NULL,
      acquired_at=NULL,expires_at=NULL,heartbeat_at=NULL,updated_at=pg_catalog.clock_timestamp()
    WHERE tenant_id=p_tenant_id AND target_id=p_target_id AND lease_token=p_lease_token
      AND epoch=p_epoch AND state='held';
    RETURN 'completed';
END;
$$;

ALTER FUNCTION public.rss_append_device_certificate_artifact(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint) OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_write_device_certificate_conditions(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text[],text[],text[],bigint[]) OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_accept_device_certificate_desired(uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[]) OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_mark_device_certificate_ready(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bytea,text,bytea,bytea,bytea,text,bigint,bigint,bytea,bigint,bigint,bigint) OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_rotate_device_certificate_generation(uuid,uuid,uuid,uuid,bigint,bigint,bigint) OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_request_device_certificate_deletion(uuid,uuid,uuid,uuid,bigint,bigint,bigint) OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_complete_device_certificate_deletion(uuid,uuid,uuid,uuid,bigint) OWNER TO rss_device_certificate_funnel_owner;

REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint),
 public.rss_write_device_certificate_conditions(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text[],text[],text[],bigint[]),
 public.rss_accept_device_certificate_desired(uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[]),
 public.rss_mark_device_certificate_ready(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bytea,text,bytea,bytea,bytea,text,bigint,bigint,bytea,bigint,bigint,bigint),
 public.rss_rotate_device_certificate_generation(uuid,uuid,uuid,uuid,bigint,bigint,bigint),
 public.rss_request_device_certificate_deletion(uuid,uuid,uuid,uuid,bigint,bigint,bigint)
 ,public.rss_complete_device_certificate_deletion(uuid,uuid,uuid,uuid,bigint)
FROM PUBLIC,rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_append_device_certificate_artifact(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint),
 public.rss_write_device_certificate_conditions(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text[],text[],text[],bigint[]),
 public.rss_accept_device_certificate_desired(uuid,uuid,uuid,bytea,bigint,bigint,integer,integer,boolean,boolean,text[]),
 public.rss_mark_device_certificate_ready(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bytea,text,bytea,bytea,bytea,text,bigint,bigint,bytea,bigint,bigint,bigint),
 public.rss_rotate_device_certificate_generation(uuid,uuid,uuid,uuid,bigint,bigint,bigint),
 public.rss_request_device_certificate_deletion(uuid,uuid,uuid,uuid,bigint,bigint,bigint)
 ,public.rss_complete_device_certificate_deletion(uuid,uuid,uuid,uuid,bigint)
TO rss_app;

REVOKE INSERT,UPDATE ON public.device_certificate_conditions FROM rss_app;
REVOKE INSERT ON public.device_certificate_authorized_artifacts FROM rss_app;
REVOKE UPDATE (deletion_requested_at,finalizer_present)
ON public.device_certificate_desired_states FROM rss_app;
REVOKE INSERT,UPDATE ON public.device_certificate_desired_states FROM rss_app;
REVOKE INSERT ON public.device_certificate_policy_operations FROM rss_app;
