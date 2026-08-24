-- Keep the Ready=True proof transaction closed over the receipt-bound command schema introduced
-- by the authorization-receipt lineage. No table shape changes are required.
CREATE OR REPLACE FUNCTION public.rss_mark_device_certificate_ready(
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
    durable_authorization_receipt_id uuid;
    command_payload bytea;
    command_deadline_epoch_seconds bigint;
    payload_json jsonb;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        p_tenant_id::text || ':' || p_device_id::text || ':' ||
        pg_catalog.encode(p_serial, 'hex'), 1901));
    SELECT target.target_id, desired.renew_before_seconds, desired.authorization_receipt_id
      INTO authority_target_id, durable_renew_before_seconds, durable_authorization_receipt_id
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
      AND artifact.authorization_receipt_id=durable_authorization_receipt_id
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
      AND outbox.schema_hash='sha256:a45a6ce5b930e2921919b10d688321bb05f59117fa8b8cb9076a7c455bff213b'
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
        AND payload_json->>'authorizationReceiptId'=durable_authorization_receipt_id::text
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

REVOKE ALL ON FUNCTION public.rss_mark_device_certificate_ready(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bytea,text,bytea,bytea,bytea,text,bigint,
    bigint,bytea,bigint,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_mark_device_certificate_ready(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bytea,text,bytea,bytea,bytea,text,bigint,
    bigint,bytea,bigint,bigint,bigint) TO rss_app;
