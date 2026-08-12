-- 0106_install_l2_dr_admission.sql
--
-- Breaking, stop-the-world admission fence for application-owned L2 recovery. PostgreSQL stores
-- the declared process set and acknowledgements, but does not claim that the declaration is the
-- deployment's complete replica inventory; that remains the delivery owner's responsibility.
--
-- ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main (closed desired-state transitions)

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE public.event_l2_dr_recovery_receipt
    ADD COLUMN protocol_revision smallint,
    ADD COLUMN admission_epoch_id uuid DEFAULT
        NULLIF(pg_catalog.current_setting('rss.dr_admission_epoch_id', true), '')::uuid;
UPDATE public.event_l2_dr_recovery_receipt SET protocol_revision = 1;
ALTER TABLE public.event_l2_dr_recovery_receipt
    ALTER COLUMN protocol_revision SET DEFAULT 2,
    ALTER COLUMN protocol_revision SET NOT NULL,
    ADD CONSTRAINT event_l2_dr_recovery_receipt_protocol_revision CHECK (
        (protocol_revision = 1 AND admission_epoch_id IS NULL)
        OR (protocol_revision = 2 AND admission_epoch_id IS NOT NULL)
    );

CREATE TABLE public.event_l2_dr_admission_epoch (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    admission_epoch_id uuid NOT NULL UNIQUE CHECK (
        admission_epoch_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    recovery_epoch_id uuid NOT NULL CHECK (
        recovery_epoch_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    recovery_tenant_id uuid NOT NULL CHECK (
        recovery_tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    plan_digest bytea NOT NULL CHECK (pg_catalog.octet_length(plan_digest) = 32),
    phase text NOT NULL CHECK (phase IN (
        'pause_requested', 'drained', 'applied_paused',
        'relay_resume_requested', 'relay_running',
        'consumer_resume_requested', 'consumer_running',
        'writes_resume_requested', 'running'
    )),
    declared_instances jsonb NOT NULL CHECK (
        pg_catalog.jsonb_typeof(declared_instances) = 'array'
        AND pg_catalog.jsonb_array_length(declared_instances) BETWEEN 1 AND 256
    ),
    requires_startup_epoch_witness boolean NOT NULL,
    invalidated boolean NOT NULL DEFAULT false,
    drained_at timestamptz,
    expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CHECK ((phase = 'pause_requested' AND drained_at IS NULL AND expires_at IS NULL)
        OR (phase <> 'pause_requested' AND drained_at IS NOT NULL AND expires_at IS NOT NULL))
);

CREATE TABLE public.event_l2_dr_admission_phase_receipt (
    admission_epoch_id uuid NOT NULL,
    assembly_identity text NOT NULL CHECK (pg_catalog.octet_length(assembly_identity) BETWEEN 1 AND 64),
    runtime_plan_fingerprint text NOT NULL CHECK (
        pg_catalog.octet_length(runtime_plan_fingerprint) BETWEEN 8 AND 256
    ),
    instance_id uuid NOT NULL CHECK (instance_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    boot_id uuid NOT NULL CHECK (boot_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    required_admission_epoch_id uuid CHECK (
        required_admission_epoch_id IS NULL
        OR required_admission_epoch_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    phase text NOT NULL CHECK (phase IN ('drained', 'relay_running', 'consumer_running', 'running')),
    observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (
        admission_epoch_id, assembly_identity, runtime_plan_fingerprint, instance_id, phase
    )
);

CREATE TABLE public.event_l2_dr_admission_resume_authorization (
    admission_epoch_id uuid NOT NULL,
    assembly_identity text NOT NULL,
    runtime_plan_fingerprint text NOT NULL,
    instance_id uuid NOT NULL,
    boot_id uuid NOT NULL,
    phase text NOT NULL CHECK (phase IN ('relay_running', 'consumer_running', 'running')),
    authorized_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (
        admission_epoch_id, assembly_identity, runtime_plan_fingerprint, instance_id, phase
    )
);

CREATE TABLE public.event_l2_dr_admission_invalidation (
    admission_epoch_id uuid PRIMARY KEY,
    reason text NOT NULL CHECK (reason IN ('undeclared_instance', 'boot_mismatch')),
    assembly_identity text NOT NULL,
    runtime_plan_fingerprint text NOT NULL,
    instance_id uuid NOT NULL,
    boot_id uuid NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

ALTER TABLE public.event_l2_dr_admission_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_admission_epoch FORCE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_admission_phase_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_admission_phase_receipt FORCE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_admission_resume_authorization ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_admission_resume_authorization FORCE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_admission_invalidation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_admission_invalidation FORCE ROW LEVEL SECURITY;

CREATE FUNCTION public.rss_l2_dr_admission_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'L2 DR admission phase receipts are append-only' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER event_l2_dr_admission_phase_receipt_immutable
BEFORE UPDATE OR DELETE ON public.event_l2_dr_admission_phase_receipt
FOR EACH ROW EXECUTE FUNCTION public.rss_l2_dr_admission_immutable();
CREATE TRIGGER event_l2_dr_admission_resume_authorization_immutable
BEFORE UPDATE OR DELETE ON public.event_l2_dr_admission_resume_authorization
FOR EACH ROW EXECUTE FUNCTION public.rss_l2_dr_admission_immutable();
CREATE TRIGGER event_l2_dr_admission_invalidation_immutable
BEFORE UPDATE OR DELETE ON public.event_l2_dr_admission_invalidation
FOR EACH ROW EXECUTE FUNCTION public.rss_l2_dr_admission_immutable();

ALTER TABLE public.event_l2_dr_admission_epoch OWNER TO rss_l2_dr_recovery_owner;
ALTER TABLE public.event_l2_dr_admission_phase_receipt OWNER TO rss_l2_dr_recovery_owner;
ALTER TABLE public.event_l2_dr_admission_resume_authorization OWNER TO rss_l2_dr_recovery_owner;
ALTER TABLE public.event_l2_dr_admission_invalidation OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_immutable() OWNER TO rss_l2_dr_recovery_owner;
REVOKE ALL ON TABLE public.event_l2_dr_admission_epoch,
    public.event_l2_dr_admission_phase_receipt,
    public.event_l2_dr_admission_resume_authorization,
    public.event_l2_dr_admission_invalidation FROM PUBLIC, rss_app, rss_app_read;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_immutable() FROM PUBLIC, rss_app, rss_app_read;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.event_l2_dr_admission_epoch
    TO rss_l2_dr_recovery_owner;
GRANT SELECT, INSERT ON TABLE public.event_l2_dr_admission_phase_receipt
    TO rss_l2_dr_recovery_owner;
GRANT SELECT, INSERT ON TABLE public.event_l2_dr_admission_resume_authorization
    TO rss_l2_dr_recovery_owner;
GRANT SELECT, INSERT ON TABLE public.event_l2_dr_admission_invalidation
    TO rss_l2_dr_recovery_owner;

CREATE FUNCTION public.rss_l2_dr_admission_pause(
    p_admission_epoch_id uuid,
    p_recovery_epoch_id uuid,
    p_tenant_id uuid,
    p_plan_digest bytea,
    p_declared_instances jsonb,
    p_requires_startup_epoch_witness boolean
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_existing public.event_l2_dr_admission_epoch%ROWTYPE;
DECLARE v_canonical_instances jsonb;
DECLARE v_declared_count integer;
BEGIN
    IF p_admission_epoch_id IS NULL OR p_admission_epoch_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_recovery_epoch_id IS NULL OR p_recovery_epoch_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_tenant_id IS NULL OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_plan_digest IS NULL OR pg_catalog.octet_length(p_plan_digest) <> 32
        OR p_requires_startup_epoch_witness IS NULL
        OR p_declared_instances IS NULL OR pg_catalog.jsonb_typeof(p_declared_instances) <> 'array'
        OR pg_catalog.jsonb_array_length(p_declared_instances) NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION 'invalid L2 DR admission pause request' USING ERRCODE = 'P2001';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_declared_instances) AS item(value)
        WHERE pg_catalog.jsonb_typeof(item.value) <> 'object'
           OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(item.value)) <> 3
           OR NOT item.value ?& ARRAY['assemblyIdentity', 'runtimePlanFingerprint', 'instanceId']
           OR pg_catalog.octet_length(item.value->>'assemblyIdentity') NOT BETWEEN 1 AND 64
           OR pg_catalog.octet_length(item.value->>'runtimePlanFingerprint') NOT BETWEEN 8 AND 256
           OR NOT (item.value->>'instanceId' ~
               '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
           OR item.value->>'instanceId' = '00000000-0000-0000-0000-000000000000'
    ) THEN
        RAISE EXCEPTION 'invalid L2 DR declared instance' USING ERRCODE = 'P2001';
    END IF;
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'assemblyIdentity', item.value->>'assemblyIdentity',
               'runtimePlanFingerprint', item.value->>'runtimePlanFingerprint',
               'instanceId', item.value->>'instanceId'
           ) ORDER BY item.value->>'assemblyIdentity', item.value->>'runtimePlanFingerprint',
                    item.value->>'instanceId'),
           pg_catalog.count(DISTINCT (
               item.value->>'assemblyIdentity', item.value->>'runtimePlanFingerprint',
               item.value->>'instanceId'
           ))::integer
    INTO v_canonical_instances, v_declared_count
    FROM pg_catalog.jsonb_array_elements(p_declared_instances) AS item(value);
    IF v_declared_count <> pg_catalog.jsonb_array_length(p_declared_instances) THEN
        RAISE EXCEPTION 'duplicate L2 DR declared instance' USING ERRCODE = 'P2001';
    END IF;
    SELECT * INTO v_existing FROM public.event_l2_dr_admission_epoch WHERE singleton FOR UPDATE;
    IF FOUND AND v_existing.admission_epoch_id = p_admission_epoch_id THEN
        IF v_existing.recovery_epoch_id IS DISTINCT FROM p_recovery_epoch_id
            OR v_existing.recovery_tenant_id IS DISTINCT FROM p_tenant_id
            OR v_existing.plan_digest IS DISTINCT FROM p_plan_digest
            OR v_existing.declared_instances IS DISTINCT FROM v_canonical_instances
            OR v_existing.requires_startup_epoch_witness IS DISTINCT FROM
                p_requires_startup_epoch_witness
        THEN
            RAISE EXCEPTION 'L2 DR admission epoch conflict' USING ERRCODE = 'P2002';
        END IF;
        RETURN;
    END IF;
    IF FOUND AND NOT v_existing.invalidated AND v_existing.phase <> 'running' THEN
        IF v_existing.phase NOT IN (
                'applied_paused', 'relay_resume_requested', 'relay_running',
                'consumer_resume_requested', 'consumer_running', 'writes_resume_requested'
            )
            OR v_existing.recovery_epoch_id IS DISTINCT FROM p_recovery_epoch_id
            OR v_existing.recovery_tenant_id IS DISTINCT FROM p_tenant_id
            OR v_existing.plan_digest IS DISTINCT FROM p_plan_digest
            OR NOT EXISTS (
                SELECT 1 FROM public.event_l2_dr_recovery_receipt receipt
                WHERE receipt.epoch_id = p_recovery_epoch_id
                  AND receipt.tenant_id = p_tenant_id
                  AND receipt.plan_digest = p_plan_digest
                  AND receipt.protocol_revision = 2
            )
        THEN
            RAISE EXCEPTION 'another L2 DR admission epoch is active' USING ERRCODE = 'P2002';
        END IF;
    END IF;
    DELETE FROM public.event_l2_dr_admission_epoch WHERE singleton;
    INSERT INTO public.event_l2_dr_admission_epoch (
        singleton, admission_epoch_id, recovery_epoch_id, recovery_tenant_id, plan_digest,
        phase, declared_instances, requires_startup_epoch_witness
    ) VALUES (
        true, p_admission_epoch_id, p_recovery_epoch_id, p_tenant_id, p_plan_digest,
        'pause_requested', v_canonical_instances, p_requires_startup_epoch_witness
    );
END;
$$;

CREATE FUNCTION public.rss_l2_dr_admission_authorize_resume(
    p_admission_epoch_id uuid,
    p_assembly_identity text,
    p_runtime_plan_fingerprint text,
    p_instance_id uuid,
    p_boot_id uuid,
    p_phase text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_epoch public.event_l2_dr_admission_epoch%ROWTYPE;
BEGIN
    SELECT * INTO v_epoch FROM public.event_l2_dr_admission_epoch
    WHERE singleton AND admission_epoch_id = p_admission_epoch_id FOR UPDATE;
    IF NOT FOUND OR v_epoch.invalidated OR v_epoch.expires_at <= pg_catalog.clock_timestamp()
        OR p_phase NOT IN ('relay_running', 'consumer_running', 'running')
    THEN
        RETURN false;
    END IF;
    IF (p_phase = 'relay_running' AND v_epoch.phase <> 'relay_resume_requested')
        OR (p_phase = 'consumer_running' AND v_epoch.phase <> 'consumer_resume_requested')
        OR (p_phase = 'running' AND v_epoch.phase <> 'writes_resume_requested')
    THEN
        RETURN EXISTS (
            SELECT 1 FROM public.event_l2_dr_admission_resume_authorization resume_auth
            WHERE resume_auth.admission_epoch_id = p_admission_epoch_id
              AND resume_auth.assembly_identity = p_assembly_identity
              AND resume_auth.runtime_plan_fingerprint = p_runtime_plan_fingerprint
              AND resume_auth.instance_id = p_instance_id
              AND resume_auth.boot_id = p_boot_id AND resume_auth.phase = p_phase
        );
    END IF;
    IF NOT v_epoch.declared_instances @> pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
        'assemblyIdentity', p_assembly_identity,
        'runtimePlanFingerprint', p_runtime_plan_fingerprint,
        'instanceId', p_instance_id::text
    )) OR EXISTS (
        SELECT 1 FROM public.event_l2_dr_admission_phase_receipt receipt
        WHERE receipt.admission_epoch_id = p_admission_epoch_id
          AND receipt.assembly_identity = p_assembly_identity
          AND receipt.runtime_plan_fingerprint = p_runtime_plan_fingerprint
          AND receipt.instance_id = p_instance_id AND receipt.boot_id <> p_boot_id
    ) THEN
        INSERT INTO public.event_l2_dr_admission_invalidation (
            admission_epoch_id, reason, assembly_identity, runtime_plan_fingerprint,
            instance_id, boot_id
        ) VALUES (
            p_admission_epoch_id,
            CASE WHEN NOT v_epoch.declared_instances @> pg_catalog.jsonb_build_array(
                pg_catalog.jsonb_build_object(
                    'assemblyIdentity', p_assembly_identity,
                    'runtimePlanFingerprint', p_runtime_plan_fingerprint,
                    'instanceId', p_instance_id::text
                )
            ) THEN 'undeclared_instance' ELSE 'boot_mismatch' END,
            p_assembly_identity, p_runtime_plan_fingerprint, p_instance_id, p_boot_id
        ) ON CONFLICT DO NOTHING;
        UPDATE public.event_l2_dr_admission_epoch SET invalidated = true,
            updated_at = pg_catalog.clock_timestamp() WHERE singleton;
        RETURN false;
    END IF;
    INSERT INTO public.event_l2_dr_admission_resume_authorization (
        admission_epoch_id, assembly_identity, runtime_plan_fingerprint, instance_id, boot_id, phase
    ) VALUES (
        p_admission_epoch_id, p_assembly_identity, p_runtime_plan_fingerprint,
        p_instance_id, p_boot_id, p_phase
    ) ON CONFLICT DO NOTHING;
    RETURN true;
END;
$$;

CREATE FUNCTION public.rss_l2_dr_admission_ack(
    p_admission_epoch_id uuid,
    p_assembly_identity text,
    p_runtime_plan_fingerprint text,
    p_instance_id uuid,
    p_boot_id uuid,
    p_phase text,
    p_required_admission_epoch_id uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_epoch public.event_l2_dr_admission_epoch%ROWTYPE;
DECLARE v_expected integer;
DECLARE v_acknowledged integer;
BEGIN
    SELECT * INTO v_epoch FROM public.event_l2_dr_admission_epoch
    WHERE singleton AND admission_epoch_id = p_admission_epoch_id FOR UPDATE;
    IF NOT FOUND OR v_epoch.invalidated THEN RETURN false; END IF;
    IF (p_phase = 'drained' AND v_epoch.phase NOT IN ('pause_requested', 'drained', 'applied_paused'))
        OR (p_phase = 'relay_running' AND v_epoch.phase NOT IN ('relay_resume_requested', 'relay_running'))
        OR (p_phase = 'consumer_running' AND v_epoch.phase NOT IN ('consumer_resume_requested', 'consumer_running'))
        OR (p_phase = 'running' AND v_epoch.phase NOT IN ('writes_resume_requested', 'running'))
        OR p_phase NOT IN ('drained', 'relay_running', 'consumer_running', 'running')
        OR (v_epoch.phase NOT IN ('pause_requested', 'running')
            AND v_epoch.expires_at <= pg_catalog.clock_timestamp())
        OR (p_required_admission_epoch_id IS NOT NULL
            AND p_required_admission_epoch_id IS DISTINCT FROM p_admission_epoch_id)
        OR (v_epoch.requires_startup_epoch_witness
            AND p_required_admission_epoch_id IS DISTINCT FROM p_admission_epoch_id)
        OR (NOT v_epoch.requires_startup_epoch_witness
            AND p_required_admission_epoch_id IS NOT NULL)
    THEN
        RETURN false;
    END IF;
    IF NOT v_epoch.declared_instances @> pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
        'assemblyIdentity', p_assembly_identity,
        'runtimePlanFingerprint', p_runtime_plan_fingerprint,
        'instanceId', p_instance_id::text
    )) THEN
        INSERT INTO public.event_l2_dr_admission_invalidation (
            admission_epoch_id, reason, assembly_identity, runtime_plan_fingerprint,
            instance_id, boot_id
        ) VALUES (
            p_admission_epoch_id, 'undeclared_instance', p_assembly_identity,
            p_runtime_plan_fingerprint, p_instance_id, p_boot_id
        ) ON CONFLICT DO NOTHING;
        UPDATE public.event_l2_dr_admission_epoch SET invalidated = true,
            updated_at = pg_catalog.clock_timestamp() WHERE singleton;
        RETURN false;
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.event_l2_dr_admission_phase_receipt r
        WHERE r.admission_epoch_id = p_admission_epoch_id
          AND r.assembly_identity = p_assembly_identity
          AND r.runtime_plan_fingerprint = p_runtime_plan_fingerprint
          AND r.instance_id = p_instance_id AND r.boot_id <> p_boot_id
    ) THEN
        INSERT INTO public.event_l2_dr_admission_invalidation (
            admission_epoch_id, reason, assembly_identity, runtime_plan_fingerprint,
            instance_id, boot_id
        ) VALUES (
            p_admission_epoch_id, 'boot_mismatch', p_assembly_identity,
            p_runtime_plan_fingerprint, p_instance_id, p_boot_id
        ) ON CONFLICT DO NOTHING;
        UPDATE public.event_l2_dr_admission_epoch SET invalidated = true,
            updated_at = pg_catalog.clock_timestamp() WHERE singleton;
        RETURN false;
    END IF;
    IF p_phase IN ('relay_running', 'consumer_running', 'running') AND NOT EXISTS (
        SELECT 1 FROM public.event_l2_dr_admission_resume_authorization resume_auth
        WHERE resume_auth.admission_epoch_id = p_admission_epoch_id
          AND resume_auth.assembly_identity = p_assembly_identity
          AND resume_auth.runtime_plan_fingerprint = p_runtime_plan_fingerprint
          AND resume_auth.instance_id = p_instance_id
          AND resume_auth.boot_id = p_boot_id AND resume_auth.phase = p_phase
    ) THEN
        RETURN false;
    END IF;
    INSERT INTO public.event_l2_dr_admission_phase_receipt (
        admission_epoch_id, assembly_identity, runtime_plan_fingerprint, instance_id, boot_id,
        required_admission_epoch_id, phase
    ) VALUES (
        p_admission_epoch_id, p_assembly_identity, p_runtime_plan_fingerprint,
        p_instance_id, p_boot_id, p_required_admission_epoch_id, p_phase
    ) ON CONFLICT DO NOTHING;
    SELECT pg_catalog.jsonb_array_length(v_epoch.declared_instances), pg_catalog.count(*)::integer
    INTO v_expected, v_acknowledged
    FROM public.event_l2_dr_admission_phase_receipt r
    WHERE r.admission_epoch_id = p_admission_epoch_id AND r.phase = p_phase;
    IF v_expected = v_acknowledged THEN
        IF p_phase = 'drained' AND v_epoch.phase = 'pause_requested' THEN
            UPDATE public.event_l2_dr_admission_epoch SET phase = CASE
                    WHEN EXISTS (
                        SELECT 1 FROM public.event_l2_dr_recovery_receipt receipt
                        WHERE receipt.epoch_id = v_epoch.recovery_epoch_id
                          AND receipt.tenant_id = v_epoch.recovery_tenant_id
                          AND receipt.plan_digest = v_epoch.plan_digest
                          AND receipt.protocol_revision = 2
                    ) THEN 'applied_paused'
                    ELSE 'drained'
                END,
                drained_at = pg_catalog.clock_timestamp(),
                expires_at = pg_catalog.clock_timestamp() + interval '15 minutes',
                updated_at = pg_catalog.clock_timestamp() WHERE singleton;
        ELSIF p_phase = 'relay_running' AND v_epoch.phase = 'relay_resume_requested' THEN
            UPDATE public.event_l2_dr_admission_epoch SET phase = 'relay_running',
                updated_at = pg_catalog.clock_timestamp() WHERE singleton;
        ELSIF p_phase = 'consumer_running' AND v_epoch.phase = 'consumer_resume_requested' THEN
            UPDATE public.event_l2_dr_admission_epoch SET phase = 'consumer_running',
                updated_at = pg_catalog.clock_timestamp() WHERE singleton;
        ELSIF p_phase = 'running' AND v_epoch.phase = 'writes_resume_requested' THEN
            UPDATE public.event_l2_dr_admission_epoch SET phase = 'running',
                updated_at = pg_catalog.clock_timestamp() WHERE singleton;
        END IF;
    END IF;
    RETURN true;
END;
$$;

CREATE FUNCTION public.rss_l2_dr_admission_request_resume(
    p_admission_epoch_id uuid,
    p_tenant_id uuid,
    p_lane text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_from text; v_to text;
BEGIN
    SELECT CASE p_lane WHEN 'relay' THEN 'applied_paused' WHEN 'consumer' THEN 'relay_running'
        WHEN 'writes' THEN 'consumer_running' ELSE NULL END,
        CASE p_lane WHEN 'relay' THEN 'relay_resume_requested'
        WHEN 'consumer' THEN 'consumer_resume_requested'
        WHEN 'writes' THEN 'writes_resume_requested' ELSE NULL END
    INTO v_from, v_to;
    IF v_from IS NULL THEN RAISE EXCEPTION 'invalid L2 DR resume lane' USING ERRCODE = 'P2003'; END IF;
    UPDATE public.event_l2_dr_admission_epoch SET phase = v_to,
        updated_at = pg_catalog.clock_timestamp()
    WHERE singleton AND admission_epoch_id = p_admission_epoch_id
      AND recovery_tenant_id = p_tenant_id AND phase = v_from
      AND NOT invalidated AND expires_at > pg_catalog.clock_timestamp();
    IF NOT FOUND THEN RAISE EXCEPTION 'L2 DR resume phase conflict' USING ERRCODE = 'P2003'; END IF;
END;
$$;

CREATE FUNCTION public.rss_l2_dr_admission_observe()
RETURNS TABLE (
    admission_epoch_id uuid, recovery_epoch_id uuid, tenant_id uuid, plan_digest bytea,
    phase text, declared_instances jsonb, acknowledged_instances jsonb,
    invalidation_evidence jsonb, invalidated boolean, expired boolean, expires_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT state.admission_epoch_id, state.recovery_epoch_id, state.recovery_tenant_id,
        state.plan_digest, state.phase, state.declared_instances,
        COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'assemblyIdentity', receipt.assembly_identity,
                'runtimePlanFingerprint', receipt.runtime_plan_fingerprint,
                'instanceId', receipt.instance_id::text,
                'bootId', receipt.boot_id::text
            ) ORDER BY receipt.assembly_identity, receipt.runtime_plan_fingerprint, receipt.instance_id)
            FROM public.event_l2_dr_admission_phase_receipt receipt
            WHERE receipt.admission_epoch_id = state.admission_epoch_id
              AND receipt.phase = CASE
                  WHEN state.phase IN ('pause_requested', 'drained', 'applied_paused') THEN 'drained'
                  WHEN state.phase IN ('relay_resume_requested', 'relay_running') THEN 'relay_running'
                  WHEN state.phase IN ('consumer_resume_requested', 'consumer_running') THEN 'consumer_running'
                  ELSE 'running'
              END
        ), '[]'::jsonb), COALESCE((
            SELECT pg_catalog.jsonb_build_object(
                'reason', rejected.reason,
                'assemblyIdentity', rejected.assembly_identity,
                'runtimePlanFingerprint', rejected.runtime_plan_fingerprint,
                'instanceId', rejected.instance_id::text,
                'bootId', rejected.boot_id::text,
                'observedAtMicros',
                    (EXTRACT(EPOCH FROM rejected.observed_at) * 1000000)::bigint
            )
            FROM public.event_l2_dr_admission_invalidation rejected
            WHERE rejected.admission_epoch_id = state.admission_epoch_id
        ), 'null'::jsonb), state.invalidated,
        COALESCE(
            state.phase <> 'running' AND state.expires_at <= pg_catalog.clock_timestamp(),
            false
        ), state.expires_at
    FROM public.event_l2_dr_admission_epoch AS state
    WHERE state.singleton
$$;

CREATE FUNCTION public.rss_l2_dr_admission_observe(
    p_admission_epoch_id uuid,
    p_tenant_id uuid
)
RETURNS TABLE (
    admission_epoch_id uuid, recovery_epoch_id uuid, tenant_id uuid, plan_digest bytea,
    phase text, declared_instances jsonb, acknowledged_instances jsonb,
    invalidation_evidence jsonb, invalidated boolean, expired boolean, expires_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT observed.*
    FROM public.rss_l2_dr_admission_observe() AS observed
    WHERE observed.admission_epoch_id = p_admission_epoch_id
      AND observed.tenant_id = p_tenant_id
$$;

CREATE FUNCTION public.rss_l2_dr_admission_record_audit(
    p_occurred_at_secs bigint,
    p_occurred_at_nanos integer,
    p_operator_subject text,
    p_target_tenant uuid,
    p_admission_epoch_id uuid,
    p_action text,
    p_stage text,
    p_outcome text,
    p_failure_reason text,
    p_request_id uuid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_occurred_at_secs < 0 OR p_occurred_at_nanos NOT BETWEEN 0 AND 999999999
        OR pg_catalog.octet_length(p_operator_subject) NOT BETWEEN 1 AND 128
        OR p_target_tenant IS NULL OR p_target_tenant = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_admission_epoch_id IS NULL OR p_admission_epoch_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_action NOT IN ('pause', 'status', 'resume-relay', 'resume-consumer', 'resume-writes')
        OR p_stage NOT IN ('start', 'finish')
        OR p_outcome NOT IN ('success', 'failure')
        OR ((p_outcome = 'failure') IS DISTINCT FROM (p_failure_reason IS NOT NULL))
        OR (p_stage = 'start' AND p_outcome <> 'success')
        OR p_request_id IS NULL OR p_request_id = '00000000-0000-0000-0000-000000000000'::uuid
    THEN
        RAISE EXCEPTION 'invalid L2 DR admission audit record' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.auth_audit_events (
        occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
        resource_kind, resource_id, action, outcome, failure_reason, request_id
    ) VALUES (
        p_occurred_at_secs, p_occurred_at_nanos, p_operator_subject, 'service', p_target_tenant,
        'eventing.l2-dr-admission', p_admission_epoch_id::text,
        'eventing.l2-dr-admission.' || p_action || '.' || p_stage,
        p_outcome, p_failure_reason, p_request_id::text
    );
END;
$$;

-- The historical executable signature is removed. Its implementation becomes a private mutation
-- kernel invoked only by the new fence-validating function in the same SQL transaction.
REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid
) FROM PUBLIC, rss_app, rss_l2_dr_recovery_executor;
ALTER FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid
) RENAME TO rss_l2_dr_recovery_apply_mutation;

CREATE FUNCTION public.rss_l2_dr_recovery_apply(
    p_epoch_id uuid, p_tenant_id uuid, p_direction text,
    p_pg_restore_point_epoch_micros bigint, p_rabbitmq_restore_point_epoch_micros bigint,
    p_change_ticket text, p_event_ids text[], p_plan_digest bytea,
    p_operator_subject text, p_start_audit_id uuid, p_admission_epoch_id uuid
) RETURNS TABLE (
    result_epoch_id uuid, result_tenant_id uuid, result_direction text,
    result_pg_restore_point_epoch_micros bigint,
    result_rabbitmq_restore_point_epoch_micros bigint, result_event_ids text[],
    result_plan_digest bytea, result_policy_revision text, result_operator_subject text,
    result_start_audit_id uuid, result_applied_at timestamptz, result_store_outcome text,
    result_already_applied boolean, result_outcome text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '5s' SET statement_timeout = '5min' AS $$
DECLARE v_epoch public.event_l2_dr_admission_epoch%ROWTYPE;
DECLARE v_same_admission_retry boolean;
DECLARE v_epoch_found boolean;
BEGIN
    SELECT * INTO v_epoch FROM public.event_l2_dr_admission_epoch
    WHERE singleton AND admission_epoch_id = p_admission_epoch_id FOR UPDATE;
    v_epoch_found := FOUND;
    SELECT EXISTS (
        SELECT 1 FROM public.event_l2_dr_recovery_receipt receipt
        WHERE receipt.epoch_id = p_epoch_id AND receipt.tenant_id = p_tenant_id
          AND receipt.plan_digest = p_plan_digest AND receipt.protocol_revision = 2
          AND receipt.admission_epoch_id = p_admission_epoch_id
    ) INTO v_same_admission_retry;
    IF NOT v_epoch_found OR v_epoch.invalidated
        OR (v_epoch.phase <> 'drained' AND NOT v_same_admission_retry)
        OR (v_epoch.phase = 'drained' AND v_epoch.expires_at <= pg_catalog.clock_timestamp())
        OR v_epoch.recovery_epoch_id IS DISTINCT FROM p_epoch_id
        OR v_epoch.recovery_tenant_id IS DISTINCT FROM p_tenant_id
        OR v_epoch.plan_digest IS DISTINCT FROM p_plan_digest
        OR pg_catalog.jsonb_array_length(v_epoch.declared_instances) <> (
            SELECT pg_catalog.count(*) FROM public.event_l2_dr_admission_phase_receipt r
            WHERE r.admission_epoch_id = p_admission_epoch_id AND r.phase = 'drained'
              AND r.required_admission_epoch_id = p_admission_epoch_id
        )
    THEN
        RAISE EXCEPTION 'L2 DR admission fence is missing, stale, or incomplete'
            USING ERRCODE = 'P2004';
    END IF;
    PERFORM pg_catalog.set_config('rss.dr_admission_epoch_id', p_admission_epoch_id::text, true);
    RETURN QUERY SELECT * FROM public.rss_l2_dr_recovery_apply_mutation(
        p_epoch_id, p_tenant_id, p_direction, p_pg_restore_point_epoch_micros,
        p_rabbitmq_restore_point_epoch_micros, p_change_ticket, p_event_ids, p_plan_digest,
        p_operator_subject, p_start_audit_id
    );
    IF v_epoch.phase = 'drained' THEN
        UPDATE public.event_l2_dr_admission_epoch SET phase = 'applied_paused',
            updated_at = pg_catalog.clock_timestamp()
        WHERE singleton AND admission_epoch_id = p_admission_epoch_id AND phase = 'drained';
        IF NOT FOUND THEN RAISE EXCEPTION 'L2 DR apply lost admission lock' USING ERRCODE = 'P2005'; END IF;
    END IF;
END;
$$;

ALTER FUNCTION public.rss_l2_dr_recovery_apply_mutation(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid
) OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid, uuid
) OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_pause(uuid, uuid, uuid, bytea, jsonb, boolean)
    OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_ack(uuid, text, text, uuid, uuid, text, uuid)
    OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_authorize_resume(uuid, text, text, uuid, uuid, text)
    OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_request_resume(uuid, uuid, text)
    OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_observe()
    OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_observe(uuid, uuid)
    OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_admission_record_audit(
    bigint, integer, text, uuid, uuid, text, text, text, text, uuid
) OWNER TO rss_l2_dr_recovery_owner;

REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_apply_mutation(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid
) FROM PUBLIC, rss_app, rss_app_read, rss_l2_dr_recovery_executor;
REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid, uuid
) FROM PUBLIC, rss_app, rss_app_read;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_pause(uuid, uuid, uuid, bytea, jsonb, boolean)
    FROM PUBLIC, rss_app, rss_app_read, rss_l2_dr_recovery_auditor;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_request_resume(uuid, uuid, text)
    FROM PUBLIC, rss_app, rss_app_read, rss_l2_dr_recovery_auditor;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_ack(uuid, text, text, uuid, uuid, text, uuid)
    FROM PUBLIC, rss_app_read, rss_l2_dr_recovery_auditor, rss_l2_dr_recovery_executor;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_authorize_resume(uuid, text, text, uuid, uuid, text)
    FROM PUBLIC, rss_app_read, rss_l2_dr_recovery_auditor, rss_l2_dr_recovery_executor;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_observe()
    FROM PUBLIC, rss_app_read, rss_l2_dr_recovery_auditor;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_observe(uuid, uuid)
    FROM PUBLIC, rss_app, rss_app_read, rss_l2_dr_recovery_auditor;
REVOKE ALL ON FUNCTION public.rss_l2_dr_admission_record_audit(
    bigint, integer, text, uuid, uuid, text, text, text, text, uuid
) FROM PUBLIC, rss_app, rss_app_read, rss_l2_dr_recovery_executor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid, uuid
) TO rss_l2_dr_recovery_executor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_admission_pause(uuid, uuid, uuid, bytea, jsonb, boolean)
    TO rss_l2_dr_recovery_executor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_admission_request_resume(uuid, uuid, text)
    TO rss_l2_dr_recovery_executor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_admission_ack(uuid, text, text, uuid, uuid, text, uuid)
    TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_admission_authorize_resume(uuid, text, text, uuid, uuid, text)
    TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_admission_observe() TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_admission_observe(uuid, uuid)
    TO rss_l2_dr_recovery_executor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_admission_record_audit(
    bigint, integer, text, uuid, uuid, text, text, text, text, uuid
) TO rss_l2_dr_recovery_auditor;
