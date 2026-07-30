-- 0081_create_device_certificate_states.sql
--
-- Tenant/device-scoped desired, reported high-water, and closed reconcile-condition authority.
-- Command, ingress-receipt, idempotency-operation, target, and scheduler wake state intentionally
-- remain outside this migration.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE public.device_certificate_desired_states (
    tenant_id            uuid        NOT NULL,
    device_id            uuid        NOT NULL,
    generation           bigint      NOT NULL,
    policy_hash          bytea       NOT NULL,
    validity_seconds     integer     NOT NULL,
    renew_before_seconds integer     NOT NULL,
    client_auth          boolean     NOT NULL,
    server_auth          boolean     NOT NULL,
    sans                 text[]      NOT NULL,
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_id),
    CONSTRAINT device_certificate_desired_generation_positive
        CHECK (generation > 0),
    CONSTRAINT device_certificate_desired_policy_hash_sha256
        CHECK (pg_catalog.octet_length(policy_hash) = 32),
    CONSTRAINT device_certificate_desired_validity_bounded
        CHECK (validity_seconds BETWEEN 300 AND 31536000),
    CONSTRAINT device_certificate_desired_renew_before_bounded
        CHECK (renew_before_seconds BETWEEN 60 AND 31535999),
    CONSTRAINT device_certificate_desired_renew_before_validity
        CHECK (renew_before_seconds < validity_seconds),
    CONSTRAINT device_certificate_desired_key_usages_nonempty
        CHECK (client_auth OR server_auth),
    CONSTRAINT device_certificate_desired_sans_bounded
        CHECK (
            pg_catalog.cardinality(sans) BETWEEN 0 AND 32
            AND pg_catalog.array_position(sans, NULL) IS NULL
        ),
    CONSTRAINT device_certificate_desired_timestamps_ordered
        CHECK (created_at <= updated_at)
);

CREATE TABLE public.device_certificate_reported_states (
    tenant_id            uuid        NOT NULL,
    device_id            uuid        NOT NULL,
    observed_generation  bigint      NOT NULL,
    fence_epoch          bigint      NOT NULL,
    state_hash           bytea       NOT NULL,
    artifact_digest      bytea       NOT NULL,
    report_envelope_id   text        NOT NULL,
    device_sequence      bigint      NOT NULL,
    expires_at           timestamptz,
    device_observed_at   timestamptz,
    received_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_id),
    CONSTRAINT device_certificate_reported_desired_fk
        FOREIGN KEY (tenant_id, device_id)
        REFERENCES public.device_certificate_desired_states (tenant_id, device_id),
    CONSTRAINT device_certificate_reported_generation_positive
        CHECK (observed_generation > 0),
    CONSTRAINT device_certificate_reported_fence_positive
        CHECK (fence_epoch > 0),
    CONSTRAINT device_certificate_reported_state_hash_sha256
        CHECK (pg_catalog.octet_length(state_hash) = 32),
    CONSTRAINT device_certificate_reported_artifact_digest_sha256
        CHECK (pg_catalog.octet_length(artifact_digest) = 32),
    CONSTRAINT device_certificate_reported_envelope_bounded
        CHECK (
            pg_catalog.octet_length(report_envelope_id) BETWEEN 1 AND 256
        ),
    CONSTRAINT device_certificate_reported_sequence_nonnegative
        CHECK (device_sequence >= 0)
);

CREATE TABLE public.device_certificate_conditions (
    tenant_id           uuid        NOT NULL,
    device_id           uuid        NOT NULL,
    condition_type      text        NOT NULL,
    status              text        NOT NULL,
    reason              text        NOT NULL,
    observed_generation bigint,
    last_transition_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_id, condition_type),
    CONSTRAINT device_certificate_conditions_desired_fk
        FOREIGN KEY (tenant_id, device_id)
        REFERENCES public.device_certificate_desired_states (tenant_id, device_id),
    CONSTRAINT device_certificate_conditions_type_closed
        CHECK (condition_type IN (
            'Ready', 'Reconciling', 'PendingDevice',
            'Degraded', 'Quarantined', 'Deleting'
        )),
    CONSTRAINT device_certificate_conditions_status_closed
        CHECK (status IN ('True', 'False', 'Unknown')),
    CONSTRAINT device_certificate_conditions_observed_positive
        CHECK (observed_generation IS NULL OR observed_generation > 0),
    CONSTRAINT device_certificate_conditions_ready_not_true
        CHECK (condition_type <> 'Ready' OR status <> 'True'),
    CONSTRAINT device_certificate_conditions_reason_closed
        CHECK (
            (condition_type = 'Ready' AND reason IN (
                'StateMatches', 'StateDrift', 'AwaitingDevice', 'CommandRejected',
                'CommandTimedOut', 'ProtocolViolation', 'ArtifactUnavailable',
                'TransportUnavailable'
            ))
            OR (condition_type = 'Reconciling' AND reason IN (
                'DesiredAccepted', 'CommandQueued', 'DeviceReported', 'StateDrift'
            ))
            OR (condition_type = 'PendingDevice' AND reason IN (
                'CommandQueued', 'AwaitingDevice', 'CommandTimedOut', 'TransportUnavailable'
            ))
            OR (condition_type = 'Degraded' AND reason IN (
                'CommandRejected', 'CommandTimedOut', 'ProtocolViolation',
                'ArtifactUnavailable', 'TransportUnavailable'
            ))
            OR (condition_type = 'Quarantined' AND reason IN (
                'ProtocolViolation', 'QuarantinedByOperator'
            ))
            OR (condition_type = 'Deleting' AND reason IN (
                'DeletionPending', 'DeletionComplete'
            ))
        )
);

CREATE FUNCTION public.rss_device_certificate_desired_guard()
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
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.generation <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'initial device certificate desired generation must be one';
        END IF;
        NEW.created_at := pg_catalog.clock_timestamp();
    ELSE
        IF NEW.tenant_id <> OLD.tenant_id
            OR NEW.device_id <> OLD.device_id
            OR NEW.created_at <> OLD.created_at
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate desired identity is immutable';
        END IF;
        IF NEW.generation <> OLD.generation + 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate desired generation must advance exactly once';
        END IF;
    END IF;

    IF pg_catalog.cardinality(NEW.sans) NOT BETWEEN 0 AND 32 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate SAN count is outside bounds';
    END IF;
    previous := NULL;
    FOREACH item IN ARRAY NEW.sans LOOP
        IF item IS NULL OR pg_catalog.char_length(item) NOT BETWEEN 1 AND 253 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate SAN length is outside bounds';
        END IF;

        first_codepoint := pg_catalog.ascii(pg_catalog.substr(item, 1, 1));
        last_codepoint := pg_catalog.ascii(
            pg_catalog.substr(item, pg_catalog.char_length(item), 1)
        );
        IF first_codepoint IN (9, 10, 11, 12, 13, 32, 133, 160, 5760, 8232, 8233, 8239, 8287, 12288)
            OR first_codepoint BETWEEN 8192 AND 8202
            OR last_codepoint IN (9, 10, 11, 12, 13, 32, 133, 160, 5760, 8232, 8233, 8239, 8287, 12288)
            OR last_codepoint BETWEEN 8192 AND 8202
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate SAN must be trimmed';
        END IF;

        FOR character_index IN 1..pg_catalog.char_length(item) LOOP
            codepoint := pg_catalog.ascii(pg_catalog.substr(item, character_index, 1));
            IF codepoint BETWEEN 0 AND 31 OR codepoint BETWEEN 127 AND 159 THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'device certificate SAN must not contain control characters';
            END IF;
        END LOOP;

        IF previous IS NOT NULL AND previous COLLATE "C" >= item COLLATE "C" THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate SANs must be C-sorted and unique';
        END IF;
        previous := item;
    END LOOP;

    encoded := pg_catalog.convert_to(
        'rss.deviceloop.device-certificate-policy.v1', 'UTF8'
    ) || pg_catalog.decode('00', 'hex');
    encoded := encoded || pg_catalog.int4send(NEW.validity_seconds);
    encoded := encoded || pg_catalog.int4send(NEW.renew_before_seconds);
    encoded := encoded || pg_catalog.int4send(
        NEW.client_auth::integer + NEW.server_auth::integer
    );
    IF NEW.client_auth THEN
        item := 'clientAuth';
        encoded := encoded
            || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(item, 'UTF8')))
            || pg_catalog.convert_to(item, 'UTF8');
    END IF;
    IF NEW.server_auth THEN
        item := 'serverAuth';
        encoded := encoded
            || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(item, 'UTF8')))
            || pg_catalog.convert_to(item, 'UTF8');
    END IF;
    encoded := encoded || pg_catalog.int4send(pg_catalog.cardinality(NEW.sans));
    FOREACH item IN ARRAY NEW.sans LOOP
        encoded := encoded
            || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(item, 'UTF8')))
            || pg_catalog.convert_to(item, 'UTF8');
    END LOOP;
    NEW.policy_hash := pg_catalog.sha256(encoded);
    NEW.updated_at := pg_catalog.clock_timestamp();
    IF TG_OP = 'INSERT' THEN
        NEW.created_at := NEW.updated_at;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_certificate_desired_monotonic
BEFORE INSERT OR UPDATE ON public.device_certificate_desired_states
FOR EACH ROW EXECUTE FUNCTION public.rss_device_certificate_desired_guard();

CREATE FUNCTION public.rss_device_certificate_reported_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    desired_generation bigint;
    character_index integer;
    codepoint integer;
    first_codepoint integer;
    last_codepoint integer;
BEGIN
    first_codepoint := pg_catalog.ascii(pg_catalog.substr(NEW.report_envelope_id, 1, 1));
    last_codepoint := pg_catalog.ascii(
        pg_catalog.substr(
            NEW.report_envelope_id,
            pg_catalog.char_length(NEW.report_envelope_id),
            1
        )
    );
    IF first_codepoint IN (9, 10, 11, 12, 13, 32, 133, 160, 5760, 8232, 8233, 8239, 8287, 12288)
        OR first_codepoint BETWEEN 8192 AND 8202
        OR last_codepoint IN (9, 10, 11, 12, 13, 32, 133, 160, 5760, 8232, 8233, 8239, 8287, 12288)
        OR last_codepoint BETWEEN 8192 AND 8202
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate report envelope must be trimmed';
    END IF;

    FOR character_index IN 1..pg_catalog.char_length(NEW.report_envelope_id) LOOP
        codepoint := pg_catalog.ascii(
            pg_catalog.substr(NEW.report_envelope_id, character_index, 1)
        );
        IF codepoint BETWEEN 0 AND 31 OR codepoint BETWEEN 127 AND 159 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate report envelope must not contain control characters';
        END IF;
    END LOOP;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.tenant_id <> OLD.tenant_id OR NEW.device_id <> OLD.device_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate reported identity is immutable';
        END IF;
        IF (
            NEW.observed_generation, NEW.fence_epoch, NEW.state_hash,
            NEW.artifact_digest, NEW.report_envelope_id, NEW.device_sequence,
            NEW.expires_at, NEW.device_observed_at
        ) IS NOT DISTINCT FROM (
            OLD.observed_generation, OLD.fence_epoch, OLD.state_hash,
            OLD.artifact_digest, OLD.report_envelope_id, OLD.device_sequence,
            OLD.expires_at, OLD.device_observed_at
        ) THEN
            RETURN NULL;
        END IF;
        IF NEW.observed_generation <= OLD.observed_generation
            OR NEW.device_sequence <= OLD.device_sequence
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate reported generation and sequence must advance';
        END IF;
    END IF;

    SELECT desired.generation
    INTO desired_generation
    FROM public.device_certificate_desired_states AS desired
    WHERE desired.tenant_id = NEW.tenant_id
      AND desired.device_id = NEW.device_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device certificate reported state has no desired authority';
    END IF;
    IF NEW.observed_generation > desired_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate reported generation exceeds desired generation';
    END IF;

    NEW.received_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_certificate_reported_monotonic
BEFORE INSERT OR UPDATE ON public.device_certificate_reported_states
FOR EACH ROW EXECUTE FUNCTION public.rss_device_certificate_reported_guard();

CREATE FUNCTION public.rss_device_certificate_condition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    desired_generation bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.tenant_id <> OLD.tenant_id
            OR NEW.device_id <> OLD.device_id
            OR NEW.condition_type <> OLD.condition_type
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate condition identity is immutable';
        END IF;
        IF (NEW.status, NEW.reason, NEW.observed_generation)
            IS NOT DISTINCT FROM (OLD.status, OLD.reason, OLD.observed_generation)
        THEN
            RETURN NULL;
        END IF;
    END IF;

    SELECT desired.generation
    INTO desired_generation
    FROM public.device_certificate_desired_states AS desired
    WHERE desired.tenant_id = NEW.tenant_id
      AND desired.device_id = NEW.device_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device certificate condition has no desired authority';
    END IF;
    IF NEW.observed_generation IS NOT NULL
        AND NEW.observed_generation > desired_generation
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate condition generation exceeds desired generation';
    END IF;

    NEW.last_transition_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_certificate_condition_transition
BEFORE INSERT OR UPDATE ON public.device_certificate_conditions
FOR EACH ROW EXECUTE FUNCTION public.rss_device_certificate_condition_guard();

ALTER TABLE public.device_certificate_desired_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_certificate_desired_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_certificate_desired_states
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE public.device_certificate_reported_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_certificate_reported_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_certificate_reported_states
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE public.device_certificate_conditions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_certificate_conditions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_certificate_conditions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE
    public.device_certificate_desired_states,
    public.device_certificate_reported_states,
    public.device_certificate_conditions
FROM PUBLIC, rss_app, rss_app_read;

GRANT SELECT ON TABLE
    public.device_certificate_desired_states,
    public.device_certificate_reported_states,
    public.device_certificate_conditions
TO rss_app, rss_app_read;

GRANT INSERT (
    tenant_id, device_id, generation, validity_seconds,
    renew_before_seconds, client_auth, server_auth, sans
) ON public.device_certificate_desired_states TO rss_app;
GRANT UPDATE (
    generation, validity_seconds, renew_before_seconds, client_auth, server_auth, sans
) ON public.device_certificate_desired_states TO rss_app;

GRANT INSERT (
    tenant_id, device_id, observed_generation, fence_epoch, state_hash,
    artifact_digest, report_envelope_id, device_sequence,
    expires_at, device_observed_at
) ON public.device_certificate_reported_states TO rss_app;
GRANT UPDATE (
    observed_generation, fence_epoch, state_hash, artifact_digest,
    report_envelope_id, device_sequence, expires_at, device_observed_at
) ON public.device_certificate_reported_states TO rss_app;

GRANT INSERT (
    tenant_id, device_id, condition_type, status, reason, observed_generation
) ON public.device_certificate_conditions TO rss_app;
GRANT UPDATE (status, reason, observed_generation)
    ON public.device_certificate_conditions TO rss_app;

REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE
    public.device_certificate_desired_states,
    public.device_certificate_reported_states,
    public.device_certificate_conditions
FROM rss_app, rss_app_read;

REVOKE ALL ON FUNCTION
    public.rss_device_certificate_desired_guard(),
    public.rss_device_certificate_reported_guard(),
    public.rss_device_certificate_condition_guard()
FROM PUBLIC, rss_app, rss_app_read;
