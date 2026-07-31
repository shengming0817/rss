-- 0082_create_device_commands.sql
--
-- Durable DeviceLatent command aggregate and append-once authenticated ingress evidence.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE public.device_commands (
    tenant_id         uuid        NOT NULL,
    command_id        text        NOT NULL,
    device_id         uuid        NOT NULL,
    generation        bigint      NOT NULL,
    fence_epoch       bigint      NOT NULL,
    intent_digest     bytea       NOT NULL,
    deadline          timestamptz NOT NULL,
    state             text        NOT NULL,
    version           bigint      NOT NULL,
    queued_at         timestamptz NOT NULL,
    published_at      timestamptz,
    received_at       timestamptz,
    terminal_at       timestamptz,
    PRIMARY KEY (tenant_id, command_id),
    CONSTRAINT device_commands_desired_fk
        FOREIGN KEY (tenant_id, device_id)
        REFERENCES public.device_certificate_desired_states (tenant_id, device_id),
    CONSTRAINT device_commands_id_bounded
        CHECK (pg_catalog.octet_length(command_id) BETWEEN 1 AND 256),
    CONSTRAINT device_commands_generation_positive CHECK (generation > 0),
    CONSTRAINT device_commands_fence_positive CHECK (fence_epoch > 0),
    CONSTRAINT device_commands_intent_digest_sha256
        CHECK (pg_catalog.octet_length(intent_digest) = 32),
    CONSTRAINT device_commands_state_closed
        CHECK (state IN (
            'queued', 'published', 'received', 'applied', 'rejected',
            'timed_out', 'superseded', 'cancelled'
        )),
    CONSTRAINT device_commands_version_positive CHECK (version > 0),
    CONSTRAINT device_commands_deadline_after_queue CHECK (deadline > queued_at),
    CONSTRAINT device_commands_state_timestamp_matrix CHECK (
        (state = 'queued' AND version = 1
            AND published_at IS NULL AND received_at IS NULL AND terminal_at IS NULL)
        OR (state = 'published' AND version = 2
            AND published_at IS NOT NULL AND received_at IS NULL AND terminal_at IS NULL)
        OR (state = 'received' AND version = 3
            AND published_at IS NOT NULL AND received_at IS NOT NULL AND terminal_at IS NULL)
        OR (state = 'applied' AND version = 4
            AND published_at IS NOT NULL AND received_at IS NOT NULL AND terminal_at IS NOT NULL)
        OR (state = 'rejected' AND version = 3
            AND published_at IS NOT NULL AND received_at IS NULL AND terminal_at IS NOT NULL)
        OR (state IN ('timed_out', 'superseded', 'cancelled')
            AND terminal_at IS NOT NULL
            AND (
                (version = 2 AND published_at IS NULL AND received_at IS NULL)
                OR (version = 3 AND published_at IS NOT NULL AND received_at IS NULL)
                OR (version = 4 AND published_at IS NOT NULL AND received_at IS NOT NULL)
            ))
    ),
    CONSTRAINT device_commands_timestamps_ordered CHECK (
        (published_at IS NULL OR published_at >= queued_at)
        AND (received_at IS NULL OR (published_at IS NOT NULL AND received_at >= published_at))
        AND (
            terminal_at IS NULL
            OR terminal_at >= COALESCE(received_at, published_at, queued_at)
        )
        AND (state <> 'timed_out' OR terminal_at >= deadline)
    )
);

CREATE UNIQUE INDEX device_commands_one_active_intent
    ON public.device_commands (tenant_id, device_id, generation, intent_digest)
    WHERE state IN ('queued', 'published', 'received');

CREATE FUNCTION public.rss_device_command_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'queued' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command must be inserted in queued version one';
        END IF;
        NEW.queued_at := pg_catalog.transaction_timestamp();
    ELSE
        IF (
            NEW.tenant_id, NEW.command_id, NEW.device_id, NEW.generation,
            NEW.fence_epoch, NEW.intent_digest, NEW.deadline, NEW.queued_at
        ) IS DISTINCT FROM (
            OLD.tenant_id, OLD.command_id, OLD.device_id, OLD.generation,
            OLD.fence_epoch, OLD.intent_digest, OLD.deadline, OLD.queued_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command immutable fields cannot change';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command version must advance exactly once';
        END IF;
        IF (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)
            OR (OLD.received_at IS NOT NULL AND NEW.received_at IS DISTINCT FROM OLD.received_at)
            OR (OLD.terminal_at IS NOT NULL AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command historical timestamps are immutable';
        END IF;
        IF (NEW.published_at IS DISTINCT FROM OLD.published_at
                AND NEW.published_at IS DISTINCT FROM pg_catalog.transaction_timestamp())
            OR (NEW.received_at IS DISTINCT FROM OLD.received_at
                AND NEW.received_at IS DISTINCT FROM pg_catalog.transaction_timestamp())
            OR (NEW.terminal_at IS DISTINCT FROM OLD.terminal_at
                AND NEW.terminal_at IS DISTINCT FROM pg_catalog.transaction_timestamp())
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command transition timestamps must use transaction time';
        END IF;
        IF NOT (
            (OLD.state = 'queued' AND NEW.state IN (
                'published', 'timed_out', 'superseded', 'cancelled'
            ))
            OR (OLD.state = 'published' AND NEW.state IN (
                'received', 'rejected', 'timed_out', 'superseded', 'cancelled'
            ))
            OR (OLD.state = 'received' AND NEW.state IN (
                'applied', 'timed_out', 'superseded', 'cancelled'
            ))
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command transition is not canonical';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_command_lifecycle_guard
BEFORE INSERT OR UPDATE ON public.device_commands
FOR EACH ROW EXECUTE FUNCTION public.rss_device_command_guard();

CREATE TABLE public.device_ingress_receipts (
    tenant_id       uuid        NOT NULL,
    event_id        text        NOT NULL,
    device_id       uuid        NOT NULL,
    kind            text        NOT NULL,
    command_id      text,
    generation      bigint      NOT NULL,
    fence_epoch     bigint      NOT NULL,
    device_sequence bigint      NOT NULL,
    fingerprint     bytea       NOT NULL,
    disposition     text        NOT NULL,
    received_at     timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
    committed_at    timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT device_ingress_receipts_event_bounded
        CHECK (pg_catalog.octet_length(event_id) BETWEEN 1 AND 256),
    CONSTRAINT device_ingress_receipts_kind_closed
        CHECK (kind IN ('ack_received', 'ack_rejected', 'report')),
    CONSTRAINT device_ingress_receipts_kind_shape CHECK (
        (kind IN ('ack_received', 'ack_rejected')
            AND command_id IS NOT NULL
            AND pg_catalog.octet_length(command_id) BETWEEN 1 AND 256)
        OR (kind = 'report' AND command_id IS NULL)
    ),
    CONSTRAINT device_ingress_receipts_generation_positive CHECK (generation > 0),
    CONSTRAINT device_ingress_receipts_fence_positive CHECK (fence_epoch > 0),
    CONSTRAINT device_ingress_receipts_sequence_nonnegative CHECK (device_sequence >= 0),
    CONSTRAINT device_ingress_receipts_fingerprint_sha256
        CHECK (pg_catalog.octet_length(fingerprint) = 32),
    CONSTRAINT device_ingress_receipts_disposition_closed
        CHECK (disposition IN (
            'advanced', 'duplicate', 'late', 'rejected', 'scope_mismatch', 'out_of_order'
        )),
    CONSTRAINT device_ingress_receipts_timestamps_ordered CHECK (committed_at >= received_at)
);

ALTER TABLE public.device_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_commands
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE public.device_ingress_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_ingress_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_ingress_receipts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE
    public.device_commands,
    public.device_ingress_receipts
FROM PUBLIC, rss_app, rss_app_read;

GRANT SELECT ON TABLE
    public.device_commands,
    public.device_ingress_receipts
TO rss_app, rss_app_read;

GRANT INSERT (
    tenant_id, command_id, device_id, generation, fence_epoch,
    intent_digest, deadline, state, version
) ON public.device_commands TO rss_app;
GRANT UPDATE (
    state, version, published_at, received_at, terminal_at
) ON public.device_commands TO rss_app;

GRANT INSERT (
    tenant_id, event_id, device_id, kind, command_id, generation,
    fence_epoch, device_sequence, fingerprint, disposition
) ON public.device_ingress_receipts TO rss_app;

REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON public.device_ingress_receipts FROM rss_app, rss_app_read;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON public.device_commands FROM rss_app, rss_app_read;

REVOKE ALL ON FUNCTION public.rss_device_command_guard()
FROM PUBLIC, rss_app, rss_app_read;
