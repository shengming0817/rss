-- 0083_create_saga_step_receipts.sql
--
-- Breaking pre-GA cutover to a protected Saga receipt + Completed journal durable fact. Existing
-- journal rows cannot be proven to have an exact receipt, so this migration refuses to guess or
-- install a compatibility path.
--
-- ref: oxidecomputer/steno src/saga_log.rs@b47f830210ed26b9b0bc0aa03f5ba1708333c30c

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.saga_instances, public.saga_journal IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.saga_instances LIMIT 1)
        OR EXISTS (SELECT 1 FROM public.saga_journal LIMIT 1)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot install saga receipts while saga durable rows exist';
    END IF;
END
$$;

ALTER TABLE public.saga_instances
    ADD COLUMN terminal_at timestamptz,
    ADD CONSTRAINT saga_instances_terminal_time_consistent CHECK (
        (status IN ('succeeded', 'compensated', 'failed')) = (terminal_at IS NOT NULL)
    ),
    ADD CONSTRAINT saga_instances_exact_identity_unique UNIQUE (
        tenant_id,
        saga_id,
        owner,
        contract_id,
        definition_version,
        definition_schema_digest,
        action_registry_generation
    );

CREATE FUNCTION public.rss_saga_terminal_at_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.status IN ('succeeded', 'compensated', 'failed') THEN
        IF TG_OP = 'INSERT' OR OLD.status NOT IN ('succeeded', 'compensated', 'failed') THEN
            NEW.terminal_at := pg_catalog.clock_timestamp();
        ELSE
            NEW.terminal_at := OLD.terminal_at;
        END IF;
    ELSE
        NEW.terminal_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER saga_instances_terminal_at_guard
BEFORE INSERT OR UPDATE ON public.saga_instances
FOR EACH ROW EXECUTE FUNCTION public.rss_saga_terminal_at_guard();

REVOKE ALL ON FUNCTION public.rss_saga_terminal_at_guard() FROM PUBLIC;
REVOKE UPDATE (terminal_at) ON public.saga_instances FROM rss_app;

CREATE TABLE public.saga_step_receipts (
    tenant_id                     uuid        NOT NULL,
    saga_id                       uuid        NOT NULL,
    owner                         text        NOT NULL,
    contract_id                   text        NOT NULL,
    definition_version            text        NOT NULL,
    definition_schema_digest      text        NOT NULL,
    action_registry_generation    text        NOT NULL,
    step_name                     text        NOT NULL,
    effect_key                    bytea       NOT NULL,
    receipt_schema                text        NOT NULL,
    format_version                smallint    NOT NULL,
    ciphertext                    bytea       NOT NULL,
    key_ref                       text        NOT NULL,
    content_hmac_key_id           text        NOT NULL,
    content_hmac                  bytea       NOT NULL,
    successful_attempt            integer     NOT NULL,
    completed_seq                 bigint      NOT NULL,
    committed_at                  timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (
        tenant_id,
        saga_id,
        owner,
        contract_id,
        definition_version,
        definition_schema_digest,
        action_registry_generation,
        step_name
    ),
    CONSTRAINT saga_step_receipts_instance_fk FOREIGN KEY (
        tenant_id,
        saga_id,
        owner,
        contract_id,
        definition_version,
        definition_schema_digest,
        action_registry_generation
    ) REFERENCES public.saga_instances (
        tenant_id,
        saga_id,
        owner,
        contract_id,
        definition_version,
        definition_schema_digest,
        action_registry_generation
    ) ON DELETE CASCADE,
    CONSTRAINT saga_step_receipts_completed_journal_fk FOREIGN KEY (
        tenant_id,
        saga_id,
        completed_seq
    ) REFERENCES public.saga_journal (tenant_id, saga_id, seq)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT saga_step_receipts_effect_unique UNIQUE (tenant_id, effect_key),
    CONSTRAINT saga_step_receipts_completed_seq_unique UNIQUE (
        tenant_id, saga_id, completed_seq
    ),
    CONSTRAINT saga_step_receipts_owner_valid CHECK (
        pg_catalog.octet_length(owner) BETWEEN 1 AND 128
    ),
    CONSTRAINT saga_step_receipts_contract_valid CHECK (
        pg_catalog.octet_length(contract_id) BETWEEN 1 AND 256
    ),
    CONSTRAINT saga_step_receipts_definition_version_valid CHECK (
        definition_version ~ '^v[1-9][0-9]*$'
    ),
    CONSTRAINT saga_step_receipts_definition_schema_valid CHECK (
        definition_schema_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT saga_step_receipts_action_generation_valid CHECK (
        action_registry_generation ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT saga_step_receipts_step_valid CHECK (
        pg_catalog.octet_length(step_name) BETWEEN 1 AND 128
        AND step_name ~ '^[A-Za-z_][A-Za-z0-9_]*$'
    ),
    CONSTRAINT saga_step_receipts_effect_key_width CHECK (
        pg_catalog.octet_length(effect_key) = 32
    ),
    CONSTRAINT saga_step_receipts_schema_valid CHECK (
        pg_catalog.octet_length(receipt_schema) BETWEEN 1 AND 256
        AND receipt_schema ~ '^[A-Za-z0-9_.-]+$'
    ),
    CONSTRAINT saga_step_receipts_format_v1 CHECK (format_version = 1),
    CONSTRAINT saga_step_receipts_ciphertext_nonempty CHECK (
        pg_catalog.octet_length(ciphertext) > 0
    ),
    CONSTRAINT saga_step_receipts_key_ref_valid CHECK (
        pg_catalog.octet_length(key_ref) BETWEEN 3 AND 512
    ),
    CONSTRAINT saga_step_receipts_hmac_key_id_valid CHECK (
        pg_catalog.octet_length(content_hmac_key_id) BETWEEN 1 AND 64
        AND content_hmac_key_id ~ '^[A-Za-z0-9._-]+$'
    ),
    CONSTRAINT saga_step_receipts_hmac_width CHECK (
        pg_catalog.octet_length(content_hmac) = 32
    ),
    CONSTRAINT saga_step_receipts_attempt_positive CHECK (successful_attempt > 0),
    CONSTRAINT saga_step_receipts_completed_seq_nonnegative CHECK (completed_seq >= 0)
);

CREATE FUNCTION public.rss_assert_saga_receipt_has_completed()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.saga_journal AS journal
        WHERE journal.tenant_id = NEW.tenant_id
          AND journal.saga_id = NEW.saga_id
          AND journal.seq = NEW.completed_seq
          AND journal.step_name = NEW.step_name
          AND journal.status = 'completed'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'saga receipt requires exact completed journal row';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.rss_assert_saga_completed_has_receipt()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.status = 'completed' AND NOT EXISTS (
        SELECT 1
        FROM public.saga_step_receipts AS receipt
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.saga_id = NEW.saga_id
          AND receipt.completed_seq = NEW.seq
          AND receipt.step_name = NEW.step_name
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'saga completed journal row requires exact receipt';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER saga_receipt_requires_completed
AFTER INSERT OR UPDATE ON public.saga_step_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.rss_assert_saga_receipt_has_completed();

CREATE CONSTRAINT TRIGGER saga_completed_requires_receipt
AFTER INSERT OR UPDATE ON public.saga_journal
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.rss_assert_saga_completed_has_receipt();

REVOKE ALL ON FUNCTION public.rss_assert_saga_receipt_has_completed() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_assert_saga_completed_has_receipt() FROM PUBLIC;

ALTER TABLE public.saga_step_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.saga_step_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.saga_step_receipts
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

REVOKE ALL ON TABLE public.saga_step_receipts FROM PUBLIC, rss_app, rss_app_read;
GRANT SELECT ON TABLE public.saga_step_receipts TO rss_app;
GRANT INSERT (
    tenant_id,
    saga_id,
    owner,
    contract_id,
    definition_version,
    definition_schema_digest,
    action_registry_generation,
    step_name,
    effect_key,
    receipt_schema,
    format_version,
    ciphertext,
    key_ref,
    content_hmac_key_id,
    content_hmac,
    successful_attempt,
    completed_seq
) ON public.saga_step_receipts TO rss_app;
GRANT SELECT ON TABLE public.saga_step_receipts TO rss_app_read;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.saga_step_receipts FROM rss_app, rss_app_read;
REVOKE INSERT (committed_at) ON public.saga_step_receipts FROM rss_app, rss_app_read;

CREATE INDEX saga_instances_terminal_retention_idx
    ON public.saga_instances (terminal_at, tenant_id, saga_id)
    WHERE status IN ('succeeded', 'compensated', 'failed');

DO $$
DECLARE
    maintenance_oid oid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_saga_receipt_maintenance'
    ) THEN
        CREATE ROLE rss_saga_receipt_maintenance
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
    ELSE
        ALTER ROLE rss_saga_receipt_maintenance
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
    END IF;

    SELECT oid INTO STRICT maintenance_oid
    FROM pg_catalog.pg_roles
    WHERE rolname = 'rss_saga_receipt_maintenance';
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = maintenance_oid OR membership.member = maintenance_oid
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'rss_saga_receipt_maintenance must have no role memberships';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO rss_saga_receipt_maintenance;
REVOKE ALL ON TABLE public.saga_instances FROM rss_saga_receipt_maintenance;
-- UPDATE is required by SELECT ... FOR UPDATE; the NOLOGIN role is reachable only through the
-- zero-argument fixed-policy function below.
GRANT SELECT, UPDATE, DELETE ON TABLE public.saga_instances TO rss_saga_receipt_maintenance;

CREATE FUNCTION public.rss_sweep_terminal_sagas()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
    observed_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
    WITH expired AS (
        SELECT tenant_id, saga_id
        FROM public.saga_instances
        WHERE status IN ('succeeded', 'compensated', 'failed')
          AND terminal_at < observed_at - interval '30 days'
          AND (lease_token IS NULL OR expires_at <= observed_at)
        ORDER BY terminal_at, tenant_id, saga_id
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    ),
    deleted AS (
        DELETE FROM public.saga_instances AS instance
        USING expired
        WHERE instance.tenant_id = expired.tenant_id
          AND instance.saga_id = expired.saga_id
        RETURNING 1
    )
    SELECT pg_catalog.count(*) INTO deleted_rows FROM deleted;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION public.rss_sweep_terminal_sagas() OWNER TO rss_saga_receipt_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_terminal_sagas() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_sweep_terminal_sagas() TO rss_app;
