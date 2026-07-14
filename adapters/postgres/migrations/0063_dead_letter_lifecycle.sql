-- 0063_dead_letter_lifecycle.sql
--
-- Breaking pre-GA cutover from a mutable hot-retention sweep to an archive-before-purge DLX
-- lifecycle. Existing v1/v2 ciphertext cannot authenticate the v3 replay capsule, so the cutover
-- refuses to guess, backfill, dual-read, or retain a compatibility decoder.
--
-- ref: spring-projects/spring-modulith spring-modulith-events/spring-modulith-events-jdbc/src/main/java/org/springframework/modulith/events/jdbc/JdbcEventPublicationRepositoryV2.java@c4f6d51365bdb7f943327392a9cd4e828a58af0f

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.dead_letter LIMIT 1) THEN
        RAISE EXCEPTION 'dead_letter must be empty before enabling DLX lifecycle v3; automatic legacy disposal is forbidden';
    END IF;
END
$$;

DROP FUNCTION IF EXISTS public.rss_sweep_dead_letter(bigint);
REVOKE ALL PRIVILEGES ON public.dead_letter FROM rss_dead_letter_maintenance;
DROP ROLE IF EXISTS rss_dead_letter_maintenance;

ALTER TABLE public.dead_letter
    DROP CONSTRAINT chk_dead_letter_tenant_required,
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN source_kind DROP DEFAULT,
    DROP COLUMN original_entry,
    DROP COLUMN original_entry_key_ref,
    DROP COLUMN original_entry_payload_len,
    DROP COLUMN original_entry_encoding,
    DROP COLUMN metadata,
    ADD COLUMN replay_capsule jsonb NOT NULL,
    ADD COLUMN replay_capsule_key_ref text NOT NULL,
    ADD COLUMN replay_capsule_encoding text NOT NULL,
    ADD COLUMN payload_len bigint NOT NULL,
    ADD COLUMN metadata_digest bytea NOT NULL,
    ADD COLUMN archive_claim_token uuid,
    ADD COLUMN archive_lease_until timestamptz,
    ADD COLUMN archive_next_attempt_at timestamptz NOT NULL DEFAULT '-infinity',
    ADD COLUMN archive_failure_count int NOT NULL DEFAULT 0,
    ADD COLUMN archive_last_failure_reason text,
    ADD COLUMN archive_quarantined_at timestamptz,
    ADD CONSTRAINT chk_dead_letter_replay_capsule_ciphertext_only CHECK (
        jsonb_typeof(replay_capsule) = 'object'
        AND replay_capsule ? 'ciphertext'
        AND NOT (replay_capsule ? 'bytes')
        AND NOT (replay_capsule ? 'payload')
        AND NOT (replay_capsule ? 'metadata')
    ),
    ADD CONSTRAINT chk_dead_letter_replay_capsule_encoding CHECK (
        replay_capsule_encoding = 'key-provider-v3'
    ),
    ADD CONSTRAINT chk_dead_letter_payload_len_nonnegative CHECK (payload_len >= 0),
    ADD CONSTRAINT chk_dead_letter_metadata_digest_sha256 CHECK (
        octet_length(metadata_digest) = 32
    ),
    ADD CONSTRAINT chk_dead_letter_archive_lease_pair CHECK (
        (archive_claim_token IS NULL) = (archive_lease_until IS NULL)
    ),
    ADD CONSTRAINT chk_dead_letter_archive_failure_count CHECK (archive_failure_count >= 0),
    ADD CONSTRAINT chk_dead_letter_archive_quarantine CHECK (
        archive_quarantined_at IS NULL
        OR (archive_claim_token IS NULL AND archive_lease_until IS NULL)
    ),
    ADD CONSTRAINT chk_dead_letter_archive_failure_reason CHECK (
        archive_last_failure_reason IS NULL OR archive_last_failure_reason IN (
            'provider_unavailable', 'provider_timeout', 'object_missing', 'version_drift',
            'invalid_persisted_data', 'invalid_archive_format', 'size_limit_exceeded',
            'key_not_found', 'key_forbidden', 'key_rejected', 'key_mismatch',
            'checksum_mismatch', 'canonical_mismatch', 'retention_invalid', 'cas_rejected',
            'arithmetic_overflow', 'unexpected_provider_response', 'internal_invariant'
        )
    ),
    ADD CONSTRAINT uq_dead_letter_tenant_id UNIQUE (tenant_id, id);

DROP INDEX IF EXISTS idx_dead_letter_sweep;
CREATE INDEX idx_dead_letter_archive_order
    ON public.dead_letter (archive_next_attempt_at, first_attempt_at, id)
    WHERE archive_quarantined_at IS NULL;
CREATE INDEX idx_dead_letter_verified_purge
    ON public.dead_letter (last_attempt_at, id);

CREATE TABLE public.dead_letter_archive_receipts (
    tenant_id uuid NOT NULL,
    dead_letter_id uuid NOT NULL,
    object_key text NOT NULL CHECK (
        char_length(object_key) BETWEEN 1 AND 1024
        AND object_key = btrim(object_key)
        AND object_key !~ '[[:cntrl:]]'
    ),
    object_version_id text NOT NULL CHECK (
        octet_length(object_version_id) BETWEEN 1 AND 1024
        AND object_version_id = btrim(object_version_id)
        AND object_version_id !~ '[[:cntrl:]]'
    ),
    checksum_sha256 bytea NOT NULL CHECK (octet_length(checksum_sha256) = 32),
    archive_key_ref text NOT NULL CHECK (
        char_length(archive_key_ref) BETWEEN 1 AND 1024
        AND archive_key_ref = btrim(archive_key_ref)
        AND archive_key_ref !~ '[[:cntrl:]]'
    ),
    object_lock_mode text NOT NULL CHECK (object_lock_mode = 'COMPLIANCE'),
    object_lock_retain_until timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    reconcile_after timestamptz NOT NULL,
    CONSTRAINT chk_dead_letter_archive_receipt_minimum_retention CHECK (
        object_lock_retain_until > verified_at + interval '30 days'
    ),
    PRIMARY KEY (tenant_id, dead_letter_id),
    UNIQUE (object_key)
);

CREATE INDEX idx_dead_letter_archive_receipts_expiry
    ON public.dead_letter_archive_receipts (reconcile_after, dead_letter_id);

ALTER TABLE public.dead_letter_archive_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dead_letter_archive_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.dead_letter_archive_receipts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON public.dead_letter_archive_receipts FROM PUBLIC;
REVOKE ALL ON public.dead_letter_archive_receipts FROM rss_app;
REVOKE UPDATE, DELETE ON public.dead_letter FROM rss_app;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'rss_dlx_archiver') THEN
        CREATE ROLE rss_dlx_archiver NOLOGIN NOBYPASSRLS NOSUPERUSER
            NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'rss_dlx_verifier') THEN
        CREATE ROLE rss_dlx_verifier NOLOGIN NOBYPASSRLS NOSUPERUSER
            NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'rss_dlx_purger') THEN
        CREATE ROLE rss_dlx_purger NOLOGIN NOBYPASSRLS NOSUPERUSER
            NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname IN ('rss_dlx_archiver', 'rss_dlx_verifier', 'rss_dlx_purger')
          AND (
              rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication
              OR rolinherit
          )
    ) THEN
        RAISE EXCEPTION 'DLX workload role has forbidden role attributes';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS lifecycle_role
          ON lifecycle_role.oid IN (membership.roleid, membership.member)
        WHERE lifecycle_role.rolname IN (
            'rss_dlx_archiver', 'rss_dlx_verifier', 'rss_dlx_purger'
        )
    ) THEN
        RAISE EXCEPTION 'DLX workload roles must have no role memberships';
    END IF;

    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'rss_dlx_lifecycle_owner') THEN
        CREATE ROLE rss_dlx_lifecycle_owner NOLOGIN BYPASSRLS NOSUPERUSER
            NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    ELSIF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname = 'rss_dlx_lifecycle_owner'
          AND (
              rolcanlogin OR NOT rolbypassrls OR rolsuper OR rolcreatedb OR rolcreaterole
              OR rolreplication OR rolinherit
          )
    ) THEN
        RAISE EXCEPTION 'pre-existing rss_dlx_lifecycle_owner has forbidden role attributes';
    END IF;


    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid IN (membership.roleid, membership.member)
        WHERE owner_role.rolname = 'rss_dlx_lifecycle_owner'
    ) THEN
        RAISE EXCEPTION 'rss_dlx_lifecycle_owner must have no role memberships';
    END IF;
END
$$;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM rss_dlx_archiver;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM rss_dlx_archiver;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM rss_dlx_archiver;
REVOKE CREATE ON SCHEMA public FROM rss_dlx_archiver;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM rss_dlx_verifier;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM rss_dlx_verifier;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM rss_dlx_verifier;
REVOKE CREATE ON SCHEMA public FROM rss_dlx_verifier;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM rss_dlx_purger;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM rss_dlx_purger;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM rss_dlx_purger;
REVOKE CREATE ON SCHEMA public FROM rss_dlx_purger;
GRANT USAGE ON SCHEMA public TO rss_dlx_archiver, rss_dlx_verifier, rss_dlx_purger;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- UPDATE is required by PostgreSQL for SELECT ... FOR UPDATE SKIP LOCKED; the fixed functions do
-- not expose an UPDATE statement or accept mutable row fields.
GRANT SELECT, UPDATE, DELETE ON public.dead_letter TO rss_dlx_lifecycle_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dead_letter_archive_receipts TO rss_dlx_lifecycle_owner;
-- This immutable helper participates in the dead_letter CHECK/index predicate installed by 0040.
-- PUBLIC execution is removed above, so both the HOT writer and lifecycle definer need an explicit
-- grant; neither grant widens the lifecycle SQL surface.
GRANT EXECUTE ON FUNCTION public.rss_projection_dead_letter_source_kind()
    TO rss_app, rss_dlx_lifecycle_owner;

CREATE FUNCTION public.rss_dlx_archive_backlog()
RETURNS TABLE(pending_depth bigint, oldest_age_seconds bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT count(*)::bigint,
           COALESCE(
               GREATEST(
                   0,
                   EXTRACT(EPOCH FROM (now() - min(d.first_attempt_at)))::bigint
               ),
               0
           )
    FROM public.dead_letter AS d
    WHERE d.archive_quarantined_at IS NULL
      AND NOT EXISTS (
        SELECT 1
        FROM public.dead_letter_archive_receipts AS receipt
        WHERE receipt.tenant_id = d.tenant_id
          AND receipt.dead_letter_id = d.id
    )
$$;

CREATE FUNCTION public.rss_dlx_claim_archive_candidates()
RETURNS TABLE(
    tenant_id uuid,
    dead_letter_id uuid,
    message_id text,
    producer_domain text,
    consumer_domain text,
    contract_id text,
    topic text,
    consumer_group text,
    source_kind text,
    error_summary text,
    num_attempts int,
    first_attempt_at timestamptz,
    last_attempt_at timestamptz,
    replay_capsule jsonb,
    replay_capsule_key_ref text,
    replay_capsule_encoding text,
    payload_len bigint,
    metadata_digest bytea,
    archive_claim_token uuid,
    archive_lease_until timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH claim_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS claimed_at
    ), candidates AS MATERIALIZED (
        SELECT d.ctid, claim_clock.claimed_at
        FROM public.dead_letter AS d
        CROSS JOIN claim_clock
        WHERE d.archive_quarantined_at IS NULL
          AND d.archive_next_attempt_at <= claim_clock.claimed_at
          AND (d.archive_claim_token IS NULL OR d.archive_lease_until <= claim_clock.claimed_at)
          AND NOT EXISTS (
              SELECT 1
              FROM public.dead_letter_archive_receipts AS receipt
              WHERE receipt.tenant_id = d.tenant_id
                AND receipt.dead_letter_id = d.id
          )
        ORDER BY d.archive_next_attempt_at, d.first_attempt_at, d.id
        LIMIT 100
        FOR UPDATE OF d SKIP LOCKED
    ), claimed AS (
        UPDATE public.dead_letter AS d
        SET archive_claim_token = gen_random_uuid(),
            archive_lease_until = candidates.claimed_at + interval '5 minutes'
        FROM candidates
        WHERE d.ctid = candidates.ctid
          AND d.archive_quarantined_at IS NULL
          AND (d.archive_claim_token IS NULL OR d.archive_lease_until <= candidates.claimed_at)
        RETURNING d.*
    )
    SELECT claimed.tenant_id,
           claimed.id,
           claimed.message_id,
           claimed.producer_domain,
           claimed.consumer_domain,
           claimed.contract_id,
           claimed.topic,
           claimed.consumer_group,
           claimed.source_kind,
           claimed.error_summary,
           claimed.num_attempts,
           claimed.first_attempt_at,
           claimed.last_attempt_at,
           claimed.replay_capsule,
           claimed.replay_capsule_key_ref,
           claimed.replay_capsule_encoding,
           claimed.payload_len,
           claimed.metadata_digest,
           claimed.archive_claim_token,
           claimed.archive_lease_until
    FROM claimed
    ORDER BY claimed.archive_next_attempt_at, claimed.first_attempt_at, claimed.id
$$;

CREATE FUNCTION public.rss_dlx_settle_archive_retry(
    p_tenant_id uuid,
    p_dead_letter_id uuid,
    p_archive_claim_token uuid,
    p_failure_reason text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    settled_at timestamptz := clock_timestamp();
    updated_rows bigint;
BEGIN
    IF p_failure_reason NOT IN (
        'provider_unavailable', 'provider_timeout', 'object_missing', 'version_drift'
    ) THEN
        RAISE EXCEPTION 'invalid transient DLX archive failure reason';
    END IF;
    UPDATE public.dead_letter AS d
    SET archive_claim_token = NULL,
        archive_lease_until = NULL,
        archive_failure_count = d.archive_failure_count + 1,
        archive_last_failure_reason = p_failure_reason,
        archive_next_attempt_at = settled_at + make_interval(
            secs => LEAST(
                3600,
                5 * power(2::numeric, LEAST(d.archive_failure_count, 10))::int
            )
        )
    WHERE d.tenant_id = p_tenant_id
      AND d.id = p_dead_letter_id
      AND d.archive_claim_token = p_archive_claim_token
      AND d.archive_lease_until > settled_at
      AND d.archive_quarantined_at IS NULL;
    GET DIAGNOSTICS updated_rows = ROW_COUNT;
    RETURN updated_rows;
END;
$$;

CREATE FUNCTION public.rss_dlx_quarantine_archive_candidate(
    p_tenant_id uuid,
    p_dead_letter_id uuid,
    p_archive_claim_token uuid,
    p_failure_reason text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    settled_at timestamptz := clock_timestamp();
    updated_rows bigint;
BEGIN
    IF p_failure_reason NOT IN (
        'invalid_persisted_data', 'invalid_archive_format', 'size_limit_exceeded',
        'key_not_found', 'key_forbidden', 'key_rejected', 'key_mismatch',
        'checksum_mismatch', 'canonical_mismatch', 'retention_invalid', 'cas_rejected',
        'arithmetic_overflow', 'unexpected_provider_response', 'internal_invariant'
    ) THEN
        RAISE EXCEPTION 'invalid invariant DLX archive failure reason';
    END IF;
    UPDATE public.dead_letter AS d
    SET archive_claim_token = NULL,
        archive_lease_until = NULL,
        archive_failure_count = d.archive_failure_count + 1,
        archive_last_failure_reason = p_failure_reason,
        archive_next_attempt_at = 'infinity',
        archive_quarantined_at = settled_at
    WHERE d.tenant_id = p_tenant_id
      AND d.id = p_dead_letter_id
      AND d.archive_claim_token = p_archive_claim_token
      AND d.archive_lease_until > settled_at
      AND d.archive_quarantined_at IS NULL;
    GET DIAGNOSTICS updated_rows = ROW_COUNT;
    RETURN updated_rows;
END;
$$;

CREATE FUNCTION public.rss_dlx_record_archive_receipt(
    p_tenant_id uuid,
    p_dead_letter_id uuid,
    p_archive_claim_token uuid,
    p_object_version_id text,
    p_checksum_sha256 bytea,
    p_archive_key_ref text,
    p_object_lock_mode text,
    p_object_lock_retain_until timestamptz
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    verified_at timestamptz := clock_timestamp();
    derived_object_key text := 'dead-letter/' || p_dead_letter_id::text || '.v1.enc';
    inserted_rows bigint;
    cleared_claims bigint;
BEGIN
    IF p_object_lock_mode <> 'COMPLIANCE'
       OR p_object_lock_retain_until <= verified_at + interval '30 days'
       OR octet_length(p_checksum_sha256) <> 32
       OR p_object_version_id IS NULL
       OR octet_length(p_object_version_id) NOT BETWEEN 1 AND 1024
       OR p_object_version_id <> btrim(p_object_version_id)
       OR p_object_version_id ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid verified DLX archive receipt';
    END IF;

    -- Idempotency is checked before HOT existence: a crash/retry may replay the same verified
    -- receipt after another worker has already purged its HOT row.
    IF EXISTS (
        SELECT 1
        FROM public.dead_letter_archive_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.dead_letter_id = p_dead_letter_id
          AND receipt.object_key = derived_object_key
          AND receipt.object_version_id = p_object_version_id
          AND receipt.checksum_sha256 = p_checksum_sha256
          AND receipt.archive_key_ref = p_archive_key_ref
          AND receipt.object_lock_mode = p_object_lock_mode
          AND receipt.object_lock_retain_until = p_object_lock_retain_until
    ) THEN
        RETURN 0;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.dead_letter AS d
        WHERE d.tenant_id = p_tenant_id
          AND d.id = p_dead_letter_id
          AND d.archive_claim_token = p_archive_claim_token
          AND d.archive_lease_until > verified_at
          AND d.archive_quarantined_at IS NULL
    ) THEN
        RAISE EXCEPTION 'verified DLX archive receipt has no fresh matching claim';
    END IF;

    INSERT INTO public.dead_letter_archive_receipts (
        tenant_id,
        dead_letter_id,
        object_key,
        object_version_id,
        checksum_sha256,
        archive_key_ref,
        object_lock_mode,
        object_lock_retain_until,
        verified_at,
        reconcile_after
    ) VALUES (
        p_tenant_id,
        p_dead_letter_id,
        derived_object_key,
        p_object_version_id,
        p_checksum_sha256,
        p_archive_key_ref,
        p_object_lock_mode,
        p_object_lock_retain_until,
        verified_at,
        p_object_lock_retain_until
    )
    ON CONFLICT (tenant_id, dead_letter_id) DO NOTHING;
    GET DIAGNOSTICS inserted_rows = ROW_COUNT;

    IF inserted_rows = 1 THEN
        UPDATE public.dead_letter AS d
        SET archive_claim_token = NULL,
            archive_lease_until = NULL,
            archive_next_attempt_at = '-infinity',
            archive_last_failure_reason = NULL
        WHERE d.tenant_id = p_tenant_id
          AND d.id = p_dead_letter_id
          AND d.archive_claim_token = p_archive_claim_token
          AND d.archive_lease_until > verified_at;
        GET DIAGNOSTICS cleared_claims = ROW_COUNT;
        IF cleared_claims <> 1 THEN
            RAISE EXCEPTION 'verified DLX archive receipt claim changed before commit';
        END IF;
        RETURN 1;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.dead_letter_archive_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.dead_letter_id = p_dead_letter_id
          AND receipt.object_key = derived_object_key
          AND receipt.object_version_id = p_object_version_id
          AND receipt.checksum_sha256 = p_checksum_sha256
          AND receipt.archive_key_ref = p_archive_key_ref
          AND receipt.object_lock_mode = p_object_lock_mode
          AND receipt.object_lock_retain_until = p_object_lock_retain_until
    ) THEN
        RETURN 0;
    END IF;

    RAISE EXCEPTION 'conflicting verified DLX archive receipt';
END;
$$;

CREATE FUNCTION public.rss_dlx_purge_verified()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    WITH eligible AS MATERIALIZED (
        SELECT d.ctid
        FROM public.dead_letter AS d
        JOIN public.dead_letter_archive_receipts AS receipt
          ON receipt.tenant_id = d.tenant_id
         AND receipt.dead_letter_id = d.id
        WHERE d.last_attempt_at <= now() - interval '30 days'
          AND receipt.object_lock_mode = 'COMPLIANCE'
          AND receipt.object_lock_retain_until > now()
        ORDER BY d.last_attempt_at, d.id
        LIMIT 1000
        FOR UPDATE OF d SKIP LOCKED
    )
    DELETE FROM public.dead_letter AS d
    USING eligible
    WHERE d.ctid = eligible.ctid;
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

CREATE FUNCTION public.rss_dlx_reconcile_expired_receipts()
RETURNS TABLE(
    tenant_id uuid,
    dead_letter_id uuid,
    object_key text,
    object_version_id text,
    checksum_sha256 bytea,
    object_lock_retain_until timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH candidates AS MATERIALIZED (
        SELECT receipt.ctid
        FROM public.dead_letter_archive_receipts AS receipt
        WHERE receipt.object_lock_retain_until <= now()
          AND receipt.reconcile_after <= now()
        ORDER BY receipt.reconcile_after, receipt.dead_letter_id
        LIMIT 100
        FOR UPDATE SKIP LOCKED
    ), claimed AS (
        UPDATE public.dead_letter_archive_receipts AS receipt
        SET reconcile_after = now() + interval '1 day'
        FROM candidates
        WHERE receipt.ctid = candidates.ctid
        RETURNING receipt.*
    )
    SELECT claimed.tenant_id,
           claimed.dead_letter_id,
           claimed.object_key,
           claimed.object_version_id,
           claimed.checksum_sha256,
           claimed.object_lock_retain_until
    FROM claimed
    ORDER BY claimed.reconcile_after, claimed.dead_letter_id
$$;

CREATE FUNCTION public.rss_dlx_delete_missing_archive_receipt(
    p_tenant_id uuid,
    p_dead_letter_id uuid,
    p_object_key text,
    p_object_version_id text,
    p_checksum_sha256 bytea
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    DELETE FROM public.dead_letter_archive_receipts AS receipt
    WHERE receipt.tenant_id = p_tenant_id
      AND receipt.dead_letter_id = p_dead_letter_id
      AND receipt.object_key = p_object_key
      AND receipt.object_version_id = p_object_version_id
      AND receipt.checksum_sha256 = p_checksum_sha256
      AND receipt.object_lock_retain_until <= now();
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION public.rss_dlx_claim_archive_candidates() OWNER TO rss_dlx_lifecycle_owner;
ALTER FUNCTION public.rss_dlx_archive_backlog() OWNER TO rss_dlx_lifecycle_owner;
ALTER FUNCTION public.rss_dlx_settle_archive_retry(uuid, uuid, uuid, text)
    OWNER TO rss_dlx_lifecycle_owner;
ALTER FUNCTION public.rss_dlx_quarantine_archive_candidate(uuid, uuid, uuid, text)
    OWNER TO rss_dlx_lifecycle_owner;
ALTER FUNCTION public.rss_dlx_record_archive_receipt(uuid, uuid, uuid, text, bytea, text, text, timestamptz)
    OWNER TO rss_dlx_lifecycle_owner;
ALTER FUNCTION public.rss_dlx_purge_verified() OWNER TO rss_dlx_lifecycle_owner;
ALTER FUNCTION public.rss_dlx_reconcile_expired_receipts() OWNER TO rss_dlx_lifecycle_owner;
ALTER FUNCTION public.rss_dlx_delete_missing_archive_receipt(uuid, uuid, text, text, bytea)
    OWNER TO rss_dlx_lifecycle_owner;

REVOKE ALL ON FUNCTION public.rss_dlx_claim_archive_candidates() FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_dlx_archive_backlog() FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_dlx_settle_archive_retry(uuid, uuid, uuid, text)
    FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_dlx_quarantine_archive_candidate(uuid, uuid, uuid, text)
    FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_dlx_record_archive_receipt(uuid, uuid, uuid, text, bytea, text, text, timestamptz)
    FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_dlx_purge_verified() FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_dlx_reconcile_expired_receipts() FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_dlx_delete_missing_archive_receipt(uuid, uuid, text, text, bytea)
    FROM PUBLIC, rss_app;

GRANT EXECUTE ON FUNCTION public.rss_dlx_claim_archive_candidates() TO rss_dlx_archiver;
GRANT EXECUTE ON FUNCTION public.rss_dlx_archive_backlog() TO rss_dlx_archiver;
GRANT EXECUTE ON FUNCTION public.rss_dlx_settle_archive_retry(uuid, uuid, uuid, text)
    TO rss_dlx_archiver;
GRANT EXECUTE ON FUNCTION public.rss_dlx_quarantine_archive_candidate(uuid, uuid, uuid, text)
    TO rss_dlx_archiver;
GRANT EXECUTE ON FUNCTION public.rss_dlx_record_archive_receipt(uuid, uuid, uuid, text, bytea, text, text, timestamptz)
    TO rss_dlx_verifier;
GRANT EXECUTE ON FUNCTION public.rss_dlx_purge_verified() TO rss_dlx_purger;
GRANT EXECUTE ON FUNCTION public.rss_dlx_reconcile_expired_receipts() TO rss_dlx_purger;
GRANT EXECUTE ON FUNCTION public.rss_dlx_delete_missing_archive_receipt(uuid, uuid, text, text, bytea)
    TO rss_dlx_purger;

-- Keep published outbox retention deterministic and bounded without changing its already-fixed
-- retain_seconds policy surface. 1001 eligible rows are intentionally removed in two ticks.
CREATE OR REPLACE FUNCTION public.rss_sweep_outbox_published(p_retain_seconds bigint)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    IF p_retain_seconds IS NULL OR p_retain_seconds <= 0 THEN
        RAISE EXCEPTION 'rss_sweep_outbox_published retain seconds must be positive';
    END IF;

    WITH eligible AS MATERIALIZED (
        SELECT o.ctid
        FROM public.outbox AS o
        WHERE o.status = 'published'
          AND o.published_at <= now() - make_interval(secs => p_retain_seconds::double precision)
        ORDER BY o.published_at, o.event_id
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.outbox AS o
    USING eligible
    WHERE o.ctid = eligible.ctid;
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION public.rss_sweep_outbox_published(bigint) OWNER TO rss_outbox_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_outbox_published(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_sweep_outbox_published(bigint) TO rss_app;
