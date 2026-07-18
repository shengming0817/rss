-- 0068_replace_service_token_replay_store.sql
-- Breaking cutover from raw jti storage to fixed-width scoped replay digests (#1829).
-- Active legacy rows cannot be scoped safely, so migration fails closed; no compatibility path.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';
LOCK TABLE public.service_token_replay_nonces IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.service_token_replay_nonces
        WHERE expires_at > pg_catalog.clock_timestamp()
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'active legacy service-token replay entries prevent scoped-store cutover';
    END IF;
END
$$;
DROP TABLE public.service_token_replay_nonces;
DO $$
DECLARE owner_oid oid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_service_token_replay_owner'
    ) THEN
        CREATE ROLE rss_service_token_replay_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE rss_service_token_replay_owner
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;

    SELECT oid INTO STRICT owner_oid
    FROM pg_catalog.pg_roles
    WHERE rolname = 'rss_service_token_replay_owner';
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = owner_oid OR membership.member = owner_oid
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'rss_service_token_replay_owner must have no role memberships';
    END IF;
END
$$;
CREATE TABLE public.service_token_replay_keys (
    key_digest bytea PRIMARY KEY CONSTRAINT service_token_replay_keys_digest_width
        CHECK (pg_catalog.octet_length(key_digest) = 32),
    retain_until timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
CREATE INDEX service_token_replay_keys_retention_idx ON public.service_token_replay_keys
    (retain_until, key_digest);
ALTER TABLE public.service_token_replay_keys OWNER TO rss_service_token_replay_owner;
GRANT USAGE ON SCHEMA public TO rss_service_token_replay_owner;
REVOKE ALL ON TABLE public.service_token_replay_keys FROM PUBLIC, rss_app;
CREATE FUNCTION public.rss_service_token_replay_check_and_record(
    scoped_key_digest bytea, expires_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE inserted_rows bigint;
BEGIN
    IF scoped_key_digest IS NULL
        OR pg_catalog.octet_length(scoped_key_digest) <> 32
        OR expires_at IS NULL
        OR expires_at <= pg_catalog.clock_timestamp()
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid service-token replay record';
    END IF;
    INSERT INTO public.service_token_replay_keys (key_digest, retain_until)
    VALUES (scoped_key_digest, expires_at)
    ON CONFLICT (key_digest) DO NOTHING;

    GET DIAGNOSTICS inserted_rows = ROW_COUNT;
    RETURN inserted_rows = 1;
END;
$$;
ALTER FUNCTION public.rss_service_token_replay_check_and_record(bytea, timestamptz)
    OWNER TO rss_service_token_replay_owner;
REVOKE ALL ON FUNCTION public.rss_service_token_replay_check_and_record(bytea, timestamptz)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_check_and_record(bytea, timestamptz) TO rss_app;
CREATE FUNCTION public.rss_service_token_replay_sweep_expired()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE deleted_rows bigint;
BEGIN
    WITH expired AS (
        SELECT key_digest
        FROM public.service_token_replay_keys
        WHERE retain_until <= pg_catalog.clock_timestamp() - interval '5 minutes'
        ORDER BY retain_until, key_digest
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    ),
    deleted AS (
        DELETE FROM public.service_token_replay_keys AS replay
        USING expired
        WHERE replay.key_digest = expired.key_digest
        RETURNING 1
    )
    SELECT pg_catalog.count(*) INTO deleted_rows FROM deleted;
    RETURN deleted_rows;
END;
$$;
ALTER FUNCTION public.rss_service_token_replay_sweep_expired() OWNER TO rss_service_token_replay_owner;
REVOKE ALL ON FUNCTION public.rss_service_token_replay_sweep_expired() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_sweep_expired() TO rss_app;
