-- 0070_create_auth_grants.sql
--
-- Non-rolling pre-GA cutover from independently persisted sessions and refresh families to one
-- server-side authentication-grant root. Legacy rows cannot prove a user/epoch/root binding, so
-- they are deleted under writer-blocking locks; there is no backfill, nullable compatibility
-- shape, view, trigger, dual write or legacy decoder.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.sessions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.refresh_tokens IN SHARE ROW EXCLUSIVE MODE;

DELETE FROM public.refresh_tokens;

DROP FUNCTION public.rss_sweep_expired_sessions();
DROP TABLE public.sessions;
DROP ROLE rss_session_maintenance;

CREATE TABLE public.auth_grants (
    tenant_id                uuid        NOT NULL,
    grant_id                 text        NOT NULL,
    user_id                  uuid        NOT NULL,
    auth_time                timestamptz NOT NULL,
    authn_epoch_at_issue     bigint      NOT NULL,
    status                   text        NOT NULL,
    expires_at               timestamptz NOT NULL,
    created_at               timestamptz NOT NULL,
    closed_at                timestamptz,
    close_reason             text,
    PRIMARY KEY (tenant_id, grant_id),
    CONSTRAINT auth_grants_binding_unique
        UNIQUE (tenant_id, grant_id, user_id, authn_epoch_at_issue, status),
    CONSTRAINT auth_grants_account_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES public.account_security_states (tenant_id, user_id),
    CONSTRAINT auth_grants_epoch_nonnegative
        CHECK (authn_epoch_at_issue >= 0),
    CONSTRAINT auth_grants_time_order
        CHECK (
            auth_time <= created_at
            AND created_at < expires_at
            AND (closed_at IS NULL OR closed_at >= created_at)
        ),
    CONSTRAINT auth_grants_state_closed
        CHECK (
            (
                status = 'active'
                AND closed_at IS NULL
                AND close_reason IS NULL
            )
            OR (
                status = 'revoked'
                AND closed_at IS NOT NULL
                AND close_reason IN (
                    'logout_current',
                    'logout_all',
                    'password_changed',
                    'password_reset',
                    'account_locked',
                    'account_suspended',
                    'account_deactivated',
                    'credential_deleted'
                )
            )
            OR (
                status = 'compromised'
                AND closed_at IS NOT NULL
                AND close_reason = 'refresh_reuse_detected'
            )
        )
);

CREATE INDEX idx_auth_grants_expiry
    ON public.auth_grants (expires_at, tenant_id, grant_id);
CREATE INDEX idx_auth_grants_user
    ON public.auth_grants (tenant_id, user_id, status);

ALTER TABLE public.auth_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY auth_grant_tenant_isolation
    ON public.auth_grants
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

REVOKE ALL ON TABLE public.auth_grants FROM PUBLIC;
REVOKE UPDATE ON TABLE public.auth_grants FROM rss_app, rss_app_read;
GRANT SELECT, INSERT ON TABLE public.auth_grants TO rss_app;
GRANT UPDATE (status, closed_at, close_reason) ON TABLE public.auth_grants TO rss_app;
GRANT SELECT ON TABLE public.auth_grants TO rss_app_read;
REVOKE DELETE ON TABLE public.auth_grants FROM rss_app, rss_app_read;

ALTER TABLE public.refresh_tokens
    DROP COLUMN subject,
    DROP COLUMN kind,
    ADD COLUMN auth_grant_id text NOT NULL,
    ADD COLUMN user_id uuid NOT NULL,
    ADD COLUMN auth_grant_status text NOT NULL,
    ADD CONSTRAINT refresh_tokens_auth_grant_status_closed
        CHECK (auth_grant_status IN ('active', 'revoked', 'compromised')),
    ADD CONSTRAINT refresh_tokens_terminal_grant_requires_revoked
        CHECK (auth_grant_status = 'active' OR status = 'revoked'),
    ADD CONSTRAINT refresh_tokens_auth_grant_fk
        FOREIGN KEY (
            tenant_id,
            auth_grant_id,
            user_id,
            authn_epoch_at_issue,
            auth_grant_status
        )
        REFERENCES public.auth_grants (
            tenant_id,
            grant_id,
            user_id,
            authn_epoch_at_issue,
            status
        )
        ON UPDATE CASCADE
        ON DELETE CASCADE;

CREATE INDEX idx_refresh_tokens_auth_grant_fk
    ON public.refresh_tokens (
        tenant_id,
        auth_grant_id,
        user_id,
        authn_epoch_at_issue,
        auth_grant_status
    );

REVOKE UPDATE ON TABLE public.refresh_tokens FROM rss_app, rss_app_read;
GRANT UPDATE (status) ON TABLE public.refresh_tokens TO rss_app;
REVOKE DELETE ON TABLE public.refresh_tokens FROM rss_app, rss_app_read;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_auth_grant_maintenance') THEN
        CREATE ROLE rss_auth_grant_maintenance NOLOGIN BYPASSRLS;
    ELSE
        ALTER ROLE rss_auth_grant_maintenance NOLOGIN BYPASSRLS;
    END IF;
END
$$;

-- UPDATE is required by SELECT ... FOR UPDATE; the NOLOGIN role is reachable only through the
-- fixed SECURITY DEFINER function below.
GRANT SELECT, UPDATE, DELETE ON TABLE public.auth_grants TO rss_auth_grant_maintenance;
-- Required by the FK cascade trigger; the serving roles still have no direct DELETE capability.
GRANT DELETE ON TABLE public.refresh_tokens TO rss_auth_grant_maintenance;

CREATE FUNCTION public.rss_sweep_expired_auth_grants()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    WITH expired AS (
        SELECT tenant_id, grant_id
        FROM public.auth_grants
        WHERE expires_at <= pg_catalog.clock_timestamp()
        ORDER BY expires_at, tenant_id, grant_id
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.auth_grants AS root
    USING expired
    WHERE root.tenant_id = expired.tenant_id
      AND root.grant_id = expired.grant_id;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION public.rss_sweep_expired_auth_grants()
    OWNER TO rss_auth_grant_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_expired_auth_grants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_sweep_expired_auth_grants() TO rss_app;
