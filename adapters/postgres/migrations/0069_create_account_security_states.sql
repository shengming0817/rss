-- 0069_create_account_security_states.sql
--
-- Durable account lifecycle is a separate aggregate from temporary credential
-- lockout. Every credential must have exactly one state row at transaction
-- commit, and a state row can never outlive its credential.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE public.account_security_states (
    tenant_id          uuid        NOT NULL,
    user_id            uuid        NOT NULL,
    status             text        NOT NULL,
    authn_epoch        bigint      NOT NULL,
    version            bigint      NOT NULL,
    status_changed_at  timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT account_security_states_credential_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES public.credentials (tenant_id, user_id)
        ON DELETE CASCADE,
    CONSTRAINT account_security_states_status_closed
        CHECK (status IN ('active', 'suspended', 'locked', 'deactivated')),
    CONSTRAINT account_security_states_authn_epoch_nonnegative
        CHECK (authn_epoch >= 0),
    CONSTRAINT account_security_states_version_positive
        CHECK (version >= 1),
    CONSTRAINT account_security_states_timestamps_ordered
        CHECK (status_changed_at <= updated_at)
);

-- Stop credential writers before taking the backfill snapshot. The reverse FK
-- below is validated in this transaction, so no credential can cross the
-- cutover without its state row.
LOCK TABLE public.credentials IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.refresh_tokens IN SHARE ROW EXCLUSIVE MODE;

-- A legacy refresh family has no issuance epoch, and the current account epoch
-- cannot reconstruct it safely. Active families must first be revoked through
-- the normal application lifecycle while the old binary is still running.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.refresh_tokens
        WHERE status = 'active'
        LIMIT 1
    ) THEN
        RAISE EXCEPTION
            '0069 requires all active legacy refresh families to be revoked before cutover';
    END IF;
END
$$;

-- Consumed/revoked legacy rows cannot participate in the new epoch-bound
-- protocol and carry no live bearer capability. Remove them inside the locked
-- cutover transaction; no legacy decoder or guessed epoch survives commit.
DELETE FROM public.refresh_tokens;

ALTER TABLE public.refresh_tokens
    ADD COLUMN authn_epoch_at_issue bigint NOT NULL,
    ADD CONSTRAINT refresh_tokens_authn_epoch_at_issue_nonnegative
        CHECK (authn_epoch_at_issue >= 0);

INSERT INTO public.account_security_states (
    tenant_id,
    user_id,
    status,
    authn_epoch,
    version,
    status_changed_at,
    updated_at
)
SELECT
    tenant_id,
    user_id,
    'active',
    0,
    1,
    transaction_timestamp(),
    transaction_timestamp()
FROM public.credentials;

-- This reverse edge makes the relationship strictly one-to-one at commit while
-- still allowing CredentialRepo::save to write credential first and state
-- second in one transaction. It also rejects direct user rebinds.
ALTER TABLE public.credentials
    ADD CONSTRAINT credentials_account_security_state_fk
    FOREIGN KEY (tenant_id, user_id)
    REFERENCES public.account_security_states (tenant_id, user_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE public.account_security_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.account_security_states FORCE ROW LEVEL SECURITY;

CREATE POLICY account_security_tenant_isolation
    ON public.account_security_states
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

REVOKE ALL ON TABLE public.account_security_states FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.account_security_states TO rss_app;
GRANT SELECT ON TABLE public.account_security_states TO rss_app_read;
REVOKE DELETE ON TABLE public.account_security_states FROM rss_app, rss_app_read;
