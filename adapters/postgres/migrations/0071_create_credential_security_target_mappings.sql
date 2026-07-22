-- 0071_create_credential_security_target_mappings.sql
--
-- Opaque security-event target references resolve through this immutable provider-owned mapping.
-- Raw subject/grant identifiers never enter the generated payload or outbox envelope.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE public.credential_security_target_mappings (
    target_ref  uuid        PRIMARY KEY,
    tenant_id   uuid        NOT NULL,
    target_kind text        NOT NULL,
    user_id     uuid        NOT NULL,
    grant_id    text,
    created_at  timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT credential_security_target_kind_closed
        CHECK (target_kind IN ('subject', 'grant')),
    CONSTRAINT credential_security_target_shape_closed
        CHECK (
            (target_kind = 'subject' AND grant_id IS NULL)
            OR (target_kind = 'grant' AND grant_id IS NOT NULL AND grant_id <> '')
        )
);

ALTER TABLE public.credential_security_target_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.credential_security_target_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_security_target_tenant_isolation
    ON public.credential_security_target_mappings
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

REVOKE ALL ON TABLE public.credential_security_target_mappings FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.credential_security_target_mappings TO rss_app;
GRANT SELECT ON TABLE public.credential_security_target_mappings TO rss_app_read;
REVOKE UPDATE, DELETE ON TABLE public.credential_security_target_mappings
    FROM rss_app, rss_app_read;
