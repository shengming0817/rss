-- httpserve auth decision flat audit events (#1231).
--
-- This table is intentionally separate from audit_entries:
--   * audit_entries is a per-tenant hash-chain ledger whose actor is ids::UserId;
--   * auth decisions can be made for user, service, super-admin, or tenantless principals whose subject is a generic
--     verified principal id.
--
-- `principal_tenant` is a nullable snapshot of the authenticated subject's tenant, not an ownership/RLS column. It is
-- deliberately not named `tenant_id` so schema-rls does not classify this platform audit table as a tenant-owned table.
-- Tenantless service/super-admin events must remain durable.
--
-- Append-only: rss_app gets SELECT + INSERT only.
-- Timestamp uses secs+nanos columns to avoid timestamptz precision loss, matching audit_entries.

CREATE TABLE auth_audit_events (
    id                  bigserial   PRIMARY KEY,
    occurred_at_secs    bigint      NOT NULL CHECK (occurred_at_secs >= 0),
    occurred_at_nanos   integer     NOT NULL CHECK (occurred_at_nanos >= 0 AND occurred_at_nanos < 1000000000),
    principal_id        text        NOT NULL,
    principal_kind      text        NOT NULL CHECK (principal_kind IN ('user','device','admin','super_admin','service','anonymous')),
    principal_tenant    uuid        NULL,
    resource_kind       text        NOT NULL,
    resource_id         text        NOT NULL,
    action              text        NOT NULL,
    outcome             text        NOT NULL CHECK (outcome IN ('success','failure')),
    failure_reason      text        NULL,
    request_id          text        NULL,
    correlation_id      text        NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CHECK ((outcome = 'failure') = (failure_reason IS NOT NULL))
);

CREATE INDEX auth_audit_events_principal_tenant_idx
    ON auth_audit_events (principal_tenant, id)
    WHERE principal_tenant IS NOT NULL;

GRANT SELECT, INSERT ON auth_audit_events TO rss_app;
GRANT USAGE, SELECT ON SEQUENCE auth_audit_events_id_seq TO rss_app;
REVOKE UPDATE, DELETE ON auth_audit_events FROM PUBLIC;
