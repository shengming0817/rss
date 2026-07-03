-- 0041_create_reconcile_schema.sql
-- Durable reconcile target/lease/attempt/action schema (#1629).
--
-- Hard boundaries:
-- - target uniqueness is tenant/resource scoped by DB UNIQUE.
-- - every child table carries tenant_id and points back to the target through a composite FK.
-- - attempts/actions are append-only for rss_app through grants/revokes.
-- - all tables are tenant-scoped with FORCE RLS and the standard tenant policy.

CREATE TABLE reconcile_targets (
    tenant_id       uuid        NOT NULL,
    target_id       uuid        NOT NULL DEFAULT gen_random_uuid(),
    reconciler_id   text        NOT NULL,
    resource_kind   text        NOT NULL,
    resource_id     text        NOT NULL,
    status          text        NOT NULL DEFAULT 'active',
    next_run_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, target_id),
    CONSTRAINT reconcile_targets_tenant_resource_unique
        UNIQUE (tenant_id, reconciler_id, resource_kind, resource_id),
    CONSTRAINT reconcile_targets_reconciler_id_valid
        CHECK (length(reconciler_id) > 0 AND octet_length(reconciler_id) <= 128),
    CONSTRAINT reconcile_targets_resource_kind_valid
        CHECK (length(resource_kind) > 0 AND octet_length(resource_kind) <= 128),
    CONSTRAINT reconcile_targets_resource_id_valid
        CHECK (length(resource_id) > 0 AND octet_length(resource_id) <= 512),
    CONSTRAINT reconcile_targets_status_valid
        CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE reconcile_leases (
    tenant_id    uuid        NOT NULL,
    target_id    uuid        NOT NULL,
    state        text        NOT NULL DEFAULT 'free',
    lease_token  uuid,
    holder_id    text,
    epoch        bigint      NOT NULL DEFAULT 0,
    acquired_at  timestamptz,
    expires_at   timestamptz,
    heartbeat_at timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, target_id),
    CONSTRAINT reconcile_leases_target_fk
        FOREIGN KEY (tenant_id, target_id)
        REFERENCES reconcile_targets (tenant_id, target_id)
        ON DELETE CASCADE,
    CONSTRAINT reconcile_leases_state_valid
        CHECK (state IN ('free', 'held')),
    CONSTRAINT reconcile_leases_epoch_non_negative
        CHECK (epoch >= 0),
    CONSTRAINT reconcile_leases_holder_id_valid
        CHECK (holder_id IS NULL OR (length(holder_id) > 0 AND octet_length(holder_id) <= 256)),
    CONSTRAINT reconcile_leases_state_fields_consistent
        CHECK (
            (
                state = 'free'
                AND lease_token IS NULL
                AND holder_id IS NULL
                AND acquired_at IS NULL
                AND expires_at IS NULL
                AND heartbeat_at IS NULL
            )
            OR (
                state = 'held'
                AND lease_token IS NOT NULL
                AND holder_id IS NOT NULL
                AND acquired_at IS NOT NULL
                AND expires_at IS NOT NULL
                AND heartbeat_at IS NOT NULL
                AND expires_at > acquired_at
            )
        )
);

CREATE TABLE reconcile_attempts (
    tenant_id    uuid        NOT NULL,
    attempt_id   uuid        NOT NULL DEFAULT gen_random_uuid(),
    target_id    uuid        NOT NULL,
    lease_token  uuid        NOT NULL,
    epoch        bigint      NOT NULL,
    holder_id    text        NOT NULL,
    trigger_kind text        NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, attempt_id),
    CONSTRAINT reconcile_attempts_target_fk
        FOREIGN KEY (tenant_id, target_id)
        REFERENCES reconcile_targets (tenant_id, target_id)
        ON DELETE CASCADE,
    CONSTRAINT reconcile_attempts_attempt_target_unique
        UNIQUE (tenant_id, attempt_id, target_id),
    CONSTRAINT reconcile_attempts_epoch_positive
        CHECK (epoch >= 1),
    CONSTRAINT reconcile_attempts_holder_id_valid
        CHECK (length(holder_id) > 0 AND octet_length(holder_id) <= 256),
    CONSTRAINT reconcile_attempts_trigger_kind_valid
        CHECK (trigger_kind IN ('resync', 'targeted', 'requeue', 'lease_reclaim'))
);

CREATE TABLE reconcile_actions (
    tenant_id        uuid        NOT NULL,
    action_id        uuid        NOT NULL DEFAULT gen_random_uuid(),
    attempt_id       uuid        NOT NULL,
    target_id        uuid        NOT NULL,
    action_kind      text        NOT NULL,
    result_label     text        NOT NULL,
    requeue_after_ms bigint,
    error_kind       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, action_id),
    CONSTRAINT reconcile_actions_attempt_target_fk
        FOREIGN KEY (tenant_id, attempt_id, target_id)
        REFERENCES reconcile_attempts (tenant_id, attempt_id, target_id)
        ON DELETE CASCADE,
    CONSTRAINT reconcile_actions_target_fk
        FOREIGN KEY (tenant_id, target_id)
        REFERENCES reconcile_targets (tenant_id, target_id)
        ON DELETE CASCADE,
    CONSTRAINT reconcile_actions_action_kind_valid
        CHECK (action_kind IN ('noop', 'create', 'update', 'delete')),
    CONSTRAINT reconcile_actions_result_label_valid
        CHECK (result_label IN ('settled', 'requeue_after', 'transient', 'permanent', 'invariant')),
    CONSTRAINT reconcile_actions_error_kind_valid
        CHECK (error_kind IS NULL OR error_kind IN ('transient', 'permanent', 'invariant')),
    CONSTRAINT reconcile_actions_requeue_after_valid
        CHECK (requeue_after_ms IS NULL OR requeue_after_ms >= 0)
);

CREATE INDEX idx_reconcile_targets_due
    ON reconcile_targets (tenant_id, reconciler_id, next_run_at)
    WHERE status = 'active';

CREATE INDEX idx_reconcile_leases_held_expiry
    ON reconcile_leases (tenant_id, expires_at)
    WHERE state = 'held';

CREATE INDEX idx_reconcile_attempts_target_started
    ON reconcile_attempts (tenant_id, target_id, started_at);

CREATE INDEX idx_reconcile_actions_attempt_created
    ON reconcile_actions (tenant_id, attempt_id, created_at);

CREATE INDEX idx_reconcile_actions_result
    ON reconcile_actions (tenant_id, result_label, created_at);

GRANT SELECT, INSERT, UPDATE ON reconcile_targets TO rss_app;
REVOKE DELETE ON reconcile_targets FROM rss_app;

GRANT SELECT, INSERT, UPDATE ON reconcile_leases TO rss_app;
REVOKE DELETE ON reconcile_leases FROM rss_app;

GRANT SELECT, INSERT ON reconcile_attempts TO rss_app;
REVOKE UPDATE, DELETE ON reconcile_attempts FROM rss_app;

GRANT SELECT, INSERT ON reconcile_actions TO rss_app;
REVOKE UPDATE, DELETE ON reconcile_actions FROM rss_app;

ALTER TABLE reconcile_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconcile_targets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON reconcile_targets
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE reconcile_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconcile_leases FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON reconcile_leases
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE reconcile_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconcile_attempts FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON reconcile_attempts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE reconcile_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconcile_actions FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON reconcile_actions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
