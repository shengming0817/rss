-- 0044_create_reconcile_attempt_results.sql
-- Append-only durable terminal results for reconcile attempts (#1636).
--
-- Keep reconcile_actions scoped to real converge actions. Observe/error/pre-action terminal
-- outcomes are recorded here instead of making action_kind nullable.

CREATE TABLE reconcile_attempt_results (
    tenant_id        uuid        NOT NULL,
    attempt_id       uuid        NOT NULL,
    target_id        uuid        NOT NULL,
    result_label     text        NOT NULL,
    requeue_after_ms bigint,
    error_kind       text,
    completed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, attempt_id),
    CONSTRAINT reconcile_attempt_results_attempt_target_fk
        FOREIGN KEY (tenant_id, attempt_id, target_id)
        REFERENCES reconcile_attempts (tenant_id, attempt_id, target_id)
        ON DELETE CASCADE,
    CONSTRAINT reconcile_attempt_results_target_fk
        FOREIGN KEY (tenant_id, target_id)
        REFERENCES reconcile_targets (tenant_id, target_id)
        ON DELETE CASCADE,
    CONSTRAINT reconcile_attempt_results_result_label_valid
        CHECK (result_label IN ('settled', 'requeue_after', 'transient', 'permanent', 'invariant')),
    CONSTRAINT reconcile_attempt_results_error_kind_valid
        CHECK (error_kind IS NULL OR error_kind IN ('transient', 'permanent', 'invariant')),
    CONSTRAINT reconcile_attempt_results_requeue_after_valid
        CHECK (requeue_after_ms IS NULL OR requeue_after_ms >= 0),
    CONSTRAINT reconcile_attempt_results_error_consistent
        CHECK (
            (
                result_label IN ('settled', 'requeue_after')
                AND error_kind IS NULL
            )
            OR (
                result_label IN ('transient', 'permanent', 'invariant')
                AND error_kind IS NOT NULL
            )
        )
);

CREATE INDEX idx_reconcile_attempt_results_completed
    ON reconcile_attempt_results (tenant_id, completed_at);

CREATE INDEX idx_reconcile_attempt_results_result
    ON reconcile_attempt_results (tenant_id, result_label, completed_at);

CREATE INDEX idx_reconcile_attempt_results_latest_target
    ON reconcile_attempt_results (tenant_id, target_id, completed_at DESC, attempt_id DESC);

GRANT SELECT, INSERT ON reconcile_attempt_results TO rss_app;
REVOKE UPDATE, DELETE ON reconcile_attempt_results FROM rss_app;

ALTER TABLE reconcile_attempt_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconcile_attempt_results FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON reconcile_attempt_results
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
