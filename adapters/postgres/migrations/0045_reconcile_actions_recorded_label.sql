-- 0045_reconcile_actions_recorded_label.sql
-- Make reconcile_actions action-local. Terminal attempt outcomes live in reconcile_attempt_results.

INSERT INTO reconcile_attempt_results
    (tenant_id, attempt_id, target_id, result_label, requeue_after_ms, error_kind, completed_at)
SELECT tenant_id,
       attempt_id,
       target_id,
       result_label,
       requeue_after_ms,
       CASE
         WHEN result_label IN ('transient', 'permanent', 'invariant')
         THEN COALESCE(error_kind, result_label)
         ELSE NULL
       END,
       created_at
FROM (
    SELECT DISTINCT ON (tenant_id, attempt_id)
           tenant_id,
           attempt_id,
           target_id,
           result_label,
           requeue_after_ms,
           error_kind,
           created_at,
           action_id
    FROM reconcile_actions
    ORDER BY tenant_id, attempt_id, created_at DESC, action_id DESC
) legacy_terminal
ON CONFLICT (tenant_id, attempt_id) DO NOTHING;

ALTER TABLE reconcile_actions
    DROP CONSTRAINT reconcile_actions_result_label_valid;

UPDATE reconcile_actions
SET result_label = 'recorded',
    requeue_after_ms = NULL,
    error_kind = NULL;

ALTER TABLE reconcile_actions
    ADD CONSTRAINT reconcile_actions_result_label_valid
    CHECK (result_label = 'recorded');

ALTER TABLE reconcile_actions
    ADD CONSTRAINT reconcile_actions_terminal_fields_absent
    CHECK (requeue_after_ms IS NULL AND error_kind IS NULL);
