const ALERT_RULES: &str = include_str!("../../../docs/ops/localtx-alerts.rules.yaml");
const DASHBOARD: &str =
    include_str!("../../../docs/ops/202607082104-1642-consistency-dashboard-checklist.md");
const RUNBOOK: &str =
    include_str!("../../../docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md");

const DASHBOARD_QUERIES: [(&str, &str); 4] = [
    (
        "localtx_retry_attempts_total",
        "sum by (domain, contract_id, boundary, retry_class) (rate(localtx_retry_attempts_total[5m]))",
    ),
    (
        "localtx_final_total",
        "sum by (domain, contract_id, boundary, final_status) (rate(localtx_final_total[5m]))",
    ),
    (
        "localtx_attempts",
        "sum by (domain, contract_id, boundary, final_status, le) (rate(localtx_attempts_bucket[5m]))",
    ),
    (
        "tx_settlement_final_total",
        "sum by (boundary, final_status) (rate(tx_settlement_final_total[5m]))",
    ),
];

#[test]
fn dashboard_consumes_every_transaction_settlement_metric_with_closed_labels() {
    for (metric, query) in DASHBOARD_QUERIES {
        assert!(
            DASHBOARD.contains(query),
            "dashboard omits exact query/labels for {metric}"
        );
    }
}

#[test]
fn alert_rules_page_only_on_actionable_unsafe_settlements() {
    for (alert, status) in [
        ("LocalTxCommitUnknown", "commit_unknown"),
        ("LocalTxRollbackFailed", "rollback_failed"),
    ] {
        let expression = format!(
            "sum by (domain, contract_id, boundary) (increase(localtx_final_total{{final_status=\"{status}\"}}[5m])) > 0"
        );
        assert!(ALERT_RULES.contains(alert), "rules omit {alert}");
        assert!(
            ALERT_RULES.contains(&expression),
            "{alert} does not preserve the closed metric/label contract"
        );
    }
    for (alert, status) in [
        ("GenericTxCommitUnknown", "commit_unknown"),
        ("GenericTxRollbackFailed", "rollback_failed"),
    ] {
        let expression = format!(
            "sum by (boundary) (increase(tx_settlement_final_total{{final_status=\"{status}\"}}[5m])) > 0"
        );
        assert!(ALERT_RULES.contains(alert), "rules omit {alert}");
        assert!(
            ALERT_RULES.contains(&expression),
            "{alert} does not preserve the closed metric/label contract"
        );
    }
    assert!(
        !ALERT_RULES.contains("tx_retry_final_total"),
        "generic retry exhaustion must not page"
    );
    assert!(
        !ALERT_RULES.contains("retry_status=\"exhausted\""),
        "retry exhaustion must not page"
    );
}

#[test]
fn alerts_link_an_actionable_runbook() {
    for token in [
        "202607130312-1705-localtx-unsafe-settlement.md",
        "commit_unknown",
        "rollback_failed",
        "do not retry",
    ] {
        assert!(
            ALERT_RULES.contains(token) || RUNBOOK.contains(token),
            "operator contract omits {token}"
        );
    }
}

#[test]
fn generic_unsafe_warn_uses_the_metric_routing_scope_without_localtx_duplication() {
    for token in [
        "generic WARN routing fields are exactly",
        "`boundary` and",
        "`final_status`; both values come from the same closed settlement routing",
        "The generic runner is the only generic unsafe-settlement WARN emitter",
        "HTTP LocalTx keeps its contract-attributed WARN path",
    ] {
        assert!(
            RUNBOOK.contains(token),
            "runbook does not lock the generic metric/WARN routing contract: {token}"
        );
    }
}
