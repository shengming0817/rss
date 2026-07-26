//! Typed LocalTx operations descriptor ↔ Prometheus alert rules 对账。
//!
//! 只锁真配置：`docs/ops/localtx-alerts.rules.yaml` 是告警系统实际消费的规则文件，
//! descriptor 与它之间的 metric/label/anchor 漂移会让告警静默，属于代码↔配置契约。
//! 面向人的 runbook / dashboard checklist / proof report / adoption 模板不在此对账——
//! 要求散文包含某句话不增加任何 enforcement 强度（见 `docs/rules/README.md` §红线一）。

use observ::{LocalTxMetricPurpose, localtx_operations_descriptor};

const ALERT_RULES: &str = include_str!("../../../docs/ops/localtx-alerts.rules.yaml");

#[test]
fn localtx_operations_descriptor_is_internally_consistent() {
    let operations = localtx_operations_descriptor();
    assert!(operations.is_consistent());
    assert_eq!(
        operations.metrics().len(),
        4,
        "real descriptor anti-vacuity"
    );
    assert_eq!(operations.alerts().len(), 2, "real descriptor anti-vacuity");
    assert_eq!(
        operations
            .metrics()
            .iter()
            .filter(|metric| metric.purpose() == LocalTxMetricPurpose::DeadlineDiagnostic)
            .count(),
        1,
        "typed deadline metric anti-vacuity"
    );
}

#[test]
fn alert_rules_page_only_on_actionable_unsafe_settlements() {
    let operations = localtx_operations_descriptor();
    assert_eq!(operations.alerts().len(), 2, "real descriptor anti-vacuity");
    for alert in operations.alerts() {
        let expression = format!(
            "sum by (domain, contract_id, boundary) (increase({}{{final_status=\"{}\"}}[5m])) > 0",
            alert.metric().name(),
            alert.final_status().as_label()
        );
        assert!(
            ALERT_RULES.contains(alert.name()),
            "rules omit {}",
            alert.name()
        );
        assert!(
            ALERT_RULES.contains(&expression),
            "{} does not preserve the closed metric/label contract",
            alert.name()
        );
        assert!(
            ALERT_RULES.contains(&format!(
                "{}#{}",
                operations.runbook_path(),
                alert.runbook_anchor()
            )),
            "{} does not preserve its runbook anchor",
            alert.name()
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
    for metric in operations
        .metrics()
        .iter()
        .filter(|metric| metric.purpose() == LocalTxMetricPurpose::DeadlineDiagnostic)
    {
        assert!(
            !ALERT_RULES.contains(metric.name()),
            "typed deadline diagnostics must not acquire a paging alert"
        );
    }
}
