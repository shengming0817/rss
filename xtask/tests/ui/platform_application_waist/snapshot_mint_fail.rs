use platform_application_waist_contract::{
    ConditionCode, ConditionStatus, ConditionsSnapshot, Diagnostic, DiagnosticCode,
    DiagnosticsSnapshot,
};

fn main() {
    let _conditions = ConditionsSnapshot {
        conditions: Box::new([]),
    };
    let _diagnostics = DiagnosticsSnapshot {
        diagnostics: Box::new([]),
    };
    let _diagnostic = Diagnostic {
        code: DiagnosticCode::RuntimeFailed,
        retryable: true,
        details: Box::new([]),
    };
    let _ = (ConditionCode::RuntimeReady, ConditionStatus::Unknown);
}
