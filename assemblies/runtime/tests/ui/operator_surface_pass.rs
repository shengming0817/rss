fn main() {
    let _ = runtime::operator::is_projection_command;
    let _ = runtime::operator::is_audit_ledger_verify_command;
    let _ = runtime::operator::is_dlq_command;
    let _ = runtime::operator::is_device_latent_inspection_command;
    let _ = runtime::operator::is_reconcile_target_command;
    let _ = runtime::operator::is_settings_config_value_maintenance_command;
    let _ = runtime::operator::is_rss_access_jwks_export_command;
    let _ = runtime::operator::run_projection_control_command;
    let _ = runtime::operator::run_audit_ledger_verify_command;
    let _ = runtime::operator::run_dlq_control_command;
    let _ = runtime::operator::run_device_latent_inspection_command;
    let _ = runtime::operator::run_reconcile_target_command;
    let _ = runtime::operator::run_settings_config_value_maintenance;
    let _ = runtime::operator::run_rss_access_jwks_export_command;
    let _ = runtime::operator::prepare_runtime;
    let _ = runtime::operator::shutdown_runtime;
    let _: Option<runtime::operator::OperatorRuntimeInputs> = None;
    let _ = runtime::support::SystemClock;
    let _ = runtime::support::TracingAuthAuditSink;
}
