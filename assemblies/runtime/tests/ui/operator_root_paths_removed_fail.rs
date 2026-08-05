use runtime::{
    OperatorRuntimeInputs, is_audit_ledger_command, is_dlq_command, is_postgres_command,
    is_projection_command, is_reconcile_target_command, is_rss_access_jwks_export_command,
    is_settings_config_value_maintenance_command, prepare_operator_runtime,
    run_audit_ledger_verify_command, run_dlq_control_command,
    run_postgres_reader_migration_command, run_projection_control_command,
    run_reconcile_target_command, run_rss_access_jwks_export_command,
    run_settings_config_value_maintenance, shutdown_operator_runtime,
};

fn main() {}
