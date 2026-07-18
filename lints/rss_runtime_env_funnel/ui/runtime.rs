#![allow(dead_code, unused, unknown_lints)]
// aux-build: macro_helper.rs
// compile-flags: --crate-name runtime

macro_rules! production_module {
    () => {
        #[path = "auxiliary/generated.rs"]
        mod generated;
    };
}
production_module!();

#[cfg(test)]
#[path = "auxiliary/generated.rs"]
mod test_generated;

extern crate macro_helper;
use macro_helper::reexported_invoke as invoke;

const CROSS_FILE_COMPILE_ENV: Option<&str> = invoke!(option_env);
const DIRECT_COMPILE_ENV: &str = env!("CARGO_PKG_NAME");
const INCLUDED_EXPR: &str = include!("auxiliary/included_expr.rs");

mod config {
    pub(crate) trait RuntimeConfigSource {
        fn read(&mut self);
    }

    pub(crate) struct EnvConfigSource;

    impl RuntimeConfigSource for EnvConfigSource {
        fn read(&mut self) {
            // G1: exact canonical source owner and exact direct reader are allowed.
            let _ = std::env::var_os("RSS_CANONICAL");
        }
    }

    pub(crate) struct RuntimeConfigSnapshot;

    impl RuntimeConfigSnapshot {
        pub(crate) fn capture_process_snapshot() -> Self {
            Self
        }
    }
}

fn prepare_runtime_kernel() {
    // G2: exact top-level lifecycle owner may reference the sole process factory.
    let _ = config::RuntimeConfigSnapshot::capture_process_snapshot();
}

fn second_capture() {
    // R1: factory reference from any other owner is rejected.
    let _ = config::RuntimeConfigSnapshot::capture_process_snapshot();
}

fn ambient_direct() {
    // R2: direct std::env reader outside the funnel is rejected.
    let _ = std::env::var("RSS_DIRECT");
}

fn ambient_function_item_alias() {
    // R3: a function-item alias resolves to the same std::env DefId and is rejected.
    use std::env::var_os as read;
    let read_later = read;
    let _ = read_later("RSS_ALIAS");
}

fn load_projection_maintenance_grants_from_command_env() {
    let _ = std::env::var("RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS");
}

fn load_audit_ledger_verify_grants_from_command_env() {
    let _ = std::env::var("RSS_AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS");
}

fn load_dlq_operator_grants_from_command_env() {
    let _ = std::env::var("RSS_DLQ_OPERATOR_GRANTS");
}

fn load_reconcile_operator_grants_from_command_env() {
    let _ = std::env::var("RSS_RECONCILE_OPERATOR_GRANTS");
}

struct UnrelatedSnapshot;

impl UnrelatedSnapshot {
    fn capture_process_snapshot() -> Self {
        Self
    }
}

fn specificity_greens() {
    // G3: non-reader std::env functions and same-named unrelated methods are not governed.
    let _ = std::env::current_dir();
    let _ = UnrelatedSnapshot::capture_process_snapshot();
}

fn main() {}
