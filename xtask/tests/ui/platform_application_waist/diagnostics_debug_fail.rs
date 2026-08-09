use std::fmt::Debug;

use platform_application_waist_contract::DiagnosticsSnapshot;

fn demand_debug<T: Debug>() {}

fn main() {
    demand_debug::<DiagnosticsSnapshot>();
}
