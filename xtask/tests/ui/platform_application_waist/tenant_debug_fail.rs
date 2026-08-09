use std::fmt::Debug;

use platform_application_waist_contract::VerifiedTenant;

fn demand_debug<T: Debug>() {}

fn main() {
    demand_debug::<VerifiedTenant<'static>>();
}
