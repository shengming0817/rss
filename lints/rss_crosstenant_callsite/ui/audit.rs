#![allow(dead_code)]

mod ports {
    pub struct CrossTenantReadScope;

    impl CrossTenantReadScope {
        pub(crate) fn from_durable_append() {
            let capability = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin();
            let visibility = vocab::tenant::CrossTenantVisibility::authorize(capability);
            let _scope = vocab::tenant::RowVisibility::new_cross_tenant(visibility);
        }
    }
}

fn from_durable_append() {
    let _capability = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin();
}

fn main() {}
