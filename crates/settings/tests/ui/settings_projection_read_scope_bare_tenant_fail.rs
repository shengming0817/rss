use settings::ports::{SettingsProjectionReadScope, TenantId};

fn bad(tenant: TenantId) {
    let _scope: SettingsProjectionReadScope = tenant.into();
}

fn main() {}
