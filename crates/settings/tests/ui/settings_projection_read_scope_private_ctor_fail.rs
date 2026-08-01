use eventexec::ProjectionVersion;
use settings::ports::{SettingsProjectionReadScope, TenantRepoScope};

fn bad(tenant: TenantRepoScope, generation: ProjectionVersion) {
    let _scope = SettingsProjectionReadScope::from_tenant_generation(tenant, generation);
}

fn main() {}
