use eventexec::ProjectionVersion;
use settings::ports::{SettingsProjectionReadScope, TenantRepoScope};

fn bad(tenant: TenantRepoScope, generation: ProjectionVersion) {
    let _scope = SettingsProjectionReadScope {
        tenant,
        generation,
        _seal: (),
    };
}

fn main() {}
