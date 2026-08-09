use platform_application_waist_contract::{TenantId, VerifiedTenant};

fn forge(tenant_id: &TenantId) -> VerifiedTenant<'_> {
    VerifiedTenant { id: tenant_id }
}

fn main() {
    let _ = forge;
}
