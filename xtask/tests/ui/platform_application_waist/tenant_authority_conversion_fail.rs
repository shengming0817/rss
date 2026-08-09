use platform_application_waist_contract::{TenantId, VerifiedTenant};

fn forge(tenant_id: TenantId) -> VerifiedTenant<'static> {
    tenant_id.into()
}

fn main() {
    let tenant_id = TenantId::parse("8b117a90-752f-4f2a-85f1-00c7c4e1f41c").unwrap();
    let _ = forge(tenant_id);
}
