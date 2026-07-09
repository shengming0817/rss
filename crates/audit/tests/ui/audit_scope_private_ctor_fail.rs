use audit::ports::{TenantId, TenantRepoScope};

fn main() {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let _scope = TenantRepoScope::from_authenticated_tenant(tenant);
}
