use settings::ports::RowRepoScope;

fn accepts_row_scope(_scope: RowRepoScope) {}

fn main() {
    let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let visibility = vocab::RowVisibility::new(vocab::ScopedTenant::Tenant, tenant);

    accepts_row_scope(vocab::RowScope::All);
    accepts_row_scope(vocab::ScopedTenant::Tenant);
    accepts_row_scope(visibility);
}
