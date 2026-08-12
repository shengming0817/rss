use settings::ports::RowRepoScope;

fn accepts_row_scope(_scope: RowRepoScope) {}

fn main() {
    let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let visibility = vocab::RowVisibility::new(rss_request_context::RowScope::Tenant, tenant);

    accepts_row_scope(rss_request_context::RowScope::All);
    accepts_row_scope(rss_request_context::RowScope::Tenant);
    accepts_row_scope(visibility);
}
