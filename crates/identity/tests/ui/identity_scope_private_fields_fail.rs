use identity::ports::TenantRepoScope;

fn main() {
    let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let _scope = TenantRepoScope { tenant, _seal: () };
}
