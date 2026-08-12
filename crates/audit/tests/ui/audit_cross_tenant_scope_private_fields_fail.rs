use audit::ports::CrossTenantReadScope;

fn bypass(visibility: vocab::RowVisibility, target: rss_request_context::TenantId) {
    let _scope = CrossTenantReadScope {
        visibility,
        target,
        _seal: (),
    };
}

fn main() {}
