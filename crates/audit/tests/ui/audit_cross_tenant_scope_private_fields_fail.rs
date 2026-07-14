use audit::ports::CrossTenantReadScope;

fn bypass(visibility: vocab::RowVisibility, target: vocab::TenantId) {
    let _scope = CrossTenantReadScope {
        visibility,
        target,
        _seal: (),
    };
}

fn main() {}
