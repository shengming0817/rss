use audit::ports::CrossTenantReadScope;

fn duplicate(scope: CrossTenantReadScope) {
    let _duplicate = scope.clone();
}

fn main() {}
