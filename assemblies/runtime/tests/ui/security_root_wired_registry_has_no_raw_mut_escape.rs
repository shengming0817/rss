fn replace_authorizer(
    mut registry: runtime::test_support::SecurityRootWiredRegistry,
    authorizer: std::sync::Arc<dyn httpserve::RouteAuthorizer>,
) {
    registry.register_primary_authorizer(authorizer).unwrap();
}

fn escape_raw_registry(
    mut registry: runtime::test_support::SecurityRootWiredRegistry,
    authorizer: std::sync::Arc<dyn httpserve::RouteAuthorizer>,
) {
    let raw: &mut bootstrap::WriteAdmittedRegistry = registry.as_mut();
    raw.register_primary_authorizer(authorizer).unwrap();
}

fn main() {}
