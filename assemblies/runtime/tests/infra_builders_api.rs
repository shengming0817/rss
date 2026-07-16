#[test]
fn infra_builder_paths_are_public() {
    let _ = runtime::infra::oidc::build_provider;
    let _ = runtime::infra::oidc::provider_from_b64;
}
