#[test]
fn explicit_oidc_builder_path_is_public() {
    let _ = runtime::infra::oidc::provider_from_static_config;
}
