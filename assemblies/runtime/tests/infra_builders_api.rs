#[test]
fn explicit_rss_access_builder_path_is_public() {
    let _ = runtime::infra::oidc::rss_access_provider_from_static_config;
}
