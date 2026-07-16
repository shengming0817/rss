#[test]
fn infra_builder_paths_are_public() {
    let _ = runtime::infra::oidc::build_provider;
    let _ = runtime::infra::oidc::provider_from_b64;
    assert!(runtime::infra::vault::build_vault_runtime_deps(|_| None).is_err());
    assert!(runtime::infra::s3::build_s3_runtime_deps_from(|_| None).is_err());
    assert!(runtime::infra::vault::build_settings_config_value_key_name_from(|_| None).is_err());
}
