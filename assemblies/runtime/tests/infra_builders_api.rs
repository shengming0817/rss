#[test]
fn infra_builder_paths_are_public() {
    let _ = runtime::infra::oidc::build_provider;
    let _ = runtime::infra::oidc::provider_from_b64;
    let _ = runtime::infra::pg::build_pg_config;
    let _ = runtime::infra::pg::build_pg_read_config;
    let _ = runtime::infra::pg::build_pg_audit_admin_config;
    let _ = runtime::infra::pg::build_pg_migrator_config;
    let _ = runtime::build_pg_read_config;
    assert!(runtime::infra::vault::build_vault_runtime_deps(|_| None).is_err());
    let redis_future = runtime::infra::redis::build_redis_runtime_deps(|_| None);
    drop(redis_future);
    assert!(runtime::infra::s3::build_s3_runtime_deps_from(|_| None).is_err());
    assert!(runtime::infra::vault::build_settings_config_value_key_name_from(|_| None).is_err());
}
