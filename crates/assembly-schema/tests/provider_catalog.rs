#![allow(clippy::expect_used, clippy::panic)]
// reason: fixed protocol fixtures use direct assertion failures with local context.

use assembly_schema::{
    AssemblyManifest, DiportPort, LifecycleChannel, ProviderCatalogEntry, ProviderConstructor,
    ProviderConsumer, ProviderDurability, ProviderFactorySymbol, ProviderFailurePosture,
    ProviderRole, ProviderScope,
};

const RUNTIME_MANIFEST: &str = include_str!("../../../assemblies/runtime/assembly.toml");

#[test]
fn provider_roles_and_consumers_are_closed_at_deserialization() {
    let unknown_role = RUNTIME_MANIFEST.replace(
        "id = \"listener-pdp\"",
        "id = \"unregistered-listener-pdp\"",
    );
    assert!(AssemblyManifest::from_toml_str(&unknown_role).is_err());

    let unknown_consumer =
        RUNTIME_MANIFEST.replace("consumer = \"httpserve\"", "consumer = \"unknown-http\"");
    assert!(AssemblyManifest::from_toml_str(&unknown_consumer).is_err());
}

#[test]
fn canonicalization_rejects_registry_drift() {
    for (from, to, field, expected, actual) in [
        (
            "port = \"diport::Pdp\"",
            "port = \"diport::Signer\"",
            "port",
            "diport::Pdp",
            "diport::Signer",
        ),
        (
            "provider = \"oidc::OidcProvider\"",
            "provider = \"vault::VaultSigner\"",
            "provider",
            "oidc::OidcProvider",
            "vault::VaultSigner",
        ),
        (
            "providerCrate = \"oidc\"",
            "providerCrate = \"vault\"",
            "providerCrate",
            "\"oidc\"",
            "\"vault\"",
        ),
        (
            "consumer = \"httpserve\"",
            "consumer = \"oidc\"",
            "consumer",
            "httpserve",
            "oidc",
        ),
        (
            "requiredFeatures = [\"backend\"]",
            "requiredFeatures = []",
            "requiredFeatures",
            "[\"backend\"]",
            "[]",
        ),
        (
            "lifecycle = \"active\"",
            "lifecycle = \"draft\"",
            "lifecycle",
            "active",
            "draft",
        ),
        (
            "durability = \"ephemeral-memory\"",
            "durability = \"persistent\"",
            "durability",
            "ephemeral-memory",
            "persistent",
        ),
        (
            "outputs = [\"resources\"]",
            "outputs = [\"workers\"]",
            "outputs",
            "[\"resources\"]",
            "[\"workers\"]",
        ),
    ] {
        let changed = RUNTIME_MANIFEST.replacen(from, to, 1);
        let manifest = AssemblyManifest::from_toml_str(&changed).expect("typed manifest");
        let error = match manifest.canonicalize_v2() {
            Ok(_) => panic!("registry drift must fail closed"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(field), "{field}: {error}");
        assert!(
            error.contains("provider="),
            "provider identity must remain actionable: {error}"
        );
        assert!(
            error.contains(&format!("expected={expected} actual={actual}")),
            "registry correction must preserve expected/actual: {error}"
        );
    }
}

#[test]
fn factory_symbol_serde_and_schema_use_the_display_id() {
    let schema =
        serde_json::to_value(schemars::schema_for!(ProviderFactorySymbol)).expect("factory schema");
    let values = schema["enum"].as_array().expect("factory enum values");
    assert_eq!(values.len(), 17);
    for value in values {
        let factory: ProviderFactorySymbol =
            serde_json::from_value(value.clone()).expect("schema factory ID deserializes");
        assert_eq!(
            serde_json::to_value(factory).expect("serialize factory symbol"),
            serde_json::json!(factory.as_str())
        );
    }
}

#[test]
fn active_revocation_role_cannot_be_demoted_without_a_registry_change() {
    let changed = RUNTIME_MANIFEST.replacen(
        "id = \"device-revocation-store\"\nport = \"diport::RevocationStore\"\nprovider = \"postgres::PgRevocationStore\"\nproviderCrate = \"postgres\"\nrequiredFeatures = []\nconsumer = \"deviceloop\"\nlifecycle = \"active\"",
        "id = \"device-revocation-store\"\nport = \"diport::RevocationStore\"\nprovider = \"postgres::PgRevocationStore\"\nproviderCrate = \"postgres\"\nrequiredFeatures = []\nconsumer = \"deviceloop\"\nlifecycle = \"draft\"",
        1,
    );
    let manifest = AssemblyManifest::from_toml_str(&changed).expect("typed manifest");
    assert!(manifest.canonicalize_v2().is_err());
}

#[test]
fn active_empty_output_provider_is_a_canonical_registry_fact() {
    let manifest = AssemblyManifest::from_toml_str(RUNTIME_MANIFEST).expect("runtime manifest");
    let canonical = manifest.canonicalize_v2().expect("canonical manifest");
    let limiter = canonical
        .diport_providers()
        .iter()
        .find(|provider| provider.id == ProviderRole::ListenerRateLimiter)
        .expect("rate limiter");
    assert!(limiter.outputs.is_empty());
}

const RATE_LIMITER_ENTRY: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    DiportPort::RateLimiter,
    ProviderConstructor::RatelimitGovernorLimiter,
    ProviderFactorySymbol::HttpserveGovernorRateLimiter,
    "ratelimit",
    &[],
    ProviderConsumer::Httpserve,
    ProviderDurability::EphemeralMemory,
    None,
    None,
    &[],
);

const REPLAY_ENTRY: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ServiceTokenReplayStore,
    DiportPort::ServiceTokenReplayStore,
    ProviderConstructor::PostgresServiceTokenReplayStore,
    ProviderFactorySymbol::OidcPostgresServiceTokenReplayStore,
    "postgres",
    &[],
    ProviderConsumer::Oidc,
    ProviderDurability::Persistent,
    Some(ProviderScope::ClusterGlobal),
    Some(ProviderFailurePosture::FailClosed),
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

#[test]
fn checked_entry_exposes_only_canonical_capability_evidence() {
    assert_eq!(RATE_LIMITER_ENTRY.role(), ProviderRole::ListenerRateLimiter);
    assert_eq!(
        RATE_LIMITER_ENTRY.factory(),
        ProviderFactorySymbol::HttpserveGovernorRateLimiter
    );
    assert_eq!(
        RATE_LIMITER_ENTRY.evidence().constructor(),
        ProviderConstructor::RatelimitGovernorLimiter
    );
    assert!(RATE_LIMITER_ENTRY.evidence().outputs().is_empty());
    assert_eq!(
        RATE_LIMITER_ENTRY.evidence().consumer(),
        ProviderConsumer::Httpserve
    );
    assert_eq!(
        RATE_LIMITER_ENTRY.evidence().durability(),
        ProviderDurability::EphemeralMemory
    );
    assert_eq!(RATE_LIMITER_ENTRY.evidence().scope(), None);
    assert_eq!(RATE_LIMITER_ENTRY.evidence().failure_posture(), None);
    assert_eq!(
        RATE_LIMITER_ENTRY.evidence().required_features(),
        &[] as &[&str]
    );
    assert_eq!(
        RATE_LIMITER_ENTRY.evidence().port(),
        DiportPort::RateLimiter
    );
    assert_eq!(LifecycleChannel::Resources.as_str(), "resources");
}

#[test]
fn replay_catalog_evidence_is_cluster_global_and_fail_closed() {
    assert_eq!(
        REPLAY_ENTRY.evidence().scope(),
        Some(ProviderScope::ClusterGlobal)
    );
    assert_eq!(
        REPLAY_ENTRY.evidence().failure_posture(),
        Some(ProviderFailurePosture::FailClosed)
    );
}
