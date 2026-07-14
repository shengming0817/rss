//! Postgres domain capability feature contract.
//!
//! Domain-shaped dependencies are opt-in and the integration test profile explicitly exercises all
//! domain capabilities. Cargo/rustc then reject any domain API compiled without its matching feature.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn manifest() -> Result<toml::Value, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

fn string_set(value: &toml::Value) -> Result<BTreeSet<String>, std::io::Error> {
    value
        .as_array()
        .ok_or_else(|| std::io::Error::other("feature value must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| std::io::Error::other("feature member must be a string"))
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()
}

fn feature_set(
    features: &toml::map::Map<String, toml::Value>,
    name: &str,
) -> Result<BTreeSet<String>, std::io::Error> {
    let value = features
        .get(name)
        .ok_or_else(|| std::io::Error::other(format!("missing feature `{name}`")))?;
    string_set(value)
}

fn expected_domain_feature_members(domain: &str) -> BTreeSet<String> {
    let mut expected = BTreeSet::from([format!("dep:{domain}")]);
    if matches!(domain, "settings" | "identity" | "audit") {
        expected.insert("dep:observ".to_owned());
    }
    expected
}

#[test]
fn domain_dependencies_are_optional_and_features_are_explicit()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("dependencies must be a table"))?;
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("features must be a table"))?;
    let domain_feature_names: BTreeSet<_> = features
        .keys()
        .filter(|name| name.starts_with("domain-"))
        .cloned()
        .collect();
    assert!(
        !domain_feature_names.is_empty(),
        "postgres must declare at least one domain-* feature"
    );

    for feature_name in &domain_feature_names {
        let domain = feature_name
            .strip_prefix("domain-")
            .ok_or_else(|| std::io::Error::other(format!("bad domain feature `{feature_name}`")))?;
        let dependency = dependencies
            .get(domain)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| {
                std::io::Error::other(format!("{domain} must be a normal dependency table"))
            })?;
        assert_eq!(
            dependency.get("optional").and_then(toml::Value::as_bool),
            Some(true),
            "{domain} must be optional"
        );
        let expected_path = format!("../../crates/{domain}");
        assert_eq!(
            dependency.get("path").and_then(toml::Value::as_str),
            Some(expected_path.as_str()),
            "{domain} must resolve to the workspace domain crate"
        );
        assert_eq!(
            feature_set(features, feature_name)?,
            expected_domain_feature_members(domain),
            "{feature_name} must activate its matching dependency and only sanctioned shared capabilities"
        );
    }

    assert_eq!(
        feature_set(features, "default")?,
        BTreeSet::new(),
        "default features must be empty"
    );
    let mut expected_integration = domain_feature_names.clone();
    expected_integration.insert("testkit/containers".to_owned());
    assert_eq!(
        feature_set(features, "integration")?,
        expected_integration,
        "integration must explicitly exercise all derived domain features"
    );
    Ok(())
}

#[test]
fn domain_feature_shared_capability_allowlist_is_closed() {
    assert_eq!(
        expected_domain_feature_members("settings"),
        BTreeSet::from(["dep:observ".to_owned(), "dep:settings".to_owned()])
    );
    assert_eq!(
        expected_domain_feature_members("identity"),
        BTreeSet::from(["dep:identity".to_owned(), "dep:observ".to_owned()])
    );
    assert_eq!(
        expected_domain_feature_members("audit"),
        BTreeSet::from(["dep:audit".to_owned(), "dep:observ".to_owned()])
    );
    assert_ne!(
        expected_domain_feature_members("settings"),
        BTreeSet::from([
            "dep:observ".to_owned(),
            "dep:settings".to_owned(),
            "dep:unknown".to_owned(),
        ]),
        "unknown shared dependencies must not be accepted"
    );
}

#[test]
fn journey_fault_support_is_independent_from_general_test_support()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("features must be a table"))?;

    assert_eq!(
        feature_set(features, "test-support")?,
        BTreeSet::new(),
        "general test support must not activate journey transaction faults"
    );
    assert_eq!(
        feature_set(features, "journey-fault-support")?,
        BTreeSet::new(),
        "journey fault support must remain an explicit leaf feature"
    );

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for source in ["src/cotx/mod.rs", "src/refresh_token_store.rs"] {
        let source = fs::read_to_string(root.join(source))?;
        assert!(
            !source.contains("feature = \"test-support\""),
            "transaction fault code must not be compiled by general test support"
        );
    }
    let bundle = fs::read_to_string(root.join("src/bundle.rs"))?;
    assert!(
        bundle.contains(
            "#[cfg(feature = \"journey-fault-support\")]\n    #[must_use]\n    pub fn refresh_token_store_with_commit_unknown_once"
        ),
        "the public one-shot constructor must be owned by the narrow journey fault feature"
    );
    Ok(())
}

#[cfg(all(feature = "domain-identity", feature = "journey-fault-support"))]
#[test]
fn journey_fault_feature_exposes_only_the_named_refresh_constructor() {
    let _constructor: fn(
        &postgres::PgDomainDeps<postgres::caps::Identity>,
        &str,
    ) -> postgres::PgRefreshTokenStore = postgres::PgDomainDeps::<
        postgres::caps::Identity,
    >::refresh_token_store_with_commit_unknown_once;
}

#[test]
fn backend_profiles_do_not_hand_author_provider_outcomes() -> Result<(), Box<dyn std::error::Error>>
{
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/integration_tests.rs"),
    )?;
    for forbidden in [
        "AuditLocalTxProfileError::synthetic",
        "refresh request rejected before rotate",
        "cross-tenant refresh rejected before rotate",
        "let conflict_attempts = AtomicUsize::new(0)",
        "let rejected_mutations = AtomicUsize::new(0)",
    ] {
        assert!(
            !source.contains(forbidden),
            "backend profile must not hand-author provider outcome via `{forbidden}`"
        );
    }
    Ok(())
}
