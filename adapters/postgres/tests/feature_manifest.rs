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
        let mut expected_members = BTreeSet::from([format!("dep:{domain}")]);
        if domain == "identity" {
            expected_members.insert("dep:observ".to_owned());
        }
        assert_eq!(
            feature_set(features, feature_name)?,
            expected_members,
            "{feature_name} must activate only its matching dependency and reviewed companions"
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
