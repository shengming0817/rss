//! Postgres domain capability feature contract.
//!
//! Domain-shaped dependencies are opt-in and the integration test profile explicitly exercises all
//! domain capabilities. Cargo/rustc then reject any domain API compiled without its matching feature.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

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
    if matches!(domain, "settings" | "identity") {
        expected.insert("dep:httpserve".to_owned());
    }
    if domain == "identity" {
        // Device-certificate persistence vocabulary lives behind domain-identity.
        expected.insert("dep:deviceloop".to_owned());
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
    expected_integration.insert("auth-audit-sink".to_owned());
    expected_integration.insert("dep:serde_json_canonicalizer".to_owned());
    expected_integration.insert("eventexec/internal-test-support".to_owned());
    expected_integration.insert("eventexec/l2-test-support".to_owned());
    expected_integration.insert("test-support".to_owned());
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
        BTreeSet::from([
            "dep:httpserve".to_owned(),
            "dep:observ".to_owned(),
            "dep:settings".to_owned(),
        ])
    );
    assert_eq!(
        expected_domain_feature_members("identity"),
        BTreeSet::from([
            "dep:deviceloop".to_owned(),
            "dep:httpserve".to_owned(),
            "dep:identity".to_owned(),
            "dep:observ".to_owned(),
        ])
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
fn journey_fault_support_does_not_restore_refresh_store_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("features must be a table"))?;

    assert_eq!(
        feature_set(features, "test-support")?,
        BTreeSet::from([
            "eventexec/internal-test-support".to_owned(),
            "eventexec/l2-test-support".to_owned(),
        ]),
        "general test support may forward eventexec fixtures but must not activate journey transaction faults"
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
        !bundle.contains("refresh_token_store_with_commit_unknown_once"),
        "journey faults must not restore the deleted refresh writer constructor"
    );
    Ok(())
}

#[test]
fn fault_matrix_support_closes_its_shipped_dependency_graph()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("dependencies must be a table"))?;
    let dev_dependencies = manifest
        .get("dev-dependencies")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("dev-dependencies must be a table"))?;
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("features must be a table"))?;

    // After #1903 / PR #675, fault-matrix shipped feature no longer optional-deps `generated`;
    // integration fixtures keep it as a normal (non-optional) dev-dependency only.
    assert!(
        dependencies.get("generated").is_none(),
        "fault-matrix shipped feature must not pull generated into normal dependencies"
    );
    let generated = dev_dependencies
        .get("generated")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| std::io::Error::other("generated must be a normal dev-dependency table"))?;
    assert_eq!(
        generated.get("path").and_then(toml::Value::as_str),
        Some("../../generated")
    );
    assert_eq!(
        feature_set(features, "fault-matrix-test-support")?,
        BTreeSet::from([
            "auth-audit-sink".to_owned(),
            "dep:anyhow".to_owned(),
            "dep:identity".to_owned(),
            "dep:serde_json_canonicalizer".to_owned(),
            "diport/test-support".to_owned(),
            "domain-audit".to_owned(),
            "domain-identity".to_owned(),
            "domain-settings".to_owned(),
            "eventexec/internal-test-support".to_owned(),
            "eventexec/l2-test-support".to_owned(),
            "identity/fault-matrix-test-support".to_owned(),
            "test-support".to_owned(),
        ]),
        "fault support must compile from its declared shipped feature alone"
    );
    Ok(())
}

fn sha256(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let digest = Sha256::digest(fs::read(path)?);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hex, "{byte:02x}")?;
    }
    Ok(hex)
}

fn collect_vendor_files(
    root: &std::path::Path,
    directory: &std::path::Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_vendor_files(root, &path, files)?;
        } else {
            files.push(path.strip_prefix(root)?.to_path_buf());
        }
    }
    Ok(())
}

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}

#[test]
fn exclusive_root_vendor_matches_the_audited_crates_io_delta()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendor = root.join("../../vendor/sqlx-core-0.8.6");
    let modified = BTreeSet::from([
        "Cargo.toml",
        "Cargo.toml.orig",
        "src/lib.rs",
        "src/net/tls/mod.rs",
        "src/net/tls/tls_rustls.rs",
    ]);
    // Complete code/manifest delta against the crates.io 0.8.6 archive. Every other upstream file
    // is covered by the aggregate tree receipt below.
    let expected_delta = [
        (
            "Cargo.toml",
            "05446ffc84fbeb8dffca4dd61138911f53b044792889400e9244529e44b3b22e",
            "e15ff012a980f27416146561573e7011e022f05db817bfb7365e70a2fe110c16",
        ),
        (
            "Cargo.toml.orig",
            "e9f6cb3c07e434a902dff58029c6ef7289009951f31c2eae1ae240d2465e3470",
            "7a0cdd6dacff2176ca7088125b621c03802912f23855026283e21dc07a7bc821",
        ),
        (
            "src/lib.rs",
            "7189282445ae36a313b70d71263ce41a80e64d939de7c60318cc4e5f010b16f0",
            "b6f6c6eb6efd2ec30fffd4bf4f8c2b9edd79f77bfb6b6f5cd2eeef953df4b7b3",
        ),
        (
            "src/net/tls/mod.rs",
            "01696d72da790695731b565f9473e3047ff5651b4d71781ef38e9e53fe104c81",
            "fd174c34f469e58f724b4a2808ee55339b44fab79728399da598a2b2377ed926",
        ),
        (
            "src/net/tls/tls_rustls.rs",
            "c0d2428e5c5e8610856b44f50c1553eca8956297ca21269347571d29c2e08807",
            "aa1da2086ef820b0b425b73c7b9b82f757ebf6478aa815fa46c176b6be129d00",
        ),
    ];
    for (path, upstream, patched) in expected_delta {
        let actual = sha256(&vendor.join(path))?;
        assert_ne!(
            actual, upstream,
            "{path} unexpectedly reverted to upstream bytes"
        );
        assert_eq!(actual, patched, "unexpected patched bytes in {path}");
    }
    assert_eq!(
        sha256(&vendor.join(".cargo-ok"))?,
        "afbf9d0f3560b0fd7795e81c42a0a79ee6b6fc67e064f77826aee642cad28d91"
    );
    assert_eq!(
        sha256(&vendor.join("RSS-PATCH.md"))?,
        "ef622e8e045425ed0a5721d19aa629495057c6b5345411079e824afe5a217177"
    );

    let mut files = Vec::new();
    collect_vendor_files(&vendor, &vendor, &mut files)?;
    files.sort();
    let mut unmodified_tree = Sha256::new();
    for relative in files {
        let relative = relative
            .to_str()
            .ok_or_else(|| std::io::Error::other("vendor path must be UTF-8"))?;
        if modified.contains(relative) || matches!(relative, ".cargo-ok" | "RSS-PATCH.md") {
            continue;
        }
        unmodified_tree.update(relative.as_bytes());
        unmodified_tree.update([0]);
        unmodified_tree.update(Sha256::digest(fs::read(vendor.join(relative))?));
    }
    let mut actual_tree = String::new();
    for byte in unmodified_tree.finalize() {
        write!(&mut actual_tree, "{byte:02x}")?;
    }
    assert_eq!(
        actual_tree, "8c915906ac162b2a49e74c4fde70e3a43da5c1477d3e063ce87dc4558accd136",
        "unmodified files must exactly match the sqlx-core 0.8.6 archive (sha256 ee6798b1838b6a0f69c007c133b8df5866302197e404e8b6ee8ed3e3a5e68dc6)"
    );
    Ok(())
}

#[test]
fn exclusive_root_vendor_tests_and_feature_union_compile_fail_are_executable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sandbox = std::env::temp_dir().join(format!(
        "rss-vendor-sqlx-core-policy-{}",
        std::process::id()
    ));
    if sandbox.exists() {
        fs::remove_dir_all(&sandbox)?;
    }
    let source = sandbox.join("source");
    copy_tree(&root.join("vendor/sqlx-core-0.8.6"), &source)?;
    let manifest = source.join("Cargo.toml");
    let target = sandbox.join("target");
    let positive = Command::new(env!("CARGO"))
        .args(["test", "--manifest-path"])
        .arg(&manifest)
        .args([
            "--features",
            "rss-exclusive-explicit-roots",
            "rss_exclusive_explicit_roots_tests",
            "--quiet",
        ])
        .env("CARGO_TARGET_DIR", &target)
        .output()?;
    let negative = Command::new(env!("CARGO"))
        .args(["check", "--manifest-path"])
        .arg(&manifest)
        .args([
            "--no-default-features",
            "--features",
            "rss-exclusive-explicit-roots,_tls-native-tls",
        ])
        .env("CARGO_TARGET_DIR", &target)
        .output()?;
    let stderr = String::from_utf8_lossy(&negative.stderr);
    fs::remove_dir_all(&sandbox)?;
    assert!(
        positive.status.success(),
        "vendored exclusive-root tests failed:\n{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    assert!(
        !negative.status.success(),
        "forbidden TLS feature union compiled"
    );
    assert!(
        stderr.contains(
            "rss-exclusive-explicit-roots cannot be combined with native-tls because native roots are ambient"
        ),
        "feature union failed for the wrong reason:\n{stderr}"
    );
    Ok(())
}

#[test]
fn backend_profiles_do_not_hand_author_provider_outcomes() -> Result<(), Box<dyn std::error::Error>>
{
    let source = read_integration_test_sources(&PathBuf::from(env!("CARGO_MANIFEST_DIR")))?;
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

fn read_integration_test_sources(
    crate_root: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let facade = crate_root.join("src/integration_tests.rs");
    let mut paths = vec![facade];
    collect_ordinary_rust_files(&crate_root.join("src/integration_tests"), &mut paths)?;
    paths.sort();
    let mut combined = String::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "integration evidence source must be an ordinary non-symlink file: {}",
                path.display()
            )
            .into());
        }
        let bytes = fs::read(&path)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            format!(
                "integration evidence source must be UTF-8: {}",
                path.display()
            )
        })?;
        combined.push_str(text);
        combined.push('\n');
    }
    Ok(combined)
}

fn collect_ordinary_rust_files(
    dir: &std::path::Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "integration evidence tree must not contain symlinks: {}",
                path.display()
            )
            .into());
        }
        if metadata.is_dir() {
            collect_ordinary_rust_files(&path, paths)?;
        } else if metadata.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            paths.push(path);
        }
    }
    Ok(())
}
