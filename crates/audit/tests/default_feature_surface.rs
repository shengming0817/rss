//! Proves the production-default feature graph cannot name audit's in-memory provider.

#![allow(clippy::expect_used)] // reason: isolated compile-fixture setup must fail the test on I/O errors.

use std::path::Path;
use std::process::Command;

fn write_fixture(root: &Path, dependency_path: &str, features: &str, source: &str) {
    std::fs::create_dir_all(root.join("src")).expect("create fixture");
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            r#"[workspace]

[package]
name = "audit-feature-surface-fixture"
version = "0.0.0"
edition = "2024"

[dependencies]
audit = {{ path = {dependency_path:?}, default-features = false{features} }}
"#,
        ),
    )
    .expect("write manifest");
    std::fs::write(root.join("src/main.rs"), source).expect("write source");
}

fn cargo_check(manifest: &Path, target: &Path) -> std::process::Output {
    Command::new(env!("CARGO"))
        .arg("check")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(target)
        .output()
        .expect("run isolated cargo check")
}

fn assert_default_import_rejected(
    fixture_root: &Path,
    target_root: &Path,
    dependency_path: &str,
    source: &str,
    expected_diagnostic: &str,
) {
    write_fixture(fixture_root, dependency_path, "", source);
    let fixture_name = fixture_root.file_name().expect("fixture name");
    let output = cargo_check(
        &fixture_root.join("Cargo.toml"),
        &target_root.join(format!("{}-target", fixture_name.to_string_lossy())),
    );
    assert!(
        !output.status.success(),
        "default import unexpectedly compiled"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected_diagnostic),
        "compile failure did not prove the expected visibility boundary:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[allow(clippy::expect_used)]
fn in_memory_provider_is_test_support_only() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let target_root = manifest_dir.join("../../target/audit-default-feature-ui");
    let dependency_path = manifest_dir
        .canonicalize()
        .expect("canonical audit path")
        .display()
        .to_string();

    assert_default_import_rejected(
        &target_root.join("default-test-support-fixture"),
        &target_root,
        &dependency_path,
        "use audit::test_support::InMemAuditRepo;\nfn main() {}\n",
        "test_support",
    );
    assert_default_import_rejected(
        &target_root.join("default-root-alias-fixture"),
        &target_root,
        &dependency_path,
        "use audit::InMemAuditRepo;\nfn main() {}\n",
        "InMemAuditRepo",
    );

    let support_fixture = target_root.join("support-fixture");
    write_fixture(
        &support_fixture,
        &dependency_path,
        ", features = [\"test-support\"]",
        "use audit::test_support::{InMemAuditRepo, TestKeyedHasher, keyed_hasher};\nfn main() {}\n",
    );
    let support_output = cargo_check(
        &support_fixture.join("Cargo.toml"),
        &target_root.join("support-target"),
    );
    assert!(
        support_output.status.success(),
        "test-support API did not compile:\n{}",
        String::from_utf8_lossy(&support_output.stderr)
    );
}
