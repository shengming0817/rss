//! Proves the default production feature graph has no raw route-mounting surface.
//!
//! The crate's own dev-dependency enables `test-util`, so a normal trybuild case cannot prove the
//! default graph. This test checks an isolated, default-features-only consumer with a dedicated,
//! reusable target directory. The residual feature-gated test surface remains a Medium guard.
//!
//! This is the isolated default-feature compile evidence for `ROUTE-MOUNT-NOBYPASS-01`.

use std::path::Path;
use std::process::Command;

#[test]
#[allow(clippy::expect_used)]
fn default_feature_graph_excludes_raw_mounting_api() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_target = manifest_dir.join("../../target/httpserve-default-feature-ui");
    let fixture = workspace_target.join("fixture");
    std::fs::create_dir_all(fixture.join("src")).expect("create fixture");

    let dependency_path = manifest_dir
        .canonicalize()
        .expect("canonical httpserve path")
        .display()
        .to_string();
    std::fs::write(
        fixture.join("Cargo.toml"),
        format!(
            r#"[workspace]

[package]
name = "httpserve-default-feature-ui"
version = "0.0.0"
edition = "2024"

[dependencies]
httpserve = {{ path = {dependency_path:?}, default-features = false }}
"#,
        ),
    )
    .expect("write fixture manifest");
    std::fs::write(
        fixture.join("src/main.rs"),
        r#"use httpserve::{Listener, ListenerRouter, TestPrimaryRoute, TestRoute, TestRoutePermission, TestRouteResourceScope};
use httpserve::routes::unfinalized_for_test;

fn raw_method<L: Listener>(router: ListenerRouter<L>) {
    let _ = router.mount_raw_for_test;
}

fn main() {}
"#,
    )
    .expect("write fixture source");

    let output = Command::new(env!("CARGO"))
        .arg("check")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(fixture.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(workspace_target.join("target"))
        .output()
        .expect("run isolated cargo check");

    assert!(
        !output.status.success(),
        "raw test API unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for symbol in [
        "TestPrimaryRoute",
        "TestRoute",
        "TestRoutePermission",
        "TestRouteResourceScope",
        "unfinalized_for_test",
        "mount_raw_for_test",
        "test-util",
    ] {
        assert!(
            stderr.contains(symbol),
            "missing {symbol:?} diagnostic:\n{stderr}"
        );
    }
}
