//! Always-on Medium ownership gate for the MQTT wire namespace.
//!
//! Kept outside `#![cfg(feature = "broker-tests")]` so ArchRules enrolls `exec = "test"`
//! against default-feature AST symbols.

use std::path::{Path, PathBuf};

/// INVARIANT: MQTT-RAW-NAMESPACE-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "raw_mqtt_namespace_detects_rogue_concat", anti_vacuity = "raw_mqtt_namespace_anti_vacuity_ignores_comment_only_bait" }
/// Medium gate: `rss/v1/` concatenation is confined to policy/plugin/fixture owners.

const NAMESPACE_MARKER: &str = "rss/v1/";

fn mqtt_raw_namespace_sites(source: &str) -> Vec<String> {
    source
        .lines()
        .filter(|line| line.contains(NAMESPACE_MARKER) && !line.trim_start().starts_with("//"))
        .map(str::to_owned)
        .collect()
}

fn allowlisted_owner(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    normalized.ends_with("adapters/mqtt/src/topic.rs")
        || normalized.ends_with("adapters/mqtt/mosquitto-plugin/plugin.c")
        || normalized.ends_with("crates/testkit/src/containers.rs")
        || normalized.ends_with("adapters/mqtt/tests/ownership_gate.rs")
}

fn walk_source_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_source_files(&path, out);
            continue;
        }
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if matches!(ext, "rs" | "c") {
            out.push(path);
        }
    }
}

fn workspace_roots() -> [PathBuf; 2] {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [
        manifest.clone(),
        manifest
            .join("../../crates/testkit")
            .canonicalize()
            .expect("testkit crate path"),
    ]
}

#[test]
fn raw_mqtt_namespace_owners_mint_prefix() {
    let policy = include_str!("../src/topic.rs");
    let plugin = include_str!("../mosquitto-plugin/plugin.c");
    let fixture = include_str!("../../../crates/testkit/src/containers.rs");
    assert!(
        !mqtt_raw_namespace_sites(policy).is_empty() || policy.contains("TOPIC_PREFIX"),
        "policy owner must mint the namespace"
    );
    assert!(
        !mqtt_raw_namespace_sites(plugin).is_empty(),
        "plugin owner must compare exact rss/v1 topics"
    );
    assert!(
        !mqtt_raw_namespace_sites(fixture).is_empty(),
        "fixture owner may render exact ACL topics"
    );
}

#[test]
fn raw_mqtt_namespace_anti_vacuity_ignores_comment_only_bait() {
    // Anti-vacuity / string bait: comments alone are not production sites; literal bait still is.
    let bait = "// rss/v1/ should not count\nlet _ = \"rss/v1/\";\n";
    let sites = mqtt_raw_namespace_sites(bait);
    assert!(
        sites.iter().all(|line| line.contains("let _")),
        "gate must still observe literal bait for anti-vacuity: {sites:?}"
    );
    assert!(
        mqtt_raw_namespace_sites("// rss/v1/ comment only\n").is_empty(),
        "comment-only bait must not count as a production site"
    );
}

#[test]
fn raw_mqtt_namespace_detects_rogue_concat() {
    // Synthetic red: a rogue concat outside owners must be detectable.
    let rogue = r#"fn bad() { let _ = format!("rss/v1/{}/uplink", "x"); }"#;
    assert!(!mqtt_raw_namespace_sites(rogue).is_empty());
}

#[test]
fn raw_mqtt_namespace_is_confined_to_allowlisted_owners() {
    let mut files = Vec::new();
    for root in workspace_roots() {
        walk_source_files(&root, &mut files);
    }
    assert!(
        !files.is_empty(),
        "ownership gate must discover mqtt/testkit sources"
    );

    let mut violations = Vec::new();
    for path in files {
        if allowlisted_owner(&path) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("readable source");
        let sites = mqtt_raw_namespace_sites(&source);
        if !sites.is_empty() {
            violations.push(format!("{}: {sites:?}", path.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "rss/v1/ must stay in allowlisted owners; violations: {violations:?}"
    );
}
