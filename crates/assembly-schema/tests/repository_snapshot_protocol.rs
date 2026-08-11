#![allow(clippy::expect_used)]
// reason: protocol fixtures should stop at the exact local assertion when repository bytes drift.

use assembly_schema::{RepositoryAssemblyManifestV2, RepositoryAssemblySnapshotV2};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .to_path_buf()
}

fn captured_runtime() -> (Vec<u8>, Value) {
    let root = repository_root();
    let assembly = root.join("assemblies/runtime");
    let manifest =
        RepositoryAssemblyManifestV2::discover_v2(&root, &assembly).expect("repository manifest");
    let lock = std::fs::read(assembly.join("assembly.lock.json")).expect("AssemblyLock");
    let snapshot =
        RepositoryAssemblySnapshotV2::capture_v2(&manifest, &lock).expect("repository snapshot");
    let bytes = snapshot.to_pretty_json_vec().expect("snapshot JSON");
    let value = serde_json::from_slice(&bytes).expect("snapshot value");
    (bytes, value)
}

fn rejected(value: &Value) {
    let bytes = serde_json::to_vec(value).expect("mutated snapshot JSON");
    assert!(RepositoryAssemblySnapshotV2::from_json_slice(&bytes).is_err());
}

#[test]
fn repository_snapshot_is_deterministic_nonempty_and_round_trips_exact_identity() {
    let (first, value) = captured_runtime();
    let (second, _) = captured_runtime();
    assert_eq!(first, second);
    assert!(first.ends_with(b"\n"));
    assert!(
        !value["generatedFiles"]
            .as_array()
            .expect("generated")
            .is_empty()
    );
    assert!(
        !value["contractFiles"]
            .as_array()
            .expect("contracts")
            .is_empty()
    );

    let parsed = RepositoryAssemblySnapshotV2::from_json_slice(&first).expect("verified snapshot");
    assert_eq!(parsed.manifest().name(), "runtime");
    assert_eq!(
        parsed.lock().fingerprint().as_str(),
        value["assemblyLock"]["content"]
            .as_str()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|lock| lock["fingerprint"].as_str().map(str::to_owned))
            .expect("lock fingerprint")
    );
}

#[test]
fn repository_snapshot_rejects_closed_wire_and_every_source_class_tamper() {
    let (_, baseline) = captured_runtime();

    let mut changed = baseline.clone();
    changed["unknown"] = Value::Bool(true);
    rejected(&changed);

    let mut changed = baseline.clone();
    changed["schemaVersion"] = Value::from(1);
    rejected(&changed);

    let mut changed = baseline.clone();
    changed["assemblyManifest"]["content"] = Value::String("name = [".to_owned());
    rejected(&changed);

    let mut changed = baseline.clone();
    let manifest = changed["assemblyManifest"]["content"]
        .as_str()
        .expect("manifest")
        .replacen(
            "purpose = \"device-certificate-revocation\"",
            "purpose = \"device-certificate-revocation-v2\"",
            1,
        );
    changed["assemblyManifest"]["content"] = Value::String(manifest);
    rejected(&changed);

    let mut changed = baseline.clone();
    changed["assemblyLock"]["content"] = Value::String("{".to_owned());
    rejected(&changed);

    let mut changed = baseline.clone();
    let mut lock: Value =
        serde_json::from_str(changed["assemblyLock"]["content"].as_str().expect("lock"))
            .expect("lock JSON");
    lock["fingerprint"] = Value::String(format!("sha256:{}", "0".repeat(64)));
    changed["assemblyLock"]["content"] =
        Value::String(serde_json::to_string(&lock).expect("mutated lock"));
    rejected(&changed);

    let mut changed = baseline.clone();
    changed["generatedFiles"] = Value::Array(Vec::new());
    rejected(&changed);

    let mut changed = baseline.clone();
    changed["generatedFiles"][0]["content"] = Value::String("not generated".to_owned());
    rejected(&changed);

    let mut changed = baseline.clone();
    changed["generatedFiles"][0]["path"] = Value::String("../escape.rs".to_owned());
    rejected(&changed);

    let mut changed = baseline.clone();
    let duplicate = changed["generatedFiles"][0].clone();
    changed["generatedFiles"]
        .as_array_mut()
        .expect("generated")
        .insert(1, duplicate);
    rejected(&changed);

    let mut changed = baseline.clone();
    changed["contractFiles"] = Value::Array(Vec::new());
    rejected(&changed);

    let mut changed = baseline.clone();
    let contracts = changed["contractFiles"].as_array_mut().expect("contracts");
    let contract = contracts
        .iter_mut()
        .find(|file| {
            file["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("contract.toml"))
        })
        .expect("contract manifest");
    contract["content"] = Value::String("id = [".to_owned());
    rejected(&changed);

    let mut changed = baseline.clone();
    let contracts = changed["contractFiles"].as_array_mut().expect("contracts");
    let schema = contracts
        .iter_mut()
        .find(|file| {
            file["path"].as_str().is_some_and(|path| {
                path.ends_with(".schema.json")
                    && !path.contains("/components/")
                    && path.contains("/settings/")
            })
        })
        .expect("contract schema");
    schema["content"] = Value::String("{}".to_owned());
    rejected(&changed);

    let mut changed = baseline.clone();
    let contracts = changed["contractFiles"].as_array_mut().expect("contracts");
    let component = contracts
        .iter()
        .position(|file| {
            file["path"]
                .as_str()
                .is_some_and(|path| path.contains("/components/"))
        })
        .expect("component source");
    contracts.remove(component);
    rejected(&changed);

    let mut changed = baseline;
    let contracts = changed["contractFiles"].as_array_mut().expect("contracts");
    contracts.push(serde_json::json!({
        "path": "contracts/http/settings/v1/undeclared.schema.json",
        "content": "{}"
    }));
    contracts.sort_by(|left, right| {
        left["path"]
            .as_str()
            .expect("left path")
            .cmp(right["path"].as_str().expect("right path"))
    });
    rejected(&changed);
}
