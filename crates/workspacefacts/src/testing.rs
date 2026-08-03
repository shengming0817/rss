//! Synthetic Cargo metadata JSON builders shared by façade and xtask tests.

use serde_json::{Value, json};

/// Build a Cargo metadata target object.
pub fn target(
    name: &str,
    kind: &str,
    src_path: &str,
    test: bool,
    required_features: &[&str],
) -> Value {
    json!({
        "name": name,
        "kind": [kind],
        "crate_types": [if matches!(kind, "lib" | "proc-macro") { kind } else { "bin" }],
        "required-features": required_features,
        "src_path": src_path,
        "edition": "2024",
        "doctest": kind == "lib",
        "test": test,
        "doc": matches!(kind, "lib" | "proc-macro")
    })
}

/// Build a path dependency declaration.
pub fn path_dependency(name: &str, path: &str) -> Value {
    json!({
        "name": name,
        "source": null,
        "req": "*",
        "kind": null,
        "rename": null,
        "optional": false,
        "uses_default_features": true,
        "features": [],
        "target": null,
        "registry": null,
        "path": path
    })
}

/// Build a path package entry.
pub fn path_package(
    name: &str,
    absolute_path: &str,
    targets: Vec<Value>,
    dependencies: Vec<Value>,
    features: Value,
) -> Value {
    json!({
        "name": name,
        "version": "0.0.0",
        "id": format!("path+file://{absolute_path}#0.0.0"),
        "license": null,
        "license_file": null,
        "description": null,
        "source": null,
        "dependencies": dependencies,
        "targets": targets,
        "features": features,
        "manifest_path": format!("{absolute_path}/Cargo.toml"),
        "metadata": null,
        "publish": [],
        "authors": [],
        "categories": [],
        "keywords": [],
        "readme": null,
        "repository": null,
        "homepage": null,
        "documentation": null,
        "edition": "2024",
        "links": null,
        "default_run": null,
        "rust_version": "1.86"
    })
}

/// Build a crates.io registry package that must stay outside `workspace_members`.
pub fn registry_package(
    name: &str,
    version: &str,
    manifest_path: &str,
    targets: Vec<Value>,
) -> Value {
    let id = format!("registry+https://github.com/rust-lang/crates.io-index#{name}@{version}");
    json!({
        "name": name,
        "version": version,
        "id": id,
        "license": null,
        "license_file": null,
        "description": null,
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "dependencies": [],
        "targets": targets,
        "features": {},
        "manifest_path": manifest_path,
        "metadata": null,
        "publish": null,
        "authors": [],
        "categories": [],
        "keywords": [],
        "readme": null,
        "repository": null,
        "homepage": null,
        "documentation": null,
        "edition": "2021",
        "links": null,
        "default_run": null,
        "rust_version": null
    })
}

/// Build a resolve node. `dependencies` are `(dep_name, dep_package_id)`.
pub fn resolve_node(package_id: &str, dependencies: &[(&str, &str)]) -> Value {
    let dependency_ids = dependencies
        .iter()
        .map(|(_, id)| (*id).to_owned())
        .collect::<Vec<_>>();
    let deps = dependencies
        .iter()
        .map(|(name, id)| {
            json!({
                "name": name,
                "pkg": id,
                "dep_kinds": [{"kind": null, "target": null}]
            })
        })
        .collect::<Vec<_>>();
    json!({
        "id": package_id,
        "dependencies": dependency_ids,
        "deps": deps,
        "features": []
    })
}

/// Render a complete `cargo metadata --format-version 1` document.
///
/// `workspace_member_ids` is the exact membership set; packages listed only in `packages` and
/// resolve nodes remain external (registry anti-vacuity).
pub fn metadata_json(
    workspace_root: &str,
    packages: Vec<Value>,
    workspace_member_ids: Vec<String>,
    nodes: Vec<Value>,
) -> String {
    json!({
        "packages": packages,
        "workspace_members": workspace_member_ids.clone(),
        "workspace_default_members": workspace_member_ids,
        "resolve": {
            "nodes": nodes,
            "root": null
        },
        "workspace_root": workspace_root,
        "target_directory": format!("{workspace_root}/target"),
        "build_directory": format!("{workspace_root}/target"),
        "metadata": null,
        "version": 1
    })
    .to_string()
}

/// Convenience path-package id for fixtures rooted at `/workspace/...`.
pub fn path_package_id(absolute_path: &str) -> String {
    format!("path+file://{absolute_path}#0.0.0")
}
