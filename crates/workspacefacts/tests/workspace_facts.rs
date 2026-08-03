use serde_json::json;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;
use workspacefacts::testing::{
    metadata_json, path_dependency, path_package, path_package_id, registry_package, resolve_node,
    target,
};
use workspacefacts::{TargetKind, WorkspaceFacts, WorkspaceFactsError};

fn synthetic_metadata() -> String {
    let leaf_path = "/workspace/crates/leaf";
    let consumer_path = "/workspace/crates/consumer";
    let top_path = "/workspace/crates/top";
    let parent_path = "/workspace/crates/parent";
    let nested_path = "/workspace/crates/parent/nested";

    let leaf = path_package(
        "leaf",
        leaf_path,
        vec![target(
            "leaf",
            "lib",
            &format!("{leaf_path}/src/lib.rs"),
            false,
            &[],
        )],
        vec![],
        json!({"remote": []}),
    );
    let consumer = path_package(
        "consumer",
        consumer_path,
        vec![
            target(
                "consumer",
                "lib",
                &format!("{consumer_path}/src/lib.rs"),
                true,
                &[],
            ),
            target(
                "remote_case",
                "test",
                &format!("{consumer_path}/tests/remote_case.rs"),
                true,
                &["remote"],
            ),
            target(
                "demo",
                "example",
                &format!("{consumer_path}/examples/demo.rs"),
                true,
                &[],
            ),
            target(
                "throughput",
                "bench",
                &format!("{consumer_path}/benches/throughput.rs"),
                true,
                &[],
            ),
            target(
                "build-script",
                "custom-build",
                &format!("{consumer_path}/build.rs"),
                false,
                &[],
            ),
        ],
        vec![path_dependency("leaf", leaf_path)],
        json!({"remote": []}),
    );
    let top = path_package(
        "top",
        top_path,
        vec![target(
            "top",
            "bin",
            &format!("{top_path}/src/main.rs"),
            true,
            &[],
        )],
        vec![path_dependency("consumer", consumer_path)],
        json!({"remote": []}),
    );
    let parent = path_package(
        "parent",
        parent_path,
        vec![target(
            "parent",
            "lib",
            &format!("{parent_path}/src/lib.rs"),
            false,
            &[],
        )],
        vec![],
        json!({}),
    );
    let nested = path_package(
        "nested",
        nested_path,
        vec![target(
            "nested",
            "lib",
            &format!("{nested_path}/src/lib.rs"),
            false,
            &[],
        )],
        vec![],
        json!({}),
    );
    let serde_pkg = registry_package(
        "serde",
        "1.0.0",
        "/registry/serde/Cargo.toml",
        vec![target(
            "serde",
            "lib",
            "/registry/serde/src/lib.rs",
            true,
            &[],
        )],
    );

    let leaf_id = path_package_id(leaf_path);
    let consumer_id = path_package_id(consumer_path);
    let top_id = path_package_id(top_path);
    let parent_id = path_package_id(parent_path);
    let nested_id = path_package_id(nested_path);
    let serde_id = serde_pkg["id"].as_str().expect("serde id").to_owned();

    metadata_json(
        "/workspace",
        vec![leaf, consumer, top, parent, nested, serde_pkg],
        vec![
            leaf_id.clone(),
            consumer_id.clone(),
            top_id.clone(),
            parent_id.clone(),
            nested_id.clone(),
        ],
        vec![
            resolve_node(&leaf_id, &[]),
            resolve_node(&consumer_id, &[("leaf", leaf_id.as_str())]),
            resolve_node(&top_id, &[("consumer", consumer_id.as_str())]),
            resolve_node(&parent_id, &[]),
            resolve_node(&nested_id, &[]),
            resolve_node(&serde_id, &[]),
        ],
    )
}

#[test]
fn reverse_closure_path_ownership_and_target_catalog_are_owned() -> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &synthetic_metadata())?;
    let leaf = facts.package_key("leaf")?;
    let closure = facts.reverse_workspace_closure(&BTreeSet::from([leaf.clone()]))?;
    assert_eq!(
        closure
            .iter()
            .map(|package| package.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["consumer", "leaf", "top"])
    );
    assert!(
        !closure.iter().any(|package| package.as_str() == "serde"),
        "registry packages must stay outside reverse workspace closure"
    );
    assert!(
        matches!(
            facts.package_key("serde"),
            Err(WorkspaceFactsError::UnknownPackage(_))
        ),
        "registry package present in metadata must not become a workspace package key"
    );
    assert_eq!(
        facts
            .package_for_repo_path(Path::new("crates/consumer/tests/remote_case.rs"))?
            .as_ref()
            .map(|package| package.as_str()),
        Some("consumer")
    );

    let consumer = facts.package_key("consumer")?;
    let targets = facts.targets(&consumer)?;
    drop(facts);
    let integration = targets
        .iter()
        .find(|target| target.name() == "remote_case")
        .ok_or("remote_case target missing")?;
    assert_eq!(integration.kind(), TargetKind::Test);
    assert_eq!(integration.required_features(), ["remote"]);
    assert_eq!(
        integration.repo_relative_src_path(),
        Path::new("crates/consumer/tests/remote_case.rs")
    );
    assert!(integration.test_by_default());

    let by_name = |name: &str| {
        targets
            .iter()
            .find(|target| target.name() == name)
            .map(|target| target.kind())
    };
    assert_eq!(by_name("demo"), Some(TargetKind::Example));
    assert_eq!(by_name("throughput"), Some(TargetKind::Benchmark));
    assert_eq!(by_name("build-script"), Some(TargetKind::BuildScript));
    Ok(())
}

#[test]
fn nested_package_roots_resolve_deepest_owner() -> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &synthetic_metadata())?;
    assert_eq!(
        facts
            .package_for_repo_path(Path::new("crates/parent/nested/src/lib.rs"))?
            .as_ref()
            .map(|package| package.as_str()),
        Some("nested")
    );
    assert_eq!(
        facts
            .package_for_repo_path(Path::new("crates/parent/src/lib.rs"))?
            .as_ref()
            .map(|package| package.as_str()),
        Some("parent")
    );
    assert_eq!(
        facts.package_for_repo_path(Path::new("crates/unowned/src/lib.rs"))?,
        None
    );
    Ok(())
}

#[test]
fn invalid_metadata_root_unknown_package_and_path_escape_fail_closed() -> Result<(), Box<dyn Error>>
{
    assert!(matches!(
        WorkspaceFacts::from_metadata_json(Path::new("/workspace"), "not-json"),
        Err(WorkspaceFactsError::InvalidMetadata(_))
    ));
    assert!(matches!(
        WorkspaceFacts::from_metadata_json(Path::new("/elsewhere"), &synthetic_metadata()),
        Err(WorkspaceFactsError::WorkspaceRootMismatch { .. })
    ));
    assert!(matches!(
        WorkspaceFacts::from_metadata_json(Path::new("relative"), &synthetic_metadata()),
        Err(WorkspaceFactsError::InvalidWorkspaceRoot(_))
    ));
    let escaped_target = synthetic_metadata().replace(
        "/workspace/crates/leaf/src/lib.rs",
        "/outside/leaf/src/lib.rs",
    );
    assert!(matches!(
        WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &escaped_target),
        Err(WorkspaceFactsError::WorkspacePathEscape(_))
    ));
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &synthetic_metadata())?;
    assert!(matches!(
        facts.package_key("missing"),
        Err(WorkspaceFactsError::UnknownPackage(_))
    ));
    assert!(matches!(
        facts.package_for_repo_path(Path::new("../escape.rs")),
        Err(WorkspaceFactsError::InvalidRepoPath(_))
    ));
    assert!(matches!(
        facts.package_for_repo_path(Path::new("/workspace/crates/leaf/src/lib.rs")),
        Err(WorkspaceFactsError::InvalidRepoPath(_))
    ));
    Ok(())
}

#[test]
fn targets_for_borrows_without_clone() -> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &synthetic_metadata())?;
    let consumer = facts.package_key("consumer")?;
    let borrowed = facts.targets_for(&consumer)?;
    assert!(
        borrowed
            .iter()
            .any(|target| target.name() == "remote_case" && target.kind() == TargetKind::Test)
    );
    Ok(())
}
