use serde_json::json;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use workspacefacts::testing::{
    metadata_json, path_dependency, path_package, path_package_id, registry_package, resolve_node,
    target,
};
use workspacefacts::{
    ApiStability, DependencyKind, DependencyResolution, DependencySource, GitDependencyReq,
    OfficialProfile, PackageKey, PublicApiOwner, PublishPolicy, TargetKind, WorkspaceFacts,
    WorkspaceFactsError,
};

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
    let serde_id = serde_pkg["id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| "invalid synthetic serde package id".to_owned());

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

#[test]
fn direct_dependencies_for_borrows_and_owned_delegates() -> Result<(), Box<dyn Error>> {
    let facts =
        WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &direct_dependency_metadata())?;
    let consumer = facts.package_key("consumer")?;
    let borrowed = facts.direct_dependencies_for(&consumer)?;
    assert!(
        !borrowed.is_empty(),
        "anti-vacuous: consumer must have projected direct dependencies"
    );
    assert!(
        borrowed.iter().any(|dep| {
            dep.name() == "leaf_a" && dep.resolved().map(PackageKey::as_str) == Some("leaf")
        }),
        "borrowed query must surface declaration-granularity rename"
    );
    let owned = facts.direct_dependencies(&consumer)?;
    assert_eq!(
        owned,
        borrowed.to_vec(),
        "owned direct_dependencies must delegate to borrowed slice"
    );
    drop(facts);

    let leaf_only = path_package(
        "leaf",
        "/workspace/crates/leaf",
        vec![target(
            "leaf",
            "lib",
            "/workspace/crates/leaf/src/lib.rs",
            false,
            &[],
        )],
        vec![],
        json!({}),
    );
    let leaf_id = path_package_id("/workspace/crates/leaf");
    let only_leaf = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &metadata_json(
            "/workspace",
            vec![leaf_only],
            vec![leaf_id.clone()],
            vec![resolve_node(&leaf_id, &[])],
        ),
    )?;
    assert!(matches!(
        only_leaf.direct_dependencies_for(&consumer),
        Err(WorkspaceFactsError::UnknownPackage(_))
    ));
    Ok(())
}

#[test]
fn repo_relative_root_for_borrows_workspace_member_root() -> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &synthetic_metadata())?;
    let nested = facts.package_key("nested")?;
    assert_eq!(
        facts.repo_relative_root_for(&nested)?,
        Path::new("crates/parent/nested")
    );
    let catalog = facts.workspace_packages();
    let nested_owned = catalog
        .iter()
        .find(|pkg| pkg.key().as_str() == "nested")
        .ok_or("nested missing from catalog")?;
    assert_eq!(
        facts.repo_relative_root_for(nested_owned.key())?,
        nested_owned.repo_relative_root()
    );

    let foreign_consumer = facts.package_key("consumer")?;
    drop(facts);
    let leaf_only = path_package(
        "leaf",
        "/workspace/crates/leaf",
        vec![target(
            "leaf",
            "lib",
            "/workspace/crates/leaf/src/lib.rs",
            false,
            &[],
        )],
        vec![],
        json!({}),
    );
    let leaf_id = path_package_id("/workspace/crates/leaf");
    let only_leaf = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &metadata_json(
            "/workspace",
            vec![leaf_only],
            vec![leaf_id.clone()],
            vec![resolve_node(&leaf_id, &[])],
        ),
    )?;
    assert!(matches!(
        only_leaf.repo_relative_root_for(&foreign_consumer),
        Err(WorkspaceFactsError::UnknownPackage(_))
    ));
    Ok(())
}

#[test]
fn workspace_package_catalog_is_owned_key_ordered_and_excludes_registry()
-> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &synthetic_metadata())?;
    let catalog = facts.workspace_packages();
    let consumer = catalog
        .iter()
        .find(|pkg| pkg.key().as_str() == "consumer")
        .ok_or("consumer missing in catalog")?;
    let consumer_targets = facts.targets_for(consumer.key())?;
    assert!(
        consumer_targets
            .iter()
            .any(|target| target.name() == "remote_case" && target.kind() == TargetKind::Test)
    );
    let remote = facts.feature_key(consumer.key(), "remote")?;
    assert_eq!(remote.package().as_str(), "consumer");
    assert_eq!(remote.name(), "remote");

    let nested_owner = facts
        .package_for_repo_path(Path::new("crates/parent/nested/src/lib.rs"))?
        .ok_or("nested owner missing")?;
    assert_eq!(nested_owner.as_str(), "nested");

    let catalog_names: Vec<&str> = catalog.iter().map(|pkg| pkg.key().as_str()).collect();
    assert_eq!(
        catalog_names,
        vec!["consumer", "leaf", "nested", "parent", "top"],
        "catalog must be workspace members sorted by PackageKey, not path-depth ownership order"
    );
    assert!(
        !catalog_names.contains(&"serde"),
        "registry packages must stay outside workspace package catalog"
    );

    let by_name = |name: &str| {
        catalog
            .iter()
            .find(|pkg| pkg.key().as_str() == name)
            .map(|pkg| pkg.repo_relative_root().to_path_buf())
    };
    assert_eq!(by_name("parent"), Some(PathBuf::from("crates/parent")));
    assert_eq!(
        by_name("nested"),
        Some(PathBuf::from("crates/parent/nested"))
    );
    assert_eq!(by_name("leaf"), Some(PathBuf::from("crates/leaf")));

    // Deepest-ownership order puts nested ahead of shallower roots; PackageKey order does not.
    assert!(
        catalog_names.iter().position(|name| *name == "consumer")
            < catalog_names.iter().position(|name| *name == "nested"),
        "catalog order must stay PackageKey lexicographic, decoupled from deepest-owner scan order"
    );

    drop(facts);
    let owned_roots: Vec<(String, PathBuf)> = catalog
        .into_iter()
        .map(|pkg| {
            (
                pkg.key().as_str().to_owned(),
                pkg.repo_relative_root().to_path_buf(),
            )
        })
        .collect();
    assert_eq!(
        owned_roots,
        vec![
            ("consumer".to_owned(), PathBuf::from("crates/consumer")),
            ("leaf".to_owned(), PathBuf::from("crates/leaf")),
            ("nested".to_owned(), PathBuf::from("crates/parent/nested")),
            ("parent".to_owned(), PathBuf::from("crates/parent")),
            ("top".to_owned(), PathBuf::from("crates/top")),
        ],
        "WorkspacePackageFacts must remain usable after WorkspaceFacts drops"
    );
    Ok(())
}

#[test]
fn release_package_facts_project_version_msrv_and_publish_policy_as_owned_values()
-> Result<(), Box<dyn Error>> {
    let mut metadata: serde_json::Value = serde_json::from_str(&synthetic_metadata())?;
    let packages = metadata["packages"]
        .as_array_mut()
        .ok_or("synthetic packages must be an array")?;
    for package in packages {
        match package["name"].as_str() {
            Some("consumer") => {
                package["version"] = json!("1.2.3");
                package["rust_version"] = json!("1.82");
                package["publish"] = json!(null);
            }
            Some("leaf") => {
                package["rust_version"] = json!(null);
                package["publish"] = json!(["private", "crates-io"]);
            }
            Some("top") => {
                package["publish"] = json!([]);
            }
            _ => {}
        }
    }

    let facts = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &serde_json::to_string(&metadata)?,
    )?;
    let catalog = facts.workspace_packages();
    drop(facts);

    let package = |name: &str| {
        catalog
            .iter()
            .find(|package| package.key().as_str() == name)
            .ok_or_else(|| format!("missing synthetic package {name}"))
    };
    let consumer = package("consumer")?;
    assert_eq!(consumer.version().to_string(), "1.2.3");
    assert_eq!(
        consumer.minimum_rust_version().map(ToString::to_string),
        Some("1.82.0".to_owned())
    );
    assert_eq!(consumer.publish_policy(), &PublishPolicy::Unrestricted);

    let leaf = package("leaf")?;
    assert_eq!(leaf.minimum_rust_version(), None);
    assert_eq!(
        leaf.publish_policy(),
        &PublishPolicy::Registries(BTreeSet::from([
            "crates-io".to_owned(),
            "private".to_owned(),
        ]))
    );

    let top = package("top")?;
    assert_eq!(top.publish_policy(), &PublishPolicy::Disabled);
    assert!(!top.publish_policy().is_publishable());
    assert!(consumer.publish_policy().is_publishable());
    Ok(())
}

#[test]
fn release_selection_is_strict_typed_and_distinguishes_absent_from_empty()
-> Result<(), Box<dyn Error>> {
    let absent =
        WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &synthetic_metadata())?;
    assert_eq!(absent.release_selection()?, None);

    let mut metadata: serde_json::Value = serde_json::from_str(&synthetic_metadata())?;
    metadata["metadata"] = json!({
        "release-surface": {
            "packages": [{
                "package": "consumer",
                "public-api-owner": "standalone-component",
                "api-stability": "experimental",
                "profiles": ["core", "eventing"]
            }],
            "profile-artifacts": [{
                "profile": "core",
                "assembly": "runtime"
            }]
        }
    });
    let facts = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &serde_json::to_string(&metadata)?,
    )?;
    let selection = facts
        .release_selection()?
        .ok_or("release selection must be declared")?;
    assert_eq!(selection.packages().len(), 1);
    let package = &selection.packages()[0];
    assert_eq!(package.package(), "consumer");
    assert_eq!(
        package.public_api_owner(),
        PublicApiOwner::StandaloneComponent
    );
    assert_eq!(package.api_stability(), ApiStability::Experimental);
    assert_eq!(
        package.profiles(),
        &[OfficialProfile::Core, OfficialProfile::Eventing]
    );
    assert_eq!(selection.profile_artifacts().len(), 1);
    assert_eq!(
        selection.profile_artifacts()[0].profile(),
        OfficialProfile::Core
    );
    assert_eq!(selection.profile_artifacts()[0].assembly(), "runtime");

    let invalid_cases = [
        json!({
            "packages": [{
                "package": "consumer",
                "public-api-owner": "secret-bait",
                "api-stability": "stable",
                "profiles": []
            }],
            "profile-artifacts": []
        }),
        json!({
            "packages": [{
                "package": "consumer",
                "public-api-owner": "platform-public",
                "api-stability": "secret-bait",
                "profiles": []
            }],
            "profile-artifacts": []
        }),
        json!({
            "packages": [{
                "package": "consumer",
                "public-api-owner": "platform-public",
                "api-stability": "stable",
                "profiles": ["secret-bait"]
            }],
            "profile-artifacts": []
        }),
        json!({
            "packages": [],
            "profile-artifacts": [{"profile": "secret-bait", "assembly": "runtime"}]
        }),
        json!({
            "packages": [{
                "package": "consumer",
                "public-api-owner": "platform-public",
                "api-stability": "stable",
                "profiles": [],
                "release-status": "secret-bait"
            }],
            "profile-artifacts": []
        }),
    ];
    for selection in invalid_cases {
        let mut invalid: serde_json::Value = serde_json::from_str(&synthetic_metadata())?;
        invalid["metadata"] = json!({"release-surface": selection});
        let invalid_facts = WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &serde_json::to_string(&invalid)?,
        )?;
        let error = match invalid_facts.release_selection() {
            Err(error) => error,
            Ok(_) => return Err("unknown selection value/field must fail closed".into()),
        };
        assert!(
            error
                .subject()
                .starts_with("workspace.metadata.release-surface."),
            "invalid row path must be precise without echoing its value: {error}"
        );
        assert!(
            error.detail().contains("invalid release selection")
                && !error.to_string().contains("secret-bait"),
            "diagnostic must be categorized without echoing raw TOML: {error}"
        );
    }
    Ok(())
}

/// Synthetic graph covering declaration-granularity rename / kind / source / target facts.
///
/// Includes two distinct rename keys to the same resolved package — provenance that Guppy's
/// `PackageLink` merge (`graph/build.rs` `PackageLinkImpl::new` + `update_edge`) would drop.
fn direct_dependency_metadata() -> String {
    let leaf_path = "/workspace/crates/leaf";
    let consumer_path = "/workspace/crates/consumer";
    let external_path = "/outside/external_path";
    let unknown_source = "not-a-known-source+https://example.invalid";
    let sparse_source = "sparse+https://index.crates.io/";
    let git_source =
        "git+https://example.com/gitdep.git?branch=main#0123456789abcdef0123456789abcdef01234567";

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
        json!({}),
    );
    let external_path_pkg = path_package(
        "external_path",
        external_path,
        vec![target(
            "external_path",
            "lib",
            &format!("{external_path}/src/lib.rs"),
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
    let git_pkg = external_source_package(
        "gitdep",
        "0.1.0",
        git_source,
        &format!("{git_source}#gitdep@0.1.0"),
        "/git/gitdep",
    );
    let unknown_pkg = external_source_package(
        "unkdep",
        "0.1.0",
        unknown_source,
        &format!("{unknown_source}#unkdep@0.1.0"),
        "/unknown/unkdep",
    );
    let sparse_pkg = external_source_package(
        "sparsedep",
        "0.1.0",
        sparse_source,
        "sparse+https://index.crates.io/#sparsedep@0.1.0",
        "/sparse/sparsedep",
    );

    let leaf_id = path_package_id(leaf_path);
    let consumer_id = path_package_id(consumer_path);
    let external_id = path_package_id(external_path);
    let serde_id = package_id_string(&serde_pkg, "serde");
    let git_pkg_id = package_id_string(&git_pkg, "gitdep");
    let unknown_pkg_id = package_id_string(&unknown_pkg, "unkdep");
    let sparse_pkg_id = package_id_string(&sparse_pkg, "sparsedep");

    let consumer = path_package(
        "consumer",
        consumer_path,
        vec![target(
            "consumer",
            "lib",
            &format!("{consumer_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![
            // Two rename keys → same resolved package (declaration provenance Guppy would fold).
            renamed_path_dep("leaf", "leaf_a", leaf_path, None, None),
            renamed_path_dep("leaf", "leaf_b", leaf_path, None, None),
            // Same key: unconditional + target-conditioned.
            renamed_path_dep("leaf", "leaf_shared", leaf_path, None, None),
            renamed_path_dep("leaf", "leaf_shared", leaf_path, None, Some("cfg(unix)")),
            renamed_path_dep("leaf", "leaf_alias", leaf_path, Some("build"), None),
            renamed_path_dep("leaf", "leaf_alias", leaf_path, Some("dev"), None),
            json!({
                "name": "serde",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "req": "^1",
                "kind": null,
                "rename": null,
                "optional": false,
                "uses_default_features": true,
                "features": ["derive"],
                "target": "cfg(windows)",
                "registry": null
            }),
            path_dependency("external_path", external_path),
            external_dep("gitdep", git_source, None),
            external_dep("unkdep", unknown_source, None),
            external_dep("sparsedep", sparse_source, Some("sparse_alias")),
        ],
        json!({}),
    );

    metadata_json(
        "/workspace",
        vec![
            leaf,
            consumer,
            external_path_pkg,
            serde_pkg,
            git_pkg,
            unknown_pkg,
            sparse_pkg,
        ],
        vec![leaf_id.clone(), consumer_id.clone()],
        vec![
            resolve_node(&leaf_id, &[]),
            json!({
                "id": consumer_id,
                "dependencies": [
                    leaf_id.clone(),
                    external_id.clone(),
                    serde_id.clone(),
                    git_pkg_id.clone(),
                    unknown_pkg_id.clone(),
                    sparse_pkg_id.clone()
                ],
                "deps": [
                    {
                        "name": "leaf_a",
                        "pkg": leaf_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    },
                    {
                        "name": "leaf_b",
                        "pkg": leaf_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    },
                    {
                        "name": "leaf_shared",
                        "pkg": leaf_id,
                        "dep_kinds": [
                            {"kind": null, "target": null},
                            {"kind": null, "target": "cfg(unix)"}
                        ]
                    },
                    {
                        "name": "leaf_alias",
                        "pkg": leaf_id,
                        "dep_kinds": [
                            {"kind": "build", "target": null},
                            {"kind": "dev", "target": null}
                        ]
                    },
                    {
                        "name": "external_path",
                        "pkg": external_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    },
                    {
                        "name": "serde",
                        "pkg": serde_id,
                        "dep_kinds": [{"kind": null, "target": "cfg(windows)"}]
                    },
                    {
                        "name": "gitdep",
                        "pkg": git_pkg_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    },
                    {
                        "name": "unkdep",
                        "pkg": unknown_pkg_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    },
                    {
                        "name": "sparse_alias",
                        "pkg": sparse_pkg_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    }
                ],
                "features": []
            }),
            resolve_node(&external_id, &[]),
            resolve_node(&serde_id, &[]),
            resolve_node(&git_pkg_id, &[]),
            resolve_node(&unknown_pkg_id, &[]),
            resolve_node(&sparse_pkg_id, &[]),
        ],
    )
}

fn package_id_string(package: &serde_json::Value, label: &str) -> String {
    package["id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("invalid synthetic {label} package id"))
}

fn external_source_package(
    name: &str,
    version: &str,
    source: &str,
    id: &str,
    root: &str,
) -> serde_json::Value {
    json!({
        "name": name,
        "version": version,
        "id": id,
        "license": null,
        "license_file": null,
        "description": null,
        "source": source,
        "dependencies": [],
        "targets": [target(name, "lib", &format!("{root}/src/lib.rs"), true, &[])],
        "features": {},
        "manifest_path": format!("{root}/Cargo.toml"),
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

fn renamed_path_dep(
    name: &str,
    rename: &str,
    path: &str,
    kind: Option<&str>,
    target: Option<&str>,
) -> serde_json::Value {
    json!({
        "name": name,
        "source": null,
        "req": "*",
        "kind": kind,
        "rename": rename,
        "optional": false,
        "uses_default_features": true,
        "features": [],
        "target": target,
        "registry": null,
        "path": path
    })
}

fn external_dep(name: &str, source: &str, rename: Option<&str>) -> serde_json::Value {
    json!({
        "name": name,
        "source": source,
        "req": "*",
        "kind": null,
        "rename": rename,
        "optional": false,
        "uses_default_features": true,
        "features": [],
        "target": null,
        "registry": null
    })
}

fn load_consumer_direct_deps() -> Result<
    (
        WorkspaceFacts,
        workspacefacts::PackageKey,
        Vec<workspacefacts::DirectDependencyFacts>,
    ),
    Box<dyn Error>,
> {
    let facts =
        WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &direct_dependency_metadata())?;
    let consumer = facts.package_key("consumer")?;
    let deps = facts.direct_dependencies(&consumer)?;
    Ok((facts, consumer, deps))
}

fn find_dep<'a>(
    deps: &'a [workspacefacts::DirectDependencyFacts],
    name: &str,
    kind: DependencyKind,
) -> Option<&'a workspacefacts::DirectDependencyFacts> {
    deps.iter()
        .find(|dep| dep.name() == name && dep.kind() == kind)
}

fn find_deps<'a>(
    deps: &'a [workspacefacts::DirectDependencyFacts],
    name: &str,
    kind: DependencyKind,
) -> Vec<&'a workspacefacts::DirectDependencyFacts> {
    deps.iter()
        .filter(|dep| dep.name() == name && dep.kind() == kind)
        .collect()
}

#[test]
fn direct_dependencies_keep_dual_rename_keys_for_same_resolved_package()
-> Result<(), Box<dyn Error>> {
    let (_facts, _consumer, deps) = load_consumer_direct_deps()?;
    let leaf_a = find_dep(&deps, "leaf_a", DependencyKind::Normal).ok_or("leaf_a missing")?;
    let leaf_b = find_dep(&deps, "leaf_b", DependencyKind::Normal).ok_or("leaf_b missing")?;
    assert_eq!(leaf_a.resolved().map(PackageKey::as_str), Some("leaf"));
    assert_eq!(leaf_b.resolved().map(PackageKey::as_str), Some("leaf"));
    assert!(leaf_a.unconditional());
    assert!(leaf_b.unconditional());
    assert_eq!(
        leaf_a.source(),
        &DependencySource::Workspace {
            repo_relative_root: PathBuf::from("crates/leaf"),
        }
    );
    Ok(())
}

#[test]
fn direct_dependencies_keep_conditional_and_unconditional_for_same_key()
-> Result<(), Box<dyn Error>> {
    let (_facts, _consumer, deps) = load_consumer_direct_deps()?;
    let shared = find_deps(&deps, "leaf_shared", DependencyKind::Normal);
    assert_eq!(shared.len(), 2, "unconditional + conditional declarations");
    let unconditional = shared.iter().filter(|dep| dep.unconditional()).count();
    let conditional = shared.iter().filter(|dep| !dep.unconditional()).count();
    assert_eq!(unconditional, 1);
    assert_eq!(conditional, 1);
    assert!(
        shared
            .iter()
            .all(|dep| dep.resolved().map(PackageKey::as_str) == Some("leaf")),
        "both declarations resolve to leaf"
    );
    Ok(())
}

#[test]
fn direct_dependencies_preserve_rename_and_multi_kind() -> Result<(), Box<dyn Error>> {
    let (_facts, _consumer, deps) = load_consumer_direct_deps()?;
    assert!(find_dep(&deps, "leaf_alias", DependencyKind::Dev).is_some());
    assert!(find_dep(&deps, "leaf_alias", DependencyKind::Build).is_some());
    assert!(find_dep(&deps, "leaf_alias", DependencyKind::Normal).is_none());
    Ok(())
}

#[test]
fn direct_dependencies_distinguish_sources_and_target_conditions() -> Result<(), Box<dyn Error>> {
    let (_facts, _consumer, deps) = load_consumer_direct_deps()?;

    let serde = find_dep(&deps, "serde", DependencyKind::Normal).ok_or("serde missing")?;
    assert_eq!(
        serde.requested_features(),
        &BTreeSet::from(["derive".to_owned()])
    );
    assert!(
        !serde.unconditional(),
        "target-conditioned edge must not claim unconditional"
    );
    assert!(matches!(serde.source(), DependencySource::Registry { .. }));

    let external =
        find_dep(&deps, "external_path", DependencyKind::Normal).ok_or("path missing")?;
    assert_eq!(
        external.source(),
        &DependencySource::Path {
            repo_relative_root: PathBuf::from("../outside/external_path"),
        }
    );
    assert!(external.unconditional());

    let git = find_dep(&deps, "gitdep", DependencyKind::Normal).ok_or("git missing")?;
    assert_eq!(
        git.source(),
        &DependencySource::Git {
            repository: "https://example.com/gitdep.git".to_owned(),
            req: GitDependencyReq::Branch("main".to_owned()),
            resolved: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        }
    );

    let unknown = find_dep(&deps, "unkdep", DependencyKind::Normal).ok_or("unknown missing")?;
    assert_eq!(
        unknown.source(),
        &DependencySource::UnknownExternal {
            source: "not-a-known-source+https://example.invalid".to_owned(),
        }
    );

    let sparse = find_dep(&deps, "sparse_alias", DependencyKind::Normal).ok_or("sparse missing")?;
    assert_eq!(
        sparse.source(),
        &DependencySource::Sparse {
            url: "https://index.crates.io/".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn direct_dependency_requested_features_fail_closed_when_malformed() -> Result<(), Box<dyn Error>> {
    let mut metadata: serde_json::Value = serde_json::from_str(&direct_dependency_metadata())?;
    let dependency = metadata["packages"]
        .as_array_mut()
        .and_then(|packages| {
            packages
                .iter_mut()
                .find(|package| package["name"] == "consumer")
        })
        .and_then(|consumer| consumer["dependencies"].as_array_mut())
        .and_then(|dependencies| dependencies.first_mut())
        .ok_or("consumer dependency fixture missing")?;
    dependency["features"] = json!(["backend", 7]);
    let error = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &serde_json::to_string(&metadata)?,
    )
    .err()
    .ok_or("non-string requested feature must fail closed")?;
    assert!(error.to_string().contains("features"));
    Ok(())
}

#[test]
fn direct_dependencies_are_sorted_distinct_and_owned() -> Result<(), Box<dyn Error>> {
    let (facts, _consumer, deps) = load_consumer_direct_deps()?;

    let order: Vec<(&str, DependencyKind, bool, &str)> = deps
        .iter()
        .map(|dep| {
            (
                dep.name(),
                dep.kind(),
                dep.unconditional(),
                dep.resolved().map(PackageKey::as_str).unwrap_or(""),
            )
        })
        .collect();
    let mut expected = order.clone();
    expected.sort();
    assert_eq!(order, expected, "direct_dependencies must be stably sorted");

    let names: BTreeSet<&str> = deps.iter().map(|dep| dep.name()).collect();
    for name in [
        "leaf_a",
        "leaf_b",
        "leaf_shared",
        "leaf_alias",
        "external_path",
        "serde",
        "gitdep",
        "unkdep",
        "sparse_alias",
    ] {
        assert!(
            names.contains(name),
            "missing distinct manifest name {name}"
        );
    }

    drop(facts);
    let owned: Vec<(String, DependencyKind, Option<String>)> = deps
        .into_iter()
        .map(|dep| {
            (
                dep.name().to_owned(),
                dep.kind(),
                dep.resolved().map(|key| key.as_str().to_owned()),
            )
        })
        .collect();
    assert!(
        owned.iter().any(|(name, kind, resolved)| {
            name == "leaf_a"
                && *kind == DependencyKind::Normal
                && resolved.as_deref() == Some("leaf")
        }),
        "DirectDependencyFacts must remain usable after WorkspaceFacts drops ('static owned)"
    );
    Ok(())
}

#[test]
fn direct_dependencies_reject_unknown_package() -> Result<(), Box<dyn Error>> {
    let with_consumer =
        WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &direct_dependency_metadata())?;
    let consumer = with_consumer.package_key("consumer")?;
    drop(with_consumer);

    let leaf_only = path_package(
        "leaf",
        "/workspace/crates/leaf",
        vec![target(
            "leaf",
            "lib",
            "/workspace/crates/leaf/src/lib.rs",
            false,
            &[],
        )],
        vec![],
        json!({}),
    );
    let leaf_id = path_package_id("/workspace/crates/leaf");
    let only_leaf = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &metadata_json(
            "/workspace",
            vec![leaf_only],
            vec![leaf_id.clone()],
            vec![resolve_node(&leaf_id, &[])],
        ),
    )?;
    assert!(matches!(
        only_leaf.direct_dependencies(&consumer),
        Err(WorkspaceFactsError::UnknownPackage(_))
    ));
    Ok(())
}

#[test]
fn direct_dependencies_fail_closed_on_ambiguous_resolution() -> Result<(), Box<dyn Error>> {
    let leaf_path = "/workspace/crates/leaf";
    let other_path = "/workspace/crates/other";
    let consumer_path = "/workspace/crates/consumer";
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
        json!({}),
    );
    let other = path_package(
        "other",
        other_path,
        vec![target(
            "other",
            "lib",
            &format!("{other_path}/src/lib.rs"),
            false,
            &[],
        )],
        vec![],
        json!({}),
    );
    let consumer = path_package(
        "consumer",
        consumer_path,
        vec![target(
            "consumer",
            "lib",
            &format!("{consumer_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![renamed_path_dep("leaf", "alias", leaf_path, None, None)],
        json!({}),
    );
    let leaf_id = path_package_id(leaf_path);
    let other_id = path_package_id(other_path);
    let consumer_id = path_package_id(consumer_path);
    let metadata = metadata_json(
        "/workspace",
        vec![leaf, other, consumer],
        vec![leaf_id.clone(), other_id.clone(), consumer_id.clone()],
        vec![
            resolve_node(&leaf_id, &[]),
            resolve_node(&other_id, &[]),
            json!({
                "id": consumer_id,
                "dependencies": [leaf_id.clone(), other_id.clone()],
                "deps": [
                    {
                        "name": "alias",
                        "pkg": leaf_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    },
                    {
                        "name": "alias",
                        "pkg": other_id,
                        "dep_kinds": [{"kind": null, "target": null}]
                    }
                ],
                "features": []
            }),
        ],
    );
    let err = match WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata) {
        Ok(_) => return Err("ambiguous resolve mapping must fail closed".into()),
        Err(error) => error,
    };
    assert!(matches!(
        err,
        WorkspaceFactsError::AmbiguousDependencyResolution { .. }
    ));
    Ok(())
}

#[test]
fn resolve_dep_kinds_missing_null_or_empty_fail_closed() -> Result<(), Box<dyn Error>> {
    let leaf_path = "/workspace/crates/leaf";
    let consumer_path = "/workspace/crates/consumer";
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
        json!({}),
    );
    let leaf_id = path_package_id(leaf_path);
    let consumer_id = path_package_id(consumer_path);
    let consumer = path_package(
        "consumer",
        consumer_path,
        vec![target(
            "consumer",
            "lib",
            &format!("{consumer_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![path_dependency("leaf", leaf_path)],
        json!({}),
    );
    let cases = [
        ("missing", None),
        ("null", Some(json!(null))),
        ("empty", Some(json!([]))),
    ];
    for (label, dep_kinds) in cases {
        let mut dep = json!({
            "name": "leaf",
            "pkg": leaf_id,
        });
        match dep_kinds {
            None => {}
            Some(kinds) => {
                let Some(object) = dep.as_object_mut() else {
                    return Err(format!("{label}: dep must be object").into());
                };
                object.insert("dep_kinds".into(), kinds);
            }
        }
        let metadata = metadata_json(
            "/workspace",
            vec![leaf.clone(), consumer.clone()],
            vec![leaf_id.clone(), consumer_id.clone()],
            vec![
                resolve_node(&leaf_id, &[]),
                json!({
                    "id": consumer_id,
                    "dependencies": [leaf_id.clone()],
                    "deps": [dep],
                    "features": []
                }),
            ],
        );
        let err = match WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata) {
            Ok(_) => return Err(format!("{label} dep_kinds must fail closed").into()),
            Err(error) => error,
        };
        assert!(
            matches!(err, WorkspaceFactsError::InvalidMetadata(_)),
            "{label}: {err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("dep_kinds"),
            "{label} diagnostic must name dep_kinds: {message}"
        );
    }
    Ok(())
}

#[test]
fn malformed_optional_string_fields_fail_closed() -> Result<(), Box<dyn Error>> {
    let leaf_path = "/workspace/crates/leaf";
    let consumer_path = "/workspace/crates/consumer";
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
        json!({}),
    );
    let leaf_id = path_package_id(leaf_path);
    let consumer_id = path_package_id(consumer_path);
    let mut dependency = path_dependency("leaf", leaf_path);
    let Some(object) = dependency.as_object_mut() else {
        return Err("dependency must be object".into());
    };
    object.insert("target".into(), json!(true));
    let consumer = path_package(
        "consumer",
        consumer_path,
        vec![target(
            "consumer",
            "lib",
            &format!("{consumer_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![dependency],
        json!({}),
    );
    let metadata = metadata_json(
        "/workspace",
        vec![leaf, consumer],
        vec![leaf_id.clone(), consumer_id.clone()],
        vec![
            resolve_node(&leaf_id, &[]),
            resolve_node(&consumer_id, &[("leaf", &leaf_id)]),
        ],
    );
    let err = match WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata) {
        Ok(facts) => {
            let consumer = facts.package_key("consumer")?;
            let deps = facts.direct_dependencies(&consumer)?;
            // Must not silently treat non-string target as unconditional.
            return Err(format!(
                "non-string target must fail closed, got unconditional={}",
                deps[0].unconditional()
            )
            .into());
        }
        Err(error) => error,
    };
    assert!(matches!(err, WorkspaceFactsError::InvalidMetadata(_)));
    assert!(
        err.to_string().contains("target"),
        "malformed optional field diagnostic: {err}"
    );
    Ok(())
}

#[test]
fn unmatched_resolve_dep_is_unresolved_not_guessed() -> Result<(), Box<dyn Error>> {
    let leaf_path = "/workspace/crates/leaf";
    let consumer_path = "/workspace/crates/consumer";
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
        json!({}),
    );
    let leaf_id = path_package_id(leaf_path);
    let consumer_id = path_package_id(consumer_path);
    let consumer = path_package(
        "consumer",
        consumer_path,
        vec![target(
            "consumer",
            "lib",
            &format!("{consumer_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![path_dependency("leaf", leaf_path)],
        json!({}),
    );
    // Declaration exists, but resolve has no matching dep for the declaration name/kind/target.
    let metadata = metadata_json(
        "/workspace",
        vec![leaf, consumer],
        vec![leaf_id.clone(), consumer_id.clone()],
        vec![resolve_node(&leaf_id, &[]), resolve_node(&consumer_id, &[])],
    );
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
    let consumer = facts.package_key("consumer")?;
    let deps = facts.direct_dependencies(&consumer)?;
    assert_eq!(deps.len(), 1);
    assert_eq!(
        deps[0].resolution(),
        &DependencyResolution::Unresolved,
        "resolution() accessor must surface Unresolved"
    );
    assert_eq!(deps[0].resolved(), None);
    Ok(())
}

#[test]
fn direct_dependencies_resolve_cargo_normalized_hyphenated_key() -> Result<(), Box<dyn Error>> {
    let consumer_path = "/workspace/crates/consumer";
    let dependency_path = "/workspace/adapters/crypto";
    let dependency_id = path_package_id(dependency_path);
    let consumer_id = path_package_id(consumer_path);
    let dependency = path_package(
        "crypto-adapter",
        dependency_path,
        vec![target(
            "crypto",
            "lib",
            &format!("{dependency_path}/src/lib.rs"),
            false,
            &[],
        )],
        vec![],
        json!({}),
    );
    let consumer = path_package(
        "consumer",
        consumer_path,
        vec![target(
            "consumer",
            "lib",
            &format!("{consumer_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![path_dependency("crypto-adapter", dependency_path)],
        json!({}),
    );
    let metadata = metadata_json(
        "/workspace",
        vec![dependency, consumer],
        vec![dependency_id.clone(), consumer_id.clone()],
        vec![
            resolve_node(&dependency_id, &[]),
            resolve_node(&consumer_id, &[("crypto", &dependency_id)]),
        ],
    );
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
    let consumer = facts.package_key("consumer")?;
    let dependency = facts
        .direct_dependencies_for(&consumer)?
        .first()
        .ok_or("hyphenated dependency missing")?;
    assert_eq!(dependency.name(), "crypto-adapter");
    assert_eq!(
        dependency.resolved().map(PackageKey::as_str),
        Some("crypto-adapter")
    );
    Ok(())
}

/// Load WorkspaceFacts from the real shipped workspace via nested `cargo metadata`.
///
/// Root is taken from metadata JSON itself (not `CARGO_MANIFEST_DIR` walk) so
/// `from_metadata_json` expected/actual root comparison stays stable under nested cargo.
fn load_shipped_workspace_facts() -> Result<(PathBuf, WorkspaceFacts), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut probe = manifest_dir.clone();
    // crates/workspacefacts → workspace root; fail loud if layout drifts.
    if probe.file_name().and_then(|name| name.to_str()) != Some("workspacefacts") {
        return Err(format!(
            "expected CARGO_MANIFEST_DIR to end with workspacefacts, got {}",
            probe.display()
        )
        .into());
    }
    probe.pop();
    if probe.file_name().and_then(|name| name.to_str()) != Some("crates") {
        return Err(format!(
            "expected parent of workspacefacts to be crates, got {}",
            probe.display()
        )
        .into());
    }
    probe.pop();
    let workspace_cargo = probe.join("Cargo.toml");
    if !workspace_cargo.is_file() {
        return Err(format!(
            "workspace Cargo.toml missing at {}",
            workspace_cargo.display()
        )
        .into());
    }

    let cargo = option_env!("CARGO").unwrap_or("cargo");
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&workspace_cargo)
        // Nested cargo under `cargo test` must not inherit parent jobserver / target-dir
        // wrappers that can rewrite paths or hang on the parent lock.
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTDOCFLAGS")
        .output()
        .map_err(|error| format!("failed to spawn `{cargo} metadata`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{cargo} metadata` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let metadata_json = String::from_utf8(output.stdout)
        .map_err(|error| format!("cargo metadata stdout is not UTF-8: {error}"))?;
    let parsed: serde_json::Value = serde_json::from_str(&metadata_json)
        .map_err(|error| format!("cargo metadata JSON parse failed: {error}"))?;
    let workspace_root = parsed
        .get("workspace_root")
        .and_then(serde_json::Value::as_str)
        .ok_or("cargo metadata missing string workspace_root")?;
    let root = PathBuf::from(workspace_root);
    if !root.is_absolute() {
        return Err(format!("workspace_root must be absolute, got {workspace_root}").into());
    }
    let facts = WorkspaceFacts::from_metadata_json(&root, &metadata_json)?;
    Ok((root, facts))
}

#[test]
fn shipped_workspace_graph_projects_xtask_dependency_on_workspacefacts()
-> Result<(), Box<dyn Error>> {
    let (_root, facts) = load_shipped_workspace_facts()?;
    let catalog = facts.workspace_packages();
    assert!(
        !catalog.is_empty(),
        "anti-vacuous: shipped workspace_packages must be non-empty"
    );
    assert!(
        catalog
            .iter()
            .any(|pkg| pkg.key().as_str() == "workspacefacts"),
        "anti-vacuous: workspacefacts must appear in shipped catalog"
    );
    assert!(
        catalog.iter().any(|pkg| pkg.key().as_str() == "xtask"),
        "anti-vacuous: preferred shipped consumer xtask must be a workspace member"
    );

    let xtask = facts.package_key("xtask")?;
    let deps = facts.direct_dependencies_for(&xtask)?;
    assert!(
        !deps.is_empty(),
        "anti-vacuous: xtask must declare direct dependencies"
    );
    let workspacefacts_dep = deps
        .iter()
        .find(|dep| {
            dep.resolved().map(PackageKey::as_str) == Some("workspacefacts")
                || dep.name() == "workspacefacts"
        })
        .ok_or_else(|| {
            format!(
                "xtask direct dependencies must project workspacefacts; got: {:?}",
                deps.iter()
                    .map(|dep| {
                        (
                            dep.name(),
                            dep.kind(),
                            dep.resolved().map(PackageKey::as_str),
                        )
                    })
                    .collect::<Vec<_>>()
            )
        })?;
    assert_eq!(
        workspacefacts_dep.resolved().map(PackageKey::as_str),
        Some("workspacefacts"),
        "workspacefacts declaration must resolve in shipped graph"
    );
    assert!(
        matches!(
            workspacefacts_dep.source(),
            DependencySource::Workspace { .. }
        ),
        "workspacefacts must project as workspace source, got {:?}",
        workspacefacts_dep.source()
    );
    let xtask_root = facts.repo_relative_root_for(&xtask)?;
    assert!(
        !xtask_root.as_os_str().is_empty() || catalog.iter().any(|pkg| pkg.key() == &xtask),
        "repo_relative_root_for(xtask) must succeed for shipped member"
    );
    Ok(())
}
