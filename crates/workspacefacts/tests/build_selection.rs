use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;
use workspacefacts::testing::{
    metadata_json, path_build_dependency_with_features, path_dependency_with_features,
    path_package, path_package_id, registry_package, resolve_node_with_dep_kinds,
    resolve_node_with_features, target,
};
use workspacefacts::{
    BuildPlatforms, BuildSelection, BuildSide, CargoPlatform, FeatureSelection, ResolverVersion,
    WorkspaceFacts, WorkspaceFactsError,
};

fn package(name: &str, path: &str, dependencies: Vec<Value>, features: Value) -> Value {
    path_package(
        name,
        path,
        vec![target(
            name,
            if name == "root" { "bin" } else { "lib" },
            &format!("{path}/src/lib.rs"),
            true,
            &[],
        )],
        dependencies,
        features,
    )
}

fn feature_metadata() -> String {
    let root_path = "/workspace/bins/root";
    let middle_path = "/workspace/crates/middle";
    let guarded_path = "/workspace/crates/guarded";
    let catalog_path = "/workspace/crates/catalog";

    let root = package(
        "root",
        root_path,
        vec![
            path_dependency_with_features("middle", middle_path, false, true, &[]),
            path_dependency_with_features("catalog", catalog_path, true, true, &["catalog-only"]),
            path_dependency_with_features("guarded", guarded_path, false, true, &[]),
        ],
        json!({
            "default": [],
            "all-only": ["dep:catalog"]
        }),
    );
    let middle = package(
        "middle",
        middle_path,
        vec![path_dependency_with_features(
            "guarded",
            guarded_path,
            false,
            true,
            &["danger"],
        )],
        json!({}),
    );
    let guarded = package("guarded", guarded_path, vec![], json!({"danger": []}));
    let catalog = package("catalog", catalog_path, vec![], json!({"catalog-only": []}));

    let root_id = path_package_id(root_path);
    let middle_id = path_package_id(middle_path);
    let guarded_id = path_package_id(guarded_path);
    let catalog_id = path_package_id(catalog_path);
    metadata_json(
        "/workspace",
        vec![root, middle, guarded, catalog],
        vec![
            root_id.clone(),
            middle_id.clone(),
            guarded_id.clone(),
            catalog_id.clone(),
        ],
        vec![
            resolve_node_with_features(
                &root_id,
                &[
                    ("middle", middle_id.as_str()),
                    ("catalog", catalog_id.as_str()),
                    ("guarded", guarded_id.as_str()),
                ],
                &["all-only"],
            ),
            resolve_node_with_features(&middle_id, &[("guarded", guarded_id.as_str())], &[]),
            resolve_node_with_features(&guarded_id, &[], &["danger"]),
            resolve_node_with_features(&catalog_id, &[], &["catalog-only"]),
        ],
    )
}

fn selection(
    facts: &WorkspaceFacts,
    feature_selection: FeatureSelection,
) -> Result<BuildSelection, WorkspaceFactsError> {
    let root = facts.package_key("root")?;
    let guarded = facts.package_key("guarded")?;
    let catalog = facts.package_key("catalog")?;
    let explain = BTreeSet::from([
        facts.feature_key(&guarded, "danger")?,
        facts.feature_key(&catalog, "catalog-only")?,
    ]);
    let platform = CargoPlatform::build_target()?;
    Ok(BuildSelection::new(
        root,
        ResolverVersion::V2,
        feature_selection,
        BuildPlatforms::new(platform.clone(), platform),
        explain,
    ))
}

#[test]
fn all_features_catalog_is_not_a_default_root_selection() -> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &feature_metadata())?;
    let guarded = facts.package_key("guarded")?;
    let catalog = facts.package_key("catalog")?;
    let danger = facts.feature_key(&guarded, "danger")?;
    let catalog_only = facts.feature_key(&catalog, "catalog-only")?;

    let default_build = facts.resolve_build(selection(&facts, FeatureSelection::Default)?)?;
    assert!(default_build.is_feature_enabled(BuildSide::Target, &danger));
    assert!(!default_build.is_feature_enabled(BuildSide::Target, &catalog_only));
    assert!(!default_build.is_feature_enabled(BuildSide::Host, &danger));
    assert!(
        !default_build
            .workspace_packages(BuildSide::Target)
            .contains(&catalog)
    );

    let all_build = facts.resolve_build(selection(&facts, FeatureSelection::All)?)?;
    assert!(all_build.is_feature_enabled(BuildSide::Target, &catalog_only));
    assert!(
        all_build
            .workspace_packages(BuildSide::Target)
            .contains(&catalog)
    );
    let catalog_path = all_build
        .activation_path(BuildSide::Target, &catalog_only)
        .ok_or("catalog-only activation path missing")?
        .to_string();
    assert!(
        catalog_path.contains("target:root/dep:catalog")
            || catalog_path.contains("target:root/all-only"),
        "All selection path must keep optional-dep or named-feature hops: {catalog_path}"
    );
    assert!(
        catalog_path.ends_with("target:catalog/catalog-only"),
        "All selection path must end at catalog-only: {catalog_path}"
    );
    Ok(())
}

#[test]
fn activation_path_is_owned_stable_and_root_specific() -> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &feature_metadata())?;
    let guarded = facts.package_key("guarded")?;
    let danger = facts.feature_key(&guarded, "danger")?;
    let build = facts.resolve_build(selection(&facts, FeatureSelection::Default)?)?;
    drop(facts);

    let rendered = build
        .activation_path(BuildSide::Target, &danger)
        .ok_or("danger activation path missing")?
        .to_string();
    assert_eq!(
        rendered,
        "target:root -> target:middle -> target:guarded/danger"
    );
    Ok(())
}

#[test]
fn build_dependency_activation_path_crosses_to_host() -> Result<(), Box<dyn Error>> {
    let root_path = "/workspace/bins/root";
    let middle_path = "/workspace/crates/middle";
    let guarded_path = "/workspace/crates/guarded";
    let catalog_path = "/workspace/crates/catalog";
    let root_id = path_package_id(root_path);
    let middle_id = path_package_id(middle_path);
    let guarded_id = path_package_id(guarded_path);
    let catalog_id = path_package_id(catalog_path);

    let root = path_package(
        "root",
        root_path,
        vec![
            target("root", "bin", &format!("{root_path}/src/lib.rs"), true, &[]),
            target(
                "build-script-build",
                "custom-build",
                &format!("{root_path}/build.rs"),
                false,
                &[],
            ),
        ],
        vec![
            path_build_dependency_with_features("middle", middle_path, false, true, &[]),
            path_dependency_with_features("catalog", catalog_path, true, true, &["catalog-only"]),
            path_dependency_with_features("guarded", guarded_path, false, true, &[]),
        ],
        json!({
            "default": [],
            "all-only": ["dep:catalog"]
        }),
    );
    let middle = package(
        "middle",
        middle_path,
        vec![path_dependency_with_features(
            "guarded",
            guarded_path,
            false,
            true,
            &["danger"],
        )],
        json!({}),
    );
    let guarded = package("guarded", guarded_path, vec![], json!({"danger": []}));
    let catalog = package("catalog", catalog_path, vec![], json!({"catalog-only": []}));
    let metadata = metadata_json(
        "/workspace",
        vec![root, middle, guarded, catalog],
        vec![
            root_id.clone(),
            middle_id.clone(),
            guarded_id.clone(),
            catalog_id.clone(),
        ],
        vec![
            resolve_node_with_dep_kinds(
                &root_id,
                &[
                    ("middle", middle_id.as_str(), Some("build")),
                    ("catalog", catalog_id.as_str(), None),
                    ("guarded", guarded_id.as_str(), None),
                ],
                &["all-only"],
            ),
            resolve_node_with_features(&middle_id, &[("guarded", guarded_id.as_str())], &[]),
            resolve_node_with_features(&guarded_id, &[], &["danger"]),
            resolve_node_with_features(&catalog_id, &[], &["catalog-only"]),
        ],
    );

    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
    let guarded = facts.package_key("guarded")?;
    let danger = facts.feature_key(&guarded, "danger")?;
    let build = facts.resolve_build(selection(&facts, FeatureSelection::Default)?)?;
    assert!(!build.is_feature_enabled(BuildSide::Target, &danger));
    assert!(build.is_feature_enabled(BuildSide::Host, &danger));
    assert_eq!(
        build
            .activation_path(BuildSide::Host, &danger)
            .ok_or("host danger activation path missing")?
            .to_string(),
        "target:root -> host:middle -> host:guarded/danger"
    );
    Ok(())
}

#[test]
fn selected_feature_graph_warning_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut metadata: Value = serde_json::from_str(&feature_metadata())?;
    let guarded = metadata["packages"]
        .as_array_mut()
        .and_then(|packages| {
            packages
                .iter_mut()
                .find(|package| package["name"] == "guarded")
        })
        .ok_or("synthetic guarded package missing")?;
    guarded["features"]["danger"] = json!(["danger"]);

    let facts = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &serde_json::to_string(&metadata)?,
    )?;
    assert!(matches!(
        facts.resolve_build(selection(&facts, FeatureSelection::Default)?),
        Err(WorkspaceFactsError::IncompleteFeatureGraph(_))
    ));
    Ok(())
}

#[test]
fn missing_named_feature_edge_fails_closed_when_selected() -> Result<(), Box<dyn Error>> {
    let mut metadata: Value = serde_json::from_str(&feature_metadata())?;
    let guarded = metadata["packages"]
        .as_array_mut()
        .and_then(|packages| {
            packages
                .iter_mut()
                .find(|package| package["name"] == "guarded")
        })
        .ok_or("synthetic guarded package missing")?;
    guarded["features"]["danger"] = json!(["does-not-exist"]);

    let facts = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &serde_json::to_string(&metadata)?,
    )?;
    assert!(matches!(
        facts.resolve_build(selection(&facts, FeatureSelection::Default)?),
        Err(WorkspaceFactsError::IncompleteFeatureGraph(_))
    ));
    Ok(())
}

#[test]
fn missing_dependency_feature_edge_is_scoped_when_unselected() -> Result<(), Box<dyn Error>> {
    let mut metadata: Value = serde_json::from_str(&feature_metadata())?;
    let middle = metadata["packages"]
        .as_array_mut()
        .and_then(|packages| {
            packages
                .iter_mut()
                .find(|package| package["name"] == "middle")
        })
        .ok_or("synthetic middle package missing")?;
    // Optional-dep edge referenced by an unused named feature: MissingFeature
    // AddDependencyEdges warning must be scoped out because `selected_dependency` is false
    // for the unused `absent` edge under Default root selection.
    middle["features"] = json!({"pull-missing": ["dep:absent"]});
    middle["dependencies"]
        .as_array_mut()
        .ok_or("middle dependencies missing")?
        .push(path_dependency_with_features(
            "absent",
            "/workspace/crates/absent",
            true,
            true,
            &[],
        ));

    let facts = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &serde_json::to_string(&metadata)?,
    )?;
    facts.resolve_build(selection(&facts, FeatureSelection::Default)?)?;
    Ok(())
}

#[test]
fn unknown_feature_and_platform_fail_closed() -> Result<(), Box<dyn Error>> {
    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &feature_metadata())?;
    let guarded = facts.package_key("guarded")?;
    assert!(matches!(
        facts.feature_key(&guarded, "missing"),
        Err(WorkspaceFactsError::UnknownFeature { .. })
    ));
    assert!(matches!(
        CargoPlatform::from_triple("definitely-not-a-rust-target", BTreeSet::<String>::new()),
        Err(WorkspaceFactsError::UnknownPlatform(_))
    ));
    Ok(())
}

#[test]
fn incomplete_resolve_graph_fails_closed() -> Result<(), Box<dyn Error>> {
    let metadata = feature_metadata();
    let mut value: Value = serde_json::from_str(&metadata)?;
    value
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .ok_or("synthetic packages missing")?
        .retain(|node| !node["id"].as_str().is_some_and(|id| id.contains("guarded")));
    let incomplete_metadata = serde_json::to_string(&value)?;
    assert!(
        WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &incomplete_metadata,).is_err()
    );
    Ok(())
}

#[test]
fn feature_graph_warnings_are_scoped_to_the_selected_build() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(&feature_metadata())?;
    let catalog = value
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| {
            packages
                .iter_mut()
                .find(|package| package["name"] == "catalog")
        })
        .ok_or("synthetic catalog package missing")?;
    catalog["features"] = json!({"catalog-only": ["catalog-only"]});
    let facts = WorkspaceFacts::from_metadata_json(
        Path::new("/workspace"),
        &serde_json::to_string(&value)?,
    )?;

    facts.resolve_build(selection(&facts, FeatureSelection::Default)?)?;
    assert!(matches!(
        facts.resolve_build(selection(&facts, FeatureSelection::All)?),
        Err(WorkspaceFactsError::IncompleteFeatureGraph(_))
    ));
    Ok(())
}

#[test]
fn side_facts_skip_non_workspace_packages_and_mark_proc_macro_initials_host()
-> Result<(), Box<dyn Error>> {
    let root_path = "/workspace/bins/root";
    let macro_path = "/workspace/crates/codegen";
    let vendor_path = "/workspace/vendor/external_lib";
    let root_id = path_package_id(root_path);
    let macro_id = path_package_id(macro_path);
    let vendor_id = path_package_id(vendor_path);
    let registry = registry_package(
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
    let registry_id = registry["id"].as_str().ok_or("registry id")?.to_owned();

    let root = path_package(
        "root",
        root_path,
        vec![target(
            "root",
            "bin",
            &format!("{root_path}/src/main.rs"),
            true,
            &[],
        )],
        vec![
            path_dependency_with_features("codegen", macro_path, false, true, &["expand"]),
            path_dependency_with_features("external_lib", vendor_path, false, true, &[]),
        ],
        json!({"default": []}),
    );
    let codegen = path_package(
        "codegen",
        macro_path,
        vec![target(
            "codegen",
            "proc-macro",
            &format!("{macro_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![],
        json!({"default": [], "expand": []}),
    );
    // Path package outside workspace_members — selected by CargoSet but filtered from side facts.
    let vendor = path_package(
        "external_lib",
        vendor_path,
        vec![target(
            "external_lib",
            "lib",
            &format!("{vendor_path}/src/lib.rs"),
            true,
            &[],
        )],
        vec![],
        json!({"default": []}),
    );
    let metadata = metadata_json(
        "/workspace",
        vec![root, codegen, vendor, registry],
        vec![root_id.clone(), macro_id.clone()],
        vec![
            resolve_node_with_features(
                &root_id,
                &[
                    ("codegen", macro_id.as_str()),
                    ("external_lib", vendor_id.as_str()),
                ],
                &["default"],
            ),
            resolve_node_with_features(&macro_id, &[], &["default", "expand"]),
            resolve_node_with_features(&vendor_id, &[], &["default"]),
            resolve_node_with_features(&registry_id, &[], &[]),
        ],
    );

    let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
    let root = facts.package_key("root")?;
    let codegen = facts.package_key("codegen")?;
    let expand = facts.feature_key(&codegen, "expand")?;
    assert!(matches!(
        facts.package_key("external_lib"),
        Err(WorkspaceFactsError::UnknownPackage(_))
    ));
    assert!(matches!(
        facts.package_key("serde"),
        Err(WorkspaceFactsError::UnknownPackage(_))
    ));
    let platform = CargoPlatform::build_target()?;
    let build = facts.resolve_build(BuildSelection::new(
        root,
        ResolverVersion::V2,
        FeatureSelection::Default,
        BuildPlatforms::new(platform.clone(), platform),
        BTreeSet::from([expand.clone()]),
    ))?;

    assert!(
        !build
            .workspace_packages(BuildSide::Target)
            .iter()
            .any(|package| package.as_str() == "external_lib")
    );
    assert!(
        !build
            .workspace_packages(BuildSide::Host)
            .iter()
            .any(|package| matches!(package.as_str(), "external_lib" | "serde"))
    );
    assert!(build.workspace_packages(BuildSide::Host).contains(&codegen));
    assert!(build.is_feature_enabled(BuildSide::Host, &expand));
    assert!(!build.is_feature_enabled(BuildSide::Target, &expand));
    Ok(())
}
