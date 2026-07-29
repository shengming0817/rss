//! Complete repository contract discovery shared by codegen and AssemblyLock.

use crate::contract_manifest::{
    ConsistencyLevel, ContractManifest, ContractOwner, Lifecycle, WorkflowMode,
};
use crate::{
    CanonicalAssemblyManifestV2, ProjectionActivation, SagaActivation, WorkflowActivation,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

const SCHEMA_HASH_TAG: &[u8] = b"rss-schema-hash-v1\0";

/// A typed contract discovered from one real repository `contract.toml`.
#[derive(Debug, Clone)]
pub struct DiscoveredContract {
    pub dir: PathBuf,
    pub path_kind: String,
    pub path_domain: String,
    pub path_version: String,
    pub slug: Option<String>,
    pub manifest: ContractManifest,
}

/// Closed discovery/schema error used by the complete catalog funnel.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryContractError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Manifest {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid contract repository input: {0}")]
    Invalid(String),
    #[error("failed to parse schema {path}: {source}")]
    SchemaJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

impl RepositoryContractError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

/// Recursively discover every real `contract.toml`, typed-parse it, and path-sort the result.
pub fn discover_contracts(
    contracts_root: &Path,
) -> Result<Vec<DiscoveredContract>, RepositoryContractError> {
    let mut toml_paths = Vec::new();
    collect_contract_tomls(contracts_root, &mut toml_paths)?;
    toml_paths.sort();
    toml_paths
        .into_iter()
        .map(|path| load_contract(contracts_root, &path))
        .collect()
}

/// Validate every assembly-local workflow activation against the complete repository catalog.
pub fn validate_workflow_activations(
    manifest: &CanonicalAssemblyManifestV2,
    contracts: &[DiscoveredContract],
) -> Result<(), RepositoryContractError> {
    let mut errors = Vec::new();
    for activation in manifest.workflow_activations() {
        let matches = contracts
            .iter()
            .filter(|contract| contract.manifest.id == activation.id())
            .collect::<Vec<_>>();
        let [contract] = matches.as_slice() else {
            errors.push(format!(
                "activation id=`{}` field=definition-count actual={} expected=1",
                activation.id(),
                matches.len()
            ));
            continue;
        };
        let definition = &contract.manifest;
        if definition.consistency_level != ConsistencyLevel::WorkflowEventual {
            errors.push(format!(
                "activation id=`{}` field=consistencyLevel actual={:?} expected=WorkflowEventual",
                activation.id(),
                definition.consistency_level
            ));
        }
        if definition.version != activation.definition_version() {
            errors.push(format!(
                "activation id=`{}` field=definitionVersion actual=`{}` expected=`{}`",
                activation.id(),
                activation.definition_version(),
                definition.version
            ));
        }
        match schema_hash(contract) {
            Ok(digest) if digest != activation.definition_schema_digest() => errors.push(format!(
                "activation id=`{}` field=definitionSchemaDigest actual=`{}` expected=`{digest}`",
                activation.id(),
                activation.definition_schema_digest()
            )),
            Err(error) => errors.push(format!(
                "activation id=`{}` field=definitionSchemaDigest actual=<unavailable> expected=repository-schema-hash cause=`{error}`",
                activation.id()
            )),
            Ok(_) => {}
        }
        match &definition.owner {
            ContractOwner::Domain(owner) if owner != &definition.domain => errors.push(format!(
                "activation id=`{}` field=owner actual=`{owner}` expected=`{}`",
                activation.id(),
                definition.domain
            )),
            ContractOwner::Framework => errors.push(format!(
                "activation id=`{}` field=owner actual=`_framework` expected=`{}`",
                activation.id(),
                definition.domain
            )),
            ContractOwner::Domain(_) => {}
        }
        if !manifest
            .domains()
            .iter()
            .any(|domain| domain.as_str() == definition.domain)
        {
            errors.push(format!(
                "activation id=`{}` field=domain actual=`{}` expected-one-of={:?}",
                activation.id(),
                definition.domain,
                manifest.domains()
            ));
        }
        let Some(workflow) = definition.capabilities.workflow.as_ref() else {
            errors.push(format!(
                "activation id=`{}` field=capabilities.workflow actual=missing expected=present",
                activation.id()
            ));
            continue;
        };
        let expected_mode = match activation {
            WorkflowActivation::Projection { .. } => WorkflowMode::Projection,
            WorkflowActivation::Saga { .. } => WorkflowMode::Saga,
        };
        if workflow.mode != expected_mode {
            errors.push(format!(
                "activation id=`{}` field=mode actual={:?} expected={expected_mode:?}",
                activation.id(),
                workflow.mode
            ));
        }
        let allowed_lifecycles = allowed_lifecycles(activation);
        if !allowed_lifecycles.contains(&definition.lifecycle) {
            errors.push(format!(
                "activation id=`{}` field=lifecycle actual={:?} expected-one-of={allowed_lifecycles:?}",
                activation.id(), definition.lifecycle
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(RepositoryContractError::Invalid(format!(
            "workflow activation repository join failed:\n- {}",
            errors.join("\n- ")
        )))
    }
}

fn allowed_lifecycles(activation: &WorkflowActivation) -> &'static [Lifecycle] {
    match activation {
        WorkflowActivation::Projection {
            activation: ProjectionActivation::Disabled,
            ..
        }
        | WorkflowActivation::Saga {
            activation: SagaActivation::Disabled,
            ..
        } => &[Lifecycle::Draft, Lifecycle::Active, Lifecycle::Deprecated],
        WorkflowActivation::Projection {
            activation: ProjectionActivation::CaptureOnly,
            ..
        } => &[Lifecycle::Draft, Lifecycle::Active],
        WorkflowActivation::Projection {
            activation: ProjectionActivation::Shadow | ProjectionActivation::Active,
            ..
        }
        | WorkflowActivation::Saga {
            activation: SagaActivation::Active,
            ..
        } => &[Lifecycle::Active],
    }
}

fn load_contract(
    contracts_root: &Path,
    manifest_path: &Path,
) -> Result<DiscoveredContract, RepositoryContractError> {
    let dir = manifest_path.parent().ok_or_else(|| {
        RepositoryContractError::Invalid(format!(
            "contract.toml has no parent: {}",
            manifest_path.display()
        ))
    })?;
    let text = std::fs::read_to_string(manifest_path).map_err(|source| {
        RepositoryContractError::io(
            format!("failed to read {}", manifest_path.display()),
            source,
        )
    })?;
    let manifest = ContractManifest::from_toml_str(&text).map_err(|source| {
        RepositoryContractError::Manifest {
            path: manifest_path.to_path_buf(),
            source,
        }
    })?;
    let (path_kind, path_domain, path_version, slug) = path_segments(contracts_root, dir)
        .ok_or_else(|| {
            RepositoryContractError::Invalid(format!(
                "contract directory must be contracts/{{kind}}/{{domain}}/{{version}}/[<slug>/]: {}",
                dir.display()
            ))
        })?;
    Ok(DiscoveredContract {
        dir: dir.to_path_buf(),
        path_kind,
        path_domain,
        path_version,
        slug,
        manifest,
    })
}

fn collect_contract_tomls(
    directory: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), RepositoryContractError> {
    let metadata = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(RepositoryContractError::io(
                format!("failed to inspect {}", directory.display()),
                source,
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(RepositoryContractError::Invalid(format!(
            "contract discovery rejects symlink directory: {}",
            directory.display()
        )));
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(directory).map_err(|source| {
        RepositoryContractError::io(format!("failed to read {}", directory.display()), source)
    })? {
        let entry = entry.map_err(|source| {
            RepositoryContractError::io(
                format!("failed to read entry under {}", directory.display()),
                source,
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| {
            RepositoryContractError::io(format!("failed to inspect {}", path.display()), source)
        })?;
        if file_type.is_symlink() {
            return Err(RepositoryContractError::Invalid(format!(
                "contract discovery rejects symlink: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_contract_tomls(&path, out)?;
        } else if file_type.is_file()
            && path.file_name().and_then(|name| name.to_str()) == Some("contract.toml")
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Parse the two supported contract directory layouts.
pub fn path_segments(
    contracts_root: &Path,
    dir: &Path,
) -> Option<(String, String, String, Option<String>)> {
    let relative = dir.strip_prefix(contracts_root).ok()?;
    let segments = relative
        .components()
        .map(|component| match component {
            Component::Normal(segment) => segment.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    match segments.as_slice() {
        [kind, domain, version] => Some((
            (*kind).to_owned(),
            (*domain).to_owned(),
            (*version).to_owned(),
            None,
        )),
        [kind, domain, version, slug] => Some((
            (*kind).to_owned(),
            (*domain).to_owned(),
            (*version).to_owned(),
            Some((*slug).to_owned()),
        )),
        _ => None,
    }
}

/// Preserve the existing schemaHash protocol while sharing it with AssemblyLock discovery.
pub fn schema_hash(contract: &DiscoveredContract) -> Result<String, RepositoryContractError> {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_HASH_TAG);
    for file in contract.manifest.declared_schema_files() {
        validate_schema_filename(file)?;
        let path = contract.dir.join(file);
        let text = std::fs::read_to_string(&path).map_err(|source| {
            RepositoryContractError::io(format!("failed to read schema {}", path.display()), source)
        })?;
        let value: Value =
            serde_json::from_str(&text).map_err(|source| RepositoryContractError::SchemaJson {
                path: path.clone(),
                source,
            })?;
        let canonical = serde_json::to_vec(&canonical_json(value)).map_err(|source| {
            RepositoryContractError::SchemaJson {
                path: path.clone(),
                source,
            }
        })?;
        hasher.update(file.as_bytes());
        hasher.update(b"\0");
        hasher.update(canonical.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(&canonical);
        hasher.update(b"\0");
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        Value::Object(map) => {
            let sorted = map
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        other => other,
    }
}

/// Require a schema declaration to be one safe repository-local filename.
pub fn validate_schema_filename(file: &str) -> Result<(), RepositoryContractError> {
    let unsafe_component = Path::new(file).components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if file.is_empty() || unsafe_component || file.contains('/') || file.contains('\\') {
        return Err(RepositoryContractError::Invalid(format!(
            "schema filename contains a path component: {file}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use crate::{AssemblyManifest, CanonicalAssemblyManifestV2};

    const SETTINGS_DIGEST: &str =
        "sha256:3504a1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa";

    fn contracts() -> Vec<DiscoveredContract> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
        let Ok(contracts) = discover_contracts(&root) else {
            panic!("repository contracts must be discoverable");
        };
        contracts
    }

    fn manifest(
        mode: &str,
        activation: &str,
        digest: &str,
        id: &str,
        version: &str,
        domain: &str,
    ) -> CanonicalAssemblyManifestV2 {
        canonical_manifest(&format!(
            r#"
schemaVersion = 2
name = "settings-fixture"
profile = "demo"
domains = ["{domain}"]
topology = "demo"
frameworkContracts = []
workflowActivations = [{{ mode = "{mode}", id = "{id}", definitionVersion = "{version}", definitionSchemaDigest = "{digest}", activation = "{activation}" }}]

[[listeners]]
kind = "primary"
domains = ["{domain}"]

[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "fixture"
outputs = ["resources"]
"#
        ))
    }

    fn canonical_manifest(text: &str) -> CanonicalAssemblyManifestV2 {
        let Ok(parsed) = AssemblyManifest::from_toml_str(text) else {
            panic!("test manifest must parse");
        };
        let Ok(canonical) = parsed.canonicalize_v2() else {
            panic!("test manifest must canonicalize");
        };
        canonical
    }

    fn settings_manifest(mode: &str, activation: &str) -> CanonicalAssemblyManifestV2 {
        manifest(
            mode,
            activation,
            SETTINGS_DIGEST,
            "settings.config-projection",
            "v3",
            "settings",
        )
    }

    fn settings_contract(catalog: &[DiscoveredContract]) -> DiscoveredContract {
        let Some(contract) = catalog
            .iter()
            .find(|contract| contract.manifest.id == "settings.config-projection")
        else {
            panic!("settings workflow contract must exist");
        };
        contract.clone()
    }

    fn only_settings_contract() -> Vec<DiscoveredContract> {
        let catalog = contracts();
        vec![settings_contract(&catalog)]
    }

    fn assert_invalid_contains(
        manifest: &CanonicalAssemblyManifestV2,
        catalog: &[DiscoveredContract],
        expected: &[&str],
    ) {
        let Err(error) = validate_workflow_activations(manifest, catalog) else {
            panic!("repository join unexpectedly succeeded");
        };
        let diagnostic = error.to_string();
        for fragment in expected {
            assert!(
                diagnostic.contains(fragment),
                "diagnostic `{diagnostic}` must contain `{fragment}`"
            );
        }
    }

    #[test]
    fn workflow_activation_exact_join_mutation_table() {
        enum Mutation {
            Unknown,
            Duplicate,
            Version,
            Digest,
            FrameworkOwner,
            WrongOwner,
            OutsideDomain,
            Mode,
            Consistency,
            MissingCapability,
            DeprecatedShadow,
        }
        let cases = [
            (Mutation::Unknown, "field=definition-count"),
            (Mutation::Duplicate, "field=definition-count actual=2"),
            (Mutation::Version, "field=definitionVersion"),
            (Mutation::Digest, "field=definitionSchemaDigest"),
            (Mutation::FrameworkOwner, "field=owner actual=`_framework`"),
            (Mutation::WrongOwner, "field=owner actual=`identity`"),
            (Mutation::OutsideDomain, "field=domain actual=`settings`"),
            (Mutation::Mode, "field=mode actual=Projection expected=Saga"),
            (Mutation::Consistency, "field=consistencyLevel"),
            (Mutation::MissingCapability, "field=capabilities.workflow"),
            (
                Mutation::DeprecatedShadow,
                "field=lifecycle actual=Deprecated",
            ),
        ];

        for (mutation, expected) in cases {
            let mut catalog = only_settings_contract();
            let mut candidate = settings_manifest("projection", "disabled");
            match mutation {
                Mutation::Unknown => {
                    candidate = manifest(
                        "projection",
                        "disabled",
                        SETTINGS_DIGEST,
                        "settings.unknown-workflow",
                        "v3",
                        "settings",
                    );
                }
                Mutation::Duplicate => catalog.push(catalog[0].clone()),
                Mutation::Version => {
                    candidate = manifest(
                        "projection",
                        "disabled",
                        SETTINGS_DIGEST,
                        "settings.config-projection",
                        "v99",
                        "settings",
                    );
                }
                Mutation::Digest => {
                    candidate = manifest(
                        "projection",
                        "disabled",
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "settings.config-projection",
                        "v3",
                        "settings",
                    );
                }
                Mutation::FrameworkOwner => catalog[0].manifest.owner = ContractOwner::Framework,
                Mutation::WrongOwner => {
                    catalog[0].manifest.owner = ContractOwner::Domain("identity".to_owned());
                }
                Mutation::OutsideDomain => {
                    candidate = manifest(
                        "projection",
                        "disabled",
                        SETTINGS_DIGEST,
                        "settings.config-projection",
                        "v3",
                        "identity",
                    );
                }
                Mutation::Mode => {
                    candidate = settings_manifest("saga", "disabled");
                }
                Mutation::Consistency => {
                    catalog[0].manifest.consistency_level = ConsistencyLevel::LocalOnly;
                }
                Mutation::MissingCapability => {
                    catalog[0].manifest.capabilities.workflow = None;
                }
                Mutation::DeprecatedShadow => {
                    catalog[0].manifest.lifecycle = Lifecycle::Deprecated;
                    candidate = settings_manifest("projection", "shadow");
                }
            }
            assert_invalid_contains(&candidate, &catalog, &[expected]);
        }
    }

    #[test]
    fn workflow_activation_lifecycle_truth_matrix_is_exhaustive() {
        let projection_cases = [
            ("disabled", Lifecycle::Draft, true),
            ("disabled", Lifecycle::Active, true),
            ("disabled", Lifecycle::Deprecated, true),
            ("capture-only", Lifecycle::Draft, true),
            ("capture-only", Lifecycle::Active, true),
            ("capture-only", Lifecycle::Deprecated, false),
            ("shadow", Lifecycle::Draft, false),
            ("shadow", Lifecycle::Active, true),
            ("shadow", Lifecycle::Deprecated, false),
            ("active", Lifecycle::Draft, false),
            ("active", Lifecycle::Active, true),
            ("active", Lifecycle::Deprecated, false),
        ];
        for (activation, lifecycle, expected) in projection_cases {
            let mut catalog = only_settings_contract();
            catalog[0].manifest.lifecycle = lifecycle;
            let actual = validate_workflow_activations(
                &settings_manifest("projection", activation),
                &catalog,
            )
            .is_ok();
            assert_eq!(actual, expected, "projection {activation:?} {lifecycle:?}");
        }

        let saga_cases = [
            ("disabled", Lifecycle::Draft, true),
            ("disabled", Lifecycle::Active, true),
            ("disabled", Lifecycle::Deprecated, true),
            ("active", Lifecycle::Draft, false),
            ("active", Lifecycle::Active, true),
            ("active", Lifecycle::Deprecated, false),
        ];
        for (activation, lifecycle, expected) in saga_cases {
            let mut catalog = only_settings_contract();
            catalog[0].manifest.lifecycle = lifecycle;
            let Some(workflow) = catalog[0].manifest.capabilities.workflow.as_mut() else {
                panic!("settings workflow capability must exist");
            };
            workflow.mode = WorkflowMode::Saga;
            let actual =
                validate_workflow_activations(&settings_manifest("saga", activation), &catalog)
                    .is_ok();
            assert_eq!(actual, expected, "saga {activation:?} {lifecycle:?}");
        }
    }

    #[test]
    fn workflow_activation_diagnostics_aggregate_all_field_failures() {
        let mut catalog = only_settings_contract();
        catalog[0].manifest.version = "v4".to_owned();
        catalog[0].manifest.owner = ContractOwner::Framework;
        catalog[0].manifest.consistency_level = ConsistencyLevel::LocalOnly;
        catalog[0].manifest.lifecycle = Lifecycle::Deprecated;
        let Some(workflow) = catalog[0].manifest.capabilities.workflow.as_mut() else {
            panic!("settings workflow capability must exist");
        };
        workflow.mode = WorkflowMode::Saga;
        let candidate = manifest(
            "projection",
            "shadow",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "settings.config-projection",
            "v3",
            "identity",
        );

        assert_invalid_contains(
            &candidate,
            &catalog,
            &[
                "id=`settings.config-projection`",
                "field=consistencyLevel",
                "field=definitionVersion actual=`v3` expected=`v4`",
                "field=definitionSchemaDigest",
                "field=owner actual=`_framework` expected=`settings`",
                "field=domain actual=`settings`",
                "field=mode actual=Saga expected=Projection",
                "field=lifecycle actual=Deprecated expected-one-of=[Active]",
            ],
        );

        let two_unknown = canonical_manifest(
            r#"
schemaVersion = 2
name = "aggregate-fixture"
profile = "demo"
domains = ["settings"]
topology = "demo"
frameworkContracts = []
workflowActivations = [
  { mode = "projection", id = "settings.unknown-a", definitionVersion = "v1", definitionSchemaDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", activation = "disabled" },
  { mode = "projection", id = "settings.unknown-b", definitionVersion = "v1", definitionSchemaDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", activation = "disabled" },
]

[[listeners]]
kind = "primary"
domains = ["settings"]

[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "fixture"
outputs = ["resources"]
"#,
        );
        assert_invalid_contains(
            &two_unknown,
            &[],
            &["id=`settings.unknown-a`", "id=`settings.unknown-b`"],
        );
    }
}
