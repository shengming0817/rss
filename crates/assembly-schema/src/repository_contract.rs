//! Complete repository contract discovery shared by codegen and AssemblyLock.

use crate::contract_manifest::{
    ConsistencyLevel, ContractManifest, Lifecycle, RawContractOwner, WorkflowMode,
};
use crate::{
    CanonicalAssemblyManifestV2, ContractOwner, ProjectionActivation, SagaActivation,
    WorkflowActivation,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

const SCHEMA_HASH_TAG: &[u8] = b"rss-schema-hash-v1\0";
const SOURCE_SNAPSHOT_TAG: &[u8] = b"rss-contract-source-snapshot-v2\0";
const COMPONENT_URI_PREFIX: &str = "rss://component/";
const FRAMEWORK_OWNER: &str = "_framework";

/// Canonical identity of a repository-local JSON Schema component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentId(String);

impl ComponentId {
    pub fn parse(raw: &str) -> Result<Self, RepositoryContractError> {
        component_segments(raw)?;
        Ok(Self(raw.to_owned()))
    }

    /// Derive and validate an ID from `contracts/components/<domain>/<version>/<slug>.schema.json`.
    pub fn from_repository_path(path: &str) -> Result<Option<Self>, RepositoryContractError> {
        let Some(relative) = path.strip_prefix("contracts/components/") else {
            return Ok(None);
        };
        let stem = relative.strip_suffix(".schema.json").ok_or_else(|| {
            RepositoryContractError::Invalid(format!(
                "RSS component path must end in .schema.json: {path:?}"
            ))
        })?;
        let id = Self::parse(&format!("{COMPONENT_URI_PREFIX}{stem}"))?;
        let expected = PathBuf::from("contracts").join(id.relative_path()?);
        if expected != Path::new(path) {
            return Err(RepositoryContractError::Invalid(format!(
                "non-canonical RSS component path: {path:?}"
            )));
        }
        Ok(Some(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn relative_path(&self) -> Result<PathBuf, RepositoryContractError> {
        let [domain, version, slug] = component_segments(self.as_str())?;
        Ok(PathBuf::from("components")
            .join(domain)
            .join(version)
            .join(format!("{slug}.schema.json")))
    }
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Pure reverse-reference graph over already-read schema documents. IO remains at the caller.
#[derive(Debug, Clone)]
pub struct ComponentGraph {
    components: BTreeMap<ComponentId, BTreeSet<ComponentId>>,
    consumers: BTreeMap<String, BTreeSet<ComponentId>>,
}

impl ComponentGraph {
    pub fn from_documents(
        documents: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<Self, RepositoryContractError> {
        let mut components = BTreeMap::new();
        let mut consumers = BTreeMap::new();
        for (path, value) in documents {
            let references = component_references(&value)?;
            if let Some(path_id) = ComponentId::from_repository_path(&path)? {
                let declared = value.get("$id").and_then(Value::as_str).ok_or_else(|| {
                    RepositoryContractError::Invalid(format!(
                        "RSS component graph node {path:?} must declare $id"
                    ))
                })?;
                let declared = ComponentId::parse(declared)?;
                if declared != path_id {
                    return Err(RepositoryContractError::Invalid(format!(
                        "RSS component graph node {path:?} must declare exact $id {path_id:?}"
                    )));
                }
                if components.insert(path_id.clone(), references).is_some() {
                    return Err(RepositoryContractError::Invalid(format!(
                        "duplicate RSS component graph identity {path_id:?}"
                    )));
                }
            } else {
                consumers.insert(path, references);
            }
        }
        for references in components.values().chain(consumers.values()) {
            for reference in references {
                if !components.contains_key(reference) {
                    return Err(RepositoryContractError::Invalid(format!(
                        "RSS component graph references missing component {reference:?}"
                    )));
                }
            }
        }
        reject_component_graph_cycles(&components)?;
        Ok(Self {
            components,
            consumers,
        })
    }

    /// All non-component document paths that directly or transitively reference `target`.
    pub fn transitive_consumer_paths(
        &self,
        target: &ComponentId,
    ) -> Result<BTreeSet<String>, RepositoryContractError> {
        if !self.components.contains_key(target) {
            return Err(RepositoryContractError::Invalid(format!(
                "RSS component graph target is missing: {target:?}"
            )));
        }
        let mut pending = vec![target.clone()];
        let mut reached = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if !reached.insert(current.clone()) {
                continue;
            }
            pending.extend(
                self.components
                    .iter()
                    .filter(|(_, references)| references.contains(&current))
                    .map(|(id, _)| id.clone()),
            );
        }
        Ok(self
            .consumers
            .iter()
            .filter(|(_, references)| references.iter().any(|id| reached.contains(id)))
            .map(|(path, _)| path.clone())
            .collect())
    }
}

fn reject_component_graph_cycles(
    components: &BTreeMap<ComponentId, BTreeSet<ComponentId>>,
) -> Result<(), RepositoryContractError> {
    fn visit(
        id: &ComponentId,
        components: &BTreeMap<ComponentId, BTreeSet<ComponentId>>,
        visiting: &mut BTreeSet<ComponentId>,
        complete: &mut BTreeSet<ComponentId>,
    ) -> Result<(), RepositoryContractError> {
        if complete.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.clone()) {
            return Err(RepositoryContractError::Invalid(format!(
                "RSS component graph cycle includes {id:?}"
            )));
        }
        for reference in &components[id] {
            visit(reference, components, visiting, complete)?;
        }
        visiting.remove(id);
        complete.insert(id.clone());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut complete = BTreeSet::new();
    for id in components.keys() {
        visit(id, components, &mut visiting, &mut complete)?;
    }
    Ok(())
}

/// Self-contained semantic schema plus the canonical component provenance used to build it.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedSchema {
    value: Value,
    component_ids: Vec<String>,
    component_definition_names: BTreeSet<String>,
}

impl ResolvedSchema {
    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn into_value(self) -> Value {
        self.value
    }

    pub fn component_ids(&self) -> &[String] {
        &self.component_ids
    }

    /// Root `definitions` entries introduced by component resolution, used by semantic
    /// consumers that must distinguish governed shared definitions from author inline schemas.
    pub fn component_definition_names(&self) -> &BTreeSet<String> {
        &self.component_definition_names
    }
}

impl std::ops::Deref for ResolvedSchema {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

fn promote_contract_owner(
    raw: &RawContractOwner,
) -> Result<ContractOwner, RepositoryContractError> {
    ContractOwner::promote(raw).map_err(|_| {
        let raw = match raw {
            RawContractOwner::Domain(domain) => domain.as_str(),
            RawContractOwner::Framework => FRAMEWORK_OWNER,
        };
        RepositoryContractError::Invalid(format!(
            "contract owner must be a canonical domain name: {raw:?}"
        ))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFileIdentity {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl SourceFileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFileSnapshot {
    path: PathBuf,
    bytes: Arc<[u8]>,
    digest: String,
    identity: SourceFileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemaSourceSnapshot {
    Present(SourceFileSnapshot),
    Missing { path: PathBuf },
    UnsafeName,
}

impl SchemaSourceSnapshot {
    fn path(&self) -> Option<&Path> {
        match self {
            Self::Present(source) => Some(&source.path),
            Self::Missing { path } => Some(path),
            Self::UnsafeName => None,
        }
    }

    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Present(source) => Some(&source.bytes),
            Self::Missing { .. } | Self::UnsafeName => None,
        }
    }

    fn digest(&self) -> Option<&str> {
        match self {
            Self::Present(source) => Some(&source.digest),
            Self::Missing { .. } | Self::UnsafeName => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContractSourceSnapshot {
    contracts_root: PathBuf,
    manifest: SourceFileSnapshot,
    schemas: BTreeMap<String, SchemaSourceSnapshot>,
    components: BTreeMap<String, SourceFileSnapshot>,
    digest: String,
    repository_backed: bool,
}

/// A typed, immutable contract promoted from one real repository `contract.toml`.
#[derive(Debug, Clone)]
pub struct RepositoryContract {
    dir: PathBuf,
    path_kind: String,
    path_domain: String,
    path_version: String,
    slug: Option<String>,
    owner: ContractOwner,
    manifest: ContractManifest,
    source: Arc<ContractSourceSnapshot>,
}

impl RepositoryContract {
    /// Parsed manifest facts captured by repository discovery.
    pub const fn manifest(&self) -> &ContractManifest {
        &self.manifest
    }

    /// Canonical owner promoted from the real manifest source.
    pub const fn owner(&self) -> &ContractOwner {
        &self.owner
    }

    /// Contract source directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_kind(&self) -> &str {
        &self.path_kind
    }

    pub fn path_domain(&self) -> &str {
        &self.path_domain
    }

    pub fn path_version(&self) -> &str {
        &self.path_version
    }

    pub fn slug(&self) -> Option<&str> {
        self.slug.as_deref()
    }

    /// Real `contract.toml` path represented by this snapshot.
    pub fn manifest_path(&self) -> &Path {
        &self.source.manifest.path
    }

    /// Exact raw bytes parsed into [`Self::manifest`].
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.source.manifest.bytes
    }

    /// SHA-256 of the exact captured manifest bytes.
    pub fn manifest_source_digest(&self) -> &str {
        &self.source.manifest.digest
    }

    /// Safe repository-local path for a declared schema, including a currently missing schema.
    pub fn schema_path(&self, file: &str) -> Option<&Path> {
        self.source
            .schemas
            .get(file)
            .and_then(SchemaSourceSnapshot::path)
    }

    /// Exact captured schema bytes, or `None` when the declared schema was missing or unsafe.
    fn schema_bytes(&self, file: &str) -> Option<&[u8]> {
        self.source
            .schemas
            .get(file)
            .and_then(SchemaSourceSnapshot::bytes)
    }

    /// Whether a declared schema was captured as one safe regular file.
    pub fn has_schema_source(&self, file: &str) -> bool {
        self.schema_bytes(file).is_some()
    }

    /// SHA-256 of exact captured schema bytes, if the declared schema existed.
    pub fn schema_source_digest(&self, file: &str) -> Option<&str> {
        self.source
            .schemas
            .get(file)
            .and_then(SchemaSourceSnapshot::digest)
    }

    /// Self-contained schema used by validation, hashing, breaking checks and code generation.
    /// Local RSS component references are rewritten to root definitions from the immutable source
    /// snapshot; no filesystem or network access occurs here.
    pub fn resolved_schema(&self, file: &str) -> Result<ResolvedSchema, RepositoryContractError> {
        let path = self
            .schema_path(file)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.dir.join(file));
        let bytes = self.schema_bytes(file).ok_or_else(|| {
            RepositoryContractError::io(
                format!("failed to read schema {}", path.display()),
                std::io::Error::new(std::io::ErrorKind::NotFound, "declared schema is missing"),
            )
        })?;
        let schema = serde_json::from_slice(bytes).map_err(|source| {
            RepositoryContractError::SchemaJson {
                path: path.clone(),
                source,
            }
        })?;
        resolve_component_references(schema, |id| {
            let source = self.source.components.get(id).ok_or_else(|| {
                RepositoryContractError::Invalid(format!(
                    "schema {} references uncaptured component {id:?}",
                    path.display()
                ))
            })?;
            serde_json::from_slice(&source.bytes).map_err(|source_error| {
                RepositoryContractError::SchemaJson {
                    path: source.path.clone(),
                    source: source_error,
                }
            })
        })
    }

    /// Direct `$ref` values used by every schema property with the requested name. `None` means
    /// the property was inlined or otherwise failed to declare a direct reference.
    pub fn schema_property_references(
        &self,
        file: &str,
        property: &str,
    ) -> Result<Vec<Option<String>>, RepositoryContractError> {
        let path = self
            .schema_path(file)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.dir.join(file));
        let bytes = self.schema_bytes(file).ok_or_else(|| {
            RepositoryContractError::io(
                format!("failed to read schema {}", path.display()),
                std::io::Error::new(std::io::ErrorKind::NotFound, "declared schema is missing"),
            )
        })?;
        let value: Value = serde_json::from_slice(bytes).map_err(|source| {
            RepositoryContractError::SchemaJson {
                path: path.clone(),
                source,
            }
        })?;
        let mut references = Vec::new();
        collect_property_references(&value, property, &mut references);
        Ok(references)
    }

    /// Digest of the complete captured manifest/schema source state. This is provenance evidence,
    /// not the generated wire `schemaHash` or AssemblyLock contract identity.
    pub fn source_snapshot_digest(&self) -> &str {
        &self.source.digest
    }

    /// Fail closed if any captured manifest/schema path, bytes, or file identity changed.
    pub fn verify_unchanged(&self) -> Result<(), RepositoryContractError> {
        if !self.source.repository_backed {
            return Err(RepositoryContractError::Invalid(
                "synthetic test contract snapshots have no repository provenance".to_owned(),
            ));
        }
        let current =
            load_contract(&self.source.contracts_root, self.manifest_path()).map_err(|error| {
                RepositoryContractError::stale(self.manifest_path(), error.to_string())
            })?;
        if current.dir != self.dir
            || current.path_kind != self.path_kind
            || current.path_domain != self.path_domain
            || current.path_version != self.path_version
            || current.slug != self.slug
            || current.owner != self.owner
            || current.manifest != self.manifest
            || current.source.as_ref() != self.source.as_ref()
        {
            return Err(RepositoryContractError::stale(
                self.manifest_path(),
                "captured path, identity, or bytes differ",
            ));
        }
        Ok(())
    }
}

fn collect_property_references(
    value: &Value,
    property: &str,
    references: &mut Vec<Option<String>>,
) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_property_references(value, property, references);
            }
        }
        Value::Object(map) => {
            if let Some(Value::Object(properties)) = map.get("properties")
                && let Some(schema) = properties.get(property)
            {
                references.push(
                    schema
                        .get("$ref")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                );
            }
            for value in map.values() {
                collect_property_references(value, property, references);
            }
        }
        _ => {}
    }
}

/// Explicit, feature-gated construction seam for synthetic xtask tests.
///
/// This builder is absent from default/production builds. Its output deliberately has no real
/// repository provenance, so [`RepositoryContract::verify_unchanged`] always rejects it.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub struct RepositoryContractTestBuilder {
    manifest: ContractManifest,
    dir: PathBuf,
    path_kind: String,
    path_domain: String,
    path_version: String,
    slug: Option<String>,
}

#[cfg(feature = "test-support")]
impl RepositoryContractTestBuilder {
    pub fn new(manifest: ContractManifest, dir: PathBuf) -> Self {
        Self {
            path_kind: manifest.kind.as_dir().to_owned(),
            path_domain: manifest.domain.clone(),
            path_version: manifest.version.clone(),
            manifest,
            dir,
            slug: None,
        }
    }

    pub fn path_kind(mut self, value: impl Into<String>) -> Self {
        self.path_kind = value.into();
        self
    }

    pub fn path_domain(mut self, value: impl Into<String>) -> Self {
        self.path_domain = value.into();
        self
    }

    pub fn path_version(mut self, value: impl Into<String>) -> Self {
        self.path_version = value.into();
        self
    }

    pub fn slug(mut self, value: Option<impl Into<String>>) -> Self {
        self.slug = value.map(Into::into);
        self
    }

    pub fn build(self) -> Result<RepositoryContract, RepositoryContractError> {
        let owner = promote_contract_owner(&self.manifest.owner)?;
        // Synthetic test snapshots do not claim repository/TOML provenance. Debug bytes keep
        // their digest deterministic without imposing a TOML round-trip requirement on map-key
        // newtypes such as `HttpStatusCode`.
        let manifest_bytes = format!("{:#?}", self.manifest);
        let manifest_source = synthetic_source_file(
            self.dir.join("contract.toml"),
            Arc::from(manifest_bytes.into_bytes()),
        );
        let schemas = capture_synthetic_schema_sources(&self.dir, &self.manifest)?;
        let components = BTreeMap::new();
        let digest = source_snapshot_digest(&manifest_source, &schemas, &components);
        let source = Arc::new(ContractSourceSnapshot {
            contracts_root: self.dir.clone(),
            manifest: manifest_source,
            schemas,
            components,
            digest,
            repository_backed: false,
        });
        Ok(RepositoryContract {
            dir: self.dir,
            path_kind: self.path_kind,
            path_domain: self.path_domain,
            path_version: self.path_version,
            slug: self.slug,
            owner,
            manifest: self.manifest,
            source,
        })
    }
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
    #[error("repository contract source changed after snapshot: {path} ({reason})")]
    Stale { path: PathBuf, reason: String },
}

impl RepositoryContractError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    fn stale(path: &Path, reason: impl Into<String>) -> Self {
        Self::Stale {
            path: path.to_path_buf(),
            reason: reason.into(),
        }
    }
}

/// Recursively discover every real `contract.toml`, typed-parse it, and path-sort the result.
pub fn load_contract_repository(
    contracts_root: &Path,
) -> Result<Vec<RepositoryContract>, RepositoryContractError> {
    let mut toml_paths = Vec::new();
    collect_contract_tomls(contracts_root, &mut toml_paths)?;
    toml_paths.sort();
    let contracts = toml_paths
        .into_iter()
        .map(|path| load_contract(contracts_root, &path))
        .collect::<Result<Vec<_>, _>>()?;
    verify_component_universe(contracts_root, contracts.iter())?;
    Ok(contracts)
}

/// Verify both the closed manifest universe and every captured contract source snapshot.
pub fn verify_contract_repository_unchanged<'a>(
    contracts_root: &Path,
    contracts: impl IntoIterator<Item = &'a RepositoryContract>,
) -> Result<(), RepositoryContractError> {
    let contracts = contracts.into_iter().collect::<Vec<_>>();
    let mut current_paths = Vec::new();
    collect_contract_tomls(contracts_root, &mut current_paths)?;
    current_paths.sort();
    let mut expected_paths = contracts
        .iter()
        .map(|contract| contract.manifest_path().to_path_buf())
        .collect::<Vec<_>>();
    expected_paths.sort();
    if current_paths != expected_paths {
        return Err(RepositoryContractError::stale(
            contracts_root,
            format!(
                "contract manifest universe differs: expected={expected_paths:?} current={current_paths:?}"
            ),
        ));
    }
    for contract in &contracts {
        contract.verify_unchanged()?;
    }
    verify_component_universe(contracts_root, contracts.iter().copied())?;
    Ok(())
}

fn verify_component_universe<'a>(
    contracts_root: &Path,
    contracts: impl IntoIterator<Item = &'a RepositoryContract>,
) -> Result<(), RepositoryContractError> {
    let mut actual = BTreeSet::new();
    collect_component_files(&contracts_root.join("components"), &mut actual)?;
    let expected = contracts
        .into_iter()
        .flat_map(|contract| contract.source.components.values())
        .map(|source| source.path.clone())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(RepositoryContractError::Invalid(format!(
            "component universe must equal the transitively referenced set: expected={expected:?} actual={actual:?}"
        )));
    }
    Ok(())
}

fn collect_component_files(
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(), RepositoryContractError> {
    let metadata = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(RepositoryContractError::io(
                format!(
                    "failed to inspect component directory {}",
                    directory.display()
                ),
                source,
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RepositoryContractError::Invalid(format!(
            "component path must be a non-symlink directory: {}",
            directory.display()
        )));
    }
    for entry in std::fs::read_dir(directory).map_err(|source| {
        RepositoryContractError::io(
            format!("failed to read component directory {}", directory.display()),
            source,
        )
    })? {
        let entry = entry.map_err(|source| {
            RepositoryContractError::io(
                format!(
                    "failed to read component entry under {}",
                    directory.display()
                ),
                source,
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| {
            RepositoryContractError::io(
                format!("failed to inspect component entry {}", path.display()),
                source,
            )
        })?;
        if file_type.is_symlink() {
            return Err(RepositoryContractError::Invalid(format!(
                "component repository rejects symlink: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_component_files(&path, files)?;
        } else if file_type.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".schema.json"))
        {
            files.insert(path);
        } else {
            return Err(RepositoryContractError::Invalid(format!(
                "component repository contains a non-schema file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Validate every assembly-local workflow activation against the complete repository catalog.
pub fn validate_workflow_activations(
    manifest: &CanonicalAssemblyManifestV2,
    contracts: &[RepositoryContract],
) -> Result<(), RepositoryContractError> {
    let mut errors = Vec::new();
    for activation in manifest.workflow_activations() {
        let matches = contracts
            .iter()
            .filter(|contract| contract.manifest().id == activation.id())
            .collect::<Vec<_>>();
        let [contract] = matches.as_slice() else {
            errors.push(format!(
                "activation id=`{}` field=definition-count actual={} expected=1",
                activation.id(),
                matches.len()
            ));
            continue;
        };
        let definition = contract.manifest();
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
        match contract.owner().domain() {
            Some(owner) if owner.as_str() != definition.domain => errors.push(format!(
                "activation id=`{}` field=owner actual=`{}` expected=`{}`",
                activation.id(),
                owner.as_str(),
                definition.domain
            )),
            None => errors.push(format!(
                "activation id=`{}` field=owner actual=`_framework` expected=`{}`",
                activation.id(),
                definition.domain
            )),
            Some(_) => {}
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
) -> Result<RepositoryContract, RepositoryContractError> {
    let dir = manifest_path.parent().ok_or_else(|| {
        RepositoryContractError::Invalid(format!(
            "contract.toml has no parent: {}",
            manifest_path.display()
        ))
    })?;
    let manifest_source = read_source_file(contracts_root, manifest_path)?;
    let text = std::str::from_utf8(&manifest_source.bytes).map_err(|source| {
        RepositoryContractError::io(
            format!("failed to decode {} as UTF-8", manifest_path.display()),
            std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        )
    })?;
    let manifest = ContractManifest::from_toml_str(text).map_err(|source| {
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
    let owner = promote_contract_owner(&manifest.owner)?;
    let schemas = capture_schema_sources(contracts_root, dir, &manifest)?;
    let components = capture_component_sources(contracts_root, &schemas)?;
    let digest = source_snapshot_digest(&manifest_source, &schemas, &components);
    let source = Arc::new(ContractSourceSnapshot {
        contracts_root: contracts_root.to_path_buf(),
        manifest: manifest_source,
        schemas,
        components,
        digest,
        repository_backed: true,
    });
    verify_source_snapshot(source.as_ref())?;
    Ok(RepositoryContract {
        dir: dir.to_path_buf(),
        path_kind,
        path_domain,
        path_version,
        slug,
        owner,
        manifest,
        source,
    })
}

fn capture_schema_sources(
    contracts_root: &Path,
    dir: &Path,
    manifest: &ContractManifest,
) -> Result<BTreeMap<String, SchemaSourceSnapshot>, RepositoryContractError> {
    let mut schemas = BTreeMap::new();
    for file in manifest.declared_schema_files() {
        if schemas.contains_key(file) {
            continue;
        }
        let source = if validate_schema_filename(file).is_err() {
            SchemaSourceSnapshot::UnsafeName
        } else {
            let path = dir.join(file);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => SchemaSourceSnapshot::Present(read_source_file(contracts_root, &path)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    ensure_safe_source_parent(contracts_root, &path)?;
                    SchemaSourceSnapshot::Missing { path }
                }
                Err(source) => {
                    return Err(RepositoryContractError::io(
                        format!("failed to inspect schema {}", path.display()),
                        source,
                    ));
                }
            }
        };
        schemas.insert(file.to_owned(), source);
    }
    Ok(schemas)
}

fn capture_component_sources(
    contracts_root: &Path,
    schemas: &BTreeMap<String, SchemaSourceSnapshot>,
) -> Result<BTreeMap<String, SourceFileSnapshot>, RepositoryContractError> {
    let mut pending = BTreeSet::new();
    for schema in schemas.values() {
        let SchemaSourceSnapshot::Present(source) = schema else {
            continue;
        };
        let value: Value = serde_json::from_slice(&source.bytes).map_err(|parse_error| {
            RepositoryContractError::SchemaJson {
                path: source.path.clone(),
                source: parse_error,
            }
        })?;
        collect_component_refs(&value, &mut pending)?;
    }

    let mut captured = BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if captured.contains_key(id.as_str()) {
            continue;
        }
        let path = contracts_root.join(id.relative_path()?);
        let source = read_source_file(contracts_root, &path)?;
        let value: Value = serde_json::from_slice(&source.bytes).map_err(|parse_error| {
            RepositoryContractError::SchemaJson {
                path: source.path.clone(),
                source: parse_error,
            }
        })?;
        if value.get("$id").and_then(Value::as_str) != Some(id.as_str()) {
            return Err(RepositoryContractError::Invalid(format!(
                "component {} must declare exact $id {id:?}",
                path.display()
            )));
        }
        collect_component_refs(&value, &mut pending)?;
        captured.insert(id.to_string(), source);
    }
    Ok(captured)
}

fn collect_component_refs(
    value: &Value,
    refs: &mut BTreeSet<ComponentId>,
) -> Result<(), RepositoryContractError> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_component_refs(value, refs)?;
            }
        }
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                if reference.starts_with(COMPONENT_URI_PREFIX) {
                    refs.insert(ComponentId::parse(reference)?);
                } else if !reference.starts_with('#') {
                    return Err(RepositoryContractError::Invalid(format!(
                        "external schema reference is not a local RSS component: {reference:?}"
                    )));
                }
            }
            for value in map.values() {
                collect_component_refs(value, refs)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Canonical local component references in one parsed schema. Every non-fragment external
/// reference is rejected through the same parser used by repository resolution and CI impact.
pub fn component_references(
    value: &Value,
) -> Result<BTreeSet<ComponentId>, RepositoryContractError> {
    let mut references = BTreeSet::new();
    collect_component_refs(value, &mut references)?;
    Ok(references)
}

fn component_segments(id: &str) -> Result<[&str; 3], RepositoryContractError> {
    let suffix = id.strip_prefix(COMPONENT_URI_PREFIX).ok_or_else(|| {
        RepositoryContractError::Invalid(format!("invalid RSS component id: {id:?}"))
    })?;
    if suffix.contains(['#', '?', '\\']) {
        return Err(RepositoryContractError::Invalid(format!(
            "RSS component id must not contain fragment, query or backslash: {id:?}"
        )));
    }
    let segments = suffix.split('/').collect::<Vec<_>>();
    let [domain, version, slug] = segments.as_slice() else {
        return Err(RepositoryContractError::Invalid(format!(
            "RSS component id must be rss://component/<domain>/<version>/<slug>: {id:?}"
        )));
    };
    if [domain, version, slug].iter().any(|segment| {
        segment.is_empty()
            || !segment.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
    }) {
        return Err(RepositoryContractError::Invalid(format!(
            "RSS component id contains a non-canonical segment: {id:?}"
        )));
    }
    Ok([domain, version, slug])
}

/// Canonical repository-relative path for one validated RSS component id.
pub fn component_relative_path(id: &str) -> Result<PathBuf, RepositoryContractError> {
    ComponentId::parse(id)?.relative_path()
}

/// Resolve local RSS component references without coupling the algorithm to filesystem or Git IO.
pub fn resolve_component_references<F>(
    mut schema: Value,
    mut load: F,
) -> Result<ResolvedSchema, RepositoryContractError>
where
    F: FnMut(&str) -> Result<Value, RepositoryContractError>,
{
    struct Resolver<'a, F> {
        load: &'a mut F,
        resolving: BTreeSet<String>,
        resolved: BTreeMap<String, String>,
        definitions: BTreeMap<String, Value>,
    }

    impl<F> Resolver<'_, F>
    where
        F: FnMut(&str) -> Result<Value, RepositoryContractError>,
    {
        fn value(&mut self, value: &mut Value) -> Result<(), RepositoryContractError> {
            match value {
                Value::Array(values) => {
                    for value in values {
                        self.value(value)?;
                    }
                }
                Value::Object(map) => {
                    let external = map
                        .get("$ref")
                        .and_then(Value::as_str)
                        .filter(|reference| reference.starts_with(COMPONENT_URI_PREFIX))
                        .map(str::to_owned);
                    if let Some(id) = external {
                        let title = self.component(&id)?;
                        map.insert(
                            "$ref".to_owned(),
                            Value::String(format!("#/definitions/{title}")),
                        );
                    } else if let Some(reference) = map.get("$ref").and_then(Value::as_str)
                        && !reference.starts_with('#')
                    {
                        return Err(RepositoryContractError::Invalid(format!(
                            "external schema reference is not a local RSS component: {reference:?}"
                        )));
                    }
                    for value in map.values_mut() {
                        self.value(value)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }

        fn component(&mut self, id: &str) -> Result<String, RepositoryContractError> {
            component_segments(id)?;
            if let Some(title) = self.resolved.get(id) {
                return Ok(title.clone());
            }
            if !self.resolving.insert(id.to_owned()) {
                return Err(RepositoryContractError::Invalid(format!(
                    "RSS component reference cycle includes {id:?}"
                )));
            }
            let mut component = (self.load)(id)?;
            if component.get("$id").and_then(Value::as_str) != Some(id) {
                return Err(RepositoryContractError::Invalid(format!(
                    "RSS component must declare exact $id {id:?}"
                )));
            }
            let title = component
                .get("title")
                .and_then(Value::as_str)
                .filter(|title| !title.is_empty())
                .ok_or_else(|| {
                    RepositoryContractError::Invalid(format!(
                        "RSS component {id:?} must declare a non-empty root title"
                    ))
                })?
                .to_owned();
            self.value(&mut component)?;
            let object = component.as_object_mut().ok_or_else(|| {
                RepositoryContractError::Invalid(format!(
                    "RSS component {id:?} root must be a schema object"
                ))
            })?;
            object.remove("$id");
            object.remove("$schema");
            if let Some(local) = object.remove("definitions") {
                let local = local.as_object().ok_or_else(|| {
                    RepositoryContractError::Invalid(format!(
                        "RSS component {id:?} definitions must be an object"
                    ))
                })?;
                for (name, value) in local {
                    self.insert_definition(name, value.clone())?;
                }
            }
            self.insert_definition(&title, component)?;
            self.resolving.remove(id);
            self.resolved.insert(id.to_owned(), title.clone());
            Ok(title)
        }

        fn insert_definition(
            &mut self,
            name: &str,
            value: Value,
        ) -> Result<(), RepositoryContractError> {
            if let Some(existing) = self.definitions.get(name) {
                if existing != &value {
                    return Err(RepositoryContractError::Invalid(format!(
                        "resolved schema definition collision for {name:?}"
                    )));
                }
                return Ok(());
            }
            self.definitions.insert(name.to_owned(), value);
            Ok(())
        }
    }

    let mut resolver = Resolver {
        load: &mut load,
        resolving: BTreeSet::new(),
        resolved: BTreeMap::new(),
        definitions: BTreeMap::new(),
    };
    resolver.value(&mut schema)?;
    let component_definition_names = resolver.definitions.keys().cloned().collect();
    if !resolver.definitions.is_empty() {
        let object = schema.as_object_mut().ok_or_else(|| {
            RepositoryContractError::Invalid("schema root must be an object".to_owned())
        })?;
        let definitions = object
            .entry("definitions")
            .or_insert_with(|| Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or_else(|| {
                RepositoryContractError::Invalid("schema definitions must be an object".to_owned())
            })?;
        for (name, value) in resolver.definitions {
            if definitions.contains_key(&name) {
                return Err(RepositoryContractError::Invalid(format!(
                    "resolved component definition collides with author definition {name:?}"
                )));
            }
            definitions.insert(name, value);
        }
    }
    Ok(ResolvedSchema {
        value: schema,
        component_ids: resolver.resolved.into_keys().collect(),
        component_definition_names,
    })
}

#[cfg(feature = "test-support")]
fn capture_synthetic_schema_sources(
    dir: &Path,
    manifest: &ContractManifest,
) -> Result<BTreeMap<String, SchemaSourceSnapshot>, RepositoryContractError> {
    let mut schemas = BTreeMap::new();
    for file in manifest.declared_schema_files() {
        if schemas.contains_key(file) {
            continue;
        }
        let source = if validate_schema_filename(file).is_err() {
            SchemaSourceSnapshot::UnsafeName
        } else {
            let path = dir.join(file);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(RepositoryContractError::Invalid(format!(
                        "synthetic schema source must be a non-symlink regular file: {}",
                        path.display()
                    )));
                }
                Ok(metadata) => {
                    let before = SourceFileIdentity::from_metadata(&metadata);
                    let bytes = std::fs::read(&path).map_err(|source| {
                        RepositoryContractError::io(
                            format!("failed to read synthetic schema {}", path.display()),
                            source,
                        )
                    })?;
                    let after = std::fs::symlink_metadata(&path).map_err(|source| {
                        RepositoryContractError::io(
                            format!("failed to re-inspect synthetic schema {}", path.display()),
                            source,
                        )
                    })?;
                    if after.file_type().is_symlink()
                        || !after.is_file()
                        || SourceFileIdentity::from_metadata(&after) != before
                        || before.len != bytes.len() as u64
                    {
                        return Err(RepositoryContractError::stale(
                            &path,
                            "synthetic schema changed while reading",
                        ));
                    }
                    SchemaSourceSnapshot::Present(synthetic_source_file(path, Arc::from(bytes)))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    SchemaSourceSnapshot::Missing { path }
                }
                Err(source) => {
                    return Err(RepositoryContractError::io(
                        format!("failed to inspect synthetic schema {}", path.display()),
                        source,
                    ));
                }
            }
        };
        schemas.insert(file.to_owned(), source);
    }
    Ok(schemas)
}

#[cfg(feature = "test-support")]
fn synthetic_source_file(path: PathBuf, bytes: Arc<[u8]>) -> SourceFileSnapshot {
    let len = bytes.len() as u64;
    SourceFileSnapshot {
        path,
        digest: sha256_digest(&bytes),
        bytes,
        identity: SourceFileIdentity {
            len,
            modified: None,
            #[cfg(unix)]
            device: 0,
            #[cfg(unix)]
            inode: 0,
        },
    }
}

fn read_source_file(
    contracts_root: &Path,
    path: &Path,
) -> Result<SourceFileSnapshot, RepositoryContractError> {
    let before = inspect_safe_source_file(contracts_root, path)?;
    let before_identity = SourceFileIdentity::from_metadata(&before);
    let mut file = File::open(path).map_err(|source| {
        RepositoryContractError::io(format!("failed to open source {}", path.display()), source)
    })?;
    let opened_identity =
        SourceFileIdentity::from_metadata(&file.metadata().map_err(|source| {
            RepositoryContractError::io(
                format!("failed to inspect open source {}", path.display()),
                source,
            )
        })?);
    if opened_identity != before_identity {
        return Err(RepositoryContractError::stale(
            path,
            "file identity changed while opening",
        ));
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|source| {
        RepositoryContractError::io(format!("failed to read source {}", path.display()), source)
    })?;
    let opened_after = SourceFileIdentity::from_metadata(&file.metadata().map_err(|source| {
        RepositoryContractError::io(
            format!("failed to re-inspect open source {}", path.display()),
            source,
        )
    })?);
    let after = inspect_safe_source_file(contracts_root, path)?;
    let after_identity = SourceFileIdentity::from_metadata(&after);
    if opened_after != before_identity
        || after_identity != before_identity
        || before_identity.len != bytes.len() as u64
    {
        return Err(RepositoryContractError::stale(
            path,
            "file changed while reading",
        ));
    }

    Ok(SourceFileSnapshot {
        path: path.to_path_buf(),
        digest: sha256_digest(&bytes),
        bytes: Arc::from(bytes),
        identity: before_identity,
    })
}

fn inspect_safe_source_file(
    contracts_root: &Path,
    path: &Path,
) -> Result<Metadata, RepositoryContractError> {
    ensure_safe_source_parent(contracts_root, path)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|source| {
        RepositoryContractError::io(
            format!("failed to inspect source {}", path.display()),
            source,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RepositoryContractError::Invalid(format!(
            "contract source must be a non-symlink regular file: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn ensure_safe_source_parent(
    contracts_root: &Path,
    path: &Path,
) -> Result<(), RepositoryContractError> {
    let relative = path.strip_prefix(contracts_root).map_err(|_| {
        RepositoryContractError::Invalid(format!(
            "contract source escapes contracts root: {}",
            path.display()
        ))
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RepositoryContractError::Invalid(format!(
            "contract source path contains a non-normal component: {}",
            path.display()
        )));
    }

    let root_metadata = std::fs::symlink_metadata(contracts_root).map_err(|source| {
        RepositoryContractError::io(
            format!(
                "failed to inspect contracts root {}",
                contracts_root.display()
            ),
            source,
        )
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(RepositoryContractError::Invalid(format!(
            "contracts root must be a non-symlink directory: {}",
            contracts_root.display()
        )));
    }

    let parent = path.parent().ok_or_else(|| {
        RepositoryContractError::Invalid(format!(
            "contract source has no parent: {}",
            path.display()
        ))
    })?;
    let parent_relative = parent.strip_prefix(contracts_root).map_err(|_| {
        RepositoryContractError::Invalid(format!(
            "contract source parent escapes contracts root: {}",
            parent.display()
        ))
    })?;
    let mut current = contracts_root.to_path_buf();
    for component in parent_relative.components() {
        let Component::Normal(segment) = component else {
            return Err(RepositoryContractError::Invalid(format!(
                "contract source parent contains a non-normal component: {}",
                parent.display()
            )));
        };
        current.push(segment);
        let metadata = std::fs::symlink_metadata(&current).map_err(|source| {
            RepositoryContractError::io(
                format!(
                    "failed to inspect contract source parent {}",
                    current.display()
                ),
                source,
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RepositoryContractError::Invalid(format!(
                "contract source parent must be a non-symlink directory: {}",
                current.display()
            )));
        }
    }
    Ok(())
}

fn verify_source_snapshot(
    snapshot: &ContractSourceSnapshot,
) -> Result<(), RepositoryContractError> {
    verify_file_snapshot(&snapshot.contracts_root, &snapshot.manifest)?;
    for schema in snapshot.schemas.values() {
        match schema {
            SchemaSourceSnapshot::Present(source) => {
                verify_file_snapshot(&snapshot.contracts_root, source)?;
            }
            SchemaSourceSnapshot::Missing { path } => {
                ensure_safe_source_parent(&snapshot.contracts_root, path)?;
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => {
                        return Err(RepositoryContractError::stale(
                            path,
                            "declared schema appeared while snapshotting",
                        ));
                    }
                    Err(source) => {
                        return Err(RepositoryContractError::io(
                            format!("failed to re-inspect missing schema {}", path.display()),
                            source,
                        ));
                    }
                }
            }
            SchemaSourceSnapshot::UnsafeName => {}
        }
    }
    for component in snapshot.components.values() {
        verify_file_snapshot(&snapshot.contracts_root, component)?;
    }
    Ok(())
}

fn verify_file_snapshot(
    contracts_root: &Path,
    expected: &SourceFileSnapshot,
) -> Result<(), RepositoryContractError> {
    let current = read_source_file(contracts_root, &expected.path)?;
    if current != *expected {
        return Err(RepositoryContractError::stale(
            &expected.path,
            "file identity or bytes differ",
        ));
    }
    Ok(())
}

fn source_snapshot_digest(
    manifest: &SourceFileSnapshot,
    schemas: &BTreeMap<String, SchemaSourceSnapshot>,
    components: &BTreeMap<String, SourceFileSnapshot>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_SNAPSHOT_TAG);
    hash_snapshot_component(&mut hasher, b"contract.toml");
    hash_snapshot_component(&mut hasher, &manifest.bytes);
    for (name, schema) in schemas {
        hash_snapshot_component(&mut hasher, name.as_bytes());
        match schema {
            SchemaSourceSnapshot::Present(source) => {
                hash_snapshot_component(&mut hasher, b"present");
                hash_snapshot_component(&mut hasher, &source.bytes);
            }
            SchemaSourceSnapshot::Missing { .. } => {
                hash_snapshot_component(&mut hasher, b"missing");
            }
            SchemaSourceSnapshot::UnsafeName => {
                hash_snapshot_component(&mut hasher, b"unsafe-name");
            }
        }
    }
    for (id, component) in components {
        hash_snapshot_component(&mut hasher, id.as_bytes());
        hash_snapshot_component(&mut hasher, &component.bytes);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn hash_snapshot_component(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    hasher.update(b"\0");
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
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
pub fn schema_hash(contract: &RepositoryContract) -> Result<String, RepositoryContractError> {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_HASH_TAG);
    for file in contract.manifest().declared_schema_files() {
        validate_schema_filename(file)?;
        let path = contract
            .schema_path(file)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| contract.dir().join(file));
        let value = contract.resolved_schema(file)?.into_value();
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
    use anyhow::Context as _;
    use std::collections::BTreeSet;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    const SETTINGS_DIGEST: &str =
        "sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8";
    static TEMP_REPOSITORY_ID: AtomicU64 = AtomicU64::new(0);

    struct TestRepository {
        root: PathBuf,
    }

    impl TestRepository {
        fn contracts_root(&self) -> PathBuf {
            self.root.join("contracts")
        }

        fn contract_dir(&self) -> PathBuf {
            self.contracts_root().join("projection/settings/v3")
        }
    }

    impl Drop for TestRepository {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn fixture_repository(owner: &str) -> anyhow::Result<TestRepository> {
        let id = TEMP_REPOSITORY_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rss-assembly-schema-contract-{}-{id}",
            std::process::id()
        ));
        let repository = TestRepository { root };
        let contract_dir = repository.contract_dir();
        fs::create_dir_all(&contract_dir)?;

        let workspace_contract =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/projection/settings/v3");
        let source = fs::read_to_string(workspace_contract.join("contract.toml"))?;
        fs::write(
            contract_dir.join("contract.toml"),
            source.replace("owner = \"settings\"", &format!("owner = {owner:?}")),
        )?;
        for schema in ["projection.schema.json"] {
            fs::copy(workspace_contract.join(schema), contract_dir.join(schema))?;
        }
        Ok(repository)
    }

    fn contracts() -> Vec<RepositoryContract> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
        let Ok(contracts) = load_contract_repository(&root) else {
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
        let target_generation = if mode == "projection" {
            r#", targetGeneration = "v3""#
        } else {
            ""
        };
        canonical_manifest(&format!(
            r#"
schemaVersion = 2
name = "settings-fixture"
profile = "demo"
domains = ["{domain}"]
topology = "demo"
frameworkContracts = []
workflowActivations = [{{ mode = "{mode}", id = "{id}", definitionVersion = "{version}", definitionSchemaDigest = "{digest}"{target_generation}, activation = "{activation}" }}]

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
outputs = ["probes", "resources"]
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

    fn settings_contract(catalog: &[RepositoryContract]) -> RepositoryContract {
        let Some(contract) = catalog
            .iter()
            .find(|contract| contract.manifest().id == "settings.config-projection")
        else {
            panic!("settings workflow contract must exist");
        };
        contract.clone()
    }

    fn only_settings_contract() -> Vec<RepositoryContract> {
        let catalog = contracts();
        vec![settings_contract(&catalog)]
    }

    fn assert_invalid_contains(
        manifest: &CanonicalAssemblyManifestV2,
        catalog: &[RepositoryContract],
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
    fn workflow_activation_diagnostics_aggregate_all_field_failures() -> anyhow::Result<()> {
        let repository = fixture_repository(FRAMEWORK_OWNER)?;
        let mut catalog = load_contract_repository(&repository.contracts_root())?;
        catalog[0].manifest.version = "v4".to_owned();
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
  { mode = "projection", id = "settings.unknown-a", definitionVersion = "v1", definitionSchemaDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", targetGeneration = "unknown-a-v1", activation = "disabled" },
  { mode = "projection", id = "settings.unknown-b", definitionVersion = "v1", definitionSchemaDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", targetGeneration = "unknown-b-v1", activation = "disabled" },
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
outputs = ["probes", "resources"]
"#,
        );
        assert_invalid_contains(
            &two_unknown,
            &[],
            &["id=`settings.unknown-a`", "id=`settings.unknown-b`"],
        );
        Ok(())
    }

    #[test]
    fn manifest_backed_owner_is_promoted_only_from_legal_repository_source() -> anyhow::Result<()> {
        for (raw, expected_domain, framework) in [
            ("settings", Some("settings"), false),
            (FRAMEWORK_OWNER, None, true),
        ] {
            let repository = fixture_repository(raw)?;
            let contracts = load_contract_repository(&repository.contracts_root())?;
            let [contract] = contracts.as_slice() else {
                panic!("fixture must contain one contract");
            };
            assert_eq!(
                contract.owner().domain().map(vocab::DomainName::as_str),
                expected_domain
            );
            assert_eq!(contract.owner().is_framework_owned(), framework);
            assert_eq!(contract.owner().as_str(), raw);
            contract.verify_unchanged()?;
        }

        let repository = fixture_repository("Settings")?;
        let Err(error) = load_contract_repository(&repository.contracts_root()) else {
            panic!("non-canonical owner must fail promotion");
        };
        assert!(error.to_string().contains("canonical domain name"));
        Ok(())
    }

    #[test]
    fn source_snapshot_exposes_immutable_manifest_schema_and_path_views() -> anyhow::Result<()> {
        let repository = fixture_repository("settings")?;
        let contracts = load_contract_repository(&repository.contracts_root())?;
        let [contract] = contracts.as_slice() else {
            panic!("fixture must contain one contract");
        };

        assert_eq!(contract.path_kind(), "projection");
        assert_eq!(contract.path_domain(), "settings");
        assert_eq!(contract.path_version(), "v3");
        assert_eq!(contract.slug(), None);
        assert_eq!(contract.dir(), repository.contract_dir());
        assert_eq!(contract.manifest().id, "settings.config-projection");
        assert_eq!(
            contract.manifest_bytes(),
            fs::read(contract.manifest_path())?
        );
        assert!(contract.manifest_source_digest().starts_with("sha256:"));
        assert!(contract.source_snapshot_digest().starts_with("sha256:"));
        for schema in ["projection.schema.json"] {
            let Some(schema_path) = contract.schema_path(schema) else {
                panic!("declared schema path must be captured");
            };
            let expected = fs::read(schema_path)?;
            assert_eq!(contract.schema_bytes(schema), Some(expected.as_slice()));
            assert!(
                contract
                    .schema_source_digest(schema)
                    .is_some_and(|digest| digest.starts_with("sha256:"))
            );
        }
        assert_eq!(schema_hash(contract)?, SETTINGS_DIGEST);
        contract.verify_unchanged()?;
        Ok(())
    }

    #[test]
    fn source_snapshot_rejects_stale_manifest_and_schema_mutations() -> anyhow::Result<()> {
        for target in ["contract.toml", "projection.schema.json"] {
            let repository = fixture_repository("settings")?;
            let contracts = load_contract_repository(&repository.contracts_root())?;
            let [contract] = contracts.as_slice() else {
                panic!("fixture must contain one contract");
            };
            let path = repository.contract_dir().join(target);
            let mut bytes = fs::read(&path)?;
            bytes.extend_from_slice(b"\n");
            fs::write(&path, bytes)?;
            let Err(error) = contract.verify_unchanged() else {
                panic!("source mutation must invalidate snapshot");
            };
            assert!(error.to_string().contains("changed after snapshot"));
        }
        Ok(())
    }

    #[test]
    fn repository_contract_resolves_and_snapshots_local_components() -> anyhow::Result<()> {
        let repository = fixture_repository("settings")?;
        let component_dir = repository.contracts_root().join("components/settings/v3");
        fs::create_dir_all(&component_dir)?;
        let component_path = component_dir.join("projection-row.schema.json");
        fs::write(
            &component_path,
            br#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "rss://component/settings/v3/projection-row",
  "title": "SettingsProjectionRow",
  "type": "object",
  "required": ["value"],
  "properties": {"value": {"type": "string"}},
  "additionalProperties": false
}"#,
        )?;
        fs::write(
            repository.contract_dir().join("projection.schema.json"),
            br#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "SettingsProjectionEnvelope",
  "type": "object",
  "required": ["row"],
  "properties": {
    "row": {"$ref": "rss://component/settings/v3/projection-row"}
  },
  "additionalProperties": false
}"#,
        )?;

        let contracts = load_contract_repository(&repository.contracts_root())?;
        let [contract] = contracts.as_slice() else {
            panic!("fixture must contain one contract");
        };
        let resolved = contract.resolved_schema("projection.schema.json")?;
        assert_eq!(
            resolved["properties"]["row"]["$ref"],
            "#/definitions/SettingsProjectionRow"
        );
        assert_eq!(
            resolved["definitions"]["SettingsProjectionRow"]["properties"]["value"]["type"],
            "string"
        );
        assert_eq!(
            resolved.component_ids(),
            &["rss://component/settings/v3/projection-row".to_string()]
        );
        assert!(contract.source_snapshot_digest().starts_with("sha256:"));
        let hash_before = schema_hash(contract)?;

        fs::write(
            &component_path,
            br#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "rss://component/settings/v3/projection-row",
  "title": "SettingsProjectionRow",
  "type": "object",
  "required": ["value"],
  "properties": {"value": {"type": "string", "minLength": 1}},
  "additionalProperties": false
}"#,
        )?;
        assert!(contract.verify_unchanged().is_err());
        let refreshed = load_contract_repository(&repository.contracts_root())?;
        let [refreshed] = refreshed.as_slice() else {
            panic!("fixture must contain one refreshed contract");
        };
        let hash_after = schema_hash(refreshed)?;
        assert_ne!(
            hash_before, hash_after,
            "component semantics must affect hash"
        );
        let deterministic = load_contract_repository(&repository.contracts_root())?;
        assert_eq!(hash_after, schema_hash(&deterministic[0])?);
        Ok(())
    }

    #[test]
    fn component_resolver_rejects_nonlocal_invalid_and_cyclic_references() {
        for reference in [
            "https://example.invalid/operator.schema.json",
            "file:///tmp/operator.schema.json",
            "../operator.schema.json",
            "rss://component/identity/v1/../operator",
        ] {
            let schema = serde_json::json!({"$ref": reference});
            assert!(resolve_component_references(schema, |_| unreachable!()).is_err());
        }

        let schema = serde_json::json!({"$ref": "rss://component/identity/v1/a"});
        let error = resolve_component_references(schema, |id| match id {
            "rss://component/identity/v1/a" => Ok(serde_json::json!({
                "$id": id,
                "title": "A",
                "$ref": "rss://component/identity/v1/b"
            })),
            "rss://component/identity/v1/b" => Ok(serde_json::json!({
                "$id": id,
                "title": "B",
                "$ref": "rss://component/identity/v1/a"
            })),
            _ => unreachable!(),
        })
        .expect_err("cycle must fail closed");
        assert!(error.to_string().contains("cycle"));

        let schema = serde_json::json!({
            "$ref": "rss://component/identity/v1/a",
            "definitions": {"A": {"title": "A", "type": "string"}}
        });
        let error = resolve_component_references(schema, |id| {
            Ok(serde_json::json!({"$id": id, "title": "A", "type": "string"}))
        })
        .expect_err("an identical author definition must not impersonate component provenance");
        assert!(
            error
                .to_string()
                .contains("collides with author definition")
        );
    }

    #[test]
    fn component_graph_owns_canonical_identity_and_transitive_referrers() -> anyhow::Result<()> {
        let target = ComponentId::parse("rss://component/identity/v1/target")?;
        let graph = ComponentGraph::from_documents([
            (
                "contracts/components/identity/v1/target.schema.json".to_owned(),
                serde_json::json!({"$id": target.as_str(), "title": "Target"}),
            ),
            (
                "contracts/components/identity/v1/referrer.schema.json".to_owned(),
                serde_json::json!({
                    "$id": "rss://component/identity/v1/referrer",
                    "$ref": target.as_str()
                }),
            ),
            (
                "contracts/http/identity/v1/use/request.schema.json".to_owned(),
                serde_json::json!({"$ref": "rss://component/identity/v1/referrer"}),
            ),
        ])?;
        assert_eq!(
            graph.transitive_consumer_paths(&target)?,
            BTreeSet::from(["contracts/http/identity/v1/use/request.schema.json".to_owned()])
        );

        let mismatch = ComponentGraph::from_documents([(
            "contracts/components/identity/v1/target.schema.json".to_owned(),
            serde_json::json!({"$id": "rss://component/identity/v1/other"}),
        )]);
        assert!(mismatch.is_err(), "path-derived identity must be exact");
        let missing = ComponentGraph::from_documents([(
            "contracts/http/identity/v1/use/request.schema.json".to_owned(),
            serde_json::json!({"$ref": target.as_str()}),
        )]);
        assert!(
            missing.is_err(),
            "component graph must reject missing targets"
        );
        Ok(())
    }

    #[test]
    fn component_repository_rejects_orphans_and_symlinks() -> anyhow::Result<()> {
        let repository = fixture_repository("settings")?;
        let component_dir = repository.contracts_root().join("components/settings/v3");
        fs::create_dir_all(&component_dir)?;
        fs::write(component_dir.join("orphan.schema.json"), b"{}")?;
        assert!(load_contract_repository(&repository.contracts_root()).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            fs::remove_file(component_dir.join("orphan.schema.json"))?;
            symlink(
                repository.contract_dir().join("projection.schema.json"),
                component_dir.join("linked.schema.json"),
            )?;
            let error = load_contract_repository(&repository.contracts_root())
                .expect_err("component symlink must fail closed");
            assert!(error.to_string().contains("symlink"));
        }
        Ok(())
    }

    #[test]
    fn common_abac_component_resolves_to_self_contained_definitions() -> anyhow::Result<()> {
        let contracts_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
        let contracts = load_contract_repository(&contracts_root)?;
        let contract = contracts
            .iter()
            .find(|contract| contract.manifest().id == "identity.policies-create")
            .context("identity policies-create contract")?;
        let schema = contract.resolved_schema("request.schema.json")?;
        assert_eq!(
            schema.pointer("/properties/rules/items/properties/condition/properties/operator/$ref"),
            Some(&serde_json::json!("#/definitions/IdentityPolicyOperator"))
        );
        for name in [
            "IdentityPolicyOperator",
            "IdentityPolicyOperatorEqualityFamily",
            "IdentityPolicyOperatorLiteralOperand",
        ] {
            assert!(
                schema.pointer(&format!("/definitions/{name}")).is_some(),
                "missing resolved definition {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn repository_snapshot_rejects_manifest_universe_additions() -> anyhow::Result<()> {
        let repository = fixture_repository("settings")?;
        let contracts_root = repository.contracts_root();
        let contracts = load_contract_repository(&contracts_root)?;
        verify_contract_repository_unchanged(&contracts_root, &contracts)?;

        let added = contracts_root.join("event/settings/v99/contract.toml");
        let Some(parent) = added.parent() else {
            panic!("added manifest must have a parent");
        };
        fs::create_dir_all(parent)?;
        fs::write(added, b"")?;
        let Err(error) = verify_contract_repository_unchanged(&contracts_root, &contracts) else {
            panic!("new contract manifest must invalidate repository snapshot");
        };
        assert!(error.to_string().contains("manifest universe differs"));
        Ok(())
    }

    #[test]
    fn missing_schema_remains_a_validation_fact_and_appearance_is_stale() -> anyhow::Result<()> {
        let repository = fixture_repository("settings")?;
        let missing = repository.contract_dir().join("projection.schema.json");
        fs::remove_file(&missing)?;

        let contracts = load_contract_repository(&repository.contracts_root())?;
        let [contract] = contracts.as_slice() else {
            panic!("fixture must contain one contract");
        };
        assert_eq!(
            contract.schema_path("projection.schema.json"),
            Some(missing.as_path())
        );
        assert_eq!(contract.schema_bytes("projection.schema.json"), None);
        assert!(schema_hash(contract).is_err());
        contract.verify_unchanged()?;

        fs::write(&missing, b"{}")?;
        assert!(contract.verify_unchanged().is_err());
        Ok(())
    }

    #[test]
    fn settings_projection_schema_covers_materialized_row_and_receipt_carriers()
    -> anyhow::Result<()> {
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/projection/settings/v3/projection.schema.json");
        let schema: serde_json::Value = serde_json::from_slice(&fs::read(schema_path)?)?;
        let properties = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .context("projection schema properties")?;

        for (carrier, expected_fields) in [
            (
                "materializedRow",
                [
                    "tenantId",
                    "projectionId",
                    "generation",
                    "configKey",
                    "configVersion",
                    "changeKind",
                    "sourceEventId",
                    "sourceLsn",
                    "sourceOccurredAtSecs",
                    "createdAt",
                    "updatedAt",
                ]
                .as_slice(),
            ),
            (
                "dedupeReceipt",
                [
                    "tenantId",
                    "projectionId",
                    "generation",
                    "sourceEventId",
                    "sourceLsn",
                    "factDigest",
                    "actor",
                    "purpose",
                    "appliedAt",
                ]
                .as_slice(),
            ),
        ] {
            let required = properties
                .get(carrier)
                .and_then(|value| value.get("required"))
                .and_then(serde_json::Value::as_array)
                .context("projection carrier required fields")?;
            let actual = required
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected_fields.iter().copied().collect());
        }

        let receipt = &properties["dedupeReceipt"];
        assert_eq!(
            receipt["properties"]["actor"]["enum"],
            serde_json::json!(["rss-projection-worker", "rss-projection-replay"])
        );
        assert_eq!(
            receipt["properties"]["purpose"]["enum"],
            serde_json::json!(["background-worker", "operator-replay"])
        );
        assert_eq!(
            receipt["oneOf"],
            serde_json::json!([
                {
                    "properties": {
                        "actor": {
                            "const": "rss-projection-worker",
                            "x-redaction": "internal"
                        },
                        "purpose": { "const": "background-worker" }
                    }
                },
                {
                    "properties": {
                        "actor": {
                            "const": "rss-projection-replay",
                            "x-redaction": "internal"
                        },
                        "purpose": { "const": "operator-replay" }
                    }
                }
            ])
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn source_snapshot_rejects_schema_symlink_substitution() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let repository = fixture_repository("settings")?;
        let contracts = load_contract_repository(&repository.contracts_root())?;
        let [contract] = contracts.as_slice() else {
            panic!("fixture must contain one contract");
        };
        let projection = repository.contract_dir().join("projection.schema.json");
        fs::remove_file(&projection)?;
        symlink("contract.toml", &projection)?;
        assert!(contract.verify_unchanged().is_err());
        assert!(load_contract_repository(&repository.contracts_root()).is_err());
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn test_support_builder_is_explicitly_synthetic_and_immutable() -> anyhow::Result<()> {
        let repository = fixture_repository("settings")?;
        let mut manifest = ContractManifest::from_toml_str(&fs::read_to_string(
            repository.contract_dir().join("contract.toml"),
        )?)?;
        manifest.test_set_domain_owner("identity");
        let contract = RepositoryContractTestBuilder::new(manifest, repository.contract_dir())
            .path_kind("event")
            .path_domain("identity")
            .path_version("v9")
            .slug(Some("fixture"))
            .build()?;

        assert_eq!(contract.owner().as_str(), "identity");
        assert_eq!(contract.path_kind(), "event");
        assert_eq!(contract.path_domain(), "identity");
        assert_eq!(contract.path_version(), "v9");
        assert_eq!(contract.slug(), Some("fixture"));
        assert!(contract.schema_bytes("projection.schema.json").is_some());
        let Err(error) = contract.verify_unchanged() else {
            panic!("synthetic contract must not acquire repository provenance");
        };
        assert!(error.to_string().contains("no repository provenance"));

        let mut manifest = contract.manifest().clone();
        manifest.test_set_framework_owner();
        let framework =
            RepositoryContractTestBuilder::new(manifest, PathBuf::from("/missing")).build()?;
        assert!(framework.owner().is_framework_owned());
        Ok(())
    }
}
