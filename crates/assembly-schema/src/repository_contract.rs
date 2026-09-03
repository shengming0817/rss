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

/// One declared schema promoted from a captured raw document and its resolved semantic view.
#[derive(Debug, Clone, Copy)]
pub struct DeclaredSchema<'a> {
    file: &'a str,
    bytes: &'a [u8],
    source_digest: &'a str,
    raw: &'a Value,
    resolved: &'a ResolvedSchema,
}

impl<'a> DeclaredSchema<'a> {
    pub const fn file(self) -> &'a str {
        self.file
    }

    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub const fn source_digest(self) -> &'a str {
        self.source_digest
    }

    pub const fn resolved(self) -> &'a ResolvedSchema {
        self.resolved
    }

    /// Captured authored JSON value from the repository's parse-once source funnel.
    pub const fn authored(self) -> &'a Value {
        self.raw
    }

    pub fn property_references(self, property: &str) -> Vec<Option<String>> {
        let mut references = Vec::new();
        collect_property_references(self.raw, property, &mut references);
        references
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaSourceIssueKind {
    Missing,
    UnsafeName,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaJsonErrorCategory {
    Io,
    Syntax,
    Data,
    Eof,
}

impl SchemaJsonErrorCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Syntax => "syntax",
            Self::Data => "data",
            Self::Eof => "eof",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaSourceIssue {
    kind: SchemaSourceIssueKind,
    file: String,
    path: PathBuf,
    line: usize,
    column: usize,
    category: Option<SchemaJsonErrorCategory>,
    message: String,
}

impl SchemaSourceIssue {
    pub const fn kind(&self) -> SchemaSourceIssueKind {
        self.kind
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn line(&self) -> usize {
        self.line
    }

    pub const fn column(&self) -> usize {
        self.column
    }

    pub const fn category(&self) -> Option<SchemaJsonErrorCategory> {
        self.category
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSourceFileSnapshot {
    source: SourceFileSnapshot,
    outcome: SchemaParseOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemaParseOutcome {
    Parsed(Arc<Value>),
    Malformed(SchemaSourceIssue),
}

impl ParsedSourceFileSnapshot {
    fn value(&self) -> Option<&Arc<Value>> {
        match &self.outcome {
            SchemaParseOutcome::Parsed(value) => Some(value),
            SchemaParseOutcome::Malformed(_) => None,
        }
    }

    fn issue(&self) -> Option<&SchemaSourceIssue> {
        match &self.outcome {
            SchemaParseOutcome::Parsed(_) => None,
            SchemaParseOutcome::Malformed(issue) => Some(issue),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemaSourceSnapshot {
    Present(ParsedSourceFileSnapshot),
    Missing { path: PathBuf },
    UnsafeName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComponentSourceSnapshot {
    Present(ParsedSourceFileSnapshot),
    Missing { path: PathBuf },
}

impl ComponentSourceSnapshot {
    fn parsed(&self) -> Option<&ParsedSourceFileSnapshot> {
        match self {
            Self::Present(source) => Some(source),
            Self::Missing { .. } => None,
        }
    }
}

impl SchemaSourceSnapshot {
    fn digest(&self) -> Option<&str> {
        match self {
            Self::Present(source) => Some(&source.source.digest),
            Self::Missing { .. } | Self::UnsafeName => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ContractSourceSnapshot {
    contracts_root: PathBuf,
    manifest: SourceFileSnapshot,
    schemas: BTreeMap<String, SchemaSourceSnapshot>,
    components: BTreeMap<String, ComponentSourceSnapshot>,
    resolved_schemas: BTreeMap<String, ResolvedSchema>,
    schema_hash: String,
    digest: String,
    repository_backed: bool,
    #[cfg(feature = "test-support")]
    fixture_owner: Option<Arc<FixtureRepositoryOwner>>,
}

#[cfg(feature = "test-support")]
#[derive(Debug, PartialEq, Eq)]
struct FixtureRepositoryOwner {
    root: PathBuf,
}

#[cfg(feature = "test-support")]
impl Drop for FixtureRepositoryOwner {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
struct InspectedRepositoryContract {
    dir: PathBuf,
    path_kind: String,
    path_domain: String,
    path_version: String,
    slug: Option<String>,
    owner: ContractOwner,
    manifest: ContractManifest,
    source: Arc<ContractSourceSnapshot>,
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

    /// SHA-256 of exact captured schema bytes, if the declared schema existed.
    pub fn schema_source_digest(&self, file: &str) -> Option<&str> {
        self.source
            .schemas
            .get(file)
            .and_then(SchemaSourceSnapshot::digest)
    }

    /// Self-contained schema promoted from the immutable parse-once source snapshot.
    pub fn schema(&self, file: &str) -> Option<&ResolvedSchema> {
        self.source.resolved_schemas.get(file)
    }

    /// Exact declared schema set. Every item has both captured raw semantics and a resolved view.
    pub fn declared_schemas(&self) -> impl Iterator<Item = DeclaredSchema<'_>> {
        self.source
            .schemas
            .iter()
            .filter_map(|(file, source)| self.declared_schema_parts(file.as_str(), source))
    }

    /// Typed lookup into the promoted declared schema set.
    pub fn declared_schema(&self, file: &str) -> Option<DeclaredSchema<'_>> {
        let (file, source) = self.source.schemas.get_key_value(file)?;
        self.declared_schema_parts(file.as_str(), source)
    }

    fn declared_schema_parts<'a>(
        &'a self,
        file: &'a str,
        source: &'a SchemaSourceSnapshot,
    ) -> Option<DeclaredSchema<'a>> {
        let SchemaSourceSnapshot::Present(source) = source else {
            return None;
        };
        let raw = source.value().map(Arc::as_ref)?;
        let resolved = self.source.resolved_schemas.get(file)?;
        Some(DeclaredSchema {
            file,
            bytes: &source.source.bytes,
            source_digest: &source.source.digest,
            raw,
            resolved,
        })
    }

    pub fn schema_hash(&self) -> &str {
        &self.source.schema_hash
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
        verify_source_snapshot(&self.source)
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

/// Feature-gated fixture writer that still enters through canonical inspection and promotion.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub struct RepositoryContractTestBuilder {
    manifest: ContractManifest,
    dir: PathBuf,
    path_kind: String,
    path_domain: String,
    path_version: String,
    slug: Option<String>,
    schemas: BTreeMap<String, Value>,
    components: BTreeMap<String, Value>,
}

#[cfg(feature = "test-support")]
static TEST_REPOSITORY_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

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
            schemas: BTreeMap::new(),
            components: BTreeMap::new(),
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

    pub fn schema(mut self, file: impl Into<String>, value: Value) -> Self {
        self.schemas.insert(file.into(), value);
        self
    }

    pub fn component(mut self, id: impl Into<String>, value: Value) -> Self {
        self.components.insert(id.into(), value);
        self
    }

    pub fn build(self) -> Result<RepositoryContract, RepositoryContractError> {
        use std::sync::atomic::Ordering;

        let contracts_root = std::env::temp_dir().join(format!(
            "rss-contract-fixture-{}-{}",
            std::process::id(),
            TEST_REPOSITORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let fixture_owner = Arc::new(FixtureRepositoryOwner {
            root: contracts_root.clone(),
        });
        let mut contract_dir = contracts_root
            .join(&self.path_kind)
            .join(&self.path_domain)
            .join(&self.path_version);
        if let Some(slug) = &self.slug {
            contract_dir.push(slug);
        }
        std::fs::create_dir_all(&contract_dir).map_err(|source| {
            RepositoryContractError::io(
                format!("failed to create fixture {}", contract_dir.display()),
                source,
            )
        })?;
        let mut manifest_for_toml = self.manifest.clone();
        let responses = std::mem::take(&mut manifest_for_toml.schemas.responses);
        let mut manifest_source = toml::to_string(&manifest_for_toml).map_err(|source| {
            RepositoryContractError::Invalid(format!("serialize fixture contract.toml: {source}"))
        })?;
        if !responses.is_empty() {
            let mut response_entries = String::new();
            for (status, file) in responses {
                response_entries.push_str(&format!("\"{}\" = {file:?}\n", status.get()));
            }
            manifest_source = manifest_source.replacen(
                "[schemas.responses]\n",
                &format!("[schemas.responses]\n{response_entries}"),
                1,
            );
        }
        std::fs::write(contract_dir.join("contract.toml"), manifest_source).map_err(|source| {
            RepositoryContractError::io("failed to write fixture contract.toml", source)
        })?;
        for file in self.manifest.declared_schema_files() {
            if validate_schema_filename(file).is_err() {
                continue;
            }
            let target = contract_dir.join(file);
            if let Some(value) = self.schemas.get(file) {
                let bytes = serde_json::to_vec(value).map_err(|source| {
                    RepositoryContractError::Invalid(format!(
                        "serialize fixture schema {file}: {source}"
                    ))
                })?;
                std::fs::write(&target, bytes).map_err(|source| {
                    RepositoryContractError::io(
                        format!("failed to write fixture schema {}", target.display()),
                        source,
                    )
                })?;
            } else {
                let source_path = self.dir.join(file);
                if source_path.is_file() {
                    std::fs::copy(&source_path, &target).map_err(|source| {
                        RepositoryContractError::io(
                            format!("failed to copy fixture schema {}", source_path.display()),
                            source,
                        )
                    })?;
                }
            }
        }
        for (id, value) in self.components {
            let path = contracts_root.join(component_relative_path(&id)?);
            let parent = path.parent().ok_or_else(|| {
                RepositoryContractError::Invalid(format!(
                    "fixture component has no parent: {}",
                    path.display()
                ))
            })?;
            std::fs::create_dir_all(parent).map_err(|source| {
                RepositoryContractError::io(
                    format!(
                        "failed to create fixture component parent {}",
                        parent.display()
                    ),
                    source,
                )
            })?;
            let bytes = serde_json::to_vec(&value).map_err(|source| {
                RepositoryContractError::Invalid(format!(
                    "serialize fixture component {id}: {source}"
                ))
            })?;
            std::fs::write(&path, bytes).map_err(|source| {
                RepositoryContractError::io(
                    format!("failed to write fixture component {}", path.display()),
                    source,
                )
            })?;
        }
        let mut contracts = inspect_contract_repository(&contracts_root)?.promote()?;
        if contracts.len() != 1 {
            return Err(RepositoryContractError::Invalid(format!(
                "fixture promotion expected one contract, got {}",
                contracts.len()
            )));
        }
        let Some(mut contract) = contracts.pop() else {
            unreachable!("fixture length checked above")
        };
        Arc::make_mut(&mut contract.source).fixture_owner = Some(fixture_owner);
        Ok(contract)
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

/// Immutable repository discovery result. Invalid schema sources remain inspectable but cannot be
/// promoted into the typed contract repository consumed by validation, codegen or AssemblyLock.
pub struct ContractRepositoryInspection {
    contracts_root: PathBuf,
    contracts: Vec<InspectedRepositoryContract>,
    issues: Vec<SchemaSourceIssue>,
    snapshot_component_files: Option<BTreeSet<PathBuf>>,
}

#[derive(Default)]
struct SchemaSourceParser {
    cache: BTreeMap<PathBuf, ParsedSourceFileSnapshot>,
}

impl SchemaSourceParser {
    fn parse(
        &mut self,
        contracts_root: &Path,
        path: &Path,
        file: &str,
    ) -> Result<ParsedSourceFileSnapshot, RepositoryContractError> {
        if let Some(source) = self.cache.get(path) {
            return Ok(source.clone());
        }
        let captured = read_source_file(contracts_root, path)?;
        self.parse_captured(contracts_root, path, file, captured)
    }

    fn parse_captured(
        &mut self,
        contracts_root: &Path,
        path: &Path,
        file: &str,
        captured: SourceFileSnapshot,
    ) -> Result<ParsedSourceFileSnapshot, RepositoryContractError> {
        if let Some(source) = self.cache.get(path) {
            return Ok(source.clone());
        }
        let source = parse_source_file(
            file,
            repository_relative_path(contracts_root, path)?,
            captured,
        );
        self.cache.insert(path.to_path_buf(), source.clone());
        Ok(source)
    }
}

impl ContractRepositoryInspection {
    pub fn len(&self) -> usize {
        self.contracts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contracts.is_empty()
    }

    pub fn issues(&self) -> &[SchemaSourceIssue] {
        &self.issues
    }

    pub fn promote(self) -> Result<Vec<RepositoryContract>, RepositoryContractError> {
        if !self.issues.is_empty() {
            let details = self
                .issues
                .iter()
                .map(render_schema_source_issue)
                .collect::<Vec<_>>()
                .join("\n- ");
            return Err(RepositoryContractError::Invalid(format!(
                "contract repository contains {} invalid schema source(s):\n- {details}",
                self.issues.len(),
            )));
        }
        let contracts = self
            .contracts
            .into_iter()
            .map(promote_inspected_contract)
            .collect::<Result<Vec<_>, _>>()?;
        match self.snapshot_component_files {
            Some(actual) => verify_component_universe_exact(&actual, contracts.iter())?,
            None => verify_component_universe(&self.contracts_root, contracts.iter())?,
        }
        Ok(contracts)
    }
}

fn render_schema_source_issue(issue: &SchemaSourceIssue) -> String {
    let category = issue
        .category
        .map_or("none", SchemaJsonErrorCategory::as_str);
    format!(
        "{} file={} kind={:?} category={category} line={} column={}: {}",
        issue.path.display(),
        issue.file,
        issue.kind,
        issue.line,
        issue.column,
        issue.message
    )
}

/// Recursively discover every real `contract.toml` and parse each physical JSON source once.
pub fn inspect_contract_repository(
    contracts_root: &Path,
) -> Result<ContractRepositoryInspection, RepositoryContractError> {
    let mut toml_paths = Vec::new();
    collect_contract_tomls(contracts_root, &mut toml_paths)?;
    toml_paths.sort();
    let mut parser = SchemaSourceParser::default();
    let contracts = toml_paths
        .into_iter()
        .map(|path| load_contract(contracts_root, &path, &mut parser))
        .collect::<Result<Vec<_>, _>>()?;
    let mut issues = Vec::new();
    for contract in &contracts {
        issues.extend(contract_source_issues(contract)?);
    }
    issues.sort_by(|left, right| left.path.cmp(&right.path));
    issues.dedup_by(|left, right| left.path == right.path && left.file == right.file);
    Ok(ContractRepositoryInspection {
        contracts_root: contracts_root.to_path_buf(),
        contracts,
        issues,
        snapshot_component_files: None,
    })
}

fn contract_source_issues(
    contract: &InspectedRepositoryContract,
) -> Result<Vec<SchemaSourceIssue>, RepositoryContractError> {
    let mut issues = Vec::new();
    for (file, schema) in &contract.source.schemas {
        match schema {
            SchemaSourceSnapshot::Present(source) => {
                if let Some(issue) = source.issue() {
                    issues.push(issue.clone());
                }
            }
            SchemaSourceSnapshot::Missing { path } => issues.push(SchemaSourceIssue {
                kind: SchemaSourceIssueKind::Missing,
                file: file.clone(),
                path: repository_relative_path(&contract.source.contracts_root, path)?,
                line: 0,
                column: 0,
                category: None,
                message: "declared schema is missing".to_owned(),
            }),
            SchemaSourceSnapshot::UnsafeName => issues.push(SchemaSourceIssue {
                kind: SchemaSourceIssueKind::UnsafeName,
                file: file.clone(),
                // Bind an unsafe declaration to its owning contract without resolving or
                // touching the attacker-controlled path. This also prevents cross-contract
                // deduplication of identical unsafe strings.
                path: repository_relative_path(&contract.source.contracts_root, &contract.dir)?,
                line: 0,
                column: 0,
                category: None,
                message: "schema filename is not a safe single path segment".to_owned(),
            }),
        }
    }
    for (id, component) in &contract.source.components {
        match component {
            ComponentSourceSnapshot::Present(source) => {
                if let Some(issue) = source.issue() {
                    issues.push(issue.clone());
                }
            }
            ComponentSourceSnapshot::Missing { path } => issues.push(SchemaSourceIssue {
                kind: SchemaSourceIssueKind::Missing,
                file: id.clone(),
                path: repository_relative_path(&contract.source.contracts_root, path)?,
                line: 0,
                column: 0,
                category: None,
                message: "referenced schema component is missing".to_owned(),
            }),
        }
    }
    Ok(issues)
}

fn promote_inspected_contract(
    contract: InspectedRepositoryContract,
) -> Result<RepositoryContract, RepositoryContractError> {
    let complete_schemas = contract.source.schemas.iter().all(|(file, source)| {
        matches!(source, SchemaSourceSnapshot::Present(source) if source.value().is_some())
            && contract.source.resolved_schemas.contains_key(file)
    });
    let complete_components = contract
        .source
        .components
        .values()
        .all(|source| {
            matches!(source, ComponentSourceSnapshot::Present(source) if source.value().is_some())
        });
    if !complete_schemas
        || !complete_components
        || contract.source.resolved_schemas.len() != contract.source.schemas.len()
        || contract.source.schema_hash.is_empty()
    {
        return Err(RepositoryContractError::Invalid(
            "incomplete schema inspection cannot promote RepositoryContract".to_owned(),
        ));
    }
    Ok(RepositoryContract {
        dir: contract.dir,
        path_kind: contract.path_kind,
        path_domain: contract.path_domain,
        path_version: contract.path_version,
        slug: contract.slug,
        owner: contract.owner,
        manifest: contract.manifest,
        source: contract.source,
    })
}

/// Exact UTF-8 source owned by the governed contract repository snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositoryContractSourceFile {
    pub(crate) path: String,
    pub(crate) content: String,
}

/// Capture precisely the contract sources consumed by repository verification.
pub(crate) fn capture_contract_repository_sources(
    repository_root: &Path,
    contracts: &[RepositoryContract],
) -> Result<Vec<RepositoryContractSourceFile>, RepositoryContractError> {
    let mut files = BTreeMap::<String, String>::new();
    for contract in contracts {
        insert_repository_contract_source(repository_root, &mut files, &contract.source.manifest)?;
        for schema in contract.source.schemas.values() {
            let SchemaSourceSnapshot::Present(source) = schema else {
                return Err(RepositoryContractError::Invalid(
                    "promoted repository contains an invalid schema source".to_owned(),
                ));
            };
            insert_repository_contract_source(repository_root, &mut files, &source.source)?;
        }
        for component in contract.source.components.values() {
            let ComponentSourceSnapshot::Present(source) = component else {
                return Err(RepositoryContractError::Invalid(
                    "promoted repository contains a missing component source".to_owned(),
                ));
            };
            insert_repository_contract_source(repository_root, &mut files, &source.source)?;
        }
    }
    Ok(files
        .into_iter()
        .map(|(path, content)| RepositoryContractSourceFile { path, content })
        .collect())
}

fn insert_repository_contract_source(
    repository_root: &Path,
    files: &mut BTreeMap<String, String>,
    source: &SourceFileSnapshot,
) -> Result<(), RepositoryContractError> {
    let path = source.path.strip_prefix(repository_root).map_err(|_| {
        RepositoryContractError::Invalid(format!(
            "contract snapshot path escapes repository root: {}",
            source.path.display()
        ))
    })?;
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RepositoryContractError::Invalid(format!(
            "contract snapshot path is not normalized: {}",
            path.display()
        )));
    }
    let label = path
        .to_str()
        .ok_or_else(|| {
            RepositoryContractError::Invalid(format!(
                "contract snapshot path is not UTF-8: {}",
                path.display()
            ))
        })?
        .replace('\\', "/");
    let content = std::str::from_utf8(&source.bytes).map_err(|error| {
        RepositoryContractError::io(
            format!("failed to decode {} as UTF-8", source.path.display()),
            std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        )
    })?;
    match files.insert(label.clone(), content.to_owned()) {
        Some(previous) if previous != content => Err(RepositoryContractError::Invalid(format!(
            "contract snapshot path has conflicting content: {label}"
        ))),
        _ => Ok(()),
    }
}

/// Inspect an immutable repository-relative source universe through the same typed funnel.
pub(crate) fn inspect_contract_repository_snapshot(
    files: &[RepositoryContractSourceFile],
) -> Result<ContractRepositoryInspection, RepositoryContractError> {
    let contracts_root = Path::new("contracts");
    let mut sources = BTreeMap::<PathBuf, Arc<[u8]>>::new();
    for file in files {
        let path = PathBuf::from(&file.path);
        if !path.starts_with(contracts_root)
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(RepositoryContractError::Invalid(format!(
                "contract snapshot path must be normalized below contracts/: {:?}",
                file.path
            )));
        }
        if sources
            .insert(path, Arc::from(file.content.as_bytes()))
            .is_some()
        {
            return Err(RepositoryContractError::Invalid(format!(
                "duplicate contract snapshot path: {:?}",
                file.path
            )));
        }
    }

    let mut manifests = sources
        .keys()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("contract.toml"))
        .cloned()
        .collect::<Vec<_>>();
    manifests.sort();
    if manifests.is_empty() {
        return Err(RepositoryContractError::Invalid(
            "contract snapshot manifest universe is empty".to_owned(),
        ));
    }
    let mut consumed = BTreeSet::new();
    let mut parser = SchemaSourceParser::default();
    let contracts = manifests
        .into_iter()
        .map(|path| {
            load_contract_snapshot(contracts_root, &path, &sources, &mut consumed, &mut parser)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let actual = sources.keys().cloned().collect::<BTreeSet<_>>();
    if consumed != actual {
        return Err(RepositoryContractError::Invalid(format!(
            "contract snapshot universe differs: consumed={consumed:?} actual={actual:?}"
        )));
    }
    let mut issues = Vec::new();
    for contract in &contracts {
        issues.extend(contract_source_issues(contract)?);
    }
    issues.sort_by(|left, right| left.path.cmp(&right.path));
    issues.dedup_by(|left, right| left.path == right.path && left.file == right.file);
    Ok(ContractRepositoryInspection {
        contracts_root: contracts_root.to_path_buf(),
        contracts,
        issues,
        snapshot_component_files: Some(
            actual
                .into_iter()
                .filter(|path| path.starts_with(contracts_root.join("components")))
                .collect(),
        ),
    })
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
    verify_component_universe_exact(&actual, contracts)
}

fn verify_component_universe_exact<'a>(
    actual: &BTreeSet<PathBuf>,
    contracts: impl IntoIterator<Item = &'a RepositoryContract>,
) -> Result<(), RepositoryContractError> {
    let expected = contracts
        .into_iter()
        .flat_map(|contract| contract.source.components.values())
        .filter_map(ComponentSourceSnapshot::parsed)
        .map(|source| source.source.path.clone())
        .collect::<BTreeSet<_>>();
    if *actual != expected {
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
        match contract.schema_hash() {
            digest if digest != activation.definition_schema_digest() => errors.push(format!(
                "activation id=`{}` field=definitionSchemaDigest actual=`{}` expected=`{digest}`",
                activation.id(),
                activation.definition_schema_digest()
            )),
            _ => {}
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
    parser: &mut SchemaSourceParser,
) -> Result<InspectedRepositoryContract, RepositoryContractError> {
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
    let schemas = capture_schema_sources(contracts_root, dir, &manifest, parser)?;
    let components = capture_component_sources(contracts_root, &schemas, parser)?;
    let digest = source_snapshot_digest(&manifest_source, &schemas, &components);
    let (resolved_schemas, schema_hash) =
        finalize_schema_sources(&manifest, &schemas, &components)?;
    let source = Arc::new(ContractSourceSnapshot {
        contracts_root: contracts_root.to_path_buf(),
        manifest: manifest_source,
        schemas,
        components,
        resolved_schemas,
        schema_hash,
        digest,
        repository_backed: true,
        #[cfg(feature = "test-support")]
        fixture_owner: None,
    });
    verify_source_snapshot(source.as_ref())?;
    Ok(InspectedRepositoryContract {
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

fn load_contract_snapshot(
    contracts_root: &Path,
    manifest_path: &Path,
    files: &BTreeMap<PathBuf, Arc<[u8]>>,
    consumed: &mut BTreeSet<PathBuf>,
    parser: &mut SchemaSourceParser,
) -> Result<InspectedRepositoryContract, RepositoryContractError> {
    let dir = manifest_path.parent().ok_or_else(|| {
        RepositoryContractError::Invalid(format!(
            "contract.toml has no parent: {}",
            manifest_path.display()
        ))
    })?;
    let manifest_bytes = files.get(manifest_path).ok_or_else(|| {
        RepositoryContractError::Invalid(format!(
            "contract snapshot omits {}",
            manifest_path.display()
        ))
    })?;
    consumed.insert(manifest_path.to_path_buf());
    let manifest_source = snapshot_source_file(manifest_path.to_path_buf(), manifest_bytes.clone());
    let text = std::str::from_utf8(manifest_bytes).map_err(|source| {
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
    let mut schemas = BTreeMap::new();
    for file in manifest.declared_schema_files() {
        if schemas.contains_key(file) {
            continue;
        }
        let source = if validate_schema_filename(file).is_err() {
            SchemaSourceSnapshot::UnsafeName
        } else {
            let path = dir.join(file);
            match files.get(&path) {
                Some(bytes) => {
                    consumed.insert(path.clone());
                    SchemaSourceSnapshot::Present(parser.parse_captured(
                        contracts_root,
                        &path,
                        file,
                        snapshot_source_file(path.clone(), bytes.clone()),
                    )?)
                }
                None => SchemaSourceSnapshot::Missing { path },
            }
        };
        schemas.insert(file.to_owned(), source);
    }
    let components =
        capture_component_snapshot_sources(contracts_root, &schemas, files, consumed, parser)?;
    let digest = source_snapshot_digest(&manifest_source, &schemas, &components);
    let (resolved_schemas, schema_hash) =
        finalize_schema_sources(&manifest, &schemas, &components)?;
    let source = Arc::new(ContractSourceSnapshot {
        contracts_root: contracts_root.to_path_buf(),
        manifest: manifest_source,
        schemas,
        components,
        resolved_schemas,
        schema_hash,
        digest,
        repository_backed: false,
        #[cfg(feature = "test-support")]
        fixture_owner: None,
    });
    Ok(InspectedRepositoryContract {
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

fn capture_component_snapshot_sources(
    contracts_root: &Path,
    schemas: &BTreeMap<String, SchemaSourceSnapshot>,
    files: &BTreeMap<PathBuf, Arc<[u8]>>,
    consumed: &mut BTreeSet<PathBuf>,
    parser: &mut SchemaSourceParser,
) -> Result<BTreeMap<String, ComponentSourceSnapshot>, RepositoryContractError> {
    let mut pending = BTreeSet::new();
    for schema in schemas.values() {
        let SchemaSourceSnapshot::Present(source) = schema else {
            continue;
        };
        if let Some(value) = source.value() {
            collect_component_refs(value, &mut pending)?;
        }
    }
    let mut captured = BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if captured.contains_key(id.as_str()) {
            continue;
        }
        let path = contracts_root.join(id.relative_path()?);
        let Some(bytes) = files.get(&path) else {
            captured.insert(id.to_string(), ComponentSourceSnapshot::Missing { path });
            continue;
        };
        consumed.insert(path.clone());
        let source = parser.parse_captured(
            contracts_root,
            &path,
            id.as_str(),
            snapshot_source_file(path.clone(), bytes.clone()),
        )?;
        let Some(value) = source.value() else {
            captured.insert(id.to_string(), ComponentSourceSnapshot::Present(source));
            continue;
        };
        if value.get("$id").and_then(Value::as_str) != Some(id.as_str()) {
            return Err(RepositoryContractError::Invalid(format!(
                "component {} must declare exact $id {id:?}",
                path.display()
            )));
        }
        collect_component_refs(value, &mut pending)?;
        captured.insert(id.to_string(), ComponentSourceSnapshot::Present(source));
    }
    Ok(captured)
}

fn capture_schema_sources(
    contracts_root: &Path,
    dir: &Path,
    manifest: &ContractManifest,
    parser: &mut SchemaSourceParser,
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
                Ok(_) => {
                    SchemaSourceSnapshot::Present(parser.parse(contracts_root, &path, file)?)
                }
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
    parser: &mut SchemaSourceParser,
) -> Result<BTreeMap<String, ComponentSourceSnapshot>, RepositoryContractError> {
    let mut pending = BTreeSet::new();
    for schema in schemas.values() {
        let SchemaSourceSnapshot::Present(source) = schema else {
            continue;
        };
        if let Some(value) = source.value() {
            collect_component_refs(value, &mut pending)?;
        }
    }

    let mut captured = BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if captured.contains_key(id.as_str()) {
            continue;
        }
        let path = contracts_root.join(id.relative_path()?);
        let source = match std::fs::symlink_metadata(&path) {
            Ok(_) => parser.parse(contracts_root, &path, id.as_str())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure_safe_source_parent(contracts_root, &path)?;
                captured.insert(id.to_string(), ComponentSourceSnapshot::Missing { path });
                continue;
            }
            Err(source) => {
                return Err(RepositoryContractError::io(
                    format!("failed to inspect component {}", path.display()),
                    source,
                ));
            }
        };
        let Some(value) = source.value() else {
            captured.insert(id.to_string(), ComponentSourceSnapshot::Present(source));
            continue;
        };
        if value.get("$id").and_then(Value::as_str) != Some(id.as_str()) {
            return Err(RepositoryContractError::Invalid(format!(
                "component {} must declare exact $id {id:?}",
                path.display()
            )));
        }
        collect_component_refs(value, &mut pending)?;
        captured.insert(id.to_string(), ComponentSourceSnapshot::Present(source));
    }
    Ok(captured)
}

fn repository_relative_path(
    contracts_root: &Path,
    path: &Path,
) -> Result<PathBuf, RepositoryContractError> {
    path.strip_prefix(contracts_root)
        .map(Path::to_path_buf)
        .map_err(|_| {
            RepositoryContractError::Invalid(format!(
                "contract source escapes contracts root: {}",
                path.display()
            ))
        })
}

fn parse_source_file(
    file: &str,
    relative_path: PathBuf,
    source: SourceFileSnapshot,
) -> ParsedSourceFileSnapshot {
    match serde_json::from_slice::<Value>(&source.bytes) {
        Ok(value) => ParsedSourceFileSnapshot {
            source,
            outcome: SchemaParseOutcome::Parsed(Arc::new(value)),
        },
        Err(error) => ParsedSourceFileSnapshot {
            outcome: SchemaParseOutcome::Malformed(SchemaSourceIssue {
                kind: SchemaSourceIssueKind::Malformed,
                file: file.to_owned(),
                path: relative_path,
                line: error.line(),
                column: error.column(),
                category: Some(match error.classify() {
                    serde_json::error::Category::Io => SchemaJsonErrorCategory::Io,
                    serde_json::error::Category::Syntax => SchemaJsonErrorCategory::Syntax,
                    serde_json::error::Category::Data => SchemaJsonErrorCategory::Data,
                    serde_json::error::Category::Eof => SchemaJsonErrorCategory::Eof,
                }),
                message: error.to_string(),
            }),
            source,
        },
    }
}

fn finalize_schema_sources(
    manifest: &ContractManifest,
    schemas: &BTreeMap<String, SchemaSourceSnapshot>,
    components: &BTreeMap<String, ComponentSourceSnapshot>,
) -> Result<(BTreeMap<String, ResolvedSchema>, String), RepositoryContractError> {
    let incomplete = schemas.values().any(|schema| match schema {
        SchemaSourceSnapshot::Present(source) => source.value().is_none(),
        SchemaSourceSnapshot::Missing { .. } | SchemaSourceSnapshot::UnsafeName => true,
    }) || components.values().any(|component| match component {
        ComponentSourceSnapshot::Present(source) => source.value().is_none(),
        ComponentSourceSnapshot::Missing { .. } => true,
    });
    if incomplete {
        return Ok((BTreeMap::new(), String::new()));
    }
    let resolved = resolve_schema_sources(schemas, components)?;
    let hash = schema_hash_from_resolved(manifest, &resolved)?;
    Ok((resolved, hash))
}

fn resolve_schema_sources(
    schemas: &BTreeMap<String, SchemaSourceSnapshot>,
    components: &BTreeMap<String, ComponentSourceSnapshot>,
) -> Result<BTreeMap<String, ResolvedSchema>, RepositoryContractError> {
    schemas
        .iter()
        .map(|(file, source)| {
            let SchemaSourceSnapshot::Present(source) = source else {
                return Err(RepositoryContractError::Invalid(
                    "invalid schema source reached typed promotion".to_owned(),
                ));
            };
            let value = source.value().ok_or_else(|| {
                RepositoryContractError::Invalid(
                    "malformed schema source reached typed promotion".to_owned(),
                )
            })?;
            let resolved = resolve_component_references((**value).clone(), |id| {
                let component = components
                    .get(id)
                    .and_then(ComponentSourceSnapshot::parsed)
                    .ok_or_else(|| {
                        RepositoryContractError::Invalid(format!(
                            "schema {} references uncaptured component {id:?}",
                            source.source.path.display()
                        ))
                    })?;
                component
                    .value()
                    .map(|value| (**value).clone())
                    .ok_or_else(|| {
                        RepositoryContractError::Invalid(format!(
                            "malformed component reached typed promotion: {}",
                            component.source.path.display()
                        ))
                    })
            })?;
            Ok((file.clone(), resolved))
        })
        .collect()
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

fn snapshot_source_file(path: PathBuf, bytes: Arc<[u8]>) -> SourceFileSnapshot {
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
                verify_file_snapshot(&snapshot.contracts_root, &source.source)?;
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
        match component {
            ComponentSourceSnapshot::Present(component) => {
                verify_file_snapshot(&snapshot.contracts_root, &component.source)?;
            }
            ComponentSourceSnapshot::Missing { path } => {
                ensure_safe_source_parent(&snapshot.contracts_root, path)?;
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => {
                        return Err(RepositoryContractError::stale(
                            path,
                            "referenced component appeared while snapshotting",
                        ));
                    }
                    Err(source) => {
                        return Err(RepositoryContractError::io(
                            format!("failed to re-inspect missing component {}", path.display()),
                            source,
                        ));
                    }
                }
            }
        }
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
    components: &BTreeMap<String, ComponentSourceSnapshot>,
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
                hash_snapshot_component(&mut hasher, &source.source.bytes);
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
        match component {
            ComponentSourceSnapshot::Present(component) => {
                hash_snapshot_component(&mut hasher, b"present");
                hash_snapshot_component(&mut hasher, &component.source.bytes);
            }
            ComponentSourceSnapshot::Missing { .. } => {
                hash_snapshot_component(&mut hasher, b"missing");
            }
        }
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

fn schema_hash_from_resolved(
    manifest: &ContractManifest,
    schemas: &BTreeMap<String, ResolvedSchema>,
) -> Result<String, RepositoryContractError> {
    let mut ordered = Vec::new();
    for file in manifest.declared_schema_files() {
        validate_schema_filename(file)?;
        let value = schemas.get(file).ok_or_else(|| {
            RepositoryContractError::Invalid(format!(
                "promoted repository is missing declared schema {file:?}"
            ))
        })?;
        ordered.push((file, value.value()));
    }
    resolved_schema_hash(ordered)
}

/// Hash an already-resolved ordered schema set with the canonical contract binding protocol.
///
/// Git-ref consumers use this seam after resolving component references from immutable base
/// bytes, so breaking detection and working-tree codegen cannot drift into parallel hash logic.
pub fn resolved_schema_hash<'a>(
    schemas: impl IntoIterator<Item = (&'a str, &'a Value)>,
) -> Result<String, RepositoryContractError> {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_HASH_TAG);
    for (file, value) in schemas {
        validate_schema_filename(file)?;
        let canonical = serde_json::to_vec(&canonical_json(value.clone())).map_err(|source| {
            RepositoryContractError::SchemaJson {
                path: PathBuf::from(file),
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
