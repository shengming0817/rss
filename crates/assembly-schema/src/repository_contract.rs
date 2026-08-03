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
use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

const SCHEMA_HASH_TAG: &[u8] = b"rss-schema-hash-v1\0";
const SOURCE_SNAPSHOT_TAG: &[u8] = b"rss-contract-source-snapshot-v1\0";
const FRAMEWORK_OWNER: &str = "_framework";

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
    pub fn schema_bytes(&self, file: &str) -> Option<&[u8]> {
        self.source
            .schemas
            .get(file)
            .and_then(SchemaSourceSnapshot::bytes)
    }

    /// SHA-256 of exact captured schema bytes, if the declared schema existed.
    pub fn schema_source_digest(&self, file: &str) -> Option<&str> {
        self.source
            .schemas
            .get(file)
            .and_then(SchemaSourceSnapshot::digest)
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
        let digest = source_snapshot_digest(&manifest_source, &schemas);
        let source = Arc::new(ContractSourceSnapshot {
            contracts_root: self.dir.clone(),
            manifest: manifest_source,
            schemas,
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
    toml_paths
        .into_iter()
        .map(|path| load_contract(contracts_root, &path))
        .collect()
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
    for contract in contracts {
        contract.verify_unchanged()?;
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
    let digest = source_snapshot_digest(&manifest_source, &schemas);
    let source = Arc::new(ContractSourceSnapshot {
        contracts_root: contracts_root.to_path_buf(),
        manifest: manifest_source,
        schemas,
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
        let bytes = contract.schema_bytes(file).ok_or_else(|| {
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
        "sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103";
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
outputs = ["resources"]
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
