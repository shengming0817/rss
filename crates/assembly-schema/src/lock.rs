//! Canonical AssemblyLock v2 identity protocol.
//!
//! INVARIANT: ASSEMBLY-LOCK-CONSTRUCTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private lock/canonical fields plus no public digest, tag, catalog, or compiler constructors" } — external code cannot mint an AssemblyLock or canonical manifest.

use crate::contract_manifest::{
    Capabilities, ConsistencyLevel, ContractKind, ContractManifest, Delivery, EffectProfile,
    Endpoints, HttpMethod, Lifecycle, RawContractOwner, SagaBlock, Schemas, Subscription,
};
use crate::repository_contract::{
    RepositoryContract, RepositoryContractSourceFile, capture_contract_repository_sources,
    inspect_contract_repository, inspect_contract_repository_snapshot,
    validate_workflow_activations, verify_contract_repository_unchanged,
};
use crate::{
    AssemblyManifest, AssemblyProfile, CanonicalAssemblyManifestV2,
    CanonicalAssemblyManifestV2Value,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use vocab::CanonicalSha256Digest;

const ASSEMBLY_LOCK_TAG: &str = "rss-assembly-lock-v2";
const MANIFEST_TAG: &str = "rss-assembly-manifest-v2";
const GENERATED_TAG: &str = "rss-assembly-generated-v2";
const CONTRACTS_TAG: &str = "rss-assembly-contracts-v2";
const CONTRACT_RUNTIME_SEMANTICS_TAG: &str = "rss-contract-runtime-semantics-v2";
const SCHEMA_VERSION: u32 = 2;
const SNAPSHOT_SCHEMA_VERSION: u32 = 2;
#[cfg(test)]
const NON_BLANK_NAME_PATTERN: &str = r"^.*\S.*$";

/// Single source for identifying files owned by the assembly module generator.
pub const GENERATED_MODULE_OWNERSHIP_MARKER: &str = "// @generated assembly modules; DO NOT EDIT.";
/// Single source for identifying files owned by the assembly provider generator.
pub const GENERATED_PROVIDER_OWNERSHIP_MARKER: &str =
    "// @generated assembly providers; DO NOT EDIT.";

struct SchemaVersionV2;
impl JsonSchema for SchemaVersionV2 {
    fn is_referenceable() -> bool {
        false
    }
    fn schema_name() -> String {
        "AssemblyLockSchemaVersionV2".to_owned()
    }
    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            const_value: Some(serde_json::json!(2)),
            ..schemars::schema::SchemaObject::default()
        })
    }
}
struct Sha256Digest;
impl JsonSchema for Sha256Digest {
    fn is_referenceable() -> bool {
        false
    }
    fn schema_name() -> String {
        "Sha256Digest".to_owned()
    }
    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            string: Some(Box::new(schemars::schema::StringValidation {
                pattern: Some("^sha256:[0-9a-f]{64}$".to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

/// Version-two trusted AssemblyLock value, obtainable only through repository verification.
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssemblyLock {
    #[schemars(with = "SchemaVersionV2")]
    schema_version: u32,
    identity: AssemblyIdentity,
    digests: AssemblyDigests,
    #[schemars(with = "Sha256Digest")]
    fingerprint: AssemblyFingerprint,
}
impl AssemblyLock {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub const fn identity(&self) -> &AssemblyIdentity {
        &self.identity
    }
    pub const fn digests(&self) -> &AssemblyDigests {
        &self.digests
    }
    pub const fn fingerprint(&self) -> &AssemblyFingerprint {
        &self.fingerprint
    }
}

/// Strictly parsed wire data whose fingerprint is internally self-consistent.
/// Repository provenance has not yet been verified.
pub struct ParsedAssemblyLock(AssemblyLock);

impl ParsedAssemblyLock {
    /// Parse a closed v2 JSON object and verify its self-excluding fingerprint.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, AssemblyLockError> {
        let wire = strict_json(bytes)?;
        if wire.schema_version != SCHEMA_VERSION {
            return Err(AssemblyLockError::new(
                AssemblyLockErrorKind::UnsupportedVersion(wire.schema_version),
            ));
        }
        if wire.identity.name.trim().is_empty() {
            return Err(AssemblyLockError::new(AssemblyLockErrorKind::EmptyIdentity));
        }
        let identity = AssemblyIdentity {
            name: wire.identity.name,
            profile: wire.identity.profile,
        };
        let digests = AssemblyDigests {
            manifest: wire.digests.manifest,
            generated: wire.digests.generated,
            contracts: wire.digests.contracts,
        };
        let expected = fingerprint_for(&identity, &digests)?;
        if wire.fingerprint != expected {
            return Err(AssemblyLockError::new(
                AssemblyLockErrorKind::FingerprintMismatch {
                    expected: expected.to_string(),
                    actual: wire.fingerprint.to_string(),
                },
            ));
        }
        Ok(Self(AssemblyLock {
            schema_version: SCHEMA_VERSION,
            identity,
            digests,
            fingerprint: AssemblyFingerprint(expected),
        }))
    }

    pub const fn identity(&self) -> &AssemblyIdentity {
        self.0.identity()
    }

    pub const fn digests(&self) -> &AssemblyDigests {
        self.0.digests()
    }

    pub const fn fingerprint(&self) -> &AssemblyFingerprint {
        self.0.fingerprint()
    }

    /// Recompute the complete repository universe and promote only an exact match.
    pub fn verify_repository_v2(
        self,
        manifest: &RepositoryAssemblyManifestV2,
    ) -> Result<RepositoryVerifiedAssemblyLock, AssemblyLockError> {
        let verified = RepositoryVerifiedAssemblyLock::compile_v2(manifest)?;
        let actual = self.0.fingerprint().as_str();
        let expected = verified.fingerprint().as_str();
        if actual != expected {
            return Err(AssemblyLockError::new(
                AssemblyLockErrorKind::RepositoryMismatch {
                    expected: expected.to_owned(),
                    actual: actual.to_owned(),
                },
            ));
        }
        Ok(verified)
    }
}

/// Opaque canonical manifest discovered from one normalized repository assembly path.
///
/// Private fields make it impossible for governance consumers to pair canonical manifest facts
/// with a different source path or source text.
#[derive(Clone)]
pub struct RepositoryAssemblyManifestV2 {
    canonical: CanonicalAssemblyManifestV2,
    repository_root: PathBuf,
    assembly_dir: PathBuf,
    source_label: String,
    source_text: String,
}

/// Immutable presented repository source universe that replays the complete AssemblyLock v2 join.
///
/// As with path-based repository discovery, verification proves completeness relative to the
/// supplied source universe. The build capture owns binding that universe to a specific checkout.
pub struct RepositoryAssemblySnapshotV2 {
    wire: WireRepositoryAssemblySnapshotV2,
    manifest: CanonicalAssemblyManifestV2,
    lock: RepositoryVerifiedAssemblyLock,
}

impl RepositoryAssemblySnapshotV2 {
    /// Capture and verify the exact repository sources consumed by one committed AssemblyLock.
    pub fn capture_v2(
        manifest: &RepositoryAssemblyManifestV2,
        lock_bytes: &[u8],
    ) -> Result<Self, AssemblyLockError> {
        let current = manifest.rediscover_unchanged()?;
        let lock_path = current.assembly_dir.join("assembly.lock.json");
        verify_snapshot_file_unchanged(&lock_path, lock_bytes, "AssemblyLock")?;
        let contracts = inspect_contract_repository(&current.repository_root.join("contracts"))
            .and_then(|inspection| inspection.promote())
            .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        validate_workflow_activations(current.canonical(), &contracts)
            .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        let contract_files =
            capture_contract_repository_sources(&current.repository_root, &contracts)
                .map_err(|error| AssemblyLockError::contract(error.to_string()))?
                .into_iter()
                .map(|file| SnapshotSourceFileV2 {
                    path: file.path,
                    content: file.content,
                })
                .collect();
        let generated_files = capture_generated_sources_v2(
            &current.repository_root,
            &current.assembly_dir.join("src/generated"),
        )?;
        let lock_content = std::str::from_utf8(lock_bytes)
            .map_err(|error| {
                AssemblyLockError::snapshot(format!("AssemblyLock is not UTF-8: {error}"))
            })?
            .to_owned();
        let wire = WireRepositoryAssemblySnapshotV2 {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            assembly_manifest: SnapshotSourceFileV2 {
                path: current.source_label.clone(),
                content: current.source_text.clone(),
            },
            assembly_lock: SnapshotSourceFileV2 {
                path: format!("assemblies/{}/assembly.lock.json", current.canonical.name()),
                content: lock_content,
            },
            generated_files,
            contract_files,
        };
        let snapshot = Self::verify_wire(wire)?;
        verify_contract_repository_unchanged(
            &current.repository_root.join("contracts"),
            &contracts,
        )
        .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        verify_generated_sources_unchanged(
            &current.repository_root,
            &current.assembly_dir.join("src/generated"),
            &snapshot.wire.generated_files,
        )?;
        verify_snapshot_file_unchanged(&lock_path, lock_bytes, "AssemblyLock")?;
        current.rediscover_unchanged()?;
        Ok(snapshot)
    }

    /// Parse a strict snapshot and replay every repository validation before minting the lock.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, AssemblyLockError> {
        let wire = serde_json::from_slice(bytes).map_err(|source| {
            AssemblyLockError::new(AssemblyLockErrorKind::StrictSnapshotJson(source))
        })?;
        Self::verify_wire(wire)
    }

    /// Serialize deterministic pretty JSON with exactly one trailing line feed.
    pub fn to_pretty_json_vec(&self) -> Result<Vec<u8>, AssemblyLockError> {
        let mut bytes = serde_json::to_vec_pretty(&self.wire).map_err(|source| {
            AssemblyLockError::new(AssemblyLockErrorKind::SnapshotSerialization(source))
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub const fn manifest(&self) -> &CanonicalAssemblyManifestV2 {
        &self.manifest
    }

    pub const fn lock(&self) -> &RepositoryVerifiedAssemblyLock {
        &self.lock
    }

    fn verify_wire(wire: WireRepositoryAssemblySnapshotV2) -> Result<Self, AssemblyLockError> {
        if wire.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(AssemblyLockError::snapshot(format!(
                "unsupported repository snapshot schemaVersion {}",
                wire.schema_version
            )));
        }
        let manifest_path = normalized_snapshot_path(&wire.assembly_manifest.path)?;
        let components = manifest_path.components().collect::<Vec<_>>();
        let [
            Component::Normal(assemblies),
            Component::Normal(directory),
            Component::Normal(file),
        ] = components.as_slice()
        else {
            return Err(AssemblyLockError::snapshot(
                "assembly manifest path must be assemblies/<name>/assembly.toml",
            ));
        };
        if assemblies.to_str() != Some("assemblies") || file.to_str() != Some("assembly.toml") {
            return Err(AssemblyLockError::snapshot(
                "assembly manifest path must be assemblies/<name>/assembly.toml",
            ));
        }
        let directory = directory.to_str().ok_or_else(|| {
            AssemblyLockError::snapshot("assembly snapshot directory is not UTF-8")
        })?;
        let manifest =
            AssemblyManifest::from_toml_str(&wire.assembly_manifest.content).map_err(|source| {
                AssemblyLockError::new(AssemblyLockErrorKind::AssemblyManifestToml {
                    path: manifest_path.clone(),
                    source,
                })
            })?;
        let canonical = manifest.canonicalize_v2().map_err(|source| {
            AssemblyLockError::new(AssemblyLockErrorKind::AssemblyManifestCanonicalization {
                path: manifest_path.clone(),
                source: Box::new(source),
            })
        })?;
        if canonical.name() != directory {
            return Err(AssemblyLockError::snapshot(format!(
                "assembly directory basename `{directory}` does not match manifest name `{}`",
                canonical.name()
            )));
        }
        let expected_lock_path = format!("assemblies/{directory}/assembly.lock.json");
        if wire.assembly_lock.path != expected_lock_path {
            return Err(AssemblyLockError::snapshot(format!(
                "AssemblyLock path must be {expected_lock_path}"
            )));
        }
        normalized_snapshot_path(&wire.assembly_lock.path)?;

        let generated = generated_digest_from_snapshot_v2(directory, &wire.generated_files)?;
        if wire.contract_files.is_empty() {
            return Err(AssemblyLockError::snapshot(
                "contract snapshot universe is empty",
            ));
        }
        let mut previous = None::<&str>;
        let mut contract_sources = Vec::with_capacity(wire.contract_files.len());
        for file in &wire.contract_files {
            normalized_snapshot_path(&file.path)?;
            if !file.path.starts_with("contracts/") {
                return Err(AssemblyLockError::snapshot(format!(
                    "contract snapshot path is outside contracts/: {}",
                    file.path
                )));
            }
            if previous.is_some_and(|value| value >= file.path.as_str()) {
                return Err(AssemblyLockError::snapshot(
                    "contract snapshot paths must be strictly sorted",
                ));
            }
            previous = Some(&file.path);
            contract_sources.push(RepositoryContractSourceFile {
                path: file.path.clone(),
                content: file.content.clone(),
            });
        }
        let contracts = inspect_contract_repository_snapshot(&contract_sources)
            .and_then(|inspection| inspection.promote())
            .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        validate_workflow_activations(&canonical, &contracts)
            .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        let catalog = RepositoryContractCatalogV2::from_repository(&contracts)?;
        let expected = RepositoryVerifiedAssemblyLock(compile_with_digests_v2(
            &canonical, generated, &catalog,
        )?);
        let parsed = ParsedAssemblyLock::from_json_slice(wire.assembly_lock.content.as_bytes())?;
        if parsed.fingerprint().as_str() != expected.fingerprint().as_str() {
            return Err(AssemblyLockError::new(
                AssemblyLockErrorKind::RepositoryMismatch {
                    expected: expected.fingerprint().as_str().to_owned(),
                    actual: parsed.fingerprint().as_str().to_owned(),
                },
            ));
        }
        Ok(Self {
            wire,
            manifest: canonical,
            lock: expected,
        })
    }
}

impl RepositoryAssemblyManifestV2 {
    /// Discover, validate, and canonicalize `assemblies/<name>/assembly.toml` exactly once.
    pub fn discover_v2(
        repository_root: &Path,
        assembly_dir: &Path,
    ) -> Result<Self, AssemblyLockError> {
        discover_assembly_manifest_v2(repository_root, assembly_dir)
    }

    pub const fn canonical(&self) -> &CanonicalAssemblyManifestV2 {
        &self.canonical
    }

    pub fn assembly_dir(&self) -> &Path {
        &self.assembly_dir
    }

    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    pub fn source_text(&self) -> &str {
        &self.source_text
    }

    fn rediscover_unchanged(&self) -> Result<Self, AssemblyLockError> {
        let current = discover_assembly_manifest_v2(&self.repository_root, &self.assembly_dir)?;
        if current.repository_root != self.repository_root
            || current.assembly_dir != self.assembly_dir
            || current.source_label != self.source_label
            || current.source_text.as_bytes() != self.source_text.as_bytes()
        {
            return Err(AssemblyLockError::new(
                AssemblyLockErrorKind::StaleAssemblyManifest {
                    path: self.assembly_dir.join("assembly.toml"),
                },
            ));
        }
        Ok(current)
    }
}

/// AssemblyLock compiled from a complete deterministic repository input universe.
#[derive(Serialize)]
#[serde(transparent)]
pub struct RepositoryVerifiedAssemblyLock(AssemblyLock);

impl RepositoryVerifiedAssemblyLock {
    /// Sole production compiler: discovers contracts itself and accepts no raw digest/catalog input.
    pub fn compile_v2(manifest: &RepositoryAssemblyManifestV2) -> Result<Self, AssemblyLockError> {
        let current = manifest.rediscover_unchanged()?;
        let repository_root = &current.repository_root;
        let contracts = inspect_contract_repository(&repository_root.join("contracts"))
            .and_then(|inspection| inspection.promote())
            .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        validate_workflow_activations(current.canonical(), &contracts)
            .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        let catalog = RepositoryContractCatalogV2::from_repository(&contracts)?;
        let lock = compile_with_catalog_v2(
            current.canonical(),
            repository_root,
            current.assembly_dir(),
            &catalog,
        )?;
        verify_contract_repository_unchanged(&repository_root.join("contracts"), &contracts)
            .map_err(|error| AssemblyLockError::contract(error.to_string()))?;
        current.rediscover_unchanged()?;
        Ok(Self(lock))
    }

    pub const fn as_lock(&self) -> &AssemblyLock {
        &self.0
    }

    pub const fn identity(&self) -> &AssemblyIdentity {
        self.0.identity()
    }

    pub const fn digests(&self) -> &AssemblyDigests {
        self.0.digests()
    }

    pub const fn fingerprint(&self) -> &AssemblyFingerprint {
        self.0.fingerprint()
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyIdentity {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    name: String,
    profile: AssemblyProfile,
}
impl AssemblyIdentity {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn profile(&self) -> AssemblyProfile {
        self.profile
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyDigests {
    #[schemars(with = "Sha256Digest")]
    manifest: CanonicalSha256Digest,
    #[schemars(with = "Sha256Digest")]
    generated: CanonicalSha256Digest,
    #[schemars(with = "Sha256Digest")]
    contracts: CanonicalSha256Digest,
}
impl AssemblyDigests {
    pub const fn manifest(&self) -> &CanonicalSha256Digest {
        &self.manifest
    }
    pub const fn generated(&self) -> &CanonicalSha256Digest {
        &self.generated
    }
    pub const fn contracts(&self) -> &CanonicalSha256Digest {
        &self.contracts
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct AssemblyFingerprint(
    #[schemars(with = "String", regex(pattern = "^sha256:[0-9a-f]{64}$"))] CanonicalSha256Digest,
);
impl AssemblyFingerprint {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn from_validated(value: CanonicalSha256Digest) -> Self {
        Self(value)
    }
}

/// Closed protocol error; source chains retain JSON and filesystem diagnostics.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AssemblyLockError(AssemblyLockErrorKind);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyLockErrorStage {
    LockFile,
    Manifest,
    ContractCatalog,
    GeneratedUniverse,
    FileSystem,
    Serialization,
    RepositorySnapshot,
}
#[derive(Debug, thiserror::Error)]
enum AssemblyLockErrorKind {
    #[error("invalid strict AssemblyLock JSON: {0}")]
    StrictJson(#[source] serde_json::Error),
    #[error("invalid strict repository assembly snapshot JSON: {0}")]
    StrictSnapshotJson(#[source] serde_json::Error),
    #[error("repository assembly snapshot: {0}")]
    Snapshot(String),
    #[error("repository assembly snapshot serialization failed: {0}")]
    SnapshotSerialization(#[source] serde_json::Error),
    #[error("RFC8785 canonical serialization failed: {0}")]
    CanonicalJson(#[source] serde_json::Error),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("unsupported AssemblyLock schemaVersion {0}")]
    UnsupportedVersion(u32),
    #[error("assembly identity name is empty")]
    EmptyIdentity,
    #[error("{0} is not a lowercase sha256 digest")]
    InvalidDigest(&'static str),
    #[error(
        "AssemblyLock fingerprint mismatch: expected `{expected}`, actual `{actual}`; regenerate the lock file"
    )]
    FingerprintMismatch { expected: String, actual: String },
    #[error(
        "AssemblyLock repository inputs mismatch: expected `{expected}`, actual `{actual}`; regenerate the lock file"
    )]
    RepositoryMismatch { expected: String, actual: String },
    #[error("generated input: {0}")]
    Generated(String),
    #[error("assembly input: {0}")]
    Assembly(String),
    #[error("assembly manifest changed after repository discovery: {path}")]
    StaleAssemblyManifest { path: PathBuf },
    #[error("contract catalog: {0}")]
    Contract(String),
    #[error("failed to parse assembly manifest {path}: {source}")]
    AssemblyManifestToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to canonicalize assembly manifest {path}: {source}")]
    AssemblyManifestCanonicalization {
        path: PathBuf,
        #[source]
        source: Box<crate::AssemblyManifestCanonicalizationError>,
    },
}
impl AssemblyLockError {
    pub const fn stage(&self) -> AssemblyLockErrorStage {
        match &self.0 {
            AssemblyLockErrorKind::AssemblyManifestToml { .. }
            | AssemblyLockErrorKind::AssemblyManifestCanonicalization { .. }
            | AssemblyLockErrorKind::StaleAssemblyManifest { .. }
            | AssemblyLockErrorKind::Assembly(_) => AssemblyLockErrorStage::Manifest,
            AssemblyLockErrorKind::Contract(_) => AssemblyLockErrorStage::ContractCatalog,
            AssemblyLockErrorKind::Generated(_) => AssemblyLockErrorStage::GeneratedUniverse,
            AssemblyLockErrorKind::Io { .. } => AssemblyLockErrorStage::FileSystem,
            AssemblyLockErrorKind::CanonicalJson(_) => AssemblyLockErrorStage::Serialization,
            AssemblyLockErrorKind::SnapshotSerialization(_) => {
                AssemblyLockErrorStage::Serialization
            }
            AssemblyLockErrorKind::StrictSnapshotJson(_) | AssemblyLockErrorKind::Snapshot(_) => {
                AssemblyLockErrorStage::RepositorySnapshot
            }
            _ => AssemblyLockErrorStage::LockFile,
        }
    }

    fn new(kind: AssemblyLockErrorKind) -> Self {
        Self(kind)
    }
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self(AssemblyLockErrorKind::Io {
            context: context.into(),
            source,
        })
    }
    fn generated(message: impl Into<String>) -> Self {
        Self(AssemblyLockErrorKind::Generated(message.into()))
    }
    fn assembly(message: impl Into<String>) -> Self {
        Self(AssemblyLockErrorKind::Assembly(message.into()))
    }
    fn contract(message: impl Into<String>) -> Self {
        Self(AssemblyLockErrorKind::Contract(message.into()))
    }
    fn snapshot(message: impl Into<String>) -> Self {
        Self(AssemblyLockErrorKind::Snapshot(message.into()))
    }
}
fn io_error(context: impl Into<String>) -> impl FnOnce(io::Error) -> AssemblyLockError {
    let context = context.into();
    move |source| AssemblyLockError::io(context, source)
}
fn generated_path(reason: &str, path: &Path) -> AssemblyLockError {
    AssemblyLockError::generated(format!("{reason}: {}", path.display()))
}
fn assembly_path(reason: &str, path: &Path) -> AssemblyLockError {
    AssemblyLockError::assembly(format!("{reason}: {}", path.display()))
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRepositoryAssemblySnapshotV2 {
    schema_version: u32,
    assembly_manifest: SnapshotSourceFileV2,
    assembly_lock: SnapshotSourceFileV2,
    generated_files: Vec<SnapshotSourceFileV2>,
    contract_files: Vec<SnapshotSourceFileV2>,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SnapshotSourceFileV2 {
    path: String,
    content: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireAssemblyLock {
    schema_version: u32,
    identity: WireIdentity,
    digests: WireDigests,
    fingerprint: CanonicalSha256Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIdentity {
    name: String,
    profile: AssemblyProfile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDigests {
    manifest: CanonicalSha256Digest,
    generated: CanonicalSha256Digest,
    contracts: CanonicalSha256Digest,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedLock<'a> {
    schema_version: u32,
    identity: &'a AssemblyIdentity,
    digests: &'a AssemblyDigests,
}
pub(super) fn canonical_manifest_digest(
    value: &CanonicalAssemblyManifestV2Value,
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    tagged_digest(MANIFEST_TAG, value)
}
fn fingerprint_for(
    identity: &AssemblyIdentity,
    digests: &AssemblyDigests,
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    tagged_digest(
        ASSEMBLY_LOCK_TAG,
        &UnsignedLock {
            schema_version: SCHEMA_VERSION,
            identity,
            digests,
        },
    )
}
fn tagged_digest(
    tag: &str,
    value: &impl Serialize,
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    let canonical = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    CanonicalSha256Digest::parse(format!("sha256:{:x}", hasher.finalize()))
        .map_err(|_| AssemblyLockError::new(AssemblyLockErrorKind::InvalidDigest("computed")))
}
fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, AssemblyLockError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|source| AssemblyLockError::new(AssemblyLockErrorKind::CanonicalJson(source)))
}
fn strict_json(bytes: &[u8]) -> Result<WireAssemblyLock, AssemblyLockError> {
    serde_json::from_slice(bytes)
        .map_err(|source| AssemblyLockError::new(AssemblyLockErrorKind::StrictJson(source)))
}
#[derive(Serialize)]
struct GeneratedFileDigest {
    path: String,
    digest: CanonicalSha256Digest,
}
fn generated_digest_v2(
    repository_root: &Path,
    generated_root: &Path,
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    tagged_digest(
        GENERATED_TAG,
        &discover_generated_files_v2(repository_root, generated_root)?,
    )
}
fn capture_generated_sources_v2(
    repository_root: &Path,
    generated_root: &Path,
) -> Result<Vec<SnapshotSourceFileV2>, AssemblyLockError> {
    discover_generated_files_v2(repository_root, generated_root)?
        .into_iter()
        .map(|entry| {
            let path = repository_root.join(&entry.path);
            let bytes =
                fs::read(&path).map_err(io_error(format!("failed to read {}", path.display())))?;
            let actual = digest_owned_bytes(&path, &bytes)?;
            if actual != entry.digest {
                return Err(AssemblyLockError::generated(format!(
                    "generated file changed while snapshotting: {}",
                    path.display()
                )));
            }
            let content = String::from_utf8(bytes).map_err(|error| {
                AssemblyLockError::generated(format!(
                    "generated file is not UTF-8: {}: {error}",
                    path.display()
                ))
            })?;
            Ok(SnapshotSourceFileV2 {
                path: entry.path,
                content,
            })
        })
        .collect()
}

fn verify_generated_sources_unchanged(
    repository_root: &Path,
    generated_root: &Path,
    expected: &[SnapshotSourceFileV2],
) -> Result<(), AssemblyLockError> {
    let current = capture_generated_sources_v2(repository_root, generated_root)?;
    if current != expected {
        return Err(AssemblyLockError::generated(
            "generated universe changed while snapshotting",
        ));
    }
    Ok(())
}

fn verify_snapshot_file_unchanged(
    path: &Path,
    expected: &[u8],
    label: &str,
) -> Result<(), AssemblyLockError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(io_error(format!("failed to inspect {}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AssemblyLockError::snapshot(format!(
            "{label} must be a non-symlink regular file: {}",
            path.display()
        )));
    }
    let current = fs::read(path).map_err(io_error(format!("failed to read {}", path.display())))?;
    if current != expected {
        return Err(AssemblyLockError::snapshot(format!(
            "{label} changed while snapshotting: {}",
            path.display()
        )));
    }
    Ok(())
}

fn generated_digest_from_snapshot_v2(
    assembly: &str,
    files: &[SnapshotSourceFileV2],
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    if files.is_empty() {
        return Err(AssemblyLockError::generated("file universe is empty"));
    }
    let expected_prefix = format!("assemblies/{assembly}/src/generated/");
    let mut seen = BTreeSet::new();
    let mut previous = None::<&str>;
    let mut digests = Vec::with_capacity(files.len());
    for file in files {
        normalized_snapshot_path(&file.path)?;
        if !file.path.starts_with(&expected_prefix) {
            return Err(AssemblyLockError::generated(format!(
                "snapshot path is outside {expected_prefix}: {}",
                file.path
            )));
        }
        if previous.is_some_and(|value| value >= file.path.as_str()) {
            return Err(AssemblyLockError::generated(
                "snapshot paths must be strictly sorted",
            ));
        }
        previous = Some(&file.path);
        if !seen.insert(file.path.as_str()) {
            return Err(AssemblyLockError::generated(format!(
                "duplicate generated path: {}",
                file.path
            )));
        }
        digests.push(GeneratedFileDigest {
            path: file.path.clone(),
            digest: digest_owned_bytes(Path::new(&file.path), file.content.as_bytes())?,
        });
    }
    tagged_digest(GENERATED_TAG, &digests)
}

fn normalized_snapshot_path(label: &str) -> Result<PathBuf, AssemblyLockError> {
    if label.is_empty() || label.contains('\\') {
        return Err(AssemblyLockError::snapshot(format!(
            "snapshot path is not normalized: {label:?}"
        )));
    }
    let path = PathBuf::from(label);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AssemblyLockError::snapshot(format!(
            "snapshot path is not normalized: {label:?}"
        )));
    }
    Ok(path)
}
fn discover_generated_files_v2(
    repository_root: &Path,
    generated_root: &Path,
) -> Result<Vec<GeneratedFileDigest>, AssemblyLockError> {
    ensure_path_below_repository(repository_root, generated_root)?;
    let metadata = fs::symlink_metadata(generated_root).map_err(io_error(format!(
        "generated root is missing: {}",
        generated_root.display()
    )))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(generated_path(
            "generated root is not a real directory",
            generated_root,
        ));
    }
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    collect_generated_files(repository_root, generated_root, &mut seen, &mut entries)?;
    if entries.is_empty() {
        return Err(AssemblyLockError::generated("file universe is empty"));
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}
fn collect_generated_files(
    repository_root: &Path,
    directory: &Path,
    seen: &mut BTreeSet<String>,
    entries: &mut Vec<GeneratedFileDigest>,
) -> Result<(), AssemblyLockError> {
    let mut children = fs::read_dir(directory)
        .map_err(io_error(format!(
            "failed to read generated directory {}",
            directory.display()
        )))?
        .collect::<Result<Vec<_>, io::Error>>()
        .map_err(io_error("failed to read generated entry"))?;
    children.sort_by_key(fs::DirEntry::path);
    for child in children {
        let path = child.path();
        let file_type = child.file_type().map_err(io_error(format!(
            "failed to read generated entry type: {}",
            path.display()
        )))?;
        if file_type.is_symlink() {
            return Err(generated_path("input is a symlink", &path));
        }
        if file_type.is_dir() {
            collect_generated_files(repository_root, &path, seen, entries)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(generated_path("input is not a regular file", &path));
        }
        let label = repository_label(repository_root, &path)?;
        if !seen.insert(label.clone()) {
            return Err(AssemblyLockError::generated(format!(
                "duplicate generated path: {label}"
            )));
        }
        entries.push(GeneratedFileDigest {
            path: label,
            digest: digest_owned_file(&path)?,
        });
    }
    Ok(())
}
fn digest_owned_file(path: &Path) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    let mut file =
        File::open(path).map_err(io_error(format!("failed to open {}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(io_error(format!("failed to stat {}", path.display())))?;
    if !metadata.is_file() {
        return Err(generated_path("input is not a regular file", path));
    }
    let mut buffer = [0_u8; 8192];
    let mut bytes = Vec::new();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(io_error(format!("failed to read {}", path.display())))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    digest_owned_bytes(path, &bytes)
}

fn digest_owned_bytes(
    path: &Path,
    bytes: &[u8],
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    let markers = [
        GENERATED_MODULE_OWNERSHIP_MARKER.as_bytes(),
        GENERATED_PROVIDER_OWNERSHIP_MARKER.as_bytes(),
    ];
    let owned = markers
        .iter()
        .any(|marker| bytes.starts_with(marker) && bytes.get(marker.len()).copied() == Some(b'\n'));
    if !owned {
        return Err(generated_path(
            "generated file lacks ownership marker",
            path,
        ));
    }
    CanonicalSha256Digest::parse(format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|_| AssemblyLockError::new(AssemblyLockErrorKind::InvalidDigest("computed")))
}
fn ensure_path_below_repository(
    repository_root: &Path,
    path: &Path,
) -> Result<(), AssemblyLockError> {
    let relative = path
        .strip_prefix(repository_root)
        .map_err(|_| generated_path("path escapes repository root", path))?;
    let mut current = PathBuf::from(repository_root);
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(generated_path("path contains traversal component", path));
        };
        current.push(segment);
        let metadata = fs::symlink_metadata(&current).map_err(io_error(format!(
            "failed to inspect repository path {}",
            current.display()
        )))?;
        if metadata.file_type().is_symlink() {
            return Err(generated_path(
                "repository input path contains a symlink",
                &current,
            ));
        }
    }
    Ok(())
}
fn repository_label(repository_root: &Path, path: &Path) -> Result<String, AssemblyLockError> {
    let relative = path
        .strip_prefix(repository_root)
        .map_err(|_| AssemblyLockError::generated("generated path escapes repository root"))?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AssemblyLockError::generated(
            "generated path is not normalized",
        ));
    }
    relative
        .to_str()
        .map(|label| label.replace('\\', "/"))
        .ok_or_else(|| AssemblyLockError::generated("generated path is not UTF-8"))
}

fn discover_assembly_manifest_v2(
    repository_root: &Path,
    assembly_dir: &Path,
) -> Result<RepositoryAssemblyManifestV2, AssemblyLockError> {
    let canonical_root = fs::canonicalize(repository_root).map_err(io_error(format!(
        "failed to canonicalize repository root {}",
        repository_root.display()
    )))?;
    if canonical_root != repository_root {
        return Err(assembly_path(
            "repository root must be an absolute canonical path without symlink aliases",
            repository_root,
        ));
    }
    let relative = assembly_dir
        .strip_prefix(repository_root)
        .map_err(|_| assembly_path("path escapes repository root", assembly_dir))?;
    let mut components = relative.components();
    let (Some(Component::Normal(namespace)), Some(Component::Normal(directory_name)), None) =
        (components.next(), components.next(), components.next())
    else {
        return Err(assembly_path(
            "path must be exactly assemblies/<name>",
            assembly_dir,
        ));
    };
    if namespace.to_str() != Some("assemblies") {
        return Err(assembly_path(
            "path must be exactly assemblies/<name>",
            assembly_dir,
        ));
    }
    let directory_name = directory_name
        .to_str()
        .ok_or_else(|| assembly_path("assembly directory name is not UTF-8", assembly_dir))?;
    let expected = repository_root.join("assemblies").join(directory_name);
    if assembly_dir != expected {
        return Err(assembly_path(
            "path must use normalized assemblies/<name> components",
            assembly_dir,
        ));
    }
    ensure_path_below_repository(repository_root, assembly_dir)?;
    let metadata = fs::symlink_metadata(assembly_dir).map_err(io_error(format!(
        "failed to inspect assembly directory {}",
        assembly_dir.display()
    )))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(assembly_path(
            "assembly input is not a real directory",
            assembly_dir,
        ));
    }
    let manifest_path = assembly_dir.join("assembly.toml");
    ensure_path_below_repository(repository_root, &manifest_path)?;
    let metadata = fs::symlink_metadata(&manifest_path).map_err(io_error(format!(
        "failed to inspect assembly manifest {}",
        manifest_path.display()
    )))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(assembly_path(
            "assembly manifest is not a real file",
            &manifest_path,
        ));
    }
    let source_text = fs::read_to_string(&manifest_path).map_err(io_error(format!(
        "failed to read assembly manifest {}",
        manifest_path.display()
    )))?;
    let manifest = AssemblyManifest::from_toml_str(&source_text).map_err(|source| {
        AssemblyLockError::new(AssemblyLockErrorKind::AssemblyManifestToml {
            path: manifest_path.clone(),
            source,
        })
    })?;
    let canonical = manifest.canonicalize_v2().map_err(|source| {
        AssemblyLockError::new(AssemblyLockErrorKind::AssemblyManifestCanonicalization {
            path: manifest_path.clone(),
            source: Box::new(source),
        })
    })?;
    if canonical.name() != directory_name {
        return Err(AssemblyLockError::assembly(format!(
            "assembly directory basename `{directory_name}` does not match manifest name `{}`",
            canonical.name()
        )));
    }
    let source_label = manifest_path
        .strip_prefix(repository_root)
        .map_err(|_| assembly_path("manifest path escapes repository root", &manifest_path))?
        .to_str()
        .ok_or_else(|| assembly_path("manifest path is not UTF-8", &manifest_path))?
        .replace('\\', "/");
    Ok(RepositoryAssemblyManifestV2 {
        canonical,
        repository_root: canonical_root,
        assembly_dir: assembly_dir.to_path_buf(),
        source_label,
        source_text,
    })
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[cfg_attr(test, derive(Debug, Deserialize))]
#[serde(rename_all = "camelCase")]
struct ContractBindingV2 {
    domain: String,
    id: String,
    version: String,
    schema_hash: CanonicalSha256Digest,
    semantics_hash: CanonicalSha256Digest,
}
/// Complete, deterministic repository catalog. Production construction only discovers real files.
struct RepositoryContractCatalogV2 {
    bindings: Vec<ContractBindingV2>,
}
impl RepositoryContractCatalogV2 {
    fn from_repository(contracts: &[RepositoryContract]) -> Result<Self, AssemblyLockError> {
        let mut bindings = Vec::with_capacity(contracts.len());
        for contract in contracts {
            let manifest = contract.manifest();
            if contract.path_kind() != manifest.kind.as_dir()
                || contract.path_domain() != manifest.domain
                || contract.path_version() != manifest.version
            {
                return Err(AssemblyLockError::contract(format!(
                    "contract path and manifest identity differ: {}",
                    contract.dir().display()
                )));
            }
            bindings.push(ContractBindingV2 {
                domain: manifest.domain.clone(),
                id: manifest.id.clone(),
                version: manifest.version.clone(),
                schema_hash: CanonicalSha256Digest::parse(contract.schema_hash())
                    .map_err(|_| AssemblyLockError::contract("contract schema hash is invalid"))?,
                semantics_hash: runtime_semantics_hash_v2(manifest)?,
            });
        }
        Self::from_complete_bindings(bindings)
    }

    fn from_complete_bindings(bindings: Vec<ContractBindingV2>) -> Result<Self, AssemblyLockError> {
        let mut identities = BTreeSet::new();
        for binding in &bindings {
            if binding.domain.trim().is_empty()
                || binding.id.trim().is_empty()
                || binding.version.trim().is_empty()
            {
                return Err(AssemblyLockError::contract(
                    "contract binding identity contains an empty field",
                ));
            }
            if !identities.insert((
                binding.domain.as_str(),
                binding.id.as_str(),
                binding.version.as_str(),
            )) {
                return Err(AssemblyLockError::contract(format!(
                    "duplicate contract binding: {}/{}/{}",
                    binding.domain, binding.id, binding.version
                )));
            }
        }
        Ok(Self { bindings })
    }

    #[cfg(test)]
    fn try_from_bindings(bindings: Vec<ContractBindingV2>) -> Result<Self, AssemblyLockError> {
        Self::from_complete_bindings(bindings)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractRuntimeSemanticsV2 {
    id: String,
    kind: ContractKind,
    domain: String,
    version: String,
    owner: RawContractOwner,
    consistency_level: ConsistencyLevel,
    lifecycle: Lifecycle,
    schemas: Schemas,
    endpoints: Option<Endpoints>,
    path: Option<String>,
    method: Option<HttpMethod>,
    topic: Option<String>,
    delivery: Option<Delivery>,
    saga: Option<SagaBlock>,
    effect_profile: Option<EffectProfile>,
    subscriptions: Vec<Subscription>,
    capabilities: Capabilities,
}

fn runtime_semantics_hash_v2(
    manifest: &ContractManifest,
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    let ContractManifest {
        id,
        kind,
        domain,
        version,
        owner,
        consistency_level,
        lifecycle,
        schemas,
        endpoints,
        path,
        method,
        topic,
        delivery,
        saga,
        effect_profile,
        subscriptions,
        capabilities,
    } = manifest;

    let mut effect_profile = effect_profile.clone();
    if let Some(profile) = &mut effect_profile {
        profile.effects.sort();
        if profile.effects.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AssemblyLockError::contract(
                "effectProfile.effects contains a duplicate set identity",
            ));
        }
    }
    let mut subscriptions = subscriptions.clone();
    subscriptions
        .sort_by(|left, right| (&left.consumer, &left.group).cmp(&(&right.consumer, &right.group)));
    if subscriptions
        .windows(2)
        .any(|pair| pair[0].consumer == pair[1].consumer && pair[0].group == pair[1].group)
    {
        return Err(AssemblyLockError::contract(
            "subscriptions contains a duplicate set identity",
        ));
    }
    let endpoints = endpoints.clone();
    let mut capabilities = capabilities.clone();
    if let Some(outbox) = &mut capabilities.outbox {
        outbox.emits.sort();
        if outbox.emits.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AssemblyLockError::contract(
                "capabilities.outbox.emits contains a duplicate set identity",
            ));
        }
    }

    tagged_digest(
        CONTRACT_RUNTIME_SEMANTICS_TAG,
        &ContractRuntimeSemanticsV2 {
            id: id.clone(),
            kind: *kind,
            domain: domain.clone(),
            version: version.clone(),
            owner: owner.clone(),
            consistency_level: *consistency_level,
            lifecycle: *lifecycle,
            schemas: schemas.clone(),
            endpoints,
            path: path.clone(),
            method: *method,
            topic: topic.clone(),
            delivery: *delivery,
            saga: saga.clone(),
            effect_profile,
            subscriptions,
            capabilities,
        },
    )
}
fn contracts_digest_v2(
    manifest: &CanonicalAssemblyManifestV2,
    catalog: &RepositoryContractCatalogV2,
) -> Result<CanonicalSha256Digest, AssemblyLockError> {
    let selected = select_contracts(manifest, catalog)?;
    tagged_digest(CONTRACTS_TAG, &selected)
}
fn select_contracts(
    manifest: &CanonicalAssemblyManifestV2,
    catalog: &RepositoryContractCatalogV2,
) -> Result<Vec<ContractBindingV2>, AssemblyLockError> {
    let domains = manifest
        .domains()
        .iter()
        .map(crate::AssemblyDomain::as_str)
        .collect::<BTreeSet<_>>();
    let framework_ids = manifest
        .framework_contracts()
        .iter()
        .map(|mount| mount.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut selected = catalog
        .bindings
        .iter()
        .filter(|binding| {
            domains.contains(binding.domain.as_str()) || framework_ids.contains(binding.id.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    for domain in domains {
        if !selected.iter().any(|binding| binding.domain == domain) {
            return Err(AssemblyLockError::contract(format!(
                "declared assembly domain `{domain}` has no contract binding"
            )));
        }
    }
    for contract_id in framework_ids {
        if selected
            .iter()
            .filter(|binding| binding.id == contract_id)
            .count()
            != 1
        {
            return Err(AssemblyLockError::contract(format!(
                "framework contract `{contract_id}` must resolve exactly once"
            )));
        }
    }
    selected.sort();
    Ok(selected)
}
fn compile_with_catalog_v2(
    manifest: &CanonicalAssemblyManifestV2,
    repository_root: &Path,
    assembly_dir: &Path,
    catalog: &RepositoryContractCatalogV2,
) -> Result<AssemblyLock, AssemblyLockError> {
    let generated = generated_digest_v2(repository_root, &assembly_dir.join("src/generated"))?;
    compile_with_digests_v2(manifest, generated, catalog)
}

fn compile_with_digests_v2(
    manifest: &CanonicalAssemblyManifestV2,
    generated: CanonicalSha256Digest,
    catalog: &RepositoryContractCatalogV2,
) -> Result<AssemblyLock, AssemblyLockError> {
    let identity = AssemblyIdentity {
        name: manifest.name().to_owned(),
        profile: manifest.profile(),
    };
    let digests = AssemblyDigests {
        manifest: manifest.manifest_digest().clone(),
        generated,
        contracts: contracts_digest_v2(manifest, catalog)?,
    };
    let fingerprint = AssemblyFingerprint(fingerprint_for(&identity, &digests)?);
    Ok(AssemblyLock {
        schema_version: SCHEMA_VERSION,
        identity,
        digests,
        fingerprint,
    })
}

#[cfg(test)]
fn compile_v2(
    manifest: &CanonicalAssemblyManifestV2,
    repository_root: &Path,
    assembly_dir: &Path,
    catalog: &RepositoryContractCatalogV2,
) -> Result<AssemblyLock, AssemblyLockError> {
    compile_with_catalog_v2(manifest, repository_root, assembly_dir, catalog)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: protocol tests use fixed fixtures and isolated temporary repositories.

    use super::*;
    use crate::contract_manifest::{
        CompensationOrder, ConsistencyLevel, ContractManifest, Delivery, ExternalEffectPolicy,
        HttpAuthMode, HttpMethod, Lifecycle, LocalTxModel,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const HASH_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SECRET: &str = "ZZ_RSS_LOCK_SECRET_SENTINEL_1780_DO_NOT_SERIALIZE";
    fn digest(raw: &str) -> CanonicalSha256Digest {
        CanonicalSha256Digest::parse(raw).expect("canonical digest fixture")
    }
    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rss-assembly-lock-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn owned(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().expect("generated parent")).expect("create parent");
        fs::write(path, format!("{GENERATED_MODULE_OWNERSHIP_MARKER}\n{body}"))
            .expect("write generated file");
    }
    fn provider_owned(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().expect("generated parent")).expect("create parent");
        fs::write(
            path,
            format!("{GENERATED_PROVIDER_OWNERSHIP_MARKER}\n{body}"),
        )
        .expect("write provider generated file");
    }
    fn binding(domain: &str, id: &str, version: &str, schema_hash: &str) -> ContractBindingV2 {
        ContractBindingV2 {
            domain: domain.into(),
            id: id.into(),
            version: version.into(),
            schema_hash: digest(schema_hash),
            semantics_hash: digest(HASH_B),
        }
    }
    fn make_catalog(bindings: Vec<ContractBindingV2>) -> RepositoryContractCatalogV2 {
        RepositoryContractCatalogV2::try_from_bindings(bindings).expect("valid catalog")
    }
    fn rejected<T, E: std::fmt::Debug>(result: Result<T, E>) {
        assert!(result.is_err());
    }
    fn same<T: std::fmt::Debug + PartialEq>(left: T, right: T) {
        assert_eq!(left, right);
    }
    fn canonical(template: &str, framework: &str) -> CanonicalAssemblyManifestV2 {
        crate::AssemblyManifest::from_toml_str(&template.replace("$FRAMEWORK", framework))
            .expect("parse manifest")
            .canonicalize_v2()
            .expect("canonical manifest")
    }
    fn vector_string(value: &serde_json::Value) -> &str {
        value.as_str().expect("vector string")
    }
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/assembly-lock-v2-vectors.json"
        ))
        .expect("vectors")
    }
    fn fingerprint_vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/fingerprint-v2-vectors.json"
        ))
        .expect("SpecKit fingerprint vectors")
    }
    fn fixture_bindings(value: &serde_json::Value) -> Vec<ContractBindingV2> {
        serde_json::from_value(value.clone()).expect("fixture bindings")
    }
    fn same_vector(actual: impl AsRef<str>, expected: &serde_json::Value) {
        assert_eq!(actual.as_ref(), vector_string(expected));
    }
    fn semantic(key: &str) -> String {
        let vectors = vectors();
        vector_string(&vectors[key]).to_owned()
    }
    fn canonical_hex(value: &impl Serialize) -> String {
        canonical_bytes(value)
            .expect("canonical bytes")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn shared_child_vectors_freeze_bytes_and_child_universes() {
        let vector = vectors();
        let manifest = canonical(vector_string(&vector["manifest"]["toml"]), "");
        let reparsed = canonical(vector_string(&vector["manifest"]["toml"]), "");
        same(
            canonical_hex(&manifest.value),
            canonical_hex(&reparsed.value),
        );
        assert!(manifest.manifest_digest().as_str().starts_with("sha256:"));
        let root = root("vectors");
        for file in vector["generated"]["files"]
            .as_array()
            .expect("generated files")
        {
            let path = root.join(vector_string(&file["path"]));
            fs::create_dir_all(path.parent().expect("file parent")).expect("create parent");
            fs::write(path, vector_string(&file["content"])).expect("write vector");
        }
        let generated = root.join("assemblies/runtime/src/generated");
        let entries = discover_generated_files_v2(&root, &generated).expect("entries");
        same_vector(
            canonical_hex(&entries),
            &vector["generated"]["canonicalHex"],
        );
        let generated_digest = generated_digest_v2(&root, &generated).expect("digest");
        same_vector(&generated_digest, &vector["generated"]["digest"]);
        let catalog = make_catalog(fixture_bindings(&vector["contracts"]["bindings"]));
        let selected = select_contracts(&manifest, &catalog).expect("selected");
        let mut expected_contracts = fixture_bindings(&vector["contracts"]["bindings"]);
        expected_contracts.sort();
        same(selected, expected_contracts);
        let contract_digest = contracts_digest_v2(&manifest, &catalog).expect("digest");
        assert!(contract_digest.as_str().starts_with("sha256:"));
        fs::remove_dir_all(root).expect("remove vectors");
    }

    #[test]
    fn speckit_is_the_single_final_fingerprint_vector() {
        let private = vectors();
        assert!(
            private.get("fingerprint").is_none(),
            "crate-private child vectors must not define the final fingerprint"
        );

        let vectors = fingerprint_vectors();
        let vector = vectors["vectors"]
            .as_array()
            .expect("fingerprint vectors")
            .iter()
            .find(|vector| vector["stageTag"] == ASSEMBLY_LOCK_TAG)
            .expect("AssemblyLock fingerprint vector");
        let unsigned = &vector["unsigned"];
        let identity = AssemblyIdentity {
            name: vector_string(&unsigned["identity"]["name"]).to_owned(),
            profile: serde_json::from_value(unsigned["identity"]["profile"].clone())
                .expect("profile"),
        };
        let digests = AssemblyDigests {
            manifest: digest(vector_string(&unsigned["digests"]["manifest"])),
            generated: digest(vector_string(&unsigned["digests"]["generated"])),
            contracts: digest(vector_string(&unsigned["digests"]["contracts"])),
        };
        let preimage = UnsignedLock {
            schema_version: SCHEMA_VERSION,
            identity: &identity,
            digests: &digests,
        };
        same_vector(canonical_hex(&preimage), &vector["canonicalHex"]);
        same_vector(
            fingerprint_for(&identity, &digests).expect("fingerprint"),
            &vector["expected"],
        );
    }

    #[test]
    fn canonical_and_lock_semantics_are_shared_end_to_end() {
        let framework = "{ id = \"framework.alpha\", listener = \"primary\" }, { id = \"framework.beta\", listener = \"admin\" }";
        let source = semantic("semanticToml").replace("$FRAMEWORK", framework);
        let first = canonical(&source, framework);
        let equivalent = canonical(&semantic("equivalentToml"), framework);
        same(
            canonical_bytes(&first.value).expect("fixture invariant"),
            canonical_bytes(&equivalent.value).expect("fixture invariant"),
        );
        same(first.manifest_digest(), equivalent.manifest_digest());
        for duplicate in [
            source.replacen("[\"backend\"]", "[\"backend\", \"backend\"]", 1),
            source.replacen(
                "[\"probes\", \"resources\", \"workers\"]",
                "[\"probes\", \"resources\", \"workers\", \"workers\"]",
                1,
            ),
        ] {
            rejected(
                crate::AssemblyManifest::from_toml_str(&duplicate)
                    .expect("fixture invariant")
                    .canonicalize_v2(),
            );
        }
        let root = root("semantics");
        let assembly = root.join("assemblies/runtime");
        owned(
            &assembly.join("src/generated/modules_gen.rs"),
            "pub const MODULES: u8 = 1;",
        );
        let catalog = make_catalog(vec![
            binding("runtime", "runtime.session", "v1", HASH_A),
            binding("platform", "platform.entry", "v1", HASH_B),
            binding("framework", "framework.alpha", "v1", HASH_A),
            binding("framework", "framework.beta", "v1", HASH_B),
        ]);
        let lock = compile_v2(&first, &root, &assembly, &catalog).expect("lock");
        same(
            serde_json::to_vec(&lock).expect("fixture invariant"),
            serde_json::to_vec(
                &compile_v2(&equivalent, &root, &assembly, &catalog).expect("fixture invariant"),
            )
            .expect("fixture invariant"),
        );
        for changed in [
            source.replacen("[\"runtime\", \"platform\"]", "[\"platform\", \"runtime\"]", 1),
            source.replace(framework, "{ id = \"framework.beta\", listener = \"admin\" }, { id = \"framework.alpha\", listener = \"primary\" }"),
            source.replace(
                "listeners = [{ kind = \"primary\", domains = [\"runtime\", \"platform\"] }, { kind = \"admin\", domains = [\"platform\"] }]",
                "listeners = [{ kind = \"admin\", domains = [\"platform\"] }, { kind = \"primary\", domains = [\"runtime\", \"platform\"] }]",
            ),
            source.replace("kind = \"primary\", domains = [\"runtime\", \"platform\"]", "kind = \"primary\", domains = [\"platform\", \"runtime\"]"),
        ] {
            let changed = canonical(&changed, framework);
            assert_ne!(first.manifest_digest(), changed.manifest_digest());
            assert_ne!(lock.fingerprint().as_str(), compile_v2(&changed, &root, &assembly, &catalog).expect("fixture invariant").fingerprint().as_str());
        }
        fs::remove_dir_all(root).expect("remove semantics");
    }

    #[test]
    fn generated_universe_is_sorted_sensitive_and_closed() {
        let root = root("generated");
        let generated = root.join("assemblies/runtime/src/generated");
        rejected(generated_digest_v2(&root, &generated));
        fs::create_dir_all(&generated).expect("generated root");
        rejected(generated_digest_v2(&root, &generated));
        provider_owned(
            &generated.join("zeta.rs"),
            &format!("const SECRET: &str = \"{SECRET}:a\";"),
        );
        owned(
            &generated.join("nested/alpha.rs"),
            "pub const ALPHA: u8 = 1;",
        );
        let entries = discover_generated_files_v2(&root, &generated).expect("entries");
        let paths = entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();
        same(
            serde_json::to_value(paths).expect("fixture invariant"),
            vectors()["generatedPaths"].clone(),
        );
        let first = generated_digest_v2(&root, &generated).expect("digest");
        provider_owned(
            &generated.join("zeta.rs"),
            &format!("const SECRET: &str = \"{SECRET}:b\";"),
        );
        assert_ne!(
            first,
            generated_digest_v2(&root, &generated).expect("changed digest")
        );
        fs::write(generated.join("foreign.rs"), "not owned").expect("foreign");
        rejected(generated_digest_v2(&root, &generated));
        fs::remove_file(generated.join("foreign.rs")).expect("remove foreign");
        fs::write(
            generated.join("foreign.rs"),
            format!("{GENERATED_PROVIDER_OWNERSHIP_MARKER} forged\n"),
        )
        .expect("forged marker");
        rejected(generated_digest_v2(&root, &generated));
        rejected(generated_digest_v2(&generated, &root));
        fs::remove_dir_all(&root).expect("remove root");
        fs::create_dir_all(root.join("assemblies/runtime/src")).expect("source root");
        fs::write(
            root.join("assemblies/runtime/src/generated"),
            "not a directory",
        )
        .expect("file root");
        rejected(generated_digest_v2(
            &root,
            &root.join("assemblies/runtime/src/generated"),
        ));
        fs::remove_dir_all(root).expect("remove file root");
    }

    #[test]
    fn repository_snapshot_final_check_rejects_generated_and_lock_mutation() {
        let root = root("snapshot-final-check");
        let assembly = root.join("assemblies/runtime");
        let generated = assembly.join("src/generated");
        owned(
            &generated.join("modules_gen.rs"),
            "pub const MODULES: u8 = 1;",
        );
        let expected = capture_generated_sources_v2(&root, &generated).expect("capture generated");
        verify_generated_sources_unchanged(&root, &generated, &expected)
            .expect("unchanged generated universe");
        provider_owned(
            &generated.join("providers_gen.rs"),
            "pub const PROVIDERS: u8 = 1;",
        );
        rejected(verify_generated_sources_unchanged(
            &root, &generated, &expected,
        ));

        let lock_path = assembly.join("assembly.lock.json");
        fs::write(&lock_path, b"old lock").expect("write lock");
        verify_snapshot_file_unchanged(&lock_path, b"old lock", "AssemblyLock")
            .expect("unchanged lock");
        fs::write(&lock_path, b"new lock").expect("mutate lock");
        rejected(verify_snapshot_file_unchanged(
            &lock_path,
            b"old lock",
            "AssemblyLock",
        ));
        fs::remove_dir_all(root).expect("remove snapshot fixture");
    }

    #[cfg(unix)]
    #[test]
    fn generated_universe_rejects_symlink_and_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::{ffi::OsStringExt, fs::symlink};
        let root = root("paths");
        let generated = root.join("assemblies/runtime/src/generated");
        owned(&generated.join("owned.rs"), "pub const OWNED: u8 = 1;");
        symlink(generated.join("owned.rs"), generated.join("alias.rs")).expect("symlink");
        rejected(generated_digest_v2(&root, &generated));
        fs::remove_file(generated.join("alias.rs")).expect("remove symlink");
        let invalid = generated.join(OsString::from_vec(vec![b'x', 0xff, b'.', b'r', b's']));
        let result = fs::write(
            &invalid,
            format!("{GENERATED_MODULE_OWNERSHIP_MARKER}\ninvalid"),
        );
        if let Err(error) = result {
            assert!(
                cfg!(target_os = "macos") && error.raw_os_error() == Some(92),
                "{error}"
            );
        } else {
            rejected(generated_digest_v2(&root, &generated));
        }
        fs::remove_dir_all(root).expect("remove paths");
    }

    #[test]
    fn contract_catalog_closes_selection_validation_and_tuple_order() {
        let manifest = canonical(
            &semantic("semanticToml"),
            "{ id = \"framework.status\", listener = \"admin\" }",
        );
        let vectors = vectors();
        let catalog = make_catalog(fixture_bindings(&vectors["contractOrderInput"]));
        let mut expected = fixture_bindings(&vectors["contractOrderExpected"]);
        expected.sort();
        same(
            select_contracts(&manifest, &catalog).expect("fixture invariant"),
            expected,
        );
        assert!(
            contracts_digest_v2(&manifest, &catalog)
                .expect("fixture invariant")
                .as_str()
                .starts_with("sha256:")
        );
        let duplicate = binding("runtime", "runtime.session", "v1", HASH_A);
        rejected(RepositoryContractCatalogV2::try_from_bindings(vec![
            duplicate.clone(),
            duplicate,
        ]));
        for bindings in vectors["contractInvalidSelections"]
            .as_array()
            .expect("fixture invariant")
        {
            rejected(select_contracts(
                &manifest,
                &make_catalog(fixture_bindings(bindings)),
            ));
        }
    }

    #[test]
    fn runtime_semantics_hash_binds_non_schema_contract_behavior() {
        let source = r#"
id = "runtime.profile"
kind = "http"
domain = "runtime"
version = "v1"
owner = "runtime"
consistencyLevel = "LocalTx"
lifecycle = "active"
path = "/api/v1/runtime/profile"
method = "GET"
[endpoints.http]
successStatus = 200
idempotency = "idempotent"
[endpoints.http.auth]
mode = "public"
[capabilities.localTx]
boundary = "single-domain"
txModel = "tenant-scoped-uow"
retry = "bounded-transient"
commitUnknown = "not-retryable"
"#;
        let baseline = ContractManifest::from_toml_str(source).expect("HTTP contract");
        let baseline_hash = runtime_semantics_hash_v2(&baseline).expect("baseline semantics");

        let mut mutations = Vec::new();
        let mut lifecycle = baseline.clone();
        lifecycle.lifecycle = Lifecycle::Deprecated;
        mutations.push(lifecycle);
        let mut path = baseline.clone();
        path.path = Some("/api/v1/runtime/profile-alt".to_owned());
        mutations.push(path);
        let mut method = baseline.clone();
        method.method = Some(HttpMethod::Post);
        mutations.push(method);
        let mut auth = baseline.clone();
        auth.endpoints
            .as_mut()
            .and_then(|endpoints| endpoints.http.as_mut())
            .and_then(|http| http.auth.as_mut())
            .expect("HTTP auth")
            .mode = HttpAuthMode::ServiceOwned;
        mutations.push(auth);
        let mut consistency = baseline.clone();
        consistency.consistency_level = ConsistencyLevel::LocalOnly;
        mutations.push(consistency);
        let mut capability = baseline.clone();
        capability
            .capabilities
            .local_tx
            .as_mut()
            .expect("localTx capability")
            .tx_model = LocalTxModel::RepoAtomicCas;
        mutations.push(capability);

        for changed in mutations {
            assert_ne!(
                baseline_hash,
                runtime_semantics_hash_v2(&changed).expect("changed semantics")
            );
        }

        let event = ContractManifest::from_toml_str(
            r#"
id = "runtime.changed"
kind = "event"
domain = "runtime"
version = "v1"
owner = "runtime"
consistencyLevel = "OutboxFact"
lifecycle = "active"
topic = "runtime.changed"
delivery = "at-least-once"
[[subscriptions]]
consumer = "observer"
group = "observer.runtime.changed"
execution = "adapter-native"
externalEffectPolicy = "transactional-only"
[subscriptions.topology]
partitionKey = "aggregate"
readiness = "required"
"#,
        )
        .expect("event contract");
        let event_hash = runtime_semantics_hash_v2(&event).expect("event semantics");
        let mut topic = event.clone();
        topic.topic = Some("runtime.changed-v2".to_owned());
        let mut delivery = event.clone();
        delivery.delivery = Some(Delivery::AtMostOnce);
        let mut subscriptions = event.clone();
        subscriptions.subscriptions[0].group = "observer.runtime.changed-v2".to_owned();
        let mut external_effect_policy = event.clone();
        external_effect_policy.subscriptions[0].external_effect_policy =
            ExternalEffectPolicy::Reconcile;
        for changed in [topic, delivery, subscriptions, external_effect_policy] {
            assert_ne!(
                event_hash,
                runtime_semantics_hash_v2(&changed).expect("changed event semantics")
            );
        }

        let saga = ContractManifest::from_toml_str(
            r#"
id = "billing.checkout"
kind = "saga"
domain = "billing"
version = "v1"
owner = "billing"
consistencyLevel = "WorkflowEventual"
lifecycle = "active"
[saga]
compensationOrder = "reverse"
steps = [{ name = "reserve", receiptSchema = "reserve.schema.json", effectScope = "billing.reserve", compensationEffectScope = "billing.release", idempotencyClass = "deterministic-key", compensationInput = "receipt", retryClass = "transient" }]
[saga.retry]
maxAttempts = 3
timeBudgetMillis = 30000
backoff = "fixed"
initialBackoffMillis = 5000
maxBackoffMillis = 5000
jitter = "none"
"#,
        )
        .expect("saga contract");
        let mut policy = saga.clone();
        policy.saga.as_mut().expect("saga").compensation_order = CompensationOrder::Reverse;
        policy
            .saga
            .as_mut()
            .expect("saga")
            .retry
            .initial_backoff_millis = 6000;
        assert_ne!(
            runtime_semantics_hash_v2(&saga).expect("saga semantics"),
            runtime_semantics_hash_v2(&policy).expect("changed saga semantics")
        );

        let outbox = ContractManifest::from_toml_str(
            r#"
id = "runtime.command"
kind = "http"
domain = "runtime"
version = "v1"
owner = "runtime"
consistencyLevel = "OutboxFact"
lifecycle = "active"
path = "/api/v1/runtime/command"
method = "POST"
[capabilities.outbox]
role = "producer"
atomicity = "same-transaction"
emits = ["runtime.alpha", "runtime.beta"]
"#,
        )
        .expect("outbox contract");
        let outbox_hash = runtime_semantics_hash_v2(&outbox).expect("outbox semantics");
        let mut reordered = outbox.clone();
        reordered
            .capabilities
            .outbox
            .as_mut()
            .expect("outbox capability")
            .emits
            .reverse();
        assert_eq!(
            outbox_hash,
            runtime_semantics_hash_v2(&reordered).expect("reordered outbox semantics")
        );
        let mut duplicate = outbox;
        duplicate
            .capabilities
            .outbox
            .as_mut()
            .expect("outbox capability")
            .emits
            .push("runtime.alpha".to_owned());
        rejected(runtime_semantics_hash_v2(&duplicate));
    }

    #[test]
    fn repository_verified_typestate_binds_discovered_contract_semantics() {
        let root = root("repository-verified");
        fs::create_dir_all(&root).expect("repository root");
        let root = fs::canonicalize(root).expect("canonical repository root");
        let assembly = root.join("assemblies/runtime");
        let assembly_source = semantic("semanticToml").replace("$FRAMEWORK", "");
        fs::create_dir_all(&assembly).expect("assembly directory");
        fs::write(assembly.join("assembly.toml"), &assembly_source).expect("assembly manifest");
        owned(
            &assembly.join("src/generated/modules_gen.rs"),
            "pub const MODULES: u8 = 1;",
        );
        for domain in ["runtime", "platform"] {
            let contract_dir = root.join(format!("contracts/event/{domain}/v1"));
            fs::create_dir_all(&contract_dir).expect("contract directory");
            fs::write(
                contract_dir.join("payload.schema.json"),
                format!(r#"{{"title":"{domain}Event","type":"object"}}"#),
            )
            .expect("schema");
            fs::write(
                contract_dir.join("contract.toml"),
                format!(
                    r#"
id = "{domain}.event"
kind = "event"
domain = "{domain}"
version = "v1"
owner = "{domain}"
consistencyLevel = "OutboxFact"
lifecycle = "active"
topic = "{domain}.event"
delivery = "at-least-once"
[schemas]
payload = "payload.schema.json"
"#
                ),
            )
            .expect("manifest");
        }
        let before_contracts = inspect_contract_repository(&root.join("contracts"))
            .and_then(|inspection| inspection.promote())
            .expect("discovery");
        let before_schema_hash = before_contracts[0].schema_hash().to_owned();
        assert_eq!(
            before_schema_hash,
            "sha256:f33fb685e97cae89b698a98304ab67ec085f9eb3c63d58452dd378290a52b55a"
        );
        let source = RepositoryAssemblyManifestV2::discover_v2(&root, &assembly)
            .expect("repository manifest source");
        assert_eq!(source.canonical().name(), "runtime");
        assert_eq!(source.assembly_dir(), assembly);
        assert_eq!(source.source_label(), "assemblies/runtime/assembly.toml");
        let first = RepositoryVerifiedAssemblyLock::compile_v2(&source).expect("verified lock");
        let parsed = ParsedAssemblyLock::from_json_slice(
            &serde_json::to_vec(&first).expect("verified lock JSON"),
        )
        .expect("parsed lock");

        let changed_assembly_source =
            assembly_source.replace("profile = \"demo\"", "profile = \"production\"");
        fs::write(assembly.join("assembly.toml"), &changed_assembly_source)
            .expect("change assembly manifest after discovery");
        assert_eq!(
            RepositoryVerifiedAssemblyLock::compile_v2(&source)
                .err()
                .expect("stale source must not compile")
                .stage(),
            AssemblyLockErrorStage::Manifest
        );
        assert_eq!(
            parsed
                .verify_repository_v2(&source)
                .err()
                .expect("stale source must not verify")
                .stage(),
            AssemblyLockErrorStage::Manifest
        );
        fs::write(assembly.join("assembly.toml"), &assembly_source)
            .expect("restore assembly manifest");

        let parsed = ParsedAssemblyLock::from_json_slice(
            &serde_json::to_vec(&first).expect("verified lock JSON"),
        )
        .expect("parsed lock");

        let identity_manifest = root.join("contracts/event/runtime/v1/contract.toml");
        let changed_source = fs::read_to_string(&identity_manifest)
            .expect("read identity manifest")
            .replace("lifecycle = \"active\"", "lifecycle = \"deprecated\"");
        fs::write(&identity_manifest, changed_source).expect("change runtime semantics");
        let after_contracts = inspect_contract_repository(&root.join("contracts"))
            .and_then(|inspection| inspection.promote())
            .expect("rediscovery");
        let after_schema_hash = after_contracts[0].schema_hash();
        assert_eq!(before_schema_hash, after_schema_hash);

        let changed =
            RepositoryVerifiedAssemblyLock::compile_v2(&source).expect("changed verified lock");
        assert_eq!(first.digests().manifest(), changed.digests().manifest());
        assert_eq!(first.digests().generated(), changed.digests().generated());
        assert_ne!(first.digests().contracts(), changed.digests().contracts());
        assert_ne!(first.fingerprint().as_str(), changed.fingerprint().as_str());
        rejected(parsed.verify_repository_v2(&source));
        rejected(RepositoryAssemblyManifestV2::discover_v2(
            &root.join("assemblies/.."),
            &assembly,
        ));

        let mismatched = root.join("assemblies/other");
        fs::create_dir_all(&mismatched).expect("mismatched assembly directory");
        fs::write(mismatched.join("assembly.toml"), &assembly_source)
            .expect("mismatched assembly manifest");
        owned(
            &mismatched.join("src/generated/modules_gen.rs"),
            "pub const MODULES: u8 = 1;",
        );
        rejected(RepositoryAssemblyManifestV2::discover_v2(
            &root,
            &mismatched,
        ));

        fs::write(
            root.join("contracts/event/runtime/v1/payload.schema.json"),
            br#"{"title":"IdentityEvent""#,
        )
        .expect("malformed schema fixture");
        assert_eq!(
            RepositoryVerifiedAssemblyLock::compile_v2(&source)
                .err()
                .expect("malformed contract schema must not mint AssemblyLock")
                .stage(),
            AssemblyLockErrorStage::ContractCatalog
        );

        let synthetic = root.join("synthetic/runtime");
        fs::create_dir_all(&synthetic).expect("synthetic assembly directory");
        fs::write(synthetic.join("assembly.toml"), &assembly_source)
            .expect("synthetic assembly manifest");
        owned(
            &synthetic.join("src/generated/modules_gen.rs"),
            "pub const MODULES: u8 = 1;",
        );
        rejected(RepositoryAssemblyManifestV2::discover_v2(&root, &synthetic));
        fs::remove_dir_all(root).expect("remove repository");
    }

    #[test]
    fn parsed_reader_is_strict_and_secret_opaque() {
        let root = root("reader");
        let assembly = root.join("assemblies/runtime");
        owned(
            &assembly.join("src/generated/modules_gen.rs"),
            &format!("const VALUE: &str = \"{SECRET}:a\";"),
        );
        let manifest = canonical(&semantic("semanticToml"), "");
        let catalog = make_catalog(fixture_bindings(&vectors()["baseContracts"]));
        let first = compile_v2(&manifest, &root, &assembly, &catalog).expect("lock");
        owned(
            &assembly.join("src/generated/modules_gen.rs"),
            &format!("const VALUE: &str = \"{SECRET}:b\";"),
        );
        let lock = compile_v2(&manifest, &root, &assembly, &catalog).expect("changed lock");
        assert_eq!(first.digests().manifest(), lock.digests().manifest());
        assert_eq!(first.digests().contracts(), lock.digests().contracts());
        assert_ne!(first.digests().generated(), lock.digests().generated());
        assert_ne!(first.fingerprint().as_str(), lock.fingerprint().as_str());
        let bytes = serde_json::to_vec(&lock).expect("lock JSON");
        let text = std::str::from_utf8(&bytes).expect("UTF-8");
        let unsigned = canonical_bytes(&UnsignedLock {
            schema_version: SCHEMA_VERSION,
            identity: &lock.identity,
            digests: &lock.digests,
        })
        .expect("unsigned");
        for carrier in [
            text,
            std::str::from_utf8(&unsigned).expect("fixture invariant"),
            include_str!("../tests/fixtures/assembly-lock-v2-vectors.json"),
            include_str!("../schemas/assembly-lock.schema.json"),
        ] {
            assert!(!carrier.contains(SECRET));
        }
        same(
            ParsedAssemblyLock::from_json_slice(&bytes)
                .expect("fixture invariant")
                .fingerprint()
                .as_str(),
            lock.fingerprint().as_str(),
        );
        let duplicate_digest = format!(
            "\"manifest\":\"{}\",\"manifest\":\"",
            lock.digests().manifest()
        );
        for malformed in [
            text.replace("\"schemaVersion\":2", "\"schemaVersion\":1"),
            text.replacen("sha256:", "sha512:", 1),
            text.replacen("sha256:", "sha256:AAAA", 1),
            text.replace("\"name\":\"runtime\"", "\"name\":\"   \""),
            text.replace(
                "\"name\":\"runtime\"",
                "\"name\":\"runtime\",\"name\":\"other\"",
            ),
            text.replace(
                "\"profile\":\"demo\"",
                "\"profile\":\"demo\",\"alias\":true",
            ),
            text.replace("\"manifest\":\"", &duplicate_digest),
            text.replace("\"contracts\":\"", "\"legacy\":true,\"contracts\":\""),
            text.replace("\"fingerprint\":\"", "\"legacy\":true,\"fingerprint\":\""),
            text.replace(lock.fingerprint().as_str(), HASH_A),
        ] {
            rejected(ParsedAssemblyLock::from_json_slice(malformed.as_bytes()));
        }
        fs::remove_dir_all(root).expect("remove reader");
    }

    #[test]
    fn fingerprint_mismatch_reports_expected_actual_and_recovery() {
        let identity = AssemblyIdentity {
            name: "runtime".to_owned(),
            profile: AssemblyProfile::Production,
        };
        let digests = AssemblyDigests {
            manifest: digest(HASH_A),
            generated: digest(HASH_B),
            contracts: digest(HASH_A),
        };
        let expected = fingerprint_for(&identity, &digests).expect("expected fingerprint");
        let wire = serde_json::json!({
            "schemaVersion": SCHEMA_VERSION,
            "identity": { "name": identity.name(), "profile": identity.profile() },
            "digests": {
                "manifest": digests.manifest(),
                "generated": digests.generated(),
                "contracts": digests.contracts(),
            },
            "fingerprint": HASH_A,
        });

        let result = ParsedAssemblyLock::from_json_slice(
            &serde_json::to_vec(&wire).expect("mismatched lock JSON"),
        );
        assert!(result.is_err(), "mismatched fingerprint must fail");
        let error = result.err().expect("asserted error");
        assert_eq!(
            error.to_string(),
            format!(
                "AssemblyLock fingerprint mismatch: expected `{expected}`, actual `{HASH_A}`; regenerate the lock file"
            )
        );
    }
    fn assert_closed(value: &serde_json::Value, fields: &[&str]) {
        let fields = fields.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(value["additionalProperties"], false);
        same(
            value["properties"]
                .as_object()
                .expect("fixture invariant")
                .keys()
                .map(String::as_str)
                .collect(),
            fields.clone(),
        );
        same(
            value["required"]
                .as_array()
                .expect("fixture invariant")
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect(),
            fields,
        );
    }

    #[test]
    fn derived_schema_structurally_matches_closed_contract() {
        let schema =
            serde_json::to_value(schemars::schema_for!(AssemblyLock)).expect("fixture invariant");
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/assembly-lock.schema.json"))
                .expect("fixture invariant");
        assert_eq!(
            contract["$id"],
            "https://rss.local/assembly-schema/assembly-lock.schema.json"
        );
        let root_fields = ["schemaVersion", "identity", "digests", "fingerprint"];
        assert_closed(&schema, &root_fields);
        assert_closed(&contract, &root_fields);
        let derived = &schema;
        assert_eq!(derived["properties"]["schemaVersion"]["const"], 2);
        assert_eq!(contract["properties"]["schemaVersion"]["const"], 2);
        let definitions = &derived["definitions"];
        let identity_fields = ["name", "profile"];
        let identity = &definitions["AssemblyIdentity"];
        let target_identity = &contract["definitions"]["identity"];
        assert_closed(identity, &identity_fields);
        assert_closed(target_identity, &identity_fields);
        for candidate in [identity, target_identity] {
            assert_eq!(candidate["properties"]["name"]["minLength"], 1);
            assert_eq!(
                candidate["properties"]["name"]["pattern"],
                NON_BLANK_NAME_PATTERN
            );
        }
        let profiles = serde_json::json!(["production", "demo", "test"]);
        assert_eq!(definitions["AssemblyProfile"]["enum"], profiles);
        assert_eq!(target_identity["properties"]["profile"]["enum"], profiles);
        let digest_fields = ["manifest", "generated", "contracts"];
        let digests = &definitions["AssemblyDigests"];
        assert_closed(digests, &digest_fields);
        assert_closed(&contract["definitions"]["digests"], &digest_fields);
        let pattern = &contract["definitions"]["sha256"]["pattern"];
        assert_eq!(derived["properties"]["fingerprint"]["pattern"], *pattern);
        for field in digest_fields {
            assert_eq!(digests["properties"][field]["pattern"], *pattern);
        }
    }
}
