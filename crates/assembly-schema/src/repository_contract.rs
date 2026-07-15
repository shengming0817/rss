//! Complete repository contract discovery shared by codegen and AssemblyLock.

use crate::contract_manifest::ContractManifest;
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
