//! Real `.crate` → local registry → independent locked/offline consumer proof.

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use workspacefacts::{
    DependencyKind, DependencyResolution, DependencySource, PublicApiOwner, WorkspaceFacts,
};

pub(crate) fn run_command() -> Result<()> {
    let root = crate::workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let facts = command_facts.get()?;
    let surface = crate::publicapi::validated_release_surface(&root, facts)?;
    run(&root, facts, &surface)
}

pub(crate) fn run(
    root: &Path,
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
) -> Result<()> {
    let plan = ReleaseProofPlan::derive(facts, surface)?;
    let temp = TempProof::new()?;
    let target = temp.root.join("target");
    package(root, &target, &plan)?;
    let package = target
        .join("package")
        .join(format!("{}-{}.crate", plan.package, plan.version));
    if !package.is_file() {
        bail!("cargo package did not produce {}", package.display());
    }

    let registry = temp.root.join("registry");
    let index = registry.join("index");
    let index_entry = index.join(index_relative_path(&plan.package));
    fs::create_dir_all(index_entry.parent().context("index path has no parent")?)?;
    let download = registry
        .join("crates")
        .join(&plan.package)
        .join(&plan.version)
        .join("download");
    fs::create_dir_all(download.parent().context("download path has no parent")?)?;
    fs::copy(&package, &download)?;
    let checksum = format!("{:x}", Sha256::digest(fs::read(&package)?));
    let download_root = file_url(&registry.join("crates"))?;
    fs::write(
        index.join("config.json"),
        serde_json::to_vec(&json!({ "dl": download_root, "api": null }))?,
    )?;
    fs::write(
        index_entry,
        format!("{}\n", plan.registry_record(&checksum)),
    )?;
    init_git(&index)?;

    let consumer = temp.root.join("consumer");
    copy_tree(
        &root.join("xtask/tests/fixtures/platform_public_consumer"),
        &consumer,
    )?;
    render_consumer_manifest(&consumer.join("Cargo.toml"), &plan)?;
    fs::create_dir_all(consumer.join(".cargo"))?;
    fs::write(
        consumer.join(".cargo/config.toml"),
        format!("[registries.local]\nindex = {:?}\n", file_url(&index)?),
    )?;
    run_cargo(
        crate::cmd::CargoSubcommand::GenerateLockfile,
        &[],
        &consumer,
        "generate independent Cargo.lock",
    )?;
    run_cargo(
        crate::cmd::CargoSubcommand::Fetch,
        &["--locked"],
        &consumer,
        "fetch the local-registry crate archive",
    )?;
    init_git(&consumer)?;
    run_cargo(
        crate::cmd::CargoSubcommand::Check,
        &["--locked", "--offline"],
        &consumer,
        "build independent local-registry consumer",
    )?;
    let receipt = run_cargo_output(
        crate::cmd::CargoSubcommand::Run,
        &["--locked", "--offline"],
        &consumer,
        "run independent T2 consumer",
    )?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt.stdout)
        .context("T2 consumer stdout is not the structured receipt")?;
    validate_receipt(&receipt)?;
    println!(
        "package-proof: {}@{} real .crate local-registry T2 passed",
        plan.package, plan.version
    );
    Ok(())
}

struct ReleaseProofPlan {
    package: String,
    version: String,
    dependencies: Vec<serde_json::Value>,
    features: BTreeMap<String, std::collections::BTreeSet<String>>,
}

impl ReleaseProofPlan {
    fn derive(
        facts: &WorkspaceFacts,
        surface: &crate::release_surface::ReleaseSurface,
    ) -> Result<Self> {
        let selected = surface
            .packages()
            .iter()
            .filter(|package| package.public_api_owner() == PublicApiOwner::PlatformPublic)
            .collect::<Vec<_>>();
        if selected.len() != 1 {
            bail!("package proof requires exactly one Platform Public release package");
        }
        let release = selected[0];
        let package = facts
            .workspace_packages()
            .into_iter()
            .find(|candidate| candidate.key().as_str() == release.package())
            .context("Platform Public release package is absent from workspace facts")?;
        if package.version() != release.version() {
            bail!("Platform Public Release Surface version drifted from workspace facts");
        }
        let key = facts.package_key(release.package())?;
        let mut dependencies = Vec::new();
        for dependency in facts.direct_dependencies_for(&key)? {
            if dependency.kind() == DependencyKind::Dev {
                continue;
            }
            if !dependency.unconditional() {
                bail!("package proof requires an owned target expression projection");
            }
            let registry = match dependency.source() {
                DependencySource::Registry { url } | DependencySource::Sparse { url } => url,
                _ => bail!(
                    "Platform Public package proof forbids non-registry production dependencies"
                ),
            };
            let resolved = match dependency.resolution() {
                DependencyResolution::Resolved(package) => package.as_str(),
                DependencyResolution::Unresolved => {
                    bail!("release dependency identity is unresolved")
                }
            };
            let package_rename = (resolved != dependency.name()).then_some(resolved);
            let kind = match dependency.kind() {
                DependencyKind::Normal => "normal",
                DependencyKind::Build => "build",
                DependencyKind::Dev => unreachable!(),
            };
            dependencies.push(json!({
                "name": dependency.name(),
                "req": dependency.version_requirement().to_string(),
                "features": dependency.requested_features(),
                "optional": dependency.optional(),
                "default_features": dependency.uses_default_features(),
                "target": null,
                "kind": kind,
                "registry": registry,
                "package": package_rename,
            }));
        }
        Ok(Self {
            package: release.package().to_owned(),
            version: release.version().to_string(),
            dependencies,
            features: package.publish_metadata().features().clone(),
        })
    }

    fn registry_record(&self, checksum: &str) -> serde_json::Value {
        json!({
            "name": self.package,
            "vers": self.version,
            "deps": self.dependencies,
            "cksum": checksum,
            "features": self.features,
            "yanked": false,
            "links": null,
        })
    }
}

fn expected_receipt() -> serde_json::Value {
    json!({
        "contract": "runtime.inventory",
        "subjectMatched": true,
        "tenantMatched": true,
        "permissionMatched": true,
        "requestIdMatched": true,
        "dispatch": true,
        "conditionsRead": true,
        "diagnosticsRead": true,
        "shutdown": true,
        "stoppedFailClosed": true
    })
}

fn validate_receipt(receipt: &serde_json::Value) -> Result<()> {
    if receipt != &expected_receipt() {
        bail!("T2 consumer receipt is incomplete or non-canonical");
    }
    Ok(())
}

fn package(root: &Path, target: &Path, plan: &ReleaseProofPlan) -> Result<()> {
    let target = target
        .to_str()
        .context("package proof target path is not UTF-8")?;
    run_cargo(
        crate::cmd::CargoSubcommand::Package,
        &["-p", &plan.package, "--locked", "--target-dir", target],
        root,
        "build real crate archive",
    )
}

fn run_cargo(
    subcommand: crate::cmd::CargoSubcommand,
    args: &[&str],
    cwd: &Path,
    operation: &str,
) -> Result<()> {
    let _ = run_cargo_output(subcommand, args, cwd, operation)?;
    Ok(())
}

fn run_cargo_output(
    subcommand: crate::cmd::CargoSubcommand,
    args: &[&str],
    cwd: &Path,
    operation: &str,
) -> Result<std::process::Output> {
    let output = crate::cmd::cargo_cmd(subcommand, args, &[], Some(cwd))
        .output()
        .with_context(|| operation.to_owned())?;
    if !output.status.success() {
        bail!(
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn render_consumer_manifest(path: &Path, plan: &ReleaseProofPlan) -> Result<()> {
    let template = fs::read_to_string(path)?;
    let rendered = template
        .replace("__RELEASE_PACKAGE__", &plan.package)
        .replace("__RELEASE_VERSION__", &plan.version);
    if rendered.contains("__RELEASE_") {
        bail!("package consumer manifest contains an unresolved release placeholder");
    }
    fs::write(path, rendered)?;
    Ok(())
}

fn index_relative_path(package: &str) -> PathBuf {
    match package.len() {
        1 => PathBuf::from("1").join(package),
        2 => PathBuf::from("2").join(package),
        3 => PathBuf::from("3").join(&package[..1]).join(package),
        _ => PathBuf::from(&package[..2])
            .join(&package[2..4])
            .join(package),
    }
}

fn init_git(root: &Path) -> Result<()> {
    for args in [&["init", "-q"][..], &["add", "."][..]] {
        let output = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            args,
            &[],
            Some(root),
        )
        .output()?;
        if !output.status.success() {
            bail!("git fixture initialization failed");
        }
    }
    let mut commit = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["commit", "-qm", "package proof fixture"],
        &[],
        Some(root),
    );
    let output = commit
        .env("GIT_AUTHOR_NAME", "RSS package proof")
        .env("GIT_AUTHOR_EMAIL", "package-proof@invalid")
        .env("GIT_COMMITTER_NAME", "RSS package proof")
        .env("GIT_COMMITTER_EMAIL", "package-proof@invalid")
        .output()?;
    if !output.status.success() {
        bail!("git fixture commit failed");
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            bail!("package proof fixture contains a non-file entry");
        }
    }
    Ok(())
}

fn file_url(path: &Path) -> Result<String> {
    let canonical = fs::canonicalize(path)?;
    let text = canonical
        .to_str()
        .context("local registry path is not UTF-8")?;
    Ok(format!("file://{text}"))
}

struct TempProof {
    root: PathBuf,
}
impl TempProof {
    #[allow(
        clippy::disallowed_methods,
        reason = "wall time is only entropy in an atomically reserved temporary path, never a domain clock"
    )]
    fn new() -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("package proof system clock is before the Unix epoch")?
            .as_nanos();
        for _ in 0..32 {
            let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "rss-package-proof-{}-{epoch}-{nonce}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self { root }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        bail!("package proof could not atomically reserve a temporary root")
    }
}
impl Drop for TempProof {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn t2_receipt_requires_every_stage_and_exact_identity() {
        let green = expected_receipt();
        assert!(validate_receipt(&green).is_ok());
        for field in [
            "contract",
            "subjectMatched",
            "tenantMatched",
            "permissionMatched",
            "requestIdMatched",
            "dispatch",
            "conditionsRead",
            "diagnosticsRead",
            "shutdown",
            "stoppedFailClosed",
        ] {
            let mut red = green.clone();
            red.as_object_mut().expect("receipt object").remove(field);
            assert!(validate_receipt(&red).is_err(), "missing {field} must fail");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn release_proof_plan_is_derived_from_canonical_workspace_facts() {
        let root = crate::workspace_root().expect("workspace root");
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get().expect("workspace facts");
        let surface = crate::publicapi::validated_release_surface(&root, facts)
            .expect("validated release surface");
        let plan = ReleaseProofPlan::derive(facts, &surface).expect("release proof plan");
        assert_eq!(plan.package, "rss-platform");
        assert_eq!(plan.version, "0.1.0");
        assert!(plan.dependencies.iter().all(|dependency| {
            dependency["registry"].as_str().is_some()
                && dependency["target"].is_null()
                && dependency["kind"] != "dev"
        }));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn temporary_roots_are_atomically_unique() {
        let first = TempProof::new().expect("first temp root");
        let second = TempProof::new().expect("second temp root");
        assert_ne!(first.root, second.root);
        assert!(first.root.is_dir() && second.root.is_dir());
    }

    #[test]
    fn package_proof_has_no_parallel_cargo_metadata_or_fixed_archive_owner() {
        let source = include_str!("package_proof.rs");
        for forbidden in [
            concat!("metadata_", "json("),
            concat!("const ", "PACKAGE:"),
            concat!("const ", "VERSION:"),
            concat!(".cache/cargo-target", "/package"),
        ] {
            assert!(
                !source.contains(forbidden),
                "parallel fact owner: {forbidden}"
            );
        }
    }

    #[test]
    fn registry_index_paths_follow_cargo_layout() {
        assert_eq!(index_relative_path("a"), PathBuf::from("1/a"));
        assert_eq!(index_relative_path("ab"), PathBuf::from("2/ab"));
        assert_eq!(index_relative_path("abc"), PathBuf::from("3/a/abc"));
        assert_eq!(
            index_relative_path("rss-platform"),
            PathBuf::from("rs/s-/rss-platform")
        );
    }
}
