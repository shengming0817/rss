//! Real `.crate` → local registry → independent locked/offline consumer proof.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use workspacefacts::{
    BuildPlatforms, BuildSelection, BuildSide, CargoPlatform, DependencyKind, DependencyResolution,
    DependencySource, FeatureSelection, ResolverVersion, WorkspaceFacts,
};

/// INVARIANT: RELEASE-PACKAGE-PROOF-COVERAGE-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "proof_behavior_is_closed_and_unknown_release_packages_fail", anti_vacuity = "release_proof_plans_are_derived_from_the_complete_release_surface" }.
/// Every package selected by the validated Release Surface is planned and executed exactly once.
/// The closed behavior projection supplies only package-specific consumer semantics; it cannot
/// select, omit, or invent lifecycle entries.
///
/// INVARIANT: RELEASE-PACKAGE-SAME-HEAD-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "vcs_revision_requires_exact_clean_head" }.
/// The proof packages a tracked-clean checkout without `--allow-dirty`, parses the archive's
/// `.cargo_vcs_info.json`, and requires its revision to equal the checkout HEAD.
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
    require_tracked_clean(root)?;
    let head = crate::cmd::source_revision(root)?;
    let plans = PackageProofPlan::derive_all(facts, surface)?;
    if plans.is_empty() {
        bail!("package proof requires at least one selected Release Surface package");
    }
    let temp = TempProof::new()?;
    let target = temp.root.join("target");
    let unpacked = temp.root.join("unpacked");
    fs::create_dir_all(&unpacked)?;
    let mut artifacts = Vec::with_capacity(plans.len());
    for plan in &plans {
        package(root, &target, plan)?;
        let archive = target
            .join("package")
            .join(format!("{}-{}.crate", plan.package, plan.version));
        if !archive.is_file() {
            bail!("cargo package did not produce {}", archive.display());
        }
        let crate_root = extract_archive(&archive, &unpacked)?;
        validate_archive(plan, &crate_root, &head)
            .with_context(|| format!("archive validation failed for `{}`", plan.package))?;
        run_archive_matrix(plan, &crate_root, &temp.root)
            .with_context(|| format!("archive matrix failed for `{}`", plan.package))?;
        let checksum = format!("{:x}", Sha256::digest(fs::read(&archive)?));
        artifacts.push(PackageArtifact {
            plan,
            archive,
            checksum,
        });
    }

    let registry = temp.root.join("registry");
    let index = registry.join("index");
    fs::create_dir_all(registry.join("crates"))?;
    fs::create_dir_all(&index)?;
    let download_root = file_url(&registry.join("crates"))?;
    fs::write(
        index.join("config.json"),
        serde_json::to_vec(&json!({ "dl": download_root, "api": null }))?,
    )?;
    for artifact in &artifacts {
        let plan = artifact.plan;
        let index_entry = index.join(index_relative_path(&plan.package));
        fs::create_dir_all(index_entry.parent().context("index path has no parent")?)?;
        let download = registry
            .join("crates")
            .join(&plan.package)
            .join(&plan.version)
            .join("download");
        fs::create_dir_all(download.parent().context("download path has no parent")?)?;
        fs::copy(&artifact.archive, &download)?;
        fs::write(
            index_entry,
            format!("{}\n", plan.registry_record(&artifact.checksum)),
        )?;
    }
    init_git(&index)?;

    let mut executed = BTreeSet::new();
    for artifact in &artifacts {
        run_consumer(root, artifact.plan, &index, &temp.root).with_context(|| {
            format!(
                "independent consumer proof failed for `{}`",
                artifact.plan.package
            )
        })?;
        if !executed.insert(artifact.plan.package.clone()) {
            bail!("package proof executed a selected package more than once");
        }
        println!(
            "package-proof: package={} version={} head={} sha256={} axes=content,vcs,default,no-default,all-features,msrv,docs,doctest,consumer",
            artifact.plan.package, artifact.plan.version, head, artifact.checksum
        );
    }
    validate_execution_coverage(&plans, &executed)?;
    Ok(())
}

fn validate_execution_coverage(
    plans: &[PackageProofPlan],
    executed: &BTreeSet<String>,
) -> Result<()> {
    let planned = plans
        .iter()
        .map(|plan| plan.package.clone())
        .collect::<BTreeSet<_>>();
    if executed != &planned {
        bail!("selected/planned/executed package proof sets differ");
    }
    Ok(())
}

struct PackageArtifact<'a> {
    plan: &'a PackageProofPlan,
    archive: PathBuf,
    checksum: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofBehavior {
    Platform,
    DiagContext,
    TraceContext,
}

impl ProofBehavior {
    fn for_package(package: &str) -> Result<Self> {
        match package {
            "rss-platform" => Ok(Self::Platform),
            "rss-diag-context" => Ok(Self::DiagContext),
            "rss-trace-context" => Ok(Self::TraceContext),
            _ => bail!("selected release package `{package}` has no closed proof behavior"),
        }
    }

    const fn fixture(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::DiagContext => "diag-context",
            Self::TraceContext => "trace-context",
        }
    }

    fn validate_receipt(self, receipt: &serde_json::Value) -> Result<()> {
        let expected = match self {
            Self::Platform => platform_receipt(),
            Self::DiagContext => diag_context_receipt(),
            Self::TraceContext => trace_context_receipt(),
        };
        if receipt != &expected {
            bail!("package consumer receipt is incomplete or non-canonical");
        }
        Ok(())
    }
}

struct PackageProofPlan {
    package: String,
    version: String,
    minimum_rust_version: String,
    dependencies: Vec<serde_json::Value>,
    features: BTreeMap<String, BTreeSet<String>>,
    behavior: ProofBehavior,
}

impl PackageProofPlan {
    fn derive_all(
        facts: &WorkspaceFacts,
        surface: &crate::release_surface::ReleaseSurface,
    ) -> Result<Vec<Self>> {
        surface
            .packages()
            .iter()
            .map(|release| Self::derive(facts, release))
            .collect()
    }

    fn derive(
        facts: &WorkspaceFacts,
        release: &crate::release_surface::ReleasePackage,
    ) -> Result<Self> {
        let package = facts
            .workspace_packages()
            .into_iter()
            .find(|candidate| candidate.key().as_str() == release.package())
            .context("selected release package is absent from workspace facts")?;
        if package.version() != release.version() {
            bail!("selected Release Surface version drifted from workspace facts");
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
                _ => bail!("release package proof forbids non-registry production dependencies"),
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
        let behavior = ProofBehavior::for_package(release.package())?;
        if behavior == ProofBehavior::TraceContext {
            validate_trace_context_default_closure(facts, &key)?;
        }
        Ok(Self {
            package: release.package().to_owned(),
            version: release.version().to_string(),
            minimum_rust_version: release.minimum_rust_version().to_string(),
            dependencies,
            features: package.publish_metadata().features().clone(),
            behavior,
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

/// INVARIANT: TRACE-CONTEXT-DEFAULT-CLOSURE-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "tests::trace_context_default_closure_rejects_forbidden_transitive_features", anti_vacuity = "tests::trace_context_default_closure_accepts_trace_only_graph|tests::release_proof_plans_are_derived_from_the_complete_release_surface" }.
fn validate_trace_context_default_closure(
    facts: &WorkspaceFacts,
    package: &workspacefacts::PackageKey,
) -> Result<()> {
    let target = CargoPlatform::build_target()?;
    let build = facts.resolve_build(BuildSelection::new(
        package.clone(),
        ResolverVersion::V2,
        FeatureSelection::Default,
        BuildPlatforms::new(target.clone(), target),
        BTreeSet::new(),
    ))?;
    for side in [BuildSide::Target, BuildSide::Host] {
        for package in [
            "opentelemetry",
            "opentelemetry_sdk",
            "tracing-opentelemetry",
        ] {
            for feature in ["metrics", "logs", "internal-logs", "testing"] {
                if !build.is_package_feature_enabled(side, package, feature) {
                    continue;
                }
                bail!(
                    "rss-trace-context default closure enables forbidden feature `{}/{}`",
                    package,
                    feature
                );
            }
        }
    }
    Ok(())
}

fn platform_receipt() -> serde_json::Value {
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

fn diag_context_receipt() -> serde_json::Value {
    json!({
        "package": "rss-diag-context",
        "maxLen": 128,
        "emptyRejected": true,
        "tooLongRejected": true,
        "invalidCharRejected": true,
        "ambientMissingFailOpen": true,
        "scopeRoundtrip": true,
        "nestedRestored": true,
        "sendSync": true
    })
}

fn trace_context_receipt() -> serde_json::Value {
    json!({
        "package": "rss-trace-context",
        "v00Roundtrip": true,
        "futureVersionAccepted": true,
        "malformedRejected": true,
        "oversizedRejected": true,
        "unsupportedRejected": true,
        "restoreRestored": true,
        "restoreUnavailable": true,
        "invalidStateDropped": true,
        "failOpenNoPanic": true
    })
}

fn package(root: &Path, target: &Path, plan: &PackageProofPlan) -> Result<()> {
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

fn require_tracked_clean(root: &Path) -> Result<()> {
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["status", "--porcelain", "--untracked-files=no"],
        &[],
        Some(root),
    )
    .output()?;
    if !output.status.success() || !output.stdout.is_empty() {
        bail!("package proof requires a tracked-clean checkout");
    }
    Ok(())
}

fn extract_archive(archive: &Path, destination: &Path) -> Result<PathBuf> {
    let archive = archive
        .to_str()
        .context("crate archive path is not UTF-8")?;
    let destination_text = destination
        .to_str()
        .context("crate extraction path is not UTF-8")?;
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::Tar,
        &["-xzf", archive, "-C", destination_text],
        &[],
        None,
    )
    .output()?;
    if !output.status.success() {
        bail!("crate archive extraction failed");
    }
    let stem = archive
        .strip_suffix(".crate")
        .context("crate archive does not have .crate suffix")?;
    let name = Path::new(stem)
        .file_name()
        .context("crate archive has no filename")?;
    Ok(destination.join(name))
}

#[derive(Deserialize)]
struct CargoVcsInfo {
    git: CargoVcsGit,
}

#[derive(Deserialize)]
struct CargoVcsGit {
    sha1: String,
    #[serde(default)]
    dirty: bool,
}

fn validate_vcs_revision(text: &str, head: &str) -> Result<()> {
    let info: CargoVcsInfo = serde_json::from_str(text).context("invalid .cargo_vcs_info.json")?;
    if info.git.dirty || info.git.sha1 != head {
        bail!("crate archive revision does not equal the clean checkout HEAD");
    }
    Ok(())
}

#[derive(Deserialize)]
struct PackagedManifest {
    package: PackagedPackage,
    #[serde(default)]
    lib: Option<PackagedTarget>,
    #[serde(default, rename = "bin")]
    bins: Vec<PackagedTarget>,
    #[serde(default)]
    example: Vec<PackagedTarget>,
    #[serde(default)]
    test: Vec<PackagedTarget>,
    #[serde(default)]
    bench: Vec<PackagedTarget>,
    #[serde(skip)]
    document: toml::Table,
}

#[derive(Deserialize)]
struct PackagedPackage {
    name: String,
    version: String,
    #[serde(rename = "rust-version")]
    rust_version: Option<String>,
    readme: Option<String>,
    #[serde(rename = "license-file")]
    license_file: Option<String>,
}

#[derive(Deserialize)]
struct PackagedTarget {
    path: Option<String>,
}

impl PackagedManifest {
    fn library_path(&self) -> &Path {
        self.lib
            .as_ref()
            .and_then(|target| target.path.as_deref())
            .map(Path::new)
            .unwrap_or_else(|| Path::new("src/lib.rs"))
    }

    fn declared_content(&self) -> Vec<&Path> {
        let mut paths = vec![Path::new("Cargo.toml"), self.library_path()];
        if let Some(readme) = self.package.readme.as_deref() {
            paths.push(Path::new(readme));
        }
        if let Some(license) = self.package.license_file.as_deref() {
            paths.push(Path::new(license));
        }
        for target in self
            .bins
            .iter()
            .chain(&self.example)
            .chain(&self.test)
            .chain(&self.bench)
        {
            if let Some(path) = target.path.as_deref() {
                paths.push(Path::new(path));
            }
        }
        paths
    }
}

fn parse_packaged_manifest(text: &str) -> Result<PackagedManifest> {
    let document = toml::from_str::<toml::Table>(text).context("invalid packaged Cargo.toml")?;
    let mut manifest = toml::from_str::<PackagedManifest>(text)
        .context("packaged Cargo.toml lacks required release metadata")?;
    manifest.document = document;
    Ok(manifest)
}

fn validate_packaged_dependencies(document: &toml::Table) -> Result<()> {
    fn validate_table(table: &toml::value::Table) -> Result<()> {
        for (name, dependency) in table {
            if let Some(detail) = dependency.as_table() {
                for forbidden in ["path", "git", "workspace"] {
                    if detail.contains_key(forbidden) {
                        bail!("packaged dependency `{name}` contains forbidden `{forbidden}`");
                    }
                }
                if !detail.contains_key("version") {
                    bail!("packaged dependency `{name}` has no registry version");
                }
            } else if !dependency.is_str() {
                bail!("packaged dependency `{name}` has an unsupported shape");
            }
        }
        Ok(())
    }
    for key in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if let Some(table) = document.get(key).and_then(toml::Value::as_table) {
            validate_table(table)?;
        }
    }
    if let Some(targets) = document.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            for key in ["dependencies", "build-dependencies", "dev-dependencies"] {
                if let Some(table) = target.get(key).and_then(toml::Value::as_table) {
                    validate_table(table)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_archive(plan: &PackageProofPlan, crate_root: &Path, head: &str) -> Result<()> {
    let manifest_text = fs::read_to_string(crate_root.join("Cargo.toml"))?;
    let manifest = parse_packaged_manifest(&manifest_text)?;
    let packaged_msrv = manifest
        .package
        .rust_version
        .as_deref()
        .context("packaged manifest has no rust-version")?;
    if manifest.package.name != plan.package
        || manifest.package.version != plan.version
        || parse_rust_version(packaged_msrv)?
            != semver::Version::parse(&plan.minimum_rust_version)
                .context("typed proof plan has invalid MSRV")?
    {
        bail!("packaged manifest identity or MSRV differs from the typed proof plan");
    }
    validate_packaged_dependencies(&manifest.document)?;
    validate_declared_content(&manifest, crate_root)?;
    if plan.behavior == ProofBehavior::TraceContext {
        let library = fs::read_to_string(crate_root.join(manifest.library_path()))?;
        let readme_path = manifest
            .package
            .readme
            .as_deref()
            .context("rss-trace-context archive has no README")?;
        let readme = fs::read_to_string(crate_root.join(readme_path))?;
        validate_trace_context_doctest_source(&library, &readme)?;
    }
    let vcs = fs::read_to_string(crate_root.join(".cargo_vcs_info.json"))?;
    validate_vcs_revision(&vcs, head)
}

/// INVARIANT: TRACE-CONTEXT-DOCTEST-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "tests::trace_context_doctest_source_rejects_unowned_or_empty_example", anti_vacuity = "tests::trace_context_archive_doctest_source_is_non_vacuous" }.
/// The archive matrix may claim its doctest axis only when the packaged README is the crate-level
/// rustdoc owner and contains at least one executable Rust fence.
fn validate_trace_context_doctest_source(library: &str, readme: &str) -> Result<()> {
    if !library
        .lines()
        .any(|line| line.trim() == "#![doc = include_str!(\"../README.md\")]")
    {
        bail!("rss-trace-context library does not include its packaged README as crate rustdoc");
    }
    if !readme.lines().any(|line| line.trim() == "```rust") {
        bail!("rss-trace-context README has no executable Rust doctest");
    }
    Ok(())
}

fn parse_rust_version(value: &str) -> Result<semver::Version> {
    let normalized = match value.bytes().filter(|byte| *byte == b'.').count() {
        0 => format!("{value}.0.0"),
        1 => format!("{value}.0"),
        _ => value.to_owned(),
    };
    semver::Version::parse(&normalized).context("packaged manifest has invalid rust-version")
}

fn validate_declared_content(manifest: &PackagedManifest, crate_root: &Path) -> Result<()> {
    for relative in manifest.declared_content() {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || !crate_root.join(relative).is_file()
        {
            bail!(
                "packaged manifest declares missing or unsafe content: {}",
                relative.display()
            );
        }
    }
    Ok(())
}

fn run_archive_matrix(plan: &PackageProofPlan, crate_root: &Path, proof_root: &Path) -> Result<()> {
    let target = proof_root.join("matrix-target").join(&plan.package);
    let target = target.to_str().context("matrix target path is not UTF-8")?;
    let env = [
        ("RUSTUP_TOOLCHAIN", plan.minimum_rust_version.as_str()),
        ("CARGO_TARGET_DIR", target),
    ];
    for (args, operation) in [
        (&["--locked", "--offline"][..], "archive default check"),
        (
            &["--locked", "--offline", "--no-default-features"][..],
            "archive no-default-features check",
        ),
        (
            &["--locked", "--offline", "--all-features"][..],
            "archive all-features check",
        ),
    ] {
        run_cargo_env(
            crate::cmd::CargoSubcommand::Check,
            args,
            &env,
            crate_root,
            operation,
        )?;
    }
    run_cargo_env(
        crate::cmd::CargoSubcommand::Doc,
        &["--locked", "--offline", "--no-deps", "--all-features"],
        &env,
        crate_root,
        "archive rustdoc",
    )?;
    run_cargo_env(
        crate::cmd::CargoSubcommand::Test,
        &["--locked", "--offline", "--doc", "--all-features"],
        &env,
        crate_root,
        "archive doctest",
    )
}

fn run_consumer(
    root: &Path,
    plan: &PackageProofPlan,
    index: &Path,
    proof_root: &Path,
) -> Result<()> {
    let consumer = proof_root.join("consumer").join(&plan.package);
    copy_tree(
        &root
            .join("xtask/tests/fixtures/package_proof")
            .join(plan.behavior.fixture()),
        &consumer,
    )?;
    render_consumer_manifest(&consumer.join("Cargo.toml"), plan)?;
    fs::create_dir_all(consumer.join(".cargo"))?;
    fs::write(
        consumer.join(".cargo/config.toml"),
        format!("[registries.local]\nindex = {:?}\n", file_url(index)?),
    )?;
    let env = [("RUSTUP_TOOLCHAIN", plan.minimum_rust_version.as_str())];
    run_cargo_env(
        crate::cmd::CargoSubcommand::GenerateLockfile,
        &[],
        &env,
        &consumer,
        "generate independent Cargo.lock",
    )?;
    run_cargo_env(
        crate::cmd::CargoSubcommand::Fetch,
        &["--locked"],
        &env,
        &consumer,
        "fetch local-registry crate archive",
    )?;
    init_git(&consumer)?;
    run_cargo_env(
        crate::cmd::CargoSubcommand::Check,
        &["--locked", "--offline"],
        &env,
        &consumer,
        "build independent local-registry consumer",
    )?;
    let receipt = run_cargo_output_env(
        crate::cmd::CargoSubcommand::Run,
        &["--locked", "--offline"],
        &env,
        &consumer,
        "run independent package consumer",
    )?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt.stdout)
        .context("package consumer stdout is not the structured receipt")?;
    plan.behavior.validate_receipt(&receipt)
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

fn run_cargo_env(
    subcommand: crate::cmd::CargoSubcommand,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: &Path,
    operation: &str,
) -> Result<()> {
    let _ = run_cargo_output_env(subcommand, args, env, cwd, operation)?;
    Ok(())
}

fn run_cargo_output_env(
    subcommand: crate::cmd::CargoSubcommand,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: &Path,
    operation: &str,
) -> Result<std::process::Output> {
    let output = crate::cmd::cargo_cmd(subcommand, args, env, Some(cwd))
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

fn render_consumer_manifest(path: &Path, plan: &PackageProofPlan) -> Result<()> {
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
    let url = url::Url::from_file_path(&canonical).map_err(|()| {
        anyhow::anyhow!(
            "local registry path cannot be represented as a file URL: {}",
            canonical.display()
        )
    })?;
    Ok(url.into())
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

    fn trace_context_closure_facts(
        dependency_feature: &str,
    ) -> anyhow::Result<(WorkspaceFacts, workspacefacts::PackageKey)> {
        use workspacefacts::testing::{
            path_dependency_with_features, path_package, path_package_id, resolve_node,
            resolve_node_with_features, target,
        };

        let root_path = "/workspace/crates/tracewire";
        let dependency_path = "/workspace/vendor/opentelemetry";
        let root = path_package(
            "rss-trace-context",
            root_path,
            vec![target(
                "rss_trace_context",
                "lib",
                "/workspace/crates/tracewire/src/lib.rs",
                true,
                &[],
            )],
            vec![path_dependency_with_features(
                "opentelemetry",
                dependency_path,
                false,
                false,
                &[dependency_feature],
            )],
            json!({"default": []}),
        );
        let dependency_features = serde_json::Map::from_iter([
            ("default".to_owned(), json!([])),
            (dependency_feature.to_owned(), json!([])),
        ]);
        let dependency = path_package(
            "opentelemetry",
            dependency_path,
            vec![target(
                "opentelemetry",
                "lib",
                "/workspace/vendor/opentelemetry/src/lib.rs",
                true,
                &[],
            )],
            vec![],
            serde_json::Value::Object(dependency_features),
        );
        let root_id = path_package_id(root_path);
        let dependency_id = path_package_id(dependency_path);
        let facts = crate::testutil::synthetic_workspace_facts_from_parts(
            Path::new("/workspace"),
            vec![root, dependency],
            vec![root_id.clone()],
            vec![
                resolve_node(&root_id, &[("opentelemetry", &dependency_id)]),
                resolve_node_with_features(&dependency_id, &[], &[dependency_feature]),
            ],
        )?;
        let key = facts.package_key("rss-trace-context")?;
        Ok((facts, key))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn trace_context_default_closure_rejects_forbidden_transitive_features() -> anyhow::Result<()> {
        for feature in ["metrics", "logs", "internal-logs", "testing"] {
            let (facts, key) = trace_context_closure_facts(feature)?;
            let error = validate_trace_context_default_closure(&facts, &key)
                .expect_err("forbidden OpenTelemetry feature must fail closed");
            assert!(error.to_string().contains(feature), "{error:#}");
        }
        Ok(())
    }

    #[test]
    fn trace_context_default_closure_accepts_trace_only_graph() -> anyhow::Result<()> {
        let (facts, key) = trace_context_closure_facts("trace")?;
        validate_trace_context_default_closure(&facts, &key)
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn t2_receipt_requires_every_stage_and_exact_identity() {
        let green = platform_receipt();
        assert!(ProofBehavior::Platform.validate_receipt(&green).is_ok());
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
            assert!(
                ProofBehavior::Platform.validate_receipt(&red).is_err(),
                "missing {field} must fail"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn diag_receipt_requires_every_public_behavior_axis() {
        let green = diag_context_receipt();
        assert!(ProofBehavior::DiagContext.validate_receipt(&green).is_ok());
        for field in [
            "package",
            "maxLen",
            "emptyRejected",
            "tooLongRejected",
            "invalidCharRejected",
            "ambientMissingFailOpen",
            "scopeRoundtrip",
            "nestedRestored",
            "sendSync",
        ] {
            let mut red = green.clone();
            red.as_object_mut().expect("receipt object").remove(field);
            assert!(
                ProofBehavior::DiagContext.validate_receipt(&red).is_err(),
                "missing {field} must fail"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn trace_receipt_requires_every_public_behavior_axis() {
        let green = trace_context_receipt();
        assert!(ProofBehavior::TraceContext.validate_receipt(&green).is_ok());
        for field in [
            "package",
            "v00Roundtrip",
            "futureVersionAccepted",
            "malformedRejected",
            "oversizedRejected",
            "unsupportedRejected",
            "restoreRestored",
            "restoreUnavailable",
            "invalidStateDropped",
            "failOpenNoPanic",
        ] {
            let mut red = green.clone();
            red.as_object_mut().expect("receipt object").remove(field);
            assert!(
                ProofBehavior::TraceContext.validate_receipt(&red).is_err(),
                "missing {field} must fail"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn trace_context_archive_doctest_source_is_non_vacuous() {
        let root = crate::workspace_root().expect("workspace root");
        let library = fs::read_to_string(root.join("crates/tracewire/src/lib.rs"))
            .expect("trace-context library source");
        let readme = fs::read_to_string(root.join("crates/tracewire/README.md"))
            .expect("trace-context README");
        assert!(validate_trace_context_doctest_source(&library, &readme).is_ok());
    }

    #[test]
    fn trace_context_doctest_source_rejects_unowned_or_empty_example() {
        const LIBRARY: &str = "#![doc = include_str!(\"../README.md\")]";
        const README: &str = "# candidate\n\n```rust\nassert!(true);\n```";
        assert!(validate_trace_context_doctest_source(LIBRARY, README).is_ok());
        assert!(validate_trace_context_doctest_source("pub struct Candidate;", README).is_err());
        assert!(validate_trace_context_doctest_source(LIBRARY, "# no example").is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn release_proof_plans_are_derived_from_the_complete_release_surface() {
        let root = crate::workspace_root().expect("workspace root");
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get().expect("workspace facts");
        let surface = crate::publicapi::validated_release_surface(&root, facts)
            .expect("validated release surface");
        let plans = PackageProofPlan::derive_all(facts, &surface).expect("release proof plans");
        assert_eq!(plans.len(), surface.packages().len());
        let projected = plans
            .iter()
            .map(|plan| (plan.package.as_str(), plan.behavior))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            projected,
            BTreeMap::from([
                ("rss-diag-context", ProofBehavior::DiagContext),
                ("rss-platform", ProofBehavior::Platform),
                ("rss-trace-context", ProofBehavior::TraceContext),
            ])
        );
        for plan in &plans {
            assert_eq!(plan.version, "0.1.0");
            assert_eq!(plan.minimum_rust_version, "1.96.0");
            assert!(plan.dependencies.iter().all(|dependency| {
                dependency["registry"].as_str().is_some()
                    && dependency["target"].is_null()
                    && dependency["kind"] != "dev"
            }));
        }
    }

    #[test]
    fn proof_behavior_is_closed_and_unknown_release_packages_fail() {
        assert_eq!(
            ProofBehavior::for_package("rss-platform").expect("platform behavior"),
            ProofBehavior::Platform
        );
        assert_eq!(
            ProofBehavior::for_package("rss-diag-context").expect("diag behavior"),
            ProofBehavior::DiagContext
        );
        assert_eq!(
            ProofBehavior::for_package("rss-trace-context").expect("trace behavior"),
            ProofBehavior::TraceContext
        );
        assert!(ProofBehavior::for_package("future-release").is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn proof_execution_coverage_is_exact_and_non_vacuous() {
        let root = crate::workspace_root().expect("workspace root");
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get().expect("workspace facts");
        let surface = crate::publicapi::validated_release_surface(&root, facts)
            .expect("validated release surface");
        let plans = PackageProofPlan::derive_all(facts, &surface).expect("release proof plans");
        let complete = plans
            .iter()
            .map(|plan| plan.package.clone())
            .collect::<BTreeSet<_>>();
        assert!(validate_execution_coverage(&plans, &complete).is_ok());
        let mut missing = complete.clone();
        missing.pop_first();
        assert!(validate_execution_coverage(&plans, &missing).is_err());
        let mut extra = complete;
        extra.insert("unselected-package".to_owned());
        assert!(validate_execution_coverage(&plans, &extra).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn packaged_manifest_validation_is_structured_and_fail_closed() {
        let valid = r#"
            [package]
            name = "rss-diag-context"
            version = "0.1.0"
            rust-version = "1.96"
            readme = "README.md"
            license-file = "LICENSE"

            [lib]
            path = "src/lib.rs"

            [features]
            default = []

            [dependencies.tokio]
            version = "1"
            default-features = false
        "#;
        let parsed = parse_packaged_manifest(valid).expect("valid packaged manifest");
        assert_eq!(parsed.package.name, "rss-diag-context");
        assert_eq!(parsed.library_path(), Path::new("src/lib.rs"));
        assert!(validate_packaged_dependencies(&parsed.document).is_ok());
        assert_eq!(
            parse_rust_version("1.96").expect("Cargo partial MSRV"),
            semver::Version::new(1, 96, 0)
        );

        let root = TempProof::new().expect("temporary package root");
        fs::write(root.root.join("Cargo.toml"), valid).expect("manifest fixture");
        fs::write(root.root.join("README.md"), "readme").expect("readme fixture");
        fs::write(root.root.join("LICENSE"), "license").expect("license fixture");
        fs::create_dir_all(root.root.join("src")).expect("source directory");
        assert!(validate_declared_content(&parsed, &root.root).is_err());
        fs::write(root.root.join("src/lib.rs"), "").expect("library fixture");
        assert!(validate_declared_content(&parsed, &root.root).is_ok());

        for forbidden in [
            valid.replace("version = \"1\"", "version = \"1\"\npath = \"../tokio\""),
            valid.replace(
                "version = \"1\"",
                "version = \"1\"\ngit = \"https://invalid\"",
            ),
            valid.replace("version = \"1\"", "workspace = true"),
        ] {
            let parsed = parse_packaged_manifest(&forbidden).expect("TOML remains structured");
            assert!(validate_packaged_dependencies(&parsed.document).is_err());
        }
    }

    #[test]
    fn vcs_revision_requires_exact_clean_head() {
        let clean = r#"{"git":{"sha1":"0123456789abcdef0123456789abcdef01234567"}}"#;
        assert!(validate_vcs_revision(clean, "0123456789abcdef0123456789abcdef01234567").is_ok());
        assert!(validate_vcs_revision(clean, "1123456789abcdef0123456789abcdef01234567").is_err());
        let dirty = r#"{"git":{"sha1":"0123456789abcdef0123456789abcdef01234567","dirty":true}}"#;
        assert!(validate_vcs_revision(dirty, "0123456789abcdef0123456789abcdef01234567").is_err());
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

    #[test]
    #[allow(clippy::expect_used)]
    fn file_urls_percent_encode_reserved_path_characters() {
        let root = TempProof::new().expect("temporary root");
        let reserved = root.root.join("registry # proof");
        fs::create_dir(&reserved).expect("reserved-character directory");
        let rendered = file_url(&reserved).expect("file URL");
        assert!(rendered.starts_with("file://"));
        assert!(rendered.contains("registry%20%23%20proof"));
        assert!(!rendered.contains('#'));
    }
}
