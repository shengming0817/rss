//! Real `.crate` → local registry → independent locked/offline consumer proof.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use workspacefacts::{
    BuildPlatforms, BuildSelection, BuildSide, CargoPlatform, DependencyKind, DependencyResolution,
    DependencySource, FeatureSelection, PublicApiOwner, ResolverVersion, WorkspaceFacts,
};

const STANDALONE_CONSUMER_PATH: &str = "consumers/standalone";
const STANDALONE_REGISTRY: &str = "rss-candidate";
const STANDALONE_REPOSITORY: &str = "https://github.com/shengming0817/rss-standalone-consumer.git";

/// INVARIANT: RELEASE-PACKAGE-PROOF-COVERAGE-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "proof_behavior_is_closed_and_unknown_release_packages_fail", anti_vacuity = "release_proof_plans_are_derived_from_the_complete_release_surface" }.
/// Every package selected by the validated Release Surface is planned and executed exactly once.
/// The closed behavior projection supplies only package-specific consumer semantics; it cannot
/// select, omit, or invent lifecycle entries.
///
/// INVARIANT: RELEASE-PACKAGE-SAME-HEAD-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "vcs_revision_requires_exact_clean_head" }.
/// The proof packages a tracked-clean checkout without `--allow-dirty`, parses the archive's
/// `.cargo_vcs_info.json`, and requires its revision to equal the checkout HEAD.
///
/// INVARIANT: RELEASE-STANDALONE-CONSUMER-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "tests::standalone_manifest_requires_exact_registry_candidates|tests::standalone_metadata_rejects_renamed_internal_packages|tests::standalone_metadata_rejects_non_registry_source|tests::standalone_lock_requires_same_artifact_checksums|tests::gitlink_parser_requires_exact_path_and_mode|tests::standalone_checkout_rejects_missing_dirty_drift_and_hidden_flags|tests::standalone_checkout_rejects_noncanonical_remote", anti_vacuity = "run_standalone_consumer|tests::standalone_checkout_materializes_pinned_commit_blobs" }.
/// The pinned external Git repository consumes both standalone candidates from this invocation's
/// same-HEAD local registry. Its manifest, resolved graph, generated lock and executed tests must
/// agree exactly; path/git/workspace sources and every other RSS package fail closed.
pub(crate) fn run_command(export_candidate_bundle: Option<&Path>) -> Result<()> {
    let root = crate::workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let facts = command_facts.get()?;
    let surface = crate::publicapi::validated_release_surface(&root, facts)?;
    run(&root, facts, &surface, export_candidate_bundle)
}

pub(crate) fn run(
    root: &Path,
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
    export_candidate_bundle_path: Option<&Path>,
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

    if let Some(output) = export_candidate_bundle_path {
        let packages = artifacts
            .iter()
            .map(|artifact| CandidateBundlePackage {
                name: artifact.plan.package.clone(),
                version: artifact.plan.version.clone(),
                checksum: artifact.checksum.clone(),
            })
            .collect::<Vec<_>>();
        let portable_registry = temp.root.join("portable-candidate-registry");
        export_candidate_bundle(output, &head, &packages, &registry, |bundle| {
            materialize_candidate_bundle_registry(bundle, &portable_registry)?;
            run_registry_consumers(
                root,
                facts,
                surface,
                &plans,
                &artifacts,
                &portable_registry.join("index"),
                &temp.root,
                &head,
            )?;
            Ok(())
        })?;
        println!(
            "package-proof: candidate-bundle={} rss-head={} packages={}",
            output.display(),
            head,
            packages.len()
        );
    } else {
        run_registry_consumers(
            root, facts, surface, &plans, &artifacts, &index, &temp.root, &head,
        )?;
    }
    Ok(())
}

fn run_registry_consumers(
    root: &Path,
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
    plans: &[PackageProofPlan],
    artifacts: &[PackageArtifact<'_>],
    index: &Path,
    proof_root: &Path,
    head: &str,
) -> Result<String> {
    let mut executed = BTreeSet::new();
    for artifact in artifacts {
        run_archive_consumer(root, artifact.plan, index, proof_root).with_context(|| {
            format!(
                "archive consumer proof failed for `{}`",
                artifact.plan.package
            )
        })?;
        if !executed.insert(artifact.plan.package.clone()) {
            bail!("package proof executed a selected package more than once");
        }
        println!(
            "package-proof: package={} version={} head={} sha256={} axes=content,vcs,default,no-default,all-features,msrv,docs,doctest,archive-consumer",
            artifact.plan.package, artifact.plan.version, head, artifact.checksum
        );
    }
    validate_execution_coverage(plans, &executed)?;
    let standalone_packages = surface
        .packages()
        .iter()
        .filter(|package| package.public_api_owner() == PublicApiOwner::StandaloneComponent)
        .map(|package| package.package().to_owned())
        .collect::<BTreeSet<_>>();
    let consumer_revision = run_standalone_consumer(
        root,
        facts,
        artifacts,
        &standalone_packages,
        index,
        proof_root,
    )?;
    println!(
        "package-proof: standalone-consumer={} rss-head={} axes=gitlink,exact-candidates,lock,metadata,check,test,clippy",
        consumer_revision, head
    );
    Ok(consumer_revision)
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

fn run_archive_consumer(
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

fn run_standalone_consumer(
    root: &Path,
    facts: &WorkspaceFacts,
    artifacts: &[PackageArtifact<'_>],
    standalone_packages: &BTreeSet<String>,
    index: &Path,
    proof_root: &Path,
) -> Result<String> {
    let candidates = standalone_candidate_artifacts(artifacts, standalone_packages)?;
    let forbidden_packages = facts
        .workspace_packages()
        .into_iter()
        .map(|package| package.key().as_str().to_owned())
        .filter(|package| !candidates.contains_key(package))
        .collect::<BTreeSet<_>>();
    let (checkout, revision) = validate_standalone_checkout(root)?;
    let consumer = proof_root.join("standalone-consumer");
    copy_pinned_checkout(&checkout, &revision, &consumer)?;

    let manifest_path = consumer.join("Cargo.toml");
    validate_standalone_manifest(
        &fs::read_to_string(&manifest_path)?,
        &candidates,
        &forbidden_packages,
        false,
    )?;
    let script = consumer.join("scripts/upgrade-candidates.sh");
    let registry_index = fs::canonicalize(index)?;
    let registry_index_text = registry_index
        .to_str()
        .context("standalone registry index path is not UTF-8")?;
    let (diag_version, _) = candidates
        .get("rss-diag-context")
        .context("standalone consumer plan has no diag candidate")?;
    let (trace_version, _) = candidates
        .get("rss-trace-context")
        .context("standalone consumer plan has no trace candidate")?;
    let mut msrvs = artifacts
        .iter()
        .filter(|artifact| standalone_packages.contains(&artifact.plan.package))
        .map(|artifact| artifact.plan.minimum_rust_version.as_str())
        .collect::<BTreeSet<_>>();
    if msrvs.len() != 1 {
        bail!("standalone candidates must share one exact MSRV");
    }
    let msrv = msrvs
        .pop_first()
        .context("standalone candidate MSRV is empty")?;
    let output = crate::cmd::standalone_upgrade_cmd(
        &consumer,
        &script,
        registry_index_text,
        diag_version,
        trace_version,
        msrv,
    )?
    .output()
    .context("run standalone candidate upgrade entry")?;
    if !output.status.success() {
        bail!(
            "standalone candidate upgrade failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    validate_standalone_manifest(
        &fs::read_to_string(&manifest_path)?,
        &candidates,
        &forbidden_packages,
        true,
    )?;
    let registry_url = file_url(&registry_index)?;
    validate_standalone_lock(
        &fs::read_to_string(consumer.join("Cargo.lock"))?,
        &candidates,
        &forbidden_packages,
        &registry_url,
    )?;
    let env = [("RUSTUP_TOOLCHAIN", msrv)];
    let consumer_root = fs::canonicalize(&consumer)?;
    let consumer_facts =
        crate::workspace_facts::CommandWorkspaceFacts::new_locked_offline(&consumer_root);
    validate_standalone_facts(
        consumer_facts.get()?,
        &candidates,
        &forbidden_packages,
        &registry_url,
    )?;
    for (subcommand, args, operation) in [
        (
            crate::cmd::CargoSubcommand::Check,
            &["--locked", "--offline", "--all-targets"][..],
            "check standalone consumer",
        ),
        (
            crate::cmd::CargoSubcommand::Test,
            &["--locked", "--offline", "--all-targets"][..],
            "test standalone consumer",
        ),
        (
            crate::cmd::CargoSubcommand::Clippy,
            &[
                "--locked",
                "--offline",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ][..],
            "clippy standalone consumer",
        ),
    ] {
        run_cargo_env(subcommand, args, &env, &consumer, operation)?;
    }
    Ok(revision)
}

fn standalone_candidate_artifacts(
    artifacts: &[PackageArtifact<'_>],
    standalone_packages: &BTreeSet<String>,
) -> Result<BTreeMap<String, (String, String)>> {
    let mut candidates = BTreeMap::new();
    for artifact in artifacts {
        if !standalone_packages.contains(&artifact.plan.package) {
            continue;
        }
        if candidates
            .insert(
                artifact.plan.package.clone(),
                (artifact.plan.version.clone(), artifact.checksum.clone()),
            )
            .is_some()
        {
            bail!("standalone candidate artifact executed more than once");
        }
    }
    if candidates.keys().cloned().collect::<BTreeSet<_>>() != *standalone_packages {
        bail!("standalone candidate artifact exact-set is incomplete");
    }
    Ok(candidates)
}

fn validate_standalone_checkout(root: &Path) -> Result<(PathBuf, String)> {
    let gitmodules = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &[
            "config",
            "--blob",
            "HEAD:.gitmodules",
            "--get",
            "submodule.consumers/standalone.url",
        ],
        &[("GIT_NO_REPLACE_OBJECTS", "1")],
        Some(root),
    )
    .output()?;
    if !gitmodules.status.success() {
        bail!("standalone consumer .gitmodules is missing from HEAD");
    }
    let url = String::from_utf8(gitmodules.stdout).context(".gitmodules URL is not UTF-8")?;
    if url.trim_end() != STANDALONE_REPOSITORY {
        bail!("standalone consumer repository URL differs from the canonical public remote");
    }
    let relative = Path::new(STANDALONE_CONSUMER_PATH);
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["ls-files", "--stage", "--", STANDALONE_CONSUMER_PATH],
        &[],
        Some(root),
    )
    .output()?;
    if !output.status.success() {
        bail!("cannot read standalone consumer gitlink");
    }
    let staged = String::from_utf8(output.stdout).context("gitlink output is not UTF-8")?;
    let pinned = parse_gitlink_revision(&staged, relative)?;
    let checkout = root.join(relative);
    if !checkout.is_dir() {
        bail!("standalone consumer submodule is not initialized");
    }
    let revision = crate::cmd::source_revision(&checkout)?;
    if revision != pinned {
        bail!("standalone consumer checkout does not match the pinned gitlink");
    }
    let flags = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["ls-files", "-v", "-z"],
        &[],
        Some(&checkout),
    )
    .output()?;
    if !flags.status.success()
        || flags
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .any(|entry| !entry.starts_with(b"H "))
    {
        bail!("standalone consumer tracked files contain hidden index flags");
    }
    let status = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["status", "--porcelain"],
        &[],
        Some(&checkout),
    )
    .output()?;
    if !status.status.success() || !status.stdout.is_empty() {
        bail!("standalone consumer checkout must be clean");
    }
    Ok((checkout, revision))
}

fn parse_gitlink_revision(output: &str, expected_path: &Path) -> Result<String> {
    let mut lines = output.lines();
    let line = lines
        .next()
        .context("standalone consumer gitlink is missing")?;
    if lines.next().is_some() {
        bail!("standalone consumer gitlink is ambiguous");
    }
    let (metadata, path) = line
        .split_once('\t')
        .context("standalone consumer gitlink has invalid staging output")?;
    let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 3
        || fields[0] != "160000"
        || fields[2] != "0"
        || Path::new(path) != expected_path
        || fields[1].len() != 40
        || !fields[1].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("standalone consumer path is not one exact gitlink");
    }
    Ok(fields[1].to_owned())
}

fn copy_pinned_checkout(source: &Path, revision: &str, destination: &Path) -> Result<()> {
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["ls-tree", "-rz", "--full-tree", revision],
        &[("GIT_NO_REPLACE_OBJECTS", "1")],
        Some(source),
    )
    .output()?;
    if !output.status.success() {
        bail!("cannot enumerate standalone consumer commit tree");
    }
    let mut copied = 0_usize;
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let record = std::str::from_utf8(raw).context("commit tree entry is not UTF-8")?;
        let (metadata, path) = record
            .split_once('\t')
            .context("commit tree entry has no path")?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3
            || !matches!(fields[0], "100644" | "100755")
            || fields[1] != "blob"
            || fields[2].len() != 40
            || !fields[2].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("standalone consumer commit tree contains a non-regular entry");
        }
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("standalone consumer contains an unsafe tracked path");
        }
        let to = destination.join(relative);
        fs::create_dir_all(to.parent().context("tracked path has no parent")?)?;
        let blob = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            &["cat-file", "blob", fields[2]],
            &[("GIT_NO_REPLACE_OBJECTS", "1")],
            Some(source),
        )
        .output()?;
        if !blob.status.success() {
            bail!("cannot read standalone consumer commit blob");
        }
        fs::write(&to, blob.stdout)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = if fields[0] == "100755" { 0o755 } else { 0o644 };
            fs::set_permissions(&to, fs::Permissions::from_mode(mode))?;
        }
        copied += 1;
    }
    if copied == 0 {
        bail!("standalone consumer checkout has no tracked files");
    }
    Ok(())
}

fn validate_standalone_manifest(
    text: &str,
    candidates: &BTreeMap<String, (String, String)>,
    forbidden_packages: &BTreeSet<String>,
    require_current_versions: bool,
) -> Result<()> {
    let document =
        toml::from_str::<toml::Table>(text).context("standalone consumer Cargo.toml is invalid")?;
    let package = document
        .get("package")
        .and_then(toml::Value::as_table)
        .context("standalone consumer manifest has no package")?;
    if package.get("publish").and_then(toml::Value::as_bool) != Some(false) {
        bail!("standalone consumer must be publish=false");
    }
    let dependencies = document
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .context("standalone consumer has no dependencies")?;
    let mut seen = BTreeSet::new();
    validate_standalone_dependency_table(
        dependencies,
        candidates,
        forbidden_packages,
        &mut seen,
        true,
        require_current_versions,
    )?;
    for key in ["build-dependencies", "dev-dependencies"] {
        if let Some(table) = document.get(key).and_then(toml::Value::as_table) {
            validate_standalone_dependency_table(
                table,
                candidates,
                forbidden_packages,
                &mut seen,
                false,
                require_current_versions,
            )?;
        }
    }
    if let Some(targets) = document.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            for key in ["dependencies", "build-dependencies", "dev-dependencies"] {
                if let Some(table) = target.get(key).and_then(toml::Value::as_table) {
                    validate_standalone_dependency_table(
                        table,
                        candidates,
                        forbidden_packages,
                        &mut seen,
                        false,
                        require_current_versions,
                    )?;
                }
            }
        }
    }
    if seen != candidates.keys().cloned().collect::<BTreeSet<_>>() {
        bail!("standalone consumer direct candidate exact-set differs from the artifact plan");
    }
    Ok(())
}

fn validate_standalone_dependency_table(
    dependencies: &toml::Table,
    candidates: &BTreeMap<String, (String, String)>,
    forbidden_packages: &BTreeSet<String>,
    seen: &mut BTreeSet<String>,
    allow_candidates: bool,
    require_current_versions: bool,
) -> Result<()> {
    for (alias, dependency) in dependencies {
        let Some(detail) = dependency.as_table() else {
            if forbidden_packages.contains(alias)
                || alias.starts_with("rss-")
                || alias.starts_with("rss_")
            {
                bail!("standalone consumer RSS dependencies require explicit identity");
            }
            if !dependency.is_str() {
                bail!("standalone consumer dependency has unsupported shape");
            }
            continue;
        };
        for forbidden in ["path", "git", "workspace"] {
            if detail.contains_key(forbidden) {
                bail!("standalone consumer dependency `{alias}` contains forbidden `{forbidden}`");
            }
        }
        let package = detail
            .get("package")
            .and_then(toml::Value::as_str)
            .unwrap_or(alias);
        if let Some((version, _)) = candidates.get(package) {
            let declared_version = detail
                .get("version")
                .and_then(toml::Value::as_str)
                .and_then(|version| version.strip_prefix('='));
            let declared_version_is_exact =
                declared_version.is_some_and(|version| semver::Version::parse(version).is_ok());
            if !allow_candidates
                || !declared_version_is_exact
                || (require_current_versions && declared_version != Some(version.as_str()))
                || detail.get("registry").and_then(toml::Value::as_str) != Some(STANDALONE_REGISTRY)
                || detail.get("optional").and_then(toml::Value::as_bool) == Some(true)
                || !seen.insert(package.to_owned())
            {
                bail!("standalone candidate dependency `{package}` is not one exact registry pin");
            }
        } else if forbidden_packages.contains(package)
            || package.starts_with("rss-")
            || alias.starts_with("rss_")
        {
            bail!("standalone consumer contains forbidden RSS package `{package}`");
        }
    }
    Ok(())
}

fn validate_standalone_facts(
    facts: &WorkspaceFacts,
    candidates: &BTreeMap<String, (String, String)>,
    forbidden_packages: &BTreeSet<String>,
    registry_url: &str,
) -> Result<()> {
    let packages = facts.workspace_packages();
    if packages.len() != 1
        || packages[0].key().as_str() != "rss-standalone-consumer"
        || packages[0].version() != &semver::Version::new(0, 0, 0)
    {
        bail!("standalone metadata root identity is invalid");
    }
    let root = facts.package_key("rss-standalone-consumer")?;
    let mut seen = BTreeSet::new();
    for dependency in facts.direct_dependencies_for(&root)? {
        let resolved = dependency
            .resolved()
            .context("standalone dependency is unresolved")?
            .as_str();
        let registry = standalone_registry_url(resolved, dependency.source())?;
        if let Some((version, _)) = candidates.get(resolved) {
            if dependency.kind() != DependencyKind::Normal
                || dependency.optional()
                || dependency.version_requirement().to_string() != format!("={version}")
                || registry != registry_url
                || !seen.insert(resolved.to_owned())
            {
                bail!("standalone candidate resolution differs from the artifact plan");
            }
        } else if forbidden_packages.contains(resolved) || resolved.starts_with("rss-") {
            bail!("standalone consumer resolved forbidden RSS package `{resolved}`");
        }
    }
    if seen != candidates.keys().cloned().collect::<BTreeSet<_>>() {
        bail!("standalone selected/resolved/direct candidate sets differ");
    }
    Ok(())
}

fn standalone_registry_url<'a>(resolved: &str, source: &'a DependencySource) -> Result<&'a str> {
    match source {
        DependencySource::Registry { url } | DependencySource::Sparse { url } => Ok(url),
        _ => bail!("standalone consumer declared a non-registry dependency `{resolved}`"),
    }
}

fn validate_standalone_lock(
    text: &str,
    candidates: &BTreeMap<String, (String, String)>,
    forbidden_packages: &BTreeSet<String>,
    registry_url: &str,
) -> Result<()> {
    let lock = toml::from_str::<toml::Table>(text).context("standalone Cargo.lock is invalid")?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .context("standalone Cargo.lock has no packages")?;
    let mut seen = BTreeSet::new();
    let mut root_count = 0_usize;
    for package in packages.iter().filter_map(toml::Value::as_table) {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        if name == "rss-standalone-consumer" {
            root_count += 1;
            if package.get("version").and_then(toml::Value::as_str) != Some("0.0.0")
                || package.contains_key("source")
                || package.contains_key("checksum")
            {
                bail!("standalone lock root identity is invalid");
            }
            continue;
        }
        let source = package
            .get("source")
            .and_then(toml::Value::as_str)
            .with_context(|| format!("standalone lock package `{name}` has no registry source"))?;
        if !(source.starts_with("registry+") || source.starts_with("sparse+"))
            || package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .is_none()
        {
            bail!("standalone lock package `{name}` is not a checksummed registry package");
        }
        if !candidates.contains_key(name)
            && !forbidden_packages.contains(name)
            && !name.starts_with("rss-")
        {
            continue;
        }
        let Some((version, checksum)) = candidates.get(name) else {
            bail!("standalone lock contains forbidden RSS package `{name}`");
        };
        if package.get("version").and_then(toml::Value::as_str) != Some(version)
            || source != format!("registry+{registry_url}")
            || package.get("checksum").and_then(toml::Value::as_str) != Some(checksum)
            || !seen.insert(name.to_owned())
        {
            bail!("standalone lock candidate identity/checksum differs from this artifact");
        }
    }
    if seen != candidates.keys().cloned().collect::<BTreeSet<_>>() {
        bail!("standalone lock candidate exact-set is incomplete");
    }
    if root_count != 1 {
        bail!("standalone lock must contain one exact consumer root");
    }
    Ok(())
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CandidateBundlePackage {
    name: String,
    version: String,
    checksum: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateBundleManifest {
    schema_version: u32,
    rss_revision: String,
    packages: Vec<CandidateBundlePackage>,
}

fn candidate_bundle_manifest(
    rss_revision: &str,
    mut packages: Vec<CandidateBundlePackage>,
) -> Result<CandidateBundleManifest> {
    if rss_revision.len() != 40
        || !rss_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("candidate bundle RSS revision must be a lowercase 40-hex Git identity");
    }
    if packages.is_empty() {
        bail!("candidate bundle requires at least one Release Surface package");
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    let mut seen = BTreeSet::new();
    for package in &packages {
        if !seen.insert(package.name.as_str()) {
            bail!(
                "candidate bundle contains duplicate package `{}`",
                package.name
            );
        }
        if package.checksum.len() != 64
            || !package
                .checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!(
                "candidate bundle package `{}` has an invalid checksum",
                package.name
            );
        }
    }
    Ok(CandidateBundleManifest {
        schema_version: 1,
        rss_revision: rss_revision.to_owned(),
        packages,
    })
}

fn export_candidate_bundle(
    output: &Path,
    rss_revision: &str,
    packages: &[CandidateBundlePackage],
    registry: &Path,
    prove_portable_bundle: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    if !output.is_absolute() {
        bail!("candidate bundle output must be an absolute path");
    }
    if output.exists() {
        bail!(
            "candidate bundle output already exists: {}",
            output.display()
        );
    }
    let parent = output
        .parent()
        .context("candidate bundle output has no parent")?;
    if !parent.is_dir() {
        bail!(
            "candidate bundle output parent is not a directory: {}",
            parent.display()
        );
    }
    let manifest = candidate_bundle_manifest(rss_revision, packages.to_vec())?;
    validate_candidate_registry_exact_set(registry, &manifest.packages)?;
    let staging = parent.join(format!(
        ".rss-candidate-bundle-{}-{}.tmp",
        std::process::id(),
        NEXT_BUNDLE_STAGE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&staging).with_context(|| {
        format!(
            "reserve candidate bundle staging directory `{}`",
            staging.display()
        )
    })?;

    let result = (|| -> Result<()> {
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        manifest_bytes.push(b'\n');
        fs::write(staging.join("candidate-bundle.json"), manifest_bytes)?;

        for package in &manifest.packages {
            let relative_index = index_relative_path(&package.name);
            let source_index = registry.join("index").join(&relative_index);
            if !source_index.is_file() {
                bail!(
                    "candidate bundle index entry is missing for `{}`",
                    package.name
                );
            }
            let target_index = staging.join("registry/index").join(&relative_index);
            fs::create_dir_all(
                target_index
                    .parent()
                    .context("bundle index has no parent")?,
            )?;
            fs::copy(source_index, target_index)?;

            let relative_archive = PathBuf::from("registry/crates")
                .join(&package.name)
                .join(&package.version)
                .join("download");
            let source_archive = registry
                .join("crates")
                .join(&package.name)
                .join(&package.version)
                .join("download");
            if !source_archive.is_file() {
                bail!(
                    "candidate bundle archive is missing for `{}@{}`",
                    package.name,
                    package.version
                );
            }
            let target_archive = staging.join(relative_archive);
            fs::create_dir_all(
                target_archive
                    .parent()
                    .context("bundle archive has no parent")?,
            )?;
            fs::copy(source_archive, target_archive)?;
        }
        validate_candidate_bundle_archive_checksums(&staging, &manifest.packages)?;
        prove_portable_bundle(&staging).context("portable candidate bundle proof failed")?;
        fs::rename(&staging, output).with_context(|| {
            format!("atomically publish candidate bundle `{}`", output.display())
        })?;
        Ok(())
    })();
    if let Err(error) = result {
        if let Err(cleanup_error) = fs::remove_dir_all(&staging) {
            bail!(
                "candidate bundle export failed: {error:#}; cleanup of `{}` also failed: {cleanup_error}",
                staging.display()
            );
        }
        return Err(error);
    }
    Ok(())
}

fn validate_candidate_bundle_archive_checksums(
    bundle: &Path,
    packages: &[CandidateBundlePackage],
) -> Result<()> {
    for package in packages {
        let archive = bundle
            .join("registry/crates")
            .join(&package.name)
            .join(&package.version)
            .join("download");
        let actual = format!("{:x}", Sha256::digest(fs::read(&archive)?));
        if actual != package.checksum {
            bail!(
                "candidate bundle archive checksum differs for `{}@{}`",
                package.name,
                package.version
            );
        }
    }
    Ok(())
}

fn materialize_candidate_bundle_registry(bundle: &Path, registry: &Path) -> Result<()> {
    if registry.exists() {
        bail!(
            "portable candidate registry destination already exists: {}",
            registry.display()
        );
    }
    copy_tree(&bundle.join("registry"), registry)?;
    let index = registry.join("index");
    let download_root = file_url(&registry.join("crates"))?;
    fs::write(
        index.join("config.json"),
        serde_json::to_vec(&json!({ "dl": download_root, "api": null }))?,
    )?;
    init_git(&index)?;
    Ok(())
}

fn validate_candidate_registry_exact_set(
    registry: &Path,
    packages: &[CandidateBundlePackage],
) -> Result<()> {
    let expected_index = packages
        .iter()
        .map(|package| index_relative_path(&package.name))
        .collect::<BTreeSet<_>>();
    let mut actual_index = collect_regular_files(&registry.join("index"))?;
    actual_index.remove(Path::new("config.json"));
    actual_index.retain(|path| {
        path.components()
            .next()
            .is_none_or(|part| part.as_os_str() != ".git")
    });
    if actual_index != expected_index {
        bail!("candidate bundle registry index exact-set differs from Release Surface");
    }

    let expected_archives = packages
        .iter()
        .map(|package| {
            PathBuf::from(&package.name)
                .join(&package.version)
                .join("download")
        })
        .collect::<BTreeSet<_>>();
    if collect_regular_files(&registry.join("crates"))? != expected_archives {
        bail!("candidate bundle registry archive exact-set differs from Release Surface");
    }
    Ok(())
}

fn collect_regular_files(root: &Path) -> Result<BTreeSet<PathBuf>> {
    fn visit(root: &Path, directory: &Path, output: &mut BTreeSet<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("candidate registry contains a symlink: {}", path.display());
            }
            if kind.is_dir() {
                visit(root, &path, output)?;
            } else if kind.is_file() {
                output.insert(path.strip_prefix(root)?.to_owned());
            } else {
                bail!(
                    "candidate registry contains a non-file entry: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    let mut output = BTreeSet::new();
    visit(root, root, &mut output)?;
    Ok(output)
}

static NEXT_BUNDLE_STAGE: AtomicU64 = AtomicU64::new(0);

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
        let release_identities = surface
            .packages()
            .iter()
            .map(|package| (package.package().to_owned(), package.version().to_string()))
            .collect::<BTreeSet<_>>();
        let plan_identities = plans
            .iter()
            .map(|plan| (plan.package.clone(), plan.version.clone()))
            .collect::<BTreeSet<_>>();
        assert_eq!(plan_identities, release_identities);
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
    fn candidate_bundle_manifest_is_sorted_and_rejects_duplicates() {
        let manifest = candidate_bundle_manifest(
            "0123456789abcdef0123456789abcdef01234567",
            vec![
                CandidateBundlePackage {
                    name: "rss-trace-context".to_owned(),
                    version: "0.1.0".to_owned(),
                    checksum: "bb".repeat(32),
                },
                CandidateBundlePackage {
                    name: "rss-diag-context".to_owned(),
                    version: "0.1.0".to_owned(),
                    checksum: "aa".repeat(32),
                },
            ],
        )
        .expect("valid candidate bundle manifest");
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.packages[0].name, "rss-diag-context");
        assert_eq!(manifest.packages[1].name, "rss-trace-context");

        let duplicate = manifest.packages[0].clone();
        assert!(
            candidate_bundle_manifest(
                "0123456789abcdef0123456789abcdef01234567",
                vec![duplicate.clone(), duplicate],
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_bundle_export_is_atomic_and_portable() {
        let temp = TempProof::new().expect("temporary bundle fixture");
        let registry = temp.root.join("registry");
        let index = registry.join("index");
        let crates = registry.join("crates");
        let package = CandidateBundlePackage {
            name: "rss-diag-context".to_owned(),
            version: "0.1.0".to_owned(),
            checksum: format!("{:x}", Sha256::digest(b"crate archive")),
        };
        let index_entry = index.join(index_relative_path(&package.name));
        fs::create_dir_all(index_entry.parent().expect("index parent"))
            .expect("create index parent");
        fs::write(&index_entry, "index-record\n").expect("write index record");
        fs::write(index.join("config.json"), r#"{"dl":"file:///host-only"}"#)
            .expect("write non-portable config");
        fs::create_dir_all(index.join(".git")).expect("create git metadata");
        fs::write(index.join(".git/HEAD"), "ref: refs/heads/main\n").expect("write git metadata");
        let archive = crates
            .join(&package.name)
            .join(&package.version)
            .join("download");
        fs::create_dir_all(archive.parent().expect("archive parent"))
            .expect("create archive parent");
        fs::write(&archive, b"crate archive").expect("write archive");

        let output = temp.root.join("candidate-bundle");
        let materialized_registry = temp.root.join("materialized-registry");
        export_candidate_bundle(
            &output,
            "0123456789abcdef0123456789abcdef01234567",
            &[package.clone()],
            &registry,
            |bundle| materialize_candidate_bundle_registry(bundle, &materialized_registry),
        )
        .expect("export bundle");

        assert!(output.join("candidate-bundle.json").is_file());
        assert!(
            output
                .join("registry/index")
                .join(index_relative_path("rss-diag-context"))
                .is_file()
        );
        assert!(
            output
                .join("registry/crates/rss-diag-context/0.1.0/download")
                .is_file()
        );
        assert!(!output.join("registry/index/config.json").exists());
        assert!(!output.join("registry/index/.git").exists());
        assert!(materialized_registry.join("index/config.json").is_file());
        assert!(materialized_registry.join("index/.git/HEAD").is_file());
        let materialized_config =
            fs::read_to_string(materialized_registry.join("index/config.json"))
                .expect("read relocated registry config");
        assert!(materialized_config.contains(
            &file_url(&materialized_registry.join("crates")).expect("materialized crates URL")
        ));
        assert!(!materialized_config.contains("host-only"));

        let proof_failure = temp.root.join("proof-failure-bundle");
        assert!(
            export_candidate_bundle(
                &proof_failure,
                "0123456789abcdef0123456789abcdef01234567",
                &[package.clone()],
                &registry,
                |_| bail!("synthetic portable consumer failure"),
            )
            .is_err()
        );
        assert!(
            !proof_failure.exists(),
            "portable consumer failure must not publish a bundle"
        );
        assert_no_bundle_staging(&temp.root);

        let checksum_mismatch = temp.root.join("checksum-mismatch-bundle");
        assert!(
            export_candidate_bundle(
                &checksum_mismatch,
                "0123456789abcdef0123456789abcdef01234567",
                &[CandidateBundlePackage {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    checksum: "aa".repeat(32),
                }],
                &registry,
                |_| Ok(()),
            )
            .is_err()
        );
        assert!(
            !checksum_mismatch.exists(),
            "checksum mismatch must not publish a bundle"
        );
        assert_no_bundle_staging(&temp.root);

        let extra = temp.root.join("extra-bundle");
        fs::write(index.join("unexpected-record"), "unexpected\n").expect("write extra record");
        assert!(
            export_candidate_bundle(
                &extra,
                "0123456789abcdef0123456789abcdef01234567",
                &[package.clone()],
                &registry,
                |_| Ok(()),
            )
            .is_err()
        );
        assert!(!extra.exists(), "extra registry artifacts must fail closed");
        assert_no_bundle_staging(&temp.root);
        fs::remove_file(index.join("unexpected-record")).expect("remove extra record");

        let missing = temp.root.join("missing-bundle");
        fs::remove_file(index_entry).expect("remove required index entry");
        assert!(
            export_candidate_bundle(
                &missing,
                "0123456789abcdef0123456789abcdef01234567",
                &[CandidateBundlePackage {
                    name: "rss-diag-context".to_owned(),
                    version: "0.1.0".to_owned(),
                    checksum: "aa".repeat(32),
                }],
                &registry,
                |_| Ok(()),
            )
            .is_err()
        );
        assert!(!missing.exists(), "failed exports must not publish output");
        assert_no_bundle_staging(&temp.root);
    }

    fn assert_no_bundle_staging(root: &Path) {
        let staging = fs::read_dir(root)
            .expect("read fixture root")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rss-candidate-bundle-")
            })
            .collect::<Vec<_>>();
        assert!(staging.is_empty(), "failed export left staging behind");
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

    fn standalone_candidates() -> BTreeMap<String, (String, String)> {
        BTreeMap::from([
            (
                "rss-diag-context".to_owned(),
                ("0.1.0".to_owned(), "diag-checksum".to_owned()),
            ),
            (
                "rss-trace-context".to_owned(),
                ("0.1.0".to_owned(), "trace-checksum".to_owned()),
            ),
        ])
    }

    fn standalone_forbidden_packages() -> BTreeSet<String> {
        ["diagctx", "rss-platform", "tracewire"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn standalone_manifest_requires_exact_registry_candidates() {
        let green = r#"
            [package]
            name = "rss-standalone-consumer"
            version = "0.0.0"
            publish = false

            [dependencies]
            tower = "0.5"
            rss_diag_context = { package = "rss-diag-context", version = "=0.1.0", registry = "rss-candidate" }
            rss_trace_context = { package = "rss-trace-context", version = "=0.1.0", registry = "rss-candidate" }
        "#;
        assert!(
            validate_standalone_manifest(
                green,
                &standalone_candidates(),
                &standalone_forbidden_packages(),
                true
            )
            .is_ok()
        );
        for red in [
            green.replace("publish = false", "publish = true"),
            green.replace("=0.1.0", "0.1",),
            green.replace("registry = \"rss-candidate\"", "path = \"../rss\""),
            green.replace(
                "tower = \"0.5\"",
                "rss_platform = { package = \"rss-platform\", version = \"=0.1.0\", registry = \"rss-candidate\" }",
            ),
            green.replace(
                "tower = \"0.5\"",
                "observation = { package = \"diagctx\", version = \"=0.1.0\", registry = \"rss-candidate\" }",
            ),
            green.replacen(
                "registry = \"rss-candidate\"",
                "registry = \"rss-candidate\", optional = true",
                1,
            ),
        ] {
            assert!(
                validate_standalone_manifest(
                    &red,
                    &standalone_candidates(),
                    &standalone_forbidden_packages(),
                    true
                )
                .is_err(),
                "forbidden manifest remained valid: {red}"
            );
        }
        let stale = green.replace("=0.1.0", "=0.0.9");
        assert!(
            validate_standalone_manifest(
                &stale,
                &standalone_candidates(),
                &standalone_forbidden_packages(),
                false
            )
            .is_ok(),
            "pre-upgrade structure check must admit stale exact pins"
        );
        assert!(
            validate_standalone_manifest(
                &stale,
                &standalone_candidates(),
                &standalone_forbidden_packages(),
                true
            )
            .is_err(),
            "post-upgrade check must require current artifact pins"
        );
    }

    fn standalone_metadata_facts(mutation: &str) -> WorkspaceFacts {
        use workspacefacts::testing::{
            path_dependency, path_package, path_package_id, registry_package, resolve_node,
            resolve_node_with_dep_kinds, target,
        };

        let registry = "file:///registry/index";
        let dependency = |name: &str, rename: &str, version: &str, source: &str| {
            json!({
                "name": name,
                "source": format!("registry+{source}"),
                "req": format!("={version}"),
                "kind": null,
                "rename": rename,
                "optional": false,
                "uses_default_features": true,
                "features": [],
                "target": null,
                "registry": source,
                "path": null
            })
        };
        let external = |name: &str, version: &str, source: &str| {
            let mut package = registry_package(
                name,
                version,
                &format!("/registry/{name}/Cargo.toml"),
                vec![target(
                    name,
                    "lib",
                    &format!("/registry/{name}/src/lib.rs"),
                    true,
                    &[],
                )],
            );
            package["source"] = json!(format!("registry+{source}"));
            package["id"] = json!(format!("registry+{source}#{name}@{version}"));
            package
        };

        let crates_io = "https://github.com/rust-lang/crates.io-index";
        let diag_registry = if mutation == "wrong-registry" {
            crates_io
        } else {
            registry
        };
        let diag_dependency = if mutation == "path-source" {
            let mut dependency = path_dependency("rss-diag-context", "/workspace/vendor/diag");
            dependency["rename"] = json!("rss_diag_context");
            dependency
        } else {
            dependency(
                "rss-diag-context",
                "rss_diag_context",
                "0.1.0",
                diag_registry,
            )
        };
        let mut dependencies = vec![
            diag_dependency,
            dependency("rss-trace-context", "rss_trace_context", "0.1.0", registry),
            dependency("tower", "tower", "0.5.3", crates_io),
        ];
        match mutation {
            "" | "wrong-registry" | "wrong-root" | "path-source" => {}
            "internal" => {
                dependencies.push(dependency("diagctx", "observation", "0.1.0", registry));
            }
            "missing" => {
                dependencies.remove(1);
            }
            "duplicate" => {
                dependencies.push(dependency(
                    "rss-diag-context",
                    "diag_again",
                    "0.1.0",
                    registry,
                ));
            }
            "dev-kind" => dependencies[0]["kind"] = json!("dev"),
            "wrong-version" => dependencies[0]["req"] = json!("^0.1"),
            "optional" => dependencies[0]["optional"] = json!(true),
            _ => panic!("unknown synthetic metadata mutation"),
        }
        let root_path = "/workspace";
        let root_id = path_package_id(root_path);
        let mut packages = vec![path_package(
            "rss-standalone-consumer",
            root_path,
            vec![target(
                "rss_standalone_consumer",
                "lib",
                "/workspace/src/lib.rs",
                true,
                &[],
            )],
            dependencies,
            json!({"default": []}),
        )];
        if mutation == "wrong-root" {
            packages[0]["name"] = json!("other-root");
        }
        if mutation == "path-source" {
            packages.push(path_package(
                "rss-diag-context",
                "/workspace/vendor/diag",
                vec![target(
                    "rss_diag_context",
                    "lib",
                    "/workspace/vendor/diag/src/lib.rs",
                    true,
                    &[],
                )],
                vec![],
                json!({"default": []}),
            ));
        } else {
            packages.push(external("rss-diag-context", "0.1.0", diag_registry));
        }
        packages.extend([
            external("rss-trace-context", "0.1.0", registry),
            external("tower", "0.5.3", crates_io),
        ]);
        if mutation == "internal" {
            packages.push(external("diagctx", "0.1.0", registry));
        }
        let ids = packages
            .iter()
            .skip(1)
            .map(|package| package["id"].as_str().expect("external id").to_owned())
            .collect::<Vec<_>>();
        let mut root_dependencies = vec![("rss_diag_context", ids[0].as_str())];
        if mutation != "missing" {
            root_dependencies.push(("rss_trace_context", ids[1].as_str()));
        }
        root_dependencies.push(("tower", ids[2].as_str()));
        if mutation == "internal" {
            root_dependencies.push(("observation", ids[3].as_str()));
        } else if mutation == "duplicate" {
            root_dependencies.push(("diag_again", ids[0].as_str()));
        }
        let root_dependency_kinds = root_dependencies
            .iter()
            .map(|(name, id)| {
                (
                    *name,
                    *id,
                    (mutation == "dev-kind" && *name == "rss_diag_context").then_some("dev"),
                )
            })
            .collect::<Vec<_>>();
        let mut nodes = vec![resolve_node_with_dep_kinds(
            &root_id,
            &root_dependency_kinds,
            &[],
        )];
        nodes.extend(ids.iter().map(|id| resolve_node(id, &[])));
        crate::testutil::synthetic_workspace_facts_from_parts(
            Path::new(root_path),
            packages,
            vec![root_id],
            nodes,
        )
        .unwrap_or_else(|error| panic!("standalone synthetic metadata `{mutation}`: {error:#}"))
    }

    #[test]
    fn standalone_metadata_rejects_renamed_internal_packages() {
        assert!(
            validate_standalone_facts(
                &standalone_metadata_facts(""),
                &standalone_candidates(),
                &standalone_forbidden_packages(),
                "file:///registry/index"
            )
            .is_ok()
        );
        for mutation in [
            "internal",
            "missing",
            "duplicate",
            "dev-kind",
            "wrong-version",
            "optional",
            "wrong-registry",
            "path-source",
            "wrong-root",
        ] {
            assert!(
                validate_standalone_facts(
                    &standalone_metadata_facts(mutation),
                    &standalone_candidates(),
                    &standalone_forbidden_packages(),
                    "file:///registry/index"
                )
                .is_err(),
                "forbidden metadata mutation remained valid: {mutation}"
            );
        }
    }

    #[test]
    fn standalone_metadata_rejects_non_registry_source() {
        assert!(
            standalone_registry_url(
                "rss-diag-context",
                &DependencySource::Path {
                    repo_relative_root: PathBuf::from("external/diag"),
                }
            )
            .is_err()
        );
        assert_eq!(
            standalone_registry_url(
                "rss-diag-context",
                &DependencySource::Registry {
                    url: "file:///registry/index".to_owned(),
                }
            )
            .expect("registry source"),
            "file:///registry/index"
        );
    }

    #[test]
    fn standalone_lock_requires_same_artifact_checksums() {
        let green = r#"
            version = 4
            [[package]]
            name = "rss-standalone-consumer"
            version = "0.0.0"
            [[package]]
            name = "rss-diag-context"
            version = "0.1.0"
            source = "registry+file:///registry/index"
            checksum = "diag-checksum"
            [[package]]
            name = "rss-trace-context"
            version = "0.1.0"
            source = "registry+file:///registry/index"
            checksum = "trace-checksum"
        "#;
        assert!(
            validate_standalone_lock(
                green,
                &standalone_candidates(),
                &standalone_forbidden_packages(),
                "file:///registry/index"
            )
            .is_ok()
        );
        let path_package =
            format!("{green}\n[[package]]\nname = \"path-helper\"\nversion = \"0.1.0\"\n");
        let duplicate_candidate = format!(
            "{green}\n[[package]]\nname = \"rss-diag-context\"\nversion = \"0.1.0\"\nsource = \"registry+file:///registry/index\"\nchecksum = \"diag-checksum\"\n"
        );
        let forbidden = format!(
            "{green}\n[[package]]\nname = \"rss-platform\"\nversion = \"0.1.0\"\nsource = \"registry+file:///registry/index\"\nchecksum = \"platform-checksum\"\n"
        );
        let duplicate_root = format!(
            "{green}\n[[package]]\nname = \"rss-standalone-consumer\"\nversion = \"0.0.0\"\n"
        );
        for red in [
            green.replace("trace-checksum", "stale-checksum"),
            green.replacen("name = \"rss-trace-context\"", "name = \"other\"", 1),
            green.replacen("version = \"0.1.0\"", "version = \"0.2.0\"", 1),
            green.replacen(
                "source = \"registry+file:///registry/index\"",
                "source = \"registry+https://github.com/rust-lang/crates.io-index\"",
                1,
            ),
            path_package,
            duplicate_candidate,
            forbidden,
            duplicate_root,
        ] {
            assert!(
                validate_standalone_lock(
                    &red,
                    &standalone_candidates(),
                    &standalone_forbidden_packages(),
                    "file:///registry/index"
                )
                .is_err(),
                "forbidden lock mutation remained valid: {red}"
            );
        }
    }

    #[test]
    fn gitlink_parser_requires_exact_path_and_mode() {
        let line = "160000 0123456789abcdef0123456789abcdef01234567 0\tconsumers/standalone\n";
        assert_eq!(
            parse_gitlink_revision(line, Path::new("consumers/standalone")).expect("valid gitlink"),
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert!(
            parse_gitlink_revision(
                &line.replacen("160000", "100644", 1),
                Path::new("consumers/standalone")
            )
            .is_err()
        );
        assert!(parse_gitlink_revision(line, Path::new("consumers/another")).is_err());
        assert!(parse_gitlink_revision("", Path::new("consumers/standalone")).is_err());
        assert!(
            parse_gitlink_revision(&format!("{line}{line}"), Path::new("consumers/standalone"))
                .is_err()
        );
    }

    fn standalone_checkout_fixture(repository: &str) -> (TempProof, PathBuf, PathBuf, String) {
        let temp = TempProof::new().expect("temporary checkout fixture");
        let root = temp.root.join("super");
        let checkout = root.join(STANDALONE_CONSUMER_PATH);
        fs::create_dir_all(&checkout).expect("consumer directory");
        fs::write(checkout.join("payload.txt"), "reviewed\n").expect("consumer payload");
        init_git(&checkout).expect("consumer git fixture");
        let revision = crate::cmd::source_revision(&checkout).expect("consumer revision");
        fs::write(
            root.join(".gitmodules"),
            format!(
                "[submodule \"{STANDALONE_CONSUMER_PATH}\"]\n\tpath = {STANDALONE_CONSUMER_PATH}\n\turl = {repository}\n"
            ),
        )
        .expect("gitmodules fixture");
        init_git(&root).expect("superproject git fixture");
        (temp, root, checkout, revision)
    }

    #[test]
    fn standalone_checkout_rejects_missing_dirty_drift_and_hidden_flags() {
        let (_temp, root, checkout, revision) = standalone_checkout_fixture(STANDALONE_REPOSITORY);
        let (validated, pinned) =
            validate_standalone_checkout(&root).expect("clean pinned checkout");
        assert_eq!(validated, checkout);
        assert_eq!(pinned, revision);

        fs::write(checkout.join("untracked.txt"), "drift\n").expect("untracked drift");
        assert!(validate_standalone_checkout(&root).is_err());
        fs::remove_file(checkout.join("untracked.txt")).expect("remove untracked drift");

        fs::write(checkout.join("payload.txt"), "dirty\n").expect("tracked drift");
        assert!(validate_standalone_checkout(&root).is_err());
        fs::write(checkout.join("payload.txt"), "reviewed\n").expect("restore payload");

        let hidden = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            &["update-index", "--assume-unchanged", "payload.txt"],
            &[],
            Some(&checkout),
        )
        .status()
        .expect("set hidden index flag");
        assert!(hidden.success());
        assert!(validate_standalone_checkout(&root).is_err());

        fs::write(checkout.join("payload.txt"), "new commit\n").expect("new payload");
        let clear = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            &["update-index", "--no-assume-unchanged", "payload.txt"],
            &[],
            Some(&checkout),
        )
        .status()
        .expect("clear hidden index flag");
        assert!(clear.success());
        init_git(&checkout).expect("advance consumer HEAD");
        assert!(validate_standalone_checkout(&root).is_err());

        fs::rename(&checkout, root.join("missing-checkout")).expect("remove checkout path");
        assert!(validate_standalone_checkout(&root).is_err());
    }

    #[test]
    fn standalone_checkout_materializes_pinned_commit_blobs() {
        let (temp, root, checkout, revision) = standalone_checkout_fixture(STANDALONE_REPOSITORY);
        let hidden = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            &["update-index", "--assume-unchanged", "payload.txt"],
            &[],
            Some(&checkout),
        )
        .status()
        .expect("set hidden index flag");
        assert!(hidden.success());
        fs::write(checkout.join("payload.txt"), "unreviewed\n").expect("hidden worktree drift");
        let destination = temp.root.join("materialized");
        copy_pinned_checkout(&checkout, &revision, &destination).expect("materialize commit tree");
        assert_eq!(
            fs::read_to_string(destination.join("payload.txt")).expect("materialized payload"),
            "reviewed\n"
        );
        assert!(validate_standalone_checkout(&root).is_err());
    }

    #[test]
    fn standalone_checkout_ignores_git_replace_objects() {
        let (temp, _root, checkout, revision) = standalone_checkout_fixture(STANDALONE_REPOSITORY);
        fs::write(checkout.join("payload.txt"), "unreviewed\n").expect("replacement payload");
        init_git(&checkout).expect("replacement commit");
        let replacement = crate::cmd::source_revision(&checkout).expect("replacement revision");
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            &["replace", &revision, &replacement],
            &[],
            Some(&checkout),
        )
        .status()
        .expect("install replacement ref");
        assert!(status.success());
        let destination = temp.root.join("replace-materialized");
        copy_pinned_checkout(&checkout, &revision, &destination)
            .expect("materialize reviewed tree");
        assert_eq!(
            fs::read_to_string(destination.join("payload.txt")).expect("materialized payload"),
            "reviewed\n"
        );
    }

    #[test]
    fn standalone_checkout_rejects_noncanonical_remote() {
        let (_temp, root, _checkout, _revision) =
            standalone_checkout_fixture("https://example.invalid/consumer.git");
        assert!(validate_standalone_checkout(&root).is_err());
    }
}
