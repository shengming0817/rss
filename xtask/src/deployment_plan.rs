//! RuntimePlan-bound DeploymentPlan generation and raw-byte drift checking.
//!
//! INVARIANT: DEPLOYMENT-PLAN-ARTIFACT-CLOSURE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "deployment_plan::tests::output_closure_rejects_missing_extra_crlf_and_symlink + deployment_plan::tests::output_reader_rejects_invalid_utf8 + deployment_plan::tests::render_preflight_failure_is_zero_write", anti_vacuity = "deployment_plan::tests::three_repository_profiles_compile_and_match_committed_bytes" } — the verified assembly artifact matrix and all three profiles across both closed phases are preflighted before render; managed plan, values, golden, core and extension directories remain exact regular-file LF sets. Cross-resource semantics are owned exclusively by `deployment_policy::validate_rendered_phase`.

use anyhow::{Context, Result, ensure};
use assembly_schema::{DeploymentPlan, MigrationMode, ParsedDeploymentPlan};
use serde::Deserialize;
use serde_yaml_ng::Value as YamlValue;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const GENERATED_DIR: &str = "deploy/generated";
const CHART_DIR: &str = "deploy/helm/rss";
const HELM_RELEASE_NAME: &str = "rss";
const HELM_NAMESPACE: &str = "rss-system";
pub(crate) const HELM_VERSION: &str = env!("RSS_TOOL_VERSION_HELM");
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_CHART_BYTES: u64 = 1024 * 1024;
const DEFAULT_PROFILE: &str = "runtime";
const PHASES: [&str; 2] = ["migration", "serving"];
const FORWARD_RENDER_PHASES: [(&str, crate::deployment_policy::RenderPhase); 2] = [
    (
        "migration",
        crate::deployment_policy::RenderPhase::Migration,
    ),
    ("serving", crate::deployment_policy::RenderPhase::Serving),
];
const NONE_RENDER_PHASES: [(&str, crate::deployment_policy::RenderPhase); 1] =
    [("serving", crate::deployment_policy::RenderPhase::Serving)];
const STATIC_CHART_ASSETS: [&str; 13] = [
    "Chart.yaml",
    "configs/identity-audit-v1.toml",
    "configs/settings-only-v1.toml",
    "templates/_helpers.tpl",
    "templates/availability.yaml",
    "templates/configmap.yaml",
    "templates/deployment.yaml",
    "templates/migration-job.yaml",
    "templates/networkpolicy.yaml",
    "templates/secretproviderclass.yaml",
    "templates/service.yaml",
    "templates/serviceaccount.yaml",
    "templates/servicemonitor.yaml",
];
const MANAGED_DIRECTORIES: [&str; 6] = [
    GENERATED_DIR,
    "deploy/helm/rss/plans",
    "deploy/helm/rss/values",
    "deploy/helm/rss/tests/golden",
    "deploy/rendered",
    "deploy/rendered/extensions",
];
const LF_RULES: [(&str, &str); 8] = [
    (
        "deploy/generated/",
        "deploy/generated/*.deployment-plan.json text eol=lf",
    ),
    (
        "deploy/helm/rss/plans/",
        "deploy/helm/rss/plans/*.deployment-plan.json text eol=lf",
    ),
    (
        "deploy/helm/rss/values/",
        "deploy/helm/rss/values/*.yaml text eol=lf",
    ),
    (
        "deploy/helm/rss/values.yaml",
        "deploy/helm/rss/values.yaml text eol=lf",
    ),
    (
        "deploy/helm/rss/values.schema.json",
        "deploy/helm/rss/values.schema.json text eol=lf",
    ),
    (
        "deploy/helm/rss/tests/golden/",
        "deploy/helm/rss/tests/golden/*.yaml text eol=lf",
    ),
    ("deploy/rendered/", "deploy/rendered/*.yaml text eol=lf"),
    (
        "deploy/rendered/extensions/",
        "deploy/rendered/extensions/*.yaml text eol=lf",
    ),
];
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Render,
    Check,
}

pub(crate) fn run(action: Action) -> Result<()> {
    run_root(&crate::workspace_root()?, action)
}

fn run_root(root: &Path, action: Action) -> Result<()> {
    run_with_planner(root, action, || plan_all(root))
}

fn run_with_planner(
    root: &Path,
    action: Action,
    planner: impl FnOnce() -> Result<Vec<PlannedOutput>>,
) -> Result<()> {
    let planned = planner()?;
    match action {
        Action::Render => render(root, &planned).map(|_| ()),
        Action::Check => {
            validate_output_closure(root, &planned)?;
            check(&planned)
        }
    }
}

struct PlannedOutput {
    path: PathBuf,
    relative: String,
    expected: Vec<u8>,
    actual: Option<Vec<u8>>,
}

fn plan_all(root: &Path) -> Result<Vec<PlannedOutput>> {
    plan_all_with_stage_hook(root, |_| Ok(()))
}

fn plan_all_with_stage_hook(
    root: &Path,
    stage_hook: impl FnOnce(&Path) -> Result<()>,
) -> Result<Vec<PlannedOutput>> {
    let matrix = crate::assembly_artifacts::load_verified(root)
        .context("deployment plan preflight: artifact matrix rejected")?;
    ensure!(
        !matrix.supported_rows().is_empty(),
        "deployment plan preflight: empty supported assembly universe"
    );

    let profile_names = matrix
        .supported_rows()
        .iter()
        .map(|row| row.name())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        profile_names.contains(DEFAULT_PROFILE),
        "deployment plan preflight: default runtime profile is unsupported"
    );
    let profile_names = profile_names.into_iter().collect::<Vec<_>>();

    let mut planned = Vec::with_capacity(profile_names.len() * 9 + 2);
    let mut compiled = Vec::with_capacity(profile_names.len());
    for row in matrix.supported_rows() {
        let profile = row.deployment();
        let runtime = profile.runtime_plan();
        let plan =
            DeploymentPlan::compile_v1(runtime, profile.plan_input()).with_context(|| {
                format!(
                    "deployment plan preflight: invalid {} deployment facts",
                    row.name()
                )
            })?;
        let mut expected = serde_json::to_vec_pretty(&plan).with_context(|| {
            format!("deployment plan preflight: cannot serialize {}", row.name())
        })?;
        expected.push(b'\n');
        ParsedDeploymentPlan::from_json_slice(runtime, &expected).with_context(|| {
            format!(
                "deployment plan preflight: generated {} bytes rejected",
                row.name()
            )
        })?;
        compiled.push((row.name().to_owned(), plan, expected.clone()));

        for relative in [
            format!("{GENERATED_DIR}/{}.deployment-plan.json", row.name()),
            format!("{CHART_DIR}/plans/{}.deployment-plan.json", row.name()),
        ] {
            planned.push(planned_output(root, &relative, expected.clone())?);
        }
        planned.push(planned_output(
            root,
            &format!("assemblies/{}/src/deployment_facts.rs", row.name()),
            format!(
                "// @generated by `cargo xtask deployment plan render`; do not edit.\n\
                 pub(crate) const TOTAL_DRAIN_SECONDS: u64 = {};\n",
                profile.drain_seconds()
            )
            .into_bytes(),
        )?);
        planned.push(planned_output(
            root,
            &format!("{CHART_DIR}/values/{}.yaml", row.name()),
            format!("profile: {}\nphase: migration\n", row.name()).into_bytes(),
        )?);
    }
    planned.push(planned_output(
        root,
        &format!("{CHART_DIR}/values.yaml"),
        format!("profile: {DEFAULT_PROFILE}\nphase: migration\n").into_bytes(),
    )?);
    planned.push(planned_output(
        root,
        &format!("{CHART_DIR}/values.schema.json"),
        values_schema(&profile_names)?,
    )?);
    let staged = StagedChart::prepare(root, &planned)?;
    stage_hook(&staged.path())?;
    let default_render = helm_preflight(root, staged.path(), &profile_names)?;
    let mut default_matched = false;
    for (profile, plan, _plan_bytes) in &compiled {
        for &(phase, render_phase) in render_phases(plan.migration_mode()) {
            let rendered = helm_template(root, staged.path(), profile, phase)?;
            if profile == DEFAULT_PROFILE && phase == "migration" {
                ensure!(
                    rendered == default_render,
                    "deployment plan preflight: default render is not runtime migration"
                );
                default_matched = true;
            }
            crate::deployment_policy::validate_rendered_phase(
                &rendered,
                plan,
                profile,
                render_phase,
            )?;
            let (core, extensions) = split_rendered_manifests(&rendered, profile, phase)?;
            for (relative, bytes) in [
                (format!("deploy/rendered/{profile}-{phase}.yaml"), core),
                (
                    format!("deploy/rendered/extensions/{profile}-{phase}.yaml"),
                    extensions,
                ),
                (
                    format!("{CHART_DIR}/tests/golden/{profile}-{phase}.yaml"),
                    rendered,
                ),
            ] {
                planned.push(planned_output(root, &relative, bytes)?);
            }
        }
    }
    ensure!(
        default_matched,
        "deployment plan preflight: runtime render missing"
    );
    planned.sort_by(|left, right| left.path.cmp(&right.path));
    validate_planned_bytes(&planned)?;
    verify_lf_policy(root, &planned)?;
    Ok(planned)
}

fn render_phases(
    migration_mode: MigrationMode,
) -> &'static [(&'static str, crate::deployment_policy::RenderPhase)] {
    match migration_mode {
        MigrationMode::ForwardOnlyTwoPhase => &FORWARD_RENDER_PHASES,
        MigrationMode::None => &NONE_RENDER_PHASES,
    }
}

fn values_schema(profiles: &[&str]) -> Result<Vec<u8>> {
    let schema = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": false,
        "required": ["profile", "phase"],
        "properties": {
            "profile": { "type": "string", "enum": profiles },
            "phase": { "type": "string", "enum": PHASES }
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&schema)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn planned_output(root: &Path, relative: &str, expected: Vec<u8>) -> Result<PlannedOutput> {
    ensure!(
        !relative.starts_with('/')
            && relative
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && relative.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'/' | b'-' | b'.' | b'_')
            }),
        "deployment plan output path is unsafe"
    );
    let path = root.join(relative);
    let actual = read_existing_output(&path)?;
    Ok(PlannedOutput {
        path,
        relative: relative.to_owned(),
        expected,
        actual,
    })
}

fn validate_planned_bytes(planned: &[PlannedOutput]) -> Result<()> {
    ensure!(
        !planned.is_empty(),
        "deployment plan preflight: empty output set"
    );
    for item in planned {
        ensure!(
            !item.expected.is_empty()
                && item.expected.ends_with(b"\n")
                && !item.expected.windows(2).any(|window| window == b"\r\n"),
            "deployment plan preflight: empty or non-LF output {}",
            safe_output_name(item)
        );
    }
    Ok(())
}

fn verify_lf_policy(root: &Path, planned: &[PlannedOutput]) -> Result<()> {
    for (prefix, declaration) in LF_RULES {
        let targets = planned
            .iter()
            .filter(|item| {
                item.path
                    .strip_prefix(root)
                    .ok()
                    .and_then(Path::to_str)
                    .is_some_and(|relative| relative == prefix || relative.starts_with(prefix))
            })
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();
        crate::generated_file::verify_lf_checkout(root, declaration, &targets).map_err(|_| {
            anyhow::anyhow!("deployment plan preflight: LF checkout policy rejected")
        })?;
    }
    Ok(())
}

struct StagedChart {
    root: PathBuf,
}

impl StagedChart {
    fn prepare(root: &Path, planned: &[PlannedOutput]) -> Result<Self> {
        let stage_root = create_staging_directory()?;
        let chart = stage_root.join("rss");
        let prepared = Self { root: stage_root };
        validate_static_chart_closure(root, planned)?;
        for relative in STATIC_CHART_ASSETS {
            let source = root.join(CHART_DIR).join(relative);
            let content = crate::generated_file::read_stable_utf8_file(
                &source,
                MAX_CHART_BYTES,
                "Helm static asset",
            )?;
            ensure!(
                !content.is_empty(),
                "Helm static asset is empty: {relative}"
            );
            crate::generated_file::atomic_replace(&chart.join(relative), content.as_bytes())?;
        }
        let chart_root = root.join(CHART_DIR);
        for item in planned {
            let Ok(relative) = item.path.strip_prefix(&chart_root) else {
                continue;
            };
            crate::generated_file::atomic_replace(&chart.join(relative), &item.expected)?;
        }
        Ok(prepared)
    }

    fn path(&self) -> PathBuf {
        self.root.join("rss")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChartEntryKind {
    Directory,
    File,
}

fn validate_static_chart_closure(root: &Path, planned: &[PlannedOutput]) -> Result<()> {
    let chart = root.join(CHART_DIR);
    let metadata = fs::symlink_metadata(&chart)
        .context("deployment plan preflight: Helm chart root inspection failed")?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "deployment plan preflight: Helm chart closure drift at root"
    );
    let mut expected = BTreeMap::new();
    for relative in STATIC_CHART_ASSETS {
        add_expected_chart_file(&mut expected, Path::new(relative));
    }
    for item in planned {
        if let Ok(relative) = item.path.strip_prefix(&chart) {
            add_expected_chart_file(&mut expected, relative);
        }
    }
    if chart.join("tests/golden").is_dir() {
        expected.insert(PathBuf::from("tests"), ChartEntryKind::Directory);
        expected.insert(PathBuf::from("tests/golden"), ChartEntryKind::Directory);
    }
    let mut observed = BTreeMap::new();
    collect_chart_tree(&chart, &chart, &mut observed)?;
    let is_managed_generated_file = |path: &Path, kind: &ChartEntryKind| {
        *kind == ChartEntryKind::File
            && [
                Path::new("plans"),
                Path::new("values"),
                Path::new("tests/golden"),
            ]
            .iter()
            .any(|directory| path.starts_with(directory))
    };
    expected.retain(|path, kind| !is_managed_generated_file(path, kind));
    observed.retain(|path, kind| !is_managed_generated_file(path, kind));
    if observed != expected {
        let missing = expected
            .keys()
            .filter(|path| !observed.contains_key(*path))
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        let extra = observed
            .keys()
            .filter(|path| !expected.contains_key(*path))
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        anyhow::bail!(
            "deployment plan preflight: Helm chart closure drift; missing={missing:?} extra={extra:?}"
        );
    }
    Ok(())
}

fn add_expected_chart_file(entries: &mut BTreeMap<PathBuf, ChartEntryKind>, relative: &Path) {
    let mut parent = relative.parent();
    while let Some(directory) = parent {
        if directory.as_os_str().is_empty() {
            break;
        }
        entries.insert(directory.to_owned(), ChartEntryKind::Directory);
        parent = directory.parent();
    }
    entries.insert(relative.to_owned(), ChartEntryKind::File);
}

fn collect_chart_tree(
    chart: &Path,
    directory: &Path,
    entries: &mut BTreeMap<PathBuf, ChartEntryKind>,
) -> Result<()> {
    for item in fs::read_dir(directory).context("Helm chart directory read failed")? {
        let item = item.context("Helm chart entry read failed")?;
        let path = item.path();
        let relative = path
            .strip_prefix(chart)
            .context("Helm chart entry escaped chart root")?
            .to_owned();
        let metadata = fs::symlink_metadata(&path).context("Helm chart entry inspection failed")?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "deployment plan preflight: Helm chart closure drift at {}: symlink",
            relative.display()
        );
        if metadata.is_dir() {
            entries.insert(relative, ChartEntryKind::Directory);
            collect_chart_tree(chart, &path, entries)?;
        } else {
            ensure!(
                metadata.is_file(),
                "deployment plan preflight: Helm chart closure drift at {}: non-regular entry",
                relative.display()
            );
            entries.insert(relative, ChartEntryKind::File);
        }
    }
    Ok(())
}

impl Drop for StagedChart {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_staging_directory() -> Result<PathBuf> {
    for _ in 0..128 {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rss-deployment-plan-stage-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("cannot create Helm staging directory"),
        }
    }
    anyhow::bail!("cannot allocate unique Helm staging directory")
}

fn helm_preflight(root: &Path, chart: PathBuf, profiles: &[&str]) -> Result<Vec<u8>> {
    helm_probe(root)?;
    let chart_label = chart.to_str().context("Helm staging path is not UTF-8")?;
    let _ = helm_output(root, &["lint", chart_label])?;
    let default = helm_output(
        root,
        &[
            "template",
            HELM_RELEASE_NAME,
            chart_label,
            "--namespace",
            HELM_NAMESPACE,
        ],
    )?;
    ensure!(
        !default.is_empty(),
        "deployment plan preflight: default render is empty"
    );

    let mut ordered = profiles.to_vec();
    ordered.sort_unstable_by_key(|profile| (*profile != DEFAULT_PROFILE, *profile));
    for profile in ordered {
        let values = chart.join("values").join(format!("{profile}.yaml"));
        let values = values.to_str().context("Helm values path is not UTF-8")?;
        for phase in PHASES {
            let phase_value = format!("phase={phase}");
            let _ = helm_output(
                root,
                &[
                    "lint",
                    chart_label,
                    "--values",
                    values,
                    "--set",
                    &phase_value,
                ],
            )?;
        }
    }
    for invalid in [
        "profile=unknown",
        "profile=Runtime",
        "profile=",
        "profile=../runtime",
        "phase=unknown",
        "phase=Serving",
        "phase=",
        "image=forbidden",
        "deploymentPlan=forbidden",
    ] {
        helm_expect_failure(root, &["lint", chart_label, "--set", invalid])?;
    }
    Ok(default)
}

fn helm_expect_failure(root: &Path, args: &[&str]) -> Result<()> {
    let output = crate::cmd::external_cmd(crate::cmd::ExternalProgram::Helm, args, &[], Some(root))
        .output()
        .with_context(|| format!("deployment plan preflight: Helm {} probe failed", args[0]))?;
    ensure!(
        !output.status.success(),
        "deployment plan preflight: Helm {} accepted forbidden input",
        args[0]
    );
    Ok(())
}

fn helm_template(root: &Path, chart: PathBuf, profile: &str, phase: &str) -> Result<Vec<u8>> {
    let values = chart.join("values").join(format!("{profile}.yaml"));
    let chart = chart.to_str().context("Helm staging path is not UTF-8")?;
    let values = values.to_str().context("Helm values path is not UTF-8")?;
    let phase_value = format!("phase={phase}");
    let output = helm_output(
        root,
        &[
            "template",
            HELM_RELEASE_NAME,
            chart,
            "--namespace",
            HELM_NAMESPACE,
            "--values",
            values,
            "--set",
            &phase_value,
        ],
    )?;
    ensure!(
        !output.is_empty() && output.ends_with(b"\n"),
        "deployment plan preflight: Helm rendered empty output for {profile}/{phase}"
    );
    Ok(output)
}

fn split_rendered_manifests(
    rendered: &[u8],
    profile: &str,
    phase: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let documents = serde_yaml_ng::Deserializer::from_slice(rendered)
        .map(|document| {
            YamlValue::deserialize(document).with_context(|| {
                format!("profile={profile} phase={phase}: rendered manifest is invalid YAML")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !documents.is_empty(),
        "profile={profile} phase={phase}: rendered manifest set is empty"
    );
    let mut core = Vec::new();
    let mut extensions = Vec::new();
    for document in documents {
        let target = match document.get("kind").and_then(YamlValue::as_str) {
            Some("SecretProviderClass" | "ServiceMonitor") => &mut extensions,
            _ => &mut core,
        };
        append_yaml_document(target, &document)?;
    }
    ensure!(
        !core.is_empty() && !extensions.is_empty(),
        "profile={profile} phase={phase}: core/extension split is vacuous"
    );
    Ok((core, extensions))
}

fn append_yaml_document(output: &mut Vec<u8>, document: &YamlValue) -> Result<()> {
    if !output.is_empty() {
        output.extend_from_slice(b"---\n");
    }
    let serialized =
        serde_yaml_ng::to_string(document).context("cannot serialize rendered YAML")?;
    output.extend_from_slice(serialized.as_bytes());
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    Ok(())
}

fn helm_output(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = crate::cmd::external_cmd(crate::cmd::ExternalProgram::Helm, args, &[], Some(root))
        .output()
        .with_context(|| format!("deployment plan preflight: Helm {} failed", args[0]))?;
    ensure!(
        output.status.success(),
        "deployment plan preflight: Helm {} rejected chart: {}",
        args[0],
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HelmProbeError {
    Missing,
    Failed(String),
    InvalidUtf8,
    VersionMismatch { expected: String, actual: String },
}

impl std::fmt::Display for HelmProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("Helm executable is missing"),
            Self::Failed(status) => write!(formatter, "Helm version probe failed: {status}"),
            Self::InvalidUtf8 => formatter.write_str("Helm version probe output is not UTF-8"),
            Self::VersionMismatch { expected, actual } => write!(
                formatter,
                "Helm version mismatch: expected {expected}, actual {actual:?}"
            ),
        }
    }
}

impl std::error::Error for HelmProbeError {}

fn classify_helm_probe(
    result: io::Result<std::process::Output>,
) -> std::result::Result<(), HelmProbeError> {
    let output = result.map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            HelmProbeError::Missing
        } else {
            HelmProbeError::Failed(error.to_string())
        }
    })?;
    if !output.status.success() {
        return Err(HelmProbeError::Failed(format!(
            "exit={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let actual = String::from_utf8(output.stdout).map_err(|_| HelmProbeError::InvalidUtf8)?;
    let actual = actual.trim_end().to_owned();
    let expected = format!("v{HELM_VERSION}");
    if actual != expected {
        return Err(HelmProbeError::VersionMismatch { expected, actual });
    }
    Ok(())
}

pub(crate) fn helm_probe(root: &Path) -> std::result::Result<(), HelmProbeError> {
    classify_helm_probe(
        crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::Helm,
            &["version", "--template", "{{.Version}}"],
            &[],
            Some(root),
        )
        .output(),
    )
}

fn read_existing_output(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => crate::generated_file::read_stable_utf8_file(
            path,
            MAX_PLAN_BYTES,
            "deployment plan output",
        )
        .map(String::into_bytes)
        .map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("deployment plan output metadata failed"),
    }
}

fn validate_output_closure(root: &Path, planned: &[PlannedOutput]) -> Result<()> {
    for relative in MANAGED_DIRECTORIES {
        let directory = root.join(relative);
        let expected = planned
            .iter()
            .filter(|item| item.path.parent() == Some(directory.as_path()))
            .filter_map(|item| item.path.file_name().map(ToOwned::to_owned))
            .collect::<std::collections::BTreeSet<_>>();
        if expected.is_empty() {
            continue;
        }
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).context("deployment plan output directory inspection failed");
            }
        };
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "deployment plan output directory is not a real directory"
        );
        let observed = list_managed_regular_files(root, relative)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let extras = observed.difference(&expected).count();
        ensure!(
            extras == 0,
            "deployment plan output: {extras} orphan entries in {relative}"
        );
    }
    Ok(())
}

fn list_managed_regular_files(root: &Path, relative: &str) -> Result<Vec<std::ffi::OsString>> {
    let directory = root.join(relative);
    if relative != "deploy/rendered" {
        return crate::generated_file::list_stable_regular_files(&directory);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&directory).context("deployment rendered directory read failed")? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if entry.file_name() == "extensions" {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "deployment rendered extensions entry is unsafe"
            );
            continue;
        }
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "deployment rendered directory contains a non-regular entry"
        );
        files.push(entry.file_name());
    }
    files.sort();
    Ok(files)
}

fn check(planned: &[PlannedOutput]) -> Result<()> {
    let missing = planned
        .iter()
        .filter(|item| item.actual.is_none())
        .map(safe_output_name)
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "deployment plan check: missing {}",
        missing.join(",")
    );
    let drift = planned
        .iter()
        .filter(|item| {
            item.actual
                .as_deref()
                .is_some_and(|actual| actual != item.expected)
        })
        .map(safe_output_name)
        .collect::<Vec<_>>();
    ensure!(
        drift.is_empty(),
        "deployment plan check: drift {}",
        drift.join(",")
    );
    eprintln!(
        "deployment plan check: {} managed outputs clean",
        planned.len()
    );
    Ok(())
}

fn safe_output_name(item: &PlannedOutput) -> String {
    item.relative.clone()
}

fn render(root: &Path, planned: &[PlannedOutput]) -> Result<usize> {
    validate_managed_directory_safety(root)?;
    let mut changed = 0usize;
    for item in planned {
        if item.actual.as_deref() == Some(item.expected.as_slice()) {
            continue;
        }
        crate::generated_file::atomic_replace(&item.path, &item.expected)
            .context("deployment plan render: atomic publication failed")?;
        changed += 1;
    }
    changed += remove_output_orphans(root, planned)?;
    validate_output_closure(root, planned)?;
    for item in planned {
        let actual = read_existing_output(&item.path)?;
        ensure!(
            actual.as_deref() == Some(item.expected.as_slice()),
            "deployment plan render: post-publication drift {}",
            safe_output_name(item)
        );
    }
    eprintln!("deployment plan render: {changed} managed outputs updated");
    Ok(changed)
}

fn validate_managed_directory_safety(root: &Path) -> Result<()> {
    for relative in MANAGED_DIRECTORIES {
        let directory = root.join(relative);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).context("deployment plan output directory inspection failed");
            }
        };
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "deployment plan output directory is not a real directory"
        );
        let _ = list_managed_regular_files(root, relative)?;
    }
    Ok(())
}

fn remove_output_orphans(root: &Path, planned: &[PlannedOutput]) -> Result<usize> {
    let mut removed = 0;
    for relative in MANAGED_DIRECTORIES {
        let directory = root.join(relative);
        if !directory.exists() {
            continue;
        }
        let expected = planned
            .iter()
            .filter(|item| item.path.parent() == Some(directory.as_path()))
            .filter_map(|item| item.path.file_name().map(ToOwned::to_owned))
            .collect::<std::collections::BTreeSet<_>>();
        for name in list_managed_regular_files(root, relative)? {
            if expected.contains(&name) {
                continue;
            }
            fs::remove_file(directory.join(name))
                .context("deployment plan render: orphan removal failed")?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_mode_plans_only_serving_outputs() {
        assert_eq!(
            render_phases(MigrationMode::None),
            &[("serving", crate::deployment_policy::RenderPhase::Serving)]
        );
        assert_eq!(
            render_phases(MigrationMode::ForwardOnlyTwoPhase),
            &[
                (
                    "migration",
                    crate::deployment_policy::RenderPhase::Migration,
                ),
                ("serving", crate::deployment_policy::RenderPhase::Serving),
            ]
        );
    }

    fn repository_profiles(root: &Path) -> Result<Vec<String>> {
        Ok(crate::assembly_artifacts::load_verified(root)?
            .supported_rows()
            .iter()
            .map(|row| row.name().to_owned())
            .collect())
    }

    #[test]
    fn three_repository_profiles_have_complete_helm_assets() -> Result<()> {
        let root = crate::workspace_root()?;
        let chart = root.join("deploy/helm/rss");
        let static_assets = [
            "Chart.yaml",
            "values.yaml",
            "templates/_helpers.tpl",
            "templates/configmap.yaml",
            "templates/deployment.yaml",
            "templates/service.yaml",
            "templates/serviceaccount.yaml",
            "values.schema.json",
        ];

        for relative in static_assets {
            let path = chart.join(relative);
            ensure!(
                path.is_file() && path.metadata()?.len() > 0,
                "Helm asset missing or empty: {}",
                path.display()
            );
        }
        for profile in repository_profiles(&root)? {
            let mut profile_assets = vec![
                format!("values/{profile}.yaml"),
                format!("plans/{profile}.deployment-plan.json"),
            ];
            profile_assets.extend(
                PHASES
                    .iter()
                    .map(|phase| format!("tests/golden/{profile}-{phase}.yaml")),
            );
            for relative in profile_assets {
                let path = chart.join(relative);
                ensure!(
                    path.is_file() && path.metadata()?.len() > 0,
                    "Helm profile asset missing or empty: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn helm_chart_tree_is_recursive_exact_and_no_follow() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-template-closure");
        let templates = root.join(CHART_DIR).join("templates");
        fs::create_dir_all(&templates)?;
        for relative in STATIC_CHART_ASSETS {
            let path = root.join(CHART_DIR).join(relative);
            fs::create_dir_all(path.parent().context("static asset parent missing")?)?;
            fs::write(path, b"non-empty\n")?;
        }
        validate_static_chart_closure(&root, &[])?;

        fs::write(templates.join("orphan.yaml"), b"orphan\n")?;
        let error = validate_static_chart_closure(&root, &[])
            .err()
            .context("extra Helm template escaped closure")?;
        assert!(error.to_string().contains("closure drift"));
        fs::remove_file(templates.join("orphan.yaml"))?;

        for unexpected in [
            "orphan.yaml",
            "charts/dependency/Chart.yaml",
            "crds/escape.yaml",
        ] {
            let path = root.join(CHART_DIR).join(unexpected);
            fs::create_dir_all(path.parent().context("unexpected chart parent missing")?)?;
            fs::write(&path, b"orphan\n")?;
            ensure!(
                validate_static_chart_closure(&root, &[]).is_err(),
                "recursive chart entry escaped closure: {unexpected}"
            );
            fs::remove_file(path)?;
            if let Some(top_level) = unexpected.split('/').next()
                && unexpected.contains('/')
            {
                fs::remove_dir_all(root.join(CHART_DIR).join(top_level))?;
            }
        }
        fs::create_dir_all(root.join(CHART_DIR).join("charts"))?;
        ensure!(
            validate_static_chart_closure(&root, &[]).is_err(),
            "empty reserved chart directory escaped closure"
        );
        fs::remove_dir(root.join(CHART_DIR).join("charts"))?;

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                templates.join("service.yaml"),
                templates.join("orphan-link.yaml"),
            )?;
            assert!(validate_static_chart_closure(&root, &[]).is_err());
        }
        Ok(())
    }

    #[test]
    fn helm_deployment_template_declares_the_closed_container_security_baseline() -> Result<()> {
        let root = crate::workspace_root()?;
        let path = root.join("deploy/helm/rss/templates/deployment.yaml");
        let template = fs::read_to_string(&path)
            .with_context(|| format!("read Helm deployment template {}", path.display()))?;

        for required in [
            "runAsNonRoot: true",
            "readOnlyRootFilesystem: true",
            "allowPrivilegeEscalation: false",
            "drop:",
            "- ALL",
        ] {
            ensure!(
                template.contains(required),
                "Helm deployment security baseline is missing {required}"
            );
        }
        for forbidden in ["/bin/sh", "/bin/bash", "sh -c", "bash -c"] {
            ensure!(
                !template.contains(forbidden),
                "Helm deployment template assumes a shell"
            );
        }
        Ok(())
    }

    fn output(path: PathBuf, bytes: &[u8]) -> Result<PlannedOutput> {
        let relative = path
            .file_name()
            .context("test output file name missing")?
            .to_string_lossy()
            .into_owned();
        Ok(PlannedOutput {
            path,
            relative,
            expected: bytes.to_vec(),
            actual: Some(bytes.to_vec()),
        })
    }

    fn planned_output(path: PathBuf, bytes: &[u8]) -> Result<PlannedOutput> {
        let actual = read_existing_output(&path)?;
        let relative = path
            .file_name()
            .context("test planned output file name missing")?
            .to_string_lossy()
            .into_owned();
        Ok(PlannedOutput {
            path,
            relative,
            expected: bytes.to_vec(),
            actual,
        })
    }

    #[test]
    fn output_closure_rejects_missing_extra_crlf_and_symlink() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-output-red");
        let generated = root.join(GENERATED_DIR);
        fs::create_dir_all(&generated)?;
        let path = generated.join("runtime.deployment-plan.json");
        fs::write(&path, b"{}\r\n")?;
        let mut planned = vec![output(path.clone(), b"{}\n")?];
        planned[0].actual = Some(b"{}\r\n".to_vec());
        let drift = check(&planned).err().context("CRLF/raw-byte red escaped")?;
        assert!(
            drift
                .to_string()
                .contains("drift runtime.deployment-plan.json")
        );

        planned[0].actual = None;
        let missing = check(&planned).err().context("missing red escaped")?;
        assert!(
            missing
                .to_string()
                .contains("missing runtime.deployment-plan.json")
        );
        fs::write(generated.join("orphan.json"), b"{}\n")?;
        let orphan = validate_output_closure(&root, &planned)
            .err()
            .context("orphan red escaped")?;
        assert!(orphan.to_string().contains("1 orphan entries"));
        fs::remove_file(generated.join("orphan.json"))?;

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&path, generated.join("orphan-link"))?;
            assert!(validate_output_closure(&root, &planned).is_err());
            fs::remove_file(generated.join("orphan-link"))?;
            fs::remove_file(&path)?;
            let target = generated.join("target.json");
            fs::write(&target, b"{}\n")?;
            std::os::unix::fs::symlink(&target, &path)?;
            let error = read_existing_output(&path)
                .err()
                .context("expected symlink was accepted")?;
            assert!(error.to_string().contains("symlink"));
        }
        Ok(())
    }

    #[test]
    fn output_reader_rejects_invalid_utf8() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-invalid-utf8");
        let path = root
            .join(GENERATED_DIR)
            .join("runtime.deployment-plan.json");
        fs::create_dir_all(path.parent().context("generated parent missing")?)?;
        fs::write(&path, [0xff, b'\n'])?;
        let error = read_existing_output(&path)
            .err()
            .context("invalid UTF-8 output was accepted")?;
        assert!(error.to_string().contains("UTF-8"));
        Ok(())
    }

    #[test]
    fn helm_probe_diagnostics_are_exact() -> Result<()> {
        let missing = classify_helm_probe(Err(io::Error::from(io::ErrorKind::NotFound)))
            .err()
            .context("missing Helm accepted")?;
        assert_eq!(missing, HelmProbeError::Missing);

        #[cfg(unix)]
        fn output(status: i32, stdout: &[u8]) -> std::process::Output {
            use std::os::unix::process::ExitStatusExt;
            std::process::Output {
                status: std::process::ExitStatus::from_raw(status),
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
            }
        }
        #[cfg(unix)]
        {
            assert!(matches!(
                classify_helm_probe(Ok(output(1, b""))),
                Err(HelmProbeError::Failed(_))
            ));
            assert_eq!(
                classify_helm_probe(Ok(output(0, &[0xff]))),
                Err(HelmProbeError::InvalidUtf8)
            );
            assert!(matches!(
                classify_helm_probe(Ok(output(0, b"v0.0.0\n"))),
                Err(HelmProbeError::VersionMismatch { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn three_repository_profiles_compile_and_match_committed_bytes() -> Result<()> {
        let root = crate::workspace_root()?;
        let mut planned = plan_all(&root)?;
        ensure!(
            planned.len() == 32,
            "expected 32 managed deployment outputs"
        );
        let actual = planned
            .iter()
            .map(|item| {
                item.path
                    .strip_prefix(&root)
                    .map(|path| path.to_string_lossy().replace('\\', "/"))
            })
            .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
        let mut expected = std::collections::BTreeSet::new();
        expected.insert("deploy/helm/rss/values.yaml".to_owned());
        expected.insert("deploy/helm/rss/values.schema.json".to_owned());
        for profile in repository_profiles(&root)? {
            expected.insert(format!("assemblies/{profile}/src/deployment_facts.rs"));
            expected.insert(format!("deploy/generated/{profile}.deployment-plan.json"));
            expected.insert(format!(
                "deploy/helm/rss/plans/{profile}.deployment-plan.json"
            ));
            expected.insert(format!("deploy/helm/rss/values/{profile}.yaml"));
            for phase in PHASES {
                expected.insert(format!(
                    "deploy/helm/rss/tests/golden/{profile}-{phase}.yaml"
                ));
                expected.insert(format!("deploy/rendered/{profile}-{phase}.yaml"));
                expected.insert(format!("deploy/rendered/extensions/{profile}-{phase}.yaml"));
            }
        }
        ensure!(actual == expected, "managed Helm output closure drift");
        validate_output_closure(&root, &planned)?;
        let drifted_index = planned
            .iter_mut()
            .position(|item| item.relative.starts_with("deploy/"))
            .context("missing deploy output")?;
        let original = planned[drifted_index]
            .actual
            .replace(b"tampered\n".to_vec());
        let diagnostic = check(&planned)
            .err()
            .context("synthetic workspace drift was accepted")?
            .to_string();
        ensure!(
            diagnostic.contains("deploy/"),
            "drift path is not workspace-relative"
        );
        ensure!(
            !diagnostic.contains(&root.to_string_lossy().to_string()),
            "drift diagnostic leaked absolute workspace path"
        );
        planned[drifted_index].actual = original;
        check(&planned)
    }

    #[test]
    fn check_is_zero_write_for_clean_and_drifted_outputs() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-check-zero-write");
        let path = root
            .join(GENERATED_DIR)
            .join("runtime.deployment-plan.json");
        fs::create_dir_all(path.parent().context("missing generated parent")?)?;
        fs::write(&path, b"committed\n")?;
        let before = fs::read(&path)?;

        run_with_planner(&root, Action::Check, || {
            Ok(vec![super::planned_output(
                &root,
                "deploy/generated/runtime.deployment-plan.json",
                before.clone(),
            )?])
        })?;
        assert_eq!(fs::read(&path)?, before);

        let error = run_with_planner(&root, Action::Check, || {
            Ok(vec![super::planned_output(
                &root,
                "deploy/generated/runtime.deployment-plan.json",
                b"expected\n".to_vec(),
            )?])
        })
        .err()
        .context("drifted check unexpectedly passed")?;
        assert!(error.to_string().contains("drift"));
        assert_eq!(fs::read(&path)?, before);
        assert_eq!(
            fs::read_dir(path.parent().context("missing parent")?)?.count(),
            1
        );
        Ok(())
    }

    #[test]
    fn render_preflight_failure_is_zero_write() -> Result<()> {
        let root = crate::workspace_root()?;
        let mut before = std::collections::BTreeMap::new();
        for relative in MANAGED_DIRECTORIES {
            let directory = root.join(relative);
            for name in list_managed_regular_files(&root, relative)? {
                let path = directory.join(name);
                before.insert(path.clone(), fs::read(path)?);
            }
        }
        for relative in [
            "deploy/helm/rss/values.yaml",
            "deploy/helm/rss/values.schema.json",
        ] {
            let path = root.join(relative);
            before.insert(path.clone(), fs::read(path)?);
        }
        let error = plan_all_with_stage_hook(&root, |chart| {
            let mut profiles = repository_profiles(&root)?;
            profiles.sort_unstable_by_key(|profile| (profile != DEFAULT_PROFILE, profile.clone()));
            let third = profiles.get(2).context("third Helm profile missing")?;
            fs::write(
                chart.join("values").join(format!("{third}.yaml")),
                format!("profile: {third}\nforbidden: true\n"),
            )?;
            Ok(())
        })
        .err()
        .context("preflight failure was accepted")?;
        assert!(error.to_string().contains("Helm lint rejected chart"));
        for (path, expected) in before {
            assert_eq!(fs::read(path)?, expected);
        }
        Ok(())
    }

    #[test]
    fn render_publishes_exact_set_repairs_drift_and_is_idempotent() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-render-green");
        let generated = root.join(GENERATED_DIR);
        let expected = [
            (
                "identityaudit.deployment-plan.json",
                b"{\"profile\":\"identityaudit\"}\n".as_slice(),
            ),
            (
                "runtime.deployment-plan.json",
                b"{\"profile\":\"runtime\"}\n".as_slice(),
            ),
        ];
        let plan = |name: &str, bytes: &[u8]| planned_output(generated.join(name), bytes);

        let first = expected
            .iter()
            .map(|(name, bytes)| plan(name, bytes))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(render(&root, &first)?, 2);
        validate_output_closure(&root, &first)?;
        for (name, bytes) in expected {
            assert_eq!(fs::read(generated.join(name))?, bytes);
        }
        assert_eq!(
            crate::generated_file::list_stable_regular_files(&generated)?,
            expected
                .iter()
                .map(|(name, _)| std::ffi::OsString::from(name))
                .collect::<Vec<_>>()
        );

        let unchanged = expected
            .iter()
            .map(|(name, bytes)| plan(name, bytes))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(render(&root, &unchanged)?, 0);

        fs::write(generated.join(expected[0].0), b"tampered\n")?;
        let drifted = expected
            .iter()
            .map(|(name, bytes)| plan(name, bytes))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(render(&root, &drifted)?, 1);
        validate_output_closure(&root, &drifted)?;
        for (name, bytes) in expected {
            assert_eq!(fs::read(generated.join(name))?, bytes);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn directory_replacement_during_closure_is_rejected() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-directory-swap");
        let generated = root.join(GENERATED_DIR);
        let displaced = root.join("deploy/generated-old");
        fs::create_dir_all(&generated)?;
        fs::write(generated.join("runtime.deployment-plan.json"), b"{}\n")?;
        let error = crate::generated_file::list_stable_regular_files_with_hook(&generated, || {
            fs::rename(&generated, &displaced)?;
            fs::create_dir(&generated)?;
            fs::write(generated.join("runtime.deployment-plan.json"), b"{}\n")?;
            Ok(())
        })
        .err()
        .context("directory replacement was accepted")?;
        assert!(error.to_string().contains("replaced"));
        Ok(())
    }
}
