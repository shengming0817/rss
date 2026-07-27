//! RuntimePlan-bound DeploymentPlan generation and raw-byte drift checking.
//!
//! INVARIANT: DEPLOYMENT-PLAN-ARTIFACT-CLOSURE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "deployment_plan::tests::output_closure_rejects_missing_extra_crlf_and_symlink + deployment_plan::tests::output_reader_rejects_invalid_utf8 + deployment_plan::tests::render_preflight_failure_is_zero_write + deployment_plan::tests::rendered_manifest_invariants_reject_synthetic_mutations", anti_vacuity = "deployment_plan::tests::three_repository_profiles_compile_and_match_committed_bytes + deployment_plan::tests::service_accounts_are_unique_by_workload_identity + deployment_plan::tests::longest_release_names_preserve_semantic_suffixes_and_digest" } — the verified assembly artifact matrix and every Helm profile are preflighted in full before render, and all managed directories are exact regular-file LF sets; independently parsed manifests must remain a typed bijection of the DeploymentPlan.

use anyhow::{Context, Result, ensure};
use assembly_schema::{DeploymentPlan, ParsedDeploymentPlan, PortExposure, ProbeKind};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
const STATIC_CHART_ASSETS: [&str; 6] = [
    "Chart.yaml",
    "templates/_helpers.tpl",
    "templates/configmap.yaml",
    "templates/deployment.yaml",
    "templates/service.yaml",
    "templates/serviceaccount.yaml",
];
const MANAGED_DIRECTORIES: [&str; 4] = [
    GENERATED_DIR,
    "deploy/helm/rss/plans",
    "deploy/helm/rss/values",
    "deploy/helm/rss/tests/golden",
];
const LF_RULES: [(&str, &str); 6] = [
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

    let mut planned = Vec::with_capacity(profile_names.len() * 4 + 2);
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
            &format!("{CHART_DIR}/values/{}.yaml", row.name()),
            format!("profile: {}\n", row.name()).into_bytes(),
        )?);
    }
    planned.push(planned_output(
        root,
        &format!("{CHART_DIR}/values.yaml"),
        format!("profile: {DEFAULT_PROFILE}\n").into_bytes(),
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
    for (profile, plan, plan_bytes) in &compiled {
        let rendered = helm_template(root, staged.path(), profile)?;
        if profile == DEFAULT_PROFILE {
            ensure!(
                rendered == default_render,
                "deployment plan preflight: default render is not runtime"
            );
            default_matched = true;
        }
        validate_rendered_manifests(&rendered, plan, plan_bytes, HELM_RELEASE_NAME, profile)?;
        planned.push(planned_output(
            root,
            &format!("{CHART_DIR}/tests/golden/{profile}.yaml"),
            rendered,
        )?);
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

fn values_schema(profiles: &[&str]) -> Result<Vec<u8>> {
    let schema = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": false,
        "required": ["profile"],
        "properties": { "profile": { "type": "string", "enum": profiles } }
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
            if relative.parent() == Some(Path::new("values"))
                && relative
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("yaml")
            {
                let golden = Path::new("tests/golden").join(
                    relative
                        .file_name()
                        .context("Helm profile values file name missing")?,
                );
                add_expected_chart_file(&mut expected, &golden);
            }
        }
    }
    let mut observed = BTreeMap::new();
    collect_chart_tree(&chart, &chart, &mut observed)?;
    ensure!(
        observed == expected,
        "deployment plan preflight: Helm chart closure drift"
    );
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
        let _ = helm_output(root, &["lint", chart_label, "--values", values])?;
    }
    for invalid in [
        "profile=unknown",
        "profile=Runtime",
        "profile=",
        "profile=../runtime",
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

fn helm_template(root: &Path, chart: PathBuf, profile: &str) -> Result<Vec<u8>> {
    let values = chart.join("values").join(format!("{profile}.yaml"));
    let chart = chart.to_str().context("Helm staging path is not UTF-8")?;
    let values = values.to_str().context("Helm values path is not UTF-8")?;
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
        ],
    )?;
    ensure!(
        !output.is_empty() && output.ends_with(b"\n"),
        "deployment plan preflight: Helm rendered empty output for {profile}"
    );
    Ok(output)
}

fn validate_rendered_manifests(
    rendered: &[u8],
    plan: &DeploymentPlan,
    plan_bytes: &[u8],
    release: &str,
    profile: &str,
) -> Result<()> {
    let documents = serde_yaml_ng::Deserializer::from_slice(rendered)
        .map(|document| {
            Value::deserialize(document)
                .with_context(|| format!("profile={profile}: rendered manifest is invalid YAML"))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected = expected_manifests(plan, plan_bytes, release, profile)?;
    ensure!(
        documents.len() == expected.len(),
        "profile={profile} resource=set field=/: manifest cardinality drift"
    );
    let actual_refs = documents.iter().collect::<Vec<_>>();
    for expected_document in &expected {
        let kind = required_string(expected_document, "/kind", profile, "expected")?;
        let name = required_string(expected_document, "/metadata/name", profile, kind)?;
        let actual = unique_named(&actual_refs, name, kind).with_context(|| {
            format!("profile={profile} resource={kind}/{name} field=/metadata/name")
        })?;
        validate_exact_value(
            actual,
            expected_document,
            profile,
            &format!("{kind}/{name}"),
            "",
        )?;
    }
    Ok(())
}

fn unique_named<'a>(documents: &[&'a Value], name: &str, kind: &str) -> Result<&'a Value> {
    let matching = documents
        .iter()
        .copied()
        .filter(|document| {
            document.pointer("/kind").and_then(Value::as_str) == Some(kind)
                && document.pointer("/metadata/name").and_then(Value::as_str) == Some(name)
        })
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "rendered {kind} name bijection failed for {name}"
    );
    Ok(matching[0])
}

fn expected_resource_name(release: &str, suffix: &str) -> Result<String> {
    ensure!(
        suffix.len() <= 63,
        "resource suffix exceeds DNS label budget"
    );
    if suffix.len() >= 62 {
        return Ok(suffix.to_owned());
    }
    let budget = 62usize - suffix.len();
    let prefix = release.trim_end_matches('-');
    let prefix = &prefix[..prefix.len().min(budget)];
    Ok(format!("{}-{suffix}", prefix.trim_end_matches('-')))
}

fn expected_service_account_name(release: &str, identity: &str) -> Result<String> {
    ensure!(
        valid_dns_subdomain(identity),
        "service account identity is not a DNS subdomain"
    );
    let fullname = if release.contains("rss") {
        release.to_owned()
    } else {
        format!("{release}-rss")
    };
    let scope = fullname
        .get(..fullname.len().min(20))
        .context("release name is not ASCII")?
        .trim_end_matches('-');
    let identity_budget = 49usize
        .checked_sub(scope.len())
        .context("release scope exceeds ServiceAccount name budget")?;
    let physical_identity = identity.replace('.', "-");
    let identity_part = physical_identity
        .get(..physical_identity.len().min(identity_budget))
        .context("service account identity is not ASCII")?
        .trim_end_matches('-');
    let digest_source = format!("{HELM_NAMESPACE}/{release}/rss/{identity}");
    let digest = format!("{:x}", Sha256::digest(digest_source.as_bytes()));
    Ok(format!("{scope}-{identity_part}-{}", &digest[..12]))
}

fn valid_dns_subdomain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(valid_dns_label)
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn expected_manifests(
    plan: &DeploymentPlan,
    plan_bytes: &[u8],
    release: &str,
    profile: &str,
) -> Result<Vec<Value>> {
    let mut manifests = Vec::new();
    let mut identities = BTreeSet::new();
    for workload in plan.workloads() {
        if identities.insert(workload.identity().service_account()) {
            manifests.push(expected_service_account(plan, workload, release, profile)?);
        }
    }
    manifests.push(expected_config_map(plan, plan_bytes, release, profile)?);
    for service in plan.services().iter().filter(|service| {
        service
            .ports()
            .iter()
            .any(|port| port.exposure() == PortExposure::ServiceExposed)
    }) {
        manifests.push(expected_service(plan, service, release, profile)?);
    }
    for workload in plan.workloads() {
        manifests.push(expected_deployment(plan, workload, release, profile)?);
    }
    Ok(manifests)
}

fn expected_service_account(
    plan: &DeploymentPlan,
    workload: &assembly_schema::WorkloadPlan,
    release: &str,
    profile: &str,
) -> Result<Value> {
    Ok(serde_json::json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": expected_metadata(
            plan,
            expected_service_account_name(release, workload.identity().service_account())?,
            release,
            profile,
            workload.name(),
        ),
        "automountServiceAccountToken": false,
    }))
}

fn expected_config_map(
    plan: &DeploymentPlan,
    plan_bytes: &[u8],
    release: &str,
    profile: &str,
) -> Result<Value> {
    let digest = deployment_digest(plan)?;
    let name = expected_resource_name(release, &format!("{profile}-plan-{}", &digest[..12]))?;
    let raw = std::str::from_utf8(plan_bytes)
        .with_context(|| format!("profile={profile}: typed DeploymentPlan bytes are not UTF-8"))?;
    Ok(serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": expected_metadata(plan, name, release, profile, profile),
        "immutable": true,
        "data": { "plan.json": raw },
    }))
}

fn expected_service(
    plan: &DeploymentPlan,
    service: &assembly_schema::ServicePlan,
    release: &str,
    profile: &str,
) -> Result<Value> {
    let ports = service
        .ports()
        .iter()
        .filter(|port| port.exposure() == PortExposure::ServiceExposed)
        .map(|port| {
            serde_json::json!({
                "name": port.name(),
                "port": port.port(),
                "targetPort": port.name(),
                "protocol": "TCP",
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": expected_metadata(
            plan,
            expected_resource_name(release, service.name())?,
            release,
            profile,
            service.workload(),
        ),
        "spec": {
            "type": "ClusterIP",
            "selector": expected_selector_labels(release, service.workload()),
            "ports": ports,
        },
    }))
}

fn expected_deployment(
    plan: &DeploymentPlan,
    workload: &assembly_schema::WorkloadPlan,
    release: &str,
    profile: &str,
) -> Result<Value> {
    let ports = plan
        .services()
        .iter()
        .filter(|service| service.workload() == workload.name())
        .flat_map(|service| service.ports())
        .map(|port| {
            serde_json::json!({
                "name": port.name(),
                "containerPort": port.port(),
                "protocol": "TCP",
            })
        })
        .collect::<Vec<_>>();
    let mut container = serde_json::json!({
        "name": workload.name(),
        "image": workload.image(),
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "allowPrivilegeEscalation": false,
            "capabilities": { "drop": ["ALL"] },
            "privileged": false,
            "readOnlyRootFilesystem": true,
            "runAsNonRoot": true,
            "runAsUser": 65532,
            "runAsGroup": 65532,
            "seccompProfile": { "type": "RuntimeDefault" },
        },
        "ports": ports,
        "resources": serde_json::to_value(workload.resources())?,
        "volumeMounts": [{
            "name": "deployment-plan",
            "mountPath": "/var/run/rss/deployment",
            "readOnly": true,
        }],
    });
    let container_object = container
        .as_object_mut()
        .context("expected container is not an object")?;
    for probe in workload.probes() {
        let field = match probe.kind() {
            ProbeKind::Startup => "startupProbe",
            ProbeKind::Readiness => "readinessProbe",
            ProbeKind::Liveness => "livenessProbe",
        };
        container_object.insert(
            field.to_owned(),
            serde_json::json!({
                "httpGet": {
                    "path": probe.path(),
                    "port": probe.port(),
                    "scheme": "HTTP",
                }
            }),
        );
    }
    let digest = deployment_digest(plan)?;
    let config_map_name =
        expected_resource_name(release, &format!("{profile}-plan-{}", &digest[..12]))?;
    Ok(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": expected_metadata(
            plan,
            expected_resource_name(release, workload.name())?,
            release,
            profile,
            workload.name(),
        ),
        "spec": {
            "replicas": 1,
            "strategy": { "type": "Recreate" },
            "selector": { "matchLabels": expected_selector_labels(release, workload.name()) },
            "template": {
                "metadata": {
                    "labels": expected_selector_labels(release, workload.name()),
                    "annotations": expected_annotations(plan),
                },
                "spec": {
                    "serviceAccountName": expected_service_account_name(
                        release,
                        workload.identity().service_account(),
                    )?,
                    "automountServiceAccountToken": false,
                    "enableServiceLinks": false,
                    "terminationGracePeriodSeconds": 60,
                    "securityContext": {
                        "runAsNonRoot": true,
                        "runAsUser": 65532,
                        "runAsGroup": 65532,
                        "seccompProfile": { "type": "RuntimeDefault" },
                    },
                    "containers": [container],
                    "volumes": [{
                        "name": "deployment-plan",
                        "projected": {
                            "defaultMode": "0444",
                            "sources": [{
                                "configMap": {
                                    "name": config_map_name,
                                    "items": [{ "key": "plan.json", "path": "plan.json" }],
                                }
                            }],
                        },
                    }],
                },
            },
        },
    }))
}

fn deployment_digest(plan: &DeploymentPlan) -> Result<&str> {
    let fingerprint = plan.deployment_fingerprint().as_str();
    let digest = fingerprint
        .strip_prefix("sha256:")
        .context("deployment fingerprint is not sha256")?;
    ensure!(digest.len() >= 12, "deployment fingerprint is truncated");
    Ok(digest)
}

fn expected_metadata(
    plan: &DeploymentPlan,
    name: String,
    release: &str,
    profile: &str,
    component: &str,
) -> Value {
    serde_json::json!({
        "name": name,
        "labels": {
            "helm.sh/chart": "rss-0.1.0",
            "app.kubernetes.io/name": "rss",
            "app.kubernetes.io/instance": release,
            "app.kubernetes.io/component": component,
            "app.kubernetes.io/managed-by": "Helm",
            "rss.gocell.io/profile": profile,
        },
        "annotations": expected_annotations(plan),
    })
}

fn expected_selector_labels(release: &str, component: &str) -> Value {
    serde_json::json!({
        "app.kubernetes.io/name": "rss",
        "app.kubernetes.io/instance": release,
        "app.kubernetes.io/component": component,
    })
}

fn expected_annotations(plan: &DeploymentPlan) -> Value {
    serde_json::json!({
        "rss.gocell.io/assembly-fingerprint": plan.assembly_fingerprint().as_str(),
        "rss.gocell.io/runtime-plan-fingerprint": plan.runtime_plan_fingerprint().as_str(),
        "rss.gocell.io/deployment-fingerprint": plan.deployment_fingerprint().as_str(),
    })
}

fn required_string<'a>(
    document: &'a Value,
    pointer: &str,
    profile: &str,
    resource: &str,
) -> Result<&'a str> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| {
            format!("profile={profile} resource={resource} field={pointer}: string missing")
        })
}

fn validate_exact_value(
    actual: &Value,
    expected: &Value,
    profile: &str,
    resource: &str,
    pointer: &str,
) -> Result<()> {
    let field = if pointer.is_empty() { "/" } else { pointer };
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            let actual_keys = actual.keys().collect::<BTreeSet<_>>();
            let expected_keys = expected.keys().collect::<BTreeSet<_>>();
            if actual_keys != expected_keys {
                let key = actual_keys
                    .symmetric_difference(&expected_keys)
                    .next()
                    .context("object key-set drift has no differing key")?;
                let drift_pointer = format!("{pointer}/{}", escape_json_pointer(key));
                anyhow::bail!(
                    "profile={profile} resource={resource} field={drift_pointer}: object key set drift"
                );
            }
            for (key, expected_child) in expected {
                let child_pointer = format!("{pointer}/{}", escape_json_pointer(key));
                let actual_child = actual.get(key).with_context(|| {
                    format!(
                        "profile={profile} resource={resource} field={child_pointer}: field missing"
                    )
                })?;
                validate_exact_value(
                    actual_child,
                    expected_child,
                    profile,
                    resource,
                    &child_pointer,
                )?;
            }
        }
        (Value::Array(actual), Value::Array(expected)) => {
            if actual.len() != expected.len() {
                let drift_pointer = format!("{pointer}/{}", actual.len().min(expected.len()));
                anyhow::bail!(
                    "profile={profile} resource={resource} field={drift_pointer}: array cardinality drift"
                );
            }
            for (index, (actual_child, expected_child)) in
                actual.iter().zip(expected.iter()).enumerate()
            {
                let child_pointer = format!("{pointer}/{index}");
                validate_exact_value(
                    actual_child,
                    expected_child,
                    profile,
                    resource,
                    &child_pointer,
                )?;
            }
        }
        _ => ensure!(
            actual == expected,
            "profile={profile} resource={resource} field={field}: typed value drift"
        ),
    }
    Ok(())
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
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
        let observed = crate::generated_file::list_stable_regular_files(&directory)?
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
    validate_output_closure(root, planned)?;
    let mut changed = 0usize;
    for item in planned {
        if item.actual.as_deref() == Some(item.expected.as_slice()) {
            continue;
        }
        crate::generated_file::atomic_replace(&item.path, &item.expected)
            .context("deployment plan render: atomic publication failed")?;
        changed += 1;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
            for relative in [
                format!("values/{profile}.yaml"),
                format!("plans/{profile}.deployment-plan.json"),
                format!("tests/golden/{profile}.yaml"),
            ] {
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

    fn runtime_typed_plan(root: &Path) -> Result<(DeploymentPlan, Vec<u8>)> {
        let matrix = crate::assembly_artifacts::load_verified(root)?;
        let row = matrix
            .supported_rows()
            .iter()
            .find(|row| row.name() == DEFAULT_PROFILE)
            .context("runtime profile missing")?;
        let profile = row.deployment();
        let plan = DeploymentPlan::compile_v1(profile.runtime_plan(), profile.plan_input())?;
        let mut bytes = serde_json::to_vec_pretty(&plan)?;
        bytes.push(b'\n');
        Ok((plan, bytes))
    }

    fn mutate_yaml(
        rendered: &[u8],
        mutate: impl FnOnce(&mut Vec<Value>) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut documents = serde_yaml_ng::Deserializer::from_slice(rendered)
            .map(|document| Value::deserialize(document).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        mutate(&mut documents)?;
        let mut output = Vec::new();
        for document in documents {
            output.extend_from_slice(b"---\n");
            output.extend_from_slice(serde_yaml_ng::to_string(&document)?.as_bytes());
        }
        Ok(output)
    }

    #[test]
    fn rendered_manifest_invariants_reject_synthetic_mutations() -> Result<()> {
        let root = crate::workspace_root()?;
        let (plan, plan_bytes) = runtime_typed_plan(&root)?;
        let chart = root.join(CHART_DIR);
        let chart = chart
            .to_str()
            .context("repository chart path is not UTF-8")?;
        let golden = helm_output(
            &root,
            &[
                "template",
                HELM_RELEASE_NAME,
                chart,
                "--namespace",
                HELM_NAMESPACE,
                "--set",
                "profile=runtime",
            ],
        )?;
        validate_rendered_manifests(
            &golden,
            &plan,
            &plan_bytes,
            HELM_RELEASE_NAME,
            DEFAULT_PROFILE,
        )?;

        for (kind, pointer) in [
            ("Deployment", "/spec/template/spec/enableServiceLinks"),
            (
                "Deployment",
                "/spec/template/spec/automountServiceAccountToken",
            ),
            (
                "Deployment",
                "/spec/template/spec/terminationGracePeriodSeconds",
            ),
            (
                "Deployment",
                "/spec/template/spec/securityContext/runAsNonRoot",
            ),
            (
                "Deployment",
                "/spec/template/spec/securityContext/runAsUser",
            ),
            (
                "Deployment",
                "/spec/template/spec/securityContext/runAsGroup",
            ),
            (
                "Deployment",
                "/spec/template/spec/securityContext/seccompProfile",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/runAsUser",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/runAsGroup",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/seccompProfile",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/privileged",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
            ),
            (
                "Deployment",
                "/spec/template/spec/containers/0/securityContext/capabilities",
            ),
            ("ServiceAccount", "/automountServiceAccountToken"),
        ] {
            let unsafe_security = mutate_yaml(&golden, |documents| {
                let document = documents
                    .iter_mut()
                    .find(|document| document["kind"] == kind)
                    .with_context(|| format!("{kind} fixture missing"))?;
                let (parent, key) = pointer
                    .rsplit_once('/')
                    .with_context(|| format!("invalid mutation pointer {pointer}"))?;
                document
                    .pointer_mut(parent)
                    .with_context(|| format!("mutation parent missing: {parent}"))?
                    .as_object_mut()
                    .with_context(|| format!("mutation parent is not an object: {parent}"))?
                    .remove(key);
                Ok(())
            })?;
            ensure!(
                validate_rendered_manifests(
                    &unsafe_security,
                    &plan,
                    &plan_bytes,
                    HELM_RELEASE_NAME,
                    DEFAULT_PROFILE,
                )
                .is_err(),
                "security mutation escaped validator: {kind}{pointer}"
            );
        }

        for (pointer, value) in [
            (
                "/spec/template/spec/containers/0/command",
                serde_json::json!(["/bin/sh"]),
            ),
            (
                "/spec/template/spec/containers/0/args",
                serde_json::json!(["-c"]),
            ),
            (
                "/spec/template/spec/containers/0/env",
                serde_json::json!([{"name":"SECRET","value":"redacted"}]),
            ),
            (
                "/spec/template/spec/containers/0/envFrom",
                serde_json::json!([{"secretRef":{"name":"escape"}}]),
            ),
            (
                "/spec/template/spec/containers/0/lifecycle",
                serde_json::json!({"postStart":{"exec":{"command":["true"]}}}),
            ),
            (
                "/spec/template/spec/containers/0/securityContext/capabilities/add",
                serde_json::json!(["NET_ADMIN"]),
            ),
            (
                "/spec/template/spec/containers/0/volumeMounts/1",
                serde_json::json!({"name":"escape","mountPath":"/escape"}),
            ),
            (
                "/spec/template/spec/containers/0/startupProbe/tcpSocket",
                serde_json::json!({"port":8080}),
            ),
            ("/spec/template/spec/hostNetwork", serde_json::json!(true)),
            ("/spec/template/spec/hostPID", serde_json::json!(true)),
            ("/spec/template/spec/hostIPC", serde_json::json!(true)),
            (
                "/spec/template/spec/initContainers",
                serde_json::json!([{"name":"escape","image":"escape"}]),
            ),
            (
                "/spec/template/spec/ephemeralContainers",
                serde_json::json!([{"name":"escape","image":"escape"}]),
            ),
            (
                "/spec/template/spec/volumes/1",
                serde_json::json!({"name":"escape","hostPath":{"path":"/"}}),
            ),
            (
                "/spec/template/spec/volumes/0/projected/sources/1",
                serde_json::json!({"serviceAccountToken":{"path":"token"}}),
            ),
        ] {
            let unsafe_field = mutate_yaml(&golden, |documents| {
                let deployment = documents
                    .iter_mut()
                    .find(|doc| doc["kind"] == "Deployment")
                    .context("Deployment fixture missing")?;
                insert_json_pointer(deployment, pointer, value.clone())
            })?;
            let diagnostic = validate_rendered_manifests(
                &unsafe_field,
                &plan,
                &plan_bytes,
                HELM_RELEASE_NAME,
                DEFAULT_PROFILE,
            )
            .err()
            .with_context(|| format!("unplanned manifest field escaped validator: {pointer}"))?
            .to_string();
            ensure!(
                diagnostic.contains("profile=runtime")
                    && diagnostic.contains("resource=Deployment/rss-runtime")
                    && diagnostic.contains(&format!("field={pointer}")),
                "manifest diagnostic lost profile/resource/field context: {pointer}"
            );
            ensure!(
                !diagnostic.contains("SECRET")
                    && !diagnostic.contains("redacted")
                    && !diagnostic.contains("/bin/sh"),
                "manifest diagnostic disclosed mutated values: {pointer}"
            );
        }

        for pointer in [
            "/spec/selector/matchLabels/app.kubernetes.io~1component",
            "/spec/template/metadata/labels/app.kubernetes.io~1component",
        ] {
            let selector_drift = mutate_yaml(&golden, |documents| {
                let deployment = documents
                    .iter_mut()
                    .find(|doc| doc["kind"] == "Deployment")
                    .context("Deployment fixture missing")?;
                insert_json_pointer(deployment, pointer, serde_json::json!("other"))
            })?;
            ensure!(
                validate_rendered_manifests(
                    &selector_drift,
                    &plan,
                    &plan_bytes,
                    HELM_RELEASE_NAME,
                    DEFAULT_PROFILE
                )
                .is_err(),
                "selector/label drift escaped validator: {pointer}"
            );
        }

        for pointer in ["/spec/ports/1", "/spec/template/spec/containers/0/ports/1"] {
            let duplicate_port = mutate_yaml(&golden, |documents| {
                let kind = if pointer.starts_with("/spec/ports") {
                    "Service"
                } else {
                    "Deployment"
                };
                let document = documents
                    .iter_mut()
                    .find(|doc| doc["kind"] == kind)
                    .with_context(|| format!("{kind} fixture missing"))?;
                let duplicate = document
                    .pointer(pointer)
                    .with_context(|| format!("port fixture missing: {pointer}"))?
                    .clone();
                let parent = pointer.rsplit_once('/').context("port parent missing")?.0;
                document
                    .pointer_mut(parent)
                    .and_then(Value::as_array_mut)
                    .with_context(|| format!("port array missing: {parent}"))?
                    .push(duplicate);
                Ok(())
            })?;
            ensure!(
                validate_rendered_manifests(
                    &duplicate_port,
                    &plan,
                    &plan_bytes,
                    HELM_RELEASE_NAME,
                    DEFAULT_PROFILE
                )
                .is_err(),
                "duplicate port escaped validator: {pointer}"
            );
        }

        let exposed_internal = mutate_yaml(&golden, |documents| {
            let mut service = documents
                .iter()
                .find(|doc| doc["kind"] == "Service")
                .context("Service fixture missing")?
                .clone();
            service["metadata"]["name"] = Value::String("rss-runtime-internal".to_owned());
            service["spec"]["ports"] = serde_json::json!([{"name":"internal","port":8083,"targetPort":"internal","protocol":"TCP"}]);
            documents.push(service);
            Ok(())
        })?;
        assert!(
            validate_rendered_manifests(
                &exposed_internal,
                &plan,
                &plan_bytes,
                HELM_RELEASE_NAME,
                DEFAULT_PROFILE,
            )
            .is_err()
        );

        let tampered_plan = mutate_yaml(&golden, |documents| {
            let config = documents
                .iter_mut()
                .find(|doc| doc["kind"] == "ConfigMap")
                .context("ConfigMap fixture missing")?;
            config["data"]["plan.json"] = Value::String("{}\n".to_owned());
            Ok(())
        })?;
        assert!(
            validate_rendered_manifests(
                &tampered_plan,
                &plan,
                &plan_bytes,
                HELM_RELEASE_NAME,
                DEFAULT_PROFILE,
            )
            .is_err()
        );
        Ok(())
    }

    fn insert_json_pointer(document: &mut Value, pointer: &str, value: Value) -> Result<()> {
        let (parent, key) = pointer
            .rsplit_once('/')
            .with_context(|| format!("invalid mutation pointer {pointer}"))?;
        let parent = document
            .pointer_mut(parent)
            .with_context(|| format!("mutation parent missing: {parent}"))?;
        if let Some(object) = parent.as_object_mut() {
            object.insert(key.replace("~1", "/").replace("~0", "~"), value);
            return Ok(());
        }
        let index = key
            .parse::<usize>()
            .with_context(|| format!("mutation index invalid: {pointer}"))?;
        let array = parent
            .as_array_mut()
            .with_context(|| format!("mutation parent is not an array: {pointer}"))?;
        ensure!(
            index <= array.len(),
            "mutation index out of range: {pointer}"
        );
        array.insert(index, value);
        Ok(())
    }

    #[test]
    fn longest_release_names_preserve_semantic_suffixes_and_digest() -> Result<()> {
        let root = crate::workspace_root()?;
        let planned = plan_all(&root)?;
        let staged = StagedChart::prepare(&root, &planned)?;
        let release = "a".repeat(53);
        let chart = staged.path();
        let chart = chart.to_str().context("chart path UTF-8")?;
        let release_arg = release.as_str();
        let rendered = helm_output(
            &root,
            &["template", release_arg, chart, "--set", "profile=runtime"],
        )?;
        let documents = serde_yaml_ng::Deserializer::from_slice(&rendered)
            .map(|document| Value::deserialize(document).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        let (_, plan_bytes) = runtime_typed_plan(&root)?;
        let plan_json: Value = serde_json::from_slice(&plan_bytes)?;
        let digest = plan_json["deploymentFingerprint"]
            .as_str()
            .context("deployment fingerprint missing")?
            .trim_start_matches("sha256:");
        for document in documents {
            let name = document
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .context("resource name missing")?;
            ensure!(name.len() <= 63, "resource name exceeds DNS label limit");
            match document["kind"].as_str() {
                Some("Deployment" | "Service") => {
                    ensure!(name.ends_with("-runtime"), "semantic runtime suffix lost")
                }
                Some("ConfigMap") => ensure!(
                    name.ends_with(&format!("-runtime-plan-{}", &digest[..12])),
                    "ConfigMap digest suffix lost"
                ),
                _ => {}
            }
        }
        Ok(())
    }

    #[test]
    fn resource_names_preserve_valid_typed_suffix_boundaries() -> Result<()> {
        let root = crate::workspace_root()?;
        for suffix_len in [61usize, 62, 63] {
            let planned = plan_all(&root)?;
            let staged = StagedChart::prepare(&root, &planned)?;
            let plan_path = staged.path().join("plans/runtime.deployment-plan.json");
            let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
            let workload_name = "a".repeat(suffix_len);
            let service_name = "b".repeat(suffix_len);
            plan["workloads"][0]["name"] = Value::String(workload_name.clone());
            for service in plan["services"]
                .as_array_mut()
                .context("runtime services missing")?
            {
                service["workload"] = Value::String(workload_name.clone());
            }
            plan["services"][0]["name"] = Value::String(service_name.clone());
            let mut bytes = serde_json::to_vec_pretty(&plan)?;
            bytes.push(b'\n');
            fs::write(&plan_path, bytes)?;

            let rendered = helm_template(&root, staged.path(), DEFAULT_PROFILE)?;
            let documents = serde_yaml_ng::Deserializer::from_slice(&rendered)
                .map(|document| Value::deserialize(document).map_err(Into::into))
                .collect::<Result<Vec<_>>>()?;
            for (kind, suffix) in [
                ("Deployment", workload_name.as_str()),
                ("Service", service_name.as_str()),
            ] {
                let actual = documents
                    .iter()
                    .find(|document| {
                        document["kind"] == kind
                            && document["metadata"]["name"]
                                .as_str()
                                .is_some_and(|name| name.ends_with(suffix))
                    })
                    .and_then(|document| document["metadata"]["name"].as_str())
                    .with_context(|| format!("{kind} suffix boundary {suffix_len} missing"))?;
                ensure!(
                    actual == expected_resource_name(HELM_RELEASE_NAME, suffix)?,
                    "{kind} suffix boundary {suffix_len} drift"
                );
                ensure!(
                    actual.len() <= 63 && !actual.starts_with('-'),
                    "{kind} suffix boundary {suffix_len} is not a DNS label"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn service_accounts_are_unique_by_workload_identity() -> Result<()> {
        let root = crate::workspace_root()?;
        let planned = plan_all(&root)?;
        let staged = StagedChart::prepare(&root, &planned)?;
        let plan_path = staged.path().join("plans/runtime.deployment-plan.json");
        let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
        let workloads = plan["workloads"]
            .as_array_mut()
            .context("runtime workloads missing")?;
        let mut duplicate = workloads[0].clone();
        duplicate["name"] = Value::String("runtime-copy".to_owned());
        workloads.push(duplicate);
        let mut bytes = serde_json::to_vec_pretty(&plan)?;
        bytes.push(b'\n');
        fs::write(&plan_path, bytes)?;

        let rendered = helm_template(&root, staged.path(), DEFAULT_PROFILE)?;
        let documents = serde_yaml_ng::Deserializer::from_slice(&rendered)
            .map(|document| Value::deserialize(document).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        let count = |kind: &str| {
            documents
                .iter()
                .filter(|document| document["kind"].as_str() == Some(kind))
                .count()
        };
        ensure!(
            count("Deployment") == 2,
            "synthetic workload was not rendered"
        );
        ensure!(
            count("ServiceAccount") == 1,
            "duplicate identity rendered duplicate ServiceAccounts"
        );
        Ok(())
    }

    #[test]
    fn service_accounts_are_release_scoped_and_validator_accepts_each_release() -> Result<()> {
        let root = crate::workspace_root()?;
        let planned = plan_all(&root)?;
        let staged = StagedChart::prepare(&root, &planned)?;
        let chart = staged.path();
        let chart = chart.to_str().context("chart path UTF-8")?;
        let (plan, plan_bytes) = runtime_typed_plan(&root)?;
        let mut account_sets = Vec::new();
        for release in ["rss-a", "rss-b"] {
            let rendered = helm_output(
                &root,
                &[
                    "template",
                    release,
                    chart,
                    "--namespace",
                    HELM_NAMESPACE,
                    "--set",
                    "profile=runtime",
                ],
            )?;
            validate_rendered_manifests(&rendered, &plan, &plan_bytes, release, DEFAULT_PROFILE)?;
            let names = serde_yaml_ng::Deserializer::from_slice(&rendered)
                .map(|document| Value::deserialize(document).map_err(Into::into))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|document| document["kind"] == "ServiceAccount")
                .map(|document| {
                    document
                        .pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .context("ServiceAccount name missing")
                })
                .collect::<Result<std::collections::BTreeSet<_>>>()?;
            ensure!(!names.is_empty(), "release rendered no ServiceAccount");
            account_sets.push(names);
        }
        ensure!(
            account_sets[0].is_disjoint(&account_sets[1]),
            "ServiceAccount names collide across releases"
        );
        Ok(())
    }

    #[test]
    fn service_accounts_accept_full_typed_dns_subdomain_boundaries() -> Result<()> {
        let root = crate::workspace_root()?;
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        ensure!(longest.len() == 253, "test DNS boundary is not 253 bytes");

        for identity in ["runtime.team".to_owned(), longest] {
            let planned = plan_all(&root)?;
            let staged = StagedChart::prepare(&root, &planned)?;
            let plan_path = staged.path().join("plans/runtime.deployment-plan.json");
            let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
            for workload in plan["workloads"]
                .as_array_mut()
                .context("runtime workloads missing")?
            {
                workload["identity"]["serviceAccount"] = Value::String(identity.clone());
            }
            let mut bytes = serde_json::to_vec_pretty(&plan)?;
            bytes.push(b'\n');
            fs::write(&plan_path, bytes)?;

            let rendered = helm_template(&root, staged.path(), DEFAULT_PROFILE)?;
            let documents = serde_yaml_ng::Deserializer::from_slice(&rendered)
                .map(|document| Value::deserialize(document).map_err(Into::into))
                .collect::<Result<Vec<_>>>()?;
            let expected = expected_service_account_name(HELM_RELEASE_NAME, &identity)?;
            let accounts = documents
                .iter()
                .filter(|document| document["kind"] == "ServiceAccount")
                .map(|document| {
                    document
                        .pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .context("ServiceAccount name missing")
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                accounts == [expected.as_str()],
                "typed identity did not render the expected ServiceAccount"
            );
            ensure!(
                expected.len() <= 63 && valid_dns_label(&expected),
                "physical ServiceAccount name is not a DNS label"
            );
            for deployment in documents
                .iter()
                .filter(|document| document["kind"] == "Deployment")
            {
                ensure!(
                    deployment.pointer("/spec/template/spec/serviceAccountName")
                        == Some(&Value::String(expected.clone())),
                    "Deployment does not reference the physical ServiceAccount"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn three_repository_profiles_compile_and_match_committed_bytes() -> Result<()> {
        let root = crate::workspace_root()?;
        let mut planned = plan_all(&root)?;
        ensure!(
            planned.len() == 14,
            "expected fourteen managed Helm outputs"
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
            expected.insert(format!("deploy/generated/{profile}.deployment-plan.json"));
            expected.insert(format!(
                "deploy/helm/rss/plans/{profile}.deployment-plan.json"
            ));
            expected.insert(format!("deploy/helm/rss/values/{profile}.yaml"));
            expected.insert(format!("deploy/helm/rss/tests/golden/{profile}.yaml"));
        }
        ensure!(actual == expected, "managed Helm output closure drift");
        validate_output_closure(&root, &planned)?;
        let original = planned[0].actual.replace(b"tampered\n".to_vec());
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
        planned[0].actual = original;
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
        for directory in MANAGED_DIRECTORIES {
            let directory = root.join(directory);
            for name in crate::generated_file::list_stable_regular_files(&directory)? {
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
