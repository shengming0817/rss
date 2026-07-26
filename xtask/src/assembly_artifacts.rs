//! Closed deployment-artifact inventory for every discovered assembly.
//!
//! INVARIANT: ASSEMBLY-ARTIFACT-MATRIX-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::synthetic_red_rejects_incomplete_or_unsafe_rows", anti_vacuity = "tests::real_workspace_matrix_is_exact_and_complete" } -- the schema-v1 lifecycle declaration is an exact bijection with `assemblies/*`; only rows whose Cargo, image, config, health/inventory and journey evidence all validate can become `VerifiedArtifactMatrix` values.

use anyhow::{Context, Result, bail};
use assembly_schema::{AssemblyListenerKind, AssemblyManifest};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

use crate::diagnostic::{self, finding};

const MATRIX_PATH: &str = "assemblies/artifacts.toml";
const SCHEMA_VERSION: u32 = 1;
const MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024;
const MISSING: &str = "[missing]";
const UNKNOWN: &str = "[unknown]";
const INVALID: &str = "[invalid]";
const UNPARSEABLE: &str = "[unparseable]";
const REQUIRED_SUPPORTED_ASSEMBLIES: &[&str] = &["identityaudit", "runtime", "settingsonly"];
const MARKDOWN_HEADER: &str = "# Assembly Artifact Matrix\n\n| Assembly | Declared lifecycle | Binary | Image | Config carrier | Health / inventory | Journey | Reason |\n|---|---|---|---|---|---|---|---|\n";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMatrix {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    assemblies: Vec<RawAssembly>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAssembly {
    name: String,
    lifecycle: Lifecycle,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    binary: Option<RawBinary>,
    #[serde(default)]
    image: Option<RawImage>,
    #[serde(default, rename = "configSchema")]
    config_schema: Option<RawConfigSchema>,
    #[serde(default, rename = "healthInventory")]
    health_inventory: Option<RawHealthInventory>,
    #[serde(default)]
    journey: Option<RawJourney>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Lifecycle {
    Supported,
    CompileOnly,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBinary {
    package: String,
    target: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImage {
    dockerfile: String,
    target: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RawConfigSchema {
    JsonSchema { path: String },
    TypedEnvCatalog { path: String },
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHealthInventory {
    owner: HealthOwner,
    listener: HealthListener,
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum HealthOwner {
    #[serde(rename = "runtimeexec")]
    Runtimeexec,
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum HealthListener {
    #[serde(rename = "health")]
    Health,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RawJourney {
    CargoTest {
        package: String,
        target: String,
        test: String,
    },
    ComposeSmokeV1 {
        path: String,
    },
}

/// The only deployment-facing matrix value. Its fields are private and construction is confined to
/// full validation below, so callers cannot accidentally treat observed declarations as evidence.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct VerifiedArtifactMatrix {
    supported: Vec<SupportedArtifact>,
}

impl VerifiedArtifactMatrix {
    #[allow(dead_code)]
    pub(crate) fn supported_rows(&self) -> &[SupportedArtifact] {
        &self.supported
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct SupportedArtifact {
    name: String,
    binary: RawBinary,
    image: RawImage,
    config_schema: RawConfigSchema,
    health_inventory: RawHealthInventory,
    journey: RawJourney,
}

#[allow(dead_code)]
impl SupportedArtifact {
    #[allow(dead_code)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn binary(&self) -> (&str, &str) {
        (&self.binary.package, &self.binary.target)
    }

    pub(crate) fn image(&self) -> (&str, &str) {
        (&self.image.dockerfile, &self.image.target)
    }

    pub(crate) fn config_carrier(&self) -> (&'static str, &str) {
        match &self.config_schema {
            RawConfigSchema::JsonSchema { path } => ("json-schema", path),
            RawConfigSchema::TypedEnvCatalog { path } => ("typed-env-catalog", path),
        }
    }

    pub(crate) fn health_inventory(&self) -> (&'static str, &'static str) {
        let RawHealthInventory { owner, listener } = self.health_inventory;
        (owner.as_str(), listener.as_str())
    }

    pub(crate) fn journey(&self) -> String {
        journey_identity(&self.journey)
    }
}

impl HealthOwner {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Runtimeexec => "runtimeexec",
        }
    }
}

impl HealthListener {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactRule {
    Schema,
    AssemblyBijection,
    SupportedRatchet,
    LifecycleShape,
    Identity,
    Binary,
    Image,
    Config,
    Health,
    Journey,
    PathSafety,
    SpecializedBoundary,
}

type ArtifactFinding = diagnostic::Finding<ArtifactRule>;

macro_rules! reject {
    ($findings:expr, $rule:ident, $subject:expr, $($arg:tt)*) => {
        $findings.push(finding(ArtifactRule::$rule, $subject, format!($($arg)*)))
    };
}

struct Validation {
    verified: Option<VerifiedArtifactMatrix>,
    findings: Vec<ArtifactFinding>,
}

/// Validate the workspace matrix and always print its stable observed view before returning status.
pub(crate) fn run() -> Result<()> {
    let root = crate::workspace_root()?;
    let path = root.join(MATRIX_PATH);
    if let Err(error) = ensure_regular_path(&root, MATRIX_PATH) {
        print!("{MARKDOWN_HEADER}");
        print_verification_failure(&[format!("{error:#}")]);
        return Err(error).with_context(|| format!("检查 {} 失败", path.display()));
    }
    let source = match read_artifact_utf8(&path, "assembly artifact matrix") {
        Ok(source) => source,
        Err(error) => {
            print!("{MARKDOWN_HEADER}");
            print_verification_failure(&[format!("{error:#}")]);
            return Err(error).with_context(|| format!("读取 {} 失败", path.display()));
        }
    };
    let raw: RawMatrix = match toml::from_str(&source) {
        Ok(raw) => raw,
        Err(error) => {
            print!("{}", render_unverified_source(&source));
            print_verification_failure(&[error.to_string()]);
            return Err(error)
                .with_context(|| format!("解析 closed artifact matrix {} 失败", path.display()));
        }
    };
    let observed = render_observed(&raw);
    print!("{observed}");
    let validation = match validate_matrix(&root, raw) {
        Ok(validation) => validation,
        Err(error) => {
            print_verification_failure(&[format!("{error:#}")]);
            return Err(error);
        }
    };
    if validation.findings.is_empty() {
        let verified = validation
            .verified
            .context("artifact matrix validation succeeded without verified value")?;
        println!(
            "\n## Verification\n\n**STATIC CARRIERS VERIFIED** — {} supported assembly artifact rows passed closed validation.\n\nThis verdict does not include same-head test, image-build, or deployment execution receipts.",
            verified.supported_rows().len()
        );
        Ok(())
    } else {
        print_artifact_findings(&validation.findings);
        bail!(
            "{}",
            format_artifact_findings(&validation.findings).join("\n")
        )
    }
}

fn print_verification_failure(errors: &[String]) {
    print!("{}", verification_failure_markdown(errors));
}

fn print_artifact_findings(findings: &[ArtifactFinding]) {
    let errors = format_artifact_findings(findings);
    print_verification_failure(&errors);
}

fn format_artifact_findings(findings: &[ArtifactFinding]) -> Vec<String> {
    findings.iter().map(diagnostic::format_finding).collect()
}

fn verification_failure_markdown(errors: &[String]) -> String {
    let mut output = String::from("\n## Verification\n\n**FAILED**\n\n");
    for error in errors {
        let _ = writeln!(output, "- {}", markdown_cell(error));
    }
    output
}

/// Load the verified typed carrier for DeploymentPlan/release consumers. Observed rows never cross
/// this boundary when any closed-world or artifact-semantic finding exists.
#[allow(dead_code)]
pub(crate) fn load_verified(root: &Path) -> Result<VerifiedArtifactMatrix> {
    let validation = validate_root(root)?;
    if !validation.findings.is_empty() {
        bail!(
            "{}",
            format_artifact_findings(&validation.findings).join("\n")
        );
    }
    validation
        .verified
        .context("artifact matrix validation succeeded without verified value")
}

fn validate_root(root: &Path) -> Result<Validation> {
    let path = root.join(MATRIX_PATH);
    ensure_regular_path(root, MATRIX_PATH)?;
    let source = read_artifact_utf8(&path, "assembly artifact matrix")
        .with_context(|| format!("读取 {} 失败", path.display()))?;
    let raw: RawMatrix = toml::from_str(&source)
        .with_context(|| format!("解析 closed artifact matrix {} 失败", path.display()))?;
    validate_matrix(root, raw)
}

fn validate_matrix(root: &Path, raw: RawMatrix) -> Result<Validation> {
    let mut findings = Vec::new();
    let discovered = crate::assembly::discover_targets(root)?;
    let cargo = crate::assembly::CargoTargetCatalog::load(root)?;
    let universe = discovered
        .iter()
        .map(|target| target.name().to_owned())
        .collect::<BTreeSet<_>>();
    validate_closed_world(&raw, &universe, &mut findings);
    validate_supported_ratchet(&raw, &universe, &mut findings);

    let mut supported = Vec::new();
    let mut identities: BTreeMap<String, String> = BTreeMap::new();
    for row in raw.assemblies {
        validate_lifecycle_shape(&row, &mut findings);
        match row.lifecycle {
            Lifecycle::CompileOnly => {}
            Lifecycle::Supported => {
                let (
                    Some(binary),
                    Some(image),
                    Some(config_schema),
                    Some(health_inventory),
                    Some(journey),
                ) = (
                    row.binary,
                    row.image,
                    row.config_schema,
                    row.health_inventory,
                    row.journey,
                )
                else {
                    continue;
                };
                validate_supported(
                    root,
                    &cargo,
                    &row.name,
                    &binary,
                    &image,
                    &config_schema,
                    health_inventory,
                    &journey,
                    &mut findings,
                )?;
                register_identity(
                    &mut identities,
                    "binary",
                    format!("{}#{}", binary.package, binary.target),
                    &row.name,
                    &mut findings,
                );
                register_identity(
                    &mut identities,
                    "image",
                    format!("{}#{}", image.dockerfile, image.target),
                    &row.name,
                    &mut findings,
                );
                register_identity(
                    &mut identities,
                    "config",
                    config_identity(&config_schema),
                    &row.name,
                    &mut findings,
                );
                register_identity(
                    &mut identities,
                    "journey",
                    journey_identity(&journey),
                    &row.name,
                    &mut findings,
                );
                supported.push(SupportedArtifact {
                    name: row.name,
                    binary,
                    image,
                    config_schema,
                    health_inventory,
                    journey,
                });
            }
        }
    }
    supported.sort_by(|left, right| left.name.cmp(&right.name));
    for boundary in crate::assembly::artifact_boundary_findings(root)? {
        reject!(
            findings,
            SpecializedBoundary,
            boundary.subject,
            "{:?}: {}",
            boundary.rule,
            boundary.detail
        );
    }
    let verified = findings
        .is_empty()
        .then_some(VerifiedArtifactMatrix { supported });
    Ok(Validation { verified, findings })
}

fn validate_closed_world(
    raw: &RawMatrix,
    universe: &BTreeSet<String>,
    findings: &mut Vec<ArtifactFinding>,
) {
    if raw.schema_version != SCHEMA_VERSION {
        reject!(
            findings,
            Schema,
            MATRIX_PATH,
            "schemaVersion 必须严格为 {SCHEMA_VERSION}，实际为 {}",
            raw.schema_version
        );
    }
    let mut declared = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for row in &raw.assemblies {
        validate_identifier("assembly name", &row.name, findings);
        if !declared.insert(row.name.clone()) {
            duplicates.insert(row.name.clone());
        }
    }
    for name in duplicates {
        reject!(
            findings,
            AssemblyBijection,
            name.clone(),
            "assembly 重复声明"
        );
    }
    for name in universe.difference(&declared) {
        reject!(
            findings,
            AssemblyBijection,
            name.clone(),
            "缺少 lifecycle/artifact 声明"
        );
    }
    for name in declared.difference(universe) {
        reject!(
            findings,
            AssemblyBijection,
            name.clone(),
            "artifact matrix 含幽灵 assembly"
        );
    }
}

fn validate_supported_ratchet(
    raw: &RawMatrix,
    universe: &BTreeSet<String>,
    findings: &mut Vec<ArtifactFinding>,
) {
    validate_supported_ratchet_for(raw, universe, REQUIRED_SUPPORTED_ASSEMBLIES, findings);
}

fn validate_supported_ratchet_for(
    raw: &RawMatrix,
    universe: &BTreeSet<String>,
    required: &[&str],
    findings: &mut Vec<ArtifactFinding>,
) {
    let required = required
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    for name in required.difference(universe) {
        reject!(
            findings,
            SupportedRatchet,
            name.clone(),
            "required supported assembly 不在 discovered universe"
        );
    }
    let supported = raw
        .assemblies
        .iter()
        .filter(|row| matches!(row.lifecycle, Lifecycle::Supported))
        .map(|row| row.name.clone())
        .collect::<BTreeSet<_>>();
    for name in required.difference(&supported) {
        reject!(
            findings,
            SupportedRatchet,
            name.clone(),
            "production supported assembly 禁止降级为 compile-only"
        );
    }
}

fn validate_lifecycle_shape(row: &RawAssembly, findings: &mut Vec<ArtifactFinding>) {
    match row.lifecycle {
        Lifecycle::CompileOnly => {
            if row
                .reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
            {
                reject!(
                    findings,
                    LifecycleShape,
                    row.name.clone(),
                    "compile-only reason 必须非空"
                );
            }
            if row.binary.is_some()
                || row.image.is_some()
                || row.config_schema.is_some()
                || row.health_inventory.is_some()
                || row.journey.is_some()
            {
                reject!(
                    findings,
                    LifecycleShape,
                    row.name.clone(),
                    "compile-only 禁止携带 deployable artifact 字段"
                );
            }
        }
        Lifecycle::Supported => {
            if row.reason.is_some() {
                reject!(
                    findings,
                    LifecycleShape,
                    row.name.clone(),
                    "supported 禁止 reason 字段"
                );
            }
            for (field, present) in [
                ("binary", row.binary.is_some()),
                ("image", row.image.is_some()),
                ("configSchema", row.config_schema.is_some()),
                ("healthInventory", row.health_inventory.is_some()),
                ("journey", row.journey.is_some()),
            ] {
                if !present {
                    reject!(
                        findings,
                        LifecycleShape,
                        row.name.clone(),
                        "supported 缺少 {field}"
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_supported(
    root: &Path,
    cargo: &crate::assembly::CargoTargetCatalog,
    assembly: &str,
    binary: &RawBinary,
    image: &RawImage,
    config: &RawConfigSchema,
    _health: RawHealthInventory,
    journey: &RawJourney,
    findings: &mut Vec<ArtifactFinding>,
) -> Result<()> {
    validate_identifier("binary.package", &binary.package, findings);
    validate_identifier("binary.target", &binary.target, findings);
    if !cargo.binary_belongs_to_assembly(assembly, &binary.package, &binary.target) {
        reject!(
            findings,
            Binary,
            assembly,
            "exact binary {}#{} 不属于该 assembly",
            binary.package,
            binary.target
        );
    }
    validate_image(root, assembly, image, binary, config, findings)?;
    validate_config(root, assembly, config, findings)?;
    validate_health_inventory(root, cargo, assembly, findings)?;
    validate_journey(root, cargo, assembly, journey, findings)?;
    Ok(())
}

fn validate_identifier(label: &str, value: &str, findings: &mut Vec<ArtifactFinding>) {
    if value.is_empty()
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        reject!(
            findings,
            Identity,
            label,
            "`{value}` 不是 closed identifier"
        );
    }
}

fn register_identity(
    seen: &mut BTreeMap<String, String>,
    kind: &str,
    value: String,
    owner: &str,
    findings: &mut Vec<ArtifactFinding>,
) {
    let key = format!("{kind}:{value}");
    if let Some(previous) = seen.insert(key, owner.to_owned())
        && previous != owner
    {
        reject!(
            findings,
            Identity,
            owner,
            "{kind} identity `{value}` 被 `{previous}` 与 `{owner}` 复用"
        );
    }
}

fn validate_config(
    root: &Path,
    assembly: &str,
    config: &RawConfigSchema,
    findings: &mut Vec<ArtifactFinding>,
) -> Result<()> {
    match config {
        RawConfigSchema::JsonSchema { path } => {
            let expected = format!("assemblies/{assembly}/config.schema.json");
            if path != &expected {
                reject!(
                    findings,
                    Config,
                    assembly,
                    "json-schema path 必须 exact 为 {expected}"
                );
            }
            let Some(file) = regular_file(root, path, assembly, "configSchema", findings)? else {
                return Ok(());
            };
            let source = read_artifact_utf8(&file, &format!("{assembly} JSON Schema"))
                .with_context(|| format!("读取 {} 失败", file.display()))?;
            let schema: serde_json::Value = match serde_json::from_str(&source) {
                Ok(schema) => schema,
                Err(error) => {
                    reject!(findings, Config, assembly, "JSON Schema 解析失败: {error}");
                    return Ok(());
                }
            };
            if schema.get("$schema").and_then(serde_json::Value::as_str)
                != Some("http://json-schema.org/draft-07/schema#")
            {
                reject!(findings, Config, assembly, "configSchema 必须为 Draft-07");
            }
            if jsonschema::draft7::options().build(&schema).is_err() {
                reject!(
                    findings,
                    Config,
                    assembly,
                    "configSchema 不是合法 Draft-07 schema"
                );
            }
            if schema.get("type") != Some(&serde_json::json!("object"))
                || schema.get("additionalProperties") != Some(&serde_json::json!(false))
                || !crate::assembly::schema_objects_are_closed(&schema)
            {
                reject!(
                    findings,
                    Config,
                    assembly,
                    "configSchema 根与每个 object 都必须 closed"
                );
            }
        }
        RawConfigSchema::TypedEnvCatalog { path } => {
            if assembly != "runtime" || path != "assemblies/runtime/src/config.rs" {
                reject!(
                    findings,
                    Config,
                    assembly,
                    "typed-env-catalog 仅允许 runtime 绑定 assemblies/runtime/src/config.rs"
                );
            }
            let Some(file) = regular_file(root, path, assembly, "configSchema", findings)? else {
                return Ok(());
            };
            let source = read_artifact_utf8(&file, &format!("{assembly} typed env catalog"))
                .with_context(|| format!("读取 {} 失败", file.display()))?;
            if !typed_env_catalog_is_bound(&source)? {
                reject!(
                    findings,
                    Config,
                    assembly,
                    "typed-env carrier 未绑定 RuntimeEnvGuard 的 typed capture"
                );
            }
            for guard in crate::runtime_env_guard::validate_root(root)? {
                reject!(
                    findings,
                    Config,
                    guard.subject,
                    "RuntimeEnvGuard::{:?}: {}",
                    guard.rule,
                    guard.detail
                );
            }
        }
    }
    Ok(())
}

fn typed_env_catalog_is_bound(source: &str) -> Result<bool> {
    let file = syn::parse_file(source)?;
    let env_source = file.items.iter().any(|item| {
        matches!(
            item,
            syn::Item::Struct(item)
                if item.ident == "EnvConfigSource"
                    && matches!(item.fields, syn::Fields::Unit)
                    && !item.attrs.iter().any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        )
    });
    let capture = file.items.iter().any(|item| {
        let syn::Item::Impl(item) = item else {
            return false;
        };
        let syn::Type::Path(owner) = item.self_ty.as_ref() else {
            return false;
        };
        if !owner.path.is_ident("RuntimeConfigSnapshot") {
            return false;
        }
        item.items.iter().any(|member| {
            let syn::ImplItem::Fn(method) = member else {
                return false;
            };
            method.sig.ident == "capture_process_snapshot"
                && method.sig.inputs.is_empty()
                && !method.attrs.iter().any(|attr| {
                    attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr")
                })
                && matches!(method.block.stmts.as_slice(), [syn::Stmt::Expr(expr, None)] if exact_typed_env_capture_call(expr))
        })
    });
    Ok(env_source && capture)
}

fn exact_typed_env_capture_call(expression: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let function_segments = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    let Some(argument) = call.args.first().filter(|_| call.args.len() == 1) else {
        return false;
    };
    let syn::Expr::Path(argument) = argument else {
        return false;
    };
    function_segments == ["Self", "capture_with_forbidden_check"]
        && argument.path.is_ident("EnvConfigSource")
}

fn validate_health_inventory(
    root: &Path,
    cargo: &crate::assembly::CargoTargetCatalog,
    assembly: &str,
    findings: &mut Vec<ArtifactFinding>,
) -> Result<()> {
    let manifest_path = format!("assemblies/{assembly}/assembly.toml");
    let Some(manifest_file) = regular_file(root, &manifest_path, assembly, "health", findings)?
    else {
        return Ok(());
    };
    let manifest = AssemblyManifest::from_toml_str(
        &read_artifact_utf8(&manifest_file, &format!("{assembly} assembly manifest"))
            .with_context(|| format!("读取 {} 失败", manifest_file.display()))?,
    )
    .with_context(|| format!("解析 {} 失败", manifest_file.display()))?;
    let health = manifest
        .listeners
        .iter()
        .filter(|listener| listener.kind == AssemblyListenerKind::Health)
        .collect::<Vec<_>>();
    if !matches!(health.as_slice(), [listener] if listener.domains.is_empty()) {
        reject!(
            findings,
            Health,
            assembly,
            "manifest 必须有且仅有 exact Health(domains=[]) listener"
        );
    }

    if !cargo.has_exact_normal_dependency(assembly, "runtimeexec", "crates/runtimeexec/Cargo.toml")
    {
        reject!(
            findings,
            Health,
            assembly,
            "assembly 必须 exact normal-depend on workspace runtimeexec"
        );
    }
    if assembly == "runtime" {
        for baseline in crate::runtime_baseline::artifact_launch_findings(root)? {
            reject!(
                findings,
                Health,
                baseline.subject,
                "{:?}: {}",
                baseline.rule,
                baseline.detail
            );
        }
    }
    Ok(())
}

fn validate_journey(
    root: &Path,
    cargo: &crate::assembly::CargoTargetCatalog,
    assembly: &str,
    journey: &RawJourney,
    findings: &mut Vec<ArtifactFinding>,
) -> Result<()> {
    match journey {
        RawJourney::CargoTest {
            package,
            target,
            test,
        } => {
            for (label, value) in [
                ("journey.package", package.as_str()),
                ("journey.target", target.as_str()),
                ("journey.test", test.as_str()),
            ] {
                validate_identifier(label, value, findings);
            }
            if !cargo.target_exists(package, target, "test") {
                reject!(
                    findings,
                    Journey,
                    assembly,
                    "Cargo metadata 不含 exact journey target {package}#{target}"
                );
                return Ok(());
            }
            let Some(path) = cargo.target_path(package, target, "test") else {
                reject!(
                    findings,
                    Journey,
                    assembly,
                    "无法解析 journey target {package}#{target} 的 path"
                );
                return Ok(());
            };
            let label = path
                .strip_prefix(root)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            let Some(path) = regular_file(root, &label, assembly, "journey", findings)? else {
                return Ok(());
            };
            let source = read_artifact_utf8(&path, &format!("{assembly} Cargo journey"))
                .with_context(|| format!("读取 {} 失败", path.display()))?;
            if !cargo_journey_has_exact_test(&source, test)? {
                reject!(
                    findings,
                    Journey,
                    assembly,
                    "journey `{test}` 必须是非 ignored、非 cfg、非空的 exact test"
                );
            }
        }
        RawJourney::ComposeSmokeV1 { path } => {
            let Some(path) = regular_file(root, path, assembly, "journey", findings)? else {
                return Ok(());
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if std::fs::metadata(&path)?.permissions().mode() & 0o111 == 0 {
                    reject!(
                        findings,
                        Journey,
                        assembly,
                        "compose smoke 必须为可执行普通文件"
                    );
                }
            }
            let source = read_artifact_utf8(&path, &format!("{assembly} compose journey"))
                .with_context(|| format!("读取 {} 失败", path.display()))?;
            if !compose_smoke_is_closed(&source) {
                reject!(
                    findings,
                    Journey,
                    assembly,
                    "compose-smoke-v1 缺 strict mode、build/up、readyz、healthz 或 cleanup 锚点"
                );
            }
        }
    }
    Ok(())
}

fn cargo_journey_has_exact_test(source: &str, required: &str) -> Result<bool> {
    let file = syn::parse_file(source)?;
    Ok(file.items.iter().any(|item| {
        let syn::Item::Fn(function) = item else {
            return false;
        };
        function.sig.ident == required
            && function.attrs.iter().any(|attribute| {
                attribute.path().is_ident("test")
                    || (attribute.path().segments.len() == 2
                        && attribute.path().segments[0].ident == "tokio"
                        && attribute.path().segments[1].ident == "test")
            })
            && !function.attrs.iter().any(|attribute| {
                attribute.path().is_ident("ignore")
                    || attribute.path().is_ident("cfg")
                    || attribute.path().is_ident("cfg_attr")
            })
            && !function.block.stmts.is_empty()
            && function
                .block
                .stmts
                .iter()
                .any(|statement| !stmt_is_vacuous_test_carrier(statement))
    }))
}

fn stmt_is_vacuous_test_carrier(statement: &syn::Stmt) -> bool {
    match statement {
        syn::Stmt::Local(local) => local.init.as_ref().is_some_and(|init| {
            matches!(
                init.expr.as_ref(),
                syn::Expr::Closure(_) | syn::Expr::Async(_) | syn::Expr::Const(_)
            )
        }),
        syn::Stmt::Expr(
            syn::Expr::Closure(_)
            | syn::Expr::Async(_)
            | syn::Expr::Const(_)
            | syn::Expr::If(_)
            | syn::Expr::Match(_)
            | syn::Expr::Loop(_)
            | syn::Expr::While(_)
            | syn::Expr::ForLoop(_),
            _,
        )
        | syn::Stmt::Item(syn::Item::Fn(_) | syn::Item::Const(_) | syn::Item::Static(_)) => true,
        syn::Stmt::Expr(expression, _) => expression_is_trivial_success(expression),
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
    }
}

fn expression_is_trivial_success(expression: &syn::Expr) -> bool {
    if matches!(expression, syn::Expr::Tuple(tuple) if tuple.elems.is_empty()) {
        return true;
    }
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    matches!(call.func.as_ref(), syn::Expr::Path(path) if path.path.is_ident("Ok"))
        && matches!(call.args.first(), Some(syn::Expr::Tuple(tuple)) if call.args.len() == 1 && tuple.elems.is_empty())
}

fn compose_smoke_is_closed(source: &str) -> bool {
    let Some(commands) = shell_semantic_lines(source) else {
        return false;
    };
    let top_level = commands
        .iter()
        .filter(|command| command.function.is_none() && command.scopes.is_empty())
        .map(|command| command.text)
        .collect::<Vec<_>>();
    top_level.contains(&"set -euo pipefail")
        && top_level.contains(&"COMPOSE=\"docker compose -f ${SCRIPT_DIR}/docker-compose.yml\"")
        && top_level.contains(&"$COMPOSE build")
        && top_level.contains(&"$COMPOSE up -d")
        && top_level.contains(&"trap cleanup EXIT")
        && commands.iter().any(|command| {
            command.function == Some("cleanup")
                && command.scopes.is_empty()
                && command.text.starts_with("$COMPOSE down -v ")
        })
        && commands.iter().any(|command| {
            command.function.is_none()
                && command.scopes == [ShellScope::Loop]
                && command
                    .text
                    .starts_with("if curl -fsS \"${HEALTH_URL}/readyz\"")
        })
        && top_level
            .iter()
            .any(|line| line.starts_with("curl -fsS \"${HEALTH_URL}/healthz\" >/dev/null || fail"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShellSemanticLine<'a> {
    text: &'a str,
    function: Option<&'a str>,
    scopes: Vec<ShellScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellScope {
    Conditional,
    Loop,
    Case,
    Group,
    Subshell,
}

fn shell_semantic_lines(source: &str) -> Option<Vec<ShellSemanticLine<'_>>> {
    let mut commands = Vec::new();
    let mut heredoc_delimiter: Option<String> = None;
    let mut function = None;
    let mut scopes = Vec::new();
    let mut pending_scope = None;
    for line in source.lines().map(str::trim) {
        if let Some(delimiter) = &heredoc_delimiter {
            if line == delimiter {
                heredoc_delimiter = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = shell_function_name(line) {
            if function.replace(name).is_some() || !scopes.is_empty() || pending_scope.is_some() {
                return None;
            }
            continue;
        }
        if consume_shell_scope_close(line, &mut function, &mut scopes, pending_scope).ok()? {
            continue;
        }
        if line.starts_with("function ") || line.contains(" () {") {
            return None;
        }
        commands.push(ShellSemanticLine {
            text: line,
            function,
            scopes: scopes.clone(),
        });
        if let Some(delimiter) = line.split_whitespace().find_map(heredoc_token_delimiter) {
            heredoc_delimiter = Some(delimiter);
        }
        advance_shell_scope(line, &mut scopes, &mut pending_scope);
    }
    (heredoc_delimiter.is_none()
        && function.is_none()
        && scopes.is_empty()
        && pending_scope.is_none())
    .then_some(commands)
}

fn consume_shell_scope_close(
    line: &str,
    function: &mut Option<&str>,
    scopes: &mut Vec<ShellScope>,
    pending_scope: Option<ShellScope>,
) -> std::result::Result<bool, ()> {
    let expected = match line {
        "fi" => Some(ShellScope::Conditional),
        "done" => Some(ShellScope::Loop),
        "esac" => Some(ShellScope::Case),
        ")" => Some(ShellScope::Subshell),
        "}" if scopes.last() == Some(&ShellScope::Group) => Some(ShellScope::Group),
        _ => None,
    };
    if let Some(expected) = expected {
        return (scopes.pop() == Some(expected)).then_some(true).ok_or(());
    }
    if line != "}" {
        return Ok(false);
    }
    if function.take().is_some() && scopes.is_empty() && pending_scope.is_none() {
        Ok(true)
    } else {
        Err(())
    }
}

fn advance_shell_scope(
    line: &str,
    scopes: &mut Vec<ShellScope>,
    pending_scope: &mut Option<ShellScope>,
) {
    if let Some(pending) = *pending_scope {
        let closes_header = matches!(pending, ShellScope::Conditional) && line.ends_with("; then")
            || matches!(pending, ShellScope::Loop) && (line == "do" || line.ends_with("; do"));
        if closes_header {
            scopes.push(pending);
            *pending_scope = None;
        }
        return;
    }
    if line.starts_with("if ") {
        open_or_defer_shell_scope(
            line,
            "; then",
            ShellScope::Conditional,
            scopes,
            pending_scope,
        );
    } else if ["for ", "while ", "until "]
        .iter()
        .any(|prefix| line.starts_with(prefix))
    {
        open_or_defer_shell_scope(line, "; do", ShellScope::Loop, scopes, pending_scope);
    } else if line.starts_with("case ") && line.ends_with(" in") {
        scopes.push(ShellScope::Case);
    } else if line == "(" {
        scopes.push(ShellScope::Subshell);
    } else if line == "{" || line.ends_with("|| {") {
        scopes.push(ShellScope::Group);
    }
}

fn open_or_defer_shell_scope(
    line: &str,
    terminator: &str,
    scope: ShellScope,
    scopes: &mut Vec<ShellScope>,
    pending_scope: &mut Option<ShellScope>,
) {
    if line.ends_with(terminator) {
        scopes.push(scope);
    } else {
        *pending_scope = Some(scope);
    }
}

fn shell_function_name(line: &str) -> Option<&str> {
    let name = line.strip_suffix("() {")?;
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !name.as_bytes()[0].is_ascii_digit())
    .then_some(name)
}

fn heredoc_token_delimiter(token: &str) -> Option<String> {
    let token = token.strip_prefix("<<")?;
    let token = token.strip_prefix('-').unwrap_or(token);
    let delimiter = token.trim_matches(['\'', '"']);
    (!delimiter.is_empty()).then(|| delimiter.to_owned())
}

fn validate_image(
    root: &Path,
    assembly: &str,
    image: &RawImage,
    binary: &RawBinary,
    config: &RawConfigSchema,
    findings: &mut Vec<ArtifactFinding>,
) -> Result<()> {
    validate_identifier("image.target", &image.target, findings);
    let Some(path) = regular_file(root, &image.dockerfile, assembly, "image", findings)? else {
        return Ok(());
    };
    let source = read_artifact_utf8(&path, &format!("{assembly} Dockerfile"))
        .with_context(|| format!("读取 {} 失败", path.display()))?;
    let stages = crate::assembly::docker_stages(&source);
    let selected = stages
        .iter()
        .filter(|stage| stage.name == image.target)
        .collect::<Vec<_>>();
    let [stage] = selected.as_slice() else {
        reject!(
            findings,
            Image,
            assembly,
            "Docker target `{}` 必须存在且唯一",
            image.target
        );
        return Ok(());
    };
    if stage.base != "gcr.io/distroless/cc-debian12:nonroot" {
        reject!(
            findings,
            Image,
            assembly,
            "Docker target 必须使用 distroless nonroot base"
        );
    }
    if stage
        .instructions
        .iter()
        .any(|line| crate::assembly::docker_instruction_arguments(line, "USER").is_some())
    {
        reject!(
            findings,
            Image,
            assembly,
            "distroless nonroot target 禁止 USER override"
        );
    }
    let entrypoint = format!("[\"/usr/local/bin/{}\"]", binary.target);
    let entrypoints = stage
        .instructions
        .iter()
        .filter_map(|line| crate::assembly::docker_instruction_arguments(line, "ENTRYPOINT"))
        .collect::<Vec<_>>();
    if entrypoints != [entrypoint.as_str()] {
        reject!(
            findings,
            Image,
            assembly,
            "Docker ENTRYPOINT 必须 exact 指向 binary {}",
            binary.target
        );
    }
    let builders = stages
        .iter()
        .filter(|candidate| {
            candidate.instructions.iter().any(|line| {
                crate::assembly::docker_instruction_arguments(line, "RUN").is_some_and(|args| {
                    docker_run_builds_binary(args, assembly, &binary.package, &binary.target)
                })
            })
        })
        .collect::<Vec<_>>();
    let [builder] = builders.as_slice() else {
        reject!(
            findings,
            Image,
            assembly,
            "Docker 必须有唯一 exact binary builder stage（cargo build --release --locked，不得吞错）"
        );
        return Ok(());
    };
    let binary_source = format!("/app/target/release/{}", binary.target);
    let binary_destination = format!("/usr/local/bin/{}", binary.target);
    if !stage.instructions.iter().any(|line| {
        crate::assembly::docker_instruction_arguments(line, "COPY").is_some_and(|args| {
            docker_copy_is_exact(args, builder.name, &binary_source, &binary_destination)
        })
    }) {
        reject!(
            findings,
            Image,
            assembly,
            "Docker target 未从 exact builder COPY binary"
        );
    }
    match config {
        RawConfigSchema::JsonSchema { path } => {
            let schema_source = format!("/app/{path}");
            let schema_destination = format!("/usr/share/rss/{assembly}/config.schema.json");
            if !stage.instructions.iter().any(|line| {
                crate::assembly::docker_instruction_arguments(line, "COPY").is_some_and(|args| {
                    docker_copy_is_exact(args, builder.name, &schema_source, &schema_destination)
                })
            }) {
                reject!(
                    findings,
                    Image,
                    assembly,
                    "Docker target 未 COPY JSON schema"
                );
            }
        }
        RawConfigSchema::TypedEnvCatalog { path } => {
            if stage.instructions.iter().any(|line| {
                crate::assembly::docker_instruction_arguments(line, "COPY")
                    .is_some_and(|args| args.contains(path) || args.contains("config.schema.json"))
            }) {
                reject!(
                    findings,
                    Image,
                    assembly,
                    "typed-env image 禁止伪造 JSON Schema COPY"
                );
            }
        }
    }
    Ok(())
}

fn docker_run_builds_binary(args: &str, assembly: &str, package: &str, target: &str) -> bool {
    let tokens = args.split_whitespace().collect::<Vec<_>>();
    if assembly == "runtime" {
        tokens
            == [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--bin",
                target,
                "--bin",
                "rss",
            ]
    } else {
        tokens
            == [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--package",
                package,
                "--bin",
                target,
            ]
    }
}

fn docker_copy_is_exact(args: &str, builder: &str, source: &str, destination: &str) -> bool {
    let from = format!("--from={builder}");
    args.split_whitespace().collect::<Vec<_>>() == [from.as_str(), source, destination]
}

fn regular_file(
    root: &Path,
    relative: &str,
    assembly: &str,
    field: &str,
    findings: &mut Vec<ArtifactFinding>,
) -> Result<Option<PathBuf>> {
    if let Err(error) = ensure_regular_path(root, relative) {
        reject!(
            findings,
            PathSafety,
            assembly,
            "{field} path `{relative}`: {error:#}"
        );
        return Ok(None);
    }
    Ok(Some(root.join(relative)))
}

fn read_artifact_utf8(path: &Path, label: &str) -> Result<String> {
    crate::generated_file::read_stable_utf8_file(path, MAX_ARTIFACT_BYTES, label)
}

fn ensure_regular_path(root: &Path, relative: &str) -> Result<()> {
    if relative.is_empty() || relative.contains('\\') {
        bail!("路径必须为非空 slash-normalized repository relative path");
    }
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("路径禁止 absolute、`.` 或 `..` component");
    }
    let mut current = root.to_path_buf();
    for component in path.components() {
        let Component::Normal(segment) = component else {
            unreachable!();
        };
        current.push(segment);
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("检查 {} 失败", current.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("路径禁止符号链接 component");
        }
    }
    if !std::fs::symlink_metadata(&current)?.is_file() {
        bail!("路径必须指向普通文件");
    }
    Ok(())
}

fn config_identity(config: &RawConfigSchema) -> String {
    match config {
        RawConfigSchema::JsonSchema { path } => format!("json-schema:{path}"),
        RawConfigSchema::TypedEnvCatalog { path } => format!("typed-env-catalog:{path}"),
    }
}

fn journey_identity(journey: &RawJourney) -> String {
    match journey {
        RawJourney::CargoTest {
            package,
            target,
            test,
        } => format!("cargo-test:{package}#{target}#{test}"),
        RawJourney::ComposeSmokeV1 { path } => format!("compose-smoke-v1:{path}"),
    }
}

struct ObservedRow {
    cells: [String; 8],
}

fn render_rows(mut rows: Vec<ObservedRow>) -> String {
    rows.sort_by(|left, right| left.cells[0].cmp(&right.cells[0]));
    let mut output = String::from(MARKDOWN_HEADER);
    for row in rows {
        let cells = row.cells.map(|cell| markdown_cell(&cell));
        let _ = writeln!(
            output,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6], cells[7]
        );
    }
    output
}

fn render_observed(raw: &RawMatrix) -> String {
    let rows = raw
        .assemblies
        .iter()
        .map(|row| {
            let (lifecycle, binary, image, config, health, journey, reason) = match row.lifecycle {
                Lifecycle::CompileOnly => (
                    "compile-only".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    row.reason.as_deref().unwrap_or(MISSING).to_owned(),
                ),
                Lifecycle::Supported => (
                    "supported".to_owned(),
                    row.binary.as_ref().map_or_else(
                        || MISSING.to_owned(),
                        |binary| format!("{}#{}", binary.package, binary.target),
                    ),
                    row.image.as_ref().map_or_else(
                        || MISSING.to_owned(),
                        |image| format!("{}#{}", image.dockerfile, image.target),
                    ),
                    row.config_schema
                        .as_ref()
                        .map_or_else(|| MISSING.to_owned(), config_identity),
                    row.health_inventory.as_ref().map_or_else(
                        || MISSING.to_owned(),
                        |health| format!("{}#{}", health.owner.as_str(), health.listener.as_str()),
                    ),
                    row.journey
                        .as_ref()
                        .map_or_else(|| MISSING.to_owned(), journey_identity),
                    "—".to_owned(),
                ),
            };
            ObservedRow {
                cells: [
                    row.name.clone(),
                    lifecycle,
                    binary,
                    image,
                    config,
                    health,
                    journey,
                    reason,
                ],
            }
        })
        .collect();
    render_rows(rows)
}

fn render_unverified_source(source: &str) -> String {
    let Ok(value) = source.parse::<toml::Value>() else {
        return format!(
            "{MARKDOWN_HEADER}| {UNPARSEABLE} | {INVALID} | {UNKNOWN} | {UNKNOWN} | {UNKNOWN} | {UNKNOWN} | {UNKNOWN} | {UNKNOWN} |\n"
        );
    };
    let rows = value
        .get("assemblies")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .map(|row| {
            let name = value_string(row.get("name"));
            let lifecycle = value_string(row.get("lifecycle"));
            let reason = value_string(row.get("reason"));
            let binary = observed_pair(row.get("binary"), "package", "target", "#");
            let image = observed_pair(row.get("image"), "dockerfile", "target", "#");
            let config = observed_pair(row.get("configSchema"), "kind", "path", ":");
            let health = observed_pair(row.get("healthInventory"), "owner", "listener", "#");
            let journey = row.get("journey").map_or_else(
                || MISSING.to_owned(),
                |journey| {
                    let kind = value_string(journey.get("kind"));
                    if kind == "cargo-test" {
                        format!(
                            "{kind}:{}#{}#{}",
                            value_string(journey.get("package")),
                            value_string(journey.get("target")),
                            value_string(journey.get("test"))
                        )
                    } else {
                        format!("{kind}:{}", value_string(journey.get("path")))
                    }
                },
            );
            let (binary, image, config, health, journey, reason) = match lifecycle.as_str() {
                "compile-only" => (
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    reason,
                ),
                "supported" => (binary, image, config, health, journey, "—".to_owned()),
                _ => (binary, image, config, health, journey, reason),
            };
            ObservedRow {
                cells: [
                    name, lifecycle, binary, image, config, health, journey, reason,
                ],
            }
        })
        .collect::<Vec<_>>();
    render_rows(rows)
}

fn observed_pair(value: Option<&toml::Value>, left: &str, right: &str, separator: &str) -> String {
    value.map_or_else(
        || MISSING.to_owned(),
        |value| {
            format!(
                "{}{}{}",
                value_string(value.get(left)),
                separator,
                value_string(value.get(right))
            )
        },
    )
}

fn value_string(value: Option<&toml::Value>) -> String {
    value
        .and_then(toml::Value::as_str)
        .unwrap_or(MISSING)
        .to_owned()
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_v1_and_lifecycle_are_closed() -> Result<()> {
        let green = green_matrix()?;
        assert_eq!(green.schema_version, 1);
        assert_eq!(green.assemblies.len(), 2);
        let unknown = include_str!("../fixtures/assembly-artifacts/unknown-field.toml");
        assert!(toml::from_str::<RawMatrix>(unknown).is_err());
        let observed = render_unverified_source(unknown);
        assert!(observed.starts_with(MARKDOWN_HEADER));
        let unknown_with_rows = include_str!("../fixtures/assembly-artifacts/green.toml").replacen(
            "schemaVersion = 1",
            "schemaVersion = 1\nunexpected = true",
            1,
        );
        assert!(toml::from_str::<RawMatrix>(&unknown_with_rows).is_err());
        assert!(render_unverified_source(&unknown_with_rows).contains("| demo | supported |"));
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)] // one red matrix mutates every closed declaration dimension.
    fn synthetic_red_rejects_incomplete_or_unsafe_rows() -> Result<()> {
        let mut green = green_matrix()?;
        let supported = &green.assemblies[0];
        let mut errors = Vec::new();
        validate_lifecycle_shape(supported, &mut errors);
        assert!(errors.is_empty());

        for field in [
            "binary",
            "image",
            "configSchema",
            "healthInventory",
            "journey",
        ] {
            let mut row = supported.clone();
            match field {
                "binary" => row.binary = None,
                "image" => row.image = None,
                "configSchema" => row.config_schema = None,
                "healthInventory" => row.health_inventory = None,
                "journey" => row.journey = None,
                _ => unreachable!(),
            }
            let mut errors = Vec::new();
            validate_lifecycle_shape(&row, &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.rule == ArtifactRule::LifecycleShape
                        && error.detail.contains(field)),
                "missing {field} escaped: {errors:?}"
            );
        }

        let missing: RawMatrix = toml::from_str(include_str!(
            "../fixtures/assembly-artifacts/missing-artifact.toml"
        ))?;
        let mut errors = Vec::new();
        validate_lifecycle_shape(&missing.assemblies[0], &mut errors);
        assert!(!errors.is_empty());

        let compile_with_artifact: RawMatrix = toml::from_str(include_str!(
            "../fixtures/assembly-artifacts/compile-only-with-artifact.toml"
        ))?;
        let mut errors = Vec::new();
        validate_lifecycle_shape(&compile_with_artifact.assemblies[0], &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.rule == ArtifactRule::LifecycleShape
                    && error.detail.contains("禁止携带"))
        );
        let mut compile_without_reason = compile_with_artifact.assemblies[0].clone();
        compile_without_reason.binary = None;
        compile_without_reason.reason = Some("  ".to_owned());
        let mut errors = Vec::new();
        validate_lifecycle_shape(&compile_without_reason, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.rule == ArtifactRule::LifecycleShape
                    && error.detail.contains("reason 必须非空"))
        );

        let universe = BTreeSet::from(["demo".to_owned(), "sourcecheck".to_owned()]);
        let mut errors = Vec::new();
        validate_closed_world(&green, &universe, &mut errors);
        assert!(errors.is_empty());

        let mut downgraded = green.clone();
        downgraded.assemblies[0].lifecycle = Lifecycle::CompileOnly;
        downgraded.assemblies[0].reason = Some("downgrade bait".to_owned());
        downgraded.assemblies[0].binary = None;
        downgraded.assemblies[0].image = None;
        downgraded.assemblies[0].config_schema = None;
        downgraded.assemblies[0].health_inventory = None;
        downgraded.assemblies[0].journey = None;
        let mut ratchet_findings = Vec::new();
        validate_supported_ratchet_for(&downgraded, &universe, &["demo"], &mut ratchet_findings);
        assert!(
            ratchet_findings
                .iter()
                .any(|finding| finding.rule == ArtifactRule::SupportedRatchet)
        );

        green.schema_version = 2;
        green.assemblies.push(green.assemblies[0].clone());
        green.assemblies[1].name = "ghost".to_owned();
        let mut errors = Vec::new();
        validate_closed_world(&green, &universe, &mut errors);
        let joined = format_artifact_findings(&errors).join("\n");
        assert!(joined.contains("schemaVersion"));
        assert!(joined.contains("重复声明"));
        assert!(joined.contains("缺少 lifecycle/artifact"));
        assert!(joined.contains("幽灵 assembly"));

        for kind in ["binary", "image", "config", "journey"] {
            let mut seen = BTreeMap::new();
            let mut errors = Vec::new();
            register_identity(&mut seen, kind, "same".to_owned(), "a", &mut errors);
            register_identity(&mut seen, kind, "same".to_owned(), "b", &mut errors);
            assert_eq!(errors.len(), 1, "{kind} identity reuse escaped");
        }

        for path in [
            "/tmp/schema.json",
            "../schema.json",
            "a\\b",
            "./schema.json",
        ] {
            assert!(ensure_regular_path(Path::new("/does-not-matter"), path).is_err());
        }
        let root = temp_root("paths")?;
        std::fs::create_dir_all(root.join("dir"))?;
        std::fs::write(root.join("regular"), "ok")?;
        assert!(ensure_regular_path(&root, "regular").is_ok());
        assert!(ensure_regular_path(&root, "dir").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("regular"), root.join("link"))?;
            assert!(ensure_regular_path(&root, "link").is_err());
        }
        std::fs::remove_dir_all(root)?;

        let ignored = "#[test]\n#[ignore]\nfn exact() { panic!() }";
        let cfg = "#[cfg(test)]\n#[test]\nfn exact() { panic!() }";
        let empty = "#[test]\nfn exact() {}";
        assert!(!cargo_journey_has_exact_test(ignored, "exact")?);
        assert!(!cargo_journey_has_exact_test(cfg, "exact")?);
        assert!(!cargo_journey_has_exact_test(empty, "exact")?);
        Ok(())
    }

    fn green_matrix() -> Result<RawMatrix> {
        Ok(toml::from_str(include_str!(
            "../fixtures/assembly-artifacts/green.toml"
        ))?)
    }

    fn temp_root(label: &str) -> Result<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "rss-assembly-artifacts-{label}-{}",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }

    #[test]
    fn docker_and_journey_parsers_reject_comment_string_and_test_bait() -> Result<()> {
        let docker = "# FROM gcr.io/distroless/cc-debian12:nonroot AS demo\nFROM chef AS real\n# ENTRYPOINT [\"/usr/local/bin/demo\"]\n";
        assert!(
            crate::assembly::docker_stages(docker)
                .iter()
                .all(|stage| stage.name != "demo")
        );
        assert!(!compose_smoke_is_closed(
            "# docker compose; $COMPOSE build; $COMPOSE up -d; /readyz /healthz; trap cleanup EXIT; $COMPOSE down -v"
        ));
        assert!(!compose_smoke_is_closed(
            "BAIT='docker compose $COMPOSE build $COMPOSE up -d /readyz /healthz trap cleanup EXIT $COMPOSE down -v'"
        ));
        assert!(!compose_smoke_is_closed(concat!(
            "cat <<'BAIT'\n",
            "COMPOSE=\"docker compose -f ${SCRIPT_DIR}/docker-compose.yml\"\n",
            "$COMPOSE build\n",
            "$COMPOSE up -d\n",
            "trap cleanup EXIT\n",
            "$COMPOSE down -v --remove-orphans\n",
            "if curl -fsS \"${HEALTH_URL}/readyz\"; then\n",
            "curl -fsS \"${HEALTH_URL}/healthz\" >/dev/null || fail\n",
            "BAIT\n",
        )));
        assert!(!compose_smoke_is_closed(concat!(
            "COMPOSE=\"docker compose -f ${SCRIPT_DIR}/docker-compose.yml\"\n",
            "$COMPOSE build\n",
            "$COMPOSE up -d\n",
            "trap cleanup EXIT\n",
            "$COMPOSE down -v --remove-orphans\n",
            "if curl -fsS \"${HEALTH_URL}/readyz\"; then\n",
            "curl -fsS \"${HEALTH_URL}/healthz\" >/dev/null || fail\n",
        )));
        assert!(!cargo_journey_has_exact_test(
            "const BAIT: &str = \"#[test] fn exact() {}\";",
            "exact"
        )?);
        let root = temp_root("docker")?;
        let image = RawImage {
            dockerfile: "Dockerfile".to_owned(),
            target: "demo-runtime".to_owned(),
        };
        let binary = RawBinary {
            package: "demo".to_owned(),
            target: "demo-server".to_owned(),
        };
        let config = RawConfigSchema::JsonSchema {
            path: "assemblies/demo/config.schema.json".to_owned(),
        };
        let green = concat!(
            "FROM chef AS demo-builder\n",
            "RUN cargo build --release --locked --package demo --bin demo-server\n",
            "FROM gcr.io/distroless/cc-debian12:nonroot AS demo-runtime\n",
            "COPY --from=demo-builder /app/target/release/demo-server /usr/local/bin/demo-server\n",
            "COPY --from=demo-builder /app/assemblies/demo/config.schema.json /usr/share/rss/demo/config.schema.json\n",
            "ENTRYPOINT [\"/usr/local/bin/demo-server\"]\n",
        );
        for (label, candidate) in [
            ("green", green.to_owned()),
            (
                "duplicate-stage",
                format!(
                    "{green}FROM gcr.io/distroless/cc-debian12:nonroot AS demo-runtime\n"
                ),
            ),
            (
                "comment-entrypoint-bait",
                green.replace(
                    "ENTRYPOINT [\"/usr/local/bin/demo-server\"]",
                    "# ENTRYPOINT [\"/usr/local/bin/demo-server\"]",
                ),
            ),
            (
                "wrong-entrypoint",
                green.replace("/usr/local/bin/demo-server\"]", "/usr/local/bin/other\"]"),
            ),
            (
                "missing-schema-copy",
                green.replace(
                    "COPY --from=demo-builder /app/assemblies/demo/config.schema.json /usr/share/rss/demo/config.schema.json\n",
                    "",
                ),
            ),
            (
                "run-string-bait",
                green.replace(
                    "RUN cargo build --release --locked --package demo --bin demo-server",
                    "RUN echo cargo build --release --locked --package demo --bin demo-server",
                ),
            ),
            (
                "root-user-override",
                green.replace(
                    "ENTRYPOINT [\"/usr/local/bin/demo-server\"]",
                    "USER 0\nENTRYPOINT [\"/usr/local/bin/demo-server\"]",
                ),
            ),
            ("missing-release", green.replace(" --release", "")),
            ("missing-locked", green.replace(" --locked", "")),
            (
                "swallowed-build-error",
                green.replace(
                    "--bin demo-server",
                    "--bin demo-server || true",
                ),
            ),
            (
                "target-prefix-collision",
                green.replace("--bin demo-server", "--bin demo-server-bait"),
            ),
            (
                "foreign-builder-copy",
                green.replace("COPY --from=demo-builder /app/target", "COPY --from=attacker /app/target"),
            ),
            (
                "schema-source-prefix-collision",
                green.replace("config.schema.json /usr/share", "config.schema.json.bak /usr/share"),
            ),
        ] {
            std::fs::write(root.join("Dockerfile"), candidate)?;
            let mut errors = Vec::new();
            validate_image(&root, "demo", &image, &binary, &config, &mut errors)?;
            if label == "green" {
                assert!(errors.is_empty(), "green Docker closure failed: {errors:?}");
            } else {
                assert!(!errors.is_empty(), "{label} Docker red escaped");
            }
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn closed_source_grammar_rejects_non_executed_witnesses() -> Result<()> {
        assert!(!cargo_journey_has_exact_test(
            "#[test]\nfn exact() { let dead = || panic!(\"not executed\"); }",
            "exact"
        )?);
        assert!(!cargo_journey_has_exact_test(
            "#[test]\nfn exact() -> Result<()> { if false { panic!(\"not executed\"); } Ok(()) }",
            "exact"
        )?);

        let uncalled_smoke = concat!(
            "smoke_bait() {\n",
            "set -euo pipefail\n",
            "COMPOSE=\"docker compose -f ${SCRIPT_DIR}/docker-compose.yml\"\n",
            "$COMPOSE build\n",
            "$COMPOSE up -d\n",
            "trap cleanup EXIT\n",
            "$COMPOSE down -v --remove-orphans\n",
            "if curl -fsS \"${HEALTH_URL}/readyz\"; then\n",
            "curl -fsS \"${HEALTH_URL}/healthz\" >/dev/null || fail\n",
            "}\n",
        );
        assert!(!compose_smoke_is_closed(uncalled_smoke));

        for (scope, open, close) in [
            ("conditional", "if false; then", "fi"),
            ("loop", "while false; do", "done"),
            ("case", "case false in\nfalse)", ";;\nesac"),
            ("group", "{", "}"),
            ("subshell", "(", ")"),
        ] {
            let scoped_smoke = format!(
                "set -euo pipefail\nCOMPOSE=\"docker compose -f ${{SCRIPT_DIR}}/docker-compose.yml\"\ncleanup() {{\n$COMPOSE down -v --remove-orphans\n}}\ntrap cleanup EXIT\n{open}\n$COMPOSE build\n$COMPOSE up -d\nif curl -fsS \"${{HEALTH_URL}}/readyz\"; then\ntrue\nfi\ncurl -fsS \"${{HEALTH_URL}}/healthz\" >/dev/null || fail\n{close}\n"
            );
            assert!(
                !compose_smoke_is_closed(&scoped_smoke),
                "compose gate accepted {scope} witness scope"
            );
        }

        assert!(docker_run_builds_binary(
            "cargo build --release --locked --package demo --bin demo-server",
            "demo",
            "demo",
            "demo-server"
        ));
        for bypass in [
            "cargo build --release --locked --package demo --bin demo-server --help",
            "cargo build --release --locked --package missing --bin missing --help --package demo --bin demo-server",
            "cargo build --release --locked --package demo --bin demo-server --features bait",
        ] {
            assert!(
                !docker_run_builds_binary(bypass, "demo", "demo", "demo-server"),
                "Docker build grammar accepted `{bypass}`"
            );
        }
        Ok(())
    }

    #[test]
    fn markdown_is_stably_sorted_and_has_complete_columns() -> Result<()> {
        let raw = green_matrix()?;
        let markdown = render_observed(&raw);
        assert!(
            markdown.find("| demo |").context("missing demo row")?
                < markdown
                    .find("| sourcecheck |")
                    .context("missing sourcecheck row")?
        );
        assert!(markdown.contains("| Assembly | Declared lifecycle | Binary | Image | Config carrier | Health / inventory | Journey | Reason |"));
        assert!(markdown.contains(
            "| sourcecheck | compile-only | — | — | — | — | — | no deployable composition root |"
        ));
        assert_eq!(markdown, render_observed(&raw));
        assert_eq!(
            markdown,
            render_unverified_source(include_str!("../fixtures/assembly-artifacts/green.toml")),
            "strict and tolerant projections must share the same row semantics and renderer"
        );
        let mut escaped = raw;
        escaped.assemblies[0]
            .binary
            .as_mut()
            .context("green binary")?
            .target = "server|bait\nline".to_owned();
        escaped.assemblies[1].reason = Some("reason|bait\nline".to_owned());
        let escaped = render_observed(&escaped);
        assert!(escaped.contains("server\\|bait line"));
        assert!(escaped.contains("reason\\|bait line"));
        let failed = verification_failure_markdown(&["bad|field\nline".to_owned()]);
        assert!(failed.contains("**FAILED**"));
        assert!(failed.contains("- bad\\|field line"));
        let missing =
            render_unverified_source("schemaVersion = 1\n[[assemblies]]\nname = 'demo'\n");
        assert!(!missing.contains("<missing>"));
        assert!(missing.contains("[missing]"));
        Ok(())
    }

    #[test]
    fn json_schema_recursively_requires_closed_objects() {
        let open = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "nested": { "type": "object" } }
        });
        let closed = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "nested": { "type": "object", "additionalProperties": false } }
        });
        assert!(!crate::assembly::schema_objects_are_closed(&open));
        assert!(crate::assembly::schema_objects_are_closed(&closed));
        for accept_all in [
            serde_json::json!({}),
            serde_json::json!({"properties": {"nested": {"type": "string"}}}),
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"nested": {"properties": {"value": {"type": "string"}}}}
            }),
        ] {
            assert!(!crate::assembly::schema_objects_are_closed(&accept_all));
        }
    }

    #[test]
    fn typed_env_catalog_rejects_text_and_cfg_bait() -> Result<()> {
        let green = concat!(
            "struct EnvConfigSource;\n",
            "struct RuntimeConfigSnapshot;\n",
            "impl RuntimeConfigSnapshot {\n",
            "fn capture_process_snapshot() {\n",
            "Self::capture_with_forbidden_check(EnvConfigSource)\n",
            "}\n",
            "}\n",
        );
        assert!(typed_env_catalog_is_bound(green)?);
        for red in [
            "const BAIT: &str = \"struct EnvConfigSource; impl RuntimeConfigSnapshot { fn capture_process_snapshot() { Self::capture_with_forbidden_check(EnvConfigSource) } }\";",
            "struct EnvConfigSource; struct RuntimeConfigSnapshot; impl RuntimeConfigSnapshot { #[cfg(test)] fn capture_process_snapshot() { Self::capture_with_forbidden_check(EnvConfigSource) } }",
            "struct EnvConfigSource; struct RuntimeConfigSnapshot; impl RuntimeConfigSnapshot { fn capture_process_snapshot() { let bait = EnvConfigSource; Self::capture_with_forbidden_check(bait) } }",
            "struct EnvConfigSource { value: String } struct RuntimeConfigSnapshot; impl RuntimeConfigSnapshot { fn capture_process_snapshot() { Self::capture_with_forbidden_check(EnvConfigSource) } }",
        ] {
            assert!(!typed_env_catalog_is_bound(red)?, "typed env bait escaped");
        }
        Ok(())
    }

    #[test]
    fn health_inventory_rejects_listener_and_runtimeexec_dependency_drift() -> Result<()> {
        let workspace = crate::workspace_root()?;
        let cargo_catalog = crate::assembly::CargoTargetCatalog::load(&workspace)?;
        let root = temp_root("health")?;
        let assembly_dir = root.join("assemblies/settingsonly");
        std::fs::create_dir_all(&assembly_dir)?;
        let manifest =
            std::fs::read_to_string(workspace.join("assemblies/settingsonly/assembly.toml"))?;
        std::fs::write(assembly_dir.join("assembly.toml"), &manifest)?;

        let mut errors = Vec::new();
        validate_health_inventory(&root, &cargo_catalog, "settingsonly", &mut errors)?;
        assert!(
            errors.is_empty(),
            "green health inventory failed: {errors:?}"
        );

        let without_health =
            manifest.replace("[[listeners]]\nkind = \"health\"\ndomains = []\n", "");
        assert_ne!(
            without_health, manifest,
            "health fixture mutation was vacuous"
        );
        std::fs::write(assembly_dir.join("assembly.toml"), without_health)?;
        let mut errors = Vec::new();
        validate_health_inventory(&root, &cargo_catalog, "settingsonly", &mut errors)?;
        assert!(errors.iter().any(|error| error.rule == ArtifactRule::Health
            && error.detail.contains("Health(domains=[])")));

        assert!(cargo_catalog.has_exact_normal_dependency(
            "settingsonly",
            "runtimeexec",
            "crates/runtimeexec/Cargo.toml"
        ));
        assert!(!cargo_catalog.has_exact_normal_dependency(
            "settingsonly",
            "runtimeexec",
            "crates/support/Cargo.toml"
        ));
        assert!(!cargo_catalog.has_exact_normal_dependency(
            "server",
            "runtimeexec",
            "crates/runtimeexec/Cargo.toml"
        ));

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)] // anti-vacuity pins every typed supported-row accessor.
    fn real_workspace_matrix_is_exact_and_complete() -> Result<()> {
        let root = crate::workspace_root()?;
        let cargo_catalog = crate::assembly::CargoTargetCatalog::load(&root)?;
        let raw: RawMatrix = toml::from_str(&read_artifact_utf8(
            &root.join(MATRIX_PATH),
            "test artifact matrix",
        )?)?;
        let observed = render_observed(&raw);
        let validation = validate_root(&root)?;
        assert!(validation.findings.is_empty(), "{:#?}", validation.findings);
        for assembly in ["identityaudit", "runtime", "settingsonly"] {
            let row = observed
                .lines()
                .find(|line| line.starts_with(&format!("| {assembly} |")))
                .with_context(|| format!("missing observed row for {assembly}"))?;
            assert_eq!(
                row.matches('|').count(),
                9,
                "incomplete Markdown row: {row}"
            );
            assert!(!row.contains(MISSING), "vacuous Markdown row: {row}");
        }
        let verified = validation.verified.context("missing verified matrix")?;
        let rows = verified.supported_rows();
        assert_eq!(
            rows.iter().map(SupportedArtifact::name).collect::<Vec<_>>(),
            ["identityaudit", "runtime", "settingsonly"]
        );
        assert_eq!(rows[0].binary(), ("identityaudit", "identityaudit-server"));
        assert_eq!(rows[0].image(), ("Dockerfile", "identityaudit-runtime"));
        assert_eq!(
            rows[0].config_carrier(),
            ("json-schema", "assemblies/identityaudit/config.schema.json")
        );
        assert_eq!(rows[0].health_inventory(), ("runtimeexec", "health"));
        assert_eq!(
            rows[0].journey(),
            "cargo-test:journeys#identityaudit_runtime#identityaudit_login_audit_ready_sigterm_drain"
        );
        assert_eq!(rows[1].binary(), ("server", "server"));
        assert_eq!(
            rows[1].config_carrier(),
            ("typed-env-catalog", "assemblies/runtime/src/config.rs")
        );
        assert_eq!(rows[1].journey(), "compose-smoke-v1:deploy/smoke.sh");
        assert_eq!(rows[2].binary(), ("settingsonly", "settingsonly-server"));
        assert!(!cargo_catalog.target_exists("server", "ghost", "bin"));
        assert!(
            cargo_catalog
                .target_path("journeys", "ghost", "test")
                .is_none()
        );
        assert!(!cargo_catalog.binary_belongs_to_assembly(
            "settingsonly",
            "identityaudit",
            "identityaudit-server"
        ));
        Ok(())
    }
}
