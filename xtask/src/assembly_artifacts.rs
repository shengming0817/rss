//! Closed application-artifact inventory for every discovered assembly.
//!
//! INVARIANT: ASSEMBLY-ARTIFACT-MATRIX-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::synthetic_red_rejects_incomplete_or_unsafe_rows", anti_vacuity = "tests::real_workspace_matrix_is_exact_and_complete" } -- the schema-v1 lifecycle declaration is an exact bijection with `assemblies/*`; only rows whose Cargo, image, config, health/inventory and journey evidence all validate can become `VerifiedArtifactMatrix` values.
//! INVARIANT: PRODUCTION-SMOKE-POLICY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::strict_compose_smoke_policy_rejects_synthetic_mutations_and_binds_the_real_file", anti_vacuity = "tests::strict_compose_smoke_policy_rejects_synthetic_mutations_and_binds_the_real_file" } -- the executable compose journey requires an explicit closed mode, release never permits skip, and only an explicit developer opt-in can emit the unique non-production receipt before Docker execution.
//! INVARIANT: COMPOSE-RUNTIME-DELIVERY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::compose_runtime_delivery_rejects_each_synthetic_mutation", anti_vacuity = "tests::compose_runtime_delivery_rejects_each_synthetic_mutation" } -- the developer Compose carrier keeps operator and serving images distinct, grants the serving process enough grace for its application-owned drain budget, and the executable smoke witness proves ordered SIGTERM reception, complete drain, and exit zero.

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
#[cfg(test)]
const UNKNOWN: &str = "[unknown]";
#[cfg(test)]
const INVALID: &str = "[invalid]";
#[cfg(test)]
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
#[derive(Debug)]
struct VerifiedArtifactMatrix {
    supported_count: usize,
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
    let raw: RawMatrix = match parse_raw_matrix(&source) {
        Ok(raw) => raw,
        Err(error) => {
            print!("{MARKDOWN_HEADER}");
            print_verification_failure(&["artifact matrix TOML rejected".to_owned()]);
            return Err(error).context("解析 closed artifact matrix 失败");
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
            "\n## Verification\n\n**STATIC CARRIERS VERIFIED** — {} supported assembly artifact rows passed closed validation.\n\nThis verdict does not include same-head test or image-build receipts.",
            verified.supported_count
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

#[cfg(test)]
fn validate_root(root: &Path) -> Result<Validation> {
    let path = root.join(MATRIX_PATH);
    ensure_regular_path(root, MATRIX_PATH)?;
    let source = read_artifact_utf8(&path, "assembly artifact matrix")
        .with_context(|| format!("读取 {} 失败", path.display()))?;
    let raw = parse_raw_matrix(&source)?;
    validate_matrix(root, raw)
}

fn parse_raw_matrix(source: &str) -> Result<RawMatrix> {
    toml::from_str(source).map_err(|error: toml::de::Error| {
        let category = if error.message().starts_with("unknown field")
            || error.message().starts_with("missing field")
            || error.message().starts_with("invalid type")
        {
            "data"
        } else {
            "syntax"
        };
        let (line, column) = error.span().map_or((1, 1), |span| {
            let prefix = &source.as_bytes()[..span.start.min(source.len())];
            let line = prefix.iter().filter(|byte| **byte == b'\n').count() + 1;
            let column = prefix
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(prefix.len() + 1, |offset| prefix.len() - offset);
            (line, column)
        });
        anyhow::anyhow!(
            "artifact matrix TOML rejected ({category} at line {line}, column {column})"
        )
    })
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

    let mut supported_count = 0;
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
                supported_count += 1;
            }
        }
    }
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
        .then_some(VerifiedArtifactMatrix { supported_count });
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
                && !method
                    .attrs
                    .iter()
                    .any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
                && method
                    .block
                    .stmts
                    .iter()
                    .filter(|statement| statement_contains_typed_env_capture(statement))
                    .count()
                    == 1
        })
    });
    Ok(env_source && capture)
}

fn statement_contains_typed_env_capture(statement: &syn::Stmt) -> bool {
    let expression = match statement {
        syn::Stmt::Local(local) => local.init.as_ref().map(|init| init.expr.as_ref()),
        syn::Stmt::Expr(expression, _) => Some(expression),
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => None,
    };
    let Some(expression) = expression else {
        return false;
    };
    let expression = match expression {
        syn::Expr::Try(expression) => expression.expr.as_ref(),
        expression => expression,
    };
    exact_typed_env_capture_call(expression)
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
            if let Err(rule) = validate_compose_smoke(&source) {
                reject!(
                    findings,
                    Journey,
                    assembly,
                    "compose-smoke-v1 违反精确规则 {}",
                    rule.as_str()
                );
            }
            let compose_path = root.join("deploy/docker-compose.yml");
            let compose_source = std::fs::read_to_string(&compose_path)
                .with_context(|| format!("读取 {} 失败", compose_path.display()))?;
            if let Err(rule) = validate_compose_runtime_delivery(&compose_source, &source) {
                reject!(
                    findings,
                    Journey,
                    assembly,
                    "compose-smoke-v1 违反运行时交付规则 {}",
                    rule.as_str()
                );
            }
            let env_path = root.join("deploy/.env.example");
            let env_source = std::fs::read_to_string(&env_path)
                .with_context(|| format!("读取 {} 失败", env_path.display()))?;
            let bundle_path = root.join("deploy/demo-secrets/runtime-serving-secret-bundle");
            let bundle_source = std::fs::read_to_string(&bundle_path)
                .with_context(|| format!("读取 {} 失败", bundle_path.display()))?;
            if !compose_serving_secret_bundle_is_closed(&env_source, &bundle_source) {
                reject!(
                    findings,
                    Journey,
                    assembly,
                    "compose-smoke-v1 的 serving Secret bundle/env 边界不闭合"
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComposeSmokeRule {
    ComposeGrammar,
    ShellGrammar,
    StrictShell,
    ModeDeclaration,
    ModeClosure,
    AllowSkipDeclaration,
    AllowSkipClosure,
    ReleaseSkip,
    ReleaseKeepUp,
    DeveloperSkip,
    FixtureDispatch,
    SuccessTermination,
    PolicyOrder,
    ReleaseTeardown,
    ReleaseReceipt,
    OutageClosure,
    ComposeLifecycle,
    Cleanup,
    Readiness,
    OperatorProjection,
    ServerProjection,
    DrainWitness,
}

impl ComposeSmokeRule {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ComposeGrammar => "COMPOSE-GRAMMAR-01",
            Self::ShellGrammar => "SMOKE-SHELL-GRAMMAR-01",
            Self::StrictShell => "SMOKE-STRICT-SHELL-01",
            Self::ModeDeclaration => "SMOKE-MODE-DECLARATION-01",
            Self::ModeClosure => "SMOKE-MODE-CLOSURE-01",
            Self::AllowSkipDeclaration => "SMOKE-ALLOW-SKIP-DECLARATION-01",
            Self::AllowSkipClosure => "SMOKE-ALLOW-SKIP-CLOSURE-01",
            Self::ReleaseSkip => "SMOKE-RELEASE-SKIP-01",
            Self::ReleaseKeepUp => "SMOKE-RELEASE-KEEP-UP-01",
            Self::DeveloperSkip => "SMOKE-DEVELOPER-SKIP-01",
            Self::FixtureDispatch => "SMOKE-FIXTURE-DISPATCH-01",
            Self::SuccessTermination => "SMOKE-SUCCESS-TERMINATION-01",
            Self::PolicyOrder => "SMOKE-POLICY-ORDER-01",
            Self::ReleaseTeardown => "SMOKE-RELEASE-TEARDOWN-01",
            Self::ReleaseReceipt => "SMOKE-RELEASE-RECEIPT-01",
            Self::OutageClosure => "SMOKE-OUTAGE-CLOSURE-01",
            Self::ComposeLifecycle => "SMOKE-COMPOSE-LIFECYCLE-01",
            Self::Cleanup => "SMOKE-CLEANUP-01",
            Self::Readiness => "SMOKE-READINESS-01",
            Self::OperatorProjection => "COMPOSE-OPERATOR-PROJECTION-01",
            Self::ServerProjection => "COMPOSE-SERVER-PROJECTION-01",
            Self::DrainWitness => "COMPOSE-SIGTERM-DRAIN-WITNESS-01",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ComposeDeliveryFile {
    services: ComposeDeliveryServices,
}

#[derive(Debug, Deserialize)]
struct ComposeDeliveryServices {
    #[serde(rename = "rss-access-jwks-init")]
    rss_access_jwks_init: ComposeDeliveryService,
    migration: ComposeDeliveryService,
    server: ComposeDeliveryService,
}

#[derive(Debug, Deserialize)]
struct ComposeDeliveryService {
    build: ComposeDeliveryBuild,
    image: String,
    #[serde(default)]
    stop_grace_period: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ComposeDeliveryBuild {
    target: String,
}

fn validate_compose_runtime_delivery(
    compose: &str,
    smoke: &str,
) -> std::result::Result<(), ComposeSmokeRule> {
    let compose: ComposeDeliveryFile =
        serde_yaml_ng::from_str(compose).map_err(|_| ComposeSmokeRule::ComposeGrammar)?;
    for service in [
        &compose.services.rss_access_jwks_init,
        &compose.services.migration,
    ] {
        if service.build.target != "operator-runtime" || service.image != "rss-operator:dev" {
            return Err(ComposeSmokeRule::OperatorProjection);
        }
    }
    let server = &compose.services.server;
    if server.build.target != "runtime"
        || server.image != "rss-runtime:dev"
        || server.stop_grace_period.as_deref() != Some("30s")
    {
        return Err(ComposeSmokeRule::ServerProjection);
    }

    let commands = shell_semantic_lines(smoke).ok_or(ComposeSmokeRule::ShellGrammar)?;
    let ordered: [(&str, &[ShellScope]); 3] = [
        ("docker kill --signal=TERM \"$cid\" >/dev/null", &[]),
        (
            "server_state=\"$(docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' \"$cid\")\"",
            &[ShellScope::Loop],
        ),
        (
            "[[ \"$server_state\" = \"exited:0\" ]] && break",
            &[ShellScope::Loop],
        ),
    ];
    let mut cursor = 0;
    for (text, scopes) in ordered {
        let Some(offset) = commands[cursor..].iter().position(|command| {
            command.function.is_none() && command.scopes == scopes && command.text == text
        }) else {
            return Err(ComposeSmokeRule::DrainWitness);
        };
        cursor += offset + 1;
    }
    if !commands[cursor..].iter().any(is_exit_zero_assertion) {
        return Err(ComposeSmokeRule::DrainWitness);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ShellAssertion<'a> {
    subject: &'a str,
    operator: &'a str,
    expected: &'a str,
    failure_command: &'a str,
}

fn parse_shell_assertion(command: &str) -> Option<ShellAssertion<'_>> {
    let (condition, failure) = command.split_once("||")?;
    let condition = condition.trim().strip_prefix("[[")?.strip_suffix("]]")?;
    let mut terms = condition.split_ascii_whitespace();
    let assertion = ShellAssertion {
        subject: terms.next()?.trim_matches(['\'', '"']),
        operator: terms.next()?,
        expected: terms.next()?.trim_matches(['\'', '"']),
        failure_command: failure.split_ascii_whitespace().next()?,
    };
    terms.next().is_none().then_some(assertion)
}

fn is_exit_zero_assertion(command: &ShellSemanticLine<'_>) -> bool {
    command.function.is_none()
        && command.scopes.is_empty()
        && parse_shell_assertion(command.text).is_some_and(|assertion| {
            assertion.subject == "$server_state"
                && matches!(assertion.operator, "=" | "==")
                && assertion.expected == "exited:0"
                && assertion.failure_command == "fail"
        })
}

fn validate_compose_smoke(source: &str) -> std::result::Result<(), ComposeSmokeRule> {
    let commands = shell_semantic_lines(source).ok_or(ComposeSmokeRule::ShellGrammar)?;
    let top_level = commands
        .iter()
        .filter(|command| command.function.is_none() && command.scopes.is_empty())
        .map(|command| command.text)
        .collect::<Vec<_>>();
    if !top_level.contains(&"set -euo pipefail") {
        return Err(ComposeSmokeRule::StrictShell);
    }
    validate_compose_smoke_policy(&commands)?;
    validate_compose_smoke_outage_closure(&commands)?;
    if !top_level.contains(&"COMPOSE=\"docker compose -f ${SCRIPT_DIR}/docker-compose.yml\"")
        || !top_level.contains(&"$COMPOSE build")
        || !top_level.contains(&"$COMPOSE up -d")
        || !top_level.contains(&"trap cleanup EXIT")
    {
        return Err(ComposeSmokeRule::ComposeLifecycle);
    }
    if !commands.iter().any(|command| {
        command.function == Some("cleanup")
            && command.scopes.is_empty()
            && command.text.starts_with("$COMPOSE down -v ")
    }) {
        return Err(ComposeSmokeRule::Cleanup);
    }
    validate_compose_smoke_release_teardown(&commands)?;
    let ready = commands.iter().any(|command| {
        command.function.is_none()
            && command.scopes == [ShellScope::Loop]
            && command
                .text
                .starts_with("if curl -fsS \"${HEALTH_URL}/readyz\"")
    });
    let health = top_level
        .iter()
        .any(|line| line.starts_with("curl -fsS \"${HEALTH_URL}/healthz\" >/dev/null || fail"));
    if !ready || !health {
        return Err(ComposeSmokeRule::Readiness);
    }
    Ok(())
}

fn validate_compose_smoke_release_teardown(
    commands: &[ShellSemanticLine<'_>],
) -> std::result::Result<(), ComposeSmokeRule> {
    let exact = |function, scopes: &[ShellScope], text| {
        commands.iter().any(|command| {
            command.function == function && command.scopes == scopes && command.text == text
        })
    };
    if !exact(
        Some("teardown"),
        &[ShellScope::Conditional],
        "$COMPOSE down -v >/dev/null 2>&1",
    ) || commands
        .iter()
        .any(|command| command.function == Some("teardown") && command.text.contains("|| true"))
    {
        return Err(ComposeSmokeRule::ReleaseTeardown);
    }
    let top_position = |text| {
        commands.iter().position(|command| {
            command.function.is_none() && command.scopes.is_empty() && command.text == text
        })
    };
    let teardown = top_position("teardown");
    let disarm = top_position("trap - EXIT");
    let success = top_position("log \"全部冒烟通过 ✅\"");
    if teardown.is_none()
        || disarm.is_none()
        || success.is_none()
        || teardown >= disarm
        || disarm >= success
    {
        return Err(ComposeSmokeRule::ReleaseTeardown);
    }
    Ok(())
}

fn validate_compose_smoke_outage_closure(
    commands: &[ShellSemanticLine<'_>],
) -> std::result::Result<(), ComposeSmokeRule> {
    let has_text = |text: &str| commands.iter().any(|command| command.text.contains(text));
    for witness in [
        "\"name\":\"keyprovider_ready\",\"status\":\"unhealthy\"",
        "\"name\":\"keyprovider_ready\",\"status\":\"healthy\"",
        "\"name\":\"vault_secret_resolver_ready\",\"status\":\"unhealthy\"",
        "\"name\":\"vault_secret_resolver_ready\",\"status\":\"healthy\"",
        "\"name\":\"s3_object_store_ready\",\"status\":\"unhealthy\"",
        "\"name\":\"s3_object_store_ready\",\"status\":\"healthy\"",
        "\"name\":\"redis_ready\",\"status\":\"unhealthy\"",
        "\"name\":\"redis_ready\",\"status\":\"healthy\"",
    ] {
        if !has_text(witness) {
            return Err(ComposeSmokeRule::OutageClosure);
        }
    }
    let top_position = |text| {
        commands.iter().position(|command| {
            command.function.is_none() && command.scopes.is_empty() && command.text == text
        })
    };
    let redis_stop = top_position("$COMPOSE stop redis >/dev/null");
    let redis_start = top_position("$COMPOSE start redis >/dev/null");
    let redis_unhealthy_between = commands.iter().enumerate().any(|(index, command)| {
        Some(index) > redis_stop
            && Some(index) < redis_start
            && command
                .text
                .contains("\"name\":\"redis_ready\",\"status\":\"unhealthy\"")
    });
    let redis_healthy_after_start = commands.iter().enumerate().any(|(index, command)| {
        Some(index) > redis_start
            && command.scopes == [ShellScope::Loop]
            && command
                .text
                .contains("\"name\":\"redis_ready\",\"status\":\"healthy\"")
    });
    if redis_stop.is_none()
        || redis_start.is_none()
        || redis_stop >= redis_start
        || !redis_unhealthy_between
        || !redis_healthy_after_start
    {
        return Err(ComposeSmokeRule::OutageClosure);
    }
    Ok(())
}

fn compose_serving_secret_bundle_is_closed(env_source: &str, bundle_source: &str) -> bool {
    const FORBIDDEN_ENV_KEYS: &[&str] = &[
        "RSS_AMQP_URL",
        "RSS_SETTINGS_AMQP_URL",
        "RSS_IDENTITY_AMQP_URL",
        "RSS_AUDIT_AMQP_URL",
        "RSS_AUDIT_CHAIN_KEY_B64URL",
        "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON",
        "RSS_DLX_ARCHIVE_VAULT_TOKEN",
        "RSS_DLX_HOT_VAULT_TOKEN",
        "RSS_PG_PASSWORD_FILE",
        "RSS_PG_READ_PASSWORD_FILE",
        "RSS_PG_AUDIT_ADMIN_PASSWORD_FILE",
        "RSS_PG_DLX_ARCHIVER_PASSWORD_FILE",
        "RSS_PG_DLX_VERIFIER_PASSWORD_FILE",
        "RSS_PG_DLX_PURGER_PASSWORD_FILE",
        "RSS_REDIS_URL",
        "RSS_S3_ACCESS_KEY_ID",
        "RSS_S3_SECRET_ACCESS_KEY",
        "RSS_S3_SESSION_TOKEN",
        "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
        "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
        "RSS_VAULT_TOKEN",
    ];
    if env_source.lines().any(|line| {
        FORBIDDEN_ENV_KEYS
            .iter()
            .any(|key| line.starts_with(&format!("{key}=")))
    }) {
        return false;
    }
    let Ok(bundle) = serde_json::from_str::<serde_json::Value>(bundle_source) else {
        return false;
    };
    let Some(bundle) = bundle.as_object() else {
        return false;
    };
    let required = [
        "amqpUrl",
        "auditChainKey",
        "commandIdempotencyKeys",
        "dlxArchiveVaultToken",
        "dlxHotVaultToken",
        "pgPassword",
        "pgReadPassword",
        "pgDlxArchiverPassword",
        "pgDlxVerifierPassword",
        "pgDlxPurgerPassword",
        "redisUrl",
        "s3AccessKeyId",
        "s3SecretAccessKey",
        "serviceTokenSecret",
        "tenantAuthorityKey",
        "vaultToken",
    ];
    if bundle.len() != required.len()
        || required.iter().any(|key| {
            !bundle
                .get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
    {
        return false;
    }
    let Some(raw_keyring) = bundle
        .get("commandIdempotencyKeys")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw_keyring) else {
        return false;
    };
    value
        .get("current")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|current| {
            current.len() == 2
                && current
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|id| !id.is_empty())
                && current
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|key| !key.is_empty())
        })
}

fn validate_compose_smoke_policy(
    commands: &[ShellSemanticLine<'_>],
) -> std::result::Result<(), ComposeSmokeRule> {
    let has = |function: Option<&str>, scopes: &[ShellScope], text: &str| {
        commands.iter().any(|command| {
            command.function == function && command.scopes == scopes && command.text == text
        })
    };
    let top = |text| has(None, &[], text);
    let policy = |scopes: &[ShellScope], text| has(Some("validate_smoke_policy"), scopes, text);
    let missing = |scopes: &[ShellScope], text| has(Some("missing_spiffe_fixture"), scopes, text);
    let top_position = |text| {
        commands.iter().position(|command| {
            command.function.is_none() && command.scopes.is_empty() && command.text == text
        })
    };

    if !top("RSS_SMOKE_MODE=\"${RSS_SMOKE_MODE-}\"") {
        return Err(ComposeSmokeRule::ModeDeclaration);
    }
    if !policy(&[], "case \"$RSS_SMOKE_MODE\" in")
        || !policy(&[ShellScope::Case], "developer|release) ;;")
        || !policy(
            &[ShellScope::Case],
            "\"\") fail \"RSS_SMOKE_MODE 必填（developer|release）\" ;;",
        )
        || !policy(
            &[ShellScope::Case],
            "*) fail \"RSS_SMOKE_MODE 非法：仅允许 developer|release\" ;;",
        )
    {
        return Err(ComposeSmokeRule::ModeClosure);
    }
    if !top("RSS_SMOKE_ALLOW_SKIP=\"${RSS_SMOKE_ALLOW_SKIP-0}\"") {
        return Err(ComposeSmokeRule::AllowSkipDeclaration);
    }
    if !policy(&[], "case \"$RSS_SMOKE_ALLOW_SKIP\" in")
        || !policy(&[ShellScope::Case], "0|1) ;;")
        || !policy(
            &[ShellScope::Case],
            "*) fail \"RSS_SMOKE_ALLOW_SKIP 非法：仅允许 0|1\" ;;",
        )
    {
        return Err(ComposeSmokeRule::AllowSkipClosure);
    }
    if !policy(
        &[],
        "if [[ \"$RSS_SMOKE_MODE\" = \"release\" && \"$RSS_SMOKE_ALLOW_SKIP\" = \"1\" ]]; then",
    ) || !policy(
        &[ShellScope::Conditional],
        "fail \"release smoke 禁止 RSS_SMOKE_ALLOW_SKIP=1\"",
    ) {
        return Err(ComposeSmokeRule::ReleaseSkip);
    }
    if !policy(
        &[],
        "if [[ \"$RSS_SMOKE_MODE\" = \"release\" && \"${KEEP_UP:-0}\" = \"1\" ]]; then",
    ) || !policy(
        &[ShellScope::Conditional],
        "fail \"release smoke 禁止 KEEP_UP=1\"",
    ) {
        return Err(ComposeSmokeRule::ReleaseKeepUp);
    }
    if !missing(
        &[],
        "if [[ \"$RSS_SMOKE_MODE\" = \"developer\" && \"$RSS_SMOKE_ALLOW_SKIP\" = \"1\" ]]; then",
    ) || !missing(
        &[ShellScope::Conditional],
        "printf '%s\\n' 'NOT PRODUCTION EVIDENCE'",
    ) || !missing(&[ShellScope::Conditional], "exit 0")
        || !missing(
            &[],
            "fail \"Remote/SPIFFE fixture 不完整（缺少 ${missing}）\"",
        )
        || commands
            .iter()
            .filter(|command| command.text == "printf '%s\\n' 'NOT PRODUCTION EVIDENCE'")
            .count()
            != 1
    {
        return Err(ComposeSmokeRule::DeveloperSkip);
    }
    if !has(
        Some("require_spiffe_fixture"),
        &[ShellScope::Conditional],
        "missing_spiffe_fixture \"${missing[*]}\"",
    ) {
        return Err(ComposeSmokeRule::FixtureDispatch);
    }
    let allowed_success = |command: &ShellSemanticLine<'_>| {
        command.function == Some("missing_spiffe_fixture")
            && command.scopes == [ShellScope::Conditional]
            && command.text == "exit 0"
    };
    let mut success_terminations = commands.iter().filter(|command| {
        matches!(command.text, "exit" | "exit 0")
            || (command.function.is_none() && matches!(command.text, "return" | "return 0"))
    });
    if success_terminations.clone().count() != 1 || !success_terminations.all(allowed_success) {
        return Err(ComposeSmokeRule::SuccessTermination);
    }
    if !top("validate_smoke_policy")
        || !top("require_spiffe_fixture")
        || top_position("validate_smoke_policy") >= top_position("require_spiffe_fixture")
        || top_position("require_spiffe_fixture") >= top_position("$COMPOSE build")
    {
        return Err(ComposeSmokeRule::PolicyOrder);
    }
    let release_condition = commands.iter().position(|command| {
        command.function.is_none()
            && command.scopes.is_empty()
            && command.text == "if [[ \"$RSS_SMOKE_MODE\" = \"release\" ]]; then"
    });
    let release_receipt = commands.iter().position(|command| {
        command.function.is_none()
            && command.scopes == [ShellScope::Conditional]
            && command.text == "printf '%s\\n' 'RELEASE IMAGE ON DEMO INFRA EVIDENCE'"
    });
    let success_log = commands.iter().position(|command| {
        command.function.is_none()
            && command.scopes.is_empty()
            && command.text == "log \"全部冒烟通过 ✅\""
    });
    if release_condition.is_none()
        || release_receipt.is_none()
        || success_log.is_none()
        || success_log >= release_condition
        || release_receipt <= release_condition
        || commands
            .iter()
            .filter(|command| {
                command.text == "printf '%s\\n' 'RELEASE IMAGE ON DEMO INFRA EVIDENCE'"
            })
            .count()
            != 1
    {
        return Err(ComposeSmokeRule::ReleaseReceipt);
    }
    Ok(())
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
    if stage.instructions.iter().any(|line| {
        crate::assembly::docker_instruction_arguments(line, "COPY").is_some_and(|args| {
            args.contains("/app/target/release/rss") || args.contains("/usr/local/bin/rss")
        })
    }) {
        reject!(
            findings,
            Image,
            assembly,
            "serving Docker target 禁止包含 rss migration operator"
        );
    }
    let operator_stages = stages
        .iter()
        .filter(|candidate| candidate.name == "operator-runtime")
        .collect::<Vec<_>>();
    let [operator] = operator_stages.as_slice() else {
        reject!(
            findings,
            Image,
            assembly,
            "Docker 必须有唯一 operator-runtime stage"
        );
        return Ok(());
    };
    if operator.base != "gcr.io/distroless/cc-debian12:nonroot"
        || operator.instructions.iter().any(|line| {
            crate::assembly::docker_instruction_arguments(line, "COPY")
                .is_some_and(|args| !args.contains("/app/target/release/rss"))
        })
        || !operator.instructions.iter().any(|line| {
            crate::assembly::docker_instruction_arguments(line, "COPY").is_some_and(|args| {
                args.contains("/app/target/release/rss") && args.ends_with("/usr/local/bin/rss")
            })
        })
    {
        reject!(
            findings,
            Image,
            assembly,
            "operator-runtime 必须仅投影 rss migration operator"
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
        tokens == ["cargo", "build", "--release", "--locked", "--bin", target]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

    fn compose_service_block<'a>(compose: &'a str, service: &str) -> Option<&'a str> {
        let marker = format!("  {service}:\n");
        let start = compose.find(&marker)?;
        let body_start = start + marker.len();
        let mut end = compose.len();
        let mut offset = body_start;
        for line in compose[body_start..].split_inclusive('\n') {
            if !line.trim().is_empty() && !line.starts_with("    ") {
                end = offset;
                break;
            }
            offset += line.len();
        }
        Some(&compose[start..end])
    }

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
    fn artifact_toml_parse_error_never_echoes_input_bait() -> Result<()> {
        let bait = "ZZ_ARTIFACT_INPUT_BAIT";
        let source = format!("schemaVersion = 1\nvalue = \"{bait}\"\n");
        let error = parse_raw_matrix(&source)
            .err()
            .context("unknown artifact field was accepted")?;
        assert!(!error.to_string().contains(bait));
        assert!(!format!("{error:?}").contains(bait));
        Ok(())
    }

    #[test]
    fn artifact_toml_parse_error_retains_sanitized_location_and_category() -> Result<()> {
        let bait = "ZZ_ARTIFACT_INPUT_BAIT";
        let source = format!("schemaVersion = 1\nvalue = \"{bait}\n");
        let error = parse_raw_matrix(&source)
            .err()
            .context("malformed artifact TOML was accepted")?;
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains(bait));
        assert!(
            diagnostic.contains("syntax"),
            "missing category: {diagnostic}"
        );
        assert!(
            diagnostic.contains("line 2"),
            "missing safe line: {diagnostic}"
        );
        assert!(
            diagnostic.contains("column"),
            "missing safe column: {diagnostic}"
        );
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
        assert!(validate_compose_smoke(
            "# docker compose; $COMPOSE build; $COMPOSE up -d; /readyz /healthz; trap cleanup EXIT; $COMPOSE down -v"
        ).is_err());
        assert!(validate_compose_smoke(
            "BAIT='docker compose $COMPOSE build $COMPOSE up -d /readyz /healthz trap cleanup EXIT $COMPOSE down -v'"
        ).is_err());
        assert!(
            validate_compose_smoke(concat!(
                "cat <<'BAIT'\n",
                "COMPOSE=\"docker compose -f ${SCRIPT_DIR}/docker-compose.yml\"\n",
                "$COMPOSE build\n",
                "$COMPOSE up -d\n",
                "trap cleanup EXIT\n",
                "$COMPOSE down -v --remove-orphans\n",
                "if curl -fsS \"${HEALTH_URL}/readyz\"; then\n",
                "curl -fsS \"${HEALTH_URL}/healthz\" >/dev/null || fail\n",
                "BAIT\n",
            ))
            .is_err()
        );
        assert!(
            validate_compose_smoke(concat!(
                "COMPOSE=\"docker compose -f ${SCRIPT_DIR}/docker-compose.yml\"\n",
                "$COMPOSE build\n",
                "$COMPOSE up -d\n",
                "trap cleanup EXIT\n",
                "$COMPOSE down -v --remove-orphans\n",
                "if curl -fsS \"${HEALTH_URL}/readyz\"; then\n",
                "curl -fsS \"${HEALTH_URL}/healthz\" >/dev/null || fail\n",
            ))
            .is_err()
        );
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
            "FROM chef AS operator-builder\n",
            "RUN cargo build --release --locked --package rss --bin rss\n",
            "FROM gcr.io/distroless/cc-debian12:nonroot AS operator-runtime\n",
            "COPY --from=operator-builder /app/target/release/rss /usr/local/bin/rss\n",
            "ENTRYPOINT [\"/usr/local/bin/rss\"]\n",
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
                "operator-leaks-into-serving",
                green.replace(
                    "COPY --from=demo-builder /app/assemblies/demo/config.schema.json /usr/share/rss/demo/config.schema.json\n",
                    "COPY --from=operator-builder /app/target/release/rss /usr/local/bin/rss\nCOPY --from=demo-builder /app/assemblies/demo/config.schema.json /usr/share/rss/demo/config.schema.json\n",
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
    fn strict_compose_smoke_policy_rejects_synthetic_mutations_and_binds_the_real_file()
    -> Result<()> {
        let workspace = crate::workspace_root()?;
        let source = std::fs::read_to_string(workspace.join("deploy/smoke.sh"))?;
        assert!(
            validate_compose_smoke(&source).is_ok(),
            "real deploy/smoke.sh is not strict production evidence"
        );
        let env_source = std::fs::read_to_string(workspace.join("deploy/.env.example"))?;
        let bundle_source = std::fs::read_to_string(
            workspace.join("deploy/demo-secrets/runtime-serving-secret-bundle"),
        )?;
        assert!(
            compose_serving_secret_bundle_is_closed(&env_source, &bundle_source),
            "real compose serving Secret boundary is not closed"
        );
        for (label, mutated_bundle) in [
            (
                "missing-command-keyring",
                bundle_source.replace("\"commandIdempotencyKeys\"", "\"removedKeyring\""),
            ),
            (
                "malformed-command-keyring",
                bundle_source.replace("{\\\"current\\\"", "not-json"),
            ),
        ] {
            assert_ne!(
                mutated_bundle, bundle_source,
                "{label} mutation was vacuous"
            );
            assert!(
                !compose_serving_secret_bundle_is_closed(&env_source, &mutated_bundle),
                "{label} mutation escaped"
            );
        }
        let raw_env = format!("{env_source}\nRSS_REDIS_URL=redis://legacy\n");
        assert!(
            !compose_serving_secret_bundle_is_closed(&raw_env, &bundle_source),
            "legacy raw Secret environment mutation escaped"
        );

        for (label, expected, needle, replacement) in [
            (
                "required-mode",
                ComposeSmokeRule::ModeDeclaration,
                "RSS_SMOKE_MODE=\"${RSS_SMOKE_MODE-}\"",
                "RSS_SMOKE_MODE=\"${RSS_SMOKE_MODE-developer}\"",
            ),
            (
                "closed-allow-skip",
                ComposeSmokeRule::AllowSkipDeclaration,
                "RSS_SMOKE_ALLOW_SKIP=\"${RSS_SMOKE_ALLOW_SKIP-0}\"",
                "RSS_SMOKE_ALLOW_SKIP=\"${RSS_SMOKE_ALLOW_SKIP:-0}\"",
            ),
            (
                "closed-mode-values",
                ComposeSmokeRule::ModeClosure,
                "developer|release) ;;",
                "developer|release|compat) ;;",
            ),
            (
                "closed-allow-values",
                ComposeSmokeRule::AllowSkipClosure,
                "0|1) ;;",
                "0|1|true) ;;",
            ),
            (
                "release-rejects-skip",
                ComposeSmokeRule::ReleaseSkip,
                "[[ \"$RSS_SMOKE_MODE\" = \"release\" && \"$RSS_SMOKE_ALLOW_SKIP\" = \"1\" ]]",
                "[[ \"$RSS_SMOKE_MODE\" = \"release\" && \"$RSS_SMOKE_ALLOW_SKIP\" = \"2\" ]]",
            ),
            (
                "release-rejects-keep-up",
                ComposeSmokeRule::ReleaseKeepUp,
                "[[ \"$RSS_SMOKE_MODE\" = \"release\" && \"${KEEP_UP:-0}\" = \"1\" ]]",
                "[[ \"$RSS_SMOKE_MODE\" = \"release\" && \"${KEEP_UP:-0}\" = \"2\" ]]",
            ),
            (
                "developer-only-skip",
                ComposeSmokeRule::DeveloperSkip,
                "[[ \"$RSS_SMOKE_MODE\" = \"developer\" && \"$RSS_SMOKE_ALLOW_SKIP\" = \"1\" ]]",
                "[[ \"$RSS_SMOKE_ALLOW_SKIP\" = \"1\" ]]",
            ),
            (
                "evidence-classification",
                ComposeSmokeRule::DeveloperSkip,
                "printf '%s\\n' 'NOT PRODUCTION EVIDENCE'",
                "printf '%s\\n' 'SKIPPED'",
            ),
            (
                "missing-fixture-call",
                ComposeSmokeRule::FixtureDispatch,
                "missing_spiffe_fixture \"${missing[*]}\"",
                "log \"missing fixture\"",
            ),
            (
                "release-receipt",
                ComposeSmokeRule::ReleaseReceipt,
                "printf '%s\\n' 'RELEASE IMAGE ON DEMO INFRA EVIDENCE'",
                "printf '%s\\n' 'RELEASE EVIDENCE'",
            ),
        ] {
            let mutated = source.replacen(needle, replacement, 1);
            assert_ne!(mutated, source, "{label} mutation was vacuous");
            assert_eq!(validate_compose_smoke(&mutated), Err(expected), "{label}");
        }

        let early_success = source.replacen("$COMPOSE build", "exit 0\n$COMPOSE build", 1);
        assert_ne!(early_success, source, "early-exit mutation was vacuous");
        assert_eq!(
            validate_compose_smoke(&early_success),
            Err(ComposeSmokeRule::SuccessTermination),
            "top-level exit 0 bypass escaped"
        );
        for (label, mutated) in [
            (
                "teardown-failure-swallowed",
                source.replacen(
                    "$COMPOSE down -v >/dev/null 2>&1\n",
                    "$COMPOSE down -v >/dev/null 2>&1 || true\n",
                    1,
                ),
            ),
            (
                "receipt-before-teardown",
                source.replacen(
                    "teardown\ntrap - EXIT\nlog \"全部冒烟通过 ✅\"",
                    "trap - EXIT\nlog \"全部冒烟通过 ✅\"\nteardown",
                    1,
                ),
            ),
        ] {
            assert_ne!(mutated, source, "{label} mutation was vacuous");
            assert_eq!(
                validate_compose_smoke(&mutated),
                Err(ComposeSmokeRule::ReleaseTeardown),
                "{label}"
            );
        }
        for probe in ["keyprovider_ready", "s3_object_store_ready", "redis_ready"] {
            let unhealthy = format!("\"name\":\"{probe}\",\"status\":\"unhealthy\"");
            let mutated = source.replacen(&unhealthy, &format!("\"name\":\"{probe}\""), 1);
            assert_ne!(mutated, source, "{probe} outage mutation was vacuous");
            assert_eq!(
                validate_compose_smoke(&mutated),
                Err(ComposeSmokeRule::OutageClosure),
                "{probe} exact unhealthy mutation escaped"
            );
        }
        Ok(())
    }

    #[test]
    fn compose_runtime_delivery_rejects_each_synthetic_mutation() -> Result<()> {
        let workspace = crate::workspace_root()?;
        let compose = std::fs::read_to_string(workspace.join("deploy/docker-compose.yml"))?;
        let smoke = std::fs::read_to_string(workspace.join("deploy/smoke.sh"))?;
        assert_eq!(validate_compose_runtime_delivery(&compose, &smoke), Ok(()));

        let mutate_service = |service: &str, needle: &str, replacement: &str| -> Result<String> {
            let block = compose_service_block(&compose, service)
                .with_context(|| format!("canonical Compose service missing: {service}"))?;
            let mutated_block = block.replacen(needle, replacement, 1);
            Ok(compose.replacen(block, &mutated_block, 1))
        };
        for (label, service, needle, replacement, expected) in [
            (
                "jwks-operator-target",
                "rss-access-jwks-init",
                "      target: operator-runtime",
                "      target: runtime",
                ComposeSmokeRule::OperatorProjection,
            ),
            (
                "jwks-operator-image",
                "rss-access-jwks-init",
                "    image: rss-operator:dev",
                "    image: rss-runtime:dev",
                ComposeSmokeRule::OperatorProjection,
            ),
            (
                "migration-operator-target",
                "migration",
                "      target: operator-runtime",
                "      target: runtime",
                ComposeSmokeRule::OperatorProjection,
            ),
            (
                "migration-operator-image",
                "migration",
                "    image: rss-operator:dev",
                "    image: rss-runtime:dev",
                ComposeSmokeRule::OperatorProjection,
            ),
            (
                "server-target",
                "server",
                "      target: runtime",
                "      target: operator-runtime",
                ComposeSmokeRule::ServerProjection,
            ),
            (
                "server-image",
                "server",
                "    image: rss-runtime:dev",
                "    image: rss-operator:dev",
                ComposeSmokeRule::ServerProjection,
            ),
            (
                "server-grace",
                "server",
                "    stop_grace_period: 30s",
                "    stop_grace_period: 20s",
                ComposeSmokeRule::ServerProjection,
            ),
        ] {
            let mutated = mutate_service(service, needle, replacement)?;
            assert_ne!(mutated, compose, "{label} mutation was vacuous");
            assert_eq!(
                validate_compose_runtime_delivery(&mutated, &smoke),
                Err(expected),
                "{label}"
            );
        }

        for (label, needle, replacement) in [
            (
                "missing-sigterm",
                "docker kill --signal=TERM \"$cid\" >/dev/null",
                "docker stop \"$cid\" >/dev/null",
            ),
            (
                "missing-state-observation",
                "server_state=\"$(docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' \"$cid\")\"",
                "server_state=unknown",
            ),
            (
                "missing-exit-zero",
                "[[ \"$server_state\" = \"exited:0\" ]] || fail",
                "[[ \"$server_state\" = exited:* ]] || fail",
            ),
            (
                "missing-fail-branch",
                "[[ \"$server_state\" = \"exited:0\" ]] || fail",
                "[[ \"$server_state\" = \"exited:0\" ]] || log",
            ),
        ] {
            let mutated = smoke.replacen(needle, replacement, 1);
            assert_ne!(mutated, smoke, "{label} mutation was vacuous");
            assert_eq!(
                validate_compose_runtime_delivery(&compose, &mutated),
                Err(ComposeSmokeRule::DrainWitness),
                "{label}"
            );
        }
        for removed_log_witness in [
            "server_logs=\"$($COMPOSE logs --no-color server 2>&1)\"",
            "shutdown signal received",
            "all runtime resources drained; exiting",
        ] {
            assert!(
                !smoke.contains(removed_log_witness),
                "smoke must use the process exit receipt instead of log wording: {removed_log_witness}"
            );
        }
        let term = "docker kill --signal=TERM \"$cid\" >/dev/null";
        let exit_zero = "[[ \"$server_state\" = \"exited:0\" ]] || fail \"SIGTERM 后 server 未在 30 秒内正常退出（state=${server_state}）\"";
        let reordered_chain = smoke
            .replacen(term, "__TERM_WITNESS__", 1)
            .replacen(exit_zero, term, 1)
            .replacen("__TERM_WITNESS__", exit_zero, 1);
        assert_ne!(reordered_chain, smoke, "TERM/exit-zero reorder was vacuous");
        assert_eq!(
            validate_compose_runtime_delivery(&compose, &reordered_chain),
            Err(ComposeSmokeRule::DrainWitness)
        );
        Ok(())
    }

    #[test]
    fn compose_runtime_delivery_accepts_typed_yaml_equivalence() -> Result<()> {
        let compose = r#"
services:
  server:
    stop_grace_period: "30s"
    image: 'rss-runtime:dev'
    build: { target: "runtime", dockerfile: Dockerfile, context: .. }
  migration:
    image: "rss-operator:dev"
    build: { target: 'operator-runtime', context: .. }
  rss-access-jwks-init:
    build:
      target: "operator-runtime"
    image: 'rss-operator:dev'
"#;
        let smoke = std::fs::read_to_string(crate::workspace_root()?.join("deploy/smoke.sh"))?;

        assert_eq!(validate_compose_runtime_delivery(compose, &smoke), Ok(()));
        let reworded_diagnostic = smoke.replace(
            "SIGTERM 后 server 未在 30 秒内正常退出（state=${server_state}）",
            "server failed to stop cleanly (state=${server_state})",
        );
        assert_ne!(reworded_diagnostic, smoke, "diagnostic rewrite was vacuous");
        assert_eq!(
            validate_compose_runtime_delivery(compose, &reworded_diagnostic),
            Ok(()),
            "human-readable failure wording must not be part of the drain witness identity"
        );
        Ok(())
    }

    #[test]
    fn compose_runtime_delivery_rejects_non_executable_drain_witnesses() -> Result<()> {
        let compose =
            std::fs::read_to_string(crate::workspace_root()?.join("deploy/docker-compose.yml"))?;
        let witnesses = concat!(
            "docker kill --signal=TERM \"$cid\" >/dev/null\n",
            "[[ \"$server_state\" = \"exited:0\" ]] && break\n",
            "[[ \"$server_state\" = \"exited:0\" ]] || fail\n",
            "server_logs=\"$($COMPOSE logs --no-color server 2>&1)\"\n",
            "[[ \"$server_logs\" = *\"shutdown signal received\"* ]]\n",
            "[[ \"$server_logs\" = *\"all runtime resources drained; exiting\"* ]]\n",
        );
        let commented = witnesses
            .lines()
            .map(|line| format!("# {line}\n"))
            .collect::<String>();
        let heredoc = format!("cat <<'WITNESSES'\n{witnesses}WITNESSES\n");
        let uncalled_function = format!("unused_witnesses() {{\n{witnesses}}}\n");

        for (label, smoke) in [
            ("comment", commented),
            ("here-doc", heredoc),
            ("uncalled-function", uncalled_function),
        ] {
            assert_eq!(
                validate_compose_runtime_delivery(&compose, &smoke),
                Err(ComposeSmokeRule::DrainWitness),
                "non-executable {label} witness satisfied the delivery gate"
            );
        }
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
        assert!(validate_compose_smoke(uncalled_smoke).is_err());

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
                validate_compose_smoke(&scoped_smoke).is_err(),
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
            "cargo build --release --locked --package demo --bin demo-server --package rss --bin rss",
            "cargo build --release --locked --package demo --bin demo-server --package rss --bin rss --help",
            "cargo build --release --locked --package demo --bin demo-server --package rss --bin other",
            "cargo build --release --locked --package demo --bin demo-server --package rss --bin rss --package third --bin third",
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
        assert_eq!(verified.supported_count, 3);
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
