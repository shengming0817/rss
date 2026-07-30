//! Typed repository assembly source shared by xtask governance consumers.
//!
//! INVARIANT: ASSEMBLY-PRODUCTION-IDENTITY-RATCHET-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::production_profile_and_lifecycle_cannot_be_downgraded_together", anti_vacuity = "tests::real_workspace_core_is_closed" } -- the closed production identity set is exactly equal to manifests carrying the production profile.
//! INVARIANT: ASSEMBLY-GOVERNANCE-SOURCE-FUNNEL-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::source_funnel_rejects_parallel_manifest_readers", anti_vacuity = "tests::real_workspace_has_one_governance_source_owner" } -- non-test xtask code may only discover or parse assembly governance sources through this module.

use anyhow::{Context, Result, bail};
use assembly_schema::{AssemblyProfile, RepositoryAssemblyManifestV2};
use quote::ToTokens as _;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::visit::Visit;

pub(crate) const ARTIFACT_MATRIX_PATH: &str = "assemblies/artifacts.toml";
const MAX_ARTIFACT_MATRIX_BYTES: u64 = 4 * 1024 * 1024;

macro_rules! production_assembly_ids {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub(crate) enum ProductionAssemblyId {
            $($variant),+
        }

        impl ProductionAssemblyId {
            pub(crate) const VALUES: &'static [Self] = &[$(Self::$variant),+];

            fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub(crate) const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),+
                }
            }
        }
    };
}

production_assembly_ids! {
    IdentityAudit => "identityaudit",
    Runtime => "runtime",
    SettingsOnly => "settingsonly",
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AssemblyId(String);

impl AssemblyId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A normalized direct child of `assemblies/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssemblyTarget {
    id: AssemblyId,
    dir: PathBuf,
    lock_path: PathBuf,
    has_manifest: bool,
    has_cargo_manifest: bool,
}

impl AssemblyTarget {
    pub(crate) fn name(&self) -> &str {
        self.id.as_str()
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn cargo_path(&self) -> PathBuf {
        self.dir.join("Cargo.toml")
    }

    pub(crate) fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub(crate) const fn has_manifest(&self) -> bool {
        self.has_manifest
    }

    pub(crate) const fn has_cargo_manifest(&self) -> bool {
        self.has_cargo_manifest
    }
}

#[derive(Clone)]
pub(crate) struct GovernedAssembly {
    dir: PathBuf,
    cargo_path: PathBuf,
    manifest_label: String,
    cargo_label: String,
    manifest: RepositoryAssemblyManifestV2,
    cargo_toml: toml::Value,
}

#[derive(Clone, Copy)]
pub(crate) struct ProductionAssembly<'a>(&'a GovernedAssembly);

impl GovernedAssembly {
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn cargo_path(&self) -> &Path {
        &self.cargo_path
    }

    pub(crate) fn manifest_label(&self) -> &str {
        &self.manifest_label
    }

    pub(crate) fn cargo_label(&self) -> &str {
        &self.cargo_label
    }

    pub(crate) fn manifest(&self) -> &assembly_schema::CanonicalAssemblyManifestV2 {
        self.manifest.canonical()
    }

    pub(crate) fn source(&self) -> &RepositoryAssemblyManifestV2 {
        &self.manifest
    }

    pub(crate) fn source_label(&self) -> &str {
        self.manifest.source_label()
    }

    pub(crate) fn source_text(&self) -> &str {
        self.manifest.source_text()
    }

    pub(crate) fn cargo_toml(&self) -> &toml::Value {
        &self.cargo_toml
    }

    pub(crate) fn production(&self) -> Option<ProductionAssembly<'_>> {
        (self.manifest().profile() == AssemblyProfile::Production
            && ProductionAssemblyId::from_name(self.manifest().name()).is_some())
        .then_some(ProductionAssembly(self))
    }

    #[cfg(test)]
    pub(crate) fn fixture(root: &Path, dir: &Path) -> Result<Self> {
        let target = AssemblyTarget {
            id: AssemblyId(
                dir.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .context("fixture assembly name must be UTF-8")?
                    .to_owned(),
            ),
            dir: dir.to_path_buf(),
            lock_path: dir.join("assembly.lock.json"),
            has_manifest: true,
            has_cargo_manifest: true,
        };
        load_target_source(root, &target)
    }
}

impl std::ops::Deref for ProductionAssembly<'_> {
    type Target = GovernedAssembly;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

mod phase {
    pub(crate) trait Sealed {}
    pub(crate) struct Core;
    pub(crate) struct ArtifactsJoined {
        pub(crate) artifacts: Vec<super::GovernedArtifact>,
    }
    impl Sealed for Core {}
    impl Sealed for ArtifactsJoined {}
}

pub(crate) use phase::{ArtifactsJoined, Core};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactMatrixDeclaration {
    #[serde(rename = "schemaVersion")]
    pub(crate) schema_version: u32,
    pub(crate) assemblies: Vec<ArtifactDeclaration>,
}

pub(crate) fn load_artifact_declaration(root: &Path) -> Result<ArtifactMatrixDeclaration> {
    let path = root.join(ARTIFACT_MATRIX_PATH);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("检查 {} 失败", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("assembly artifact matrix 必须是无符号链接的普通文件")
    }
    if metadata.len() > MAX_ARTIFACT_MATRIX_BYTES {
        bail!("assembly artifact matrix 超过大小上限")
    }
    let bytes = std::fs::read(&path).with_context(|| format!("读取 {} 失败", path.display()))?;
    let source =
        std::str::from_utf8(&bytes).with_context(|| format!("{} 不是 UTF-8", path.display()))?;
    parse_artifact_declaration(source)
}

pub(crate) fn parse_artifact_declaration(source: &str) -> Result<ArtifactMatrixDeclaration> {
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactDeclaration {
    pub(crate) name: String,
    pub(crate) lifecycle: DeclaredLifecycle,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) binary: Option<ArtifactBinary>,
    #[serde(default)]
    pub(crate) image: Option<ArtifactImage>,
    #[serde(default, rename = "configSchema")]
    pub(crate) config_schema: Option<ArtifactConfigSchema>,
    #[serde(default, rename = "healthInventory")]
    pub(crate) health_inventory: Option<ArtifactHealthInventory>,
    #[serde(default)]
    pub(crate) journey: Option<JourneyCarrier>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeclaredLifecycle {
    Supported,
    CompileOnly,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactBinary {
    pub(crate) package: String,
    pub(crate) target: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactImage {
    pub(crate) dockerfile: String,
    pub(crate) target: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ArtifactConfigSchema {
    JsonSchema { path: String },
    TypedEnvCatalog { path: String },
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactHealthInventory {
    pub(crate) owner: HealthOwner,
    pub(crate) listener: HealthListener,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) enum HealthOwner {
    #[serde(rename = "runtimeexec")]
    Runtimeexec,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) enum HealthListener {
    #[serde(rename = "health")]
    Health,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum JourneyCarrier {
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
pub(crate) struct SupportedArtifacts {
    pub(crate) binary: ArtifactBinary,
    pub(crate) image: ArtifactImage,
    pub(crate) config_schema: ArtifactConfigSchema,
    pub(crate) health_inventory: ArtifactHealthInventory,
    pub(crate) journey: JourneyCarrier,
}

#[derive(Debug)]
pub(crate) struct CompileOnlyReason(String);

impl CompileOnlyReason {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub(crate) enum ArtifactLifecycle {
    Supported(SupportedArtifacts),
    CompileOnly(CompileOnlyReason),
}

#[derive(Debug)]
pub(crate) struct GovernedArtifact {
    pub(crate) id: AssemblyId,
    pub(crate) lifecycle: ArtifactLifecycle,
}

pub(crate) struct AssemblyGovernanceIr<Phase: phase::Sealed> {
    targets: Vec<AssemblyTarget>,
    assemblies: Vec<GovernedAssembly>,
    phase: Phase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GovernanceLoadStage {
    Discovery,
    EmptyUniverse,
    Manifest,
    ProductionRatchet,
}

#[derive(Debug)]
pub(crate) struct GovernanceLoadError {
    stage: GovernanceLoadStage,
    source: anyhow::Error,
}

impl GovernanceLoadError {
    fn new(stage: GovernanceLoadStage, source: impl Into<anyhow::Error>) -> Self {
        Self {
            stage,
            source: source.into(),
        }
    }

    pub(crate) const fn stage(&self) -> GovernanceLoadStage {
        self.stage
    }
}

impl std::fmt::Display for GovernanceLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "assembly governance {:?}: {}",
            self.stage, self.source
        )
    }
}

impl std::error::Error for GovernanceLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.root_cause())
    }
}

impl AssemblyGovernanceIr<Core> {
    pub(crate) fn load(root: &Path) -> Result<Self> {
        Self::load_inner(root, production_ratchet_applies(root))
    }

    pub(crate) fn load_staged(root: &Path) -> std::result::Result<Self, GovernanceLoadError> {
        Self::load_staged_inner(root, production_ratchet_applies(root))
    }

    fn load_staged_inner(
        root: &Path,
        enforce_production_ratchet: bool,
    ) -> std::result::Result<Self, GovernanceLoadError> {
        let targets = discover_targets(root)
            .map_err(|error| GovernanceLoadError::new(GovernanceLoadStage::Discovery, error))?;
        if !targets.iter().any(AssemblyTarget::has_manifest) {
            return Err(GovernanceLoadError::new(
                GovernanceLoadStage::EmptyUniverse,
                anyhow::anyhow!("assembly manifest universe is empty"),
            ));
        }
        let mut assemblies = Vec::new();
        for target in targets.iter().filter(|target| target.has_manifest()) {
            assemblies.push(
                load_target_source(root, target).map_err(|error| {
                    GovernanceLoadError::new(GovernanceLoadStage::Manifest, error)
                })?,
            );
        }
        if enforce_production_ratchet {
            validate_production_identities(&assemblies).map_err(|error| {
                GovernanceLoadError::new(GovernanceLoadStage::ProductionRatchet, error)
            })?;
        }
        Ok(Self {
            targets,
            assemblies,
            phase: Core,
        })
    }

    /// Load exactly one direct assembly target without evaluating repository-global ratchets.
    pub(crate) fn load_target(
        root: &Path,
        name: &str,
    ) -> std::result::Result<Option<Self>, GovernanceLoadError> {
        let target = discover_target(root, name)
            .map_err(|error| GovernanceLoadError::new(GovernanceLoadStage::Discovery, error))?;
        let Some(target) = target else {
            return Ok(None);
        };
        let assembly = target
            .has_manifest()
            .then(|| load_target_source(root, &target))
            .transpose()
            .map_err(|error| GovernanceLoadError::new(GovernanceLoadStage::Manifest, error))?;
        Ok(Some(Self {
            targets: vec![target],
            assemblies: assembly.into_iter().collect(),
            phase: Core,
        }))
    }

    fn load_inner(root: &Path, enforce_production_ratchet: bool) -> Result<Self> {
        let targets = discover_targets(root)?;
        let mut assemblies = Vec::new();
        for target in targets.iter().filter(|target| target.has_manifest()) {
            assemblies.push(load_target_source(root, target)?);
        }
        if enforce_production_ratchet {
            validate_production_identities(&assemblies)?;
        }
        Ok(Self {
            targets,
            assemblies,
            phase: Core,
        })
    }

    #[cfg(test)]
    fn load_with_ratchet(root: &Path) -> Result<Self> {
        Self::load_inner(root, true)
    }

    #[cfg(test)]
    fn load_staged_with_ratchet(root: &Path) -> std::result::Result<Self, GovernanceLoadError> {
        Self::load_staged_inner(root, true)
    }

    pub(crate) fn join_artifacts(
        self,
        declaration: ArtifactMatrixDeclaration,
    ) -> Result<AssemblyGovernanceIr<ArtifactsJoined>> {
        let mut diagnostics = Vec::new();
        if declaration.schema_version != 1 {
            diagnostics.push("artifact matrix schemaVersion 必须严格为 1".to_owned());
        }
        let universe = self
            .targets
            .iter()
            .map(|target| target.name().to_owned())
            .collect::<BTreeSet<_>>();
        let mut declared = BTreeSet::new();
        let mut declared_lifecycles = BTreeMap::new();
        let mut artifacts = Vec::with_capacity(declaration.assemblies.len());
        for row in declaration.assemblies {
            if !declared.insert(row.name.clone()) {
                diagnostics.push(format!("artifact matrix assembly `{}` 重复声明", row.name));
            }
            if !universe.contains(&row.name) {
                diagnostics.push(format!("artifact matrix 含幽灵 assembly `{}`", row.name));
            }
            declared_lifecycles
                .entry(row.name.clone())
                .or_insert(row.lifecycle);
            if let Some(artifact) = promote_artifact(row, &mut diagnostics) {
                artifacts.push(artifact);
            }
        }
        let missing = universe.difference(&declared).cloned().collect::<Vec<_>>();
        if !missing.is_empty() {
            diagnostics.push(format!(
                "artifact matrix 缺少 lifecycle/artifact 声明: {missing:?}"
            ));
        }
        for id in ProductionAssemblyId::VALUES {
            match declared_lifecycles.get(id.as_str()) {
                None => diagnostics.push(format!("production artifact `{}` 缺失", id.as_str())),
                Some(DeclaredLifecycle::CompileOnly) => diagnostics.push(format!(
                    "production assembly `{}` 禁止降级为 compile-only",
                    id.as_str()
                )),
                Some(DeclaredLifecycle::Supported) => {}
            }
        }
        if !diagnostics.is_empty() {
            bail!(
                "artifact matrix governance diagnostics:\n{}",
                diagnostics.join("\n")
            )
        }
        Ok(AssemblyGovernanceIr {
            targets: self.targets,
            assemblies: self.assemblies,
            phase: ArtifactsJoined { artifacts },
        })
    }
}

fn promote_artifact(
    row: ArtifactDeclaration,
    diagnostics: &mut Vec<String>,
) -> Option<GovernedArtifact> {
    let name = row.name;
    let lifecycle = match row.lifecycle {
        DeclaredLifecycle::Supported => {
            if row.reason.is_some() {
                diagnostics.push(format!("supported `{name}` 禁止 reason 字段"));
            }
            let binary = require_supported_field(&name, "binary", row.binary, diagnostics);
            let image = require_supported_field(&name, "image", row.image, diagnostics);
            let config_schema =
                require_supported_field(&name, "configSchema", row.config_schema, diagnostics);
            let health_inventory = require_supported_field(
                &name,
                "healthInventory",
                row.health_inventory,
                diagnostics,
            );
            let journey = require_supported_field(&name, "journey", row.journey, diagnostics)
                .and_then(|journey| match validate_journey_carrier(&journey) {
                    Ok(()) => Some(journey),
                    Err(error) => {
                        diagnostics.push(format!("supported `{name}` {error}"));
                        None
                    }
                });
            match (binary, image, config_schema, health_inventory, journey) {
                (
                    Some(binary),
                    Some(image),
                    Some(config_schema),
                    Some(health_inventory),
                    Some(journey),
                ) => Some(ArtifactLifecycle::Supported(SupportedArtifacts {
                    binary,
                    image,
                    config_schema,
                    health_inventory,
                    journey,
                })),
                _ => None,
            }
        }
        DeclaredLifecycle::CompileOnly => {
            if row.binary.is_some()
                || row.image.is_some()
                || row.config_schema.is_some()
                || row.health_inventory.is_some()
                || row.journey.is_some()
            {
                diagnostics.push(format!(
                    "compile-only `{name}` 禁止携带 deployable artifact 字段"
                ));
            }
            match row.reason {
                Some(reason) if !reason.trim().is_empty() => {
                    Some(ArtifactLifecycle::CompileOnly(CompileOnlyReason(reason)))
                }
                _ => {
                    diagnostics.push(format!("compile-only `{name}` reason 必须非空"));
                    None
                }
            }
        }
    }?;
    Some(GovernedArtifact {
        id: AssemblyId(name),
        lifecycle,
    })
}

fn require_supported_field<T>(
    name: &str,
    field: &str,
    value: Option<T>,
    diagnostics: &mut Vec<String>,
) -> Option<T> {
    if value.is_none() {
        diagnostics.push(format!("supported `{name}` 缺少 {field}"));
    }
    value
}

fn validate_journey_carrier(journey: &JourneyCarrier) -> Result<()> {
    let fields: &[(&str, &str)] = match journey {
        JourneyCarrier::CargoTest {
            package,
            target,
            test,
        } => &[("package", package), ("target", target), ("test", test)],
        JourneyCarrier::ComposeSmokeV1 { path } => &[("path", path)],
    };
    if let Some((field, _)) = fields.iter().find(|(_, value)| value.trim().is_empty()) {
        bail!("supported journey `{field}` 必须非空")
    }
    Ok(())
}

#[cfg(not(test))]
const fn production_ratchet_applies(_root: &Path) -> bool {
    true
}

#[cfg(test)]
fn production_ratchet_applies(root: &Path) -> bool {
    crate::workspace_root().is_ok_and(|workspace| workspace == root)
}

pub(crate) fn validate_source_funnel(root: &Path) -> Result<()> {
    let source_root = root.join("xtask/src");
    if !source_root.is_dir() {
        return Ok(());
    }
    let mut files = Vec::new();
    collect_rust_sources(&source_root, &mut files)?;
    files.sort();
    let owner = source_root.join("assembly_governance.rs");
    let mut violations = Vec::new();
    for path in files.into_iter().filter(|path| path != &owner) {
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("读取 governance source {} 失败", path.display()))?;
        violations.extend(
            forbidden_source_calls(&source)
                .with_context(|| format!("解析 governance source {} 失败", path.display()))?
                .into_iter()
                .map(|call| format!("{}: {call}", relative_label(root, &path))),
        );
    }
    if !violations.is_empty() {
        bail!(
            "assembly governance source funnel 存在旁路:\n{}",
            violations.join("\n")
        )
    }
    Ok(())
}

fn collect_rust_sources(directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("读取 {} 失败", directory.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!("xtask source tree 禁止符号链接: {}", entry.path().display())
        }
        if file_type.is_dir() {
            collect_rust_sources(&entry.path(), out)?;
        } else if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            out.push(entry.path());
        }
    }
    Ok(())
}

fn forbidden_source_calls(source: &str) -> Result<Vec<String>> {
    let syntax = syn::parse_file(source)?;
    let mut assembly_manifest_aliases = BTreeSet::from(["AssemblyManifest".to_owned()]);
    for item in &syntax.items {
        if let syn::Item::Use(item) = item {
            collect_manifest_aliases(&item.tree, &mut assembly_manifest_aliases);
        }
    }
    let mut function_collector = FunctionCollector::default();
    function_collector.visit_file(&syntax);
    let mut visitor = SourceFunnelVisitor {
        assembly_manifest_aliases,
        functions: function_collector.functions,
        ..SourceFunnelVisitor::default()
    };
    visitor.visit_file(&syntax);
    Ok(visitor.violations)
}

#[derive(Default)]
struct FunctionCollector {
    functions: BTreeMap<String, Vec<syn::ItemFn>>,
}

impl<'ast> Visit<'ast> for FunctionCollector {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if item_is_test_only(item) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.functions
            .entry(item.sig.ident.to_string())
            .or_default()
            .push(item.clone());
        syn::visit::visit_item_fn(self, item);
    }
}

fn collect_manifest_aliases(tree: &syn::UseTree, aliases: &mut BTreeSet<String>) {
    match tree {
        syn::UseTree::Path(path) => collect_manifest_aliases(&path.tree, aliases),
        syn::UseTree::Name(name) if name.ident == "AssemblyManifest" => {
            aliases.insert(name.ident.to_string());
        }
        syn::UseTree::Rename(rename) if rename.ident == "AssemblyManifest" => {
            aliases.insert(rename.rename.to_string());
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_manifest_aliases(item, aliases);
            }
        }
        _ => {}
    }
}

#[derive(Default)]
struct SourceFunnelVisitor {
    violations: Vec<String>,
    assembly_manifest_aliases: BTreeSet<String>,
    values: BTreeMap<String, SourceFlow>,
    functions: BTreeMap<String, Vec<syn::ItemFn>>,
    call_stack: Vec<String>,
    return_flows: Vec<SourceFlow>,
}

#[derive(Clone, Default)]
struct SourceFlow {
    text: Option<String>,
    under_assemblies: bool,
    assemblies_root: bool,
    governance_source: bool,
    source_data: bool,
}

impl SourceFlow {
    fn text(value: String) -> Self {
        let normalized = value.replace('\\', "/");
        let components = normalized.split('/').collect::<Vec<_>>();
        let under_assemblies = components.contains(&"assemblies");
        let assemblies_root = normalized.trim_end_matches('/').ends_with("assemblies")
            && components
                .last()
                .is_some_and(|component| *component == "assemblies");
        let governance_source = normalized == "assemblies/artifacts.toml"
            || (under_assemblies && normalized.ends_with("/assembly.toml"));
        Self {
            text: Some(value),
            under_assemblies,
            assemblies_root,
            governance_source,
            source_data: false,
        }
    }
}

impl SourceFunnelVisitor {
    fn record_path(&mut self, path: &syn::Path) {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let assembly_from_toml = segments
            .last()
            .is_some_and(|segment| segment == "from_toml_str")
            && segments
                .iter()
                .any(|segment| self.assembly_manifest_aliases.contains(segment));
        if assembly_from_toml
            || segments
                .last()
                .is_some_and(|segment| segment == "discover_v2")
            || (segments.last().is_some_and(|segment| segment == "from_str")
                && path
                    .to_token_stream()
                    .to_string()
                    .contains("AssemblyManifest"))
        {
            self.violations.push(segments.join("::"));
        }
    }

    fn flow(&mut self, expression: &syn::Expr) -> SourceFlow {
        match expression {
            syn::Expr::Lit(literal) => match &literal.lit {
                syn::Lit::Str(value) => SourceFlow::text(value.value()),
                _ => SourceFlow::default(),
            },
            syn::Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.values.get(&ident.to_string()))
                .cloned()
                .unwrap_or_default(),
            syn::Expr::Group(group) => self.flow(&group.expr),
            syn::Expr::Paren(paren) => self.flow(&paren.expr),
            syn::Expr::Reference(reference) => self.flow(&reference.expr),
            syn::Expr::MethodCall(call) if call.method == "concat" => self
                .array_text(&call.receiver, "")
                .map(SourceFlow::text)
                .unwrap_or_default(),
            syn::Expr::MethodCall(call) if call.method == "join" => {
                if let Some(separator) = call.args.first().and_then(|arg| self.flow(arg).text)
                    && let Some(text) = self.array_text(&call.receiver, &separator)
                {
                    return SourceFlow::text(text);
                }
                let receiver = self.flow(&call.receiver);
                let argument = call
                    .args
                    .first()
                    .map_or_else(SourceFlow::default, |arg| self.flow(arg));
                self.join_flow(receiver, argument)
            }
            syn::Expr::MethodCall(call) if call.method == "source_text" => SourceFlow {
                source_data: true,
                ..SourceFlow::default()
            },
            syn::Expr::MethodCall(call) => {
                let receiver = self.flow(&call.receiver);
                SourceFlow {
                    source_data: receiver.source_data,
                    ..SourceFlow::default()
                }
            }
            syn::Expr::Call(call) => {
                if let Some(flow) = self.helper_call_flow(call) {
                    return flow;
                }
                let operation = call.func.to_token_stream().to_string();
                let operation = operation.rsplit("::").next().unwrap_or(&operation).trim();
                let argument = call
                    .args
                    .first()
                    .map_or_else(SourceFlow::default, |arg| self.flow(arg));
                SourceFlow {
                    source_data: matches!(operation, "read" | "read_to_string" | "open")
                        && argument.governance_source,
                    ..SourceFlow::default()
                }
            }
            syn::Expr::Macro(expression) if expression.mac.path.is_ident("concat") => self
                .macro_text(&expression.mac, "")
                .map_or_else(SourceFlow::default, SourceFlow::text),
            syn::Expr::Macro(expression) if expression.mac.path.is_ident("include_str") => {
                SourceFlow {
                    source_data: self
                        .macro_text(&expression.mac, "")
                        .is_some_and(|path| SourceFlow::text(path).governance_source),
                    ..SourceFlow::default()
                }
            }
            _ => SourceFlow::default(),
        }
    }

    fn array_text(&mut self, expression: &syn::Expr, separator: &str) -> Option<String> {
        let syn::Expr::Array(array) = expression else {
            return None;
        };
        let mut parts = Vec::with_capacity(array.elems.len());
        for element in &array.elems {
            parts.push(self.flow(element).text?);
        }
        Some(parts.join(separator))
    }

    fn macro_text(&mut self, value: &syn::Macro, separator: &str) -> Option<String> {
        use syn::parse::Parser as _;
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        let expressions = parser.parse2(value.tokens.clone()).ok()?;
        let mut parts = Vec::with_capacity(expressions.len());
        for expression in &expressions {
            parts.push(self.flow(expression).text?);
        }
        Some(parts.join(separator))
    }

    fn join_flow(&self, receiver: SourceFlow, argument: SourceFlow) -> SourceFlow {
        let mut joined = SourceFlow {
            text: match (&receiver.text, &argument.text) {
                (Some(base), Some(component)) => {
                    Some(format!("{}/{}", base.trim_end_matches('/'), component))
                }
                _ => None,
            },
            under_assemblies: receiver.under_assemblies,
            assemblies_root: receiver.assemblies_root,
            governance_source: receiver.governance_source,
            source_data: receiver.source_data,
        };
        if let Some(component) = argument.text.as_deref() {
            let normalized = component.replace('\\', "/");
            joined.under_assemblies |= normalized == "assemblies"
                || normalized.starts_with("assemblies/")
                || argument.under_assemblies;
            joined.assemblies_root = normalized == "assemblies" && !receiver.under_assemblies;
            joined.governance_source |= normalized == "assemblies/artifacts.toml"
                || (receiver.under_assemblies && normalized == "assembly.toml")
                || argument.governance_source;
        } else {
            joined.under_assemblies |= argument.under_assemblies;
            joined.assemblies_root |= argument.assemblies_root;
            joined.governance_source |= argument.governance_source;
            joined.source_data |= argument.source_data;
        }
        joined
    }

    fn record_source_capability_call(&mut self, call: &syn::ExprCall) {
        let function = call.func.to_token_stream().to_string();
        let operation = function.rsplit("::").next().unwrap_or(&function).trim();
        let flow = call
            .args
            .first()
            .map_or_else(SourceFlow::default, |arg| self.flow(arg));
        if matches!(operation, "read" | "read_to_string" | "open") && flow.governance_source {
            self.violations
                .push(format!("direct governance source read via `{operation}`"));
        }
        if matches!(operation, "read_dir" | "member_dirs") && flow.assemblies_root {
            self.violations.push(format!(
                "direct assemblies directory discovery via `{function}` path={:?}",
                flow.text
            ));
        }
        if matches!(operation, "from_str" | "from_slice") && flow.source_data {
            self.violations.push(format!(
                "parallel governance source deserialize via `{operation}`"
            ));
        }
    }

    fn helper_call_flow(&mut self, call: &syn::ExprCall) -> Option<SourceFlow> {
        let syn::Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        let name = function.path.get_ident()?.to_string();
        let candidates = self.functions.get(&name)?.clone();
        if self.call_stack.contains(&name) {
            return Some(SourceFlow::default());
        }
        let mut arguments = Vec::with_capacity(call.args.len());
        for argument in &call.args {
            arguments.push(self.flow(argument));
        }

        let mut combined = SourceFlow::default();
        self.call_stack.push(name);
        for candidate in candidates {
            let outer_values = self.values.clone();
            let return_start = self.return_flows.len();
            for (input, argument) in candidate.sig.inputs.iter().zip(&arguments) {
                let syn::FnArg::Typed(input) = input else {
                    continue;
                };
                let syn::Pat::Ident(binding) = input.pat.as_ref() else {
                    continue;
                };
                self.values
                    .insert(binding.ident.to_string(), argument.clone());
            }
            self.visit_block(&candidate.block);
            let mut flows = self.return_flows.split_off(return_start);
            if let Some(syn::Stmt::Expr(tail, None)) = candidate.block.stmts.last() {
                flows.push(self.flow(tail));
            }
            for flow in flows {
                combined.merge(flow);
            }
            self.values = outer_values;
        }
        self.call_stack.pop();
        Some(combined)
    }
}

impl SourceFlow {
    fn merge(&mut self, other: Self) {
        self.under_assemblies |= other.under_assemblies;
        self.assemblies_root |= other.assemblies_root;
        self.governance_source |= other.governance_source;
        self.source_data |= other.source_data;
        self.text = match (&self.text, other.text) {
            (None, text) => text,
            (Some(current), Some(next)) if current == &next => Some(current.clone()),
            _ => None,
        };
    }
}

impl<'ast> Visit<'ast> for SourceFunnelVisitor {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_manifest_aliases(&item.tree, &mut self.assembly_manifest_aliases);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if item_is_test_only(item) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let outer_values = self.values.clone();
        syn::visit::visit_item_fn(self, item);
        self.values = outer_values;
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        let value = self.flow(&item.expr);
        if value.text.is_some()
            || value.under_assemblies
            || value.governance_source
            || value.source_data
        {
            self.values.insert(item.ident.to_string(), value);
        }
        syn::visit::visit_item_const(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = call.func.as_ref() {
            self.record_path(&function.path);
        }
        self.record_source_capability_call(call);
        let _ = self.helper_call_flow(call);
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        if let Some(value) = &expression.expr {
            let flow = self.flow(value);
            self.return_flows.push(flow);
        }
        syn::visit::visit_expr_return(self, expression);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        self.record_path(&expression.path);
        syn::visit::visit_expr_path(self, expression);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        let tokens = local.to_token_stream().to_string();
        if tokens.contains("AssemblyManifest") && tokens.contains("toml :: from_str") {
            self.violations
                .push("typed toml::from_str AssemblyManifest parse".to_owned());
        }
        if let (syn::Pat::Ident(binding), Some(initializer)) = (&local.pat, &local.init) {
            let value = self.flow(&initializer.expr);
            if value.text.is_some()
                || value.under_assemblies
                || value.governance_source
                || value.source_data
            {
                self.values.insert(binding.ident.to_string(), value);
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        if expression.mac.path.is_ident("include_str")
            && self
                .macro_text(&expression.mac, "")
                .is_some_and(|path| SourceFlow::text(path).governance_source)
        {
            self.violations
                .push("direct governance source read via `include_str`".to_owned());
        }
        syn::visit::visit_expr_macro(self, expression);
    }
}

fn item_is_test_only(item: &syn::Item) -> bool {
    let attrs: &[syn::Attribute] = match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        _ => &[],
    };
    attrs.iter().any(attribute_requires_test)
}

fn attribute_requires_test(attribute: &syn::Attribute) -> bool {
    if attribute.path().is_ident("test") {
        return true;
    }
    let syn::Meta::List(cfg) = &attribute.meta else {
        return false;
    };
    if !cfg.path.is_ident("cfg") {
        return false;
    }
    syn::parse2::<syn::Meta>(cfg.tokens.clone())
        .is_ok_and(|predicate| meta_requires_test(&predicate))
}

fn meta_requires_test(meta: &syn::Meta) -> bool {
    use syn::parse::Parser as _;
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
            let Ok(nested) = parser.parse2(list.tokens.clone()) else {
                return false;
            };
            if list.path.is_ident("all") {
                nested.iter().any(meta_requires_test)
            } else {
                !nested.is_empty() && nested.iter().all(meta_requires_test)
            }
        }
        _ => false,
    }
}

impl<Phase: phase::Sealed> AssemblyGovernanceIr<Phase> {
    pub(crate) fn targets(&self) -> &[AssemblyTarget] {
        &self.targets
    }

    pub(crate) fn assemblies(&self) -> &[GovernedAssembly] {
        &self.assemblies
    }

    pub(crate) fn assembly(&self, name: &str) -> Option<&GovernedAssembly> {
        self.assemblies
            .iter()
            .find(|assembly| assembly.manifest().name() == name)
    }
}

impl AssemblyGovernanceIr<ArtifactsJoined> {
    pub(crate) fn artifacts(&self) -> &[GovernedArtifact] {
        &self.phase.artifacts
    }
}

pub(crate) fn discover_targets(root: &Path) -> Result<Vec<AssemblyTarget>> {
    let assemblies_root = root.join("assemblies");
    let metadata = match std::fs::symlink_metadata(&assemblies_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("检查 {} 失败", assemblies_root.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("assemblies 根必须是真实目录")
    }

    let mut entries = std::fs::read_dir(&assemblies_root)
        .with_context(|| format!("读 assembly 目录 {} 失败", assemblies_root.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .context("遍历 assembly 目录失败")?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut targets = Vec::new();
    for entry in entries {
        let file_type = entry
            .file_type()
            .context("检查 assembly direct child 类型失败")?;
        if file_type.is_symlink() {
            bail!("assemblies direct child 禁止符号链接")
        }
        if !file_type.is_dir() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("assembly 目录名必须是 UTF-8"))?;
        let dir = entry.path();
        if dir != root.join("assemblies").join(&name) {
            bail!("assembly 目录必须是规范 direct child")
        }
        let has_manifest = regular_file_or_missing(&dir.join("assembly.toml"))?;
        let has_cargo_manifest = regular_file_or_missing(&dir.join("Cargo.toml"))?;
        targets.push(AssemblyTarget {
            id: AssemblyId(name),
            lock_path: dir.join("assembly.lock.json"),
            dir,
            has_manifest,
            has_cargo_manifest,
        });
    }
    Ok(targets)
}

fn discover_target(root: &Path, name: &str) -> Result<Option<AssemblyTarget>> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
        || name.is_empty()
    {
        bail!("assembly target name must be one normal path component")
    }
    let dir = root.join("assemblies").join(name);
    let metadata = match std::fs::symlink_metadata(&dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("检查 assembly target 失败"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("assembly target 必须是真实 direct child 目录")
    }
    Ok(Some(AssemblyTarget {
        id: AssemblyId(name.to_owned()),
        lock_path: dir.join("assembly.lock.json"),
        has_manifest: regular_file_or_missing(&dir.join("assembly.toml"))?,
        has_cargo_manifest: regular_file_or_missing(&dir.join("Cargo.toml"))?,
        dir,
    }))
}

fn load_target_source(root: &Path, target: &AssemblyTarget) -> Result<GovernedAssembly> {
    let cargo_path = target.cargo_path();
    let cargo_src = std::fs::read_to_string(&cargo_path)
        .with_context(|| format!("读 {} 失败", cargo_path.display()))?;
    let manifest = RepositoryAssemblyManifestV2::discover_v2(root, target.dir())
        .with_context(|| format!("编译 {}/assembly.toml 失败", target.name()))?;
    Ok(GovernedAssembly {
        dir: target.dir().to_path_buf(),
        cargo_path: cargo_path.clone(),
        manifest_label: manifest.source_label().to_owned(),
        cargo_label: relative_label(root, &cargo_path),
        manifest,
        cargo_toml: toml::from_str(&cargo_src)
            .with_context(|| format!("解析 {} 失败", cargo_path.display()))?,
    })
}

fn validate_production_identities(assemblies: &[GovernedAssembly]) -> Result<()> {
    let declared = assemblies
        .iter()
        .filter(|assembly| assembly.manifest().profile() == AssemblyProfile::Production)
        .map(|assembly| assembly.manifest().name())
        .collect::<BTreeSet<_>>();
    validate_production_names(&declared)
}

fn validate_production_names(declared: &BTreeSet<&str>) -> Result<()> {
    let required = ProductionAssemblyId::VALUES
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    if *declared != required {
        let missing = required.difference(declared).copied().collect::<Vec<_>>();
        let extra = declared.difference(&required).copied().collect::<Vec<_>>();
        bail!("production assembly identity ratchet mismatch: missing={missing:?} extra={extra:?}")
    }
    Ok(())
}

fn regular_file_or_missing(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => bail!("assembly input 禁止符号链接"),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => bail!("assembly input 必须是普通文件"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("检查 assembly input 失败"),
    }
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEMP_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct FixtureRepository(PathBuf);

    impl FixtureRepository {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for FixtureRepository {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn real_matrix() -> Result<ArtifactMatrixDeclaration> {
        let root = crate::workspace_root()?;
        Ok(toml::from_str(&std::fs::read_to_string(
            root.join("assemblies/artifacts.toml"),
        )?)?)
    }

    fn ratchet_fixture() -> Result<(FixtureRepository, ArtifactMatrixDeclaration)> {
        use std::sync::atomic::Ordering;

        let workspace = crate::workspace_root()?;
        let created_root = std::env::temp_dir().join(format!(
            "rss-assembly-governance-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&created_root)?;
        let repository = FixtureRepository(std::fs::canonicalize(created_root)?);
        std::fs::create_dir(repository.path().join("assemblies"))?;

        for name in ["identityaudit", "runtime", "settingsonly"] {
            let source = workspace.join("assemblies").join(name);
            let target = repository.path().join("assemblies").join(name);
            std::fs::create_dir(&target)?;
            std::fs::copy(source.join("assembly.toml"), target.join("assembly.toml"))?;
            std::fs::copy(source.join("Cargo.toml"), target.join("Cargo.toml"))?;
        }

        let source = workspace.join("assemblies/settingsonly");
        let target = repository.path().join("assemblies/sourcecheck");
        std::fs::create_dir(&target)?;
        let compile_only_manifest = std::fs::read_to_string(source.join("assembly.toml"))?
            .replace("settingsonly", "sourcecheck")
            .replace("profile = \"production\"", "profile = \"demo\"");
        std::fs::write(target.join("assembly.toml"), compile_only_manifest)?;
        std::fs::write(
            target.join("Cargo.toml"),
            std::fs::read_to_string(source.join("Cargo.toml"))?
                .replace("settingsonly", "sourcecheck"),
        )?;

        let mut matrix = real_matrix()?;
        matrix
            .assemblies
            .retain(|row| ProductionAssemblyId::from_name(&row.name).is_some());
        matrix.assemblies.push(ArtifactDeclaration {
            name: "sourcecheck".to_owned(),
            lifecycle: DeclaredLifecycle::CompileOnly,
            reason: Some("compile-time governance utility".to_owned()),
            binary: None,
            image: None,
            config_schema: None,
            health_inventory: None,
            journey: None,
        });
        Ok((repository, matrix))
    }

    #[test]
    fn real_workspace_core_is_closed() -> Result<()> {
        let root = crate::workspace_root()?;
        let ir = AssemblyGovernanceIr::<Core>::load(&root)?;
        assert_eq!(
            ir.assemblies()
                .iter()
                .filter(|assembly| assembly.manifest().profile() == AssemblyProfile::Production)
                .map(|assembly| assembly.manifest().name())
                .collect::<BTreeSet<_>>(),
            ProductionAssemblyId::VALUES
                .iter()
                .map(|id| id.as_str())
                .collect()
        );
        Ok(())
    }

    #[test]
    fn source_funnel_rejects_parallel_manifest_readers() -> Result<()> {
        let violations = forbidden_source_calls(
            r#"
                #[cfg(not(test))]
                fn bypass(root: &std::path::Path, raw: &str) {
                    use assembly_schema::AssemblyManifest as M;
                    let path = root.join("assembly.toml");
                    let parse = M::from_toml_str;
                    let _: AssemblyManifest = toml::from_str(raw).unwrap();
                    let _ = RepositoryAssemblyManifestV2::discover_v2(root, &path);
                    let _ = crate::src_scan::member_dirs(&root.join("assemblies"));
                }

                #[cfg(test)]
                fn test_fixture() {
                    let _ = AssemblyManifest::from_toml_str("name = 'allowed-test-only'");
                }
            "#,
        )?;
        assert!(violations.len() >= 5, "synthetic red: {violations:?}");
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("directory discovery"))
        );
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.contains("allowed-test-only"))
                .count(),
            0
        );
        Ok(())
    }

    #[test]
    fn source_funnel_rejects_split_path_and_deserialize_reader() -> Result<()> {
        let violations = forbidden_source_calls(
            r#"
                #[derive(serde::Deserialize)]
                struct ShadowManifest {
                    name: String,
                }

                fn bypass(root: &std::path::Path, governed: &GovernedAssembly) {
                    let directory = ["assem", "blies"].concat();
                    let leaf = ["assembly", "toml"].join(".");
                    let path = root.join(directory).join("runtime").join(leaf);
                    let source = std::fs::read_to_string(path).unwrap();
                    let _: ShadowManifest = toml::from_str(&source).unwrap();
                    let _: ShadowManifest = toml::from_str(governed.source_text()).unwrap();
                }
            "#,
        )?;
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("governance source read")),
            "split source path plus local Deserialize mirror escaped: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("source deserialize")),
            "local Deserialize mirror escaped the typed source capability: {violations:?}"
        );
        Ok(())
    }

    #[test]
    fn source_funnel_rejects_helper_boundary_source_flow() -> Result<()> {
        let violations = forbidden_source_calls(
            r#"
                #[derive(serde::Deserialize)]
                struct ShadowManifest {
                    name: String,
                }

                fn load(path: &std::path::Path) -> String {
                    std::fs::read_to_string(path).unwrap()
                }

                fn parse(source: &str) -> ShadowManifest {
                    toml::from_str(source).unwrap()
                }

                fn bypass(root: &std::path::Path) {
                    let directory = ["assem", "blies"].concat();
                    let leaf = ["assembly", "toml"].join(".");
                    let path = root.join(directory).join("runtime").join(leaf);
                    let source = load(&path);
                    let _ = parse(&source);
                }
            "#,
        )?;
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("governance source read")),
            "path capability was lost at load helper boundary: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("source deserialize")),
            "source text capability was lost at parse helper boundary: {violations:?}"
        );
        Ok(())
    }

    #[test]
    fn source_funnel_allows_harmless_help_text() -> Result<()> {
        assert!(
            forbidden_source_calls(
                r#"
                    fn render_help(text: &str) -> String {
                        text.to_owned()
                    }

                    fn help() {
                        eprintln!("{}", render_help("assembly.toml"));
                    }
                "#,
            )?
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn cfg_predicates_skip_only_test_required_items() -> Result<()> {
        for (source, expected) in [
            ("#[cfg(test)] fn f() {}", true),
            ("#[cfg(all(test, unix))] fn f() {}", true),
            ("#[cfg(not(test))] fn f() {}", false),
            ("#[cfg(any(test, unix))] fn f() {}", false),
        ] {
            let file = syn::parse_file(source)?;
            assert_eq!(item_is_test_only(&file.items[0]), expected, "{source}");
        }
        Ok(())
    }

    #[test]
    fn real_workspace_has_one_governance_source_owner() -> Result<()> {
        validate_source_funnel(&crate::workspace_root()?)
    }

    #[test]
    fn artifact_join_rejects_missing_ghost_duplicate_and_production_downgrade() -> Result<()> {
        let root = crate::workspace_root()?;
        let mut missing = real_matrix()?;
        missing.assemblies.pop();
        assert!(
            AssemblyGovernanceIr::<Core>::load(&root)?
                .join_artifacts(missing)
                .err()
                .context("missing row was accepted")?
                .to_string()
                .contains("缺少")
        );

        let mut ghost = real_matrix()?;
        ghost.assemblies[0].name = "ghost".to_owned();
        assert!(
            AssemblyGovernanceIr::<Core>::load(&root)?
                .join_artifacts(ghost)
                .err()
                .context("ghost row was accepted")?
                .to_string()
                .contains("幽灵")
        );

        let mut duplicate = real_matrix()?;
        duplicate.assemblies.push(duplicate.assemblies[0].clone());
        assert!(
            AssemblyGovernanceIr::<Core>::load(&root)?
                .join_artifacts(duplicate)
                .err()
                .context("duplicate row was accepted")?
                .to_string()
                .contains("重复")
        );

        let mut downgraded = real_matrix()?;
        let row = downgraded
            .assemblies
            .iter_mut()
            .find(|row| row.name == "settingsonly")
            .context("settingsonly artifact row")?;
        row.lifecycle = DeclaredLifecycle::CompileOnly;
        row.reason = Some("synthetic downgrade".to_owned());
        row.binary = None;
        row.image = None;
        row.config_schema = None;
        row.health_inventory = None;
        row.journey = None;
        assert!(
            AssemblyGovernanceIr::<Core>::load(&root)?
                .join_artifacts(downgraded)
                .err()
                .context("production downgrade was accepted")?
                .to_string()
                .contains("禁止降级")
        );

        for blank in ["", "  "] {
            let mut matrix = real_matrix()?;
            let journey = matrix
                .assemblies
                .iter_mut()
                .find(|row| row.name == "settingsonly")
                .and_then(|row| row.journey.as_mut())
                .context("settingsonly journey")?;
            let JourneyCarrier::CargoTest { test, .. } = journey else {
                bail!("settingsonly journey fixture must be cargo-test")
            };
            *test = blank.to_owned();
            assert!(
                AssemblyGovernanceIr::<Core>::load(&root)?
                    .join_artifacts(matrix)
                    .err()
                    .context("blank journey was accepted")?
                    .to_string()
                    .contains("必须非空")
            );
        }
        Ok(())
    }

    #[test]
    fn artifact_join_reports_schema_bijection_and_lifecycle_diagnostics_together() -> Result<()> {
        let root = crate::workspace_root()?;
        let mut matrix = real_matrix()?;
        matrix.schema_version = 2;
        matrix.assemblies.pop();
        matrix.assemblies.push(matrix.assemblies[0].clone());
        matrix.assemblies.push(ArtifactDeclaration {
            name: "ghost".to_owned(),
            lifecycle: DeclaredLifecycle::CompileOnly,
            reason: Some(" ".to_owned()),
            binary: Some(ArtifactBinary {
                package: "ghost".to_owned(),
                target: "ghost".to_owned(),
            }),
            image: None,
            config_schema: None,
            health_inventory: None,
            journey: None,
        });

        let diagnostic = AssemblyGovernanceIr::<Core>::load(&root)?
            .join_artifacts(matrix)
            .err()
            .context("invalid matrix was promoted")?
            .to_string();
        for expected in [
            "schemaVersion",
            "重复声明",
            "幽灵",
            "缺少 lifecycle/artifact 声明",
            "禁止携带 deployable",
            "reason 必须非空",
        ] {
            assert!(
                diagnostic.contains(expected),
                "missing `{expected}` from aggregate diagnostic: {diagnostic}"
            );
        }
        Ok(())
    }

    #[test]
    fn production_profile_and_lifecycle_cannot_be_downgraded_together() -> Result<()> {
        let (repository, mut matrix) = ratchet_fixture()?;
        let manifest_path = repository
            .path()
            .join("assemblies/settingsonly/assembly.toml");
        let downgraded = std::fs::read_to_string(&manifest_path)?
            .replace("profile = \"production\"", "profile = \"demo\"");
        std::fs::write(&manifest_path, downgraded)?;
        let row = matrix
            .assemblies
            .iter_mut()
            .find(|row| row.name == "settingsonly")
            .context("settingsonly artifact row")?;
        row.lifecycle = DeclaredLifecycle::CompileOnly;
        row.reason = Some("paired downgrade".to_owned());
        row.binary = None;
        row.image = None;
        row.config_schema = None;
        row.health_inventory = None;
        row.journey = None;
        assert!(
            AssemblyGovernanceIr::<Core>::load_with_ratchet(repository.path())
                .and_then(|core| core.join_artifacts(matrix))
                .err()
                .context("paired profile/lifecycle downgrade was accepted")?
                .to_string()
                .contains("settingsonly")
        );
        Ok(())
    }

    #[test]
    fn newly_discovered_compile_only_assembly_joins_without_a_second_registry() -> Result<()> {
        let (repository, matrix) = ratchet_fixture()?;
        let joined = AssemblyGovernanceIr::<Core>::load_with_ratchet(repository.path())?
            .join_artifacts(matrix)?;
        assert!(joined.artifacts().iter().any(|artifact| {
            artifact.id.as_str() == "sourcecheck"
                && matches!(artifact.lifecycle, ArtifactLifecycle::CompileOnly(_))
        }));
        Ok(())
    }

    #[test]
    fn scoped_target_load_skips_global_ratchet_but_staged_load_classifies_it() -> Result<()> {
        let (repository, _) = ratchet_fixture()?;
        std::fs::remove_dir_all(repository.path().join("assemblies/identityaudit"))?;

        let scoped = AssemblyGovernanceIr::<Core>::load_target(repository.path(), "sourcecheck")?
            .context("sourcecheck target")?;
        assert_eq!(scoped.targets().len(), 1);
        assert_eq!(
            scoped
                .assembly("sourcecheck")
                .context("sourcecheck manifest")?
                .manifest()
                .name(),
            "sourcecheck"
        );
        assert_eq!(
            AssemblyGovernanceIr::<Core>::load_staged_with_ratchet(repository.path())
                .err()
                .context("global ratchet unexpectedly passed")?
                .stage(),
            GovernanceLoadStage::ProductionRatchet
        );
        Ok(())
    }
}
