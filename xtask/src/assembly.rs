//! `assembly validate` —— assembly-level DI provider 声明治理。
//!
//! DI-infra port（如 `diport::RevocationStore` / `diport::LockStore` / `diport::CasStore`）不是跨域 wire
//! contract，不放进 `contracts/**/contract.toml`。
//! 但 provider 选择属于组合根部署事实：哪个 assembly 注入哪个 provider、是否持久、是否已 active，必须有机器可读
//! 声明和 verify 门，避免生产在 dev/demo provider 上静默运行。

use anyhow::{Context, Result, bail};
use assembly_schema::{
    AssemblyDomain, AssemblyManifest, AssemblyProfile, AssemblyTopology, DiportPort,
    DiportProvider, ManifestValidationError, ProviderConstructor, ProviderDurability,
    ProviderLifecycle,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// `assemblies/*/Cargo.toml` 必须有同目录 `assembly.toml`。
    MissingManifest,
    /// manifest `name` 必须非空且匹配 assembly 目录名。
    ManifestNameMismatch,
    /// assembly manifest 必须声明至少一个 domain。
    EmptyDomains,
    /// assembly manifest 中 `domains` 不得重复。
    DuplicateDomain,
    /// manifest 声明的 active domain 必须是 assembly crate 的直接 normal dependency。
    ActiveDomainDependency,
    /// 未声明 domain 不得进入 assembly normal dependency closure。
    InactiveDomainDependencyClosure,
    /// identityaudit 必须保持 lib-only，且 normal closure 不得引入 runtime/settings/transport。
    IdentityAuditBoundary,
    /// assembly manifest 必须声明至少一个 listener。
    EmptyListeners,
    /// assembly manifest 中 `listeners` 不得重复。
    DuplicateListener,
    /// Framework contract declarations must exactly cover active framework-owned contracts.
    FrameworkContractServing,
    /// assembly manifest 不能空转：至少声明一个 DI provider。
    EmptyDiportProviders,
    /// assembly manifest 中 `diportProviders` 不得重复。
    DuplicateDiportProvider,
    /// assembly manifest 中 provider 字段不得为空。
    InvalidDiportProvider,
    /// production `diport::RevocationStore` provider 必须持久。
    RevocationDurability,
    /// active provider 必须由 assembly Cargo.toml `[dependencies]` 声明。
    ActiveProviderDependency,
    /// active provider 必须是 xtask 认识的 provider→port 映射。
    ActiveProviderPort,
    /// 声明的 durability 必须与已知 provider 真身一致。
    ProviderDurabilityMismatch,
    /// active provider 必须启用 provider symbol 所需 feature。
    ActiveProviderFeature,
    /// manifest 声明的 providerCrate 与 xtask provider matrix 锁定的实现 crate 不符。
    ///
    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 { level = "Medium", exec = "verify", source = "code" }— provider↔providerCrate 绑定由 xtask provider
    /// matrix 单源锁定；manifest 声明错误 crate 名须被机器拒（Medium，red test 反恒真）。
    ProviderCrateMismatch,
    /// active distributed provider 必须有组合根 consumer 接线证据。
    ActiveDistributedProviderConsumer,
    /// production security closeout 必须声明 active critical provider。
    ProductionSecurityCriticalProvider,
    /// production security closeout 必须有本地 JWKS 文件源与 readiness 证据。
    ProductionSecurityJwksCloseout,
    /// production security closeout 必须有 SPIFFE/mTLS 证据且不得保留 service-token 迁移口。
    ProductionSecuritySpiffeCloseout,
    /// production token profiles must each be built and wired on the `run()`-reachable path.
    ///
    /// INVARIANT: TOKEN-PROFILE-ASSEMBLY-01 { level = "Medium", exec = "verify", source = "code" } —
    /// RSS/Federated/Service providers, closed listener bindings, and profile-specific JWKS
    /// resources/probes are structural assembly facts. AST reachability plus mutation fixtures
    /// reject missing and bait-only evidence.
    TokenProfileTrustChain,
    /// Generic/legacy token configuration and the old shared JWKS probe are forbidden.
    TokenProfileLegacySurface,
    /// Access and service key sources must not be assembled by one mixed provider.
    TokenProfileKeyIsolation,
    /// Scheme and provider must not be independently supplied to the verification bridge.
    TokenProfileBinding,
    /// runtime 的 active PDP 必须绑定 exact active persistent replay-store provider。
    PdpReplayStoreCapability,
    /// domain/topology required capability 必须有 active persistent provider 或 exact Cargo dependency 事实。
    ///
    /// INVARIANT: ASSEMBLY-REQUIRED-CAPABILITY-01 { level = "Medium", exec = "verify", source = "code" } —
    /// domain→capability 静态表由 xtask 单源锁定；assembly 声明 domain/topology 后，缺失能力、draft
    /// provider、ephemeral critical provider 必须被机器拒。anti-vacuity red/green tests 以
    /// `assembly_capabilities_*` 前缀覆盖。
    RequiredCapability,
}

pub(crate) struct AssemblyValidate;

impl GovernanceCheck for AssemblyValidate {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "assembly validate"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let (count, findings) = validate_root(&root)?;
        Ok((format!("{count} assembly 声明全部通过"), findings))
    }
}

struct DiscoveredAssembly {
    dir: PathBuf,
    cargo_path: PathBuf,
    manifest_label: String,
    cargo_label: String,
    manifest_src: String,
    manifest: AssemblyManifest,
    cargo_toml: toml::Value,
}

/// A normalized direct child of `assemblies/`; fields stay private so callers cannot pair an
/// assembly name with a different repository path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssemblyTarget {
    name: String,
    dir: PathBuf,
    lock_path: PathBuf,
    has_manifest: bool,
    has_cargo_manifest: bool,
}

impl AssemblyTarget {
    pub(crate) fn name(&self) -> &str {
        &self.name
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

    const fn has_cargo_manifest(&self) -> bool {
        self.has_cargo_manifest
    }
}

/// Discover the shared assembly target universe without following repository-controlled links.
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
        .collect::<Result<Vec<_>, _>>()
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
        let name = assembly_name(entry.file_name())?;
        let dir = entry.path();
        let expected = root.join("assemblies").join(&name);
        if dir != expected {
            bail!("assembly 目录必须是规范 direct child")
        }
        let lock_path = dir.join("assembly.lock.json");
        let has_manifest = regular_file_or_missing(&dir.join("assembly.toml"))?;
        let has_cargo_manifest = regular_file_or_missing(&dir.join("Cargo.toml"))?;
        targets.push(AssemblyTarget {
            name,
            dir,
            lock_path,
            has_manifest,
            has_cargo_manifest,
        });
    }
    Ok(targets)
}

fn assembly_name(file_name: std::ffi::OsString) -> Result<String> {
    file_name
        .into_string()
        .map_err(|_| anyhow::anyhow!("assembly 目录名必须是 UTF-8"))
}

fn regular_file_or_missing(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("assembly input 禁止符号链接")
        }
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => bail!("assembly input 必须是普通文件"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| "检查 assembly input 失败"),
    }
}

pub(crate) fn validate_root(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let (assemblies, mut findings) = discover(root)?;
    findings.extend(validate_framework_contracts(root, &assemblies)?);
    let metadata = load_workspace_metadata(root)?;
    for assembly in &assemblies {
        findings.extend(validate_assembly(assembly));
        if let Some(metadata) = &metadata {
            findings.extend(validate_target_domain_closure(root, assembly, metadata)?);
        }
    }
    Ok((assemblies.len(), findings))
}

fn validate_framework_contracts(
    root: &Path,
    assemblies: &[DiscoveredAssembly],
) -> Result<Vec<Finding>> {
    use crate::contract::manifest::{ContractOwner, Lifecycle};

    let contracts = crate::contract::discover(&root.join("contracts"))?;
    let by_id = contracts
        .iter()
        .map(|contract| (contract.manifest.id.as_str(), contract))
        .collect::<BTreeMap<_, _>>();
    let mut declarations: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut findings = Vec::new();
    for assembly in assemblies {
        for contract_id in &assembly.manifest.framework_contracts {
            declarations
                .entry(contract_id)
                .or_default()
                .push(&assembly.manifest_label);
            match by_id.get(contract_id.as_str()) {
                Some(contract)
                    if contract.manifest.lifecycle == Lifecycle::Active
                        && contract.manifest.owner == ContractOwner::Framework => {}
                Some(_) => findings.push(finding(
                    Rule::FrameworkContractServing,
                    &assembly.manifest_label,
                    format!(
                        "frameworkContracts entry `{contract_id}` must reference an active framework-owned contract"
                    ),
                )),
                None => findings.push(finding(
                    Rule::FrameworkContractServing,
                    &assembly.manifest_label,
                    format!("frameworkContracts entry `{contract_id}` is unknown"),
                )),
            }
        }
    }
    for contract in contracts.iter().filter(|contract| {
        contract.manifest.lifecycle == Lifecycle::Active
            && contract.manifest.owner == ContractOwner::Framework
    }) {
        match declarations.get(contract.manifest.id.as_str()).map(Vec::as_slice) {
            None | Some([]) => findings.push(finding(
                Rule::FrameworkContractServing,
                rel_label(root, &contract.dir.join("contract.toml")),
                format!(
                    "active framework contract `{}` must be declared by exactly one assembly",
                    contract.manifest.id
                ),
            )),
            Some([_]) => {}
            Some(many) => findings.push(finding(
                Rule::FrameworkContractServing,
                many.join(", "),
                format!(
                    "active framework contract `{}` is declared by {} assemblies; expected exactly one",
                    contract.manifest.id,
                    many.len()
                ),
            )),
        }
    }
    Ok(findings)
}

/// 对单个目标执行与 aggregate gate 相同的完整验证，不读取其它 assembly。
pub(crate) fn validate_target(root: &Path, name: &str) -> Result<Vec<Finding>> {
    let assembly = load_target(root, &root.join("assemblies").join(name))?;
    let mut findings = validate_assembly(&assembly);
    if let Some(metadata) = load_workspace_metadata(root)? {
        findings.extend(validate_target_domain_closure(root, &assembly, &metadata)?);
    }
    Ok(findings)
}

fn load_target(root: &Path, dir: &Path) -> Result<DiscoveredAssembly> {
    let manifest_path = dir.join("assembly.toml");
    let cargo_path = dir.join("Cargo.toml");
    let manifest_src = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读 {} 失败", manifest_path.display()))?;
    let cargo_src = std::fs::read_to_string(&cargo_path)
        .with_context(|| format!("读 {} 失败", cargo_path.display()))?;
    Ok(DiscoveredAssembly {
        dir: dir.to_path_buf(),
        cargo_path: cargo_path.clone(),
        manifest_label: rel_label(root, &manifest_path),
        cargo_label: rel_label(root, &cargo_path),
        manifest: AssemblyManifest::from_toml_str(&manifest_src)
            .with_context(|| format!("解析 {} 失败", manifest_path.display()))?,
        cargo_toml: toml::from_str(&cargo_src)
            .with_context(|| format!("解析 {} 失败", cargo_path.display()))?,
        manifest_src,
    })
}

fn validate_target_domain_closure(
    root: &Path,
    assembly: &DiscoveredAssembly,
    metadata: &CargoMetadata,
) -> Result<Vec<Finding>> {
    // INVARIANT: ASSEMBLY-DOMAIN-CLOSURE-01 { level = "Medium", exec = "verify", source = "code" } —
    // 每个 assembly.toml 的 active domain 必须是目标 assembly package 当前 target 图中同名、未 rename、
    // 指向同名 workspace domain crate 的直接 normal dependency；inactive domain 不得进入该目标 package 的
    // normal dependency closure。真实 Cargo fixture 覆盖 alias、target cfg、dev/build、optional、
    // direct/transitive red case。
    let package = package_by_manifest(metadata, &assembly.cargo_path).with_context(|| {
        format!(
            "{} 未出现在 cargo metadata packages 中；manifest_path={}",
            assembly.cargo_label,
            assembly.cargo_path.display()
        )
    })?;
    let declared_direct_domains = direct_normal_domain_deps(root, metadata, package)?;
    let target_direct_domains = cargo_tree_domains(root, assembly, metadata, Some(1))?;
    let direct_domains = declared_direct_domains
        .intersection(&target_direct_domains)
        .cloned()
        .collect();
    let closure_domains = cargo_tree_domains(root, assembly, metadata, None)?;
    let mut findings = validate_domain_sets(assembly, direct_domains, closure_domains)?;
    if assembly.manifest.name == "identityaudit" {
        let closure_packages = cargo_tree_package_names(root, assembly)?;
        let workspace_closure = metadata
            .packages
            .iter()
            .filter(|package| closure_packages.contains(&package.name))
            .filter_map(|package| {
                workspace_package_layer(root, metadata, package)
                    .map(|layer| (package.name.clone(), layer))
            })
            .collect::<Vec<_>>();
        findings.extend(validate_identityaudit_boundary(
            &assembly.manifest_label,
            &assembly.cargo_label,
            &package.targets,
            &workspace_closure,
        ));
    }
    Ok(findings)
}

fn discover(root: &Path) -> Result<(Vec<DiscoveredAssembly>, Vec<Finding>)> {
    let mut assemblies = Vec::new();
    let mut findings = Vec::new();
    for target in discover_targets(root)? {
        let cargo_path = target.cargo_path();
        if !target.has_manifest() {
            if target.has_cargo_manifest() {
                let label = target
                    .dir()
                    .strip_prefix(root)
                    .unwrap_or(target.dir())
                    .display()
                    .to_string();
                findings.push(finding(
                    Rule::MissingManifest,
                    &label,
                    format!(
                        "assembly crate 必须声明 {}/assembly.toml；source={}",
                        label,
                        rel_label(root, &cargo_path)
                    ),
                ));
            }
            continue;
        }
        assemblies.push(load_target(root, target.dir())?);
    }
    Ok((assemblies, findings))
}

fn validate_assembly(a: &DiscoveredAssembly) -> Vec<Finding> {
    let mut findings = Vec::new();
    validate_manifest_intent(a, &mut findings);

    for (index, provider) in a.manifest.diport_providers.iter().enumerate() {
        let source = format!(
            "{}:{}",
            a.manifest_label,
            provider_table_line(&a.manifest_src, index)
        );
        let subject = format!("{source} {}", provider.provider);
        if a.manifest.profile == AssemblyProfile::Production
            && provider.port == DiportPort::RevocationStore
            && provider.durability != ProviderDurability::Persistent
        {
            findings.push(finding(
                Rule::RevocationDurability,
                &subject,
                "field=durability/profile production diport::RevocationStore provider 必须 durability=persistent；ephemeral-memory 只能用于 demo/test assembly",
            ));
        }

        if provider.lifecycle == ProviderLifecycle::Active
            && dependency_features(&a.cargo_toml, &provider.provider_crate).is_none()
        {
            findings.push(finding(
                Rule::ActiveProviderDependency,
                &subject,
                format!(
                    "field=providerCrate active providerCrate `{}` 必须出现在 {} [dependencies]",
                    provider.provider_crate, a.cargo_label
                ),
            ));
        }

        if provider.lifecycle == ProviderLifecycle::Active {
            let constructor = provider.provider;
            if constructor.port() != provider.port {
                findings.push(finding(
                    Rule::ActiveProviderPort,
                    &subject,
                    format!(
                        "field=provider typed provider `{}` 的真实 port 是 `{}`，manifest 不得声明为 `{}`",
                        constructor,
                        constructor.port(),
                        provider.port
                    ),
                ));
            } else {
                if constructor.durability() != provider.durability {
                    findings.push(finding(
                        Rule::ProviderDurabilityMismatch,
                        &subject,
                        format!(
                            "field=durability provider `{}` 的真实 durability 是 `{}`，manifest 不得声明为 `{}`",
                            constructor,
                            constructor.durability(),
                            provider.durability
                        ),
                    ));
                }
                if constructor.provider_crate() != provider.provider_crate {
                    findings.push(finding(
                        Rule::ProviderCrateMismatch,
                        &subject,
                        format!(
                            "field=providerCrate provider `{}` 的实现 crate 是 `{}`，manifest 不得声明为 `{}`",
                            constructor,
                            constructor.provider_crate(),
                            provider.provider_crate
                        ),
                    ));
                }
            }

            let required_features = required_features(provider);
            if let Some(actual_features) =
                dependency_features(&a.cargo_toml, &provider.provider_crate)
            {
                let missing: Vec<_> = required_features
                    .iter()
                    .filter(|feature| !actual_features.contains(**feature))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    findings.push(finding(
                        Rule::ActiveProviderFeature,
                        &subject,
                        format!(
                            "field=requiredFeatures active provider `{}` for port `{}` 需要启用 Cargo feature {:?}；检查 {} [dependencies].{}",
                            provider.provider,
                            provider.port,
                            missing,
                            a.cargo_label,
                            provider.provider_crate
                        ),
                    ));
                }
            }

            if is_active_distributed_provider(provider) && !has_distributed_consumer_evidence(a) {
                findings.push(finding(
                    Rule::ActiveDistributedProviderConsumer,
                    &subject,
                    "field=consumer active distributed Lock/CAS provider 必须在唯一 run_startup composition root 有 consumer 证据：wire_distributed + DistributedRuntimeDeps 必填注入真实 consumer",
                ));
            }
        }
    }
    validate_required_capabilities(a, &mut findings);
    validate_pdp_replay_store_capability(a, &mut findings);
    if a.manifest.profile == AssemblyProfile::Production {
        validate_production_security_closeout(a, &mut findings);
    }
    findings
}

fn validate_pdp_replay_store_capability(a: &DiscoveredAssembly, findings: &mut Vec<Finding>) {
    let has_active_pdp = a.manifest.diport_providers.iter().any(|provider| {
        provider.port == DiportPort::Pdp && provider.lifecycle == ProviderLifecycle::Active
    });
    if a.manifest.name != "runtime" || !has_active_pdp {
        return;
    }

    let provider = ProviderConstructor::PostgresServiceTokenReplayStore;
    let consumer = "oidc";
    if !has_active_persistent_provider(a, provider, consumer) {
        findings.push(finding(
            Rule::PdpReplayStoreCapability,
            &a.manifest_label,
            format!(
                "field=diportProviders capability=PdpReplayStore expected active persistent `{provider}` for `{}` providerCrate `{}` consumer `{consumer}`; actual={}",
                provider.port(),
                provider.provider_crate(),
                provider_actual(a, provider, consumer)
            ),
        ));
    }
}

fn validate_manifest_intent(a: &DiscoveredAssembly, findings: &mut Vec<Finding>) {
    // INVARIANT: ASSEMBLY-MANIFEST-INTENT-01 { level = "Medium", exec = "verify", source = "code" } —
    // assembly manifest intent 字段是静态声明源，必须非空、闭值、去重，并绑定到 assembly 目录名；
    // anti-vacuity red/green tests 覆盖 name/domains/topology/listeners。
    let dir_name = a
        .dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    for error in a.manifest.basic_validation_errors() {
        push_manifest_validation_finding(a, error, findings);
    }

    if !a.manifest.name.trim().is_empty() && a.manifest.name != dir_name {
        findings.push(finding(
            Rule::ManifestNameMismatch,
            &a.manifest_label,
            format!(
                "field=name 必须非空且等于 assembly 目录名 `{dir_name}`；实际 `{}`",
                a.manifest.name
            ),
        ));
    }
}

fn push_manifest_validation_finding(
    a: &DiscoveredAssembly,
    error: ManifestValidationError,
    findings: &mut Vec<Finding>,
) {
    match error {
        ManifestValidationError::Empty { field: "name" } => {
            findings.push(finding(
                Rule::ManifestNameMismatch,
                &a.manifest_label,
                "field=name 必须非空且等于 assembly 目录名",
            ));
        }
        ManifestValidationError::Empty { field: "domains" } => {
            findings.push(finding(
                Rule::EmptyDomains,
                &a.manifest_label,
                "field=domains 至少声明一个 domain，避免 assembly intent 空转通过",
            ));
        }
        ManifestValidationError::Duplicate { field: "domains" } => {
            findings.push(finding(
                Rule::DuplicateDomain,
                &a.manifest_label,
                "field=domains domain 重复声明",
            ));
        }
        ManifestValidationError::Empty { field: "listeners" } => {
            findings.push(finding(
                Rule::EmptyListeners,
                &a.manifest_label,
                "field=listeners 至少声明一个 listener，避免 assembly listener surface 空转通过",
            ));
        }
        ManifestValidationError::Duplicate { field: "listeners" } => {
            findings.push(finding(
                Rule::DuplicateListener,
                &a.manifest_label,
                "field=listeners listener 重复声明",
            ));
        }
        ManifestValidationError::Empty {
            field: "frameworkContracts",
        } => findings.push(finding(
            Rule::FrameworkContractServing,
            &a.manifest_label,
            "field=frameworkContracts entries must not be empty",
        )),
        ManifestValidationError::Duplicate {
            field: "frameworkContracts",
        } => findings.push(finding(
            Rule::FrameworkContractServing,
            &a.manifest_label,
            "field=frameworkContracts contains a duplicate contract id",
        )),
        ManifestValidationError::Empty {
            field: "diportProviders",
        } => {
            findings.push(finding(
                Rule::EmptyDiportProviders,
                &a.manifest_label,
                "field=diportProviders 至少声明一个 provider，避免 assembly fact source 空转通过",
            ));
        }
        ManifestValidationError::Duplicate {
            field: "diportProviders",
        } => {
            findings.push(finding(
                Rule::DuplicateDiportProvider,
                &a.manifest_label,
                "field=diportProviders provider 声明重复",
            ));
        }
        ManifestValidationError::Empty { field } if field.starts_with("diportProviders.") => {
            findings.push(finding(
                Rule::InvalidDiportProvider,
                &a.manifest_label,
                format!("field={field} must not be empty"),
            ));
        }
        ManifestValidationError::Empty { field } | ManifestValidationError::Duplicate { field } => {
            findings.push(finding(
                Rule::InvalidDiportProvider,
                &a.manifest_label,
                format!("field={field} invalid assembly manifest declaration"),
            ));
        }
        ManifestValidationError::Invalid { field } => {
            findings.push(finding(
                Rule::InvalidDiportProvider,
                &a.manifest_label,
                format!("field={field} invalid assembly manifest declaration"),
            ));
        }
    }
}

#[derive(Clone, Copy)]
struct DomainCapabilitySpec {
    domain: &'static str,
    capabilities: &'static [RequiredCapabilitySpec],
}

#[derive(Clone, Copy)]
struct RequiredCapabilitySpec {
    capability: &'static str,
    expectation: RequiredCapabilityExpectation,
}

#[derive(Clone, Copy)]
enum RequiredCapabilityExpectation {
    CargoDependency {
        dependency: &'static str,
        required_features: &'static [&'static str],
    },
    ActivePersistentProvider {
        provider: ProviderConstructor,
        consumer: &'static str,
    },
}

const IDENTITY_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Pg",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "postgres",
            required_features: &["domain-identity"],
        },
    },
    RequiredCapabilitySpec {
        capability: "Signer",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::VaultSigner,
            consumer: "identity",
        },
    },
    RequiredCapabilitySpec {
        capability: "Pdp",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::OidcProvider,
            consumer: "httpserve",
        },
    },
];

const SETTINGS_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Pg",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "postgres",
            required_features: &["domain-settings"],
        },
    },
    RequiredCapabilitySpec {
        capability: "VaultKeyProvider",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::VaultKeyProvider,
            consumer: "settings",
        },
    },
];

const AUDIT_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Pg",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "postgres",
            required_features: &["domain-audit"],
        },
    },
    RequiredCapabilitySpec {
        capability: "MacVerifier",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "crypto-adapter",
            required_features: &[],
        },
    },
    RequiredCapabilitySpec {
        capability: "AuthAuditSink",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::PostgresAuthAuditSink,
            consumer: "httpserve",
        },
    },
];

const EMPTY_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[];

const DURABLE_TOPOLOGY_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Publisher",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::AmqpPublisher,
            consumer: "eventexec",
        },
    },
    RequiredCapabilitySpec {
        capability: "AckableSubscriber",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::AmqpSubscriber,
            consumer: "eventexec",
        },
    },
    RequiredCapabilitySpec {
        capability: "LockStore",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::RedisLockStore,
            consumer: "distributed",
        },
    },
    RequiredCapabilitySpec {
        capability: "CasStore",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::PostgresCasStore,
            consumer: "distributed",
        },
    },
];

const REQUIRED_CAPABILITY_DOMAINS: &[DomainCapabilitySpec] = &[
    DomainCapabilitySpec {
        domain: "identity",
        capabilities: IDENTITY_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "settings",
        capabilities: SETTINGS_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "audit",
        capabilities: AUDIT_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "contractreg",
        capabilities: EMPTY_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "syshealth",
        capabilities: EMPTY_REQUIRED_CAPABILITIES,
    },
];

#[cfg(test)]
fn required_capability_domain_specs() -> &'static [DomainCapabilitySpec] {
    REQUIRED_CAPABILITY_DOMAINS
}

fn validate_required_capabilities(a: &DiscoveredAssembly, findings: &mut Vec<Finding>) {
    // INVARIANT: ASSEMBLY-REQUIRED-CAPABILITY-01 { level = "Medium", exec = "verify", source = "code" } —
    // assembly.toml 的 domains/topology 声明必须闭合到最小 provider/Cargo capability 事实。此 guard
    // 不改变 runtime 接线，不新增兼容路径；缺失、draft、ephemeral critical 均 fail-closed。
    for domain in &a.manifest.domains {
        let domain = domain.as_str();
        let Some(spec) = REQUIRED_CAPABILITY_DOMAINS
            .iter()
            .find(|spec| spec.domain == domain)
        else {
            findings.push(finding(
                Rule::RequiredCapability,
                &a.manifest_label,
                format!(
                    "field=domains domain={domain} capability=DomainCapabilityTable expected domain present in xtask required capability table; actual=missing-domain-spec"
                ),
            ));
            continue;
        };
        for capability in spec.capabilities {
            validate_required_capability(a, spec.domain, capability, findings);
        }
    }

    if requires_distributed_capabilities(a) {
        for capability in DURABLE_TOPOLOGY_REQUIRED_CAPABILITIES {
            validate_required_capability(a, "distributed", capability, findings);
        }
    }
}

fn validate_required_capability(
    a: &DiscoveredAssembly,
    domain: &str,
    spec: &RequiredCapabilitySpec,
    findings: &mut Vec<Finding>,
) {
    match spec.expectation {
        RequiredCapabilityExpectation::CargoDependency {
            dependency,
            required_features,
        } => match dependency_features(&a.cargo_toml, dependency) {
            None => findings.push(finding(
                Rule::RequiredCapability,
                &a.cargo_label,
                format!(
                    "field=dependencies domain={domain} capability={} expected exact [dependencies].{dependency} in {}; actual=missing-dependency",
                    spec.capability, a.cargo_label
                ),
            )),
            Some(features)
                if required_features
                    .iter()
                    .any(|required| !features.iter().any(|actual| actual == required)) =>
            {
                findings.push(finding(
                    Rule::RequiredCapability,
                    &a.cargo_label,
                    format!(
                        "field=dependencies domain={domain} capability={} expected [dependencies].{dependency} features {:?}; actual={features:?}",
                        spec.capability, required_features
                    ),
                ));
            }
            Some(_) => {}
        }
        RequiredCapabilityExpectation::ActivePersistentProvider {
            provider,
            consumer,
        } => {
            if !has_active_persistent_provider(a, provider, consumer) {
                findings.push(finding(
                    Rule::RequiredCapability,
                    &a.manifest_label,
                    format!(
                        "field=diportProviders domain={domain} capability={} expected active persistent `{provider}` for `{}` providerCrate `{}` consumer `{consumer}`; actual={}",
                        spec.capability,
                        provider.port(),
                        provider.provider_crate(),
                        provider_actual(a, provider, consumer)
                    ),
                ));
            }
        }
    }
}

fn requires_distributed_capabilities(a: &DiscoveredAssembly) -> bool {
    a.manifest.profile == AssemblyProfile::Production
        || matches!(
            a.manifest.topology,
            AssemblyTopology::DurableShared | AssemblyTopology::DurableIsolated
        )
}

fn has_active_persistent_provider(
    a: &DiscoveredAssembly,
    provider: ProviderConstructor,
    consumer: &str,
) -> bool {
    a.manifest.diport_providers.iter().any(|candidate| {
        candidate.lifecycle == ProviderLifecycle::Active
            && candidate.durability == ProviderDurability::Persistent
            && candidate.port == provider.port()
            && candidate.provider == provider
            && candidate.provider_crate == provider.provider_crate()
            && candidate.consumer == consumer
    })
}

fn provider_actual(
    a: &DiscoveredAssembly,
    provider: ProviderConstructor,
    consumer: &str,
) -> String {
    let actual = a
        .manifest
        .diport_providers
        .iter()
        .filter(|candidate| {
            candidate.port == provider.port()
                || candidate.provider == provider
                || candidate.provider_crate == provider.provider_crate()
                || candidate.consumer == consumer
        })
        .map(provider_state)
        .collect::<Vec<_>>()
        .join(", ");
    if actual.is_empty() {
        "missing-provider".to_string()
    } else {
        actual
    }
}

fn provider_state(provider: &DiportProvider) -> String {
    format!(
        "port={} provider={} providerCrate={} consumer={} lifecycle={} durability={}",
        provider.port,
        provider.provider,
        provider.provider_crate,
        provider.consumer,
        provider.lifecycle,
        provider.durability
    )
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    workspace_members: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    #[serde(default)]
    dependencies: Vec<MetadataDependency>,
    #[serde(default)]
    targets: Vec<MetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct MetadataTarget {
    #[serde(default)]
    kind: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    kind: Option<String>,
    rename: Option<String>,
    path: Option<PathBuf>,
}

fn load_workspace_metadata(root: &Path) -> Result<Option<CargoMetadata>> {
    let manifest = root.join("Cargo.toml");
    if !manifest.exists() {
        return Ok(None);
    }

    let manifest_arg = manifest.display().to_string();
    let args = cargo_metadata_args(manifest_arg.as_str());
    let mut cmd = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Metadata,
        &args[1..],
        &[],
        Some(root),
    );
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("执行 cargo metadata 失败：{}", manifest.display()))?;
    if !output.status.success() {
        bail!(
            "cargo metadata --locked 失败（{}）：{}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let metadata = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("解析 cargo metadata JSON 失败：{}", manifest.display()))?;
    Ok(Some(metadata))
}

fn cargo_metadata_args(manifest_arg: &str) -> [&str; 6] {
    [
        "metadata",
        "--format-version=1",
        "--locked",
        "--all-features",
        "--manifest-path",
        manifest_arg,
    ]
}

fn cargo_tree_stdout(
    root: &Path,
    assembly: &DiscoveredAssembly,
    depth: Option<usize>,
) -> Result<String> {
    let manifest = assembly.cargo_path.display().to_string();
    let depth_value = depth.map(|value| value.to_string());
    let mut args = vec![
        "tree",
        "--manifest-path",
        manifest.as_str(),
        "--edges",
        "normal",
        "--all-features",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ];
    if let Some(value) = depth_value.as_deref() {
        args.extend(["--depth", value]);
    }
    let output = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Tree,
        &args[1..],
        &[],
        Some(root),
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .with_context(|| format!("执行 cargo tree 失败：{}", assembly.cargo_label))?;
    if !output.status.success() {
        bail!(
            "cargo tree 失败（{}）：{}",
            assembly.cargo_label,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    String::from_utf8(output.stdout)
        .with_context(|| format!("cargo tree 输出不是 UTF-8：{}", assembly.cargo_label))
}

fn cargo_tree_domains(
    root: &Path,
    assembly: &DiscoveredAssembly,
    metadata: &CargoMetadata,
    depth: Option<usize>,
) -> Result<BTreeSet<String>> {
    let stdout = cargo_tree_stdout(root, assembly, depth)?;
    let mut domains = BTreeSet::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| package_is_workspace_domain(root, metadata, package))
    {
        let Some(package_dir) = package.manifest_path.parent() else {
            continue;
        };
        let path_marker = format!("({})", package_dir.display());
        if stdout.lines().any(|line| {
            line.starts_with(&format!("{} ", package.name)) && line.ends_with(&path_marker)
        }) {
            domains.insert(package.name.clone());
        }
    }
    Ok(domains)
}

fn cargo_tree_package_names(
    root: &Path,
    assembly: &DiscoveredAssembly,
) -> Result<BTreeSet<String>> {
    Ok(cargo_tree_stdout(root, assembly, None)?
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect())
}

fn package_by_manifest<'a>(
    metadata: &'a CargoMetadata,
    manifest_path: &Path,
) -> Option<&'a MetadataPackage> {
    metadata
        .packages
        .iter()
        .find(|package| package.manifest_path == manifest_path)
}

fn direct_normal_domain_deps(
    root: &Path,
    metadata: &CargoMetadata,
    assembly: &MetadataPackage,
) -> Result<BTreeSet<String>> {
    let mut domains = BTreeSet::new();
    for dependency in assembly
        .dependencies
        .iter()
        .filter(|dep| dep.kind.is_none())
    {
        if dependency.rename.is_some() {
            continue;
        }
        let Some(path) = &dependency.path else {
            continue;
        };
        for package in metadata
            .packages
            .iter()
            .filter(|package| package_is_workspace_domain(root, metadata, package))
        {
            let Some(package_dir) = package.manifest_path.parent() else {
                continue;
            };
            if dependency.name == package.name && path == package_dir {
                domains.insert(package.name.clone());
            }
        }
    }
    Ok(domains)
}

fn validate_domain_sets(
    a: &DiscoveredAssembly,
    direct_domains: BTreeSet<String>,
    closure_domains: BTreeSet<String>,
) -> Result<Vec<Finding>> {
    let manifest_domains: BTreeSet<&str> = a
        .manifest
        .domains
        .iter()
        .map(AssemblyDomain::as_str)
        .collect();
    let mut findings = Vec::new();
    for domain in &manifest_domains {
        if !direct_domains.contains(*domain) {
            findings.push(finding(
                Rule::ActiveDomainDependency,
                &a.manifest_label,
                format!(
                    "field=domains domain `{domain}` 必须在 {} [dependencies] 中以同名 normal dependency 直接依赖同名 workspace domain crate；dev/build/alias/package rename/crates.io 同名包均不满足",
                    a.cargo_label
                ),
            ));
        }
    }

    for domain in closure_domains {
        if !manifest_domains.contains(domain.as_str()) {
            findings.push(finding(
                Rule::InactiveDomainDependencyClosure,
                &a.cargo_label,
                format!(
                    "field=domains inactive domain `{domain}` 出现在 assembly normal dependency closure；必须加入 {} domains 或移除/拆分该 normal 依赖",
                    a.manifest_label
                ),
            ));
        }
    }
    Ok(findings)
}

fn validate_identityaudit_boundary(
    manifest_label: &str,
    cargo_label: &str,
    targets: &[MetadataTarget],
    closure_packages: &[(String, crate::layers::Layer)],
) -> Vec<Finding> {
    // identityaudit is a compile-time composition proof, not a launch assembly. Keep this boundary
    // executable: Cargo target drift and transport/runtime dependencies must fail assembly validate.
    let mut findings = Vec::new();
    let lib_only = targets.len() == 1 && targets[0].kind.as_slice() == ["lib"];
    if !lib_only {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            manifest_label,
            format!(
                "field=package.targets {cargo_label} 必须保持唯一 lib target；identityaudit 不得新增 bin/example/launch target"
            ),
        ));
    }

    for (package, layer) in closure_packages {
        if !identityaudit_package_allowed(package, *layer) {
            findings.push(finding(
                Rule::IdentityAuditBoundary,
                manifest_label,
                format!(
                    "field=normal-dependency-closure {cargo_label} 禁止 {layer:?} package `{package}`；identityaudit 只允许 identity+audit composition proof 所需 domain/adapter/root"
                ),
            ));
        }
    }
    findings
}

fn identityaudit_package_allowed(package: &str, layer: crate::layers::Layer) -> bool {
    use crate::layers::Layer::{Adapter, Domain, Root};
    match layer {
        Domain => matches!(package, "identity" | "audit"),
        Adapter => matches!(package, "postgres" | "vault" | "oidc" | "crypto-adapter"),
        Root => matches!(
            package,
            "identityaudit" | "identity-composition" | "audit-composition"
        ),
        _ => true,
    }
}

fn package_is_workspace_domain(
    root: &Path,
    metadata: &CargoMetadata,
    package: &MetadataPackage,
) -> bool {
    workspace_package_layer(root, metadata, package) == Some(crate::layers::Layer::Domain)
}

fn workspace_package_layer(
    root: &Path,
    metadata: &CargoMetadata,
    package: &MetadataPackage,
) -> Option<crate::layers::Layer> {
    if !metadata.workspace_members.contains(&package.id) {
        return None;
    }
    let package_dir = package.manifest_path.parent()?;
    let member_path = package_dir.strip_prefix(root).ok()?;
    crate::layers::classify(&package.name, &member_path.display().to_string())
}

struct CriticalProviderSpec {
    gate: &'static str,
    provider: ProviderConstructor,
}

fn validate_production_security_closeout(a: &DiscoveredAssembly, findings: &mut Vec<Finding>) {
    // INVARIANT: SECURITY-PRODUCTION-CLOSEOUT-01 { level = "Medium", exec = "verify", source = "code" } —
    // production assembly 必须同时具备 active persistent OIDC/Vault provider、JWKS 文件源 ready probe 证据、
    // SPIFFE/mTLS 证据，且拒绝 legacy Internal service-token migration env 常量；red/green fixture 见本模块测试。
    const CRITICAL_PROVIDERS: &[CriticalProviderSpec] = &[
        CriticalProviderSpec {
            gate: "oidc-pdp",
            provider: ProviderConstructor::OidcProvider,
        },
        CriticalProviderSpec {
            gate: "vault-signer",
            provider: ProviderConstructor::VaultSigner,
        },
        CriticalProviderSpec {
            gate: "vault-keyprovider",
            provider: ProviderConstructor::VaultKeyProvider,
        },
    ];

    for spec in CRITICAL_PROVIDERS {
        if !has_active_persistent_backend_provider(a, spec) {
            findings.push(finding(
                Rule::ProductionSecurityCriticalProvider,
                &a.manifest_label,
                format!(
                    "field=diportProviders profile=production gate={} 必须声明 active persistent `{}` for `{}`，且 {} [dependencies].{} 必须启用 backend feature",
                    spec.gate,
                    spec.provider,
                    spec.provider.port(),
                    a.cargo_label,
                    spec.provider.provider_crate()
                ),
            ));
        }
    }

    let evidence = security_closeout_evidence_from_sources(&a.dir).unwrap_or_default();
    if !evidence.has_jwks_closeout() {
        findings.push(finding(
            Rule::ProductionSecurityJwksCloseout,
            &a.manifest_label,
            "source=rust-ast-run-reachable profile=production gate=jwks 必须在 run() 可达路径有 profile-specific JwksKeySource::load_and_watch + typed VerifierConfigBuilder::keys_jwks + verifier managed resource + profile-specific JWKS readiness probe 注册证据",
        ));
    }
    if !evidence.has_spiffe_closeout() {
        findings.push(finding(
            Rule::ProductionSecuritySpiffeCloseout,
            &a.manifest_label,
            "source=rust-ast-run-reachable profile=production gate=spiffe-mtls 必须在 run() 可达路径有 MtlsServerConfig::from_spire + DomainHttpTransport::from_spire + domain_transport_ready probe 证据，且不得保留 Internal service-token migration env 常量",
        ));
    }
    validate_token_profile_trust_chain(a, &evidence, findings);
}

fn validate_token_profile_trust_chain(
    a: &DiscoveredAssembly,
    evidence: &SecurityCloseoutEvidence,
    findings: &mut Vec<Finding>,
) {
    // INVARIANT: TOKEN-PROFILE-ASSEMBLY-01 { level = "Medium", exec = "verify", source = "code" } —
    // typed construction alone does not prove that all three exclusive profiles are reachable from
    // the production entrypoint. This gate consumes AST facts only from the free `run()` call graph;
    // comments, strings, dead helpers, and cfg(test) modules cannot satisfy it.
    let mut missing = Vec::new();
    for (present, fact) in [
        (
            evidence.rss_access_provider_build,
            "build_rss_access_provider",
        ),
        (
            evidence.federated_access_provider_build,
            "build_federated_access_provider",
        ),
        (
            evidence.service_token_provider_build,
            "build_service_token_provider",
        ),
        (evidence.rss_access_binding, "ProfileBinding::RssAccess"),
        (
            evidence.federated_access_binding,
            "ProfileBinding::FederatedAccess",
        ),
        (
            evidence.service_token_binding,
            "ProfileBinding::ServiceToken",
        ),
        (
            evidence.rss_access_jwks_probe,
            "AccessTokenJwksReadyProbe::rss_access",
        ),
        (
            evidence.federated_access_jwks_probe,
            "AccessTokenJwksReadyProbe::federated_access",
        ),
        (
            evidence.rss_access_probe_name,
            "RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
        ),
        (
            evidence.federated_access_probe_name,
            "FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
        ),
        (
            evidence.rss_access_resource_name,
            "RSS_ACCESS_TOKEN_RESOURCE_NAME",
        ),
        (
            evidence.federated_access_resource_name,
            "FEDERATED_ACCESS_TOKEN_RESOURCE_NAME",
        ),
        (
            evidence.service_token_resource_name,
            "SERVICE_TOKEN_RESOURCE_NAME",
        ),
        (
            evidence.profile_managed_resource_calls >= 3,
            "three profile managed_resource registrations",
        ),
        (
            evidence.rss_access_reaches_verify_bridge(),
            "ProfileBinding::RssAccess -> apply_verify_bridge",
        ),
        (
            evidence.federated_access_reaches_verify_bridge(),
            "ProfileBinding::FederatedAccess -> apply_verify_bridge",
        ),
        (
            evidence.service_token_reaches_verify_bridge(),
            "ProfileBinding::ServiceToken -> apply_verify_bridge",
        ),
    ] {
        if !present {
            missing.push(fact);
        }
    }
    if !missing.is_empty() {
        findings.push(finding(
            Rule::TokenProfileTrustChain,
            &a.manifest_label,
            format!(
                "source=rust-ast-run-reachable profile=production token profile trust chain incomplete; missing={missing:?}"
            ),
        ));
    }
    if evidence.legacy_token_surface {
        findings.push(finding(
            Rule::TokenProfileLegacySurface,
            &a.manifest_label,
            "source=production-rust legacy/generic token env, shared OIDC provider/probe, or old collapse helper is forbidden",
        ));
    }
    if evidence.mixed_key_provider {
        findings.push(finding(
            Rule::TokenProfileKeyIsolation,
            &a.manifest_label,
            "source=rust-ast production assembly must not use generic StaticKeySource, `.keys(...)`, or combine ES256 and HS256 key APIs",
        ));
    }
    if evidence.split_scheme_provider_binding {
        findings.push(finding(
            Rule::TokenProfileBinding,
            &a.manifest_label,
            "source=rust-ast provider and scheme/profile must be carried by one ProfileBinding; apply_verify_bridge accepts exactly (routes, binding)",
        ));
    }
}

fn has_active_persistent_backend_provider(
    a: &DiscoveredAssembly,
    spec: &CriticalProviderSpec,
) -> bool {
    a.manifest.diport_providers.iter().any(|provider| {
        provider.lifecycle == ProviderLifecycle::Active
            && provider.durability == ProviderDurability::Persistent
            && provider.port == spec.provider.port()
            && provider.provider == spec.provider
            && provider.provider_crate == spec.provider.provider_crate()
            && dependency_features(&a.cargo_toml, spec.provider.provider_crate())
                .is_some_and(|features| features.contains("backend"))
    })
}

fn is_active_distributed_provider(provider: &DiportProvider) -> bool {
    provider.lifecycle == ProviderLifecycle::Active
        && provider.consumer == "distributed"
        && matches!(provider.port, DiportPort::Lock | DiportPort::Cas)
}

fn has_distributed_consumer_evidence(a: &DiscoveredAssembly) -> bool {
    distributed_consumer_evidence_from_sources(&a.dir).unwrap_or(false)
}

fn distributed_consumer_evidence_from_sources(dir: &Path) -> Result<bool> {
    let src_dir = dir.join("src");
    if !src_dir.exists() {
        return Ok(false);
    }
    let mut files = Vec::new();
    collect_rust_sources(&src_dir, &mut files)?;
    files.sort();
    for path in files {
        let content = std::fs::read_to_string(&path)?;
        let file = syn::parse_file(&content)
            .with_context(|| format!("parse rust source {}", path.display()))?;
        if file_has_distributed_consumer_evidence(&file) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn collect_rust_sources(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_sources(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

#[derive(Default)]
struct DistributedConsumerVisitor {
    root_entrypoint_depth: usize,
    distributed_bindings: BTreeSet<String>,
    found_consumer: bool,
}

impl<'ast> syn::visit::Visit<'ast> for DistributedConsumerVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.ident != "run_startup" {
            return;
        }

        self.root_entrypoint_depth += 1;
        syn::visit::visit_item_fn(self, node);
        self.root_entrypoint_depth -= 1;
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if self.root_entrypoint_depth == 0 {
            return;
        }
        if let Some(ident) = local_binding_ident(&node.pat)
            && let Some(init) = &node.init
            && expr_contains_wire_distributed(&init.expr)
        {
            self.distributed_bindings.insert(ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if self.root_entrypoint_depth == 0 {
            return;
        }
        if call_path_ends_with(node.func.as_ref(), "wire_event_transport") {
            let second_arg = node.args.iter().nth(1);
            if second_arg.is_some_and(|expr| self.expr_is_distributed_arg(expr)) {
                self.found_consumer = true;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

impl DistributedConsumerVisitor {
    fn expr_is_distributed_arg(&self, expr: &syn::Expr) -> bool {
        if expr_contains_wire_distributed(expr) {
            return true;
        }
        matches!(
            expr,
            syn::Expr::Path(path)
                if path.path.get_ident().is_some_and(|ident| {
                    self.distributed_bindings.contains(&ident.to_string())
                })
        )
    }
}

fn file_has_distributed_consumer_evidence(file: &syn::File) -> bool {
    let mut visitor = DistributedConsumerVisitor::default();
    syn::visit::Visit::visit_file(&mut visitor, file);
    visitor.found_consumer
}

fn local_binding_ident(pat: &syn::Pat) -> Option<&syn::Ident> {
    match pat {
        syn::Pat::Ident(pat) => Some(&pat.ident),
        syn::Pat::Type(pat) => local_binding_ident(&pat.pat),
        _ => None,
    }
}

fn expr_contains_wire_distributed(expr: &syn::Expr) -> bool {
    struct WireDistributedVisitor {
        found: bool,
    }

    impl<'ast> syn::visit::Visit<'ast> for WireDistributedVisitor {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if call_path_ends_with(node.func.as_ref(), "wire_distributed") {
                self.found = true;
            }
            syn::visit::visit_expr_call(self, node);
        }
    }

    let mut visitor = WireDistributedVisitor { found: false };
    syn::visit::Visit::visit_expr(&mut visitor, expr);
    visitor.found
}

#[derive(Clone, Default)]
struct SecurityCloseoutEvidence {
    runtime_oidc_provider_build: bool,
    runtime_oidc_provider_handle: bool,
    runtime_oidc_managed_resource: bool,
    jwks_load_and_watch: bool,
    jwks_keys_jwks: bool,
    jwks_ready_probe: bool,
    jwks_probe_registered: bool,
    mtls_server_from_spire: bool,
    domain_transport_from_spire: bool,
    domain_transport_ready_probe: bool,
    legacy_service_token_migration: bool,
    rss_access_provider_build: bool,
    federated_access_provider_build: bool,
    service_token_provider_build: bool,
    rss_access_binding: bool,
    federated_access_binding: bool,
    service_token_binding: bool,
    rss_access_jwks_probe: bool,
    federated_access_jwks_probe: bool,
    rss_access_probe_name: bool,
    federated_access_probe_name: bool,
    rss_access_resource_name: bool,
    federated_access_resource_name: bool,
    service_token_resource_name: bool,
    profile_managed_resource_calls: usize,
    rss_access_bound_to_verify_bridge: bool,
    federated_access_bound_to_verify_bridge: bool,
    service_token_bound_to_verify_bridge: bool,
    rss_access_packed_in_profile_carrier: bool,
    federated_access_packed_in_profile_carrier: bool,
    service_token_packed_in_profile_carrier: bool,
    typed_primary_access_binding_carrier_call: bool,
    typed_admin_access_binding_carrier_call: bool,
    typed_service_binding_carrier_call: bool,
    exact_access_binding_mapping: bool,
    exact_service_binding_mapping: bool,
    profile_carrier_bound_to_verify_bridge: bool,
    legacy_token_surface: bool,
    mixed_key_provider: bool,
    split_scheme_provider_binding: bool,
}

impl SecurityCloseoutEvidence {
    fn merge(&mut self, other: Self) {
        self.runtime_oidc_provider_build |= other.runtime_oidc_provider_build;
        self.runtime_oidc_provider_handle |= other.runtime_oidc_provider_handle;
        self.runtime_oidc_managed_resource |= other.runtime_oidc_managed_resource;
        self.jwks_load_and_watch |= other.jwks_load_and_watch;
        self.jwks_keys_jwks |= other.jwks_keys_jwks;
        self.jwks_ready_probe |= other.jwks_ready_probe;
        self.jwks_probe_registered |= other.jwks_probe_registered;
        self.mtls_server_from_spire |= other.mtls_server_from_spire;
        self.domain_transport_from_spire |= other.domain_transport_from_spire;
        self.domain_transport_ready_probe |= other.domain_transport_ready_probe;
        self.legacy_service_token_migration |= other.legacy_service_token_migration;
        self.rss_access_provider_build |= other.rss_access_provider_build;
        self.federated_access_provider_build |= other.federated_access_provider_build;
        self.service_token_provider_build |= other.service_token_provider_build;
        self.rss_access_binding |= other.rss_access_binding;
        self.federated_access_binding |= other.federated_access_binding;
        self.service_token_binding |= other.service_token_binding;
        self.rss_access_jwks_probe |= other.rss_access_jwks_probe;
        self.federated_access_jwks_probe |= other.federated_access_jwks_probe;
        self.rss_access_probe_name |= other.rss_access_probe_name;
        self.federated_access_probe_name |= other.federated_access_probe_name;
        self.rss_access_resource_name |= other.rss_access_resource_name;
        self.federated_access_resource_name |= other.federated_access_resource_name;
        self.service_token_resource_name |= other.service_token_resource_name;
        self.profile_managed_resource_calls = self
            .profile_managed_resource_calls
            .saturating_add(other.profile_managed_resource_calls);
        self.rss_access_bound_to_verify_bridge |= other.rss_access_bound_to_verify_bridge;
        self.federated_access_bound_to_verify_bridge |=
            other.federated_access_bound_to_verify_bridge;
        self.service_token_bound_to_verify_bridge |= other.service_token_bound_to_verify_bridge;
        self.rss_access_packed_in_profile_carrier |= other.rss_access_packed_in_profile_carrier;
        self.federated_access_packed_in_profile_carrier |=
            other.federated_access_packed_in_profile_carrier;
        self.service_token_packed_in_profile_carrier |=
            other.service_token_packed_in_profile_carrier;
        self.typed_primary_access_binding_carrier_call |=
            other.typed_primary_access_binding_carrier_call;
        self.typed_admin_access_binding_carrier_call |=
            other.typed_admin_access_binding_carrier_call;
        self.typed_service_binding_carrier_call |= other.typed_service_binding_carrier_call;
        self.exact_access_binding_mapping |= other.exact_access_binding_mapping;
        self.exact_service_binding_mapping |= other.exact_service_binding_mapping;
        self.profile_carrier_bound_to_verify_bridge |= other.profile_carrier_bound_to_verify_bridge;
        self.legacy_token_surface |= other.legacy_token_surface;
        self.mixed_key_provider |= other.mixed_key_provider;
        self.split_scheme_provider_binding |= other.split_scheme_provider_binding;
    }

    fn has_jwks_closeout(&self) -> bool {
        self.runtime_oidc_provider_build
            && self.runtime_oidc_provider_handle
            && self.runtime_oidc_managed_resource
            && self.jwks_load_and_watch
            && self.jwks_keys_jwks
            && self.jwks_ready_probe
            && self.jwks_probe_registered
    }

    fn has_spiffe_closeout(&self) -> bool {
        self.mtls_server_from_spire
            && self.domain_transport_from_spire
            && self.domain_transport_ready_probe
            && !self.legacy_service_token_migration
    }

    fn rss_access_reaches_verify_bridge(&self) -> bool {
        self.rss_access_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.rss_access_packed_in_profile_carrier
                    || (self.typed_primary_access_binding_carrier_call
                        && self.typed_admin_access_binding_carrier_call
                        && self.exact_access_binding_mapping)))
    }

    fn federated_access_reaches_verify_bridge(&self) -> bool {
        self.federated_access_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.federated_access_packed_in_profile_carrier
                    || (self.typed_primary_access_binding_carrier_call
                        && self.typed_admin_access_binding_carrier_call
                        && self.exact_access_binding_mapping)))
    }

    fn service_token_reaches_verify_bridge(&self) -> bool {
        self.service_token_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.service_token_packed_in_profile_carrier
                    || (self.typed_service_binding_carrier_call
                        && self.exact_service_binding_mapping)))
    }
}

fn security_closeout_evidence_from_sources(dir: &Path) -> Result<SecurityCloseoutEvidence> {
    let src_dir = dir.join("src");
    if !src_dir.exists() {
        return Ok(SecurityCloseoutEvidence::default());
    }
    let mut files = Vec::new();
    collect_rust_sources(&src_dir, &mut files)?;
    files.sort();
    let mut program = SecurityCloseoutProgram::default();
    for path in files {
        let content = std::fs::read_to_string(&path)?;
        let file = syn::parse_file(&content)
            .with_context(|| format!("parse rust source {}", path.display()))?;
        let mut file_program = file_security_closeout_program(&file);
        file_program.legacy_token_surface |= source_contains_legacy_token_surface(&content);
        program.merge(file_program);
    }
    Ok(program.reachable_evidence_from_run())
}

fn source_contains_legacy_token_surface(source: &str) -> bool {
    // Intentionally scan raw source rather than string literals alone: the destructive migration
    // requires the old vocabulary to disappear, and comments/cfg(test) must not preserve bait that
    // makes grep-based reviews ambiguous.
    const FORBIDDEN: &[&str] = &[
        "RSS_JWT_",
        "RSS_OIDC_",
        "OIDC_JWKS_READY_PROBE_NAME",
        "oidc_jwks_ready",
        "OidcJwksReadyProbe",
        "RuntimeOidcProvider",
        "PreparedRuntimeOidcProvider",
        "build_runtime_oidc_provider",
        "required_scheme_for_auth_scheme",
    ];
    FORBIDDEN.iter().any(|needle| source.contains(needle))
}

#[derive(Default)]
struct SecurityCloseoutProgram {
    functions: BTreeMap<String, SecurityFunctionEvidence>,
    access_binding_definitions: usize,
    exact_access_binding_definitions: usize,
    service_binding_definitions: usize,
    exact_service_binding_definitions: usize,
    legacy_service_token_migration: bool,
    legacy_token_surface: bool,
    mixed_key_provider: bool,
    split_scheme_provider_binding: bool,
}

impl SecurityCloseoutProgram {
    fn merge(&mut self, other: Self) {
        self.access_binding_definitions = self
            .access_binding_definitions
            .saturating_add(other.access_binding_definitions);
        self.exact_access_binding_definitions = self
            .exact_access_binding_definitions
            .saturating_add(other.exact_access_binding_definitions);
        self.service_binding_definitions = self
            .service_binding_definitions
            .saturating_add(other.service_binding_definitions);
        self.exact_service_binding_definitions = self
            .exact_service_binding_definitions
            .saturating_add(other.exact_service_binding_definitions);
        self.legacy_service_token_migration |= other.legacy_service_token_migration;
        self.legacy_token_surface |= other.legacy_token_surface;
        self.mixed_key_provider |= other.mixed_key_provider;
        self.split_scheme_provider_binding |= other.split_scheme_provider_binding;
        for (name, info) in other.functions {
            self.functions.entry(name).or_default().merge(info);
        }
    }

    fn reachable_evidence_from_run(&self) -> SecurityCloseoutEvidence {
        let mut out = SecurityCloseoutEvidence {
            legacy_service_token_migration: self.legacy_service_token_migration,
            legacy_token_surface: self.legacy_token_surface,
            mixed_key_provider: self.mixed_key_provider,
            split_scheme_provider_binding: self.split_scheme_provider_binding,
            ..SecurityCloseoutEvidence::default()
        };
        let mut seen = BTreeSet::new();
        let mut stack = vec!["free::run".to_string()];
        while let Some(name) = stack.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some(info) = self.functions.get(&name) else {
                continue;
            };
            out.merge(info.evidence.clone());
            stack.extend(info.calls.iter().cloned());
        }
        out.exact_access_binding_mapping =
            self.access_binding_definitions == 1 && self.exact_access_binding_definitions == 1;
        out.exact_service_binding_mapping =
            self.service_binding_definitions == 1 && self.exact_service_binding_definitions == 1;
        out.legacy_service_token_migration = self.legacy_service_token_migration;
        out.legacy_token_surface = self.legacy_token_surface;
        out.mixed_key_provider = self.mixed_key_provider;
        out.split_scheme_provider_binding = self.split_scheme_provider_binding;
        out
    }
}

#[derive(Clone, Default)]
struct SecurityFunctionEvidence {
    evidence: SecurityCloseoutEvidence,
    calls: BTreeSet<String>,
}

impl SecurityFunctionEvidence {
    fn merge(&mut self, other: Self) {
        self.evidence.merge(other.evidence);
        self.calls.extend(other.calls);
    }
}

fn file_security_closeout_program(file: &syn::File) -> SecurityCloseoutProgram {
    let mut visitor = SecurityCloseoutVisitor::default();
    syn::visit::Visit::visit_file(&mut visitor, file);
    visitor.program
}

#[derive(Default)]
struct SecurityCloseoutVisitor {
    program: SecurityCloseoutProgram,
    function_stack: Vec<String>,
    impl_stack: Vec<String>,
    function_key_apis: Vec<(bool, bool)>,
    profile_binding_locals: Vec<BTreeMap<String, TokenProfileBridgeKind>>,
    profile_carrier_bindings: Vec<BTreeSet<String>>,
    typed_token_provider_bindings: Vec<BTreeSet<String>>,
    typed_route_assembly_contexts: Vec<BTreeSet<String>>,
    route_assembly_selections: Vec<BTreeMap<String, RouteAssemblySelectionKind>>,
    listener_arms: Vec<Option<ListenerSelectionKind>>,
    internal_selection_matches: Vec<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TokenProfileBridgeKind {
    RssAccess,
    FederatedAccess,
    ServiceToken,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RouteAssemblySelectionKind {
    Primary,
    Admin,
    Internal,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListenerSelectionKind {
    Primary,
    Admin,
    InternalServiceToken,
}

impl<'ast> syn::visit::Visit<'ast> for SecurityCloseoutVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.function_stack
            .push(format!("free::{}", node.sig.ident));
        self.function_key_apis.push((false, false));
        self.profile_binding_locals.push(BTreeMap::new());
        self.typed_token_provider_bindings
            .push(token_provider_binding_parameters(&node.sig));
        self.typed_route_assembly_contexts
            .push(route_assembly_context_parameters(&node.sig));
        self.route_assembly_selections.push(BTreeMap::new());
        syn::visit::visit_item_fn(self, node);
        self.route_assembly_selections.pop();
        self.typed_route_assembly_contexts.pop();
        self.typed_token_provider_bindings.pop();
        self.profile_binding_locals.pop();
        self.finish_function_key_apis();
        self.function_stack.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        let owner = match node.self_ty.as_ref() {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        };
        if let Some(owner) = owner {
            self.impl_stack.push(owner);
            syn::visit::visit_item_impl(self, node);
            self.impl_stack.pop();
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        let Some(owner) = self.impl_stack.last().cloned() else {
            return;
        };
        if owner == "TokenProviderBindings" {
            match node.sig.ident.to_string().as_str() {
                "access_binding" => {
                    self.program.access_binding_definitions =
                        self.program.access_binding_definitions.saturating_add(1);
                    if exact_access_binding_definition(node) {
                        self.program.exact_access_binding_definitions = self
                            .program
                            .exact_access_binding_definitions
                            .saturating_add(1);
                    }
                }
                "service_binding" => {
                    self.program.service_binding_definitions =
                        self.program.service_binding_definitions.saturating_add(1);
                    if exact_service_binding_definition(node) {
                        self.program.exact_service_binding_definitions = self
                            .program
                            .exact_service_binding_definitions
                            .saturating_add(1);
                    }
                }
                _ => {}
            }
        }
        self.function_stack
            .push(format!("{owner}::{}", node.sig.ident));
        self.function_key_apis.push((false, false));
        self.profile_binding_locals.push(BTreeMap::new());
        self.typed_token_provider_bindings
            .push(token_provider_binding_parameters(&node.sig));
        self.typed_route_assembly_contexts
            .push(route_assembly_context_parameters(&node.sig));
        self.route_assembly_selections.push(BTreeMap::new());
        syn::visit::visit_impl_item_fn(self, node);
        self.route_assembly_selections.pop();
        self.typed_route_assembly_contexts.pop();
        self.typed_token_provider_bindings.pop();
        self.profile_binding_locals.pop();
        self.finish_function_key_apis();
        self.function_stack.pop();
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        if ident_contains(&node.ident, "INTERNAL_SERVICE_TOKEN_MIGRATION") {
            self.program.legacy_service_token_migration = true;
        }
        syn::visit::visit_item_const(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(call) = call_path_last_segment(node.func.as_ref()) {
            if let Some(identity) = self.path_call_identity(node.func.as_ref()) {
                self.record_call(&identity);
            }
            if call == "Token"
                && call_path_contains_segment(node.func.as_ref(), "ListenerAuthBinding")
                && node.args.len() == 1
                && let Some(binding) = node.args.first()
            {
                self.record_profile_carrier_input(binding);
            }
            if call == "build_runtime_oidc_provider" {
                self.record_evidence(|e| e.runtime_oidc_provider_build = true);
            }
            match call.as_str() {
                "build_rss_access_provider" => {
                    self.record_evidence(|e| {
                        e.runtime_oidc_provider_build = true;
                        e.rss_access_provider_build = true;
                    });
                }
                "build_federated_access_provider" => {
                    self.record_evidence(|e| {
                        e.runtime_oidc_provider_build = true;
                        e.federated_access_provider_build = true;
                    });
                }
                "build_service_token_provider" => {
                    self.record_evidence(|e| e.service_token_provider_build = true);
                }
                "apply_verify_bridge" => {
                    if node.args.len() == 2 {
                        if let Some(binding) = node.args.iter().nth(1) {
                            self.record_profile_bridge(binding);
                        }
                    } else {
                        self.program.split_scheme_provider_binding = true;
                    }
                }
                _ => {}
            }
        }
        if call_path_ends_with(node.func.as_ref(), "load_and_watch")
            && call_path_contains_segment(node.func.as_ref(), "JwksKeySource")
        {
            self.record_evidence(|e| e.jwks_load_and_watch = true);
        }
        if call_path_ends_with(node.func.as_ref(), "new")
            && call_path_contains_segment(node.func.as_ref(), "OidcJwksReadyProbe")
        {
            self.record_evidence(|e| e.jwks_ready_probe = true);
        }
        if call_path_ends_with(node.func.as_ref(), "rss_access")
            && call_path_contains_segment(node.func.as_ref(), "AccessTokenJwksReadyProbe")
        {
            self.record_evidence(|e| {
                e.jwks_ready_probe = true;
                e.rss_access_jwks_probe = true;
            });
        }
        if call_path_ends_with(node.func.as_ref(), "federated_access")
            && call_path_contains_segment(node.func.as_ref(), "AccessTokenJwksReadyProbe")
        {
            self.record_evidence(|e| {
                e.jwks_ready_probe = true;
                e.federated_access_jwks_probe = true;
            });
        }
        if call_path_ends_with(node.func.as_ref(), "from_spire")
            && call_path_contains_segment(node.func.as_ref(), "MtlsServerConfig")
        {
            self.record_evidence(|e| e.mtls_server_from_spire = true);
        }
        if call_path_ends_with(node.func.as_ref(), "from_spire")
            && call_path_contains_segment(node.func.as_ref(), "DomainHttpTransport")
        {
            self.record_evidence(|e| e.domain_transport_from_spire = true);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(selections) =
            route_assembly_context_destructure(node, self.typed_route_assembly_contexts.last())
            && let Some(current) = self.route_assembly_selections.last_mut()
        {
            current.extend(selections);
        }
        let local_binding = match (&node.pat, &node.init) {
            (syn::Pat::Ident(pattern), Some(init)) => self
                .profile_binding_kind(init.expr.as_ref())
                .map(|kind| (pattern.ident.to_string(), kind)),
            _ => None,
        };
        if let (Some(locals), Some((name, kind))) =
            (self.profile_binding_locals.last_mut(), local_binding)
        {
            locals.insert(name, kind);
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let listener = listener_selection_pattern_kind(
            &node.pat,
            self.internal_selection_matches
                .last()
                .copied()
                .unwrap_or(false),
        );
        self.listener_arms.push(listener);
        let carrier = profile_carrier_binding(&node.pat);
        if let Some(binding) = carrier.as_ref() {
            self.profile_carrier_bindings
                .push(BTreeSet::from([binding.clone()]));
        }
        syn::visit::visit_arm(self, node);
        if carrier.is_some() {
            self.profile_carrier_bindings.pop();
        }
        self.listener_arms.pop();
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let internal_match =
            simple_path_ident(ungroup_profile_expression(node.expr.as_ref())).and_then(|name| {
                self.route_assembly_selections
                    .last()
                    .and_then(|selections| selections.get(&name))
                    .copied()
            }) == Some(RouteAssemblySelectionKind::Internal);
        self.internal_selection_matches.push(internal_match);
        syn::visit::visit_expr_match(self, node);
        self.internal_selection_matches.pop();
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if let Some(owner) = self.method_receiver_owner(&node.receiver) {
            self.record_call(&format!("{owner}::{method}"));
        }
        if node.method == "keys_jwks" {
            self.record_evidence(|e| e.jwks_keys_jwks = true);
            self.record_key_api(true, false);
        }
        if node.method == "keys_static" || node.method == "add_es256_sec1" {
            self.record_key_api(true, false);
        }
        if node.method == "keys_hs256" || node.method == "add_hs256_secret" {
            self.record_key_api(false, true);
        }
        if node.method == "keys" {
            self.program.mixed_key_provider = true;
        }
        if node.method == "provider" {
            self.record_evidence(|e| e.runtime_oidc_provider_handle = true);
        }
        if node.method == "managed_resource" {
            self.record_evidence(|e| {
                e.runtime_oidc_managed_resource = true;
                e.profile_managed_resource_calls =
                    e.profile_managed_resource_calls.saturating_add(1);
            });
        }
        if node.method == "probe" {
            self.record_evidence(|e| e.jwks_probe_registered = true);
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if path_contains_segment(&node.path, "DOMAIN_TRANSPORT_READY_PROBE_NAME") {
            self.record_evidence(|e| e.domain_transport_ready_probe = true);
        }
        if path_contains_segment(&node.path, "RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME") {
            self.record_evidence(|e| e.rss_access_probe_name = true);
        }
        if path_contains_segment(&node.path, "FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME") {
            self.record_evidence(|e| e.federated_access_probe_name = true);
        }
        if path_contains_segment(&node.path, "RSS_ACCESS_TOKEN_RESOURCE_NAME") {
            self.record_evidence(|e| e.rss_access_resource_name = true);
        }
        if path_contains_segment(&node.path, "FEDERATED_ACCESS_TOKEN_RESOURCE_NAME") {
            self.record_evidence(|e| e.federated_access_resource_name = true);
        }
        if path_contains_segment(&node.path, "SERVICE_TOKEN_RESOURCE_NAME") {
            self.record_evidence(|e| e.service_token_resource_name = true);
        }
        if path_ends_with(&node.path, "RssAccess")
            && path_contains_segment(&node.path, "ProfileBinding")
        {
            self.record_evidence(|e| e.rss_access_binding = true);
        }
        if path_ends_with(&node.path, "FederatedAccess")
            && path_contains_segment(&node.path, "ProfileBinding")
        {
            self.record_evidence(|e| e.federated_access_binding = true);
        }
        if path_ends_with(&node.path, "ServiceToken")
            && path_contains_segment(&node.path, "ProfileBinding")
        {
            self.record_evidence(|e| e.service_token_binding = true);
        }
        if path_contains_segment(&node.path, "StaticKeySource") {
            self.program.mixed_key_provider = true;
        }
        if path_contains_segment_matching(&node.path, |segment| {
            segment.contains("INTERNAL_SERVICE_TOKEN_MIGRATION")
        }) {
            self.program.legacy_service_token_migration = true;
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        for segment in &node.path.segments {
            if segment.ident == "StaticKeySource" {
                self.program.mixed_key_provider = true;
            }
            if segment.ident == "OidcProvider"
                && matches!(segment.arguments, syn::PathArguments::None)
            {
                self.program.split_scheme_provider_binding = true;
            }
        }
        syn::visit::visit_type_path(self, node);
    }
}

impl SecurityCloseoutVisitor {
    fn current_function(&self) -> Option<&str> {
        self.function_stack.last().map(String::as_str)
    }

    fn current_info_mut(&mut self) -> Option<&mut SecurityFunctionEvidence> {
        let name = self.current_function()?.to_owned();
        Some(self.program.functions.entry(name).or_default())
    }

    fn record_call(&mut self, call: &str) {
        if let Some(info) = self.current_info_mut() {
            info.calls.insert(call.to_owned());
        }
    }

    fn record_evidence(&mut self, f: impl FnOnce(&mut SecurityCloseoutEvidence)) {
        if let Some(info) = self.current_info_mut() {
            f(&mut info.evidence);
        }
    }

    fn record_profile_bridge(&mut self, binding: &syn::Expr) {
        if let Some(kind) = self.profile_binding_kind(binding) {
            self.record_evidence(|evidence| match kind {
                TokenProfileBridgeKind::RssAccess => {
                    evidence.rss_access_bound_to_verify_bridge = true;
                }
                TokenProfileBridgeKind::FederatedAccess => {
                    evidence.federated_access_bound_to_verify_bridge = true;
                }
                TokenProfileBridgeKind::ServiceToken => {
                    evidence.service_token_bound_to_verify_bridge = true;
                }
            });
            return;
        }

        let Some(name) = simple_path_ident(binding) else {
            return;
        };
        if self
            .profile_carrier_bindings
            .iter()
            .rev()
            .any(|bindings| bindings.contains(&name))
        {
            // `ListenerAuthBinding::Token(profile)` is a closed carrier whose payload type is
            // `ProfileBinding`. The match arm moves that exact payload into the only token verify
            // bridge, so every exhaustive ProfileBinding variant that reaches the carrier has a
            // binding→bridge path.
            self.record_evidence(|evidence| {
                evidence.profile_carrier_bound_to_verify_bridge = true;
            });
        }
    }

    fn record_profile_carrier_input(&mut self, binding: &syn::Expr) {
        let binding = ungroup_profile_expression(binding);
        if let Some(kind) = self.profile_binding_kind(binding) {
            self.record_evidence(|evidence| match kind {
                TokenProfileBridgeKind::RssAccess => {
                    evidence.rss_access_packed_in_profile_carrier = true;
                }
                TokenProfileBridgeKind::FederatedAccess => {
                    evidence.federated_access_packed_in_profile_carrier = true;
                }
                TokenProfileBridgeKind::ServiceToken => {
                    evidence.service_token_packed_in_profile_carrier = true;
                }
            });
            return;
        }
        let syn::Expr::MethodCall(call) = binding else {
            return;
        };
        if !self.receiver_is_typed_token_provider(call.receiver.as_ref()) {
            return;
        }
        match call.method.to_string().as_str() {
            "access_binding" if call.args.len() == 1 => {
                let Some(selection) = call
                    .args
                    .first()
                    .and_then(|argument| simple_path_ident(ungroup_profile_expression(argument)))
                else {
                    return;
                };
                let selected_kind = self
                    .route_assembly_selections
                    .last()
                    .and_then(|selections| selections.get(&selection))
                    .copied();
                let listener_kind = self.listener_arms.last().copied().flatten();
                self.record_evidence(|evidence| match (listener_kind, selected_kind) {
                    (
                        Some(ListenerSelectionKind::Primary),
                        Some(RouteAssemblySelectionKind::Primary),
                    ) => evidence.typed_primary_access_binding_carrier_call = true,
                    (
                        Some(ListenerSelectionKind::Admin),
                        Some(RouteAssemblySelectionKind::Admin),
                    ) => evidence.typed_admin_access_binding_carrier_call = true,
                    _ => {}
                });
            }
            "service_binding" => {
                let exact_service_selection = call.args.is_empty()
                    && self.listener_arms.last().copied().flatten()
                        == Some(ListenerSelectionKind::InternalServiceToken);
                self.record_evidence(|evidence| {
                    evidence.typed_service_binding_carrier_call = exact_service_selection;
                });
            }
            _ => {}
        }
    }

    fn profile_binding_kind(&self, expression: &syn::Expr) -> Option<TokenProfileBridgeKind> {
        let expression = ungroup_profile_expression(expression);
        if let syn::Expr::Call(call) = expression
            && let syn::Expr::Path(path) = call.func.as_ref()
            && path_contains_segment(&path.path, "ProfileBinding")
        {
            return match path.path.segments.last()?.ident.to_string().as_str() {
                "RssAccess" => Some(TokenProfileBridgeKind::RssAccess),
                "FederatedAccess" => Some(TokenProfileBridgeKind::FederatedAccess),
                "ServiceToken" => Some(TokenProfileBridgeKind::ServiceToken),
                _ => None,
            };
        }
        let name = simple_path_ident(expression)?;
        self.profile_binding_locals
            .last()
            .and_then(|locals| locals.get(&name))
            .copied()
    }

    fn record_key_api(&mut self, es256: bool, hs256: bool) {
        if let Some((used_es256, used_hs256)) = self.function_key_apis.last_mut() {
            *used_es256 |= es256;
            *used_hs256 |= hs256;
        }
    }

    fn receiver_is_typed_token_provider(&self, receiver: &syn::Expr) -> bool {
        let Some(name) = simple_path_ident(ungroup_profile_expression(receiver)) else {
            return false;
        };
        self.typed_token_provider_bindings
            .last()
            .is_some_and(|bindings| bindings.contains(&name))
    }

    fn finish_function_key_apis(&mut self) {
        if let Some((used_es256, used_hs256)) = self.function_key_apis.pop() {
            self.program.mixed_key_provider |= used_es256 && used_hs256;
        }
    }

    fn method_receiver_owner(&self, receiver: &syn::Expr) -> Option<String> {
        let receiver = match receiver {
            syn::Expr::Paren(paren) => paren.expr.as_ref(),
            syn::Expr::Group(group) => group.expr.as_ref(),
            _ => receiver,
        };
        if matches!(receiver, syn::Expr::Path(path) if path.path.is_ident("self")) {
            return self.impl_stack.last().cloned();
        }
        let syn::Expr::Call(call) = receiver else {
            return None;
        };
        let syn::Expr::Path(path) = call.func.as_ref() else {
            return None;
        };
        let segments = path.path.segments.iter().collect::<Vec<_>>();
        (segments.len() >= 2).then(|| segments[segments.len() - 2].ident.to_string())
    }

    fn path_call_identity(&self, function: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = function else {
            return None;
        };
        let segments = path.path.segments.iter().collect::<Vec<_>>();
        let method = segments.last()?.ident.to_string();
        let Some(owner) = segments
            .iter()
            .rev()
            .nth(1)
            .map(|segment| segment.ident.to_string())
        else {
            return Some(format!("free::{method}"));
        };
        if owner == "Self" {
            return self
                .impl_stack
                .last()
                .map(|owner| format!("{owner}::{method}"));
        }
        if owner.chars().next().is_some_and(char::is_uppercase) {
            Some(format!("{owner}::{method}"))
        } else {
            // Module-qualified free functions retain their free-function identity. This is
            // conservative across source files while preventing Type::method name collisions.
            Some(format!("free::{method}"))
        }
    }
}

fn token_provider_binding_parameters(signature: &syn::Signature) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            if !type_contains_ident(argument.ty.as_ref(), "TokenProviderBindings") {
                return None;
            }
            let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
                return None;
            };
            Some(pattern.ident.to_string())
        })
        .collect()
}

fn route_assembly_context_parameters(signature: &syn::Signature) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            if !type_contains_ident(argument.ty.as_ref(), "RouteAssemblyContext") {
                return None;
            }
            let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
                return None;
            };
            Some(pattern.ident.to_string())
        })
        .collect()
}

fn route_assembly_context_destructure(
    local: &syn::Local,
    typed_contexts: Option<&BTreeSet<String>>,
) -> Option<BTreeMap<String, RouteAssemblySelectionKind>> {
    let init = local.init.as_ref()?;
    let source = simple_path_ident(ungroup_profile_expression(init.expr.as_ref()))?;
    if !typed_contexts.is_some_and(|contexts| contexts.contains(&source)) {
        return None;
    }
    let syn::Pat::Struct(pattern) = &local.pat else {
        return None;
    };
    if !path_contains_segment(&pattern.path, "RouteAssemblyContext") || pattern.rest.is_some() {
        return None;
    }
    let mut selections = BTreeMap::new();
    for field in &pattern.fields {
        let syn::Member::Named(member) = &field.member else {
            continue;
        };
        let kind = match member.to_string().as_str() {
            "primary" => RouteAssemblySelectionKind::Primary,
            "admin" => RouteAssemblySelectionKind::Admin,
            "internal" => RouteAssemblySelectionKind::Internal,
            _ => continue,
        };
        let syn::Pat::Ident(binding) = field.pat.as_ref() else {
            return None;
        };
        if selections.insert(binding.ident.to_string(), kind).is_some() {
            return None;
        }
    }
    let observed = selections.values().copied().collect::<BTreeSet<_>>();
    (observed
        == BTreeSet::from([
            RouteAssemblySelectionKind::Primary,
            RouteAssemblySelectionKind::Admin,
            RouteAssemblySelectionKind::Internal,
        ]))
    .then_some(selections)
}

fn listener_selection_pattern_kind(
    pattern: &syn::Pat,
    internal_selection_match: bool,
) -> Option<ListenerSelectionKind> {
    let syn::Pat::Path(path) = pattern else {
        return None;
    };
    match path.path.segments.last()?.ident.to_string().as_str() {
        "Primary" if path_contains_segment(&path.path, "ListenerKind") => {
            Some(ListenerSelectionKind::Primary)
        }
        "Admin" if path_contains_segment(&path.path, "ListenerKind") => {
            Some(ListenerSelectionKind::Admin)
        }
        "ServiceToken"
            if internal_selection_match
                && path_contains_segment(&path.path, "InternalAuthSelection") =>
        {
            Some(ListenerSelectionKind::InternalServiceToken)
        }
        _ => None,
    }
}

fn exact_access_binding_definition(function: &syn::ImplItemFn) -> bool {
    if function.sig.receiver().is_none()
        || !return_type_contains_ident(&function.sig.output, "ProfileBinding")
    {
        return false;
    }
    let mut selection_names = function.sig.inputs.iter().filter_map(|input| {
        let syn::FnArg::Typed(argument) = input else {
            return None;
        };
        if !type_contains_ident(argument.ty.as_ref(), "AccessTokenProfileSelection") {
            return None;
        }
        let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
            return None;
        };
        Some(pattern.ident.to_string())
    });
    let Some(selection) = selection_names.next() else {
        return false;
    };
    if selection_names.next().is_some() {
        return false;
    }
    let Some(syn::Expr::Match(mapping)) = sole_block_expression(&function.block) else {
        return false;
    };
    if simple_path_ident(ungroup_profile_expression(mapping.expr.as_ref())).as_deref()
        != Some(selection.as_str())
        || mapping.arms.len() != 2
    {
        return false;
    }

    let mut observed = BTreeSet::new();
    for arm in &mapping.arms {
        if arm.guard.is_some() || matches!(arm.body.as_ref(), syn::Expr::Block(_)) {
            return false;
        }
        let Some(kind) = access_selection_pattern_kind(&arm.pat) else {
            return false;
        };
        if !profile_mapping_expression_is_exact(arm.body.as_ref(), kind) {
            return false;
        }
        observed.insert(kind);
    }
    observed
        == BTreeSet::from([
            TokenProfileBridgeKind::RssAccess,
            TokenProfileBridgeKind::FederatedAccess,
        ])
}

fn exact_service_binding_definition(function: &syn::ImplItemFn) -> bool {
    if function.sig.receiver().is_none()
        || function
            .sig
            .inputs
            .iter()
            .any(|input| matches!(input, syn::FnArg::Typed(_)))
        || !return_type_contains_ident(&function.sig.output, "ProfileBinding")
    {
        return false;
    }
    let Some(expression) = sole_block_expression(&function.block) else {
        return false;
    };
    !matches!(expression, syn::Expr::Block(_))
        && profile_mapping_expression_is_exact(expression, TokenProfileBridgeKind::ServiceToken)
}

fn sole_block_expression(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(expression, None)] => Some(expression),
        _ => None,
    }
}

fn access_selection_pattern_kind(pattern: &syn::Pat) -> Option<TokenProfileBridgeKind> {
    let syn::Pat::Path(path) = pattern else {
        return None;
    };
    if !path_contains_segment(&path.path, "AccessTokenProfileSelection") {
        return None;
    }
    match path.path.segments.last()?.ident.to_string().as_str() {
        "RssAccess" => Some(TokenProfileBridgeKind::RssAccess),
        "FederatedAccess" => Some(TokenProfileBridgeKind::FederatedAccess),
        _ => None,
    }
}

#[derive(Default)]
struct ProfileMappingExpressionEvidence {
    rss_fields: usize,
    federated_fields: usize,
    service_fields: usize,
    rss_variants: usize,
    federated_variants: usize,
    service_variants: usize,
}

impl ProfileMappingExpressionEvidence {
    fn is_exact(&self, expected: TokenProfileBridgeKind) -> bool {
        let fields = [self.rss_fields, self.federated_fields, self.service_fields];
        let variants = [
            self.rss_variants,
            self.federated_variants,
            self.service_variants,
        ];
        let index = match expected {
            TokenProfileBridgeKind::RssAccess => 0,
            TokenProfileBridgeKind::FederatedAccess => 1,
            TokenProfileBridgeKind::ServiceToken => 2,
        };
        fields[index] == 1
            && variants[index] == 1
            && fields.iter().sum::<usize>() == 1
            && variants.iter().sum::<usize>() == 1
    }
}

impl<'ast> syn::visit::Visit<'ast> for ProfileMappingExpressionEvidence {
    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if matches!(node.base.as_ref(), syn::Expr::Path(path) if path.path.is_ident("self")) {
            let name = match &node.member {
                syn::Member::Named(name) => name.to_string(),
                syn::Member::Unnamed(_) => String::new(),
            };
            match name.as_str() {
                "rss_access" => self.rss_fields = self.rss_fields.saturating_add(1),
                "federated_access" => {
                    self.federated_fields = self.federated_fields.saturating_add(1);
                }
                "service_token" => {
                    self.service_fields = self.service_fields.saturating_add(1);
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if path_contains_segment(&node.path, "ProfileBinding") {
            match node
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
            {
                Some(name) if name == "RssAccess" => {
                    self.rss_variants = self.rss_variants.saturating_add(1);
                }
                Some(name) if name == "FederatedAccess" => {
                    self.federated_variants = self.federated_variants.saturating_add(1);
                }
                Some(name) if name == "ServiceToken" => {
                    self.service_variants = self.service_variants.saturating_add(1);
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_path(self, node);
    }
}

fn profile_mapping_expression_is_exact(
    expression: &syn::Expr,
    expected: TokenProfileBridgeKind,
) -> bool {
    let mut evidence = ProfileMappingExpressionEvidence::default();
    syn::visit::Visit::visit_expr(&mut evidence, expression);
    evidence.is_exact(expected)
}

fn return_type_contains_ident(output: &syn::ReturnType, expected: &str) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    type_contains_ident(ty.as_ref(), expected)
}

fn type_contains_ident(ty: &syn::Type, expected: &str) -> bool {
    struct TypeIdentVisitor<'a> {
        expected: &'a str,
        found: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for TypeIdentVisitor<'_> {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            self.found |= node
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == self.expected);
            if !self.found {
                syn::visit::visit_type_path(self, node);
            }
        }
    }
    let mut visitor = TypeIdentVisitor {
        expected,
        found: false,
    };
    syn::visit::Visit::visit_type(&mut visitor, ty);
    visitor.found
}

fn ungroup_profile_expression(expression: &syn::Expr) -> &syn::Expr {
    match expression {
        syn::Expr::Group(group) => ungroup_profile_expression(group.expr.as_ref()),
        syn::Expr::Paren(paren) => ungroup_profile_expression(paren.expr.as_ref()),
        syn::Expr::Try(try_expression) => ungroup_profile_expression(try_expression.expr.as_ref()),
        _ => expression,
    }
}

fn simple_path_ident(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    path.path.get_ident().map(ToString::to_string)
}

fn profile_carrier_binding(pattern: &syn::Pat) -> Option<String> {
    let syn::Pat::TupleStruct(tuple) = pattern else {
        return None;
    };
    if !path_ends_with(&tuple.path, "Token")
        || !path_contains_segment(&tuple.path, "ListenerAuthBinding")
        || tuple.elems.len() != 1
    {
        return None;
    }
    let syn::Pat::Ident(binding) = tuple.elems.first()? else {
        return None;
    };
    Some(binding.ident.to_string())
}

fn call_path_ends_with(func: &syn::Expr, segment: &str) -> bool {
    matches!(
        func,
        syn::Expr::Path(path)
            if path
                .path
                .segments
                .last()
                .is_some_and(|last| last.ident == segment)
    )
}

fn call_path_last_segment(func: &syn::Expr) -> Option<String> {
    match func {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn call_path_contains_segment(func: &syn::Expr, segment: &str) -> bool {
    matches!(func, syn::Expr::Path(path) if path_contains_segment(&path.path, segment))
}

fn path_contains_segment(path: &syn::Path, segment: &str) -> bool {
    path_contains_segment_matching(path, |actual| actual == segment)
}

fn path_ends_with(path: &syn::Path, segment: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|actual| actual.ident == segment)
}

fn path_contains_segment_matching(path: &syn::Path, f: impl Fn(&str) -> bool) -> bool {
    path.segments
        .iter()
        .any(|segment| f(&segment.ident.to_string()))
}

fn ident_contains(ident: &syn::Ident, needle: &str) -> bool {
    ident.to_string().contains(needle)
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("test") {
                found = true;
            }
            Ok(())
        });
        found
    })
}

fn required_features(provider: &DiportProvider) -> Vec<&str> {
    let mut features: Vec<&str> = provider
        .required_features
        .iter()
        .map(String::as_str)
        .collect();
    features.extend(provider.provider.required_features());
    features.sort_unstable();
    features.dedup();
    features
}

fn dependency_features(cargo_toml: &toml::Value, dependency: &str) -> Option<BTreeSet<String>> {
    let dep = cargo_toml
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .and_then(|deps| deps.get(dependency))?;
    let features = dep
        .as_table()
        .and_then(|table| table.get("features"))
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(features)
}

fn provider_table_line(src: &str, provider_index: usize) -> usize {
    let mut seen = 0;
    for (line_index, line) in src.lines().enumerate() {
        if line.trim() == "[[diportProviders]]" {
            if seen == provider_index {
                return line_index + 1;
            }
            seen += 1;
        }
    }
    1
}

fn rel_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;
    use std::fs;
    use std::path::Path;

    #[cfg(unix)]
    #[test]
    fn assembly_lock_discovery_rejects_non_utf8_name() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = std::ffi::OsString::from_vec(vec![b'n', b'a', b'm', b'e', 0xff]);
        assert!(assembly_name(invalid).is_err());
    }

    fn write(path: &Path, text: &str) -> anyhow::Result<()> {
        fs::write(path, text)?;
        Ok(())
    }

    fn write_assembly(root: &Path, manifest: &str, cargo: &str) -> anyhow::Result<()> {
        let dir = root.join("assemblies/runtime");
        fs::create_dir_all(&dir)?;
        write(&dir.join("assembly.toml"), manifest)?;
        write(&dir.join("Cargo.toml"), cargo)?;
        Ok(())
    }

    fn write_runtime_src(root: &Path, path: &str, text: &str) -> anyhow::Result<()> {
        let file = root.join("assemblies/runtime/src").join(path);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        write(&file, text)
    }

    fn valid_manifest_with_profile(profile: &str, provider_extra: &str) -> String {
        format!(
            r#"
name = "runtime"
profile = "{profile}"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "softca::InMemRevocationLedger"
providerCrate = "softca"
consumer = "deviceloop"
purpose = "device-certificate-revocation"
outputs = []
{provider_extra}
"#
        )
    }

    fn valid_manifest(provider_extra: &str) -> String {
        valid_manifest_with_profile("production", provider_extra)
    }

    fn manifest_with_intent() -> String {
        r#"
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "softca::InMemRevocationLedger"
providerCrate = "softca"
consumer = "deviceloop"
lifecycle = "draft"
durability = "ephemeral-memory"
purpose = "device-certificate-revocation"
outputs = []
"#
        .to_string()
    }

    fn manifest_with_domains(domains: &[&str]) -> String {
        let rendered = domains
            .iter()
            .map(|domain| format!(r#""{domain}""#))
            .collect::<Vec<_>>()
            .join(", ");
        manifest_with_intent().replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            &format!("domains = [{rendered}]"),
        )
    }

    fn domain_findings(
        root: &Path,
        manifest: &str,
        runtime_dependency_tables: &str,
        postgres_dependencies: &str,
    ) -> anyhow::Result<Vec<Finding>> {
        fs::create_dir_all(root)?;
        write(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = [
  "assemblies/runtime",
  "crates/identity",
  "crates/settings",
  "crates/audit",
  "adapters/postgres",
]
resolver = "2"
"#,
        )?;
        write_assembly(
            root,
            manifest,
            &format!(
                r#"[package]
name = "runtime"
version = "0.0.0"
edition = "2024"

{runtime_dependency_tables}
"#
            ),
        )?;
        write_runtime_src(root, "lib.rs", "pub fn fixture() {}")?;

        for domain in ["identity", "settings", "audit"] {
            let dir = root.join("crates").join(domain);
            fs::create_dir_all(dir.join("src"))?;
            write(
                &dir.join("Cargo.toml"),
                &format!(
                    r#"[package]
name = "{domain}"
version = "0.0.0"
edition = "2024"
"#
                ),
            )?;
            write(&dir.join("src/lib.rs"), "pub fn fixture() {}")?;
        }

        let postgres_dir = root.join("adapters/postgres");
        fs::create_dir_all(postgres_dir.join("src"))?;
        write(
            &postgres_dir.join("Cargo.toml"),
            &format!(
                r#"[package]
name = "postgres"
version = "0.0.0"
edition = "2024"

{postgres_dependencies}
"#
            ),
        )?;
        write(&postgres_dir.join("src/lib.rs"), "pub fn fixture() {}")?;

        let manifest_path = root.join("Cargo.toml");
        let manifest_arg = manifest_path.display().to_string();
        let output = crate::cmd::cargo_cmd(
            crate::cmd::CargoSubcommand::GenerateLockfile,
            &["--manifest-path", manifest_arg.as_str()],
            &[],
            Some(root),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
        anyhow::ensure!(
            output.status.success(),
            "generate fixture Cargo.lock failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let (_count, findings) = validate_root(root)?;
        Ok(findings
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.rule,
                    Rule::ActiveDomainDependency | Rule::InactiveDomainDependencyClosure
                )
            })
            .collect())
    }

    #[test]
    fn assembly_domain_metadata_indexes_all_workspace_features() {
        let args = cargo_metadata_args("/tmp/rss/Cargo.toml");
        assert!(
            args.contains(&"--all-features"),
            "workspace package classification must see the full compile surface: {args:?}"
        );
    }

    fn production_security_manifest(
        profile: &str,
        include_oidc: bool,
        include_vault_signer: bool,
        include_vault_keyprovider: bool,
    ) -> String {
        let topology = if profile == "production" {
            "durable-shared"
        } else {
            "demo"
        };
        let mut manifest = format!(
            r#"
name = "runtime"
profile = "{profile}"
domains = ["identity", "settings", "audit"]
topology = "{topology}"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []
"#
        );
        if include_oidc {
            manifest.push_str(
                r#"
[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#,
            );
        }
        if include_vault_signer {
            manifest.push_str(
                r#"
[[diportProviders]]
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = []
"#,
            );
        }
        if include_vault_keyprovider {
            manifest.push_str(
                r#"
[[diportProviders]]
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-configvalue-at-rest-encryption"
outputs = []
"#,
            );
        }
        manifest.push_str(
            r#"
[[diportProviders]]
id = "auth-audit-sink"
port = "diport::AuditSink"
provider = "postgres::PgAuthAuditSink"
providerCrate = "postgres"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "http-auth-decision-audit"
outputs = []
"#,
        );
        if profile == "production" {
            manifest.push_str(
                r#"
[[diportProviders]]
id = "event-publisher"
port = "diport::Publisher"
provider = "amqp::AmqpPublisher"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "outbox event publishing"
outputs = []

[[diportProviders]]
id = "event-subscriber"
port = "diport::AckableSubscriber"
provider = "amqp::AmqpSubscriber"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "manual-ack event subscriber workers"
outputs = []

[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = []

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = []
"#,
            );
        }
        manifest
    }

    const CARGO_SECURITY_BACKEND: &str = r#"[package]
name = "runtime"

[dependencies]
oidc = { path = "../../adapters/oidc", features = ["backend"] }
vault = { path = "../../adapters/vault", features = ["backend"] }
postgres = { path = "../../adapters/postgres", features = ["domain-identity", "domain-settings", "domain-audit"] }
crypto-adapter = { path = "../../adapters/crypto" }
redis = { path = "../../adapters/redis", features = ["backend"] }
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#;

    fn capability_manifest(
        profile: &str,
        topology: &str,
        domains: &[&str],
        providers: &str,
    ) -> String {
        let rendered_domains = domains
            .iter()
            .map(|domain| format!(r#""{domain}""#))
            .collect::<Vec<_>>()
            .join(", ");
        let empty_providers = if providers.trim().is_empty() {
            "diportProviders = []\n"
        } else {
            ""
        };
        format!(
            r#"
name = "runtime"
profile = "{profile}"
domains = [{rendered_domains}]
topology = "{topology}"
frameworkContracts = []
{empty_providers}

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []
{providers}
"#
        )
    }

    const CAPABILITY_CARGO_FULL: &str = r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres", features = ["domain-identity", "domain-settings", "domain-audit"] }
crypto-adapter = { path = "../../adapters/crypto" }
vault = { path = "../../adapters/vault", features = ["backend"] }
oidc = { path = "../../adapters/oidc", features = ["backend"] }
redis = { path = "../../adapters/redis", features = ["backend"] }
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#;

    const CAPABILITY_DOMAIN_PROVIDERS: &str = r#"
[[diportProviders]]
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = []

[[diportProviders]]
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-configvalue-at-rest-encryption"
outputs = []

[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []

[[diportProviders]]
id = "auth-audit-sink"
port = "diport::AuditSink"
provider = "postgres::PgAuthAuditSink"
providerCrate = "postgres"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "http-auth-decision-audit"
outputs = []
"#;

    const CAPABILITY_REPLAY_STORE_PROVIDER: &str = r#"
[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#;

    const IDENTITYAUDIT_MANIFEST: &str =
        include_str!("../../assemblies/identityaudit/assembly.toml");
    const IDENTITYAUDIT_CARGO: &str = include_str!("../../assemblies/identityaudit/Cargo.toml");
    const SETTINGSONLY_MANIFEST: &str = include_str!("../../assemblies/settingsonly/assembly.toml");
    const SETTINGSONLY_CARGO: &str = include_str!("../../assemblies/settingsonly/Cargo.toml");

    const CAPABILITY_EVENT_TRANSPORT_PROVIDERS: &str = r#"
[[diportProviders]]
id = "event-publisher"
port = "diport::Publisher"
provider = "amqp::AmqpPublisher"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "outbox event publishing"
outputs = []

[[diportProviders]]
id = "event-subscriber"
port = "diport::AckableSubscriber"
provider = "amqp::AmqpSubscriber"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "manual-ack event subscriber workers"
outputs = []
"#;

    const CAPABILITY_DISTRIBUTED_PROVIDERS: &str = r#"
[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = []

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = []
"#;

    fn required_capability_findings(manifest: &str, cargo: &str) -> anyhow::Result<Vec<Finding>> {
        let root = unique_tmp("assembly-capabilities");
        write_assembly(&root, manifest, cargo)?;
        let (_count, findings) = validate_root(&root)?;
        Ok(findings
            .into_iter()
            .filter(|finding| finding.rule == Rule::RequiredCapability)
            .collect())
    }

    fn assert_required_capability(findings: &[Finding], domain: &str, capability: &str) {
        assert!(
            findings.iter().any(|finding| {
                finding.detail.contains(&format!("domain={domain}"))
                    && finding.detail.contains(&format!("capability={capability}"))
            }),
            "missing RequiredCapability finding for domain={domain} capability={capability}: {findings:?}"
        );
    }

    /// INVARIANT: ASSEMBLY-REQUIRED-CAPABILITY-01 { level = "Medium", exec = "verify", source = "code" } —
    /// required capability 表必须显式覆盖每个 workspace domain；新增 domain 不得静默漏管。
    #[test]
    fn assembly_capabilities_table_covers_all_domain_crates() {
        let domains: Vec<_> = required_capability_domain_specs()
            .iter()
            .map(|spec| spec.domain)
            .collect();
        assert_eq!(domains, crate::layers::DOMAIN_CRATES);
    }

    #[test]
    fn assembly_capabilities_runtime_like_manifest_passes() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["identity", "settings", "audit"],
            &format!(
                "{CAPABILITY_DOMAIN_PROVIDERS}{CAPABILITY_REPLAY_STORE_PROVIDER}{CAPABILITY_EVENT_TRANSPORT_PROVIDERS}{CAPABILITY_DISTRIBUTED_PROVIDERS}"
            ),
        );
        let findings = required_capability_findings(&manifest, CAPABILITY_CARGO_FULL)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn runtime_pdp_requires_durable_replay_store_provider() -> anyhow::Result<()> {
        let manifest =
            capability_manifest("demo", "demo", &["identity"], CAPABILITY_DOMAIN_PROVIDERS);
        let root = unique_tmp("assembly-runtime-pdp-missing-replay-store");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::PdpReplayStoreCapability),
            "runtime Pdp without durable replay provider must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_pdp_rejects_wrong_replay_store_provider() -> anyhow::Result<()> {
        let wrong_provider = CAPABILITY_REPLAY_STORE_PROVIDER.replace(
            "postgres::PgServiceTokenReplayStore",
            "postgres::PgCasStore",
        );
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            &format!("{CAPABILITY_DOMAIN_PROVIDERS}{wrong_provider}"),
        );
        let root = unique_tmp("assembly-runtime-pdp-wrong-replay-store");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::PdpReplayStoreCapability),
            "wrong provider must not satisfy replay capability: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_pdp_rejects_ephemeral_replay_store_provider() -> anyhow::Result<()> {
        let ephemeral = CAPABILITY_REPLAY_STORE_PROVIDER.replace("persistent", "ephemeral-memory");
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            &format!("{CAPABILITY_DOMAIN_PROVIDERS}{ephemeral}"),
        );
        let root = unique_tmp("assembly-runtime-pdp-ephemeral-replay-store");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::PdpReplayStoreCapability),
            "ephemeral declaration must not satisfy replay capability: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_capabilities_identityaudit_closure_is_non_vacuous() -> anyhow::Result<()> {
        let findings = required_capability_findings(IDENTITYAUDIT_MANIFEST, IDENTITYAUDIT_CARGO)?;
        assert!(
            findings.is_empty(),
            "green identityaudit closure: {findings:?}"
        );

        for (cargo, manifest, domain, capability) in [
            (
                IDENTITYAUDIT_CARGO.replace(
                    "postgres = { path = \"../../adapters/postgres\", features = [\"domain-identity\", \"domain-audit\"] }\n",
                    "",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "identity",
                "Pg",
            ),
            (
                IDENTITYAUDIT_CARGO.replace(
                    "[\"domain-identity\", \"domain-audit\"]",
                    "[\"domain-audit\"]",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "identity",
                "Pg",
            ),
            (
                IDENTITYAUDIT_CARGO.replace(
                    "[\"domain-identity\", \"domain-audit\"]",
                    "[\"domain-identity\"]",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "audit",
                "Pg",
            ),
            (
                IDENTITYAUDIT_CARGO.replace(
                    "crypto-adapter = { path = \"../../adapters/crypto\" }\n",
                    "",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "audit",
                "MacVerifier",
            ),
            (
                IDENTITYAUDIT_CARGO.to_owned(),
                IDENTITYAUDIT_MANIFEST.replace(
                    "provider = \"vault::VaultSigner\"",
                    "provider = \"vault::VaultKeyProvider\"",
                ),
                "identity",
                "Signer",
            ),
            (
                IDENTITYAUDIT_CARGO.to_owned(),
                IDENTITYAUDIT_MANIFEST.replace(
                    "provider = \"oidc::OidcProvider\"",
                    "provider = \"vault::VaultSigner\"",
                ),
                "identity",
                "Pdp",
            ),
            (
                IDENTITYAUDIT_CARGO.to_owned(),
                IDENTITYAUDIT_MANIFEST.replace(
                    "provider = \"postgres::PgAuthAuditSink\"",
                    "provider = \"postgres::PgCasStore\"",
                ),
                "audit",
                "AuthAuditSink",
            ),
        ] {
            let findings = required_capability_findings(&manifest, &cargo)?;
            assert_required_capability(&findings, domain, capability);
        }
        Ok(())
    }

    #[test]
    fn assembly_capabilities_settings_requires_vault_keyprovider() -> anyhow::Result<()> {
        let manifest = capability_manifest("demo", "demo", &["settings"], "");
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
        )?;
        assert_required_capability(&findings, "settings", "VaultKeyProvider");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_settings_requires_domain_feature() -> anyhow::Result<()> {
        let findings = required_capability_findings(
            SETTINGSONLY_MANIFEST,
            &SETTINGSONLY_CARGO.replace("features = [\"domain-settings\"]", "features = []"),
        )?;
        assert_required_capability(&findings, "settings", "Pg");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("domain-settings")),
            "missing domain-settings feature must be explicit: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_capabilities_identity_requires_signer() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            r#"
[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
oidc = { path = "../../adapters/oidc", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "identity", "Signer");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_audit_requires_crypto_adapter_dependency() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["audit"],
            r#"
[[diportProviders]]
id = "auth-audit-sink"
port = "diport::AuditSink"
provider = "postgres::PgAuthAuditSink"
providerCrate = "postgres"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "http-auth-decision-audit"
outputs = []
"#,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
        )?;
        assert_required_capability(&findings, "audit", "MacVerifier");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_audit_requires_pg_auth_audit_sink() -> anyhow::Result<()> {
        let manifest = capability_manifest("demo", "demo", &["audit"], "");
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
crypto-adapter = { path = "../../adapters/crypto" }
"#,
        )?;
        assert_required_capability(&findings, "audit", "AuthAuditSink");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_required_provider_consumer_must_match() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            r#"
[[diportProviders]]
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = []

[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []
"#,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
vault = { path = "../../adapters/vault", features = ["backend"] }
oidc = { path = "../../adapters/oidc", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "identity", "Signer");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("consumer=settings")),
            "wrong consumer detail must be present: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_capabilities_durable_topology_requires_distributed_lock_and_cas()
    -> anyhow::Result<()> {
        let manifest = capability_manifest("demo", "durable-shared", &["contractreg"], "");
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"
"#,
        )?;
        assert_required_capability(&findings, "distributed", "LockStore");
        assert_required_capability(&findings, "distributed", "CasStore");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_durable_topology_requires_event_transport() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["contractreg"],
            CAPABILITY_DISTRIBUTED_PROVIDERS,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
redis = { path = "../../adapters/redis", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "distributed", "Publisher");
        assert_required_capability(&findings, "distributed", "AckableSubscriber");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_durable_topology_requires_exact_pg_cas() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["contractreg"],
            &format!(
                r#"{CAPABILITY_EVENT_TRANSPORT_PROVIDERS}
[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = []

[[diportProviders]]
id = "distributed-cas-store-alternative"
port = "diport::CasStore"
provider = "redis::RedisCasStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas-redis-alternative"
outputs = []
"#
            ),
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
redis = { path = "../../adapters/redis", features = ["backend"] }
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "distributed", "CasStore");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("redis::RedisCasStore")),
            "wrong CAS provider detail must be present: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_capabilities_required_provider_must_be_active_persistent() -> anyhow::Result<()> {
        for (case, lifecycle, durability) in [
            ("draft", "draft", "persistent"),
            ("ephemeral", "active", "ephemeral-memory"),
        ] {
            let manifest = capability_manifest(
                "demo",
                "demo",
                &["settings"],
                &format!(
                    r#"
[[diportProviders]]
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "{lifecycle}"
durability = "{durability}"
purpose = "settings-configvalue-at-rest-encryption"
outputs = []
"#
                ),
            );
            let findings = required_capability_findings(
                &manifest,
                r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
vault = { path = "../../adapters/vault", features = ["backend"] }
"#,
            )?;
            assert_required_capability(&findings, "settings", "VaultKeyProvider");
            assert!(
                findings.iter().any(|finding| finding.detail.contains(case)),
                "{case} detail must be present: {findings:?}"
            );
        }
        Ok(())
    }

    const SECURITY_CLOSEOUT_FULL_SOURCE: &str = r#"
fn build_runtime_oidc_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "primary-idp",
        "/etc/rss/oidc-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let readiness = jwks.readiness_handle();
    let _config = oidc::VerifierConfigBuilder::new("https://issuer", "rss")
        .keys_jwks(jwks);
    let _probe = OidcJwksReadyProbe::new(readiness);
}

fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}

fn wire_domain_transport_from() {
    let _ = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
    let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
}
"#;

    const SECURITY_CLOSEOUT_JWKS_ONLY_SOURCE: &str = r#"
fn build_runtime_oidc_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "primary-idp",
        "/etc/rss/oidc-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let readiness = jwks.readiness_handle();
    let _config = oidc::VerifierConfigBuilder::new("https://issuer", "rss")
        .keys_jwks(jwks);
    let _probe = OidcJwksReadyProbe::new(readiness);
}
"#;

    const SECURITY_CLOSEOUT_SPIFFE_ONLY_SOURCE: &str = r#"
fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}

fn wire_domain_transport_from() {
    let _ = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
    let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
}
"#;

    const SECURITY_CLOSEOUT_RUN_PATH_SOURCE: &str = r#"
fn build_rss_access_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "rss-access",
        "/etc/rss/rss-access-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let _config = oidc::VerifierConfigBuilder::<RssAccessProfile>::new("https://rss", "rss")
        .keys_jwks(jwks);
    RuntimeAccessProvider { resource_name: RSS_ACCESS_TOKEN_RESOURCE_NAME }
}

fn build_federated_access_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "federated-access",
        "/etc/rss/federated-access-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let _config = oidc::VerifierConfigBuilder::<FederatedAccessProfile>::new("https://federated", "federated")
        .keys_jwks(jwks);
    RuntimeAccessProvider { resource_name: FEDERATED_ACCESS_TOKEN_RESOURCE_NAME }
}

fn build_service_token_provider() {
    let _config = oidc::VerifierConfigBuilder::<ServiceTokenProfile>::new("https://service", "service")
        .keys_hs256(service_keys);
    RuntimeServiceTokenProvider { resource_name: SERVICE_TOKEN_RESOURCE_NAME }
}

fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}

fn wire_domain_transport_from() {
    let transport = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
    let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
    transport
}

fn run_startup() {
    let rss_access = build_rss_access_provider();
    let federated_access = build_federated_access_provider();
    let service_token = build_service_token_provider();
    let rss_provider = rss_access.provider();
    let federated_provider = federated_access.provider();
    let service_provider = service_token.provider();
    module.resources.push(rss_access.managed_resource());
    module.resources.push(federated_access.managed_resource());
    module.resources.push(service_token.managed_resource());
    registry.probe(
        RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
        Box::new(AccessTokenJwksReadyProbe::rss_access(rss_access.jwks_readiness())),
    ).unwrap();
    registry.probe(
        FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
        Box::new(AccessTokenJwksReadyProbe::federated_access(federated_access.jwks_readiness())),
    ).unwrap();
    let rss_binding = ProfileBinding::RssAccess(rss_provider);
    let federated_binding = ProfileBinding::FederatedAccess(federated_provider);
    let service_binding = ProfileBinding::ServiceToken(service_provider);
    let _ = apply_verify_bridge(routes, rss_binding);
    let _ = apply_verify_bridge(routes, federated_binding);
    let _ = apply_verify_bridge(routes, service_binding);
    let domain_transport = wire_domain_transport_from();
    module.merge(domain_transport.module_result().unwrap());
    let _ = mtls_config_from_env();
    let pg = ();
    let subscribers = Vec::new();
    let cfg = ();
    let distributed = wire_distributed(deps);
    let _ = wire_event_transport(&pg, distributed, subscribers, cfg);
    let _ = assemble_authed_routers();
}

fn run() {
    run_startup();
}
"#;

    const PROFILE_BINDING_MAPPING_SOURCE: &str = r#"
struct TokenProviderBindings {
    rss_access: Provider,
    federated_access: Provider,
    service_token: Provider,
}

impl TokenProviderBindings {
    fn access_binding(
        &self,
        selection: AccessTokenProfileSelection,
    ) -> ProfileBinding {
        match selection {
            AccessTokenProfileSelection::RssAccess => self
                .rss_access
                .map(|provider| ProfileBinding::RssAccess(provider)),
            AccessTokenProfileSelection::FederatedAccess => self
                .federated_access
                .map(|provider| ProfileBinding::FederatedAccess(provider)),
        }
    }

    fn service_binding(&self) -> ProfileBinding {
        self.service_token
            .map(|provider| ProfileBinding::ServiceToken(provider))
    }
}

fn apply_verify_bridge(routes: Routes, binding: ProfileBinding) {
    match binding {
        ProfileBinding::RssAccess(provider) => verify_rss(routes, provider),
        ProfileBinding::FederatedAccess(provider) => verify_federated(routes, provider),
        ProfileBinding::ServiceToken(provider) => verify_service(routes, provider),
    }
}

fn assemble(
    providers: &TokenProviderBindings,
    context: RouteAssemblyContext,
) {
    let RouteAssemblyContext {
        primary,
        admin,
        internal,
    } = context;
    let binding = match listener {
        ListenerKind::Primary => {
            ListenerAuthBinding::Token(providers.access_binding(primary))
        }
        ListenerKind::Admin => {
            ListenerAuthBinding::Token(providers.access_binding(admin))
        }
        ListenerKind::Internal => match internal {
            InternalAuthSelection::Mtls => ListenerAuthBinding::Mtls,
            InternalAuthSelection::ServiceToken => {
                ListenerAuthBinding::Token(providers.service_binding())
            }
        },
    };
    match binding {
        ListenerAuthBinding::Token(profile) => apply_verify_bridge(routes, profile),
        ListenerAuthBinding::Mtls => apply_mtls_verify_bridge(routes),
    }
}

fn run() {
    assemble(&providers, context);
}
"#;

    fn security_closeout_run_to_launch_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "    let _ = assemble_authed_routers();",
            "    let _ = assemble_authed_routers();\n    launch();",
        )
    }

    fn security_closeout_only_rss_carrier_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            r#"    let _ = apply_verify_bridge(routes, rss_binding);
    let _ = apply_verify_bridge(routes, federated_binding);
    let _ = apply_verify_bridge(routes, service_binding);"#,
            r#"    let binding = ListenerAuthBinding::Token(rss_binding);
    let _ = match binding {
        ListenerAuthBinding::Token(profile) => apply_verify_bridge(routes, profile),
        ListenerAuthBinding::Mtls => apply_mtls_verify_bridge(routes),
    };
    drop(federated_binding);
    drop(service_binding);"#,
        )
    }

    fn security_closeout_lifecycle_owner_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "fn run() {\n    run_startup();\n}",
            r#"struct RuntimeLifecycleOwner;

impl RuntimeLifecycleOwner {
    fn new() -> Self { Self }

    async fn run(self) {
        run_startup();
    }
}

pub async fn run() {
    RuntimeLifecycleOwner::new().run().await;
}"#,
        )
    }

    fn security_closeout_disconnected_free_run_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "fn run() {\n    run_startup();\n}",
            r#"struct DeadOwner;

impl DeadOwner {
    fn run(self) {
        run_startup();
    }
}

pub fn run() {}"#,
        )
    }

    const SECURITY_CLOSEOUT_LAUNCH_SOURCE: &str = r#"
fn launch() {
    launch_until();
}

fn launch_until() {
    bind_and_register();
}

fn bind_and_register() {
    let _ = mtls_config_from_env();
}

fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}
"#;

    #[test]
    fn manifest_rejects_unknown_fields() {
        let raw = manifest_with_intent().replace(
            "topology = \"durable-shared\"",
            "topology = \"durable-shared\"\nunknown = true",
        );
        assert!(AssemblyManifest::from_toml_str(&raw).is_err());
    }

    #[test]
    fn manifest_rejects_invalid_enums() {
        assert!(
            AssemblyManifest::from_toml_str(&valid_manifest(
                r#"lifecycle = "preview"
durability = "ephemeral-memory""#
            ))
            .is_err()
        );
        assert!(
            AssemblyManifest::from_toml_str(&valid_manifest(
                r#"lifecycle = "draft"
durability = "memory""#
            ))
            .is_err()
        );
    }

    #[test]
    fn manifest_rejects_unknown_diport_port() {
        assert!(
            AssemblyManifest::from_toml_str(
                &valid_manifest(
                    r#"lifecycle = "draft"
durability = "ephemeral-memory""#
                )
                .replace("diport::RevocationStore", "diport::RevocationStore ")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_accepts_domains_topology_and_listeners() -> anyhow::Result<()> {
        let manifest = AssemblyManifest::from_toml_str(&manifest_with_intent())?;
        let domains: Vec<_> = manifest
            .domains
            .iter()
            .map(AssemblyDomain::as_str)
            .collect();
        assert_eq!(domains, vec!["identity", "settings", "audit"]);
        assert_eq!(manifest.topology.as_str(), "durable-shared");
        let listeners: Vec<_> = manifest
            .listeners
            .iter()
            .map(|listener| listener.kind.as_str())
            .collect();
        assert_eq!(listeners, vec!["primary", "internal", "admin", "health"]);
        Ok(())
    }

    #[test]
    fn active_framework_contract_requires_one_exact_assembly_declaration() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-framework-contract");
        let contract_dir = root.join("contracts/http/_seed/v1");
        fs::create_dir_all(&contract_dir)?;
        write(
            &contract_dir.join("contract.toml"),
            &include_str!("../../contracts/http/_seed/v1/contract.toml")
                .replace("lifecycle = \"draft\"", "lifecycle = \"active\""),
        )?;
        write(&contract_dir.join("request.schema.json"), "{}")?;
        write(&contract_dir.join("response.schema.json"), "{}")?;
        write_assembly(
            &root,
            &manifest_with_intent(),
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;

        let (assemblies, _) = discover(&root)?;
        let missing = validate_framework_contracts(&root, &assemblies)?;
        assert!(
            missing
                .iter()
                .any(|finding| finding.rule == Rule::FrameworkContractServing)
        );

        let declared = manifest_with_intent().replace(
            "frameworkContracts = []",
            "frameworkContracts = [\"seed.echo\"]",
        );
        write_assembly(
            &root,
            &declared,
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let (assemblies, _) = discover(&root)?;
        assert!(validate_framework_contracts(&root, &assemblies)?.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_manifest_accepts_all_registered_domains() -> anyhow::Result<()> {
        let manifest =
            AssemblyManifest::from_toml_str(&manifest_with_domains(crate::layers::DOMAIN_CRATES))?;
        let domains: Vec<_> = manifest
            .domains
            .iter()
            .map(AssemblyDomain::as_str)
            .collect();
        assert_eq!(domains, crate::layers::DOMAIN_CRATES);
        Ok(())
    }

    #[test]
    fn assembly_manifest_requires_domains_topology_and_listeners() {
        assert!(
            AssemblyManifest::from_toml_str(
                r#"
name = "runtime"
profile = "demo"

[[diportProviders]]
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "softca::InMemRevocationLedger"
providerCrate = "softca"
consumer = "deviceloop"
lifecycle = "draft"
durability = "ephemeral-memory"
purpose = "device-certificate-revocation"
outputs = []
"#
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_rejects_unknown_domain() {
        assert!(
            AssemblyManifest::from_toml_str(
                &manifest_with_intent().replace("\"identity\"", "\"billing\"")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_validate_rejects_empty_domains() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-empty-domains");
        write_assembly(
            &root,
            &manifest_with_intent().replace(
                r#"domains = ["identity", "settings", "audit"]"#,
                "domains = []",
            ),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.iter().any(|f| f.rule == Rule::EmptyDomains),
            "empty domains must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_manifest_validate_rejects_duplicate_domains() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-duplicate-domains");
        write_assembly(
            &root,
            &manifest_with_intent().replace(
                r#"domains = ["identity", "settings", "audit"]"#,
                r#"domains = ["identity", "settings", "identity"]"#,
            ),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.iter().any(|f| f.rule == Rule::DuplicateDomain),
            "duplicate domains must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_active_manifest_domain_requires_direct_normal_dependency()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-missing-active");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity", "settings"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDomainDependency),
            "manifest domain missing from direct normal dependencies must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_dev_or_build_dependency_does_not_satisfy_active_domain() -> anyhow::Result<()>
    {
        for (case, dependency_table) in [
            (
                "dev",
                r#"[dev-dependencies]
identity = { path = "../../crates/identity" }
"#,
            ),
            (
                "build",
                r#"[build-dependencies]
identity = { path = "../../crates/identity" }
"#,
            ),
        ] {
            let root = unique_tmp(&format!("assembly-domain-{case}"));
            let findings = domain_findings(
                &root,
                &manifest_with_domains(&["identity"]),
                dependency_table,
                "",
            )?;
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule == Rule::ActiveDomainDependency),
                "{case} domain dependency must not satisfy active domain closure: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn assembly_domain_alias_or_package_rename_mismatch_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-alias");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
id = { package = "identity", path = "../../crates/identity" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDomainDependency),
            "alias/package rename must not satisfy active domain dependency: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_inactive_target_dependency_does_not_satisfy_active_domain()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-inactive-target");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[target.'cfg(any())'.dependencies]
identity = { path = "../../crates/identity" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDomainDependency),
            "current-target-inactive domain dependency must not satisfy active domain closure: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_inactive_direct_dependency_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-inactive-direct");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
settings = { path = "../../crates/settings" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::InactiveDomainDependencyClosure),
            "inactive direct domain dependency must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_all_features_optional_inactive_dependency_is_rejected() -> anyhow::Result<()>
    {
        let root = unique_tmp("assembly-domain-feature-optional");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
settings = { path = "../../crates/settings", optional = true }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::InactiveDomainDependencyClosure),
            "inactive domain resolved through an all-features optional edge must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_inactive_transitive_normal_dependency_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-inactive-transitive");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
postgres = { path = "../../adapters/postgres" }
"#,
            r#"[dependencies]
settings = { path = "../../crates/settings" }
"#,
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::InactiveDomainDependencyClosure),
            "inactive transitive normal domain dependency must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_declared_domains_with_normal_closure_pass() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-green");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity", "settings", "audit"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
settings = { path = "../../crates/settings" }
audit = { path = "../../crates/audit" }
"#,
            "",
        )?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn assembly_domain_real_workspace_closures_match_manifests() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let (assemblies, discovery_findings) = discover(&root)?;
        assert!(
            discovery_findings.is_empty(),
            "real workspace discovery should be clean: {discovery_findings:?}"
        );
        let metadata = load_workspace_metadata(&root)?.context("real workspace has Cargo.toml")?;
        assert_eq!(
            assemblies
                .iter()
                .map(|assembly| assembly.manifest.name.as_str())
                .collect::<Vec<_>>(),
            ["identityaudit", "runtime", "settingsonly"]
        );
        for assembly in &assemblies {
            let findings = validate_target_domain_closure(&root, assembly, &metadata)?;
            assert!(
                findings.is_empty(),
                "{} target closure findings: {findings:?}",
                assembly.manifest.name
            );
        }
        Ok(())
    }

    #[test]
    fn identityaudit_boundary_rejects_launch_and_transport_closure() {
        use crate::layers::Layer::{Adapter, Domain, Root};

        let targets = ["lib", "bin"].map(|kind| MetadataTarget {
            kind: vec![kind.to_owned()],
        });
        let forbidden = [
            ("settings", Domain),
            ("runtime", Root),
            ("amqp", Adapter),
            ("redis-adapter", Adapter),
            ("mqtt", Adapter),
            ("grpc", Adapter),
            ("httpd", Adapter),
        ];
        let packages = forbidden
            .map(|(package, layer)| (package.to_owned(), layer))
            .to_vec();
        let findings = validate_identityaudit_boundary(
            "assemblies/identityaudit/assembly.toml",
            "assemblies/identityaudit/Cargo.toml",
            &targets,
            &packages,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::IdentityAuditBoundary
                && finding.detail.contains("唯一 lib target")
        }));
        for (forbidden, _) in forbidden {
            assert!(findings.iter().any(|finding| {
                finding.rule == Rule::IdentityAuditBoundary
                    && finding.detail.contains(&format!("`{forbidden}`"))
            }));
        }
    }

    #[test]
    fn identityaudit_wire_domains_is_private() -> anyhow::Result<()> {
        let path = crate::workspace_root()?.join("assemblies/identityaudit/src/lib.rs");
        let syntax = syn::parse_file(&std::fs::read_to_string(path)?)?;
        assert!(syntax.items.iter().any(|item| matches!(
            item,
            syn::Item::Fn(function)
                if function.sig.ident == "wire_domains"
                    && matches!(function.vis, syn::Visibility::Inherited)
        )));
        Ok(())
    }

    #[test]
    fn assembly_manifest_rejects_unknown_topology() {
        assert!(
            AssemblyManifest::from_toml_str(
                &manifest_with_intent().replace("durable-shared", "single-node")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_rejects_unknown_listener() {
        assert!(
            AssemblyManifest::from_toml_str(
                &manifest_with_intent().replace("kind = \"primary\"", "kind = \"public\"")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_validate_rejects_empty_listeners() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-empty-listeners");
        let manifest = manifest_with_intent().replace(
            r#"
[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []
"#,
            "listeners = []\n",
        );
        write_assembly(
            &root,
            &manifest,
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.iter().any(|f| f.rule == Rule::EmptyListeners),
            "empty listeners must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_manifest_validate_rejects_duplicate_listeners() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-duplicate-listeners");
        write_assembly(
            &root,
            &manifest_with_intent().replace("kind = \"internal\"", "kind = \"primary\""),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.iter().any(|f| f.rule == Rule::DuplicateListener),
            "duplicate listeners must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_manifest_validate_rejects_name_mismatch() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-name-mismatch");
        write_assembly(
            &root,
            &manifest_with_intent().replace("name = \"runtime\"", "name = \"other\""),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ManifestNameMismatch),
            "manifest name must match assembly directory: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_crate_without_manifest_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-missing-manifest");
        let dir = root.join("assemblies/runtime");
        fs::create_dir_all(&dir)?;
        write(
            &dir.join("Cargo.toml"),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (count, findings) = validate_root(&root)?;
        assert_eq!(count, 0);
        assert!(
            findings.iter().any(|f| f.rule == Rule::MissingManifest),
            "assembly crate without assembly.toml must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn manifest_without_diport_providers_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-empty-providers");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "production"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"
frameworkContracts = []
diportProviders = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []
"#,
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::EmptyDiportProviders),
            "empty diportProviders must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_revocation_store_requires_persistent_durability() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-ephemeral");
        write_assembly(
            &root,
            &valid_manifest(
                r#"lifecycle = "active"
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
softca = { path = "../../adapters/softca" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RevocationDurability),
            "active RevocationStore ephemeral provider must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_revocation_store_requires_persistent_durability_even_when_draft()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-draft-ephemeral");
        write_assembly(
            &root,
            &valid_manifest(
                r#"lifecycle = "draft"
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        let finding = findings
            .iter()
            .find(|f| f.rule == Rule::RevocationDurability)
            .ok_or_else(|| anyhow::anyhow!("production ephemeral provider must fail"))?;
        assert!(
            finding
                .subject
                .contains("assemblies/runtime/assembly.toml:"),
            "{finding:?}"
        );
        assert!(finding.detail.contains("field=durability"), "{finding:?}");
        Ok(())
    }

    #[test]
    fn production_security_closeout_requires_critical_providers() -> anyhow::Result<()> {
        for (name, manifest, gate) in [
            (
                "assembly-production-security-missing-oidc",
                production_security_manifest("production", false, true, true),
                "gate=oidc-pdp",
            ),
            (
                "assembly-production-security-missing-vault-signer",
                production_security_manifest("production", true, false, true),
                "gate=vault-signer",
            ),
            (
                "assembly-production-security-missing-vault-keyprovider",
                production_security_manifest("production", true, true, false),
                "gate=vault-keyprovider",
            ),
        ] {
            let root = unique_tmp(name);
            write_assembly(&root, &manifest, CARGO_SECURITY_BACKEND)?;
            write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_FULL_SOURCE)?;

            let (_count, findings) = validate_root(&root)?;
            assert!(
                findings.iter().any(|f| {
                    f.rule == Rule::ProductionSecurityCriticalProvider && f.detail.contains(gate)
                }),
                "{gate} must be required for production security closeout: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn production_security_closeout_requires_jwks_runtime_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-missing-jwks");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_SPIFFE_ONLY_SOURCE)?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "production assembly without JWKS runtime evidence must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_requires_spiffe_mtls_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-missing-spiffe");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_JWKS_ONLY_SOURCE)?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "production assembly without SPIFFE/mTLS evidence must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_ignores_comment_and_string_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            r#"
// oidc::JwksKeySource::load_and_watch(...).keys_jwks(...) OidcJwksReadyProbe::new(...)
// httpd::MtlsServerConfig::from_spire(...) httpd::DomainHttpTransport::from_spire(...)
const BAIT: &str = "JwksKeySource::load_and_watch keys_jwks OidcJwksReadyProbe::new DOMAIN_TRANSPORT_READY_PROBE_NAME MtlsServerConfig::from_spire DomainHttpTransport::from_spire";

#[cfg(test)]
mod tests {
    fn test_bait() {
        let jwks = oidc::JwksKeySource::load_and_watch("id", "path", interval, token).unwrap();
        let _ = oidc::VerifierConfigBuilder::new("iss", "aud").keys_jwks(jwks);
        let _ = OidcJwksReadyProbe::new(handle);
        let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
        let _ = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
        let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
    }
}
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "comment/string/cfg(test) JWKS bait must not satisfy production evidence: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "comment/string/cfg(test) SPIFFE bait must not satisfy production evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_ignores_cfg_test_run_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-cfg-test-run-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            r#"
#[cfg(test)]
mod tests {
    fn build_runtime_oidc_provider() {
        let jwks = oidc::JwksKeySource::load_and_watch(
            "primary-idp",
            "/etc/rss/oidc-jwks.json",
            std::time::Duration::from_secs(60),
            tokio_util::sync::CancellationToken::new(),
        ).unwrap();
        let readiness = jwks.readiness_handle();
        let _config = oidc::VerifierConfigBuilder::new("https://issuer", "rss")
            .keys_jwks(jwks);
        RuntimeOidcProvider { readiness }
    }

    fn mtls_config_from_env() {
        let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
    }

    fn wire_domain_transport_from() {
        let transport = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
        let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
        transport
    }

    fn run() {
        let runtime_oidc = build_runtime_oidc_provider();
        let provider = runtime_oidc.provider();
        module.resources.push(runtime_oidc.managed_resource());
        registry.probe(
            oidc_jwks_probe_name,
            Box::new(OidcJwksReadyProbe::new(runtime_oidc.jwks_readiness())),
        ).unwrap();
        let domain_transport = wire_domain_transport_from();
        module.merge(domain_transport.module_result().unwrap());
        let _ = mtls_config_from_env();
        let _ = assemble_authed_routers(provider);
    }
}
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "cfg(test) run() JWKS bait must not satisfy production evidence: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "cfg(test) run() SPIFFE bait must not satisfy production evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_rejects_dead_helper_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-dead-helper");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_FULL_SOURCE)?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "dead helper JWKS evidence must not satisfy production closeout: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "dead helper SPIFFE evidence must not satisfy production closeout: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_rejects_each_missing_runtime_fact() -> anyhow::Result<()> {
        for (case, mutated) in [
            (
                "rss-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "build_rss_access_provider()",
                    "missing_rss_provider()",
                    2,
                ),
            ),
            (
                "federated-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "build_federated_access_provider()",
                    "missing_federated_provider()",
                    2,
                ),
            ),
            (
                "service-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "build_service_token_provider()",
                    "missing_service_provider()",
                    2,
                ),
            ),
            (
                "rss-binding",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace("ProfileBinding::RssAccess", "WrongBinding::RssAccess"),
            ),
            (
                "federated-binding",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "ProfileBinding::FederatedAccess",
                    "WrongBinding::FederatedAccess",
                ),
            ),
            (
                "service-binding",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace("ProfileBinding::ServiceToken", "WrongBinding::ServiceToken"),
            ),
            (
                "rss-probe",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "AccessTokenJwksReadyProbe::rss_access",
                    "WrongProbe::rss_access",
                ),
            ),
            (
                "federated-probe",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "AccessTokenJwksReadyProbe::federated_access",
                    "WrongProbe::federated_access",
                ),
            ),
            (
                "rss-probe-name",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
                    "WRONG_RSS_PROBE_NAME",
                ),
            ),
            (
                "federated-probe-name",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
                    "WRONG_FEDERATED_PROBE_NAME",
                ),
            ),
            (
                "rss-resource",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace("RSS_ACCESS_TOKEN_RESOURCE_NAME", "WRONG_RSS_RESOURCE_NAME"),
            ),
            (
                "federated-resource",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "FEDERATED_ACCESS_TOKEN_RESOURCE_NAME",
                    "WRONG_FEDERATED_RESOURCE_NAME",
                ),
            ),
            (
                "service-resource",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace("SERVICE_TOKEN_RESOURCE_NAME", "WRONG_SERVICE_RESOURCE_NAME"),
            ),
            (
                "resource-registration",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "module.resources.push(rss_access.managed_resource());",
                    "",
                    1,
                ),
            ),
        ] {
            let root = unique_tmp(&format!("assembly-token-profile-{case}"));
            write_assembly(
                &root,
                &production_security_manifest("production", true, true, true),
                CARGO_SECURITY_BACKEND,
            )?;
            write_runtime_src(&root, "lib.rs", &mutated)?;
            let (_count, findings) = validate_root(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
                "missing {case} must fail token-profile trust-chain validation: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn token_profile_gate_rejects_legacy_mixed_and_split_surfaces() -> anyhow::Result<()> {
        for (case, mutation, expected) in [
            (
                "legacy-env",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nconst LEGACY: &str = \"RSS_OIDC_ISSUER\";"
                ),
                Rule::TokenProfileLegacySurface,
            ),
            (
                "old-probe-comment",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\n// OIDC_JWKS_READY_PROBE_NAME = oidc_jwks_ready"
                ),
                Rule::TokenProfileLegacySurface,
            ),
            (
                "mixed-key-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace(".keys_hs256(service_keys)", ".keys(service_keys)"),
                Rule::TokenProfileKeyIsolation,
            ),
            (
                "split-provider-scheme",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "apply_verify_bridge(routes, rss_binding)",
                    "apply_verify_bridge(routes, rss_provider, RequiredScheme::RssAccessToken)",
                    1,
                ),
                Rule::TokenProfileBinding,
            ),
            (
                "generic-provider-type",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nfn bad(provider: Arc<OidcProvider>) {{ drop(provider); }}"
                ),
                Rule::TokenProfileBinding,
            ),
        ] {
            let root = unique_tmp(&format!("assembly-token-profile-{case}"));
            write_assembly(
                &root,
                &production_security_manifest("production", true, true, true),
                CARGO_SECURITY_BACKEND,
            )?;
            write_runtime_src(&root, "lib.rs", &mutation)?;
            let (_count, findings) = validate_root(&root)?;
            assert!(
                findings.iter().any(|finding| finding.rule == expected),
                "{case} must fail with {expected:?}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_rejects_bindings_discarded_before_bridge() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-token-profile-discarded-bindings");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        let source = security_closeout_only_rss_carrier_source();
        write_runtime_src(&root, "lib.rs", &source)?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
            "three constructors with only RSS entering the bridge must fail: {findings:?}"
        );
        Ok(())
    }

    fn profile_binding_mapping_evidence(
        case: &str,
        source: &str,
    ) -> anyhow::Result<SecurityCloseoutEvidence> {
        let root = unique_tmp(&format!("assembly-profile-binding-mapping-{case}"));
        write_runtime_src(&root, "lib.rs", source)?;
        security_closeout_evidence_from_sources(&root.join("assemblies/runtime"))
    }

    #[test]
    fn token_profile_carrier_requires_exact_typed_mapping() -> anyhow::Result<()> {
        let green = profile_binding_mapping_evidence("green", PROFILE_BINDING_MAPPING_SOURCE)?;
        assert!(green.rss_access_reaches_verify_bridge());
        assert!(green.federated_access_reaches_verify_bridge());
        assert!(green.service_token_reaches_verify_bridge());

        let swapped = PROFILE_BINDING_MAPPING_SOURCE
            .replacen(
                "ProfileBinding::RssAccess(provider)),",
                "ProfileBinding::__SwapPlaceholder(provider)),",
                1,
            )
            .replacen(
                "ProfileBinding::FederatedAccess(provider)),",
                "ProfileBinding::RssAccess(provider)),",
                1,
            )
            .replacen(
                "ProfileBinding::__SwapPlaceholder(provider)),",
                "ProfileBinding::FederatedAccess(provider)),",
                1,
            );
        let wildcard = PROFILE_BINDING_MAPPING_SOURCE.replace(
            "AccessTokenProfileSelection::FederatedAccess => self",
            "_ => self",
        );
        let alias = PROFILE_BINDING_MAPPING_SOURCE.replace(
            r#"AccessTokenProfileSelection::RssAccess => self
                .rss_access
                .map(|provider| ProfileBinding::RssAccess(provider)),"#,
            r#"AccessTokenProfileSelection::RssAccess => {
                let alias = self
                    .rss_access
                    .map(|provider| ProfileBinding::RssAccess(provider));
                alias
            },"#,
        );
        let wrong_receiver = PROFILE_BINDING_MAPPING_SOURCE.replace(
            "providers.access_binding(primary)",
            "decoy.access_binding(primary)",
        );
        let hardcoded = PROFILE_BINDING_MAPPING_SOURCE.replace(
            "providers.access_binding(primary)",
            "providers.access_binding(AccessTokenProfileSelection::RssAccess)",
        );
        let swapped_selection = PROFILE_BINDING_MAPPING_SOURCE
            .replace(
                "providers.access_binding(primary)",
                "providers.access_binding(__PrimaryPlaceholder)",
            )
            .replace(
                "providers.access_binding(admin)",
                "providers.access_binding(primary)",
            )
            .replace(
                "providers.access_binding(__PrimaryPlaceholder)",
                "providers.access_binding(admin)",
            );
        let selection_alias = PROFILE_BINDING_MAPPING_SOURCE
            .replace(
                "let binding = match listener {",
                "let selected = primary;\n    let binding = match listener {",
            )
            .replace(
                "providers.access_binding(primary)",
                "providers.access_binding(selected)",
            );
        let listener_wildcard =
            PROFILE_BINDING_MAPPING_SOURCE.replace("ListenerKind::Admin => {", "_ => {");
        let service_mismatch = PROFILE_BINDING_MAPPING_SOURCE.replacen(
            "ProfileBinding::ServiceToken(provider))",
            "ProfileBinding::RssAccess(provider))",
            1,
        );

        for (case, source) in [
            ("swapped", swapped),
            ("wildcard", wildcard),
            ("alias", alias),
            ("wrong-receiver", wrong_receiver),
            ("hardcoded-selection", hardcoded),
            ("swapped-selection", swapped_selection),
            ("selection-alias", selection_alias),
            ("listener-wildcard", listener_wildcard),
        ] {
            let evidence = profile_binding_mapping_evidence(case, &source)?;
            assert!(
                !evidence.rss_access_reaches_verify_bridge()
                    || !evidence.federated_access_reaches_verify_bridge(),
                "{case} must not certify both access-profile mappings"
            );
        }
        let service = profile_binding_mapping_evidence("service-mismatch", &service_mismatch)?;
        assert!(
            !service.service_token_reaches_verify_bridge(),
            "service binding must map the service provider field to ServiceToken"
        );
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_ignores_dead_profile_bridge_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-token-profile-dead-bridge-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        let source = security_closeout_only_rss_carrier_source();
        let source = format!(
            r#"{source}
fn dead_bridge_bait(federated_binding: ProfileBinding, service_binding: ProfileBinding) {{
    let _ = apply_verify_bridge(routes, federated_binding);
    let _ = apply_verify_bridge(routes, service_binding);
}}
"#
        );
        write_runtime_src(&root, "lib.rs", &source)?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
            "dead helper bridge calls must not associate discarded production bindings: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_ignores_comment_string_and_cfg_test_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-token-profile-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        let bait = format!(
            r#"
{SECURITY_CLOSEOUT_SPIFFE_ONLY_SOURCE}
// build_rss_access_provider build_federated_access_provider build_service_token_provider
const BAIT: &str = "ProfileBinding::RssAccess ProfileBinding::FederatedAccess ProfileBinding::ServiceToken AccessTokenJwksReadyProbe::rss_access AccessTokenJwksReadyProbe::federated_access";
#[cfg(test)]
fn run() {{
    let rss = build_rss_access_provider();
    let fed = build_federated_access_provider();
    let service = build_service_token_provider();
    module.resources.push(rss.managed_resource());
    module.resources.push(fed.managed_resource());
    module.resources.push(service.managed_resource());
    registry.probe(RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME, AccessTokenJwksReadyProbe::rss_access(rss.jwks_readiness()));
    registry.probe(FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME, AccessTokenJwksReadyProbe::federated_access(fed.jwks_readiness()));
    let _ = RSS_ACCESS_TOKEN_RESOURCE_NAME;
    let _ = FEDERATED_ACCESS_TOKEN_RESOURCE_NAME;
    let _ = SERVICE_TOKEN_RESOURCE_NAME;
    let _ = apply_verify_bridge(routes, ProfileBinding::RssAccess(rss.provider()));
    let _ = apply_verify_bridge(routes, ProfileBinding::FederatedAccess(fed.provider()));
    let _ = apply_verify_bridge(routes, ProfileBinding::ServiceToken(service.provider()));
}}
"#
        );
        write_runtime_src(&root, "lib.rs", &bait)?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
            "comment/string/cfg(test) facts must not satisfy token-profile trust chain: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_full_fixture_passes() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-green");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_RUN_PATH_SOURCE)?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn production_security_closeout_run_to_launch_fixture_passes() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-run-launch-green");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", &security_closeout_run_to_launch_source())?;
        write_runtime_src(&root, "launch.rs", SECURITY_CLOSEOUT_LAUNCH_SOURCE)?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn production_security_closeout_follows_qualified_lifecycle_owner_run() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-lifecycle-owner-green");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", &security_closeout_lifecycle_owner_source())?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn production_security_closeout_rejects_disconnected_free_run() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-disconnected-free-run");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            &security_closeout_disconnected_free_run_source(),
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "disconnected impl method named run must not lend JWKS evidence to free run: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "disconnected impl method named run must not lend SPIFFE evidence to free run: {findings:?}"
        );

        let associated_call_bait = security_closeout_disconnected_free_run_source()
            .replace("fn run_startup()", "fn decoy()")
            .replace("        run_startup();\n", "")
            .replace("pub fn run() {}", "pub fn run() { DeadOwner::decoy(); }");
        write_runtime_src(&root, "lib.rs", &associated_call_bait)?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "Type::method must not resolve to an evidence-bearing free function with the same name: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "associated/free function identities must remain disjoint for SPIFFE evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn demo_security_closeout_allows_missing_runtime_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-demo-security-no-evidence");
        write_assembly(
            &root,
            &production_security_manifest("demo", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn active_provider_crate_must_be_declared_in_assembly_cargo_toml() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-missing-provider-dep");
        write_assembly(
            &root,
            &valid_manifest(
                r#"lifecycle = "active"
durability = "persistent""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
deviceloop = { path = "../../crates/deviceloop" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderDependency),
            "active provider missing from Cargo.toml must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_provider_required_feature_must_be_enabled() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-missing-provider-feature");
        write_assembly(
            &root,
            &valid_manifest(
                r#"lifecycle = "active"
durability = "persistent""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
softca = { path = "../../adapters/softca" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderFeature),
            "active softca provider without backend feature must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn unknown_provider_is_rejected_by_typed_manifest() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-unknown-active-provider");
        write_assembly(
            &root,
            &valid_manifest_with_profile(
                "demo",
                r#"provider = "softca::MissingProvider"
lifecycle = "active"
durability = "ephemeral-memory""#,
            )
            .replace("provider = \"softca::InMemRevocationLedger\"\n", ""),
            r#"[package]
name = "runtime"

[dependencies]
softca = { path = "../../adapters/softca", features = ["backend"] }
"#,
        )?;

        let Err(error) = validate_root(&root) else {
            bail!("unknown typed provider must fail to parse");
        };
        assert!(
            format!("{error:#}").contains("softca::MissingProvider"),
            "typed provider diagnostic lost the rejected constructor: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn active_provider_declared_durability_must_match_known_provider() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-durability-mismatch");
        write_assembly(
            &root,
            &valid_manifest_with_profile(
                "demo",
                r#"lifecycle = "active"
durability = "persistent""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
softca = { path = "../../adapters/softca", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProviderDurabilityMismatch),
            "known ephemeral provider must not be declared persistent: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_provider_with_dependency_and_required_feature_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-provider-green");
        write_assembly(
            &root,
            &valid_manifest_with_profile(
                "demo",
                r#"lifecycle = "active"
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
softca = { path = "../../adapters/softca", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn active_rate_limiter_provider_passes() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-rate-limiter-active");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "softca::InMemRevocationLedger"
providerCrate = "softca"
consumer = "deviceloop"
lifecycle = "draft"
durability = "ephemeral-memory"
purpose = "device-certificate-revocation"
outputs = []

[[diportProviders]]
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting (pre-auth, DoS/brute-force 防护)"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
ratelimit = { path = "../../adapters/ratelimit" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.is_empty(),
            "active ratelimit::GovernorLimiter provider (no required_features) must pass: {findings:?}"
        );
        Ok(())
    }

    /// distributed Lock（redis, backend feature）+ Cas（postgres）provider 矩阵识别 + feature/crate 绑定绿测。
    /// 实 assembly.toml 现声明为 draft（#332 F4 无 consumer），本测以合成 active manifest 验证 validator 对
    /// Lock/CasStore active provider 的识别路径（go-live 翻转 active 时复用）。
    #[test]
    fn active_distributed_lock_cas_providers_pass() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-distributed-lock-cas-active");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = []

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
postgres = { path = "../../adapters/postgres" }
"#,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            r#"
pub struct DistributedRuntimeDeps;
	pub fn wire_distributed(_: &SharedRuntimeDeps) -> DistributedRuntimeDeps { DistributedRuntimeDeps }
	pub struct SharedRuntimeDeps;
	pub fn run_startup(deps: &SharedRuntimeDeps) {
	    let pg = ();
	    let subscribers = Vec::new();
	    let cfg = ();
	    let distributed: DistributedRuntimeDeps = wire_distributed(deps);
	    let _ = wire_event_transport(&pg, distributed, subscribers, cfg);
	}
	fn wire_event_transport(_: &(), _: DistributedRuntimeDeps, _: Vec<()>, _: ()) {}
	"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.is_empty(),
            "active distributed Lock/Cas providers (feature + providerCrate bound) must pass: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_distributed_provider_comment_or_outer_run_bait_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-distributed-string-evidence");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
"#,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            r#"
pub struct DistributedRuntimeDeps;
pub struct SharedRuntimeDeps;

// wire_distributed( DistributedRuntimeDeps wire_event_transport
const COMMENT_BAIT: &str = "wire_distributed(DistributedRuntimeDeps) wire_event_transport";

fn run(deps: &SharedRuntimeDeps) {
    let distributed: DistributedRuntimeDeps = wire_distributed(deps);
    let pg = ();
    let subscribers = Vec::new();
    let cfg = ();
    let _ = wire_event_transport(&pg, distributed, subscribers, cfg);
}

fn wire_distributed(_: &SharedRuntimeDeps) -> DistributedRuntimeDeps {
    DistributedRuntimeDeps
}
fn wire_event_transport(_: &(), _: DistributedRuntimeDeps, _: Vec<()>, _: ()) {}
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDistributedProviderConsumer),
            "comment/string/outer run bait must not satisfy the run_startup consumer guard: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_distributed_provider_without_composition_root_consumer_is_rejected()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-distributed-no-consumer");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDistributedProviderConsumer),
            "active distributed provider without consumer evidence must be rejected: {findings:?}"
        );
        Ok(())
    }

    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 { level = "Medium", exec = "verify", source = "code" }— provider↔providerCrate 绑定 red test（anti-vacuity）。
    /// `ratelimit::GovernorLimiter` 与 `providerCrate = "softca"` 不匹配，active 声明必须被拒。
    #[test]
    fn active_provider_with_wrong_provider_crate_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-crate-mismatch");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "softca"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
softca = { path = "../../adapters/softca" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProviderCrateMismatch),
            "provider↔providerCrate mismatch must be rejected: {findings:?}"
        );
        Ok(())
    }

    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 { level = "Medium", exec = "verify", source = "code" }— provider↔providerCrate 绑定正例（non-vacuous green path）。
    /// `ratelimit::GovernorLimiter` + `providerCrate = "ratelimit"` 正确绑定，不应产生 ProviderCrateMismatch。
    #[test]
    fn active_provider_with_correct_provider_crate_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-crate-correct");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
ratelimit = { path = "../../adapters/ratelimit" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .all(|f| f.rule != Rule::ProviderCrateMismatch),
            "correct providerCrate must not produce ProviderCrateMismatch: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn demo_draft_ephemeral_revocation_provider_is_allowed_without_dependency() -> anyhow::Result<()>
    {
        let root = unique_tmp("assembly-draft-ephemeral");
        write_assembly(
            &root,
            &valid_manifest_with_profile(
                "demo",
                r#"lifecycle = "draft"
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    // ---- #1251 eventbus 真传输 provider（diport::Publisher / diport::AckableSubscriber）----

    /// demo-profile manifest，单条 amqp transport provider（topology-gated durable 选型）。
    fn amqp_manifest(provider: &str, port: &str, lifecycle: &str, durability: &str) -> String {
        format!(
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "fixture-provider"
port = "{port}"
provider = "{provider}"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "{lifecycle}"
durability = "{durability}"
purpose = "eventbus-transport"
outputs = []
"#
        )
    }

    const CARGO_AMQP_BACKEND: &str = r#"[package]
name = "runtime"

[dependencies]
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#;

    const CARGO_AMQP_NO_BACKEND: &str = r#"[package]
name = "runtime"

[dependencies]
amqp = { path = "../../adapters/amqp" }
"#;

    #[test]
    fn amqp_publisher_active_persistent_with_backend_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-publisher-green");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpPublisher",
                "diport::Publisher",
                "active",
                "persistent",
            ),
            CARGO_AMQP_BACKEND,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn amqp_subscriber_active_persistent_with_backend_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-subscriber-green");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpSubscriber",
                "diport::AckableSubscriber",
                "active",
                "persistent",
            ),
            CARGO_AMQP_BACKEND,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn active_vault_signer_with_dependency_and_required_feature_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-vault-signer");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
vault = { path = "../../adapters/vault", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn active_vault_keyprovider_with_dependency_and_required_feature_is_allowed()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-vault-keyprovider");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-configvalue-at-rest-encryption"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
vault = { path = "../../adapters/vault", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn active_oidc_pdp_with_dependency_and_required_feature_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-oidc-pdp");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
oidc = { path = "../../adapters/oidc", features = ["backend"] }
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn active_s3_object_store_with_dependency_and_required_feature_is_allowed() -> anyhow::Result<()>
    {
        let root = unique_tmp("assembly-active-s3-object-store");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
id = "runtime-object-store"
port = "diport::ObjectStore"
provider = "s3::S3Store"
providerCrate = "s3"
requiredFeatures = ["backend"]
consumer = "runtime"
lifecycle = "active"
durability = "persistent"
purpose = "runtime-s3-readiness-canary"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
s3 = { path = "../../adapters/s3", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn amqp_subscriber_active_without_backend_feature_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-subscriber-no-backend");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpSubscriber",
                "diport::AckableSubscriber",
                "active",
                "persistent",
            ),
            CARGO_AMQP_NO_BACKEND,
        )?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderFeature),
            "active amqp subscriber without backend feature must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn amqp_subscriber_declared_ephemeral_durability_mismatch() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-subscriber-durability");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpSubscriber",
                "diport::AckableSubscriber",
                "active",
                "ephemeral-memory",
            ),
            CARGO_AMQP_BACKEND,
        )?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProviderDurabilityMismatch),
            "persistent amqp subscriber must not be declared ephemeral-memory: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn amqp_publisher_active_without_backend_feature_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-publisher-no-backend");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpPublisher",
                "diport::Publisher",
                "active",
                "persistent",
            ),
            CARGO_AMQP_NO_BACKEND,
        )?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderFeature),
            "active amqp publisher without backend feature must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn amqp_publisher_declared_ephemeral_durability_mismatch() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-publisher-durability");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpPublisher",
                "diport::Publisher",
                "active",
                "ephemeral-memory",
            ),
            CARGO_AMQP_BACKEND,
        )?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProviderDurabilityMismatch),
            "persistent amqp publisher must not be declared ephemeral-memory: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn amqp_provider_declared_on_wrong_port_rejected() -> anyhow::Result<()> {
        // amqp::AmqpPublisher 声明在 AckableSubscriber 端口上 ⇒ typed metadata 不匹配 ⇒ ActiveProviderPort。
        let root = unique_tmp("assembly-amqp-wrong-port");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpPublisher",
                "diport::AckableSubscriber",
                "active",
                "persistent",
            ),
            CARGO_AMQP_BACKEND,
        )?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.iter().any(|f| f.rule == Rule::ActiveProviderPort),
            "amqp publisher declared on subscriber port must be rejected: {findings:?}"
        );
        Ok(())
    }
}
