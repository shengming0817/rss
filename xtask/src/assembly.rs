//! `assembly validate` —— assembly-level DI provider 声明治理。
//!
//! DI-infra port（如 `diport::RevocationStore` / `diport::LockStore` / `diport::CasStore`）不是跨域 wire
//! contract，不放进 `contracts/**/contract.toml`。
//! 但 provider 选择属于组合根部署事实：哪个 assembly 注入哪个 provider、是否持久、是否已 active，必须有机器可读
//! 声明和 verify 门，避免生产在 dev/demo provider 上静默运行。

use anyhow::{Context, Result, bail};
use assembly_schema::{
    AssemblyDomain, AssemblyManifest, AssemblyProfile, AssemblyTopology, DiportPort,
    DiportProvider, ManifestValidationError, ProviderConstructor, ProviderConsumer,
    ProviderDurability, ProviderFailurePosture, ProviderLifecycle, ProviderScope,
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
    /// identityaudit 必须保持 #1797 的独立双域 binary/schema/journey/image/production closure。
    ///
    /// INVARIANT: IDENTITYAUDIT-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::identityaudit_executable_boundary_rejects_lib_only_shape", anti_vacuity = "tests::identityaudit_real_executable_artifact_closure_is_complete" } -- #1797 replaces the demo composition proof with one exact executable package and its closed production transport/artifact closure.
    IdentityAuditBoundary,
    /// settingsonly 必须保持 #1796 的独立 binary/schema/精确 journey/image/default-closure 闭包。
    ///
    /// INVARIANT: SETTINGSONLY-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::settingsonly_executable_boundary_rejects_each_incomplete_artifact_fact", anti_vacuity = "tests::settingsonly_real_executable_boundary_is_complete" } -- this target-specific gate closes only the settingsonly artifacts introduced by #1796; the cross-assembly artifact matrix and bijection remain owned by #1798.
    SettingsOnlyExecutableBoundary,
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
    /// active distributed provider 必须有真实 phase owner 的 consumer 接线证据。
    ///
    /// INVARIANT: ASSEMBLY-DISTRIBUTED-CONSUMER-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::active_distributed_provider_reordered_comment_or_test_bait_is_rejected", anti_vacuity = "tests::active_distributed_lock_cas_providers_pass" }— only the ordered `InfraBuilt::wire_domains` producer→consumer dataflow in `src/phase/domains.rs` is production evidence.
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
        let (closure_packages, test_support_enabled) =
            cargo_tree_default_normal_evidence(root, assembly, metadata)?;
        findings.extend(validate_identityaudit_boundary(
            &assembly.manifest_label,
            &assembly.cargo_label,
            &package.targets,
            &closure_packages,
        ));
        let schema_is_closed =
            identityaudit_schema_is_closed(&assembly.dir.join("config.schema.json"))?;
        let sample_is_regular_file =
            is_regular_file_without_symlink(&assembly.dir.join("identityaudit.example.toml"))?;
        let runbook_is_regular_file = is_regular_file_without_symlink(
            &root.join("docs/ops/202607251200-1797-identityaudit-runtime.md"),
        )?;
        let migration_runbook =
            std::fs::read_to_string(root.join("adapters/postgres/migrations/README.md"))
                .context("读取 identityaudit audit-chain migration runbook 失败")?;
        let key_pin_cutover_is_closed = identityaudit_key_pin_cutover_is_closed(&migration_runbook);
        let artifact_acceptance = identityaudit_artifact_acceptance_evidence(root)?;
        let (journey_target_declared, required_journey_test_declared) =
            identityaudit_journey_evidence(root)?;
        let dockerfile = std::fs::read_to_string(root.join("Dockerfile"))
            .context("读取 identityaudit image source Dockerfile 失败")?;
        findings.extend(validate_identityaudit_executable_evidence(
            IdentityAuditExecutableEvidence {
                test_support_enabled,
                schema_is_closed,
                sample_is_regular_file,
                runbook_is_regular_file,
                key_pin_cutover_is_closed,
                artifact_acceptance,
                journey_target_declared,
                required_journey_test_declared,
                dockerfile: &dockerfile,
            },
        ));
    }
    if assembly.manifest.name == "settingsonly" {
        let (closure_packages, test_support_enabled) =
            cargo_tree_default_normal_evidence(root, assembly, metadata)?;
        let schema_is_regular_file =
            is_regular_file_without_symlink(&assembly.dir.join("config.schema.json"))?;
        let sample_is_regular_file =
            is_regular_file_without_symlink(&assembly.dir.join("settingsonly.example.toml"))?;
        let runbook_is_regular_file = is_regular_file_without_symlink(
            &root.join("docs/ops/202607230700-1796-settingsonly-runtime.md"),
        )?;
        let artifact_acceptance = settingsonly_artifact_acceptance_evidence(root)?;
        let (journey_target_declared, required_journey_test_declared) =
            settingsonly_journey_evidence(root)?;
        let dockerfile = std::fs::read_to_string(root.join("Dockerfile"))
            .context("读取 settingsonly image source Dockerfile 失败")?;
        findings.extend(validate_settingsonly_executable_evidence(
            SettingsOnlyExecutableEvidence {
                targets: &package.targets,
                closure_packages: &closure_packages,
                test_support_enabled,
                schema_is_regular_file,
                sample_is_regular_file,
                runbook_is_regular_file,
                artifact_acceptance,
                journey_target_declared,
                required_journey_test_declared,
                dockerfile: &dockerfile,
            },
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
    validate_identityaudit_manifest_boundary(a, &mut findings);

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

            if a.manifest.name == "runtime"
                && is_active_distributed_provider(provider)
                && !has_distributed_consumer_evidence(a)
            {
                findings.push(finding(
                    Rule::ActiveDistributedProviderConsumer,
                    &subject,
                    "field=consumer active distributed Lock/CAS provider 必须在 src/phase/domains.rs 的唯一 InfraBuilt::wire_domains phase owner 有 consumer 证据：wire_distributed 结果须按序注入 wire_event_transport",
                ));
            }
        }
    }
    validate_required_capabilities(a, &mut findings);
    validate_pdp_replay_store_capability(a, &mut findings);
    // Production provider/JWKS closeout is semantic and applies independent of assembly name.
    // Internal mTLS and the three-profile trust chain are required only when the manifest actually
    // declares an Internal listener; subset production assemblies must not inherit that topology.
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
    let has_required_posture = a.manifest.diport_providers.iter().any(|candidate| {
        candidate.provider == provider
            && candidate.consumer.as_str() == consumer
            && candidate.lifecycle == ProviderLifecycle::Active
            && candidate.durability == ProviderDurability::Persistent
            && candidate.scope == Some(ProviderScope::ClusterGlobal)
            && candidate.failure_posture == Some(ProviderFailurePosture::FailClosed)
    });
    if !has_required_posture {
        findings.push(finding(
            Rule::PdpReplayStoreCapability,
            &a.manifest_label,
            format!(
                "field=diportProviders capability=PdpReplayStore expected active persistent cluster-global fail-closed `{provider}` for `{}` providerCrate `{}` consumer `{consumer}`; actual={}",
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
        error @ ManifestValidationError::ProviderRegistryMismatch { .. } => {
            findings.push(finding(
                Rule::InvalidDiportProvider,
                &a.manifest_label,
                error.to_string(),
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
            && candidate.consumer.as_str() == consumer
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
                || candidate.consumer.as_str() == consumer
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
    name: String,
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
    all_features: bool,
) -> Result<String> {
    let manifest = assembly.cargo_path.display().to_string();
    let depth_value = depth.map(|value| value.to_string());
    let mut args = vec![
        "tree",
        "--manifest-path",
        manifest.as_str(),
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}|{f}",
    ];
    if all_features {
        args.insert(5, "--all-features");
    }
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
    let stdout = cargo_tree_stdout(root, assembly, depth, true)?;
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
        if stdout
            .lines()
            .filter_map(|line| line.split_once('|'))
            .any(|(line, _)| {
                line.starts_with(&format!("{} ", package.name)) && line.ends_with(&path_marker)
            })
        {
            domains.insert(package.name.clone());
        }
    }
    Ok(domains)
}

fn cargo_tree_default_normal_evidence(
    root: &Path,
    assembly: &DiscoveredAssembly,
    metadata: &CargoMetadata,
) -> Result<(BTreeSet<String>, bool)> {
    let stdout = cargo_tree_stdout(root, assembly, None, false)?;
    let mut packages = BTreeSet::new();
    let mut test_support_enabled = false;
    for (package, features) in stdout.lines().filter_map(|line| line.split_once('|')) {
        if let Some(name) = package.split_whitespace().next() {
            packages.insert(name.to_owned());
        }
        test_support_enabled |= features
            .split(',')
            .map(str::trim)
            .any(|feature| feature == "test-support");
    }
    let workspace_packages = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .filter(|package| packages.contains(&package.name))
        .map(|package| package.name.clone())
        .collect();
    Ok((workspace_packages, test_support_enabled))
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
    closure_packages: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let exact_targets = targets.len() == 3
        && targets
            .iter()
            .any(|target| target.name == "identityaudit" && target.kind.as_slice() == ["lib"])
        && targets.iter().any(|target| {
            target.name == "identityaudit-server" && target.kind.as_slice() == ["bin"]
        })
        && targets.iter().any(|target| {
            target.name == "identityaudit_artifact_acceptance" && target.kind.as_slice() == ["test"]
        });
    if !exact_targets {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            manifest_label,
            format!(
                "field=package.targets {cargo_label} expected exactly lib `identityaudit`, bin `identityaudit-server`, and binary+image test `identityaudit_artifact_acceptance`"
            ),
        ));
    }

    let expected = IDENTITYAUDIT_ALLOWED_NORMAL_WORKSPACE_PACKAGES
        .iter()
        .map(|package| (*package).to_owned())
        .collect::<BTreeSet<_>>();
    let missing = expected
        .difference(closure_packages)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            manifest_label,
            format!(
                "field=default-normal-workspace-closure {cargo_label} missing required identityaudit packages: {}",
                missing.join(", ")
            ),
        ));
    }
    let unexpected = closure_packages
        .difference(&expected)
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            manifest_label,
            format!(
                "field=default-normal-workspace-closure {cargo_label} unexpected packages entered identityaudit: {}",
                unexpected.join(", ")
            ),
        ));
    }
    findings
}

fn validate_identityaudit_manifest_boundary(a: &DiscoveredAssembly, findings: &mut Vec<Finding>) {
    if a.manifest.name != "identityaudit" {
        return;
    }
    let listeners = a
        .manifest
        .listeners
        .iter()
        .map(|listener| {
            (
                listener.kind.as_str(),
                listener
                    .domains
                    .iter()
                    .map(AssemblyDomain::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let expected_listeners = vec![
        ("primary", vec!["identity"]),
        ("admin", vec!["audit"]),
        ("health", Vec::new()),
    ];
    if a.manifest.profile != AssemblyProfile::Production
        || a.manifest.topology != AssemblyTopology::DurableIsolated
        || listeners != expected_listeners
    {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            &a.manifest_label,
            format!(
                "field=profile/topology/listeners identityaudit requires profile=production, topology=durable-isolated, and exact Primary(identity)+Admin(audit)+Health(empty); actual profile={} topology={} listeners={listeners:?}",
                a.manifest.profile.as_str(),
                a.manifest.topology.as_str(),
            ),
        ));
    }
}

const IDENTITYAUDIT_ALLOWED_NORMAL_WORKSPACE_PACKAGES: &[&str] = &[
    "amqp",
    "assembly-schema",
    "audit",
    "audit-composition",
    "authn",
    "bootstrap",
    "consistency",
    "crypto-adapter",
    "deviceloop",
    "diagctx",
    "diport",
    "distributed",
    "eventexec",
    "eventing-composition",
    "generated",
    "httpd",
    "httpserve",
    "identity",
    "identity-composition",
    "identityaudit",
    "ids",
    "observ",
    "oidc",
    "postgres",
    "primitives",
    "prometheus-adapter",
    "ratelimit",
    "redis-adapter",
    "runctx",
    "runtimeexec",
    "secure",
    "securederive",
    "support",
    "tracewire",
    "vault",
    "vocab",
];

#[derive(Clone, Copy)]
struct IdentityAuditExecutableEvidence<'a> {
    test_support_enabled: bool,
    schema_is_closed: bool,
    sample_is_regular_file: bool,
    runbook_is_regular_file: bool,
    key_pin_cutover_is_closed: bool,
    artifact_acceptance: bool,
    journey_target_declared: bool,
    required_journey_test_declared: bool,
    dockerfile: &'a str,
}

fn validate_identityaudit_executable_evidence(
    evidence: IdentityAuditExecutableEvidence<'_>,
) -> Vec<Finding> {
    let subject = "assemblies/identityaudit";
    let mut findings = Vec::new();
    if evidence.test_support_enabled {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=default-normal-features `test-support` must stay disabled in the production closure",
        ));
    }
    if !evidence.schema_is_closed {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=config-schema expected a non-symlink closed object schema at assemblies/identityaudit/config.schema.json",
        ));
    }
    if !evidence.sample_is_regular_file {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=config-sample expected a non-symlink regular file at assemblies/identityaudit/identityaudit.example.toml",
        ));
    }
    if !evidence.runbook_is_regular_file {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=operator-runbook expected docs/ops/202607251200-1797-identityaudit-runtime.md",
        ));
    }
    if !evidence.key_pin_cutover_is_closed {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=audit-chain-key-cutover expected a forward-only ledger 72→73 hard-cutover and failure-recovery fence in adapters/postgres/migrations/README.md",
        ));
    }
    if !evidence.artifact_acceptance {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=artifact-acceptance expected exact binary+image executable assertions in assemblies/identityaudit/tests/artifact_acceptance.rs",
        ));
    }
    if !evidence.journey_target_declared || !evidence.required_journey_test_declared {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=journey expected explicit `identityaudit_runtime` target with non-ignored `identityaudit_login_audit_ready_sigterm_drain`",
        ));
    }
    if !identityaudit_docker_target_is_closed(evidence.dockerfile) {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=Dockerfile expected exact two-COPY + ENTRYPOINT identityaudit-runtime on the distroless nonroot base, with no EXPOSE/ENV/CMD/USER override, while runtime remains the default final stage",
        ));
    }
    findings
}

// INVARIANT: IDENTITYAUDIT-AUDIT-KEY-CUTOVER-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::identityaudit_key_pin_cutover_requires_forward_only_recovery_fence", anti_vacuity = "tests::identityaudit_real_executable_boundary_is_complete" } -- migration 0073 is a non-rolling forward-only cutover: old audit writers stop at ledger 72, only the new binary starts after ledger 73, and committed failures roll forward without compatibility defaults or down migrations.
fn identityaudit_key_pin_cutover_is_closed(migration_runbook: &str) -> bool {
    [
        "### 0073 audit-chain key pin",
        "ledger=72",
        "ledger=73",
        "停止全部旧 audit writer",
        "不得启动旧 binary",
        "新的前向修复 migration",
    ]
    .iter()
    .all(|required| migration_runbook.contains(required))
}

const SETTINGSONLY_ALLOWED_NORMAL_WORKSPACE_PACKAGES: &[&str] = &[
    "assembly-schema",
    "authn",
    "bootstrap",
    "consistency",
    "diagctx",
    "diport",
    "distributed",
    "eventexec",
    "generated",
    "httpd",
    "httpserve",
    "ids",
    "observ",
    "oidc",
    "postgres",
    "primitives",
    "prometheus-adapter",
    "ratelimit",
    "runctx",
    "runtimeexec",
    "secure",
    "securederive",
    "settings",
    "settings-composition",
    "settingsonly",
    "support",
    "tracewire",
    "vault",
    "vocab",
];

#[derive(Clone, Copy)]
struct SettingsOnlyExecutableEvidence<'a> {
    targets: &'a [MetadataTarget],
    closure_packages: &'a BTreeSet<String>,
    test_support_enabled: bool,
    schema_is_regular_file: bool,
    sample_is_regular_file: bool,
    runbook_is_regular_file: bool,
    artifact_acceptance: bool,
    journey_target_declared: bool,
    required_journey_test_declared: bool,
    dockerfile: &'a str,
}

fn validate_settingsonly_executable_evidence(
    evidence: SettingsOnlyExecutableEvidence<'_>,
) -> Vec<Finding> {
    let subject = "assemblies/settingsonly";
    let mut findings = Vec::new();
    let exact_targets = evidence.targets.len() == 3
        && evidence
            .targets
            .iter()
            .any(|target| target.name == "settingsonly" && target.kind.as_slice() == ["lib"])
        && evidence.targets.iter().any(|target| {
            target.name == "settingsonly-server" && target.kind.as_slice() == ["bin"]
        })
        && evidence.targets.iter().any(|target| {
            target.name == "settingsonly_artifact_acceptance" && target.kind.as_slice() == ["test"]
        });
    if !exact_targets {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=package.targets expected exactly lib `settingsonly`, bin `settingsonly-server`, and binary+image test `settingsonly_artifact_acceptance`",
        ));
    }

    let allowed = SETTINGSONLY_ALLOWED_NORMAL_WORKSPACE_PACKAGES
        .iter()
        .map(|package| (*package).to_owned())
        .collect::<BTreeSet<_>>();
    let missing = allowed
        .difference(evidence.closure_packages)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            format!(
                "field=default-normal-workspace-closure missing allowed settingsonly packages: {}",
                missing.join(", ")
            ),
        ));
    }
    let unexpected = evidence
        .closure_packages
        .difference(&allowed)
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            format!(
                "field=default-normal-workspace-closure unexpected packages entered settingsonly: {}",
                unexpected.join(", ")
            ),
        ));
    }
    if evidence.test_support_enabled {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=default-normal-features `test-support` must stay disabled in the production closure",
        ));
    }
    if !evidence.schema_is_regular_file {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=config-schema expected a non-symlink regular file at assemblies/settingsonly/config.schema.json",
        ));
    }
    if !evidence.sample_is_regular_file {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=config-sample expected a non-symlink regular file at assemblies/settingsonly/settingsonly.example.toml",
        ));
    }
    if !evidence.runbook_is_regular_file {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=operator-runbook expected docs/ops/202607230700-1796-settingsonly-runtime.md",
        ));
    }
    if !evidence.artifact_acceptance {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=artifact-acceptance expected exact binary+image --help tests plus the closed Docker build/include-ignored harness",
        ));
    }
    if !evidence.journey_target_declared || !evidence.required_journey_test_declared {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=journey expected explicit `settingsonly_runtime` target with non-ignored `settingsonly_lifecycle_fixture_ready_request_sigterm_drain`",
        ));
    }
    if !settingsonly_docker_target_is_closed(evidence.dockerfile) {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=Dockerfile expected exact two-COPY + ENTRYPOINT settingsonly-runtime on the distroless nonroot base, with no EXPOSE/ENV/CMD/USER override, while runtime remains the default final stage",
        ));
    }
    findings
}

fn is_regular_file_without_symlink(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("检查 {} 失败", path.display())),
    }
}

fn identityaudit_schema_is_closed(path: &Path) -> Result<bool> {
    if !is_regular_file_without_symlink(path)? {
        return Ok(false);
    }
    let source =
        std::fs::read_to_string(path).with_context(|| format!("读取 {} 失败", path.display()))?;
    let Ok(schema) = serde_json::from_str::<serde_json::Value>(&source) else {
        return Ok(false);
    };
    Ok(schema_objects_are_closed(&schema))
}

fn schema_objects_are_closed(value: &serde_json::Value) -> bool {
    let object_schema = value.get("type").is_some_and(|kind| {
        kind == "object"
            || kind
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "object"))
    });
    (!object_schema || value.get("additionalProperties") == Some(&serde_json::json!(false)))
        && match value {
            serde_json::Value::Array(values) => values.iter().all(schema_objects_are_closed),
            serde_json::Value::Object(fields) => fields.values().all(schema_objects_are_closed),
            _ => true,
        }
}

fn identityaudit_journey_evidence(root: &Path) -> Result<(bool, bool)> {
    let manifest_path = root.join("journeys/Cargo.toml");
    let manifest: toml::Value = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读取 {} 失败", manifest_path.display()))?
        .parse()
        .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
    let target_declared = manifest
        .get("test")
        .and_then(toml::Value::as_array)
        .is_some_and(|targets| {
            targets.iter().any(|target| {
                target.get("name").and_then(toml::Value::as_str) == Some("identityaudit_runtime")
                    && target.get("path").and_then(toml::Value::as_str)
                        == Some("tests/identityaudit_runtime.rs")
            })
        });
    let source_path = root.join("journeys/tests/identityaudit_runtime.rs");
    let required_test_declared = match std::fs::read_to_string(&source_path) {
        Ok(source) => identityaudit_journey_has_required_test(&source)
            .with_context(|| format!("解析 {} 失败", source_path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", source_path.display()));
        }
    };
    Ok((target_declared, required_test_declared))
}

fn identityaudit_journey_has_required_test(source: &str) -> Result<bool> {
    const REQUIRED_TEST: &str = "identityaudit_login_audit_ready_sigterm_drain";
    for item in syn::parse_file(source)?.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if function.sig.ident != REQUIRED_TEST
            || !function.attrs.iter().any(is_test_attribute)
            || function.attrs.iter().any(is_ignore_attribute)
            || function.attrs.iter().any(is_conditional_attribute)
        {
            continue;
        }
        let mut visitor = IdentityAuditJourneyVisitor::default();
        syn::visit::Visit::visit_block(&mut visitor, &function.block);
        return Ok(visitor.is_complete());
    }
    Ok(false)
}

#[derive(Default)]
struct IdentityAuditJourneyVisitor {
    runtime_start: bool,
    wait_until_ready: bool,
    login: bool,
    wait_for_auth_audit: bool,
    wait_for_session_created_hash_chain: bool,
    send_sigterm: bool,
    wait_for_drain: bool,
}

impl IdentityAuditJourneyVisitor {
    fn is_complete(&self) -> bool {
        self.runtime_start
            && self.wait_until_ready
            && self.login
            && self.wait_for_auth_audit
            && self.wait_for_session_created_hash_chain
            && self.send_sigterm
            && self.wait_for_drain
    }
}

impl<'ast> syn::visit::Visit<'ast> for IdentityAuditJourneyVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.runtime_start |= expression_path_ends_with(
            node.func.as_ref(),
            &["RuntimeFixture", "start"],
        ) && matches!(node.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident("providers"));
        self.wait_for_auth_audit |= expression_path_ends_with(
            node.func.as_ref(),
            &["wait_for_auth_audit"],
        ) && matches!(node.args.first(), Some(syn::Expr::Reference(pool)) if matches!(pool.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("pool")));
        self.wait_for_session_created_hash_chain |= expression_path_ends_with(
            node.func.as_ref(),
            &["wait_for_session_created_hash_chain"],
        ) && matches!(node.args.first(), Some(syn::Expr::Reference(pool)) if matches!(pool.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("pool")))
            && matches!(node.args.iter().nth(1), Some(syn::Expr::Reference(login)) if matches!(login.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("login")));
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let runtime = matches!(node.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident("runtime"));
        self.wait_until_ready |= runtime && node.method == "wait_until_ready";
        self.login |= runtime && node.method == "login";
        self.send_sigterm |= runtime && node.method == "send_sigterm";
        self.wait_for_drain |= runtime && node.method == "wait_for_drain";
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn identityaudit_artifact_acceptance_evidence(root: &Path) -> Result<bool> {
    let source_path = root.join("assemblies/identityaudit/tests/artifact_acceptance.rs");
    if !is_regular_file_without_symlink(&source_path)? {
        return Ok(false);
    }
    let source = std::fs::read_to_string(&source_path)
        .with_context(|| format!("读取 {} 失败", source_path.display()))?;
    identityaudit_artifact_source_is_closed(&source)
        .with_context(|| format!("解析 {} 失败", source_path.display()))
}

fn identityaudit_artifact_source_is_closed(source: &str) -> Result<bool> {
    let syntax = syn::parse_file(source)?;
    let mut binary = false;
    let mut image = false;
    let mut executable_contract = false;
    for item in syntax.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if function.sig.ident == "assert_executable_contract"
            && !function.attrs.iter().any(is_conditional_attribute)
        {
            let mut visitor = IdentityAuditExecutableContractVisitor::default();
            syn::visit::Visit::visit_block(&mut visitor, &function.block);
            executable_contract = visitor.is_complete();
        }
        if !function.attrs.iter().any(is_test_attribute)
            || function.attrs.iter().any(is_conditional_attribute)
        {
            continue;
        }
        if function.sig.ident == "identityaudit_server_binary_is_an_executable_artifact"
            && !function.attrs.iter().any(is_ignore_attribute)
            && identityaudit_artifact_contract_tail(&function, ArtifactContractKind::Binary)
        {
            binary = true;
        }
        if function.sig.ident == "identityaudit_runtime_image_is_an_executable_artifact"
            && function.attrs.iter().any(is_ignore_attribute)
            && identityaudit_artifact_contract_tail(&function, ArtifactContractKind::Image)
            && image_environment_is_loaded(&function)
        {
            image = true;
        }
    }
    Ok(binary && image && executable_contract)
}

#[derive(Default)]
struct IdentityAuditExecutableContractVisitor {
    help_execution: bool,
    missing_config_execution: bool,
    assertions: usize,
}

impl IdentityAuditExecutableContractVisitor {
    fn is_complete(&self) -> bool {
        self.help_execution && self.missing_config_execution && self.assertions >= 4
    }
}

impl<'ast> syn::visit::Visit<'ast> for IdentityAuditExecutableContractVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "execute"
            && matches!(node.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident("artifact"))
            && let Some(syn::Expr::Reference(arguments)) = node.args.first()
            && let syn::Expr::Array(arguments) = arguments.expr.as_ref()
        {
            match arguments.elems.first() {
                Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(argument),
                    ..
                })) if arguments.elems.len() == 1 && argument.value() == "--help" => {
                    self.help_execution = true;
                }
                None => self.missing_config_execution = true,
                _ => {}
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("assert") {
            self.assertions = self.assertions.saturating_add(1);
        }
        syn::visit::visit_macro(self, node);
    }
}

fn identityaudit_artifact_contract_tail(
    function: &syn::ItemFn,
    kind: ArtifactContractKind,
) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Call(assertion), None)) = function.block.stmts.last()
    else {
        return false;
    };
    if !expression_path_ends_with(assertion.func.as_ref(), &["assert_executable_contract"])
        || assertion.args.len() != 1
    {
        return false;
    }
    let Some(syn::Expr::Call(artifact)) = assertion.args.first() else {
        return false;
    };
    let expected = match kind {
        ArtifactContractKind::Binary => "Binary",
        ArtifactContractKind::Image => "Image",
    };
    if !expression_path_ends_with(artifact.func.as_ref(), &["Artifact", expected])
        || artifact.args.len() != 1
    {
        return false;
    }
    match (kind, artifact.args.first()) {
        (ArtifactContractKind::Binary, Some(syn::Expr::Macro(expression))) => {
            expression.mac.path.is_ident("env")
                && syn::parse2::<syn::LitStr>(expression.mac.tokens.clone())
                    .is_ok_and(|literal| literal.value() == "CARGO_BIN_EXE_identityaudit-server")
        }
        (ArtifactContractKind::Image, Some(syn::Expr::Reference(reference))) => {
            matches!(reference.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("image"))
        }
        _ => false,
    }
}

fn identityaudit_docker_target_is_closed(source: &str) -> bool {
    let stages = docker_stages(source);
    let builders = stages
        .iter()
        .filter(|stage| stage.name == "identityaudit-builder")
        .collect::<Vec<_>>();
    let runtimes = stages
        .iter()
        .filter(|stage| stage.name == "identityaudit-runtime")
        .collect::<Vec<_>>();
    let ([builder], [runtime]) = (builders.as_slice(), runtimes.as_slice()) else {
        return false;
    };
    let builder_ok = builder.base == "chef"
        && builder.instructions.iter().any(|instruction| {
            docker_instruction_arguments(instruction, "RUN").is_some_and(|arguments| {
                arguments.starts_with("cargo chef cook ")
                    && arguments.contains("--package identityaudit")
                    && arguments.contains("--bin identityaudit-server")
            })
        })
        && builder.instructions.iter().any(|instruction| {
            docker_instruction_arguments(instruction, "RUN").is_some_and(|arguments| {
                arguments.starts_with("cargo build ")
                    && arguments.contains("--package identityaudit")
                    && arguments.contains("--bin identityaudit-server")
            })
        });
    const RUNTIME_INSTRUCTIONS: &[(&str, &str)] = &[
        (
            "COPY",
            "--from=identityaudit-builder /app/target/release/identityaudit-server /usr/local/bin/identityaudit-server",
        ),
        (
            "COPY",
            "--from=identityaudit-builder /app/assemblies/identityaudit/config.schema.json /usr/share/rss/identityaudit/config.schema.json",
        ),
        ("ENTRYPOINT", "[\"/usr/local/bin/identityaudit-server\"]"),
    ];
    let runtime_ok = runtime.base == "gcr.io/distroless/cc-debian12:nonroot"
        && runtime.instructions.len() == RUNTIME_INSTRUCTIONS.len()
        && runtime.instructions.iter().zip(RUNTIME_INSTRUCTIONS).all(
            |(instruction, (keyword, arguments))| {
                docker_instruction_arguments(instruction, keyword) == Some(*arguments)
            },
        );
    let default_runtime_unchanged = stages.last().is_some_and(|stage| stage.name == "runtime");
    builder_ok && runtime_ok && default_runtime_unchanged
}

fn settingsonly_journey_evidence(root: &Path) -> Result<(bool, bool)> {
    let manifest_path = root.join("journeys/Cargo.toml");
    let manifest: toml::Value = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读取 {} 失败", manifest_path.display()))?
        .parse()
        .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
    let target_declared = manifest
        .get("test")
        .and_then(toml::Value::as_array)
        .is_some_and(|targets| {
            targets.iter().any(|target| {
                target.get("name").and_then(toml::Value::as_str) == Some("settingsonly_runtime")
                    && target.get("path").and_then(toml::Value::as_str)
                        == Some("tests/settingsonly_runtime.rs")
            })
        });
    let source_path = root.join("journeys/tests/settingsonly_runtime.rs");
    let required_test_declared = match std::fs::read_to_string(&source_path) {
        Ok(source) => settingsonly_journey_has_required_test(&source)
            .with_context(|| format!("解析 {} 失败", source_path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", source_path.display()));
        }
    };
    Ok((target_declared, required_test_declared))
}

fn settingsonly_journey_has_required_test(source: &str) -> Result<bool> {
    const REQUIRED_TEST: &str = "settingsonly_lifecycle_fixture_ready_request_sigterm_drain";
    Ok(syn::parse_file(source)?.items.into_iter().any(|item| {
        matches!(item, syn::Item::Fn(function)
            if function.sig.ident == REQUIRED_TEST
                && function.attrs.iter().any(is_test_attribute)
                && !function.attrs.iter().any(is_ignore_attribute)
                && !function.attrs.iter().any(is_conditional_attribute)
                && !function.block.stmts.is_empty())
    }))
}

fn settingsonly_artifact_acceptance_evidence(root: &Path) -> Result<bool> {
    let source_path = root.join("assemblies/settingsonly/tests/artifact_acceptance.rs");
    let source = match std::fs::read_to_string(&source_path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", source_path.display()));
        }
    };
    let source_closed = settingsonly_artifact_source_is_closed(&source)
        .with_context(|| format!("解析 {} 失败", source_path.display()))?;
    let script_path = root.join("hack/settingsonly-artifact-acceptance.sh");
    let script = match std::fs::read_to_string(&script_path) {
        Ok(script) => script,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", script_path.display()));
        }
    };
    Ok(source_closed && settingsonly_artifact_script_is_closed(&script))
}

fn settingsonly_artifact_source_is_closed(source: &str) -> Result<bool> {
    let syntax = syn::parse_file(source)?;
    let mut binary = false;
    let mut image = false;
    let mut live = false;
    for item in syntax.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if !function.attrs.iter().any(is_test_attribute)
            || function.attrs.iter().any(is_conditional_attribute)
        {
            continue;
        }
        if function.sig.ident == "settingsonly_server_binary_is_an_executable_artifact"
            && !function.attrs.iter().any(is_ignore_attribute)
            && artifact_contract_tail(&function, ArtifactContractKind::Binary)
        {
            binary = true;
        }
        if function.sig.ident == "settingsonly_runtime_image_is_an_executable_artifact"
            && function.attrs.iter().any(is_ignore_attribute)
            && artifact_contract_tail(&function, ArtifactContractKind::Image)
            && image_environment_is_loaded(&function)
        {
            image = true;
        }
        if function.sig.ident == "settingsonly_binary_and_image_are_live_deployments"
            && function.attrs.iter().any(is_ignore_attribute)
            && live_artifact_contract_tail(&function)
            && image_environment_is_loaded(&function)
        {
            live = true;
        }
    }
    Ok(binary && image && live)
}

#[derive(Clone, Copy)]
enum ArtifactContractKind {
    Binary,
    Image,
}

fn artifact_contract_tail(function: &syn::ItemFn, kind: ArtifactContractKind) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Call(assertion), None)) = function.block.stmts.last()
    else {
        return false;
    };
    if !expression_path_ends_with(assertion.func.as_ref(), &["assert_executable_contract"])
        || assertion.args.len() != 1
    {
        return false;
    }
    artifact_constructor_matches(assertion.args.first(), kind)
}

fn live_artifact_contract_tail(function: &syn::ItemFn) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Call(assertion), None)) = function.block.stmts.last()
    else {
        return false;
    };
    expression_path_ends_with(
        assertion.func.as_ref(),
        &["assert_live_deployment_contract"],
    ) && assertion.args.len() == 2
        && artifact_constructor_matches(assertion.args.first(), ArtifactContractKind::Binary)
        && artifact_constructor_matches(assertion.args.iter().nth(1), ArtifactContractKind::Image)
}

fn artifact_constructor_matches(
    expression: Option<&syn::Expr>,
    kind: ArtifactContractKind,
) -> bool {
    let Some(syn::Expr::Call(artifact)) = expression else {
        return false;
    };
    let expected = match kind {
        ArtifactContractKind::Binary => "Binary",
        ArtifactContractKind::Image => "Image",
    };
    if !expression_path_ends_with(artifact.func.as_ref(), &["Artifact", expected])
        || artifact.args.len() != 1
    {
        return false;
    }
    match (kind, artifact.args.first()) {
        (ArtifactContractKind::Binary, Some(syn::Expr::Macro(expression))) => {
            expression.mac.path.is_ident("env")
                && syn::parse2::<syn::LitStr>(expression.mac.tokens.clone())
                    .is_ok_and(|literal| literal.value() == "CARGO_BIN_EXE_settingsonly-server")
        }
        (ArtifactContractKind::Image, Some(syn::Expr::Reference(reference))) => {
            matches!(reference.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("image"))
        }
        _ => false,
    }
}

fn image_environment_is_loaded(function: &syn::ItemFn) -> bool {
    let mut visitor = SettingsOnlyImageEnvironmentVisitor::default();
    syn::visit::Visit::visit_block(&mut visitor, &function.block);
    visitor.image_environment
}

#[derive(Default)]
struct SettingsOnlyImageEnvironmentVisitor {
    image_environment: bool,
}

impl<'ast> syn::visit::Visit<'ast> for SettingsOnlyImageEnvironmentVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if expression_path_ends_with(node.func.as_ref(), &["env", "var"])
            && node.args.len() == 1
            && matches!(node.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident("IMAGE_ENV"))
        {
            self.image_environment = true;
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn expression_path_ends_with(expression: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    let segments = path.path.segments.iter().collect::<Vec<_>>();
    segments.len() >= expected.len()
        && segments[segments.len() - expected.len()..]
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected)
}

fn settingsonly_artifact_script_is_closed(source: &str) -> bool {
    const EXPECTED: &[&str] = &[
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "script_dir=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"",
        "repo_root=\"$(cd \"$script_dir/..\" && pwd)\"",
        "image=\"${RSS_SETTINGSONLY_ACCEPTANCE_IMAGE:-rss-settingsonly:artifact-acceptance}\"",
        "unset RSS_SETTINGSONLY_PG_WRITER_PASSWORD",
        "unset RSS_SETTINGSONLY_PG_READER_PASSWORD",
        "unset RSS_SETTINGSONLY_PG_MIGRATOR_PASSWORD",
        "unset RSS_SETTINGSONLY_VAULT_TOKEN",
        "cd \"$repo_root\"",
        "docker build --target settingsonly-runtime --tag \"$image\" .",
        "RSS_SETTINGSONLY_ACCEPTANCE_IMAGE=\"$image\" ./hack/cargo.sh test -p settingsonly --test settingsonly_artifact_acceptance -- --include-ignored --test-threads=1",
    ];
    logical_shell_statements(source) == EXPECTED
}

fn logical_shell_statements(source: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    for line in source.lines().map(str::trim) {
        if line.is_empty() || (line.starts_with('#') && !line.starts_with("#!")) {
            continue;
        }
        let continued = line.strip_suffix('\\');
        let fragment = continued.unwrap_or(line).trim_end();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(fragment);
        if continued.is_none() {
            statements.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        statements.push(current);
    }
    statements
}

fn is_test_attribute(attribute: &syn::Attribute) -> bool {
    let segments = attribute
        .path()
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), [test] if test == "test")
        || matches!(segments.as_slice(), [runtime, test] if runtime == "tokio" && test == "test")
}

fn is_ignore_attribute(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("ignore")
}

fn is_conditional_attribute(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr")
}

struct DockerStage<'a> {
    base: &'a str,
    name: &'a str,
    instructions: Vec<&'a str>,
}

fn settingsonly_docker_target_is_closed(source: &str) -> bool {
    let stages = docker_stages(source);
    let builders = stages
        .iter()
        .filter(|stage| stage.name == "settingsonly-builder")
        .collect::<Vec<_>>();
    let runtimes = stages
        .iter()
        .filter(|stage| stage.name == "settingsonly-runtime")
        .collect::<Vec<_>>();
    let ([builder], [runtime]) = (builders.as_slice(), runtimes.as_slice()) else {
        return false;
    };
    let builder_ok = builder.base == "chef"
        && builder.instructions.iter().any(|instruction| {
            docker_instruction_arguments(instruction, "RUN").is_some_and(|arguments| {
                arguments.starts_with("cargo chef cook ")
                    && arguments.contains("--bin settingsonly-server")
            })
        })
        && builder.instructions.iter().any(|instruction| {
            docker_instruction_arguments(instruction, "RUN").is_some_and(|arguments| {
                arguments.starts_with("cargo build ")
                    && arguments.contains("--bin settingsonly-server")
            })
        });
    const RUNTIME_INSTRUCTIONS: &[(&str, &str)] = &[
        (
            "COPY",
            "--from=settingsonly-builder /app/target/release/settingsonly-server /usr/local/bin/settingsonly-server",
        ),
        (
            "COPY",
            "--from=settingsonly-builder /app/assemblies/settingsonly/config.schema.json /usr/share/rss/settingsonly/config.schema.json",
        ),
        ("ENTRYPOINT", "[\"/usr/local/bin/settingsonly-server\"]"),
    ];
    let runtime_ok = runtime.base == "gcr.io/distroless/cc-debian12:nonroot"
        && runtime.instructions.len() == RUNTIME_INSTRUCTIONS.len()
        && runtime.instructions.iter().zip(RUNTIME_INSTRUCTIONS).all(
            |(instruction, (keyword, arguments))| {
                docker_instruction_arguments(instruction, keyword) == Some(*arguments)
            },
        );
    let default_runtime_unchanged = stages.last().is_some_and(|stage| stage.name == "runtime");
    builder_ok && runtime_ok && default_runtime_unchanged
}

fn docker_stages(source: &str) -> Vec<DockerStage<'_>> {
    let mut stages = Vec::new();
    for line in source.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(from) = docker_instruction_arguments(line, "FROM") {
            let mut parts = from.split_whitespace();
            let (Some(base), Some(as_keyword), Some(name), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if !as_keyword.eq_ignore_ascii_case("AS") {
                continue;
            }
            stages.push(DockerStage {
                base,
                name,
                instructions: Vec::new(),
            });
        } else if let Some(stage) = stages.last_mut() {
            stage.instructions.push(line);
        }
    }
    stages
}

fn docker_instruction_arguments<'a>(instruction: &'a str, expected: &str) -> Option<&'a str> {
    let keyword_end = instruction
        .find(char::is_whitespace)
        .unwrap_or(instruction.len());
    let (keyword, arguments) = instruction.split_at(keyword_end);
    keyword
        .eq_ignore_ascii_case(expected)
        .then(|| arguments.trim_start())
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
            "source=rust-ast-run-reachable profile=production gate=jwks 必须在 run() 或 typed StartupAdapter::prepare 可达路径有 profile-specific JwksKeySource::load_and_watch + typed VerifierConfigBuilder::keys_jwks + verifier managed resource + profile-specific JWKS readiness probe 注册证据",
        ));
    }
    let owns_internal_listener = a
        .manifest
        .listeners
        .iter()
        .any(|listener| listener.kind == assembly_schema::AssemblyListenerKind::Internal);
    if owns_internal_listener && !evidence.has_spiffe_closeout() {
        findings.push(finding(
            Rule::ProductionSecuritySpiffeCloseout,
            &a.manifest_label,
            "source=rust-ast-run-reachable profile=production gate=spiffe-mtls 必须在 run() 可达路径有 MtlsServerConfig::from_spire + DomainHttpTransport::from_spire + domain_transport_ready probe 证据，且不得保留 Internal service-token migration env 常量",
        ));
    }
    if owns_internal_listener {
        validate_token_profile_trust_chain(a, &evidence, findings);
    }
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
        && provider.consumer == ProviderConsumer::Distributed
        && matches!(provider.port, DiportPort::Lock | DiportPort::Cas)
}

fn has_distributed_consumer_evidence(a: &DiscoveredAssembly) -> bool {
    distributed_consumer_evidence_from_sources(&a.dir).unwrap_or(false)
}

fn distributed_consumer_evidence_from_sources(dir: &Path) -> Result<bool> {
    let path = dir.join("src/phase/domains.rs");
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path)?;
    let file = syn::parse_file(&content)
        .with_context(|| format!("parse rust source {}", path.display()))?;
    Ok(file_has_distributed_consumer_evidence(&file))
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

fn file_has_distributed_consumer_evidence(file: &syn::File) -> bool {
    let methods = file
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            if has_cfg_test(&implementation.attrs)
                || implementation.trait_.is_some()
                || !matches!(
                    implementation.self_ty.as_ref(),
                    syn::Type::Path(path)
                        if path.path.segments.last().is_some_and(|segment| segment.ident == "InfraBuilt")
                )
            {
                return None;
            }
            Some(implementation)
        })
        .flat_map(|implementation| &implementation.items)
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if method.sig.ident == "wire_domains"
                    && method.sig.asyncness.is_some()
                    && !has_cfg_test(&method.attrs) =>
            {
                Some(method)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = methods.as_slice() else {
        return false;
    };
    let phase_bodies = method
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let binding = local_binding_ident(&local.pat)?;
            let init = local.init.as_ref()?;
            let syn::Expr::Await(awaited) = init.expr.as_ref() else {
                return None;
            };
            let syn::Expr::Async(body) = awaited.base.as_ref() else {
                return None;
            };
            (binding == "result").then_some(&body.block)
        })
        .collect::<Vec<_>>();
    let [body] = phase_bodies.as_slice() else {
        return false;
    };

    let producers = body
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let binding = local_binding_ident(&local.pat)?;
            let init = local.init.as_ref()?;
            terminal_path_call(
                &init.expr,
                &["crate", "distributed_runtime", "wire_distributed"],
            )
            .is_some()
            .then_some((index, binding.to_string()))
        })
        .collect::<Vec<_>>();
    let [(producer_index, binding)] = producers.as_slice() else {
        return false;
    };
    let consumers = body
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let init = local.init.as_ref()?;
            let call = terminal_path_call(
                &init.expr,
                &["crate", "event_transport", "wire_event_transport"],
            )?;
            call.args
                .iter()
                .nth(1)
                .is_some_and(|argument| {
                    matches!(
                        argument,
                        syn::Expr::Path(path)
                            if path.path.get_ident().is_some_and(|ident| ident == binding)
                    )
                })
                .then_some(index)
        })
        .collect::<Vec<_>>();
    matches!(consumers.as_slice(), [consumer_index] if consumer_index > producer_index)
}

fn local_binding_ident(pat: &syn::Pat) -> Option<&syn::Ident> {
    match pat {
        syn::Pat::Ident(pat) => Some(&pat.ident),
        syn::Pat::Type(pat) => local_binding_ident(&pat.pat),
        _ => None,
    }
}

fn terminal_path_call<'a>(expr: &'a syn::Expr, expected: &[&str]) -> Option<&'a syn::ExprCall> {
    match expr {
        syn::Expr::Call(call) if expr_path_is_exact(&call.func, expected) => Some(call),
        syn::Expr::Await(awaited) => terminal_path_call(&awaited.base, expected),
        syn::Expr::Try(propagated) => terminal_path_call(&propagated.expr, expected),
        syn::Expr::Paren(paren) => terminal_path_call(&paren.expr, expected),
        syn::Expr::Group(group) => terminal_path_call(&group.expr, expected),
        syn::Expr::MethodCall(method)
            if matches!(
                method.method.to_string().as_str(),
                "context" | "with_context"
            ) && method.args.len() == 1 =>
        {
            terminal_path_call(&method.receiver, expected)
        }
        _ => None,
    }
}

fn expr_path_is_exact(expr: &syn::Expr, expected: &[&str]) -> bool {
    matches!(
        expr,
        syn::Expr::Path(path)
            if path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == expected.len()
                && path.path.segments.iter().zip(expected).all(|(segment, expected)| {
                    segment.ident == *expected
                        && matches!(segment.arguments, syn::PathArguments::None)
                })
    )
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
    exact_profile_binding_mapping: bool,
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
        self.exact_profile_binding_mapping |= other.exact_profile_binding_mapping;
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
                        && self.exact_profile_binding_mapping)))
    }

    fn federated_access_reaches_verify_bridge(&self) -> bool {
        self.federated_access_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.federated_access_packed_in_profile_carrier
                    || (self.typed_primary_access_binding_carrier_call
                        && self.typed_admin_access_binding_carrier_call
                        && self.exact_profile_binding_mapping)))
    }

    fn service_token_reaches_verify_bridge(&self) -> bool {
        self.service_token_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.service_token_packed_in_profile_carrier
                    || (self.typed_service_binding_carrier_call
                        && self.exact_profile_binding_mapping)))
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
    const FORBIDDEN_SUBSTRINGS: &[&str] = &["RSS_JWT_", "RSS_OIDC_", "AssembledListener::plain"];
    const FORBIDDEN_IDENTIFIERS: &[&str] = &[
        "OIDC_JWKS_READY_PROBE_NAME",
        "oidc_jwks_ready",
        "OidcJwksReadyProbe",
        "RuntimeOidcProvider",
        "PreparedRuntimeOidcProvider",
        "build_runtime_oidc_provider",
        "required_scheme_for_auth_scheme",
        "RouteAssemblyContext",
        "assemble_authed_routers_from_values",
        "assemble_authed_routers",
        "health_listener",
        "health_auth_scheme",
    ];
    FORBIDDEN_SUBSTRINGS
        .iter()
        .any(|needle| source.contains(needle))
        || FORBIDDEN_IDENTIFIERS
            .iter()
            .any(|identifier| source_contains_exact_rust_identifier(source, identifier))
}

fn source_contains_exact_rust_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(start, matched)| {
        let before = source[..start].chars().next_back();
        let after = source[start + matched.len()..].chars().next();
        before.is_none_or(|ch| !is_rust_identifier_continue(ch))
            && after.is_none_or(|ch| !is_rust_identifier_continue(ch))
    })
}

fn is_rust_identifier_continue(ch: char) -> bool {
    ch == '_'
        || ch.is_ascii_alphanumeric()
        || (!ch.is_ascii() && syn::parse_str::<syn::Ident>(&format!("a{ch}")).is_ok())
}

#[derive(Default)]
struct SecurityCloseoutProgram {
    functions: BTreeMap<String, SecurityFunctionEvidence>,
    startup_adapter_roots: BTreeSet<String>,
    profile_binding_definitions: usize,
    exact_profile_binding_definitions: usize,
    legacy_service_token_migration: bool,
    legacy_token_surface: bool,
    mixed_key_provider: bool,
    split_scheme_provider_binding: bool,
}

impl SecurityCloseoutProgram {
    fn merge(&mut self, other: Self) {
        self.profile_binding_definitions = self
            .profile_binding_definitions
            .saturating_add(other.profile_binding_definitions);
        self.exact_profile_binding_definitions = self
            .exact_profile_binding_definitions
            .saturating_add(other.exact_profile_binding_definitions);
        self.legacy_service_token_migration |= other.legacy_service_token_migration;
        self.legacy_token_surface |= other.legacy_token_surface;
        self.mixed_key_provider |= other.mixed_key_provider;
        self.split_scheme_provider_binding |= other.split_scheme_provider_binding;
        self.startup_adapter_roots
            .extend(other.startup_adapter_roots);
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
        stack.extend(self.startup_adapter_roots.iter().cloned());
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
        out.exact_profile_binding_mapping =
            self.profile_binding_definitions == 1 && self.exact_profile_binding_definitions == 1;
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
    typed_listener_spec_bindings: Vec<BTreeSet<String>>,
    plan_auth_scheme_locals: Vec<BTreeSet<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TokenProfileBridgeKind {
    RssAccess,
    FederatedAccess,
    ServiceToken,
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
        self.typed_listener_spec_bindings
            .push(listener_execution_spec_parameters(&node.sig));
        self.plan_auth_scheme_locals.push(BTreeSet::new());
        syn::visit::visit_item_fn(self, node);
        self.plan_auth_scheme_locals.pop();
        self.typed_listener_spec_bindings.pop();
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
            let is_startup_adapter = node.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments
                    .last()
                    .is_some_and(|segment| segment.ident == "StartupAdapter")
            });
            if is_startup_adapter
                && node.items.iter().any(|item| {
                    matches!(item, syn::ImplItem::Fn(function) if function.sig.ident == "prepare")
                })
            {
                self.program
                    .startup_adapter_roots
                    .insert(format!("{owner}::prepare"));
            }
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
                "profile_binding" => {
                    self.program.profile_binding_definitions =
                        self.program.profile_binding_definitions.saturating_add(1);
                    if exact_profile_binding_definition(node) {
                        self.program.exact_profile_binding_definitions = self
                            .program
                            .exact_profile_binding_definitions
                            .saturating_add(1);
                    }
                }
                "access_binding" => {
                    self.program.legacy_token_surface = true;
                }
                "service_binding" => {
                    self.program.legacy_token_surface = true;
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
        self.typed_listener_spec_bindings
            .push(listener_execution_spec_parameters(&node.sig));
        self.plan_auth_scheme_locals.push(BTreeSet::new());
        syn::visit::visit_impl_item_fn(self, node);
        self.plan_auth_scheme_locals.pop();
        self.typed_listener_spec_bindings.pop();
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
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init)
            && let syn::Expr::MethodCall(call) = ungroup_profile_expression(init.expr.as_ref())
            && call.method == "auth_scheme"
            && call.args.is_empty()
            && let Some(receiver) =
                simple_path_ident(ungroup_profile_expression(call.receiver.as_ref()))
            && self
                .typed_listener_spec_bindings
                .last()
                .is_some_and(|bindings| bindings.contains(&receiver))
            && let Some(locals) = self.plan_auth_scheme_locals.last_mut()
        {
            locals.insert(pattern.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let carrier = profile_carrier_binding(&node.pat);
        if let Some(binding) = carrier.as_ref() {
            self.profile_carrier_bindings
                .push(BTreeSet::from([binding.clone()]));
        }
        syn::visit::visit_arm(self, node);
        if carrier.is_some() {
            self.profile_carrier_bindings.pop();
        }
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
        if node.method == "profile_binding"
            && self.receiver_is_typed_token_provider(node.receiver.as_ref())
        {
            self.record_call("TokenProviderBindings::profile_binding");
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
            if segment.ident == "RouteAssemblyContext" {
                self.program.legacy_token_surface = true;
            }
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
            "profile_binding" if call.args.len() == 1 => {
                let plan_auth = call
                    .args
                    .first()
                    .and_then(|argument| simple_path_ident(ungroup_profile_expression(argument)))
                    .is_some_and(|name| {
                        self.plan_auth_scheme_locals
                            .last()
                            .is_some_and(|locals| locals.contains(&name))
                    });
                self.record_evidence(|evidence| {
                    evidence.typed_primary_access_binding_carrier_call |= plan_auth;
                    evidence.typed_admin_access_binding_carrier_call |= plan_auth;
                    evidence.typed_service_binding_carrier_call |= plan_auth;
                });
            }
            "access_binding" | "service_binding" => self.program.legacy_token_surface = true,
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

fn listener_execution_spec_parameters(signature: &syn::Signature) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            if !type_contains_ident(argument.ty.as_ref(), "ListenerExecutionSpec") {
                return None;
            }
            let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
                return None;
            };
            Some(pattern.ident.to_string())
        })
        .collect()
}

fn exact_profile_binding_definition(function: &syn::ImplItemFn) -> bool {
    if function.sig.receiver().is_none()
        || !return_type_contains_ident(&function.sig.output, "ProfileBinding")
    {
        return false;
    }
    let mut scheme_names = function.sig.inputs.iter().filter_map(|input| {
        let syn::FnArg::Typed(argument) = input else {
            return None;
        };
        if !type_contains_ident(argument.ty.as_ref(), "AuthScheme") {
            return None;
        }
        let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
            return None;
        };
        Some(pattern.ident.to_string())
    });
    let Some(scheme) = scheme_names.next() else {
        return false;
    };
    if scheme_names.next().is_some() {
        return false;
    }
    let Some(syn::Expr::Match(mapping)) = sole_block_expression(&function.block) else {
        return false;
    };
    if simple_path_ident(ungroup_profile_expression(mapping.expr.as_ref())).as_deref()
        != Some(scheme.as_str())
    {
        return false;
    }
    let mut observed = BTreeSet::new();
    for arm in &mapping.arms {
        if arm.guard.is_some() || matches!(arm.body.as_ref(), syn::Expr::Block(_)) {
            return false;
        }
        let kind = match auth_scheme_profile_pattern_kind(&arm.pat) {
            Some(kind) => kind,
            None => {
                let mut evidence = ProfileMappingExpressionEvidence::default();
                syn::visit::Visit::visit_expr(&mut evidence, arm.body.as_ref());
                if evidence.rss_variants + evidence.federated_variants + evidence.service_variants
                    != 0
                {
                    return false;
                }
                continue;
            }
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
            TokenProfileBridgeKind::ServiceToken,
        ])
}

fn auth_scheme_profile_pattern_kind(pattern: &syn::Pat) -> Option<TokenProfileBridgeKind> {
    let syn::Pat::Path(path) = pattern else {
        return None;
    };
    if !path_contains_segment(&path.path, "AuthScheme") {
        return None;
    }
    match path.path.segments.last()?.ident.to_string().as_str() {
        "RssAccessToken" => Some(TokenProfileBridgeKind::RssAccess),
        "FederatedAccessToken" => Some(TokenProfileBridgeKind::FederatedAccess),
        "ServiceToken" => Some(TokenProfileBridgeKind::ServiceToken),
        _ => None,
    }
}

fn sole_block_expression(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(expression, None)] => Some(expression),
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

    fn write_distributed_consumer_fixture(root: &Path) -> anyhow::Result<()> {
        write_runtime_src(
            root,
            "phase/domains.rs",
            r#"
pub struct InfraBuilt;

impl InfraBuilt {
    pub async fn wire_domains(self) {
        let result = async move {
            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)
                    .context("wire distributed")?;
            let event_module = crate::event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            )
            .await
            .context("wire event transport")?;
            Ok::<_, anyhow::Error>(event_module)
        }
        .await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
"#,
        )
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
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]
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
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]
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
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = ["resources"]

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
scope = "cluster-global"
failurePosture = "fail-closed"
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
requiredFeatures = ["backend"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = ["resources"]
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
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-configvalue-at-rest-encryption"
outputs = ["resources"]
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
outputs = ["resources", "workers"]
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
outputs = ["probes", "resources", "workers"]

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
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["resources"]

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = ["resources", "workers"]
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
scope = "cluster-global"
failurePosture = "fail-closed"
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
requiredFeatures = ["backend"]
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
    fn runtime_pdp_rejects_replay_store_without_cluster_global_fail_closed_posture()
    -> anyhow::Result<()> {
        let replay_without_posture = CAPABILITY_REPLAY_STORE_PROVIDER
            .replace("scope = \"cluster-global\"\n", "")
            .replace("failurePosture = \"fail-closed\"\n", "");
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["identity"],
            &format!("{CAPABILITY_DOMAIN_PROVIDERS}{replay_without_posture}"),
        );
        let root = unique_tmp("assembly-runtime-pdp-replay-posture-missing");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::PdpReplayStoreCapability),
            "runtime replay store without cluster-global fail-closed posture must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_pdp_rejects_process_local_or_fail_open_replay_posture() -> anyhow::Result<()> {
        for (name, replay_provider) in [
            (
                "assembly-runtime-pdp-process-local-replay",
                CAPABILITY_REPLAY_STORE_PROVIDER.replace("cluster-global", "process-local"),
            ),
            (
                "assembly-runtime-pdp-fail-open-replay",
                CAPABILITY_REPLAY_STORE_PROVIDER.replace("fail-closed", "fail-open"),
            ),
        ] {
            let manifest = capability_manifest(
                "demo",
                "durable-shared",
                &["identity"],
                &format!("{CAPABILITY_DOMAIN_PROVIDERS}{replay_provider}"),
            );
            let root = unique_tmp(name);
            write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
            let (_count, findings) = validate_root(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::PdpReplayStoreCapability),
                "weak replay posture must fail: {findings:?}"
            );
        }
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
scope = "cluster-global"
failurePosture = "fail-closed"
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
    let _ = finalize_listener_plan();
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
    fn profile_binding(
        &self,
        scheme: AuthScheme,
    ) -> ProfileBinding {
        match scheme {
            AuthScheme::RssAccessToken => self
                .rss_access
                .map(|provider| ProfileBinding::RssAccess(provider)),
            AuthScheme::FederatedAccessToken => self
                .federated_access
                .map(|provider| ProfileBinding::FederatedAccess(provider)),
            AuthScheme::ServiceToken => self
                .service_token
                .map(|provider| ProfileBinding::ServiceToken(provider)),
            AuthScheme::Mtls | AuthScheme::NoAuth => fail(),
            _ => fail(),
        }
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
    spec: ListenerExecutionSpec,
) {
    let scheme = spec.auth_scheme();
    let binding = ListenerAuthBinding::Token(providers.profile_binding(scheme));
    match binding {
        ListenerAuthBinding::Token(profile) => apply_verify_bridge(routes, profile),
        ListenerAuthBinding::Mtls => apply_mtls_verify_bridge(routes),
    }
}

fn run() {
    assemble(&providers, spec);
}
"#;

    fn security_closeout_run_to_launch_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "    let _ = finalize_listener_plan();",
            "    let _ = finalize_listener_plan();\n    launch();",
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
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]
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

    fn identityaudit_executable_targets() -> [MetadataTarget; 3] {
        [
            MetadataTarget {
                name: "identityaudit".to_owned(),
                kind: vec!["lib".to_owned()],
            },
            MetadataTarget {
                name: "identityaudit-server".to_owned(),
                kind: vec!["bin".to_owned()],
            },
            MetadataTarget {
                name: "identityaudit_artifact_acceptance".to_owned(),
                kind: vec!["test".to_owned()],
            },
        ]
    }

    fn identityaudit_production_closure() -> BTreeSet<String> {
        IDENTITYAUDIT_ALLOWED_NORMAL_WORKSPACE_PACKAGES
            .iter()
            .map(|package| (*package).to_owned())
            .collect()
    }

    /// INVARIANT: IDENTITYAUDIT-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::identityaudit_executable_boundary_rejects_lib_only_shape", anti_vacuity = "tests::identityaudit_real_executable_artifact_closure_is_complete" } -- #1797 replaces the demo composition proof with one exact executable package and its closed production transport/artifact closure.
    #[test]
    fn identityaudit_executable_boundary_accepts_exact_targets_and_production_closure() {
        let findings = validate_identityaudit_boundary(
            "assemblies/identityaudit/assembly.toml",
            "assemblies/identityaudit/Cargo.toml",
            &identityaudit_executable_targets(),
            &identityaudit_production_closure(),
        );
        assert!(
            findings.is_empty(),
            "identityaudit executable + production transport closure must pass: {findings:?}"
        );
    }

    #[test]
    fn identityaudit_executable_boundary_rejects_lib_only_shape() {
        let lib_only = [MetadataTarget {
            name: "identityaudit".to_owned(),
            kind: vec!["lib".to_owned()],
        }];
        let findings = validate_identityaudit_boundary(
            "assemblies/identityaudit/assembly.toml",
            "assemblies/identityaudit/Cargo.toml",
            &lib_only,
            &identityaudit_production_closure(),
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::IdentityAuditBoundary
                    && finding.detail.contains("package.targets")
            }),
            "lib-only identityaudit must fail the executable boundary: {findings:?}"
        );
    }

    #[test]
    fn identityaudit_manifest_boundary_rejects_demo_profile_and_topology() -> anyhow::Result<()> {
        let demo_manifest = IDENTITYAUDIT_MANIFEST
            .replace("profile = \"production\"", "profile = \"demo\"")
            .replace("topology = \"durable-isolated\"", "topology = \"demo\"");
        let manifest = AssemblyManifest::from_toml_str(&demo_manifest)?;
        let assembly = DiscoveredAssembly {
            dir: PathBuf::from("assemblies/identityaudit"),
            cargo_path: PathBuf::from("assemblies/identityaudit/Cargo.toml"),
            manifest_label: "assemblies/identityaudit/assembly.toml".to_owned(),
            cargo_label: "assemblies/identityaudit/Cargo.toml".to_owned(),
            manifest_src: demo_manifest,
            manifest,
            cargo_toml: toml::from_str(IDENTITYAUDIT_CARGO)?,
        };
        let findings = validate_assembly(&assembly);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::IdentityAuditBoundary
                    && finding.detail.contains("profile")
                    && finding.detail.contains("topology")
            }),
            "demo identityaudit must fail the production executable boundary: {findings:?}"
        );
        Ok(())
    }

    /// identityaudit participates in production provider/JWKS closeout, but has no Internal mTLS
    /// listener or federated/service token profiles and therefore must not inherit those gates.
    #[test]
    fn identityaudit_production_boundary_does_not_inherit_full_runtime_only_gates()
    -> anyhow::Result<()> {
        let production_manifest = IDENTITYAUDIT_MANIFEST
            .replace("profile = \"demo\"", "profile = \"production\"")
            .replace("topology = \"demo\"", "topology = \"durable-isolated\"");
        let assembly = DiscoveredAssembly {
            dir: PathBuf::from("assemblies/identityaudit"),
            cargo_path: PathBuf::from("assemblies/identityaudit/Cargo.toml"),
            manifest_label: "assemblies/identityaudit/assembly.toml".to_owned(),
            cargo_label: "assemblies/identityaudit/Cargo.toml".to_owned(),
            manifest_src: production_manifest.clone(),
            manifest: AssemblyManifest::from_toml_str(&production_manifest)?,
            cargo_toml: toml::from_str(IDENTITYAUDIT_CARGO)?,
        };
        let findings = validate_assembly(&assembly);
        assert!(
            findings.iter().all(|finding| !matches!(
                finding.rule,
                Rule::ProductionSecuritySpiffeCloseout
                    | Rule::TokenProfileTrustChain
                    | Rule::ActiveDistributedProviderConsumer
            )),
            "identityaudit must use semantic production gates without full-runtime closeout: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn identityaudit_real_executable_artifact_closure_is_complete() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let manifest = AssemblyManifest::from_toml_str(IDENTITYAUDIT_MANIFEST)?;
        assert_eq!(manifest.profile, AssemblyProfile::Production);
        assert_eq!(manifest.topology, AssemblyTopology::DurableIsolated);

        let metadata = load_workspace_metadata(&root)?.context("real workspace has Cargo.toml")?;
        let package = metadata
            .packages
            .iter()
            .find(|package| package.name == "identityaudit")
            .context("identityaudit package missing from cargo metadata")?;
        assert_eq!(
            package
                .targets
                .iter()
                .map(|target| (target.name.as_str(), target.kind.as_slice()))
                .collect::<BTreeSet<_>>(),
            identityaudit_executable_targets()
                .iter()
                .map(|target| (target.name.as_str(), target.kind.as_slice()))
                .collect::<BTreeSet<_>>()
        );

        let schema_path = root.join("assemblies/identityaudit/config.schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&schema_path)?)?;
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&serde_json::json!(false))
        );
        for path in [
            schema_path,
            root.join("assemblies/identityaudit/identityaudit.example.toml"),
            root.join("docs/ops/202607251200-1797-identityaudit-runtime.md"),
        ] {
            assert!(
                is_regular_file_without_symlink(&path)?,
                "required identityaudit artifact is missing or symlinked: {}",
                path.display()
            );
        }

        let journeys_manifest: toml::Value =
            std::fs::read_to_string(root.join("journeys/Cargo.toml"))?.parse()?;
        assert!(
            journeys_manifest
                .get("test")
                .and_then(toml::Value::as_array)
                .is_some_and(|tests| tests.iter().any(|test| {
                    test.get("name").and_then(toml::Value::as_str) == Some("identityaudit_runtime")
                        && test.get("path").and_then(toml::Value::as_str)
                            == Some("tests/identityaudit_runtime.rs")
                }))
        );
        let journey =
            std::fs::read_to_string(root.join("journeys/tests/identityaudit_runtime.rs"))?;
        assert!(identityaudit_journey_has_required_test(&journey)?);

        let dockerfile = std::fs::read_to_string(root.join("Dockerfile"))?;
        assert!(
            identityaudit_docker_target_is_closed(&dockerfile),
            "identityaudit-runtime must be one closed distroless target while runtime remains default"
        );

        let findings = validate_target(&root, "identityaudit")?;
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::IdentityAuditBoundary),
            "real identityaudit executable closure must be complete: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn identityaudit_artifact_gate_rejects_noop_contracts() -> anyhow::Result<()> {
        let source = include_str!("../../assemblies/identityaudit/tests/artifact_acceptance.rs");
        assert!(identityaudit_artifact_source_is_closed(source)?);
        for broken in [
            source.replace(
                "assert_executable_contract(Artifact::Binary(env!(\"CARGO_BIN_EXE_identityaudit-server\")))",
                "Ok(())",
            ),
            source.replace(
                "assert_executable_contract(Artifact::Image(&image))",
                "Ok(())",
            ),
        ] {
            assert!(
                !identityaudit_artifact_source_is_closed(&broken)?,
                "identityaudit artifact gate accepted a no-op contract"
            );
        }
        assert!(!identityaudit_artifact_source_is_closed(
            r#"
            fn assert_executable_contract(_artifact: Artifact<'_>) -> anyhow::Result<()> { Ok(()) }
            #[test]
            fn identityaudit_server_binary_is_an_executable_artifact() -> anyhow::Result<()> {
                assert_executable_contract(Artifact::Binary(env!("CARGO_BIN_EXE_identityaudit-server")))
            }
            #[test]
            #[ignore]
            fn identityaudit_runtime_image_is_an_executable_artifact() -> anyhow::Result<()> {
                let image = std::env::var(IMAGE_ENV)?;
                assert_executable_contract(Artifact::Image(&image))
            }
            "#
        )?);
        Ok(())
    }

    #[test]
    fn identityaudit_key_pin_cutover_requires_forward_only_recovery_fence() {
        let migration_runbook = include_str!("../../adapters/postgres/migrations/README.md");
        assert!(identityaudit_key_pin_cutover_is_closed(migration_runbook));
        for required in [
            "ledger=72",
            "ledger=73",
            "停止全部旧 audit writer",
            "不得启动旧 binary",
            "新的前向修复 migration",
        ] {
            assert!(
                !identityaudit_key_pin_cutover_is_closed(
                    &migration_runbook.replace(required, "missing-cutover-proof")
                ),
                "cutover guard accepted missing proof: {required}"
            );
        }
    }

    #[test]
    fn identityaudit_journey_gate_requires_runtime_witness_chain() -> anyhow::Result<()> {
        let source = include_str!("../../journeys/tests/identityaudit_runtime.rs");
        assert!(identityaudit_journey_has_required_test(source)?);
        for required_call in [
            "RuntimeFixture::start",
            "wait_until_ready",
            "login",
            "wait_for_auth_audit",
            "wait_for_session_created_hash_chain",
            "send_sigterm",
            "wait_for_drain",
        ] {
            let broken = source.replace(required_call, "noop_witness");
            assert!(
                !identityaudit_journey_has_required_test(&broken)?,
                "identityaudit journey gate accepted missing witness {required_call}"
            );
        }
        assert!(!identityaudit_journey_has_required_test(
            "#[tokio::test]\nasync fn identityaudit_login_audit_ready_sigterm_drain() -> anyhow::Result<()> { Ok(()) }"
        )?);
        Ok(())
    }

    const SETTINGSONLY_DOCKER_FIXTURE: &str = r#"
FROM chef AS settingsonly-builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json --bin settingsonly-server
COPY . .
RUN cargo build --release --locked --bin settingsonly-server && strip target/release/settingsonly-server
FROM gcr.io/distroless/cc-debian12:nonroot AS settingsonly-runtime
COPY --from=settingsonly-builder /app/target/release/settingsonly-server /usr/local/bin/settingsonly-server
COPY --from=settingsonly-builder /app/assemblies/settingsonly/config.schema.json /usr/share/rss/settingsonly/config.schema.json
ENTRYPOINT ["/usr/local/bin/settingsonly-server"]
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
ENTRYPOINT ["/usr/local/bin/server"]
"#;

    fn settingsonly_boundary_evidence<'a>(
        targets: &'a [MetadataTarget],
        closure_packages: &'a BTreeSet<String>,
        dockerfile: &'a str,
    ) -> SettingsOnlyExecutableEvidence<'a> {
        SettingsOnlyExecutableEvidence {
            targets,
            closure_packages,
            test_support_enabled: false,
            schema_is_regular_file: true,
            sample_is_regular_file: true,
            runbook_is_regular_file: true,
            artifact_acceptance: true,
            journey_target_declared: true,
            required_journey_test_declared: true,
            dockerfile,
        }
    }

    /// INVARIANT: SETTINGSONLY-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::settingsonly_executable_boundary_rejects_each_incomplete_artifact_fact", anti_vacuity = "tests::settingsonly_real_executable_boundary_is_complete" } -- the #1796 target is one lib+bin+artifact-acceptance package whose default normal closure, committed config schema, exact non-ignored lifecycle fixture, and closed named distroless image target are checked without introducing the cross-assembly artifact matrix owned by #1798.
    #[test]
    fn settingsonly_executable_boundary_rejects_each_incomplete_artifact_fact() {
        let targets = [
            MetadataTarget {
                name: "settingsonly".to_owned(),
                kind: vec!["lib".to_owned()],
            },
            MetadataTarget {
                name: "settingsonly-server".to_owned(),
                kind: vec!["bin".to_owned()],
            },
            MetadataTarget {
                name: "settingsonly_artifact_acceptance".to_owned(),
                kind: vec!["test".to_owned()],
            },
        ];
        let required = SETTINGSONLY_ALLOWED_NORMAL_WORKSPACE_PACKAGES
            .iter()
            .map(|package| (*package).to_owned())
            .collect::<BTreeSet<_>>();
        assert!(
            validate_settingsonly_executable_evidence(settingsonly_boundary_evidence(
                &targets,
                &required,
                SETTINGSONLY_DOCKER_FIXTURE,
            ))
            .is_empty()
        );

        let mut unexpected_closure = required.clone();
        unexpected_closure.insert("mqtt".to_owned());
        assert!(
            validate_settingsonly_executable_evidence(settingsonly_boundary_evidence(
                &targets,
                &unexpected_closure,
                SETTINGSONLY_DOCKER_FIXTURE,
            ))
            .iter()
            .any(|finding| finding.detail.contains("unexpected packages")),
            "positive dependency closure accepted an unlisted package"
        );

        let mut incomplete_closure = required
            .iter()
            .filter(|package| package.as_str() != "runtimeexec")
            .cloned()
            .collect::<BTreeSet<_>>();
        incomplete_closure.insert("identity".to_owned());
        let broken_docker = SETTINGSONLY_DOCKER_FIXTURE
            .replace(
                "COPY --from=settingsonly-builder /app/assemblies/settingsonly/config.schema.json /usr/share/rss/settingsonly/config.schema.json",
                "",
            )
            .replace(
                "ENTRYPOINT [\"/usr/local/bin/settingsonly-server\"]",
                "ENTRYPOINT [\"/usr/local/bin/server\"]",
            );
        let mut incomplete =
            settingsonly_boundary_evidence(&targets[..1], &incomplete_closure, &broken_docker);
        incomplete.test_support_enabled = true;
        incomplete.schema_is_regular_file = false;
        incomplete.sample_is_regular_file = false;
        incomplete.runbook_is_regular_file = false;
        incomplete.artifact_acceptance = false;
        incomplete.journey_target_declared = false;
        incomplete.required_journey_test_declared = false;
        let details = validate_settingsonly_executable_evidence(incomplete)
            .into_iter()
            .map(|finding| finding.detail)
            .collect::<Vec<_>>()
            .join("\n");
        for field in [
            "package.targets",
            "missing allowed",
            "unexpected packages",
            "default-normal-features",
            "config-schema",
            "config-sample",
            "operator-runbook",
            "artifact-acceptance",
            "journey",
            "Dockerfile",
        ] {
            assert!(details.contains(field), "missing red evidence for {field}");
        }
    }

    #[test]
    fn settingsonly_docker_boundary_rejects_runtime_copy_and_add_bypasses() {
        let lowercase_allowed_copy = SETTINGSONLY_DOCKER_FIXTURE.replace(
            "COPY --from=settingsonly-builder /app/target/release/settingsonly-server /usr/local/bin/settingsonly-server",
            "copy --from=settingsonly-builder /app/target/release/settingsonly-server /usr/local/bin/settingsonly-server",
        );
        assert!(
            settingsonly_docker_target_is_closed(&lowercase_allowed_copy),
            "Docker instruction parsing must be case-insensitive"
        );

        let runtime_marker = "ENTRYPOINT [\"/usr/local/bin/settingsonly-server\"]";
        let cases = [
            ("ADD", "ADD /tmp/unexpected /usr/local/share/unexpected"),
            (
                "lowercase COPY",
                "copy --from=settingsonly-builder /app/target/release/settingsonly-server /usr/local/bin/unexpected",
            ),
            (
                "third COPY",
                "COPY --from=settingsonly-builder /app/target/release/settingsonly-server /usr/local/bin/unexpected",
            ),
            ("root user override", "USER 0"),
            (
                "entrypoint override",
                "ENTRYPOINT [\"/usr/local/bin/unexpected\"]",
            ),
            ("unexpected environment", "ENV UNEXPECTED=true"),
            ("false port publication", "EXPOSE 8080 8083"),
            ("command override", "CMD [\"--help\"]"),
        ];
        for (case, extra_instruction) in cases {
            let dockerfile = SETTINGSONLY_DOCKER_FIXTURE.replace(
                runtime_marker,
                &format!("{extra_instruction}\n{runtime_marker}"),
            );
            assert!(
                !settingsonly_docker_target_is_closed(&dockerfile),
                "settingsonly runtime accepted {case} bypass"
            );
        }
    }

    #[test]
    fn settingsonly_journey_gate_requires_exact_non_ignored_parent() -> anyhow::Result<()> {
        let cases = [
            ("missing parent", "#[test]\nfn unrelated_journey() {}"),
            (
                "only ignored child",
                "#[tokio::test]\n#[ignore]\nasync fn settingsonly_lifecycle_fixture_child() {}",
            ),
            (
                "name bait",
                "#[test]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain_decoy() {}",
            ),
            (
                "ignored parent",
                "#[tokio::test]\n#[ignore]\nasync fn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() {}",
            ),
            (
                "conditionally compiled parent",
                "#[test]\n#[cfg(any())]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() { run(); }",
            ),
            (
                "conditionally ignored parent",
                "#[test]\n#[cfg_attr(all(), ignore)]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() { run(); }",
            ),
            (
                "empty parent",
                "#[test]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() {}",
            ),
        ];
        for (case, source) in cases {
            assert!(
                !settingsonly_journey_has_required_test(source)?,
                "settingsonly journey gate accepted {case}"
            );
        }

        assert!(settingsonly_journey_has_required_test(
            "#[tokio::test]\nasync fn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() { run().await; }"
        )?);
        Ok(())
    }

    #[test]
    fn settingsonly_artifact_gate_requires_binary_image_and_closed_harness() -> anyhow::Result<()> {
        let source = include_str!("../../assemblies/settingsonly/tests/artifact_acceptance.rs");
        assert!(settingsonly_artifact_source_is_closed(source)?);
        for (case, broken) in [
            (
                "wrong binary",
                source.replace("CARGO_BIN_EXE_settingsonly-server", "CARGO_BIN_EXE_server"),
            ),
            (
                "non-ignored image",
                source.replace("#[ignore =", "#[allow(dead_code)]\n#[doc ="),
            ),
            (
                "conditional binary",
                source.replacen("#[test]", "#[test]\n#[cfg(any())]", 1),
            ),
            (
                "wrong image environment",
                source.replace("std::env::var(IMAGE_ENV)", "std::env::var(WRONG_ENV)"),
            ),
            (
                "binary artifact constructed without assertion",
                source.replace(
                    "assert_executable_contract(Artifact::Binary(env!(\"CARGO_BIN_EXE_settingsonly-server\")))",
                    "{ let _artifact = Artifact::Binary(env!(\"CARGO_BIN_EXE_settingsonly-server\")); Ok(()) }",
                ),
            ),
            (
                "image artifact constructed without assertion",
                source.replace(
                    "assert_executable_contract(Artifact::Image(&image))",
                    "{ let _artifact = Artifact::Image(&image); Ok(()) }",
                ),
            ),
            (
                "live artifact behavior omitted",
                source.replace(
                    "assert_live_deployment_contract(\n        Artifact::Binary(env!(\"CARGO_BIN_EXE_settingsonly-server\")),\n        Artifact::Image(&image),\n    )",
                    "{\n        let _binary = Artifact::Binary(env!(\"CARGO_BIN_EXE_settingsonly-server\"));\n        let _image = Artifact::Image(&image);\n        Ok(())\n    }",
                ),
            ),
        ] {
            assert!(
                !settingsonly_artifact_source_is_closed(&broken)?,
                "settingsonly artifact source gate accepted {case}"
            );
        }

        let script = include_str!("../../hack/settingsonly-artifact-acceptance.sh");
        assert!(
            settingsonly_artifact_script_is_closed(script),
            "logical statements: {:?}",
            logical_shell_statements(script)
        );
        for (case, broken) in [
            (
                "wrong Docker target",
                script.replace("--target settingsonly-runtime", "--target runtime"),
            ),
            (
                "ignored image omitted",
                script.replace("--include-ignored", ""),
            ),
            (
                "wrong test target",
                script.replace("--test settingsonly_artifact_acceptance", "--test other"),
            ),
            ("extra command", format!("{script}\ntrue\n")),
        ] {
            assert!(
                !settingsonly_artifact_script_is_closed(&broken),
                "settingsonly artifact script gate accepted {case}"
            );
        }
        Ok(())
    }

    #[test]
    fn settingsonly_real_executable_boundary_is_complete() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let findings = validate_target(&root, "settingsonly")?;
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::SettingsOnlyExecutableBoundary),
            "real settingsonly artifact closure must be complete: {findings:?}"
        );
        Ok(())
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
postgres = { path = "../../adapters/postgres" }
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
        let _ = finalize_listener_plan(provider);
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
                "legacy-listener-config-decision",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nfn legacy(context: RouteAssemblyContext) {{ drop(context); }}"
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
    fn token_profile_legacy_surface_uses_exact_identifier_boundaries() -> anyhow::Result<()> {
        for collision in [
            "finalize_health_listener",
            "health_listener_v2",
            "my_health_listener",
            "éhealth_listener",
        ] {
            let root = unique_tmp(&format!("assembly-token-profile-collision-{collision}"));
            write_assembly(
                &root,
                &production_security_manifest("production", true, true, true),
                CARGO_SECURITY_BACKEND,
            )?;
            write_runtime_src(
                &root,
                "lib.rs",
                &format!("{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nfn {collision}() {{}}"),
            )?;
            let (_count, findings) = validate_root(&root)?;
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule != Rule::TokenProfileLegacySurface),
                "identifier collision `{collision}` must not be treated as legacy: {findings:?}"
            );
        }

        let root = unique_tmp("assembly-token-profile-exact-health-listener");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            &format!(
                "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\n\
                 #[cfg(test)] fn health_listener() {{}}\n\
                 // health_listener remains forbidden even in comments"
            ),
        )?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileLegacySurface),
            "the exact legacy identifier must remain forbidden in cfg(test) and comments"
        );
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
        let wildcard = PROFILE_BINDING_MAPPING_SOURCE
            .replace("AuthScheme::FederatedAccessToken => self", "_ => self");
        let alias = PROFILE_BINDING_MAPPING_SOURCE.replace(
            r#"AuthScheme::RssAccessToken => self
                .rss_access
                .map(|provider| ProfileBinding::RssAccess(provider)),"#,
            r#"AuthScheme::RssAccessToken => {
                let alias = self
                    .rss_access
                    .map(|provider| ProfileBinding::RssAccess(provider));
                alias
            },"#,
        );
        let wrong_receiver = PROFILE_BINDING_MAPPING_SOURCE.replace(
            "providers.profile_binding(scheme)",
            "decoy.profile_binding(scheme)",
        );
        let hardcoded = PROFILE_BINDING_MAPPING_SOURCE.replace(
            "providers.profile_binding(scheme)",
            "providers.profile_binding(AuthScheme::RssAccessToken)",
        );
        let selection_alias = PROFILE_BINDING_MAPPING_SOURCE
            .replace(
                "let scheme = spec.auth_scheme();",
                "let scheme = spec.auth_scheme();\n    let selected = scheme;",
            )
            .replace(
                "providers.profile_binding(scheme)",
                "providers.profile_binding(selected)",
            );
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
            ("selection-alias", selection_alias),
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
        write_distributed_consumer_fixture(&root)?;

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
        write_distributed_consumer_fixture(&root)?;

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
        write_distributed_consumer_fixture(&root)?;

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
        let manifest = format!(
            "{}\n{}",
            manifest_with_intent(),
            r#"[[diportProviders]]
id = "event-publisher"
port = "diport::Publisher"
provider = "amqp::AmqpPublisher"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "outbox-relay-amqp-publish"
outputs = ["probes", "resources", "workers"]
"#,
        );
        write_assembly(
            &root,
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
amqp = { path = "../../adapters/amqp" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderFeature),
            "active AMQP provider without backend feature must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn unknown_provider_is_rejected_by_typed_manifest() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-unknown-active-provider");
        let manifest = manifest_with_intent()
            .replace("postgres::PgRevocationStore", "postgres::MissingProvider");
        write_assembly(
            &root,
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        let Err(error) = validate_root(&root) else {
            bail!("unknown typed provider must fail to parse");
        };
        assert!(
            format!("{error:#}").contains("postgres::MissingProvider"),
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
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProviderDurabilityMismatch),
            "known persistent provider must not be declared ephemeral: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn draft_only_provider_cannot_be_activated_even_with_dependency() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-draft-only-provider-active");
        let manifest = manifest_with_intent()
            .replace(
                "device-revocation-store",
                "distributed-cas-store-alternative",
            )
            .replace("diport::RevocationStore", "diport::CasStore")
            .replace("postgres::PgRevocationStore", "redis::RedisCasStore")
            .replace("providerCrate = \"postgres\"", "providerCrate = \"redis\"")
            .replace("requiredFeatures = []", "requiredFeatures = [\"backend\"]")
            .replace("consumer = \"deviceloop\"", "consumer = \"distributed\"")
            .replace(
                "outputs = [\"probes\", \"workers\"]",
                "outputs = [\"resources\"]",
            );
        write_assembly(
            &root,
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::InvalidDiportProvider && finding.detail.contains("lifecycle")
            }),
            "draft-only role must reject active lifecycle before downstream consumption: {findings:?}"
        );
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
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]

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
postgres = { path = "../../adapters/postgres" }
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
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["resources"]

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = ["resources", "workers"]
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
            "phase/domains.rs",
            r#"
pub struct InfraBuilt;

impl InfraBuilt {
    pub async fn wire_domains(self) {
        let result = async move {
            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)
                    .context("wire distributed")?;
            let event_module = crate::event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            )
            .await
            .context("wire event transport")?;
            Ok::<_, anyhow::Error>(event_module)
        }
        .await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
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
    fn distributed_consumer_evidence_rejects_same_name_and_alias_decoys() -> anyhow::Result<()> {
        let canonical = r#"
impl InfraBuilt {
    async fn wire_domains(self) {
        let result = async move {
            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)?;
            let event_module = crate::event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            ).await?;
            Ok::<_, anyhow::Error>(event_module)
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
"#;
        assert!(
            file_has_distributed_consumer_evidence(&syn::parse_file(canonical)?),
            "canonical fully-qualified producer and consumer paths must pass"
        );

        let same_name_decoy = canonical.replace(
            "crate::distributed_runtime::wire_distributed",
            "crate::decoy::wire_distributed",
        );
        assert!(
            !file_has_distributed_consumer_evidence(&syn::parse_file(&same_name_decoy)?),
            "same-name producer in a non-canonical module must be rejected"
        );

        let alias_decoy = canonical
            .replace(
                "impl InfraBuilt {",
                "use crate::distributed_runtime::wire_distributed as build_distributed;\n\nimpl InfraBuilt {",
            )
            .replace(
                "crate::distributed_runtime::wire_distributed",
                "build_distributed",
            );
        assert!(
            !file_has_distributed_consumer_evidence(&syn::parse_file(&alias_decoy)?),
            "aliases are intentionally unsupported and must be rejected"
        );

        let consumer_decoy = canonical.replace(
            "crate::event_transport::wire_event_transport",
            "crate::decoy::wire_event_transport",
        );
        assert!(
            !file_has_distributed_consumer_evidence(&syn::parse_file(&consumer_decoy)?),
            "same-name consumer in a non-canonical module must be rejected"
        );
        Ok(())
    }

    #[test]
    fn active_distributed_provider_reordered_comment_or_test_bait_is_rejected() -> anyhow::Result<()>
    {
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
            "phase/domains.rs",
            r#"
#[cfg(test)]
impl InfraBuilt {
    async fn wire_domains(self) {
        let result = async move {
            let distributed = wire_distributed(&deps, distributed_worker)?;
            let event_module = wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            ).await?;
            Ok::<_, anyhow::Error>(event_module)
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}

impl InfraBuilt {
    async fn wire_domains(self) {
        // wire_distributed(&deps, distributed_worker)
        let result = async move {
            let _bait = "wire_event_transport(&deps.pg, distributed)";
            Ok::<_, anyhow::Error>(())
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}

fn outer_bait() {
    let distributed = wire_distributed(&deps, distributed_worker);
    let _ = wire_event_transport(&deps.pg, distributed);
}
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDistributedProviderConsumer),
            "comment/string/cfg(test)/outer-function bait must not satisfy the phase-owner consumer guard: {findings:?}"
        );

        write_runtime_src(
            &root,
            "phase/domains.rs",
            r#"
impl InfraBuilt {
    async fn wire_domains(self) {
        let result = async move {
            let event_module = wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            ).await?;
            let distributed = wire_distributed(&deps, distributed_worker)?;
            Ok::<_, anyhow::Error>(event_module)
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
"#,
        )?;
        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDistributedProviderConsumer),
            "a consumer ordered before its distributed producer must fail closed: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_distributed_provider_without_domains_phase_consumer_is_rejected() -> anyhow::Result<()>
    {
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
    fn demo_draft_ephemeral_revocation_provider_is_rejected_by_canonical_registry()
    -> anyhow::Result<()> {
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
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::InvalidDiportProvider)
                .count(),
            2,
            "canonical lifecycle and durability must both fail closed: {findings:?}"
        );
        assert!(
            findings.iter().any(|finding| {
                finding.detail.contains("field=diportProviders.lifecycle")
                    && finding.detail.contains("expected=active actual=draft")
            }),
            "canonical lifecycle mismatch missing: {findings:?}"
        );
        assert!(
            findings.iter().any(|finding| {
                finding.detail.contains("field=diportProviders.durability")
                    && finding
                        .detail
                        .contains("expected=persistent actual=ephemeral-memory")
            }),
            "canonical durability mismatch missing: {findings:?}"
        );
        Ok(())
    }

    // ---- #1251 eventbus 真传输 provider（diport::Publisher / diport::AckableSubscriber）----

    /// demo-profile manifest，单条 amqp transport provider（topology-gated durable 选型）。
    #[allow(clippy::panic)]
    // reason: closed test helper rejects accidental non-AMQP fixture input at the call site.
    fn amqp_manifest(provider: &str, port: &str, lifecycle: &str, durability: &str) -> String {
        let role = match provider {
            "amqp::AmqpPublisher" => "event-publisher",
            "amqp::AmqpSubscriber" => "event-subscriber",
            _ => panic!("test helper only admits closed AMQP providers"),
        };
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
id = "{role}"
port = "{port}"
provider = "{provider}"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "{lifecycle}"
durability = "{durability}"
purpose = "eventbus-transport"
outputs = ["probes", "resources", "workers"]
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
outputs = ["resources"]
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
outputs = ["resources"]
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
outputs = ["resources"]

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
scope = "cluster-global"
failurePosture = "fail-closed"
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
outputs = ["resources"]
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
            findings.iter().any(|f| {
                f.rule == Rule::InvalidDiportProvider && f.detail.contains("durability")
            }),
            "closed subscriber role must reject ephemeral durability before downstream consumption: {findings:?}"
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
            findings.iter().any(|f| {
                f.rule == Rule::InvalidDiportProvider && f.detail.contains("durability")
            }),
            "closed publisher role must reject ephemeral durability before downstream consumption: {findings:?}"
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
            findings
                .iter()
                .any(|f| f.rule == Rule::InvalidDiportProvider && f.detail.contains("port")),
            "closed publisher role must reject the subscriber port before downstream consumption: {findings:?}"
        );
        Ok(())
    }
}
