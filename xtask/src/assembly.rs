//! `assembly validate` —— assembly-level DI provider 声明治理。
//!
//! DI-infra port（如 `diport::RevocationStore` / `diport::LockStore` / `diport::CasStore`）不是跨域 wire
//! contract，不放进 `contracts/**/contract.toml`。
//! 但 provider 选择属于组合根部署事实：哪个 assembly 注入哪个 provider、是否持久、是否已 active，必须有机器可读
//! 声明和 verify 门，避免生产在 dev/demo provider 上静默运行。

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const REVOCATION_STORE_PORT: &str = "diport::RevocationStore";
const RATE_LIMITER_PORT: &str = "diport::RateLimiter";
const LOCK_STORE_PORT: &str = "diport::LockStore";
const CAS_STORE_PORT: &str = "diport::CasStore";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// `assemblies/*/Cargo.toml` 必须有同目录 `assembly.toml`。
    MissingManifest,
    /// assembly manifest 不能空转：至少声明一个 DI provider。
    EmptyDiportProviders,
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
    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 — provider↔providerCrate 绑定由 xtask provider
    /// matrix 单源锁定；manifest 声明错误 crate 名须被机器拒（Medium，red test 反恒真）。
    ProviderCrateMismatch,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssemblyManifest {
    pub(crate) name: String,
    pub(crate) profile: AssemblyProfile,
    #[serde(rename = "diportProviders")]
    pub(crate) diport_providers: Vec<DiportProvider>,
}

impl AssemblyManifest {
    pub(crate) fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AssemblyProfile {
    Production,
    Demo,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiportProvider {
    pub(crate) port: DiportPort,
    pub(crate) provider: String,
    #[serde(rename = "providerCrate")]
    pub(crate) provider_crate: String,
    #[serde(default, rename = "requiredFeatures")]
    pub(crate) required_features: Vec<String>,
    pub(crate) consumer: String,
    pub(crate) lifecycle: ProviderLifecycle,
    pub(crate) durability: ProviderDurability,
    pub(crate) purpose: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum DiportPort {
    #[serde(rename = "diport::RevocationStore")]
    RevocationStore,
    #[serde(rename = "diport::RateLimiter")]
    RateLimiter,
    #[serde(rename = "diport::LockStore")]
    Lock,
    #[serde(rename = "diport::CasStore")]
    Cas,
}

impl DiportPort {
    fn as_str(self) -> &'static str {
        match self {
            Self::RevocationStore => REVOCATION_STORE_PORT,
            Self::RateLimiter => RATE_LIMITER_PORT,
            Self::Lock => LOCK_STORE_PORT,
            Self::Cas => CAS_STORE_PORT,
        }
    }
}

impl fmt::Display for DiportPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProviderLifecycle {
    Draft,
    Active,
    Deprecated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProviderDurability {
    EphemeralMemory,
    Persistent,
}

impl fmt::Display for ProviderDurability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EphemeralMemory => f.write_str("ephemeral-memory"),
            Self::Persistent => f.write_str("persistent"),
        }
    }
}

struct DiscoveredAssembly {
    manifest_label: String,
    cargo_label: String,
    manifest_src: String,
    manifest: AssemblyManifest,
    cargo_toml: toml::Value,
}

pub(crate) fn validate_root(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let (assemblies, mut findings) = discover(root)?;
    for assembly in &assemblies {
        findings.extend(validate_assembly(assembly));
    }
    Ok((assemblies.len(), findings))
}

fn discover(root: &Path) -> Result<(Vec<DiscoveredAssembly>, Vec<Finding>)> {
    let assemblies_root = root.join("assemblies");
    if !assemblies_root.exists() {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&assemblies_root)
        .with_context(|| format!("读 assembly 目录 {} 失败", assemblies_root.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "遍历 assembly 目录失败")?
        .into_iter()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    let mut assemblies = Vec::new();
    let mut findings = Vec::new();
    for dir in dirs {
        let manifest_path = dir.join("assembly.toml");
        let cargo_path = dir.join("Cargo.toml");
        if !manifest_path.exists() {
            if cargo_path.exists() {
                let label = dir.strip_prefix(root).unwrap_or(&dir).display().to_string();
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
        let manifest_src = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("读 {} 失败", manifest_path.display()))?;
        let cargo_src = std::fs::read_to_string(&cargo_path)
            .with_context(|| format!("读 {} 失败", cargo_path.display()))?;
        let manifest = AssemblyManifest::from_toml_str(&manifest_src)
            .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
        let cargo_toml: toml::Value = toml::from_str(&cargo_src)
            .with_context(|| format!("解析 {} 失败", cargo_path.display()))?;
        let manifest_label = rel_label(root, &manifest_path);
        let cargo_label = rel_label(root, &cargo_path);
        assemblies.push(DiscoveredAssembly {
            manifest_label,
            cargo_label,
            manifest_src,
            manifest,
            cargo_toml,
        });
    }
    Ok((assemblies, findings))
}

fn validate_assembly(a: &DiscoveredAssembly) -> Vec<Finding> {
    let mut findings = Vec::new();
    if a.manifest.diport_providers.is_empty() {
        findings.push(finding(
            Rule::EmptyDiportProviders,
            &a.manifest_label,
            "field=diportProviders 至少声明一个 provider，避免 assembly fact source 空转通过",
        ));
        return findings;
    }

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
            let spec = provider_spec(&provider.provider);
            match spec {
                Some(spec) if spec.port == provider.port => {
                    if spec.durability != provider.durability {
                        findings.push(finding(
                            Rule::ProviderDurabilityMismatch,
                            &subject,
                            format!(
                                "field=durability provider `{}` 的真实 durability 是 `{}`，manifest 不得声明为 `{}`",
                                provider.provider,
                                spec.durability,
                                provider.durability
                            ),
                        ));
                    }
                    if spec.provider_crate != provider.provider_crate {
                        findings.push(finding(
                            Rule::ProviderCrateMismatch,
                            &subject,
                            format!(
                                "field=providerCrate provider `{}` 的实现 crate 是 `{}`，manifest 不得声明为 `{}`",
                                provider.provider,
                                spec.provider_crate,
                                provider.provider_crate
                            ),
                        ));
                    }
                }
                _ => findings.push(finding(
                    Rule::ActiveProviderPort,
                    &subject,
                    format!(
                        "field=provider active provider `{}` 未在 xtask provider matrix 中声明为 `{}` 的实现",
                        provider.provider, provider.port
                    ),
                )),
            }

            let required_features = required_features(provider, spec);
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
        }
    }
    findings
}

#[derive(Clone, Copy)]
struct ProviderSpec {
    port: DiportPort,
    durability: ProviderDurability,
    required_features: &'static [&'static str],
    /// xtask provider matrix 锁定的实现 crate 名；必须与 manifest `providerCrate` 严格匹配。
    provider_crate: &'static str,
}

fn provider_spec(provider: &str) -> Option<ProviderSpec> {
    match provider {
        "softca::InMemRevocationLedger" => Some(ProviderSpec {
            port: DiportPort::RevocationStore,
            durability: ProviderDurability::EphemeralMemory,
            required_features: &["backend"],
            provider_crate: "softca",
        }),
        "ratelimit::GovernorLimiter" => Some(ProviderSpec {
            port: DiportPort::RateLimiter,
            durability: ProviderDurability::EphemeralMemory,
            required_features: &[],
            provider_crate: "ratelimit",
        }),
        "redis::RedisLockStore" => Some(ProviderSpec {
            port: DiportPort::Lock,
            durability: ProviderDurability::Persistent,
            required_features: &["backend"],
            provider_crate: "redis",
        }),
        "redis::RedisCasStore" => Some(ProviderSpec {
            port: DiportPort::Cas,
            durability: ProviderDurability::Persistent,
            required_features: &["backend"],
            provider_crate: "redis",
        }),
        "postgres::PgCasStore" => Some(ProviderSpec {
            port: DiportPort::Cas,
            durability: ProviderDurability::Persistent,
            required_features: &[],
            provider_crate: "postgres",
        }),
        _ => None,
    }
}

fn required_features(provider: &DiportProvider, spec: Option<ProviderSpec>) -> Vec<&str> {
    let mut features: Vec<&str> = provider
        .required_features
        .iter()
        .map(String::as_str)
        .collect();
    if let Some(spec) = spec {
        features.extend(spec.required_features);
    }
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

    fn valid_manifest_with_profile(profile: &str, provider_extra: &str) -> String {
        format!(
            r#"
name = "runtime"
profile = "{profile}"

[[diportProviders]]
port = "diport::RevocationStore"
provider = "softca::InMemRevocationLedger"
providerCrate = "softca"
consumer = "deviceloop"
purpose = "device-certificate-revocation"
{provider_extra}
"#
        )
    }

    fn valid_manifest(provider_extra: &str) -> String {
        valid_manifest_with_profile("production", provider_extra)
    }

    #[test]
    fn manifest_rejects_unknown_fields() {
        let raw = r#"
name = "runtime"
profile = "production"
unknown = true

[[diportProviders]]
port = "diport::RevocationStore"
provider = "softca::InMemRevocationLedger"
providerCrate = "softca"
consumer = "deviceloop"
lifecycle = "draft"
durability = "ephemeral-memory"
purpose = "device-certificate-revocation"
"#;
        assert!(AssemblyManifest::from_toml_str(raw).is_err());
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
diportProviders = []
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
                .contains("assemblies/runtime/assembly.toml:5"),
            "{finding:?}"
        );
        assert!(finding.detail.contains("field=durability"), "{finding:?}");
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
    fn active_provider_must_match_known_port_matrix() -> anyhow::Result<()> {
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

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.iter().any(|f| f.rule == Rule::ActiveProviderPort),
            "unknown active provider must be rejected: {findings:?}"
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

[[diportProviders]]
port = "diport::RevocationStore"
provider = "softca::InMemRevocationLedger"
providerCrate = "softca"
consumer = "deviceloop"
lifecycle = "draft"
durability = "ephemeral-memory"
purpose = "device-certificate-revocation"

[[diportProviders]]
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting (pre-auth, DoS/brute-force 防护)"
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

[[diportProviders]]
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"

[[diportProviders]]
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
"#,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        let (_count, findings) = validate_root(&root)?;
        assert!(
            findings.is_empty(),
            "active distributed Lock/Cas providers (feature + providerCrate bound) must pass: {findings:?}"
        );
        Ok(())
    }

    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 — provider↔providerCrate 绑定 red test（anti-vacuity）。
    /// `ratelimit::GovernorLimiter` 与 `providerCrate = "softca"` 不匹配，active 声明必须被拒。
    #[test]
    fn active_provider_with_wrong_provider_crate_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-crate-mismatch");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"

[[diportProviders]]
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "softca"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting"
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

    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 — provider↔providerCrate 绑定正例（non-vacuous green path）。
    /// `ratelimit::GovernorLimiter` + `providerCrate = "ratelimit"` 正确绑定，不应产生 ProviderCrateMismatch。
    #[test]
    fn active_provider_with_correct_provider_crate_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-crate-correct");
        write_assembly(
            &root,
            r#"
name = "runtime"
profile = "demo"

[[diportProviders]]
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting"
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
}
