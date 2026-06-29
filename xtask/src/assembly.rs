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
const PUBLISHER_PORT: &str = "diport::Publisher";
const ACKABLE_SUBSCRIBER_PORT: &str = "diport::AckableSubscriber";
const SIGNER_PORT: &str = "diport::Signer";
const PDP_PORT: &str = "diport::Pdp";
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
    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 { level = "Medium", exec = "verify", source = "code" }— provider↔providerCrate 绑定由 xtask provider
    /// matrix 单源锁定；manifest 声明错误 crate 名须被机器拒（Medium，red test 反恒真）。
    ProviderCrateMismatch,
    /// active distributed provider 必须有组合根 consumer 接线证据。
    ActiveDistributedProviderConsumer,
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
    /// `diport::Publisher` —— at-most-once 事件发布端口（amqp publisher 实现，#1251）。
    #[serde(rename = "diport::Publisher")]
    Publisher,
    /// `diport::AckableSubscriber` —— manual-ack at-least-once 订阅端口（amqp subscriber 实现，#1251）。
    #[serde(rename = "diport::AckableSubscriber")]
    AckableSubscriber,
    #[serde(rename = "diport::Signer")]
    Signer,
    #[serde(rename = "diport::Pdp")]
    Pdp,
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
            Self::Publisher => PUBLISHER_PORT,
            Self::AckableSubscriber => ACKABLE_SUBSCRIBER_PORT,
            Self::Signer => SIGNER_PORT,
            Self::Pdp => PDP_PORT,
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
    dir: PathBuf,
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
            dir,
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

            if is_active_distributed_provider(provider) && !has_distributed_consumer_evidence(a) {
                findings.push(finding(
                    Rule::ActiveDistributedProviderConsumer,
                    &subject,
                    "field=consumer active distributed Lock/CAS provider 必须有 composition-root consumer 证据：wire_distributed + DistributedRuntimeDeps 必填注入真实 consumer",
                ));
            }
        }
    }
    findings
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
        if node.sig.ident != "run" {
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
        // #1251 eventbus 真传输：amqp publisher/subscriber 是 topology-gated durable 选型的 diport-infra
        // provider；真 lapin impl 经 amqp `backend` feature 门控（持久 broker，非内存）。
        "amqp::AmqpPublisher" => Some(ProviderSpec {
            port: DiportPort::Publisher,
            durability: ProviderDurability::Persistent,
            required_features: &["backend"],
            provider_crate: "amqp",
        }),
        "amqp::AmqpSubscriber" => Some(ProviderSpec {
            port: DiportPort::AckableSubscriber,
            durability: ProviderDurability::Persistent,
            required_features: &["backend"],
            provider_crate: "amqp",
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
        "vault::VaultSigner" => Some(ProviderSpec {
            port: DiportPort::Signer,
            durability: ProviderDurability::Persistent,
            required_features: &["backend"],
            provider_crate: "vault",
        }),
        "oidc::OidcProvider" => Some(ProviderSpec {
            port: DiportPort::Pdp,
            durability: ProviderDurability::Persistent,
            required_features: &["backend"],
            provider_crate: "oidc",
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
        write_runtime_src(
            &root,
            "lib.rs",
            r#"
pub struct DistributedRuntimeDeps;
	pub fn wire_distributed(_: &SharedRuntimeDeps) -> DistributedRuntimeDeps { DistributedRuntimeDeps }
	pub struct SharedRuntimeDeps;
	pub fn run(deps: &SharedRuntimeDeps) {
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
    fn active_distributed_provider_comment_or_dead_helper_evidence_is_rejected()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-distributed-string-evidence");
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

fn unused_helper(deps: &SharedRuntimeDeps) {
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
            "comment/string/dead helper evidence must not satisfy real consumer guard: {findings:?}"
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

[[diportProviders]]
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
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

    // ---- #1251 eventbus 真传输 provider（diport::Publisher / diport::AckableSubscriber）----

    /// demo-profile manifest，单条 amqp transport provider（topology-gated durable 选型）。
    fn amqp_manifest(provider: &str, port: &str, lifecycle: &str, durability: &str) -> String {
        format!(
            r#"
name = "runtime"
profile = "demo"

[[diportProviders]]
port = "{port}"
provider = "{provider}"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "{lifecycle}"
durability = "{durability}"
purpose = "eventbus-transport"
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

[[diportProviders]]
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
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

[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
"#,
            r#"[package]
name = "runtime"

[dependencies]
oidc = { path = "../../adapters/oidc", features = ["backend"] }
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
        // amqp::AmqpPublisher 声明在 AckableSubscriber 端口上 ⇒ spec.port 不匹配 ⇒ ActiveProviderPort。
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
