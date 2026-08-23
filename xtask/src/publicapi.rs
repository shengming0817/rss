//! 两类 Rust exported-symbol baseline 的唯一实现。
//!
//! `internal` owner 写入 `public-api/`，只证明内部签名漂移；`release` owner 写入
//! `release-api/`，目标严格来自 validated positive Release Surface。baseline 本身不授予 Release API。
//!
//! 依赖：外部 `cargo-public-api`（版本由 CI tool catalog 编译期派生）+ 钉版 nightly rustdoc-json
//! （`rustup toolchain install <PINNED_NIGHTLY>`，见 [`PINNED_NIGHTLY`]）。未满足时本命令给指引并**非零退出**（非静默 noop）。
//!
//! **不在 `cargo xtask verify` 快门内**：本命令提供 owner-typed baseline；完整 ReleaseCheck 的唯一
//! `public-api` gate 在同一实现内聚合 internal/release exact-set、逐包 SemVer、公共依赖与类型泄漏。
//!
//! INVARIANT: PUBLICAPI-TOOL-GATE-01 { level = "Medium", exec = "release-check", source = "public-api" }—— 工具缺失 fail-fast，不静默成功。
//! INVARIANT: PUBLICAPI-DRIFT-GATE-01 { level = "Medium", exec = "release-check", source = "public-api" }—— owner exact-set 的缺失、漂移、孤儿和异常目录均 fail-closed。
//! INVARIANT: RELEASE-API-OWNER-PROJECTION-01 { level = "Medium", exec = "release-check", source = "public-api", synthetic_red = "tests::checked_in_rustdoc_fixture_filters_only_external_blanket_impl_noise|tests::release_projection_rejects_malformed_blanket_identity", anti_vacuity = "tests::checked_in_rustdoc_fixture_filters_only_external_blanket_impl_noise" }—— leakage proof 只排除 typed identity 证明属于外部 trait owner 的 blanket impl projection；owned signature 与不可解析 identity 保持 fail-closed。
//! INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }—— rustdoc-json 用钉版 nightly（[`PINNED_NIGHTLY`]，非 rolling）；该 pin 四处
//!   一致：`PINNED_NIGHTLY` ⇔ `lints/rust-toolchain.toml` channel ⇔ reusable CI `RSS_NIGHTLY_PINNED`（三方功能值，
//!   `pinned_nightly_single_source_of_truth` 守）+ `verify.rs` public-api install_hint（`verify::tests::
//!   public_api_install_hint_pins_nightly` 守，绑真实字段值非源码全文）。漂移即 fail。

use crate::layers::{BASIS_CRATES, ENGINE_CRATES};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use workspacefacts::{PackageKey, PublicApiOwner, TargetKind, WorkspaceFacts};

/// INVARIANT: EVENTING-CONSUMER-TX-PUBLIC-SURFACE-01 { level = "Medium", exec = "check", source = "public-api", synthetic_red = "tests::consumer_tx_surface_rejects_extra_public_owner|tests::consumer_tx_surface_rejects_trait_bridge|tests::consumer_tx_surface_rejects_associated_item|tests::consumer_tx_root_rejects_alias_facade", anti_vacuity = "tests::real_consumer_tx_surface_is_exact|tests::consumer_tx_surface_allows_private_implementation" } -- the current Eventing transaction seam exposes exactly one flat outcome and one reject kind from its owner module; runtime/provider types and compatibility facades are forbidden.
fn validate_consumer_tx_public_surface(root: &Path) -> Result<()> {
    let path = root.join("crates/eventexec/src/consumer_tx.rs");
    let source = fs::read_to_string(&path)
        .with_context(|| format!("读取 ConsumerTx 公共面失败: {}", path.display()))?;
    validate_consumer_tx_public_source(&source)
        .with_context(|| format!("ConsumerTx 公共面不符合 exact-set: {}", path.display()))?;

    let root_path = root.join("crates/eventexec/src/lib.rs");
    let root_source = fs::read_to_string(&root_path)
        .with_context(|| format!("读取 eventexec crate root 失败: {}", root_path.display()))?;
    validate_consumer_tx_root_source(&root_source).with_context(|| {
        format!(
            "ConsumerTx crate-root facade 被禁止: {}",
            root_path.display()
        )
    })
}

fn validate_consumer_tx_public_source(source: &str) -> Result<()> {
    use quote::ToTokens as _;

    let file = syn::parse_file(source).context("解析 ConsumerTx owner 模块失败")?;
    let public_items = file
        .items
        .iter()
        .filter(|item| match item {
            syn::Item::Const(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Enum(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Fn(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Mod(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Static(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Struct(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Trait(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::TraitAlias(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Type(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Union(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Use(item) => matches!(item.vis, syn::Visibility::Public(_)),
            _ => false,
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        public_items.len() == 2,
        "owner module must expose exactly two public items"
    );

    let mut enums = BTreeMap::new();
    for item in public_items {
        let syn::Item::Enum(item) = item else {
            bail!("ConsumerTx owner public surface may contain enums only")
        };
        enums.insert(item.ident.to_string(), item);
    }
    anyhow::ensure!(
        enums.keys().map(String::as_str).collect::<Vec<_>>() == ["ConsumerTxOutcome", "RejectKind"],
        "ConsumerTx owner enum exact-set drifted"
    );

    let reject = enums["RejectKind"];
    anyhow::ensure!(
        reject.generics.params.is_empty(),
        "RejectKind must not be generic"
    );
    assert_enum_shape(reject, &[("Permanent", None), ("Invariant", None)])?;

    let outcome = enums["ConsumerTxOutcome"];
    anyhow::ensure!(
        outcome.generics.params.len() == 1
            && matches!(outcome.generics.params.first(), Some(syn::GenericParam::Type(param)) if param.ident == "C"),
        "ConsumerTxOutcome must carry only generic commit proof C"
    );
    assert_enum_shape(
        outcome,
        &[
            ("Committed", Some("C")),
            ("HandlerTransient", None),
            ("InfrastructureTransient", None),
            ("Rejected", Some("RejectKind")),
            ("CommitUnknown", None),
            ("RollbackFailed", None),
            ("Fenced", None),
        ],
    )?;

    let mut public_methods = BTreeMap::<String, Vec<&syn::ImplItemFn>>::new();
    for item in &file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        let owner = item.self_ty.to_token_stream().to_string().replace(' ', "");
        if item.trait_.is_some() {
            anyhow::ensure!(
                !owner.starts_with("ConsumerTxOutcome"),
                "ConsumerTxOutcome trait bridges are forbidden"
            );
            continue;
        }
        if owner != "RejectKind" && owner != "ConsumerTxOutcome<C>" {
            continue;
        }
        for member in &item.items {
            match member {
                syn::ImplItem::Fn(method) if matches!(method.vis, syn::Visibility::Public(_)) => {
                    public_methods
                        .entry(owner.clone())
                        .or_default()
                        .push(method);
                }
                syn::ImplItem::Const(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
                    bail!("public associated const is forbidden for {owner}")
                }
                syn::ImplItem::Type(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
                    bail!("public associated type is forbidden for {owner}")
                }
                _ => {}
            }
        }
    }
    anyhow::ensure!(
        public_methods
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == ["ConsumerTxOutcome<C>", "RejectKind"],
        "ConsumerTx owner public impl exact-set drifted"
    );
    for (owner, methods) in public_methods {
        let expected_signature = match owner.as_str() {
            "RejectKind" => "constfnas_label(self)->&'staticstr",
            "ConsumerTxOutcome<C>" => "constfnas_label(&self)->&'staticstr",
            _ => unreachable!("owner exact-set checked above"),
        };
        let actual_signature = methods
            .first()
            .map(|method| method.sig.to_token_stream().to_string().replace(' ', ""));
        anyhow::ensure!(
            methods.len() == 1
                && methods[0].sig.ident == "as_label"
                && actual_signature.as_deref() == Some(expected_signature),
            "{owner} may expose only const as_label"
        );
    }
    Ok(())
}

fn validate_consumer_tx_root_source(source: &str) -> Result<()> {
    fn exposes_consumer_tx(item: &syn::Item) -> bool {
        use quote::ToTokens as _;

        if let syn::Item::Mod(module) = item {
            if !matches!(module.vis, syn::Visibility::Public(_)) {
                return false;
            }
            return module
                .content
                .as_ref()
                .is_some_and(|(_, items)| items.iter().any(exposes_consumer_tx));
        }
        let is_public = match item {
            syn::Item::Const(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Enum(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::ExternCrate(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Fn(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Static(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Struct(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Trait(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::TraitAlias(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Type(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Union(item) => matches!(item.vis, syn::Visibility::Public(_)),
            syn::Item::Use(item) => matches!(item.vis, syn::Visibility::Public(_)),
            _ => false,
        };
        if !is_public {
            return false;
        }
        let tokens = item.to_token_stream().to_string().replace(' ', "");
        tokens.contains("ConsumerTxOutcome")
            || tokens.contains("RejectKind")
            || tokens.contains("consumer_tx::")
    }

    let file = syn::parse_file(source).context("解析 eventexec crate root 失败")?;
    for item in &file.items {
        if matches!(item, syn::Item::Mod(module) if module.ident == "consumer_tx") {
            continue;
        }
        anyhow::ensure!(
            !exposes_consumer_tx(item),
            "ConsumerTx root alias, facade, or re-export is forbidden"
        );
    }
    Ok(())
}

fn assert_enum_shape(item: &syn::ItemEnum, expected: &[(&str, Option<&str>)]) -> Result<()> {
    use quote::ToTokens as _;

    anyhow::ensure!(
        item.variants.len() == expected.len(),
        "{} variant count drifted",
        item.ident
    );
    for (variant, (name, field_type)) in item.variants.iter().zip(expected) {
        anyhow::ensure!(
            variant.ident == *name,
            "{} variant order/name drifted",
            item.ident
        );
        match (&variant.fields, field_type) {
            (syn::Fields::Unit, None) => {}
            (syn::Fields::Unnamed(fields), Some(expected_type)) if fields.unnamed.len() == 1 => {
                let actual = fields.unnamed[0]
                    .ty
                    .to_token_stream()
                    .to_string()
                    .replace(' ', "");
                anyhow::ensure!(
                    actual == *expected_type,
                    "{}::{name} payload drifted",
                    item.ident
                );
            }
            _ => bail!("{}::{name} field shape drifted", item.ident),
        }
    }
    Ok(())
}

static GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// 分层成员单源 = `layers.rs`（basis = PR-1 验收集、engine = PR-2 验收集）；此处复用，不另列副本。
// curated extras 不是架构 layer，只是安全敏感 exported-symbol 面的定点 golden 例外；其中 internal crate
// 的 baseline 是漂移审查，不是 Release API / SemVer 承诺。
// `diport`（DI-infra 层，非 basis/engine）：持全部安全敏感 DI port（Signer/SecretResolver/Pdp/Revocation/
// KeyProvider…），以 internal exported-symbol baseline 锁住安全/封装漂移，列入 curated extras（#1470）。
// `generated` 暴露 contract-derived metadata，作为 PR review 审查材料定点冻结（#1472/#1688）。
// `runtimeexec` 的 launch/probe/inventory hook 是三个 assembly 的稳定内部接缝（#1795）；冻结其窄公开面，
// 防止 ShutdownStack、HTTP/provider 类型或第二 executor 意外外泄。
const CURATED_EXTRA_CRATES: &[&str] = &["authn", "diport", "generated", "runtimeexec"];

/// public-api baseline（rustdoc-json）用的**钉版 nightly**。cargo-public-api 在 stable 上探测到 stable
/// 编译器即强制回退 rolling `nightly`（其 rustdoc-json 格式随日期漂移 ⇒ baseline 误报）；本 const 经
/// [`public_api_cmd`] 设 `RUSTUP_TOOLCHAIN`（等价 `cargo +<此值> public-api`）把 nightly 钉死，使快照可复现（#1145）。
///
/// **单一事实源（NIGHTLY-PIN-01）**：本 const ⇔ `lints/rust-toolchain.toml` 的 `[toolchain].channel`
/// （dylint 实际 nightly）⇔ `.github/workflows/rss-rust-job.yml` 的 `RSS_NIGHTLY_PINNED`（CI 安装的 nightly）三方功能值由
/// `pinned_nightly_single_source_of_truth` 守；第四处 `verify.rs` public-api install_hint 由
/// `verify::tests::public_api_install_hint_pins_nightly` 守（绑真实 install_hint 字段值、非源码全文，避免注释
/// 含 pin 的误绿）——漂移即 fail。**与 dylint nightly 成对、CI 只装一份**：dylint 因 `clippy_utils` rev 升 nightly 时——
/// 该 rev 与本 nightly 配对（见 `lints/rss_*/Cargo.toml`，由 dylint 编译失败 **Hard** 强制，非本治理测试
/// 覆盖）——**须同步重跑 owner-typed `cargo xtask public-api internal|release`**；忘记不会静默，会被
/// PUBLICAPI-DRIFT-GATE-01（`--check`，共用同一 pin）在 CI 直接 drift-fail 抓住。
pub(crate) const PINNED_NIGHTLY: &str = "nightly-2026-04-16";

/// 封装面 baseline 的目标层。无 `--layer` 时取 basis + engine + curated extras 全集（收口 GATE 用）。
/// 服务/域/adapters 内部接缝默认多变，不整体入 baseline；安全敏感 crate 需定点列入 curated extras。
#[derive(Debug, PartialEq, Eq, Clone, Copy, clap::ValueEnum)]
pub(crate) enum InternalLayer {
    Basis,
    Engine,
    Curated,
}

/// 解析 layer → 目标 crate 集。`None` = basis + engine + curated extras（不另列第三份 ALL，避免漂移）。
/// 排除 proc-macro 工具 crate（[`crate::layers::is_proc_macro`]）——其契约由 codegen golden 守，
/// 非 SemVer 库 API 面，不入 public-api baseline。
pub(crate) fn target_crates(layer: Option<InternalLayer>) -> Vec<&'static str> {
    let select: Vec<&'static str> = match layer {
        Some(InternalLayer::Basis) => BASIS_CRATES.to_vec(),
        Some(InternalLayer::Engine) => ENGINE_CRATES.to_vec(),
        Some(InternalLayer::Curated) => CURATED_EXTRA_CRATES.to_vec(),
        None => BASIS_CRATES
            .iter()
            .chain(ENGINE_CRATES)
            .chain(CURATED_EXTRA_CRATES)
            .copied()
            .collect(),
    };
    select
        .into_iter()
        .filter(|c| !crate::layers::is_proc_macro(c))
        .collect()
}

#[derive(Debug, PartialEq, Eq, clap::Subcommand)]
pub(crate) enum Command {
    /// Update/check internal signatures; update removes stale snapshots in the selected scope.
    Internal {
        /// Read-only fail-closed validation; without it, update the selected baseline scope.
        #[arg(long)]
        check: bool,
        /// Limit update/check and stale cleanup to one complete layer ownership universe.
        #[arg(long, value_enum)]
        layer: Option<InternalLayer>,
    },
    /// Update/check the complete release-selected owner and remove stale snapshots on update.
    Release {
        /// Read-only fail-closed validation; without it, atomically update the complete owner.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BaselineOwner {
    Internal,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BaselineScope {
    Complete(BaselineOwner),
    InternalLayer(InternalLayer),
    AffectedInternal,
}

#[derive(Clone, Copy)]
enum StaticBaselineScope {
    Complete(BaselineOwner),
    InternalLayer(InternalLayer),
}

impl BaselineScope {
    const fn owner(self) -> BaselineOwner {
        match self {
            Self::Complete(owner) => owner,
            Self::InternalLayer(_) | Self::AffectedInternal => BaselineOwner::Internal,
        }
    }
}

impl BaselineOwner {
    const fn label(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Release => "release",
        }
    }

    const fn directory(self) -> &'static str {
        match self {
            Self::Internal => "public-api",
            Self::Release => "release-api",
        }
    }
}

#[derive(Debug)]
struct BaselineCatalog {
    internal_universe: Vec<PackageKey>,
    internal: Vec<PackageKey>,
    release: Vec<PackageKey>,
    library_targets: BTreeMap<PackageKey, String>,
}

impl BaselineCatalog {
    fn derive(root: &Path, facts: &WorkspaceFacts) -> Result<Self> {
        crate::workspace_facts::validate_command_funnel(root)?;
        crate::assembly_governance::validate_source_funnel(root)?;
        let ir = crate::assembly_governance::AssemblyGovernanceIr::<
            crate::assembly_governance::Core,
        >::load(root)?;
        let artifacts = if crate::release_surface::requires_artifact_join(facts) {
            let joined =
                ir.join_artifacts(crate::assembly_governance::load_artifact_declaration(root)?)?;
            crate::release_surface::project_artifacts(&joined)
        } else {
            Vec::new()
        };
        let (surface, findings) = crate::release_surface::validate(facts, &artifacts);
        if !findings.is_empty() {
            let details = findings
                .iter()
                .map(crate::diagnostic::format_finding)
                .collect::<Vec<_>>()
                .join("\n");
            bail!("validated Release Surface 失败:\n{details}");
        }
        let surface = surface.context("validated Release Surface 未生成 typed surface")?;
        Self::from_release_surface(facts, &surface)
    }

    fn from_release_surface(
        facts: &WorkspaceFacts,
        surface: &crate::release_surface::ReleaseSurface,
    ) -> Result<Self> {
        Self::from_selected_packages(
            facts,
            surface.packages().iter().map(|package| package.package()),
        )
    }

    fn derive_from_release_surface(
        root: &Path,
        facts: &WorkspaceFacts,
        surface: &crate::release_surface::ReleaseSurface,
    ) -> Result<Self> {
        crate::workspace_facts::validate_command_funnel(root)?;
        crate::assembly_governance::validate_source_funnel(root)?;
        Self::from_release_surface(facts, surface)
    }

    fn from_selected_packages<'a>(
        facts: &WorkspaceFacts,
        selected: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        let release = selected
            .into_iter()
            .map(|name| resolve_library(facts, name))
            .collect::<Result<BTreeSet<_>>>()?;
        let internal_universe = target_crates(None)
            .into_iter()
            .map(|name| resolve_library(facts, name))
            .collect::<Result<BTreeSet<_>>>()?;
        let internal = internal_universe.difference(&release).cloned().collect();
        let library_targets = internal_universe
            .union(&release)
            .map(|package| {
                let target = facts
                    .targets_for(package)?
                    .iter()
                    .find(|target| target.kind() == TargetKind::Library)
                    .with_context(|| {
                        format!("baseline target `{}` 没有 library target", package.as_str())
                    })?;
                Ok((package.clone(), target.name().to_owned()))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            internal_universe: internal_universe.into_iter().collect(),
            internal,
            release: release.into_iter().collect(),
            library_targets,
        })
    }

    fn plan(&self, selection: StaticBaselineScope) -> BaselinePlan {
        let (scope, targets, universe) = match selection {
            StaticBaselineScope::Complete(BaselineOwner::Internal) => (
                BaselineScope::Complete(BaselineOwner::Internal),
                self.internal.clone(),
                BaselineUniverse::Complete,
            ),
            StaticBaselineScope::Complete(BaselineOwner::Release) => (
                BaselineScope::Complete(BaselineOwner::Release),
                self.release.clone(),
                BaselineUniverse::Complete,
            ),
            StaticBaselineScope::InternalLayer(layer) => {
                let selected = target_crates(Some(layer))
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                let targets = self
                    .internal
                    .iter()
                    .filter(|package| selected.contains(package.as_str()))
                    .cloned()
                    .collect();
                let universe = self
                    .internal_universe
                    .iter()
                    .filter(|package| selected.contains(package.as_str()))
                    .cloned()
                    .collect();
                (
                    BaselineScope::InternalLayer(layer),
                    targets,
                    BaselineUniverse::Packages(universe),
                )
            }
        };
        BaselinePlan {
            scope,
            universe,
            targets,
            library_targets: self.library_targets.clone(),
        }
    }

    fn affected_internal_plan(&self, packages: &BTreeSet<String>) -> Result<BaselinePlan> {
        let universe = self
            .internal
            .iter()
            .filter(|package| packages.contains(package.as_str()))
            .cloned()
            .collect::<BTreeSet<_>>();
        if universe.len() != packages.len() {
            let known = universe
                .iter()
                .map(|package| package.as_str())
                .collect::<BTreeSet<_>>();
            let unknown = packages
                .iter()
                .filter(|package| !known.contains(package.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            bail!(
                "affected internal public-api packages are not baseline owners: {}",
                unknown.join(", ")
            );
        }
        let targets = self
            .internal
            .iter()
            .filter(|package| packages.contains(package.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        anyhow::ensure!(
            targets.len() == packages.len(),
            "affected internal public-api selection did not resolve every owner"
        );
        Ok(BaselinePlan {
            scope: BaselineScope::AffectedInternal,
            universe: BaselineUniverse::Packages(universe),
            targets,
            library_targets: self.library_targets.clone(),
        })
    }
}

pub(crate) fn affected_internal_packages(
    root: &Path,
    facts: &WorkspaceFacts,
    candidates: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let possible_owners = target_crates(None).into_iter().collect::<BTreeSet<_>>();
    if candidates.is_empty()
        || candidates
            .iter()
            .all(|candidate| !possible_owners.contains(candidate.as_str()))
    {
        return Ok(BTreeSet::new());
    }
    let catalog = BaselineCatalog::derive(root, facts)?;
    let internal = catalog
        .internal
        .iter()
        .map(|package| package.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    Ok(candidates.intersection(&internal).cloned().collect())
}

pub(crate) fn run_affected_internal_check(
    root: &Path,
    facts: &WorkspaceFacts,
    packages: &[String],
) -> Result<()> {
    let selected = packages.iter().cloned().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        !selected.is_empty(),
        "affected internal public-api selection is empty"
    );
    let catalog = BaselineCatalog::derive(root, facts)?;
    let plan = catalog.affected_internal_plan(&selected)?;
    execute(root, &plan, true).map(drop)
}

pub(crate) fn run_complete_internal_check(root: &Path, facts: &WorkspaceFacts) -> Result<()> {
    let catalog = BaselineCatalog::derive(root, facts)?;
    execute(
        root,
        &catalog.plan(StaticBaselineScope::Complete(BaselineOwner::Internal)),
        true,
    )
    .map(drop)
}

fn resolve_library(facts: &WorkspaceFacts, name: &str) -> Result<PackageKey> {
    let package = facts
        .package_key(name)
        .with_context(|| format!("baseline target `{name}` 不属于 workspace"))?;
    let has_library = facts
        .targets_for(&package)?
        .iter()
        .any(|target| target.kind() == TargetKind::Library);
    if !has_library {
        bail!("baseline target `{name}` 没有 library target");
    }
    Ok(package)
}

#[derive(Debug)]
struct BaselinePlan {
    scope: BaselineScope,
    universe: BaselineUniverse,
    targets: Vec<PackageKey>,
    library_targets: BTreeMap<PackageKey, String>,
}

#[derive(Debug, Eq, PartialEq)]
struct ReleaseSelectionDelta {
    semver_packages: Vec<String>,
    first_release_packages: Vec<String>,
    removed_packages: Vec<String>,
}

impl ReleaseSelectionDelta {
    fn derive(current: &BTreeSet<String>, base: &BTreeSet<String>) -> Self {
        Self {
            semver_packages: current.intersection(base).cloned().collect(),
            first_release_packages: current.difference(base).cloned().collect(),
            removed_packages: base.difference(current).cloned().collect(),
        }
    }
}

fn changed_frozen_version_line<'a>(
    base: Option<&'a str>,
    current: &'a str,
) -> Option<(&'a str, &'a str)> {
    base.filter(|base| *base != current)
        .map(|base| (base, current))
}

fn referenced_type_paths(tokens: &[public_api::tokens::Token]) -> BTreeSet<String> {
    use public_api::tokens::Token;
    let mut paths = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if !matches!(token, Token::Type(_)) {
            continue;
        }
        let mut parts = vec![token.text()];
        let mut cursor = index;
        while cursor >= 2
            && matches!(&tokens[cursor - 1], Token::Symbol(symbol) if symbol == "::")
            && matches!(
                &tokens[cursor - 2],
                Token::Identifier(_) | Token::Type(_) | Token::Self_(_)
            )
        {
            parts.push(tokens[cursor - 2].text());
            cursor -= 2;
        }
        parts.reverse();
        paths.insert(parts.join("::"));
    }
    paths
}

fn normalized_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn forbidden_type_root<'a>(
    owner: PublicApiOwner,
    library_target: &str,
    path: &'a str,
    workspace: &BTreeSet<String>,
    selected: &BTreeSet<String>,
    resolved_workspace_dependency: Option<&str>,
) -> Option<&'a str> {
    let (root, qualified) = path
        .split_once("::")
        .map_or((path, false), |(root, _)| (root, true));
    if !qualified
        || matches!(root, "std" | "core" | "alloc")
        || root == normalized_crate_name(library_target)
    {
        return None;
    }
    let workspace_package = resolved_workspace_dependency.or_else(|| {
        workspace
            .iter()
            .find(|candidate| normalized_crate_name(candidate) == root)
            .map(String::as_str)
    });
    if let Some(candidate) = workspace_package {
        return match owner {
            PublicApiOwner::FoundationPublic => Some(root),
            PublicApiOwner::PlatformPublic => {
                (!matches!(candidate, "rss-contract" | "rss-request-context")).then_some(root)
            }
            PublicApiOwner::StandaloneComponent => (!selected.contains(candidate)).then_some(root),
        };
    }
    match owner {
        PublicApiOwner::FoundationPublic => Some(root),
        PublicApiOwner::PlatformPublic => Some(root),
        PublicApiOwner::StandaloneComponent if path == "tracing::Span" => None,
        PublicApiOwner::StandaloneComponent => Some(root),
    }
}

fn release_api_findings(
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
    captures: &BTreeMap<String, ApiCapture>,
) -> Result<Vec<crate::diagnostic::Finding<ReleaseApiRule>>> {
    let mut items = BTreeMap::new();
    for release_package in surface.packages() {
        let package = release_package.package();
        let capture = captures
            .get(package)
            .with_context(|| format!("release package `{package}` 缺 API capture"))?;
        let mut package_items = Vec::new();
        for (profile, rustdoc_json) in &capture.rustdoc_json {
            let api = public_api::Builder::from_rustdoc_json(rustdoc_json)
                .omit_blanket_impls(false)
                .build()
                .with_context(|| {
                    format!("解析 `{package}` {} rustdoc JSON 失败", profile.label())
                })?;
            let rustdoc: rustdoc_types::Crate =
                serde_json::from_slice(&fs::read(rustdoc_json).with_context(|| {
                    format!("读取 `{package}` {} rustdoc JSON 失败", profile.label())
                })?)
                .with_context(|| {
                    format!(
                        "解析 `{package}` {} typed rustdoc JSON 失败",
                        profile.label()
                    )
                })?;
            for item in api.items() {
                match project_release_api_item(&rustdoc, *profile, item)? {
                    ReleaseApiItemProjection::Owned(item) => package_items.push(item),
                    ReleaseApiItemProjection::ExternalBlanketImplNoise => {}
                }
            }
        }
        items.insert(package.to_owned(), package_items);
    }
    release_api_findings_from_items(facts, surface, &items)
}

#[derive(Debug)]
struct ApiItemProjection {
    profile: ApiProfile,
    rendered: String,
    tokens: Vec<public_api::tokens::Token>,
    source_paths: BTreeSet<String>,
    foundation_exposure: Option<FoundationExposure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FoundationExposure {
    Definition { name: String },
    Reexport { name: String, source_root: String },
    Alias { name: String, source_root: String },
    GlobReexport { source_root: String },
}

const CANONICAL_FOUNDATION_PRIMITIVES: [(&str, &str); 6] = [
    ("rss-request-context", "TenantId"),
    ("rss-contract", "ContractDescriptor"),
    ("rss-contract", "Timepoint"),
    ("rss-contract", "PageCursor"),
    ("rss-contract", "DataClass"),
    ("rss-contract", "SafeError"),
];

const fn canonical_foundation_primitives() -> &'static [(&'static str, &'static str)] {
    &CANONICAL_FOUNDATION_PRIMITIVES
}

#[derive(Debug)]
enum ReleaseApiItemProjection {
    Owned(ApiItemProjection),
    ExternalBlanketImplNoise,
}

/// Build the only release-leakage projection for one rendered public item.
///
/// `rustdoc` materializes dependency blanket impls on local public types and reports those impl
/// items with the local crate id. The trait path remains the typed identity of the coherence owner,
/// so it is the only stable discriminator: external owner means rustdoc noise; local owner remains
/// part of the crate-authored API. Missing parent/trait identities fail closed instead of falling
/// back to names, source paths, or dependency allowlists.
fn project_release_api_item(
    krate: &rustdoc_types::Crate,
    profile: ApiProfile,
    item: &public_api::PublicItem,
) -> Result<ReleaseApiItemProjection> {
    let rustdoc_item = krate
        .index
        .get(&item.id())
        .with_context(|| format!("public rustdoc item {} 缺 index entry", item.id().0))?;
    let enclosing_impl = match &rustdoc_item.inner {
        rustdoc_types::ItemEnum::Impl(implementation) => Some(implementation),
        _ => match item.parent_id() {
            Some(parent_id) => {
                let parent = krate.index.get(&parent_id).with_context(|| {
                    format!(
                        "public rustdoc item {} 的 parent {} 缺 index entry",
                        item.id().0,
                        parent_id.0
                    )
                })?;
                match &parent.inner {
                    rustdoc_types::ItemEnum::Impl(implementation) => Some(implementation),
                    _ => None,
                }
            }
            None => None,
        },
    };

    if let Some(implementation) = enclosing_impl
        && implementation.blanket_impl.is_some()
    {
        let trait_path = implementation
            .trait_
            .as_ref()
            .context("blanket impl 缺 trait identity")?;
        let trait_summary = krate.paths.get(&trait_path.id).with_context(|| {
            format!(
                "blanket impl trait {} 缺 path owner identity",
                trait_path.id.0
            )
        })?;
        anyhow::ensure!(
            trait_summary.kind == rustdoc_types::ItemKind::Trait,
            "blanket impl trait {} path kind 不是 trait: {:?}",
            trait_path.id.0,
            trait_summary.kind
        );
        let root = krate
            .index
            .get(&krate.root)
            .context("rustdoc crate root 缺 index entry")?;
        anyhow::ensure!(
            !krate.external_crates.contains_key(&root.crate_id),
            "rustdoc crate root owner {} 不能同时声明为 external crate",
            root.crate_id
        );
        if trait_summary.crate_id == root.crate_id {
            let trait_item = krate.index.get(&trait_path.id).with_context(|| {
                format!(
                    "local blanket impl trait {} 缺 index entry",
                    trait_path.id.0
                )
            })?;
            anyhow::ensure!(
                trait_item.crate_id == trait_summary.crate_id,
                "blanket impl trait {} owner identity 不一致: index={} path={}",
                trait_path.id.0,
                trait_item.crate_id,
                trait_summary.crate_id
            );
            anyhow::ensure!(
                matches!(trait_item.inner, rustdoc_types::ItemEnum::Trait(_)),
                "local blanket impl trait {} index kind 不是 trait",
                trait_path.id.0
            );
        } else {
            anyhow::ensure!(
                krate.external_crates.contains_key(&trait_summary.crate_id),
                "blanket impl trait {} 的 external owner {} 未声明",
                trait_path.id.0,
                trait_summary.crate_id
            );
            if let Some(trait_item) = krate.index.get(&trait_path.id) {
                anyhow::ensure!(
                    trait_item.crate_id == trait_summary.crate_id,
                    "blanket impl trait {} owner identity 不一致: index={} path={}",
                    trait_path.id.0,
                    trait_item.crate_id,
                    trait_summary.crate_id
                );
            }
            return Ok(ReleaseApiItemProjection::ExternalBlanketImplNoise);
        }
    }

    Ok(ReleaseApiItemProjection::Owned(ApiItemProjection {
        profile,
        rendered: format!("profile={} {}", profile.label(), item),
        tokens: item.tokens().cloned().collect(),
        source_paths: source_type_paths(krate, item.id())?,
        foundation_exposure: foundation_exposure(krate, rustdoc_item)?,
    }))
}

fn foundation_exposure(
    krate: &rustdoc_types::Crate,
    item: &rustdoc_types::Item,
) -> Result<Option<FoundationExposure>> {
    let canonical_name = |name: &str| {
        canonical_foundation_primitives()
            .iter()
            .any(|(_, canonical)| *canonical == name)
    };
    match &item.inner {
        rustdoc_types::ItemEnum::Use(import) if import.is_glob => {
            let Some(id) = import.id else {
                bail!(
                    "public glob re-export `{}` 缺 typed source identity",
                    import.source
                );
            };
            let source = typed_source_summary(krate, id, "foundation glob re-export")?;
            let source_root = source
                .path
                .first()
                .context("foundation glob re-export source path 为空")?
                .to_owned();
            Ok(Some(FoundationExposure::GlobReexport { source_root }))
        }
        rustdoc_types::ItemEnum::Use(import) => {
            let Some(id) = import.id else {
                let source_name = import
                    .source
                    .trim_start_matches("::")
                    .rsplit("::")
                    .next()
                    .unwrap_or(import.source.as_str());
                if canonical_name(&import.name) || canonical_name(source_name) {
                    bail!(
                        "canonical Foundation re-export `{}` 缺 typed source identity",
                        import.name
                    );
                }
                return Ok(None);
            };
            let source = typed_source_summary(krate, id, "public re-export")?;
            let source_root = source
                .path
                .first()
                .with_context(|| {
                    format!(
                        "canonical Foundation re-export `{}` source path 为空",
                        import.name
                    )
                })?
                .to_owned();
            let source_name = source
                .path
                .last()
                .context("public re-export source path 为空")?;
            let canonical_source = canonical_foundation_primitives()
                .iter()
                .find(|(_, canonical)| *canonical == source_name);
            if canonical_source.is_some() {
                anyhow::ensure!(
                    matches!(
                        source.kind,
                        rustdoc_types::ItemKind::Struct | rustdoc_types::ItemKind::Enum
                    ),
                    "canonical Foundation re-export `{}` source kind 不是 struct/enum: {:?}",
                    import.name,
                    source.kind
                );
            }
            let name = canonical_source
                .map(|(_, canonical)| (*canonical).to_owned())
                .or_else(|| canonical_name(&import.name).then(|| import.name.clone()));
            let Some(name) = name else {
                return Ok(None);
            };
            Ok(Some(FoundationExposure::Reexport { name, source_root }))
        }
        rustdoc_types::ItemEnum::Struct(_)
        | rustdoc_types::ItemEnum::Enum(_)
        | rustdoc_types::ItemEnum::Union(_)
            if item.name.as_deref().is_some_and(canonical_name) =>
        {
            Ok(Some(FoundationExposure::Definition {
                name: item
                    .name
                    .clone()
                    .context("canonical Foundation item 缺 name")?,
            }))
        }
        rustdoc_types::ItemEnum::TypeAlias(_) => {
            let item = krate.index.get(&item.id).with_context(|| {
                format!("canonical Foundation alias {} 缺 index entry", item.id.0)
            })?;
            let value = serde_json::to_value(item).context("投影 Foundation alias 失败")?;
            let mut ids = BTreeSet::new();
            collect_source_ids(&value, &mut ids);
            let mut canonical_target = None;
            for raw_id in ids {
                let source = typed_source_summary(
                    krate,
                    rustdoc_types::Id(raw_id),
                    "canonical Foundation alias",
                )?;
                let Some(name) = source.path.last().filter(|name| canonical_name(name)) else {
                    continue;
                };
                anyhow::ensure!(
                    matches!(
                        source.kind,
                        rustdoc_types::ItemKind::Struct | rustdoc_types::ItemKind::Enum
                    ),
                    "canonical Foundation alias source kind 不是 struct/enum: {:?}",
                    source.kind
                );
                let source_root = source
                    .path
                    .first()
                    .context("canonical Foundation alias source path 为空")?
                    .to_owned();
                canonical_target = Some((name.to_owned(), source_root));
                break;
            }
            let local_root = krate
                .paths
                .get(&krate.root)
                .and_then(|root| root.path.first())
                .context("rustdoc local crate root 缺 path identity")?
                .to_owned();
            let target = canonical_target.or_else(|| {
                item.name
                    .as_deref()
                    .filter(|name| canonical_name(name))
                    .map(|name| (name.to_owned(), local_root))
            });
            Ok(target.map(|(name, source_root)| FoundationExposure::Alias { name, source_root }))
        }
        _ => Ok(None),
    }
}

fn typed_source_summary<'a>(
    krate: &'a rustdoc_types::Crate,
    id: rustdoc_types::Id,
    context: &str,
) -> Result<&'a rustdoc_types::ItemSummary> {
    let summary = krate
        .paths
        .get(&id)
        .with_context(|| format!("{context} source {} 缺 path identity", id.0))?;
    let source_root = summary
        .path
        .first()
        .with_context(|| format!("{context} source {} path 为空", id.0))?;
    let root = krate
        .index
        .get(&krate.root)
        .context("rustdoc crate root 缺 index entry")?;
    if summary.crate_id == root.crate_id {
        let local_root = krate
            .paths
            .get(&krate.root)
            .and_then(|root| root.path.first())
            .context("rustdoc local crate root 缺 path identity")?;
        anyhow::ensure!(
            source_root == local_root,
            "{context} source {} local owner identity 冲突: path={} root={}",
            id.0,
            source_root,
            local_root
        );
        let source_item = krate
            .index
            .get(&id)
            .with_context(|| format!("{context} local source {} 缺 index entry", id.0))?;
        anyhow::ensure!(
            source_item.crate_id == summary.crate_id,
            "{context} source {} owner identity 不一致: index={} path={}",
            id.0,
            source_item.crate_id,
            summary.crate_id
        );
    } else {
        let external = krate
            .external_crates
            .get(&summary.crate_id)
            .with_context(|| {
                format!(
                    "{context} source {} 的 external owner {} 未声明",
                    id.0, summary.crate_id
                )
            })?;
        anyhow::ensure!(
            normalized_crate_name(&external.name) == *source_root,
            "{context} source {} external owner identity 冲突: path={} external={}",
            id.0,
            source_root,
            external.name
        );
        if let Some(source_item) = krate.index.get(&id) {
            anyhow::ensure!(
                source_item.crate_id == summary.crate_id,
                "{context} source {} owner identity 不一致: index={} path={}",
                id.0,
                source_item.crate_id,
                summary.crate_id
            );
        }
    }
    Ok(summary)
}

/// INVARIANT: RELEASE-FOUNDATION-CANONICAL-OWNER-01 { level = "Medium", exec = "release-check", source = "public-api", synthetic_red = "tests::canonical_foundation_owner_policy_rejects_mirror_alias_and_foreign_reexport|tests::canonical_foundation_projection_requires_typed_reexport_identity", anti_vacuity = "tests::checked_in_typed_foundation_projection_is_exact_once_per_profile" }.
fn append_foundation_owner_findings(
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
    items: &BTreeMap<String, Vec<ApiItemProjection>>,
    findings: &mut Vec<crate::diagnostic::Finding<ReleaseApiRule>>,
) {
    let selected = surface
        .packages()
        .iter()
        .map(|package| package.package())
        .collect::<BTreeSet<_>>();
    let mut occurrences = BTreeMap::<(&str, ApiProfile, &str), usize>::new();

    for (package, package_items) in items {
        for item in package_items {
            let Some(exposure) = &item.foundation_exposure else {
                continue;
            };
            if let FoundationExposure::GlobReexport { source_root } = exposure {
                findings.push(crate::diagnostic::finding(
                    ReleaseApiRule::ForbiddenType,
                    release_subject(package, &item.rendered),
                    format!(
                        "public glob re-export from crate `{source_root}` cannot prove canonical Foundation provenance"
                    ),
                ));
                continue;
            }

            let named = match exposure {
                FoundationExposure::Definition { name } => {
                    Some((name.as_str(), package.to_owned(), false))
                }
                FoundationExposure::Reexport { name, source_root } => Some((
                    name.as_str(),
                    resolved_source_package(facts, package, source_root),
                    false,
                )),
                FoundationExposure::Alias { name, source_root } => Some((
                    name.as_str(),
                    resolved_source_package(facts, package, source_root),
                    true,
                )),
                FoundationExposure::GlobReexport { .. } => None,
            };
            let Some((name, source_package, alias)) = named else {
                continue;
            };
            let Some((owner, _)) = canonical_foundation_primitives()
                .iter()
                .find(|(_, canonical)| *canonical == name)
            else {
                continue;
            };
            if !selected.contains(owner) {
                continue;
            }
            let correct_owner = package == owner;
            let correct_source = source_package == *owner;
            if alias || !correct_owner || !correct_source {
                findings.push(crate::diagnostic::finding(
                    ReleaseApiRule::ForbiddenType,
                    release_subject(package, &item.rendered),
                    format!(
                        "canonical Foundation primitive `{name}` must be defined only by `{owner}`; exposure package=`{package}` source-package=`{source_package}` alias={alias}"
                    ),
                ));
                continue;
            }
            *occurrences.entry((owner, item.profile, name)).or_default() += 1;
        }
    }

    for (owner, name) in canonical_foundation_primitives() {
        if !selected.contains(owner) {
            continue;
        }
        for profile in ApiProfile::RELEASE {
            let count = occurrences
                .get(&(owner, profile, name))
                .copied()
                .unwrap_or(0);
            if count != 1 {
                findings.push(crate::diagnostic::finding(
                    ReleaseApiRule::ForbiddenType,
                    format!(
                        "package={owner}/profile={}/canonical={name}",
                        profile.label()
                    ),
                    format!(
                        "canonical Foundation primitive must have exactly one typed owner exposure; observed={count}"
                    ),
                ));
            }
        }
    }
}

fn resolved_source_package(facts: &WorkspaceFacts, package: &str, source_root: &str) -> String {
    if normalized_crate_name(package) == source_root {
        return package.to_owned();
    }
    let Ok(package_key) = facts.package_key(package) else {
        return format!("<unresolved:{source_root}>");
    };
    let Ok(dependencies) = facts.direct_dependencies_for(&package_key) else {
        return format!("<unresolved:{source_root}>");
    };
    dependencies
        .iter()
        .filter(|dependency| dependency.kind() == workspacefacts::DependencyKind::Normal)
        .find(|dependency| {
            normalized_crate_name(dependency.name()) == source_root
                || dependency
                    .resolved()
                    .is_some_and(|resolved| normalized_crate_name(resolved.as_str()) == source_root)
        })
        .and_then(workspacefacts::DirectDependencyFacts::resolved)
        .map_or_else(
            || format!("<unresolved:{source_root}>"),
            |resolved| resolved.as_str().to_owned(),
        )
}

fn release_api_findings_from_items(
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
    items: &BTreeMap<String, Vec<ApiItemProjection>>,
) -> Result<Vec<crate::diagnostic::Finding<ReleaseApiRule>>> {
    let workspace = facts
        .workspace_packages()
        .into_iter()
        .map(|package| package.key().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let selected = surface
        .packages()
        .iter()
        .map(|package| package.package().to_owned())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();

    append_foundation_owner_findings(facts, surface, items, &mut findings);

    for release_package in surface.packages() {
        let package = release_package.package();
        let package_key = facts
            .package_key(package)
            .with_context(|| format!("release package `{package}` 不属于 workspace"))?;
        let dependencies = facts.direct_dependencies_for(&package_key)?;
        let library_target = facts
            .targets_for(&package_key)?
            .iter()
            .find(|target| target.kind() == TargetKind::Library)
            .with_context(|| format!("release package `{package}` 缺 library target"))?
            .name();
        let package_items = items
            .get(package)
            .with_context(|| format!("release package `{package}` 缺 API item projection"))?;

        for item in package_items {
            let paths = referenced_type_paths(&item.tokens)
                .union(&item.source_paths)
                .cloned()
                .collect::<BTreeSet<_>>();
            for path in paths {
                let resolved_workspace =
                    resolved_workspace_dependency(dependencies, &path, &workspace).or_else(|| {
                        let root = path.split("::").next().unwrap_or(path.as_str());
                        workspace
                            .iter()
                            .find(|candidate| normalized_crate_name(candidate) == root)
                            .map(String::as_str)
                    });
                let Some(root) = forbidden_type_root(
                    release_package.public_api_owner(),
                    library_target,
                    &path,
                    &workspace,
                    &selected,
                    resolved_workspace,
                ) else {
                    let root = path.split("::").next().unwrap_or(path.as_str());
                    if path.contains("::")
                        && !matches!(path.split("::").next(), Some("std" | "core" | "alloc"))
                        && root != normalized_crate_name(library_target)
                        && !has_direct_normal_dependency(dependencies, &path, None)
                    {
                        findings.push(crate::diagnostic::finding(
                            ReleaseApiRule::PublicDependency,
                            release_subject(package, &item.rendered),
                            format!(
                                "public type `{path}` is not backed by a direct normal dependency"
                            ),
                        ));
                    }
                    continue;
                };

                findings.push(crate::diagnostic::finding(
                    ReleaseApiRule::ForbiddenType,
                    release_subject(package, &item.rendered),
                    format!("forbidden public type `{path}` (crate root `{root}`)"),
                ));
                if resolved_workspace.is_some_and(|dependency| !selected.contains(dependency))
                    || (resolved_workspace.is_some()
                        && !has_direct_normal_dependency(dependencies, &path, resolved_workspace))
                {
                    findings.push(crate::diagnostic::finding(
                        ReleaseApiRule::PublicDependency,
                        release_subject(package, &item.rendered),
                        format!("public workspace type `{path}` is not a selected direct normal dependency"),
                    ));
                }
            }
        }
    }
    findings.sort_by(|left, right| {
        (left.rule, &left.subject, &left.detail).cmp(&(right.rule, &right.subject, &right.detail))
    });
    findings.dedup();
    Ok(findings)
}

fn source_type_paths(
    krate: &rustdoc_types::Crate,
    item_id: rustdoc_types::Id,
) -> Result<BTreeSet<String>> {
    let item = krate
        .index
        .get(&item_id)
        .with_context(|| format!("public rustdoc item {} 缺 index entry", item_id.0))?;
    let value = serde_json::to_value(item).context("投影 rustdoc item 失败")?;
    let mut ids = BTreeSet::new();
    collect_source_ids(&value, &mut ids);
    let mut paths = BTreeSet::new();
    for id in ids {
        let summary =
            typed_source_summary(krate, rustdoc_types::Id(id), "public API source projection")?;
        paths.insert(summary.path.join("::"));
    }
    Ok(paths)
}

fn collect_source_ids(value: &serde_json::Value, ids: &mut BTreeSet<u32>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, nested) in object {
                if matches!(key.as_str(), "resolved_path" | "use")
                    && let Some(id) = nested
                        .as_object()
                        .and_then(|fields| fields.get("id"))
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|id| u32::try_from(id).ok())
                {
                    ids.insert(id);
                }
                collect_source_ids(nested, ids);
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                collect_source_ids(nested, ids);
            }
        }
        _ => {}
    }
}

fn release_subject(package: &str, rendered: &str) -> String {
    let module = rendered
        .split_whitespace()
        .find(|part| part.contains("::"))
        .unwrap_or("<root>")
        .trim_matches(|character: char| {
            !character.is_alphanumeric() && character != ':' && character != '_'
        });
    format!("package={package}/module={module}/item={rendered}")
}

fn has_direct_normal_dependency(
    dependencies: &[workspacefacts::DirectDependencyFacts],
    path: &str,
    expected_package: Option<&str>,
) -> bool {
    let root = path.split("::").next().unwrap_or(path);
    dependencies.iter().any(|dependency| {
        dependency.kind() == workspacefacts::DependencyKind::Normal
            && (normalized_crate_name(dependency.name()) == root
                || dependency
                    .resolved()
                    .is_some_and(|resolved| normalized_crate_name(resolved.as_str()) == root))
            && expected_package.is_none_or(|expected| {
                dependency
                    .resolved()
                    .is_some_and(|resolved| resolved.as_str() == expected)
            })
    })
}

fn resolved_workspace_dependency<'a>(
    dependencies: &'a [workspacefacts::DirectDependencyFacts],
    path: &str,
    workspace: &BTreeSet<String>,
) -> Option<&'a str> {
    let root = path.split("::").next().unwrap_or(path);
    dependencies.iter().find_map(|dependency| {
        let resolved = dependency.resolved()?.as_str();
        (workspace.contains(resolved)
            && (normalized_crate_name(dependency.name()) == root
                || normalized_crate_name(resolved) == root))
            .then_some(resolved)
    })
}

#[derive(Debug)]
enum BaselineUniverse {
    Complete,
    Packages(BTreeSet<PackageKey>),
}

impl BaselineUniverse {
    fn contains_file(&self, name: &str) -> bool {
        match self {
            Self::Complete => true,
            Self::Packages(packages) => name
                .strip_suffix(".txt")
                .is_some_and(|package| packages.iter().any(|key| key.as_str() == package)),
        }
    }
}

pub(crate) fn run(command: Command) -> Result<()> {
    let root = crate::workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let facts = command_facts.get()?;
    let catalog = BaselineCatalog::derive(&root, facts)?;
    let (plan, check) = match command {
        Command::Internal { check, layer } => {
            let selection = layer.map_or(
                StaticBaselineScope::Complete(BaselineOwner::Internal),
                StaticBaselineScope::InternalLayer,
            );
            (catalog.plan(selection), check)
        }
        Command::Release { check } => (
            catalog.plan(StaticBaselineScope::Complete(BaselineOwner::Release)),
            check,
        ),
    };
    execute(&root, &plan, check).map(drop)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ReleaseApiRule {
    PublicDependency,
    ForbiddenType,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReleaseProofFailure {
    stage: u8,
    subject: String,
    detail: String,
}

impl ReleaseProofFailure {
    fn from_error(stage: u8, subject: impl Into<String>, error: anyhow::Error) -> Self {
        Self {
            stage,
            subject: subject.into(),
            detail: format!("{error:#}"),
        }
    }
}

fn collect_release_stage<T>(
    failures: &mut Vec<ReleaseProofFailure>,
    stage: u8,
    subject: &str,
    run: impl FnOnce() -> Result<T>,
) -> Option<T> {
    match run() {
        Ok(value) => Some(value),
        Err(error) => {
            failures.push(ReleaseProofFailure::from_error(stage, subject, error));
            None
        }
    }
}

/// Canonical ReleaseCheck proof. The Cargo graph and validated positive selection remain the typed
/// authority; rustdoc token projection only closes residual public-signature leakage.
/// INVARIANT: RELEASE-API-COMPAT-01 { level = "Medium", exec = "release-check", source = "public-api", synthetic_red = "tests::checked_in_rustdoc_fixture_crosses_builder_and_source_identity_projection", anti_vacuity = "tests::checked_in_rustdoc_fixture_crosses_builder_and_source_identity_projection" }.
pub(crate) fn run_release_check(
    root: &Path,
    facts: &WorkspaceFacts,
    against: &str,
    allow_missing_tools: bool,
) -> Result<crate::release_surface::ReleaseSurface> {
    let surface = validated_release_surface(root, facts)?;
    let catalog = BaselineCatalog::derive_from_release_surface(root, facts, &surface)?;

    let mut failures = Vec::new();
    collect_release_stage(&mut failures, 0, "internal-exact-set", || {
        execute(
            root,
            &catalog.plan(StaticBaselineScope::Complete(BaselineOwner::Internal)),
            true,
        )
    });

    let base_revision = match merge_base(root, against) {
        Ok(revision) => Some(revision),
        Err(error) => {
            failures.push(ReleaseProofFailure::from_error(1, "base-revision", error));
            None
        }
    };
    let base_packages = match &base_revision {
        Some(revision) => match release_packages_at(root, revision) {
            Ok(packages) => Some(packages),
            Err(error) => {
                failures.push(ReleaseProofFailure::from_error(
                    1,
                    "base-release-surface",
                    error,
                ));
                None
            }
        },
        None => None,
    };
    let current_packages = catalog
        .release
        .iter()
        .map(|package| package.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let delta = base_packages.as_ref().map(|base| {
        ReleaseSelectionDelta::derive(&current_packages, &base.keys().cloned().collect())
    });
    if let Some(base) = &base_packages {
        for package in surface.packages() {
            if let Some((base_line, current_line)) = changed_frozen_version_line(
                base.get(package.package()).and_then(Option::as_deref),
                package.version_line(),
            ) {
                failures.push(ReleaseProofFailure {
                    stage: 2,
                    subject: format!("package:{}", package.package()),
                    detail: format!(
                        "prepublication version-line changed from `{base_line}` to `{}`; major/minor is frozen against the merge base",
                        current_line
                    ),
                });
            }
        }
    }

    let captures = match execute(
        root,
        &catalog.plan(StaticBaselineScope::Complete(BaselineOwner::Release)),
        true,
    ) {
        Ok(captures) => Some(captures),
        Err(error) => {
            failures.push(ReleaseProofFailure::from_error(
                2,
                "release-exact-set",
                error,
            ));
            None
        }
    };

    if !current_packages.is_empty()
        && let Some(captures) = captures.as_ref()
    {
        match release_api_findings(facts, &surface, captures) {
            Ok(findings) => {
                failures.extend(findings.into_iter().map(|finding| ReleaseProofFailure {
                    stage: 3,
                    subject: finding.subject,
                    detail: format!("rule={:?}: {}", finding.rule, finding.detail),
                }))
            }
            Err(error) => failures.push(ReleaseProofFailure::from_error(
                3,
                "release-type-projection",
                error,
            )),
        }
    }

    if let (Some(delta), Some(base_revision)) = (&delta, &base_revision)
        && !delta.semver_packages.is_empty()
    {
        match ensure_semver_tool_available(allow_missing_tools) {
            Ok(true) => {
                if let Err(error) =
                    run_semver_packages(&delta.semver_packages, |package, profile| {
                        run_semver_check(root, package, base_revision, profile)
                    })
                {
                    failures.push(ReleaseProofFailure::from_error(4, "semver", error));
                }
            }
            Ok(false) => {}
            Err(error) => failures.push(ReleaseProofFailure::from_error(
                4,
                "semver-prerequisite",
                error,
            )),
        }
    }

    if !failures.is_empty() {
        failures.sort();
        for failure in &failures {
            eprintln!(
                "release-check finding: stage={} subject={} detail={}",
                failure.stage, failure.subject, failure.detail
            );
        }
        bail!(
            "release-check public-api: {} 项聚合校验失败",
            failures.len()
        );
    }
    let Some(delta) = delta else {
        bail!("release-check public-api: base Release Surface 不可用")
    };
    if current_packages.is_empty() {
        eprintln!(
            "release-check public-api: Release Surface 为空；release drift/SemVer/leakage 无目标"
        );
    }
    eprintln!(
        "release-check public-api: {} release package(s), {} SemVer package comparison(s) × {} profiles, {} first-release baseline(s), {} explicit removal(s)",
        current_packages.len(),
        delta.semver_packages.len(),
        ApiProfile::RELEASE.len(),
        delta.first_release_packages.len(),
        delta.removed_packages.len()
    );
    Ok(surface)
}

fn run_semver_packages(
    packages: &[String],
    mut run: impl FnMut(&str, ApiProfile) -> Result<()>,
) -> Result<()> {
    let mut failures = Vec::new();
    for package in packages {
        for profile in ApiProfile::RELEASE {
            if let Err(error) = run(package, profile) {
                failures.push(format!(
                    "package={package}/profile={}: {error:#}",
                    profile.label()
                ));
            }
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    bail!(
        "release-check public-api: {} 项 SemVer 校验失败:\n{}",
        failures.len(),
        failures.join("\n")
    )
}

pub(crate) fn validated_release_surface(
    root: &Path,
    facts: &WorkspaceFacts,
) -> Result<crate::release_surface::ReleaseSurface> {
    let ir =
        crate::assembly_governance::AssemblyGovernanceIr::<crate::assembly_governance::Core>::load(
            root,
        )?;
    let artifacts = if crate::release_surface::requires_artifact_join(facts) {
        let joined =
            ir.join_artifacts(crate::assembly_governance::load_artifact_declaration(root)?)?;
        crate::release_surface::project_artifacts(&joined)
    } else {
        Vec::new()
    };
    let (surface, findings) = crate::release_surface::validate(facts, &artifacts);
    if !findings.is_empty() {
        bail!(
            "validated Release Surface 失败:\n{}",
            findings
                .iter()
                .map(crate::diagnostic::format_finding)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    surface.context("validated Release Surface 未生成 typed surface")
}

fn merge_base(root: &Path, against: &str) -> Result<String> {
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["merge-base", against, "HEAD"],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("运行 git merge-base {against} HEAD 失败"))?;
    if !output.status.success() {
        bail!(
            "git merge-base {against} HEAD 非零退出:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let revision = String::from_utf8(output.stdout)?.trim().to_owned();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("git merge-base 返回非法 revision `{revision}`");
    }
    Ok(revision)
}

fn release_packages_at(root: &Path, revision: &str) -> Result<BTreeMap<String, Option<String>>> {
    let object = format!("{revision}:Cargo.toml");
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["show", &object],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("运行 git show {object} 失败"))?;
    if !output.status.success() {
        bail!(
            "git show {object} 非零退出:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let manifest = String::from_utf8(output.stdout)?
        .parse::<toml::Value>()
        .context("解析 base Cargo.toml 失败")?;
    let metadata = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("metadata"))
        .cloned()
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));
    let metadata = serde_json::to_value(metadata).context("投影 base workspace.metadata 失败")?;
    let selection = workspacefacts::parse_release_selection(&metadata)
        .map_err(anyhow::Error::new)?
        .context("base Cargo.toml 缺 workspace.metadata.release-surface")?;
    let mut packages = BTreeMap::new();
    for package in selection.packages() {
        if packages
            .insert(
                package.package().to_owned(),
                package.version_line().map(str::to_owned),
            )
            .is_some()
        {
            bail!(
                "base Cargo.toml Release Surface 重复选择 package `{}`",
                package.package()
            );
        }
    }
    Ok(packages)
}

#[derive(Debug)]
struct ApiCapture {
    baseline: String,
    rustdoc_json: Vec<(ApiProfile, PathBuf)>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ApiProfile {
    Default,
    AllFeatures,
}

impl ApiProfile {
    const RELEASE: [Self; 2] = [Self::Default, Self::AllFeatures];

    const fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AllFeatures => "all-features",
        }
    }

    const fn all_features(self) -> bool {
        matches!(self, Self::AllFeatures)
    }
}

fn combine_release_captures(default: ApiCapture, all_features: ApiCapture) -> ApiCapture {
    let baseline = format!(
        "== release-api profile: default ==\n{}\n== release-api profile: all-features ==\n{}\n",
        default.baseline.trim_end_matches('\n'),
        all_features.baseline.trim_end_matches('\n')
    );
    let mut rustdoc_json = default.rustdoc_json;
    rustdoc_json.extend(all_features.rustdoc_json);
    ApiCapture {
        baseline,
        rustdoc_json,
    }
}

fn execute(root: &Path, plan: &BaselinePlan, check: bool) -> Result<BTreeMap<String, ApiCapture>> {
    let owner = plan.scope.owner();
    if owner == BaselineOwner::Internal {
        validate_consumer_tx_public_surface(root)?;
    }
    let _owner_lock = BaselineOwnerLock::acquire(root, owner, check)?;
    let dir = root.join(owner.directory());
    let before = scan_baselines(&dir)?;
    if plan.targets.is_empty() {
        finish_empty_or_orphan(plan, &dir, check, &before)?;
        return Ok(BTreeMap::new());
    }

    ensure_tool_available()?;
    let target_dir = root.join(".cache/public-api-target").join(owner.label());
    let mut captures = BTreeMap::new();
    for package in &plan.targets {
        let library_target = plan
            .library_targets
            .get(package)
            .with_context(|| format!("{} 缺 library target identity", package.as_str()))?;
        let capture = if owner == BaselineOwner::Release {
            combine_release_captures(
                capture_public_api(
                    root,
                    package.as_str(),
                    library_target,
                    &target_dir.join(ApiProfile::Default.label()),
                    ApiProfile::Default,
                )?,
                capture_public_api(
                    root,
                    package.as_str(),
                    library_target,
                    &target_dir.join(ApiProfile::AllFeatures.label()),
                    ApiProfile::AllFeatures,
                )?,
            )
        } else {
            capture_public_api(
                root,
                package.as_str(),
                library_target,
                &target_dir,
                ApiProfile::Default,
            )?
        };
        captures.insert(package.as_str().to_owned(), capture);
    }
    let expected = captures
        .iter()
        .map(|(package, capture)| {
            (
                format!("{package}.txt"),
                capture.baseline.as_bytes().to_vec(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if scan_baselines(&dir)? != before {
        bail!("baseline capture 期间目录发生并发变化: {}", dir.display());
    }
    let differences = differences(plan, &dir, &before.files, &expected);
    if check {
        report_differences(owner, &differences)?;
        return Ok(captures);
    }
    apply_generation(&dir, plan, &before, &expected)?;
    eprintln!(
        "public-api {}: {} baseline 已原子更新",
        owner.label(),
        expected.len()
    );
    Ok(captures)
}

fn finish_empty_or_orphan(
    plan: &BaselinePlan,
    dir: &Path,
    check: bool,
    before: &BaselineSnapshot,
) -> Result<()> {
    if scan_baselines(dir)? != *before {
        bail!("baseline 校验期间目录发生并发变化: {}", dir.display());
    }
    let expected = BTreeMap::new();
    let differences = differences(plan, dir, &before.files, &expected);
    if check {
        return report_differences(plan.scope.owner(), &differences);
    }
    if differences
        .items
        .iter()
        .any(|difference| difference.kind == DifferenceKind::Orphan)
    {
        apply_generation(dir, plan, before, &expected)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DifferenceKind {
    Missing,
    Drift,
    Orphan,
}

impl DifferenceKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Drift => "drift",
            Self::Orphan => "orphan",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct BaselineDifference {
    kind: DifferenceKind,
    package: String,
    path: PathBuf,
}

#[derive(Default)]
struct Differences {
    items: Vec<BaselineDifference>,
}

fn differences(
    plan: &BaselinePlan,
    dir: &Path,
    actual: &BTreeMap<String, Vec<u8>>,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Differences {
    let mut result = Differences::default();
    for (name, bytes) in expected {
        match actual.get(name) {
            None => result
                .items
                .push(difference(DifferenceKind::Missing, dir, name)),
            Some(current) if current != bytes => {
                result
                    .items
                    .push(difference(DifferenceKind::Drift, dir, name))
            }
            Some(_) => {}
        }
    }
    result.items.extend(
        actual
            .keys()
            .filter(|name| plan.universe.contains_file(name) && !expected.contains_key(*name))
            .map(|name| difference(DifferenceKind::Orphan, dir, name)),
    );
    result
}

fn difference(kind: DifferenceKind, dir: &Path, name: &str) -> BaselineDifference {
    BaselineDifference {
        kind,
        package: name.strip_suffix(".txt").unwrap_or(name).to_owned(),
        path: dir.join(name),
    }
}

fn report_differences(owner: BaselineOwner, differences: &Differences) -> Result<()> {
    if differences.items.is_empty() {
        eprintln!("public-api {} --check: exact-set 无 drift", owner.label());
        return Ok(());
    }
    let details = differences
        .items
        .iter()
        .map(|difference| {
            format!(
                "status={} owner={} package={} path={}",
                difference.kind.label(),
                owner.label(),
                difference.package,
                difference.path.display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "public-api owner={} 校验失败（{} 项）:\n{}",
        owner.label(),
        differences.items.len(),
        details
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BaselineSnapshot {
    directory: Option<DirectoryIdentity>,
    files: BTreeMap<String, Vec<u8>>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: rustix::fs::Dev,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    canonical_path: std::path::PathBuf,
}

fn scan_baselines(dir: &Path) -> Result<BaselineSnapshot> {
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BaselineSnapshot {
            directory: None,
            files: BTreeMap::new(),
        }),
        Err(error) => Err(error).with_context(|| format!("读取 {} 失败", dir.display())),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "baseline owner 路径必须是非 symlink 目录: {}",
                dir.display()
            )
        }
        Ok(metadata) => scan_baseline_files(dir, Some(directory_identity(dir, &metadata)?)),
    }
}

#[cfg(unix)]
fn directory_identity(_dir: &Path, metadata: &fs::Metadata) -> Result<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(DirectoryIdentity {
        device: metadata.dev() as rustix::fs::Dev,
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn directory_identity(dir: &Path, _metadata: &fs::Metadata) -> Result<DirectoryIdentity> {
    Ok(DirectoryIdentity {
        canonical_path: fs::canonicalize(dir)?,
    })
}

fn scan_baseline_files(
    dir: &Path,
    directory: Option<DirectoryIdentity>,
) -> Result<BaselineSnapshot> {
    scan_baseline_files_with_hook(dir, directory, || {})
}

fn scan_baseline_files_with_hook(
    dir: &Path,
    directory: Option<DirectoryIdentity>,
    after_identity: impl FnOnce(),
) -> Result<BaselineSnapshot> {
    after_identity();
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(dir).with_context(|| format!("扫描 {} 失败", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "baseline 目录含 symlink/子目录/异常条目: {}",
                path.display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("baseline 文件名不是 UTF-8: {}", path.display()))?;
        if Path::new(&name)
            .extension()
            .and_then(|value| value.to_str())
            != Some("txt")
        {
            bail!("baseline 目录含非预期文件: {}", path.display());
        }
        let content = crate::generated_file::read_stable_utf8_file(
            &path,
            32 * 1024 * 1024,
            "public-api baseline",
        )?;
        files.insert(name, content.into_bytes());
    }
    let after = fs::symlink_metadata(dir)?;
    if after.file_type().is_symlink()
        || !after.is_dir()
        || directory.as_ref() != Some(&directory_identity(dir, &after)?)
    {
        bail!("baseline 目录在扫描期间被替换: {}", dir.display());
    }
    Ok(BaselineSnapshot { directory, files })
}

struct BaselineOwnerLock {
    #[cfg(unix)]
    _file: fs::File,
}

impl BaselineOwnerLock {
    fn acquire(root: &Path, owner: BaselineOwner, shared: bool) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (root, owner, shared);
            bail!("public-api owner lock / atomic generation update 不支持当前平台")
        }
        #[cfg(unix)]
        {
            use rustix::fs::{FileType, FlockOperation, Mode, OFlags, flock, fstat, openat};

            let cache = root.join(".cache");
            ensure_real_directory(&cache)?;
            let lock_dir = cache.join("public-api-locks");
            ensure_real_directory(&lock_dir)?;
            let capability = crate::generated_file::open_directory_capability(&lock_dir)?;
            let name = format!("{}.lock", owner.label());
            let fd = openat(
                capability.fd(),
                name.as_str(),
                OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            let stat = fstat(&fd)?;
            anyhow::ensure!(
                FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
                "baseline owner lock 不是普通文件"
            );
            flock(
                &fd,
                if shared {
                    FlockOperation::LockShared
                } else {
                    FlockOperation::LockExclusive
                },
            )?;
            Ok(Self {
                _file: fs::File::from(fd),
            })
        }
    }
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "目录必须是非 symlink 真实目录: {}",
                path.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .with_context(|| format!("{} 无父目录", path.display()))?;
            anyhow::ensure!(parent.exists(), "目录父路径不存在: {}", parent.display());
            fs::create_dir(path).with_context(|| format!("创建 {} 失败", path.display()))?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

fn apply_generation(
    dir: &Path,
    plan: &BaselinePlan,
    before: &BaselineSnapshot,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    apply_generation_with_hook(dir, plan, before, expected, || Ok(()))
}

fn apply_generation_with_hook(
    dir: &Path,
    plan: &BaselinePlan,
    before: &BaselineSnapshot,
    expected: &BTreeMap<String, Vec<u8>>,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if scan_baselines(dir)? != *before {
        bail!("baseline apply 前目录发生并发变化: {}", dir.display());
    }
    let intended = intended_generation(plan, before, expected);
    let stage = prepare_generation(dir, plan.scope.owner(), &intended)?;
    let result = commit_generation(dir, &stage, before, &intended, before_commit);
    if result.is_err() && stage.exists() {
        cleanup_generation(&stage).with_context(|| {
            format!(
                "baseline generation 提交失败且 staging 清理失败: {}",
                stage.display()
            )
        })?;
    }
    result
}

fn intended_generation(
    plan: &BaselinePlan,
    before: &BaselineSnapshot,
    expected: &BTreeMap<String, Vec<u8>>,
) -> BTreeMap<String, Vec<u8>> {
    let mut intended = before.files.clone();
    intended.extend(
        expected
            .iter()
            .map(|(name, bytes)| (name.clone(), bytes.clone())),
    );
    intended.retain(|name, _| expected.contains_key(name) || !plan.universe.contains_file(name));
    intended
}

fn prepare_generation(
    dir: &Path,
    owner: BaselineOwner,
    intended: &BTreeMap<String, Vec<u8>>,
) -> Result<PathBuf> {
    let root = dir
        .parent()
        .with_context(|| format!("{} 无 workspace root", dir.display()))?;
    let cache = root.join(".cache");
    ensure_real_directory(&cache)?;
    let staging = cache.join("public-api-staging");
    ensure_real_directory(&staging)?;
    cleanup_stale_generations(&staging, owner)?;

    let mut stage = None;
    for _ in 0..64 {
        let candidate = staging.join(format!(
            "{}-{}-{}",
            owner.label(),
            std::process::id(),
            GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                stage = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("创建 baseline staging generation 失败"),
        }
    }
    let stage = stage.context("baseline staging generation 名称冲突次数超限")?;
    for (name, bytes) in intended {
        anyhow::ensure!(
            Path::new(name).components().count() == 1 && name.ends_with(".txt"),
            "非法 baseline generation 文件名: {name}"
        );
        let path = stage.join(name);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644);
        }
        let mut file = options.open(&path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::File::open(&stage)?.sync_all()?;
    fs::File::open(&staging)?.sync_all()?;
    Ok(stage)
}

fn cleanup_stale_generations(staging: &Path, owner: BaselineOwner) -> Result<()> {
    let prefix = format!("{}-", owner.label());
    for entry in fs::read_dir(staging)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("baseline staging 文件名不是 UTF-8"))?;
        if name.starts_with(&prefix) {
            let suffix = name
                .strip_prefix(&prefix)
                .context("owner generation prefix must match")?;
            let (pid, sequence) = suffix
                .split_once('-')
                .context("baseline staging generation 名称形状非法")?;
            anyhow::ensure!(
                !pid.is_empty()
                    && !sequence.is_empty()
                    && pid.bytes().all(|byte| byte.is_ascii_digit())
                    && sequence.bytes().all(|byte| byte.is_ascii_digit()),
                "baseline staging generation 名称形状非法: {name}"
            );
            cleanup_generation(&entry.path())?;
        }
    }
    Ok(())
}

fn cleanup_generation(stage: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(stage)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "baseline staging 不是非 symlink 目录: {}",
        stage.display()
    );
    for entry in fs::read_dir(stage)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("baseline staging 文件名不是 UTF-8"))?;
        let metadata = fs::symlink_metadata(&path)?;
        anyhow::ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && Path::new(&name)
                    .extension()
                    .and_then(|value| value.to_str())
                    == Some("txt"),
            "baseline staging 含异常条目: {}",
            path.display()
        );
        fs::remove_file(&path)?;
    }
    fs::remove_dir(stage)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn commit_generation(
    dir: &Path,
    stage: &Path,
    before: &BaselineSnapshot,
    intended: &BTreeMap<String, Vec<u8>>,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    use rustix::fs::{RenameFlags, fsync, renameat_with};

    anyhow::ensure!(
        scan_baselines(dir)? == *before,
        "baseline commit 前 live owner 已变化"
    );
    before_commit()?;
    let root = dir.parent().context("baseline owner 无 parent")?;
    let stage_parent = stage.parent().context("baseline stage 无 parent")?;
    let owner_name = dir.file_name().context("baseline owner 无文件名")?;
    let stage_name = stage.file_name().context("baseline stage 无文件名")?;
    let root_capability = crate::generated_file::open_directory_capability(root)?;
    let stage_capability = crate::generated_file::open_directory_capability(stage_parent)?;

    if before.directory.is_some() {
        renameat_with(
            root_capability.fd(),
            owner_name,
            stage_capability.fd(),
            stage_name,
            RenameFlags::EXCHANGE,
        )
        .context("原子交换 baseline generation 失败")?;
    } else {
        renameat_with(
            stage_capability.fd(),
            stage_name,
            root_capability.fd(),
            owner_name,
            RenameFlags::NOREPLACE,
        )
        .context("原子发布首个 baseline generation 失败")?;
    }
    fsync(root_capability.fd())?;
    fsync(stage_capability.fd())?;

    let live = scan_baselines(dir)?;
    if live.files != *intended {
        bail!(
            "baseline generation commit 后 live owner 被并发修改；旧 generation 保留于 {}",
            stage.display()
        );
    }
    if before.directory.is_some() {
        let displaced = scan_baselines(stage)?;
        if displaced != *before {
            renameat_with(
                root_capability.fd(),
                owner_name,
                stage_capability.fd(),
                stage_name,
                RenameFlags::EXCHANGE,
            )
            .context("拒绝 raced generation 时恢复 live owner 失败")?;
            fsync(root_capability.fd())?;
            fsync(stage_capability.fd())?;
            bail!("baseline commit 窗口检测到并发修改，已原子恢复 raced owner");
        }
        cleanup_generation(stage)?;
        fsync(stage_capability.fd())?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn commit_generation(
    _dir: &Path,
    _stage: &Path,
    _before: &BaselineSnapshot,
    _intended: &BTreeMap<String, Vec<u8>>,
    _before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    bail!("当前平台不支持原子 baseline generation exchange")
}

#[cfg(test)]
fn baseline_dir() -> Result<std::path::PathBuf> {
    Ok(crate::workspace_root()?.join(BaselineOwner::Internal.directory()))
}

/// 检测外部 cargo-public-api；缺失即 fail-fast 给安装指引（INVARIANT PUBLICAPI-TOOL-GATE-01）。
fn ensure_tool_available() -> Result<()> {
    const PUBLIC_API_VERSION: &str = env!("RSS_TOOL_VERSION_CARGO_PUBLIC_API");
    if crate::cmd::tool_available(crate::cmd::CargoSubcommand::PublicApi) {
        return Ok(());
    }
    bail!(
        "未找到 `cargo public-api`。安装：\n  \
         cargo install cargo-public-api@{PUBLIC_API_VERSION}\n  \
         rustup toolchain install {PINNED_NIGHTLY}   # rustdoc-json 需钉版 nightly（NIGHTLY-PIN-01）\n\
         仅基础/引擎层与 curated extras 封装面冻结需要本工具（非全 workspace 强制门）。"
    )
}

fn ensure_semver_tool_available(allow_missing: bool) -> Result<bool> {
    semver_tool_action(
        crate::cmd::tool_available(crate::cmd::CargoSubcommand::SemverChecks),
        allow_missing,
    )
}

fn semver_tool_action(available: bool, allow_missing: bool) -> Result<bool> {
    const VERSION: &str = env!("RSS_TOOL_VERSION_CARGO_SEMVER_CHECKS");
    if available {
        return Ok(true);
    }
    if allow_missing {
        eprintln!(
            "release-check: [跳过] SemVer comparison（缺 `cargo semver-checks`，--allow-missing-tools 宽限）。装：cargo install cargo-semver-checks@{VERSION} --locked"
        );
        return Ok(false);
    }
    bail!(
        "未找到 `cargo semver-checks`。安装：\n  cargo install cargo-semver-checks@{VERSION} --locked"
    )
}

fn run_semver_check(
    root: &Path,
    package: &str,
    baseline_revision: &str,
    profile: ApiProfile,
) -> Result<()> {
    let output = semver_check_cmd(root, package, baseline_revision, profile)
        .output()
        .with_context(|| format!("运行 cargo semver-checks -p {package} 失败"))?;
    if !output.status.success() {
        bail!(
            "cargo semver-checks -p {package} profile={} 非零退出:\n{}",
            profile.label(),
            format_semver_failure(output.status.code(), &output.stdout, &output.stderr)
        );
    }
    Ok(())
}

fn format_semver_failure(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    let class = match code {
        Some(100) => "compatibility-violation",
        Some(101) => "tool-failure",
        _ => "process-failure",
    };
    let code = code.map_or_else(|| "signal".to_owned(), |code| code.to_string());
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    format!(
        "class={class} exit={code}\nstdout:\n{}\nstderr:\n{}",
        if stdout.is_empty() {
            "<empty>"
        } else {
            &stdout
        },
        if stderr.is_empty() {
            "<empty>"
        } else {
            &stderr
        }
    )
}

fn semver_check_cmd(
    root: &Path,
    package: &str,
    baseline_revision: &str,
    profile: ApiProfile,
) -> ProcessCommand {
    let mut args = vec!["check-release", "--package", package];
    if profile.all_features() {
        args.push("--all-features");
    }
    args.extend(["--baseline-rev", baseline_revision]);
    crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::SemverChecks,
        &args,
        &[],
        Some(root),
    )
}

/// 构造 `cargo public-api -p <crate>` 子进程，经 [`crate::cmd::cargo_cmd`] 漏斗把 `RUSTUP_TOOLCHAIN`
/// 显式重设为 `toolchain`（剥离后成该变量唯一来源，CMD-ENV-CLEAN-01）——等价 `cargo +<toolchain> public-api`，
/// 让 cargo-public-api 在钉版 nightly 下生成可复现 rustdoc-json（`is_probably_stable()`==false ⇒ 透传当前
/// toolchain，不再强制 rolling `nightly`）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }.
fn public_api_cmd(
    root: &Path,
    krate: &str,
    toolchain: &str,
    target_dir: &Path,
    all_features: bool,
) -> ProcessCommand {
    let mut args = vec!["-p", krate, "--omit", "blanket-impls"];
    if all_features {
        args.push("--all-features");
    }
    let mut cmd = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::PublicApi,
        &args,
        &[("RUSTUP_TOOLCHAIN", toolchain)],
        Some(root),
    );
    // cargo-public-api 的 rustdoc-json 缓存不能与前序 all-features/coverage 编译共享；否则同一
    // CI 首次 check 可能读到不同 feature 面的旧 JSON，执行刷新后立即重跑却转绿。
    cmd.env("CARGO_TARGET_DIR", target_dir);
    cmd
}

/// 运行 `cargo public-api -p <crate>`（钉版 nightly）捕获其封装面快照文本。
fn capture_public_api(
    root: &Path,
    krate: &str,
    library_target: &str,
    target_dir: &Path,
    profile: ApiProfile,
) -> Result<ApiCapture> {
    let out = public_api_cmd(
        root,
        krate,
        PINNED_NIGHTLY,
        target_dir,
        profile.all_features(),
    )
    .output()
    .with_context(|| format!("运行 cargo public-api -p {krate} 失败"))?;
    if !out.status.success() {
        let code = out
            .status
            .code()
            .map_or_else(|| "signal".to_owned(), |c| c.to_string());
        bail!(
            "cargo public-api -p {krate} 非零退出（退出码 {code}）:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let rustdoc_json = target_dir
        .join("doc")
        .join(format!("{}.json", normalized_crate_name(library_target)));
    if !rustdoc_json.is_file() {
        bail!(
            "cargo public-api -p {krate} 未留下预期 rustdoc JSON: {}",
            rustdoc_json.display()
        );
    }
    Ok(ApiCapture {
        baseline: String::from_utf8_lossy(&out.stdout).into_owned(),
        rustdoc_json: vec![(profile, rustdoc_json)],
    })
}

#[cfg(test)]
fn public_api_target_dir() -> Result<std::path::PathBuf> {
    Ok(crate::workspace_root()?
        .join(".cache/public-api-target")
        .join(BaselineOwner::Internal.label()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use workspacefacts::testing::{
        metadata_json, path_dependency, path_package, resolve_node, target,
    };

    const HTTP_ROUTE_EVIDENCE_PRIVATE_FIELDS: &[&str] = &[
        "owner",
        "contract",
        "path",
        "method",
        "query_parameters",
        "success_status",
        "idempotency",
        "auth",
        "resource",
        "self_scoped",
        "consistency_level",
        "effect_profile",
    ];

    const SYNTHETIC_CONSUMER_TX_SURFACE: &str = r#"
        pub enum RejectKind { Permanent, Invariant }
        impl RejectKind { pub const fn as_label(self) -> &'static str { "kind" } }
        pub enum ConsumerTxOutcome<C> {
            Committed(C),
            HandlerTransient,
            InfrastructureTransient,
            Rejected(RejectKind),
            CommitUnknown,
            RollbackFailed,
            Fenced,
        }
        impl<C> ConsumerTxOutcome<C> {
            pub const fn as_label(&self) -> &'static str { "outcome" }
        }
    "#;

    #[test]
    fn consumer_tx_surface_rejects_extra_public_owner() {
        let source = format!("{SYNTHETIC_CONSUMER_TX_SURFACE}\npub struct ConsumerTxRunner;");
        assert!(validate_consumer_tx_public_source(&source).is_err());
    }

    #[test]
    fn consumer_tx_surface_allows_private_implementation() {
        let source = format!(
            "{SYNTHETIC_CONSUMER_TX_SURFACE}\nconst PRIVATE: &str = \"private\"; impl RejectKind {{ fn private_helper(self) -> &'static str {{ PRIVATE }} }}"
        );
        assert!(validate_consumer_tx_public_source(&source).is_ok());
    }

    #[test]
    fn consumer_tx_surface_rejects_trait_bridge() {
        let source = format!(
            "{SYNTHETIC_CONSUMER_TX_SURFACE}\nimpl<C> core::fmt::Debug for ConsumerTxOutcome<C> {{ fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {{ Ok(()) }} }}"
        );
        assert!(validate_consumer_tx_public_source(&source).is_err());
    }

    #[test]
    fn consumer_tx_surface_rejects_associated_item() {
        let source = SYNTHETIC_CONSUMER_TX_SURFACE.replace(
            "impl RejectKind {",
            "impl RejectKind { pub const COMPAT: &'static str = \"compat\";",
        );
        assert!(validate_consumer_tx_public_source(&source).is_err());
    }

    #[test]
    fn consumer_tx_root_rejects_alias_facade() {
        assert!(
            validate_consumer_tx_root_source(
                "pub mod consumer_tx; pub use consumer_tx::ConsumerTxOutcome as Outcome;"
            )
            .is_err()
        );
    }

    #[test]
    fn consumer_tx_root_allows_private_implementation_inside_public_module() {
        assert!(
            validate_consumer_tx_root_source(
                "pub mod consumer_tx; pub mod worker { fn private(_: crate::consumer_tx::RejectKind) {} }"
            )
            .is_ok()
        );
    }

    #[test]
    fn real_consumer_tx_surface_is_exact() -> Result<()> {
        validate_consumer_tx_public_surface(&crate::workspace_root()?)
    }

    fn exposed_http_route_evidence_fields(baseline: &str) -> Vec<&'static str> {
        HTTP_ROUTE_EVIDENCE_PRIVATE_FIELDS
            .iter()
            .copied()
            .filter(|field| {
                let symbol = format!("pub vocab::http::HttpRouteEvidence::{field}:");
                baseline.lines().any(|line| line.contains(&symbol))
            })
            .collect()
    }

    fn baseline_plan(scope: BaselineScope, names: &[&str]) -> Result<BaselinePlan> {
        let root = crate::workspace_root()?;
        let facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = facts.get()?;
        let universe = match scope {
            BaselineScope::Complete(_) => BaselineUniverse::Complete,
            BaselineScope::InternalLayer(layer) => BaselineUniverse::Packages(
                target_crates(Some(layer))
                    .into_iter()
                    .map(|name| facts.package_key(name).map_err(Into::into))
                    .collect::<Result<_>>()?,
            ),
            BaselineScope::AffectedInternal => BaselineUniverse::Packages(
                names
                    .iter()
                    .map(|name| facts.package_key(name).map_err(Into::into))
                    .collect::<Result<_>>()?,
            ),
        };
        let targets = names
            .iter()
            .map(|name| facts.package_key(name).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        let library_targets = targets
            .iter()
            .map(|package| {
                let target = facts
                    .targets_for(package)?
                    .iter()
                    .find(|target| target.kind() == TargetKind::Library)
                    .context("test baseline target must be a library")?;
                Ok((package.clone(), target.name().to_owned()))
            })
            .collect::<Result<_>>()?;
        Ok(BaselinePlan {
            scope,
            universe,
            targets,
            library_targets,
        })
    }

    fn make_release_ready_package(package: &mut Value, path: &str) {
        package["version"] = json!("0.1.0");
        package["id"] = json!(format!("path+file://{path}#0.1.0"));
        package["publish"] = json!(["crates-io"]);
        package["description"] = json!("Synthetic release package");
        package["license_file"] = json!(format!("{path}/LICENSE"));
        package["repository"] = json!("https://github.com/shengming0817/rss");
        package["readme"] = json!(format!("{path}/README.md"));
        package["categories"] = json!(["development-tools"]);
        package["keywords"] = json!(["synthetic"]);
        package["features"] = json!({"default": []});
    }

    fn facts_with_nonempty_release_surface() -> Result<WorkspaceFacts> {
        let mut names = target_crates(None);
        names.push("alpha-release");
        let mut packages = Vec::<Value>::new();
        let mut member_ids = Vec::new();
        let mut nodes = Vec::new();
        for name in names {
            let path = format!("/workspace/crates/{name}");
            let mut package = path_package(
                name,
                &path,
                vec![target(
                    name,
                    "lib",
                    &format!("{path}/src/lib.rs"),
                    true,
                    &[],
                )],
                vec![],
                json!({}),
            );
            if name == "alpha-release" {
                make_release_ready_package(&mut package, &path);
            }
            let id = package["id"]
                .as_str()
                .context("synthetic release package id")?
                .to_owned();
            member_ids.push(id.clone());
            nodes.push(resolve_node(&id, &[]));
            packages.push(package);
        }
        let metadata = metadata_json("/workspace", packages, member_ids, nodes);
        let mut metadata: Value = serde_json::from_str(&metadata)?;
        metadata["metadata"] = json!({
            "release-surface": {
                "packages": [{
                    "package": "alpha-release",
                    "version-line": "0.1",
                    "public-api-owner": "standalone-component",
                    "api-stability": "experimental",
                    "profiles": []
                }],
                "profile-artifacts": []
            }
        });
        Ok(WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &serde_json::to_string(&metadata)?,
        )?)
    }

    fn facts_with_selected_renamed_dependency() -> Result<WorkspaceFacts> {
        let alpha_path = "/workspace/crates/alpha-release";
        let beta_path = "/workspace/crates/beta-release";
        let mut dependency = path_dependency("beta-release", beta_path);
        dependency["rename"] = json!("beta_api");
        dependency["req"] = json!("^0.1.0");
        let mut alpha = path_package(
            "alpha-release",
            alpha_path,
            vec![target(
                "facade_api",
                "lib",
                &format!("{alpha_path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![dependency],
            json!({}),
        );
        make_release_ready_package(&mut alpha, alpha_path);
        let mut beta = path_package(
            "beta-release",
            beta_path,
            vec![target(
                "beta_release",
                "lib",
                &format!("{beta_path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        make_release_ready_package(&mut beta, beta_path);
        let alpha_id = alpha["id"]
            .as_str()
            .context("synthetic alpha release id")?
            .to_owned();
        let beta_id = beta["id"]
            .as_str()
            .context("synthetic beta release id")?
            .to_owned();
        let metadata = metadata_json(
            "/workspace",
            vec![alpha, beta],
            vec![alpha_id.clone(), beta_id.clone()],
            vec![
                resolve_node(&alpha_id, &[("beta_api", &beta_id)]),
                resolve_node(&beta_id, &[]),
            ],
        );
        let mut metadata: Value = serde_json::from_str(&metadata)?;
        metadata["metadata"] = json!({
            "release-surface": {
                "packages": [
                    {"package":"alpha-release","version-line":"0.1","public-api-owner":"standalone-component","api-stability":"stable","profiles":[]},
                    {"package":"beta-release","version-line":"0.1","public-api-owner":"standalone-component","api-stability":"stable","profiles":[]}
                ],
                "profile-artifacts": []
            }
        });
        Ok(WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &serde_json::to_string(&metadata)?,
        )?)
    }

    fn facts_with_renamed_foundation_dependency() -> Result<WorkspaceFacts> {
        let platform_path = "/workspace/crates/platform";
        let contract_path = "/workspace/crates/contract";
        let mut dependency = path_dependency("rss-contract", contract_path);
        dependency["rename"] = json!("foundation_contract");
        let platform = path_package(
            "rss-platform",
            platform_path,
            vec![target(
                "rss_platform",
                "lib",
                &format!("{platform_path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![dependency],
            json!({}),
        );
        let contract = path_package(
            "rss-contract",
            contract_path,
            vec![target(
                "rss_contract",
                "lib",
                &format!("{contract_path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        let platform_id = platform["id"]
            .as_str()
            .context("synthetic platform id")?
            .to_owned();
        let contract_id = contract["id"]
            .as_str()
            .context("synthetic contract id")?
            .to_owned();
        let metadata = metadata_json(
            "/workspace",
            vec![platform, contract],
            vec![platform_id.clone(), contract_id.clone()],
            vec![
                resolve_node(&platform_id, &[("foundation_contract", &contract_id)]),
                resolve_node(&contract_id, &[]),
            ],
        );
        Ok(WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &metadata,
        )?)
    }

    #[test]
    fn closed_owner_routes_are_distinct() {
        assert_eq!(BaselineOwner::Internal.directory(), "public-api");
        assert_eq!(BaselineOwner::Release.directory(), "release-api");
        assert_ne!(
            BaselineOwner::Internal.directory(),
            BaselineOwner::Release.directory()
        );
    }

    #[test]
    fn selected_release_library_moves_to_one_owner_with_stable_sorting() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let catalog = BaselineCatalog::from_selected_packages(facts, ["vocab", "ids"])?;
        assert_eq!(
            catalog
                .release
                .iter()
                .map(PackageKey::as_str)
                .collect::<Vec<_>>(),
            vec!["ids", "vocab"]
        );
        let internal = catalog
            .internal
            .iter()
            .map(PackageKey::as_str)
            .collect::<BTreeSet<_>>();
        assert!(!internal.contains("ids"));
        assert!(!internal.contains("vocab"));
        assert!(internal.contains("diport"));
        Ok(())
    }

    #[test]
    fn validated_nonempty_surface_flows_into_release_owner_catalog() -> Result<()> {
        let facts = facts_with_nonempty_release_surface()?;
        let (surface, findings) = crate::release_surface::validate(&facts, &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let surface = surface.context("synthetic surface must validate")?;
        let catalog = BaselineCatalog::from_release_surface(&facts, &surface)?;
        assert_eq!(
            catalog
                .release
                .iter()
                .map(PackageKey::as_str)
                .collect::<Vec<_>>(),
            vec!["alpha-release"]
        );
        assert!(
            catalog
                .internal
                .iter()
                .all(|package| package.as_str() != "alpha-release")
        );
        Ok(())
    }

    #[test]
    fn real_workspace_catalog_has_exact_release_and_disjoint_owners() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let catalog = BaselineCatalog::derive(&root, facts)?;
        assert_eq!(
            catalog
                .release
                .iter()
                .map(PackageKey::as_str)
                .collect::<Vec<_>>(),
            vec![
                "rss-conformance",
                "rss-contract",
                "rss-device-security-contracts",
                "rss-diag-context",
                "rss-platform",
                "rss-request-context",
                "rss-trace-context"
            ]
        );
        let internal = catalog.internal.iter().collect::<BTreeSet<_>>();
        let release = catalog.release.iter().collect::<BTreeSet<_>>();
        assert!(internal.is_disjoint(&release));
        let owned = internal.union(&release).copied().collect::<BTreeSet<_>>();
        assert!(
            target_crates(None)
                .into_iter()
                .all(|package| owned.iter().any(|owned| owned.as_str() == package))
        );
        Ok(())
    }

    #[test]
    fn affected_internal_plan_is_exact_and_rejects_non_owner_packages() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let catalog = BaselineCatalog::derive(&root, command_facts.get()?)?;
        let selected = BTreeSet::from(["diport".to_owned(), "runtimeexec".to_owned()]);
        let plan = catalog.affected_internal_plan(&selected)?;
        assert_eq!(
            plan.targets
                .iter()
                .map(PackageKey::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["diport", "runtimeexec"])
        );
        assert!(matches!(plan.scope, BaselineScope::AffectedInternal));
        assert!(
            catalog
                .affected_internal_plan(&BTreeSet::from(["rss-platform".to_owned()]))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn release_selection_rejects_non_library_package() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let binary_only = facts
            .workspace_packages()
            .into_iter()
            .find(|package| {
                facts.targets_for(package.key()).is_ok_and(|targets| {
                    targets
                        .iter()
                        .any(|target| target.kind() == TargetKind::Binary)
                        && !targets
                            .iter()
                            .any(|target| target.kind() == TargetKind::Library)
                })
            })
            .context("workspace must contain a binary-only negative fixture")?;
        assert!(
            BaselineCatalog::from_selected_packages(facts, [binary_only.key().as_str()]).is_err()
        );
        Ok(())
    }

    #[test]
    fn exact_set_reports_missing_drift_and_orphan_with_owner_paths() -> Result<()> {
        let dir = Path::new("/repo/release-api");
        let plan = baseline_plan(
            BaselineScope::Complete(BaselineOwner::Release),
            &["vocab", "ids"],
        )?;
        let actual = BTreeMap::from([
            ("ids.txt".to_owned(), b"old".to_vec()),
            ("stale.txt".to_owned(), b"stale".to_vec()),
        ]);
        let expected = BTreeMap::from([
            ("ids.txt".to_owned(), b"new".to_vec()),
            ("vocab.txt".to_owned(), b"new".to_vec()),
        ]);
        let diff = differences(&plan, dir, &actual, &expected);
        assert_eq!(
            diff.items,
            vec![
                BaselineDifference {
                    kind: DifferenceKind::Drift,
                    package: "ids".to_owned(),
                    path: dir.join("ids.txt"),
                },
                BaselineDifference {
                    kind: DifferenceKind::Missing,
                    package: "vocab".to_owned(),
                    path: dir.join("vocab.txt"),
                },
                BaselineDifference {
                    kind: DifferenceKind::Orphan,
                    package: "stale".to_owned(),
                    path: dir.join("stale.txt"),
                },
            ]
        );
        let error = report_differences(BaselineOwner::Release, &diff)
            .err()
            .context("all differences must fail closed")?
            .to_string();
        assert!(error.contains("owner=release"));
        assert!(error.contains("status=missing owner=release package=vocab"));
        assert!(error.contains("status=orphan owner=release package=stale"));
        Ok(())
    }

    #[test]
    fn internal_layer_reports_release_selected_package_as_owner_moved_orphan() -> Result<()> {
        let root = crate::workspace_root()?;
        let facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let catalog = BaselineCatalog::from_selected_packages(facts.get()?, ["vocab"])?;
        let plan = catalog.plan(StaticBaselineScope::InternalLayer(InternalLayer::Basis));
        let dir = Path::new("/repo/public-api");
        let actual = BTreeMap::from([("vocab.txt".to_owned(), b"stale".to_vec())]);
        let diff = differences(&plan, dir, &actual, &BTreeMap::new());

        assert_eq!(
            diff.items,
            vec![BaselineDifference {
                kind: DifferenceKind::Orphan,
                package: "vocab".to_owned(),
                path: dir.join("vocab.txt"),
            }]
        );
        Ok(())
    }

    #[test]
    fn absent_empty_release_directory_is_valid_without_tool() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-empty-release");
        fs::create_dir(&root)?;
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Release), &[])?;
        execute(&root, &plan, true)?;
        assert!(!root.join("release-api").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn scanner_rejects_symlink_subdirectory_and_non_txt() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-shape");
        let dir = root.join("release-api");
        fs::create_dir_all(dir.join("nested"))?;
        assert!(scan_baselines(&dir).is_err());
        fs::remove_dir_all(dir.join("nested"))?;
        fs::write(dir.join("README.md"), b"not owned")?;
        assert!(scan_baselines(&dir).is_err());
        fs::remove_file(dir.join("README.md"))?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("missing", dir.join("link.txt"))?;
            assert!(scan_baselines(&dir).is_err());
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn scanner_rejects_same_content_directory_identity_swap() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-scan-swap");
        let dir = root.join("public-api");
        let moved = root.join("moved-public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"same")?;
        let metadata = fs::symlink_metadata(&dir)?;
        let identity = directory_identity(&dir, &metadata)?;
        let result = scan_baseline_files_with_hook(&dir, Some(identity), || {
            let rename = fs::rename(&dir, &moved);
            assert!(rename.is_ok(), "move original baseline dir: {rename:?}");
            let create = fs::create_dir(&dir);
            assert!(
                create.is_ok(),
                "create replacement baseline dir: {create:?}"
            );
            let write = fs::write(dir.join("vocab.txt"), b"same");
            assert!(write.is_ok(), "write same-content replacement: {write:?}");
        });
        assert!(result.is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn generation_rejects_concurrent_change_before_prepare() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-concurrent");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        let before = scan_baselines(&dir)?;
        fs::write(dir.join("vocab.txt"), b"raced")?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Internal), &["vocab"])?;
        assert!(apply_generation(&dir, &plan, &before, &expected).is_err());
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"raced");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn failed_prepare_preserves_live_generation() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-generation-failure");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        fs::write(dir.join("stale.txt"), b"stale")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Internal), &["vocab"])?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            bail!("synthetic prepare failure")
        });
        assert!(error.is_err());
        assert_eq!(scan_baselines(&dir)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn failed_first_generation_preserves_absent_owner() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-first-create-failure");
        fs::create_dir(&root)?;
        let dir = root.join("release-api");
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Release), &["vocab"])?;

        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            bail!("synthetic prepare failure")
        });

        assert!(error.is_err());
        assert!(!dir.exists(), "failed first commit must preserve absence");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn prepare_keeps_live_owner_unchanged_until_commit() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-generation-prepare");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        fs::write(dir.join("stale.txt"), b"stale")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Internal), &["vocab"])?;

        apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            anyhow::ensure!(
                scan_baselines(&dir)? == before,
                "prepare exposed a mixed live generation"
            );
            Ok(())
        })?;

        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"after");
        assert!(!dir.join("stale.txt").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn crashed_staging_generation_is_recovered_before_next_update() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-staging-recovery");
        let staging = root.join(".cache/public-api-staging");
        let crashed = staging.join("internal-999-1");
        fs::create_dir_all(&crashed)?;
        fs::write(crashed.join("vocab.txt"), b"old generation")?;
        let dir = root.join("public-api");
        let intended = BTreeMap::from([("vocab.txt".to_owned(), b"next".to_vec())]);

        let prepared = prepare_generation(&dir, BaselineOwner::Internal, &intended)?;

        assert!(!crashed.exists());
        assert_eq!(scan_baselines(&prepared)?.files, intended);
        cleanup_generation(&prepared)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn generation_exchange_never_clobbers_concurrent_live_output() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-generation-race");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(
            BaselineScope::InternalLayer(InternalLayer::Basis),
            &["vocab"],
        )?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            fs::write(dir.join("vocab.txt"), b"concurrent")?;
            Ok(())
        });
        assert!(error.is_err());
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"concurrent");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn partial_update_rejects_but_preserves_unselected_concurrent_change() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-partial-cas");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before-vocab")?;
        fs::write(dir.join("ids.txt"), b"before-ids")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after-vocab".to_vec())]);
        let plan = baseline_plan(
            BaselineScope::InternalLayer(InternalLayer::Basis),
            &["vocab"],
        )?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            fs::write(dir.join("ids.txt"), b"concurrent-ids")?;
            Ok(())
        });
        assert!(error.is_err());
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"before-vocab");
        assert_eq!(fs::read(dir.join("ids.txt"))?, b"concurrent-ids");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn generation_commit_never_redirects_to_replacement_directory() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-owner-swap");
        let dir = root.join("public-api");
        let moved = root.join("moved-public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(
            BaselineScope::InternalLayer(InternalLayer::Basis),
            &["vocab"],
        )?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            fs::rename(&dir, &moved)?;
            fs::create_dir(&dir)?;
            fs::write(dir.join("vocab.txt"), b"replacement")?;
            Ok(())
        });
        assert!(error.is_err());
        assert_eq!(fs::read(moved.join("vocab.txt"))?, b"before");
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"replacement");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn target_crates_counts_and_curated_exact_set() {
        // exact-set 单源 = layers + CURATED_EXTRA_CRATES，经 is_proc_macro 过滤（含 sagaauthmint；securederive 排除）。
        let expected_basis: Vec<_> = BASIS_CRATES
            .iter()
            .copied()
            .filter(|c| !crate::layers::is_proc_macro(c))
            .collect();
        let expected_engine: Vec<_> = ENGINE_CRATES
            .iter()
            .copied()
            .filter(|c| !crate::layers::is_proc_macro(c))
            .collect();
        let expected_curated: Vec<_> = CURATED_EXTRA_CRATES.to_vec();
        let expected_all: Vec<_> = expected_basis
            .iter()
            .chain(expected_engine.iter())
            .chain(expected_curated.iter())
            .copied()
            .collect();

        assert_eq!(target_crates(Some(InternalLayer::Basis)), expected_basis);
        assert_eq!(target_crates(Some(InternalLayer::Engine)), expected_engine);
        assert_eq!(
            target_crates(Some(InternalLayer::Curated)),
            expected_curated
        );
        assert_eq!(target_crates(None), expected_all);
        // len 仅由 exact-set 派生，禁止裸魔法数主证。
        assert_eq!(
            target_crates(Some(InternalLayer::Basis)).len(),
            expected_basis.len()
        );
        assert_eq!(
            target_crates(Some(InternalLayer::Engine)).len(),
            expected_engine.len()
        );
        assert_eq!(target_crates(None).len(), expected_all.len());
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"assembly-schema"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"authmint"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"sagaauthmint"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"vocab"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"primitives"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"rss-trace-context"));
    }

    #[test]
    fn target_crates_membership_keeps_curated_in_baseline() {
        assert!(target_crates(None).contains(&"authn"));
        assert!(target_crates(None).contains(&"diport"));
        assert!(target_crates(None).contains(&"generated"));
        assert!(target_crates(None).contains(&"runtimeexec"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"vocab"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"primitives"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"rss-trace-context"));
    }

    #[test]
    fn target_crates_membership_keeps_curated_out_of_layers() {
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"authn"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"authn"));
        // diport 是 DI-infra 层，既非 basis 也非 engine——只经 curated extras 入 baseline。
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"diport"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"diport"));
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"generated"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"generated"));
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"runtimeexec"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"runtimeexec"));
        // proc-macro 工具 crate 不入 public-api baseline（契约由 codegen golden 守）。
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"securederive"));
    }

    #[test]
    fn target_crates_have_no_duplicates() {
        let crates = target_crates(None);
        let set: std::collections::BTreeSet<_> = crates.iter().copied().collect();
        assert_eq!(set.len(), crates.len(), "public-api 目标 crate 不得重复");
    }

    #[test]
    fn runtimeexec_public_api_golden_keeps_launch_kernel_narrow() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("runtimeexec.txt"))?;
        for required in [
            "pub trait runtimeexec::LaunchAdapter",
            "pub struct runtimeexec::LaunchPlan",
            "pub fn runtimeexec::LaunchPlan<Adapter, ProbeReceipt, ReadyHook>::new",
            "pub struct runtimeexec::LaunchTransaction",
            "pub fn runtimeexec::LaunchTransaction<'stack>::stage_resource",
            "pub struct runtimeexec::LaunchRegistrar",
            "pub fn runtimeexec::LaunchRegistrar<'_>::register_listener_with_token",
            "pub fn runtimeexec::LaunchRegistrar<'_>::complete",
            "pub struct runtimeexec::Activated",
            "pub struct runtimeexec::ProviderLifecycleBatch",
            "pub struct runtimeexec::DomainLifecycleBatch",
            "pub struct runtimeexec::LaunchLifecycleBatches",
            "pub struct runtimeexec::RuntimeOutputs",
            "pub async fn runtimeexec::launch",
        ] {
            assert!(
                baseline.contains(required),
                "runtimeexec public-api golden 缺必要启动内核项: {required}"
            );
        }
        for forbidden in [
            "ShutdownStack",
            "wait_for_shutdown_signal",
            "register_detached",
            "listener_count",
            "launch_until",
            "httpd::",
            "httpserve::",
            "pub mod runtimeexec::authn",
            "pub struct runtimeexec::RuntimeInventory",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "runtimeexec public-api golden 不得泄露内部/transport/provider 项: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn authn_public_api_golden_keeps_verified_token_seal_private() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("authn.txt"))?;
        for required in [
            "pub struct authn::VerifiedJwt",
            "pub fn authn::VerifiedJwt::raw(&self) -> &str",
            "pub struct authn::VerifiedServiceToken",
            "pub fn authn::VerifiedServiceToken::raw(&self) -> &str",
            "pub fn authn::Principal::from_verified_jwt(&authn::VerifiedJwt)",
            "pub fn authn::Principal::from_verified_service_token(&authn::VerifiedServiceToken)",
            "pub async fn authn::verify_rss_access",
            "pub async fn authn::verify_federated_access",
            "pub async fn authn::verify_service_token",
            "pub struct authn::RssAccessIssueInput",
            "pub struct authn::VerifiedGrantReceipt",
            "pub fn authn::VerifiedJwt::grant_receipt(&self)",
            "pub fn authn::AuthGrant::access_issue_input(&self)",
        ] {
            assert!(
                baseline.contains(required),
                "authn public-api golden 缺少必要公开项: {required}"
            );
        }
        for forbidden in [
            "pub fn authn::VerifiedJwt::seal",
            "pub fn authn::VerifiedServiceToken::seal",
            "VerifiedJwt::seal",
            "VerifiedServiceToken::seal",
            "JwtAccessPrincipal",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "authn public-api golden 不得暴露私有 mint funnel: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn diport_internal_export_baseline_reexports_send_variant_not_base_trait() -> anyhow::Result<()>
    {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("diport.txt"))?;
        // crate 根 re-export = Send 变体 + Dyn wrapper + KeyProvider 公开类型（adapters/组合根消费面）。
        for required in [
            "pub trait diport::KeyProvider: core::marker::Send",
            "pub struct diport::DynKeyProvider",
            "pub struct diport::KeyRef",
            "pub struct diport::EncryptOutput",
            // 方法列在定义路径（cargo-public-api 惯例），非 re-export 路径；parse ⇄ to_token 对称 token 存储面单源。
            "pub fn diport::key_provider::KeyRef::to_token",
            "pub struct diport::VerifiedAccessGrantFacts",
            "pub fn diport::pdp::VerifiedClaims::rss_user",
            "pub enum diport::pdp::VerifiedClaimsView<'a>",
            "pub fn diport::pdp::VerifiedClaims::view(&self) -> diport::pdp::VerifiedClaimsView<'_>",
        ] {
            assert!(
                baseline.contains(required),
                "diport internal export baseline 缺少必要导出项: {required}"
            );
        }
        // 非 Send 基 trait `*Local` **不**在 crate 根 re-export（仅 `diport::key_provider::KeyProviderLocal`
        // 经 pub mod 可达），避免 glob import 方法解析歧义（ADR-003 落地结论）。
        assert!(
            !baseline.contains("pub trait diport::KeyProviderLocal"),
            "diport internal export baseline 不得在 crate 根 re-export 基 trait KeyProviderLocal"
        );
        assert!(
            !baseline.contains("VerifiedClaims::new"),
            "diport internal export baseline 不得恢复开放的 VerifiedClaims 构造器"
        );
        // 安全负向不变式（ADR-011 §D3 防 timing oracle）：key 标识 `KeyName`/`KeyVersion`/`KeyRef` **禁** derive
        // `PartialEq`/`Eq`——只能经 `ct_eq` 等值-only 匹配。golden 锁住「无 `==` 能力」，杜绝后续 PR 重生 baseline
        // 时误把 `==`（非常数时间）纳入公开面。负向 golden + 不 derive（类型层）双守。
        for forbidden in [
            "impl core::cmp::PartialEq for diport::key_provider::KeyName",
            "impl core::cmp::Eq for diport::key_provider::KeyName",
            "impl core::cmp::PartialEq for diport::key_provider::KeyVersion",
            "impl core::cmp::Eq for diport::key_provider::KeyVersion",
            "impl core::cmp::PartialEq for diport::key_provider::KeyRef",
            "impl core::cmp::Eq for diport::key_provider::KeyRef",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "diport internal export baseline 不得暴露 key 标识的非常数时间 `==`（ADR-011 §D3）: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn generated_public_api_golden_exposes_generated_metadata_surfaces() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("generated.txt"))?;
        for required in [
            "pub trait generated::FieldProtectionMetadata",
            "pub const generated::FieldProtectionMetadata::FIELD_PROTECTIONS: &'static [generated::FieldProtectionSpec]",
            "impl generated::FieldProtectionMetadata for generated::http::settings_v1::SettingsConfigPublishRequest",
            "pub const generated::http::settings_v1::SettingsConfigPublishRequest::FIELD_PROTECTIONS: &'static [generated::FieldProtectionSpec]",
            "pub struct generated::FieldProtectionSpec",
            "pub generated::FieldProtectionSpec::field_path: &'static str",
            "pub generated::FieldProtectionSpec::at_rest: generated::ProtectionAtRest",
            "pub generated::FieldProtectionSpec::mode: core::option::Option<generated::ProtectionMode>",
            "pub enum generated::ProtectionAadDim",
            "pub enum generated::ProtectionAtRest",
            "pub enum generated::ProtectionMode",
            "pub generated::http::HttpSpec::route: vocab::http::HttpRouteEvidence",
            "pub const generated::http::settings_v4::ROUTE: vocab::http::HttpRouteBinding<generated::http::settings_v4::RouteMarker, vocab::http::LocalOnly>",
            "pub enum generated::http::settings_v4::RouteMarker",
            "pub generated::http::HttpSpec::local_tx: core::option::Option<generated::http::LocalTxSpec>",
            "pub struct generated::http::LocalTxSpec",
            "pub generated::http::LocalTxSpec::boundary: vocab::http::LocalTxBoundary",
            "pub generated::http::LocalTxSpec::tx_model: vocab::http::LocalTxModel",
            "pub generated::http::LocalTxSpec::retry: vocab::http::LocalTxRetry",
            "pub generated::http::LocalTxSpec::commit_unknown: vocab::http::LocalTxCommitUnknown",
            "pub const generated::http::LOCAL_TX_SPECS: &[generated::http::HttpSpec]",
            "pub const generated::http::LOCAL_ONLY_SPECS: &[generated::http::HttpSpec]",
            "pub trait generated::http::HttpResponseBinding",
            "pub const generated::http::identity_v2::device_certificate_policy_put::RESPONSES: &[generated::http::HttpResponseSpec]",
            "impl generated::http::HttpResponseBinding for generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutConflictResponse",
            "pub enum generated::http::audit_v1::list_entries::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::policies_get::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::policies_list::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::profile::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::roles_list::LocalOnlyConformanceMarker",
            "pub enum generated::http::settings_v4::LocalOnlyConformanceMarker",
            "pub const generated::http::audit_v1::list_tenant_entries::LOCAL_TX: generated::http::LocalTxSpec",
            "pub const generated::http::identity_v1::logout::PRODUCER: vocab::http::HttpProducerBinding<generated::http::identity_v1::logout::RouteMarker>",
            "pub const generated::http::identity_v1::refresh::PRODUCER: vocab::http::HttpProducerBinding<generated::http::identity_v1::refresh::RouteMarker>",
            "pub const generated::http::settings_v2::LOCAL_TX: generated::http::LocalTxSpec",
            "pub struct generated::command::CommandSpec",
            "pub trait generated::command::CommandJournal",
            "pub const fn generated::command::CommandSpec::journal(self) -> generated::command::CommandJournalPolicy",
            "pub struct generated::event::EventSpec",
            "pub enum generated::event::PartitionKeyStrategy",
            "pub enum generated::event::SubscriberReadiness",
            "pub enum generated::event::SubscriptionDispatchKey",
            "pub const generated::event::EVENTS: &[generated::event::EventSpec]",
            "pub const fn generated::event::EventSpec::subscriptions(self) -> &'static [generated::event::SubscriptionSpec]",
            "pub const fn generated::event::SubscriptionSpec::dispatch(self) -> generated::event::SubscriptionDispatchKey",
            "pub const fn generated::event::SubscriptionSpec::external_effect_policy(self) -> vocab::ExternalEffectPolicy",
        ] {
            assert!(
                baseline.contains(required),
                "generated public-api golden 缺少 metadata API: {required}"
            );
        }
        for forbidden in [
            "diport::",
            "secure::aead",
            "secure::Ciphertext",
            "generated::KeyProvider",
            "generated::ProtectionContext",
            "generated::DerivedAad",
            "generated::ValueTransformer",
            "generated::KeyRef",
            "generated::EncryptOutput",
            "generated::DecryptOutput",
            "generated::seal",
            "generated::open",
            "generated::rewrap",
            "pub generated::event::SubscriptionSpec::consumer:",
            "pub generated::event::SubscriptionSpec::group:",
            "pub generated::event::EventSpec::topic:",
            "pub generated::command::CommandSpec::topic:",
            "generated::http::HttpConsistencyLevel",
            "generated::http::EffectProfile",
            "generated::http::EffectKind",
            "generated::http::HttpAuthMode",
            "generated::http::HttpAuthSpec",
            "pub generated::http::HttpSpec::contract_id:",
            "pub generated::http::HttpSpec::contract:",
            "pub generated::http::HttpSpec::path:",
            "pub generated::http::HttpSpec::method:",
            "pub generated::http::HttpSpec::auth:",
            "pub generated::http::HttpSpec::resource:",
            "pub generated::http::HttpSpec::self_scoped:",
            "pub generated::http::HttpSpec::consistency_level:",
            "pub generated::http::HttpSpec::effect_profile:",
            "generated::http::LocalTxBoundary",
            "generated::http::LocalTxModel",
            "generated::http::LocalTxRetry",
            "generated::http::LocalTxCommitUnknown",
        ] {
            assert!(
                !baseline.lines().any(|line| line.contains(forbidden)),
                "generated public-api golden 不得暴露加解密执行面符号: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn vocab_public_api_golden_exposes_canonical_http_route_evidence() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("vocab.txt"))?;
        for required in [
            "pub enum vocab::http::HttpConsistencyLevel",
            "pub trait vocab::http::HttpConsistencyClass",
            "pub trait vocab::http::NonLocalHttpConsistency",
            "pub struct vocab::http::LocalOnly",
            "pub enum vocab::http::HttpEffectKind",
            "pub struct vocab::http::HttpEffectProfile",
            "pub const fn vocab::http::HttpEffectProfile::new",
            "pub struct vocab::http::HttpSuccessStatus",
            "pub const fn vocab::http::HttpSuccessStatus::new",
            "pub const fn vocab::http::HttpSuccessStatus::get",
            "pub enum vocab::http::HttpIdempotency",
            "pub vocab::http::HttpIdempotency::Idempotent",
            "pub vocab::http::HttpIdempotency::NonIdempotent",
            "pub enum vocab::http::HttpRouteAuth",
            "pub struct vocab::http::HttpQueryParameterSpec",
            "pub const fn vocab::http::HttpQueryParameterSpec::from_static",
            "pub struct vocab::http::HttpContractOwner",
            "pub const fn vocab::http::HttpContractOwner::framework",
            "pub const fn vocab::http::HttpContractOwner::domain_name",
            "pub struct vocab::http::HttpRouteBinding<M, C>",
            "pub const fn vocab::http::HttpRouteBinding<M, C>::from_static",
            "pub const fn vocab::http::HttpRouteBinding<M, C>::evidence",
            "pub struct vocab::http::HttpRouteEvidence",
            "pub const fn vocab::http::HttpRouteEvidence::from_static",
            "pub const fn vocab::http::HttpRouteEvidence::success_status",
            "pub const fn vocab::http::HttpRouteEvidence::idempotency",
            "pub const fn vocab::http::HttpRouteEvidence::query_parameters",
            "pub const fn vocab::http::HttpRouteEvidence::effect_profile",
            "pub enum vocab::http::LocalTxBoundary",
            "pub const vocab::http::LocalTxBoundary::ALL: &'static [Self]",
            "pub const fn vocab::http::LocalTxBoundary::as_label",
            "pub enum vocab::http::LocalTxModel",
            "pub enum vocab::http::LocalTxRetry",
            "pub enum vocab::http::LocalTxCommitUnknown",
        ] {
            assert!(
                baseline.contains(required),
                "vocab public-api golden 缺少 canonical HTTP evidence API: {required}"
            );
        }
        let exposed_fields = exposed_http_route_evidence_fields(&baseline);
        assert!(
            exposed_fields.is_empty(),
            "vocab HttpRouteEvidence 全部字段必须保持私有: {exposed_fields:?}"
        );
        for forbidden in [
            "pub vocab::http::HttpEffectProfile::effects:",
            "pub vocab::http::HttpRouteBinding::evidence:",
            "pub vocab::http::HttpRouteBinding::marker:",
            "impl<M, C> core::default::Default for vocab::http::HttpRouteBinding<M, C>",
            "impl core::default::Default for vocab::http::HttpEffectProfile",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "vocab HTTP evidence 必须保持私有字段且无 Default: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn consistency_public_api_golden_exposes_closed_local_tx_vocabulary() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("consistency.txt"))?;
        for required in [
            "pub use consistency::localtx::LocalTxBoundary",
            "pub use consistency::localtx::LocalTxCommitUnknown",
            "pub use consistency::localtx::LocalTxModel",
            "pub use consistency::localtx::LocalTxRetry",
            "pub enum consistency::localtx::LocalTxFinalStatus",
            "pub consistency::localtx::LocalTxFinalStatus::Committed",
            "pub consistency::localtx::LocalTxFinalStatus::RolledBack",
            "pub consistency::localtx::LocalTxFinalStatus::RollbackFailed",
            "pub consistency::localtx::LocalTxFinalStatus::CommitUnknown",
            "pub const consistency::localtx::LocalTxFinalStatus::ALL: &'static [Self]",
            "pub const fn consistency::localtx::LocalTxFinalStatus::as_label",
            "pub const consistency::tx_retry::TxRetryClass::ALL: &'static [Self]",
            "pub const consistency::tx_retry::TxRetryFinalStatus::ALL: &'static [Self]",
        ] {
            assert!(
                baseline.contains(required),
                "consistency public-api golden 缺少闭合 LocalTx API: {required}"
            );
        }
        Ok(())
    }

    #[test]
    fn http_route_evidence_private_field_guard_covers_all_fields() {
        let synthetic = r#"
pub vocab::http::HttpRouteEvidence::owner: vocab::http::HttpContractOwner
pub vocab::http::HttpRouteEvidence::contract: vocab::contract::binding::ContractBinding
pub vocab::http::HttpRouteEvidence::path: &'static str
pub vocab::http::HttpRouteEvidence::method: &'static str
pub vocab::http::HttpRouteEvidence::success_status: vocab::http::HttpSuccessStatus
pub vocab::http::HttpRouteEvidence::idempotency: vocab::http::HttpIdempotency
pub vocab::http::HttpRouteEvidence::auth: vocab::http::HttpRouteAuth
pub vocab::http::HttpRouteEvidence::resource: core::option::Option<&'static str>
pub vocab::http::HttpRouteEvidence::self_scoped: bool
pub vocab::http::HttpRouteEvidence::consistency_level: vocab::http::HttpConsistencyLevel
pub vocab::http::HttpRouteEvidence::effect_profile: vocab::http::HttpEffectProfile
"#;
        assert_eq!(
            exposed_http_route_evidence_fields(synthetic),
            vec![
                "owner",
                "contract",
                "path",
                "method",
                "success_status",
                "idempotency",
                "auth",
                "resource",
                "self_scoped",
                "consistency_level",
                "effect_profile",
            ],
            "a refreshed golden must not hide any newly public HttpRouteEvidence field"
        );
    }

    #[test]
    fn baseline_dir_is_public_api_under_root() -> anyhow::Result<()> {
        let dir = baseline_dir()?;
        assert!(dir.ends_with("public-api"));
        assert!(dir.parent().is_some());
        Ok(())
    }

    // ---- NIGHTLY-PIN-01：public-api 钉版 nightly（RUSTUP_TOOLCHAIN 重设）+ 三方 SoT 一致 ----

    /// `public_api_cmd` 构造 `cargo public-api -p <crate>`、cwd 为 None（与原 capture 行为一致）。
    #[test]
    fn public_api_cmd_sets_program_and_args() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(
            &root,
            "vocab",
            PINNED_NIGHTLY,
            &public_api_target_dir()?,
            false,
        );
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cargo"));
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            vec![
                std::ffi::OsStr::new("public-api"),
                std::ffi::OsStr::new("-p"),
                std::ffi::OsStr::new("vocab"),
                std::ffi::OsStr::new("--omit"),
                std::ffi::OsStr::new("blanket-impls"),
            ]
        );
        assert_eq!(cmd.get_current_dir(), Some(root.as_path()));
        Ok(())
    }

    /// 传 `PINNED_NIGHTLY` 时 `RUSTUP_TOOLCHAIN` 被经 clean_cmd 显式重设为钉版 nightly
    /// （等价 `cargo +nightly-2026-04-16 public-api`，使 rustdoc-json 可复现）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }.
    #[test]
    fn public_api_cmd_injects_pinned_toolchain() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(
            &root,
            "ids",
            PINNED_NIGHTLY,
            &public_api_target_dir()?,
            false,
        );
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        assert!(
            envs.iter()
                .any(|(k, v)| *k == std::ffi::OsStr::new("RUSTUP_TOOLCHAIN")
                    && *v == Some(std::ffi::OsStr::new(PINNED_NIGHTLY))),
            "RUSTUP_TOOLCHAIN 应被显式重设为 PINNED_NIGHTLY"
        );
        Ok(())
    }

    /// rustdoc-json 快照必须使用独占 target，避免前序 all-features/coverage 产物令同一 CI 首次
    /// `public-api internal --check` 漂移、立即重跑却转绿。
    #[test]
    fn public_api_cmd_isolates_rustdoc_json_target() -> anyhow::Result<()> {
        let expected = public_api_target_dir()?;
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(&root, "consistency", PINNED_NIGHTLY, &expected, false);
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        assert!(
            envs.iter().any(|(k, v)| {
                *k == std::ffi::OsStr::new("CARGO_TARGET_DIR") && *v == Some(expected.as_os_str())
            }),
            "public-api 须使用独占 CARGO_TARGET_DIR"
        );
        Ok(())
    }

    /// 经 clean_cmd 漏斗：除 `RUSTUP_TOOLCHAIN`（本步显式重设）外，其它 ambient toolchain/flag 变量
    /// （`RUSTC`/`RUSTDOC`/`RUSTFLAGS`/…）仍被 env_remove —— 剥离后由显式 env 成唯一来源（CMD-ENV-CLEAN-01）。
    #[test]
    fn public_api_cmd_strips_other_ambient_but_resets_toolchain() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(
            &root,
            "vocab",
            PINNED_NIGHTLY,
            &public_api_target_dir()?,
            false,
        );
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        for stripped in crate::cmd::STRIPPED_ENV
            .iter()
            .filter(|v| !matches!(**v, "RUSTUP_TOOLCHAIN" | "RUSTC_WRAPPER"))
        {
            assert!(
                envs.iter()
                    .any(|(k, v)| *k == std::ffi::OsStr::new(stripped) && v.is_none()),
                "{stripped} 应被 env_remove"
            );
        }
        assert!(
            envs.iter()
                .any(|(k, v)| *k == std::ffi::OsStr::new("RUSTUP_TOOLCHAIN")
                    && *v == Some(std::ffi::OsStr::new(PINNED_NIGHTLY))),
            "RUSTUP_TOOLCHAIN 在剥离后由显式 env 重设"
        );
        let wrapper = envs
            .iter()
            .find(|(key, _)| *key == std::ffi::OsStr::new("RUSTC_WRAPPER"))
            .and_then(|(_, value)| *value);
        assert!(
            wrapper.is_none_or(|value| std::path::Path::new(value).is_absolute()),
            "RUSTC_WRAPPER 只能由 compiler-cache policy 注入绝对路径"
        );
        Ok(())
    }

    /// anti-vacuity：toolchain 入参透传（非把 `PINNED_NIGHTLY` 硬编码忽略参数）。
    #[test]
    fn public_api_cmd_toolchain_arg_flows_through() -> anyhow::Result<()> {
        let fake = "nightly-1999-01-01";
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(&root, "vocab", fake, &public_api_target_dir()?, false);
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        assert!(
            envs.iter()
                .any(|(k, v)| *k == std::ffi::OsStr::new("RUSTUP_TOOLCHAIN")
                    && *v == Some(std::ffi::OsStr::new(fake))),
            "toolchain 入参应透传进 RUSTUP_TOOLCHAIN"
        );
        Ok(())
    }

    #[test]
    fn release_capture_uses_all_features_without_changing_internal_capture() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let target = public_api_target_dir()?;
        let release = public_api_cmd(&root, "vocab", PINNED_NIGHTLY, &target, true);
        let internal = public_api_cmd(&root, "vocab", PINNED_NIGHTLY, &target, false);
        assert!(release.get_args().any(|arg| arg == "--all-features"));
        assert!(!internal.get_args().any(|arg| arg == "--all-features"));
        Ok(())
    }

    #[test]
    fn public_api_library_pin_matches_cli_tool_catalog() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let manifest = std::fs::read_to_string(root.join("Cargo.toml"))?.parse::<toml::Value>()?;
        let dependency = manifest["workspace"]["dependencies"]["public-api"]["version"]
            .as_str()
            .context("workspace public-api dependency must carry an exact version")?;
        let catalog = std::fs::read_to_string(root.join(".github/scripts/ci-tool-catalog.txt"))?;
        let cli = catalog
            .lines()
            .find_map(|line| {
                let mut fields = line.split('|');
                (fields.next() == Some("cargo-public-api"))
                    .then(|| fields.next())
                    .flatten()
            })
            .context("cargo-public-api tool catalog row is missing")?;
        assert_eq!(dependency, format!("={cli}"));
        Ok(())
    }

    // 三方 pinned-nightly SoT 解析（仅 test 用——production 无消费方读这两文件）。

    /// 从 `rust-toolchain.toml` 文本取 `[toolchain].channel`。
    fn parse_toolchain_channel(toml_src: &str) -> Option<String> {
        toml_src
            .parse::<toml::Value>()
            .ok()?
            .get("toolchain")?
            .get("channel")?
            .as_str()
            .map(str::to_owned)
    }

    /// 从 GitHub CI workflow 文本取 `RSS_NIGHTLY_PINNED` 变量值：行扫描，先 `split('#')` 剥注释、
    /// 再结构绑定 `RSS_NIGHTLY_PINNED:` 前缀——防注释内同名误满足（无 serde_yaml 依赖）。
    fn github_ci_nightly_pinned(yaml_src: &str) -> Option<String> {
        yaml_src.lines().find_map(|line| {
            let code = line.split('#').next().unwrap_or("").trim();
            let rest = code.strip_prefix("RSS_NIGHTLY_PINNED:")?;
            Some(rest.trim().to_owned())
        })
    }

    /// 三方 pinned-nightly 是否一致。
    fn nightly_pins_agree(const_val: &str, channel: &str, github_ci: &str) -> bool {
        const_val == channel && channel == github_ci
    }

    #[test]
    fn parse_toolchain_channel_extracts_channel() {
        assert_eq!(
            parse_toolchain_channel("[toolchain]\nchannel = \"nightly-2026-04-16\"\n").as_deref(),
            Some("nightly-2026-04-16")
        );
        // 缺 channel → None（不静默成空串）。
        assert_eq!(
            parse_toolchain_channel("[toolchain]\nprofile = \"minimal\"\n"),
            None
        );
    }

    #[test]
    fn github_ci_nightly_pinned_extracts_value() {
        assert_eq!(
            github_ci_nightly_pinned("env:\n  RSS_NIGHTLY_PINNED: nightly-2026-04-16\n").as_deref(),
            Some("nightly-2026-04-16")
        );
        // 值后带行尾注释：split('#') 剥注释后取值（YAML unquoted scalar 行尾注释语义，刻意支持）。
        assert_eq!(
            github_ci_nightly_pinned("  RSS_NIGHTLY_PINNED: nightly-2026-04-16 # 钉版\n")
                .as_deref(),
            Some("nightly-2026-04-16")
        );
        // synthetic red（fail-closed）：仅注释行不可误满足（对标 verify.rs codex F1）。
        assert_eq!(
            github_ci_nightly_pinned("  # RSS_NIGHTLY_PINNED: nightly-2026-04-16\n"),
            None
        );
    }

    #[test]
    fn nightly_pin_predicate_green_and_red() {
        let p = PINNED_NIGHTLY;
        // 绿：三相等。
        assert!(nightly_pins_agree(p, p, p));
        // 红：逐方向构造不一致三元组均 false（守卫非恒真）。
        let other = "nightly-2026-05-01";
        assert!(!nightly_pins_agree(p, p, other));
        assert!(!nightly_pins_agree(p, other, p));
        assert!(!nightly_pins_agree(other, p, p));
    }

    /// anti-vacuity 真实绿例：从真实 `lints/rust-toolchain.toml` + reusable workflow 解析，断言
    /// 三方功能 pinned-nightly 一致（`PINNED_NIGHTLY` == lints channel == GitHub CI `RSS_NIGHTLY_PINNED`）。
    /// 第四处镜像（verify.rs public-api install_hint）由 `verify::tests::public_api_install_hint_pins_nightly`
    /// 守——绑真实 install_hint 字段值（非源码全文，避免注释含 pin 的误绿）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }.
    #[test]
    fn pinned_nightly_single_source_of_truth() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let toolchain_toml =
            std::fs::read_to_string(root.join("lints").join("rust-toolchain.toml"))?;
        let github_ci_yaml = std::fs::read_to_string(
            root.join(".github")
                .join("workflows")
                .join("rss-rust-job.yml"),
        )?;
        let channel = parse_toolchain_channel(&toolchain_toml)
            .ok_or_else(|| anyhow::anyhow!("lints/rust-toolchain.toml 应有 [toolchain].channel"))?;
        let github_ci = github_ci_nightly_pinned(&github_ci_yaml).ok_or_else(|| {
            anyhow::anyhow!(".github/workflows/rss-rust-job.yml 应有 RSS_NIGHTLY_PINNED 变量")
        })?;
        assert!(
            nightly_pins_agree(PINNED_NIGHTLY, &channel, &github_ci),
            "pinned nightly 三方漂移：PINNED_NIGHTLY={PINNED_NIGHTLY}, lints channel={channel}, github_ci={github_ci}"
        );
        Ok(())
    }

    #[test]
    fn release_selection_delta_checks_only_intersection_and_records_explicit_removal() {
        let current = BTreeSet::from(["added".to_owned(), "kept".to_owned()]);
        let base = BTreeSet::from(["kept".to_owned(), "removed".to_owned()]);
        let delta = ReleaseSelectionDelta::derive(&current, &base);
        assert_eq!(delta.semver_packages, vec!["kept"]);
        assert_eq!(delta.first_release_packages, vec!["added"]);
        assert_eq!(delta.removed_packages, vec!["removed"]);
    }

    #[test]
    fn prepublication_version_line_is_bound_to_the_merge_base() {
        assert_eq!(
            changed_frozen_version_line(Some("0.3"), "0.4"),
            Some(("0.3", "0.4"))
        );
        assert_eq!(changed_frozen_version_line(Some("0.3"), "0.3"), None);
        assert_eq!(changed_frozen_version_line(None, "0.3"), None);
    }

    #[test]
    fn semver_command_is_per_package_all_features_and_revision_bound() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let command = semver_check_cmd(
            &root,
            "facade",
            "0123456789abcdef0123456789abcdef01234567",
            ApiProfile::AllFeatures,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "semver-checks",
                "check-release",
                "--package",
                "facade",
                "--all-features",
                "--baseline-rev",
                "0123456789abcdef0123456789abcdef01234567",
            ]
        );
        assert!(!args.iter().any(|arg| arg == "--workspace"));
        let default = semver_check_cmd(
            &root,
            "facade",
            "0123456789abcdef0123456789abcdef01234567",
            ApiProfile::Default,
        );
        assert!(!default.get_args().any(|arg| arg == "--all-features"));
        Ok(())
    }

    #[test]
    fn semver_runner_checks_both_profiles_for_every_selected_intersection_and_aggregates() {
        let packages = vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()];
        let mut called = Vec::new();
        let error = run_semver_packages(&packages, |package, profile| {
            called.push((package.to_owned(), profile));
            if matches!(package, "alpha" | "gamma") && profile == ApiProfile::Default {
                bail!("synthetic breaking change")
            }
            Ok(())
        })
        .err()
        .map(|error| error.to_string());
        assert_eq!(called.len(), packages.len() * 2);
        for package in &packages {
            assert!(called.contains(&(package.clone(), ApiProfile::Default)));
            assert!(called.contains(&(package.clone(), ApiProfile::AllFeatures)));
        }
        let error = error.as_deref().unwrap_or("");
        assert!(error.contains("2 项 SemVer 校验失败"));
        assert!(error.contains("package=alpha"));
        assert!(error.contains("package=gamma"));
        assert!(error.contains("profile=default"));
    }

    #[test]
    fn release_capture_combines_default_and_all_features_without_unioning_them() {
        let capture = combine_release_captures(
            ApiCapture {
                baseline: "pub fn facade::default_only()\n".to_owned(),
                rustdoc_json: vec![(ApiProfile::Default, PathBuf::from("default.json"))],
            },
            ApiCapture {
                baseline: "pub fn facade::feature_only()\n".to_owned(),
                rustdoc_json: vec![(ApiProfile::AllFeatures, PathBuf::from("all.json"))],
            },
        );
        assert!(capture.baseline.contains("profile: default"));
        assert!(capture.baseline.contains("facade::default_only"));
        assert!(capture.baseline.contains("profile: all-features"));
        assert!(capture.baseline.contains("facade::feature_only"));
        assert_eq!(capture.rustdoc_json.len(), 2);
    }

    #[test]
    fn semver_failure_preserves_both_labeled_channels_and_exit_class() {
        let message = format_semver_failure(Some(100), b"lint: function_missing", b"major bump");
        assert!(message.contains("compatibility-violation"));
        assert!(message.contains("stdout:\nlint: function_missing"));
        assert!(message.contains("stderr:\nmajor bump"));
        assert!(format_semver_failure(Some(101), b"", b"boom").contains("tool-failure"));
    }

    #[test]
    fn semver_lazy_prerequisite_honors_explicit_missing_tool_policy() {
        assert!(semver_tool_action(true, false).is_ok_and(|run| run));
        assert!(semver_tool_action(false, true).is_ok_and(|run| !run));
        assert!(semver_tool_action(false, false).is_err());
    }

    #[test]
    fn release_stage_collector_continues_and_sorts_independent_failures() {
        let mut called = Vec::new();
        let mut failures = Vec::new();
        for (stage, subject) in [(3, "leakage"), (0, "internal"), (2, "release")] {
            collect_release_stage::<()>(&mut failures, stage, subject, || {
                called.push(subject);
                bail!("synthetic {subject} failure")
            });
        }
        failures.sort();
        assert_eq!(called, ["leakage", "internal", "release"]);
        assert_eq!(
            failures
                .iter()
                .map(|failure| failure.subject.as_str())
                .collect::<Vec<_>>(),
            ["internal", "release", "leakage"]
        );
    }

    #[test]
    fn structured_tokens_find_nested_reexport_error_and_conversion_type_paths() {
        use public_api::tokens::Token::{Identifier, Symbol, Type};

        let tokens = vec![
            Identifier("core".into()),
            Symbol("::".into()),
            Type("Result".into()),
            Symbol("<".into()),
            Identifier("internal_crate".into()),
            Symbol("::".into()),
            Identifier("errors".into()),
            Symbol("::".into()),
            Type("SecretError".into()),
            Symbol(",".into()),
            Identifier("tracing".into()),
            Symbol("::".into()),
            Type("Span".into()),
            Symbol(">".into()),
        ];

        assert_eq!(
            referenced_type_paths(&tokens),
            BTreeSet::from([
                "core::Result".to_owned(),
                "internal_crate::errors::SecretError".to_owned(),
                "tracing::Span".to_owned(),
            ])
        );
    }

    #[test]
    fn owner_policy_is_closed_and_anti_vacuous() {
        let workspace = BTreeSet::from(["facade".to_owned(), "internal_crate".to_owned()]);
        let selected = BTreeSet::from(["facade".to_owned()]);
        assert_eq!(
            forbidden_type_root(
                workspacefacts::PublicApiOwner::PlatformPublic,
                "facade",
                "internal_crate::Secret",
                &workspace,
                &selected,
                None,
            ),
            Some("internal_crate")
        );
        assert_eq!(
            forbidden_type_root(
                workspacefacts::PublicApiOwner::StandaloneComponent,
                "facade",
                "tracing::Span",
                &workspace,
                &selected,
                None,
            ),
            None
        );
        assert_eq!(
            forbidden_type_root(
                workspacefacts::PublicApiOwner::StandaloneComponent,
                "facade",
                "opentelemetry_sdk::trace::Tracer",
                &workspace,
                &selected,
                None,
            ),
            Some("opentelemetry_sdk")
        );
    }

    #[test]
    fn canonical_foundation_owner_catalog_is_closed_and_anti_vacuous() {
        assert_eq!(
            canonical_foundation_primitives(),
            &[
                ("rss-request-context", "TenantId"),
                ("rss-contract", "ContractDescriptor"),
                ("rss-contract", "Timepoint"),
                ("rss-contract", "PageCursor"),
                ("rss-contract", "DataClass"),
                ("rss-contract", "SafeError"),
            ]
        );
    }

    fn real_release_surface_for_foundation_owner_test()
    -> anyhow::Result<crate::release_surface::ReleaseSurface> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let (surface, findings) = crate::release_surface::validate(facts, &[]);
        assert!(findings.is_empty(), "{findings:?}");
        surface.context("real Release Surface missing")
    }

    fn canonical_foundation_green_items() -> BTreeMap<String, Vec<ApiItemProjection>> {
        let mut items = BTreeMap::<String, Vec<ApiItemProjection>>::new();
        for (owner, name) in canonical_foundation_primitives() {
            for profile in ApiProfile::RELEASE {
                items
                    .entry((*owner).to_owned())
                    .or_default()
                    .push(ApiItemProjection {
                        profile,
                        rendered: format!(
                            "profile={} pub use {}::{name}",
                            profile.label(),
                            normalized_crate_name(owner)
                        ),
                        tokens: Vec::new(),
                        source_paths: BTreeSet::new(),
                        foundation_exposure: Some(FoundationExposure::Reexport {
                            name: (*name).to_owned(),
                            source_root: normalized_crate_name(owner),
                        }),
                    });
            }
        }
        items
    }

    fn unique_public_item_containing<'a>(
        api: &'a public_api::PublicApi,
        needle: &str,
    ) -> anyhow::Result<&'a public_api::PublicItem> {
        let mut matches = api.items().filter(|item| item.to_string().contains(needle));
        let Some(public_item) = matches.next() else {
            bail!("typed fixture item containing `{needle}` missing")
        };
        if matches.next().is_some() {
            bail!("typed fixture item containing `{needle}` is ambiguous")
        }
        Ok(public_item)
    }

    #[test]
    fn typed_fixture_item_lookup_rejects_missing_and_ambiguous_matches() -> anyhow::Result<()> {
        let fixture =
            crate::workspace_root()?.join("xtask/tests/fixtures/release_api/reexport.json");
        let api = public_api::Builder::from_rustdoc_json(&fixture).build()?;

        let Err(missing) = unique_public_item_containing(&api, "DefinitelyMissing") else {
            bail!("missing typed fixture identity must fail closed")
        };
        assert!(missing.to_string().contains("missing"), "{missing:#}");

        let Err(ambiguous) = unique_public_item_containing(&api, "") else {
            bail!("ambiguous typed fixture identity must fail closed")
        };
        assert!(ambiguous.to_string().contains("ambiguous"), "{ambiguous:#}");
        Ok(())
    }

    fn checked_in_typed_foundation_items()
    -> anyhow::Result<BTreeMap<String, Vec<ApiItemProjection>>> {
        let fixture =
            crate::workspace_root()?.join("xtask/tests/fixtures/release_api/reexport.json");
        let api = public_api::Builder::from_rustdoc_json(&fixture).build()?;
        let public_item = unique_public_item_containing(&api, "Secret")?;
        let base: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        let mut items = BTreeMap::<String, Vec<ApiItemProjection>>::new();
        for (owner, name) in canonical_foundation_primitives() {
            for profile in ApiProfile::RELEASE {
                let mut rustdoc = base.clone();
                let source_root = normalized_crate_name(owner);
                rustdoc
                    .paths
                    .get_mut(&rustdoc_types::Id(2))
                    .context("typed fixture source path missing")?
                    .path = vec![source_root.clone(), (*name).to_owned()];
                rustdoc
                    .external_crates
                    .get_mut(&1)
                    .context("typed fixture external crate missing")?
                    .name = source_root.clone();
                let rustdoc_types::ItemEnum::Use(import) = &mut rustdoc
                    .index
                    .get_mut(&public_item.id())
                    .context("typed fixture re-export missing")?
                    .inner
                else {
                    bail!("typed fixture item is not a re-export")
                };
                import.source = format!("{source_root}::{name}");
                import.name = (*name).to_owned();
                let ReleaseApiItemProjection::Owned(projected) =
                    project_release_api_item(&rustdoc, profile, public_item)?
                else {
                    bail!("typed Foundation fixture cannot be blanket noise")
                };
                items
                    .entry((*owner).to_owned())
                    .or_default()
                    .push(projected);
            }
        }
        Ok(items)
    }

    #[test]
    fn checked_in_typed_foundation_projection_is_exact_once_per_profile() -> anyhow::Result<()> {
        let surface = real_release_surface_for_foundation_owner_test()?;
        let root = crate::workspace_root()?;
        let typed_items = checked_in_typed_foundation_items()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let mut findings = Vec::new();
        append_foundation_owner_findings(facts, &surface, &typed_items, &mut findings);
        assert!(findings.is_empty(), "{findings:#?}");

        let mut missing = canonical_foundation_green_items();
        missing
            .get_mut("rss-contract")
            .context("rss-contract synthetic items missing")?
            .retain(|item| {
                !(item.profile == ApiProfile::Default
                    && matches!(
                        item.foundation_exposure,
                        Some(FoundationExposure::Reexport { ref name, .. }) if name == "SafeError"
                    ))
            });
        let duplicate = missing
            .get("rss-contract")
            .context("rss-contract synthetic items missing")?
            .iter()
            .find(|item| {
                item.profile == ApiProfile::AllFeatures
                    && matches!(
                        item.foundation_exposure,
                        Some(FoundationExposure::Reexport { ref name, .. }) if name == "Timepoint"
                    )
            })
            .context("Timepoint synthetic item missing")?;
        let duplicate = ApiItemProjection {
            profile: duplicate.profile,
            rendered: duplicate.rendered.clone(),
            tokens: Vec::new(),
            source_paths: BTreeSet::new(),
            foundation_exposure: duplicate.foundation_exposure.clone(),
        };
        missing
            .get_mut("rss-contract")
            .context("rss-contract synthetic items missing")?
            .push(duplicate);
        let mut findings = Vec::new();
        append_foundation_owner_findings(facts, &surface, &missing, &mut findings);
        assert!(findings.iter().any(|finding| {
            finding.subject.contains("canonical=SafeError") && finding.detail.contains("observed=0")
        }));
        assert!(findings.iter().any(|finding| {
            finding.subject.contains("canonical=Timepoint") && finding.detail.contains("observed=2")
        }));
        Ok(())
    }

    #[test]
    fn canonical_foundation_owner_policy_rejects_mirror_alias_and_foreign_reexport()
    -> anyhow::Result<()> {
        let surface = real_release_surface_for_foundation_owner_test()?;
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let mut items = canonical_foundation_green_items();
        items.entry("rss-platform".to_owned()).or_default().extend([
            ApiItemProjection {
                profile: ApiProfile::Default,
                rendered: "profile=default pub struct rss_platform::Timepoint".to_owned(),
                tokens: Vec::new(),
                source_paths: BTreeSet::new(),
                foundation_exposure: Some(FoundationExposure::Definition {
                    name: "Timepoint".to_owned(),
                }),
            },
            ApiItemProjection {
                profile: ApiProfile::AllFeatures,
                rendered: "profile=all-features pub use rss_contract::DataClass".to_owned(),
                tokens: Vec::new(),
                source_paths: BTreeSet::new(),
                foundation_exposure: Some(FoundationExposure::Reexport {
                    name: "DataClass".to_owned(),
                    source_root: "rss_contract".to_owned(),
                }),
            },
        ]);
        items
            .get_mut("rss-contract")
            .context("rss-contract synthetic items missing")?
            .push(ApiItemProjection {
                profile: ApiProfile::Default,
                rendered: "profile=default pub type rss_contract::SafeError".to_owned(),
                tokens: Vec::new(),
                source_paths: BTreeSet::new(),
                foundation_exposure: Some(FoundationExposure::Alias {
                    name: "SafeError".to_owned(),
                    source_root: "rss_contract".to_owned(),
                }),
            });

        let mut findings = Vec::new();
        append_foundation_owner_findings(facts, &surface, &items, &mut findings);
        assert!(findings.iter().any(|finding| {
            finding.subject.contains("rss_platform::Timepoint")
                && finding.detail.contains("exposure package=`rss-platform`")
        }));
        assert!(findings.iter().any(|finding| {
            finding.subject.contains("rss_contract::DataClass")
                && finding.detail.contains("exposure package=`rss-platform`")
        }));
        assert!(findings.iter().any(|finding| {
            finding.subject.contains("rss_contract::SafeError")
                && finding.detail.contains("alias=true")
        }));
        Ok(())
    }

    #[test]
    fn canonical_foundation_owner_policy_resolves_cargo_renamed_source_package()
    -> anyhow::Result<()> {
        let facts = facts_with_renamed_foundation_dependency()?;
        assert_eq!(
            resolved_source_package(&facts, "rss-platform", "foundation_contract"),
            "rss-contract"
        );
        let surface = real_release_surface_for_foundation_owner_test()?;
        let mut items = canonical_foundation_green_items();
        items.entry("rss-platform".to_owned()).or_default().extend([
            ApiItemProjection {
                profile: ApiProfile::Default,
                rendered:
                    "profile=default pub use foundation_contract::Timepoint as FoundationTime"
                        .to_owned(),
                tokens: Vec::new(),
                source_paths: BTreeSet::new(),
                foundation_exposure: Some(FoundationExposure::Reexport {
                    name: "Timepoint".to_owned(),
                    source_root: "foundation_contract".to_owned(),
                }),
            },
            ApiItemProjection {
                profile: ApiProfile::AllFeatures,
                rendered: "profile=all-features pub use foundation_contract::*".to_owned(),
                tokens: Vec::new(),
                source_paths: BTreeSet::new(),
                foundation_exposure: Some(FoundationExposure::GlobReexport {
                    source_root: "foundation_contract".to_owned(),
                }),
            },
        ]);
        let mut findings = Vec::new();
        append_foundation_owner_findings(&facts, &surface, &items, &mut findings);
        assert!(findings.iter().any(|finding| {
            finding.subject.contains("FoundationTime")
                && finding.detail.contains("source-package=`rss-contract`")
        }));
        assert!(findings.iter().any(|finding| {
            finding.subject.contains("foundation_contract::*")
                && finding
                    .detail
                    .contains("cannot prove canonical Foundation provenance")
        }));
        Ok(())
    }

    fn canonical_reexport_fixture() -> anyhow::Result<(PathBuf, rustdoc_types::Crate)> {
        let fixture =
            crate::workspace_root()?.join("xtask/tests/fixtures/release_api/reexport.json");
        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc
            .paths
            .get_mut(&rustdoc_types::Id(2))
            .context("fixture source path missing")?
            .path = vec!["rss_contract".to_owned(), "Timepoint".to_owned()];
        rustdoc
            .external_crates
            .get_mut(&1)
            .context("fixture external crate missing")?
            .name = "rss_contract".to_owned();
        {
            let rustdoc_item = rustdoc
                .index
                .get_mut(&rustdoc_types::Id(1))
                .context("fixture re-export item missing")?;
            let rustdoc_types::ItemEnum::Use(import) = &mut rustdoc_item.inner else {
                bail!("fixture item is not a re-export")
            };
            import.source = "rss_contract::Timepoint".to_owned();
            import.name = "FoundationTime".to_owned();
        }
        Ok((fixture, rustdoc))
    }

    #[test]
    fn canonical_foundation_projection_requires_typed_reexport_identity() -> anyhow::Result<()> {
        let (fixture, rustdoc) = canonical_reexport_fixture()?;
        let api = public_api::Builder::from_rustdoc_json(&fixture).build()?;
        let public_item = unique_public_item_containing(&api, "Secret")?;
        let projected = project_release_api_item(&rustdoc, ApiProfile::Default, public_item)?;
        let ReleaseApiItemProjection::Owned(projected) = projected else {
            bail!("canonical re-export cannot be blanket noise")
        };
        assert_eq!(
            projected.foundation_exposure,
            Some(FoundationExposure::Reexport {
                name: "Timepoint".to_owned(),
                source_root: "rss_contract".to_owned(),
            })
        );

        let mut primitive = rustdoc.clone();
        let rustdoc_types::ItemEnum::Use(import) = &mut primitive
            .index
            .get_mut(&public_item.id())
            .context("fixture primitive re-export item missing")?
            .inner
        else {
            bail!("fixture item is not a re-export")
        };
        import.source = "u32".to_owned();
        import.name = "PrimitiveU32".to_owned();
        import.id = None;
        let ReleaseApiItemProjection::Owned(projected) =
            project_release_api_item(&primitive, ApiProfile::Default, public_item)?
        else {
            bail!("primitive re-export cannot be blanket noise")
        };
        assert_eq!(projected.foundation_exposure, None);

        let mut missing_id = rustdoc.clone();
        let rustdoc_types::ItemEnum::Use(import) = &mut missing_id
            .index
            .get_mut(&public_item.id())
            .context("fixture re-export item missing")?
            .inner
        else {
            bail!("fixture item is not a re-export")
        };
        import.id = None;
        let Err(error) = project_release_api_item(&missing_id, ApiProfile::Default, public_item)
        else {
            bail!("renamed canonical re-export without identity must fail closed")
        };
        assert!(
            error.to_string().contains("缺 typed source identity"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn canonical_foundation_projection_rejects_glob_owner_and_kind_conflicts() -> anyhow::Result<()>
    {
        let (fixture, rustdoc) = canonical_reexport_fixture()?;
        let api = public_api::Builder::from_rustdoc_json(&fixture).build()?;
        let public_item = unique_public_item_containing(&api, "Secret")?;
        let mut missing_glob_id = rustdoc.clone();
        let rustdoc_types::ItemEnum::Use(import) = &mut missing_glob_id
            .index
            .get_mut(&public_item.id())
            .context("fixture re-export item missing")?
            .inner
        else {
            bail!("fixture item is not a re-export")
        };
        import.source = "::foundation_contract".to_owned();
        import.is_glob = true;
        import.id = None;
        let Err(error) =
            project_release_api_item(&missing_glob_id, ApiProfile::Default, public_item)
        else {
            bail!("canonical glob without identity must fail closed")
        };
        assert!(error.to_string().contains("glob re-export"), "{error:#}");

        let mut owner_conflict = rustdoc.clone();
        owner_conflict
            .external_crates
            .get_mut(&1)
            .context("fixture external crate missing")?
            .name = "forged_owner".to_owned();
        let Err(error) =
            project_release_api_item(&owner_conflict, ApiProfile::Default, public_item)
        else {
            bail!("conflicting canonical owner identity must fail closed")
        };
        assert!(
            error.to_string().contains("owner identity 冲突"),
            "{error:#}"
        );

        let mut wrong_kind = rustdoc.clone();
        wrong_kind
            .paths
            .get_mut(&rustdoc_types::Id(2))
            .context("fixture source path missing")?
            .kind = rustdoc_types::ItemKind::Function;
        let Err(error) = project_release_api_item(&wrong_kind, ApiProfile::Default, public_item)
        else {
            bail!("canonical source with non-type kind must fail closed")
        };
        assert!(error.to_string().contains("source kind"), "{error:#}");
        Ok(())
    }

    #[test]
    fn canonical_foundation_projection_rejects_unresolved_alias() -> anyhow::Result<()> {
        let (fixture, mut unresolved_alias) = canonical_reexport_fixture()?;
        let api = public_api::Builder::from_rustdoc_json(&fixture).build()?;
        let public_item = unique_public_item_containing(&api, "Secret")?;
        let item = unresolved_alias
            .index
            .get_mut(&public_item.id())
            .context("fixture alias item missing")?;
        item.name = Some("FoundationTime".to_owned());
        item.inner = serde_json::from_value(json!({
            "type_alias": {
                "type": {
                    "resolved_path": {
                        "path": "rss_contract::Timepoint",
                        "id": 99,
                        "args": null
                    }
                },
                "generics": {"params": [], "where_predicates": []}
            }
        }))?;
        let Err(error) =
            project_release_api_item(&unresolved_alias, ApiProfile::Default, public_item)
        else {
            bail!("canonical alias with unresolved identity must fail closed")
        };
        assert!(error.to_string().contains("缺 path identity"), "{error:#}");
        Ok(())
    }

    #[test]
    fn canonical_foundation_projection_rejects_union_mirror() -> anyhow::Result<()> {
        let fixture =
            crate::workspace_root()?.join("xtask/tests/fixtures/release_api/reexport.json");
        let api = public_api::Builder::from_rustdoc_json(&fixture).build()?;
        let public_item = unique_public_item_containing(&api, "Secret")?;
        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        let item = rustdoc
            .index
            .get_mut(&public_item.id())
            .context("fixture item missing")?;
        item.name = Some("Timepoint".to_owned());
        item.inner = serde_json::from_value(json!({
            "union": {
                "generics": {"params": [], "where_predicates": []},
                "fields": [],
                "impls": [],
                "has_stripped_fields": false
            }
        }))?;
        let ReleaseApiItemProjection::Owned(projected) =
            project_release_api_item(&rustdoc, ApiProfile::Default, public_item)?
        else {
            bail!("union mirror cannot be blanket noise")
        };
        assert_eq!(
            projected.foundation_exposure,
            Some(FoundationExposure::Definition {
                name: "Timepoint".to_owned()
            })
        );
        Ok(())
    }

    #[test]
    fn platform_signature_can_reference_foundation_type_without_exposing_owner() -> Result<()> {
        let surface = real_release_surface_for_foundation_owner_test()?;
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let fixture = root.join("xtask/tests/fixtures/release_api/owner-aware-blanket.json");
        let api = public_api::Builder::from_rustdoc_json(&fixture).build()?;
        let public_item = api
            .items()
            .find(|item| item.to_string().contains("leak"))
            .context("typed function fixture missing")?;
        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc
            .paths
            .get_mut(&rustdoc_types::Id(12))
            .context("typed function source path missing")?
            .path = vec!["rss_contract".to_owned(), "Timepoint".to_owned()];
        rustdoc
            .external_crates
            .get_mut(&1)
            .context("typed function external crate missing")?
            .name = "rss_contract".to_owned();
        let ReleaseApiItemProjection::Owned(projected) =
            project_release_api_item(&rustdoc, ApiProfile::Default, public_item)?
        else {
            bail!("Platform signature cannot be blanket noise")
        };
        assert!(projected.source_paths.contains("rss_contract::Timepoint"));
        assert_eq!(projected.foundation_exposure, None);

        let mut items = canonical_foundation_green_items();
        items
            .entry("rss-platform".to_owned())
            .or_default()
            .push(projected);
        let mut findings = Vec::new();
        append_foundation_owner_findings(facts, &surface, &items, &mut findings);
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn nonempty_release_surface_green_and_forbidden_workspace_type_red() -> anyhow::Result<()> {
        use public_api::tokens::Token::{Identifier, Symbol, Type};

        let facts = facts_with_nonempty_release_surface()?;
        let (surface, findings) = crate::release_surface::validate(&facts, &[]);
        assert!(
            findings.is_empty(),
            "synthetic Release Surface must be valid: {findings:?}"
        );
        let surface = surface.context("synthetic Release Surface missing")?;

        let green = BTreeMap::from([(
            "alpha-release".to_owned(),
            vec![ApiItemProjection {
                profile: ApiProfile::Default,
                rendered: "pub fn alpha_release::clean() -> core::Result".to_owned(),
                tokens: vec![
                    Identifier("alpha_release".into()),
                    Symbol("::".into()),
                    Type("Public".into()),
                    Identifier("core".into()),
                    Symbol("::".into()),
                    Type("Result".into()),
                ],
                source_paths: BTreeSet::new(),
                foundation_exposure: None,
            }],
        )]);
        assert!(release_api_findings_from_items(&facts, &surface, &green)?.is_empty());

        let red = BTreeMap::from([(
            "alpha-release".to_owned(),
            vec![ApiItemProjection {
                profile: ApiProfile::Default,
                rendered: "pub fn alpha_release::leak() -> vocab::Secret".to_owned(),
                tokens: vec![
                    Identifier("vocab".into()),
                    Symbol("::".into()),
                    Type("Secret".into()),
                ],
                source_paths: BTreeSet::new(),
                foundation_exposure: None,
            }],
        )]);
        let findings = release_api_findings_from_items(&facts, &surface, &red)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::ForbiddenType
                && finding
                    .subject
                    .contains("package=alpha-release/module=alpha_release::leak")
                && finding.detail.contains("vocab::Secret")
        }));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == ReleaseApiRule::PublicDependency)
        );

        let reexport_red = BTreeMap::from([(
            "alpha-release".to_owned(),
            vec![ApiItemProjection {
                profile: ApiProfile::Default,
                rendered: "pub use alpha_release::Secret".to_owned(),
                tokens: vec![
                    Identifier("alpha_release".into()),
                    Symbol("::".into()),
                    Type("Secret".into()),
                ],
                source_paths: BTreeSet::from(["vocab::Secret".to_owned()]),
                foundation_exposure: None,
            }],
        )]);
        let findings = release_api_findings_from_items(&facts, &surface, &reexport_red)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::ForbiddenType
                && finding.detail.contains("vocab::Secret")
        }));
        Ok(())
    }

    #[test]
    fn checked_in_rustdoc_fixture_crosses_builder_and_source_identity_projection() -> Result<()> {
        let facts = facts_with_nonempty_release_surface()?;
        let (surface, validation) = crate::release_surface::validate(&facts, &[]);
        assert!(validation.is_empty(), "{validation:?}");
        let surface = surface.context("synthetic Release Surface missing")?;
        let fixture =
            crate::workspace_root()?.join("xtask/tests/fixtures/release_api/reexport.json");
        let captures = BTreeMap::from([(
            "alpha-release".to_owned(),
            ApiCapture {
                baseline: String::new(),
                rustdoc_json: vec![
                    (ApiProfile::Default, fixture.clone()),
                    (ApiProfile::AllFeatures, fixture),
                ],
            },
        )]);

        let findings = release_api_findings(&facts, &surface, &captures)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::ForbiddenType
                && finding.detail.contains("vocab::Secret")
        }));
        for profile in ApiProfile::RELEASE {
            assert!(findings.iter().any(|finding| {
                finding
                    .subject
                    .contains(&format!("profile={}", profile.label()))
            }));
        }
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::PublicDependency
                && finding.subject.contains("package=alpha-release")
        }));
        Ok(())
    }

    #[test]
    fn checked_in_rustdoc_fixture_filters_only_external_blanket_impl_noise() -> Result<()> {
        let facts = facts_with_nonempty_release_surface()?;
        let (surface, validation) = crate::release_surface::validate(&facts, &[]);
        assert!(validation.is_empty(), "{validation:?}");
        let surface = surface.context("synthetic Release Surface missing")?;
        let fixture = crate::workspace_root()?
            .join("xtask/tests/fixtures/release_api/owner-aware-blanket.json");
        let raw_api = public_api::Builder::from_rustdoc_json(&fixture).build()?;
        let raw_items = raw_api.items().map(ToString::to_string).collect::<Vec<_>>();
        assert!(
            raw_items
                .iter()
                .any(|item| item.contains("ExternalBlanket")),
            "fixture must exercise an external blanket impl: {raw_items:#?}"
        );
        assert!(
            raw_items.iter().any(|item| item.contains("OwnedTrait")),
            "fixture must exercise a crate-owned blanket impl: {raw_items:#?}"
        );

        let captures = BTreeMap::from([(
            "alpha-release".to_owned(),
            ApiCapture {
                baseline: String::new(),
                rustdoc_json: vec![
                    (ApiProfile::Default, fixture.clone()),
                    (ApiProfile::AllFeatures, fixture),
                ],
            },
        )]);
        let findings = release_api_findings(&facts, &surface, &captures)?;

        assert!(
            findings.iter().all(|finding| {
                !finding.detail.contains("third_party::ExternalBlanket")
                    && !finding.subject.contains("ExternalBlanket")
                    && !finding.subject.contains("provided")
            }),
            "external blanket impl header and child must be noise: {findings:#?}"
        );
        for profile in ApiProfile::RELEASE {
            let profile = format!("profile={}", profile.label());
            assert!(findings.iter().any(|finding| {
                finding.rule == ReleaseApiRule::ForbiddenType
                    && finding.subject.contains(&profile)
                    && finding.subject.contains("OwnedTrait")
                    && finding.detail.contains("third_party::External")
            }));
            assert!(findings.iter().any(|finding| {
                finding.rule == ReleaseApiRule::ForbiddenType
                    && finding.subject.contains(&profile)
                    && finding.subject.contains("Regular")
                    && finding.detail.contains("third_party::Regular")
            }));
            assert!(findings.iter().any(|finding| {
                finding.rule == ReleaseApiRule::ForbiddenType
                    && finding.subject.contains(&profile)
                    && finding.subject.contains("alpha_release::leak")
                    && finding.detail.contains("third_party::External")
            }));
            assert!(findings.iter().any(|finding| {
                finding.rule == ReleaseApiRule::ForbiddenType
                    && finding.subject.contains(&profile)
                    && finding.detail.contains("vocab::Secret")
            }));
        }
        Ok(())
    }

    #[test]
    fn release_projection_rejects_malformed_blanket_identity() -> Result<()> {
        let fixture = crate::workspace_root()?
            .join("xtask/tests/fixtures/release_api/owner-aware-blanket.json");
        let api = public_api::Builder::from_rustdoc_json(&fixture)
            .omit_blanket_impls(false)
            .build()?;
        let external_blanket = api
            .items()
            .find(|item| item.to_string().contains("ExternalBlanket"))
            .context("fixture missing external blanket impl")?;
        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc.paths.remove(&rustdoc_types::Id(10));

        let Err(error) = project_release_api_item(&rustdoc, ApiProfile::Default, external_blanket)
        else {
            bail!("missing blanket trait owner must fail closed")
        };
        assert!(format!("{error:#}").contains("缺 path owner identity"));

        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc.external_crates.remove(&1);
        let Err(error) = project_release_api_item(&rustdoc, ApiProfile::Default, external_blanket)
        else {
            bail!("unknown external blanket owner must fail closed")
        };
        assert!(format!("{error:#}").contains("external owner 1 未声明"));

        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc
            .paths
            .get_mut(&rustdoc_types::Id(10))
            .context("fixture missing external trait path")?
            .kind = rustdoc_types::ItemKind::Struct;
        let Err(error) = project_release_api_item(&rustdoc, ApiProfile::Default, external_blanket)
        else {
            bail!("non-trait blanket path must fail closed")
        };
        assert!(format!("{error:#}").contains("path kind 不是 trait"));

        let external_child = api
            .items()
            .find(|item| item.to_string().contains("::provided"))
            .context("fixture missing external blanket child")?;
        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc.index.remove(&rustdoc_types::Id(2));
        let Err(error) = project_release_api_item(&rustdoc, ApiProfile::Default, external_child)
        else {
            bail!("missing blanket parent must fail closed")
        };
        assert!(format!("{error:#}").contains("parent 2 缺 index entry"));

        let owned_blanket = api
            .items()
            .find(|item| {
                item.to_string()
                    .starts_with("impl<T> alpha_release::OwnedTrait")
            })
            .context("fixture missing crate-owned blanket impl")?;
        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc.index.remove(&rustdoc_types::Id(4));
        let Err(error) = project_release_api_item(&rustdoc, ApiProfile::Default, owned_blanket)
        else {
            bail!("missing local blanket trait must fail closed")
        };
        assert!(format!("{error:#}").contains("local blanket impl trait 4 缺 index entry"));

        let mut rustdoc: rustdoc_types::Crate = serde_json::from_slice(&fs::read(&fixture)?)?;
        rustdoc
            .paths
            .get_mut(&rustdoc_types::Id(4))
            .context("fixture missing owned trait path")?
            .crate_id = 1;
        let Err(error) = project_release_api_item(&rustdoc, ApiProfile::Default, owned_blanket)
        else {
            bail!("conflicting blanket trait owners must fail closed")
        };
        assert!(format!("{error:#}").contains("owner identity 不一致"));
        Ok(())
    }

    #[test]
    fn typed_rustdoc_source_ids_cover_reexports_and_nested_resolved_paths() {
        let value = json!({
            "inner": {
                "use": {"source":"vocab::Secret","name":"Secret","id": 17,"is_glob":false},
                "function": {"output":{"resolved_path":{"path":"Alias","id":23,"args":null}}}
            }
        });
        let mut ids = BTreeSet::new();
        collect_source_ids(&value, &mut ids);
        assert_eq!(ids, BTreeSet::from([17, 23]));
    }

    #[test]
    fn selected_direct_normal_dependency_is_allowed_through_cargo_rename() -> anyhow::Result<()> {
        use public_api::tokens::Token::{Identifier, Symbol, Type};

        let facts = facts_with_selected_renamed_dependency()?;
        let (surface, validation) = crate::release_surface::validate(&facts, &[]);
        assert!(validation.is_empty(), "{validation:?}");
        let surface = surface.context("synthetic selected dependency surface missing")?;
        let items = BTreeMap::from([
            (
                "alpha-release".to_owned(),
                vec![ApiItemProjection {
                    profile: ApiProfile::Default,
                    rendered: "pub fn facade_api::api() -> beta_api::Public".to_owned(),
                    tokens: vec![
                        Identifier("facade_api".into()),
                        Symbol("::".into()),
                        Type("OwnPublic".into()),
                        Identifier("beta_api".into()),
                        Symbol("::".into()),
                        Type("Public".into()),
                    ],
                    source_paths: BTreeSet::new(),
                    foundation_exposure: None,
                }],
            ),
            (
                "beta-release".to_owned(),
                vec![ApiItemProjection {
                    profile: ApiProfile::Default,
                    rendered: "pub struct beta_release::Public".to_owned(),
                    tokens: vec![Type("Public".into())],
                    source_paths: BTreeSet::new(),
                    foundation_exposure: None,
                }],
            ),
        ]);
        assert!(release_api_findings_from_items(&facts, &surface, &items)?.is_empty());
        Ok(())
    }
}
