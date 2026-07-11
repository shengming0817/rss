//! `cargo xtask public-api` —— 库公开 API 面 baseline（封装外部 `cargo-public-api`）。
//!
//! 用途：基础/引擎层签名冻结 + 安全敏感 curated extras 的 exported 符号面冻结为可 commit 的 baseline，
//! 后续 PR diff（crate 公开 API = 轴 A SemVer，见 `.claude/rules/rss/api-versioning.md`）。
//!
//! **PR-0 仅落工具入口**；baseline 快照随 PR-1/PR-2 产出并 commit 到 `public-api/<crate>.txt`
//! （PR-1 `--layer basis`、PR-2 `--layer engine`、安全敏感例外 `--layer curated`；无 `--layer` =
//! basis + engine + curated extras 全集，收口 GATE 用）。
//!
//! **漂移门闭环**：`--check` 对目标层任一 baseline 缺失 / 不一致 **默认 fail-fast**；仅 PR-0
//! 自检可显式 `--allow-missing` 宽限缺失（drift 仍 fail）——对齐 cargo-public-api snapshot-gate
//! 范式，杜绝「无 baseline 也绿」的误绿。
//!
//! 依赖：外部 `cargo-public-api`（`cargo install cargo-public-api@0.52.0`）+ 钉版 nightly rustdoc-json
//! （`rustup toolchain install <PINNED_NIGHTLY>`，见 [`PINNED_NIGHTLY`]）。未满足时本命令给指引并**非零退出**（非静默 noop）。
//!
//! **不在 `cargo xtask verify` 聚合门内**：verify 聚合每次代码改动的强制门（fmt/build/clippy/nextest/deny/
//! dylint + meta）；public-api 是**库封装面 baseline 冻结门**（轴 A SemVer，需 nightly rustdoc-json 重新生成
//! baseline），语义与触发节奏不同，故为独立可选门（单独 `cargo xtask public-api --check`）。
//!
//! INVARIANT: PUBLICAPI-TOOL-GATE-01 { level = "Medium", exec = "ci-only", source = "public-api" }—— 工具缺失 fail-fast，不静默成功。
//! INVARIANT: PUBLICAPI-DRIFT-GATE-01 { level = "Medium", exec = "ci-only", source = "public-api" }—— `--check` 缺失/漂移默认 fail-fast；缺失豁免仅经显式 `--allow-missing`。
//! INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "ci-only", source = "public-api" }—— rustdoc-json 用钉版 nightly（[`PINNED_NIGHTLY`]，非 rolling）；该 pin 四处
//!   一致：`PINNED_NIGHTLY` ⇔ `lints/rust-toolchain.toml` channel ⇔ reusable CI `RSS_NIGHTLY_PINNED`（三方功能值，
//!   `pinned_nightly_single_source_of_truth` 守）+ `verify.rs` public-api install_hint（`verify::tests::
//!   public_api_install_hint_pins_nightly` 守，绑真实字段值非源码全文）。漂移即 fail。

use crate::layers::{BASIS_CRATES, ENGINE_CRATES};
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::process::Command;

// 分层成员单源 = `layers.rs`（basis = PR-1 验收集、engine = PR-2 验收集）；此处复用，不另列副本。
// curated extras 不是架构 layer，只是安全敏感公开 API 面的定点 golden 例外。
// `diport`（DI-infra 层，非 basis/engine）：持全部安全敏感 DI port（Signer/SecretResolver/Pdp/Revocation/
// KeyProvider…），公开 trait/类型面是轴 A SemVer 边界，列入 curated extras 定点冻结（#1470）。
// `generated` 暴露 contract-derived metadata，作为 PR review 审查材料定点冻结（#1472/#1688）。
const CURATED_EXTRA_CRATES: &[&str] = &["authn", "diport", "generated"];

/// public-api baseline（rustdoc-json）用的**钉版 nightly**。cargo-public-api 在 stable 上探测到 stable
/// 编译器即强制回退 rolling `nightly`（其 rustdoc-json 格式随日期漂移 ⇒ baseline 误报）；本 const 经
/// [`public_api_cmd`] 设 `RUSTUP_TOOLCHAIN`（等价 `cargo +<此值> public-api`）把 nightly 钉死，使快照可复现（#1145）。
///
/// **单一事实源（NIGHTLY-PIN-01）**：本 const ⇔ `lints/rust-toolchain.toml` 的 `[toolchain].channel`
/// （dylint 实际 nightly）⇔ `.github/workflows/rss-rust-lane.yml` 的 `RSS_NIGHTLY_PINNED`（CI 安装的 nightly）三方功能值由
/// `pinned_nightly_single_source_of_truth` 守；第四处 `verify.rs` public-api install_hint 由
/// `verify::tests::public_api_install_hint_pins_nightly` 守（绑真实 install_hint 字段值、非源码全文，避免注释
/// 含 pin 的误绿）——漂移即 fail。**与 dylint nightly 成对、CI 只装一份**：dylint 因 `clippy_utils` rev 升 nightly 时——
/// 该 rev 与本 nightly 配对（见 `lints/rss_*/Cargo.toml`，由 dylint 编译失败 **Hard** 强制，非本治理测试
/// 覆盖）——**须同步重跑 `cargo xtask public-api` 重生成 `public-api/*.txt`**；忘记不会静默，会被
/// PUBLICAPI-DRIFT-GATE-01（`--check`，共用同一 pin）在 CI 直接 drift-fail 抓住。
pub(crate) const PINNED_NIGHTLY: &str = "nightly-2026-04-16";

/// 封装面 baseline 的目标层。无 `--layer` 时取 basis + engine + curated extras 全集（收口 GATE 用）。
/// 服务/域/adapters 内部接缝默认多变，不整体入 baseline；安全敏感 crate 需定点列入 curated extras。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Layer {
    Basis,
    Engine,
    Curated,
}

/// 解析 layer → 目标 crate 集。`None` = basis + engine + curated extras（不另列第三份 ALL，避免漂移）。
/// 排除 proc-macro 工具 crate（[`crate::layers::is_proc_macro`]）——其契约由 codegen golden 守，
/// 非 SemVer 库 API 面，不入 public-api baseline。
pub(crate) fn target_crates(layer: Option<Layer>) -> Vec<&'static str> {
    let select: Vec<&'static str> = match layer {
        Some(Layer::Basis) => BASIS_CRATES.to_vec(),
        Some(Layer::Engine) => ENGINE_CRATES.to_vec(),
        Some(Layer::Curated) => CURATED_EXTRA_CRATES.to_vec(),
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

/// 生成（`check=false`）或校验（`check=true`）目标层封装面 baseline。
/// `allow_missing`：仅 PR-0 自检显式宽限缺失 baseline（默认缺失即 fail-fast，漂移门闭环）。
pub(crate) fn run(check: bool, allow_missing: bool, layer: Option<Layer>) -> Result<()> {
    ensure_tool_available()?;
    let crates = target_crates(layer);
    let dir = baseline_dir()?;
    if !check {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("创建 baseline 目录失败: {}", dir.display()))?;
    }

    let mut drift = Vec::new();
    let mut missing = Vec::new();
    for krate in &crates {
        let actual = capture_public_api(krate)?;
        let path = dir.join(format!("{krate}.txt"));
        if check {
            match std::fs::read_to_string(&path) {
                Ok(expected) if expected == actual => {}
                Ok(_) => drift.push((*krate).to_owned()),
                // 仅「baseline 尚未生成」(NotFound) 降级为警告；其余 I/O 错误（权限/损坏）fail-fast。
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push((*krate).to_owned())
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("读 baseline 失败: {}", path.display()));
                }
            }
        } else {
            std::fs::write(&path, &actual)
                .with_context(|| format!("写 baseline 失败: {}", path.display()))?;
            eprintln!("public-api: 写入 baseline {}", path.display());
        }
    }
    report(check, allow_missing, &drift, &missing)
}

fn baseline_dir() -> Result<PathBuf> {
    Ok(workspace_root()?.join("public-api"))
}

/// 检测外部 cargo-public-api；缺失即 fail-fast 给安装指引（INVARIANT PUBLICAPI-TOOL-GATE-01）。
fn ensure_tool_available() -> Result<()> {
    if crate::cmd::tool_available("public-api") {
        return Ok(());
    }
    bail!(
        "未找到 `cargo public-api`。安装：\n  \
         cargo install cargo-public-api@0.52.0\n  \
         rustup toolchain install {PINNED_NIGHTLY}   # rustdoc-json 需钉版 nightly（NIGHTLY-PIN-01）\n\
         仅基础/引擎层与 curated extras 封装面冻结需要本工具（非全 workspace 强制门）。"
    )
}

/// 构造 `cargo public-api -p <crate>` 子进程，经 [`crate::cmd::clean_cmd`] 漏斗把 `RUSTUP_TOOLCHAIN`
/// 显式重设为 `toolchain`（剥离后成该变量唯一来源，CMD-ENV-CLEAN-01）——等价 `cargo +<toolchain> public-api`，
/// 让 cargo-public-api 在钉版 nightly 下生成可复现 rustdoc-json（`is_probably_stable()`==false ⇒ 透传当前
/// toolchain，不再强制 rolling `nightly`）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "ci-only", source = "public-api" }.
fn public_api_cmd(krate: &str, toolchain: &str, target_dir: &std::path::Path) -> Command {
    let mut cmd = crate::cmd::clean_cmd(
        "cargo",
        &["public-api", "-p", krate, "--omit", "blanket-impls"],
        &[("RUSTUP_TOOLCHAIN", toolchain)],
        None,
    );
    // cargo-public-api 的 rustdoc-json 缓存不能与前序 all-features/coverage 编译共享；否则同一
    // CI 首次 check 可能读到不同 feature 面的旧 JSON，执行刷新后立即重跑却转绿。
    cmd.env("CARGO_TARGET_DIR", target_dir);
    cmd
}

fn public_api_target_dir() -> Result<PathBuf> {
    Ok(workspace_root()?.join(".cache/public-api-target"))
}

/// 运行 `cargo public-api -p <crate>`（钉版 nightly）捕获其封装面快照文本。
fn capture_public_api(krate: &str) -> Result<String> {
    let target_dir = public_api_target_dir()?;
    let out = public_api_cmd(krate, PINNED_NIGHTLY, &target_dir)
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
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 汇报结果。生成模式只报数。校验模式漂移门闭环：
/// - drift 非空 → fail-fast（最高优先，`--allow-missing` 不豁免漂移）。
/// - missing 非空 → 默认 fail-fast；仅 `allow_missing`（PR-0 自检显式宽限）降级为警告。
fn report(check: bool, allow_missing: bool, drift: &[String], missing: &[String]) -> Result<()> {
    if !check {
        eprintln!("public-api: baseline 生成完成");
        return Ok(());
    }
    if !drift.is_empty() {
        bail!(
            "public-api drift：{} crate 封装面与 committed baseline 不一致：{}（确认是否破坏式 API 变更，按 api-versioning.md 轴 A 处理）",
            drift.len(),
            drift.join(", ")
        );
    }
    if !missing.is_empty() {
        if !allow_missing {
            bail!(
                "public-api --check：{} crate 缺 committed baseline：{}（先 `cargo xtask public-api [--layer …]` 生成并提交；PR-0 自检可显式 `--allow-missing`）",
                missing.len(),
                missing.join(", ")
            );
        }
        // reason: --allow-missing 是 PR-0 自检的显式宽限（baseline 尚未产出），非默认路径——drift 仍 fail。
        eprintln!(
            "public-api --check（--allow-missing）：{} crate 暂无 baseline，宽限通过：{}",
            missing.len(),
            missing.join(", ")
        );
    }
    eprintln!("public-api --check: 无 drift");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTP_ROUTE_EVIDENCE_PRIVATE_FIELDS: &[&str] = &[
        "contract",
        "path",
        "method",
        "auth",
        "resource",
        "self_scoped",
        "consistency_level",
        "effect_profile",
    ];

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
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

    #[test]
    fn report_generate_always_ok() {
        assert!(report(false, false, &[], &[]).is_ok());
    }

    #[test]
    fn report_check_clean_ok() {
        assert!(report(true, false, &[], &[]).is_ok());
    }

    /// 复现测试（F1）：check 模式 missing-only **默认 fail-fast**（漂移门闭环，非误绿）。
    #[test]
    fn report_check_missing_only_fails_by_default() {
        assert!(report(true, false, &[], &v(&["vocab", "ids"])).is_err());
    }

    /// 仅 `--allow-missing` 显式宽限 missing（PR-0 自检）。
    #[test]
    fn report_check_missing_only_ok_with_allow_missing() {
        assert!(report(true, true, &[], &v(&["vocab", "ids"])).is_ok());
    }

    #[test]
    fn report_check_drift_fails() {
        assert!(report(true, false, &v(&["vocab"]), &[]).is_err());
    }

    /// drift 优先 fail-fast，即便同时有 missing。
    #[test]
    fn report_check_drift_fails_even_with_missing() {
        assert!(report(true, false, &v(&["vocab"]), &v(&["ids"])).is_err());
    }

    /// `--allow-missing` 宽限缺失，但**绝不**豁免 drift。
    #[test]
    fn report_check_drift_fails_even_with_allow_missing() {
        assert!(report(true, true, &v(&["vocab"]), &v(&["ids"])).is_err());
    }

    #[test]
    fn target_crates_counts_and_curated_exact_set() {
        // basis = assembly-schema/diagctx/vocab/ids/secure/support/runctx（proc-macro securederive 经 is_proc_macro 排除）。
        assert_eq!(target_crates(Some(Layer::Basis)).len(), 7);
        // engine = consistency/primitives/tracewire（#1224 新增 traceparent capture/restore 单源，轴 A SemVer 面）。
        assert_eq!(target_crates(Some(Layer::Engine)).len(), 3);
        // None = basis(7) + engine(3) + curated extras(authn/diport/generated=3) 全集。
        assert_eq!(target_crates(None).len(), 13);
        assert!(target_crates(Some(Layer::Basis)).contains(&"assembly-schema"));
        assert!(target_crates(Some(Layer::Basis)).contains(&"vocab"));
        assert!(target_crates(Some(Layer::Engine)).contains(&"primitives"));
        assert!(target_crates(Some(Layer::Engine)).contains(&"tracewire"));
        assert_eq!(
            target_crates(Some(Layer::Curated)),
            vec!["authn", "diport", "generated"]
        );
    }

    #[test]
    fn target_crates_membership_keeps_curated_out_of_layers() {
        assert!(target_crates(None).contains(&"authn"));
        assert!(target_crates(None).contains(&"diport"));
        assert!(target_crates(None).contains(&"generated"));
        assert!(target_crates(Some(Layer::Basis)).contains(&"vocab"));
        assert!(target_crates(Some(Layer::Engine)).contains(&"primitives"));
        assert!(target_crates(Some(Layer::Engine)).contains(&"tracewire"));
        assert!(!target_crates(Some(Layer::Basis)).contains(&"authn"));
        assert!(!target_crates(Some(Layer::Engine)).contains(&"authn"));
        // diport 是 DI-infra 层，既非 basis 也非 engine——只经 curated extras 入 baseline。
        assert!(!target_crates(Some(Layer::Basis)).contains(&"diport"));
        assert!(!target_crates(Some(Layer::Engine)).contains(&"diport"));
        assert!(!target_crates(Some(Layer::Basis)).contains(&"generated"));
        assert!(!target_crates(Some(Layer::Engine)).contains(&"generated"));
        // proc-macro 工具 crate 不入 public-api baseline（契约由 codegen golden 守）。
        assert!(!target_crates(Some(Layer::Basis)).contains(&"securederive"));
    }

    #[test]
    fn target_crates_have_no_duplicates() {
        let crates = target_crates(None);
        let set: std::collections::BTreeSet<_> = crates.iter().copied().collect();
        assert_eq!(set.len(), crates.len(), "public-api 目标 crate 不得重复");
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
            "pub async fn authn::verify_jwt",
            "pub async fn authn::verify_service_token",
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
        ] {
            assert!(
                !baseline.contains(forbidden),
                "authn public-api golden 不得暴露私有 mint funnel: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn diport_public_api_golden_reexports_send_variant_not_base_trait() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("diport.txt"))?;
        // crate 根 re-export = Send 变体 + Dyn wrapper + KeyProvider 公开类型（adapters/组合根消费面）。
        for required in [
            "pub trait diport::KeyProvider: core::marker::Send",
            "pub struct diport::DynKeyProvider",
            "pub struct diport::KeyRef",
            "pub struct diport::EncryptOutput",
            // 方法列在定义路径（cargo-public-api 惯例），非 re-export 路径；parse ⇄ to_token 对称 token 存储面单源。
            "pub fn diport::key_provider::KeyRef::to_token",
        ] {
            assert!(
                baseline.contains(required),
                "diport public-api golden 缺少必要公开项: {required}"
            );
        }
        // 非 Send 基 trait `*Local` **不**在 crate 根 re-export（仅 `diport::key_provider::KeyProviderLocal`
        // 经 pub mod 可达），避免 glob import 方法解析歧义（ADR-003 落地结论）。
        assert!(
            !baseline.contains("pub trait diport::KeyProviderLocal"),
            "diport public-api golden 不得在 crate 根 re-export 基 trait KeyProviderLocal"
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
                "diport public-api golden 不得暴露 key 标识的非常数时间 `==`（ADR-011 §D3）: {forbidden}"
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
            "pub struct generated::command::CommandSpec",
            "pub trait generated::command::CommandJournal",
            "pub const fn generated::command::CommandSpec::journal(self) -> generated::command::CommandJournalPolicy",
            "pub struct generated::event::EventSpec",
            "pub enum generated::event::PartitionKeyStrategy",
            "pub enum generated::event::SubscriberReadiness",
            "pub const generated::event::EVENTS: &[generated::event::EventSpec]",
            "pub const fn generated::event::EventSpec::subscriptions(self) -> &'static [generated::event::SubscriptionSpec]",
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
            "pub enum vocab::http::HttpRouteAuth",
            "pub struct vocab::http::HttpRouteBinding<M, C>",
            "pub const fn vocab::http::HttpRouteBinding<M, C>::from_static",
            "pub const fn vocab::http::HttpRouteBinding<M, C>::evidence",
            "pub struct vocab::http::HttpRouteEvidence",
            "pub const fn vocab::http::HttpRouteEvidence::from_static",
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
pub vocab::http::HttpRouteEvidence::contract: vocab::contract::binding::ContractBinding
pub vocab::http::HttpRouteEvidence::path: &'static str
pub vocab::http::HttpRouteEvidence::method: &'static str
pub vocab::http::HttpRouteEvidence::auth: vocab::http::HttpRouteAuth
pub vocab::http::HttpRouteEvidence::resource: core::option::Option<&'static str>
pub vocab::http::HttpRouteEvidence::self_scoped: bool
pub vocab::http::HttpRouteEvidence::consistency_level: vocab::http::HttpConsistencyLevel
pub vocab::http::HttpRouteEvidence::effect_profile: vocab::http::HttpEffectProfile
"#;
        assert_eq!(
            exposed_http_route_evidence_fields(synthetic),
            vec![
                "contract",
                "path",
                "method",
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
        let cmd = public_api_cmd("vocab", PINNED_NIGHTLY, &public_api_target_dir()?);
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
        assert_eq!(cmd.get_current_dir(), None);
        Ok(())
    }

    /// 传 `PINNED_NIGHTLY` 时 `RUSTUP_TOOLCHAIN` 被经 clean_cmd 显式重设为钉版 nightly
    /// （等价 `cargo +nightly-2026-04-16 public-api`，使 rustdoc-json 可复现）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "ci-only", source = "public-api" }.
    #[test]
    fn public_api_cmd_injects_pinned_toolchain() -> anyhow::Result<()> {
        let cmd = public_api_cmd("ids", PINNED_NIGHTLY, &public_api_target_dir()?);
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
    /// `public-api --check` 漂移、立即重跑却转绿。
    #[test]
    fn public_api_cmd_isolates_rustdoc_json_target() -> anyhow::Result<()> {
        let expected = public_api_target_dir()?;
        let cmd = public_api_cmd("consistency", PINNED_NIGHTLY, &expected);
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
        let cmd = public_api_cmd("vocab", PINNED_NIGHTLY, &public_api_target_dir()?);
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        for stripped in crate::cmd::STRIPPED_ENV
            .iter()
            .filter(|v| **v != "RUSTUP_TOOLCHAIN")
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
        Ok(())
    }

    /// anti-vacuity：toolchain 入参透传（非把 `PINNED_NIGHTLY` 硬编码忽略参数）。
    #[test]
    fn public_api_cmd_toolchain_arg_flows_through() -> anyhow::Result<()> {
        let fake = "nightly-1999-01-01";
        let cmd = public_api_cmd("vocab", fake, &public_api_target_dir()?);
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        assert!(
            envs.iter()
                .any(|(k, v)| *k == std::ffi::OsStr::new("RUSTUP_TOOLCHAIN")
                    && *v == Some(std::ffi::OsStr::new(fake))),
            "toolchain 入参应透传进 RUSTUP_TOOLCHAIN"
        );
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
    /// 守——绑真实 install_hint 字段值（非源码全文，避免注释含 pin 的误绿）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "ci-only", source = "public-api" }.
    #[test]
    fn pinned_nightly_single_source_of_truth() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let toolchain_toml =
            std::fs::read_to_string(root.join("lints").join("rust-toolchain.toml"))?;
        let github_ci_yaml = std::fs::read_to_string(
            root.join(".github")
                .join("workflows")
                .join("rss-rust-lane.yml"),
        )?;
        let channel = parse_toolchain_channel(&toolchain_toml)
            .ok_or_else(|| anyhow::anyhow!("lints/rust-toolchain.toml 应有 [toolchain].channel"))?;
        let github_ci = github_ci_nightly_pinned(&github_ci_yaml).ok_or_else(|| {
            anyhow::anyhow!(".github/workflows/rss-rust-lane.yml 应有 RSS_NIGHTLY_PINNED 变量")
        })?;
        assert!(
            nightly_pins_agree(PINNED_NIGHTLY, &channel, &github_ci),
            "pinned nightly 三方漂移：PINNED_NIGHTLY={PINNED_NIGHTLY}, lints channel={channel}, github_ci={github_ci}"
        );
        Ok(())
    }
}
