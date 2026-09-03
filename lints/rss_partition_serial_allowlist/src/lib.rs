#![feature(rustc_private)]
//! `rss_partition_serial_allowlist` — RSS 治理 dylint lint：`consistency::PartitionSerialDelivery`
//! 仅 blessed adapter / 组合根可 impl（impl-site allowlist）。
//!
//! INVARIANT: PARTITION-SERIAL-IMPL-ALLOWLIST-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! `PartitionSerialDelivery` 是 witness 铸造侧的**契约 trait**：impl 者须保证 read/poll 路径**全局
//! 单调升序**逐行交付（如 `ORDER BY id ASC`）；per-partition 串行是上游 outbox relay 的
//! head-of-partition gating（OUTBOX-PARTITION-ORDER-01）属性，非本 trait reader impl 的机制。
//! 此语义属性无法由类型系统静态验证（Hard 不可行），故「谁可铸造 witness」由本 AST lint 承载（Medium，最强可用载体）：
//! 仅 adapter / 组合根 package 可 impl，其余 crate（特别是域 / 服务 / 引擎 crate）禁止。
//!
//! 关系到 PROJECTION-SERIAL-WITNESS-01（Hard）的 Medium 半段：
//! - **Hard 半段**：`SerialInOrderGuarantor` sealed + `SerialInOrder::from_source` bound ⇒ 无
//!   `PartitionSerialDelivery` impl 的 source 拿不到 witness ⇒ 编译期挂不上 projection。
//! - **Medium 半段**（本 lint）：`PartitionSerialDelivery` 仅 allowlist crate 可 impl ⇒ 非串行
//!   非 allowlist 类型无法铸造 witness（AST 级 impl-site 管控）。
//!
//! 上下游强度（`cargo xtask archrules verify`）：
//! - 上游（witness 使用面）：`ProjectionHarness::new` 必填 `impl SerialInOrderGuarantor` ——sealed
//!   supertrait，外部无法独立 impl（Hard 类型系统）。
//! - 下游（witness 铸造面）：`PartitionSerialDelivery` impl-site allowlist——本 lint（Medium）。
//!
//! 判定面：
//! - trait 身份：被 impl 的 trait 其 `DefId` crate 名 == `consistency` **且**
//!   trait 名 == `PartitionSerialDelivery`（双重匹配，避免误拦 `consistency` 其它 trait）。
//! - impl 站点放行（二选一，均键 **package 身份 / 位置**，非源**文件**路径）：
//!   ① 被编译 crate 是 `consistency` 自身（trait 定义方；引擎侧 impl 为非预期场景，靠 review 守；
//!   `cargo dylint --all` 默认不扫 `#[cfg(test)]` 子树，此放行与 test 豁免无关）——按 `LOCAL_CRATE`
//!   crate 身份判，不可被外部 `mod consistency` 伪造；
//!   ② 被编译 package 的 `CARGO_MANIFEST_DIR`（绝对路径）其**父目录名** ∈ workspace 顶层成员
//!   目录 `adapters` / `bins`（对齐 `xtask/src/layers.rs` 顶层成员分层）——新增
//!   adapter 自动覆盖，零 lint 编辑；键 package 位置而非源文件位置 ⇒ 域内 `src/adapters/` 子目录
//!   **无法绕过**（manifest dir 仍 `crates/<domain>`，父目录 `crates`）。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；
//! ② `#[cfg(test)]` 子树因 `cargo dylint --all` 默认不带 `--all-targets` 不被扫——`consistency`
//! 单测和 `eventexec` test module 里的 `SerialFake` impl 不报（test 替身合法，不进生产构建）；
//! ③ allowlist 顶层成员目录集（`adapters`/`bins`）扩项无机器复核（与 `layers.rs` 同源，
//! 靠 greppable + 治理评审）。
//!
//! anti-vacuity（守卫非恒真 / 恒假，两向均机器锁）：红向由 UI golden 锁（example crate 路径非
//! allowlist，红例 impl `PartitionSerialDelivery` **必报**）；绿向（adapter 0 诊断）由 `cargo dylint
//! --all`（`cargo xtask verify`）工作区跑锁。adapter-path 绿分支无法在 UI harness 内单测（harness
//! 控制 example 源路径，无法置于 `adapters/`），由工作区门承载。
//!
//! Hard 化评估（cargo xtask archrules verify）：无低成本 Hard 路径——`PartitionSerialDelivery` 为 open
//! trait（非 sealed），外部 crate 须能 impl 来铸造 witness（adapters 是合法 impl 站点）。唯一 Hard
//! 路径是把 `from_source` 改为注册制（macro 或 proc-macro 生成 + golden），代价超出收益，Medium 为
//! 当前最强可用载体；无需另立 Issue。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use std::path::Path;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记**非** allowlist crate（package manifest 父目录不在 `adapters`/`bins`，
    /// 即域 / 服务 / 引擎 / 基础 crate）里对 `consistency::PartitionSerialDelivery` 的 `impl`。
    ///
    /// ### Why is this bad?
    /// `PartitionSerialDelivery` 是 per-partition 串行有序投递**契约 trait**：impl 者须保证
    /// SQL head-of-partition gating + CAS settle，使得 `SerialInOrder::from_source` 铸造的 witness
    /// 真实有效（PROJECTION-SERIAL-WITNESS-01 Medium 半段）。域 / 服务 crate 直接 impl 此 trait 会
    /// 绕过 impl-site 语义审查，让非串行类型铸造 witness，使 Hard 门禁名存实亡。
    /// INVARIANT: PARTITION-SERIAL-IMPL-ALLOWLIST-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；`#[cfg(test)]`
    /// 子树默认不被扫（test fake impl 放行）；allowlist 顶层成员目录集（`adapters`/`bins`）
    /// 扩项无机器复核（与 `xtask/src/layers.rs` 顶层成员约定同源，靠 greppable + 治理）。
    /// 确需在 allowlist 外 impl 加 `#[allow(rss_partition_serial_allowlist)] // reason: ...`。
    ///
    /// ### Example
    /// ```ignore
    /// // crates/identity（域 crate，非 allowlist）：
    /// impl consistency::PartitionSerialDelivery for MyStore { /* ... */ } // 触发
    /// ```
    /// Use instead: 把 impl 放到 `adapters/<name>`，或在 `#[cfg(test)]` 块内（不被扫）。
    pub RSS_PARTITION_SERIAL_ALLOWLIST,
    Warn,
    "consistency::PartitionSerialDelivery 仅 adapter / 组合根可 impl（impl-site allowlist，INVARIANT PARTITION-SERIAL-IMPL-ALLOWLIST-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssPartitionSerialAllowlist {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let ItemKind::Impl(impl_) = item.kind else {
            return;
        };
        // inherent impl（无 of_trait）放行。
        let Some(of_trait) = impl_.of_trait else {
            return;
        };
        let Some(trait_did) = of_trait.trait_ref.trait_def_id() else {
            return;
        };
        // 被 impl 的 trait 必须是 consistency::PartitionSerialDelivery（双重判：crate 名 + trait 名）。
        if !trait_is_partition_serial_delivery(cx, trait_did) {
            return;
        }
        // impl 站点是 consistency 自身或 adapter / 组合根 package ⇒ 放行。
        if impl_site_allowed(cx) {
            return;
        }
        // 在 impl item 处报告；用 item.hir_id() 解析级别 ⇒ impl 块上 #[allow(rss_partition_serial_allowlist)] 生效。
        span_lint_hir_and_then(
            cx,
            RSS_PARTITION_SERIAL_ALLOWLIST,
            item.hir_id(),
            item.span,
            format!(
                "consistency::PartitionSerialDelivery 仅 adapter / 组合根可 impl：此 crate 不在 impl-site allowlist"
            ),
            |diag| {
                diag.help(
                    "把 impl 放到 `adapters/<name>` 或 `bins/`；\
                     测试 fake impl 放在 `#[cfg(test)]` 块内（不被扫）；\
                     确需在 allowlist 外 impl，在 impl 块加 `#[allow(rss_partition_serial_allowlist)] // reason: ...`（item-level 逃生门）",
                );
            },
        );
    }
}

/// 被 impl 的 trait 是 `consistency::PartitionSerialDelivery`：
/// - crate 名 == `consistency`（按 crate 身份判，不可被外部 `mod consistency` 伪造）
/// - trait 名 == `PartitionSerialDelivery`（`consistency` 还有其它 trait，需精准匹配）
fn trait_is_partition_serial_delivery(cx: &LateContext<'_>, trait_did: DefId) -> bool {
    cx.tcx.crate_name(trait_did.krate).as_str() == "consistency"
        && cx.tcx.item_name(trait_did).as_str() == "PartitionSerialDelivery"
}

/// impl 站点放行条件（二选一），均键 **package 身份 / 位置**（非源**文件**路径，杜绝目录名绕过）：
/// 1. 被编译 crate 是 `consistency` 自身——trait 定义方；引擎侧 impl 为非预期场景，靠 review 守。
///    `cargo dylint --all` 默认不扫 `#[cfg(test)]` 子树，此放行与 test 豁免无关（按 `LOCAL_CRATE`
///    crate 身份判，不可被外部 `mod consistency` 伪造）。
/// 2. 被编译 package 的 manifest 目录（cargo 为每个 crate 设 `CARGO_MANIFEST_DIR`，绝对路径）
///    其**父目录名** ∈ workspace 顶层成员目录 `adapters` / `bins`。键 package 位置
///    而非源**文件**位置 ⇒ 域 crate 把 impl 放进 `crates/<domain>/src/adapters/` 等子目录**无法
///    绕过**（manifest dir 仍 `crates/<domain>`，父目录 `crates`）。
///
/// `CARGO_MANIFEST_DIR` 缺失（理论上 cargo 必设）fail-closed 视为不允许。
fn impl_site_allowed(cx: &LateContext<'_>) -> bool {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() == "consistency" {
        return true;
    }
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    matches!(
        Path::new(&manifest_dir)
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str()),
        Some("adapters" | "bins")
    )
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_partition_serial_allowlist_ui");
}
