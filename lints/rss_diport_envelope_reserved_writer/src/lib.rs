#![feature(rustc_private)]
//! `rss_diport_envelope_reserved_writer` — RSS 治理 dylint lint：限定
//! `diport::EnvelopeMetadata::insert_wire_pair` 的调用站点到 adapter / 组合根
//! （`adapters`/`bins`/`assemblies`）+ diport 自身。
//!
//! INVARIANT: DIPORT-ENVELOPE-WIRE-WRITER-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! `EnvelopeMetadata` 双写面（见 `crates/diport/src/envelope.rs` 模块 rustdoc）：
//! - **业务面**（`try_insert`）：reserved key fail-closed 拒——类型层不可表达（Hard）；任意 crate 可调。
//! - **adapter 透传面**（`insert_wire_pair`）：relay 从 `outbox.metadata` 列 / subscriber 从 broker
//!   header 逐对 rehydrate（含 reserved key，来源已 sealed）。必须 `pub`（跨 crate adapter 须调），
//!   调用站点由本 lint 限到 adapter / 组合根（Medium，DIPORT-ENVELOPE-WIRE-WRITER-01）。
//!
//! MQTT broker-verified device identity is **not** written onto `diport::Message`. It stays on
//! `mqtt::AuthenticatedDeviceDelivery` after assertion verification; this lint therefore only
//! guards the wire-metadata reserved writer.
//!
//! **真正的 Hard 锚点在 emit 层**：域只经 `OutboxEmitter::emit`（入参 `OutboxEnvelopeParts` 无 reserved
//! 槽）发事件，永不构造 wire envelope 的 reserved 面——本 lint 是纵深防御（Medium，callsite allowlist）。
//!
//! 上下游强度（`cargo xtask archrules verify`）：
//! - 上游（reserved 写保护）：`try_insert` 类型层拒 reserved key（Hard，`RESERVED_METADATA_KEYS` fail-closed）；
//!   `insert_wire_pair` bypass reserved 检查，是 adapter 专用透传口——调用站点须限制（本 lint，Medium）。
//! - 下游（relay / subscriber rehydrate）：relay 从 DB outbox 列读取、subscriber 从 broker header 读取，
//!   来源已在 sealed 路径构造（adapter / 组合根独占），wire 层 reserved 写仅在这两条路径上合法。
//!
//! 判定面：
//! - 目标方法：`ExprKind::MethodCall` 中方法名 == `insert_wire_pair`，且通过 `type_dependent_def_id`
//!   解析的方法 `DefId` 的 krate 名 == "diport"（强校验：名称 + crate 两层，非任意同名方法触发）。
//! - callsite 放行：① `LOCAL_CRATE` 名 == "diport"；② `CARGO_MANIFEST_DIR` 父目录名 ∈
//!   adapters/bins/assemblies（与 `rss_diport_impl_allowlist` 同款）。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；
//! ② `#[cfg(test)]` 子树默认不被扫（test 内调用不报，test 路径非生产路径）；③ allowlist 顶层成员目录
//! 集（`adapters`/`bins`/`assemblies`）扩项无机器复核，靠 greppable + 治理评审；④ intraprocedural 盲区：
//! allowlist crate 内封装 `fn relay_wrap() { …insert_wire_pair()… }` 被外部调用时，外部只见函数调用、
//! 不见内部 `insert_wire_pair` 调用（与 `rss_authplan_callsite` 同款盲区，#1085 跟踪）。
//!
//! anti-vacuity（守卫非恒真 / 恒假，两向均机器锁）：红向（恒放行）由 UI golden 锁（example crate 路径
//! 非 allowlist，红例 `insert_wire_pair` 调用**必报**）；绿向（恒报 /
//! 误伤 adapter）由 `cargo xtask verify` 的 `cargo dylint --all` 工作区跑锁（adapter 真实调用 0 诊断）——
//! 是 verify 机器门。
//!
//! Hard 化评估（cargo xtask archrules verify）：无低成本 Hard 路径。写面必须 `pub`（跨 crate 须调），
//! 无法用可见性封闭；sealed-trait 无法跨 crate 限制调用者；AST lint 是最强可用载体。
//! 真正 Hard 锚点已在 emit 层（`OutboxEnvelopeParts` 无 reserved 槽，域经 `emit` 永不接触 reserved 写）；
//! 本 lint 是该 Hard 锚点上的 Medium 纵深防御，无需另立 Hard 化 Issue。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use std::path::Path;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记**非** callsite-allowlist crate 里对 `diport::EnvelopeMetadata::insert_wire_pair`
    /// （allowlist：`adapters`/`bins`/`assemblies` + diport）的调用。
    ///
    /// ### Why is this bad?
    /// `insert_wire_pair` 是 reserved-capable wire 透传写面——relay（postgres）从 `outbox.metadata` 列、
    /// subscriber（amqp/mqtt/memory）从 broker header rehydrate 时用（含 reserved key，来源已 sealed）。
    /// 业务 / 域 crate 直接调用可写入 reserved key（`trace`/`correlation`/`principal`/`occurred_at`），
    /// 绕过 `try_insert` 的 Hard 拒 reserved 保护，产生数据污染。
    /// INVARIANT: DIPORT-ENVELOPE-WIRE-WRITER-01 { level = "Medium", exec = "check", source = "dylint" }。
    /// 业务 metadata 请用 `try_insert`（拒 reserved key，类型层 Hard 边界）。
    ///
    /// ### Known problems
    /// 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；`#[cfg(test)]` 子树
    /// 默认不被扫；allowlist 顶层成员目录集扩项无机器复核（靠 greppable + 治理）；intraprocedural 盲区
    /// （allowlist 内封装函数包裹调用，#1085）。确需在 allowlist 外调用加
    /// `#[allow(rss_diport_envelope_reserved_writer)] // reason: ...`（item-level 逃生门）。
    ///
    /// ### Example
    /// ```ignore
    /// // crates/identity（域 crate，非 allowlist）：
    /// md.insert_wire_pair("trace", "abc"); // 触发——业务不应写 reserved key
    /// ```
    /// Use instead: `md.try_insert("myKey", "val")?;`（非 reserved key 业务 metadata）。
    /// relay / subscriber 路径用 `insert_wire_pair` 须将代码移到 `adapters/<name>` 或组合根（`bins`/`assemblies`）。
    pub RSS_DIPORT_ENVELOPE_RESERVED_WRITER,
    Warn,
    "reserved-capable wire writer EnvelopeMetadata::insert_wire_pair is callsite-allowlisted (INVARIANT DIPORT-ENVELOPE-WIRE-WRITER-01)"
}

impl<'tcx> LateLintPass<'tcx> for RssDiportEnvelopeReservedWriter {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::MethodCall(segment, _receiver, _args, _call_span) = expr.kind else {
            return;
        };
        let method_name = segment.ident.as_str();
        // 快速预过滤：仅方法名匹配时才进行昂贵的 DefId 查找。
        if method_name != "insert_wire_pair" {
            return;
        }
        // 经 typeck 解析方法 DefId（处理重载 + trait dispatch；比 segment 名字匹配更可靠）。
        let Some(method_did) = cx.typeck_results().type_dependent_def_id(expr.hir_id) else {
            return;
        };
        // 方法必须定义在 diport crate（crate 名 == "diport"，不可被外部 `mod diport` 伪造）。
        if cx.tcx.crate_name(method_did.krate).as_str() != "diport" {
            return;
        }
        // 双重确认：item 名确为受控写面（belt-and-suspenders）。
        if cx.tcx.item_name(method_did).as_str() != method_name {
            return;
        }
        // callsite allowlist：adapter / 组合根 / diport 自身放行。
        if callsite_allowed(cx) {
            return;
        }
        // 在调用表达式处报告；用 expr.hir_id 解析 lint 级别 ⇒ 支持
        // item-level `#[allow(rss_diport_envelope_reserved_writer)]` 逃生门。
        span_lint_hir_and_then(
            cx,
            RSS_DIPORT_ENVELOPE_RESERVED_WRITER,
            expr.hir_id,
            expr.span,
            "reserved-capable wire 写面 `EnvelopeMetadata::insert_wire_pair` 仅 adapter（`adapters/`）/ 组合根（`bins`/`assemblies`）可调：此 crate 不在 callsite allowlist",
            |diag| {
                diag.help(
                    "业务写 metadata 请用 `try_insert`（拒 reserved key，Hard 边界）；adapter（`adapters/`）/ 组合根（`bins`/`assemblies`）的 relay / subscriber rehydrate 才用 `insert_wire_pair`；确需在 allowlist 外调用在该调用处加 `#[allow(rss_diport_envelope_reserved_writer)] // reason: ...`（item-level 逃生门）",
                );
            },
        );
    }
}

/// callsite 放行条件（原样复用 `rss_diport_impl_allowlist` 的 `impl_site_allowed` 逻辑，
/// 仅函数名改为 `callsite_allowed` 以反映 callsite 语义）。
/// 1. 被编译 crate 是 `diport` 自身——定义方内部调用合法（含 diport 单元测试对
///    `insert_wire_pair` 的调用）。`LOCAL_CRATE` 身份不可被外部 `mod diport` 伪造。
/// 2. 被编译 package 的 manifest 目录（`CARGO_MANIFEST_DIR`，绝对路径、随调用位置不变）其**父目录名**
///    ∈ workspace 顶层成员目录 `adapters`/`bins`/`assemblies`。键 package 位置而非源文件路径 ⇒
///    域 crate 把调用藏进 `crates/<domain>/src/adapters/` 子目录无法绕过（manifest dir 仍 `crates/<domain>`，
///    父目录 `crates`）。**allowlist 刻意窄于架构单源的「组合根」全集**——`xtask` / `journeys`（父目录均为
///    workspace 根）虽属组合根，但**不构造 wire envelope / 不调 `insert_wire_pair`**，故意不入 allowlist
///    （fail-closed 更严；确需则走 item-level `#[allow]`）。判定逻辑与兄弟 lint `rss_diport_impl_allowlist` 同款。
///
/// `CARGO_MANIFEST_DIR` 缺失（理论上 cargo 必设；非 cargo 驱动场景）fail-closed 视为不允许。
fn callsite_allowed(cx: &LateContext<'_>) -> bool {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() == "diport" {
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
        Some("adapters" | "bins" | "assemblies")
    )
}

#[cfg(test)]
mod ui {
    #[test]
    fn ui() {
        dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_diport_envelope_reserved_writer_ui");
    }
}
