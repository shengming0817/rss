#![feature(rustc_private)]
//! `rss_diport_error_debug_redacted` — RSS 治理 dylint lint：`diport` error struct 禁持裸
//! `Box<dyn std::error::Error + Send + Sync + 'static>` source 字段；改用 `pub(crate) RedactedSource`
//! newtype（`Debug`/`Display` 恒 `<redacted>`，不展开内层）。
//!
//! INVARIANT: DIPORT-ERR-RAWSOURCE-BAN-01
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（Hard，`diport` 内）：`RedactedSource` 的 `Debug`/`Display` 实现**强制脱敏**——
//!   类型系统保证，不可绕过（INVARIANT: DIPORT-ERR-SOURCE-REDACT-01，`crates/diport/src/redacted.rs`）。
//! - 下游（本 lint，Medium）：守「diport error struct 的 source 字段必须使用 RedactedSource，
//!   不得持裸 `Box<dyn Error>`」——消费方的字段类型是命名 ADT `RedactedSource`（非 `Box<dyn Error>`
//!   trait-object 字段），天然不命中；`RedactedSource` 定义自身（内层为裸 Box）按 enclosing struct 名
//!   结构性豁免（唯一名单项，系本设计核心，重命名即触发红 + 单测漂移而被发现）。
//!
//! 守护范围（MANDATORY）：仅当 `cx.tcx.crate_name(LOCAL_CRATE) == "diport"` 时激活。
//! 工作区其它 crate（`bootstrap::SubscriberHandlerError`、`eventexec::ConsumerError` 等）合法持有
//! 裸 `Box<dyn Error>` 字段（语义不同于 diport provider-error source），不得误报。
//!
//! 检测面：`check_field_def` 逐字段在 **Ty 层（typeck 后）** 判定真实字段类型——type alias 在此**透明
//! 展开**，故语法别名无法绕过（旧 HIR 语法匹配的盲区，#1144 review F2）：
//! 1. `cx.tcx.type_of(field.def_id)` 取字段类型 `Ty`；`type Source = Box<dyn Error>` /
//!    `type DynErr = dyn Error; Box<DynErr>` 均已归一化到同一 `Box<dyn Error>` Ty。
//! 2. `Ty` 是 `ty::Adt` 且 `adt_def.is_box()`（lang-item box）；取被装类型 `args.type_at(0)`。
//! 3. 被装类型是 `ty::Dynamic(predicates, ..)`（trait object）；`predicates.principal_def_id()` 经
//!    `cx.tcx.is_diagnostic_item(sym::Error, did)` 确认为 `std::error::Error`（`+ Send + Sync + 'static`
//!    属 auto-trait / lifetime bound，不影响 principal 判定）。
//! 诊断 span 置于字段类型（写法原样，alias 名亦原样高亮），item-level
//! `#[allow(rss_diport_error_debug_redacted)]` 逃生门有效。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦，
//! azure 无 CI ⇒ verify 是唯一实际 gate；② 生产 `diport` 经重构后无裸 Box 字段（#1144 Part A），
//! 「恒假」向由 UI 红例 golden 锁（直接 `Box<dyn Error>` + type-alias + dyn-alias 三形均命中，
//! 非 diport 工作区 crate 不命中，anti-vacuity 靠 UI 覆盖），
//! 「恒真」向由 not_diport 绿例 golden 锁（同形 struct 在 LOCAL_CRATE!="diport" 下不报）。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use clippy_utils::sym;
use rustc_hir::FieldDef;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty;

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记 `diport` crate 内 struct 字段类型为裸 `Box<dyn std::error::Error + ...>` 的情形。
    /// `RedactedSource` 是该形状的授权替代（它本身持有同一 `Box`，但 `Debug`/`Display` 固定脱敏）；
    /// `RedactedSource` 字段是命名 ADT 类型、不是 trait-object 字段，本 lint 自动放行。
    ///
    /// ### Why is this bad?
    /// `Box<dyn Error>` 字段的 `derive(Debug)` 会展开内层 `source` 的 `Debug` 实现，adapter
    /// 原始错误（redis URL、凭据、网络地址）可能经此泄入日志（PII 边界问题）。
    /// 上游 `RedactedSource` 已用类型系统（Hard）保证 `Debug`/`Display` 恒 `<redacted>`；
    /// 本 lint 作为下游 Medium gate，确保 diport error struct 确实采纳该 newtype。
    /// INVARIANT: DIPORT-ERR-RAWSOURCE-BAN-01。
    ///
    /// ### Known problems
    /// 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；`#[cfg(test)]`
    /// 子树默认不被扫（test-only error struct 放行）。守护范围限 `diport` crate（`LOCAL_CRATE=="diport"`）；
    /// 其它 crate 的同形字段（`bootstrap::SubscriberHandlerError` 等）不命中。
    ///
    /// `RedactedSource` 自身（脱敏 newtype 的受控持有点）经**结构性豁免**——按 enclosing struct **名字符串**
    /// （`item_name == "RedactedSource"`）判定，**非** type-identity，故是 name-based 脆弱点：重命名该 newtype
    /// 会使豁免失配 → 本 lint 对其内层裸 Box **误报红**（且 UI golden 漂移），即「rename 即被发现」的自救机制。
    /// 选 name-based 而非 `#[allow]`/cfg：避免在生产代码引入 dylint cfg（`unexpected_cfgs`）/ `unknown_lints` 噪声。
    /// 其它确需保留裸 Box 的极少数情形仍可用 item-level `#[allow(rss_diport_error_debug_redacted)] // reason: ...`
    /// 逃生门——生产 carve-out 须遵 `error-handling.md §Carve-out`（item-level + reason，必要时同步 ADR registry）；
    /// UI fixture 内的 `#[allow]`（`ui/diport.rs` G3）仅演示逃生门、属 test-only，不入 carve-out ADR registry。
    ///
    /// anti-vacuity（守卫非恒真 / 恒假，两向 UI golden 锁）：红向由 `ui/diport.rs`（example crate 名 `diport`
    /// ⇒ `LOCAL_CRATE=="diport"`）的裸 Box struct **必报** + golden `diport.stderr` 非空锁；绿向由
    /// `ui/not_diport.rs`（crate 名非 `diport`）同形字段 **不报** + 空 golden 锁（验 `LOCAL_CRATE` 分支非恒报）。
    /// 生产假阴（重构后 diport 0 裸 Box）由工作区 `cargo dylint --all`（0 诊断）承载。
    ///
    /// ### Example
    /// ```ignore
    /// // diport error struct（触发）：
    /// struct SignerError {
    ///     source: Box<dyn std::error::Error + Send + Sync + 'static>,
    /// }
    /// ```
    /// Use instead:
    /// ```ignore
    /// // 使用 RedactedSource newtype（不触发，Debug/Display 自动脱敏）：
    /// struct SignerError {
    ///     #[source]
    ///     source: RedactedSource,
    /// }
    /// ```
    pub RSS_DIPORT_ERROR_DEBUG_REDACTED,
    Warn,
    "diport error struct 不得持裸 `Box<dyn Error>` source 字段：改用 `RedactedSource` newtype（Debug/Display 脱敏，INVARIANT DIPORT-ERR-RAWSOURCE-BAN-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssDiportErrorDebugRedacted {
    fn check_field_def(&mut self, cx: &LateContext<'tcx>, field: &'tcx FieldDef<'tcx>) {
        // 守护范围：仅 diport crate 内——其它 crate 合法持裸 Box<dyn Error>，不得误报。
        if cx.tcx.crate_name(LOCAL_CRATE).as_str() != "diport" {
            return;
        }
        // 结构性豁免：`RedactedSource` 是脱敏 newtype 本身（受控持有点），其内层裸 Box 合法——
        // 它正是本 lint 守护要采纳的「正确实现」（Debug/Display 已固定 <redacted>）。按 enclosing struct
        // 名豁免（非 #[allow]，避免在生产代码引入 dylint cfg / unknown_lints / unexpected_cfgs 噪声）。
        // diport 内同名 struct 唯一且系本设计核心，重命名会触发本 lint 红 + 单测漂移而被发现。
        let parent_did = cx.tcx.parent(field.def_id.to_def_id());
        if cx.tcx.item_name(parent_did).as_str() == "RedactedSource" {
            return;
        }
        if is_raw_boxed_error_ty(cx, field) {
            span_lint_hir_and_then(
                cx,
                RSS_DIPORT_ERROR_DEBUG_REDACTED,
                field.hir_id,
                field.ty.span,
                "diport error struct 不得持裸 `Box<dyn Error>` source 字段：改用 `RedactedSource` newtype（Debug/Display 脱敏）",
                |diag| {
                    diag.help(
                        "把字段类型换成 `pub(crate) RedactedSource`（`crates/diport/src/redacted.rs`），\
                        并经 `RedactedSource::new(source)` 包装 adapter 错误（其 Debug/Display 已脱敏）；\
                        极少数确需保留裸 Box 的情形加 \
                        `#[allow(rss_diport_error_debug_redacted)] // reason: ...`（item-level 逃生门）",
                    );
                },
            );
        }
    }
}

/// 字段的**真实类型**（Ty 层，typeck 后）是否为 `Box<dyn std::error::Error + ...>`。
///
/// 在 Ty 层判定（非 HIR 语法）——type alias 已**透明展开**，故 `type Source = Box<dyn Error>; source:
/// Source` 与 `type DynErr = dyn Error; source: Box<DynErr>` 都归一化到同一 `Box<dyn Error>` Ty 而命中，
/// 关闭旧 HIR 语法匹配的 alias 绕过面（#1144 review F2）。
///
/// 判定步骤：
/// 1. `type_of(field)` 取字段 Ty；它是 `ty::Adt` 且 `adt_def.is_box()`（lang-item box）。
/// 2. 取被装类型 `T = args.type_at(0)`（`Box<T, A>` 的首个类型实参）。
/// 3. `T` 是 `ty::Dynamic`（trait object）；`predicates.principal_def_id()` 经 diagnostic item
///    `sym::Error` 识别为 `std::error::Error`（`+ Send + Sync + 'static` 不影响 principal 判定）。
fn is_raw_boxed_error_ty(cx: &LateContext<'_>, field: &FieldDef<'_>) -> bool {
    // 步骤 1：字段真实类型必须是 `Box<_>`（lang-item box 的 ADT）。type alias 在 Ty 层透明展开。
    let field_ty = cx.tcx.type_of(field.def_id).instantiate_identity();
    let ty::Adt(adt_def, args) = field_ty.kind() else {
        return false;
    };
    if !adt_def.is_box() {
        return false;
    }
    // 步骤 2：取被装类型 `T`（`Box<T, A>` 的首个类型实参）。
    let boxed_ty = args.type_at(0);
    // 步骤 3：`T` 是 trait object（`ty::Dynamic`），principal trait 经 diagnostic item 识别为 std::error::Error。
    let ty::Dynamic(predicates, ..) = boxed_ty.kind() else {
        return false;
    };
    let Some(principal_did) = predicates.principal_def_id() else {
        return false;
    };
    cx.tcx.is_diagnostic_item(sym::Error, principal_did)
}

#[test]
fn ui_diport_red() {
    // example target 名 `diport`（LOCAL_CRATE=="diport"）→ struct 持裸 Box<dyn Error> 字段触发；
    // 内嵌绿子例（非 trait-object Box / item-level #[allow]）验 anti-vacuity。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "diport");
}

#[test]
fn ui_not_diport_green() {
    // example target 名 `not_diport`（LOCAL_CRATE=="not_diport" ≠ "diport"）→ 同形 struct 不触发；
    // golden ui/not_diport.stderr 为空（anti-vacuity：验 LOCAL_CRATE 分支非恒报）。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "not_diport");
}
