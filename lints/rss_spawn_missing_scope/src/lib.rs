#![feature(rustc_private)]
//! `rss_spawn_missing_scope` — RSS G0.4 治理 dylint lint：拦截 `tokio::spawn` / `spawn_blocking`
//! 出的子任务体内读 `runctx::try_with`/`try_current`，却未在外层 `runctx::scope(...)` 重绑 ctx。
//!
//! INVARIANT: SPAWN-CTX-REBIND-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! `tokio::spawn`/`spawn_blocking`/`std::thread` 不继承 `task_local`（ADR-002 §范式 spawn 传播）。
//! 子任务读 ctx 前必须「捕获-重绑」：`let ctx = try_current()?; spawn(scope(ctx, async {…}))`。
//! 漏重绑会让子任务 fail-closed（功能性 deny），或被 consumer `unwrap_or(anonymous)` 绕成 fail-open 越权。
//! 运行时不变式已是 Medium（fail-closed + 测试锁定不继承）；本 lint 把「静态防误用」从 Soft 升到 Medium
//! （AST 级，最强可用载体）。跨任务携 ctx 是运行时概念、类型系统不天然覆盖，故以 dylint AST lint 承载；
//! Hard 化须 `CtxBound` 类型（侵入 consumer 签名，见 ADR-002 §备选，未立项）。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::DefId;
use rustc_hir::intravisit::{self, Visitor};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::hir::nested_filter;
use rustc_span::Span;

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记 `tokio::spawn(...)` / `tokio::task::spawn_blocking(...)` 的子任务体内直接读
    /// `runctx::try_with` / `runctx::try_current`，且该读未被子任务体内的 `runctx::scope(...)` 词法包裹。
    ///
    /// ### Why is this bad?
    /// `tokio::spawn`/`spawn_blocking` 出的子任务**不继承** `task_local`（ADR-002 §范式）。子任务读 ctx
    /// 前必须「捕获-重绑」（`let ctx = try_current()?; spawn(scope(ctx, async {…}))`）。漏重绑 → 子任务
    /// `Err(MissingCtx)` 功能性 deny，或被 consumer `unwrap_or(anonymous)` 绕成 fail-open 越权。跨任务携
    /// ctx 是运行时概念、类型系统不天然覆盖，故以 dylint AST lint 承载（Medium）。INVARIANT: SPAWN-CTX-REBIND-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// **仅 intraprocedural**：子任务体内调用某 helper fn、helper 内部读 ctx 的跨函数情形不检测。仅认自由
    /// 函数 `tokio::spawn` / `tokio::task::spawn_blocking`（按 crate 名 + item 名 + parent 为 module 判定，
    /// 排除 `JoinSet::spawn` 等方法）；`std::thread::spawn` 不在范围。`scope` 守卫为**词法**判定（子任务体
    /// 内出现 `runctx::scope(...)` 祖先即视为已重绑）。嵌套 spawn 各自独立检测（外层扫描不下钻内层 spawn
    /// 子树）。确需读裸 ctx 用 `#[allow(rss_spawn_missing_scope)] // reason: ...` 豁免。
    ///
    /// **方法形式 spawn 不覆盖**：`tokio::task::spawn_local`（`LocalSet::spawn_local`）、
    /// `JoinSet::spawn`/`spawn_on` 等**方法**调用因 parent 为 impl 被 `is_tokio_spawn_call` 排除——
    /// 它们同样不继承 `task_local`，使用方须手动遵守捕获-重绑范式（lint 不替其守）。
    ///
    /// **spawn 自身被 wrapper fn 包装不覆盖**：若 `tokio::spawn` 被用户
    /// `fn my_spawn<F>(f: F) { tokio::spawn(f) }` 包一层，则 `my_spawn(async {…})` callsite
    /// 解析到的 crate 名非 `tokio`，lint 不报（与「`try_*` 被 helper 包装」并列的另一类
    /// intraprocedural 盲区）。
    ///
    /// ### Example
    /// ```ignore
    /// tokio::spawn(async { runctx::try_current() }); // 触发：子任务读 ctx 未重绑
    /// ```
    /// Use instead:
    /// ```ignore
    /// let ctx = runctx::try_current()?;
    /// tokio::spawn(runctx::scope(ctx, async { runctx::try_current() })); // 已重绑
    /// ```
    pub RSS_SPAWN_MISSING_SCOPE,
    Warn,
    "spawn 子任务读 ctx 未在外层 runctx::scope 重绑（spawn footgun 静态防误用）"
}

impl<'tcx> LateLintPass<'tcx> for RssSpawnMissingScope {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // 仅自由函数调用形式的 spawn；`JoinSet::spawn` 等方法是 MethodCall，天然不匹配 `ExprKind::Call`。
        let ExprKind::Call(_callee, args) = expr.kind else {
            return;
        };
        if !is_tokio_spawn_call(cx, expr) {
            return;
        }
        let Some(arg) = args.first() else {
            return;
        };

        // 形式 A：直接 fn-path 实参，如 `spawn_blocking(runctx::try_current)`（try_current 作为 FnOnce 传入）。
        if let ExprKind::Path(qpath) = &arg.kind {
            if let Res::Def(DefKind::Fn, did) = cx.qpath_res(qpath, arg.hir_id)
                && is_runctx_try(cx, did)
            {
                emit(cx, arg.hir_id, arg.span);
            }
            return;
        }

        // 形式 B：闭包 / async block 实参——扫描体内对 try_with/try_current 的调用；`runctx::scope(...)`
        // 词法包裹（depth>0）视为已重绑；不下钻嵌套 spawn 子树（其自有 check_expr 处理，避免重复报）。
        let mut visitor = TryReadVisitor {
            cx,
            scope_depth: 0,
            root: arg.hir_id,
            findings: Vec::new(),
        };
        visitor.visit_expr(arg);
        for (hir_id, span) in visitor.findings {
            emit(cx, hir_id, span);
        }
    }
}

/// 扫描 spawn 实参子树，收集未被 `runctx::scope(...)` 词法包裹的 `runctx::try_*` 调用。
struct TryReadVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    scope_depth: u32,
    root: HirId,
    findings: Vec<(HirId, Span)>,
}

impl<'tcx> Visitor<'tcx> for TryReadVisitor<'_, 'tcx> {
    type NestedFilter = nested_filter::OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.cx.tcx
    }

    fn visit_expr(&mut self, e: &'tcx Expr<'tcx>) {
        // 嵌套 spawn（非根）：不下钻，交由其自身 check_expr 检测，避免对同一 try_* 重复报。
        if e.hir_id != self.root && is_tokio_spawn_call(self.cx, e) {
            return;
        }
        // `runctx::scope(...)` 词法包裹：进入其子树时 depth+1，离开时 depth-1。
        if is_runctx_call(self.cx, e, &["scope"]) {
            self.scope_depth += 1;
            intravisit::walk_expr(self, e);
            self.scope_depth -= 1;
            return;
        }
        // 未被 scope 包裹（depth==0）的 try_with/try_current 调用即漏重绑读。
        if self.scope_depth == 0 && is_runctx_call(self.cx, e, &["try_with", "try_current"]) {
            self.findings.push((e.hir_id, e.span));
        }
        intravisit::walk_expr(self, e);
    }
}

/// `e` 是自由函数 `tokio::spawn` / `tokio::task::spawn_blocking` 调用。按 crate 名 + item 名 + parent
/// 为 module 判定（对齐 rss_domain_no_serialize 的反路径脆弱性思路；`tokio::spawn` 真路径是
/// `tokio::task::spawn::spawn` 的 re-export，`match_def_path` 已 deprecated）。parent 为 module 排除
/// `JoinSet::spawn` 等方法（其 parent 是 impl）。
fn is_tokio_spawn_call(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    let Some(did) = clippy_utils::fn_def_id(cx, e) else {
        return false;
    };
    if cx.tcx.crate_name(did.krate).as_str() != "tokio" {
        return false;
    }
    if !matches!(cx.tcx.item_name(did).as_str(), "spawn" | "spawn_blocking") {
        return false;
    }
    matches!(cx.tcx.def_kind(cx.tcx.parent(did)), DefKind::Mod)
}

/// `e` 是 `runctx` crate 中名为 `names` 之一的自由函数调用。
fn is_runctx_call(cx: &LateContext<'_>, e: &Expr<'_>, names: &[&str]) -> bool {
    let Some(did) = clippy_utils::fn_def_id(cx, e) else {
        return false;
    };
    if cx.tcx.crate_name(did.krate).as_str() != "runctx" {
        return false;
    }
    let name = cx.tcx.item_name(did);
    names.iter().any(|n| *n == name.as_str())
}

/// `did` 是 `runctx::try_with` / `runctx::try_current`（直接 fn-path 实参判定用）。
fn is_runctx_try(cx: &LateContext<'_>, did: DefId) -> bool {
    cx.tcx.crate_name(did.krate).as_str() == "runctx"
        && matches!(cx.tcx.item_name(did).as_str(), "try_with" | "try_current")
}

/// 在漏重绑的 ctx 读处报告；emit 用该读的 `HirId` 解析 lint 级别，使 expr/item 级
/// `#[allow(rss_spawn_missing_scope)]` 逃生门生效（同 rss_domain_no_serialize）。
fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_SPAWN_MISSING_SCOPE,
        hir_id,
        span,
        "spawn 出的子任务不继承 ctx：子任务体内读 `runctx::try_with`/`try_current` 前须在外层 `runctx::scope(...)` 重绑",
        |diag| {
            diag.help(
                "捕获父 ctx 再重绑：`let ctx = runctx::try_current()?; tokio::spawn(runctx::scope(ctx, async { /* try_current() => Ok */ }));`。确需读裸 ctx 时加 `#[allow(rss_spawn_missing_scope)] // reason: ...`",
            );
        },
    );
}

#[test]
fn ui() {
    // example target 名 `spawn_missing_scope_ui`（非裸 `ui`）避免 workspace artifact 碰撞；golden 仍是源旁 ui/main.stderr。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "spawn_missing_scope_ui");
}
