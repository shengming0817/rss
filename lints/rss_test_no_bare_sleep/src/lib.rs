#![feature(rustc_private)]
//! `rss_test_no_bare_sleep` — RSS 治理 dylint lint：测试上下文禁裸
//! `tokio::time::sleep` / `std::thread::sleep`。
//!
//! INVARIANT: TEST-NO-BARE-SLEEP-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! 测试里裸 sleep 造成 flaky / 慢测 / 假绿。有界等待走 `testkit::wait`（值携带
//! ready-signal + `await_delay` 固定延时），不得直接 sleep；也**禁止**永不返回
//! `Some` 的 probe 伪装延时。
//!
//! Funnel 上下游（ai-robust.md §审查要求 funnel）：
//! - **上游 Hard**：`testkit` 不导出公开 `sleep` 名字——固定延时只经 `await_delay`；ready-signal
//!   经 `await_map*` / `await_try*` / `await_notified`。
//! - **下游 Medium**：本 lint——在测试上下文（`#[test]` 函数 / 显式 `#[cfg(test)] mod` /
//!   源路径含 `/tests/`）拦截已解析的 `tokio::time::sleep` 与 `std::thread::sleep` callsite
//!   （含 `use` 导入别名）。**不**把 `cargo test --lib` 的 ambient `--cfg test` 当作测试上下文
//!   （否则生产 backoff 在 lib test 构建中被误杀）。`testkit::wait` 模块内放行。vacuous
//!   永不返回 `Some` 的 probe 伪装延时靠迁移清零 + review，不另开 Soft / AST 恒空门。
//! - **Hard-化评估**：跨 crate「测试 vs 生产 backoff」无法类型封闭；上游 Hard 只挡公开 API，
//!   无法挡直接依赖 tokio/std 的 callsite。AST/HIR callsite lint 是最强可用 Medium 载体。
//!
//! anti-vacuity：UI golden 锁红（test 内裸 sleep / `#[cfg(test)] mod` helper）与绿（生产函数 /
//! ambient `--cfg test` 生产 backoff / `#[cfg(not(test))]` / `#[allow]`）；`/tests/` 路径分支由
//! `path_contains_tests_segment` 单测锁；全仓 `--all-targets` 迁完后由专用 verify 步 fail-closed。

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use clippy_utils::is_in_test_function;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Attribute, Expr, ExprKind, HirId, Node};
use rustc_hir::attrs::{AttributeKind, CfgEntry};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;
use rustc_span::symbol::sym;

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 在测试上下文中拦截对 `tokio::time::sleep` 与 `std::thread::sleep` 的调用
    /// （经 name resolution / def_path；`use` 导入的 `time::sleep` 同样命中）。
    ///
    /// ### Why is this bad?
    /// 测试里裸 sleep 导致 flaky、慢测与假绿。有界等待应走 `testkit::wait`
    ///（`await_map*` / `await_try*` / `await_notified` / `await_delay`）。INVARIANT: TEST-NO-BARE-SLEEP-01。
    /// 另：**禁止**永不返回 `Some` 的 probe 伪装固定延时——固定延时必须用 `await_delay`。
    ///
    /// ### Funnel
    /// - 上游 Hard：`testkit` 不导出公开 `sleep` 名字；固定延时只经 `await_delay`。
    /// - 下游 Medium：本 lint（测试上下文 callsite）。
    /// - Funnel 实现放行：`testkit` crate 的 `wait` 模块（内部 poll / delay 短 sleep）。
    /// - 逃生：`#[allow(rss_test_no_bare_sleep)] // reason: ...`（如 paused-clock hang probe）。
    ///
    /// ### Known problems
    /// 仅自由函数调用（`ExprKind::Call`）；其它 timer API（`interval` / `sleep_until` /
    /// `thread::park_timeout`）不在范围。仅 intraprocedural 解析到的 DefId——经自定义
    /// wrapper fn 间接调用不报。生产 backoff（非 test 上下文）故意不报。不拦 vacuous
    /// 永不返回 `Some` 的 probe（靠迁移 + review）。
    ///
    /// ### Example
    /// ```ignore
    /// #[tokio::test]
    /// async fn flaky() {
    ///     tokio::time::sleep(std::time::Duration::from_millis(50)).await; // 触发
    /// }
    /// ```
    /// Use instead:
    /// ```ignore
    /// use testkit::{await_delay, await_map};
    /// #[tokio::test]
    /// async fn ready() {
    ///     await_map(std::time::Duration::from_secs(1), async || ready().then_some(()))
    ///         .await
    ///         .unwrap();
    /// }
    /// #[tokio::test]
    /// async fn fixed_delay() {
    ///     await_delay(std::time::Duration::from_millis(50)).await;
    /// }
    /// ```
    pub RSS_TEST_NO_BARE_SLEEP,
    Warn,
    "测试上下文禁止裸 tokio::time::sleep / std::thread::sleep（走 testkit::wait；INVARIANT TEST-NO-BARE-SLEEP-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssTestNoBareSleep {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::Call(_, _) = expr.kind else {
            return;
        };
        let Some(did) = clippy_utils::fn_def_id(cx, expr) else {
            return;
        };
        if !is_banned_sleep(cx, did) {
            return;
        }
        if !in_test_context(cx, expr.hir_id, expr.span) {
            return;
        }
        if is_testkit_wait_funnel(cx, expr.hir_id, expr.span) {
            return;
        }
        emit(cx, expr.hir_id, expr.span);
    }
}

/// `did` 解析为 `tokio::time::sleep` 或 `std::thread::sleep`（含 re-export / `use` 导入）。
fn is_banned_sleep(cx: &LateContext<'_>, did: DefId) -> bool {
    if cx.tcx.item_name(did).as_str() != "sleep" {
        return false;
    }
    let path = cx.tcx.def_path_str(did);
    let crate_name = cx.tcx.crate_name(did.krate);
    match crate_name.as_str() {
        "tokio" => {
            path.contains("tokio::time::sleep")
                || path.contains("time::sleep")
                || path.ends_with("::sleep")
        }
        "std" => path.contains("thread::sleep") || path.contains("std::thread::sleep"),
        _ => path.contains("tokio::time::sleep") || path.contains("std::thread::sleep"),
    }
}

/// 测试上下文（刻意不含 ambient `--cfg test` / `is_test_crate()`）：
/// `cargo test --lib` 会对整库开 `--cfg test`，若用 `is_in_cfg_test`/`is_test_crate` 会把生产
/// backoff（如 mqtt DRIVER_ERROR_BACKOFF）误杀。
///
/// 判定：`#[test]`/`#[tokio::test]` 函数内；显式 `#[cfg(test)] mod`（属性挂在 mod item 上）；
/// 或源路径含 `/tests/`（integration test crate）。
fn in_test_context(cx: &LateContext<'_>, hir_id: HirId, span: Span) -> bool {
    if is_in_test_function(cx.tcx, hir_id) {
        return true;
    }
    if source_path_contains_tests(cx, span) {
        return true;
    }
    in_explicit_cfg_test_module(cx, hir_id)
}

/// 祖先链上存在**带 `#[cfg(...test...)]` 属性的 mod item**（非 ambient lib `--cfg test`）。
fn in_explicit_cfg_test_module(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    for (_id, parent) in cx.tcx.hir_parent_iter(hir_id) {
        let Node::Item(item) = parent else {
            continue;
        };
        if !matches!(item.kind, rustc_hir::ItemKind::Mod(..)) {
            continue;
        }
        if attrs_cfg_test(cx, item.hir_id()) {
            return true;
        }
    }
    false
}

fn attrs_cfg_test(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    use rustc_hir::AttrArgs;
    for attr in cx.tcx.hir_attrs(hir_id) {
        match attr {
            // nightly 把 `#[cfg(...)]` 降为 Parsed(CfgTrace)；只认 Unparsed 会漏检。
            Attribute::Parsed(AttributeKind::CfgTrace(entries)) => {
                if entries.iter().any(|(entry, _)| cfg_entry_mentions_test(entry)) {
                    return true;
                }
            }
            Attribute::Unparsed(u) => {
                let is_cfg = u.path.segments.len() == 1 && u.path.segments[0].as_str() == "cfg";
                if !is_cfg {
                    continue;
                }
                let AttrArgs::Delimited(args) = &u.args else {
                    continue;
                };
                if token_stream_mentions_test(args.tokens.iter()) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// 正提及 `test` cfg（`test` / `all(..., test, ...)` / `any(..., test, ...)`）。
/// `not(...)` 一律不算测试上下文——`not(test)` 是生产侧门控，不得误判。
fn cfg_entry_mentions_test(entry: &CfgEntry) -> bool {
    match entry {
        CfgEntry::NameValue { name, value: None, .. } => *name == sym::test,
        CfgEntry::All(subs, _) | CfgEntry::Any(subs, _) => {
            subs.iter().any(cfg_entry_mentions_test)
        }
        CfgEntry::Not(..) => false,
        CfgEntry::Bool(..) | CfgEntry::NameValue { .. } | CfgEntry::Version(..) => false,
    }
}

/// Unparsed `cfg(...)` token 流：正提及 `test`；`not(...)` 跳过其分组（与 [`cfg_entry_mentions_test`] 同语义）。
fn token_stream_mentions_test<'a>(
    tokens: impl IntoIterator<Item = &'a rustc_ast::tokenstream::TokenTree>,
) -> bool {
    use rustc_ast::token::TokenKind;
    use rustc_ast::tokenstream::TokenTree;
    let mut iter = tokens.into_iter().peekable();
    while let Some(tt) = iter.next() {
        match tt {
            TokenTree::Token(tok, _) => {
                let TokenKind::Ident(sym, _) = &tok.kind else {
                    continue;
                };
                let name = sym.as_str();
                if name == "test" {
                    return true;
                }
                if name == "not" {
                    // `not(...)`：跳过紧随的 Delimited，不把内层 `test` 当正提及。
                    if matches!(iter.peek(), Some(TokenTree::Delimited(..))) {
                        let _ = iter.next();
                    }
                }
            }
            TokenTree::Delimited(_, _, _, stream) => {
                if token_stream_mentions_test(stream.iter()) {
                    return true;
                }
            }
        }
    }
    false
}

fn source_path_contains_tests(cx: &LateContext<'_>, span: Span) -> bool {
    path_contains_tests_segment(&source_path_hint(cx, span))
}

/// 源路径是否含 integration-test 目录段（`/tests/` 或 Windows `\\tests\\`）。
fn path_contains_tests_segment(path: &str) -> bool {
    path.contains("/tests/") || path.contains("\\tests\\")
}

fn source_path_hint(cx: &LateContext<'_>, span: Span) -> String {
    use rustc_span::FileName;
    match cx.tcx.sess.source_map().span_to_filename(span) {
        FileName::Real(real) => real
            .local_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| format!("{real:?}")),
        other => format!("{other:?}"),
    }
}

/// Funnel 放行：`testkit` crate 的 `wait` 模块（DefPath/模块名含 `wait`，或源文件以 `wait.rs` 结尾）。
fn is_testkit_wait_funnel(cx: &LateContext<'_>, hir_id: HirId, span: Span) -> bool {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() != "testkit" {
        return false;
    }
    let owner = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    let def_path = cx.tcx.def_path_str(owner);
    if def_path.contains("wait") {
        return true;
    }
    let path = source_path_hint(cx, span);
    path.ends_with("wait.rs") || path.ends_with("wait.rs]")
}

fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_TEST_NO_BARE_SLEEP,
        hir_id,
        span,
        "测试上下文禁止裸 `tokio::time::sleep` / `std::thread::sleep`：改用 `testkit::wait`",
        |diag| {
            diag.help(
                "有界等待：`testkit::wait::{await_map,await_map_every,await_try,await_try_every,await_notified,await_delay}`；\
固定延时用 `await_delay`，禁止永不返回 `Some` 的 probe 伪装延时；\
                 生产 backoff 不在本 lint 范围；确需裸 sleep 加 `#[allow(rss_test_no_bare_sleep)] // reason: ...`",
            );
        },
    );
}

#[test]
fn ui() {
    // `--test` 使 `#[test]` / `#[tokio::test]` 被识别为测试函数（is_in_test_function）。
    // 内嵌 `#[cfg(test)] mod` helper 红例亦依赖 `--cfg test`（`--test` 隐含）。
    // 生产 backoff / `#[cfg(not(test))]` 绿例见 production / production_cfg_test。
    // `/tests/` 路径分支由 [`path_contains_tests_segment`] 单测锁；UI harness 临时路径无该段。
    dylint_testing::ui::Test::example(env!("CARGO_PKG_NAME"), "rss_test_no_bare_sleep_ui")
        .rustc_flags(["--test"])
        .run();
}

#[test]
fn ui_production() {
    // 非 test 上下文：生产 backoff / `#[cfg(not(test))]` 内 sleep 不报。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "production");
}

#[test]
fn ui_production_under_ambient_cfg_test() {
    // ambient `--cfg test` alone 不得把生产 backoff 误杀（防 `cargo test --lib` 假红）。
    dylint_testing::ui::Test::example(env!("CARGO_PKG_NAME"), "production_cfg_test")
        .rustc_flags(["--cfg", "test"])
        .run();
}

#[cfg(test)]
mod path_contains_tests_segment_tests {
    use super::path_contains_tests_segment;

    #[test]
    fn hits_unix_and_windows_tests_dir() {
        assert!(path_contains_tests_segment("crates/foo/tests/bar.rs"));
        assert!(path_contains_tests_segment("/abs/path/tests/integration.rs"));
        assert!(path_contains_tests_segment(r"C:\proj\tests\foo.rs"));
    }

    #[test]
    fn misses_near_homonyms_and_non_tests_paths() {
        assert!(!path_contains_tests_segment("crates/foo/src/lib.rs"));
        assert!(!path_contains_tests_segment("crates/foo/src/tests_helpers.rs"));
        assert!(!path_contains_tests_segment("crates/testimonials/src/lib.rs"));
        assert!(!path_contains_tests_segment("foo/test/bar.rs"));
        assert!(!path_contains_tests_segment("tests.rs"));
    }
}

#[cfg(test)]
mod cfg_not_test_semantics_tests {
    use super::cfg_entry_mentions_test;
    use rustc_hir::attrs::CfgEntry;
    use rustc_span::DUMMY_SP;
    use rustc_span::symbol::sym;

    fn name_test() -> CfgEntry {
        CfgEntry::NameValue {
            name: sym::test,
            value: None,
            span: DUMMY_SP,
        }
    }

    #[test]
    fn bare_test_is_test_context() {
        assert!(cfg_entry_mentions_test(&name_test()));
    }

    #[test]
    fn not_test_is_not_test_context() {
        let entry = CfgEntry::Not(Box::new(name_test()), DUMMY_SP);
        assert!(!cfg_entry_mentions_test(&entry));
    }
}
