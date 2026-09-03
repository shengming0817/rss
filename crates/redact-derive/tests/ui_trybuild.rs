//! production proc-macro closed grammar 的 Medium compile-fail golden（#1360）：`#[derive(Redact)]` 的 fail-closed 边界——缺标注 /
//! secret+show 误标 / 未知 mode 均编译错误。错误在**宏展开期**产生（早于发出任何 `::rss_redact::` 路径），
//! 故 ui crate 无需依赖 `rss-redact`，无 dev 依赖环。compile-pass + 运行期行为由 `rss-redact` 端到端覆盖。
//!
//! 刷新 golden：`TRYBUILD=overwrite cargo test -p rss-redact-derive --test ui_trybuild`。

#[test]
fn redact_fail_closed_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
    t.pass("tests/pass/renamed_dependency.rs");
}
