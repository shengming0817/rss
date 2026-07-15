//! compile-fail golden（Hard，#1360）：`#[derive(Redact)]` 的 fail-closed 边界——缺标注 /
//! secret+show 误标 / 未知 mode 均编译错误。错误在**宏展开期**产生（早于发出任何 `::secure::` 路径），
//! 故 ui crate 无需依赖 `secure`，无 dev 依赖环。compile-pass + 运行期行为在 `secure` crate 内端到端覆盖。
//!
//! 刷新 golden：`TRYBUILD=overwrite cargo test -p securederive --test ui_trybuild`。

#[test]
fn redact_fail_closed_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
