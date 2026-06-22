//! trybuild 回归锁（Medium，ADR-003 §7/§8）：DI port dyn-compatibility 的编译期 Hard 守卫 + 错误形态。
//!
//! - pass：dynosaur Send 端口可 native AFIT impl + `Box<DynX>` / `Arc<DynX>` 构造（dyn-compatible 成立）。
//! - fail：非 dyn-compatible trait（泛型方法）→ `Box<dyn _>` 直接 E0038，锁错误形态——这是 dynosaur
//!   为 DI port 解决的根问题（async fn / 泛型 / 返回 Self 破坏 dyn-compatible），守 §4.6 dos/don'ts。
//!
//! INVARIANT: DIPORT-DYN-COMPAT-01

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/dyn_compatible_pass.rs");
    t.compile_fail("tests/ui/dyn_incompatible_fail.rs");
}
