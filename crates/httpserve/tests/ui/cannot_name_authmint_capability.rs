//! AUTH-EVIDENCE-MINT-01 Hard：`AuthenticatedMint` 字段私有，外部即便经 trybuild 继承到
//! `authmint` dep 也不可 `AuthenticatedMint(())` 伪造 token；唯一入口是 `capability()`。
//!
//! 注：trybuild 会把被测 crate 的 `[dependencies]`（含 authmint）拷进临时工程，故本 harness
//! **无法**表达「无 authmint dep 的 E0433」；那半段由 deny.toml wrappers + `cargo xtask layer-deps`
//! 在真实 crate 图上 Hard 强制（journeys/域不可依赖 authmint）。
fn main() {
    let _ = authmint::AuthenticatedMint(());
}
