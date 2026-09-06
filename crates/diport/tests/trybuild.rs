//! trybuild 回归锁（Medium anti-vacuity，ADR-003 §7/§8）：DI port dyn-compatibility 与
//! concurrency-bucket 错误形态。Hard 证据在 `effect.rs`：`classify_ports!` + sealed
//! `DiPortConcurrency` + macro-internal `assert_send_sync_bound`（DIPORT-DYN-CONCURRENCY-01
//! native-compile）——**不得**把 trybuild 标成 Hard。
//!
//! - pass：representative dynosaur ports remain `new_box` / `new_arc` injectible.
//! - pass（async_sync）：`classify_ports!` `async_sync` bucket ⇒ `Arc<DynX>: Send + Sync`.
//! - fail（dyn-compat）：`async fn` in trait 裸 `Box<dyn _>` → E0038，锁 dynosaur 为 DI port 解决的根问题。
//! - fail（unsafe-forbid）：anti-vacuity——`#![forbid(unsafe_code)]` + 手写 unsafe 编不过，锁
//!   DIPORT-UNSAFE-HYGIENE-01 的基线（forbid 非恒真；dynosaur 生成 unsafe 不触发 forbid 是 hygiene 效果）。
//! - fail（arc-not-send）：`async_send` bucket 的 `Arc<DynX>: !Send`（macro-expanded exact set），锁
//!   #1095 / #1331 注入形态收口；`async_sync` 正向证据在 `async_sync_arc_send_sync_pass.rs`。
//!
//! ## TRYBUILD=overwrite discipline
//!
//! `async_send` / `async_sync` 集合变更时，macro-expanded compile-fail stderr 会按端口数 churn
//! （每端口一块 E0277）。这是 exact-set 证明的代价，**不要**手改 stderr 去「稳定」文案。
//! 本地流程：改 `classify_ports!` → `TRYBUILD=overwrite cargo test -p diport --test trybuild`
//! 重写 `tests/ui/*.stderr` → 审 diff（只应反映表变更）→ 提交。工具链 / rustc 诊断文案漂移同此。
//!
//! INVARIANT: DIPORT-DYN-COMPAT-01 · DIPORT-UNSAFE-HYGIENE-01 { level = "Medium", exec = "test", source = "trybuild" }
//! INVARIANT: DIPORT-ASYNC-ARC-SEND-01 · DIPORT-DYN-CONCURRENCY-01 { level = "Medium", exec = "test", source = "trybuild" }
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/dyn_compatible_pass.rs");
    t.pass("tests/ui/async_sync_arc_send_sync_pass.rs");
    t.pass("tests/ui/dead_letter_record_tenant_pass.rs");
    t.compile_fail("tests/ui/dyn_incompatible_fail.rs");
    t.compile_fail("tests/ui/unsafe_forbid_fail.rs");
    t.compile_fail("tests/ui/arc_dyn_ports_not_send.rs");
    t.compile_fail("tests/ui/dead_letter_record_tenant_fail.rs");
}
