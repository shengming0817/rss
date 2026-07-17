//! trybuild 回归锁（Medium，ADR-003 §7/§8）：DI port dyn-compatibility 的编译期 Hard 守卫 + 错误形态。
//!
//! - pass：dynosaur Send 端口可 native AFIT impl + `Box<DynX>` / `Arc<DynX>` 构造（dyn-compatible 成立）。
//! - fail（dyn-compat）：`async fn` in trait 裸 `Box<dyn _>` → E0038，锁 dynosaur 为 DI port 解决的根问题。
//! - fail（unsafe-forbid）：anti-vacuity——`#![forbid(unsafe_code)]` + 手写 unsafe 编不过，锁
//!   DIPORT-UNSAFE-HYGIENE-01 的基线（forbid 非恒真；dynosaur 生成 unsafe 不触发 forbid 是 hygiene 效果）。
//! - fail（arc-not-send）：**全部** async port 的 `Arc<DynX>: !Send`（dynosaur Send 变体非 Sync），锁 #1095
//!   注入形态收口决策——多次调用 async 消费者用泛型静态分发而非 `Arc<DynX>`（anti-vacuity：改 Send+Sync 即破）。
//!
//! INVARIANT: DIPORT-DYN-COMPAT-01 · DIPORT-UNSAFE-HYGIENE-01 · DIPORT-ASYNC-ARC-SEND-01 { level = "Hard", exec = "verify", source = "trybuild" }
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/dyn_compatible_pass.rs");
    t.pass("tests/ui/dead_letter_record_tenant_pass.rs");
    t.compile_fail("tests/ui/dyn_incompatible_fail.rs");
    t.compile_fail("tests/ui/unsafe_forbid_fail.rs");
    t.compile_fail("tests/ui/arc_dyn_ports_not_send.rs");
    t.compile_fail("tests/ui/dead_letter_record_tenant_fail.rs");
    t.compile_fail("tests/ui/dead_letter_record_legacy_source_fail.rs");
    t.compile_fail("tests/ui/envelope_header_private_fields_fail.rs");
    t.compile_fail("tests/ui/message_envelope_private_fields_fail.rs");
    t.compile_fail("tests/ui/publisher_error_legacy_is_transient_fail.rs");
}
