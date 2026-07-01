//! TxCapability 外部边界编译锁。
//!
//! INVARIANT: PG-TX-CAPABILITY-SEAL-01 { level = "Hard", exec = "verify", source = "trybuild" }：
//! 外部 crate 不能构造 / mint postgres 事务能力令牌；只能由 postgres adapter 在真实
//! `sqlx::Transaction` 内部铸造。

#[test]
fn tx_capability_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/tx_capability_external_construct_fail.rs");
    t.compile_fail("tests/ui/tx_capability_external_mint_fail.rs");
}
