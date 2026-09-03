//! FIELDPROT-AAD-DERIVE-FROM-CTX-01：envelope 存储的 AAD 回灌 `open` 必须编译失败。
//!
//! `env.aad()` 返回 `&ProtectionAad`（标识/审计用的存储 AAD）；`Aead::open` 第二参要 `&DerivedAad`
//! （只能经 `ProtectionContext::derive` 从受信上下文派生）。把存储 AAD 直接回灌 = 跨租重放绕过，
//! 类型层必须拒绝（`&ProtectionAad` ≠ `&DerivedAad`）。

fn misuse<A: rss_data_protection::Aead>(aead: &A, env: &rss_data_protection::CiphertextEnvelope) {
    let _ = aead.open(env, env.aad());
}

fn main() {}
