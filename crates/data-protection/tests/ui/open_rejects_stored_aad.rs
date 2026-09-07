//! FIELDPROT-AAD-DERIVE-FROM-CTX-01：envelope 存储的 AAD 回灌 `open` 必须编译失败。
//!
//! `env.aad()` 返回 `&ProtectionAad`（标识/审计用的存储 AAD）；`Aead::open` 第二参要 `&DerivedAad`
//! （经 `ProtectionContext::derive` 规范编码）。这只证明存储值与派生值的类型区分，不证明授权。

fn misuse<A: rss_data_protection::Aead>(aead: &A, env: &rss_data_protection::CiphertextEnvelope) {
    let _ = aead.open(env, env.aad());
}

fn main() {}
