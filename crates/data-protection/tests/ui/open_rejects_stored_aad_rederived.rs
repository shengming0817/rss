//! FIELDPROT-AAD-DERIVE-FROM-CTX-01：stored AAD 不能被拆字段后重新 mint 成 DerivedAad。
//!
//! 如果 envelope 中的 `ProtectionAad` 暴露 tenant/config-key/field/schema-version getter，调用方可把
//! stored coordinates 喂回 `ProtectionContext::authenticated_request(...).derive()`，绕过“open 必须从受信
//! 上下文重新派生 AAD”的类型墙。本红例锁住 stored AAD 只可作为不透明审计坐标，不能作为派生凭证。

fn misuse<A: rss_data_protection::Aead>(aead: &A, env: &rss_data_protection::CiphertextEnvelope) {
    let stored = env.aad();
    let ctx = rss_data_protection::ProtectionContext::authenticated_request(
        stored.tenant(),
        stored.config_key(),
        stored.field(),
        stored.schema_version(),
    )
    .expect("stored aad must not be reusable")
    .derive();
    let _ = aead.open(env, &ctx);
}

fn main() {}
