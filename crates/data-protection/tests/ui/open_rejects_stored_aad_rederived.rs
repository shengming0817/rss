//! Stored AAD has no coordinate getters. This is an API visibility boundary, not authorization:
//! callers that already know the coordinates can derive the same AAD using ProtectionContext::new.

fn misuse<A: rss_data_protection::Aead>(aead: &A, env: &rss_data_protection::CiphertextEnvelope) {
    let stored = env.aad();
    let ctx = rss_data_protection::ProtectionContext::new(
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
