//! Live HashiCorp Vault Transit round-trip（需真 Vault + transit 引擎已 mount + 一个签名 key）。
//! Eligibility 由 Cargo.toml `[[test]] required-features = ["integration"]` 唯一门控（#1978）；
//! 本文件不加同轴 `cfg(feature = "integration")`，也不用 test harness ignore 属性。
//! 缺 ADDR/TOKEN 时 env fail-closed。

use diport::{KeyId, KeyName, KeyProvider, KeyRef, SignRequest, Signer, SigningPurpose};
use secure::{Plaintext, ProtectionContext};
use vault::{SignatureMarshaling, VaultKeyProvider, VaultSigner};
use vocab::tenant::TenantId;

// env fail-closed：缺 ADDR/TOKEN 时 `.expect` 大声失败（不静默跳过），对标 amqp 集成测试。
// item-level expect carve-out（error-handling.md §Carve-out）；Cargo required-features 已挡默认构建。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn sign_round_trip() {
    let addr = std::env::var("RSS_VAULT_TEST_ADDR")
        .expect("RSS_VAULT_TEST_ADDR must be set to run live vault integration tests");
    let token = std::env::var("RSS_VAULT_TEST_TOKEN")
        .expect("RSS_VAULT_TEST_TOKEN must be set to run live vault integration tests");
    let mount = std::env::var("RSS_VAULT_TEST_MOUNT").unwrap_or_else(|_| "transit".to_string());
    let key = std::env::var("RSS_VAULT_TEST_KEY").unwrap_or_else(|_| "rss-test".to_string());
    // dev Vault 多为 plaintext http → new_allow_http；必填 request timeout。
    // Jws：集成测试对接 JWT/JWS 签名用途（raw r‖s，URL-safe base64）。
    let signer = VaultSigner::new_allow_http(
        reqwest::Client::new(),
        addr,
        token,
        mount,
        std::time::Duration::from_secs(30),
        SignatureMarshaling::Jws,
    )
    .expect("valid config");
    let signature = signer
        .sign(SignRequest {
            key: KeyId::new(key),
            purpose: SigningPurpose::new("integration-test"),
            message: b"hello-rss".to_vec().into(),
        })
        .await
        .expect("transit sign");
    // adapter 已 decode 出原始签名字节（剥离 vault:vN: 前缀）；非空即签名成功。
    assert!(!signature.as_bytes().is_empty());
}

#[allow(clippy::expect_used)]
fn field_aad(field: &str) -> secure::DerivedAad {
    let tenant = TenantId::parse("11111111-2222-4333-8444-555555555555").expect("canonical tenant");
    ProtectionContext::authenticated_request(tenant, "settings/db", field, 1)
        .expect("valid protection context")
        .derive()
}

#[allow(clippy::expect_used)]
fn key_name(raw: String) -> KeyName {
    KeyName::try_new(raw).expect("non-empty key")
}

#[allow(clippy::expect_used)]
fn key_provider_from_env() -> (VaultKeyProvider, KeyName) {
    let addr = std::env::var("RSS_VAULT_TEST_ADDR")
        .expect("RSS_VAULT_TEST_ADDR must be set to run live vault integration tests");
    let token = std::env::var("RSS_VAULT_TEST_TOKEN")
        .expect("RSS_VAULT_TEST_TOKEN must be set to run live vault integration tests");
    let mount = std::env::var("RSS_VAULT_TEST_MOUNT").unwrap_or_else(|_| "transit".to_string());
    let key = std::env::var("RSS_VAULT_TEST_KEY").unwrap_or_else(|_| "rss-test".to_string());
    let provider = VaultKeyProvider::new_allow_http(
        reqwest::Client::new(),
        addr,
        token,
        mount,
        std::time::Duration::from_secs(30),
    )
    .expect("valid config");
    (provider, key_name(key))
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn encrypt_decrypt_round_trip() {
    let (provider, key) = key_provider_from_env();
    let aad = field_aad("value");
    let encrypted = provider
        .encrypt(
            key,
            Plaintext::new(b"vault-field-secret".to_vec()),
            aad.clone(),
        )
        .await
        .expect("transit encrypt");
    let decrypted = provider
        .decrypt(
            encrypted.ciphertext().to_vec().into(),
            encrypted.key().clone(),
            aad,
        )
        .await
        .expect("transit decrypt");
    assert_eq!(decrypted.expose(), b"vault-field-secret");
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn decrypt_with_different_aad_fails_closed() {
    let (provider, key) = key_provider_from_env();
    let aad = field_aad("value");
    let encrypted = provider
        .encrypt(key, Plaintext::new(b"vault-field-secret".to_vec()), aad)
        .await
        .expect("transit encrypt");
    let wrong_aad = field_aad("other-field");
    let err = provider
        .decrypt(
            encrypted.ciphertext().to_vec().into(),
            encrypted.key().clone(),
            wrong_aad,
        )
        .await
        .expect_err("AAD mismatch must fail closed");
    assert_eq!(
        err.kind(),
        diport::key_provider::KeyProviderErrorKind::Rejected
    );
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn rewrap_round_trip_preserves_aad_binding() {
    let (provider, key) = key_provider_from_env();
    let aad = field_aad("value");
    let encrypted = provider
        .encrypt(
            key,
            Plaintext::new(b"vault-field-secret".to_vec()),
            aad.clone(),
        )
        .await
        .expect("transit encrypt");
    let rewrapped = provider
        .rewrap(
            encrypted.ciphertext().to_vec().into(),
            KeyRef::new(encrypted.key().name().clone(), encrypted.key().version()),
            aad.clone(),
        )
        .await
        .expect("transit rewrap");
    let decrypted = provider
        .decrypt(
            rewrapped.ciphertext().to_vec().into(),
            rewrapped.key().clone(),
            aad,
        )
        .await
        .expect("transit decrypt after rewrap");
    assert_eq!(decrypted.expose(), b"vault-field-secret");

    let wrong_aad = field_aad("other-field");
    let err = provider
        .decrypt(
            rewrapped.ciphertext().to_vec().into(),
            rewrapped.key().clone(),
            wrong_aad,
        )
        .await
        .expect_err("rewrapped ciphertext must remain AAD-bound");
    assert_eq!(
        err.kind(),
        diport::key_provider::KeyProviderErrorKind::Rejected
    );
}
