//! Live HashiCorp Vault Transit round-trip（需真 Vault + transit 引擎已 mount + signing/encryption keys）。
//!
//! # Runbook
//!
//! Offline harness（无 Vault、无 `integration`；env / anti-vacuity / warm proxy）:
//! ```text
//! ./hack/cargo.sh test -p vault --test live_vault_harness
//! ```
//!
//! Full live（本 target；Cargo `[[test]] required-features = ["integration"]` 唯一门控，#1978）:
//! ```text
//! export RSS_VAULT_TEST_ADDR='http://127.0.0.1:8200'
//! export RSS_VAULT_TEST_TOKEN='…'
//! export RSS_VAULT_TEST_MOUNT='transit'
//! export RSS_VAULT_TEST_SIGNING_KEY='rss-ecdsa'          # ECDSA signing key
//! export RSS_VAULT_TEST_ENCRYPTION_KEY='rss-aes'         # derived AES encryption key（≠ signing）
//! ./hack/cargo.sh test -p vault --features integration --test live_vault
//! ```
//!
//! Warm-outage 仅支持 plaintext `http://` upstream（https 会 fail-loud）；五坐标必填且非空，
//! 无旧单 KEY fallback。本文件不加同轴 `cfg(feature = "integration")`，也不用 harness ignore。

#[path = "live_vault_support.rs"]
mod live_vault_support;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use diport::key_provider::KeyProviderErrorKind;
use diport::{
    KeyId, KeyName, KeyProvider, KeyProviderError, KeyRef, SignRequest, Signer, SigningPurpose,
};
use live_vault_support::{
    LiveVaultInputs, REDACTED, WarmOutageProxy, assert_sensitive_text_absent,
    assert_warm_outage_trace_anti_vacuity,
};

const FIELD_PLAINTEXT: &[u8] = b"vault-field-secret";
const KEY_PROVIDER_ERROR_DISPLAY: &str = "key provider operation failed";
use secure::{Plaintext, ProtectionContext};
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context as LayerContext, Layer};
use tracing_subscriber::prelude::*;
use vault::{SignatureMarshaling, VaultKeyProvider, VaultSigner};
use vocab::tenant::TenantId;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Fail-loud env gate：panic 走 typed error 的 `Display`，避免 `expect` 绕回 `Debug`。
#[allow(clippy::panic)] // live target 缺坐标必须大声失败；消息仅含静态 env 名。
fn require_live_inputs() -> LiveVaultInputs {
    LiveVaultInputs::from_get(|name| std::env::var(name).ok())
        .unwrap_or_else(|error| panic!("{error}"))
}

/// 禁用 idle pool，避免 warm-outage cut 后复用旧连接掩盖 Unavailable。
#[allow(clippy::expect_used)]
fn integration_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .expect("reqwest client")
}

#[allow(clippy::expect_used)]
fn key_name(raw: String) -> KeyName {
    KeyName::try_new(raw).expect("non-empty key")
}

#[allow(clippy::expect_used)]
fn key_provider(
    inputs: &live_vault_support::LiveVaultInputs,
    client: reqwest::Client,
    addr_override: Option<String>,
) -> (VaultKeyProvider, KeyName) {
    let addr = addr_override.unwrap_or_else(|| inputs.addr.clone());
    let provider = VaultKeyProvider::new_allow_http(
        client,
        addr,
        inputs.token.clone(),
        inputs.mount.clone(),
        REQUEST_TIMEOUT,
    )
    .expect("valid config");
    (provider, key_name(inputs.encryption_key.clone()))
}

#[allow(clippy::expect_used)]
fn signer(inputs: &live_vault_support::LiveVaultInputs, client: reqwest::Client) -> VaultSigner {
    VaultSigner::new_allow_http(
        client,
        inputs.addr.clone(),
        inputs.token.clone(),
        inputs.mount.clone(),
        REQUEST_TIMEOUT,
        SignatureMarshaling::Jws,
    )
    .expect("valid config")
}

#[allow(clippy::expect_used)]
fn field_aad(field: &str) -> secure::DerivedAad {
    let tenant = TenantId::parse("11111111-2222-4333-8444-555555555555").expect("canonical tenant");
    ProtectionContext::authenticated_request(tenant, "settings/db", field, 1)
        .expect("valid protection context")
        .derive()
}

/// Adapter live readiness：encrypt → decrypt → mismatched DerivedAAD → Rejected。
/// 复用本 target 的 crypto helper，不复制 composition/settings 生产常量/算法。
#[allow(clippy::expect_used)]
async fn assert_key_provider_live_ready(provider: &VaultKeyProvider, key: KeyName) {
    const PLAINTEXT: &[u8] = b"rss-live-vault-readiness-v1";
    let aad = field_aad("live-readiness");
    let encrypted = provider
        .encrypt(key, Plaintext::new(PLAINTEXT.to_vec()), aad.clone())
        .await
        .expect("live readiness encrypt");
    let decrypted = provider
        .decrypt(
            encrypted.ciphertext().to_vec().into(),
            encrypted.key().clone(),
            aad,
        )
        .await
        .expect("live readiness decrypt");
    assert_eq!(decrypted.expose(), PLAINTEXT);

    let wrong_aad = field_aad("live-readiness-mismatch");
    let err = provider
        .decrypt(
            encrypted.ciphertext().to_vec().into(),
            encrypted.key().clone(),
            wrong_aad,
        )
        .await
        .expect_err("live readiness mismatched AAD must fail closed");
    assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);
}

fn assert_key_provider_error_surface_safe(
    error: &KeyProviderError,
    inputs: &live_vault_support::LiveVaultInputs,
    request_endpoint: &str,
    plaintext_marker: &[u8],
) {
    assert_eq!(
        error.to_string(),
        KEY_PROVIDER_ERROR_DISPLAY,
        "KeyProviderError Display must stay the fixed safe summary"
    );
    let debug = format!("{error:?}");
    assert!(
        debug.contains(REDACTED),
        "KeyProviderError Debug must contain redacted marker"
    );
    assert_sensitive_text_absent(
        &error.to_string(),
        inputs,
        request_endpoint,
        plaintext_marker,
    );
    assert_sensitive_text_absent(&debug, inputs, request_endpoint, plaintext_marker);
}

fn assert_sensitive_values_absent(
    error: &KeyProviderError,
    inputs: &live_vault_support::LiveVaultInputs,
    request_endpoint: &str,
    plaintext_marker: &[u8],
    trace: &str,
) {
    assert_warm_outage_trace_anti_vacuity(trace);
    assert_key_provider_error_surface_safe(error, inputs, request_endpoint, plaintext_marker);
    assert_sensitive_text_absent(trace, inputs, request_endpoint, plaintext_marker);
}

/// 最小 tracing Layer recorder：把 span/event 字段拼进共享缓冲，供脱敏断言读取。
struct TraceRecorder {
    buf: Arc<std::sync::Mutex<String>>,
    _guard: tracing::subscriber::DefaultGuard,
}

struct CaptureLayer {
    buf: Arc<std::sync::Mutex<String>>,
}

struct CaptureVisitor {
    parts: Vec<String>,
}

impl Visit for CaptureVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.parts.push(format!("{field}={value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.parts.push(format!("{field}={value}"));
    }
}

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &tracing::Id, _ctx: LayerContext<'_, S>) {
        let mut visitor = CaptureVisitor {
            parts: vec![format!("span={}", attrs.metadata().name())],
        };
        attrs.record(&mut visitor);
        self.append(visitor.parts);
    }

    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let mut visitor = CaptureVisitor {
            parts: vec![format!("target={}", event.metadata().target())],
        };
        event.record(&mut visitor);
        self.append(visitor.parts);
    }
}

impl CaptureLayer {
    fn append(&self, parts: Vec<String>) {
        let line = parts.join(" ");
        if let Ok(mut guard) = self.buf.lock() {
            guard.push_str(&line);
            guard.push('\n');
        }
    }
}

impl TraceRecorder {
    fn install() -> Self {
        let buf = Arc::new(std::sync::Mutex::new(String::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            buf: Arc::clone(&buf),
        });
        let guard = tracing::subscriber::set_default(subscriber);
        Self { buf, _guard: guard }
    }

    fn dump(&self) -> String {
        self.buf.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |trace| trace.clone(),
        )
    }
}

// env fail-closed：缺 ADDR/TOKEN/MOUNT/SIGNING_KEY/ENCRYPTION_KEY 时大声失败（不静默跳过）。
// item-level panic carve-out（error-handling.md §Carve-out）；Cargo required-features 已挡默认构建。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn sign_round_trip() {
    let inputs = require_live_inputs();
    // Jws：集成测试对接 JWT/JWS 签名用途（raw r‖s，URL-safe base64）。
    let signer = signer(&inputs, integration_client());
    let signature = signer
        .sign(SignRequest {
            key: KeyId::new(inputs.signing_key.clone()),
            purpose: SigningPurpose::new("integration-test"),
            message: b"hello-rss".to_vec().into(),
        })
        .await
        .expect("transit sign");
    // adapter 已 decode 出原始签名字节（剥离 vault:vN: 前缀）；非空即签名成功。
    assert!(!signature.as_bytes().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn decrypt_with_different_aad_fails_closed() {
    let inputs = require_live_inputs();
    let (provider, key) = key_provider(&inputs, integration_client(), None);
    let aad = field_aad("value");
    let encrypted = provider
        .encrypt(key, Plaintext::new(FIELD_PLAINTEXT.to_vec()), aad)
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
    assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn rewrap_round_trip_preserves_aad_binding() {
    let inputs = require_live_inputs();
    let (provider, key) = key_provider(&inputs, integration_client(), None);
    let aad = field_aad("value");
    let encrypted = provider
        .encrypt(key, Plaintext::new(FIELD_PLAINTEXT.to_vec()), aad.clone())
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
    assert_eq!(decrypted.expose(), FIELD_PLAINTEXT);

    let wrong_aad = field_aad("other-field");
    let err = provider
        .decrypt(
            rewrapped.ciphertext().to_vec().into(),
            rewrapped.key().clone(),
            wrong_aad,
        )
        .await
        .expect_err("rewrapped ciphertext must remain AAD-bound");
    assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);
}

/// current_thread：tracing `set_default` 是 thread-local，需与 encrypt 同线程捕获 outage 诊断。
#[tokio::test(flavor = "current_thread")]
#[allow(clippy::expect_used)]
async fn provider_readiness_succeeds_then_warm_outage_fails_closed_without_disclosure() {
    let inputs = require_live_inputs();
    let proxy = WarmOutageProxy::start(&inputs.addr)
        .await
        .expect("start live Vault cut proxy");
    let request_endpoint = proxy.endpoint().to_string();
    let (provider, key) = key_provider(
        &inputs,
        integration_client(),
        Some(request_endpoint.clone()),
    );
    assert_key_provider_live_ready(&provider, key.clone()).await;

    proxy.cut().await.expect("cut live Vault proxy");
    let plaintext_marker = b"rss-live-outage-plaintext";
    let recorder = TraceRecorder::install();
    let error = provider
        .encrypt(
            key,
            Plaintext::new(plaintext_marker.to_vec()),
            field_aad("warm-outage"),
        )
        .await
        .expect_err("warm provider outage must fail closed");
    assert_eq!(error.kind(), KeyProviderErrorKind::Unavailable);
    assert_sensitive_values_absent(
        &error,
        &inputs,
        &request_endpoint,
        plaintext_marker,
        &recorder.dump(),
    );
}
