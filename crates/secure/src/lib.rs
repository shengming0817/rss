//! secure — RSS 安全原语接缝（redaction / aead / envelope / protection / cookie / pathsafe / password）。
//!
//! 基础层 L0 纯计算：trait 均 sync 静态分发，非 DI port（ADR-004 C1）；值类型字段私有、不 derive serde。

// `#[derive(Redact)]`（securederive）生成 `::secure::…` 绝对路径；secure 内自用经此别名解析自身
// （标准 self-derive 范式，对齐 serde 的 `extern crate self as serde`）。#1360。
extern crate self as secure;

pub mod aead;
pub mod blind_index;
pub mod cookie;
pub mod envelope;
pub mod password;
pub mod pathsafe;
pub mod protection;
pub mod pseudonym;
pub mod redaction;
pub mod refresh;
pub mod saga_receipt_integrity;
mod secret_text;
#[cfg(test)]
mod secret_text_tests;
pub mod transport_endpoint;

pub use aead::{Aead, AeadError, Plaintext};
pub use blind_index::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexValue, FilterBits, IndexScope, Transform,
};
// `index` / `lookup_set` / `SubKey` / `compute` 等低层原语为 crate-visible：
// 强制消费方通过 `BlindIndex` funnel（统一 transform 链），杜绝绕过 scope/transform 绑定。
pub use cookie::{CookieCodec, CookieError, CookieValue, CookieValueError};
pub use envelope::{
    CipherAlg, CiphertextEnvelope, ENVELOPE_VERSION, EncryptionMode, EnvelopeError,
};
pub use password::{
    DigestPasswordBlocklist, PasswordError, PasswordHash, PasswordPolicy, PasswordPolicyError,
    PasswordVerification, RawPassword, ValidatedPassword, VerifiedPassword, verify_password,
};
pub use pathsafe::is_safe_segment;
pub use protection::{
    AadError, DerivedAad, ProtectionAad, ProtectionContext, SagaReceiptProtectionContext,
    SagaReceiptProtectionCoordinates,
};
pub use pseudonym::{
    PseudonymError, PseudonymKeyId, PseudonymKeyRing, PseudonymRef, VersionedPseudonymKey,
};
// 字段级脱敏策略模型（#1360）：trait `Redact` + 派生宏 `Redact`（同名异命名空间，对齐
// `serde::Serialize` trait+derive 范式）+ 策略类型 + 公开 funnel `redact_struct`（封闭 `Redacted::new`
// 的外部替身）。`Redactor` 是旧 sink 接缝；三个 key/error/url funnel 保留。
pub use redaction::{
    FieldRedaction, LastError, PiiKind, Redact, RedactField, RedactScope, RedactValue, Redacted,
    RedactionHashError, RedactionHashKey, RedactionMode, Redactor, Sensitivity, redact_error,
    redact_field, redact_hash, redact_observation_field, redact_struct, redact_url_credentials,
    safe,
};
pub use refresh::{OpaqueToken, digest};
pub use saga_receipt_integrity::{
    SagaReceiptFingerprint, SagaReceiptIntegrityError, SagaReceiptIntegrityKeyId,
    SagaReceiptIntegrityKeyring, VersionedSagaReceiptIntegrityKey,
};
pub use secret_text::SecretText;
pub use securederive::Redact;
pub use transport_endpoint::{
    AmqpEndpoint, DomainHttpEndpoint, PlaintextEndpointPolicy, RedisEndpoint, S3Endpoint,
    TransportEndpointError,
};
