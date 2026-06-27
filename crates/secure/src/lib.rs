//! secure — RSS 安全原语接缝（redaction / aead / envelope / protection / cookie / pathsafe / password）。
//!
//! 基础层 L0 纯计算：trait 均 sync 静态分发，非 DI port（ADR-004 C1）；值类型字段私有、不 derive serde。

// `#[derive(Redact)]`（securederive）生成 `::secure::…` 绝对路径；secure 内自用经此别名解析自身
// （标准 self-derive 范式，对齐 serde 的 `extern crate self as serde`）。#1360。
extern crate self as secure;

pub mod aead;
pub mod cookie;
pub mod envelope;
pub mod password;
pub mod pathsafe;
pub mod protection;
pub mod redaction;
pub mod refresh;

pub use aead::{Aead, AeadError, Plaintext};
pub use cookie::{CookieCodec, CookieError, CookieValue, CookieValueError};
pub use envelope::{
    CipherAlg, CiphertextEnvelope, ENVELOPE_VERSION, EncryptionMode, EnvelopeError,
};
pub use password::{
    PasswordError, PasswordHash, hash_password, verify_password, verify_password_constant_time,
};
pub use pathsafe::is_safe_segment;
pub use protection::{AadError, DerivedAad, ProtectionAad, ProtectionContext};
// 字段级脱敏策略模型（#1360）：trait `Redact` + 派生宏 `Redact`（同名异命名空间，对齐
// `serde::Serialize` trait+derive 范式）+ 策略类型 + 公开 funnel `redact_struct`（封闭 `Redacted::new`
// 的外部替身）。`Redactor` 是旧 sink 接缝；三个 key/error/url funnel 保留。
pub use redaction::{
    FieldRedaction, LastError, PiiKind, Redact, RedactField, RedactScope, RedactValue, Redacted,
    RedactionMode, Redactor, Sensitivity, redact_error, redact_field, redact_struct,
    redact_url_credentials, safe,
};
pub use refresh::{OpaqueToken, digest};
pub use securederive::Redact;
