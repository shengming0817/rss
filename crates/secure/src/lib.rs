//! secure — RSS 安全原语接缝（redaction / aead / cookie / pathsafe / password）。
//!
//! 基础层 L0 纯计算：trait 均 sync 静态分发，非 DI port（ADR-004 C1）；值类型字段私有、不 derive serde。

pub mod aead;
pub mod cookie;
pub mod password;
pub mod pathsafe;
pub mod redaction;
pub mod refresh;

pub use aead::{Aead, AeadError, Ciphertext};
pub use cookie::{CookieCodec, CookieError, CookieValue, CookieValueError};
pub use password::{
    PasswordError, PasswordHash, hash_password, verify_password, verify_password_constant_time,
};
pub use pathsafe::is_safe_segment;
pub use redaction::{Redacted, Redactor, redact_error, redact_field, redact_url_credentials};
pub use refresh::{OpaqueToken, digest};
