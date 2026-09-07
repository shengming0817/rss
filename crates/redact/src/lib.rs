#![doc = include_str!("../README.md")]

mod error_summary;
mod redacted_bytes;
mod redacted_source;
pub mod redaction;
mod secret_text;
#[cfg(test)]
mod secret_text_tests;

pub use error_summary::{ErrorSummary, LastError};
pub use redacted_bytes::RedactedBytes;
pub use redacted_source::RedactedSource;
pub use redaction::{
    FieldRedaction, PiiKind, Redact, RedactField, RedactScope, RedactValue, Redacted,
    RedactionHashError, RedactionHashKey, RedactionMode, Redactor, redact_field, redact_hash,
    redact_observation_field, redact_struct, redact_url_credentials, safe,
};
#[cfg(feature = "derive")]
pub use rss_redact_derive::Redact;
pub use secret_text::SecretText;
