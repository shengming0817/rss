//! Provider-neutral encrypted-data protection primitives.
//!
//! This crate owns storage encryption types and algorithms. Observable-output redaction remains in
//! `rss-redact`; concrete key providers and cryptographic backends remain outside this package.

pub mod aead;
pub mod blind_index;
pub mod envelope;
pub mod protection;

pub use aead::{Aead, AeadError, Plaintext};
pub use blind_index::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexValue, FilterBits, IndexScope, Transform,
};
pub use envelope::{
    CipherAlg, CiphertextEnvelope, ENVELOPE_VERSION, EncryptionMode, EnvelopeError,
};
pub use protection::{AadError, DerivedAad, ProtectionAad, ProtectionContext};
