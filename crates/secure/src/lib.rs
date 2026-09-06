//! Internal security utilities that have not yet moved to their final capability owners.
//!
//! 基础层 L0 纯计算：trait 均 sync 静态分发，非 DI port（ADR-004 C1）；值类型字段私有、不 derive serde。

pub mod cookie;
pub mod password;
pub mod pathsafe;
pub mod pseudonym;
pub mod refresh;
pub mod transport_endpoint;

pub use cookie::{CookieCodec, CookieError, CookieValue, CookieValueError};
pub use password::{
    DigestPasswordBlocklist, PasswordError, PasswordHash, PasswordPolicy, PasswordPolicyError,
    PasswordVerification, RawPassword, ValidatedPassword, VerifiedPassword, verify_password,
};
pub use pathsafe::is_safe_segment;
pub use pseudonym::{
    PseudonymError, PseudonymKeyId, PseudonymKeyRing, PseudonymRef, VersionedPseudonymKey,
};
pub use refresh::{OpaqueToken, digest};
pub use transport_endpoint::{
    DomainHttpEndpoint, PlaintextEndpointPolicy, RedisEndpoint, S3Endpoint, TransportEndpointError,
};
