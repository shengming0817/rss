#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
mod aggregate;
mod definition;
mod lifecycle;
pub use aggregate::*;
pub use lifecycle::*;
mod model;
mod ports;
mod query;
mod value;
pub use definition::*;
pub use model::*;
pub use ports::*;
pub use query::*;
pub use value::*;

/// Closed, payload-free failures. A write error promises rejection before effects;
/// uncertain effects belong exclusively to `Outcome::Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid timeseries input")]
    InvalidInput,
    #[error("timeseries budget exceeded")]
    BudgetExceeded,
    #[error("timeseries numeric overflow or precision loss")]
    NumericRange,
    #[error("timeseries identity conflict")]
    Conflict,
    #[error("timeseries definition is incompatible")]
    IncompatibleDefinition,
    #[error("timeseries definition is retired")]
    Retired,
    #[error("timeseries operation is unsupported")]
    Unsupported,
    #[error("timeseries access denied")]
    Unauthorized,
    #[error("timeseries continuation is invalid")]
    InvalidCursor,
    #[error("timeseries history has expired")]
    HistoryExpired,
    #[error("timeseries deadline exceeded")]
    Deadline,
    #[error("timeseries provider unavailable")]
    Unavailable,
    #[error("timeseries provider invariant violated")]
    Invariant,
}

/// SHA-256 content identity, never an authentication or durability proof.
#[derive(Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Digest([u8; 32]);
impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Digest([redacted])")
    }
}
// V1 is typed serde JSON (not a serde_json::Value roundtrip): field order is
// declared, maps are BTreeMap, numbers retain tagged i64/u64/f64 identity.
// Domain and encoding version prevent cross-kind reuse. This is not a wire API.
fn digest<T: serde::Serialize>(domain: &[u8], value: &T) -> Result<Digest, Error> {
    use sha2::{Digest as _, Sha256};
    let bytes = serde_json::to_vec(value).map_err(|_| Error::InvalidInput)?;
    let mut h = Sha256::new();
    h.update(b"rss.timeseries.v1\0");
    h.update(domain);
    h.update([0]);
    h.update(bytes);
    Ok(Digest(h.finalize().into()))
}
