#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
mod aggregate;
mod definition;
mod lifecycle;
pub use aggregate::*;
pub use lifecycle::*;
#[cfg(feature = "integration")]
pub mod measurement;
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
    /// Restart the read from its first page; this does not imply data loss.
    #[error("timeseries snapshot has changed; restart pagination")]
    SnapshotInvalidated,
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
const DIGEST_V1: &[u8] = b"rss.timeseries.v1\0";
fn hasher(domain: &[u8]) -> sha2::Sha256 {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(DIGEST_V1);
    h.update(domain);
    h.update([0]);
    h
}

fn append_canonical<T: serde::Serialize>(
    domain: &[u8],
    value: &T,
    bytes: &mut Vec<u8>,
) -> Result<Digest, Error> {
    use sha2::Digest as _;
    let begin = bytes.len();
    #[cfg(feature = "integration")]
    let start = measurement::encoding_timer();
    if serde_json::to_writer(&mut *bytes, value).is_err() {
        bytes.truncate(begin);
        return Err(Error::InvalidInput);
    }
    let appended = &bytes[begin..];
    #[cfg(feature = "integration")]
    let start = {
        measurement::record(
            if domain == b"sample" {
                "sample_payload"
            } else {
                "definition_payload"
            },
            start,
            appended.len(),
            0,
        );
        measurement::encoding_timer()
    };
    let mut h = hasher(domain);
    h.update(appended);
    let digest = Digest(h.finalize().into());
    #[cfg(feature = "integration")]
    measurement::record(
        if domain == b"sample" {
            "sample_sha"
        } else {
            "definition_sha"
        },
        start,
        0,
        DIGEST_V1.len() + domain.len() + 1 + appended.len(),
    );
    Ok(digest)
}
fn digest<T: serde::Serialize>(domain: &[u8], value: &T) -> Result<Digest, Error> {
    use sha2::Digest as _;
    let mut h = hasher(domain);
    #[cfg(feature = "integration")]
    if let Some(start) = measurement::encoding_timer() {
        let mut count = measurement::Count {
            writer: &mut h,
            bytes: 0,
        };
        serde_json::to_writer(&mut count, value).map_err(|_| Error::InvalidInput)?;
        let bytes = count.bytes;
        measurement::record(
            match domain {
                b"batch" => "batch_sha",
                b"sample" => "sample_sha",
                b"series" => "series_sha",
                b"definition" => "definition_sha",
                _ => "other_sha",
            },
            Some(start),
            bytes,
            bytes + DIGEST_V1.len() + domain.len() + 1,
        );
        return Ok(Digest(h.finalize().into()));
    }
    serde_json::to_writer(&mut h, value).map_err(|_| Error::InvalidInput)?;
    Ok(Digest(h.finalize().into()))
}
