use crate::{Error, ErrorKind, Id, Scope};
use rss_contract::Timepoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const MAX_BATCH: usize = Batch::MAX_ENCODED_BYTES as usize;
/// Trusted coverage identity and opaque product-owned definition/content references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Coverage {
    id: Id,
    version: Id,
    definition: Id,
    format: Id,
}
impl Coverage {
    /// Bind the coverage ID/version, collection-definition reference and content-format reference.
    /// The product owns their meaning and must authorize them before report admission.
    pub const fn new(id: Id, version: Id, definition: Id, format: Id) -> Self {
        Self {
            id,
            version,
            definition,
            format,
        }
    }
    /// Product-owned boundary within which a complete snapshot can imply absence.
    pub const fn id(&self) -> &Id {
        &self.id
    }
    /// Exact coverage version; a change requires a fresh snapshot baseline.
    pub const fn version(&self) -> &Id {
        &self.version
    }
    /// Exact collection-definition reference; the collection catalog remains product-owned.
    pub const fn definition(&self) -> &Id {
        &self.definition
    }
    /// Opaque content-format/version reference interpreted only by the product.
    pub const fn format(&self) -> &Id {
        &self.format
    }
}
/// One explicit fact operation. Absence of a key in a delta never means deletion.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    key: Id,
    value: Option<Vec<u8>>,
}
impl Change {
    /// Declare a positive fact; Batch validates the key set and complete encoded batch budget.
    pub const fn upsert(key: Id, value: Vec<u8>) -> Self {
        Self {
            key,
            value: Some(value),
        }
    }
    /// Declare explicit removal of this key in a delta; complete snapshots reject delete entries.
    pub const fn delete(key: Id) -> Self {
        Self { key, value: None }
    }
    /// Exact fact key within the report coverage.
    pub const fn key(&self) -> &Id {
        &self.key
    }
    /// Unredacted fact bytes, or None for an explicit delete; an empty byte slice is a value.
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}
impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Change(<redacted>)")
    }
}
/// Complete bounded batch kinds. There is deliberately no fragment-completion protocol.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Body {
    /// Complete successful collection. Absence applies only inside its declared coverage; empty is valid.
    Snapshot(Vec<Change>),
    /// Explicit operations bound to a snapshot and its immediate applicable predecessor.
    Delta {
        /// Snapshot batch ID under this same scope and exact coverage/definition.
        baseline: Id,
        /// Predecessor sequence: must equal the applicable cursor and be one less than this batch.
        previous: u64,
        /// Unique explicit upserts/deletes; missing keys do not imply deletion.
        changes: Vec<Change>,
    },
    /// Incomplete collection, retained for recovery but never applied or used as a baseline.
    Partial(Vec<Change>),
    /// Collection failure, retained without changing facts and requiring a new snapshot.
    Failed {
        /// Product-owned failure code, rather than raw provider diagnostic text.
        code: Id,
    },
}
impl Body {
    /// Authored operations; collection failure returns an empty slice without implying an empty snapshot.
    pub fn changes(&self) -> &[Change] {
        match self {
            Self::Snapshot(v) | Self::Partial(v) | Self::Delta { changes: v, .. } => v,
            Self::Failed { .. } => &[],
        }
    }
    fn normalize(&mut self) -> Result<(), Error> {
        let snapshot = matches!(self, Self::Snapshot(_));
        let changes = match self {
            Self::Snapshot(v) | Self::Partial(v) | Self::Delta { changes: v, .. } => v,
            Self::Failed { .. } => return Ok(()),
        };
        if changes.len() > 4096 || changes.iter().any(|c| snapshot && c.value.is_none()) {
            return Err(ErrorKind::InvalidInput.into());
        }
        changes.sort_by(|a, b| a.key.cmp(&b.key));
        if changes.windows(2).any(|v| v[0].key == v[1].key) {
            return Err(ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireBatch {
    version: u8,
    id: Id,
    sequence: u64,
    observed_at: i64,
    coverage: Coverage,
    body: Body,
}
/// Validated immutable V1 report. JSON is the versioned durable representation, not a product API.
#[derive(Clone, Eq, PartialEq)]
pub struct Batch {
    wire: WireBatch,
    canonical: Vec<u8>,
}
impl std::fmt::Debug for Batch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Batch(<redacted>)")
    }
}
impl Batch {
    /// Maximum canonical report size accepted by the V1 format.
    pub const MAX_ENCODED_BYTES: u32 = 4 * 1024 * 1024;
    /// Construct V1, sort facts by key and enforce the complete-batch bounds.
    /// Reject duplicate keys, snapshot deletes, more than 4,096 entries or canonical JSON
    /// over 4 MiB. Sequence is producer-local; observed time never orders facts.
    pub fn new(
        id: Id,
        sequence: u64,
        observed_at: Timepoint,
        coverage: Coverage,
        body: Body,
    ) -> Result<Self, Error> {
        Self::validated(WireBatch {
            version: 1,
            id,
            sequence,
            observed_at: observed_at.unix_seconds(),
            coverage,
            body,
        })
    }
    fn validated(mut wire: WireBatch) -> Result<Self, Error> {
        if wire.version != 1 || wire.observed_at < 0 {
            return Err(ErrorKind::InvalidInput.into());
        }
        wire.body.normalize()?;
        let mut writer = BoundedEncoding(Vec::new());
        #[cfg(feature = "integration")]
        crate::measurement::update(|w| w.encodes += 1);
        serde_json::to_writer(&mut writer, &wire)?;
        let canonical = writer.0;
        if canonical.len() > MAX_BATCH {
            return Err(ErrorKind::InvalidInput.into());
        }
        Ok(Self { wire, canonical })
    }
    /// Decode only a complete V1 body within 4 MiB and reapply all construction checks.
    /// Unknown fields/versions and invalid values are rejected; object order is normalized.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_BATCH {
            return Err(ErrorKind::InvalidInput.into());
        }
        #[cfg(feature = "integration")]
        crate::measurement::update(|w| w.decodes += 1);
        let batch = Self::validated(serde_json::from_slice(raw)?)?;
        #[cfg(feature = "integration")]
        crate::measurement::update(|w| {
            let changes = match batch.body() {
                Body::Snapshot(v) | Body::Delta { changes: v, .. } | Body::Partial(v) => Some(v),
                Body::Failed { .. } => None,
            };
            w.buffers += batch.canonical.capacity()
                + changes.map_or(0, |v| {
                    v.capacity() * size_of::<Change>()
                        + v.iter()
                            .filter_map(|c| c.value.as_ref())
                            .map(Vec::capacity)
                            .sum::<usize>()
                });
        });
        Ok(batch)
    }
    /// Immutable producer batch ID, scoped by the full stream identity.
    pub const fn id(&self) -> &Id {
        &self.wire.id
    }
    /// Producer-local sequence; unrelated streams must not compare this coordinate.
    pub const fn sequence(&self) -> u64 {
        self.wire.sequence
    }
    /// Exact coverage, definition and format binding for this report.
    pub const fn coverage(&self) -> &Coverage {
        &self.wire.coverage
    }
    /// Declared report kind and unredacted fact operations.
    pub const fn body(&self) -> &Body {
        &self.wire.body
    }
    /// Producer fact time in nonnegative Unix seconds, independent of receipt time and ordering.
    pub const fn observed_at_seconds(&self) -> i64 {
        self.wire.observed_at
    }
    /// Canonical complete V1 JSON bytes, including content; this accessor is not redacted.
    pub fn encode(&self) -> &[u8] {
        &self.canonical
    }
    /// Compute domain-separated SHA-256 over canonical scope and the complete normalized report.
    /// The digest detects changed semantic input; it does not authenticate the producer or prove collection truth.
    pub fn fingerprint(&self, scope: &Scope) -> Result<[u8; 32], Error> {
        #[cfg(feature = "integration")]
        crate::measurement::update(|w| w.fingerprints += 1);
        let mut digest = Sha256::new();
        digest.update(self.fingerprint_prefix(scope)?);
        digest.update(self.encode());
        Ok(digest.finalize().into())
    }
    /// Exact V1 SHA-256 input preceding the canonical report. A storage adapter can
    /// bind this prefix and hash the current durable bytes within its own snapshot.
    pub fn fingerprint_prefix(&self, scope: &Scope) -> Result<Vec<u8>, Error> {
        let scope = scope.encode()?;
        let mut prefix = b"rss-observation-v1".to_vec();
        prefix.extend_from_slice(&(scope.len() as u64).to_be_bytes());
        prefix.extend_from_slice(scope.as_bytes());
        prefix.extend_from_slice(&(self.encode().len() as u64).to_be_bytes());
        Ok(prefix)
    }
}

// Stop allocation at the protocol bound, including Batch::new inputs from an in-process host.
struct BoundedEncoding(Vec<u8>);
impl std::io::Write for BoundedEncoding {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BATCH - self.0.len() {
            return Err(std::io::Error::other("observation batch exceeds limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    } // reason: in-memory bounded writer has no buffered sink.
}
