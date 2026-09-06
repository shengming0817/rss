//! Extracted from consistency/src/projection.rs@5b63e10; envelope ownership removed.
use crate::{Error, ErrorKind};
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};

pub(crate) fn validate_name(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(())
}

/// Position within exactly one tenant/source. Zero is a valid first event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position(u64);
impl Position {
    /// Reject positions outside the common signed PostgreSQL integer range.
    pub const fn new(value: u64) -> Result<Self, Error> {
        if value > i64::MAX as u64 {
            Err(Error::new(ErrorKind::InvalidInput))
        } else {
            Ok(Self(value))
        }
    }
    /// Numeric coordinate, never an identity across sources.
    pub const fn get(self) -> u64 {
        self.0
    }
}
/// Bounded source fetch size.
#[derive(Debug, Clone, Copy)]
pub struct BatchLimit(u32);
impl BatchLimit {
    /// Accept 1 through 1000 records.
    pub const fn new(value: u32) -> Result<Self, Error> {
        if value == 0 || value > 1000 {
            Err(Error::new(ErrorKind::InvalidInput))
        } else {
            Ok(Self(value))
        }
    }
    /// Maximum returned records.
    pub const fn get(self) -> u32 {
        self.0
    }
}
/// A single ordered journal, scoped to one tenant. This is not authentication evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceScope {
    tenant: TenantId,
    source: String,
}
impl SourceScope {
    /// Bind a tenant and validated source name.
    pub fn new(tenant: TenantId, source: impl Into<String>) -> Result<Self, Error> {
        let source = source.into();
        validate_name(&source)?;
        Ok(Self { tenant, source })
    }
    /// Tenant selected by the authenticated application.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Source name.
    pub fn source(&self) -> &str {
        &self.source
    }
}
/// Immutable read-model generation identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectionScope {
    source: SourceScope,
    projection: String,
    generation: String,
}
impl ProjectionScope {
    /// Bind one projection generation to exactly one source.
    pub fn new(
        source: SourceScope,
        projection: impl Into<String>,
        generation: impl Into<String>,
    ) -> Result<Self, Error> {
        let projection = projection.into();
        let generation = generation.into();
        validate_name(&projection)?;
        validate_name(&generation)?;
        Ok(Self {
            source,
            projection,
            generation,
        })
    }
    /// Exact source binding.
    pub const fn source(&self) -> &SourceScope {
        &self.source
    }
    /// Projection name.
    pub fn projection(&self) -> &str {
        &self.projection
    }
    /// Generation name, also required in application read-model keys.
    pub fn generation(&self) -> &str {
        &self.generation
    }
}
/// Immutable fact with encoded application payload. Debug never exposes payload bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Event {
    source: SourceScope,
    position: Position,
    id: String,
    payload: Vec<u8>,
}
impl Event {
    /// Construct a fact. Encoded payloads are bounded to 1 MiB.
    pub fn new(
        source: SourceScope,
        position: Position,
        id: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let id = id.into();
        validate_name(&id)?;
        if payload.len() > 1_048_576 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        Ok(Self {
            source,
            position,
            id,
            payload,
        })
    }
    /// Source binding.
    pub const fn source(&self) -> &SourceScope {
        &self.source
    }
    /// Source-local position.
    pub const fn position(&self) -> Position {
        self.position
    }
    /// Stable fact identity, unchanged on retries.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Application-owned encoded payload, including any application version information.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Digest of exact encoded fact bytes. Position is deliberately excluded.
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.payload).into()
    }
}
impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("position", &self.position)
            .field("payload", &"<redacted>")
            .finish_non_exhaustive()
    }
}
/// Durable replay bound; an empty snapshot differs from a continuously advancing source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayBound {
    /// Read through the currently available committed source.
    Live,
    /// Immutable snapshot; None means the source was empty when captured.
    Through(Option<Position>),
}
/// Durable progress returned by a provider. It grants no write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Last completed source coordinate; None precedes the first event.
    pub position: Option<Position>,
    /// Generation's immutable replay boundary.
    pub bound: ReplayBound,
}
/// Successful settlement of an event and its checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// A new read-model effect was committed.
    Applied,
    /// The same fact had already committed.
    Duplicate,
    /// The application deliberately ignored this event; its checkpoint committed.
    Filtered,
}

/// Fact identity already represented by a caller-prepared generation baseline.
/// A snapshot producer must retain every processed identity, including filtered facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineReceipt {
    source: SourceScope,
    position: Position,
    id: String,
    fingerprint: [u8; 32],
}
impl BaselineReceipt {
    /// Hydrate snapshot receipt metadata. Completeness is the snapshot producer's contract.
    pub fn new(
        source: SourceScope,
        position: Position,
        id: impl Into<String>,
        fingerprint: [u8; 32],
    ) -> Result<Self, Error> {
        let id = id.into();
        validate_name(&id)?;
        Ok(Self {
            source,
            position,
            id,
            fingerprint,
        })
    }
    /// Capture a processed source fact without retaining its payload.
    pub fn from_event(event: &Event) -> Self {
        Self {
            source: event.source.clone(),
            position: event.position,
            id: event.id.clone(),
            fingerprint: event.fingerprint(),
        }
    }
    /// Source whose baseline contains this fact.
    pub const fn source(&self) -> &SourceScope {
        &self.source
    }
    /// Source-local coordinate represented in the baseline.
    pub const fn position(&self) -> Position {
        self.position
    }
    /// Stable fact identity.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Exact encoded fact digest.
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
/// Generation start together with the complete deduplication state of its baseline.
/// Private fields prevent a positioned start being supplied without an explicit receipt set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationStart {
    after: Option<Position>,
    receipts: Vec<BaselineReceipt>,
}
impl GenerationStart {
    /// Begin before the source's first event with an empty read model.
    pub const fn beginning() -> Self {
        Self {
            after: None,
            receipts: Vec::new(),
        }
    }
    /// Resume after a baseline position. Receipts must describe the complete processed prefix;
    /// the library can check coordinates/conflicts, but cannot infer an external snapshot's truth.
    pub fn after(position: Position, receipts: Vec<BaselineReceipt>) -> Result<Self, Error> {
        if receipts.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let mut unique = std::collections::BTreeMap::<String, BaselineReceipt>::new();
        for receipt in receipts {
            if receipt.position > position {
                return Err(Error::new(ErrorKind::InvalidInput));
            }
            if let Some(old) = unique.get(&receipt.id) {
                if old.source != receipt.source || old.fingerprint != receipt.fingerprint {
                    return Err(Error::new(ErrorKind::Conflict));
                }
            } else {
                unique.insert(receipt.id.clone(), receipt);
            }
        }
        Ok(Self {
            after: Some(position),
            receipts: unique.into_values().collect(),
        })
    }
    /// Last coordinate included in the supplied baseline.
    pub const fn position(&self) -> Option<Position> {
        self.after
    }
    /// Complete unique fact identities represented by that baseline.
    pub fn receipts(&self) -> &[BaselineReceipt] {
        &self.receipts
    }
}
