//! Extracted from consistency/src/projection.rs@5b63e10; envelope ownership removed.
use crate::{Error, ErrorKind};
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};

pub(crate) fn validate_name(value: &str) -> Result<(), Error> {
    validate_identity(value, 128)
}

fn validate_identity(value: &str, max_bytes: usize) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(())
}

/// Caller-declared identity of an exact projection definition and schema.
/// The library compares these opaque bytes; it does not hash or verify SQL, binaries or closures.
/// A changed definition requires a new generation, not a second identity for the same generation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefinitionIdentity([u8; 32]);
impl DefinitionIdentity {
    /// Declare an identity. The caller owns its meaning and stable derivation.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Exact bytes for persistence and comparison.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for DefinitionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DefinitionIdentity(<redacted>)")
    }
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
/// Bounded record count for a read or a settlement batch.
#[derive(Debug, Clone, Copy)]
pub struct BatchLimit(u32);
impl BatchLimit {
    /// Accept 1 through 1024 records.
    pub const fn new(value: u32) -> Result<Self, Error> {
        if value == 0 || value > 1024 {
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
/// Caller-selected limits for each source page. Bytes count only encoded event payloads.
#[derive(Debug, Clone, Copy)]
pub struct PageBudget {
    rows: BatchLimit,
    payload_bytes: u32,
}
impl PageBudget {
    /// Allow 1–1024 rows and a positive number of encoded payload bytes per page.
    pub fn new(rows: u32, payload_bytes: u32) -> Result<Self, Error> {
        if payload_bytes == 0 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        Ok(Self {
            rows: BatchLimit::new(rows)?,
            payload_bytes,
        })
    }
    /// Maximum event count, independently of payload sizes.
    pub const fn rows(self) -> u32 {
        self.rows.get()
    }
    /// Maximum sum of `Event::payload().len()` across this page.
    pub const fn payload_bytes(self) -> u32 {
        self.payload_bytes
    }
}

/// Result of one ordered source read. A short nonempty page can have a successor.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadPage<I> {
    /// Committed prefix. Empty only when the cursor has no visible successor.
    Events(Vec<I>),
    /// The first successor cannot fit in a fresh page. No body or progress is returned.
    Blocked {
        /// Position of the first successor.
        position: Position,
        /// Exact encoded payload length needed to admit it.
        required_bytes: u32,
    },
}
/// A single ordered journal, scoped to one tenant. This is not authentication evidence.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SourceScope {
    tenant: TenantId,
    source: String,
}
impl std::fmt::Debug for SourceScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceScope(<redacted>)")
    }
}
impl SourceScope {
    /// Bind a tenant and validated source name.
    pub fn new(tenant: TenantId, source: impl Into<String>) -> Result<Self, Error> {
        let source = source.into();
        validate_identity(&source, 255)?;
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
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProjectionScope {
    source: SourceScope,
    projection: String,
    generation: String,
}
impl std::fmt::Debug for ProjectionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProjectionScope(<redacted>)")
    }
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
        validate_identity(&projection, 255)?;
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
/// Read-only lookup of a stable fact identity in one exact projection definition.
/// This value grants no authentication or worker authority. It does not assert payload bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiptQuery {
    scope: ProjectionScope,
    definition: DefinitionIdentity,
    event_id: String,
}
impl ReceiptQuery {
    /// Bind the generation, expected definition and validated stable event ID.
    pub fn new(
        scope: ProjectionScope,
        definition: DefinitionIdentity,
        event_id: impl Into<String>,
    ) -> Result<Self, Error> {
        let event_id = event_id.into();
        validate_name(&event_id)?;
        Ok(Self {
            scope,
            definition,
            event_id,
        })
    }
    /// Exact tenant/source/projection/generation being inspected.
    pub const fn scope(&self) -> &ProjectionScope {
        &self.scope
    }
    /// Definition the reader expects for this generation.
    pub const fn definition_identity(&self) -> &DefinitionIdentity {
        &self.definition
    }
    /// Stable source fact ID, independent of its delivery position.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
}
impl std::fmt::Debug for ReceiptQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceiptQuery(<redacted>)")
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
mod sealed {
    pub trait EventInput {}
}

/// An input whose framework identity is fixed throughout execution and across clones.
/// Sources can attach their own data with [`Event::with_data`]. The source cannot
/// redefine which event is used for ordering, fencing, receipts or progress.
///
/// ```compile_fail
/// use rss_projection::{Event, EventInput};
/// use std::sync::atomic::{AtomicBool,Ordering};
/// struct Switching { facts: [Event; 2], next: AtomicBool }
/// impl AsRef<Event> for Switching {
///     fn as_ref(&self) -> &Event { &self.facts[self.next.load(Ordering::Relaxed) as usize] }
/// }
/// impl EventInput for Switching {}
/// ```
pub trait EventInput: sealed::EventInput + AsRef<Event> + Send + Sync {}
impl sealed::EventInput for Event {}
impl EventInput for Event {}

/// One immutable event and its page-owned application data. Clones share both.
pub struct EventWith<T>(std::sync::Arc<EventData<T>>);
struct EventData<T> {
    event: Event,
    data: T,
}
impl<T> EventWith<T> {
    /// Borrow the associated data without separating ownership from its event.
    pub fn data(&self) -> &T {
        &self.0.data
    }
}
impl<T> Clone for EventWith<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> AsRef<Event> for EventWith<T> {
    fn as_ref(&self) -> &Event {
        &self.0.event
    }
}
impl<T> std::fmt::Debug for EventWith<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.event.fmt(f)
    }
}
impl<T> sealed::EventInput for EventWith<T> {}
impl<T: Send + Sync> EventInput for EventWith<T> {}
impl AsRef<Event> for Event {
    fn as_ref(&self) -> &Event {
        self
    }
}
impl Event {
    /// Maximum encoded application payload of a single event, in bytes.
    pub const MAX_PAYLOAD_BYTES: u32 = 1024 * 1024;

    /// Attach typed data to this exact event for one local handoff.
    pub fn with_data<T>(self, data: T) -> EventWith<T> {
        EventWith(std::sync::Arc::new(EventData { event: self, data }))
    }

    /// Construct a fact. Encoded payloads are bounded to 1 MiB.
    pub fn new(
        source: SourceScope,
        position: Position,
        id: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let id = id.into();
        validate_name(&id)?;
        if payload.len() > Self::MAX_PAYLOAD_BYTES as usize {
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
/// Read-only observation of one generation and event identity. No worker authority is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// The requested generation has not been initialized.
    Uninitialized,
    /// The generation exists, but this fact has no committed receipt at the observed snapshot.
    Pending(Checkpoint),
    /// The fact has a committed receipt, including filtered facts and imported baseline facts.
    Settled(Checkpoint),
}
impl ReceiptStatus {
    /// Progress from the same database snapshot as the receipt lookup.
    pub const fn checkpoint(self) -> Option<Checkpoint> {
        match self {
            Self::Uninitialized => None,
            Self::Pending(checkpoint) | Self::Settled(checkpoint) => Some(checkpoint),
        }
    }
    /// Whether the stable fact identity has a receipt; not a payload or external effect assertion.
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Settled(_))
    }
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
#[derive(Clone, PartialEq, Eq)]
pub struct BaselineReceipt {
    source: SourceScope,
    position: Position,
    id: String,
    fingerprint: [u8; 32],
}
impl std::fmt::Debug for BaselineReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BaselineReceipt(<redacted>)")
    }
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
#[derive(Clone, PartialEq, Eq)]
pub struct GenerationStart {
    after: Option<Position>,
    receipts: Vec<BaselineReceipt>,
}
impl std::fmt::Debug for GenerationStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GenerationStart(<redacted>)")
    }
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
