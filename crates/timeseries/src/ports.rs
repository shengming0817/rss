use crate::{
    AggregatePage, AggregateQuery, Batch, Continuation, Definition, DefinitionState, Digest, Error,
    Id, Interval, Page, Query, Scope, Stream, Timestamp, digest,
};
use rss_request_context::Deadline;
use serde::Serialize;
use std::future::Future;
use std::num::{NonZeroU32, NonZeroU64};

/// Exact lookup identity, independent of the latest definition version.
#[derive(Clone, Debug)]
pub struct DefinitionId {
    pub scope: Scope,
    pub key: Id,
    pub version: NonZeroU64,
}
#[derive(Clone, Debug)]
pub enum DefinitionMutation {
    /// CAS against the latest registered version's digest; None means the key is new.
    Register {
        definition: Definition,
        expected_latest: Option<Digest>,
    },
    /// Compare the exact version/digest before retirement. Retirement is irreversible.
    Retire { id: DefinitionId, expected: Digest },
}
#[derive(Clone, Debug)]
pub struct DefinitionRecord {
    pub definition: Definition,
    pub state: DefinitionState,
}

/// Outcome of a mutation. Unknown never implies rollback; recover or retry the
/// same fixed identity/content after reauthorization. No automatic new-ID retry.
#[derive(Clone, Debug)]
pub enum Outcome<T> {
    Accepted(T),
    Replay(T),
    Unknown,
}
/// A missing read is not proof that an unknown mutation never happened.
#[derive(Clone, Debug)]
pub enum Lookup<T> {
    Found(T),
    NotVisible,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atomicity {
    AtomicBatch,
    RecoverableBatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Pending,
    Partial,
    Complete,
}
/// Deployment-specific guarantees, declared by an adapter after validating its
/// configuration. This is not an assertion that every backend shares a transaction.
#[derive(Clone, Debug)]
pub struct Guarantees {
    pub atomicity: Atomicity,
    /// Minimum promised replay horizon from original receipt, never refreshed by replay.
    pub replay_micros: NonZeroU64,
}
#[derive(Clone, Debug)]
pub struct ReceiptQuery {
    pub stream: Stream,
    pub batch_id: Id,
    pub digest: Digest,
}
#[derive(Clone, Debug)]
pub struct Receipt {
    identity: ReceiptQuery,
    received_at: Timestamp,
    new_samples: u32,
    replayed_samples: u32,
    replay_until: Timestamp,
}
/// Validated reconstruction input from a trusted durable provider, not persistence proof.
#[derive(Clone, Debug)]
pub struct ReceiptSnapshot {
    pub identity: ReceiptQuery,
    pub received_at: Timestamp,
    pub new_samples: u32,
    pub replayed_samples: u32,
    pub replay_until: Timestamp,
}
impl Receipt {
    /// Reconstruct an immutable receipt without retaining the entire producer batch.
    /// Providers additionally verify the total against the admitted batch before commit.
    pub fn from_durable(snapshot: ReceiptSnapshot) -> Result<Self, Error> {
        let total = snapshot
            .new_samples
            .checked_add(snapshot.replayed_samples)
            .ok_or(Error::Invariant)?;
        if total == 0
            || total as usize > Batch::MAX_SAMPLES
            || snapshot.replay_until <= snapshot.received_at
        {
            return Err(Error::Invariant);
        }
        Ok(Self {
            identity: snapshot.identity,
            received_at: snapshot.received_at,
            new_samples: snapshot.new_samples,
            replayed_samples: snapshot.replayed_samples,
            replay_until: snapshot.replay_until,
        })
    }
    pub const fn identity(&self) -> &ReceiptQuery {
        &self.identity
    }
    pub const fn received_at(&self) -> Timestamp {
        self.received_at
    }
    pub const fn new_samples(&self) -> u32 {
        self.new_samples
    }
    pub const fn replayed_samples(&self) -> u32 {
        self.replayed_samples
    }
    pub const fn replay_until(&self) -> Timestamp {
        self.replay_until
    }
}
/// Read progress is separate from immutable admission. Complete raw visibility
/// does not imply summary completion or visibility on every replica.
#[derive(Clone, Debug)]
pub struct ReceiptStatus {
    pub receipt: Receipt,
    pub raw: Visibility,
    pub summarized_through: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "operation", rename_all = "camelCase")]
pub enum MaintenanceAction {
    Recompute,
    /// Separate layers; providers reject cleanup that destroys required recovery input.
    Prune {
        raw_before: Timestamp,
        summaries_before: Timestamp,
        receipts_before: Timestamp,
    },
    Delete,
    /// Explicit restoration must match the existing deletion fence.
    Restore {
        deletion_fence: Id,
    },
}
/// No scheduler or arbitrary command payload. Same plan ID with changed content
/// conflicts, and the provider atomically fences each resumable step.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceRequest {
    id: Id,
    selection: crate::Selection,
    window: Interval,
    action: MaintenanceAction,
    max_items: NonZeroU32,
}
impl MaintenanceRequest {
    pub fn new(
        id: Id,
        selection: crate::Selection,
        window: Interval,
        action: MaintenanceAction,
        max_items: NonZeroU32,
    ) -> Result<Self, Error> {
        // Reuse the same scope/window validation, without implementing a query or executor.
        Query::new(
            selection.clone(),
            window,
            crate::QueryBudget {
                max_series: max_items,
                max_points: max_items,
            },
            crate::QueryMode::History,
        )?;
        if let MaintenanceAction::Prune {
            raw_before,
            summaries_before,
            receipts_before,
        } = action
            && [raw_before, summaries_before, receipts_before]
                .iter()
                .any(|t| *t > window.end())
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            id,
            selection,
            window,
            action,
            max_items,
        })
    }
    pub const fn id(&self) -> &Id {
        &self.id
    }
    pub const fn selection(&self) -> &crate::Selection {
        &self.selection
    }
    pub const fn window(&self) -> Interval {
        self.window
    }
    pub const fn action(&self) -> &MaintenanceAction {
        &self.action
    }
    pub const fn max_items(&self) -> NonZeroU32 {
        self.max_items
    }
    pub fn binding(&self) -> Result<Digest, Error> {
        digest(b"maintenance", self)
    }
}
#[derive(Clone, Debug)]
pub enum MaintenanceProgress {
    More { processed: u32, next: Continuation },
    Complete { processed: u32, fence: Id },
}

/// Products authenticate callers and decide exact operation authority. This hook
/// does not grant device registration, activate a generation or bypass storage fences.
#[derive(Clone, Copy, Debug)]
pub enum Access<'a> {
    Definition(&'a DefinitionMutation),
    DefinitionRead(&'a DefinitionId),
    Write(&'a Batch),
    Receipt(&'a ReceiptQuery),
    Query(&'a Query),
    Aggregate(&'a AggregateQuery),
    Maintain(&'a MaintenanceRequest),
}
pub trait Authority {
    fn authorize(&self, access: Access<'_>) -> Result<(), Error>;
}
/// Immutable input bound to a successful product decision. Reauthorize each host
/// operation; do not retain across revocation. There is no public unchecked constructor.
///
/// ```compile_fail
/// let forged = rss_timeseries::Authorized { request: 1u8 };
/// ```
#[derive(Debug)]
pub struct Authorized<T> {
    request: T,
}
impl<T> Authorized<T> {
    pub const fn request(&self) -> &T {
        &self.request
    }
}
macro_rules! authorization {
    ($ty:ty, $variant:ident) => {
        impl Authorized<$ty> {
            pub fn verify(authority: &impl Authority, request: $ty) -> Result<Self, Error> {
                authority.authorize(Access::$variant(&request))?;
                Ok(Self { request })
            }
        }
    };
}
authorization!(DefinitionMutation, Definition);
authorization!(DefinitionId, DefinitionRead);
authorization!(Batch, Write);
authorization!(ReceiptQuery, Receipt);
authorization!(Query, Query);
authorization!(AggregateQuery, Aggregate);
authorization!(MaintenanceRequest, Maintain);

/// Registry persistence is owned by the adapter. Registration must atomically
/// enforce exact-version immutability and latest-version compatibility. Retirement
/// preserves referenced definitions. Read uses Lookup, never a synthetic success.
pub trait DefinitionStore: Send + Sync {
    fn read(
        &self,
        request: &Authorized<DefinitionId>,
        deadline: Deadline,
    ) -> impl Future<Output = Result<Lookup<DefinitionRecord>, Error>> + Send;
    /// Errors certify no effects; otherwise return Unknown.
    fn change(
        &self,
        request: &Authorized<DefinitionMutation>,
        deadline: Deadline,
    ) -> impl Future<Output = Result<Outcome<DefinitionRecord>, Error>> + Send;
}
/// Providers validate the entire batch before effects, then enforce immutable
/// batch/sample identities, retirement, retention and tenant isolation under races.
/// A partial or unconfirmed operation is Unknown, never a confirmed rejection.
/// Expired receipts require retained fences/low-watermarks: absence cannot revive
/// deleted input. Replay guarantees and restoration are never infinite by default.
pub trait Writer: Send + Sync {
    fn guarantees(&self) -> &Guarantees;
    fn write(
        &self,
        batch: &Authorized<Batch>,
        deadline: Deadline,
    ) -> impl Future<Output = Result<Outcome<Receipt>, Error>> + Send;
    fn receipt(
        &self,
        request: &Authorized<ReceiptQuery>,
        deadline: Deadline,
    ) -> impl Future<Output = Result<Lookup<ReceiptStatus>, Error>> + Send;
}
/// Deadline is one absolute budget for every provider stage. Pagination binds the
/// full query and provider read boundary; live pagination is not a snapshot promise.
/// History order is (series digest bytes, source, generation, time, sequence, ID).
/// Latest selects the greatest (time, sequence, ID) per exact series/stream within
/// the requested window, then uses the same deterministic page order.
pub trait Reader: Send + Sync {
    fn query(
        &self,
        request: &Authorized<Query>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> impl Future<Output = Result<Page, Error>> + Send;
    fn aggregate(
        &self,
        request: &Authorized<AggregateQuery>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> impl Future<Output = Result<AggregatePage, Error>> + Send;
}
/// Each step is bounded, reauthorized and fenced by the provider. Continuation
/// must match request.binding() and be validated by the adapter before effects.
/// A failed/expired step with uncertain effects returns Unknown, not an error.
pub trait Maintainer: Send + Sync {
    fn step(
        &self,
        request: &Authorized<MaintenanceRequest>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> impl Future<Output = Result<Outcome<MaintenanceProgress>, Error>> + Send;
}
