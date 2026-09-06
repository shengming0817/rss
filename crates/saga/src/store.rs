use crate::{Control, Definition, Error, Event, Scope, Snapshot, Timer};
use std::future::Future;

/// Adapter-issued claim. Implementing a Store is a trusted provider boundary.
#[derive(Clone)]
pub struct Lease {
    scope: Scope,
    token: uuid::Uuid,
    epoch: i64,
}
impl Lease {
    /// Trusted Store implementations mint claims after atomically acquiring a fresh token and positive epoch.
    pub fn from_provider(scope: Scope, token: uuid::Uuid, epoch: i64) -> Result<Self, Error> {
        if epoch <= 0 {
            return Err(Error::new(crate::ErrorKind::Fenced));
        }
        Ok(Self {
            scope,
            token,
            epoch,
        })
    }
    /// Exact tenant/instance authorized by this claim.
    pub const fn scope(&self) -> Scope {
        self.scope
    }
    /// Opaque provider credential. Never log, persist externally or expose it as diagnostics.
    pub const fn token(&self) -> uuid::Uuid {
        self.token
    }
    /// Monotonic takeover generation used with the token to fence every write.
    pub const fn epoch(&self) -> i64 {
        self.epoch
    }
}
/// Only the executor creates mutations; adapters can inspect, validate and persist them.
pub struct Mutation {
    event: Event,
}
impl Mutation {
    pub(crate) fn new(snapshot: &Snapshot, event: Event) -> Result<Self, Error> {
        snapshot.apply(event.clone())?;
        Ok(Self { event })
    }
    /// Closed executor-created transition; persist only after validating lease and expected revision.
    pub fn event(&self) -> &Event {
        &self.event
    }
}
/// Trusted provider boundary for tenant-scoped, lease-fenced atomic Saga persistence.
pub trait Store: Send + Sync {
    /// Atomically register immutable scope/definition metadata. Same identity with changed metadata is a conflict; caller owns authorization.
    fn register<T: Timer>(
        &self,
        scope: Scope,
        definition: &Definition,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// Serialize with prior writes, reject an unexpired holder, then issue a fresh token and monotonic epoch. Use provider time for expiry.
    fn claim<T: Timer>(
        &self,
        scope: Scope,
        ttl: std::time::Duration,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Lease, Error>> + Send;
    /// Extend only the current unexpired token/epoch. Never revive a lost claim; the executor actively renews short leases.
    fn renew<T: Timer>(
        &self,
        lease: &Lease,
        ttl: std::time::Duration,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// Invalidate only the current unexpired claim and acknowledge the change. Never alter journal or instance outcome.
    fn release<T: Timer>(
        &self,
        lease: &Lease,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// Must serialize with prior writes before claiming their absence, and return one snapshot.
    fn snapshot<T: Timer>(
        &self,
        lease: &Lease,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Snapshot, Error>> + Send;
    /// Under one transaction, validate scope, live lease and expected revision, then persist journal, protected receipt and status together. Unknown settlement must return CommitUnknown; never acknowledge staged writes.
    fn commit<T: Timer>(
        &self,
        lease: &Lease,
        mutation: Mutation,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// Return at most limit runnable unleased/expired scopes for this tenant, strictly ascending after the optional UUID. Exclude terminal and explicitly paused instances.
    fn candidates<T: Timer>(
        &self,
        tenant: rss_request_context::TenantId,
        after: Option<uuid::Uuid>,
        limit: u32,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Vec<Scope>, Error>> + Send;
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("scope", &self.scope)
            .field("epoch", &self.epoch)
            .field("token", &"<redacted>")
            .finish()
    }
}
