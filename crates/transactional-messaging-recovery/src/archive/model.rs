use crate::{
    DeadLetterId, OperationId, Version,
    protection::{Capsule, CaptureContext},
};
use rss_request_context::{Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::policy::{OperationDeadline, within};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Closed archive failures; backend diagnostic text is deliberately excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// Invalid coordinates or encoding.
    #[error("invalid archive input")]
    Invalid,
    /// Product denied the exact challenge.
    #[error("archive unauthorized")]
    Unauthorized,
    /// Ownership, revision or request identity changed.
    #[error("archive conflict")]
    Conflict,
    /// Another worker still owns a live lease; retry after its expiry.
    #[error("archive lease busy")]
    Busy,
    /// No matching target exists.
    #[error("archive not found")]
    NotFound,
    /// Policy or actual Object Lock horizon is insufficient.
    #[error("archive retention insufficient")]
    Retention,
    /// Cryptographic authentication or key separation failed.
    #[error("archive protection failed")]
    Protection,
    /// Observed provider facts do not match the prepared object.
    #[error("archive evidence mismatch")]
    Evidence,
    /// Object disappeared before its protected horizon.
    #[error("archive object missing")]
    Missing,
    /// Provider unavailable; write settlement may be unknown.
    #[error("archive provider unavailable")]
    Unavailable,
    /// Schema or effective permissions violate the storage contract.
    #[error("archive storage contract mismatch")]
    StorageContract,
    /// Budget exhausted; no rollback is implied.
    #[error("archive deadline elapsed")]
    Deadline,
}
/// Explicit product policy; no historic fixed 30-day target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Retention {
    hot_seconds: i64,
    cold_seconds: i64,
}
impl Retention {
    /// Positive retention durations in seconds.
    pub fn new(hot_seconds: i64, cold_seconds: i64) -> Result<Self, Error> {
        if hot_seconds <= 0 || cold_seconds <= 0 {
            return Err(Error::Retention);
        }
        Ok(Self {
            hot_seconds,
            cold_seconds,
        })
    }
    /// Required HOT age.
    pub const fn hot_seconds(self) -> i64 {
        self.hot_seconds
    }
    /// Cold retention after the actual purge time.
    pub const fn cold_seconds(self) -> i64 {
        self.cold_seconds
    }
    /// Validate against the authoritative message policy.
    pub fn validate_hot_floor(self, window: i64, safety: i64) -> Result<(), Error> {
        if window <= 0
            || safety <= 0
            || self.hot_seconds < window.checked_add(safety).ok_or(Error::Retention)?
        {
            return Err(Error::Retention);
        }
        Ok(())
    }
    /// Strict lower bound; equality never authorizes deletion.
    pub fn minimum_lock_until(self, now: i64, receipt: i64) -> Result<i64, Error> {
        if receipt <= 0 {
            return Err(Error::Retention);
        }
        now.checked_add(self.cold_seconds.max(receipt))
            .ok_or(Error::Retention)
    }
}
/// Product hold decision, bound to the entire authorized request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hold {
    /// Keep HOT bytes.
    Retain,
    /// Permit cleanup once every other predicate is satisfied.
    Release,
}
/// Immutable, exact archive operation. Retries must retain this identity and all inputs.
#[derive(Clone, Debug)]
pub struct Request {
    tenant: TenantId,
    id: DeadLetterId,
    operation: OperationId,
    version: Version,
    retention: Retention,
    hold: Hold,
}
impl Request {
    /// Construct a request before product authorization.
    pub fn new(
        tenant: TenantId,
        id: DeadLetterId,
        operation: OperationId,
        version: Version,
        retention: Retention,
        hold: Hold,
    ) -> Self {
        Self {
            tenant,
            id,
            operation,
            version,
            retention,
            hold,
        }
    }
    /// Tenant.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Existing consumer dead letter identity.
    pub const fn id(&self) -> DeadLetterId {
        self.id
    }
    /// Stable operation identity.
    pub const fn operation(&self) -> OperationId {
        self.operation
    }
    /// Expected recovery revision.
    pub const fn version(&self) -> Version {
        self.version
    }
    /// Product retention snapshot.
    pub const fn retention(&self) -> Retention {
        self.retention
    }
    /// Product hold decision.
    pub const fn hold(&self) -> Hold {
        self.hold
    }
    /// Complete request identity for durable retry binding.
    pub fn digest(&self) -> [u8; 32] {
        crate::model::hash(&[
            "rss-archive-request-v1",
            &self.tenant.to_string(),
            &self.id.to_string(),
            &self.operation.to_string(),
            &self.version.get().to_string(),
            &self.retention.hot_seconds.to_string(),
            &self.retention.cold_seconds.to_string(),
            match self.hold {
                Hold::Retain => "hold",
                Hold::Release => "release",
            },
        ])
    }
}
/// Library-issued challenge to the trusted product authorization implementation.
pub struct Challenge<'a>(pub(crate) &'a Request);
impl Challenge<'_> {
    /// Exact facts the product must authorize.
    pub const fn request(&self) -> &Request {
        self.0
    }
    /// Record the product decision; does not authenticate an identity.
    pub fn authorized(self) -> Authorization {
        Authorization(self.0.digest())
    }
}
/// Opaque exact-request authorization.
pub struct Authorization([u8; 32]);
/// Product authentication and policy boundary.
pub trait Authorizer: Send + Sync {
    /// Authorize every requested field within the supplied budget.
    fn authorize(
        &self,
        challenge: Challenge<'_>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Authorization, Error>> + Send;
}
/// Authorized request; cannot be assembled from unchecked inputs.
pub struct AuthorizedRequest(Request);
impl AuthorizedRequest {
    /// Immutable authorized intent.
    pub const fn request(&self) -> &Request {
        &self.0
    }
}
/// Obtain exact request authority under a core-enforced absolute cutoff.
/// An elapsed cutoff never invokes the authorizer; timeout cannot produce an authorized request.
pub async fn authorize<A: Authorizer, C: ExecutionTimer>(
    authorizer: &A,
    request: Request,
    clock: &C,
    cutoff: Deadline,
) -> Result<AuthorizedRequest, Error> {
    let proof = within(clock, cutoff, |deadline| {
        authorizer.authorize(Challenge(&request), deadline)
    })
    .await
    .map_err(|_| Error::Deadline)??;
    if proof.0 != request.digest() {
        return Err(Error::Unauthorized);
    }
    Ok(AuthorizedRequest(request))
}
/// Trusted PG snapshot of a consumer capsule. No payload or key is exposed through Debug.
pub struct Candidate {
    /// Independently derived capture coordinates.
    pub context: CaptureContext,
    /// Authenticated only after opening with those coordinates.
    pub capsule: Capsule,
    /// Closed terminal rejection label.
    pub reason: rss_transactional_messaging::transaction::RejectKind,
    /// Database capture time, in epoch microseconds.
    pub captured_at: i64,
}
/// Persisted coordinates, never themselves a verified proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Object {
    /// Stable tenant/record/generation key.
    pub key: String,
    /// SHA-256 of exact ciphertext bytes.
    pub checksum: [u8; 32],
    /// Bounded ciphertext length.
    pub length: u64,
    /// Actual immutable version, absent only before upload.
    pub version: Option<String>,
    /// Explicit Object Lock expiration, seconds since epoch.
    pub retain_until: i64,
}
impl std::fmt::Debug for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchiveObject(<redacted>)")
    }
}
/// One persist-once randomized encryption result.
#[derive(Clone)]
pub struct Prepared {
    /// Expected object facts.
    pub object: Object,
    /// Opaque bytes. Never log these.
    pub bytes: Vec<u8>,
}
impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prepared(<redacted>)")
    }
}
/// Database-issued lease, snapshot and previous progress. Providers are trusted to hydrate it correctly.
pub struct Claim {
    /// Earlier immutable versions awaiting expiry reconciliation; bounded by the repository.
    pub retired: Vec<Object>,
    /// Stable archive generation.
    pub generation: String,
    /// Unpredictable fencing token.
    pub token: String,
    /// Current request digest.
    pub request_digest: [u8; 32],
    /// Persisted source when HOT remains.
    pub candidate: Option<Candidate>,
    /// Prepared bytes for safe replay of unknown PUTs.
    pub prepared: Option<Prepared>,
    /// Durable verified receipt, when available.
    pub object: Option<Object>,
    /// Database time observed after target locking.
    pub now: i64,
    /// Earliest HOT cleanup time.
    pub hot_until: i64,
    /// Authoritative recovery receipt horizon duration.
    pub receipt_seconds: i64,
    /// Whether HOT has already been removed.
    pub purged: bool,
}
/// Actual provider response for an exact object version.
pub struct Observation {
    /// Coordinates and checksum returned by the real provider.
    pub object: Object,
    /// Whether the version is locked in Compliance mode.
    pub compliance: bool,
    /// Actual body, when requested for checksum verification.
    pub bytes: Option<Vec<u8>>,
}
/// Only the lifecycle verifier can construct this receipt.
/// ```compile_fail
/// use rss_transactional_messaging_recovery::archive::Verified;
/// fn forge(object: rss_transactional_messaging_recovery::archive::Object) -> Verified {
///     Verified { object, digest: [0; 32], generation: String::new() }
/// }
/// ```
pub struct Verified {
    pub(crate) object: Object,
    pub(crate) digest: [u8; 32],
    pub(crate) generation: String,
}
impl Verified {
    /// Verified exact coordinates, for the trusted persistence implementation.
    pub const fn object(&self) -> &Object {
        &self.object
    }
    /// Complete request identity.
    pub const fn request_digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Archive generation binding.
    pub fn generation(&self) -> &str {
        &self.generation
    }
}
/// Exact-version missing proof, minted only after the protected horizon.
/// ```compile_fail
/// use rss_transactional_messaging_recovery::archive::Missing;
/// fn forge(object: rss_transactional_messaging_recovery::archive::Object) -> Missing {
///     Missing { object, digest: [0; 32], generation: String::new() }
/// }
/// ```
pub struct Missing {
    pub(crate) object: Object,
    pub(crate) digest: [u8; 32],
    pub(crate) generation: String,
}
impl Missing {
    /// Previously persisted object.
    pub const fn object(&self) -> &Object {
        &self.object
    }
    /// Exact authorized request.
    pub const fn request_digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Archive generation.
    pub fn generation(&self) -> &str {
        &self.generation
    }
}
pub(crate) fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
