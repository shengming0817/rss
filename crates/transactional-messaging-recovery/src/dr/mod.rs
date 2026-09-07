//! Bounded, externally selected message disaster recovery. No restore orchestration lives here.
use crate::{Error, OperationId, Version};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, StorageIdentity},
    inbox::ConsumerIdentity,
    message::{MessageFingerprint, MessageId},
    policy::OperationDeadline,
    transaction::LocalTxAttempt,
};
use sha2::{Digest, Sha256};

/// Opaque hashes of exact restore-point evidence verified by the product authorizer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RestoreEvidence {
    database: [u8; 32],
    broker: [u8; 32],
}
impl RestoreEvidence {
    /// Evidence is mandatory; hashes identify external facts, they do not authenticate them.
    pub fn new(database: [u8; 32], broker: [u8; 32]) -> Result<Self, Error> {
        if database == [0; 32] || broker == [0; 32] {
            return Err(Error::Evidence);
        }
        Ok(Self { database, broker })
    }
    /// Database restore evidence digest.
    pub const fn database(self) -> [u8; 32] {
        self.database
    }
    /// Broker restore evidence digest.
    pub const fn broker(self) -> [u8; 32] {
        self.broker
    }
}
/// Selected direction, never inferred by comparing timestamps from different systems.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Retained Outbox publication needs another bounded delivery to the restored broker.
    DatabaseAhead,
    /// Retained broker deliveries must pass through ordinary verified consumption.
    BrokerAhead,
}
/// Exact facts authorized for this recovery. A plan contains only one member kind.
#[derive(Clone, Eq, PartialEq)]
pub enum Member {
    /// Original, successfully published Outbox fact.
    Outbox {
        /// Stable message identity.
        message: MessageId,
        /// Immutable authored fact digest.
        fingerprint: MessageFingerprint,
        /// Expected per-message recovery version.
        version: Version,
    },
    /// Full subscription identity for ordinary consumption, including consumer group.
    Consumer {
        /// Exact tenant/message/group/contract identity.
        identity: ConsumerIdentity,
        /// Authored fact digest expected at trusted ingress.
        fingerprint: MessageFingerprint,
    },
}
impl Member {
    /// Canonical direction for the member type.
    pub const fn direction(&self) -> Direction {
        match self {
            Self::Outbox { .. } => Direction::DatabaseAhead,
            Self::Consumer { .. } => Direction::BrokerAhead,
        }
    }
    /// Stable message identity.
    pub fn message(&self) -> &MessageId {
        match self {
            Self::Outbox { message, .. } => message,
            Self::Consumer { identity, .. } => identity.message_id(),
        }
    }
    /// Immutable expected fingerprint.
    pub const fn fingerprint(&self) -> MessageFingerprint {
        match self {
            Self::Outbox { fingerprint, .. } | Self::Consumer { fingerprint, .. } => *fingerprint,
        }
    }
    fn key(&self) -> (String, String) {
        (
            self.message().as_str().to_owned(),
            match self {
                Self::Consumer { identity, .. } => identity.group().as_str().to_owned(),
                _ => String::new(),
            },
        )
    }
}
/// Closed operation authorized by the product before any storage mutation.
#[derive(Clone)]
pub enum PlanAction {
    /// Recover a bounded, homogeneous set of exact message facts.
    Recover {
        /// Verified external restore-point references.
        evidence: RestoreEvidence,
        /// Direction derived from the selected member kind.
        direction: Direction,
        /// Canonically ordered nonempty member set.
        members: Vec<Member>,
    },
    /// End the exact current plan without asserting any unfinished member succeeded.
    Terminate {
        /// Original recovery operation.
        operation: OperationId,
        /// Original complete request digest.
        digest: [u8; 32],
    },
}
/// Canonical immutable plan. Epoch advancement is exactly one step, checked at construction.
#[derive(Clone)]
pub struct Plan {
    tenant: TenantId,
    operation: OperationId,
    storage: StorageIdentity,
    expected: Epoch,
    next: Epoch,
    action: PlanAction,
    digest: [u8; 32],
}
impl Plan {
    /// Maximum atomic member set; product orchestration splits larger recovery units explicitly.
    pub const MAX_MEMBERS: usize = 500;
    /// Freeze exact inputs before requesting product authorization.
    pub fn new(
        tenant: TenantId,
        operation: OperationId,
        storage: StorageIdentity,
        expected: Epoch,
        evidence: RestoreEvidence,
        mut members: Vec<Member>,
    ) -> Result<Self, Error> {
        let next = expected.next().map_err(|_| Error::Invalid)?;
        let direction = members.first().ok_or(Error::Invalid)?.direction();
        if members.len() > Self::MAX_MEMBERS
            || members.iter().any(|m| {
                m.direction() != direction
                    || matches!(m, Member::Consumer {identity,..} if identity.tenant_id()!=tenant)
            })
        {
            return Err(Error::Invalid);
        }
        members.sort_by_key(Member::key);
        if members.windows(2).any(|m| m[0].key() == m[1].key()) {
            return Err(Error::Invalid);
        }
        let mut value = Self {
            tenant,
            operation,
            storage,
            expected,
            next,
            action: PlanAction::Recover {
                evidence,
                direction,
                members,
            },
            digest: [0; 32],
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }
    /// Authorize a fence transition for one exact current recovery plan, including all-expired plans.
    pub fn terminate(
        tenant: TenantId,
        operation: OperationId,
        storage: StorageIdentity,
        expected: Epoch,
        prior_operation: OperationId,
        prior_digest: [u8; 32],
    ) -> Result<Self, Error> {
        if operation == prior_operation || prior_digest == [0; 32] {
            return Err(Error::Invalid);
        }
        let mut value = Self {
            tenant,
            operation,
            storage,
            expected,
            next: expected.next().map_err(|_| Error::Invalid)?,
            action: PlanAction::Terminate {
                operation: prior_operation,
                digest: prior_digest,
            },
            digest: [0; 32],
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }
    /// Closed exact action; authorization cannot be moved between recovery and termination.
    pub const fn action(&self) -> &PlanAction {
        &self.action
    }
    /// Bound tenant.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Stable retry identity.
    pub const fn operation(&self) -> OperationId {
        self.operation
    }
    /// Bound physical restore unit and externally verified lineage.
    pub const fn storage(&self) -> StorageIdentity {
        self.storage
    }
    /// Expected tenant epoch.
    pub const fn expected(&self) -> Epoch {
        self.expected
    }
    /// Atomically installed tenant epoch.
    pub const fn next(&self) -> Epoch {
        self.next
    }
    /// Canonically ordered recovery members; a termination has no member execution.
    pub fn members(&self) -> &[Member] {
        match &self.action {
            PlanAction::Recover { members, .. } => members,
            PlanAction::Terminate { .. } => &[],
        }
    }
    /// Domain-separated, length-framed immutable request digest.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    fn calculate_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        for bytes in [
            b"rss.message-dr.v2".as_slice(),
            self.tenant.to_string().as_bytes(),
            self.operation.to_string().as_bytes(),
            &self.storage.target(),
            &self.storage.lineage(),
            &self.expected.get().to_be_bytes(),
            &self.next.get().to_be_bytes(),
        ] {
            frame(&mut hash, bytes);
        }
        let (evidence, direction, members) = match &self.action {
            PlanAction::Terminate { operation, digest } => {
                frame(&mut hash, b"terminate");
                frame(&mut hash, operation.to_string().as_bytes());
                frame(&mut hash, digest);
                return hash.finalize().into();
            }
            PlanAction::Recover {
                evidence,
                direction,
                members,
            } => (evidence, direction, members),
        };
        frame(&mut hash, b"recover");
        frame(&mut hash, &evidence.database);
        frame(&mut hash, &evidence.broker);
        frame(
            &mut hash,
            match direction {
                Direction::DatabaseAhead => b"database",
                Direction::BrokerAhead => b"broker",
            },
        );
        for member in members {
            frame(&mut hash, member.message().as_str().as_bytes());
            frame(&mut hash, member.fingerprint().as_bytes());
            match member {
                Member::Outbox { version, .. } => frame(&mut hash, &version.get().to_be_bytes()),
                Member::Consumer { identity, .. } => {
                    frame(&mut hash, identity.group().as_str().as_bytes());
                    frame(&mut hash, identity.contract().id().as_str().as_bytes());
                    frame(
                        &mut hash,
                        identity.contract().version().to_string().as_bytes(),
                    );
                    frame(
                        &mut hash,
                        identity.contract().schema_digest().as_str().as_bytes(),
                    );
                }
            }
        }
        hash.finalize().into()
    }
}
fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Plan([redacted])")
    }
}
/// Library-issued authorization consumed only by the DR provider port.
pub struct AuthorizedPlan(pub(crate) Plan);
impl AuthorizedPlan {
    /// Immutable exact authorized inputs.
    pub const fn request(&self) -> &Plan {
        &self.0
    }
}
/// Durable plan application. This never asserts that the broker published or consumers committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Stable operation identity.
    pub operation: OperationId,
    /// Exact request digest.
    pub digest: [u8; 32],
    /// Applied generation.
    pub epoch: Epoch,
}
/// Durable diagnostic category; raw provider errors never enter progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    /// The original same-ID automatic delivery deadline elapsed.
    DeadlineExpired,
    /// Publication was permanently rejected or its bounded retry policy was exhausted.
    PermanentPublishFailure,
}
/// Closed member state; a fenced earlier plan can be inspected without granting execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberStatus {
    /// Awaiting normal delivery/consumption.
    Pending,
    /// An acknowledged claim is in flight.
    Publishing,
    /// Confirmed by the normal publication/consumer transaction.
    Completed,
    /// Same-ID window expired or publication failed permanently; partition remains blocked.
    Blocked(BlockReason),
    /// A later epoch superseded execution authority; historical progress is retained.
    Superseded(Option<BlockReason>),
    /// An exact authorized termination fenced unfinished work; prior block evidence is retained.
    Terminated(Option<BlockReason>),
}
/// Progress projected from durable member rows.
#[derive(Clone, Debug)]
pub struct Progress {
    /// Historical application receipt.
    pub receipt: Receipt,
    /// States in canonical plan member order.
    pub members: Vec<MemberStatus>,
}
/// Trusted provider owns atomicity, RLS, fixed execution fencing and readback certainty.
pub trait Store: Send + Sync {
    /// Apply all selected members, epoch and receipt in one transaction.
    fn apply(
        &self,
        plan: &AuthorizedPlan,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<Receipt, Error>> + Send;
    /// Read only this exact operation and digest. Absence does not prove rollback.
    fn receipt(
        &self,
        plan: &AuthorizedPlan,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Option<Receipt>, Error>> + Send;
    /// Read member progress without turning historical evidence into execution authority.
    fn progress(
        &self,
        plan: &AuthorizedPlan,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Option<Progress>, Error>> + Send;
}

/// Execute one bounded application and recover commit uncertainty only through its exact receipt.
/// Uses recovery's existing closed observer; plan/member/tenant identifiers never become labels.
pub async fn execute<S: Store, C: rss_request_context::ExecutionTimer, O: crate::Observer>(
    store: &S,
    plan: &AuthorizedPlan,
    clock: &C,
    deadlines: rss_transactional_messaging::policy::ExecutionDeadlines,
    observer: &O,
) -> LocalTxAttempt<Receipt, Error> {
    crate::completion::execute(
        clock,
        deadlines,
        Error::Deadline,
        |deadline| store.apply(plan, deadline),
        |deadline| store.receipt(plan, deadline),
        |status, _, error| {
            observer.observe(crate::Observation {
                action: match plan.request().action() {
                    PlanAction::Recover { .. } => crate::ActionKind::DrApply,
                    PlanAction::Terminate { .. } => crate::ActionKind::DrTerminate,
                },
                status,
                error,
            })
        },
    )
    .await
}
