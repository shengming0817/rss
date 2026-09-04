//! Deterministic, non-durable transactional messaging test doubles.

use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::Duration;

use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ExecutionTimer, MonotonicInstant,
};

/// Manually advanced monotonic clock shared by all cloned handles.
#[derive(Clone, Default)]
pub struct FakeClock {
    inner: Arc<ClockState>,
}

#[derive(Default)]
struct ClockState {
    elapsed: Mutex<Duration>,
    waiters: Mutex<Vec<Waker>>,
}

impl FakeClock {
    /// Construct a clock at elapsed time zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance monotonically and wake all registered deadline futures.
    pub fn advance(&self, duration: Duration) {
        {
            let mut elapsed = self
                .inner
                .elapsed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *elapsed = elapsed.saturating_add(duration);
        }
        let waiters = {
            let mut waiters = self
                .inner
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(
            *self
                .inner
                .elapsed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl ExecutionTimer for FakeClock {
    fn sleep_until(&self, deadline: AbsoluteDeadline) -> impl Future<Output = ()> + Send {
        let clock = self.clone();
        poll_fn(move |context| {
            if clock.now() >= deadline.instant() {
                return Poll::Ready(());
            }
            let mut waiters = clock
                .inner
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if clock.now() >= deadline.instant() {
                return Poll::Ready(());
            }
            if !waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
    }
}

#[cfg(feature = "producer")]
mod producer {
    use std::collections::{HashMap, VecDeque};
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicBool, Ordering};

    use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
    use rss_transactional_messaging::message::{MessageFingerprint, MessageId, PartitionIdentity};
    use rss_transactional_messaging::outbox::{
        AppendOutcome, OutboxClaimBatch, OutboxDisposition, OutboxLeaseStatus, OutboxSettlement,
        OutboxStore, PendingMessage,
    };
    use rss_transactional_messaging::policy::OperationDeadline;
    use rss_transactional_messaging::transport::{
        PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage,
        PublishOutcome, Publisher,
    };

    use super::{Arc, Duration, Mutex};

    #[derive(Debug, thiserror::Error)]
    #[error("memory outbox rejected a conflicting or stale operation")]
    struct MemoryOutboxError;

    enum OutboxEntryState {
        Pending,
        Claimed { epoch: u64 },
        DeadLetter,
    }

    struct OutboxEntry<P> {
        message: Arc<PendingMessage<P>>,
        state: OutboxEntryState,
    }

    struct OutboxState<P> {
        entries: VecDeque<OutboxEntry<P>>,
        fingerprints: HashMap<String, MessageFingerprint>,
        epoch: u64,
        settlements: Vec<OutboxDisposition>,
    }

    impl<P> Default for OutboxState<P> {
        fn default() -> Self {
            Self {
                entries: VecDeque::new(),
                fingerprints: HashMap::new(),
                epoch: 1,
                settlements: Vec::new(),
            }
        }
    }

    /// Deterministic, non-durable implementation of the canonical outbox port.
    pub struct MemoryOutboxStore<P> {
        inner: Arc<Mutex<OutboxState<P>>>,
        budget: rss_transactional_messaging::policy::DeliveryBudget,
    }

    impl<P> Clone for MemoryOutboxStore<P> {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
                budget: self.budget,
            }
        }
    }

    impl<P> Default for MemoryOutboxStore<P> {
        #[allow(clippy::expect_used)]
        // reason: these fixed test-only budgets satisfy the checked constructor by construction.
        fn default() -> Self {
            Self {
                inner: Arc::new(Mutex::new(OutboxState::default())),
                budget: rss_transactional_messaging::policy::DeliveryBudget::new(
                    Duration::from_secs(30),
                    Duration::from_secs(2),
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                )
                .expect("fixed test budget"),
            }
        }
    }

    impl<P> MemoryOutboxStore<P> {
        /// Construct an empty store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Fence all outstanding claims without modifying pending facts.
        pub fn fence_claims(&self) {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.epoch = state.epoch.saturating_add(1);
        }

        /// Resolve a dead-letter partition head so its successor becomes claimable.
        pub fn resolve_partition(&self, partition: &PartitionIdentity) {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.entries.retain(|entry| {
                !matches!(entry.state, OutboxEntryState::DeadLetter)
                    || entry.message.partition() != Some(partition)
            });
        }

        /// Current pending fact count.
        #[must_use]
        pub fn pending_len(&self) -> usize {
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .len()
        }

        /// Core dispositions applied by settlement calls.
        #[must_use]
        pub fn settlements(&self) -> Vec<OutboxDisposition> {
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .settlements
                .clone()
        }
    }

    impl<P> OutboxStore<P> for MemoryOutboxStore<P>
    where
        P: AsRef<[u8]> + Send + Sync,
    {
        fn delivery_budget(&self) -> rss_transactional_messaging::policy::DeliveryBudget {
            self.budget
        }
        type Transaction<'tx> = ();
        type Claim = (Arc<PendingMessage<P>>, u64);
        type PublishReceipt = ();

        async fn append(
            &self,
            _transaction: &mut Self::Transaction<'_>,
            message: PendingMessage<P>,
        ) -> Result<AppendOutcome, MessagingError> {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let id = message.message_id().as_str().to_owned();
            if let Some(existing) = state.fingerprints.get(&id) {
                if *existing == message.fingerprint() {
                    return Ok(AppendOutcome::AlreadyPresent);
                }
                return Err(MessagingError::new(
                    MessagingErrorKind::Conflict,
                    MemoryOutboxError,
                ));
            }
            state.fingerprints.insert(id, message.fingerprint());
            state.entries.push_back(OutboxEntry {
                message: Arc::new(message),
                state: OutboxEntryState::Pending,
            });
            Ok(AppendOutcome::Inserted)
        }

        async fn claim_partition_heads(
            &self,
            limit: NonZeroUsize,
            _deadline: OperationDeadline,
        ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut claims = Vec::new();
            let mut seen_partitions = Vec::<PartitionIdentity>::new();
            let epoch = state.epoch;
            for entry in &mut state.entries {
                let partition = entry.message.partition().cloned();
                if partition
                    .as_ref()
                    .is_some_and(|partition| seen_partitions.iter().any(|seen| seen == partition))
                {
                    continue;
                }
                if let Some(partition) = partition {
                    seen_partitions.push(partition);
                }
                if claims.len() >= limit.get() {
                    continue;
                }
                let claimable = match entry.state {
                    OutboxEntryState::Pending => true,
                    OutboxEntryState::Claimed { epoch: claim_epoch } => claim_epoch != epoch,
                    OutboxEntryState::DeadLetter => false,
                };
                if claimable {
                    entry.state = OutboxEntryState::Claimed { epoch };
                    claims.push((Arc::clone(&entry.message), epoch));
                }
            }
            OutboxClaimBatch::try_from_provider(claims, limit)
                .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))
        }

        async fn lease_status(
            &self,
            claim: &Self::Claim,
            deadline: OperationDeadline,
        ) -> Result<OutboxLeaseStatus, MessagingError> {
            if deadline.timeout().is_zero() {
                return Ok(OutboxLeaseStatus::Lost);
            }
            let state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let owned = state.entries.iter().any(|entry| {
                entry.message.message_id() == claim.0.message_id()
                    && matches!(entry.state, OutboxEntryState::Claimed { epoch } if epoch == claim.1)
            });
            Ok(if claim.1 == state.epoch && owned {
                OutboxLeaseStatus::Held {
                    delivery_remaining: None,
                    remaining: self.budget.lease_ttl(),
                }
            } else {
                OutboxLeaseStatus::Lost
            })
        }

        async fn extend(
            &self,
            claim: &Self::Claim,
            deadline: OperationDeadline,
        ) -> Result<OutboxLeaseStatus, MessagingError> {
            self.lease_status(claim, deadline).await
        }

        fn message(claim: &Self::Claim) -> &PendingMessage<P> {
            claim.0.as_ref()
        }

        async fn settle(
            &self,
            claim: Self::Claim,
            settlement: OutboxSettlement<Self::PublishReceipt>,
            deadline: OperationDeadline,
        ) -> Result<(), MessagingError> {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let position = state
                .entries
                .iter()
                .position(|entry| entry.message.message_id() == claim.0.message_id());
            let Some(position) = position else {
                return Err(MessagingError::new(
                    MessagingErrorKind::OwnershipLost,
                    MemoryOutboxError,
                ));
            };
            let owned = matches!(
                state.entries[position].state,
                OutboxEntryState::Claimed { epoch } if epoch == claim.1
            ) && claim.1 == state.epoch;
            if deadline.timeout().is_zero() {
                if owned {
                    state.entries[position].state = OutboxEntryState::Pending;
                }
                return Err(MessagingError::new(
                    MessagingErrorKind::DeadlineElapsed,
                    MemoryOutboxError,
                ));
            }
            if !owned {
                if matches!(
                    state.entries[position].state,
                    OutboxEntryState::Claimed { epoch } if epoch == claim.1
                ) {
                    state.entries[position].state = OutboxEntryState::Pending;
                }
                return Err(MessagingError::new(
                    MessagingErrorKind::OwnershipLost,
                    MemoryOutboxError,
                ));
            }
            let disposition = settlement.disposition();
            state.settlements.push(disposition);
            match settlement {
                OutboxSettlement::Published(()) => {
                    state.entries.remove(position);
                }
                OutboxSettlement::Retry => {
                    state.entries[position].state = OutboxEntryState::Pending;
                }
                OutboxSettlement::DeadLetter => {
                    state.entries[position].state = OutboxEntryState::DeadLetter;
                }
            }
            Ok(())
        }
    }

    /// Scripted publisher that records stable message identities.
    pub struct MemoryPublisher<R> {
        outcomes: Mutex<VecDeque<PublishOutcome<R>>>,
        ids: Mutex<Vec<MessageId>>,
        exhausted: AtomicBool,
    }

    impl<R> MemoryPublisher<R> {
        /// Construct a publisher from an exact outcome script.
        ///
        /// Consuming past the script sets [`Self::script_exhausted`] and returns a closed permanent
        /// `InvalidMessage` sentinel. Conformance fixtures should assert that the exhaustion flag
        /// remains false so a configuration error cannot be mistaken for a transport failure.
        pub fn new(outcomes: impl IntoIterator<Item = PublishOutcome<R>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                ids: Mutex::new(Vec::new()),
                exhausted: AtomicBool::new(false),
            }
        }

        /// Stable identities observed by publish calls.
        #[must_use]
        pub fn message_ids(&self) -> Vec<MessageId> {
            self.ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        /// Whether a publish call consumed past the exact configured script.
        #[must_use]
        pub fn script_exhausted(&self) -> bool {
            self.exhausted.load(Ordering::Acquire)
        }
    }

    impl<P, R> Publisher<P> for MemoryPublisher<R>
    where
        P: Send + Sync,
        R: Send,
    {
        type Receipt = R;

        async fn publish(
            &self,
            message: &rss_transactional_messaging::message::MessageEnvelope<P>,
            _deadline: OperationDeadline,
        ) -> PublishOutcome<Self::Receipt> {
            self.ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(message.id().clone());
            match self
                .outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
            {
                Some(outcome) => outcome,
                None => {
                    self.exhausted.store(true, Ordering::Release);
                    PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
                        PublishFailureKind::Permanent,
                        PublishFailureStage::Admission,
                        PublishFailureReason::InvalidMessage,
                    ))
                }
            }
        }
    }
}

#[cfg(feature = "producer")]
pub use producer::{MemoryOutboxStore, MemoryPublisher};

mod consumer {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
    use rss_transactional_messaging::inbox::{
        ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus,
    };
    use rss_transactional_messaging::message::MessageFingerprint;
    use rss_transactional_messaging::policy::OperationDeadline;
    use rss_transactional_messaging::transaction::{
        SettlementDecision, SettlementKind, TerminalDisposition, TerminalReceipt,
    };
    use rss_transactional_messaging::transport::DeliverySettlement;

    use super::{Arc, Duration, Mutex};

    #[derive(Debug, thiserror::Error)]
    #[error("memory inbox or settlement fault")]
    struct MemoryConsumerError;

    #[derive(Clone, Eq, Hash, PartialEq)]
    struct InboxKey {
        tenant: [u8; 16],
        group: Box<str>,
        message_id: Box<str>,
        contract_id: Box<str>,
        contract_major: u32,
        schema_digest: Box<str>,
    }

    enum InboxRecord {
        Claimed {
            epoch: u64,
        },
        Terminal {
            identity: ConsumerIdentity,
            fingerprint: MessageFingerprint,
            disposition: TerminalDisposition,
        },
    }

    struct InboxState {
        records: HashMap<InboxKey, InboxRecord>,
        next_epoch: u64,
    }

    impl Default for InboxState {
        fn default() -> Self {
            Self {
                records: HashMap::new(),
                next_epoch: 1,
            }
        }
    }

    /// Deterministic, non-durable implementation of the canonical inbox port.
    #[derive(Clone)]
    pub struct MemoryInboxStore {
        inner: Arc<Mutex<InboxState>>,
        lease: Duration,
    }

    impl Default for MemoryInboxStore {
        fn default() -> Self {
            Self {
                inner: Arc::new(Mutex::new(InboxState::default())),
                lease: Duration::from_secs(30),
            }
        }
    }

    impl MemoryInboxStore {
        /// Construct an empty store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Persist a terminal receipt as if it committed atomically with a handler effect.
        pub fn store_terminal(
            &self,
            identity: ConsumerIdentity,
            fingerprint: MessageFingerprint,
            disposition: TerminalDisposition,
        ) {
            let key = identity_key(&identity);
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .records
                .insert(
                    key,
                    InboxRecord::Terminal {
                        identity,
                        fingerprint,
                        disposition,
                    },
                );
        }

        /// Expire the current claim so a later call can acquire a new epoch.
        pub fn expire(&self, identity: &ConsumerIdentity) {
            let key = identity_key(identity);
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(state.records.get(&key), Some(InboxRecord::Claimed { .. })) {
                state.records.remove(&key);
            }
        }
    }

    impl InboxStore for MemoryInboxStore {
        #[allow(clippy::expect_used)]
        // reason: this provider's fixed 30-second test lease always admits a renewal schedule.
        fn lease_policy(&self) -> rss_transactional_messaging::policy::LeaseRenewalPolicy {
            rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(self.lease)
                .expect("fixed test lease")
        }
        type Claim = (ConsumerIdentity, u64);

        async fn claim(
            &self,
            identity: &ConsumerIdentity,
            _deadline: OperationDeadline,
        ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
            let key = identity_key(identity);
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match state.records.get(&key) {
                Some(InboxRecord::Claimed { .. }) => Ok(IdempotencyDisposition::InProgress),
                Some(InboxRecord::Terminal {
                    identity,
                    fingerprint,
                    disposition,
                }) => Ok(IdempotencyDisposition::Terminal(
                    TerminalReceipt::from_durable(identity.clone(), *fingerprint, *disposition),
                )),
                None => {
                    let epoch = state.next_epoch;
                    state.next_epoch = state.next_epoch.saturating_add(1);
                    state
                        .records
                        .insert(key.clone(), InboxRecord::Claimed { epoch });
                    Ok(IdempotencyDisposition::Acquired((identity.clone(), epoch)))
                }
            }
        }

        async fn read_terminal(
            &self,
            identity: &ConsumerIdentity,
            _deadline: OperationDeadline,
        ) -> Result<Option<TerminalReceipt>, MessagingError> {
            let state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(match state.records.get(&identity_key(identity)) {
                Some(InboxRecord::Terminal {
                    identity,
                    fingerprint,
                    disposition,
                }) => Some(TerminalReceipt::from_durable(
                    identity.clone(),
                    *fingerprint,
                    *disposition,
                )),
                _ => None,
            })
        }

        async fn extend(
            &self,
            claim: &Self::Claim,
            deadline: OperationDeadline,
        ) -> Result<LeaseStatus, MessagingError> {
            if deadline.timeout().is_zero() {
                return Ok(LeaseStatus::Lost);
            }
            let state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(match state.records.get(&identity_key(&claim.0)) {
                Some(InboxRecord::Claimed { epoch }) if *epoch == claim.1 => LeaseStatus::Held {
                    remaining: self.lease,
                },
                _ => LeaseStatus::Lost,
            })
        }

        async fn release(
            &self,
            claim: Self::Claim,
            deadline: OperationDeadline,
        ) -> Result<(), MessagingError> {
            if deadline.timeout().is_zero() {
                return Err(MessagingError::new(
                    MessagingErrorKind::DeadlineElapsed,
                    MemoryConsumerError,
                ));
            }
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let key = identity_key(&claim.0);
            if matches!(state.records.get(&key), Some(InboxRecord::Claimed { epoch }) if *epoch == claim.1)
            {
                state.records.remove(&key);
                Ok(())
            } else {
                Err(MessagingError::new(
                    MessagingErrorKind::OwnershipLost,
                    MemoryConsumerError,
                ))
            }
        }
    }

    fn identity_key(identity: &ConsumerIdentity) -> InboxKey {
        InboxKey {
            tenant: identity.tenant_id().octets(),
            group: identity.group().as_str().into(),
            message_id: identity.message_id().as_str().into(),
            contract_id: identity.contract().id().as_str().into(),
            contract_major: identity.contract().version().major(),
            schema_digest: identity.contract().schema_digest().as_str().into(),
        }
    }

    /// One-shot settlement double that records only core settlement kinds.
    #[derive(Clone, Default)]
    pub struct RecordingSettlement {
        settlements: Arc<Mutex<Vec<SettlementKind>>>,
        abandons: Arc<AtomicUsize>,
        fail: bool,
    }

    impl RecordingSettlement {
        /// Construct an empty successful recorder.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Construct a recorder whose one-shot operation returns a closed transient error.
        #[must_use]
        pub fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }

        /// Construct a successful recorder backed by caller-owned observation handles.
        #[must_use]
        pub fn observing(
            settlements: Arc<Mutex<Vec<SettlementKind>>>,
            abandons: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                settlements,
                abandons,
                fail: false,
            }
        }

        /// Construct a failing recorder backed by caller-owned observation handles.
        #[must_use]
        pub fn failing_with_observers(
            settlements: Arc<Mutex<Vec<SettlementKind>>>,
            abandons: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                settlements,
                abandons,
                fail: true,
            }
        }

        /// Settlement kinds in call order.
        #[must_use]
        pub fn settlements(&self) -> Vec<SettlementKind> {
            self.settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        /// Number of abandon calls.
        #[must_use]
        pub fn abandon_count(&self) -> usize {
            self.abandons.load(Ordering::Acquire)
        }

        fn result(&self) -> Result<(), MessagingError> {
            if self.fail {
                Err(MessagingError::new(
                    MessagingErrorKind::Transient,
                    MemoryConsumerError,
                ))
            } else {
                Ok(())
            }
        }
    }

    impl DeliverySettlement for RecordingSettlement {
        async fn settle(
            self,
            decision: SettlementDecision,
            _deadline: OperationDeadline,
        ) -> Result<(), MessagingError> {
            self.settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(decision.kind());
            self.result()
        }

        async fn abandon(self, _deadline: OperationDeadline) -> Result<(), MessagingError> {
            self.abandons.fetch_add(1, Ordering::AcqRel);
            self.result()
        }
    }
}

pub use consumer::{MemoryInboxStore, RecordingSettlement};
