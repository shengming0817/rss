use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::inbox::{
    ConsumerGroup, ConsumerIdentity, IdempotencyDisposition, LeaseStatus,
};
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageFingerprint, MessageId,
    MessageMetadata, MessageMetadataExtensions, MessageRoute, MessagingDomain,
};
use rss_transactional_messaging::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingIoOutcome,
    TransactionalMessagingObservation, TransactionalMessagingTransactionStatus,
};
use rss_transactional_messaging::outbox::{AppendOutcome, OutboxDisposition, OutboxLeaseStatus};
use rss_transactional_messaging::policy::ExecutionBudget;
use rss_transactional_messaging::transaction::{
    SettlementKind, TerminalDisposition, TerminalReceipt,
};
use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome,
};
use rss_transactional_messaging_testkit::ConformanceError;
use rss_transactional_messaging_testkit::consumer::{ConsumerTxDriver, run_consumer_conformance};
use rss_transactional_messaging_testkit::inbox::{InboxDriver, run_inbox_conformance};
use rss_transactional_messaging_testkit::memory::FakeClock;
use rss_transactional_messaging_testkit::outbox::{
    OutboxDriver, ReclaimEvidence, run_outbox_conformance,
};

use rss_transactional_messaging_testkit::transport::{
    PublishAttempt, PublisherTransportDriver, run_publisher_transport_conformance,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Defect {
    OutboxAfterPublishBeforeSettle,
    OutboxTransientPublishFailure,
    OutboxConfirmLostChannelClose,
    OutboxPermanentPublishFailure,
    OutboxStaleLeaseContender,
    OutboxLeaseDeadlineExpired,
    OutboxWindowReset,
    InboxClaimCrashBeforeCommit,
    InboxCommitBeforeAckCrash,
    InboxLeaseLostBeforeCommit,
}

struct FaultCase {
    id: &'static str,
    crash_point: &'static str,
    expected_invariant: &'static str,
    expected_stage: &'static str,
    expected_error: ExpectedError,
    defect: Defect,
}

#[derive(Clone, Copy)]
enum ExpectedError {
    Mismatch,
    Count,
}

const CASES: &[FaultCase] = &[
    FaultCase {
        id: "outbox-renew-resets-window",
        crash_point: "renew",
        expected_invariant: "same-id-window-never-renewed",
        expected_stage: "outbox.window",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::OutboxWindowReset,
    },
    FaultCase {
        id: "outbox-after-publish-before-settle",
        crash_point: "after-publish-before-settle",
        expected_invariant: "outbox-publish-settled-once",
        expected_stage: "outbox.reclaim.claims",
        expected_error: ExpectedError::Count,
        defect: Defect::OutboxAfterPublishBeforeSettle,
    },
    FaultCase {
        id: "outbox-transient-publish-failure",
        crash_point: "during-transient-publish",
        expected_invariant: "outbox-transient-remains-retryable",
        expected_stage: "publisher.transient",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::OutboxTransientPublishFailure,
    },
    FaultCase {
        id: "outbox-confirm-lost-channel-close",
        crash_point: "post-send-close-before-confirm",
        expected_invariant: "publisher-ambiguous-retry-preserves-message-identity",
        expected_stage: "publisher.ambiguous.identity",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::OutboxConfirmLostChannelClose,
    },
    FaultCase {
        id: "outbox-permanent-publish-failure",
        crash_point: "during-permanent-publish",
        expected_invariant: "publisher-permanent-refusal-stays-permanent",
        expected_stage: "publisher.permanent",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::OutboxPermanentPublishFailure,
    },
    FaultCase {
        id: "outbox-stale-contender-settle",
        crash_point: "stale-contender-settle",
        expected_invariant: "outbox-stale-lease-settle-rejected",
        expected_stage: "outbox.lease.stale",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::OutboxStaleLeaseContender,
    },
    FaultCase {
        id: "outbox-deadline-expired-settle",
        crash_point: "deadline-expired-settle",
        expected_invariant: "outbox-expired-deadline-settle-rejected",
        expected_stage: "outbox.lease.expired",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::OutboxLeaseDeadlineExpired,
    },
    FaultCase {
        id: "inbox-claim-crash-before-commit",
        crash_point: "after-claim-before-commit",
        expected_invariant: "inbox-stale-claim-reclaimable",
        expected_stage: "inbox.crash-before-commit.reclaim",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::InboxClaimCrashBeforeCommit,
    },
    FaultCase {
        id: "inbox-commit-before-ack-crash",
        crash_point: "after-commit-before-ack",
        expected_invariant: "inbox-redelivery-dedupes-once",
        expected_stage: "consumer.commit-before-ack",
        expected_error: ExpectedError::Mismatch,
        defect: Defect::InboxCommitBeforeAckCrash,
    },
    FaultCase {
        id: "inbox-lease-lost-before-commit",
        crash_point: "lease-lost-before-commit",
        expected_invariant: "inbox-stale-lease-cannot-commit",
        expected_stage: "consumer.lease-lost.settlement",
        expected_error: ExpectedError::Count,
        defect: Defect::InboxLeaseLostBeforeCommit,
    },
];

#[derive(Debug, thiserror::Error)]
#[error("synthetic provider conflict")]
struct Conflict;

struct OutboxFixture {
    defect: Option<Defect>,
}
impl OutboxFixture {
    fn new(defect: Option<Defect>) -> Self {
        Self { defect }
    }
    fn is(&self, defect: Defect) -> bool {
        self.defect == Some(defect)
    }
}

impl OutboxDriver for OutboxFixture {
    async fn retry_settlement_reclaims_same_message(
        &self,
    ) -> Result<ReclaimEvidence, ConformanceError> {
        Ok(ReclaimEvidence {
            claimed_message_ids: vec![fixture_id("retry")?, fixture_id("retry")?],
            settlement: OutboxDisposition::Retry,
        })
    }
    async fn reclaim_after_publish_before_settle(
        &self,
    ) -> Result<ReclaimEvidence, ConformanceError> {
        Ok(ReclaimEvidence {
            claimed_message_ids: if self.is(Defect::OutboxAfterPublishBeforeSettle) {
                vec![]
            } else {
                vec![fixture_id("reclaim")?, fixture_id("reclaim")?]
            },
            settlement: OutboxDisposition::Published,
        })
    }

    fn reset(&self) {}
    async fn delivery_window(&self) -> Result<Option<[OutboxLeaseStatus; 3]>, MessagingError> {
        let renewed = if matches!(self.defect, Some(Defect::OutboxWindowReset)) {
            20
        } else {
            9
        };
        Ok(Some([10, renewed, 0].map(|seconds| {
            OutboxLeaseStatus::Held {
                remaining: Duration::from_secs(60),
                delivery_remaining: Some(Duration::from_secs(seconds)),
            }
        })))
    }

    async fn append_first(&self) -> Result<AppendOutcome, MessagingError> {
        Ok(AppendOutcome::Inserted)
    }

    async fn append_same(&self) -> Result<AppendOutcome, MessagingError> {
        Ok(AppendOutcome::AlreadyPresent)
    }

    async fn append_conflict(&self) -> Result<AppendOutcome, MessagingError> {
        Err(MessagingError::new(MessagingErrorKind::Conflict, Conflict))
    }

    async fn partition_head_claims(&self) -> Result<usize, MessagingError> {
        Ok(1)
    }

    async fn blocked_partition_claims(&self) -> Result<usize, MessagingError> {
        Ok(0)
    }

    async fn stale_lease(&self) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(if self.is(Defect::OutboxStaleLeaseContender) {
            OutboxLeaseStatus::Held {
                delivery_remaining: None,
                remaining: Duration::from_secs(1),
            }
        } else {
            OutboxLeaseStatus::Lost
        })
    }

    async fn expired_lease(&self) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(if self.is(Defect::OutboxLeaseDeadlineExpired) {
            OutboxLeaseStatus::Held {
                delivery_remaining: None,
                remaining: Duration::ZERO,
            }
        } else {
            OutboxLeaseStatus::Lost
        })
    }
}

fn transient_failure() -> PublishFailure {
    PublishFailure::new(
        PublishFailureKind::Transient,
        PublishFailureStage::Confirm,
        PublishFailureReason::TransportUnavailable,
    )
}

fn permanent_failure() -> PublishFailure {
    PublishFailure::new(
        PublishFailureKind::Permanent,
        PublishFailureStage::Admission,
        PublishFailureReason::ProviderRejected,
    )
}

struct InboxFixture {
    defect: Option<Defect>,
}

impl InboxFixture {
    fn is(&self, defect: Defect) -> bool {
        matches!(
            (self.defect, defect),
            (
                Some(Defect::InboxClaimCrashBeforeCommit),
                Defect::InboxClaimCrashBeforeCommit
            )
        )
    }
}

impl InboxDriver for InboxFixture {
    type Claim = ();

    fn reset(&self) {}

    async fn first_claim(&self) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(()))
    }

    async fn active_claim(&self) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::InProgress)
    }

    async fn other_group_claim(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(()))
    }

    async fn terminal_duplicate(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Terminal(terminal_receipt()?))
    }

    async fn extend_owned(&self) -> Result<LeaseStatus, MessagingError> {
        Ok(LeaseStatus::Held {
            remaining: Duration::from_secs(30),
        })
    }

    async fn reclaim_after_expiry(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(if self.is(Defect::InboxClaimCrashBeforeCommit) {
            IdempotencyDisposition::InProgress
        } else {
            IdempotencyDisposition::Acquired(())
        })
    }

    async fn reclaim_after_release(
        &self,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        Ok(IdempotencyDisposition::Acquired(()))
    }

    async fn stale_lease(&self) -> Result<LeaseStatus, MessagingError> {
        Ok(LeaseStatus::Lost)
    }
}

fn terminal_receipt() -> Result<TerminalReceipt, MessagingError> {
    let message =
        message().map_err(|_| MessagingError::new(MessagingErrorKind::Invariant, Conflict))?;
    Ok(TerminalReceipt::from_durable(
        ConsumerIdentity::new(
            message.metadata().tenant_id(),
            ConsumerGroup::parse("fault-consumer")
                .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))?,
            message.id().clone(),
            message.metadata().contract().clone(),
        ),
        MessageFingerprint::of(&message),
        TerminalDisposition::Succeeded,
    ))
}

struct ConsumerFixture {
    defect: Option<Defect>,
    committed_error: Option<ConformanceError>,
    commit_unknown_abandon: bool,
    handlers: AtomicUsize,
    commits: AtomicUsize,
    abandons: AtomicUsize,
    settlements: Mutex<Vec<SettlementKind>>,
    observations: Mutex<Vec<TransactionalMessagingObservation>>,
}

impl ConsumerFixture {
    fn new(defect: Option<Defect>) -> Self {
        Self {
            defect,
            committed_error: None,
            commit_unknown_abandon: true,
            handlers: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            abandons: AtomicUsize::new(0),
            settlements: Mutex::new(Vec::new()),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn settlement_log(&self) -> std::sync::MutexGuard<'_, Vec<SettlementKind>> {
        self.settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn without_commit_unknown_abandon(mut self) -> Self {
        self.commit_unknown_abandon = false;
        self
    }

    fn with_committed_error(mut self, error: ConformanceError) -> Self {
        self.committed_error = Some(error);
        self
    }
}

impl ConsumerTxDriver for ConsumerFixture {
    fn reset(&self) {
        self.handlers.store(0, Ordering::SeqCst);
        self.commits.store(0, Ordering::SeqCst);
        self.abandons.store(0, Ordering::SeqCst);
        self.settlement_log().clear();
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    async fn committed_delivery(
        &self,
    ) -> Result<Vec<TransactionalMessagingObservation>, ConformanceError> {
        if let Some(error) = self.committed_error {
            return Err(error);
        }
        self.handlers.store(1, Ordering::SeqCst);
        self.commits.store(1, Ordering::SeqCst);
        self.settlement_log().push(SettlementKind::Acknowledge);
        let mut observations = self
            .observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let commit = TransactionalMessagingObservation::ConsumerTransaction {
            status: TransactionalMessagingTransactionStatus::Committed,
        };
        let ack = TransactionalMessagingObservation::ConsumerSettlement {
            action: TransactionalMessagingDisposition::Ack,
            outcome: TransactionalMessagingIoOutcome::Ok,
        };
        if matches!(self.defect, Some(Defect::InboxCommitBeforeAckCrash)) {
            observations.extend([ack, commit]);
        } else {
            observations.extend([commit, ack]);
        }
        Ok(observations.clone())
    }

    async fn duplicate_delivery(
        &self,
    ) -> Result<(TerminalDisposition, Vec<TransactionalMessagingObservation>), ConformanceError>
    {
        self.settlement_log().push(SettlementKind::Acknowledge);
        let observations = vec![TransactionalMessagingObservation::ConsumerSettlement {
            action: TransactionalMessagingDisposition::Ack,
            outcome: TransactionalMessagingIoOutcome::Ok,
        }];
        Ok((TerminalDisposition::Succeeded, observations))
    }

    async fn commit_unknown_delivery(
        &self,
    ) -> Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError> {
        self.handlers.store(1, Ordering::SeqCst);
        let abandons = usize::from(self.commit_unknown_abandon);
        self.abandons.store(abandons, Ordering::SeqCst);
        Ok((
            vec![TransactionalMessagingObservation::ConsumerTransaction {
                status: TransactionalMessagingTransactionStatus::CommitUnknown,
            }],
            abandons,
        ))
    }

    async fn lease_lost_delivery(
        &self,
    ) -> Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError> {
        let mut observations = vec![TransactionalMessagingObservation::ConsumerLeaseLost];
        if matches!(self.defect, Some(Defect::InboxLeaseLostBeforeCommit)) {
            self.settlement_log().push(SettlementKind::Acknowledge);
            observations.push(TransactionalMessagingObservation::ConsumerSettlement {
                action: TransactionalMessagingDisposition::Ack,
                outcome: TransactionalMessagingIoOutcome::Ok,
            });
        } else {
            self.abandons.store(1, Ordering::SeqCst);
        }
        Ok((observations, 1))
    }
}

fn message() -> Result<MessageEnvelope<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tenant,
            Timepoint::try_from(1_700_000_000_i64)?,
            MessagingDomain::parse("orders")?,
            MessageRoute::parse("orders.created")?,
            ContractIdentity::new(
                ContractId::parse("orders.created")?,
                ContractVersion::from_major(1)?,
                SchemaDigest::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )?,
            ),
        ),
        MessageMetadataExtensions::new(None, None, None, BTreeMap::new()),
    );
    Ok(MessageEnvelope::new(
        MessageId::parse("fault-message")?,
        metadata,
        vec![],
    ))
}

#[tokio::test]
async fn conforming_drivers_pass_all_suites() -> TestResult {
    run_publisher_transport_conformance(
        &PublisherFixture(None),
        &FakeClock::new(),
        ExecutionBudget::STANDARD,
    )
    .await?;
    run_outbox_conformance(
        &OutboxFixture::new(None),
        &FakeClock::new(),
        ExecutionBudget::STANDARD,
    )
    .await?;
    run_inbox_conformance(
        &InboxFixture { defect: None },
        &FakeClock::new(),
        ExecutionBudget::STANDARD,
    )
    .await?;
    run_consumer_conformance(
        &ConsumerFixture::new(None),
        &FakeClock::new(),
        ExecutionBudget::STANDARD,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn commit_unknown_without_an_abandon_call_is_rejected() {
    let result = run_consumer_conformance(
        &ConsumerFixture::new(None).without_commit_unknown_abandon(),
        &FakeClock::new(),
        ExecutionBudget::STANDARD,
    )
    .await;
    assert!(
        result.is_err(),
        "Deferred without a real abandon observation must fail"
    );
    let Some(error) = result.err() else {
        return;
    };
    assert!(error.is_count());
    assert_eq!(error.stage(), "consumer.commit-unknown.abandon");
}

#[tokio::test]
async fn closed_provider_phase_survives_the_public_runner() {
    for (failure, expected_phase) in [
        (
            ConformanceError::fixture(MessagingErrorKind::Transient),
            "fixture",
        ),
        (
            ConformanceError::connect(MessagingErrorKind::Transient),
            "connect",
        ),
        (
            ConformanceError::publish(MessagingErrorKind::Transient),
            "publish",
        ),
        (
            ConformanceError::delivery(MessagingErrorKind::Transient),
            "delivery",
        ),
        (
            ConformanceError::settlement(MessagingErrorKind::Transient),
            "settlement",
        ),
        (
            ConformanceError::shutdown(MessagingErrorKind::Transient),
            "shutdown",
        ),
    ] {
        let result = run_consumer_conformance(
            &ConsumerFixture::new(None).with_committed_error(failure),
            &FakeClock::new(),
            ExecutionBudget::STANDARD,
        )
        .await;
        assert!(
            result.is_err(),
            "provider phase failure must reach the runner"
        );
        let Some(error) = result.err() else {
            continue;
        };
        assert_eq!(error.stage(), "consumer.committed.outcome");
        assert_eq!(error.provider_phase_label(), Some(expected_phase));
        assert!(error.to_string().contains(expected_phase));
    }
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn every_historical_fault_has_a_synthetic_red() {
    for case in CASES {
        assert!(
            !case.id.is_empty()
                && !case.crash_point.is_empty()
                && !case.expected_invariant.is_empty()
        );
        let result = match case.defect {
            Defect::InboxClaimCrashBeforeCommit => {
                run_inbox_conformance(
                    &InboxFixture {
                        defect: Some(case.defect),
                    },
                    &FakeClock::new(),
                    ExecutionBudget::STANDARD,
                )
                .await
            }
            Defect::InboxCommitBeforeAckCrash | Defect::InboxLeaseLostBeforeCommit => {
                run_consumer_conformance(
                    &ConsumerFixture::new(Some(case.defect)),
                    &FakeClock::new(),
                    ExecutionBudget::STANDARD,
                )
                .await
            }
            Defect::OutboxTransientPublishFailure
            | Defect::OutboxConfirmLostChannelClose
            | Defect::OutboxPermanentPublishFailure => {
                run_publisher_transport_conformance(
                    &PublisherFixture(Some(case.defect)),
                    &FakeClock::new(),
                    ExecutionBudget::STANDARD,
                )
                .await
            }
            _ => {
                run_outbox_conformance(
                    &OutboxFixture::new(Some(case.defect)),
                    &FakeClock::new(),
                    ExecutionBudget::STANDARD,
                )
                .await
            }
        };
        let Err(error) = result else {
            assert!(
                result.is_err(),
                "synthetic defect escaped oracle: {} ({})",
                case.id,
                case.expected_invariant
            );
            continue;
        };
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("provider.invalid"));
        let actual_error = if error.is_count() {
            ExpectedError::Count
        } else {
            ExpectedError::Mismatch
        };
        assert!(
            matches!(
                (case.expected_error, actual_error),
                (ExpectedError::Mismatch, ExpectedError::Mismatch)
                    | (ExpectedError::Count, ExpectedError::Count)
            ),
            "wrong error variant rejected {} ({})",
            case.id,
            case.expected_invariant
        );
        assert_eq!(
            error.stage(),
            case.expected_stage,
            "wrong oracle rejected {} ({})",
            case.id,
            case.expected_invariant
        );
    }
}

fn fixture_id(value: &str) -> Result<MessageId, ConformanceError> {
    MessageId::parse(value).map_err(|_| ConformanceError::fixture(MessagingErrorKind::Invariant))
}
struct PublisherFixture(Option<Defect>);
impl PublisherTransportDriver for PublisherFixture {
    async fn confirmed(&self) -> Result<PublishAttempt, ConformanceError> {
        Ok(PublishAttempt {
            message_id: fixture_id("confirmed")?,
            outcome: PublishOutcome::Confirmed(()),
        })
    }
    async fn transient(&self) -> Result<PublishAttempt, ConformanceError> {
        Ok(PublishAttempt {
            message_id: fixture_id("transient")?,
            outcome: if self.0 == Some(Defect::OutboxTransientPublishFailure) {
                PublishOutcome::Confirmed(())
            } else {
                PublishOutcome::DefinitelyNotPublished(transient_failure())
            },
        })
    }
    async fn permanent(&self) -> Result<PublishAttempt, ConformanceError> {
        Ok(PublishAttempt {
            message_id: fixture_id("permanent")?,
            outcome: if self.0 == Some(Defect::OutboxPermanentPublishFailure) {
                PublishOutcome::DefinitelyNotPublished(transient_failure())
            } else {
                PublishOutcome::DefinitelyNotPublished(permanent_failure())
            },
        })
    }
    async fn ambiguous_retry(&self) -> Result<Vec<PublishAttempt>, ConformanceError> {
        Ok(vec![
            PublishAttempt {
                message_id: fixture_id("original")?,
                outcome: PublishOutcome::Ambiguous(transient_failure()),
            },
            PublishAttempt {
                message_id: fixture_id(if self.0 == Some(Defect::OutboxConfirmLostChannelClose) {
                    "different"
                } else {
                    "original"
                })?,
                outcome: PublishOutcome::Confirmed(()),
            },
        ])
    }
}

struct FailingPublisher(&'static str);
impl PublisherTransportDriver for FailingPublisher {
    async fn confirmed(&self) -> Result<PublishAttempt, ConformanceError> {
        if self.0 == "publisher.confirmed" {
            return Err(ConformanceError::publish(MessagingErrorKind::Transient));
        }
        PublisherFixture(None).confirmed().await
    }
    async fn transient(&self) -> Result<PublishAttempt, ConformanceError> {
        if self.0 == "publisher.transient" {
            return Err(ConformanceError::publish(MessagingErrorKind::Transient));
        }
        PublisherFixture(None).transient().await
    }
    async fn permanent(&self) -> Result<PublishAttempt, ConformanceError> {
        if self.0 == "publisher.permanent" {
            return Err(ConformanceError::publish(MessagingErrorKind::Transient));
        }
        PublisherFixture(None).permanent().await
    }
    async fn ambiguous_retry(&self) -> Result<Vec<PublishAttempt>, ConformanceError> {
        if self.0 == "publisher.ambiguous" {
            return Err(ConformanceError::publish(MessagingErrorKind::Transient));
        }
        PublisherFixture(None).ambiguous_retry().await
    }
}
#[tokio::test]
#[allow(clippy::expect_used)]
// reason: fixture provider failures must remain visible at their exact scenario boundary.
async fn provider_failures_identify_the_publisher_scenario() {
    for stage in [
        "publisher.confirmed",
        "publisher.transient",
        "publisher.permanent",
        "publisher.ambiguous",
    ] {
        let result = run_publisher_transport_conformance(
            &FailingPublisher(stage),
            &FakeClock::new(),
            ExecutionBudget::STANDARD,
        )
        .await;
        let error = result.expect_err("provider failure must propagate");
        assert_eq!(error.stage(), stage);
        assert_eq!(error.provider_phase_label(), Some("publish"));
    }
}
