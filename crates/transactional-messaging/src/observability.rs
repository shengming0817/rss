//! Provider-neutral observations with fixed event identities and categorical labels.
//!
//! Keep counts and durations as measurements, not label values.
//! [`TransactionalMessagingObservation`]
//! has no fields for tenant/message IDs, payloads, credentials, or provider error text. Emitters
//! must
//! preserve that boundary when exporting diagnostics. Observations report outcomes; they do not
//! establish durable state or authorize settlement.

use std::time::Duration;

use crate::error::MessagingErrorKind;

/// Shared labels for outbox publication disposition or consumer settlement action.
/// Read the surrounding observation to distinguish these stages; consumer settlement success
/// is reported separately by [`TransactionalMessagingIoOutcome`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingDisposition {
    /// Outbox publication was confirmed, or a consumer ACK was requested.
    Ack,
    /// Outbox retry was selected, or a consumer Requeue was requested.
    Requeue,
    /// Outbox dead-letter was selected, or a consumer Reject was requested.
    Reject,
}

impl TransactionalMessagingDisposition {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Requeue => "requeue",
            Self::Reject => "reject",
        }
    }
}

/// Relay phase whose duration is observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingRelayPhase {
    /// Durable claim phase.
    Claim,
    /// Provider publication and settlement phase.
    Publish,
}

impl TransactionalMessagingRelayPhase {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Publish => "publish",
        }
    }
}

/// Data-free result of one consumer transaction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingTransactionStatus {
    /// The transaction committed durably.
    Committed,
    /// Handler failure may be retried locally.
    HandlerTransient,
    /// Infrastructure failure requires broker redelivery.
    InfrastructureTransient,
    /// A transaction failed permanently before starting or after rollback; no broker Reject is implied.
    RejectedPermanent,
    /// Commit acknowledgement was ambiguous.
    CommitUnknown,
    /// Rollback acknowledgement failed.
    RollbackFailed,
    /// The inbox lease was fenced.
    Fenced,
}

impl TransactionalMessagingTransactionStatus {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::HandlerTransient => "handler_transient",
            Self::InfrastructureTransient => "infrastructure_transient",
            Self::RejectedPermanent => "rejected_permanent",
            Self::CommitUnknown => "commit_unknown",
            Self::RollbackFailed => "rollback_failed",
            Self::Fenced => "fenced",
        }
    }
}

/// Closed result of TransactionalMessaging provider I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingIoOutcome {
    /// The operation succeeded.
    Ok,
    /// The operation failed without exposing provider error text.
    Error,
}

impl TransactionalMessagingIoOutcome {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// Closed provider-I/O phase used to diagnose managed runtime failures without identity or text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingRuntimePhase {
    /// Constructing a consumer absolute deadline.
    ConsumerDeadline,
    /// Establishing a consumer subscription.
    ConsumerSubscribe,
    /// Claiming an inbox identity.
    ConsumerClaim,
    /// Checking or renewing an inbox lease.
    ConsumerLease,
    /// Executing the provider transaction that owns handler effects and the terminal receipt.
    ConsumerTransaction,
    /// Abandoning a provider delivery/session after a hard fence or primary error.
    ConsumerAbandon,
    /// Releasing a safely rolled-back inbox claim.
    ConsumerRelease,
    /// Applying a broker settlement decision.
    ConsumerSettlement,
    /// Claiming a bounded outbox batch.
    RelayClaim,
    /// Checking or extending an outbox lease.
    RelayLease,
    /// Persisting an outbox settlement.
    RelaySettlement,
    /// Constructing a relay operation deadline.
    RelayDeadline,
}

impl TransactionalMessagingRuntimePhase {
    /// Stable low-cardinality phase label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ConsumerDeadline => "consumer_deadline",
            Self::ConsumerSubscribe => "consumer_subscribe",
            Self::ConsumerClaim => "consumer_claim",
            Self::ConsumerLease => "consumer_lease",
            Self::ConsumerTransaction => "consumer_transaction",
            Self::ConsumerAbandon => "consumer_abandon",
            Self::ConsumerRelease => "consumer_release",
            Self::ConsumerSettlement => "consumer_settlement",
            Self::RelayClaim => "relay_claim",
            Self::RelayLease => "relay_lease",
            Self::RelaySettlement => "relay_settlement",
            Self::RelayDeadline => "relay_deadline",
        }
    }
}

/// Closed subscription recovery reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingSubscribeOutcome {
    /// Initial provider subscription failed.
    SubscribeError,
    /// An established delivery stream ended unexpectedly.
    StreamEnd,
    /// Processing a delivery failed transiently and forced session replacement.
    DeliveryError,
}

impl TransactionalMessagingSubscribeOutcome {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::SubscribeError => "subscribe_error",
            Self::StreamEnd => "stream_end",
            Self::DeliveryError => "delivery_error",
        }
    }
}

/// Closed TransactionalMessaging observation. No variant can carry identity or free-form data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingObservation {
    /// A runtime port boundary failed with a closed phase and error kind.
    RuntimeFailure {
        /// Provider-neutral phase that failed.
        phase: TransactionalMessagingRuntimePhase,
        /// Closed error classification without provider text.
        kind: MessagingErrorKind,
    },
    /// One outbox settlement.
    OutboxPublish {
        /// Requested publication disposition; this observation itself proves no durable mutation.
        status: TransactionalMessagingDisposition,
    },
    /// Safe failure detail retained by the publisher mapping boundary.
    #[cfg(feature = "producer")]
    OutboxPublishFailure {
        /// Provider-neutral stage at which publication failed.
        stage: crate::transport::PublishFailureStage,
        /// Closed reason without provider text or message identity.
        reason: crate::transport::PublishFailureReason,
        /// Whether the provider may have accepted the message.
        ambiguous: bool,
    },
    /// One complete outbox backlog sample.
    OutboxBacklog {
        /// Number of pending outbox records in the sample.
        pending_depth: u64,
        /// Age of the oldest pending record.
        oldest_pending_age: Duration,
        /// Number of records waiting behind unresolved partition heads.
        partition_blocked_depth: u64,
    },
    /// Outbox backlog is not authoritative.
    OutboxBacklogUnavailable,
    /// One relay phase duration.
    RelayTick {
        /// Relay work whose elapsed time was measured.
        phase: TransactionalMessagingRelayPhase,
        /// Elapsed time for that phase.
        duration: Duration,
    },
    /// One complete inbox backlog sample.
    InboxBacklog {
        /// Number of stale inbox claims observed.
        stale_claim_depth: u64,
        /// Age of the oldest stale claim.
        oldest_stale_claim_age: Duration,
    },
    /// Inbox backlog is not authoritative.
    InboxBacklogUnavailable,
    /// An in-progress claim was observed.
    ConsumerClaimInProgress,
    /// An ingress envelope was rejected with a stable provider-neutral reason.
    #[cfg(feature = "consumer")]
    ConsumerIngressRejected {
        /// Closed validation reason safe for structured observations.
        reason: crate::transaction::EnvelopeValidationFailure,
    },
    /// One consumer transaction result.
    ConsumerTransaction {
        /// Transaction outcome classification, independent of broker settlement success.
        status: TransactionalMessagingTransactionStatus,
    },
    /// One broker settlement result.
    ConsumerSettlement {
        /// Broker action attempted for this delivery.
        action: TransactionalMessagingDisposition,
        /// Whether the settlement call returned success or error.
        outcome: TransactionalMessagingIoOutcome,
    },
    /// One supervised subscription recovery trigger.
    ConsumerSubscribeRetry {
        /// Trigger for retrying subscription establishment.
        outcome: TransactionalMessagingSubscribeOutcome,
    },
    /// Consumer ownership was fenced.
    ConsumerLeaseLost,
    /// Relay ownership was fenced before publication or settlement.
    RelayLeaseLost,
    /// Inbox claim release failed after another failure.
    ConsumerReleaseFailed,
}

impl TransactionalMessagingObservation {
    /// Static tracing event identity for this observation.
    #[must_use]
    pub const fn event(self) -> TransactionalMessagingEvent {
        match self {
            Self::RuntimeFailure { .. } => TransactionalMessagingEvent::RuntimeFailure,
            Self::OutboxPublish { .. } => TransactionalMessagingEvent::OutboxPublish,
            #[cfg(feature = "producer")]
            Self::OutboxPublishFailure { .. } => TransactionalMessagingEvent::OutboxPublishFailure,
            Self::OutboxBacklog { .. } => TransactionalMessagingEvent::OutboxBacklog,
            Self::OutboxBacklogUnavailable => TransactionalMessagingEvent::OutboxBacklogUnavailable,
            Self::RelayTick { .. } => TransactionalMessagingEvent::OutboxRelayTick,
            Self::InboxBacklog { .. } => TransactionalMessagingEvent::InboxBacklog,
            Self::InboxBacklogUnavailable => TransactionalMessagingEvent::InboxBacklogUnavailable,
            Self::ConsumerClaimInProgress => TransactionalMessagingEvent::ConsumerClaimInProgress,
            #[cfg(feature = "consumer")]
            Self::ConsumerIngressRejected { .. } => {
                TransactionalMessagingEvent::ConsumerIngressRejected
            }
            Self::ConsumerTransaction { .. } => TransactionalMessagingEvent::ConsumerTransaction,
            Self::ConsumerSettlement { .. } => TransactionalMessagingEvent::ConsumerSettlement,
            Self::ConsumerSubscribeRetry { .. } => {
                TransactionalMessagingEvent::ConsumerSubscribeRetry
            }
            Self::ConsumerLeaseLost => TransactionalMessagingEvent::ConsumerLeaseLost,
            Self::RelayLeaseLost => TransactionalMessagingEvent::RelayLeaseLost,
            Self::ConsumerReleaseFailed => TransactionalMessagingEvent::ConsumerReleaseFailed,
        }
    }
}

/// Provider-neutral sink for closed TransactionalMessaging observations.
pub trait TransactionalMessagingEmitter: Send + Sync {
    /// Export the observation using its fixed identity and typed fields.
    /// Keep this synchronous callback bounded; do not add identity or free-form provider data.
    fn emit(&self, observation: TransactionalMessagingObservation);
}

/// Closed canonical metric identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingMetric {
    /// Count of runtime port failures by phase and closed error kind.
    RuntimeFailureTotal,
    /// Count of outbox publish outcomes.
    OutboxPublishTotal,
    /// Count of safe outbox publication failure diagnostics.
    OutboxPublishFailureTotal,
    /// Current number of pending outbox records.
    OutboxPendingDepth,
    /// Age in seconds of the oldest pending outbox record.
    OutboxOldestPendingAgeSeconds,
    /// Current number of outbox records blocked by partition ordering.
    OutboxPartitionBlockedDepth,
    /// Duration in seconds of each outbox relay tick phase.
    OutboxRelayTickDurationSeconds,
    /// Current number of stale inbox claims.
    InboxStaleClaimDepth,
    /// Age in seconds of the oldest stale inbox claim.
    InboxOldestStaleClaimAgeSeconds,
    /// Count of consumer claims already in progress.
    ConsumerClaimInProgressTotal,
    /// Count of ingress validation rejections by closed reason.
    ConsumerIngressRejectedTotal,
    /// Count of consumer transaction outcomes.
    ConsumerTransactionOutcomeTotal,
    /// Count of consumer settlement outcomes by action.
    ConsumerSettlementTotal,
    /// Count of consumer subscription retry outcomes.
    ConsumerSubscribeRetryTotal,
    /// Count of consumer lease-loss detections.
    ConsumerLeaseLostTotal,
    /// Count of relay lease-loss detections.
    RelayLeaseLostTotal,
    /// Count of failed consumer releases.
    ConsumerReleaseFailedTotal,
}

impl TransactionalMessagingMetric {
    /// Complete metric inventory in stable order.
    pub const ALL: [Self; 17] = [
        Self::RuntimeFailureTotal,
        Self::OutboxPublishTotal,
        Self::OutboxPublishFailureTotal,
        Self::OutboxPendingDepth,
        Self::OutboxOldestPendingAgeSeconds,
        Self::OutboxPartitionBlockedDepth,
        Self::OutboxRelayTickDurationSeconds,
        Self::InboxStaleClaimDepth,
        Self::InboxOldestStaleClaimAgeSeconds,
        Self::ConsumerClaimInProgressTotal,
        Self::ConsumerIngressRejectedTotal,
        Self::ConsumerTransactionOutcomeTotal,
        Self::ConsumerSettlementTotal,
        Self::ConsumerSubscribeRetryTotal,
        Self::ConsumerLeaseLostTotal,
        Self::RelayLeaseLostTotal,
        Self::ConsumerReleaseFailedTotal,
    ];

    /// Stable metric family name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RuntimeFailureTotal => "transactional_messaging_runtime_failure_total",
            Self::OutboxPublishTotal => "outbox_publish_total",
            Self::OutboxPublishFailureTotal => "outbox_publish_failure_total",
            Self::OutboxPendingDepth => "outbox_pending_depth",
            Self::OutboxOldestPendingAgeSeconds => "outbox_oldest_pending_age_seconds",
            Self::OutboxPartitionBlockedDepth => "outbox_partition_blocked_depth",
            Self::OutboxRelayTickDurationSeconds => "outbox_relay_tick_duration_seconds",
            Self::InboxStaleClaimDepth => "inbox_stale_claim_depth",
            Self::InboxOldestStaleClaimAgeSeconds => "inbox_oldest_stale_claim_age_seconds",
            Self::ConsumerClaimInProgressTotal => "consumer_claim_in_progress_total",
            Self::ConsumerIngressRejectedTotal => "transactional_messaging_ingress_rejected_total",
            Self::ConsumerTransactionOutcomeTotal => "consumer_tx_outcome_total",
            Self::ConsumerSettlementTotal => "consumer_settle_total",
            Self::ConsumerSubscribeRetryTotal => "consumer_subscribe_retry_total",
            Self::ConsumerLeaseLostTotal => "consumer_lease_lost_total",
            Self::RelayLeaseLostTotal => "outbox_relay_lease_lost_total",
            Self::ConsumerReleaseFailedTotal => "consumer_release_failed_total",
        }
    }

    /// Exact label-key set in stable order.
    #[must_use]
    pub const fn label_keys(self) -> &'static [&'static str] {
        match self {
            Self::RuntimeFailureTotal => &["phase", "kind"],
            Self::OutboxPublishTotal => &["status"],
            Self::OutboxPublishFailureTotal => &["stage", "reason", "ambiguous"],
            Self::OutboxRelayTickDurationSeconds => &["phase"],
            Self::ConsumerTransactionOutcomeTotal => &["outcome"],
            Self::ConsumerSettlementTotal => &["action", "outcome"],
            Self::ConsumerIngressRejectedTotal => &["reason"],
            Self::ConsumerSubscribeRetryTotal => &["outcome"],
            Self::OutboxPendingDepth
            | Self::OutboxOldestPendingAgeSeconds
            | Self::OutboxPartitionBlockedDepth
            | Self::InboxStaleClaimDepth
            | Self::InboxOldestStaleClaimAgeSeconds
            | Self::ConsumerClaimInProgressTotal
            | Self::ConsumerLeaseLostTotal
            | Self::RelayLeaseLostTotal
            | Self::ConsumerReleaseFailedTotal => &[],
        }
    }
}

/// Closed canonical structured-event identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalMessagingEvent {
    /// One managed runtime provider-I/O failure.
    RuntimeFailure,
    /// One outbox publish outcome.
    OutboxPublish,
    /// One safe outbox publication failure diagnostic.
    OutboxPublishFailure,
    /// One available outbox backlog sample.
    OutboxBacklog,
    /// Failure to obtain an outbox backlog sample.
    OutboxBacklogUnavailable,
    /// One measured outbox relay tick phase.
    OutboxRelayTick,
    /// One available inbox backlog sample.
    InboxBacklog,
    /// Failure to obtain an inbox backlog sample.
    InboxBacklogUnavailable,
    /// A consumer claim that is already in progress.
    ConsumerClaimInProgress,
    /// One ingress rejection with a closed reason.
    ConsumerIngressRejected,
    /// One consumer transaction outcome.
    ConsumerTransaction,
    /// One consumer settlement outcome.
    ConsumerSettlement,
    /// One consumer subscription retry outcome.
    ConsumerSubscribeRetry,
    /// A consumer lease-loss detection.
    ConsumerLeaseLost,
    /// A relay lease-loss detection.
    RelayLeaseLost,
    /// A failed consumer release.
    ConsumerReleaseFailed,
}

impl TransactionalMessagingEvent {
    /// Complete event inventory in stable order.
    pub const ALL: [Self; 16] = [
        Self::RuntimeFailure,
        Self::OutboxPublish,
        Self::OutboxPublishFailure,
        Self::OutboxBacklog,
        Self::OutboxBacklogUnavailable,
        Self::OutboxRelayTick,
        Self::InboxBacklog,
        Self::InboxBacklogUnavailable,
        Self::ConsumerClaimInProgress,
        Self::ConsumerIngressRejected,
        Self::ConsumerTransaction,
        Self::ConsumerSettlement,
        Self::ConsumerSubscribeRetry,
        Self::ConsumerLeaseLost,
        Self::RelayLeaseLost,
        Self::ConsumerReleaseFailed,
    ];

    /// Stable tracing event name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RuntimeFailure => "transactional_messaging.runtime.failure",
            Self::OutboxPublish => "transactional_messaging.outbox.publish",
            Self::OutboxPublishFailure => "transactional_messaging.outbox.publish_failure",
            Self::OutboxBacklog => "transactional_messaging.outbox.backlog",
            Self::OutboxBacklogUnavailable => "transactional_messaging.outbox.backlog_unavailable",
            Self::OutboxRelayTick => "transactional_messaging.outbox.relay_tick",
            Self::InboxBacklog => "transactional_messaging.inbox.backlog",
            Self::InboxBacklogUnavailable => "transactional_messaging.inbox.backlog_unavailable",
            Self::ConsumerClaimInProgress => "transactional_messaging.consumer.claim_in_progress",
            Self::ConsumerIngressRejected => "transactional_messaging.consumer.ingress_rejected",
            Self::ConsumerTransaction => "transactional_messaging.consumer.transaction",
            Self::ConsumerSettlement => "transactional_messaging.consumer.settlement",
            Self::ConsumerSubscribeRetry => "transactional_messaging.consumer.subscribe_retry",
            Self::ConsumerLeaseLost => "transactional_messaging.consumer.lease_lost",
            Self::RelayLeaseLost => "transactional_messaging.outbox.relay_lease_lost",
            Self::ConsumerReleaseFailed => "transactional_messaging.consumer.release_failed",
        }
    }

    /// Exact structured field-key set in stable order.
    #[must_use]
    pub const fn field_keys(self) -> &'static [&'static str] {
        match self {
            Self::RuntimeFailure => &["phase", "kind"],
            Self::OutboxPublish => &["status"],
            Self::OutboxPublishFailure => &["stage", "reason", "ambiguous"],
            Self::OutboxBacklog => &[
                "pending_depth",
                "oldest_pending_age_seconds",
                "partition_blocked_depth",
            ],
            Self::OutboxRelayTick => &["phase", "duration_seconds"],
            Self::InboxBacklog => &["stale_claim_depth", "oldest_stale_claim_age_seconds"],
            Self::ConsumerTransaction => &["outcome"],
            Self::ConsumerSettlement => &["action", "outcome"],
            Self::ConsumerIngressRejected => &["reason"],
            Self::ConsumerSubscribeRetry => &["outcome"],
            Self::OutboxBacklogUnavailable
            | Self::InboxBacklogUnavailable
            | Self::ConsumerClaimInProgress
            | Self::ConsumerLeaseLost
            | Self::RelayLeaseLost
            | Self::ConsumerReleaseFailed => &[],
        }
    }
}

/// Immutable exact inventory for proof and provider implementations.
pub struct TransactionalMessagingObservabilityDescriptor {
    metrics: &'static [TransactionalMessagingMetric],
    events: &'static [TransactionalMessagingEvent],
}

impl TransactionalMessagingObservabilityDescriptor {
    /// Complete canonical metric inventory.
    #[must_use]
    pub const fn metrics(&self) -> &'static [TransactionalMessagingMetric] {
        self.metrics
    }

    /// Complete canonical event inventory.
    #[must_use]
    pub const fn events(&self) -> &'static [TransactionalMessagingEvent] {
        self.events
    }
}

const TRANSACTIONAL_MESSAGING_OBSERVABILITY_DESCRIPTOR:
    TransactionalMessagingObservabilityDescriptor = TransactionalMessagingObservabilityDescriptor {
    metrics: &TransactionalMessagingMetric::ALL,
    events: &TransactionalMessagingEvent::ALL,
};

/// Returns the immutable canonical TransactionalMessaging telemetry inventory.
#[must_use]
pub const fn transactional_messaging_observability_descriptor()
-> &'static TransactionalMessagingObservabilityDescriptor {
    &TRANSACTIONAL_MESSAGING_OBSERVABILITY_DESCRIPTOR
}
