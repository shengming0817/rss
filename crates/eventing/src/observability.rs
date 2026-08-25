//! Closed, provider-neutral Eventing telemetry vocabulary and emission contract.
//!
//! Metric/event identities and all categorical values are statically owned here. Observations can
//! carry only bounded enums, counts, and durations; tenant or event identity, payload, free-form
//! error text, and provider addresses are not representable.
//!
//! ref: tokio-rs/tracing tracing/src/macros.rs@main
//! ref: metrics-rs/metrics metrics/src/macros.rs@main

use std::time::Duration;

/// Broker disposition used by publication and settlement telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingDisposition {
    /// Delivery completed successfully.
    Ack,
    /// Delivery is eligible for another attempt.
    Requeue,
    /// Delivery was rejected terminally.
    Reject,
}

impl EventingDisposition {
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
pub enum EventingRelayPhase {
    /// Durable claim phase.
    Claim,
    /// Provider publication and settlement phase.
    Publish,
}

impl EventingRelayPhase {
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
pub enum EventingTransactionStatus {
    /// The transaction committed durably.
    Committed,
    /// Handler failure may be retried locally.
    HandlerTransient,
    /// Infrastructure failure requires broker redelivery.
    InfrastructureTransient,
    /// A permanently invalid delivery was rejected.
    RejectedPermanent,
    /// A trusted invariant was contradicted.
    RejectedInvariant,
    /// Commit acknowledgement was ambiguous.
    CommitUnknown,
    /// Rollback acknowledgement failed.
    RollbackFailed,
    /// The inbox lease was fenced.
    Fenced,
}

impl EventingTransactionStatus {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::HandlerTransient => "handler_transient",
            Self::InfrastructureTransient => "infrastructure_transient",
            Self::RejectedPermanent => "rejected_permanent",
            Self::RejectedInvariant => "rejected_invariant",
            Self::CommitUnknown => "commit_unknown",
            Self::RollbackFailed => "rollback_failed",
            Self::Fenced => "fenced",
        }
    }
}

/// Closed result of Eventing provider I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingIoOutcome {
    /// The operation succeeded.
    Ok,
    /// The operation failed without exposing provider error text.
    Error,
}

impl EventingIoOutcome {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// Closed subscription recovery reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingSubscribeOutcome {
    /// Initial provider subscription failed.
    SubscribeError,
    /// An established delivery stream ended unexpectedly.
    StreamEnd,
}

impl EventingSubscribeOutcome {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::SubscribeError => "subscribe_error",
            Self::StreamEnd => "stream_end",
        }
    }
}

/// Closed reason why a fail-closed consumer path skipped application dead-letter storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingDeadLetterSkipReason {
    /// Message identifier was not a valid idempotency key.
    MalformedId,
    /// Tenant authority evidence was absent.
    TenantAuthorityMissing,
    /// Tenant authority evidence was malformed or unauthentic.
    TenantAuthorityInvalid,
    /// Tenant authority evidence was outside its validity window.
    TenantAuthorityExpired,
    /// Tenant authority evidence did not bind the envelope.
    TenantAuthorityBindingMismatch,
    /// Required tenant metadata was absent.
    EnvelopeMissingTenantId,
    /// Tenant metadata was invalid.
    EnvelopeInvalidTenantId,
    /// Required occurrence time was absent.
    EnvelopeMissingOccurredAt,
    /// Occurrence time was invalid.
    EnvelopeInvalidOccurredAt,
    /// Required schema version was absent.
    EnvelopeMissingSchemaVersion,
    /// Schema version was invalid.
    EnvelopeInvalidSchemaVersion,
    /// Required schema digest was absent.
    EnvelopeMissingSchemaHash,
    /// Schema digest was invalid.
    EnvelopeInvalidSchemaHash,
    /// Schema version contradicted the binding.
    EnvelopeSchemaVersionMismatch,
    /// Schema digest contradicted the binding.
    EnvelopeSchemaHashMismatch,
    /// The generated consumer group was invalid.
    InboxReceiptInvalidConsumerGroup,
    /// Receipt domain was empty.
    InboxReceiptEmptyDomain,
    /// Receipt topic was empty.
    InboxReceiptEmptyTopic,
    /// Receipt contract identity was empty.
    InboxReceiptEmptyContractId,
    /// Receipt contract version was invalid.
    InboxReceiptInvalidContractVersion,
    /// Receipt schema digest was invalid.
    InboxReceiptInvalidSchemaHash,
    /// Receipt trace context was invalid.
    InboxReceiptInvalidTrace,
    /// Receipt correlation context was invalid.
    InboxReceiptInvalidCorrelationId,
    /// Receipt context failed another closed validation.
    InboxReceiptInvalidContext,
}

impl EventingDeadLetterSkipReason {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::MalformedId => "malformed_id",
            Self::TenantAuthorityMissing => "tenant_authority_missing",
            Self::TenantAuthorityInvalid => "tenant_authority_invalid",
            Self::TenantAuthorityExpired => "tenant_authority_expired",
            Self::TenantAuthorityBindingMismatch => "tenant_authority_binding_mismatch",
            Self::EnvelopeMissingTenantId => "envelope_missing_tenant_id",
            Self::EnvelopeInvalidTenantId => "envelope_invalid_tenant_id",
            Self::EnvelopeMissingOccurredAt => "envelope_missing_occurred_at",
            Self::EnvelopeInvalidOccurredAt => "envelope_invalid_occurred_at",
            Self::EnvelopeMissingSchemaVersion => "envelope_missing_schema_version",
            Self::EnvelopeInvalidSchemaVersion => "envelope_invalid_schema_version",
            Self::EnvelopeMissingSchemaHash => "envelope_missing_schema_hash",
            Self::EnvelopeInvalidSchemaHash => "envelope_invalid_schema_hash",
            Self::EnvelopeSchemaVersionMismatch => "envelope_schema_version_mismatch",
            Self::EnvelopeSchemaHashMismatch => "envelope_schema_hash_mismatch",
            Self::InboxReceiptInvalidConsumerGroup => "inbox_receipt_invalid_consumer_group",
            Self::InboxReceiptEmptyDomain => "inbox_receipt_empty_domain",
            Self::InboxReceiptEmptyTopic => "inbox_receipt_empty_topic",
            Self::InboxReceiptEmptyContractId => "inbox_receipt_empty_contract_id",
            Self::InboxReceiptInvalidContractVersion => "inbox_receipt_invalid_contract_version",
            Self::InboxReceiptInvalidSchemaHash => "inbox_receipt_invalid_schema_hash",
            Self::InboxReceiptInvalidTrace => "inbox_receipt_invalid_trace",
            Self::InboxReceiptInvalidCorrelationId => "inbox_receipt_invalid_correlation_id",
            Self::InboxReceiptInvalidContext => "inbox_receipt_invalid_context",
        }
    }
}

/// Closed failure classification for application dead-letter replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingDeadLetterReplayFailure {
    /// The requested entry was absent.
    NotFound,
    /// The entry cannot be replayed.
    NotReplayable,
    /// Payload validation failed.
    InvalidPayload,
    /// Schema header validation failed.
    InvalidSchemaHeaders,
    /// Payload key service was unavailable.
    PayloadKeyUnavailable,
    /// Payload key authorization or configuration was rejected.
    PayloadKeyForbidden,
    /// Durable outbox fact identity conflicted.
    FactConflict,
    /// Dead-letter fetch failed.
    FetchDeadLetter,
    /// Metadata encoding failed.
    EncodeMetadata,
    /// Outbox append failed.
    AppendOutbox,
    /// Projection mirror failed.
    ProjectionMirror,
    /// Transaction completion failed.
    Transaction,
    /// Generic store operation failed.
    Store,
    /// A caller reached replay through an impossible operation/error pairing.
    Invariant,
}

impl EventingDeadLetterReplayFailure {
    /// Stable metric/event field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotReplayable => "not_replayable",
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidSchemaHeaders => "invalid_schema_headers",
            Self::PayloadKeyUnavailable => "payload_key_unavailable",
            Self::PayloadKeyForbidden => "payload_key_forbidden",
            Self::FactConflict => "fact_conflict",
            Self::FetchDeadLetter => "fetch_dead_letter",
            Self::EncodeMetadata => "encode_metadata",
            Self::AppendOutbox => "append_outbox",
            Self::ProjectionMirror => "projection_mirror",
            Self::Transaction => "transaction",
            Self::Store => "store",
            Self::Invariant => "invariant",
        }
    }
}

/// Closed failure classification for restoring an outbox DLX row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingOutboxDlxRedriveFailure {
    /// The provider store operation failed.
    Store,
    /// A caller reached redrive through an impossible operation/error pairing.
    Invariant,
}

impl EventingOutboxDlxRedriveFailure {
    /// Stable outcome field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Invariant => "invariant",
        }
    }
}

/// Closed failure classification for resolving an expired outbox DLX row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingOutboxDlxResolveFailure {
    /// Expired-resolution input was invalid.
    InvalidResolutionInput,
    /// The provider store operation failed.
    Store,
    /// A caller reached resolution through an impossible operation/error pairing.
    Invariant,
}

impl EventingOutboxDlxResolveFailure {
    /// Stable outcome field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::InvalidResolutionInput => "invalid_resolution_input",
            Self::Store => "store",
            Self::Invariant => "invariant",
        }
    }
}

/// Typed result of replaying an application dead-letter record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingDeadLetterReplayResult {
    /// A new outbox fact was inserted.
    Inserted,
    /// The same outbox fact already existed.
    AlreadyExists,
    /// Replay failed at a closed stage.
    Failed(EventingDeadLetterReplayFailure),
}

impl EventingDeadLetterReplayResult {
    /// Stable outcome field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Inserted => "inserted",
            Self::AlreadyExists => "already_exists",
            Self::Failed(failure) => failure.as_label(),
        }
    }
}

/// Typed result of restoring an outbox DLX row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingOutboxDlxRedriveResult {
    /// The row returned to pending delivery.
    Redriven,
    /// The row was absent.
    NotFound,
    /// The redrive deadline elapsed.
    Expired,
    /// Redrive failed at a closed stage.
    Failed(EventingOutboxDlxRedriveFailure),
}

impl EventingOutboxDlxRedriveResult {
    /// Stable outcome field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Redriven => "redriven",
            Self::NotFound => "not_found",
            Self::Expired => "expired",
            Self::Failed(failure) => failure.as_label(),
        }
    }
}

/// Typed result of resolving an expired outbox DLX row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingOutboxDlxResolveResult {
    /// The row was resolved terminally.
    Resolved,
    /// The row was absent.
    NotFound,
    /// The row was not yet expired.
    NotExpired,
    /// Submitted evidence was rejected.
    EvidenceRejected,
    /// Resolution failed at a closed stage.
    Failed(EventingOutboxDlxResolveFailure),
}

impl EventingOutboxDlxResolveResult {
    /// Stable outcome field value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NotFound => "not_found",
            Self::NotExpired => "not_expired",
            Self::EvidenceRejected => "evidence_rejected",
            Self::Failed(failure) => failure.as_label(),
        }
    }
}

/// Closed Eventing observation. No variant can carry identity or free-form data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingObservation {
    /// One outbox settlement.
    OutboxPublish { status: EventingDisposition },
    /// One complete outbox backlog sample.
    OutboxBacklog {
        pending_depth: u64,
        oldest_pending_age: Duration,
        partition_blocked_depth: u64,
    },
    /// Outbox backlog is not authoritative.
    OutboxBacklogUnavailable,
    /// One relay phase duration.
    RelayTick {
        phase: EventingRelayPhase,
        duration: Duration,
    },
    /// One complete inbox backlog sample.
    InboxBacklog {
        stale_claim_depth: u64,
        oldest_stale_claim_age: Duration,
    },
    /// Inbox backlog is not authoritative.
    InboxBacklogUnavailable,
    /// An in-progress claim was observed.
    ConsumerClaimInProgress,
    /// One consumer transaction result.
    ConsumerTransaction { status: EventingTransactionStatus },
    /// One broker settlement result.
    ConsumerSettlement {
        action: EventingDisposition,
        outcome: EventingIoOutcome,
    },
    /// Application dead-letter storage was skipped.
    ConsumerDeadLetterSkip {
        reason: EventingDeadLetterSkipReason,
    },
    /// One application dead-letter write result.
    ConsumerDeadLetterWrite { outcome: EventingIoOutcome },
    /// One supervised subscription recovery trigger.
    ConsumerSubscribeRetry { outcome: EventingSubscribeOutcome },
    /// Consumer ownership was fenced.
    ConsumerLeaseLost,
    /// Inbox claim release failed after another failure.
    ConsumerReleaseFailed,
    /// One application dead-letter replay result.
    DeadLetterReplay {
        result: EventingDeadLetterReplayResult,
    },
    /// One outbox DLX redrive result.
    OutboxDlxRedrive {
        result: EventingOutboxDlxRedriveResult,
    },
    /// One expired outbox DLX resolution result.
    OutboxDlxResolveExpired {
        result: EventingOutboxDlxResolveResult,
    },
}

impl EventingObservation {
    /// Static tracing event identity for this observation.
    #[must_use]
    pub const fn event(self) -> EventingEvent {
        match self {
            Self::OutboxPublish { .. } => EventingEvent::OutboxPublish,
            Self::OutboxBacklog { .. } => EventingEvent::OutboxBacklog,
            Self::OutboxBacklogUnavailable => EventingEvent::OutboxBacklogUnavailable,
            Self::RelayTick { .. } => EventingEvent::OutboxRelayTick,
            Self::InboxBacklog { .. } => EventingEvent::InboxBacklog,
            Self::InboxBacklogUnavailable => EventingEvent::InboxBacklogUnavailable,
            Self::ConsumerClaimInProgress => EventingEvent::ConsumerClaimInProgress,
            Self::ConsumerTransaction { .. } => EventingEvent::ConsumerTransaction,
            Self::ConsumerSettlement { .. } => EventingEvent::ConsumerSettlement,
            Self::ConsumerDeadLetterSkip { .. } => EventingEvent::ConsumerDeadLetterSkip,
            Self::ConsumerDeadLetterWrite { .. } => EventingEvent::ConsumerDeadLetterWrite,
            Self::ConsumerSubscribeRetry { .. } => EventingEvent::ConsumerSubscribeRetry,
            Self::ConsumerLeaseLost => EventingEvent::ConsumerLeaseLost,
            Self::ConsumerReleaseFailed => EventingEvent::ConsumerReleaseFailed,
            Self::DeadLetterReplay { .. }
            | Self::OutboxDlxRedrive { .. }
            | Self::OutboxDlxResolveExpired { .. } => EventingEvent::DlqMutation,
        }
    }
}

/// Provider-neutral sink for closed Eventing observations.
pub trait EventingEmitter: Send + Sync {
    /// Emit one complete observation.
    fn emit(&self, observation: EventingObservation);
}

/// Closed canonical metric identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingMetric {
    OutboxPublishTotal,
    OutboxPendingDepth,
    OutboxOldestPendingAgeSeconds,
    OutboxPartitionBlockedDepth,
    OutboxRelayTickDurationSeconds,
    InboxStaleClaimDepth,
    InboxOldestStaleClaimAgeSeconds,
    ConsumerClaimInProgressTotal,
    ConsumerTransactionOutcomeTotal,
    ConsumerSettlementTotal,
    ConsumerDeadLetterSkipTotal,
    ConsumerDeadLetterWriteTotal,
    ConsumerSubscribeRetryTotal,
    ConsumerLeaseLostTotal,
    ConsumerReleaseFailedTotal,
    DlqRedriveTotal,
}

impl EventingMetric {
    /// Complete metric inventory in stable order.
    pub const ALL: [Self; 16] = [
        Self::OutboxPublishTotal,
        Self::OutboxPendingDepth,
        Self::OutboxOldestPendingAgeSeconds,
        Self::OutboxPartitionBlockedDepth,
        Self::OutboxRelayTickDurationSeconds,
        Self::InboxStaleClaimDepth,
        Self::InboxOldestStaleClaimAgeSeconds,
        Self::ConsumerClaimInProgressTotal,
        Self::ConsumerTransactionOutcomeTotal,
        Self::ConsumerSettlementTotal,
        Self::ConsumerDeadLetterSkipTotal,
        Self::ConsumerDeadLetterWriteTotal,
        Self::ConsumerSubscribeRetryTotal,
        Self::ConsumerLeaseLostTotal,
        Self::ConsumerReleaseFailedTotal,
        Self::DlqRedriveTotal,
    ];

    /// Stable metric family name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OutboxPublishTotal => "outbox_publish_total",
            Self::OutboxPendingDepth => "outbox_pending_depth",
            Self::OutboxOldestPendingAgeSeconds => "outbox_oldest_pending_age_seconds",
            Self::OutboxPartitionBlockedDepth => "outbox_partition_blocked_depth",
            Self::OutboxRelayTickDurationSeconds => "outbox_relay_tick_duration_seconds",
            Self::InboxStaleClaimDepth => "inbox_stale_claim_depth",
            Self::InboxOldestStaleClaimAgeSeconds => "inbox_oldest_stale_claim_age_seconds",
            Self::ConsumerClaimInProgressTotal => "consumer_claim_in_progress_total",
            Self::ConsumerTransactionOutcomeTotal => "consumer_tx_outcome_total",
            Self::ConsumerSettlementTotal => "consumer_settle_total",
            Self::ConsumerDeadLetterSkipTotal => "consumer_dlx_skip_total",
            Self::ConsumerDeadLetterWriteTotal => "consumer_dlx_write_total",
            Self::ConsumerSubscribeRetryTotal => "consumer_subscribe_retry_total",
            Self::ConsumerLeaseLostTotal => "consumer_lease_lost_total",
            Self::ConsumerReleaseFailedTotal => "consumer_release_failed_total",
            Self::DlqRedriveTotal => "dlq_redrive_total",
        }
    }

    /// Exact label-key set in stable order.
    #[must_use]
    pub const fn label_keys(self) -> &'static [&'static str] {
        match self {
            Self::OutboxPublishTotal => &["status"],
            Self::OutboxRelayTickDurationSeconds => &["phase"],
            Self::ConsumerTransactionOutcomeTotal => &["outcome"],
            Self::ConsumerSettlementTotal => &["action", "outcome"],
            Self::ConsumerDeadLetterSkipTotal => &["reason"],
            Self::ConsumerDeadLetterWriteTotal | Self::ConsumerSubscribeRetryTotal => &["outcome"],
            Self::DlqRedriveTotal => &["kind", "outcome"],
            Self::OutboxPendingDepth
            | Self::OutboxOldestPendingAgeSeconds
            | Self::OutboxPartitionBlockedDepth
            | Self::InboxStaleClaimDepth
            | Self::InboxOldestStaleClaimAgeSeconds
            | Self::ConsumerClaimInProgressTotal
            | Self::ConsumerLeaseLostTotal
            | Self::ConsumerReleaseFailedTotal => &[],
        }
    }
}

/// Closed canonical structured-event identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventingEvent {
    OutboxPublish,
    OutboxBacklog,
    OutboxBacklogUnavailable,
    OutboxRelayTick,
    InboxBacklog,
    InboxBacklogUnavailable,
    ConsumerClaimInProgress,
    ConsumerTransaction,
    ConsumerSettlement,
    ConsumerDeadLetterSkip,
    ConsumerDeadLetterWrite,
    ConsumerSubscribeRetry,
    ConsumerLeaseLost,
    ConsumerReleaseFailed,
    DlqMutation,
}

impl EventingEvent {
    /// Complete event inventory in stable order.
    pub const ALL: [Self; 15] = [
        Self::OutboxPublish,
        Self::OutboxBacklog,
        Self::OutboxBacklogUnavailable,
        Self::OutboxRelayTick,
        Self::InboxBacklog,
        Self::InboxBacklogUnavailable,
        Self::ConsumerClaimInProgress,
        Self::ConsumerTransaction,
        Self::ConsumerSettlement,
        Self::ConsumerDeadLetterSkip,
        Self::ConsumerDeadLetterWrite,
        Self::ConsumerSubscribeRetry,
        Self::ConsumerLeaseLost,
        Self::ConsumerReleaseFailed,
        Self::DlqMutation,
    ];

    /// Stable tracing event name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OutboxPublish => "eventing.outbox.publish",
            Self::OutboxBacklog => "eventing.outbox.backlog",
            Self::OutboxBacklogUnavailable => "eventing.outbox.backlog_unavailable",
            Self::OutboxRelayTick => "eventing.outbox.relay_tick",
            Self::InboxBacklog => "eventing.inbox.backlog",
            Self::InboxBacklogUnavailable => "eventing.inbox.backlog_unavailable",
            Self::ConsumerClaimInProgress => "eventing.consumer.claim_in_progress",
            Self::ConsumerTransaction => "eventing.consumer.transaction",
            Self::ConsumerSettlement => "eventing.consumer.settlement",
            Self::ConsumerDeadLetterSkip => "eventing.consumer.dead_letter_skip",
            Self::ConsumerDeadLetterWrite => "eventing.consumer.dead_letter_write",
            Self::ConsumerSubscribeRetry => "eventing.consumer.subscribe_retry",
            Self::ConsumerLeaseLost => "eventing.consumer.lease_lost",
            Self::ConsumerReleaseFailed => "eventing.consumer.release_failed",
            Self::DlqMutation => "eventing.dlq.mutation",
        }
    }

    /// Exact structured field-key set in stable order.
    #[must_use]
    pub const fn field_keys(self) -> &'static [&'static str] {
        match self {
            Self::OutboxPublish => &["status"],
            Self::OutboxBacklog => &[
                "pending_depth",
                "oldest_pending_age_seconds",
                "partition_blocked_depth",
            ],
            Self::OutboxRelayTick => &["phase", "duration_seconds"],
            Self::InboxBacklog => &["stale_claim_depth", "oldest_stale_claim_age_seconds"],
            Self::ConsumerTransaction => &["outcome"],
            Self::ConsumerSettlement => &["action", "outcome"],
            Self::ConsumerDeadLetterSkip => &["reason"],
            Self::ConsumerDeadLetterWrite | Self::ConsumerSubscribeRetry => &["outcome"],
            Self::DlqMutation => &["kind", "outcome"],
            Self::OutboxBacklogUnavailable
            | Self::InboxBacklogUnavailable
            | Self::ConsumerClaimInProgress
            | Self::ConsumerLeaseLost
            | Self::ConsumerReleaseFailed => &[],
        }
    }
}

/// Immutable exact inventory for proof and provider implementations.
pub struct EventingObservabilityDescriptor {
    metrics: &'static [EventingMetric],
    events: &'static [EventingEvent],
}

impl EventingObservabilityDescriptor {
    /// Complete canonical metric inventory.
    #[must_use]
    pub const fn metrics(&self) -> &'static [EventingMetric] {
        self.metrics
    }

    /// Complete canonical event inventory.
    #[must_use]
    pub const fn events(&self) -> &'static [EventingEvent] {
        self.events
    }
}

const EVENTING_OBSERVABILITY_DESCRIPTOR: EventingObservabilityDescriptor =
    EventingObservabilityDescriptor {
        metrics: &EventingMetric::ALL,
        events: &EventingEvent::ALL,
    };

/// Returns the immutable canonical Eventing telemetry inventory.
#[must_use]
pub const fn eventing_observability_descriptor() -> &'static EventingObservabilityDescriptor {
    &EVENTING_OBSERVABILITY_DESCRIPTOR
}
