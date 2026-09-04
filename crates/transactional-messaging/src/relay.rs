//! Provider-neutral, bounded outbox relay algorithm.

use crate::error::{MessagingError, MessagingErrorKind};
use crate::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingEmitter,
    TransactionalMessagingObservation, TransactionalMessagingRelayPhase,
};
use crate::outbox::{OutboxDisposition, OutboxLeaseStatus, OutboxSettlement, OutboxStore};
use crate::policy::{AbsoluteDeadline, Clock, DeliveryBudget, OperationDeadline};
use crate::transport::Publisher;

/// Counts the closed outcomes produced by one bounded relay batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayReport {
    claimed: usize,
    published: usize,
    retried: usize,
    dead_lettered: usize,
    fenced: usize,
}

impl RelayReport {
    /// Number of durable claims admitted into this batch.
    #[must_use]
    pub const fn claimed(self) -> usize {
        self.claimed
    }
    /// Number of claims settled as durably published.
    #[must_use]
    pub const fn published(self) -> usize {
        self.published
    }
    /// Number of claims returned for same-identity retry.
    #[must_use]
    pub const fn retried(self) -> usize {
        self.retried
    }
    /// Number of permanently rejected publishes moved to dead letter.
    #[must_use]
    pub const fn dead_lettered(self) -> usize {
        self.dead_lettered
    }
    /// Number of claims fenced before publication.
    #[must_use]
    pub const fn fenced(self) -> usize {
        self.fenced
    }
}

/// Relay one bounded batch using a fresh absolute deadline for every provider operation.
///
/// The store remains the authority for ordering, lease identity and settlement CAS. A lease that
/// cannot cover one publish plus settlement is returned for retry; only a definitive permanent
/// publisher result may enter dead letter.
pub async fn relay_once<P, S, U>(
    store: &S,
    publisher: &U,
    clock: &impl Clock,
    budget: DeliveryBudget,
    emitter: &impl TransactionalMessagingEmitter,
    limit: usize,
) -> Result<RelayReport, MessagingError>
where
    S: OutboxStore<P>,
    U: Publisher<P, Receipt = S::PublishReceipt>,
{
    let claim_started = clock.now();
    let claims = store
        .claim_partition_heads(limit, operation_deadline(clock, budget.settle_timeout())?)
        .await?;
    emitter.emit(TransactionalMessagingObservation::RelayTick {
        phase: TransactionalMessagingRelayPhase::Claim,
        duration: clock.now().saturating_duration_since(claim_started),
    });
    let mut report = RelayReport {
        claimed: claims.len(),
        ..RelayReport::default()
    };
    for claim in claims {
        match relay_claim(store, publisher, clock, budget, emitter, claim).await? {
            None => report.fenced += 1,
            Some(OutboxDisposition::Published) => report.published += 1,
            Some(OutboxDisposition::Retry) => report.retried += 1,
            Some(OutboxDisposition::DeadLetter) => report.dead_lettered += 1,
        }
    }
    Ok(report)
}

async fn relay_claim<P, S, U>(
    store: &S,
    publisher: &U,
    clock: &impl Clock,
    budget: DeliveryBudget,
    emitter: &impl TransactionalMessagingEmitter,
    claim: S::Claim,
) -> Result<Option<OutboxDisposition>, MessagingError>
where
    S: OutboxStore<P>,
    U: Publisher<P, Receipt = S::PublishReceipt>,
{
    if matches!(
        store
            .lease_status(&claim, operation_deadline(clock, budget.settle_timeout())?)
            .await?,
        OutboxLeaseStatus::Lost
    ) {
        return Ok(None);
    }
    let remaining = match store
        .extend(&claim, operation_deadline(clock, budget.settle_timeout())?)
        .await?
    {
        OutboxLeaseStatus::Held { remaining } => remaining,
        OutboxLeaseStatus::Lost => return Ok(None),
    };
    let publish_started = clock.now();
    let attempt_deadline = if budget.can_start_attempt(remaining) {
        Some(
            AbsoluteDeadline::from_timeout(clock, remaining.saturating_sub(budget.safety_margin()))
                .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))?,
        )
    } else {
        None
    };
    let settlement = match attempt_deadline {
        Some(deadline) => {
            let outcome = publisher
                .publish(
                    S::message(&claim).envelope(),
                    deadline.operation_capped(clock, budget.publish_timeout()),
                )
                .await;
            if let Some(failure) = outcome.failure() {
                emitter.emit(TransactionalMessagingObservation::OutboxPublishFailure {
                    stage: failure.stage(),
                    reason: failure.reason(),
                    ambiguous: outcome.is_ambiguous(),
                });
            }
            outcome.into_settlement()
        }
        None => OutboxSettlement::Retry,
    };
    let disposition = settlement.disposition();
    let settlement_deadline = match attempt_deadline {
        Some(deadline) => deadline.operation_capped(clock, budget.settle_timeout()),
        None => operation_deadline(clock, budget.settle_timeout())?,
    };
    store.settle(claim, settlement, settlement_deadline).await?;
    emitter.emit(TransactionalMessagingObservation::RelayTick {
        phase: TransactionalMessagingRelayPhase::Publish,
        duration: clock.now().saturating_duration_since(publish_started),
    });
    emitter.emit(TransactionalMessagingObservation::OutboxPublish {
        status: match disposition {
            OutboxDisposition::Published => TransactionalMessagingDisposition::Ack,
            OutboxDisposition::Retry => TransactionalMessagingDisposition::Requeue,
            OutboxDisposition::DeadLetter => TransactionalMessagingDisposition::Reject,
        },
    });
    Ok(Some(disposition))
}

fn operation_deadline(
    clock: &impl Clock,
    timeout: std::time::Duration,
) -> Result<OperationDeadline, MessagingError> {
    AbsoluteDeadline::from_timeout(clock, timeout)
        .map(|deadline| deadline.operation(clock))
        .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant, error))
}
