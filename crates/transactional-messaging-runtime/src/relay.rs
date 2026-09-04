//! Bounded outbox relay execution and managed worker ownership.

use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt as _};
use rss_runtime::{ManagedTask, ManagedTaskRegistration, ShutdownError, TaskStatus};
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingEmitter,
    TransactionalMessagingObservation, TransactionalMessagingRelayPhase,
    TransactionalMessagingRuntimePhase,
};
use rss_transactional_messaging::outbox::{
    OutboxDisposition, OutboxLeaseStatus, OutboxSettlement, OutboxStore,
};
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, DeliveryBudget, ExecutionTimer, ShutdownBudget, within,
};
use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome,
    Publisher,
};
use tokio::time::MissedTickBehavior;

const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(300);
const MAX_IN_FLIGHT: usize = 64;

/// Invalid relay loop configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RelayConfigError {
    /// Polling faster than the supported operational floor would create a busy loop.
    #[error("relay poll interval must be at least 100ms")]
    PollIntervalTooSmall,
    /// Polling slower than the supported operational ceiling delays recovery excessively.
    #[error("relay poll interval must not exceed 300s")]
    PollIntervalTooLarge,
    /// The requested bounded concurrency exceeds the public runtime limit.
    #[error("relay max in flight must not exceed 64")]
    MaxInFlightExceeded,
}

/// Validated polling and backpressure configuration for one relay worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    poll_interval: Duration,
    max_in_flight: RelayBatchLimit,
}

/// Validated hard bound for both claimed entries and concurrent relay work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayBatchLimit(NonZeroUsize);

impl RelayBatchLimit {
    /// Validate a public relay batch bound.
    pub fn new(value: NonZeroUsize) -> Result<Self, RelayConfigError> {
        if value.get() > MAX_IN_FLIGHT {
            return Err(RelayConfigError::MaxInFlightExceeded);
        }
        Ok(Self(value))
    }

    /// Return the validated non-zero limit.
    #[must_use]
    pub const fn get(self) -> NonZeroUsize {
        self.0
    }
}

impl RelayConfig {
    /// Validate one relay loop configuration.
    pub fn new(
        poll_interval: Duration,
        max_in_flight: NonZeroUsize,
    ) -> Result<Self, RelayConfigError> {
        if poll_interval < MIN_POLL_INTERVAL {
            return Err(RelayConfigError::PollIntervalTooSmall);
        }
        if poll_interval > MAX_POLL_INTERVAL {
            return Err(RelayConfigError::PollIntervalTooLarge);
        }
        Ok(Self {
            poll_interval,
            max_in_flight: RelayBatchLimit::new(max_in_flight)?,
        })
    }

    /// Return the fixed polling interval.
    #[must_use]
    pub const fn poll_interval(self) -> Duration {
        self.poll_interval
    }

    /// Return the hard concurrency and claim bound.
    #[must_use]
    pub const fn max_in_flight(self) -> RelayBatchLimit {
        self.max_in_flight
    }
}

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

/// Relay one bounded batch and drain every claimed entry before returning.
///
/// Claims are processed concurrently up to `limit`. If several entries fail, all already claimed
/// entries are still driven to completion and the first error in original claim order is returned.
pub async fn relay_once<P, S, U, C, E>(
    store: &S,
    publisher: &U,
    clock: &C,
    budget: DeliveryBudget,
    emitter: &E,
    limit: RelayBatchLimit,
) -> Result<RelayReport, MessagingError>
where
    P: Sync,
    S: OutboxStore<P>,
    U: Publisher<P, Receipt = S::PublishReceipt>,
    C: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let claim_started = clock.now();
    let claim_deadline = absolute_deadline(clock, budget.settle_timeout(), emitter)?;
    let claims = match within(clock, claim_deadline, |deadline| {
        store.claim_partition_heads(limit.get(), deadline)
    })
    .await
    .and_then(std::convert::identity)
    {
        Ok(claims) => claims,
        Err(error) => {
            emit_runtime_failure(
                emitter,
                TransactionalMessagingRuntimePhase::RelayClaim,
                &error,
            );
            return Err(error);
        }
    };
    emitter.emit(TransactionalMessagingObservation::RelayTick {
        phase: TransactionalMessagingRelayPhase::Claim,
        duration: clock.now().saturating_duration_since(claim_started),
    });

    let mut results = stream::iter(claims.into_iter().enumerate().map(
        |(index, claim)| async move {
            (
                index,
                relay_claim(store, publisher, clock, budget, emitter, claim).await,
            )
        },
    ))
    .buffer_unordered(limit.get().get())
    .collect::<Vec<_>>()
    .await;
    results.sort_unstable_by_key(|(index, _)| *index);

    let mut report = RelayReport {
        claimed: results.len(),
        ..RelayReport::default()
    };
    let mut first_error = None;
    for (_, result) in results {
        match result {
            Ok(None) => report.fenced += 1,
            Ok(Some(OutboxDisposition::Published)) => report.published += 1,
            Ok(Some(OutboxDisposition::Retry)) => report.retried += 1,
            Ok(Some(OutboxDisposition::DeadLetter)) => report.dead_lettered += 1,
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(report),
    }
}

async fn relay_claim<P, S, U, C, E>(
    store: &S,
    publisher: &U,
    clock: &C,
    budget: DeliveryBudget,
    emitter: &E,
    claim: S::Claim,
) -> Result<Option<OutboxDisposition>, MessagingError>
where
    P: Sync,
    S: OutboxStore<P>,
    U: Publisher<P, Receipt = S::PublishReceipt>,
    C: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let lease_deadline = absolute_deadline(clock, budget.settle_timeout(), emitter)?;
    let lease = within(clock, lease_deadline, |deadline| {
        store.lease_status(&claim, deadline)
    })
    .await
    .and_then(std::convert::identity);
    let lease = match lease {
        Ok(lease) => lease,
        Err(error) => {
            emit_runtime_failure(
                emitter,
                TransactionalMessagingRuntimePhase::RelayLease,
                &error,
            );
            return Err(error);
        }
    };
    if matches!(lease, OutboxLeaseStatus::Lost) {
        emitter.emit(TransactionalMessagingObservation::RelayLeaseLost);
        return Ok(None);
    }
    let extend_deadline = absolute_deadline(clock, budget.settle_timeout(), emitter)?;
    let extended = within(clock, extend_deadline, |deadline| {
        store.extend(&claim, deadline)
    })
    .await
    .and_then(std::convert::identity);
    let remaining = match extended {
        Err(error) => {
            emit_runtime_failure(
                emitter,
                TransactionalMessagingRuntimePhase::RelayLease,
                &error,
            );
            return Err(error);
        }
        Ok(OutboxLeaseStatus::Held { remaining }) => remaining,
        Ok(OutboxLeaseStatus::Lost) => {
            emitter.emit(TransactionalMessagingObservation::RelayLeaseLost);
            return Ok(None);
        }
    };
    let publish_started = clock.now();
    let attempt_deadline =
        AbsoluteDeadline::from_timeout(clock, remaining.saturating_sub(budget.safety_margin()))
            .map_err(|error| {
                let error = MessagingError::new(MessagingErrorKind::Invariant, error);
                emit_runtime_failure(
                    emitter,
                    TransactionalMessagingRuntimePhase::RelayDeadline,
                    &error,
                );
                error
            })?;
    let settlement = if budget.can_start_attempt(remaining) {
        let publish_deadline = attempt_deadline.capped(clock, budget.publish_timeout());
        let outcome = match within(clock, publish_deadline, |deadline| {
            publisher.publish(S::message(&claim).envelope(), deadline)
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => deadline_elapsed_publish_outcome(),
        };
        if let Some(failure) = outcome.failure() {
            emitter.emit(TransactionalMessagingObservation::OutboxPublishFailure {
                stage: failure.stage(),
                reason: failure.reason(),
                ambiguous: outcome.is_ambiguous(),
            });
        }
        outcome.into_settlement()
    } else {
        OutboxSettlement::Retry
    };
    let disposition = settlement.disposition();
    let settlement_deadline = attempt_deadline.capped(clock, budget.settle_timeout());
    if let Err(error) = within(clock, settlement_deadline, |deadline| {
        store.settle(claim, settlement, deadline)
    })
    .await
    .and_then(std::convert::identity)
    {
        emit_runtime_failure(
            emitter,
            TransactionalMessagingRuntimePhase::RelaySettlement,
            &error,
        );
        return Err(error);
    }
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

fn deadline_elapsed_publish_outcome<R>() -> PublishOutcome<R> {
    PublishOutcome::Ambiguous(PublishFailure::new(
        PublishFailureKind::Transient,
        PublishFailureStage::Confirm,
        PublishFailureReason::DeadlineElapsed,
    ))
}

fn absolute_deadline(
    clock: &impl ExecutionTimer,
    timeout: Duration,
    emitter: &impl TransactionalMessagingEmitter,
) -> Result<AbsoluteDeadline, MessagingError> {
    AbsoluteDeadline::from_timeout(clock, timeout).map_err(|error| {
        let error = MessagingError::new(MessagingErrorKind::Invariant, error);
        emit_runtime_failure(
            emitter,
            TransactionalMessagingRuntimePhase::RelayDeadline,
            &error,
        );
        error
    })
}

fn emit_runtime_failure(
    emitter: &impl TransactionalMessagingEmitter,
    phase: TransactionalMessagingRuntimePhase,
    error: &MessagingError,
) {
    emitter.emit(TransactionalMessagingObservation::RuntimeFailure {
        phase,
        kind: error.kind(),
    });
}

/// Owned dependencies for one managed outbox relay worker.
pub struct RelayWorker<P, S, U, C, E> {
    store: Arc<S>,
    publisher: Arc<U>,
    clock: Arc<C>,
    emitter: Arc<E>,
    config: RelayConfig,
    budget: DeliveryBudget,
    payload: PhantomData<fn() -> P>,
}

impl<P, S, U, C, E> RelayWorker<P, S, U, C, E>
where
    P: Send + Sync + 'static,
    S: OutboxStore<P> + 'static,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    /// Bind all mandatory relay dependencies without defaults or optional runtime paths.
    #[must_use]
    pub const fn new(
        store: Arc<S>,
        publisher: Arc<U>,
        clock: Arc<C>,
        emitter: Arc<E>,
        config: RelayConfig,
        budget: DeliveryBudget,
    ) -> Self {
        Self {
            store,
            publisher,
            clock,
            emitter,
            config,
            budget,
            payload: PhantomData,
        }
    }

    /// Transfer the worker into the `rss-runtime` startup token funnel.
    pub fn into_registration(
        self,
        name: impl Into<String>,
        shutdown_budget: ShutdownBudget,
    ) -> (ManagedTaskRegistration, TaskStatus) {
        let (start, status) = ManagedTask::prepare(name, shutdown_budget.timeout());
        let registration = start.into_registration(move |token| async move {
            relay_loop(self, token).await.map_err(ShutdownError::new)
        });
        (registration, status)
    }
}

async fn relay_loop<P, S, U, C, E>(
    worker: RelayWorker<P, S, U, C, E>,
    token: tokio_util::sync::CancellationToken,
) -> Result<(), MessagingError>
where
    P: Send + Sync + 'static,
    S: OutboxStore<P> + 'static,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    let mut ticker = tokio::time::interval(worker.config.poll_interval());
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => return Ok(()),
            _ = ticker.tick() => {}
        }
        let result = relay_once(
            worker.store.as_ref(),
            worker.publisher.as_ref(),
            worker.clock.as_ref(),
            worker.budget,
            worker.emitter.as_ref(),
            worker.config.max_in_flight(),
        )
        .await;
        if let Err(error) = result {
            if !matches!(
                error.kind(),
                MessagingErrorKind::Transient | MessagingErrorKind::DeadlineElapsed
            ) {
                return Err(error);
            }
            tracing::warn!(
                error_kind = error.kind().as_label(),
                "relay batch will retry"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_publish_outcome_is_the_closed_ambiguous_transient_tuple() {
        let outcome = deadline_elapsed_publish_outcome::<()>();
        assert!(outcome.is_ambiguous());
        let failure = outcome.failure().unwrap_or(PublishFailure::new(
            PublishFailureKind::Permanent,
            PublishFailureStage::Encode,
            PublishFailureReason::InvalidMessage,
        ));
        assert_eq!(failure.kind(), PublishFailureKind::Transient);
        assert_eq!(failure.stage(), PublishFailureStage::Confirm);
        assert_eq!(failure.reason(), PublishFailureReason::DeadlineElapsed);
    }
}
