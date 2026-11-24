//! Bounded outbox relay execution and caller-driven worker ownership.

use rss_request_context::{Deadline, ExecutionTimer};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt as _;
use futures::stream::{self, FuturesUnordered, StreamExt as _};
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingEmitter,
    TransactionalMessagingObservation, TransactionalMessagingRelayPhase,
    TransactionalMessagingRuntimePhase,
};
use rss_transactional_messaging::outbox::{
    OutboxClaimBatch, OutboxDisposition, OutboxLeaseStatus, OutboxRelayStore, OutboxSettlement,
};
use rss_transactional_messaging::policy::{DeliveryBudget, within};
use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome,
    Publisher,
};

const MIN_SCAN_DELAY: Duration = Duration::from_millis(100);

/// A scan delay below the operational floor could busy-loop on a failing or empty store.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("relay idle scan interval and error backoff must each be at least 100ms")]
pub struct RelayConfigError;

/// Admission and backpressure configuration for one relay worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    claim_limit: NonZeroUsize,
    max_in_flight: NonZeroUsize,
    idle_scan_interval: Duration,
    error_backoff: Duration,
}

impl RelayConfig {
    /// Set the per-request claim bound, total work capacity and independent scan delays.
    pub fn new(
        claim_limit: NonZeroUsize,
        max_in_flight: NonZeroUsize,
        idle_scan_interval: Duration,
        error_backoff: Duration,
    ) -> Result<Self, RelayConfigError> {
        if idle_scan_interval.min(error_backoff) < MIN_SCAN_DELAY {
            return Err(RelayConfigError);
        }
        Ok(Self {
            claim_limit,
            max_in_flight,
            idle_scan_interval,
            error_backoff,
        })
    }

    /// Maximum number of durable claims per request.
    #[must_use]
    pub const fn claim_limit(self) -> NonZeroUsize {
        self.claim_limit
    }

    /// Maximum number of claims being prepared, published or settled.
    #[must_use]
    pub const fn max_in_flight(self) -> NonZeroUsize {
        self.max_in_flight
    }

    /// Time between empty scans in the absence of completed work.
    #[must_use]
    pub const fn idle_scan_interval(self) -> Duration {
        self.idle_scan_interval
    }

    /// Minimum wait before a new scan after a recoverable infrastructure error.
    #[must_use]
    pub const fn error_backoff(self) -> Duration {
        self.error_backoff
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
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    store: &S,
    publisher: &U,
    clock: &C,
    emitter: &E,
    limit: NonZeroUsize,
) -> Result<RelayReport, MessagingError>
where
    P: Sync,
    S: OutboxRelayStore<P>,
    U: Publisher<P, Receipt = S::PublishReceipt>,
    C: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let budget = store.delivery_budget();
    let claims = claim_heads(binding, store, clock, budget, emitter, limit).await?;

    let mut results = stream::iter(claims.into_iter().enumerate().map(
        |(index, claim)| async move {
            (
                index,
                relay_claim(store, publisher, clock, budget, emitter, claim).await,
            )
        },
    ))
    .buffer_unordered(limit.get())
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

async fn claim_heads<P, S: OutboxRelayStore<P>>(
    binding: ExecutionBinding,
    store: &S,
    clock: &impl ExecutionTimer,
    budget: DeliveryBudget,
    emitter: &impl TransactionalMessagingEmitter,
    limit: NonZeroUsize,
) -> Result<OutboxClaimBatch<S::Claim>, MessagingError> {
    let claim_started = clock.now();
    let claim_deadline = absolute_deadline(clock, budget.settle_timeout(), emitter)?;
    let claims = match within(clock, claim_deadline, |deadline| {
        store.claim_partition_heads(binding, limit, deadline)
    })
    .await
    .and_then(std::convert::identity)
    {
        Ok(claims) if claims.len() <= limit.get() => claims,
        Ok(_) => {
            let error = MessagingError::new(
                MessagingErrorKind::Invariant,
                std::io::Error::other("outbox batch exceeds requested capacity"),
            );
            emit_runtime_failure(
                emitter,
                TransactionalMessagingRuntimePhase::RelayClaim,
                &error,
            );
            return Err(error);
        }
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

    Ok(claims)
}

type ClaimOutcome = Result<Option<OutboxDisposition>, MessagingError>;

async fn relay_claim<P, S, U, C, E>(
    store: &S,
    publisher: &U,
    clock: &C,
    budget: DeliveryBudget,
    emitter: &E,
    claim: S::Claim,
) -> ClaimOutcome
where
    P: Sync,
    S: OutboxRelayStore<P>,
    U: Publisher<P, Receipt = S::PublishReceipt>,
    C: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let extend_deadline = absolute_deadline(clock, budget.settle_timeout(), emitter)?;
    let extend_started = clock.now();
    let extended = within(clock, extend_deadline, |deadline| {
        store.extend(&claim, deadline)
    })
    .await
    .and_then(std::convert::identity);
    let (remaining, delivery_remaining) = match extended {
        Err(error) => {
            emit_runtime_failure(
                emitter,
                TransactionalMessagingRuntimePhase::RelayLease,
                &error,
            );
            return Err(error);
        }
        Ok(OutboxLeaseStatus::Held {
            remaining,
            delivery_remaining,
        }) => (remaining, delivery_remaining),
        Ok(OutboxLeaseStatus::Lost) => {
            emitter.emit(TransactionalMessagingObservation::RelayLeaseLost);
            return Ok(None);
        }
    };
    let elapsed = clock.now().saturating_duration_since(extend_started);
    let remaining = remaining.saturating_sub(elapsed);
    let expired = delivery_remaining.is_some_and(|value| value.is_zero());
    let delivery_budget = delivery_remaining.map_or(remaining, |value| {
        value.saturating_sub(elapsed).min(remaining)
    });
    let publish_started = clock.now();
    let attempt_deadline =
        Deadline::from_timeout(clock, remaining.saturating_sub(budget.safety_margin())).map_err(
            |error| {
                let error = MessagingError::new(MessagingErrorKind::Invariant, error);
                emit_runtime_failure(
                    emitter,
                    TransactionalMessagingRuntimePhase::RelayDeadline,
                    &error,
                );
                error
            },
        )?;
    let settlement = if expired {
        OutboxSettlement::DeadLetter
    } else if budget.can_start_attempt(delivery_budget) {
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
) -> Result<Deadline, MessagingError> {
    Deadline::from_timeout(clock, timeout).map_err(|error| {
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

/// Dependencies owned by one caller-driven outbox relay worker.
pub struct RelayWorker<P, S, U, C, E> {
    store: Arc<S>,
    publisher: Arc<U>,
    clock: Arc<C>,
    emitter: Arc<E>,
    config: RelayConfig,
    payload: PhantomData<fn() -> P>,
}

impl<P, S, U, C, E> RelayWorker<P, S, U, C, E>
where
    P: Send + Sync,
    S: OutboxRelayStore<P>,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt>,
    C: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    /// Bind all mandatory relay dependencies without defaults.
    #[must_use]
    pub const fn new(
        store: Arc<S>,
        publisher: Arc<U>,
        clock: Arc<C>,
        emitter: Arc<E>,
        config: RelayConfig,
    ) -> Self {
        Self {
            store,
            publisher,
            clock,
            emitter,
            config,
            payload: PhantomData,
        }
    }

    /// Drive this worker on the caller's Tokio host until cancellation or failure.
    ///
    /// Cancellation stops admission and lets in-flight work finish, including lease
    /// renewal and settlement. Keep polling this future after cancelling the token.
    /// The host owns the final drain timeout: dropping this future (or aborting and
    /// joining its task) forcibly ends work without inventing a durable outcome.
    /// This method does not spawn a task or catch provider panics.
    pub async fn run(
        self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        token: tokio_util::sync::CancellationToken,
    ) -> Result<(), MessagingError> {
        if token.is_cancelled() {
            return Ok(());
        }
        let longest_delay = self
            .config
            .idle_scan_interval
            .max(self.config.error_backoff);
        absolute_deadline(self.clock.as_ref(), longest_delay, self.emitter.as_ref())?;
        self.drive(binding, &token).await
    }

    async fn drive(
        &self,
        binding: ExecutionBinding,
        token: &tokio_util::sync::CancellationToken,
    ) -> Result<(), MessagingError> {
        let clock = self.clock.as_ref();
        let emitter = self.emitter.as_ref();
        let store = self.store.as_ref();
        let budget = store.delivery_budget();
        let mut active = FuturesUnordered::new();
        let mut admission = Admission::Ready;

        while !token.is_cancelled() && !matches!(admission, Admission::Stopped(_)) {
            if let Some(limit) = admission.capacity(self.config, active.len()) {
                // Start ready work before a synchronous store can fill the whole window.
                if let Some(Some(result)) = active.next().now_or_never() {
                    admission.completed(result, &self.config, clock, emitter);
                    continue;
                }
                if token.is_cancelled() {
                    break;
                }
                let request = claim_heads(binding, store, clock, budget, emitter, limit);
                let batch = admission
                    .scan(request, &mut active, &self.config, clock, emitter)
                    .await;
                for claim in batch.into_iter().flatten() {
                    active.push(relay_claim(
                        store,
                        self.publisher.as_ref(),
                        clock,
                        budget,
                        emitter,
                        claim,
                    ));
                }
                // Ready in-memory providers must also share the caller's executor.
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                biased;
                () = token.cancelled() => break,
                Some(result) = active.next(), if !active.is_empty() => {
                    admission.completed(result, &self.config, clock, emitter);
                }
                () = admission.wait(clock) => admission = Admission::Ready,
            }
        }
        admission
            .drain(&mut active, &self.config, clock, emitter)
            .await
    }
}

enum Admission {
    Ready,
    Idle(Deadline),
    Backoff(Deadline),
    Stopped(MessagingError),
}

impl Admission {
    fn capacity(&self, config: RelayConfig, in_flight: usize) -> Option<NonZeroUsize> {
        match self {
            Self::Ready => NonZeroUsize::new(
                (config.max_in_flight.get() - in_flight).min(config.claim_limit.get()),
            ),
            _ => None,
        }
    }

    // A claim can already be durable while its reply is pending. Finish the one
    // request even if cancellation or a fatal settlement stops future admission.
    async fn scan<T, F: Future<Output = ClaimOutcome>>(
        &mut self,
        request: impl Future<Output = Result<OutboxClaimBatch<T>, MessagingError>>,
        active: &mut FuturesUnordered<F>,
        config: &RelayConfig,
        clock: &impl ExecutionTimer,
        emitter: &impl TransactionalMessagingEmitter,
    ) -> Option<OutboxClaimBatch<T>> {
        tokio::pin!(request);
        let before = active.len();
        let claims = loop {
            tokio::select! {
                biased;
                result = &mut request => break result,
                Some(result) = active.next(), if !active.is_empty() => {
                    self.completed(result, config, clock, emitter);
                }
            }
        };
        match claims {
            Ok(batch) => {
                if batch.is_empty() && active.len() == before && matches!(self, Self::Ready) {
                    *self = Self::delay(clock, emitter, config.idle_scan_interval, Self::Idle);
                }
                Some(batch)
            }
            Err(error) => {
                self.failed(error, config, clock, emitter);
                None
            }
        }
    }

    async fn drain<F: Future<Output = ClaimOutcome>>(
        mut self,
        active: &mut FuturesUnordered<F>,
        config: &RelayConfig,
        clock: &impl ExecutionTimer,
        emitter: &impl TransactionalMessagingEmitter,
    ) -> Result<(), MessagingError> {
        while let Some(result) = active.next().await {
            self.completed(result, config, clock, emitter);
        }
        match self {
            Admission::Stopped(error) => Err(error),
            _ => Ok(()),
        }
    }

    fn delay(
        clock: &impl ExecutionTimer,
        emitter: &impl TransactionalMessagingEmitter,
        duration: Duration,
        state: fn(Deadline) -> Self,
    ) -> Self {
        absolute_deadline(clock, duration, emitter).map_or_else(Self::Stopped, state)
    }

    async fn wait(&self, clock: &impl ExecutionTimer) {
        match self {
            Self::Idle(at) | Self::Backoff(at) => clock.sleep_until(*at).await,
            _ => std::future::pending().await,
        }
    }

    fn completed(
        &mut self,
        result: ClaimOutcome,
        config: &RelayConfig,
        clock: &impl ExecutionTimer,
        emitter: &impl TransactionalMessagingEmitter,
    ) {
        match result {
            Err(error) => self.failed(error, config, clock, emitter),
            Ok(_) if matches!(self, Self::Idle(_)) => *self = Self::Ready,
            Ok(_) => {}
        }
    }

    fn failed(
        &mut self,
        error: MessagingError,
        config: &RelayConfig,
        clock: &impl ExecutionTimer,
        emitter: &impl TransactionalMessagingEmitter,
    ) {
        if matches!(self, Self::Stopped(_)) {
            return;
        }
        *self = match error.kind() {
            MessagingErrorKind::Transient | MessagingErrorKind::DeadlineElapsed => {
                tracing::warn!(
                    error_kind = error.kind().as_label(),
                    "relay admission will retry"
                );
                Self::delay(clock, emitter, config.error_backoff, Self::Backoff)
            }
            _ => Self::Stopped(error),
        };
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
