//! Transactional consumer execution, lease supervision, and caller-driven worker ownership.

use rss_request_context::{Deadline, ExecutionTimer};
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::inbox::{
    ConsumerGroup, IdempotencyDisposition, InboxStore, LeaseStatus,
};
use rss_transactional_messaging::message::{PartitionIdentity, SubscriptionIdentity};
use rss_transactional_messaging::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingEmitter,
    TransactionalMessagingIoOutcome, TransactionalMessagingObservation,
    TransactionalMessagingRuntimePhase, TransactionalMessagingSubscribeOutcome,
};
use rss_transactional_messaging::policy::{ConsumerExecutionPolicy, ExecutionDeadlines, within};
use rss_transactional_messaging::transaction::{
    CommittedTransaction, ConsumerTx, EnvelopeValidationFailure, FailureClass, IngressValidator,
    SettlementDecision, SettlementKind, TerminalDisposition, TransactionOutcome,
    VerifiedConsumerBinding, verify_ingress,
};
use rss_transactional_messaging::transport::{
    Delivery, DeliverySettlement, DeliverySource, IncomingDelivery,
};

/// Closed result of processing one broker delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessingDisposition {
    /// Execution capacity remained occupied through the delivery budget.
    CapacityBusy,
    /// Another live claim owns this message.
    InProgress,
    /// A matching durable terminal receipt bypassed the handler.
    Duplicate(TerminalDisposition),
    /// The consumer transaction committed a terminal result.
    Committed(TerminalDisposition),
    /// Ingress validation or durable identity verification rejected the message.
    Rejected(EnvelopeValidationFailure),
    /// Lease ownership was explicitly lost.
    Fenced,
    /// No terminal outcome was proven and the message remains eligible for redelivery.
    Deferred,
}

/// Immutable dependencies and policies shared by deliveries from one subscription.
pub struct ConsumerExecution<'a, V, R, E> {
    group: ConsumerGroup,
    validator: &'a V,
    subscription: &'a SubscriptionIdentity,
    timer: &'a R,
    policy: ConsumerExecutionPolicy,
    emitter: &'a E,
}

impl<'a, V, R, E> ConsumerExecution<'a, V, R, E> {
    /// Bind identity, ingress authority, time policy, renewal, and telemetry.
    #[must_use]
    pub const fn new(
        group: ConsumerGroup,
        validator: &'a V,
        subscription: &'a SubscriptionIdentity,
        timer: &'a R,
        policy: ConsumerExecutionPolicy,
        emitter: &'a E,
    ) -> Self {
        Self {
            group,
            validator,
            subscription,
            timer,
            policy,
            emitter,
        }
    }

    /// Return the exact subscription identity.
    #[must_use]
    pub const fn subscription(&self) -> &SubscriptionIdentity {
        self.subscription
    }

    /// Return the mandatory observation sink.
    #[must_use]
    pub const fn emitter(&self) -> &E {
        self.emitter
    }

    /// Return the complete execution policy.
    #[must_use]
    pub const fn policy(&self) -> ConsumerExecutionPolicy {
        self.policy
    }

    fn deadlines(&self) -> Result<ExecutionDeadlines, MessagingError>
    where
        R: ExecutionTimer,
        E: TransactionalMessagingEmitter,
    {
        ExecutionDeadlines::from_budget(self.timer, self.policy.budget()).map_err(|error| {
            let error = MessagingError::new(MessagingErrorKind::Invariant, error);
            emit_runtime_failure(
                self.emitter,
                TransactionalMessagingRuntimePhase::ConsumerDeadline,
                &error,
            );
            error
        })
    }
}

/// Execute the canonical validate → claim → renew/transaction → settlement pipeline once.
pub async fn consume_once<P, S, I, T, V, R, E>(
    inbox: &I,
    transaction: &T,
    execution: &ConsumerExecution<'_, V, R, E>,
    delivery: Delivery<P, S>,
) -> Result<ProcessingDisposition, MessagingError>
where
    P: AsRef<[u8]> + Send + Sync,
    S: DeliverySettlement,
    I: InboxStore,
    T: ConsumerTx<P, Claim = I::Claim>,
    V: IngressValidator<P>,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let prepared = PreparedDelivery::valid(execution, Box::new(delivery), execution.deadlines()?);
    process_prepared(inbox, transaction, execution, prepared).await
}

enum Ingress<P, S> {
    Verified(Box<Delivery<P, S>>, VerifiedConsumerBinding),
    Rejected(EnvelopeValidationFailure, SettlementDecision, S),
}

struct PreparedDelivery<P, S> {
    ingress: Ingress<P, S>,
    deadlines: ExecutionDeadlines,
}

impl<P: AsRef<[u8]>, S> PreparedDelivery<P, S> {
    fn valid<V: IngressValidator<P>, R, E>(
        execution: &ConsumerExecution<'_, V, R, E>,
        delivery: Box<Delivery<P, S>>,
        deadlines: ExecutionDeadlines,
    ) -> Self {
        let ingress = match verify_ingress(
            execution.validator,
            execution.group.clone(),
            execution.subscription,
            delivery.message(),
        ) {
            Ok(binding) => Ingress::Verified(delivery, binding),
            Err(rejection) => Ingress::Rejected(
                rejection.reason(),
                rejection.into_decision(),
                delivery.into_parts().1,
            ),
        };
        Self { ingress, deadlines }
    }

    fn incoming<V: IngressValidator<P>, R, E>(
        execution: &ConsumerExecution<'_, V, R, E>,
        item: IncomingDelivery<P, S>,
        deadlines: ExecutionDeadlines,
    ) -> Self {
        match item {
            IncomingDelivery::Valid(delivery) => Self::valid(execution, delivery, deadlines),
            IncomingDelivery::Invalid(invalid) => {
                let (rejection, settlement) = invalid.into_parts();
                PreparedDelivery {
                    ingress: Ingress::Rejected(
                        rejection.reason(),
                        rejection.into_decision(),
                        settlement,
                    ),
                    deadlines,
                }
            }
        }
    }

    fn partition(&self) -> Option<&PartitionIdentity> {
        match &self.ingress {
            Ingress::Verified(delivery, _) => delivery.message().metadata().partition(),
            Ingress::Rejected(..) => None,
        }
    }
}

async fn process_prepared<P, S, I, T, V, R, E>(
    inbox: &I,
    transaction: &T,
    execution: &ConsumerExecution<'_, V, R, E>,
    prepared: PreparedDelivery<P, S>,
) -> Result<ProcessingDisposition, MessagingError>
where
    P: AsRef<[u8]> + Send + Sync,
    S: DeliverySettlement,
    I: InboxStore,
    T: ConsumerTx<P, Claim = I::Claim>,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let PreparedDelivery { ingress, deadlines } = prepared;
    let ((message, settlement), binding) =
        match ingress {
            Ingress::Verified(delivery, binding) => (delivery.into_parts(), binding),
            Ingress::Rejected(failure, decision, settlement) => {
                execution.emitter.emit(
                    TransactionalMessagingObservation::ConsumerIngressRejected { reason: failure },
                );
                settle_observed(
                    settlement,
                    decision,
                    deadlines.settlement(),
                    execution.timer,
                    execution.emitter,
                )
                .await?;
                return Ok(if failure == EnvelopeValidationFailure::ExecutionMismatch {
                    ProcessingDisposition::Fenced
                } else {
                    ProcessingDisposition::Rejected(failure)
                });
            }
        };
    let claim = wait_for_claim(inbox, execution, &binding, deadlines.operation()).await;
    match claim {
        Ok(busy @ (IdempotencyDisposition::CapacityBusy | IdempotencyDisposition::InProgress)) => {
            settle_observed(
                settlement,
                SettlementDecision::requeue(),
                deadlines.settlement(),
                execution.timer,
                execution.emitter,
            )
            .await?;
            Ok(if matches!(busy, IdempotencyDisposition::CapacityBusy) {
                ProcessingDisposition::CapacityBusy
            } else {
                ProcessingDisposition::InProgress
            })
        }
        Err(error) => {
            emit_runtime_failure(
                execution.emitter,
                TransactionalMessagingRuntimePhase::ConsumerClaim,
                &error,
            );
            Err(abandon_after_error(
                settlement,
                deadlines.settlement(),
                execution.timer,
                execution.emitter,
                error,
            )
            .await)
        }
        Ok(IdempotencyDisposition::Terminal(receipt)) => match binding.validate_terminal(receipt) {
            Ok(terminal) => {
                let disposition = terminal.disposition();
                settle_observed(
                    settlement,
                    terminal.into_decision(),
                    deadlines.settlement(),
                    execution.timer,
                    execution.emitter,
                )
                .await?;
                Ok(ProcessingDisposition::Duplicate(disposition))
            }
            Err(rejection) => {
                let failure = rejection.reason();
                execution.emitter.emit(
                    TransactionalMessagingObservation::ConsumerIngressRejected { reason: failure },
                );
                settle_observed(
                    settlement,
                    rejection.into_decision(),
                    deadlines.settlement(),
                    execution.timer,
                    execution.emitter,
                )
                .await?;
                Ok(ProcessingDisposition::Rejected(failure))
            }
        },
        Ok(IdempotencyDisposition::Acquired(claim)) => {
            process_acquired(
                inbox,
                transaction,
                execution,
                AcquiredDelivery {
                    message,
                    settlement,
                    claim,
                    binding,
                    deadlines,
                },
            )
            .await
        }
    }
}

// Recheck busy admission on its own clock. A long lease interval can exceed the
// entire operation budget; recomputing a fraction of remaining time would spin near expiry.
async fn wait_for_claim<I, V, R, E>(
    inbox: &I,
    execution: &ConsumerExecution<'_, V, R, E>,
    binding: &VerifiedConsumerBinding,
    cutoff: Deadline,
) -> Result<IdempotencyDisposition<I::Claim>, MessagingError>
where
    I: InboxStore,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let budget = execution.policy.budget();
    let interval = ((budget.total() - budget.settlement_reserve()) / 4)
        .clamp(Duration::from_millis(1), Duration::from_millis(250));
    let mut capacity_wait = None;
    let result = loop {
        let claim = within(execution.timer, cutoff, |deadline| {
            inbox.claim(binding.execution(), binding.identity(), deadline)
        })
        .await
        .and_then(std::convert::identity);
        match &claim {
            Ok(IdempotencyDisposition::CapacityBusy) => {
                capacity_wait.get_or_insert_with(|| execution.timer.now());
                execution
                    .emitter
                    .emit(TransactionalMessagingObservation::ConsumerClaimCapacityBusy);
            }
            Ok(IdempotencyDisposition::InProgress) => execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerClaimInProgress),
            _ => break claim,
        }
        let wake = cutoff.capped(execution.timer, interval);
        if within(execution.timer, cutoff, |_| {
            execution.timer.sleep_until(wake)
        })
        .await
        .is_err()
            || cutoff
                .remaining(execution.timer.now())
                .unwrap_or_default()
                .is_zero()
        {
            break claim;
        }
    };
    if let Some(start) = capacity_wait {
        execution
            .emitter
            .emit(TransactionalMessagingObservation::ConsumerCapacityWait {
                duration: execution.timer.now().saturating_duration_since(start),
            });
    }
    result
}

struct AcquiredDelivery<P, S, C> {
    message: rss_transactional_messaging::message::MessageEnvelope<P>,
    settlement: S,
    claim: C,
    binding: VerifiedConsumerBinding,
    deadlines: ExecutionDeadlines,
}

enum RenewalExit {
    Lost,
}

enum AcquiredRace<P> {
    Transaction(TransactionOutcome<P>),
    Renewal(Result<RenewalExit, MessagingError>),
}

async fn process_acquired<P, S, I, T, V, R, E>(
    inbox: &I,
    transaction: &T,
    execution: &ConsumerExecution<'_, V, R, E>,
    state: AcquiredDelivery<P, S, I::Claim>,
) -> Result<ProcessingDisposition, MessagingError>
where
    P: AsRef<[u8]> + Send + Sync,
    S: DeliverySettlement,
    I: InboxStore,
    T: ConsumerTx<P, Claim = I::Claim>,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let first_wait = match within(execution.timer, state.deadlines.operation(), |deadline| {
        inbox.extend(&state.claim, deadline)
    })
    .await
    .and_then(std::convert::identity)
    {
        Ok(LeaseStatus::Held { remaining }) => match renewal_delay(inbox, execution, remaining) {
            Ok(wait) => wait,
            Err(error) => {
                return Err(abandon_after_error(
                    state.settlement,
                    state.deadlines.settlement(),
                    execution.timer,
                    execution.emitter,
                    error,
                )
                .await);
            }
        },
        Ok(LeaseStatus::Lost) => {
            execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerLeaseLost);
            abandon_observed(
                state.settlement,
                state.deadlines.settlement(),
                execution.timer,
                execution.emitter,
            )
            .await?;
            return Ok(ProcessingDisposition::Fenced);
        }
        Err(error) => {
            emit_runtime_failure(
                execution.emitter,
                TransactionalMessagingRuntimePhase::ConsumerLease,
                &error,
            );
            return Err(abandon_after_error(
                state.settlement,
                state.deadlines.settlement(),
                execution.timer,
                execution.emitter,
                error,
            )
            .await);
        }
    };
    let raced = {
        let transaction_flow = transaction_loop(
            transaction,
            execution,
            &state.claim,
            &state.message,
            &state.binding,
            state.deadlines.operation(),
        );
        let renewal = renewal_loop(
            inbox,
            execution,
            &state.claim,
            state.deadlines.operation(),
            first_wait,
        );
        tokio::pin!(transaction_flow);
        tokio::pin!(renewal);
        tokio::select! {
            biased;
            renewed = &mut renewal => match renewed {
                Err(error) if error.kind() == MessagingErrorKind::DeadlineElapsed => {
                    AcquiredRace::Transaction(transaction_flow.await)
                }
                renewed => AcquiredRace::Renewal(renewed),
            },
            outcome = &mut transaction_flow => AcquiredRace::Transaction(outcome),
        }
    };
    match raced {
        AcquiredRace::Transaction(outcome) => {
            finalize_outcome(inbox, execution, state, outcome).await
        }
        AcquiredRace::Renewal(Ok(RenewalExit::Lost)) => {
            execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerLeaseLost);
            abandon_observed(
                state.settlement,
                state.deadlines.settlement(),
                execution.timer,
                execution.emitter,
            )
            .await?;
            Ok(ProcessingDisposition::Fenced)
        }
        AcquiredRace::Renewal(Err(error)) => Err(abandon_after_error(
            state.settlement,
            state.deadlines.settlement(),
            execution.timer,
            execution.emitter,
            error,
        )
        .await),
    }
}

async fn renewal_loop<I, V, R, E>(
    inbox: &I,
    execution: &ConsumerExecution<'_, V, R, E>,
    claim: &I::Claim,
    deadline: Deadline,
    mut wait: Duration,
) -> Result<RenewalExit, MessagingError>
where
    I: InboxStore,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    loop {
        let wake = deadline.capped(execution.timer, wait);
        within(execution.timer, deadline, |_| {
            execution.timer.sleep_until(wake)
        })
        .await?;
        match within(execution.timer, deadline, |deadline| {
            inbox.extend(claim, deadline)
        })
        .await
        .and_then(std::convert::identity)
        {
            Ok(LeaseStatus::Held { remaining }) => {
                wait = renewal_delay(inbox, execution, remaining)?;
                tokio::task::yield_now().await;
            }
            Ok(LeaseStatus::Lost) => return Ok(RenewalExit::Lost),
            Err(error) => {
                emit_runtime_failure(
                    execution.emitter,
                    TransactionalMessagingRuntimePhase::ConsumerLease,
                    &error,
                );
                return Err(error);
            }
        }
    }
}

fn renewal_delay<I: InboxStore, V, R, E>(
    inbox: &I,
    execution: &ConsumerExecution<'_, V, R, E>,
    remaining: Duration,
) -> Result<Duration, MessagingError>
where
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let interval = inbox.lease_policy().interval();
    if inbox.lease_policy().fits(remaining) {
        return Ok(interval.min(remaining - interval));
    }
    let error = MessagingError::new(
        MessagingErrorKind::Invariant,
        std::io::Error::other("provider lease is shorter than the configured renewal interval"),
    );
    emit_runtime_failure(
        execution.emitter,
        TransactionalMessagingRuntimePhase::ConsumerLease,
        &error,
    );
    Err(error)
}

async fn transaction_loop<P, C, T, V, R, E>(
    transaction: &T,
    execution: &ConsumerExecution<'_, V, R, E>,
    claim: &C,
    message: &rss_transactional_messaging::message::MessageEnvelope<P>,
    binding: &VerifiedConsumerBinding,
    deadline: Deadline,
) -> TransactionOutcome<T::CommitProof>
where
    P: AsRef<[u8]> + Send + Sync,
    C: Send + Sync,
    T: ConsumerTx<P, Claim = C>,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let mut attempt = NonZeroU32::MIN;
    loop {
        if deadline
            .remaining(execution.timer.now())
            .unwrap_or_default()
            .is_zero()
        {
            return TransactionOutcome::not_started(FailureClass::Infrastructure);
        }
        let outcome = match within(execution.timer, deadline, |deadline| {
            transaction.execute(claim, message, binding.receipt_intent(), deadline)
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                emit_runtime_failure(
                    execution.emitter,
                    TransactionalMessagingRuntimePhase::ConsumerTransaction,
                    &error,
                );
                TransactionOutcome::commit_unknown()
            }
        };
        execution
            .emitter
            .emit(TransactionalMessagingObservation::ConsumerTransaction {
                status: outcome.status(),
            });
        if !outcome.may_retry() {
            return outcome;
        }
        let Some(next_attempt) = execution.policy.retry().next_attempt(attempt) else {
            return outcome;
        };
        let delay = execution.policy.retry().delay_after(attempt);
        if deadline
            .remaining(execution.timer.now())
            .unwrap_or_default()
            <= delay
        {
            return outcome;
        }
        let wake = deadline.capped(execution.timer, delay);
        if within(execution.timer, deadline, |_| {
            execution.timer.sleep_until(wake)
        })
        .await
        .is_err()
        {
            return outcome;
        }
        attempt = next_attempt;
    }
}

enum FoldedOutcome<P> {
    Committed(CommittedTransaction<P>),
    NotStarted(FailureClass),
    RolledBack(FailureClass),
    RollbackFailed,
    CommitUnknown,
    Fenced,
}

async fn finalize_outcome<P, S, I, Proof, V, R, E>(
    inbox: &I,
    execution: &ConsumerExecution<'_, V, R, E>,
    state: AcquiredDelivery<P, S, I::Claim>,
    outcome: TransactionOutcome<Proof>,
) -> Result<ProcessingDisposition, MessagingError>
where
    S: DeliverySettlement,
    I: InboxStore,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let outcome = outcome.fold(
        FoldedOutcome::Committed,
        FoldedOutcome::NotStarted,
        FoldedOutcome::RolledBack,
        || FoldedOutcome::RollbackFailed,
        || FoldedOutcome::CommitUnknown,
        || FoldedOutcome::Fenced,
    );
    match outcome {
        FoldedOutcome::Committed(committed) => {
            let (proof, terminal) = committed.into_parts();
            drop(proof);
            let disposition = terminal.disposition();
            settle_observed(
                state.settlement,
                terminal.into_decision(),
                state.deadlines.settlement(),
                execution.timer,
                execution.emitter,
            )
            .await?;
            Ok(ProcessingDisposition::Committed(disposition))
        }
        FoldedOutcome::NotStarted(_class) | FoldedOutcome::RolledBack(_class) => {
            release_or_abandon(inbox, execution, state).await?;
            Ok(ProcessingDisposition::Deferred)
        }
        FoldedOutcome::RollbackFailed | FoldedOutcome::CommitUnknown => {
            abandon_observed(
                state.settlement,
                state.deadlines.settlement(),
                execution.timer,
                execution.emitter,
            )
            .await?;
            Ok(ProcessingDisposition::Deferred)
        }
        FoldedOutcome::Fenced => {
            execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerLeaseLost);
            abandon_observed(
                state.settlement,
                state.deadlines.settlement(),
                execution.timer,
                execution.emitter,
            )
            .await?;
            Ok(ProcessingDisposition::Fenced)
        }
    }
}

async fn release_or_abandon<P, S, I, V, R, E>(
    inbox: &I,
    execution: &ConsumerExecution<'_, V, R, E>,
    state: AcquiredDelivery<P, S, I::Claim>,
) -> Result<(), MessagingError>
where
    S: DeliverySettlement,
    I: InboxStore,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let deadline = state.deadlines.settlement();
    match within(execution.timer, deadline, |deadline| {
        inbox.release(state.claim, deadline)
    })
    .await
    .and_then(std::convert::identity)
    {
        Ok(()) => {
            settle_observed(
                state.settlement,
                SettlementDecision::requeue(),
                deadline,
                execution.timer,
                execution.emitter,
            )
            .await
        }
        Err(error) => {
            execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerReleaseFailed);
            emit_runtime_failure(
                execution.emitter,
                TransactionalMessagingRuntimePhase::ConsumerRelease,
                &error,
            );
            Err(abandon_after_error(
                state.settlement,
                deadline,
                execution.timer,
                execution.emitter,
                error,
            )
            .await)
        }
    }
}

async fn settle_observed<S: DeliverySettlement>(
    settlement: S,
    decision: SettlementDecision,
    deadline: Deadline,
    timer: &impl ExecutionTimer,
    emitter: &impl TransactionalMessagingEmitter,
) -> Result<(), MessagingError> {
    let action = match decision.kind() {
        SettlementKind::Acknowledge => TransactionalMessagingDisposition::Ack,
        SettlementKind::Requeue => TransactionalMessagingDisposition::Requeue,
        SettlementKind::Reject => TransactionalMessagingDisposition::Reject,
    };
    let result = within(timer, deadline, |deadline| {
        settlement.settle(decision, deadline)
    })
    .await
    .and_then(std::convert::identity);
    emitter.emit(TransactionalMessagingObservation::ConsumerSettlement {
        action,
        outcome: if result.is_ok() {
            TransactionalMessagingIoOutcome::Ok
        } else {
            TransactionalMessagingIoOutcome::Error
        },
    });
    if let Err(error) = &result {
        emit_runtime_failure(
            emitter,
            TransactionalMessagingRuntimePhase::ConsumerSettlement,
            error,
        );
    }
    result
}

async fn abandon_observed<S: DeliverySettlement>(
    settlement: S,
    deadline: Deadline,
    timer: &impl ExecutionTimer,
    emitter: &impl TransactionalMessagingEmitter,
) -> Result<(), MessagingError> {
    let result = within(timer, deadline, |deadline| settlement.abandon(deadline))
        .await
        .and_then(std::convert::identity);
    if let Err(error) = &result {
        emit_runtime_failure(
            emitter,
            TransactionalMessagingRuntimePhase::ConsumerAbandon,
            error,
        );
    }
    result
}

async fn abandon_after_error<S: DeliverySettlement>(
    settlement: S,
    deadline: Deadline,
    timer: &impl ExecutionTimer,
    emitter: &impl TransactionalMessagingEmitter,
    primary: MessagingError,
) -> MessagingError {
    let _ = abandon_observed(settlement, deadline, timer, emitter).await;
    primary
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

/// Unbounded, saturating recovery schedule for reconnecting a consumer subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionBackoffPolicy {
    base: Duration,
    cap: Duration,
}

/// Validation failure for a subscription backoff schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionBackoffPolicyError {
    /// The initial delay must be positive.
    #[error("subscription backoff base must be non-zero")]
    ZeroBase,
    /// The initial delay cannot exceed the saturation cap.
    #[error("subscription backoff base exceeds cap")]
    BaseExceedsCap,
}

impl SubscriptionBackoffPolicy {
    /// Conservative default for an indefinitely supervised subscription.
    pub const STANDARD: Self = Self {
        base: Duration::from_secs(1),
        cap: Duration::from_secs(60),
    };

    /// Create an unbounded backoff which doubles after each failure and saturates at `cap`.
    pub fn new(base: Duration, cap: Duration) -> Result<Self, SubscriptionBackoffPolicyError> {
        if base.is_zero() {
            return Err(SubscriptionBackoffPolicyError::ZeroBase);
        }
        if base > cap {
            return Err(SubscriptionBackoffPolicyError::BaseExceedsCap);
        }
        Ok(Self { base, cap })
    }

    /// Return the saturated delay following the one-based failed attempt.
    #[must_use]
    pub fn delay_after(self, failed_attempt: NonZeroU32) -> Duration {
        let mut delay = self.base;
        for _ in 0..failed_attempt.get().saturating_sub(1).min(128) {
            delay = delay.saturating_mul(2).min(self.cap);
            if delay == self.cap {
                break;
            }
        }
        delay
    }
}

enum SubscriptionEvent<P, S> {
    Cancel,
    Received(Option<IncomingDelivery<P, S>>),
    Completed(
        Option<PartitionIdentity>,
        Result<ProcessingDisposition, MessagingError>,
    ),
}

/// Dependencies owned by one caller-driven transactional consumer worker.
pub struct ConsumerWorker<P, S, I, T, V, R, E> {
    window: std::num::NonZeroU16,
    source: Arc<S>,
    inbox: Arc<I>,
    transaction: Arc<T>,
    group: ConsumerGroup,
    validator: Arc<V>,
    subscription: SubscriptionIdentity,
    timer: Arc<R>,
    policy: ConsumerExecutionPolicy,
    emitter: Arc<E>,
    subscription_backoff: SubscriptionBackoffPolicy,
    payload: PhantomData<fn() -> P>,
}

impl<P, S, I, T, V, R, E> ConsumerWorker<P, S, I, T, V, R, E>
where
    P: AsRef<[u8]> + Send + Sync,
    S: DeliverySource<P>,
    I: InboxStore,
    T: ConsumerTx<P, Claim = I::Claim>,
    V: IngressValidator<P>,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    /// Bind every mandatory consumer dependency and policy.
    #[allow(clippy::too_many_arguments)]
    // reason: each argument is an independent mandatory port, identity, or closed policy.
    #[must_use]
    pub const fn new(
        window: std::num::NonZeroU16,
        source: Arc<S>,
        inbox: Arc<I>,
        transaction: Arc<T>,
        group: ConsumerGroup,
        validator: Arc<V>,
        subscription: SubscriptionIdentity,
        timer: Arc<R>,
        policy: ConsumerExecutionPolicy,
        emitter: Arc<E>,
        subscription_backoff: SubscriptionBackoffPolicy,
    ) -> Self {
        Self {
            window,
            source,
            inbox,
            transaction,
            group,
            validator,
            subscription,
            timer,
            policy,
            emitter,
            subscription_backoff,
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
        token: tokio_util::sync::CancellationToken,
    ) -> Result<(), MessagingError> {
        let mut recovery_attempt = NonZeroU32::MIN;
        loop {
            let subscribe = self.source.deliveries(&self.subscription, self.window);
            tokio::pin!(subscribe);
            let deliveries = tokio::select! {
                biased;
                () = token.cancelled() => return Ok(()),
                result = &mut subscribe => result,
            };
            let mut deliveries = match deliveries {
                Ok(deliveries) => deliveries,
                Err(error) if is_recoverable(error.kind()) => {
                    emit_runtime_failure(
                        self.emitter.as_ref(),
                        TransactionalMessagingRuntimePhase::ConsumerSubscribe,
                        &error,
                    );
                    self.emitter
                        .emit(TransactionalMessagingObservation::ConsumerSubscribeRetry {
                            outcome: TransactionalMessagingSubscribeOutcome::SubscribeError,
                        });
                    if wait_for_recovery(&self, &token, recovery_attempt).await? {
                        return Ok(());
                    }
                    recovery_attempt = recovery_attempt.saturating_add(1);
                    continue;
                }
                Err(error) => {
                    emit_runtime_failure(
                        self.emitter.as_ref(),
                        TransactionalMessagingRuntimePhase::ConsumerSubscribe,
                        &error,
                    );
                    return Err(error);
                }
            };

            match self
                .drive_subscription(&mut deliveries, &token, &mut recovery_attempt)
                .await?
            {
                None => return Ok(()),
                Some(outcome) => self
                    .emitter
                    .emit(TransactionalMessagingObservation::ConsumerSubscribeRetry { outcome }),
            }
            drop(deliveries);
            if wait_for_recovery(&self, &token, recovery_attempt).await? {
                return Ok(());
            }
            recovery_attempt = recovery_attempt.saturating_add(1);
        }
    }
    async fn drive_subscription(
        &self,
        stream: &mut rss_transactional_messaging::transport::ManagedDeliveryStream<S::Deliveries>,
        token: &tokio_util::sync::CancellationToken,
        recovery_attempt: &mut NonZeroU32,
    ) -> Result<Option<TransactionalMessagingSubscribeOutcome>, MessagingError> {
        use futures::{StreamExt as _, stream::FuturesUnordered};
        use std::collections::{HashMap, VecDeque, hash_map::Entry};
        let execution = ConsumerExecution::new(
            self.group.clone(),
            self.validator.as_ref(),
            &self.subscription,
            self.timer.as_ref(),
            self.policy,
            self.emitter.as_ref(),
        );
        let start = |item: PreparedDelivery<P, S::Settlement>| {
            let execution = &execution;
            async move {
                let key = item.partition().cloned();
                (
                    key,
                    process_prepared(
                        self.inbox.as_ref(),
                        self.transaction.as_ref(),
                        execution,
                        item,
                    )
                    .await,
                )
            }
        };
        let mut active = FuturesUnordered::new();
        let mut partitions =
            HashMap::<PartitionIdentity, VecDeque<PreparedDelivery<P, S::Settlement>>>::new();
        let mut outstanding = 0usize;
        let mut stopped = false;
        let mut retiring = false;
        let mut cause = Ok(None);
        loop {
            if stopped && active.is_empty() {
                return cause;
            }
            let event = tokio::select! {
                biased;
                () = token.cancelled(), if !stopped => SubscriptionEvent::Cancel,
                Some((key, result)) = active.next(), if !active.is_empty() => SubscriptionEvent::Completed(key, result),
                item = stream.next(), if !stopped && outstanding < usize::from(self.window.get()) => SubscriptionEvent::Received(item),
            };
            match event {
                SubscriptionEvent::Cancel => {
                    stopped = true;
                    stream.stop_admission();
                }
                SubscriptionEvent::Completed(key, result) => {
                    outstanding -= 1;
                    let reusable = can_continue(
                        result,
                        key.is_some(),
                        token.is_cancelled(),
                        recovery_attempt,
                        &mut cause,
                    );
                    if !reusable {
                        stopped = true;
                        stream.stop_admission();
                        // Dropping an unstarted AMQP handle forces the channel closed. Hold
                        // queued handles until active siblings finish their one-shot settlement.
                        retiring = true;
                        if cause.is_ok() {
                            cause = Ok(Some(TransactionalMessagingSubscribeOutcome::DeliveryError));
                        }
                    }
                    if !retiring
                        && let Some(key) = key
                        && let Entry::Occupied(mut lane) = partitions.entry(key)
                    {
                        if let Some(next) = lane.get_mut().pop_front() {
                            active.push(start(next));
                        } else {
                            lane.remove();
                        }
                    }
                }
                SubscriptionEvent::Received(None) => {
                    stopped = true;
                    stream.stop_admission();
                    cause = Ok(Some(TransactionalMessagingSubscribeOutcome::StreamEnd));
                }
                SubscriptionEvent::Received(Some(item)) => {
                    let deadlines = match execution.deadlines() {
                        Ok(deadlines) => deadlines,
                        Err(error) => {
                            stream.stop_admission();
                            stopped = true;
                            cause = Err(error);
                            continue;
                        }
                    };
                    let item = PreparedDelivery::incoming(&execution, item, deadlines);
                    outstanding += 1;
                    if let Some(key) = item.partition() {
                        match partitions.entry(key.clone()) {
                            Entry::Occupied(mut lane) => {
                                lane.get_mut().push_back(item);
                                continue;
                            }
                            Entry::Vacant(lane) => {
                                lane.insert(VecDeque::new());
                            }
                        }
                    }
                    active.push(start(item));
                }
            }
        }
    }
}

fn can_continue(
    result: Result<ProcessingDisposition, MessagingError>,
    ordered: bool,
    cancelled: bool,
    recovery_attempt: &mut NonZeroU32,
    cause: &mut Result<Option<TransactionalMessagingSubscribeOutcome>, MessagingError>,
) -> bool {
    match result {
        Ok(
            ProcessingDisposition::Committed(terminal) | ProcessingDisposition::Duplicate(terminal),
        ) => {
            *recovery_attempt = NonZeroU32::MIN;
            !ordered || terminal == TerminalDisposition::Succeeded
        }
        Ok(ProcessingDisposition::Rejected(_)) => {
            *recovery_attempt = NonZeroU32::MIN;
            true
        }
        Ok(_) => !ordered,
        Err(error) => {
            if (!is_recoverable(error.kind()) || cancelled) && cause.is_ok() {
                *cause = Err(error);
            }
            false
        }
    }
}

async fn wait_for_recovery<P, S, I, T, V, R, E>(
    worker: &ConsumerWorker<P, S, I, T, V, R, E>,
    token: &tokio_util::sync::CancellationToken,
    attempt: NonZeroU32,
) -> Result<bool, MessagingError>
where
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    let delay = worker.subscription_backoff.delay_after(attempt);
    let deadline = Deadline::from_timeout(worker.timer.as_ref(), delay).map_err(|error| {
        let error = MessagingError::new(MessagingErrorKind::Invariant, error);
        emit_runtime_failure(
            worker.emitter.as_ref(),
            TransactionalMessagingRuntimePhase::ConsumerDeadline,
            &error,
        );
        error
    })?;
    let waiting = worker.timer.sleep_until(deadline);
    tokio::pin!(waiting);
    Ok(tokio::select! {
        biased;
        () = token.cancelled() => true,
        () = &mut waiting => false,
    })
}

const fn is_recoverable(kind: MessagingErrorKind) -> bool {
    matches!(
        kind,
        MessagingErrorKind::Transient | MessagingErrorKind::DeadlineElapsed
    )
}
