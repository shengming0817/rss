//! Transactional consumer execution, lease supervision, and managed worker ownership.

use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use rss_runtime::{ManagedTask, ManagedTaskRegistration, ShutdownError, TaskStatus};
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::inbox::{
    ConsumerGroup, IdempotencyDisposition, InboxStore, LeaseStatus,
};
use rss_transactional_messaging::message::SubscriptionIdentity;
use rss_transactional_messaging::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingEmitter,
    TransactionalMessagingIoOutcome, TransactionalMessagingObservation,
    TransactionalMessagingRuntimePhase, TransactionalMessagingSubscribeOutcome,
};
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, ConsumerExecutionPolicy, ExecutionDeadlines, ExecutionTimer, ShutdownBudget,
    within,
};
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
    let (message, settlement) = delivery.into_parts();
    let deadlines = execution.deadlines()?;
    let binding =
        match verify_ingress(
            execution.validator,
            execution.group.clone(),
            execution.subscription,
            &message,
        ) {
            Ok(binding) => binding,
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
                return Ok(ProcessingDisposition::Rejected(failure));
            }
        };

    let claimed = match within(execution.timer, deadlines.operation(), |deadline| {
        inbox.claim(binding.identity(), deadline)
    })
    .await
    .and_then(std::convert::identity)
    {
        Ok(claimed) => claimed,
        Err(error) => {
            emit_runtime_failure(
                execution.emitter,
                TransactionalMessagingRuntimePhase::ConsumerClaim,
                &error,
            );
            return Err(abandon_after_error(
                settlement,
                deadlines.settlement(),
                execution.timer,
                execution.emitter,
                error,
            )
            .await);
        }
    };
    match claimed {
        IdempotencyDisposition::InProgress => {
            execution
                .emitter
                .emit(TransactionalMessagingObservation::ConsumerClaimInProgress);
            settle_observed(
                settlement,
                SettlementDecision::requeue(),
                deadlines.settlement(),
                execution.timer,
                execution.emitter,
            )
            .await?;
            Ok(ProcessingDisposition::InProgress)
        }
        IdempotencyDisposition::Terminal(receipt) => match binding.validate_terminal(receipt) {
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
        IdempotencyDisposition::Acquired(claim) => {
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
    match within(execution.timer, state.deadlines.operation(), |deadline| {
        inbox.extend(&state.claim, deadline)
    })
    .await
    .and_then(std::convert::identity)
    {
        Ok(LeaseStatus::Held { remaining }) => {
            if let Err(error) = validate_renewal_window(inbox, execution, remaining) {
                return Err(abandon_after_error(
                    state.settlement,
                    state.deadlines.settlement(),
                    execution.timer,
                    execution.emitter,
                    error,
                )
                .await);
            }
        }
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
    }
    let raced = {
        let transaction_flow = transaction_loop(
            transaction,
            execution,
            &state.claim,
            &state.message,
            &state.binding,
            state.deadlines.operation(),
        );
        let renewal = renewal_loop(inbox, execution, &state.claim, state.deadlines.operation());
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
    deadline: AbsoluteDeadline,
) -> Result<RenewalExit, MessagingError>
where
    I: InboxStore,
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    loop {
        let wake = deadline.capped(execution.timer, inbox.lease_policy().interval());
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
                validate_renewal_window(inbox, execution, remaining)?;
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

fn validate_renewal_window<I: InboxStore, V, R, E>(
    inbox: &I,
    execution: &ConsumerExecution<'_, V, R, E>,
    remaining: Duration,
) -> Result<(), MessagingError>
where
    R: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    if inbox.lease_policy().fits(remaining) {
        return Ok(());
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
    deadline: AbsoluteDeadline,
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
        if deadline.remaining(execution.timer).is_zero() {
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
        if !outcome.may_retry()
            || !execution
                .policy
                .retry()
                .allows_attempt(attempt.saturating_add(1))
        {
            return outcome;
        }
        let delay = execution.policy.retry().delay_after(attempt);
        if deadline.remaining(execution.timer) <= delay {
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
        attempt = attempt.saturating_add(1);
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

async fn reject_invalid<S: DeliverySettlement>(
    rejection: rss_transactional_messaging::transaction::DecodeRejection,
    settlement: S,
    deadline: AbsoluteDeadline,
    timer: &impl ExecutionTimer,
    emitter: &impl TransactionalMessagingEmitter,
) -> Result<(), MessagingError> {
    let failure = rejection.reason();
    emitter.emit(TransactionalMessagingObservation::ConsumerIngressRejected { reason: failure });
    settle_observed(
        settlement,
        rejection.into_decision(),
        deadline,
        timer,
        emitter,
    )
    .await
}

async fn settle_observed<S: DeliverySettlement>(
    settlement: S,
    decision: SettlementDecision,
    deadline: AbsoluteDeadline,
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
    deadline: AbsoluteDeadline,
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
    deadline: AbsoluteDeadline,
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

/// Owned dependencies for one managed transactional consumer worker.
pub struct ConsumerWorker<P, S, I, T, V, R, E> {
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
    P: AsRef<[u8]> + Send + Sync + 'static,
    S: DeliverySource<P> + 'static,
    I: InboxStore + 'static,
    T: ConsumerTx<P, Claim = I::Claim> + 'static,
    V: IngressValidator<P> + 'static,
    R: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    /// Bind every mandatory consumer dependency and policy.
    #[allow(clippy::too_many_arguments)]
    // reason: each argument is an independent mandatory port, identity, or closed policy.
    #[must_use]
    pub const fn new(
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

    /// Transfer the worker into the `rss-runtime` startup token funnel.
    pub fn into_registration(
        self,
        name: impl Into<String>,
        shutdown_budget: ShutdownBudget,
    ) -> (ManagedTaskRegistration, TaskStatus) {
        let (start, status) = ManagedTask::prepare(name, shutdown_budget.timeout());
        let registration = start.into_registration(move |token| async move {
            consumer_loop(self, token).await.map_err(ShutdownError::new)
        });
        (registration, status)
    }
}

async fn consumer_loop<P, S, I, T, V, R, E>(
    worker: ConsumerWorker<P, S, I, T, V, R, E>,
    token: tokio_util::sync::CancellationToken,
) -> Result<(), MessagingError>
where
    P: AsRef<[u8]> + Send + Sync + 'static,
    S: DeliverySource<P> + 'static,
    I: InboxStore + 'static,
    T: ConsumerTx<P, Claim = I::Claim> + 'static,
    V: IngressValidator<P> + 'static,
    R: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    let mut recovery_attempt = NonZeroU32::MIN;
    loop {
        let subscribe = worker.source.deliveries(&worker.subscription);
        tokio::pin!(subscribe);
        let deliveries = tokio::select! {
            biased;
            () = token.cancelled() => return Ok(()),
            result = &mut subscribe => result,
        };
        let mut deliveries = match deliveries {
            Ok(deliveries) => {
                recovery_attempt = NonZeroU32::MIN;
                deliveries
            }
            Err(error) if is_recoverable(error.kind()) => {
                emit_runtime_failure(
                    worker.emitter.as_ref(),
                    TransactionalMessagingRuntimePhase::ConsumerSubscribe,
                    &error,
                );
                worker
                    .emitter
                    .emit(TransactionalMessagingObservation::ConsumerSubscribeRetry {
                        outcome: TransactionalMessagingSubscribeOutcome::SubscribeError,
                    });
                if wait_for_recovery(&worker, &token, recovery_attempt).await? {
                    return Ok(());
                }
                recovery_attempt = recovery_attempt.saturating_add(1);
                continue;
            }
            Err(error) => {
                emit_runtime_failure(
                    worker.emitter.as_ref(),
                    TransactionalMessagingRuntimePhase::ConsumerSubscribe,
                    &error,
                );
                return Err(error);
            }
        };

        loop {
            let delivery = tokio::select! {
                biased;
                () = token.cancelled() => return Ok(()),
                item = deliveries.next() => item,
            };
            let Some(delivery) = delivery else {
                worker
                    .emitter
                    .emit(TransactionalMessagingObservation::ConsumerSubscribeRetry {
                        outcome: TransactionalMessagingSubscribeOutcome::StreamEnd,
                    });
                break;
            };
            let execution = ConsumerExecution::new(
                worker.group.clone(),
                worker.validator.as_ref(),
                &worker.subscription,
                worker.timer.as_ref(),
                worker.policy,
                worker.emitter.as_ref(),
            );
            let processing = async {
                match delivery {
                    IncomingDelivery::Valid(delivery) => {
                        consume_once(
                            worker.inbox.as_ref(),
                            worker.transaction.as_ref(),
                            &execution,
                            *delivery,
                        )
                        .await?;
                    }
                    IncomingDelivery::Invalid(invalid) => {
                        let (rejection, settlement) = invalid.into_parts();
                        reject_invalid(
                            rejection,
                            settlement,
                            execution.deadlines()?.settlement(),
                            execution.timer,
                            execution.emitter(),
                        )
                        .await?;
                    }
                }
                Ok::<(), MessagingError>(())
            };
            tokio::pin!(processing);
            let result = tokio::select! {
                biased;
                result = &mut processing => result,
                () = token.cancelled() => {
                    processing.await?;
                    return Ok(());
                }
            };
            match result {
                Ok(()) => {}
                Err(error) if is_recoverable(error.kind()) => {
                    worker.emitter.emit(
                        TransactionalMessagingObservation::ConsumerSubscribeRetry {
                            outcome: TransactionalMessagingSubscribeOutcome::DeliveryError,
                        },
                    );
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if wait_for_recovery(&worker, &token, recovery_attempt).await? {
            return Ok(());
        }
        recovery_attempt = recovery_attempt.saturating_add(1);
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
    let deadline =
        AbsoluteDeadline::from_timeout(worker.timer.as_ref(), delay).map_err(|error| {
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
