//! Provider-neutral transport conformance. Fixtures own I/O; evidence uses core protocol types.
use crate::{ConformanceError, suite_deadline, within_budget};
use rss_transactional_messaging::{
    message::MessageId,
    policy::{ExecutionBudget, ExecutionTimer},
};

#[cfg(feature = "producer")]
use rss_transactional_messaging::transport::{PublishFailureKind, PublishOutcome};

/// One observed provider publication attempt, including its original message identity.
#[cfg(feature = "producer")]
pub struct PublishAttempt {
    /// Identity supplied to the real provider.
    pub message_id: MessageId,
    /// Outcome returned by the provider port.
    pub outcome: PublishOutcome<()>,
}
/// Isolated publication scenarios implemented by the provider's integration driver.
#[cfg(feature = "producer")]
pub trait PublisherTransportDriver: Send + Sync {
    /// Publish a routable message and await confirmation.
    fn confirmed(&self) -> impl Future<Output = Result<PublishAttempt, ConformanceError>>;
    /// Observe a definite transient refusal (for example an unroutable destination).
    fn transient(&self) -> impl Future<Output = Result<PublishAttempt, ConformanceError>>;
    /// Observe a definite permanent refusal (for example insufficient broker authority).
    fn permanent(&self) -> impl Future<Output = Result<PublishAttempt, ConformanceError>>;
    /// Lose confirmation, then retry the original identity using replacement transport.
    fn ambiguous_retry(
        &self,
    ) -> impl Future<Output = Result<Vec<PublishAttempt>, ConformanceError>>;
}
/// Verify confirmation, definitive failures and same-identity retry after ambiguity.
#[cfg(feature = "producer")]
pub async fn run_publisher_transport_conformance(
    driver: &impl PublisherTransportDriver,
    timer: &impl ExecutionTimer,
    budget: ExecutionBudget,
) -> Result<(), ConformanceError> {
    let deadline = suite_deadline(timer, budget)?;
    let confirmed = within_budget(
        timer,
        deadline,
        "publisher.confirmed.budget",
        driver.confirmed(),
    )
    .await??;
    expect_publish("publisher.confirmed", &confirmed.outcome, "confirmed")?;
    let transient = within_budget(
        timer,
        deadline,
        "publisher.transient.budget",
        driver.transient(),
    )
    .await??;
    expect_publish("publisher.transient", &transient.outcome, "transient")?;
    let permanent = within_budget(
        timer,
        deadline,
        "publisher.permanent.budget",
        driver.permanent(),
    )
    .await??;
    expect_publish("publisher.permanent", &permanent.outcome, "permanent")?;
    let retry = within_budget(
        timer,
        deadline,
        "publisher.ambiguous.budget",
        driver.ambiguous_retry(),
    )
    .await??;
    if retry.len() != 2 {
        return Err(ConformanceError::count(
            "publisher.ambiguous.attempts",
            2,
            retry.len(),
        ));
    }
    expect_publish("publisher.ambiguous.first", &retry[0].outcome, "ambiguous")?;
    expect_publish("publisher.ambiguous.retry", &retry[1].outcome, "confirmed")?;
    if retry[0].message_id != retry[1].message_id {
        return Err(ConformanceError::mismatch(
            "publisher.ambiguous.identity",
            "same-id",
            "different-id",
        ));
    }
    Ok(())
}
#[cfg(feature = "producer")]
fn expect_publish(
    stage: &'static str,
    outcome: &PublishOutcome<()>,
    expected: &'static str,
) -> Result<(), ConformanceError> {
    let actual = match outcome {
        PublishOutcome::Confirmed(()) => "confirmed",
        PublishOutcome::Ambiguous(_) => "ambiguous",
        PublishOutcome::DefinitelyNotPublished(failure) => match failure.kind() {
            PublishFailureKind::Transient => "transient",
            PublishFailureKind::Permanent => "permanent",
        },
    };
    if actual == expected {
        Ok(())
    } else {
        Err(ConformanceError::mismatch(stage, expected, actual))
    }
}

/// Broker observations after one settlement or abandonment.
#[cfg(feature = "consumer")]
pub struct DeliveryEvidence {
    /// Identity owned by the original delivery.
    pub message_id: MessageId,
    /// Identities actually received by the subsequent consumer.
    pub redelivered_ids: Vec<MessageId>,
}
/// Observed admission boundary when a stream is cancelled with one delivery in flight.
#[cfg(feature = "consumer")]
pub struct CancellationEvidence {
    /// The first delivery that completed settlement after cancellation.
    pub drained_id: MessageId,
    /// A distinct successor queued before cancellation.
    pub pending_id: MessageId,
    /// Messages received by the replacement consumer.
    pub replacement_ids: Vec<MessageId>,
}
/// Real provider delivery, settlement and cancellation scenarios.
#[cfg(feature = "consumer")]
pub trait DeliveryTransportDriver: Send + Sync {
    /// ACK removes the original delivery.
    fn acknowledged(&self) -> impl Future<Output = Result<DeliveryEvidence, ConformanceError>>;
    /// Requeue makes the original identity available again.
    fn requeued(&self) -> impl Future<Output = Result<DeliveryEvidence, ConformanceError>>;
    /// Reject removes the original from the source route.
    fn rejected(&self) -> impl Future<Output = Result<DeliveryEvidence, ConformanceError>>;
    /// Abandon retires the original session without settlement.
    fn abandoned(&self) -> impl Future<Output = Result<DeliveryEvidence, ConformanceError>>;
    /// A failed settlement retires the original session without a contradictory decision.
    fn settlement_failed(&self)
    -> impl Future<Output = Result<DeliveryEvidence, ConformanceError>>;
    /// Cancellation stops admission while allowing an already delivered message to settle.
    fn cancelled(&self) -> impl Future<Output = Result<CancellationEvidence, ConformanceError>>;
}
/// Verify one-shot settlement, redelivery identity and the cancellation admission barrier.
#[cfg(feature = "consumer")]
pub async fn run_delivery_transport_conformance(
    driver: &impl DeliveryTransportDriver,
    timer: &impl ExecutionTimer,
    budget: ExecutionBudget,
) -> Result<(), ConformanceError> {
    let deadline = suite_deadline(timer, budget)?;
    expect_delivery(
        "delivery.ack",
        within_budget(
            timer,
            deadline,
            "delivery.ack.budget",
            driver.acknowledged(),
        )
        .await??,
        false,
    )?;
    expect_delivery(
        "delivery.requeue",
        within_budget(
            timer,
            deadline,
            "delivery.requeue.budget",
            driver.requeued(),
        )
        .await??,
        true,
    )?;
    expect_delivery(
        "delivery.reject",
        within_budget(timer, deadline, "delivery.reject.budget", driver.rejected()).await??,
        false,
    )?;
    expect_delivery(
        "delivery.abandon",
        within_budget(
            timer,
            deadline,
            "delivery.abandon.budget",
            driver.abandoned(),
        )
        .await??,
        true,
    )?;
    expect_delivery(
        "delivery.failure",
        within_budget(
            timer,
            deadline,
            "delivery.failure.budget",
            driver.settlement_failed(),
        )
        .await??,
        true,
    )?;
    let cancelled = within_budget(
        timer,
        deadline,
        "delivery.cancel.budget",
        driver.cancelled(),
    )
    .await??;
    if cancelled.drained_id == cancelled.pending_id
        || cancelled.replacement_ids != [cancelled.pending_id]
    {
        return Err(ConformanceError::mismatch(
            "delivery.cancel",
            "pending-successor-only",
            "wrong-delivery",
        ));
    }
    Ok(())
}
#[cfg(feature = "consumer")]
fn expect_delivery(
    stage: &'static str,
    evidence: DeliveryEvidence,
    redelivers: bool,
) -> Result<(), ConformanceError> {
    let expected = usize::from(redelivers);
    if evidence.redelivered_ids.len() != expected {
        return Err(ConformanceError::count(
            stage,
            expected,
            evidence.redelivered_ids.len(),
        ));
    }
    if redelivers && evidence.redelivered_ids[0] != evidence.message_id {
        return Err(ConformanceError::mismatch(stage, "same-id", "different-id"));
    }
    Ok(())
}
