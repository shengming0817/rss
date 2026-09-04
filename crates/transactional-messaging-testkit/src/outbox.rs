//! Outbox identity, lease, publication and settlement conformance.

use std::future::Future;

use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging::outbox::{
    AppendOutcome, OutboxDisposition, OutboxLeaseStatus, OutboxSettlement,
};
use rss_transactional_messaging::policy::{ExecutionBudget, ExecutionTimer};
use rss_transactional_messaging::transport::PublishOutcome;

use crate::{ConformanceError, suite_deadline, within_budget};

/// Provider-owned outbox scenarios expressed only through core outcomes.
pub trait OutboxDriver: Send + Sync {
    /// Reset the isolated fixture before one scenario.
    fn reset(&self);
    /// Append a new stable message fact.
    fn append_first(&self) -> impl Future<Output = Result<AppendOutcome, MessagingError>>;
    /// Append the same identity and fingerprint again.
    fn append_same(&self) -> impl Future<Output = Result<AppendOutcome, MessagingError>>;
    /// Append the same identity with conflicting authored facts.
    fn append_conflict(&self) -> impl Future<Output = Result<AppendOutcome, MessagingError>>;
    /// Claim only the oldest unresolved row from one partition.
    fn partition_head_claims(&self) -> impl Future<Output = Result<usize, MessagingError>>;
    /// Observe that an unresolved dead-letter head blocks its partition successor.
    fn blocked_partition_claims(&self) -> impl Future<Output = Result<usize, MessagingError>>;
    /// Publish and settle one confirmed claim.
    fn confirmed_publish(
        &self,
    ) -> impl Future<Output = Result<(PublishOutcome<()>, OutboxSettlement<()>), ConformanceError>>;
    /// Map a definite transient publication failure to retry.
    fn transient_publish(&self)
    -> impl Future<Output = Result<PublishOutcome<()>, MessagingError>>;
    /// Retry one ambiguous publication with the original identity.
    fn ambiguous_publish(
        &self,
    ) -> impl Future<Output = Result<Vec<PublishOutcome<()>>, ConformanceError>>;
    /// Observe a stale contender before settlement.
    fn stale_lease(&self) -> impl Future<Output = Result<OutboxLeaseStatus, MessagingError>>;
    /// Observe an expired settlement deadline.
    fn expired_lease(&self) -> impl Future<Output = Result<OutboxLeaseStatus, MessagingError>>;
    /// Map a definite permanent publication failure to dead letter.
    fn permanent_publish(&self)
    -> impl Future<Output = Result<PublishOutcome<()>, MessagingError>>;
    /// Publish, crash before settlement, reclaim, and finish the same durable row.
    fn publish_before_settle_recovery(
        &self,
    ) -> impl Future<Output = Result<Vec<PublishOutcome<()>>, ConformanceError>>;
    /// Stable message identities observed by the current publication scenario.
    fn published_message_ids(&self) -> Vec<MessageId>;
    /// Durable settlement dispositions observed by the current publication scenario.
    fn settlement_dispositions(&self) -> Vec<OutboxDisposition>;
    /// Final consumer effects observed across all at-least-once deliveries.
    fn consumer_effects(&self) -> usize;
}

/// Run the provider-neutral outbox conformance suite.
pub async fn run_outbox_conformance<D: OutboxDriver>(
    driver: &D,
    timer: &impl ExecutionTimer,
    budget: ExecutionBudget,
) -> Result<(), ConformanceError> {
    let deadline = suite_deadline(timer, budget)?;
    driver.reset();
    expect_append(
        "outbox.append.first",
        within_budget(
            timer,
            deadline,
            "outbox.append.first.budget",
            driver.append_first(),
        )
        .await?,
        AppendOutcome::Inserted,
    )?;
    expect_append(
        "outbox.append.same",
        within_budget(
            timer,
            deadline,
            "outbox.append.same.budget",
            driver.append_same(),
        )
        .await?,
        AppendOutcome::AlreadyPresent,
    )?;
    match within_budget(
        timer,
        deadline,
        "outbox.append.conflict.budget",
        driver.append_conflict(),
    )
    .await?
    {
        Err(error) if error.kind() == MessagingErrorKind::Conflict => {}
        Err(error) => {
            return Err(ConformanceError::provider(
                "outbox.append.conflict",
                error.kind(),
            ));
        }
        Ok(_) => {
            return Err(ConformanceError::mismatch(
                "outbox.append.conflict",
                "conflict",
                "accepted",
            ));
        }
    }
    expect_count_result(
        "outbox.partition-head.claims",
        within_budget(
            timer,
            deadline,
            "outbox.partition-head.budget",
            driver.partition_head_claims(),
        )
        .await?,
        1,
    )?;
    expect_count_result(
        "outbox.dead-letter-head.claims",
        within_budget(
            timer,
            deadline,
            "outbox.dead-letter-head.budget",
            driver.blocked_partition_claims(),
        )
        .await?,
        0,
    )?;

    driver.reset();
    let (published, settlement) = within_budget(
        timer,
        deadline,
        "outbox.publish.confirmed.budget",
        driver.confirmed_publish(),
    )
    .await?
    .map_err(|error| error.at_stage("outbox.publish.confirmed"))?;
    expect_publish("outbox.publish.confirmed", &published, "confirmed")?;
    expect_settlement(
        "outbox.publish.confirmed.settlement",
        &settlement,
        OutboxDisposition::Published,
    )?;

    driver.reset();
    let outcomes = within_budget(
        timer,
        deadline,
        "outbox.publish-before-settle.budget",
        driver.publish_before_settle_recovery(),
    )
    .await?
    .map_err(|error| error.at_stage("outbox.publish-before-settle"))?;
    expect_count(
        "outbox.publish-before-settle.publish-calls",
        2,
        outcomes.len(),
    )?;
    expect_same_ids(
        "outbox.publish-before-settle.identity",
        &driver.published_message_ids(),
    )?;
    expect_publish_sequence(
        "outbox.publish-before-settle.outcomes",
        &outcomes,
        &["ambiguous", "confirmed"],
    )?;
    expect_count(
        "outbox.publish-before-settle.settlement-calls",
        1,
        driver.settlement_dispositions().len(),
    )?;
    expect_disposition_value(
        "outbox.publish-before-settle.settlement",
        driver.settlement_dispositions()[0],
        OutboxDisposition::Published,
    )?;
    expect_count(
        "outbox.publish-before-settle.consumer-effects",
        1,
        driver.consumer_effects(),
    )?;

    driver.reset();
    let transient = within_budget(
        timer,
        deadline,
        "outbox.publish.transient.budget",
        driver.transient_publish(),
    )
    .await?
    .map_err(|error| ConformanceError::provider("outbox.publish.transient", error.kind()))?;
    expect_publish(
        "outbox.publish.transient",
        &transient,
        "definitely-not-published-transient",
    )?;
    expect_settlement(
        "outbox.publish.transient.settlement",
        &transient.into_settlement(),
        OutboxDisposition::Retry,
    )?;

    driver.reset();
    let outcomes = within_budget(
        timer,
        deadline,
        "outbox.publish.ambiguous.budget",
        driver.ambiguous_publish(),
    )
    .await?
    .map_err(|error| error.at_stage("outbox.publish.ambiguous"))?;
    expect_publish_sequence(
        "outbox.publish.ambiguous.outcomes",
        &outcomes,
        &["ambiguous", "confirmed"],
    )?;
    expect_same_ids(
        "outbox.publish.ambiguous.identity",
        &driver.published_message_ids(),
    )?;
    expect_count(
        "outbox.publish.ambiguous.consumer-effects",
        1,
        driver.consumer_effects(),
    )?;

    driver.reset();
    let permanent = within_budget(
        timer,
        deadline,
        "outbox.publish.permanent.budget",
        driver.permanent_publish(),
    )
    .await?
    .map_err(|error| ConformanceError::provider("outbox.publish.permanent", error.kind()))?;
    expect_publish(
        "outbox.publish.permanent",
        &permanent,
        "definitely-not-published-permanent",
    )?;
    expect_settlement(
        "outbox.publish.permanent.settlement",
        &permanent.into_settlement(),
        OutboxDisposition::DeadLetter,
    )?;

    expect_lease(
        "outbox.lease.stale",
        within_budget(
            timer,
            deadline,
            "outbox.lease.stale.budget",
            driver.stale_lease(),
        )
        .await?,
        false,
    )?;
    expect_lease(
        "outbox.lease.expired",
        within_budget(
            timer,
            deadline,
            "outbox.lease.expired.budget",
            driver.expired_lease(),
        )
        .await?,
        false,
    )
}

fn expect_publish(
    stage: &'static str,
    outcome: &PublishOutcome<()>,
    expected: &'static str,
) -> Result<(), ConformanceError> {
    let actual = match outcome {
        PublishOutcome::Confirmed(()) => "confirmed",
        PublishOutcome::DefinitelyNotPublished(failure) if failure.kind().is_retryable() => {
            "definitely-not-published-transient"
        }
        PublishOutcome::DefinitelyNotPublished(_) => "definitely-not-published-permanent",
        PublishOutcome::Ambiguous(_) => "ambiguous",
    };
    if actual == expected {
        Ok(())
    } else {
        Err(ConformanceError::mismatch(stage, expected, actual))
    }
}

fn expect_publish_sequence(
    stage: &'static str,
    outcomes: &[PublishOutcome<()>],
    expected: &[&'static str],
) -> Result<(), ConformanceError> {
    expect_count(stage, expected.len(), outcomes.len())?;
    for (outcome, expected) in outcomes.iter().zip(expected) {
        expect_publish(stage, outcome, expected)?;
    }
    Ok(())
}

fn expect_same_ids(stage: &'static str, ids: &[MessageId]) -> Result<(), ConformanceError> {
    if ids.len() >= 2 && ids.windows(2).all(|pair| pair[0] == pair[1]) {
        Ok(())
    } else {
        Err(ConformanceError::mismatch(
            stage,
            "same-message-id",
            "changed-or-missing-message-id",
        ))
    }
}

fn expect_settlement(
    stage: &'static str,
    settlement: &OutboxSettlement<()>,
    expected: OutboxDisposition,
) -> Result<(), ConformanceError> {
    let actual = settlement.disposition();
    if actual == expected {
        Ok(())
    } else {
        Err(ConformanceError::mismatch(
            stage,
            disposition_label(expected),
            disposition_label(actual),
        ))
    }
}

fn expect_disposition_value(
    stage: &'static str,
    actual: OutboxDisposition,
    expected: OutboxDisposition,
) -> Result<(), ConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ConformanceError::mismatch(
            stage,
            disposition_label(expected),
            disposition_label(actual),
        ))
    }
}

fn expect_count_result(
    stage: &'static str,
    actual: Result<usize, MessagingError>,
    expected: usize,
) -> Result<(), ConformanceError> {
    match actual {
        Ok(actual) => expect_count(stage, expected, actual),
        Err(error) => Err(ConformanceError::provider(stage, error.kind())),
    }
}

fn expect_count(
    stage: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), ConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ConformanceError::count(stage, expected, actual))
    }
}

fn expect_append(
    stage: &'static str,
    actual: Result<AppendOutcome, MessagingError>,
    expected: AppendOutcome,
) -> Result<(), ConformanceError> {
    match actual {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => Err(ConformanceError::mismatch(
            stage,
            append_label(expected),
            append_label(actual),
        )),
        Err(error) => Err(ConformanceError::provider(stage, error.kind())),
    }
}

fn expect_lease(
    stage: &'static str,
    actual: Result<OutboxLeaseStatus, MessagingError>,
    expected_held: bool,
) -> Result<(), ConformanceError> {
    match actual {
        Ok(OutboxLeaseStatus::Held { .. }) if expected_held => Ok(()),
        Ok(OutboxLeaseStatus::Lost) if !expected_held => Ok(()),
        Ok(OutboxLeaseStatus::Held { .. }) => {
            Err(ConformanceError::mismatch(stage, "lost", "held"))
        }
        Ok(OutboxLeaseStatus::Lost) => Err(ConformanceError::mismatch(stage, "held", "lost")),
        Err(error) => Err(ConformanceError::provider(stage, error.kind())),
    }
}

const fn append_label(value: AppendOutcome) -> &'static str {
    match value {
        AppendOutcome::Inserted => "inserted",
        AppendOutcome::AlreadyPresent => "already-present",
    }
}

const fn disposition_label(value: OutboxDisposition) -> &'static str {
    match value {
        OutboxDisposition::Published => "published",
        OutboxDisposition::Retry => "retry",
        OutboxDisposition::DeadLetter => "dead-letter",
    }
}
