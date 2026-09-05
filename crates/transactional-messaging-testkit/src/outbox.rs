//! Outbox identity, lease, publication and settlement conformance.

use std::future::Future;

use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging::outbox::{AppendOutcome, OutboxDisposition, OutboxLeaseStatus};
use rss_transactional_messaging::policy::{ExecutionBudget, ExecutionTimer};

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
    /// Observe a stale contender before settlement.
    fn stale_lease(&self) -> impl Future<Output = Result<OutboxLeaseStatus, MessagingError>>;
    /// Observe an expired settlement deadline.
    fn expired_lease(&self) -> impl Future<Output = Result<OutboxLeaseStatus, MessagingError>>;
    /// For windowed providers, observe first claim, renewal and DB-confirmed window expiry
    /// while retaining a valid lease. Providers without a same-ID window return `None`.
    fn delivery_window(
        &self,
    ) -> impl Future<Output = Result<Option<[OutboxLeaseStatus; 3]>, MessagingError>>;
    /// Claim again after Retry settlement and observe the same durable identity.
    fn retry_settlement_reclaims_same_message(
        &self,
    ) -> impl Future<Output = Result<ReclaimEvidence, ConformanceError>>;
    /// Expire a claim after publication but before settlement, then reclaim and mark Published.
    fn reclaim_after_publish_before_settle(
        &self,
    ) -> impl Future<Output = Result<ReclaimEvidence, ConformanceError>>;
}

/// Store-owned claim identities and final durable settlement observed by one scenario.
pub struct ReclaimEvidence {
    /// Identity of each successful claim, in order.
    pub claimed_message_ids: Vec<MessageId>,
    /// Actual durable disposition recorded by the store.
    pub settlement: OutboxDisposition,
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
    let recovered = within_budget(
        timer,
        deadline,
        "outbox.reclaim.budget",
        driver.reclaim_after_publish_before_settle(),
    )
    .await??;
    expect_count(
        "outbox.reclaim.claims",
        2,
        recovered.claimed_message_ids.len(),
    )?;
    expect_same_ids("outbox.reclaim.identity", &recovered.claimed_message_ids)?;
    expect_disposition_value(
        "outbox.reclaim.settlement",
        recovered.settlement,
        OutboxDisposition::Published,
    )?;
    driver.reset();
    let retried = within_budget(
        timer,
        deadline,
        "outbox.retry.budget",
        driver.retry_settlement_reclaims_same_message(),
    )
    .await??;
    expect_count("outbox.retry.claims", 2, retried.claimed_message_ids.len())?;
    expect_same_ids("outbox.retry.identity", &retried.claimed_message_ids)?;
    expect_disposition_value(
        "outbox.retry.settlement",
        retried.settlement,
        OutboxDisposition::Retry,
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
    )?;
    driver.reset();
    let window = within_budget(
        timer,
        deadline,
        "outbox.window.budget",
        driver.delivery_window(),
    )
    .await?
    .map_err(|error| ConformanceError::provider("outbox.window", error.kind()))?;
    expect_window(window)
}

fn expect_window(window: Option<[OutboxLeaseStatus; 3]>) -> Result<(), ConformanceError> {
    if let Some(states) = window {
        let mut remaining = Vec::new();
        for state in states {
            match state {
                OutboxLeaseStatus::Held {
                    remaining: lease,
                    delivery_remaining: Some(window),
                } if !lease.is_zero() => remaining.push(window),
                _ => {
                    return Err(ConformanceError::mismatch(
                        "outbox.window",
                        "held-with-window",
                        "missing-or-lost",
                    ));
                }
            }
        }
        if remaining[0].is_zero() || remaining[1] > remaining[0] || !remaining[2].is_zero() {
            return Err(ConformanceError::mismatch(
                "outbox.window",
                "frozen-then-expired",
                "reset-or-not-expired",
            ));
        }
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
