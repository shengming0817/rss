//! Inbox claim, duplicate, release and fencing conformance.

use std::future::Future;

use rss_transactional_messaging::error::MessagingError;
use rss_transactional_messaging::inbox::{IdempotencyDisposition, LeaseStatus};
use rss_transactional_messaging::policy::{ExecutionBudget, ExecutionTimer};

use crate::{ConformanceError, suite_deadline, within_budget};

/// Provider-owned inbox scenarios expressed through core dispositions.
pub trait InboxDriver: Send + Sync {
    /// Provider claim capability.
    type Claim: Send + Sync;

    /// Reset the isolated fixture before one scenario.
    fn reset(&self);
    /// First claim for one consumer identity.
    fn first_claim(
        &self,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>>;
    /// Concurrent claim for the same consumer identity.
    fn active_claim(
        &self,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>>;
    /// Claim for the same message under another consumer group.
    fn other_group_claim(
        &self,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>>;
    /// Redelivery after a durable terminal receipt.
    fn terminal_duplicate(
        &self,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>>;
    /// Extend the currently owned lease.
    fn extend_owned(&self) -> impl Future<Output = Result<LeaseStatus, MessagingError>>;
    /// Reclaim the same identity after a claim-before-commit crash expires.
    fn reclaim_after_expiry(
        &self,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>>;
    /// Release an owned non-terminal claim and acquire it again.
    fn reclaim_after_release(
        &self,
    ) -> impl Future<Output = Result<IdempotencyDisposition<Self::Claim>, MessagingError>>;
    /// Observe the previous claim after lease ownership changes.
    fn stale_lease(&self) -> impl Future<Output = Result<LeaseStatus, MessagingError>>;
}

/// Run the provider-neutral inbox conformance suite.
pub async fn run_inbox_conformance<D: InboxDriver>(
    driver: &D,
    timer: &impl ExecutionTimer,
    budget: ExecutionBudget,
) -> Result<(), ConformanceError> {
    let deadline = suite_deadline(timer, budget)?;
    driver.reset();
    expect_disposition(
        "inbox.claim.first",
        within_budget(
            timer,
            deadline,
            "inbox.claim.first.budget",
            driver.first_claim(),
        )
        .await?,
        "acquired",
    )?;
    expect_disposition(
        "inbox.claim.active",
        within_budget(
            timer,
            deadline,
            "inbox.claim.active.budget",
            driver.active_claim(),
        )
        .await?,
        "in-progress",
    )?;
    expect_disposition(
        "inbox.claim.other-group",
        within_budget(
            timer,
            deadline,
            "inbox.claim.other-group.budget",
            driver.other_group_claim(),
        )
        .await?,
        "acquired",
    )?;

    driver.reset();
    expect_disposition(
        "inbox.claim.terminal",
        within_budget(
            timer,
            deadline,
            "inbox.claim.terminal.budget",
            driver.terminal_duplicate(),
        )
        .await?,
        "terminal",
    )?;

    driver.reset();
    expect_lease(
        "inbox.extend.owned",
        within_budget(
            timer,
            deadline,
            "inbox.extend.owned.budget",
            driver.extend_owned(),
        )
        .await?,
        true,
    )?;
    expect_disposition(
        "inbox.crash-before-commit.reclaim",
        within_budget(
            timer,
            deadline,
            "inbox.crash-before-commit.budget",
            driver.reclaim_after_expiry(),
        )
        .await?,
        "acquired",
    )?;
    expect_disposition(
        "inbox.release.reclaim",
        within_budget(
            timer,
            deadline,
            "inbox.release.budget",
            driver.reclaim_after_release(),
        )
        .await?,
        "acquired",
    )?;
    expect_lease(
        "inbox.extend.stale",
        within_budget(
            timer,
            deadline,
            "inbox.extend.stale.budget",
            driver.stale_lease(),
        )
        .await?,
        false,
    )
}

fn expect_disposition<C>(
    stage: &'static str,
    result: Result<IdempotencyDisposition<C>, MessagingError>,
    expected: &'static str,
) -> Result<(), ConformanceError> {
    match result {
        Ok(actual) => {
            let actual = match actual {
                IdempotencyDisposition::Acquired(_) => "acquired",
                IdempotencyDisposition::InProgress => "in-progress",
                IdempotencyDisposition::Terminal(_) => "terminal",
            };
            if actual == expected {
                Ok(())
            } else {
                Err(ConformanceError::mismatch(stage, expected, actual))
            }
        }
        Err(error) => Err(ConformanceError::provider(stage, error.kind())),
    }
}

fn expect_lease(
    stage: &'static str,
    result: Result<LeaseStatus, MessagingError>,
    expected_held: bool,
) -> Result<(), ConformanceError> {
    match result {
        Ok(LeaseStatus::Held { .. }) if expected_held => Ok(()),
        Ok(LeaseStatus::Lost) if !expected_held => Ok(()),
        Ok(LeaseStatus::Held { .. }) => Err(ConformanceError::mismatch(stage, "lost", "held")),
        Ok(LeaseStatus::Lost) => Err(ConformanceError::mismatch(stage, "held", "lost")),
        Err(error) => Err(ConformanceError::provider(stage, error.kind())),
    }
}
