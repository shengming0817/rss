//! Local transaction settlement and no-replay conformance.

use std::future::Future;

use rss_transactional_messaging::policy::{ExecutionBudget, ExecutionTimer};
use rss_transactional_messaging::transaction::{FailureClass, LocalTxAttempt};

use crate::{ConformanceError, suite_deadline, within_budget};

/// Provider-owned LocalTx scenarios and action-local probes.
pub trait LocalTxDriver: Send + Sync {
    /// Opaque provider error. It deliberately has no formatting bound.
    type Error: Send;
    /// Provider-owned durable snapshot compared without formatting.
    type Snapshot: PartialEq + Send;

    /// Reset the isolated fixture before one scenario.
    fn reset(&self);

    /// Execute a successful transaction.
    fn committed(&self) -> impl Future<Output = LocalTxAttempt<(), Self::Error>>;

    /// Execute an operation followed by a confirmed rollback.
    fn rolled_back(&self) -> impl Future<Output = LocalTxAttempt<(), Self::Error>>;

    /// Reject before any durable write begins.
    fn validation_rejected(&self) -> impl Future<Output = LocalTxAttempt<(), Self::Error>>;

    /// Reject an unauthorized operation before any durable write begins.
    fn authorization_rejected(&self) -> impl Future<Output = LocalTxAttempt<(), Self::Error>>;

    /// Produce an unknown commit outcome.
    fn commit_unknown(&self) -> impl Future<Output = LocalTxAttempt<(), Self::Error>>;

    /// Produce a rollback failure.
    fn rollback_failed(&self) -> impl Future<Output = LocalTxAttempt<(), Self::Error>>;

    /// Map an opaque provider error to the core-owned failure class.
    fn classify(&self, error: &Self::Error) -> FailureClass;

    /// Durable writes performed by the current scenario.
    fn writes(&self) -> usize;

    /// Transaction attempts performed by the current scenario.
    fn attempts(&self) -> usize;
    /// Read the current durable state for commit/rollback/no-write assertions.
    fn snapshot(&self) -> impl Future<Output = Self::Snapshot>;
    /// Expected durable state after the successful commit scenario.
    fn committed_snapshot(&self) -> Self::Snapshot;
}

/// Run the complete provider-neutral LocalTx conformance suite.
pub async fn run_localtx_conformance<D, T>(
    driver: &D,
    timer: &T,
    budget: ExecutionBudget,
) -> Result<(), ConformanceError>
where
    D: LocalTxDriver,
    T: ExecutionTimer,
{
    let deadline = suite_deadline(timer, budget)?;
    driver.reset();
    let expected_commit = driver.committed_snapshot();
    within_budget(timer, deadline, "localtx.commit.budget", driver.committed())
        .await?
        .fold(
            |_| Ok(()),
            |_| Err(branch("localtx.commit", "committed", "not-started")),
            |_| Err(branch("localtx.commit", "committed", "rolled-back")),
            |_| Err(branch("localtx.commit", "committed", "rollback-failed")),
            |_| Err(branch("localtx.commit", "committed", "commit-unknown")),
            |_| Err(branch("localtx.commit", "committed", "fenced")),
        )?;
    expect_snapshot(
        "localtx.commit.snapshot",
        expected_commit,
        within_budget(
            timer,
            deadline,
            "localtx.commit.snapshot.budget",
            driver.snapshot(),
        )
        .await?,
    )?;
    expect_count("localtx.commit.writes", 1, driver.writes())?;

    driver.reset();
    let rollback_baseline = within_budget(
        timer,
        deadline,
        "localtx.rollback.baseline.budget",
        driver.snapshot(),
    )
    .await?;
    within_budget(
        timer,
        deadline,
        "localtx.rollback.budget",
        driver.rolled_back(),
    )
    .await?
    .fold(
        |_| Err(branch("localtx.rollback", "rolled-back", "committed")),
        |_| Err(branch("localtx.rollback", "rolled-back", "not-started")),
        |error| {
            expect_class(
                driver,
                &error,
                FailureClass::Transient,
                "localtx.rollback.class",
            )
        },
        |_| Err(branch("localtx.rollback", "rolled-back", "rollback-failed")),
        |_| Err(branch("localtx.rollback", "rolled-back", "commit-unknown")),
        |_| Err(branch("localtx.rollback", "rolled-back", "fenced")),
    )?;
    expect_snapshot(
        "localtx.rollback.snapshot",
        rollback_baseline,
        within_budget(
            timer,
            deadline,
            "localtx.rollback.snapshot.budget",
            driver.snapshot(),
        )
        .await?,
    )?;
    expect_count("localtx.rollback.writes", 0, driver.writes())?;

    driver.reset();
    let rejected_baseline = within_budget(
        timer,
        deadline,
        "localtx.validation.baseline.budget",
        driver.snapshot(),
    )
    .await?;
    within_budget(
        timer,
        deadline,
        "localtx.validation.budget",
        driver.validation_rejected(),
    )
    .await?
    .fold(
        |_| Err(branch("localtx.validation", "not-started", "committed")),
        |error| {
            expect_class(
                driver,
                &error,
                FailureClass::Permanent,
                "localtx.validation.class",
            )
        },
        |_| Err(branch("localtx.validation", "not-started", "rolled-back")),
        |_| {
            Err(branch(
                "localtx.validation",
                "not-started",
                "rollback-failed",
            ))
        },
        |_| {
            Err(branch(
                "localtx.validation",
                "not-started",
                "commit-unknown",
            ))
        },
        |_| Err(branch("localtx.validation", "not-started", "fenced")),
    )?;
    expect_snapshot(
        "localtx.validation.snapshot",
        rejected_baseline,
        within_budget(
            timer,
            deadline,
            "localtx.validation.snapshot.budget",
            driver.snapshot(),
        )
        .await?,
    )?;
    expect_count("localtx.validation.writes", 0, driver.writes())?;

    driver.reset();
    let rejected_baseline = within_budget(
        timer,
        deadline,
        "localtx.authorization.baseline.budget",
        driver.snapshot(),
    )
    .await?;
    within_budget(
        timer,
        deadline,
        "localtx.authorization.budget",
        driver.authorization_rejected(),
    )
    .await?
    .fold(
        |_| Err(branch("localtx.authorization", "not-started", "committed")),
        |error| {
            expect_class(
                driver,
                &error,
                FailureClass::Permanent,
                "localtx.authorization.class",
            )
        },
        |_| {
            Err(branch(
                "localtx.authorization",
                "not-started",
                "rolled-back",
            ))
        },
        |_| {
            Err(branch(
                "localtx.authorization",
                "not-started",
                "rollback-failed",
            ))
        },
        |_| {
            Err(branch(
                "localtx.authorization",
                "not-started",
                "commit-unknown",
            ))
        },
        |_| Err(branch("localtx.authorization", "not-started", "fenced")),
    )?;
    expect_snapshot(
        "localtx.authorization.snapshot",
        rejected_baseline,
        within_budget(
            timer,
            deadline,
            "localtx.authorization.snapshot.budget",
            driver.snapshot(),
        )
        .await?,
    )?;
    expect_count("localtx.authorization.writes", 0, driver.writes())?;

    driver.reset();
    within_budget(
        timer,
        deadline,
        "localtx.commit-unknown.budget",
        driver.commit_unknown(),
    )
    .await?
    .fold(
        |_| {
            Err(branch(
                "localtx.commit-unknown",
                "commit-unknown",
                "committed",
            ))
        },
        |_| {
            Err(branch(
                "localtx.commit-unknown",
                "commit-unknown",
                "not-started",
            ))
        },
        |_| {
            Err(branch(
                "localtx.commit-unknown",
                "commit-unknown",
                "rolled-back",
            ))
        },
        |_| {
            Err(branch(
                "localtx.commit-unknown",
                "commit-unknown",
                "rollback-failed",
            ))
        },
        |_| Ok(()),
        |_| Err(branch("localtx.commit-unknown", "commit-unknown", "fenced")),
    )?;
    expect_count("localtx.commit-unknown.attempts", 1, driver.attempts())?;

    driver.reset();
    within_budget(
        timer,
        deadline,
        "localtx.rollback-failed.budget",
        driver.rollback_failed(),
    )
    .await?
    .fold(
        |_| {
            Err(branch(
                "localtx.rollback-failed",
                "rollback-failed",
                "committed",
            ))
        },
        |_| {
            Err(branch(
                "localtx.rollback-failed",
                "rollback-failed",
                "not-started",
            ))
        },
        |_| {
            Err(branch(
                "localtx.rollback-failed",
                "rollback-failed",
                "rolled-back",
            ))
        },
        |_| Ok(()),
        |_| {
            Err(branch(
                "localtx.rollback-failed",
                "rollback-failed",
                "commit-unknown",
            ))
        },
        |_| {
            Err(branch(
                "localtx.rollback-failed",
                "rollback-failed",
                "fenced",
            ))
        },
    )?;
    expect_count("localtx.rollback-failed.attempts", 1, driver.attempts())
}

fn expect_class<D: LocalTxDriver>(
    driver: &D,
    error: &D::Error,
    expected: FailureClass,
    stage: &'static str,
) -> Result<(), ConformanceError> {
    let actual = driver.classify(error);
    if actual == expected {
        Ok(())
    } else {
        Err(branch(stage, class_label(expected), class_label(actual)))
    }
}

const fn class_label(class: FailureClass) -> &'static str {
    match class {
        FailureClass::Transient => "transient",
        FailureClass::Permanent => "permanent",
        FailureClass::Infrastructure => "infrastructure",
    }
}

const fn branch(
    stage: &'static str,
    expected: &'static str,
    actual: &'static str,
) -> ConformanceError {
    ConformanceError::mismatch(stage, expected, actual)
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

fn expect_snapshot<S: PartialEq>(
    stage: &'static str,
    expected: S,
    actual: S,
) -> Result<(), ConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ConformanceError::mismatch(
            stage,
            "expected-durable-state",
            "different-durable-state",
        ))
    }
}
