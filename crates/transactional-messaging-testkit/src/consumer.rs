//! Consumer transaction, settlement ordering and uncertainty conformance.

use std::future::Future;

use rss_transactional_messaging::observability::{
    TransactionalMessagingDisposition, TransactionalMessagingIoOutcome,
    TransactionalMessagingObservation, TransactionalMessagingTransactionStatus,
};
use rss_transactional_messaging::policy::{ExecutionBudget, ExecutionTimer};
use rss_transactional_messaging::transaction::{SettlementKind, TerminalDisposition};

use crate::{ConformanceError, suite_deadline, within_budget};

/// Provider-owned consumer scenarios that return only core-owned evidence.
pub trait ConsumerTxDriver: Send + Sync {
    /// Reset the isolated fixture before one scenario.
    fn reset(&self);
    /// Execute one committed delivery and return emitted closed observations.
    fn committed_delivery(
        &self,
    ) -> impl Future<Output = Result<Vec<TransactionalMessagingObservation>, ConformanceError>>;
    /// Redeliver the same identity after its terminal receipt exists.
    fn duplicate_delivery(
        &self,
    ) -> impl Future<
        Output = Result<
            (TerminalDisposition, Vec<TransactionalMessagingObservation>),
            ConformanceError,
        >,
    >;
    /// Execute a delivery whose commit outcome is unknown and return its abandon count.
    fn commit_unknown_delivery(
        &self,
    ) -> impl Future<Output = Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError>>;
    /// Lose lease authority before handler execution and return its abandon count.
    fn lease_lost_delivery(
        &self,
    ) -> impl Future<Output = Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError>>;
}

/// Run commit-before-ACK, duplicate, uncertainty and fencing conformance.
pub async fn run_consumer_conformance<D: ConsumerTxDriver>(
    driver: &D,
    timer: &impl ExecutionTimer,
    budget: ExecutionBudget,
) -> Result<(), ConformanceError> {
    let deadline = suite_deadline(timer, budget)?;

    driver.reset();
    let observations = within_budget(
        timer,
        deadline,
        "consumer.committed.budget",
        driver.committed_delivery(),
    )
    .await?
    .map_err(|error| error.at_stage("consumer.committed.outcome"))?;
    expect_status(
        "consumer.committed.outcome",
        &observations,
        TransactionalMessagingTransactionStatus::Committed,
    )?;
    expect_count(
        "consumer.committed.handlers",
        1,
        transaction_count(&observations),
    )?;
    expect_count(
        "consumer.committed.durable",
        1,
        status_count(
            &observations,
            TransactionalMessagingTransactionStatus::Committed,
        ),
    )?;
    expect_settlements(
        "consumer.committed.settlement",
        &settlements(&observations),
        &[SettlementKind::Acknowledge],
    )?;
    if !commit_precedes_ack(&observations) {
        return Err(ConformanceError::mismatch(
            "consumer.commit-before-ack",
            "commit-before-ack",
            "ack-before-commit",
        ));
    }

    driver.reset();
    let (terminal, observations) = within_budget(
        timer,
        deadline,
        "consumer.duplicate.budget",
        driver.duplicate_delivery(),
    )
    .await?
    .map_err(|error| error.at_stage("consumer.duplicate.outcome"))?;
    if !matches!(terminal, TerminalDisposition::Succeeded) {
        return Err(ConformanceError::mismatch(
            "consumer.duplicate.outcome",
            "succeeded-terminal",
            "rejected-terminal",
        ));
    }
    expect_count(
        "consumer.duplicate.handlers",
        0,
        transaction_count(&observations),
    )?;
    expect_settlements(
        "consumer.duplicate.settlement",
        &settlements(&observations),
        &[SettlementKind::Acknowledge],
    )?;

    driver.reset();
    let (observations, abandons) = within_budget(
        timer,
        deadline,
        "consumer.commit-unknown.budget",
        driver.commit_unknown_delivery(),
    )
    .await?
    .map_err(|error| error.at_stage("consumer.commit-unknown.outcome"))?;
    expect_status(
        "consumer.commit-unknown.outcome",
        &observations,
        TransactionalMessagingTransactionStatus::CommitUnknown,
    )?;
    expect_count(
        "consumer.commit-unknown.handlers",
        1,
        transaction_count(&observations),
    )?;
    expect_settlements(
        "consumer.commit-unknown.settlement",
        &settlements(&observations),
        &[],
    )?;
    expect_count("consumer.commit-unknown.abandon", 1, abandons)?;

    driver.reset();
    let (observations, abandons) = within_budget(
        timer,
        deadline,
        "consumer.lease-lost.budget",
        driver.lease_lost_delivery(),
    )
    .await?
    .map_err(|error| error.at_stage("consumer.lease-lost.outcome"))?;
    if !observations.iter().any(|observation| {
        matches!(
            observation,
            TransactionalMessagingObservation::ConsumerLeaseLost
                | TransactionalMessagingObservation::ConsumerTransaction {
                    status: TransactionalMessagingTransactionStatus::Fenced
                }
        )
    }) {
        return Err(ConformanceError::mismatch(
            "consumer.lease-lost.outcome",
            "fenced",
            "not-fenced",
        ));
    }
    expect_count(
        "consumer.lease-lost.durable",
        0,
        status_count(
            &observations,
            TransactionalMessagingTransactionStatus::Committed,
        ),
    )?;
    expect_settlements(
        "consumer.lease-lost.settlement",
        &settlements(&observations),
        &[],
    )?;
    expect_count("consumer.lease-lost.abandon", 1, abandons)
}

fn transaction_count(observations: &[TransactionalMessagingObservation]) -> usize {
    observations
        .iter()
        .filter(|observation| {
            matches!(
                observation,
                TransactionalMessagingObservation::ConsumerTransaction { .. }
            )
        })
        .count()
}

fn status_count(
    observations: &[TransactionalMessagingObservation],
    expected: TransactionalMessagingTransactionStatus,
) -> usize {
    observations
        .iter()
        .filter(|observation| matches!(observation, TransactionalMessagingObservation::ConsumerTransaction { status } if *status == expected))
        .count()
}

fn expect_status(
    stage: &'static str,
    observations: &[TransactionalMessagingObservation],
    expected: TransactionalMessagingTransactionStatus,
) -> Result<(), ConformanceError> {
    if status_count(observations, expected) == 1 {
        Ok(())
    } else {
        Err(ConformanceError::mismatch(
            stage,
            status_label(expected),
            "missing-or-duplicate-status",
        ))
    }
}

fn settlements(observations: &[TransactionalMessagingObservation]) -> Vec<SettlementKind> {
    observations
        .iter()
        .filter_map(|observation| match observation {
            TransactionalMessagingObservation::ConsumerSettlement { action, .. } => {
                Some(match action {
                    TransactionalMessagingDisposition::Ack => SettlementKind::Acknowledge,
                    TransactionalMessagingDisposition::Requeue => SettlementKind::Requeue,
                    TransactionalMessagingDisposition::Reject => SettlementKind::Reject,
                })
            }
            _ => None,
        })
        .collect()
}

fn commit_precedes_ack(observations: &[TransactionalMessagingObservation]) -> bool {
    let commit = observations.iter().position(|observation| {
        matches!(
            observation,
            TransactionalMessagingObservation::ConsumerTransaction {
                status: TransactionalMessagingTransactionStatus::Committed
            }
        )
    });
    let ack = observations.iter().position(|observation| {
        matches!(
            observation,
            TransactionalMessagingObservation::ConsumerSettlement {
                action: TransactionalMessagingDisposition::Ack,
                outcome: TransactionalMessagingIoOutcome::Ok,
            }
        )
    });
    matches!((commit, ack), (Some(commit), Some(ack)) if commit < ack)
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

fn expect_settlements(
    stage: &'static str,
    actual: &[SettlementKind],
    expected: &[SettlementKind],
) -> Result<(), ConformanceError> {
    if actual.len() != expected.len() {
        return Err(ConformanceError::count(stage, expected.len(), actual.len()));
    }
    match actual
        .iter()
        .zip(expected)
        .find(|(actual, expected)| actual != expected)
    {
        Some((actual, expected)) => Err(ConformanceError::mismatch(
            stage,
            settlement_label(*expected),
            settlement_label(*actual),
        )),
        None => Ok(()),
    }
}

const fn status_label(status: TransactionalMessagingTransactionStatus) -> &'static str {
    match status {
        TransactionalMessagingTransactionStatus::Committed => "committed",
        TransactionalMessagingTransactionStatus::HandlerTransient => "handler-transient",
        TransactionalMessagingTransactionStatus::RejectedPermanent => "rejected-permanent",
        TransactionalMessagingTransactionStatus::InfrastructureTransient => {
            "infrastructure-transient"
        }
        TransactionalMessagingTransactionStatus::RollbackFailed => "rollback-failed",
        TransactionalMessagingTransactionStatus::CommitUnknown => "commit-unknown",
        TransactionalMessagingTransactionStatus::Fenced => "fenced",
    }
}

const fn settlement_label(kind: SettlementKind) -> &'static str {
    match kind {
        SettlementKind::Acknowledge => "acknowledge",
        SettlementKind::Requeue => "requeue",
        SettlementKind::Reject => "reject",
    }
}
