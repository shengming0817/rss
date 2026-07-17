//! LocalTx boundary vocabulary shared by generated contract evidence and runtime consumers.
//!
//! Declaration-side values are defined once in [`vocab`] and re-exported here for consistency
//! engine consumers. Runtime settlement remains separate from retry classification: a rollback or
//! unknown commit outcome must not be inferred from [`crate::TxRetryFinalStatus`].
//!
//! ref: statig statig/src/outcome.rs@3780eecdbcf4326051c38676d592c6c2b4a3bab5
//!
//! INVARIANT: LOCALTX-FINAL-STATUS-01 { level = "Hard", exec = "native-compile", source = "code", native = "a private macro emits the closed final-status enum, ALL, and exhaustive static labels from one declaration" }
//! INVARIANT: LOCALTX-EXECUTION-BUDGET-01 { level = "Hard", exec = "native-compile", source = "code", native = "private Duration fields plus the only public constructor make zero or non-strict settlement reserve budgets unrepresentable" }

use std::time::Duration;

pub use vocab::{LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel, LocalTxRetry};

/// Validated wall-clock-independent execution budget for one LocalTx invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTxExecutionBudget {
    total: Duration,
    settlement_reserve: Duration,
}

impl LocalTxExecutionBudget {
    /// Production-wide default. Contract-specific configuration is intentionally not supported.
    pub const DEFAULT: Self = Self {
        total: Duration::from_secs(10),
        settlement_reserve: Duration::from_secs(2),
    };

    /// Construct a budget whose settlement reserve is non-zero and strictly below the total.
    pub fn new(
        total: Duration,
        settlement_reserve: Duration,
    ) -> Result<Self, LocalTxExecutionBudgetError> {
        if total.is_zero() {
            return Err(LocalTxExecutionBudgetError::ZeroTotal);
        }
        if settlement_reserve.is_zero() {
            return Err(LocalTxExecutionBudgetError::ZeroSettlementReserve);
        }
        if settlement_reserve >= total {
            return Err(LocalTxExecutionBudgetError::SettlementReserveRange);
        }
        Ok(Self {
            total,
            settlement_reserve,
        })
    }

    /// Complete invocation budget.
    #[must_use]
    pub const fn total(self) -> Duration {
        self.total
    }

    /// Portion available only to commit or rollback settlement.
    #[must_use]
    pub const fn settlement_reserve(self) -> Duration {
        self.settlement_reserve
    }

    /// Budget available to acquire, begin, setup, operation and retry backoff.
    #[must_use]
    pub fn operation(self) -> Duration {
        self.total - self.settlement_reserve
    }
}

impl Default for LocalTxExecutionBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// LocalTx execution budget construction errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LocalTxExecutionBudgetError {
    /// The invocation must have a positive total duration.
    #[error("LocalTx execution budget total must be non-zero")]
    ZeroTotal,
    /// Settlement must retain a positive reserve.
    #[error("LocalTx settlement reserve must be non-zero")]
    ZeroSettlementReserve,
    /// Operation must retain a positive duration before settlement begins.
    #[error("LocalTx settlement reserve must be strictly below the total budget")]
    SettlementReserveRange,
}

macro_rules! closed_label_enum {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $label:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Complete closed value set in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// Stable low-cardinality metrics/log label.
            #[must_use]
            pub const fn as_label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }
        }
    };
}

closed_label_enum! {
    /// Stage whose monotonic LocalTx deadline elapsed.
    pub enum LocalTxDeadlineStage {
        /// Waiting for a pooled connection.
        Acquire => "acquire",
        /// Beginning the database transaction.
        Begin => "begin",
        /// Installing transaction-local tenant and timeout state.
        Setup => "setup",
        /// Executing the mutation body.
        Operation => "operation",
        /// Waiting before another bounded attempt.
        Backoff => "backoff",
        /// Committing the transaction.
        Commit => "commit",
        /// Rolling the transaction back.
        Rollback => "rollback",
    }
}

closed_label_enum! {
    /// Final settlement observed for one LocalTx unit of work.
    pub enum LocalTxFinalStatus {
        /// Commit completed successfully.
        Committed => "committed",
        /// An explicit rollback completed successfully.
        RolledBack => "rolled_back",
        /// An explicit rollback failed; the transaction must not be reported as rolled back.
        RollbackFailed => "rollback_failed",
        /// Commit returned without a known durable outcome and must not be replayed automatically.
        CommitUnknown => "commit_unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        LocalTxDeadlineStage, LocalTxExecutionBudget, LocalTxExecutionBudgetError,
        LocalTxFinalStatus,
    };

    #[test]
    fn execution_budget_accepts_valid_total_and_reserve() -> Result<(), LocalTxExecutionBudgetError>
    {
        let budget = LocalTxExecutionBudget::new(Duration::from_secs(10), Duration::from_secs(2))?;

        assert_eq!(budget.total(), Duration::from_secs(10));
        assert_eq!(budget.settlement_reserve(), Duration::from_secs(2));
        assert_eq!(budget.operation(), Duration::from_secs(8));
        assert_eq!(LocalTxExecutionBudget::DEFAULT, budget);
        Ok(())
    }

    #[test]
    fn execution_budget_rejects_zero_and_non_strict_reserve() {
        let cases = [
            (
                Duration::ZERO,
                Duration::from_secs(1),
                LocalTxExecutionBudgetError::ZeroTotal,
            ),
            (
                Duration::from_secs(1),
                Duration::ZERO,
                LocalTxExecutionBudgetError::ZeroSettlementReserve,
            ),
            (
                Duration::from_secs(1),
                Duration::from_secs(1),
                LocalTxExecutionBudgetError::SettlementReserveRange,
            ),
            (
                Duration::from_secs(1),
                Duration::from_secs(2),
                LocalTxExecutionBudgetError::SettlementReserveRange,
            ),
        ];

        for (total, reserve, expected) in cases {
            assert_eq!(LocalTxExecutionBudget::new(total, reserve), Err(expected));
        }
    }

    #[test]
    fn deadline_stage_labels_are_closed_stable_and_distinct() {
        let labels = LocalTxDeadlineStage::ALL
            .iter()
            .map(|stage| stage.as_label())
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            [
                "acquire",
                "begin",
                "setup",
                "operation",
                "backoff",
                "commit",
                "rollback",
            ]
        );
        for (index, label) in labels.iter().enumerate() {
            assert!(!labels[index + 1..].contains(label));
        }
    }

    #[test]
    fn final_status_labels_are_closed_stable_and_distinct() {
        let labels: Vec<_> = LocalTxFinalStatus::ALL
            .iter()
            .map(|status| status.as_label())
            .collect();
        assert_eq!(
            labels,
            [
                "committed",
                "rolled_back",
                "rollback_failed",
                "commit_unknown"
            ]
        );

        for (index, label) in labels.iter().enumerate() {
            assert!(!labels[(index + 1)..].contains(label));
        }
    }
}
