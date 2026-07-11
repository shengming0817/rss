//! LocalTx boundary vocabulary shared by generated contract evidence and runtime consumers.
//!
//! Declaration-side values are defined once in [`vocab`] and re-exported here for consistency
//! engine consumers. Runtime settlement remains separate from retry classification: a rollback or
//! unknown commit outcome must not be inferred from [`crate::TxRetryFinalStatus`].
//!
//! ref: statig statig/src/outcome.rs@3780eecdbcf4326051c38676d592c6c2b4a3bab5
//!
//! INVARIANT: LOCALTX-FINAL-STATUS-01 { level = "Hard", exec = "native-compile", source = "code", native = "a private macro emits the closed final-status enum, ALL, and exhaustive static labels from one declaration" }

pub use vocab::{LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel, LocalTxRetry};

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
    use super::LocalTxFinalStatus;

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
