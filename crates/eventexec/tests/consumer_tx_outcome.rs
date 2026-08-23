use eventexec::consumer_tx::{ConsumerTxOutcome, RejectKind};

#[test]
fn consumer_tx_outcome_labels_are_closed_and_low_cardinality() {
    let outcomes = [
        ConsumerTxOutcome::Committed(()),
        ConsumerTxOutcome::<()>::HandlerTransient,
        ConsumerTxOutcome::<()>::InfrastructureTransient,
        ConsumerTxOutcome::<()>::Rejected(RejectKind::Permanent),
        ConsumerTxOutcome::<()>::Rejected(RejectKind::Invariant),
        ConsumerTxOutcome::<()>::CommitUnknown,
        ConsumerTxOutcome::<()>::RollbackFailed,
        ConsumerTxOutcome::<()>::Fenced,
    ];

    assert_eq!(
        outcomes.map(|outcome| outcome.as_label()),
        [
            "committed",
            "handler_transient",
            "infrastructure_transient",
            "rejected_permanent",
            "rejected_invariant",
            "commit_unknown",
            "rollback_failed",
            "fenced",
        ]
    );
    assert_eq!(RejectKind::Permanent.as_label(), "permanent");
    assert_eq!(RejectKind::Invariant.as_label(), "invariant");
}
