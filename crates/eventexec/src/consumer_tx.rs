//! Provider-neutral outcome of one durable consumer transaction attempt.
//!
//! The concrete transaction runner, settlement carrier, provider error, journal, projection, and
//! broker implementation remain internal. Production handlers carry a provider-owned commit proof
//! in [`ConsumerTxOutcome::Committed`]; the outcome itself does not mint Ack authority.
//!
//! INVARIANT: EVENTING-CONSUMER-TX-SEAM-01 { level = "Hard", exec = "native-compile", source = "code", native = "production provider and sealed composition handler share this closed outcome type; committed authority remains the provider-owned generic proof" }

/// Closed reason for rejecting a delivery through the terminal dead-letter path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectKind {
    /// The delivery cannot be decoded or handled permanently.
    Permanent,
    /// The delivery contradicts a trusted envelope or transaction invariant.
    Invariant,
}

impl RejectKind {
    /// Stable low-cardinality observability label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Permanent => "permanent",
            Self::Invariant => "invariant",
        }
    }
}

/// Result of one transactional Fresh-delivery attempt.
///
/// `C` is descriptive commit evidence supplied by the selected provider. The production Ack path
/// binds it to an opaque provider proof through a sealed handler; constructing an unrelated
/// `ConsumerTxOutcome<()>` does not authorize settlement.
#[must_use = "consumer transaction outcomes must be settled explicitly"]
pub enum ConsumerTxOutcome<C> {
    /// The transaction received a commit acknowledgement and carries provider-owned evidence.
    Committed(C),
    /// The handler failed without committing and may be retried within the existing local budget.
    HandlerTransient,
    /// Infrastructure failed without a confirmed commit; broker redelivery is required.
    InfrastructureTransient,
    /// The delivery is terminal and must use the existing dead-letter transaction path.
    Rejected(RejectKind),
    /// Commit may have succeeded; replaying the handler is unsafe.
    CommitUnknown,
    /// Rollback did not receive an acknowledgement; replaying the handler is unsafe.
    RollbackFailed,
    /// The claimed inbox lease is no longer authoritative.
    Fenced,
}

impl<C> ConsumerTxOutcome<C> {
    /// Stable low-cardinality observability label.
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::Committed(_) => "committed",
            Self::HandlerTransient => "handler_transient",
            Self::InfrastructureTransient => "infrastructure_transient",
            Self::Rejected(RejectKind::Permanent) => "rejected_permanent",
            Self::Rejected(RejectKind::Invariant) => "rejected_invariant",
            Self::CommitUnknown => "commit_unknown",
            Self::RollbackFailed => "rollback_failed",
            Self::Fenced => "fenced",
        }
    }
}
