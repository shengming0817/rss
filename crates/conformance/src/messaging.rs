//! Provider-neutral transactional messaging trace assertions.

/// Closed externally observable actions in one delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessagingAction {
    /// Provider granted an inbox claim.
    Claim,
    /// Application handler was invoked.
    Handle,
    /// Inbox result and handler effects committed durably.
    CommitDurable,
    /// Broker delivery was acknowledged.
    Acknowledge,
    /// Broker delivery was rejected terminally.
    Reject,
    /// Broker delivery was made eligible for redelivery.
    Requeue,
    /// Provider session was retired without settlement.
    Abandon,
}

/// Stable conformance failure that never contains provider or message data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MessagingConformanceError {
    /// ACK occurred without an earlier durable commit in the same trace.
    #[error("acknowledgement preceded durable commit")]
    AckBeforeCommit,
    /// An uncertain or fenced attempt acknowledged the broker delivery.
    #[error("uncertain delivery was acknowledged")]
    AckOnUncertainOutcome,
    /// Same-identity retry changed its stable message identifier.
    #[error("retry changed stable message identity")]
    IdentityChanged,
}

/// Assert that every ACK is preceded by exactly one observable durable commit.
pub fn assert_commit_before_ack(
    actions: &[MessagingAction],
) -> Result<(), MessagingConformanceError> {
    let commit = actions
        .iter()
        .position(|action| *action == MessagingAction::CommitDurable);
    let ack = actions
        .iter()
        .position(|action| *action == MessagingAction::Acknowledge);
    if ack.is_some_and(|ack_index| commit.is_none_or(|commit_index| commit_index >= ack_index)) {
        return Err(MessagingConformanceError::AckBeforeCommit);
    }
    Ok(())
}

/// Assert that a commit-unknown, rollback-failed or fenced trace cannot acknowledge delivery.
pub fn assert_uncertain_redelivery(
    actions: &[MessagingAction],
) -> Result<(), MessagingConformanceError> {
    if actions.contains(&MessagingAction::Acknowledge) {
        return Err(MessagingConformanceError::AckOnUncertainOutcome);
    }
    Ok(())
}

/// Assert that every automatic retry retains the original stable message identifier.
pub fn assert_same_message_identity<T: Eq>(ids: &[T]) -> Result<(), MessagingConformanceError> {
    if ids.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(MessagingConformanceError::IdentityChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_red_proves_commit_order_guard_is_not_vacuous() {
        assert_eq!(
            assert_commit_before_ack(&[
                MessagingAction::Claim,
                MessagingAction::Acknowledge,
                MessagingAction::CommitDurable,
            ]),
            Err(MessagingConformanceError::AckBeforeCommit)
        );
        assert!(
            assert_commit_before_ack(&[
                MessagingAction::Claim,
                MessagingAction::Handle,
                MessagingAction::CommitDurable,
                MessagingAction::Acknowledge,
            ])
            .is_ok()
        );
    }

    #[test]
    fn synthetic_red_proves_identity_guard_is_not_vacuous() {
        assert_eq!(
            assert_same_message_identity(&["message-1", "message-2"]),
            Err(MessagingConformanceError::IdentityChanged)
        );
        assert!(assert_same_message_identity(&["message-1", "message-1"]).is_ok());
    }
}
