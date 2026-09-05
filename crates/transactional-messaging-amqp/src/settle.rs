//! Pure mapping from closed settlement decisions to AMQP ACK/NACK options.
//! The real lapin transport is compiled in every build; these unit tests isolate the decision
//! mapping from broker I/O. `test-support` only adds explicit fixture seams.
//!
//! ref: rabbitmq docs/confirms (basic.ack / basic.nack).

use rss_transactional_messaging::transaction::SettlementKind;

/// Broker settlement mode used by the normally compiled lapin transport for
/// `basic_ack` / `basic_nack(requeue=<bool>)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettleMode {
    /// `basic_ack`（消息成功消费，broker 移除）。
    Ack,
    /// `basic_nack(requeue=<bool>)`：`true`=重入队再投；`false`=不重入队（→broker DLX/丢弃）。
    Nack { requeue: bool },
}

/// `SettlementKind → SettleMode` 纯映射：`Ack`→`Ack`；`Reject`→`Nack{requeue:false}`（broker DLX）；
/// `Requeue`→`Nack{requeue:true}`（保守重投，不丢消息）。
pub(crate) fn settle_mode(action: SettlementKind) -> SettleMode {
    match action {
        SettlementKind::Acknowledge => SettleMode::Ack,
        SettlementKind::Reject => SettleMode::Nack { requeue: false },
        SettlementKind::Requeue => SettleMode::Nack { requeue: true },
    }
}

#[cfg(test)]
mod tests {
    //! Table-driven coverage of the closed at-least-once settlement mapping.
    use super::{SettleMode, settle_mode};
    use rss_transactional_messaging::transaction::SettlementKind;

    #[test]
    fn ack_maps_to_ack() {
        assert_eq!(settle_mode(SettlementKind::Acknowledge), SettleMode::Ack);
    }

    #[test]
    fn requeue_maps_to_nack_requeue_true() {
        assert_eq!(
            settle_mode(SettlementKind::Requeue),
            SettleMode::Nack { requeue: true }
        );
    }

    #[test]
    fn reject_maps_to_nack_requeue_false() {
        assert_eq!(
            settle_mode(SettlementKind::Reject),
            SettleMode::Nack { requeue: false }
        );
    }
}
