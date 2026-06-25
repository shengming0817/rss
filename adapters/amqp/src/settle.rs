//! `AckAction → broker 结算模式`的 **feature-agnostic** 映射（不依赖 lapin）。
//!
//! 抽出此层的动机：`AckAction → broker ack/nack(requeue)` 是 at-least-once 正确性的关键映射，但
//! `BasicNackOptions` 是 lapin 类型、仅 `integration` feature 可用——若映射直接绑 lapin，则其测试只能
//! 在 integration build 跑、**不进默认 `cargo xtask verify` gate**（无 docker ⇒ 集成测试不实跑 ⇒ 该映射
//! 零 gate 覆盖）。本模块用 feature-agnostic 的 [`SettleMode`] 中间表示承载映射逻辑 + 表驱动测试（默认
//! build 可测）；`integration` 下的 `AmqpAcker` 再把 [`SettleMode`] 翻成 lapin `basic_ack`/`basic_nack`。
//!
//! ref: rabbitmq docs/confirms（basic.ack / basic.nack(requeue)）

use diport::AckAction;

/// broker 结算模式（feature-agnostic 中间表示）。`AmqpAcker`（integration）据此调 lapin
/// `basic_ack` / `basic_nack(requeue=<bool>)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettleMode {
    /// `basic_ack`（消息成功消费，broker 移除）。
    Ack,
    /// `basic_nack(requeue=<bool>)`：`true`=重入队再投；`false`=不重入队（→broker DLX/丢弃）。
    Nack { requeue: bool },
}

/// `AckAction → SettleMode` 纯映射：`Ack`→`Ack`；`Reject`→`Nack{requeue:false}`（broker DLX）；
/// `Requeue`（及未来 `#[non_exhaustive]` 新变体）→`Nack{requeue:true}`（保守重投，不丢消息）。
pub(crate) fn settle_mode(action: AckAction) -> SettleMode {
    match action {
        AckAction::Ack => SettleMode::Ack,
        AckAction::Reject => SettleMode::Nack { requeue: false },
        // Requeue + 未来新变体：保守 requeue（语义不明时不丢消息，等 eventexec 精化后再细分）。
        _ => SettleMode::Nack { requeue: true },
    }
}

#[cfg(test)]
mod tests {
    //! at-least-once 关键映射表驱动测试——**默认 build 可跑**（不依赖 lapin / integration feature），
    //! 进 `cargo xtask verify` gate。
    use super::{SettleMode, settle_mode};
    use diport::AckAction;

    #[test]
    fn ack_maps_to_ack() {
        assert_eq!(settle_mode(AckAction::Ack), SettleMode::Ack);
    }

    #[test]
    fn requeue_maps_to_nack_requeue_true() {
        assert_eq!(
            settle_mode(AckAction::Requeue),
            SettleMode::Nack { requeue: true }
        );
    }

    #[test]
    fn reject_maps_to_nack_requeue_false() {
        assert_eq!(
            settle_mode(AckAction::Reject),
            SettleMode::Nack { requeue: false }
        );
    }
}
