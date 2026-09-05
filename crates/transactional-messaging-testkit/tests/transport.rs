#![cfg(all(feature = "consumer", feature = "producer"))]
//! The public transport oracle must reject broken provider evidence, including silent loss.
use rss_transactional_messaging::{
    error::MessagingErrorKind, message::MessageId, policy::ExecutionBudget,
};
use rss_transactional_messaging_testkit::{
    ConformanceError,
    memory::FakeClock,
    transport::{
        CancellationEvidence, DeliveryEvidence, DeliveryTransportDriver,
        run_delivery_transport_conformance,
    },
};

#[derive(Clone, Copy, PartialEq)]
enum Defect {
    AckRedelivers,
    RequeueLost,
    RejectRedelivers,
    AbandonLost,
    FailureLost,
    IdentityChanges,
    CancelRedeliversDrained,
}
struct Driver(Option<Defect>);
fn id(s: &str) -> Result<MessageId, ConformanceError> {
    MessageId::parse(s).map_err(|_| ConformanceError::fixture(MessagingErrorKind::Invariant))
}
impl Driver {
    fn evidence(
        &self,
        redelivers: bool,
        defect: Defect,
    ) -> Result<DeliveryEvidence, ConformanceError> {
        let redelivers = redelivers ^ (self.0 == Some(defect));
        Ok(DeliveryEvidence {
            message_id: id("original")?,
            redelivered_ids: if redelivers {
                vec![id(if self.0 == Some(Defect::IdentityChanges) {
                    "different"
                } else {
                    "original"
                })?]
            } else {
                vec![]
            },
        })
    }
}
impl DeliveryTransportDriver for Driver {
    async fn acknowledged(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.evidence(false, Defect::AckRedelivers)
    }
    async fn requeued(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.evidence(true, Defect::RequeueLost)
    }
    async fn rejected(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.evidence(false, Defect::RejectRedelivers)
    }
    async fn abandoned(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.evidence(true, Defect::AbandonLost)
    }
    async fn settlement_failed(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.evidence(true, Defect::FailureLost)
    }
    async fn cancelled(&self) -> Result<CancellationEvidence, ConformanceError> {
        Ok(CancellationEvidence {
            drained_id: id("drained")?,
            pending_id: id("pending")?,
            replacement_ids: vec![id(if self.0 == Some(Defect::CancelRedeliversDrained) {
                "drained"
            } else {
                "pending"
            })?],
        })
    }
}
#[tokio::test]
async fn transport_oracle_accepts_conforming_delivery() -> Result<(), ConformanceError> {
    run_delivery_transport_conformance(&Driver(None), &FakeClock::new(), ExecutionBudget::STANDARD)
        .await
}
#[tokio::test]
async fn transport_oracle_rejects_loss_duplicates_and_wrong_identity() {
    for (defect, stage) in [
        (Defect::AckRedelivers, "delivery.ack"),
        (Defect::RequeueLost, "delivery.requeue"),
        (Defect::RejectRedelivers, "delivery.reject"),
        (Defect::AbandonLost, "delivery.abandon"),
        (Defect::FailureLost, "delivery.failure"),
        (Defect::IdentityChanges, "delivery.requeue"),
        (Defect::CancelRedeliversDrained, "delivery.cancel"),
    ] {
        let result = run_delivery_transport_conformance(
            &Driver(Some(defect)),
            &FakeClock::new(),
            ExecutionBudget::STANDARD,
        )
        .await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.stage(), stage);
        }
    }
}

struct FailingDelivery(&'static str);
impl DeliveryTransportDriver for FailingDelivery {
    async fn acknowledged(&self) -> Result<DeliveryEvidence, ConformanceError> {
        if self.0 == "delivery.ack" {
            return Err(ConformanceError::settlement(MessagingErrorKind::Transient));
        }
        Driver(None).acknowledged().await
    }
    async fn requeued(&self) -> Result<DeliveryEvidence, ConformanceError> {
        if self.0 == "delivery.requeue" {
            return Err(ConformanceError::settlement(MessagingErrorKind::Transient));
        }
        Driver(None).requeued().await
    }
    async fn rejected(&self) -> Result<DeliveryEvidence, ConformanceError> {
        if self.0 == "delivery.reject" {
            return Err(ConformanceError::settlement(MessagingErrorKind::Transient));
        }
        Driver(None).rejected().await
    }
    async fn abandoned(&self) -> Result<DeliveryEvidence, ConformanceError> {
        if self.0 == "delivery.abandon" {
            return Err(ConformanceError::settlement(MessagingErrorKind::Transient));
        }
        Driver(None).abandoned().await
    }
    async fn settlement_failed(&self) -> Result<DeliveryEvidence, ConformanceError> {
        if self.0 == "delivery.failure" {
            return Err(ConformanceError::settlement(MessagingErrorKind::Transient));
        }
        Driver(None).settlement_failed().await
    }
    async fn cancelled(&self) -> Result<CancellationEvidence, ConformanceError> {
        if self.0 == "delivery.cancel" {
            return Err(ConformanceError::settlement(MessagingErrorKind::Transient));
        }
        Driver(None).cancelled().await
    }
}
#[tokio::test]
#[allow(clippy::expect_used)]
// reason: fixture provider failures must remain visible at their exact scenario boundary.
async fn provider_failures_identify_the_delivery_scenario() {
    for stage in [
        "delivery.ack",
        "delivery.requeue",
        "delivery.reject",
        "delivery.abandon",
        "delivery.failure",
        "delivery.cancel",
    ] {
        let result = run_delivery_transport_conformance(
            &FailingDelivery(stage),
            &FakeClock::new(),
            ExecutionBudget::STANDARD,
        )
        .await;
        let error = result.expect_err("provider failure must propagate");
        assert_eq!(error.stage(), stage);
        assert_eq!(error.provider_phase_label(), Some("settlement"));
    }
}
