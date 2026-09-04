use futures::stream;
use rss_runtime::{ManagedResource, ShutdownError};
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::message::{MessageEnvelope, SubscriptionIdentity};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging::transaction::SettlementDecision;
use rss_transactional_messaging::transport::{
    DeliverySettlement, DeliverySource, IncomingDelivery, ManagedDeliveryStream, PublishFailure,
    PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome, Publisher,
};

pub struct AmqpPublisher(());
pub struct AmqpSubscriber(());
pub struct AmqpSettlement;

fn unavailable() -> MessagingError {
    MessagingError::new(
        MessagingErrorKind::Permanent,
        std::io::Error::other("amqp backend feature is disabled"),
    )
}

impl Publisher<Vec<u8>> for AmqpPublisher {
    type Receipt = ();

    async fn publish(
        &self,
        _message: &MessageEnvelope<Vec<u8>>,
        _deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
            PublishFailureKind::Permanent,
            PublishFailureStage::Admission,
            PublishFailureReason::TransportUnavailable,
        ))
    }
}

impl DeliverySettlement for AmqpSettlement {
    async fn settle(
        self,
        _decision: SettlementDecision,
        _deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        Err(unavailable())
    }

    async fn abandon(self, _deadline: OperationDeadline) -> Result<(), MessagingError> {
        Err(unavailable())
    }
}

impl DeliverySource<Vec<u8>> for AmqpSubscriber {
    type Settlement = AmqpSettlement;
    type Deliveries = stream::Empty<IncomingDelivery<Vec<u8>, Self::Settlement>>;

    async fn deliveries(
        &self,
        _subscription: &SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        Err(unavailable())
    }
}

impl ManagedResource for AmqpPublisher {
    fn name(&self) -> &str {
        "amqp-publisher-disabled"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

impl ManagedResource for AmqpSubscriber {
    fn name(&self) -> &str {
        "amqp-subscriber-disabled"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}
