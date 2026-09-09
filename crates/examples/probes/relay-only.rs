//! A delivery-only provider implements no transaction or append API.
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    outbox::{OutboxClaimBatch, OutboxLeaseStatus, OutboxRelayStore, OutboxSettlement, PendingMessage},
    policy::{DeliveryBudget, OperationDeadline},
};
use std::num::NonZeroUsize;
struct EmptyRelay(DeliveryBudget);
impl OutboxRelayStore<Vec<u8>> for EmptyRelay {
    type Claim = PendingMessage<Vec<u8>>;
    type PublishReceipt = ();
    fn delivery_budget(&self) -> DeliveryBudget { self.0 }
    async fn claim_partition_heads(&self, limit: NonZeroUsize, _: OperationDeadline) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        // reason: this external compile probe models a provider with no queued records.
        OutboxClaimBatch::try_from_provider(Vec::new(), limit)
            .map_err(|error| MessagingError::new(MessagingErrorKind::Invariant,error))
    }
    async fn lease_status(&self, _: &Self::Claim, _: OperationDeadline) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(OutboxLeaseStatus::Lost)
    }
    async fn extend(&self, _: &Self::Claim, _: OperationDeadline) -> Result<OutboxLeaseStatus, MessagingError> {
        Ok(OutboxLeaseStatus::Lost)
    }
    fn message(claim: &Self::Claim) -> &PendingMessage<Vec<u8>> { claim }
    async fn settle(&self, _: Self::Claim, _: OutboxSettlement<()>, _: OperationDeadline) -> Result<(), MessagingError> {
        Err(MessagingError::new(MessagingErrorKind::OwnershipLost, std::io::Error::other("no admitted claim")))
    }
}
fn requires_relay<T: OutboxRelayStore<Vec<u8>>>() {}
fn main() { requires_relay::<EmptyRelay>(); }
