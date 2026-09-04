//! Thin runtime loop over the canonical transactional messaging ports.

use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::inbox::InboxStore;
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::policy::{RetryTimer, ShutdownBudget};
use rss_transactional_messaging::transaction::{
    ConsumerExecution, ConsumerTx, IngressValidator, process_delivery,
};
use rss_transactional_messaging::transport::{DeliverySource, IncomingDelivery, settle_invalid};

/// Drain one ingress source. Lifecycle, topology, and shutdown remain outside the narrow source
/// port; every delivered settlement authority is consumed exactly once.
pub async fn run_consumer<S, I, T, V, R, E>(
    source: &S,
    inbox: &I,
    transaction: &T,
    execution: &ConsumerExecution<'_, V, R, E>,
    shutdown: &tokio_util::sync::CancellationToken,
    shutdown_budget: ShutdownBudget,
) -> Result<(), MessagingError>
where
    S: DeliverySource<Vec<u8>>,
    I: InboxStore,
    T: ConsumerTx<Vec<u8>, Claim = I::Claim>,
    V: IngressValidator<Vec<u8>>,
    R: RetryTimer,
    E: TransactionalMessagingEmitter,
{
    let mut deliveries = source.deliveries(execution.subscription()).await?;
    loop {
        let delivery = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            delivery = deliveries.next() => match delivery {
                Some(delivery) => delivery,
                None => return Ok(()),
            },
        };
        let handling = async {
            match delivery {
                IncomingDelivery::Valid(delivery) => {
                    process_delivery(inbox, transaction, execution, *delivery).await?;
                }
                IncomingDelivery::Invalid {
                    failure,
                    settlement,
                } => {
                    settle_invalid(
                        failure,
                        settlement,
                        execution.operation_deadline()?,
                        execution.emitter(),
                    )
                    .await?;
                }
            }
            Ok(())
        };
        tokio::pin!(handling);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                return tokio::time::timeout(shutdown_budget.timeout(), handling)
                    .await
                    .map_err(|error| MessagingError::new(MessagingErrorKind::Transient, error))?;
            }
            result = &mut handling => result?,
        }
    }
}
