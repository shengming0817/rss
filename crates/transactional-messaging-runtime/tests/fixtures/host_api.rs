// Compiled as an independent consumer, without workspace feature unification.
use message_core::{
    error::MessagingError, observability::TransactionalMessagingEmitter, policy::ExecutionTimer,
};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "producer")]
mod relay {
    use super::*;
    use algorithms::relay::RelayWorker;
    use message_core::{outbox::OutboxStore, transport::Publisher};

    pub async fn run<P, S, U, C, E>(
        worker: RelayWorker<P, S, U, C, E>,
        stop: CancellationToken,
    ) -> Result<(), MessagingError>
    where
        P: Send + Sync,
        S: OutboxStore<P>,
        S::Claim: Sync,
        U: Publisher<P, Receipt = S::PublishReceipt>,
        C: ExecutionTimer,
        E: TransactionalMessagingEmitter,
    {
        worker.run(stop).await
    }

    #[cfg(feature = "registration-probe")]
    pub fn register<P, S, U, C, E>(
        worker: RelayWorker<P, S, U, C, E>,
        budget: message_core::policy::ShutdownBudget,
    ) where
        P: Send + Sync + 'static,
        S: OutboxStore<P> + 'static,
        S::Claim: Sync,
        U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
        C: ExecutionTimer + 'static,
        E: TransactionalMessagingEmitter + 'static,
    {
        let _ = worker.into_registration("relay", budget);
    }
}

#[cfg(feature = "consumer")]
mod consumer {
    use super::*;
    use algorithms::consumer::ConsumerWorker;
    use message_core::{
        inbox::InboxStore,
        transaction::{ConsumerTx, IngressValidator},
        transport::DeliverySource,
    };

    pub async fn run<P, S, I, T, V, R, E>(
        worker: ConsumerWorker<P, S, I, T, V, R, E>,
        stop: CancellationToken,
    ) -> Result<(), MessagingError>
    where
        P: AsRef<[u8]> + Send + Sync,
        S: DeliverySource<P>,
        I: InboxStore,
        T: ConsumerTx<P, Claim = I::Claim>,
        V: IngressValidator<P>,
        R: ExecutionTimer,
        E: TransactionalMessagingEmitter,
    {
        worker.run(stop).await
    }

    #[cfg(feature = "registration-probe")]
    pub fn register<P, S, I, T, V, R, E>(
        worker: ConsumerWorker<P, S, I, T, V, R, E>,
        budget: message_core::policy::ShutdownBudget,
    ) where
        P: AsRef<[u8]> + Send + Sync + 'static,
        S: DeliverySource<P> + 'static,
        I: InboxStore + 'static,
        T: ConsumerTx<P, Claim = I::Claim> + 'static,
        V: IngressValidator<P> + 'static,
        R: ExecutionTimer + 'static,
        E: TransactionalMessagingEmitter + 'static,
    {
        let _ = worker.into_registration("consumer", budget);
    }
}
