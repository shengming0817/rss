use rss_request_context::ExecutionTimer;
// Compiled as an independent consumer, without workspace feature unification.
use message_core::{error::MessagingError, observability::TransactionalMessagingEmitter};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "producer")]
mod relay {
    use super::*;
    use algorithms::relay::RelayWorker;
    use message_core::{outbox::OutboxRelayStore, transport::Publisher};

    pub fn relay_config()
    -> Result<algorithms::relay::RelayConfig, algorithms::relay::RelayConfigError> {
        use algorithms::relay::{RelayConfig, RelayWaitPolicy};
        use std::num::NonZeroUsize;
        RelayConfig::new(
            NonZeroUsize::MIN,
            NonZeroUsize::MIN,
            RelayWaitPolicy {
                contention_delay: std::time::Duration::from_millis(12),
                ..RelayWaitPolicy::STANDARD
            },
        )
    }

    pub async fn run<P, S, U, C, E>(
        worker: RelayWorker<P, S, U, C, E>,
        binding: message_core::fence::ExecutionBinding,
        stop: CancellationToken,
    ) -> Result<(), MessagingError>
    where
        P: Send + Sync,
        S: OutboxRelayStore<P>,
        S::Claim: Sync,
        U: Publisher<P, Receipt = S::PublishReceipt>,
        C: ExecutionTimer,
        E: TransactionalMessagingEmitter,
    {
        worker.run(binding, stop).await
    }

    #[cfg(feature = "registration-probe")]
    pub fn register<P, S, U, C, E>(
        worker: RelayWorker<P, S, U, C, E>,
        binding: message_core::fence::ExecutionBinding,
        budget: message_core::policy::ShutdownBudget,
    ) where
        P: Send + Sync + 'static,
        S: OutboxRelayStore<P> + 'static,
        S::Claim: Sync,
        U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
        C: ExecutionTimer + 'static,
        E: TransactionalMessagingEmitter + 'static,
    {
        let _ = worker.into_registration(binding, "relay", budget);
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

    pub fn execution_policy() -> Result<
        message_core::policy::ConsumerExecutionPolicy,
        message_core::policy::RemoteClaimWaitPolicyError,
    > {
        use message_core::policy::{
            ConsumerExecutionPolicy, ExecutionBudget, RemoteClaimWaitPolicy, RetryPolicy,
        };
        use std::time::Duration;
        let wait = RemoteClaimWaitPolicy::new(
            Duration::from_millis(5),
            Duration::from_secs(2),
            Duration::from_millis(50),
        )?;
        Ok(ConsumerExecutionPolicy::new(
            RetryPolicy::STANDARD,
            ExecutionBudget::STANDARD,
            wait,
        ))
    }

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
