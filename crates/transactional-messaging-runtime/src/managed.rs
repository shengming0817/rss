//! Optional RSS lifecycle integration for the public worker futures.

use rss_runtime::{ManagedTask, ManagedTaskRegistration, ShutdownError, TaskStatus};
use rss_transactional_messaging::policy::ShutdownBudget;

#[cfg(feature = "consumer")]
use crate::consumer::ConsumerWorker;
#[cfg(feature = "producer")]
use crate::relay::RelayWorker;
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::policy::ExecutionTimer;
#[cfg(feature = "consumer")]
use rss_transactional_messaging::{
    inbox::InboxStore,
    transaction::{ConsumerTx, IngressValidator},
    transport::DeliverySource,
};
#[cfg(feature = "producer")]
use rss_transactional_messaging::{outbox::OutboxStore, transport::Publisher};

#[cfg(feature = "producer")]
impl<P, S, U, C, E> RelayWorker<P, S, U, C, E>
where
    P: Send + Sync + 'static,
    S: OutboxStore<P> + 'static,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    /// Transfer the worker into the `rss-runtime` startup token funnel.
    pub fn into_registration(
        self,
        name: impl Into<String>,
        shutdown_budget: ShutdownBudget,
    ) -> (ManagedTaskRegistration, TaskStatus) {
        let (start, status) = ManagedTask::prepare(name, shutdown_budget.timeout());
        let registration = start.into_registration(move |token| async move {
            self.run(token).await.map_err(ShutdownError::new)
        });
        (registration, status)
    }
}

#[cfg(feature = "consumer")]
impl<P, S, I, T, V, R, E> ConsumerWorker<P, S, I, T, V, R, E>
where
    P: AsRef<[u8]> + Send + Sync + 'static,
    S: DeliverySource<P> + 'static,
    I: InboxStore + 'static,
    T: ConsumerTx<P, Claim = I::Claim> + 'static,
    V: IngressValidator<P> + 'static,
    R: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    /// Transfer the worker into the `rss-runtime` startup token funnel.
    pub fn into_registration(
        self,
        name: impl Into<String>,
        shutdown_budget: ShutdownBudget,
    ) -> (ManagedTaskRegistration, TaskStatus) {
        let (start, status) = ManagedTask::prepare(name, shutdown_budget.timeout());
        let registration = start.into_registration(move |token| async move {
            self.run(token).await.map_err(ShutdownError::new)
        });
        (registration, status)
    }
}
