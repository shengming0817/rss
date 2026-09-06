//! Cloneable port and move-only lifecycle owner. Native handles never enter async tasks.
use crate::{
    KafkaConfig, KafkaError, KafkaPublishReceipt,
    engine::{self, Command, Shared, lock, now},
    record::Record,
};
use rss_transactional_messaging::{
    message::MessageEnvelope,
    policy::OperationDeadline,
    transport::{
        PublishFailureKind as Kind, PublishFailureReason as Reason, PublishFailureStage as Stage,
        PublishOutcome, Publisher,
    },
};
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};
use tokio::sync::oneshot;

/// Cloneable publishing capability; retains neither native client nor process control.
#[derive(Clone)]
pub struct KafkaPublisher {
    shared: Arc<Shared>,
    config: Arc<crate::config::PublishPlan>,
}
/// Unique native resource owner. Retain until workers stop, then consume with shutdown.
#[must_use = "dropping the resource stops publication"]
pub struct KafkaPublisherResource {
    shared: Arc<Shared>,
    completion: Option<oneshot::Receiver<Result<(), KafkaError>>>,
}
impl KafkaPublisher {
    /// Initialize the owned native client within a caller-supplied budget; not a readiness probe.
    /// Cancellation during startup requests cleanup even if native initialization has not returned.
    pub async fn create(
        config: KafkaConfig,
        startup_timeout: Duration,
    ) -> Result<(Self, KafkaPublisherResource), KafkaError> {
        let end = now()
            .checked_add(startup_timeout)
            .filter(|_| !startup_timeout.is_zero())
            .ok_or(KafkaError::InvalidLifecycleTimeout)?;
        let (plan, native) = config.into_parts();
        let config = Arc::new(plan);
        let (sender, receiver) = mpsc::sync_channel(config.limits.queued);
        let shared = Arc::new(Shared::new(sender));
        let mut resource = KafkaPublisherResource {
            shared: shared.clone(),
            completion: None,
        };
        let (started, startup) = oneshot::channel();
        let owned_config = config.clone();
        let owned_shared = shared.clone();
        let (completed, completion) = oneshot::channel();
        resource.completion = Some(completion);
        let thread = std::thread::Builder::new()
            .name("rss-kafka-publisher".into())
            .spawn(move || {
                let result = engine::run(native, owned_config, owned_shared, receiver, started);
                let _ = completed.send(result);
            })
            .map_err(|_| KafkaError::ThreadStart)?;
        // Native cleanup reports completion directly; no Tokio blocking worker waits on this thread.
        drop(thread);
        tokio::time::timeout_at(tokio::time::Instant::from_std(end), startup)
            .await
            .map_err(|_| KafkaError::DeadlineElapsed)?
            .map_err(|_| KafkaError::OwnerFailed)??;
        Ok((Self { shared, config }, resource))
    }
    /// Pause polling after one actual native send, for deterministic cancellation/fault proofs.
    #[cfg(feature = "test-support")]
    pub fn pause_next_delivery_for_test(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        *lock(&self.shared.gate) = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }
    /// Pause a dequeued command before native admission, for forced-close race proofs.
    #[cfg(feature = "test-support")]
    pub fn pause_before_send_for_test(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        *lock(&self.shared.pre_send_gate) = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }
    /// Number of native attempts whose result is still owned by this adapter.
    #[cfg(feature = "test-support")]
    pub fn pending_for_test(&self) -> usize {
        self.shared.pending_count()
    }
}
impl Publisher<Vec<u8>> for KafkaPublisher {
    type Receipt = KafkaPublishReceipt;
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        let Some(end) = now().checked_add(deadline.timeout()) else {
            return engine::expired();
        };
        if deadline.timeout().is_zero() {
            return engine::expired();
        }
        let (reply, receiver) = oneshot::channel();
        {
            let state = lock(&self.shared.admission);
            let Some(sender) = &state.sender else {
                return engine::unavailable();
            };
            // Admission and bounded copying share the close lock: no check-then-enqueue race.
            let Some(record) = Record::encode(message, &self.config) else {
                return PublishOutcome::DefinitelyNotPublished(engine::failure(
                    Kind::Permanent,
                    Stage::Encode,
                    Reason::InvalidMessage,
                ));
            };
            if now() >= end {
                return engine::expired();
            }
            if sender
                .try_send(Command {
                    record,
                    deadline: end,
                    reply,
                })
                .is_err()
            {
                return engine::unavailable();
            }
        }
        match tokio::time::timeout_at(tokio::time::Instant::from_std(end), receiver).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => engine::ambiguous(),
            Err(_) => PublishOutcome::Ambiguous(engine::failure(
                Kind::Transient,
                Stage::Confirm,
                Reason::DeadlineElapsed,
            )),
        }
    }
}
impl KafkaPublisherResource {
    /// Seal admission immediately, then wait within one total budget for flush and native teardown.
    /// Timeout or cancellation requests forced retirement; native destruction may continue afterward.
    /// This non-async entry seals admission even when the returned future is never polled.
    pub fn shutdown(
        mut self,
        timeout: Duration,
    ) -> impl Future<Output = Result<(), KafkaError>> + Send {
        let end = now().checked_add(timeout);
        self.shared.close(end.unwrap_or_else(now));
        async move {
            let end = end.ok_or(KafkaError::InvalidLifecycleTimeout)?;
            let completion = self.completion.as_mut().ok_or(KafkaError::OwnerFailed)?;
            tokio::time::timeout_at(tokio::time::Instant::from_std(end), completion)
                .await
                .map_err(|_| KafkaError::DeadlineElapsed)?
                .map_err(|_| KafkaError::OwnerFailed)?
        }
    }
}
impl Drop for KafkaPublisherResource {
    fn drop(&mut self) {
        self.shared.close(now());
    }
}

#[cfg(test)]
impl KafkaPublisher {
    pub(crate) fn for_unit_test(
        shared: Arc<Shared>,
        config: Arc<crate::config::PublishPlan>,
    ) -> Self {
        Self { shared, config }
    }
}
#[cfg(test)]
impl KafkaPublisherResource {
    pub(crate) fn for_unit_test(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            completion: None,
        }
    }
}

#[cfg(test)]
impl KafkaPublisherResource {
    pub(crate) fn with_completion_for_unit_test(
        shared: Arc<Shared>,
        completion: oneshot::Receiver<Result<(), KafkaError>>,
    ) -> Self {
        Self {
            shared,
            completion: Some(completion),
        }
    }
}
