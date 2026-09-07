use crate::{ConnectionState, MqttError, PublishRequest, RejectReason, outcome};
use rss_request_context::{Clock, Deadline};
use rss_transactional_messaging::{
    policy::OperationDeadline,
    transport::{
        PublishFailureKind as Kind, PublishFailureReason as Reason, PublishFailureStage as Stage,
        PublishOutcome,
    },
};
use std::{
    collections::VecDeque,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

pub(crate) struct ClockRef(pub Arc<dyn Clock>);
impl Clock for ClockRef {
    fn now(&self) -> std::time::Instant {
        self.0.now()
    }
}
pub(crate) enum Command {
    Publish {
        request: PublishRequest,
        deadline: Deadline,
        response: oneshot::Sender<Result<rumqttc::PublishNotice, PublishOutcome<()>>>,
    },
    Settle {
        generation: u64,
        pkid: u16,
        reason: rumqttc::mqttbytes::v5::PubAckReason,
        deadline: Deadline,
        response: oneshot::Sender<Result<(), MqttError>>,
    },
    Shutdown {
        deadline: Deadline,
        response: oneshot::Sender<Result<(), MqttError>>,
    },
}
pub(crate) struct Shared {
    #[cfg(feature = "consumer")]
    pub subscriptions: Vec<String>,
    pub commands: mpsc::Sender<Command>,
    pub clock: ClockRef,
    pub state: watch::Sender<ConnectionState>,
    pub closing: AtomicBool,
    pub generation: AtomicU64,
    pub retire: AtomicU64,
    pub wake: Notify,
    pub cancelled: CancellationToken,
    pub deliveries: Mutex<VecDeque<Delivery>>,
    pub delivered: Notify,
}
impl Shared {
    pub fn deadline(&self, budget: Duration) -> Result<Deadline, MqttError> {
        Deadline::from_timeout(&self.clock, budget).map_err(|_| MqttError::InvalidConfig)
    }
    pub fn abandon(&self, generation: u64) {
        self.retire.fetch_max(generation, Ordering::AcqRel);
        self.wake.notify_one();
    }
    pub fn clear_deliveries(&self) {
        // Poison is recoverable here: draining never admits or acknowledges a message.
        let values =
            std::mem::take(&mut *self.deliveries.lock().unwrap_or_else(|e| e.into_inner()));
        drop(values);
    }
    pub fn invalidate(&self) -> Result<(), MqttError> {
        self.generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .map_err(|_| MqttError::Closed)?;
        self.clear_deliveries();
        Ok(())
    }
}

/// Cloneable admission capability; it cannot close or expose the underlying MQTT connection.
#[derive(Clone)]
pub struct MqttPublisher {
    pub(crate) shared: Arc<Shared>,
    pub(crate) packet_bytes: u32,
}
impl MqttPublisher {
    /// Submit QoS 1 content and wait for broker evidence within the caller's budget.
    /// Cancellation after submission does not cancel upstream protocol replay.
    pub async fn publish(
        &self,
        request: PublishRequest,
        deadline: OperationDeadline,
    ) -> PublishOutcome<()> {
        if !request.valid_size(self.packet_bytes) {
            return outcome::definite(Kind::Permanent, Stage::Encode, Reason::InvalidMessage);
        }
        let Ok(cutoff) = self.shared.deadline(deadline.timeout()) else {
            return outcome::definite(Kind::Permanent, Stage::Admission, Reason::InvalidMessage);
        };
        if cutoff
            .remaining(self.shared.clock.now())
            .unwrap_or_default()
            .is_zero()
        {
            return outcome::definite(Kind::Transient, Stage::Admission, Reason::DeadlineElapsed);
        }
        if self.shared.closing.load(Ordering::Acquire) {
            return outcome::definite(
                Kind::Transient,
                Stage::Admission,
                Reason::TransportUnavailable,
            );
        }
        let (tx, rx) = oneshot::channel();
        // reserve is cancellation-safe: until the permit is sent there is no provider request.
        let permit = match tokio::time::timeout(
            cutoff
                .remaining(self.shared.clock.now())
                .unwrap_or_default(),
            self.shared.commands.reserve(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return outcome::definite(
                    Kind::Transient,
                    Stage::Admission,
                    Reason::TransportUnavailable,
                );
            }
            Err(_) => {
                return outcome::definite(
                    Kind::Transient,
                    Stage::Admission,
                    Reason::DeadlineElapsed,
                );
            }
        };
        if self.shared.closing.load(Ordering::Acquire) {
            return outcome::definite(
                Kind::Transient,
                Stage::Admission,
                Reason::TransportUnavailable,
            );
        }
        permit.send(Command::Publish {
            request,
            deadline: cutoff,
            response: tx,
        });
        match tokio::time::timeout(
            cutoff
                .remaining(self.shared.clock.now())
                .unwrap_or_default(),
            async {
                match rx.await {
                    Ok(Ok(notice)) => outcome::notice(notice.wait_async().await),
                    Ok(Err(outcome)) => outcome,
                    Err(_) => outcome::ambiguous(Reason::TransportUnavailable),
                }
            },
        )
        .await
        {
            Ok(result)
                if !cutoff
                    .remaining(self.shared.clock.now())
                    .unwrap_or_default()
                    .is_zero() =>
            {
                result
            }
            Ok(_) | Err(_) => outcome::ambiguous(Reason::DeadlineElapsed),
        }
    }
    /// Observe readiness and distinguish resumed and fresh broker sessions.
    pub fn connection_state(&self) -> watch::Receiver<ConnectionState> {
        self.shared.state.subscribe()
    }
    /// Wait for a validated subscription setup. Failure does not silently reset a persistent session.
    pub async fn wait_ready(&self, budget: Duration) -> Result<ConnectionState, MqttError> {
        let mut state = self.connection_state();
        tokio::time::timeout(budget, async {
            loop {
                match *state.borrow_and_update() {
                    ready @ ConnectionState::Ready { .. } => return Ok(ready),
                    ConnectionState::Failed(error) => return Err(error),
                    ConnectionState::Closed => return Err(MqttError::Closed),
                    _ => {}
                }
                state.changed().await.map_err(|_| MqttError::Closed)?;
            }
        })
        .await
        .map_err(|_| MqttError::DeadlineElapsed)?
    }
}

/// One receiver per connection; unprocessed messages never receive an implicit ACK.
pub struct MqttReceiver {
    pub(crate) shared: Arc<Shared>,
}
impl MqttReceiver {
    /// Cancellation-safe long-lived admission wait. Returns the terminal driver error once closed.
    pub async fn next(&mut self) -> Result<Option<Delivery>, MqttError> {
        loop {
            let notified = self.shared.delivered.notified();
            let next = self
                .shared
                .deliveries
                .lock()
                .map_err(|_| MqttError::Closed)?
                .pop_front();
            if let Some(delivery) = next {
                if delivery.settlement.generation == self.shared.generation.load(Ordering::Acquire)
                {
                    return Ok(Some(delivery));
                }
                continue;
            }
            match *self.shared.state.borrow() {
                ConnectionState::Failed(error) => return Err(error),
                ConnectionState::Closed => return Ok(None),
                _ => {}
            }
            notified.await;
        }
    }
}
impl Drop for MqttReceiver {
    fn drop(&mut self) {
        self.shared.closing.store(true, Ordering::Release);
        self.shared.cancelled.cancel();
    }
}

/// Unverified protocol delivery. Only its settlement value grants acknowledgement authority.
pub struct Delivery {
    pub(crate) publish: rumqttc::mqttbytes::v5::Publish,
    pub(crate) settlement: Settlement,
}
impl fmt::Debug for Delivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delivery")
            .field("payload_bytes", &self.publish.payload.len())
            .finish_non_exhaustive()
    }
}
impl Delivery {
    /// Raw broker-supplied topic bytes.
    pub fn topic(&self) -> &[u8] {
        &self.publish.topic
    }
    /// Raw, unverified application payload.
    pub fn payload(&self) -> &[u8] {
        &self.publish.payload
    }
    /// Whether the broker marked this delivery as retained.
    pub const fn retained(&self) -> bool {
        self.publish.retain
    }
    /// Protocol duplicate flag; not a business deduplication decision.
    pub const fn duplicate(&self) -> bool {
        self.publish.dup
    }
    /// MQTT metadata from the broker; no business interpretation is applied.
    pub fn properties(&self) -> Option<&rumqttc::mqttbytes::v5::PublishProperties> {
        self.publish.properties.as_ref()
    }
    /// Separate wire data from its move-only settlement authority.
    pub fn into_parts(self) -> (rumqttc::mqttbytes::v5::Publish, Settlement) {
        (self.publish, self.settlement)
    }
}

/// INVARIANT: MQTT-SETTLEMENT-OWNER-01. Private, move-only authority bound to one connection epoch.
pub struct Settlement {
    pub(crate) shared: Weak<Shared>,
    pub(crate) generation: u64,
    pub(crate) pkid: u16,
    pub(crate) decided: bool,
}
impl Settlement {
    /// Caller attests that durable handoff has completed. Success means local ACK write+flush only.
    pub async fn ack_after_durable_handoff(
        self,
        deadline: OperationDeadline,
    ) -> Result<(), MqttError> {
        self.settle(rumqttc::mqttbytes::v5::PubAckReason::Success, deadline)
            .await
    }
    /// Terminal negative PUBACK; the broker does not requeue a rejected delivery.
    pub async fn reject_terminal(
        self,
        reason: RejectReason,
        deadline: OperationDeadline,
    ) -> Result<(), MqttError> {
        self.settle(reason.wire(), deadline).await
    }
    /// Retire this connection without ACK. Other unsettled deliveries also need redelivery.
    pub fn abandon(self) {
        drop(self);
    }
    async fn settle(
        mut self,
        reason: rumqttc::mqttbytes::v5::PubAckReason,
        budget: OperationDeadline,
    ) -> Result<(), MqttError> {
        let shared = self.shared.upgrade().ok_or(MqttError::Closed)?;
        if shared.generation.load(Ordering::Acquire) != self.generation {
            return Err(MqttError::StaleDelivery);
        }
        if shared.closing.load(Ordering::Acquire) {
            return Err(MqttError::Closed);
        }
        let cutoff = shared.deadline(budget.timeout())?;
        let (tx, rx) = oneshot::channel();
        let result = tokio::time::timeout(
            cutoff.remaining(shared.clock.now()).unwrap_or_default(),
            async {
                shared
                    .commands
                    .send(Command::Settle {
                        generation: self.generation,
                        pkid: self.pkid,
                        reason,
                        deadline: cutoff,
                        response: tx,
                    })
                    .await
                    .map_err(|_| MqttError::Closed)?;
                rx.await.map_err(|_| MqttError::SettlementUnknown)?
            },
        )
        .await
        .map_err(|_| MqttError::SettlementUnknown)?;
        if result.is_ok() || matches!(result, Err(MqttError::StaleDelivery)) {
            self.decided = true;
        }
        result
    }
}
impl Drop for Settlement {
    fn drop(&mut self) {
        if !self.decided
            && let Some(shared) = self.shared.upgrade()
        {
            shared.abandon(self.generation);
        }
    }
}

/// Unique resource owner. Explicit shutdown joins the driver within one total budget.
pub struct MqttResource {
    pub(crate) shared: Arc<Shared>,
    pub(crate) task: Option<tokio::task::JoinHandle<()>>,
}
impl MqttResource {
    /// Stop admission, drain protocol-admitted publications, then close and join.
    pub async fn shutdown(mut self, budget: Duration) -> Result<(), MqttError> {
        let deadline = self.shared.deadline(budget)?;
        self.shared.closing.store(true, Ordering::Release);
        let (tx, rx) = oneshot::channel();
        tokio::time::timeout(budget, async {
            self.shared
                .commands
                .send(Command::Shutdown {
                    deadline,
                    response: tx,
                })
                .await
                .map_err(|_| MqttError::Closed)?;
            let result = rx.await.map_err(|_| MqttError::Closed)?;
            if let Some(task) = self.task.as_mut() {
                task.await.map_err(|_| MqttError::Closed)?;
            }
            self.task.take();
            result
        })
        .await
        .map_err(|_| MqttError::DeadlineElapsed)?
    }
}
impl Drop for MqttResource {
    fn drop(&mut self) {
        self.shared.closing.store(true, Ordering::Release);
        self.shared.cancelled.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
