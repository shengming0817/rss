use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::Duration;

use diport::{BrokerAcceptanceMint, BrokerAccepted, ManagedResource, MessageId, ShutdownError};
use identity::ports::device_certificate::{DeviceIngressContract, DeviceIngressDelivery};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{
    ConnectReturnCode, Filter, Packet, PubAck, PubAckReason, Publish, PublishProperties,
    SubscribeReasonCode,
};
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions, Request};
use rumqttc::{Outgoing, TlsConfiguration, Transport};
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{PreparedSessionConfig, prepare_tls};
use crate::{
    BrokerPublishFrame, CredentialRevision, DeviceScope, ExactMqttTopic, MqttTlsMaterial,
    MqttTopicPolicy, MqttUplinkContract,
};

const REQUEST_CAPACITY: usize = 64;
const DELIVERY_CAPACITY: usize = 32;
const RECEIVE_MAXIMUM: u16 = 32;
const _: () = assert!(RECEIVE_MAXIMUM as usize == DELIVERY_CAPACITY);
const MAX_PACKET_SIZE: u32 = 1024 * 1024;
const MAX_PAYLOAD_SIZE: usize = 512 * 1024;
const KEEP_ALIVE: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);
const RELOAD_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(15);
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const DISCONNECT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const RECONNECT_MIN: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerRejectReason {
    NotAuthorized,
    TopicNameInvalid,
}

impl BrokerRejectReason {
    const fn puback_reason(self) -> PubAckReason {
        match self {
            Self::NotAuthorized => PubAckReason::NotAuthorized,
            Self::TopicNameInvalid => PubAckReason::TopicNameInvalid,
        }
    }
}

/// Adapter-private, move-only proof that a broker publish was rejected before authentication.
struct RejectedBrokerPublish {
    publish: Publish,
    reason: BrokerRejectReason,
}

impl RejectedBrokerPublish {
    fn new(publish: Publish, reason: BrokerRejectReason, label: &'static str) -> Self {
        tracing::warn!(target: "mqtt", reason = label, "mqtt uplink rejected");
        Self { publish, reason }
    }

    fn into_negative_puback(self) -> Result<(u16, Request), MqttSessionError> {
        if self.publish.qos != QoS::AtLeastOnce || self.publish.pkid == 0 {
            tracing::error!(
                target: "mqtt",
                reason = "negative_puback_protocol_state",
                "mqtt rejected publish cannot be terminally acknowledged"
            );
            return Err(MqttSessionError::DriverFailed);
        }
        let packet_id = self.publish.pkid;
        Ok((
            packet_id,
            Request::PubAck(PubAck {
                pkid: packet_id,
                reason: self.reason.puback_reason(),
                properties: None,
            }),
        ))
    }
}

struct PendingNegativeAcks {
    packet_ids: HashSet<u16>,
}

struct DriverState {
    unassigned: VecDeque<oneshot::Sender<Result<(), MqttSessionError>>>,
    downlink_acks: HashMap<u16, oneshot::Sender<Result<(), MqttSessionError>>>,
    negative_acks: PendingNegativeAcks,
}

impl DriverState {
    fn new(negative_acks: PendingNegativeAcks) -> Self {
        Self {
            unassigned: VecDeque::new(),
            downlink_acks: HashMap::new(),
            negative_acks,
        }
    }

    fn fail_downlinks(&mut self) {
        fail_pending(&mut self.unassigned, &mut self.downlink_acks);
    }
}

struct DriverContext<'a> {
    deliveries: &'a DeliveryQueue,
    readiness: &'a watch::Sender<MqttReadiness>,
    cancel: &'a CancellationToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriverEventDisposition {
    Continue,
    RecoverTransport,
    StopNegativeAckUnknown,
}

enum ConnectionAttempt {
    Connected { session_present: bool },
    Recoverable(MqttSessionError),
    NegativeAckOutcomeUnknown,
}

fn classify_connection_attempt(
    result: Result<bool, MqttSessionError>,
    negative_acks: &PendingNegativeAcks,
) -> ConnectionAttempt {
    match result {
        Ok(session_present) => ConnectionAttempt::Connected { session_present },
        Err(_) if !negative_acks.is_empty() => ConnectionAttempt::NegativeAckOutcomeUnknown,
        Err(error) => ConnectionAttempt::Recoverable(error),
    }
}

const fn driver_event_disposition(
    event_failed: bool,
    negative_ack_pending: bool,
) -> DriverEventDisposition {
    match (event_failed, negative_ack_pending) {
        (false, _) => DriverEventDisposition::Continue,
        (true, false) => DriverEventDisposition::RecoverTransport,
        (true, true) => DriverEventDisposition::StopNegativeAckUnknown,
    }
}

impl PendingNegativeAcks {
    fn new() -> Self {
        Self {
            packet_ids: HashSet::with_capacity(usize::from(RECEIVE_MAXIMUM)),
        }
    }

    fn is_empty(&self) -> bool {
        self.packet_ids.is_empty()
    }

    fn insert(&mut self, packet_id: u16) -> Result<(), MqttSessionError> {
        if packet_id == 0
            || self.packet_ids.len() >= usize::from(RECEIVE_MAXIMUM)
            || !self.packet_ids.insert(packet_id)
        {
            tracing::error!(
                target: "mqtt",
                reason = "negative_puback_tracker",
                "mqtt negative puback tracker rejected state"
            );
            return Err(MqttSessionError::DriverFailed);
        }
        Ok(())
    }

    fn observe(&mut self, packet_id: u16) -> bool {
        self.packet_ids.remove(&packet_id)
    }

    fn enqueue(
        &mut self,
        eventloop: &mut EventLoop,
        rejected: RejectedBrokerPublish,
    ) -> Result<(), MqttSessionError> {
        let (packet_id, request) = rejected.into_negative_puback()?;
        self.insert(packet_id)?;
        eventloop.pending.push_front(request);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttReadiness {
    Starting,
    Ready {
        session_present: bool,
        credential_revision: u64,
    },
    Reloading {
        from_revision: u64,
        to_revision: u64,
    },
    Degraded {
        credential_revision: u64,
    },
    Stopped,
}

/// Adapter-private generation for one connect/reconnect/reload transport candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TransportEpoch(u64);

impl TransportEpoch {
    const fn get(self) -> u64 {
        self.0
    }
}

/// Shared fence: epoch bump / invalidation and settlement are mutually exclusive.
struct TransportEpochFence {
    epoch: AtomicU64,
    /// Private short critical-section barrier (no await while held).
    settle: StdMutex<()>,
}

impl TransportEpochFence {
    fn new(initial: u64) -> Self {
        Self {
            epoch: AtomicU64::new(initial),
            settle: StdMutex::new(()),
        }
    }

    fn current(&self) -> TransportEpoch {
        TransportEpoch(self.epoch.load(Ordering::Acquire))
    }

    fn lock_barrier(&self) -> Result<StdMutexGuard<'_, ()>, MqttSessionError> {
        self.settle.lock().map_err(|_| {
            tracing::error!(
                target: "mqtt",
                reason = "transport_epoch_fence_poisoned",
                "mqtt transport epoch fence poisoned"
            );
            MqttSessionError::DriverFailed
        })
    }

    fn bump_locked(&self) -> Result<TransportEpoch, MqttSessionError> {
        self.epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .and_then(|previous| previous.checked_add(1).map(TransportEpoch))
            .ok_or_else(|| {
                tracing::error!(
                    target: "mqtt",
                    reason = "transport_epoch_exhausted",
                    "mqtt transport epoch exhausted"
                );
                MqttSessionError::TransportEpochExhausted
            })
    }

    /// Mint a new current transport epoch. Serialized with settlement.
    #[cfg(test)]
    fn begin(&self) -> Result<TransportEpoch, MqttSessionError> {
        let _barrier = self.lock_barrier()?;
        self.bump_locked()
    }

    /// Invalidation funnel: checked epoch bump then synchronous queue clear.
    fn begin_and_clear(&self, queue: &DeliveryQueue) -> Result<TransportEpoch, MqttSessionError> {
        let _barrier = self.lock_barrier()?;
        let epoch = self.bump_locked()?;
        queue.clear()?;
        Ok(epoch)
    }

    /// Linearized settlement: current-epoch check + try_ack + error class under the barrier.
    fn settle(&self, capability: AckCapability) -> Result<(), MqttSessionError> {
        let AckCapability {
            client,
            publish,
            epoch,
            fence: _,
        } = capability;
        let _barrier = self.lock_barrier()?;
        if self.epoch.load(Ordering::Acquire) != epoch.get() {
            tracing::warn!(
                target: "mqtt",
                reason = "stale_transport_epoch",
                "mqtt ack rejected"
            );
            return Err(MqttSessionError::StaleTransportEpoch);
        }
        client.try_ack(&publish).map_err(|_| {
            let _ = client.try_disconnect();
            tracing::warn!(target: "mqtt", reason = "puback_enqueue", "mqtt ack failed");
            MqttSessionError::AckUnavailable
        })
    }

    #[cfg(test)]
    fn with_settle_barrier_for_test<R>(
        &self,
        body: impl FnOnce() -> R,
    ) -> Result<R, MqttSessionError> {
        let _barrier = self.lock_barrier()?;
        Ok(body())
    }
}

fn transport_epoch_is_current(fence: &TransportEpochFence, epoch: TransportEpoch) -> bool {
    fence.current().get() == epoch.get()
}

fn delivery_has_current_transport_epoch(
    delivery: &AuthenticatedDeviceDelivery,
    fence: &TransportEpochFence,
) -> bool {
    delivery
        .ack
        .as_ref()
        .is_some_and(|ack| transport_epoch_is_current(fence, ack.epoch))
}

/// Adapter-private bounded uplink queue: std short lock + Notify; never held across await.
struct DeliveryQueueState {
    items: VecDeque<AuthenticatedDeviceDelivery>,
    closed: bool,
}

struct DeliveryQueue {
    state: StdMutex<DeliveryQueueState>,
    notify: Notify,
}

impl DeliveryQueue {
    fn new() -> Self {
        Self {
            state: StdMutex::new(DeliveryQueueState {
                items: VecDeque::with_capacity(DELIVERY_CAPACITY),
                closed: false,
            }),
            notify: Notify::new(),
        }
    }

    fn lock_state(&self) -> Result<StdMutexGuard<'_, DeliveryQueueState>, MqttSessionError> {
        self.state.lock().map_err(|_| {
            tracing::error!(
                target: "mqtt",
                reason = "delivery_queue_poisoned",
                "mqtt delivery queue poisoned"
            );
            MqttSessionError::DriverFailed
        })
    }

    fn try_push(&self, delivery: AuthenticatedDeviceDelivery) -> Result<(), MqttSessionError> {
        let mut guard = self.lock_state()?;
        if guard.closed {
            return Err(MqttSessionError::DeliveryClosed);
        }
        if guard.items.len() >= DELIVERY_CAPACITY {
            return Err(MqttSessionError::DeliverySaturated);
        }
        guard.items.push_back(delivery);
        drop(guard);
        self.notify.notify_one();
        Ok(())
    }

    fn clear(&self) -> Result<(), MqttSessionError> {
        let mut guard = self.lock_state()?;
        guard.items.clear();
        Ok(())
    }

    fn close(&self) {
        match self.state.lock() {
            Ok(mut guard) => {
                guard.closed = true;
                guard.items.clear();
            }
            Err(poisoned) => {
                tracing::error!(
                    target: "mqtt",
                    reason = "delivery_queue_poisoned",
                    "mqtt delivery queue poisoned on close"
                );
                let mut guard = poisoned.into_inner();
                guard.closed = true;
                guard.items.clear();
            }
        }
        self.notify.notify_waiters();
    }

    #[cfg(any(test, feature = "test-support"))]
    fn is_saturated(&self) -> bool {
        match self.state.lock() {
            Ok(guard) => !guard.closed && guard.items.len() >= DELIVERY_CAPACITY,
            Err(_) => true,
        }
    }

    #[cfg(test)]
    fn len_for_test(&self) -> usize {
        self.state
            .lock()
            .map(|guard| guard.items.len())
            .unwrap_or(0)
    }

    async fn pop_current(
        &self,
        fence: &TransportEpochFence,
    ) -> Result<AuthenticatedDeviceDelivery, MqttSessionError> {
        loop {
            let notified = self.notify.notified();
            {
                let mut guard = self.lock_state()?;
                while let Some(delivery) = guard.items.pop_front() {
                    if delivery_has_current_transport_epoch(&delivery, fence) {
                        return Ok(delivery);
                    }
                    tracing::warn!(
                        target: "mqtt",
                        reason = "stale_transport_epoch",
                        "mqtt uplink skipped"
                    );
                }
                if guard.closed {
                    return Err(MqttSessionError::DeliveryClosed);
                }
            }
            notified.await;
        }
    }
}

/// RAII: every driver exit path (including early connect failure) closes the delivery queue.
struct DeliveryQueueCloseGuard(Arc<DeliveryQueue>);

impl Drop for DeliveryQueueCloseGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

struct AckCapability {
    client: AsyncClient,
    publish: Publish,
    epoch: TransportEpoch,
    fence: Arc<TransportEpochFence>,
}

/// An uplink whose peer certificate, topic coordinates and payload were bound by the broker.
pub struct AuthenticatedDeviceDelivery {
    scope: DeviceScope,
    contract: MqttUplinkContract,
    topic: ExactMqttTopic,
    payload: Vec<u8>,
    correlation: Option<Vec<u8>>,
    ack: Option<AckCapability>,
}

impl std::fmt::Debug for AuthenticatedDeviceDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedDeviceDelivery")
            .field("scope", &"<verified>")
            .field("contract", &self.contract)
            .field("topic", &self.topic)
            .field("payload", &"<redacted>")
            .field("correlation", &"<redacted>")
            .finish()
    }
}

impl AuthenticatedDeviceDelivery {
    pub fn scope(&self) -> &DeviceScope {
        &self.scope
    }

    pub fn contract(&self) -> MqttUplinkContract {
        self.contract
    }

    pub fn topic(&self) -> &ExactMqttTopic {
        &self.topic
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn correlation_data(&self) -> Option<&[u8]> {
        self.correlation.as_deref()
    }

    /// Enqueue the terminal PUBACK without waiting on a bounded client channel.
    ///
    /// This narrow bridge is public only because Rust has no friend visibility across the MQTT
    /// adapter and identity composition crates. Repository policy permits one shipped callsite:
    /// the closed durable-or-poison terminal bridge in `identity-composition`.
    #[doc(hidden)]
    pub fn settle_terminal(mut self) -> Result<(), MqttSessionError> {
        let capability = self.ack.take().ok_or(MqttSessionError::AckUnavailable)?;
        let fence = Arc::clone(&capability.fence);
        fence.settle(capability)
    }
}

impl DeviceIngressDelivery for AuthenticatedDeviceDelivery {
    fn tenant(&self) -> vocab::TenantId {
        self.scope.tenant()
    }

    fn device(&self) -> ids::DeviceId {
        self.scope.device()
    }

    fn credential_generation(&self) -> u64 {
        self.scope.generation().get()
    }

    fn contract(&self) -> DeviceIngressContract {
        match self.contract {
            MqttUplinkContract::CommandAcked => DeviceIngressContract::CommandAcked,
            MqttUplinkContract::CertificateReported => DeviceIngressContract::CertificateReported,
        }
    }

    fn correlation_data(&self) -> Option<&[u8]> {
        self.correlation.as_deref()
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub struct MqttSession {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for MqttSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MqttSession(<managed>)")
    }
}

struct Shared {
    commands: mpsc::Sender<DriverCommand>,
    deliveries: Arc<DeliveryQueue>,
    readiness: watch::Receiver<MqttReadiness>,
    cancel: CancellationToken,
    join: Mutex<Option<JoinHandle<()>>>,
    client_id: String,
    credential_revision: AtomicU64,
    reload_lock: Mutex<()>,
    epoch_fence: Arc<TransportEpochFence>,
}

impl MqttSession {
    pub async fn connect(config: crate::MqttSessionConfig) -> Result<Self, MqttSessionError> {
        let prepared = config.into_prepared();
        let client_id = prepared.client_id.clone();
        let revision = prepared.credential_revision.get();
        let (command_tx, command_rx) = mpsc::channel(REQUEST_CAPACITY);
        let deliveries = Arc::new(DeliveryQueue::new());
        let (readiness_tx, readiness_rx) = watch::channel(MqttReadiness::Starting);
        let (initial_tx, initial_rx) = oneshot::channel();
        let cancel = CancellationToken::new();
        let driver_cancel = cancel.clone();
        let epoch_fence = Arc::new(TransportEpochFence::new(0));
        let join = tokio::spawn(run_driver(
            prepared,
            Arc::clone(&epoch_fence),
            command_rx,
            Arc::clone(&deliveries),
            readiness_tx,
            driver_cancel,
            initial_tx,
        ));
        let shared = Arc::new(Shared {
            commands: command_tx,
            deliveries,
            readiness: readiness_rx,
            cancel,
            join: Mutex::new(Some(join)),
            client_id,
            credential_revision: AtomicU64::new(revision),
            reload_lock: Mutex::new(()),
            epoch_fence,
        });
        initial_rx
            .await
            .map_err(|_| MqttSessionError::DriverFailed)??;
        Ok(Self { shared })
    }

    pub fn readiness(&self) -> MqttReadiness {
        *self.shared.readiness.borrow()
    }

    pub fn readiness_changes(&self) -> watch::Receiver<MqttReadiness> {
        self.shared.readiness.clone()
    }

    /// Publish a command to the session-configured credential scope for this device.
    ///
    /// Callers cannot supply a credential generation. The authenticated session policy is the
    /// sole routing authority, independently of the desired certificate generation in payload.
    pub async fn send_command(
        &self,
        tenant: vocab::TenantId,
        device: ids::DeviceId,
        message_id: &MessageId,
        payload: Vec<u8>,
    ) -> Result<BrokerAccepted, MqttSessionError> {
        self.send_downlink(
            DownlinkContract::Command,
            tenant,
            device,
            message_id,
            payload,
        )
        .await
    }

    /// Publish a durable application receipt through the session's exact receipt downlink.
    ///
    /// Success proves only that the broker accepted the QoS 1 publication. It does not represent
    /// device acknowledgement or another application commit. As with commands, the session's
    /// configured scope is the sole credential-generation authority.
    pub async fn send_application_receipt(
        &self,
        tenant: vocab::TenantId,
        device: ids::DeviceId,
        message_id: &MessageId,
        payload: Vec<u8>,
    ) -> Result<BrokerAccepted, MqttSessionError> {
        self.send_downlink(
            DownlinkContract::ApplicationReceipt,
            tenant,
            device,
            message_id,
            payload,
        )
        .await
    }

    async fn send_downlink(
        &self,
        contract: DownlinkContract,
        tenant: vocab::TenantId,
        device: ids::DeviceId,
        message_id: &MessageId,
        payload: Vec<u8>,
    ) -> Result<BrokerAccepted, MqttSessionError> {
        if !matches!(self.readiness(), MqttReadiness::Ready { .. }) {
            return Err(MqttSessionError::NotReady);
        }
        if message_id.as_str().is_empty()
            || message_id.as_str().len() > usize::from(u16::MAX)
            || payload.len() > MAX_PAYLOAD_SIZE
        {
            return Err(MqttSessionError::PublishInvalid);
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.shared
            .commands
            .send(DriverCommand::Publish(DownlinkPublish {
                contract,
                tenant,
                device,
                message_id: message_id.as_str().to_owned(),
                payload,
                response: response_tx,
            }))
            .await
            .map_err(|_| MqttSessionError::SessionStopped)?;
        tokio::time::timeout(ACK_TIMEOUT, response_rx)
            .await
            .map_err(|_| {
                tracing::warn!(target: "mqtt", reason = "publish_ack_timeout", "mqtt publish timed out");
                MqttSessionError::BrokerTimeout
            })?
            .map_err(|_| MqttSessionError::DriverFailed)??;
        Ok(BrokerAccepted::from_provider(
            BrokerAcceptanceMint::mqtt_session_boundary(),
        ))
    }

    pub async fn next_uplink(&self) -> Result<AuthenticatedDeviceDelivery, MqttSessionError> {
        self.shared
            .deliveries
            .pop_current(&self.shared.epoch_fence)
            .await
    }

    /// Test-only: whether the adapter-private uplink queue is at capacity.
    ///
    /// Enabled only with the `test-support` feature. Does not expose counts, capacity, or the queue.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn uplink_queue_is_saturated_for_test(&self) -> bool {
        self.shared.deliveries.is_saturated()
    }

    pub async fn reload_credentials(
        &self,
        material: MqttTlsMaterial,
        revision: CredentialRevision,
    ) -> Result<(), MqttSessionError> {
        let _single_flight = self.shared.reload_lock.lock().await;
        let current = self.shared.credential_revision.load(Ordering::Acquire);
        accept_reload_revision(current, revision)?;
        let tls = prepare_tls(material, &self.shared.client_id).map_err(|error| {
            tracing::warn!(
                target: "mqtt",
                reason = "reload_tls_material",
                config_error = %error,
                "mqtt reload rejected"
            );
            MqttSessionError::TlsMaterialInvalid
        })?;
        let (response_tx, response_rx) = oneshot::channel();
        self.shared
            .commands
            .send(DriverCommand::Reload {
                tls,
                revision,
                response: response_tx,
            })
            .await
            .map_err(|_| MqttSessionError::SessionStopped)?;
        tokio::time::timeout(RELOAD_TIMEOUT, response_rx)
            .await
            .map_err(|_| {
                tracing::warn!(target: "mqtt", reason = "reload_timeout", "mqtt reload timed out");
                MqttSessionError::BrokerTimeout
            })?
            .map_err(|_| MqttSessionError::DriverFailed)??;
        self.shared
            .credential_revision
            .store(revision.get(), Ordering::Release);
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), MqttSessionError> {
        self.shutdown_inner().await;
        Ok(())
    }

    async fn shutdown_inner(&self) {
        self.shared.cancel.cancel();
        let join = self.shared.join.lock().await.take();
        if let Some(join) = join {
            let _ = join.await;
        }
    }
}

impl Drop for MqttSession {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
    }
}

impl ManagedResource for MqttSession {
    fn name(&self) -> &str {
        "mqtt-session"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.shutdown_inner().await;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum DownlinkContract {
    Command,
    ApplicationReceipt,
}

struct DownlinkPublish {
    contract: DownlinkContract,
    tenant: vocab::TenantId,
    device: ids::DeviceId,
    message_id: String,
    payload: Vec<u8>,
    response: oneshot::Sender<Result<(), MqttSessionError>>,
}

enum DriverCommand {
    Publish(DownlinkPublish),
    Reload {
        tls: Arc<rustls::ClientConfig>,
        revision: CredentialRevision,
        response: oneshot::Sender<Result<(), MqttSessionError>>,
    },
}

struct DriverRuntime {
    endpoint: crate::MqttsEndpoint,
    client_id: String,
    tls: Arc<rustls::ClientConfig>,
    verifier: crate::BrokerAssertionVerifier,
    policy: MqttTopicPolicy,
    session_expiry: crate::SessionExpiry,
    credential_revision: CredentialRevision,
    epoch_fence: Arc<TransportEpochFence>,
    #[cfg(feature = "test-support")]
    negative_ack_poll_barrier: Option<crate::NegativeAckPollBarrier>,
}

impl DriverRuntime {
    fn from_prepared(config: PreparedSessionConfig, epoch_fence: Arc<TransportEpochFence>) -> Self {
        Self {
            endpoint: config.endpoint,
            client_id: config.client_id,
            tls: config.tls,
            verifier: config.verifier,
            policy: config.policy,
            session_expiry: config.session_expiry,
            credential_revision: config.credential_revision,
            epoch_fence,
            #[cfg(feature = "test-support")]
            negative_ack_poll_barrier: config.negative_ack_poll_barrier,
        }
    }
}

async fn run_driver(
    prepared: PreparedSessionConfig,
    epoch_fence: Arc<TransportEpochFence>,
    commands: mpsc::Receiver<DriverCommand>,
    deliveries: Arc<DeliveryQueue>,
    readiness: watch::Sender<MqttReadiness>,
    cancel: CancellationToken,
    initial: oneshot::Sender<Result<(), MqttSessionError>>,
) {
    let _close_guard = DeliveryQueueCloseGuard(Arc::clone(&deliveries));
    let mut runtime = DriverRuntime::from_prepared(prepared, epoch_fence);
    let (mut client, mut eventloop) = new_connection(&runtime);
    let mut negative_acks = PendingNegativeAcks::new();
    let initial_attempt = match runtime.epoch_fence.begin_and_clear(&deliveries) {
        Ok(_) => {
            connect_once(
                &client,
                &mut eventloop,
                &runtime,
                &deliveries,
                &mut negative_acks,
            )
            .await
        }
        Err(error) => ConnectionAttempt::Recoverable(error),
    };
    let initial_result = match initial_attempt {
        ConnectionAttempt::Connected { session_present } => Ok(session_present),
        ConnectionAttempt::Recoverable(error) => Err(error),
        ConnectionAttempt::NegativeAckOutcomeUnknown => {
            stop_negative_ack_unknown(
                &runtime.epoch_fence,
                runtime.credential_revision,
                &deliveries,
                &readiness,
            );
            let _ = initial.send(Err(MqttSessionError::DriverFailed));
            return;
        }
    };
    if !announce_initial_connection(initial_result, &runtime, &readiness, initial) {
        return;
    }
    drive_session_loop(
        &mut runtime,
        &mut client,
        &mut eventloop,
        commands,
        DriverContext {
            deliveries: &deliveries,
            readiness: &readiness,
            cancel: &cancel,
        },
        DriverState::new(negative_acks),
    )
    .await;
}

fn announce_initial_connection(
    initial_result: Result<bool, MqttSessionError>,
    runtime: &DriverRuntime,
    readiness: &watch::Sender<MqttReadiness>,
    initial: oneshot::Sender<Result<(), MqttSessionError>>,
) -> bool {
    let (state, result) =
        readiness_from_connect_result(initial_result, runtime.credential_revision);
    log_initial_readiness(state);
    let _ = readiness.send(state);
    let ok = result.is_ok();
    let _ = initial.send(result);
    ok
}

fn log_session_ready(session_present: bool, credential_revision: u64) {
    tracing::info!(
        target: "mqtt",
        session_present,
        credential_revision,
        "mqtt session ready"
    );
}

fn log_session_degraded(credential_revision: u64) {
    tracing::warn!(
        target: "mqtt",
        credential_revision,
        "mqtt session degraded"
    );
}

fn log_initial_readiness(state: MqttReadiness) {
    match state {
        MqttReadiness::Ready {
            session_present,
            credential_revision,
        } => log_session_ready(session_present, credential_revision),
        MqttReadiness::Degraded {
            credential_revision,
        } => log_session_degraded(credential_revision),
        MqttReadiness::Starting | MqttReadiness::Reloading { .. } | MqttReadiness::Stopped => {}
    }
}

/// Map the first ConnAck/subscribe outcome onto a closed readiness state.
pub(crate) fn readiness_from_connect_result(
    result: Result<bool, MqttSessionError>,
    revision: CredentialRevision,
) -> (MqttReadiness, Result<(), MqttSessionError>) {
    match result {
        Ok(session_present) => (
            MqttReadiness::Ready {
                session_present,
                credential_revision: revision.get(),
            },
            Ok(()),
        ),
        Err(error) => (
            MqttReadiness::Degraded {
                credential_revision: revision.get(),
            },
            Err(error),
        ),
    }
}

async fn drive_session_loop(
    runtime: &mut DriverRuntime,
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    mut commands: mpsc::Receiver<DriverCommand>,
    context: DriverContext<'_>,
    mut state: DriverState,
) {
    loop {
        if !state.negative_acks.is_empty() {
            if !drive_pending_negative_ack(client, eventloop, runtime, &context, &mut state).await {
                return;
            }
            continue;
        }
        tokio::select! {
            biased;
            () = context.cancel.cancelled() => {
                state.fail_downlinks();
                graceful_disconnect(client, eventloop).await;
                let _ = context.readiness.send(MqttReadiness::Stopped);
                return;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    graceful_disconnect(client, eventloop).await;
                    let _ = context.readiness.send(MqttReadiness::Stopped);
                    return;
                };
                if !handle_driver_command(
                    command,
                    client,
                    eventloop,
                    runtime,
                    &context,
                    &mut state,
                ).await {
                    return;
                }
            }
            polled = eventloop.poll() => {
                if handle_polled_event(
                    polled,
                    client,
                    eventloop,
                    runtime,
                    &context,
                    &mut state,
                ).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn drive_pending_negative_ack(
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    context: &DriverContext<'_>,
    state: &mut DriverState,
) -> bool {
    #[cfg(feature = "test-support")]
    if let Some(barrier) = &runtime.negative_ack_poll_barrier {
        barrier.wait_before_poll().await;
    }
    tokio::select! {
        biased;
        () = context.cancel.cancelled() => {
            state.fail_downlinks();
            graceful_disconnect(client, eventloop).await;
            let _ = context.readiness.send(MqttReadiness::Stopped);
            false
        }
        polled = eventloop.poll() => {
            handle_polled_event(polled, client, eventloop, runtime, context, state)
                .await
                .is_ok()
        }
    }
}

async fn handle_polled_event(
    polled: Result<Event, rumqttc::v5::ConnectionError>,
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    context: &DriverContext<'_>,
    state: &mut DriverState,
) -> Result<(), ()> {
    let needs_recover = match polled {
        Ok(event) => handle_event(event, client, eventloop, runtime, context.deliveries, state)
            .await
            .is_err(),
        Err(_) => true,
    };
    match driver_event_disposition(needs_recover, !state.negative_acks.is_empty()) {
        DriverEventDisposition::Continue => return Ok(()),
        DriverEventDisposition::StopNegativeAckUnknown => {
            state.fail_downlinks();
            stop_negative_ack_unknown(
                &runtime.epoch_fence,
                runtime.credential_revision,
                context.deliveries,
                context.readiness,
            );
            return Err(());
        }
        DriverEventDisposition::RecoverTransport => {}
    }
    // Invalidate: bump epoch + sync clear before any async disconnect or reconnect backoff.
    if runtime
        .epoch_fence
        .begin_and_clear(context.deliveries)
        .is_err()
    {
        let _ = context.readiness.send(MqttReadiness::Stopped);
        return Err(());
    }
    set_degraded(context.readiness, runtime.credential_revision);
    state.fail_downlinks();
    let _ = client.disconnect().await;
    if reconnect(
        client,
        eventloop,
        runtime,
        context.deliveries,
        context.readiness,
        context.cancel,
        &mut state.negative_acks,
    )
    .await
    .is_err()
    {
        if state.negative_acks.is_empty() {
            let _ = context.readiness.send(MqttReadiness::Stopped);
        } else {
            stop_negative_ack_unknown(
                &runtime.epoch_fence,
                runtime.credential_revision,
                context.deliveries,
                context.readiness,
            );
        }
        return Err(());
    }
    Ok(())
}

async fn handle_driver_command(
    command: DriverCommand,
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &mut DriverRuntime,
    context: &DriverContext<'_>,
    state: &mut DriverState,
) -> bool {
    match command {
        DriverCommand::Publish(publish) => {
            enqueue_publish(client, &runtime.policy, publish, &mut state.unassigned).await;
            true
        }
        DriverCommand::Reload {
            tls,
            revision,
            response,
        } => {
            state.fail_downlinks();
            let result = reload(
                client,
                eventloop,
                runtime,
                tls,
                revision,
                context,
                &mut state.negative_acks,
            )
            .await;
            let _ = response.send(result);
            if state.negative_acks.is_empty() {
                true
            } else {
                state.fail_downlinks();
                stop_negative_ack_unknown(
                    &runtime.epoch_fence,
                    runtime.credential_revision,
                    context.deliveries,
                    context.readiness,
                );
                false
            }
        }
    }
}

fn new_connection(runtime: &DriverRuntime) -> (AsyncClient, EventLoop) {
    let mut options = MqttOptions::new(
        runtime.client_id.clone(),
        runtime.endpoint.host(),
        runtime.endpoint.port(),
    );
    options
        .set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
            Arc::clone(&runtime.tls),
        )))
        .set_keep_alive(KEEP_ALIVE)
        .set_clean_start(false)
        .set_session_expiry_interval(Some(runtime.session_expiry.as_secs()))
        .set_receive_maximum(Some(RECEIVE_MAXIMUM))
        .set_max_packet_size(Some(MAX_PACKET_SIZE))
        .set_manual_acks(true);
    AsyncClient::new(options, REQUEST_CAPACITY)
}

async fn connect_once(
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &DeliveryQueue,
    negative_acks: &mut PendingNegativeAcks,
) -> ConnectionAttempt {
    let result = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_and_restore(client, eventloop, runtime, deliveries, negative_acks),
    )
    .await
    .map_err(|_| {
        tracing::warn!(target: "mqtt", reason = "connect_timeout", "mqtt connect timed out");
        MqttSessionError::BrokerTimeout
    })
    .and_then(|result| result);
    classify_connection_attempt(result, negative_acks)
}

async fn connect_and_restore(
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &DeliveryQueue,
    negative_acks: &mut PendingNegativeAcks,
) -> Result<bool, MqttSessionError> {
    let session_present = wait_connack_session_present(eventloop).await?;
    if session_present_skips_subscribe(session_present) {
        return Ok(true);
    }
    restore_uplink_subscriptions(client, eventloop, runtime, deliveries, negative_acks).await?;
    Ok(false)
}

async fn wait_connack_session_present(eventloop: &mut EventLoop) -> Result<bool, MqttSessionError> {
    loop {
        match eventloop.poll().await.map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "connect_transport", "mqtt connect failed");
            MqttSessionError::BrokerRejected
        })? {
            Event::Incoming(Packet::ConnAck(ack)) if ack.code == ConnectReturnCode::Success => {
                return Ok(ack.session_present);
            }
            Event::Incoming(Packet::ConnAck(_)) => {
                tracing::warn!(target: "mqtt", reason = "connack_rejected", "mqtt connect rejected");
                return Err(MqttSessionError::BrokerRejected);
            }
            _ => {}
        }
    }
}

async fn restore_uplink_subscriptions(
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &DeliveryQueue,
    negative_acks: &mut PendingNegativeAcks,
) -> Result<(), MqttSessionError> {
    let filters: Vec<_> = runtime
        .policy
        .uplink_topics()
        .into_iter()
        .map(|topic| Filter::new(topic.as_str(), QoS::AtLeastOnce))
        .collect();
    let expected = filters.len();
    client.subscribe_many(filters).await.map_err(|_| {
        tracing::warn!(target: "mqtt", reason = "subscribe_enqueue", "mqtt subscribe failed");
        MqttSessionError::BrokerRejected
    })?;
    let mut subscriptions_granted = false;
    loop {
        match eventloop.poll().await.map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "subscribe_transport", "mqtt subscribe failed");
            MqttSessionError::BrokerRejected
        })? {
            Event::Incoming(Packet::SubAck(ack)) => {
                if !suback_grants_exact_uplinks(&ack.return_codes, expected) {
                    tracing::warn!(target: "mqtt", reason = "suback_rejected", "mqtt subscribe rejected");
                    return Err(MqttSessionError::BrokerRejected);
                }
                subscriptions_granted = true;
                if negative_acks.is_empty() {
                    return Ok(());
                }
            }
            Event::Incoming(Packet::Publish(publish)) => {
                admit_uplink_or_keep_transport(
                    client,
                    eventloop,
                    runtime,
                    deliveries,
                    negative_acks,
                    publish,
                )
                .await?;
            }
            Event::Outgoing(Outgoing::PubAck(packet_id)) => {
                let _ = negative_acks.observe(packet_id);
                if subscriptions_granted && negative_acks.is_empty() {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
}

async fn enqueue_publish(
    client: &AsyncClient,
    policy: &MqttTopicPolicy,
    publish: DownlinkPublish,
    unassigned: &mut VecDeque<oneshot::Sender<Result<(), MqttSessionError>>>,
) {
    let DownlinkPublish {
        contract,
        tenant,
        device,
        message_id,
        payload,
        response,
    } = publish;
    let Some(scope) = policy.scope(tenant, device) else {
        let _ = response.send(Err(MqttSessionError::PublishInvalid));
        return;
    };
    let topic = match contract {
        DownlinkContract::Command => policy.command_topic(scope),
        DownlinkContract::ApplicationReceipt => policy.application_receipt_topic(scope),
    };
    let Some(topic) = topic else {
        let _ = response.send(Err(MqttSessionError::PublishInvalid));
        return;
    };
    let properties = PublishProperties {
        correlation_data: Some(message_id.into_bytes().into()),
        ..PublishProperties::default()
    };
    if client
        .publish_with_properties(topic.as_str(), QoS::AtLeastOnce, false, payload, properties)
        .await
        .is_err()
    {
        let _ = response.send(Err(MqttSessionError::BrokerRejected));
        return;
    }
    unassigned.push_back(response);
}

async fn handle_event(
    event: Event,
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &DeliveryQueue,
    state: &mut DriverState,
) -> Result<(), MqttSessionError> {
    match event {
        Event::Outgoing(Outgoing::PubAck(packet_id)) => {
            let _ = state.negative_acks.observe(packet_id);
        }
        Event::Outgoing(Outgoing::Publish(packet_id)) => {
            let response = state
                .unassigned
                .pop_front()
                .ok_or(MqttSessionError::DriverFailed)?;
            if state.downlink_acks.insert(packet_id, response).is_some() {
                return Err(MqttSessionError::DriverFailed);
            }
        }
        Event::Incoming(Packet::PubAck(ack)) => {
            let response = state
                .downlink_acks
                .remove(&ack.pkid)
                .ok_or(MqttSessionError::DriverFailed)?;
            let accepted = matches!(
                ack.reason,
                PubAckReason::Success | PubAckReason::NoMatchingSubscribers
            );
            let _ = response.send(if accepted {
                Ok(())
            } else {
                Err(MqttSessionError::BrokerRejected)
            });
        }
        Event::Incoming(Packet::Publish(publish)) => {
            admit_uplink_or_keep_transport(
                client,
                eventloop,
                runtime,
                deliveries,
                &mut state.negative_acks,
                publish,
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

enum UplinkDisposition {
    Continue,
    Reject(Box<RejectedBrokerPublish>),
    Fail(MqttSessionError),
}

async fn admit_uplink_or_keep_transport(
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &DeliveryQueue,
    negative_acks: &mut PendingNegativeAcks,
    publish: Publish,
) -> Result<(), MqttSessionError> {
    match deliver_publish(client, runtime, deliveries, publish).await {
        UplinkDisposition::Continue => Ok(()),
        UplinkDisposition::Reject(rejected) => negative_acks.enqueue(eventloop, *rejected),
        UplinkDisposition::Fail(error) => Err(error),
    }
}

async fn deliver_publish(
    client: &AsyncClient,
    runtime: &DriverRuntime,
    deliveries: &DeliveryQueue,
    publish: Publish,
) -> UplinkDisposition {
    if publish.qos == QoS::AtMostOnce {
        tracing::warn!(
            target: "mqtt",
            reason = "uplink_qos0_no_terminal_ack",
            "mqtt qos0 uplink rejected without changing transport"
        );
        return UplinkDisposition::Continue;
    }
    let topic = match std::str::from_utf8(publish.topic.as_ref()) {
        Ok(topic) => topic,
        Err(_) => {
            return UplinkDisposition::Reject(Box::new(RejectedBrokerPublish::new(
                publish,
                BrokerRejectReason::TopicNameInvalid,
                "uplink_topic_utf8",
            )));
        }
    };
    let properties = publish.properties.as_ref();
    let user_properties = properties
        .map(|properties| properties.user_properties.as_slice())
        .unwrap_or_default();
    let correlation = properties.and_then(|properties| properties.correlation_data.as_deref());
    let qos = match publish.qos {
        QoS::AtMostOnce => 0,
        QoS::AtLeastOnce => 1,
        QoS::ExactlyOnce => 2,
    };
    let frame = BrokerPublishFrame::new(
        topic,
        publish.payload.as_ref(),
        correlation,
        qos,
        publish.retain,
        user_properties,
    );
    let verified = match runtime.verifier.verify(&runtime.policy, &frame) {
        Ok(verified) => verified,
        Err(_) => {
            return UplinkDisposition::Reject(Box::new(RejectedBrokerPublish::new(
                publish,
                BrokerRejectReason::NotAuthorized,
                "assertion_rejected",
            )));
        }
    };
    let (_, contract) = match runtime.policy.resolve_uplink(topic) {
        Some(resolved) => resolved,
        None => {
            return UplinkDisposition::Reject(Box::new(RejectedBrokerPublish::new(
                publish,
                BrokerRejectReason::TopicNameInvalid,
                "uplink_policy",
            )));
        }
    };
    let exact_topic = match runtime.policy.exact_verified_topic(topic) {
        Some(exact) => exact,
        None => {
            return UplinkDisposition::Reject(Box::new(RejectedBrokerPublish::new(
                publish,
                BrokerRejectReason::TopicNameInvalid,
                "uplink_topic",
            )));
        }
    };
    let delivery = AuthenticatedDeviceDelivery {
        scope: verified.into_scope(),
        contract,
        topic: exact_topic,
        payload: publish.payload.to_vec(),
        correlation: correlation.map(<[u8]>::to_vec),
        ack: Some(AckCapability {
            client: client.clone(),
            publish,
            epoch: runtime.epoch_fence.current(),
            fence: Arc::clone(&runtime.epoch_fence),
        }),
    };
    match admit_delivery(deliveries, delivery, contract) {
        Ok(()) | Err(MqttSessionError::DeliverySaturated) => UplinkDisposition::Continue,
        Err(error) => UplinkDisposition::Fail(error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttUplinkAdmissionFailureReason {
    QueueFull,
}

impl MqttUplinkAdmissionFailureReason {
    const fn as_label(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
        }
    }
}

fn admit_delivery(
    deliveries: &DeliveryQueue,
    delivery: AuthenticatedDeviceDelivery,
    contract: MqttUplinkContract,
) -> Result<(), MqttSessionError> {
    match deliveries.try_push(delivery) {
        Ok(()) => Ok(()),
        Err(MqttSessionError::DeliverySaturated) => {
            let reason = MqttUplinkAdmissionFailureReason::QueueFull;
            metrics::counter!(
                "mqtt_uplink_admission_failures_total",
                "reason" => reason.as_label(),
                "contract" => contract.as_label(),
            )
            .increment(1);
            tracing::warn!(
                target: "mqtt",
                reason = reason.as_label(),
                contract = contract.as_label(),
                "mqtt uplink admission rejected"
            );
            Err(MqttSessionError::DeliverySaturated)
        }
        Err(error) => Err(error),
    }
}

async fn reconnect(
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &DeliveryQueue,
    readiness: &watch::Sender<MqttReadiness>,
    cancel: &CancellationToken,
    negative_acks: &mut PendingNegativeAcks,
) -> Result<(), MqttSessionError> {
    // Caller already minted the candidate epoch before disconnect/backoff. Rebuild the local
    // request queue after a transport failure.
    let mut backoff = RECONNECT_MIN;
    loop {
        let (candidate_client, mut candidate_eventloop) = new_connection(runtime);
        match connect_once(
            &candidate_client,
            &mut candidate_eventloop,
            runtime,
            deliveries,
            negative_acks,
        )
        .await
        {
            ConnectionAttempt::Connected { session_present } => {
                *client = candidate_client;
                *eventloop = candidate_eventloop;
                set_ready(readiness, session_present, runtime.credential_revision);
                return Ok(());
            }
            ConnectionAttempt::NegativeAckOutcomeUnknown => {
                return Err(MqttSessionError::DriverFailed);
            }
            ConnectionAttempt::Recoverable(_) => {}
        }
        // Failed candidate: bump + clear before the next await/backoff.
        runtime.epoch_fence.begin_and_clear(deliveries)?;
        tokio::select! {
            () = cancel.cancelled() => return Err(MqttSessionError::SessionStopped),
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(RECONNECT_MAX);
    }
}

async fn reload(
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &mut DriverRuntime,
    candidate_tls: Arc<rustls::ClientConfig>,
    candidate_revision: CredentialRevision,
    context: &DriverContext<'_>,
    negative_acks: &mut PendingNegativeAcks,
) -> Result<(), MqttSessionError> {
    let previous_tls = Arc::clone(&runtime.tls);
    let previous_revision = runtime.credential_revision;
    let _ = context.readiness.send(MqttReadiness::Reloading {
        from_revision: previous_revision.get(),
        to_revision: candidate_revision.get(),
    });
    // Invalidate live generation (bump + clear) before any disconnect drain await.
    runtime.epoch_fence.begin_and_clear(context.deliveries)?;
    graceful_disconnect(client, eventloop).await;

    runtime.tls = candidate_tls;
    runtime.credential_revision = candidate_revision;
    let (candidate_client, mut candidate_eventloop) = new_connection(runtime);
    let candidate = tokio::time::timeout(
        RELOAD_CANDIDATE_TIMEOUT,
        connect_and_restore(
            &candidate_client,
            &mut candidate_eventloop,
            runtime,
            context.deliveries,
            negative_acks,
        ),
    )
    .await;
    let candidate_attempt = match candidate {
        Ok(result) => classify_connection_attempt(result, negative_acks),
        Err(_) => classify_connection_attempt(Err(MqttSessionError::BrokerTimeout), negative_acks),
    };
    match candidate_attempt {
        ConnectionAttempt::Connected { session_present } => {
            *client = candidate_client;
            *eventloop = candidate_eventloop;
            set_ready(context.readiness, session_present, candidate_revision);
            return Ok(());
        }
        ConnectionAttempt::NegativeAckOutcomeUnknown => {
            return Err(MqttSessionError::DriverFailed);
        }
        ConnectionAttempt::Recoverable(_) => {}
    }

    // Failed reload candidate: bump + clear before the rollback connect attempt.
    runtime.epoch_fence.begin_and_clear(context.deliveries)?;
    runtime.tls = previous_tls;
    runtime.credential_revision = previous_revision;
    let (rollback_client, mut rollback_eventloop) = new_connection(runtime);
    let rollback = connect_once(
        &rollback_client,
        &mut rollback_eventloop,
        runtime,
        context.deliveries,
        negative_acks,
    )
    .await;
    *client = rollback_client;
    *eventloop = rollback_eventloop;
    match rollback {
        ConnectionAttempt::Connected { session_present } => {
            set_ready(context.readiness, session_present, previous_revision);
        }
        ConnectionAttempt::Recoverable(_) => set_degraded(context.readiness, previous_revision),
        ConnectionAttempt::NegativeAckOutcomeUnknown => {
            return Err(MqttSessionError::DriverFailed);
        }
    }
    tracing::warn!(
        target: "mqtt",
        reason = "reload_rollback",
        credential_revision = previous_revision.get(),
        "mqtt reload failed; restored last-good credentials"
    );
    Err(MqttSessionError::ReloadFailed)
}

async fn graceful_disconnect(client: &AsyncClient, eventloop: &mut EventLoop) {
    if client.disconnect().await.is_err() {
        return;
    }
    let _ = tokio::time::timeout(DISCONNECT_DRAIN_TIMEOUT, async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Outgoing(Outgoing::Disconnect)) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
}

fn fail_pending(
    unassigned: &mut VecDeque<oneshot::Sender<Result<(), MqttSessionError>>>,
    pending: &mut HashMap<u16, oneshot::Sender<Result<(), MqttSessionError>>>,
) {
    for response in unassigned.drain(..) {
        let _ = response.send(Err(MqttSessionError::SessionStopped));
    }
    for (_, response) in pending.drain() {
        let _ = response.send(Err(MqttSessionError::SessionStopped));
    }
}

fn set_ready(
    readiness: &watch::Sender<MqttReadiness>,
    session_present: bool,
    revision: CredentialRevision,
) {
    tracing::info!(
        target: "mqtt",
        session_present,
        credential_revision = revision.get(),
        "mqtt session ready"
    );
    let _ = readiness.send(MqttReadiness::Ready {
        session_present,
        credential_revision: revision.get(),
    });
}

fn set_degraded(readiness: &watch::Sender<MqttReadiness>, revision: CredentialRevision) {
    tracing::warn!(
        target: "mqtt",
        credential_revision = revision.get(),
        "mqtt session degraded"
    );
    let _ = readiness.send(MqttReadiness::Degraded {
        credential_revision: revision.get(),
    });
}

fn stop_negative_ack_unknown(
    epoch_fence: &TransportEpochFence,
    credential_revision: CredentialRevision,
    deliveries: &DeliveryQueue,
    readiness: &watch::Sender<MqttReadiness>,
) {
    tracing::error!(
        target: "mqtt",
        reason = "negative_puback_outcome_unknown",
        "mqtt session stopped with terminal rejection outcome unknown"
    );
    let _ = epoch_fence.begin_and_clear(deliveries);
    set_degraded(readiness, credential_revision);
    let _ = readiness.send(MqttReadiness::Stopped);
}

/// Closed non-PII reasons for MQTT session operation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MqttSessionError {
    #[error("mqtt session is not ready")]
    NotReady,
    #[error("mqtt publish request is invalid")]
    PublishInvalid,
    #[error("mqtt credential revision is not increasing")]
    RevisionNotIncreasing,
    #[error("mqtt tls material is invalid")]
    TlsMaterialInvalid,
    #[error("mqtt broker operation timed out")]
    BrokerTimeout,
    #[error("mqtt broker rejected the operation")]
    BrokerRejected,
    #[error("mqtt session stopped")]
    SessionStopped,
    #[error("mqtt uplink delivery closed")]
    DeliveryClosed,
    #[error("mqtt uplink delivery queue is saturated")]
    DeliverySaturated,
    #[error("mqtt puback capability unavailable")]
    AckUnavailable,
    #[error("mqtt transport epoch is stale")]
    StaleTransportEpoch,
    #[error("mqtt transport epoch exhausted")]
    TransportEpochExhausted,
    #[error("mqtt session driver failed")]
    DriverFailed,
    #[error("mqtt credential reload failed")]
    ReloadFailed,
}

/// True when a reconnect ConnAck may skip re-SUBSCRIBE (broker restored the session).
pub(crate) fn session_present_skips_subscribe(session_present: bool) -> bool {
    session_present
}

/// Strictly increasing credential revision fence for reload.
pub(crate) fn accept_reload_revision(
    current: u64,
    candidate: CredentialRevision,
) -> Result<(), MqttSessionError> {
    if candidate.get() <= current {
        tracing::warn!(
            target: "mqtt",
            reason = "revision_not_increasing",
            current_revision = current,
            "mqtt reload rejected"
        );
        return Err(MqttSessionError::RevisionNotIncreasing);
    }
    Ok(())
}

/// SubAck must grant every exact uplink filter at QoS1.
pub(crate) fn suback_grants_exact_uplinks(
    return_codes: &[SubscribeReasonCode],
    expected: usize,
) -> bool {
    return_codes.len() == expected
        && return_codes
            .iter()
            .all(|reason| matches!(reason, SubscribeReasonCode::Success(QoS::AtLeastOnce)))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // reason: unit fixtures fail loudly; poison test intentionally panics under catch_unwind
mod tests {
    use super::*;
    use std::time::Duration;

    fn settle(capability: AckCapability) -> Result<(), MqttSessionError> {
        let fence = Arc::clone(&capability.fence);
        fence.settle(capability)
    }

    #[test]
    fn receive_maximum_equals_delivery_capacity() {
        assert_eq!(RECEIVE_MAXIMUM as usize, DELIVERY_CAPACITY);
    }

    #[test]
    fn negative_puback_reasons_are_terminal_rejections() {
        assert_eq!(
            BrokerRejectReason::NotAuthorized.puback_reason(),
            PubAckReason::NotAuthorized
        );
        assert_eq!(
            BrokerRejectReason::TopicNameInvalid.puback_reason(),
            PubAckReason::TopicNameInvalid
        );
    }

    #[test]
    fn rejected_publish_mints_one_negative_puback() {
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 7;
        let rejected = RejectedBrokerPublish::new(
            publish,
            BrokerRejectReason::NotAuthorized,
            "assertion_rejected",
        );
        let (packet_id, request) = rejected.into_negative_puback().expect("negative puback");
        assert_eq!(packet_id, 7);
        assert!(matches!(
            request,
            rumqttc::v5::Request::PubAck(rumqttc::v5::mqttbytes::v5::PubAck {
                pkid: 7,
                reason: PubAckReason::NotAuthorized,
                properties: None,
            })
        ));
    }

    #[test]
    fn pending_negative_acks_are_bounded_and_unique() {
        let mut pending = PendingNegativeAcks::new();
        for packet_id in 1..=RECEIVE_MAXIMUM {
            pending.insert(packet_id).expect("bounded packet id");
        }
        assert_eq!(
            pending.insert(1),
            Err(MqttSessionError::DriverFailed),
            "duplicate packet id fails closed"
        );
        assert_eq!(
            pending.insert(RECEIVE_MAXIMUM + 1),
            Err(MqttSessionError::DriverFailed),
            "tracker cannot exceed RECEIVE_MAXIMUM"
        );
        assert!(pending.observe(RECEIVE_MAXIMUM));
        assert!(!pending.observe(RECEIVE_MAXIMUM));
    }

    #[test]
    fn negative_ack_unknown_is_terminal_not_recoverable() {
        assert_eq!(
            driver_event_disposition(true, true),
            DriverEventDisposition::StopNegativeAckUnknown
        );
        assert_eq!(
            driver_event_disposition(true, false),
            DriverEventDisposition::RecoverTransport
        );
        assert_eq!(
            driver_event_disposition(false, true),
            DriverEventDisposition::Continue
        );
    }

    #[test]
    fn connection_attempts_close_negative_ack_unknown_for_every_entry_path() {
        for entry_path in ["initial", "reload", "reconnect"] {
            let mut pending = PendingNegativeAcks::new();
            pending.insert(7).expect("pending negative ack");
            assert!(
                matches!(
                    classify_connection_attempt(Err(MqttSessionError::BrokerRejected), &pending,),
                    ConnectionAttempt::NegativeAckOutcomeUnknown
                ),
                "{entry_path} must not classify unknown negative ACK outcome as recoverable"
            );
        }

        assert!(matches!(
            classify_connection_attempt(
                Err(MqttSessionError::BrokerRejected),
                &PendingNegativeAcks::new(),
            ),
            ConnectionAttempt::Recoverable(MqttSessionError::BrokerRejected)
        ));
    }

    #[test]
    fn negative_ack_terminal_funnel_invalidates_and_stops() {
        let fence = TransportEpochFence::new(1);
        let deliveries = DeliveryQueue::new();
        let (readiness, receiver) = watch::channel(MqttReadiness::Ready {
            session_present: false,
            credential_revision: 1,
        });
        stop_negative_ack_unknown(
            &fence,
            CredentialRevision::new(1).expect("revision"),
            &deliveries,
            &readiness,
        );
        assert_eq!(*receiver.borrow(), MqttReadiness::Stopped);
        assert_eq!(fence.current().get(), 2);
    }

    #[test]
    fn terminal_settlement_is_nonblocking_when_client_queue_is_saturated() {
        let options = MqttOptions::new("terminal-test", "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 1);
        client
            .try_publish("fill", QoS::AtLeastOnce, false, Vec::new())
            .expect("first request fills bounded channel");
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 1;
        let fence = Arc::new(TransportEpochFence::new(1));

        assert_eq!(
            settle(AckCapability {
                client,
                publish,
                epoch: TransportEpoch(1),
                fence,
            }),
            Err(MqttSessionError::AckUnavailable)
        );
    }

    #[test]
    fn stale_epoch_settle_returns_distinct_closed_error() {
        let options = MqttOptions::new("stale-epoch", "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 10);
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 1;
        let fence = Arc::new(TransportEpochFence::new(2));
        assert_eq!(
            settle(AckCapability {
                client,
                publish,
                epoch: TransportEpoch(1),
                fence,
            }),
            Err(MqttSessionError::StaleTransportEpoch)
        );
    }

    #[test]
    fn same_epoch_queue_failure_is_ack_unavailable_not_stale() {
        let options = MqttOptions::new("same-epoch-queue", "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 1);
        client
            .try_publish("fill", QoS::AtLeastOnce, false, Vec::new())
            .expect("fill request channel");
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 1;
        let fence = Arc::new(TransportEpochFence::new(1));
        assert_eq!(
            settle(AckCapability {
                client,
                publish,
                epoch: TransportEpoch(1),
                fence,
            }),
            Err(MqttSessionError::AckUnavailable)
        );
    }

    #[test]
    fn same_epoch_settle_can_enqueue_ack() {
        let options = MqttOptions::new("same-epoch", "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 10);
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 1;
        let fence = Arc::new(TransportEpochFence::new(1));
        assert_eq!(
            settle(AckCapability {
                client,
                publish,
                epoch: TransportEpoch(1),
                fence,
            }),
            Ok(())
        );
    }

    #[test]
    fn recovery_invalidates_before_async_cleanup_window() {
        let fence = Arc::new(TransportEpochFence::new(1));
        let queue = DeliveryQueue::new();
        let options = MqttOptions::new("recover-stale", "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 10);
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 1;
        let live = AckCapability {
            client,
            publish,
            epoch: TransportEpoch(1),
            fence: Arc::clone(&fence),
        };
        assert!(
            admit_delivery(
                &queue,
                sample_delivery(1, Arc::clone(&fence)),
                MqttUplinkContract::CommandAcked,
            )
            .is_ok()
        );
        assert_eq!(queue.len_for_test(), 1);
        let candidate = fence.begin_and_clear(&queue).expect("candidate epoch");
        assert_eq!(candidate.get(), 2);
        assert_eq!(queue.len_for_test(), 0);
        assert_eq!(settle(live), Err(MqttSessionError::StaleTransportEpoch));
    }

    #[test]
    fn failed_candidate_expires_before_backoff_window() {
        let fence = Arc::new(TransportEpochFence::new(2));
        let queue = DeliveryQueue::new();
        let options = MqttOptions::new("failed-candidate", "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 10);
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 2;
        let failed_candidate = AckCapability {
            client,
            publish,
            epoch: TransportEpoch(2),
            fence: Arc::clone(&fence),
        };
        assert!(
            admit_delivery(
                &queue,
                sample_delivery(2, Arc::clone(&fence)),
                MqttUplinkContract::CommandAcked,
            )
            .is_ok()
        );
        let next = fence.begin_and_clear(&queue).expect("next candidate");
        assert_eq!(next.get(), 3);
        assert_eq!(queue.len_for_test(), 0);
        assert_eq!(
            settle(failed_candidate),
            Err(MqttSessionError::StaleTransportEpoch)
        );
        assert_eq!(fence.current().get(), 3);
    }

    #[test]
    fn transport_epoch_is_strictly_increasing_and_fail_closed_on_exhaustion() {
        let fence = TransportEpochFence::new(0);
        assert_eq!(fence.begin().expect("e1").get(), 1);
        assert_eq!(fence.begin().expect("e2").get(), 2);
        fence.epoch.store(u64::MAX, Ordering::SeqCst);
        assert_eq!(
            fence.begin(),
            Err(MqttSessionError::TransportEpochExhausted)
        );
        assert_eq!(fence.current().get(), u64::MAX);
    }

    #[test]
    fn settle_barrier_blocks_begin_until_settlement_critical_section_releases() {
        let fence = Arc::new(TransportEpochFence::new(1));
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder_fence = Arc::clone(&fence);
        let holder = std::thread::spawn(move || {
            holder_fence
                .with_settle_barrier_for_test(|| {
                    held_tx.send(()).expect("held");
                    release_rx.recv().expect("release");
                })
                .expect("barrier");
        });
        held_rx.recv().expect("wait held");
        let begin_fence = Arc::clone(&fence);
        let beginner = std::thread::spawn(move || begin_fence.begin());
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !beginner.is_finished(),
            "begin must block while settle barrier is held"
        );
        release_tx.send(()).expect("release");
        assert_eq!(
            beginner.join().expect("join begin").expect("begin").get(),
            2
        );
        holder.join().expect("join holder");
    }

    fn sample_delivery(epoch: u64, fence: Arc<TransportEpochFence>) -> AuthenticatedDeviceDelivery {
        let options = MqttOptions::new(format!("delivery-{epoch}"), "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 10);
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = u16::try_from(epoch).unwrap_or(1);
        let scope = crate::DeviceScope::new(
            vocab::TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant"),
            ids::DeviceId::parse("22222222-2222-4222-8222-222222222222").expect("device"),
            crate::CredentialGeneration::new(2).expect("generation"),
        );
        let policy = MqttTopicPolicy::new(vec![scope.clone()]).expect("policy");
        let topic = policy.command_acked_topic(&scope).expect("ack topic");
        AuthenticatedDeviceDelivery {
            scope,
            contract: MqttUplinkContract::CommandAcked,
            topic,
            payload: Vec::new(),
            correlation: None,
            ack: Some(AckCapability {
                client,
                publish,
                epoch: TransportEpoch(epoch),
                fence,
            }),
        }
    }

    #[tokio::test]
    async fn next_uplink_skips_stale_epoch_and_returns_current() {
        let fence = Arc::new(TransportEpochFence::new(2));
        let queue = DeliveryQueue::new();
        queue
            .try_push(sample_delivery(1, Arc::clone(&fence)))
            .expect("stale");
        queue
            .try_push(sample_delivery(2, Arc::clone(&fence)))
            .expect("current");
        let delivery = queue.pop_current(&fence).await.expect("current uplink");
        assert!(delivery_has_current_transport_epoch(&delivery, &fence));
        assert_eq!(delivery.ack.as_ref().map(|ack| ack.epoch.get()), Some(2));
        queue.close();
        assert!(matches!(
            queue.pop_current(&fence).await,
            Err(MqttSessionError::DeliveryClosed)
        ));
    }

    #[tokio::test]
    async fn next_uplink_current_epoch_anti_vacuity() {
        let fence = Arc::new(TransportEpochFence::new(1));
        let queue = DeliveryQueue::new();
        queue
            .try_push(sample_delivery(1, Arc::clone(&fence)))
            .expect("current");
        let delivery = queue
            .pop_current(&fence)
            .await
            .expect("must not vacuous-skip current");
        assert_eq!(delivery.ack.as_ref().map(|ack| ack.epoch.get()), Some(1));
    }

    #[tokio::test]
    async fn delivery_queue_close_wakes_waiter() {
        let fence = Arc::new(TransportEpochFence::new(1));
        let queue = Arc::new(DeliveryQueue::new());
        let waiter_queue = Arc::clone(&queue);
        let waiter_fence = Arc::clone(&fence);
        let waiter = tokio::spawn(async move { waiter_queue.pop_current(&waiter_fence).await });
        tokio::task::yield_now().await;
        queue.close();
        assert!(matches!(
            waiter.await.expect("join"),
            Err(MqttSessionError::DeliveryClosed)
        ));
    }

    #[tokio::test]
    async fn full_delivery_queue_rejects_overflow_without_clearing_and_readmits() {
        let fence = Arc::new(TransportEpochFence::new(1));
        let queue = DeliveryQueue::new();
        for i in 0..DELIVERY_CAPACITY {
            admit_delivery(
                &queue,
                sample_delivery(u64::try_from(i + 1).expect("pkid"), Arc::clone(&fence)),
                MqttUplinkContract::CommandAcked,
            )
            .expect("admit");
        }
        assert!(queue.is_saturated());
        assert_eq!(queue.len_for_test(), DELIVERY_CAPACITY);
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            assert_eq!(
                admit_delivery(
                    &queue,
                    sample_delivery(99, Arc::clone(&fence)),
                    MqttUplinkContract::CertificateReported,
                ),
                Err(MqttSessionError::DeliverySaturated)
            );
        });
        assert_eq!(queue.len_for_test(), DELIVERY_CAPACITY);
        assert!(queue.is_saturated());
        let rendered = handle.render();
        assert!(
            rendered.contains("mqtt_uplink_admission_failures_total"),
            "{rendered}"
        );
        assert!(rendered.contains("contract=\"report\""), "{rendered}");
        assert!(rendered.contains("reason=\"queue_full\""), "{rendered}");
        let _ = queue.pop_current(&fence).await.expect("pop");
        assert!(!queue.is_saturated());
        assert!(
            admit_delivery(
                &queue,
                sample_delivery(100, Arc::clone(&fence)),
                MqttUplinkContract::CommandAcked,
            )
            .is_ok()
        );
        assert!(queue.is_saturated());
    }

    #[test]
    fn closed_delivery_queue_is_terminal() {
        let queue = DeliveryQueue::new();
        queue.close();
        let fence = Arc::new(TransportEpochFence::new(1));
        assert_eq!(
            admit_delivery(
                &queue,
                sample_delivery(1, fence),
                MqttUplinkContract::CertificateReported,
            ),
            Err(MqttSessionError::DeliveryClosed)
        );
    }

    #[test]
    fn uplink_admission_metric_labels_are_emit_owner_closed() {
        assert_eq!(MqttUplinkContract::CommandAcked.as_label(), "ack");
        assert_eq!(MqttUplinkContract::CertificateReported.as_label(), "report");
        assert_eq!(
            MqttUplinkAdmissionFailureReason::QueueFull.as_label(),
            "queue_full"
        );
    }

    #[test]
    fn session_present_skips_subscribe_only_when_restored() {
        assert!(session_present_skips_subscribe(true));
        assert!(!session_present_skips_subscribe(false));
    }

    #[test]
    fn accept_reload_revision_requires_strict_increase() {
        let next = CredentialRevision::new(3).expect("revision");
        assert!(accept_reload_revision(2, next).is_ok());
        assert_eq!(
            accept_reload_revision(3, next),
            Err(MqttSessionError::RevisionNotIncreasing)
        );
        assert_eq!(
            accept_reload_revision(4, next),
            Err(MqttSessionError::RevisionNotIncreasing)
        );
    }

    #[test]
    fn suback_grants_exact_uplinks_requires_qos1_success() {
        assert!(suback_grants_exact_uplinks(
            &[
                SubscribeReasonCode::Success(QoS::AtLeastOnce),
                SubscribeReasonCode::Success(QoS::AtLeastOnce),
            ],
            2
        ));
        assert!(!suback_grants_exact_uplinks(
            &[SubscribeReasonCode::Success(QoS::AtLeastOnce)],
            2
        ));
        assert!(!suback_grants_exact_uplinks(
            &[SubscribeReasonCode::Success(QoS::AtMostOnce)],
            1
        ));
        assert!(!suback_grants_exact_uplinks(
            &[SubscribeReasonCode::Unspecified],
            1
        ));
    }

    #[test]
    fn readiness_from_connect_result_preserves_session_present() {
        let revision = CredentialRevision::new(1).expect("revision");
        assert_eq!(
            readiness_from_connect_result(Ok(true), revision),
            (
                MqttReadiness::Ready {
                    session_present: true,
                    credential_revision: 1,
                },
                Ok(())
            )
        );
        assert_eq!(
            readiness_from_connect_result(Ok(false), revision),
            (
                MqttReadiness::Ready {
                    session_present: false,
                    credential_revision: 1,
                },
                Ok(())
            )
        );
        assert_eq!(
            readiness_from_connect_result(Err(MqttSessionError::BrokerRejected), revision),
            (
                MqttReadiness::Degraded {
                    credential_revision: 1,
                },
                Err(MqttSessionError::BrokerRejected)
            )
        );
    }

    #[test]
    fn poison_fail_closed_on_settle_barrier() {
        let fence = TransportEpochFence::new(1);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = fence.settle.lock().expect("lock");
            panic!("poison settle");
        }));
        assert_eq!(fence.begin(), Err(MqttSessionError::DriverFailed));
    }
}
