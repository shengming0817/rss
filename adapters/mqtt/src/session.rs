use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use diport::{BrokerAcceptanceMint, BrokerAccepted, ManagedResource, MessageId, ShutdownError};
use identity::ports::device_certificate::{DeviceIngressContract, DeviceIngressDelivery};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{
    ConnectReturnCode, Filter, Packet, PubAckReason, Publish, PublishProperties,
    SubscribeReasonCode,
};
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::{Outgoing, TlsConfiguration, Transport};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
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

struct AckCapability {
    client: AsyncClient,
    publish: Publish,
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
        settle_ack_capability(capability)
    }
}

fn settle_ack_capability(capability: AckCapability) -> Result<(), MqttSessionError> {
    capability.client.try_ack(&capability.publish).map_err(|_| {
        let _ = capability.client.try_disconnect();
        tracing::warn!(target: "mqtt", reason = "puback_enqueue", "mqtt ack failed");
        MqttSessionError::AckUnavailable
    })
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
    deliveries: Mutex<mpsc::Receiver<AuthenticatedDeviceDelivery>>,
    readiness: watch::Receiver<MqttReadiness>,
    cancel: CancellationToken,
    join: Mutex<Option<JoinHandle<()>>>,
    client_id: String,
    credential_revision: AtomicU64,
    reload_lock: Mutex<()>,
}

impl MqttSession {
    pub async fn connect(config: crate::MqttSessionConfig) -> Result<Self, MqttSessionError> {
        let prepared = config.into_prepared();
        let client_id = prepared.client_id.clone();
        let revision = prepared.credential_revision.get();
        let (command_tx, command_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (delivery_tx, delivery_rx) = mpsc::channel(DELIVERY_CAPACITY);
        let (readiness_tx, readiness_rx) = watch::channel(MqttReadiness::Starting);
        let (initial_tx, initial_rx) = oneshot::channel();
        let cancel = CancellationToken::new();
        let driver_cancel = cancel.clone();
        let join = tokio::spawn(run_driver(
            prepared,
            command_rx,
            delivery_tx,
            readiness_tx,
            driver_cancel,
            initial_tx,
        ));
        let shared = Arc::new(Shared {
            commands: command_tx,
            deliveries: Mutex::new(delivery_rx),
            readiness: readiness_rx,
            cancel,
            join: Mutex::new(Some(join)),
            client_id,
            credential_revision: AtomicU64::new(revision),
            reload_lock: Mutex::new(()),
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
            .lock()
            .await
            .recv()
            .await
            .ok_or(MqttSessionError::DeliveryClosed)
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
}

impl From<PreparedSessionConfig> for DriverRuntime {
    fn from(config: PreparedSessionConfig) -> Self {
        Self {
            endpoint: config.endpoint,
            client_id: config.client_id,
            tls: config.tls,
            verifier: config.verifier,
            policy: config.policy,
            session_expiry: config.session_expiry,
            credential_revision: config.credential_revision,
        }
    }
}

async fn run_driver(
    prepared: PreparedSessionConfig,
    commands: mpsc::Receiver<DriverCommand>,
    deliveries: mpsc::Sender<AuthenticatedDeviceDelivery>,
    readiness: watch::Sender<MqttReadiness>,
    cancel: CancellationToken,
    initial: oneshot::Sender<Result<(), MqttSessionError>>,
) {
    let mut runtime = DriverRuntime::from(prepared);
    let (mut client, mut eventloop) = new_connection(&runtime);
    if !announce_initial_connection(
        connect_once(&client, &mut eventloop, &runtime, &deliveries).await,
        &runtime,
        &readiness,
        initial,
    ) {
        return;
    }
    drive_session_loop(
        &mut runtime,
        &mut client,
        &mut eventloop,
        commands,
        &deliveries,
        &readiness,
        &cancel,
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
    match state {
        MqttReadiness::Ready {
            session_present,
            credential_revision,
        } => {
            tracing::info!(
                target: "mqtt",
                session_present,
                credential_revision,
                "mqtt session ready"
            );
        }
        MqttReadiness::Degraded {
            credential_revision,
        } => {
            tracing::warn!(
                target: "mqtt",
                credential_revision,
                "mqtt session degraded"
            );
        }
        _ => {}
    }
    let _ = readiness.send(state);
    let ok = result.is_ok();
    let _ = initial.send(result);
    ok
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
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
    readiness: &watch::Sender<MqttReadiness>,
    cancel: &CancellationToken,
) {
    let mut unassigned = VecDeque::new();
    let mut pending = HashMap::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                fail_pending(&mut unassigned, &mut pending);
                graceful_disconnect(client, eventloop).await;
                let _ = readiness.send(MqttReadiness::Stopped);
                return;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    graceful_disconnect(client, eventloop).await;
                    let _ = readiness.send(MqttReadiness::Stopped);
                    return;
                };
                handle_driver_command(
                    command,
                    client,
                    eventloop,
                    runtime,
                    deliveries,
                    readiness,
                    &mut unassigned,
                    &mut pending,
                ).await;
            }
            polled = eventloop.poll() => {
                if handle_polled_event(
                    polled,
                    client,
                    eventloop,
                    runtime,
                    deliveries,
                    readiness,
                    cancel,
                    &mut unassigned,
                    &mut pending,
                ).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_polled_event(
    polled: Result<Event, rumqttc::v5::ConnectionError>,
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
    readiness: &watch::Sender<MqttReadiness>,
    cancel: &CancellationToken,
    unassigned: &mut VecDeque<oneshot::Sender<Result<(), MqttSessionError>>>,
    pending: &mut HashMap<u16, oneshot::Sender<Result<(), MqttSessionError>>>,
) -> Result<(), ()> {
    let needs_recover = match polled {
        Ok(event) => handle_event(event, client, runtime, deliveries, unassigned, pending)
            .await
            .is_err(),
        Err(_) => true,
    };
    if !needs_recover {
        return Ok(());
    }
    set_degraded(readiness, runtime.credential_revision);
    fail_pending(unassigned, pending);
    let _ = client.disconnect().await;
    if reconnect(client, eventloop, runtime, deliveries, readiness, cancel)
        .await
        .is_err()
    {
        let _ = readiness.send(MqttReadiness::Stopped);
        return Err(());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_driver_command(
    command: DriverCommand,
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &mut DriverRuntime,
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
    readiness: &watch::Sender<MqttReadiness>,
    unassigned: &mut VecDeque<oneshot::Sender<Result<(), MqttSessionError>>>,
    pending: &mut HashMap<u16, oneshot::Sender<Result<(), MqttSessionError>>>,
) {
    match command {
        DriverCommand::Publish(publish) => {
            enqueue_publish(client, &runtime.policy, publish, unassigned).await;
        }
        DriverCommand::Reload {
            tls,
            revision,
            response,
        } => {
            fail_pending(unassigned, pending);
            let result = reload(
                client, eventloop, runtime, tls, revision, deliveries, readiness,
            )
            .await;
            let _ = response.send(result);
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
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
) -> Result<bool, MqttSessionError> {
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_and_restore(client, eventloop, runtime, deliveries),
    )
    .await
    .map_err(|_| {
        tracing::warn!(target: "mqtt", reason = "connect_timeout", "mqtt connect timed out");
        MqttSessionError::BrokerTimeout
    })?
}

async fn connect_and_restore(
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
) -> Result<bool, MqttSessionError> {
    let session_present = loop {
        match eventloop.poll().await.map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "connect_transport", "mqtt connect failed");
            MqttSessionError::BrokerRejected
        })? {
            Event::Incoming(Packet::ConnAck(ack)) if ack.code == ConnectReturnCode::Success => {
                break ack.session_present;
            }
            Event::Incoming(Packet::ConnAck(_)) => {
                tracing::warn!(target: "mqtt", reason = "connack_rejected", "mqtt connect rejected");
                return Err(MqttSessionError::BrokerRejected);
            }
            _ => {}
        }
    };
    if session_present_skips_subscribe(session_present) {
        return Ok(true);
    }
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
    loop {
        match eventloop.poll().await.map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "subscribe_transport", "mqtt subscribe failed");
            MqttSessionError::BrokerRejected
        })? {
            Event::Incoming(Packet::SubAck(ack)) => {
                if suback_grants_exact_uplinks(&ack.return_codes, expected) {
                    return Ok(false);
                }
                tracing::warn!(target: "mqtt", reason = "suback_rejected", "mqtt subscribe rejected");
                return Err(MqttSessionError::BrokerRejected);
            }
            Event::Incoming(Packet::Publish(publish)) => {
                deliver_publish(client, runtime, deliveries, publish).await?;
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
    runtime: &DriverRuntime,
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
    unassigned: &mut VecDeque<oneshot::Sender<Result<(), MqttSessionError>>>,
    pending: &mut HashMap<u16, oneshot::Sender<Result<(), MqttSessionError>>>,
) -> Result<(), MqttSessionError> {
    match event {
        Event::Outgoing(Outgoing::Publish(packet_id)) => {
            let response = unassigned
                .pop_front()
                .ok_or(MqttSessionError::DriverFailed)?;
            if pending.insert(packet_id, response).is_some() {
                return Err(MqttSessionError::DriverFailed);
            }
        }
        Event::Incoming(Packet::PubAck(ack)) => {
            let response = pending
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
            deliver_publish(client, runtime, deliveries, publish).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn deliver_publish(
    client: &AsyncClient,
    runtime: &DriverRuntime,
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
    publish: Publish,
) -> Result<(), MqttSessionError> {
    let topic = std::str::from_utf8(publish.topic.as_ref()).map_err(|_| {
        tracing::warn!(target: "mqtt", reason = "uplink_topic_utf8", "mqtt uplink dropped");
        MqttSessionError::AssertionRejected
    })?;
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
    let verified = runtime
        .verifier
        .verify(&runtime.policy, &frame)
        .map_err(|_| {
            tracing::warn!(target: "mqtt", reason = "assertion_rejected", "mqtt uplink dropped");
            MqttSessionError::AssertionRejected
        })?;
    let (_, contract) = runtime.policy.resolve_uplink(topic).ok_or_else(|| {
        tracing::warn!(target: "mqtt", reason = "uplink_policy", "mqtt uplink dropped");
        MqttSessionError::AssertionRejected
    })?;
    let exact_topic = runtime.policy.exact_verified_topic(topic).ok_or_else(|| {
        tracing::warn!(target: "mqtt", reason = "uplink_topic", "mqtt uplink dropped");
        MqttSessionError::AssertionRejected
    })?;
    let delivery = AuthenticatedDeviceDelivery {
        scope: verified.into_scope(),
        contract,
        topic: exact_topic,
        payload: publish.payload.to_vec(),
        correlation: correlation.map(<[u8]>::to_vec),
        ack: Some(AckCapability {
            client: client.clone(),
            publish,
        }),
    };
    admit_delivery(deliveries, delivery, contract)
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

fn admit_delivery<T>(
    deliveries: &mpsc::Sender<T>,
    delivery: T,
    contract: MqttUplinkContract,
) -> Result<(), MqttSessionError> {
    match deliveries.try_send(delivery) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
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
        Err(mpsc::error::TrySendError::Closed(_)) => Err(MqttSessionError::DeliveryClosed),
    }
}

async fn reconnect(
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &DriverRuntime,
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
    readiness: &watch::Sender<MqttReadiness>,
    cancel: &CancellationToken,
) -> Result<(), MqttSessionError> {
    let mut backoff = RECONNECT_MIN;
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Err(MqttSessionError::SessionStopped),
            () = tokio::time::sleep(backoff) => {}
        }
        // Rebuild the local request queue after a transport failure. Reusing rumqttc's queue
        // would let a caller-visible failed publish surface later without its PUBACK capability.
        let (candidate_client, mut candidate_eventloop) = new_connection(runtime);
        if let Ok(session_present) = connect_once(
            &candidate_client,
            &mut candidate_eventloop,
            runtime,
            deliveries,
        )
        .await
        {
            *client = candidate_client;
            *eventloop = candidate_eventloop;
            set_ready(readiness, session_present, runtime.credential_revision);
            return Ok(());
        }
        backoff = backoff.saturating_mul(2).min(RECONNECT_MAX);
    }
}

#[allow(clippy::too_many_arguments)]
async fn reload(
    client: &mut AsyncClient,
    eventloop: &mut EventLoop,
    runtime: &mut DriverRuntime,
    candidate_tls: Arc<rustls::ClientConfig>,
    candidate_revision: CredentialRevision,
    deliveries: &mpsc::Sender<AuthenticatedDeviceDelivery>,
    readiness: &watch::Sender<MqttReadiness>,
) -> Result<(), MqttSessionError> {
    let previous_tls = Arc::clone(&runtime.tls);
    let previous_revision = runtime.credential_revision;
    let _ = readiness.send(MqttReadiness::Reloading {
        from_revision: previous_revision.get(),
        to_revision: candidate_revision.get(),
    });
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
            deliveries,
        ),
    )
    .await;
    if let Ok(Ok(session_present)) = candidate {
        *client = candidate_client;
        *eventloop = candidate_eventloop;
        set_ready(readiness, session_present, candidate_revision);
        return Ok(());
    }

    runtime.tls = previous_tls;
    runtime.credential_revision = previous_revision;
    let (rollback_client, mut rollback_eventloop) = new_connection(runtime);
    let rollback = connect_once(
        &rollback_client,
        &mut rollback_eventloop,
        runtime,
        deliveries,
    )
    .await;
    *client = rollback_client;
    *eventloop = rollback_eventloop;
    match rollback {
        Ok(session_present) => set_ready(readiness, session_present, previous_revision),
        Err(_) => set_degraded(readiness, previous_revision),
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
    #[error("mqtt broker assertion rejected")]
    AssertionRejected,
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
mod tests {
    use super::*;

    #[test]
    fn terminal_settlement_is_nonblocking_when_client_queue_is_saturated() {
        let options = MqttOptions::new("terminal-test", "localhost", 1883);
        let (client, _eventloop) = AsyncClient::new(options, 1);
        client
            .try_publish("fill", QoS::AtLeastOnce, false, Vec::new())
            .expect("first request fills bounded channel");
        let mut publish = Publish::new("uplink", QoS::AtLeastOnce, Vec::new(), None);
        publish.pkid = 1;

        assert_eq!(
            settle_ack_capability(AckCapability { client, publish }),
            Err(MqttSessionError::AckUnavailable)
        );
    }

    struct DropProbe(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn full_delivery_queue_drops_only_the_saturated_attempt_and_recovers() {
        let (tx, mut rx) = mpsc::channel(1);
        let admitted_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saturated_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(
            admit_delivery(
                &tx,
                DropProbe(Arc::clone(&admitted_dropped)),
                MqttUplinkContract::CommandAcked,
            )
            .is_ok()
        );
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            assert_eq!(
                admit_delivery(
                    &tx,
                    DropProbe(Arc::clone(&saturated_dropped)),
                    MqttUplinkContract::CertificateReported,
                ),
                Err(MqttSessionError::DeliverySaturated)
            );
        });
        assert!(saturated_dropped.load(Ordering::SeqCst));
        assert!(!admitted_dropped.load(Ordering::SeqCst));
        let rendered = handle.render();
        assert!(
            rendered.contains("mqtt_uplink_admission_failures_total"),
            "{rendered}"
        );
        assert!(rendered.contains("contract=\"report\""), "{rendered}");
        assert!(rendered.contains("reason=\"queue_full\""), "{rendered}");
        assert!(
            rendered
                .lines()
                .any(|line| line.contains("mqtt_uplink_admission_failures_total")
                    && line.ends_with(" 1")),
            "{rendered}"
        );
        drop(rx.recv().await);
        assert!(rx.try_recv().is_err());
        assert!(admitted_dropped.load(Ordering::SeqCst));
        let recovered_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(
            admit_delivery(
                &tx,
                DropProbe(Arc::clone(&recovered_dropped)),
                MqttUplinkContract::CommandAcked,
            )
            .is_ok()
        );
        drop(rx.recv().await);
        assert!(recovered_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn closed_delivery_queue_is_terminal() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        assert_eq!(
            admit_delivery(&tx, 1_u8, MqttUplinkContract::CertificateReported),
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
}
