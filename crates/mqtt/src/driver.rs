use crate::{
    ConnectionState, MqttConfig, MqttError,
    handles::{
        ClockRef, Command, Delivery, MqttPublisher, MqttReceiver, MqttResource, Settlement, Shared,
    },
    outcome,
};
use rss_transactional_messaging::{
    policy::{AbsoluteDeadline, Clock},
    transport::{
        PublishFailureKind as Kind, PublishFailureReason as Reason, PublishFailureStage as Stage,
    },
};
use rumqttc::mqttbytes::v5::{Packet, PubAck, SubscribeReasonCode};
use rumqttc::{
    AsyncClient, ConnectionError, Event, EventLoop, ManualAck, Outgoing, PublishOptions, QoS,
    SessionStore,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, mpsc, oneshot, watch};

/// Start one driver on the current Tokio runtime. Use `wait_ready` before accepting work.
///
/// The store owns crash-consistent checkpoints for one exclusively assigned scope/client ID.
/// The adapter never resets a mismatched session or constructs a replacement outbound ledger.
pub fn connect(
    config: MqttConfig,
    clock: Arc<dyn Clock>,
    store: Arc<dyn SessionStore>,
) -> Result<(MqttPublisher, MqttReceiver, MqttResource), MqttError> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| MqttError::InvalidConfig)?;
    let mut options = config.options;
    options.set_session_store_arc(store);
    let (client, eventloop) = AsyncClient::builder(options)
        .capacity(config.limits.commands)
        .try_build()
        .map_err(|_| MqttError::InvalidConfig)?;
    let (commands, rx) = mpsc::channel(config.limits.commands);
    let (state, _) = watch::channel(ConnectionState::Connecting);
    let shared = Arc::new(Shared {
        commands,
        clock: ClockRef(clock),
        state,
        closing: AtomicBool::new(false),
        generation: AtomicU64::new(1),
        retire: AtomicU64::new(0),
        wake: Notify::new(),
        cancelled: tokio_util::sync::CancellationToken::new(),
        deliveries: Mutex::new(VecDeque::new()),
        delivered: Notify::new(),
    });
    let driver = Driver {
        shared: shared.clone(),
        outstanding: HashMap::new(),
        subscriptions: config.subscriptions,
        subscription: None,
        session_present: false,
        max_deliveries: config.limits.deliveries as usize,
        reconnect: config.reconnect.build(),
    };
    let task = runtime.spawn(run(driver, client, eventloop, rx));
    Ok((
        MqttPublisher {
            shared: shared.clone(),
            packet_bytes: config.limits.packet_bytes,
        },
        MqttReceiver {
            shared: shared.clone(),
        },
        MqttResource {
            shared,
            task: Some(task),
        },
    ))
}

type SubscriptionFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<rumqttc::mqttbytes::v5::SubAck, rumqttc::SubscribeNoticeError>,
            > + Send,
    >,
>;

enum DeliveryState {
    Delivered,
    Settling {
        deadline: AbsoluteDeadline,
        response: oneshot::Sender<Result<(), MqttError>>,
    },
}
struct Driver {
    shared: Arc<Shared>,
    outstanding: HashMap<u16, DeliveryState>,
    subscriptions: Vec<String>,
    subscription: Option<SubscriptionFuture>,
    session_present: bool,
    max_deliveries: usize,
    reconnect: crate::reconnect::Reconnect,
}
impl Driver {
    fn generation(&self) -> u64 {
        self.shared.generation.load(Ordering::Acquire)
    }
    fn retire(&mut self) {
        if self.shared.invalidate().is_err() {
            self.shared.cancelled.cancel();
        }
        for (_, value) in self.outstanding.drain() {
            if let DeliveryState::Settling { response, .. } = value {
                let _ = response.send(Err(MqttError::SettlementUnknown));
            }
        }
        self.subscription = None;
    }
    fn fail(&self, error: MqttError) {
        self.shared
            .state
            .send_replace(ConnectionState::Failed(error));
    }
    fn ready(&mut self) {
        self.reconnect.reset();
        self.shared.state.send_replace(ConnectionState::Ready {
            generation: self.generation(),
            session_present: self.session_present,
        });
    }
    fn settlement_wait(&self) -> Option<Duration> {
        self.outstanding
            .values()
            .filter_map(|v| match v {
                DeliveryState::Settling { deadline, .. } => {
                    Some(deadline.remaining(&self.shared.clock))
                }
                DeliveryState::Delivered => None,
            })
            .min()
    }
    fn handle_command(
        &mut self,
        client: &AsyncClient,
        command: Command,
    ) -> Option<(AbsoluteDeadline, oneshot::Sender<Result<(), MqttError>>)> {
        match command {
            Command::Publish {
                request,
                deadline,
                response,
            } => {
                if response.is_closed() {
                    return None;
                }
                let result = if self.shared.closing.load(Ordering::Acquire)
                    || !matches!(*self.shared.state.borrow(), ConnectionState::Ready { .. })
                {
                    Err(outcome::definite(
                        Kind::Transient,
                        Stage::Admission,
                        Reason::TransportUnavailable,
                    ))
                } else if deadline.remaining(&self.shared.clock).is_zero() {
                    Err(outcome::definite(
                        Kind::Transient,
                        Stage::Admission,
                        Reason::DeadlineElapsed,
                    ))
                } else {
                    client
                        .try_publish_tracked(
                            request.topic,
                            request.payload,
                            PublishOptions::at_least_once()
                                .retain(request.retain)
                                .properties(request.properties),
                        )
                        .map_err(outcome::admission)
                };
                let _ = response.send(result);
            }
            Command::Settle {
                generation,
                pkid,
                reason,
                deadline,
                response,
            } => {
                let result = self.submit_settlement(client, generation, pkid, reason, deadline);
                match result {
                    Ok(()) => {
                        self.outstanding
                            .insert(pkid, DeliveryState::Settling { deadline, response });
                    }
                    Err(error) => {
                        let _ = response.send(Err(error));
                    }
                }
            }
            Command::Shutdown { deadline, response } => return Some((deadline, response)),
        }
        None
    }
    fn submit_settlement(
        &self,
        client: &AsyncClient,
        generation: u64,
        pkid: u16,
        reason: rumqttc::mqttbytes::v5::PubAckReason,
        deadline: AbsoluteDeadline,
    ) -> Result<(), MqttError> {
        if generation != self.generation() {
            return Err(MqttError::StaleDelivery);
        }
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(MqttError::Closed);
        }
        if deadline.remaining(&self.shared.clock).is_zero() {
            return Err(MqttError::DeadlineElapsed);
        }
        if !matches!(self.outstanding.get(&pkid), Some(DeliveryState::Delivered)) {
            return Err(MqttError::StaleDelivery);
        }
        client
            .try_manual_ack(ManualAck::PubAck(PubAck {
                pkid,
                reason,
                properties: None,
            }))
            .map_err(|_| MqttError::Unavailable)
    }
    fn event(&mut self, client: &AsyncClient, event: Event) -> Result<(), MqttError> {
        match event {
            Event::Incoming(Packet::ConnAck(ack)) => {
                self.session_present = ack.session_present;
                if self.subscriptions.is_empty() {
                    self.ready();
                } else {
                    // Reassert the fixed desired set even after process reconstruction.
                    let filters = self.subscriptions.iter().map(|v| {
                        rumqttc::SubscribeFilterInput::new(v, QoS::AtLeastOnce).retain_forward_rule(
                            rumqttc::mqttbytes::v5::RetainForwardRule::OnNewSubscribe,
                        )
                    });
                    let notice = client
                        .try_subscribe_many_tracked(filters)
                        .map_err(|_| MqttError::SubscriptionRejected)?;
                    self.subscription = Some(Box::pin(notice.wait_async()));
                }
            }
            Event::Incoming(Packet::Publish(publish)) => self.receive(publish)?,
            Event::Incoming(Packet::PubAck(ack))
                if ack.reason == rumqttc::mqttbytes::v5::PubAckReason::PacketIdentifierInUse =>
            {
                self.shared.abandon(self.generation());
            }
            Event::Outgoing(Outgoing::PubAck(pkid)) => {
                if let Some(DeliveryState::Settling { response, deadline }) =
                    self.outstanding.remove(&pkid)
                {
                    let result = if deadline.remaining(&self.shared.clock).is_zero() {
                        self.shared.abandon(self.generation());
                        Err(MqttError::SettlementUnknown)
                    } else {
                        Ok(())
                    };
                    let _ = response.send(result);
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn check_subscription(&mut self) -> Result<(), MqttError> {
        use std::task::{Context, Poll, Waker};
        let Some(notice) = self.subscription.as_mut() else {
            return Ok(());
        };
        // Notices are completed only by EventLoop::poll. Inspect after each finished transport poll;
        // a separate select branch could cancel poll while it is persisting or flushing a packet.
        let result = notice
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        let Poll::Ready(result) = result else {
            return Ok(());
        };
        self.subscription = None;
        let ack = result.map_err(|error| match error {
            rumqttc::SubscribeNoticeError::SessionPersistence(_) => MqttError::SessionStore,
            _ => MqttError::SubscriptionRejected,
        })?;
        if ack.return_codes.len() != self.subscriptions.len() {
            return Err(MqttError::SubscriptionRejected);
        }
        let mut transient = false;
        for code in ack.return_codes {
            match code {
                SubscribeReasonCode::Success(QoS::AtLeastOnce) => {}
                SubscribeReasonCode::Failure
                | SubscribeReasonCode::Unspecified
                | SubscribeReasonCode::ImplementationSpecific
                | SubscribeReasonCode::QuotaExceeded
                | SubscribeReasonCode::PkidInUse => transient = true,
                _ => return Err(MqttError::SubscriptionRejected),
            }
        }
        if transient {
            return Err(MqttError::BrokerBusy);
        }
        self.ready();
        Ok(())
    }
    fn reconnecting(&self, cause: MqttError) {
        self.shared
            .state
            .send_replace(ConnectionState::Reconnecting {
                cause,
                generation: self.generation(),
            });
    }
    fn receive(&mut self, publish: rumqttc::mqttbytes::v5::Publish) -> Result<(), MqttError> {
        if publish.qos != QoS::AtLeastOnce {
            return Err(MqttError::UnsupportedQos);
        }
        if self.outstanding.contains_key(&publish.pkid) {
            return Ok(());
        } // reason: same-connection retransmission retains its sole settlement authority.
        if self.outstanding.len() >= self.max_deliveries {
            return Err(MqttError::ReceiveCapacity);
        }
        let pkid = publish.pkid;
        let delivery = Delivery {
            publish,
            settlement: Settlement {
                shared: Arc::downgrade(&self.shared),
                generation: self.generation(),
                pkid,
                decided: false,
            },
        };
        self.shared
            .deliveries
            .lock()
            .map_err(|_| MqttError::Closed)?
            .push_back(delivery);
        self.outstanding.insert(pkid, DeliveryState::Delivered);
        self.shared.delivered.notify_one();
        Ok(())
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.shared.closing.store(true, Ordering::Release);
        self.retire();
        if !matches!(*self.shared.state.borrow(), ConnectionState::Failed(_)) {
            self.shared.state.send_replace(ConnectionState::Closed);
        }
        self.shared.delivered.notify_waiters();
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "one driver stack value avoids allocating each MQTT packet event"
)]
enum Next {
    Event(Result<Event, ConnectionError>),
    Retire,
    Stop,
    Shutdown(AbsoluteDeadline, oneshot::Sender<Result<(), MqttError>>),
}

async fn next(
    driver: &mut Driver,
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    commands: &mut mpsc::Receiver<Command>,
) -> Next {
    // Keep poll alive across commands: cancelling it during a write could leave an unflushed event.
    let poll = eventloop.poll();
    tokio::pin!(poll);
    loop {
        let shared = driver.shared.clone();
        if shared.retire.load(Ordering::Acquire) >= driver.generation() {
            return Next::Retire;
        }
        let wait = driver.settlement_wait();
        tokio::select! {
            biased;
            () = shared.cancelled.cancelled() => return Next::Stop,
            () = shared.wake.notified() => { if shared.retire.load(Ordering::Acquire) >= driver.generation() { return Next::Retire; } }
            () = async { match wait { Some(wait) => tokio::time::sleep(wait).await, None => std::future::pending().await } } => return Next::Retire,
            event = &mut poll => return Next::Event(event),
            command = commands.recv() => match command {
                Some(command) => { if let Some((deadline, response)) = driver.handle_command(client, command) { return Next::Shutdown(deadline, response); } }
                None => return Next::Stop,
            }
        }
    }
}

async fn run(
    mut driver: Driver,
    client: AsyncClient,
    mut eventloop: EventLoop,
    mut commands: mpsc::Receiver<Command>,
) {
    loop {
        match next(&mut driver, &client, &mut eventloop, &mut commands).await {
            Next::Stop => return,
            Next::Shutdown(deadline, response) => {
                driver.retire();
                let result = shutdown(
                    &client,
                    &mut eventloop,
                    deadline.remaining(&driver.shared.clock),
                )
                .await;
                if let Err(error) = result {
                    driver.fail(error);
                }
                let _ = response.send(result);
                return;
            }
            Next::Event(Ok(event)) => {
                if let Err(error) = driver
                    .event(&client, event)
                    .and_then(|()| driver.check_subscription())
                {
                    if error == MqttError::BrokerBusy {
                        driver.retire();
                        eventloop.clean();
                        driver.reconnecting(error);
                        if !driver.reconnect.wait(&driver.shared.cancelled).await {
                            return;
                        }
                    } else {
                        driver.fail(error);
                        return;
                    }
                }
            }
            Next::Event(Err(error)) => {
                driver.retire();
                let (cause, retryable) = connection_failure(error);
                if !retryable {
                    driver.fail(cause);
                    return;
                }
                driver.reconnecting(cause);
                if !driver.reconnect.wait(&driver.shared.cancelled).await {
                    return;
                }
            }
            Next::Retire => {
                driver.retire();
                eventloop.clean();
                driver.reconnecting(MqttError::SettlementUnknown);
            }
        }
    }
}
fn connection_failure(error: ConnectionError) -> (MqttError, bool) {
    use rumqttc::{StateError, TlsError};
    match error {
        ConnectionError::SessionStore(_) => (MqttError::SessionStore, false),
        ConnectionError::SessionRestore(_) | ConnectionError::SessionStateMismatch { .. } => {
            (MqttError::SessionState, false)
        }
        ConnectionError::ConnectionRefused(reason) => connack_failure(reason),
        ConnectionError::Io(_) | ConnectionError::Timeout(_) => (MqttError::ConnectionLost, true),
        ConnectionError::MqttState(StateError::Deserialization(rumqttc::mqttbytes::Error::Io(
            _,
        ))) => (MqttError::ConnectionLost, true),
        ConnectionError::Tls(TlsError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::TimedOut
            ) =>
        {
            (MqttError::ConnectionLost, true)
        }
        ConnectionError::MqttState(
            StateError::Io(_)
            | StateError::AwaitPingResp
            | StateError::ConnectionAborted
            | StateError::CollisionTimeout,
        ) => (MqttError::ConnectionLost, true),
        ConnectionError::MqttState(StateError::ServerDisconnect { reason_code, .. }) => {
            use rumqttc::mqttbytes::v5::DisconnectReasonCode::*;
            match reason_code {
                NormalDisconnection
                | ServerBusy
                | ServerShuttingDown
                | KeepAliveTimeout
                | ConnectionRateExceeded => (MqttError::ConnectionLost, true),
                NotAuthorized => (MqttError::Authentication, false),
                _ => (MqttError::Protocol, false),
            }
        }
        ConnectionError::Tls(_) => (MqttError::Unavailable, false),
        _ => (MqttError::Protocol, false),
    }
}
fn connack_failure(reason: rumqttc::mqttbytes::v5::ConnectReturnCode) -> (MqttError, bool) {
    use rumqttc::mqttbytes::v5::ConnectReturnCode::*;
    match reason {
        ServiceUnavailable
        | ServerUnavailable
        | ServerBusy
        | QuotaExceeded
        | ConnectionRateExceeded
        | UnspecifiedError
        | ImplementationSpecificError => (MqttError::BrokerBusy, true),
        BadUserNamePassword | NotAuthorized | Banned | BadAuthenticationMethod => {
            (MqttError::Authentication, false)
        }
        _ => (MqttError::Protocol, false),
    }
}
async fn shutdown(
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    budget: Duration,
) -> Result<(), MqttError> {
    tokio::time::timeout(budget, async {
        client
            .try_disconnect_with_timeout(budget)
            .map_err(|_| MqttError::Unavailable)?;
        loop {
            match eventloop.poll().await {
                Ok(Event::Outgoing(Outgoing::Disconnect)) => return Ok(()),
                Ok(_) => {}
                Err(ConnectionError::DisconnectTimeout) => return Err(MqttError::DeadlineElapsed),
                Err(error) => return Err(connection_failure(error).0),
            }
        }
    })
    .await
    .map_err(|_| MqttError::DeadlineElapsed)?
}
