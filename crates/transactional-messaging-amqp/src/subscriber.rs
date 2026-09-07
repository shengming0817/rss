//! Private subscriber transport shared by the public delivery handle and unique resource owner.
//!
//! `basic_consume` 的 `Consumer`（`Stream<Item = Result<Delivery>>`）适配成 canonical incoming delivery stream；
//! settlement authority 随 delivery move（manual-ack）。
//! P7 manual-ack：`no_ack=false` + `basic_qos(PREFETCH)`，每条 [`rss_transactional_messaging::transport::Delivery`] 携 [`AmqpSettlement`] 句柄。
//! AMQP 仅 at-least-once（manual-ack）：经 `DeliverySource::deliveries`；
//! Provider-neutral delivery doubles live in `rss-transactional-messaging-testkit`.
//! ref: lapin examples/pubsub.rs@main；rabbitmq docs/confirms。

mod close;
use close::{OwnedSubscription, SettlementPermit, SubscriptionClose};

use std::sync::Arc;
use std::time::Duration;

use crate::shutdown::{ShutdownFailures, ShutdownStage};
use crate::{AmqpShutdownError, AmqpShutdownErrorKind};
use futures::StreamExt;
use lapin::message::Delivery;
use lapin::options::{
    BasicAckOptions, BasicCancelOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions,
};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{Channel, Connection};
use rss_redact::RedactedSource;
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageId, MessageMetadata,
    MessageMetadataExtensions, MessageRoute, MessagingDomain, PartitionKey, SubscriptionIdentity,
    TransportContext,
};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging::transaction::{EnvelopeValidationFailure, SettlementDecision};
use rss_transactional_messaging::transport::{
    Delivery as CoreDelivery, DeliverySettlement, DeliverySource, IncomingDelivery,
    ManagedDeliveryStream,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::conn::{self, REPLY_SUCCESS};
use crate::settle::{SettleMode, settle_mode};

#[derive(Debug, thiserror::Error)]
#[error("amqp subscription failed")]
struct SubscriberError {
    kind: MessagingErrorKind,
    #[source]
    source: RedactedSource,
}

impl SubscriberError {
    fn new(source: lapin::Error) -> Self {
        Self::classified(conn::transport_error_kind(&source), source)
    }
    fn classified<E: std::error::Error + Send + Sync + 'static>(
        kind: MessagingErrorKind,
        source: E,
    ) -> Self {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }
    fn into_messaging(self) -> MessagingError {
        MessagingError::new(self.kind, self)
    }
}

/// channel 上最多 unacked 消息上限（限 channel 级 unacked window；at-least-once 背压）。
/// 取值依据：RabbitMQ 推荐 100–300（ref: rabbitmq docs/confirms §prefetch / consumer-prefetch）。
// ConsumerTx is deliberately sequential. A window of one prevents a second delivery from becoming
// in-flight while the first transaction is blocked during graceful shutdown.
const PREFETCH: u16 = 1;

fn validate_queue_name(name: &str) -> Result<(), SubscriberError> {
    if name.is_empty() || name.len() > 255 {
        return Err(invalid_queue("AMQP queue name must contain 1..=255 bytes"));
    }
    Ok(())
}

fn invalid_queue(message: &'static str) -> SubscriberError {
    SubscriberError::classified(
        MessagingErrorKind::Permanent,
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message),
    )
}

/// AMQP 事件订阅 adapter（lapin）。raw `Arc<Connection>` **私有**——仅本 adapter 内部使用，不向 crate 内
/// 其它模块暴露 raw 连接。公开 port 与唯一 resource owner 分别持有同源句柄。
///
/// **每订阅独立 channel**（review #274 F4/C4）：`deliveries` 每次从 `conn` 新开一个 channel 承载该
/// 订阅，token cancel 只对**本订阅** consumer 执行 `basic.cancel`，不连带终止同实例其它
/// topic 的 consumer；subscriber 级 shutdown 关闭整个 `conn`（其下所有订阅 channel 随之关闭）。
pub(crate) struct SubscriberInner {
    endpoint: crate::endpoint::Endpoint,
    trust: conn::AmqpTlsTrust,
    recovery_timeout: Duration,
    recovery: tokio::sync::Mutex<()>,
    lifecycle: std::sync::Mutex<SubscriberLifecycle>,
    shutdown: CancellationToken,
    name: String,
    #[cfg(feature = "test-support")]
    registration_pause: std::sync::Mutex<Option<conn::TestPause>>,
    #[cfg(feature = "test-support")]
    recovery_pause: std::sync::Mutex<Option<conn::TestPause>>,
}

struct SubscriberLifecycle {
    connection: Arc<Connection>,
    generation: u64,
    closed: bool,
    cancellation_tasks: Vec<OwnedSubscription>,
}

impl SubscriberInner {
    /// Test-only default-root connection seam. Production accepts only exclusive private CA trust.
    #[cfg(feature = "test-support")]
    pub async fn connect_with_webpki_for_test(
        endpoint: &crate::endpoint::Endpoint,
        name: impl Into<String>,
        recovery_timeout: Duration,
    ) -> Result<Self, conn::AmqpConnectError> {
        conn::validate_recovery_timeout(recovery_timeout)
            .map_err(|_| conn::invalid_recovery_timeout())?;
        let name = name.into();
        let (connection, _channel) =
            conn::connect_with_webpki_for_test(endpoint, &name, false).await?;
        Ok(Self::from_connection(
            connection,
            endpoint,
            name,
            recovery_timeout,
            conn::AmqpTlsTrust::WebPki,
        ))
    }

    pub(crate) async fn connect_with_private_ca(
        endpoint: &crate::endpoint::Endpoint,
        name: impl Into<String>,
        ca: &conn::AmqpPrivateCa,
        recovery_timeout: Duration,
    ) -> Result<Self, conn::AmqpConnectError> {
        conn::validate_recovery_timeout(recovery_timeout)
            .map_err(|_| conn::invalid_recovery_timeout())?;
        let name = name.into();
        let (connection, _channel) =
            conn::connect_with_private_ca(endpoint, &name, false, ca).await?;
        Ok(Self::from_connection(
            connection,
            endpoint,
            name,
            recovery_timeout,
            conn::AmqpTlsTrust::PrivateCa(ca.clone()),
        ))
    }

    fn from_connection(
        connection: Arc<Connection>,
        endpoint: &crate::endpoint::Endpoint,
        name: String,
        recovery_timeout: Duration,
        trust: conn::AmqpTlsTrust,
    ) -> Self {
        Self {
            endpoint: endpoint.clone(),
            trust,
            recovery_timeout,
            recovery: tokio::sync::Mutex::new(()),
            lifecycle: std::sync::Mutex::new(SubscriberLifecycle {
                connection,
                generation: 1,
                closed: false,
                cancellation_tasks: Vec::new(),
            }),
            shutdown: CancellationToken::new(),
            name,
            #[cfg(feature = "test-support")]
            registration_pause: std::sync::Mutex::new(None),
            #[cfg(feature = "test-support")]
            recovery_pause: std::sync::Mutex::new(None),
        }
    }

    fn connection_snapshot(&self) -> Result<(Arc<Connection>, u64), SubscriberError> {
        let lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lifecycle.closed {
            return Err(closed_subscriber());
        }
        Ok((Arc::clone(&lifecycle.connection), lifecycle.generation))
    }

    /// One bounded call owns lock wait, authentication and installation. The runtime owns retry
    /// backoff; no detached reconnect loop can survive cancellation or resource shutdown.
    async fn connection(&self) -> Result<Arc<Connection>, SubscriberError> {
        let (current, _) = self.connection_snapshot()?;
        if current.status().connected() {
            return Ok(current);
        }
        tokio::select! {
            biased;
            () = self.shutdown.cancelled() => Err(closed_subscriber()),
            result = tokio::time::timeout(self.recovery_timeout, self.replace_connection()) => result.map_err(|error| SubscriberError::classified(MessagingErrorKind::DeadlineElapsed, error))?,
        }
    }

    async fn replace_connection(&self) -> Result<Arc<Connection>, SubscriberError> {
        let _recovery = self.recovery.lock().await;
        let (current, generation) = self.connection_snapshot()?;
        if current.status().connected() {
            return Ok(current);
        }
        let (replacement, _channel) =
            conn::reconnect_subscriber(&self.endpoint, &self.name, generation, &self.trust)
                .await
                .map_err(|error| SubscriberError::classified(error.kind(), error))?;
        let cleanup = conn::OnDrop::new(|| conn::close_connection_now(&replacement));
        #[cfg(feature = "test-support")]
        {
            let pause = self
                .recovery_pause
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(pause) = pause {
                pause.wait().await;
            }
        }
        {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if lifecycle.closed {
                return Err(closed_subscriber());
            }
            lifecycle.connection = Arc::clone(&replacement);
            lifecycle.generation = generation.saturating_add(1);
        }
        cleanup.disarm();
        Ok(replacement)
    }
}

impl SubscriberInner {
    #[cfg(feature = "managed-runtime")]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn request_shutdown(&self) {
        let (connection, tasks) = self.close_admission();
        self.shutdown.cancel();
        conn::close_connection_now(&connection);
        drop(tasks);
    }

    pub(crate) async fn shutdown(&self) -> Result<(), AmqpShutdownError> {
        let (connection, tasks) = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if lifecycle.closed {
                return Err(AmqpShutdownError::classified(
                    AmqpShutdownErrorKind::AlreadyStarted,
                ));
            }
            lifecycle.closed = true;
            (
                Arc::clone(&lifecycle.connection),
                std::mem::take(&mut lifecycle.cancellation_tasks),
            )
        };
        self.shutdown.cancel();
        let close_on_cancel = conn::OnDrop::new(|| conn::close_connection_now(&connection));
        // Finish basic.cancel/cancel-ok while the channels are still Connected. Lapin marks
        // all channels Closing when connection.close starts; racing the two RPCs can fail both.
        // The outer total budget and guard still force retirement if a cancellation gets stuck.
        let mut failures = ShutdownFailures::default();
        for task in tasks {
            failures.record_subscription(&self.name, task.wait().await);
        }
        let result = if connection.status().connected() {
            connection
                .close(REPLY_SUCCESS, "subscriber resource shutdown".into())
                .await
                .map_err(AmqpShutdownError::operation)
        } else {
            Ok(())
        };
        close_on_cancel.disarm_on_success(&result);
        failures.record(&self.name, ShutdownStage::TransportClose, result);
        failures.finish()
    }
}

const KEY_OCCURRED_AT: &str = "occurredAt";

/// AMQP [`lapin::BasicProperties`] → authored metadata attributes（adapter 透传路径）。
/// - typed `timestamp` 是 `occurredAt` 的唯一来源（unix 秒，十进制 string）。
/// - 同名 `occurredAt` header 无条件忽略；缺失或越界 timestamp 由解码器拒绝。
/// - transport-safe `headers` LongString pair → metadata pair（LongString 以 utf8_lossy Display 转 string）。
/// - 非 LongString header 值跳过（不是本 adapter `build_properties` 产出的；透传外部生产者时静默忽略）。
///
/// Pure metadata projection using the normally compiled lapin types; no broker I/O.
fn extract_metadata(props: &lapin::BasicProperties) -> std::collections::BTreeMap<String, String> {
    let mut metadata = std::collections::BTreeMap::new();
    if let Some(timestamp) = props.timestamp() {
        metadata.insert(KEY_OCCURRED_AT.to_owned(), timestamp.to_string());
    }
    if let Some(table) = props.headers() {
        for (k, v) in table.inner() {
            if k.as_str() == KEY_OCCURRED_AT {
                continue;
            }
            if let AMQPValue::LongString(ls) = v {
                metadata.insert(k.to_string(), ls.to_string());
            }
        }
    }
    metadata
}

/// lapin `Delivery` → `rss_transactional_messaging::transport::Delivery`（携 [`AmqpSettlement`] 结算句柄 + envelope metadata）。
/// 先取出 `acker`（lapin `Acker` 是 Arc handle，cheap clone）再 move `data`/`properties` 构造 Message，
/// 避免借用冲突。clone 出的句柄随 `Delivery` owned 交给 driver——driver 须保证最终只一方 settle
/// （settle-once；二次 settle 在 lapin 层返 Err，由调用方处理失败，不 panic）。
fn delivery_to_core(
    delivery: Delivery,
    permit: SettlementPermit,
    subscription_rpc: Arc<SubscriptionRpc>,
    subscription: &SubscriptionIdentity,
) -> IncomingDelivery<Vec<u8>, AmqpSettlement> {
    let acker = delivery.acker.clone();
    let producer_id = delivery
        .properties
        .message_id()
        .as_ref()
        .map(ToString::to_string);
    let broker_route = delivery.routing_key.to_string();
    let metadata = extract_metadata(&delivery.properties);
    let settlement = AmqpSettlement {
        settled: false,
        #[cfg(feature = "test-support")]
        pause: None,
        inner: acker,
        _permit: permit,
        subscription_rpc,
    };
    match decode_message(
        producer_id.as_deref().unwrap_or_default(),
        delivery.data,
        metadata,
        subscription,
        &broker_route,
    ) {
        Ok(message) => IncomingDelivery::Valid(Box::new(CoreDelivery::new(message, settlement))),
        Err(failure) => IncomingDelivery::invalid_from_provider(failure, settlement),
    }
}

fn decode_message(
    id: &str,
    payload: Vec<u8>,
    mut headers: std::collections::BTreeMap<String, String>,
    subscription: &SubscriptionIdentity,
    broker_route: &str,
) -> Result<MessageEnvelope<Vec<u8>>, EnvelopeValidationFailure> {
    let message_id =
        MessageId::parse(id).map_err(|_| EnvelopeValidationFailure::MalformedIdentity)?;
    let tenant_id = rss_request_context::TenantId::parse(&take_required(&mut headers, "tenantId")?)
        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
    let occurred_at = take_required(&mut headers, KEY_OCCURRED_AT)?
        .parse::<i64>()
        .ok()
        .and_then(|value| rss_contract::Timepoint::try_from(value).ok())
        .ok_or(EnvelopeValidationFailure::MalformedMetadata)?;
    let correlation = headers
        .remove("correlation")
        .map(|value| rss_diag_context::CorrelationId::parse(&value))
        .transpose()
        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
    let domain = MessagingDomain::parse(&take_required(&mut headers, "domain")?)
        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
    let route = MessageRoute::parse(&take_required(&mut headers, "route")?)
        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
    let contract = ContractIdentity::new(
        rss_contract::ContractId::parse(&take_required(&mut headers, "contractId")?)
            .map_err(|_| EnvelopeValidationFailure::UnsupportedContract)?,
        rss_contract::ContractVersion::parse(&take_required(&mut headers, "schemaVersion")?)
            .map_err(|_| EnvelopeValidationFailure::UnsupportedContract)?,
        rss_contract::SchemaDigest::parse(&take_required(&mut headers, "schemaHash")?)
            .map_err(|_| EnvelopeValidationFailure::UnsupportedContract)?,
    );
    let partition = decode_partition(&mut headers)?;
    let causation = headers
        .remove("causationId")
        .map(|value| MessageId::parse(&value))
        .transpose()
        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
    let trace = headers.remove("trace");
    let tenant_authority = headers.remove("tenantAuthority");
    let attributes = headers
        .into_iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("attribute.")
                .map(|key| (key.to_owned(), value))
        })
        .collect();
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(tenant_id, occurred_at, domain, route, contract),
        MessageMetadataExtensions::new(correlation, partition, causation, attributes),
    );
    let message = MessageEnvelope::new(message_id, metadata, payload)
        .with_transport_context(TransportContext::new(trace, tenant_authority));
    if broker_route != subscription.route().as_str() || !subscription.accepts(&message) {
        return Err(EnvelopeValidationFailure::UnsupportedContract);
    }
    Ok(message)
}

fn take_required(
    headers: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<String, EnvelopeValidationFailure> {
    headers
        .remove(key)
        .filter(|value| !value.is_empty())
        .ok_or(EnvelopeValidationFailure::MalformedMetadata)
}

fn decode_partition(
    headers: &mut std::collections::BTreeMap<String, String>,
) -> Result<Option<PartitionKey>, EnvelopeValidationFailure> {
    let tenant = headers.remove("partitionTenantId");
    let domain = headers.remove("partitionDomain");
    let key = headers.remove("partitionKey");
    match (tenant, domain, key) {
        (None, None, None) => Ok(None),
        (None, None, Some(key)) => {
            Ok(Some(PartitionKey::parse(&key).map_err(|_| {
                EnvelopeValidationFailure::MalformedMetadata
            })?))
        }
        _ => Err(EnvelopeValidationFailure::MalformedMetadata),
    }
}

// ── AmqpSettlement（impl rss_transactional_messaging::transport::DeliverySettlement）──────────────────────────────────────────

/// lapin broker 结算句柄的 adapter 包装（impl [`rss_transactional_messaging::transport::DeliverySettlement`]）。
///
/// The pure `crate::settle` mapping selects lapin ACK/NACK for the normally compiled transport.
/// Provider errors cross the port only through the redacted `MessagingError` boundary.
pub struct AmqpSettlement {
    settled: bool,
    #[cfg(feature = "test-support")]
    pause: Option<conn::TestPause>,
    inner: lapin::Acker,
    _permit: SettlementPermit,
    subscription_rpc: Arc<SubscriptionRpc>,
}

pub type AmqpDeliveries = std::pin::Pin<
    Box<dyn futures::Stream<Item = IncomingDelivery<Vec<u8>, AmqpSettlement>> + Send>,
>;

// A managed stream owns only its own admission token. Dropping it starts basic.cancel while
// an already delivered settlement remains usable behind the same cancellation barrier.
struct ActiveSubscription(CancellationToken);
impl Drop for ActiveSubscription {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Serializes one subscription channel's cancel and settlement RPCs while giving an already
/// requested cancellation priority. The prefetch window stays closed until the broker confirms
/// `basic.cancel`; only then may an in-flight delivery settle and reopen that window.
struct SubscriptionRpc {
    gate: tokio::sync::Mutex<()>,
    cancel_requested: CancellationToken,
    admission_stopped: CancellationToken,
    closing: SubscriptionClose,
    #[cfg(feature = "test-support")]
    cancel_pause: std::sync::Mutex<Option<conn::TestPause>>,
}

impl SubscriptionRpc {
    async fn settlement_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        let guard = self.gate.lock().await;
        if self.cancel_requested.is_cancelled() && !self.admission_stopped.is_cancelled() {
            drop(guard);
            self.admission_stopped.cancelled().await;
            self.gate.lock().await
        } else {
            guard
        }
    }
}

async fn run_subscription_close(
    rpc: &SubscriptionRpc,
    channel: &Channel,
    consumer_tag: String,
    shutdown: &CancellationToken,
    resource: &str,
) {
    await_subscription_stop(rpc).await;
    rpc.cancel_requested.cancel();
    rpc.closing.seal();
    stop_subscription_admission(rpc, channel, consumer_tag, resource).await;
    // Normal stream cancellation preserves admitted settlement authority. Abandonment or
    // resource shutdown retires it; every path still awaits the same channel-close receipt.
    await_settlement_retirement(rpc, shutdown).await;
    let result = rpc.closing.drive().await;
    ShutdownFailures::report_subscription_close(resource, &result);
}

async fn await_subscription_stop(rpc: &SubscriptionRpc) {
    tokio::select! {
        () = rpc.cancel_requested.cancelled() => {},
        () = rpc.closing.requested.cancelled() => {},
    }
}

async fn stop_subscription_admission(
    rpc: &SubscriptionRpc,
    channel: &Channel,
    consumer_tag: String,
    resource: &str,
) {
    #[cfg(feature = "test-support")]
    {
        let pause = rpc
            .cancel_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(pause) = pause {
            pause.wait().await;
        }
    }
    {
        let _gate = rpc.gate.lock().await;
        if let Err(error) = channel
            .basic_cancel(consumer_tag.into(), BasicCancelOptions::default())
            .await
        {
            crate::conn_events::emit_subscription_cancel_failed(
                resource,
                crate::conn::amqp_failure_reason(&error),
            );
            rpc.closing.requested.cancel();
        }
        rpc.admission_stopped.cancel();
    }
}

async fn await_settlement_retirement(rpc: &SubscriptionRpc, shutdown: &CancellationToken) {
    tokio::select! {
        () = rpc.closing.drained() => {},
        () = rpc.closing.requested.cancelled() => {},
        () = shutdown.cancelled() => {},
    }
}

#[cfg(feature = "test-support")]
impl AmqpSettlement {
    /// Pause the managed cancel RPC before it takes the subscription gate.
    /// Requests the real cancellation token while retaining the stream and its lapin consumer.
    pub fn pause_subscription_cancel_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (pause, entered, resume) = conn::TestPause::new();
        *self
            .subscription_rpc
            .cancel_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pause);
        self.subscription_rpc.cancel_requested.cancel();
        (entered, resume)
    }

    /// Pause the uniquely driven channel close after cancellation has finished.
    pub fn pause_subscription_close_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.subscription_rpc.closing.pause()
    }

    /// Pause this delivery before its one-shot broker decision, within the actual watchdog.
    pub fn pause_before_settlement_for_test(
        &mut self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (pause, entered, resume) = conn::TestPause::new();
        self.pause = Some(pause);
        (entered, resume)
    }
}

impl DeliverySettlement for AmqpSettlement {
    async fn settle(
        mut self,
        decision: SettlementDecision,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        if deadline.timeout().is_zero() {
            return Err(MessagingError::new(
                MessagingErrorKind::DeadlineElapsed,
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "AMQP settlement deadline elapsed before admission",
                ),
            ));
        }
        // If cancellation was requested before settlement acquires the gate, wait for cancel-ok
        // (or the failure-path channel close) before Ack/Nack can reopen the prefetch window. A
        // settlement already holding the gate remains linearized before cancellation.
        let result = tokio::time::timeout(deadline.timeout(), async {
            let _rpc = self.subscription_rpc.settlement_guard().await;
            #[cfg(feature = "test-support")]
            if let Some(pause) = self.pause.take() {
                pause.wait().await;
            }
            match settle_mode(decision.kind()) {
                SettleMode::Ack => self.inner.ack(BasicAckOptions::default()).await,
                SettleMode::Nack { requeue } => {
                    self.inner
                        .nack(BasicNackOptions {
                            multiple: false,
                            requeue,
                        })
                        .await
                }
            }
        })
        .await;
        match result {
            Ok(Ok(_)) => {
                self.settled = true;
                Ok(())
            }
            Ok(Err(error)) => {
                let error = MessagingError::new(MessagingErrorKind::Transient, error);
                self.subscription_rpc.closing.requested.cancel();
                Err(error)
            }
            Err(error) => {
                self.subscription_rpc.closing.requested.cancel();
                Err(MessagingError::new(MessagingErrorKind::Transient, error))
            }
        }
    }

    async fn abandon(self, deadline: OperationDeadline) -> Result<(), MessagingError> {
        let closing = self.subscription_rpc.closing.clone();
        closing.requested.cancel();
        drop(self);
        tokio::time::timeout(deadline.timeout(), closing.wait())
            .await
            .map_err(|error| MessagingError::new(MessagingErrorKind::DeadlineElapsed, error))?
            .map_err(|error| MessagingError::new(MessagingErrorKind::Transient, error))
    }
}

impl Drop for AmqpSettlement {
    fn drop(&mut self) {
        if !self.settled {
            self.subscription_rpc.closing.requested.cancel();
        }
    }
}

// ── impl DeliverySource for SubscriberInner（P7 manual-ack）──────────────

impl SubscriberInner {
    async fn delivery_stream(
        &self,
        subscription: &SubscriptionIdentity,
        token: CancellationToken,
    ) -> Result<AmqpDeliveries, SubscriberError> {
        self.ensure_operational()?;
        let topic = subscription.route();
        let topic_name = topic.as_str();
        validate_queue_name(topic_name)?;
        // 稳定 consumer tag（按 name+topic 派生）：重连/重订阅复用同一 tag，不变成新消费者
        // topic 来自 messaging core 的 SubscriptionIdentity，具体订阅由消费方配置。
        let consumer_tag = format!("{}-ack-{}", self.name, topic_name);
        // 每订阅独立 channel（review #274 F4/C4）：token cancel 只停止本 channel 的 consumer，
        // 不连带停掉同 subscriber 其它 topic 的 consumer。
        let connection = self.connection().await?;
        let channel = connection
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        let cleanup = conn::OnDrop::new(|| conn::close_channel_now(&channel));
        // prefetch：限 channel 上 unacked 消息上限（P7 at-least-once 背压，RabbitMQ 推荐 100–300）。
        channel
            .basic_qos(PREFETCH, BasicQosOptions::default())
            .await
            .map_err(SubscriberError::new)?;
        // Queue, bindings and policies are provisioned externally. basic.consume fails closed
        // when the exact queue is absent; this credential needs only read authority.
        let consumer = channel
            .basic_consume(
                topic_name.into(),
                consumer_tag.as_str().into(),
                // P7: no_ack=false（manual-ack，at-least-once）——消费者须 settle 每条 Delivery。
                BasicConsumeOptions {
                    no_ack: false,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(SubscriberError::new)?;
        #[cfg(feature = "test-support")]
        {
            let pause = self
                .registration_pause
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(pause) = pause {
                pause.wait().await;
            }
        }
        // Consumer → Delivery（携 acker）。take_until 在 token cancel 后以同一稳定 tag 等待
        // broker 确认 basic.cancel，再终止流；channel 保持打开，让 in-flight acker 继续 settle。
        // Drive admission cancellation independently from stream polling. ConsumerTx processes one
        // delivery at a time and may be blocked in its PG transaction when shutdown begins.
        let admission_stopped = CancellationToken::new();
        let cancel_confirmation = admission_stopped.clone();
        let close_channel = channel.clone();
        let closing =
            SubscriptionClose::new(async move { close::close_channel(&close_channel).await });
        let subscription_rpc = Arc::new(SubscriptionRpc {
            gate: tokio::sync::Mutex::new(()),
            cancel_requested: token.clone(),
            admission_stopped,
            closing: closing.clone(),
            #[cfg(feature = "test-support")]
            cancel_pause: std::sync::Mutex::new(None),
        });
        {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if lifecycle.closed {
                return Err(closed_subscriber());
            }
            let rpc = Arc::clone(&subscription_rpc);
            let cancel_channel = channel.clone();
            let retained_consumer = consumer.clone();
            let shutdown = self.shutdown.clone();
            let resource = self.name.clone();
            let abort_channel = channel.clone();
            let abort_cleanup = conn::OnDrop::new(move || conn::close_channel_now(&abort_channel));
            let task = AbortOnDropHandle::new(tokio::spawn(async move {
                let abort_cleanup = abort_cleanup;
                run_subscription_close(&rpc, &cancel_channel, consumer_tag, &shutdown, &resource)
                    .await;
                // Retain lapin's external canceler/closer until the explicit close receipt exists.
                drop(retained_consumer);
                abort_cleanup.disarm();
            }));
            lifecycle
                .cancellation_tasks
                .retain_mut(|task| !task.observed_finished());
            lifecycle
                .cancellation_tasks
                .push(OwnedSubscription { task, closing });
        }
        cleanup.disarm();
        let delivery_rpc = Arc::clone(&subscription_rpc);
        let delivery_subscription = subscription.clone();
        let delivery_resource: Arc<str> = Arc::from(self.name.as_str());
        // A delivery can already be buffered client-side when token cancellation races the
        // in-flight Ack that reopens the prefetch window. Once cancellation is requested, never
        // expose that raced delivery to ConsumerTx. Dropping it leaves it unsettled; the later
        // subscriber channel shutdown requeues it for the replacement consumer.
        let stream = consumer
            .filter_map(move |res| {
                let delivery_rpc = Arc::clone(&delivery_rpc);
                let delivery_subscription = delivery_subscription.clone();
                let delivery_resource = delivery_resource.clone();
                async move {
                    match res {
                        Ok(delivery) => delivery_rpc
                            .closing
                            .acquire(&delivery_rpc.cancel_requested)
                            .map(|permit| {
                                delivery_to_core(
                                    delivery,
                                    permit,
                                    delivery_rpc,
                                    &delivery_subscription,
                                )
                            }),
                        Err(error) => {
                            crate::conn_events::emit_delivery_failed(
                                &delivery_resource,
                                delivery_subscription.route().as_str(),
                                crate::conn::amqp_failure_reason(&error),
                            );
                            None
                        }
                    }
                }
            })
            .take_until(async move {
                cancel_confirmation.cancelled().await;
            });
        tracing::info!(target: "amqp", resource = %self.name, topic = topic_name, "amqp delivery source started");
        let guard = ActiveSubscription(subscription_rpc.cancel_requested.clone());
        Ok(Box::pin(futures::stream::unfold(
            (Box::pin(stream), guard),
            |(mut stream, guard)| async move { stream.next().await.map(|item| (item, (stream, guard))) },
        )))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause_registration(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (pause, entered, resume) = conn::TestPause::new();
        *self
            .registration_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pause);
        (entered, resume)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause_recovery(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (pause, entered, resume) = conn::TestPause::new();
        *self
            .recovery_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pause);
        (entered, resume)
    }

    fn close_admission(&self) -> (Arc<Connection>, Vec<OwnedSubscription>) {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lifecycle.closed = true;
        (
            Arc::clone(&lifecycle.connection),
            std::mem::take(&mut lifecycle.cancellation_tasks),
        )
    }

    fn ensure_operational(&self) -> Result<(), SubscriberError> {
        if !self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
        {
            return Ok(());
        }
        Err(closed_subscriber())
    }
}

fn closed_subscriber() -> SubscriberError {
    SubscriberError::classified(
        MessagingErrorKind::Permanent,
        std::io::Error::other("AMQP subscriber resource is closed"),
    )
}

impl DeliverySource<Vec<u8>> for SubscriberInner {
    type Settlement = AmqpSettlement;
    type Deliveries = AmqpDeliveries;

    async fn deliveries(
        &self,
        subscription: &SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        self.delivery_stream(subscription, self.shutdown.child_token())
            .await
            .map(ManagedDeliveryStream::from_provider)
            .map_err(SubscriberError::into_messaging)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::type_complexity)]

    use super::decode_message;

    #[test]
    fn typed_timestamp_is_the_only_occurrence_time_source() {
        use lapin::types::{AMQPValue, FieldTable};
        use rss_transactional_messaging::message::{
            ContractIdentity, MessageRoute, MessagingDomain, SubscriptionIdentity,
        };
        use rss_transactional_messaging::transaction::EnvelopeValidationFailure;

        let subscription = SubscriptionIdentity::new(
            MessagingDomain::parse("runtime").expect("domain"),
            MessageRoute::parse("runtime.message").expect("route"),
            ContractIdentity::new(
                rss_contract::ContractId::parse("runtime.message").expect("contract"),
                rss_contract::ContractVersion::from_major(1).expect("version"),
                rss_contract::SchemaDigest::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("schema"),
            ),
        );
        for timestamp in [
            None,
            Some(0),
            Some(42),
            Some(i64::MAX as u64),
            Some(u64::MAX),
        ] {
            for header in [
                None,
                Some(AMQPValue::LongString("7".into())),
                Some(AMQPValue::LongString("invalid".into())),
                Some(AMQPValue::LongLongInt(7)),
            ] {
                let mut table = FieldTable::default();
                for (key, value) in [
                    ("tenantId", "00000000-0000-0000-0000-000000000001"),
                    ("domain", "runtime"),
                    ("route", "runtime.message"),
                    ("contractId", "runtime.message"),
                    ("schemaVersion", "v1"),
                    (
                        "schemaHash",
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ),
                    ("attribute.source", "device"),
                ] {
                    table.insert(key.into(), AMQPValue::LongString(value.into()));
                }
                table.insert("attribute.numeric".into(), AMQPValue::LongLongInt(7));
                if let Some(header) = header {
                    table.insert(super::KEY_OCCURRED_AT.into(), header);
                }
                let mut props = lapin::BasicProperties::default().with_headers(table);
                if let Some(timestamp) = timestamp {
                    props = props.with_timestamp(timestamp);
                }
                let metadata = super::extract_metadata(&props);
                assert_eq!(
                    metadata.get("occurredAt"),
                    timestamp.map(|t| t.to_string()).as_ref()
                );
                assert_eq!(
                    metadata.get("attribute.source").map(String::as_str),
                    Some("device")
                );
                assert!(!metadata.contains_key("attribute.numeric"));
                let message = decode_message(
                    "message-1",
                    Vec::new(),
                    metadata,
                    &subscription,
                    "runtime.message",
                );
                match timestamp.and_then(|value| i64::try_from(value).ok()) {
                    Some(expected) => assert_eq!(
                        message
                            .expect("valid timestamp")
                            .metadata()
                            .occurred_at()
                            .unix_seconds(),
                        expected,
                    ),
                    None => assert!(matches!(
                        message,
                        Err(EnvelopeValidationFailure::MalformedMetadata)
                    )),
                }
            }
        }
    }

    #[test]
    fn subscription_errors_preserve_non_retryable_classification() {
        use rss_transactional_messaging::error::MessagingErrorKind;
        for (code, expected) in [
            (403, MessagingErrorKind::Permanent),
            (406, MessagingErrorKind::Conflict),
            (320, MessagingErrorKind::Transient),
        ] {
            let protocol = lapin::protocol::AMQPError::from_id(code, "hidden broker text".into())
                .expect("known protocol code");
            let error = super::SubscriberError::new(lapin::Error::from(
                lapin::ErrorKind::ProtocolError(protocol),
            ))
            .into_messaging();
            assert_eq!(error.kind(), expected);
        }
        assert_eq!(
            super::invalid_queue("bad route").into_messaging().kind(),
            MessagingErrorKind::Permanent
        );
    }

    #[test]
    fn queue_names_obey_amqp_short_string_limit() {
        assert!(super::validate_queue_name("").is_err());
        assert!(super::validate_queue_name(&"x".repeat(256)).is_err());
        assert!(super::validate_queue_name(&"x".repeat(255)).is_ok());
    }

    #[test]
    fn missing_message_id_is_rejected_before_metadata_is_trusted() {
        use rss_transactional_messaging::message::{
            ContractIdentity, MessageRoute, MessagingDomain, SubscriptionIdentity,
        };
        use rss_transactional_messaging::transaction::EnvelopeValidationFailure;
        let subscription = SubscriptionIdentity::new(
            MessagingDomain::parse("runtime").expect("domain"),
            MessageRoute::parse("runtime.message").expect("route"),
            ContractIdentity::new(
                rss_contract::ContractId::parse("runtime.message").expect("contract"),
                rss_contract::ContractVersion::from_major(1).expect("version"),
                rss_contract::SchemaDigest::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("schema"),
            ),
        );
        assert!(matches!(
            decode_message(
                "",
                Vec::new(),
                std::collections::BTreeMap::new(),
                &subscription,
                subscription.route().as_str(),
            ),
            Err(EnvelopeValidationFailure::MalformedIdentity)
        ));
    }

    #[test]
    fn broker_route_and_authored_contract_must_match_subscription() {
        use rss_transactional_messaging::message::{
            ContractIdentity, MessageRoute, MessagingDomain, SubscriptionIdentity,
        };
        use rss_transactional_messaging::transaction::EnvelopeValidationFailure;

        let contract = ContractIdentity::new(
            rss_contract::ContractId::parse("runtime.message").expect("contract"),
            rss_contract::ContractVersion::from_major(1).expect("version"),
            rss_contract::SchemaDigest::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("schema"),
        );
        let subscription = SubscriptionIdentity::new(
            MessagingDomain::parse("runtime").expect("domain"),
            MessageRoute::parse("runtime.message").expect("route"),
            contract,
        );
        let headers = || {
            std::collections::BTreeMap::from([
                (
                    "tenantId".to_owned(),
                    "00000000-0000-0000-0000-000000000001".to_owned(),
                ),
                (super::KEY_OCCURRED_AT.to_owned(), "1".to_owned()),
                ("domain".to_owned(), "runtime".to_owned()),
                ("route".to_owned(), "runtime.message".to_owned()),
                ("contractId".to_owned(), "runtime.message".to_owned()),
                ("schemaVersion".to_owned(), "1".to_owned()),
                (
                    "schemaHash".to_owned(),
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                ),
            ])
        };

        assert!(matches!(
            decode_message(
                "message-1",
                Vec::new(),
                headers(),
                &subscription,
                "runtime.other",
            ),
            Err(EnvelopeValidationFailure::UnsupportedContract)
        ));

        let mut mismatched_contract = headers();
        mismatched_contract.insert("contractId".to_owned(), "runtime.other".to_owned());
        assert!(matches!(
            decode_message(
                "message-1",
                Vec::new(),
                mismatched_contract,
                &subscription,
                "runtime.message",
            ),
            Err(EnvelopeValidationFailure::UnsupportedContract)
        ));
    }

    // SettlementKind → broker 结算模式映射的表驱动测试迁至 feature-agnostic `crate::settle`（默认 build 可测、
    // 与默认编译的 lapin I/O 分开验证纯映射。
}

#[cfg(test)]
mod cancellation_tests {
    use super::SubscriptionRpc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn pending_cancel_blocks_settlement_until_cancel_ok() {
        let rpc = SubscriptionRpc {
            gate: tokio::sync::Mutex::new(()),
            cancel_requested: CancellationToken::new(),
            admission_stopped: CancellationToken::new(),
            closing: super::SubscriptionClose::new(async { Ok(()) }),
            #[cfg(feature = "test-support")]
            cancel_pause: std::sync::Mutex::new(None),
        };
        rpc.cancel_requested.cancel();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), rpc.settlement_guard())
                .await
                .is_err()
        );
        rpc.admission_stopped.cancel();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), rpc.settlement_guard())
                .await
                .is_ok()
        );
    }
}
