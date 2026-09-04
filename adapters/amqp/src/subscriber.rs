//! amqp — RSS AMQP 事件订阅 adapter——impl `rss_transactional_messaging::transport::DeliverySource` + `rss_runtime::ManagedResource`。
//!
//! `basic_consume` 的 `Consumer`（`Stream<Item = Result<Delivery>>`）适配成 canonical incoming delivery stream；
//! settlement authority 随 delivery move（manual-ack）。
//! P7 manual-ack：`no_ack=false` + `basic_qos(PREFETCH)`，每条 [`rss_transactional_messaging::transport::Delivery`] 携 [`AmqpSettlement`] 句柄。
//! AMQP 仅 at-least-once（manual-ack）：经 `DeliverySource::deliveries`；
//! at-most-once 仅 demo 拓扑的 MemBus。
//! ref: lapin examples/pubsub.rs@main；rabbitmq docs/confirms。

#[cfg(feature = "integration-test-support")]
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use futures::StreamExt;
use lapin::message::Delivery;
#[cfg(feature = "integration-test-support")]
use lapin::options::QueuePurgeOptions;
use lapin::options::{
    BasicAckOptions, BasicCancelOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions,
    QueueBindOptions, QueueDeclareOptions,
};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{Channel, Connection};
use rss_redact::RedactedSource;
use rss_runtime::{ManagedResource, ShutdownError};
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

use crate::conn::{self, REPLY_SUCCESS};
use crate::settle::{SettleMode, settle_mode};

#[derive(Debug, thiserror::Error)]
#[error("amqp subscription failed")]
struct SubscriberError {
    #[source]
    source: RedactedSource,
}

impl SubscriberError {
    fn new<E: std::error::Error + Send + Sync + 'static>(source: E) -> Self {
        Self {
            source: RedactedSource::new(source),
        }
    }

    fn into_messaging(self) -> MessagingError {
        MessagingError::new(MessagingErrorKind::Transient, self)
    }
}

/// channel 上最多 unacked 消息上限（限 channel 级 unacked window；at-least-once 背压）。
/// 取值依据：RabbitMQ 推荐 100–300（ref: rabbitmq docs/confirms §prefetch / consumer-prefetch）。
// ConsumerTx is deliberately sequential. A window of one prevents a second delivery from becoming
// in-flight while the first transaction is blocked during graceful shutdown.
const PREFETCH: u16 = 1;

/// Broker quarantine is deliberately short-lived and is not the application replay/audit store.
/// The value is an application-owned queue argument, not runtime configuration or broker policy.
const BROKER_DLQ_TTL_MS: u32 = 24 * 60 * 60 * 1_000;
/// Per-topic broker storage is deliberately bounded. 256 MiB admits multiple RabbitMQ
/// maximum-sized messages while preventing one source or plaintext quarantine from consuming an
/// unbounded share of broker disk during a poison flood.
const BROKER_SOURCE_MAX_BYTES: u32 = 256 * 1024 * 1024;
const BROKER_DLQ_MAX_BYTES: u32 = 256 * 1024 * 1024;
const MAX_AMQP_SHORT_STRING_BYTES: usize = 255;
const DEAD_LETTER_QUEUE_SUFFIX: &str = ".dlq";

#[derive(Clone, Copy)]
struct BrokerQueueLimits {
    dead_letter_ttl_ms: u32,
    source_max_bytes: u32,
    dead_letter_max_bytes: u32,
}

impl BrokerQueueLimits {
    const PRODUCTION: Self = Self {
        dead_letter_ttl_ms: BROKER_DLQ_TTL_MS,
        source_max_bytes: BROKER_SOURCE_MAX_BYTES,
        dead_letter_max_bytes: BROKER_DLQ_MAX_BYTES,
    };
}

/// The sole construction funnel for subscriber-owned RabbitMQ queues.
///
/// Private fields prevent callers from declaring a source queue without its quarantine arguments.
/// RabbitMQ enforces argument equivalence on every durable declaration and closes the channel with
/// PRECONDITION_FAILED when an existing queue drifts from this topology.
#[derive(Clone)]
struct BrokerQueueTopology {
    source_queue: String,
    dead_letter_queue: String,
    source_arguments: FieldTable,
    dead_letter_arguments: FieldTable,
}

impl BrokerQueueTopology {
    fn production(topic_name: &str) -> Result<Self, SubscriberError> {
        Self::with_limits(topic_name, BrokerQueueLimits::PRODUCTION)
    }

    fn with_limits(topic_name: &str, limits: BrokerQueueLimits) -> Result<Self, SubscriberError> {
        if topic_name.is_empty()
            || topic_name.ends_with(DEAD_LETTER_QUEUE_SUFFIX)
            || limits.dead_letter_ttl_ms == 0
            || limits.source_max_bytes == 0
            || limits.dead_letter_max_bytes == 0
        {
            return Err(invalid_topology("AMQP broker queue topology is invalid"));
        }
        let dead_letter_queue = format!("{topic_name}{DEAD_LETTER_QUEUE_SUFFIX}");
        if dead_letter_queue.len() > MAX_AMQP_SHORT_STRING_BYTES {
            return Err(invalid_topology("AMQP broker queue name is too long"));
        }

        let mut source_arguments = FieldTable::default();
        source_arguments.insert(
            "x-dead-letter-exchange".into(),
            AMQPValue::LongString(crate::EVENT_EXCHANGE.as_bytes().to_vec().into()),
        );
        source_arguments.insert(
            "x-dead-letter-routing-key".into(),
            AMQPValue::LongString(dead_letter_queue.as_bytes().to_vec().into()),
        );
        insert_queue_string(&mut source_arguments, "x-queue-type", "quorum");
        insert_queue_string(
            &mut source_arguments,
            "x-dead-letter-strategy",
            "at-least-once",
        );
        insert_queue_string(&mut source_arguments, "x-overflow", "reject-publish");
        source_arguments.insert(
            "x-max-length-bytes".into(),
            AMQPValue::LongLongInt(i64::from(limits.source_max_bytes)),
        );
        let mut dead_letter_arguments = FieldTable::default();
        insert_queue_string(&mut dead_letter_arguments, "x-queue-type", "quorum");
        insert_queue_string(&mut dead_letter_arguments, "x-overflow", "reject-publish");
        dead_letter_arguments.insert(
            "x-max-length-bytes".into(),
            AMQPValue::LongLongInt(i64::from(limits.dead_letter_max_bytes)),
        );
        dead_letter_arguments.insert(
            "x-message-ttl".into(),
            AMQPValue::LongUInt(limits.dead_letter_ttl_ms),
        );
        Ok(Self {
            source_queue: topic_name.to_string(),
            dead_letter_queue,
            source_arguments,
            dead_letter_arguments,
        })
    }

    fn source_queue(&self) -> &str {
        &self.source_queue
    }

    fn dead_letter_queue(&self) -> &str {
        &self.dead_letter_queue
    }

    fn source_arguments(&self) -> &FieldTable {
        &self.source_arguments
    }

    fn dead_letter_arguments(&self) -> &FieldTable {
        &self.dead_letter_arguments
    }
}

fn insert_queue_string(arguments: &mut FieldTable, key: &'static str, value: &'static str) {
    arguments.insert(
        key.into(),
        AMQPValue::LongString(value.as_bytes().to_vec().into()),
    );
}

fn invalid_topology(message: &'static str) -> SubscriberError {
    SubscriberError::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerTopologyStage {
    DeclareDeadLetter,
    DeclareSource,
    BindDeadLetter,
    BindSource,
}

impl BrokerTopologyStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DeclareDeadLetter => "declare_dead_letter_queue",
            Self::DeclareSource => "declare_source_queue",
            Self::BindDeadLetter => "bind_dead_letter_queue",
            Self::BindSource => "bind_source_queue",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerTopologyFailureKind {
    Precondition,
    Permission,
    Transport,
    Protocol,
    Client,
}

impl BrokerTopologyFailureKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Precondition => "precondition",
            Self::Permission => "permission",
            Self::Transport => "transport",
            Self::Protocol => "protocol",
            Self::Client => "client",
        }
    }
}

fn classify_topology_failure(error: &lapin::Error) -> BrokerTopologyFailureKind {
    match error.kind() {
        lapin::ErrorKind::ProtocolError(error) => match error.get_id() {
            406 => BrokerTopologyFailureKind::Precondition,
            403 => BrokerTopologyFailureKind::Permission,
            _ => BrokerTopologyFailureKind::Protocol,
        },
        _ if error.is_io_error() => BrokerTopologyFailureKind::Transport,
        _ => BrokerTopologyFailureKind::Client,
    }
}

fn topology_rpc_error(
    resource: &str,
    topology: &BrokerQueueTopology,
    stage: BrokerTopologyStage,
    error: lapin::Error,
) -> SubscriberError {
    let kind = classify_topology_failure(&error);
    tracing::error!(
        target: "amqp",
        resource,
        source_queue = topology.source_queue(),
        dead_letter_queue = topology.dead_letter_queue(),
        stage = stage.as_str(),
        kind = kind.as_str(),
        "amqp broker queue topology declaration failed"
    );
    SubscriberError::new(error)
}

/// AMQP 事件订阅 adapter（lapin）。raw `Arc<Connection>` **私有**——仅本 adapter 内部使用，不向 crate 内
/// 其它模块暴露 raw 连接。impl `DeliverySource` + `ManagedResource`。
///
/// **每订阅独立 channel**（review #274 F4/C4）：`deliveries` 每次从 `conn` 新开一个 channel 承载该
/// 订阅，token cancel 只对**本订阅** consumer 执行 `basic.cancel`，不连带终止同实例其它
/// topic 的 consumer；subscriber 级 shutdown 关闭整个 `conn`（其下所有订阅 channel 随之关闭）。
pub struct AmqpSubscriber {
    conn: Arc<Connection>,
    channels: std::sync::Mutex<Vec<Channel>>,
    operational: AtomicBool,
    active_subscriptions: Arc<AtomicUsize>,
    shutdown: CancellationToken,
    name: String,
    broker_queue_limits: BrokerQueueLimits,
}

impl AmqpSubscriber {
    /// Test-only default-root connection seam. Production builds expose only the private-CA path.
    #[cfg(any(test, feature = "integration-test-support"))]
    pub async fn connect_with_webpki_for_test(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
    ) -> Result<Self, conn::AmqpConnectError> {
        let name = name.into();
        // confirm=false：subscriber 不需 publisher confirms。
        // reason: 订阅 channel 由 deliveries 按需 per-subscription 新开（F4）；connect 借
        // connect helper 拿连接 + redaction 日志，其返回的初始 channel 不用于订阅，drop 即可。
        let (conn, _channel) = conn::connect_with_webpki_for_test(endpoint, &name, false).await?;
        Ok(Self {
            conn,
            channels: std::sync::Mutex::new(Vec::new()),
            operational: AtomicBool::new(true),
            active_subscriptions: Arc::new(AtomicUsize::new(0)),
            shutdown: CancellationToken::new(),
            name,
            broker_queue_limits: BrokerQueueLimits::PRODUCTION,
        })
    }

    /// Integration-only queue-limit override. Production construction always uses the fixed 24h
    /// quarantine and 256 MiB per-queue bounds, with no environment/configuration seam.
    #[cfg(feature = "integration-test-support")]
    pub async fn connect_with_broker_queue_limits_for_test(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
        dead_letter_ttl_ms: NonZeroU32,
        source_max_bytes: NonZeroU32,
        dead_letter_max_bytes: NonZeroU32,
    ) -> Result<Self, conn::AmqpConnectError> {
        let mut subscriber = Self::connect_with_webpki_for_test(endpoint, name).await?;
        subscriber.broker_queue_limits = BrokerQueueLimits {
            dead_letter_ttl_ms: dead_letter_ttl_ms.get(),
            source_max_bytes: source_max_bytes.get(),
            dead_letter_max_bytes: dead_letter_max_bytes.get(),
        };
        Ok(subscriber)
    }

    pub(crate) async fn connect_with_private_ca(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
        ca: &conn::AmqpPrivateCa,
    ) -> Result<Self, conn::AmqpConnectError> {
        let name = name.into();
        let (conn, _channel) = conn::connect_with_private_ca(endpoint, &name, false, ca).await?;
        Ok(Self {
            conn,
            channels: std::sync::Mutex::new(Vec::new()),
            operational: AtomicBool::new(true),
            active_subscriptions: Arc::new(AtomicUsize::new(0)),
            shutdown: CancellationToken::new(),
            name,
            broker_queue_limits: BrokerQueueLimits::PRODUCTION,
        })
    }

    pub(crate) fn readiness_snapshot(&self) -> bool {
        self.operational.load(Ordering::Acquire)
            && self.conn.status().connected()
            && self.active_subscriptions.load(Ordering::Acquire) > 0
            && self.channels.lock().is_ok_and(|channels| {
                !channels.is_empty() && channels.iter().all(|channel| channel.status().connected())
            })
    }

    /// Purge the durable source queue and its derived broker quarantine before an integration run.
    ///
    /// Long-lived test brokers retain durable messages, and closing a manual-ack channel
    /// requeues every unsettled delivery. Fault-injection tests use this typed, test-only seam
    /// before subscribing so a failed prior run cannot enter the next run's ConsumerTx or DLQ
    /// assertions. The return value remains the number removed from the source queue.
    #[cfg(feature = "integration-test-support")]
    pub async fn purge_durable_queue_for_test(
        &self,
        topic: &MessageRoute,
    ) -> Result<u32, MessagingError> {
        self.purge_durable_queue(topic)
            .await
            .map_err(SubscriberError::into_messaging)
    }

    /// Return the broker-observed terminal quarantine depth for one integration-test route.
    #[cfg(feature = "integration-test-support")]
    pub async fn dead_letter_depth_for_test(
        &self,
        topic: &MessageRoute,
    ) -> Result<u32, MessagingError> {
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(|error| SubscriberError::new(error).into_messaging())?;
        let topology = self
            .broker_queue_topology(topic)
            .map_err(SubscriberError::into_messaging)?;
        let depth = declare_broker_queue_topology(&channel, &topology, &self.name)
            .await
            .map_err(SubscriberError::into_messaging)?;
        channel
            .close(REPLY_SUCCESS, "dead-letter depth observed".into())
            .await
            .map_err(|error| SubscriberError::new(error).into_messaging())?;
        Ok(depth)
    }

    #[cfg(feature = "integration-test-support")]
    async fn purge_durable_queue(&self, topic: &MessageRoute) -> Result<u32, SubscriberError> {
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        let topology = self.broker_queue_topology(topic)?;
        declare_broker_queue_topology(&channel, &topology, &self.name).await?;
        let purged = channel
            .queue_purge(topology.source_queue().into(), QueuePurgeOptions::default())
            .await
            .map_err(SubscriberError::new)?;
        channel
            .queue_purge(
                topology.dead_letter_queue().into(),
                QueuePurgeOptions::default(),
            )
            .await
            .map_err(SubscriberError::new)?;
        channel
            .close(REPLY_SUCCESS, "test queue purge complete".into())
            .await
            .map_err(SubscriberError::new)?;
        Ok(purged)
    }

    fn broker_queue_topology(
        &self,
        topic: &MessageRoute,
    ) -> Result<BrokerQueueTopology, SubscriberError> {
        if self.broker_queue_limits.dead_letter_ttl_ms == BROKER_DLQ_TTL_MS
            && self.broker_queue_limits.source_max_bytes == BROKER_SOURCE_MAX_BYTES
            && self.broker_queue_limits.dead_letter_max_bytes == BROKER_DLQ_MAX_BYTES
        {
            BrokerQueueTopology::production(topic.as_str())
        } else {
            BrokerQueueTopology::with_limits(topic.as_str(), self.broker_queue_limits)
        }
    }
}

/// Declare the terminal quarantine first, then the source queue that routes rejected messages to
/// it through the existing topic exchange and an exact `<topic>.dlq` routing key. MessageRoute permissions
/// keep the subscriber credential from publishing to source or adjacent queues.
async fn declare_broker_queue_topology(
    channel: &Channel,
    topology: &BrokerQueueTopology,
    resource: &str,
) -> Result<u32, SubscriberError> {
    let dead_letter = channel
        .queue_declare(
            topology.dead_letter_queue().into(),
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            topology.dead_letter_arguments().clone(),
        )
        .await
        .map_err(|error| {
            topology_rpc_error(
                resource,
                topology,
                BrokerTopologyStage::DeclareDeadLetter,
                error,
            )
        })?;
    channel
        .queue_declare(
            topology.source_queue().into(),
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            topology.source_arguments().clone(),
        )
        .await
        .map_err(|error| {
            topology_rpc_error(
                resource,
                topology,
                BrokerTopologyStage::DeclareSource,
                error,
            )
        })?;
    channel
        .queue_bind(
            topology.dead_letter_queue().into(),
            crate::EVENT_EXCHANGE.into(),
            topology.dead_letter_queue().into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|error| {
            topology_rpc_error(
                resource,
                topology,
                BrokerTopologyStage::BindDeadLetter,
                error,
            )
        })?;
    channel
        .queue_bind(
            topology.source_queue().into(),
            crate::EVENT_EXCHANGE.into(),
            topology.source_queue().into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|error| {
            topology_rpc_error(resource, topology, BrokerTopologyStage::BindSource, error)
        })?;
    Ok(dead_letter.message_count())
}

/// 两阶段排空的 admission stop：token cancel 后以稳定 tag 发送 `basic.cancel`，并等待
/// broker 的 `basic.cancel-ok`。只停止新 delivery，不关闭 channel，因此取消前已在途的
/// manual-ack delivery 仍可由 worker settle。channel/connection 只由 subscriber shutdown 关闭；若排空
/// 失败，该关闭语义使 broker 重投未 settle 消息。
async fn cancel_delivery_source(channel: Channel, consumer_tag: String) {
    if let Err(error) = channel
        .basic_cancel(consumer_tag.into(), BasicCancelOptions::default())
        .await
    {
        tracing::warn!(target: "amqp", error = %rss_redact::redact_error(&error), "amqp delivery source basic.cancel error");
        close_failed_subscription(&channel, "basic.cancel failed").await;
    }
}

async fn close_failed_subscription(channel: &Channel, reason: &'static str) {
    if let Err(error) = channel.close(REPLY_SUCCESS, reason.into()).await {
        tracing::warn!(target: "amqp", error = %rss_redact::redact_error(&error), "amqp failed subscription channel close error");
    }
}

impl ManagedResource for AmqpSubscriber {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.operational.store(false, Ordering::Release);
        self.shutdown.cancel();
        self.conn
            .close(REPLY_SUCCESS, "subscriber resource shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %rss_redact::redact_error(e), "amqp connection close error");
            })
            .map_err(ShutdownError::new)
    }
}

/// AMQP [`lapin::BasicProperties`] → authored metadata attributes（adapter 透传路径）。
/// - `timestamp` → `occurred_at`（unix 秒，十进制 string）。
/// - transport-safe `headers` LongString pair → metadata pair（LongString 以 utf8_lossy Display 转 string）。
/// - 非 LongString header 值跳过（不是本 adapter `build_properties` 产出的；透传外部生产者时静默忽略）。
///
/// 纯函数——无 broker 依赖；integration-gated（lapin 类型只在 integration feature 链接）。
fn extract_metadata(props: &lapin::BasicProperties) -> std::collections::BTreeMap<String, String> {
    let mut metadata = std::collections::BTreeMap::new();
    if let Some(timestamp) = props.timestamp() {
        metadata.insert("occurredAt".to_owned(), timestamp.to_string());
    }
    if let Some(table) = props.headers() {
        for (k, v) in table.inner() {
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
/// （settle-once；二次 settle 在 lapin 层返 Err、由 eventexec 的 settle 失败日志承接，不 panic）。
fn delivery_to_core(
    delivery: Delivery,
    channel: Channel,
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
        inner: acker,
        channel,
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
        Err(failure) => IncomingDelivery::Invalid {
            failure,
            settlement,
        },
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
    let occurred_at = take_required(&mut headers, "occurredAt")?
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
/// 映射逻辑（`SettlementKind → SettleMode`）抽到 feature-agnostic 的 [`crate::settle`]（默认 build 可测、进 verify
/// gate）；本 impl 仅把 [`SettleMode`] 翻成 lapin `basic_ack` / `basic_nack(requeue)`。内部 lapin error 经
/// `MessagingError::provider` 包装（source 脱敏，不进 wire）。
pub struct AmqpSettlement {
    inner: lapin::Acker,
    channel: Channel,
    subscription_rpc: Arc<SubscriptionRpc>,
}

pub type AmqpDeliveries = std::pin::Pin<
    Box<dyn futures::Stream<Item = IncomingDelivery<Vec<u8>, AmqpSettlement>> + Send>,
>;

struct ActiveSubscription(Arc<AtomicUsize>);

impl Drop for ActiveSubscription {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serializes one subscription channel's cancel and settlement RPCs while giving an already
/// requested cancellation priority. The prefetch window stays closed until the broker confirms
/// `basic.cancel`; only then may an in-flight delivery settle and reopen that window.
struct SubscriptionRpc {
    gate: tokio::sync::Mutex<()>,
    cancel_requested: CancellationToken,
    admission_stopped: CancellationToken,
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

impl DeliverySettlement for AmqpSettlement {
    async fn settle(
        self,
        decision: SettlementDecision,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        // If cancellation was requested before settlement acquires the gate, wait for cancel-ok
        // (or the failure-path channel close) before Ack/Nack can reopen the prefetch window. A
        // settlement already holding the gate remains linearized before cancellation.
        let result = tokio::time::timeout(deadline.timeout(), async {
            let _rpc = self.subscription_rpc.settlement_guard().await;
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
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => {
                let error = MessagingError::new(MessagingErrorKind::Transient, error);
                close_failed_subscription(&self.channel, "delivery settle failed").await;
                Err(error)
            }
            Err(error) => {
                close_failed_subscription(&self.channel, "delivery settle deadline elapsed").await;
                Err(MessagingError::new(MessagingErrorKind::Transient, error))
            }
        }
    }

    async fn abandon(self, deadline: OperationDeadline) -> Result<(), MessagingError> {
        tokio::time::timeout(
            deadline.timeout(),
            close_failed_subscription(&self.channel, "delivery ownership abandoned"),
        )
        .await
        .map_err(|error| MessagingError::new(MessagingErrorKind::Transient, error))
    }
}

// ── impl DeliverySource for AmqpSubscriber（P7 manual-ack）──────────────

impl AmqpSubscriber {
    async fn prepare_delivery_route_inner(
        &self,
        topic: &MessageRoute,
    ) -> Result<(), SubscriberError> {
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        let topology = self.broker_queue_topology(topic)?;
        declare_broker_queue_topology(&channel, &topology, &self.name).await?;
        channel
            .close(REPLY_SUCCESS, "durable topology prepared".into())
            .await
            .map_err(SubscriberError::new)?;
        Ok(())
    }

    async fn delivery_stream(
        &self,
        subscription: &SubscriptionIdentity,
        token: CancellationToken,
    ) -> Result<AmqpDeliveries, SubscriberError> {
        let topic = subscription.route();
        let topic_name = topic.as_str();
        // 稳定 consumer tag（按 name+topic 派生）：重连/重订阅复用同一 tag，不变成新消费者
        // （由 `contracts/**/contract.toml`、`generated` 与 `crates/consistency` 承载）。
        let consumer_tag = format!("{}-ack-{}", self.name, topic_name);
        // 每订阅独立 channel（review #274 F4/C4）：token cancel 只停止本 channel 的 consumer，
        // 不连带停掉同 subscriber 其它 topic 的 consumer。
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        // prefetch：限 channel 上 unacked 消息上限（P7 at-least-once 背压，RabbitMQ 推荐 100–300）。
        channel
            .basic_qos(PREFETCH, BasicQosOptions::default())
            .await
            .map_err(SubscriberError::new)?;
        let topology = self.broker_queue_topology(topic)?;
        declare_broker_queue_topology(&channel, &topology, &self.name).await?;
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
        self.channels
            .lock()
            .map_err(|_| {
                SubscriberError::new(std::io::Error::other("subscriber channel state poisoned"))
            })?
            .push(channel.clone());

        // Consumer → Delivery（携 acker）。take_until 在 token cancel 后以同一稳定 tag 等待
        // broker 确认 basic.cancel，再终止流；channel 保持打开，让 in-flight acker 继续 settle。
        // Drive admission cancellation independently from stream polling. ConsumerTx processes one
        // delivery at a time and may be blocked in its PG transaction when shutdown begins.
        let admission_stopped = CancellationToken::new();
        let cancel_confirmation = admission_stopped.clone();
        let subscription_rpc = Arc::new(SubscriptionRpc {
            gate: tokio::sync::Mutex::new(()),
            cancel_requested: token.clone(),
            admission_stopped,
        });
        let cancel_rpc = Arc::clone(&subscription_rpc);
        let cancel_channel = channel.clone();
        tokio::spawn(async move {
            token.cancelled().await;
            let _rpc = cancel_rpc.gate.lock().await;
            cancel_delivery_source(cancel_channel, consumer_tag).await;
            cancel_rpc.admission_stopped.cancel();
        });
        let delivery_rpc = Arc::clone(&subscription_rpc);
        let delivery_subscription = subscription.clone();
        // A delivery can already be buffered client-side when token cancellation races the
        // in-flight Ack that reopens the prefetch window. Once cancellation is requested, never
        // expose that raced delivery to ConsumerTx. Dropping it leaves it unsettled; the later
        // subscriber channel shutdown requeues it for the replacement consumer.
        let stream = consumer
            .filter_map(move |res| {
                let delivery_channel = channel.clone();
                let delivery_rpc = Arc::clone(&delivery_rpc);
                let delivery_subscription = delivery_subscription.clone();
                async move {
                    match res {
                        Ok(_delivery) if delivery_rpc.cancel_requested.is_cancelled() => None,
                        Ok(delivery) => Some(delivery_to_core(
                            delivery,
                            delivery_channel,
                            delivery_rpc,
                            &delivery_subscription,
                        )),
                        Err(error) => {
                            tracing::warn!(
                                target: "amqp",
                                error = %rss_redact::redact_error(&error),
                                "amqp delivery source error; skipping",
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
        self.active_subscriptions.fetch_add(1, Ordering::AcqRel);
        let guard = ActiveSubscription(Arc::clone(&self.active_subscriptions));
        Ok(Box::pin(futures::stream::unfold(
            (Box::pin(stream), guard),
            |(mut stream, guard)| async move { stream.next().await.map(|item| (item, (stream, guard))) },
        )))
    }

    pub async fn prepare_delivery_route(&self, route: &MessageRoute) -> Result<(), MessagingError> {
        self.prepare_delivery_route_inner(route)
            .await
            .map_err(SubscriberError::into_messaging)
    }
}

impl DeliverySource<Vec<u8>> for AmqpSubscriber {
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

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use lapin::types::AMQPValue;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt as _};

    use super::{
        BROKER_DLQ_TTL_MS, BrokerQueueTopology, BrokerTopologyFailureKind, BrokerTopologyStage,
        classify_topology_failure, decode_message, topology_rpc_error,
    };

    #[derive(Clone, Default)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<(String, HashMap<String, String>)>>>,
    }

    struct CaptureVisitor {
        fields: HashMap<String, String>,
    }

    impl Visit for CaptureVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut visitor = CaptureVisitor {
                fields: HashMap::new(),
            };
            event.record(&mut visitor);
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((event.metadata().target().to_string(), visitor.fields));
        }
    }

    #[test]
    fn broker_queue_topology_owns_exact_dead_letter_arguments() {
        let topology =
            BrokerQueueTopology::production("rss.events.runtime").expect("valid topic topology");

        assert_eq!(topology.source_queue(), "rss.events.runtime");
        assert_eq!(topology.dead_letter_queue(), "rss.events.runtime.dlq");
        assert_eq!(
            topology
                .source_arguments()
                .inner()
                .get("x-dead-letter-exchange"),
            Some(&AMQPValue::LongString(b"amq.topic".to_vec().into()))
        );
        assert_eq!(
            topology
                .source_arguments()
                .inner()
                .get("x-dead-letter-routing-key"),
            Some(&AMQPValue::LongString(
                b"rss.events.runtime.dlq".to_vec().into()
            ))
        );
        for (key, value) in [
            ("x-queue-type", "quorum"),
            ("x-dead-letter-strategy", "at-least-once"),
            ("x-overflow", "reject-publish"),
        ] {
            assert_eq!(
                topology.source_arguments().inner().get(key),
                Some(&AMQPValue::LongString(value.as_bytes().to_vec().into()))
            );
        }
        assert_eq!(
            topology
                .source_arguments()
                .inner()
                .get("x-max-length-bytes"),
            Some(&AMQPValue::LongLongInt(256 * 1024 * 1024))
        );
        assert_eq!(
            topology
                .dead_letter_arguments()
                .inner()
                .get("x-message-ttl"),
            Some(&AMQPValue::LongUInt(BROKER_DLQ_TTL_MS))
        );
        for (key, value) in [("x-queue-type", "quorum"), ("x-overflow", "reject-publish")] {
            assert_eq!(
                topology.dead_letter_arguments().inner().get(key),
                Some(&AMQPValue::LongString(value.as_bytes().to_vec().into()))
            );
        }
        assert_eq!(
            topology
                .dead_letter_arguments()
                .inner()
                .get("x-max-length-bytes"),
            Some(&AMQPValue::LongLongInt(256 * 1024 * 1024))
        );
        assert!(
            !topology
                .dead_letter_arguments()
                .contains_key("x-dead-letter-exchange"),
            "the quarantine queue must terminate the broker dead-letter chain"
        );
    }

    #[test]
    fn broker_queue_topology_rejects_empty_or_overlong_names() {
        assert!(BrokerQueueTopology::production("").is_err());
        assert!(BrokerQueueTopology::production("rss.events.runtime.dlq").is_err());
        assert!(BrokerQueueTopology::production(&"x".repeat(252)).is_err());
        assert!(BrokerQueueTopology::production(&"x".repeat(251)).is_ok());
    }

    #[test]
    fn broker_topology_failure_categories_are_closed_and_safe() {
        let protocol_error = |reply_code| {
            let error =
                lapin::protocol::AMQPError::from_id(reply_code, "hidden broker text".into())
                    .expect("known AMQP reply code");
            lapin::Error::from(lapin::ErrorKind::ProtocolError(error))
        };
        assert_eq!(
            classify_topology_failure(&protocol_error(406)),
            BrokerTopologyFailureKind::Precondition
        );
        assert_eq!(
            classify_topology_failure(&protocol_error(403)),
            BrokerTopologyFailureKind::Permission
        );
        assert_eq!(
            classify_topology_failure(&protocol_error(404)),
            BrokerTopologyFailureKind::Protocol
        );
        assert_eq!(
            classify_topology_failure(&lapin::Error::from(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "hidden transport text",
            ))),
            BrokerTopologyFailureKind::Transport
        );
    }

    #[test]
    fn broker_topology_diagnostic_emits_only_closed_safe_fields() {
        let layer = CaptureLayer::default();
        let events = Arc::clone(&layer.events);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let error = lapin::protocol::AMQPError::from_id(
                406,
                "hidden broker topology and credential text".into(),
            )
            .expect("known AMQP reply code");
            let topology = BrokerQueueTopology::production("rss.events.runtime")
                .expect("valid topic topology");
            let _ = topology_rpc_error(
                "runtime-subscriber",
                &topology,
                BrokerTopologyStage::DeclareSource,
                lapin::Error::from(lapin::ErrorKind::ProtocolError(error)),
            );
        });

        let events = events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(events.len(), 1);
        let (target, fields) = &events[0];
        assert_eq!(target, "amqp");
        assert_eq!(
            fields.get("resource").map(String::as_str),
            Some("runtime-subscriber")
        );
        assert_eq!(
            fields.get("source_queue").map(String::as_str),
            Some("rss.events.runtime")
        );
        assert_eq!(
            fields.get("dead_letter_queue").map(String::as_str),
            Some("rss.events.runtime.dlq")
        );
        assert_eq!(
            fields.get("message").map(String::as_str),
            Some("amqp broker queue topology declaration failed")
        );
        assert_eq!(
            fields.get("stage").map(String::as_str),
            Some("declare_source_queue")
        );
        assert_eq!(fields.get("kind").map(String::as_str), Some("precondition"));
        assert!(
            fields
                .values()
                .all(|value| !value.contains("hidden broker topology")),
            "raw broker text must not be recorded"
        );
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
                ("occurredAt".to_owned(), "1".to_owned()),
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
    // 进 verify gate），不再绑 lapin / integration feature。
}
