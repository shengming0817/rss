//! amqp — RSS AMQP 事件订阅 adapter——impl `diport::AckableSubscriber` + `diport::ManagedResource`。
//!
//! `basic_consume` 的 `Consumer`（`Stream<Item = Result<Delivery>>`）适配成 `diport::DeliveryStream`
//! （manual-ack，`AckableSubscriber`）：`token` 取消即流终止（对标 `adapters/memory` 的 `take_until`）。
//! P7 manual-ack：`no_ack=false` + `basic_qos(PREFETCH)`，每条 [`diport::Delivery`] 携 [`AmqpAcker`] 句柄。
//! AMQP 仅 at-least-once（manual-ack）：经 `AckableSubscriber::subscribe_ackable`；
//! at-most-once 仅 demo 拓扑的 MemBus。
//! ref: lapin examples/pubsub.rs@main；rabbitmq docs/confirms。

#[cfg(feature = "integration-test-support")]
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use diport::{
    AckAction, AckError, AckableSubscriber, Delivery as DiDelivery, DeliveryStream,
    EnvelopeMetadata, KEY_OCCURRED_AT, ManagedResource, Message, ShutdownError, SubscriberError,
    Topic,
};
use futures::StreamExt;
use lapin::message::Delivery;
use lapin::options::{
    BasicAckOptions, BasicCancelOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions,
    QueueBindOptions, QueueDeclareOptions,
};
#[cfg(feature = "integration-test-support")]
use lapin::options::{BasicGetOptions, BasicPublishOptions, QueueDeleteOptions, QueuePurgeOptions};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{Channel, Connection};
use tokio_util::sync::CancellationToken;

use crate::conn::{self, REPLY_SUCCESS};
use crate::settle::{SettleMode, settle_mode};

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
/// 其它模块暴露 raw 连接。impl `AckableSubscriber` + `ManagedResource`。
///
/// **每订阅独立 channel**（review #274 F4/C4）：`subscribe_ackable` 每次从 `conn` 新开一个 channel 承载该
/// 订阅，token cancel 只对**本订阅** consumer 执行 `basic.cancel`，不连带终止同实例其它
/// topic 的 consumer；subscriber 级 shutdown 关闭整个 `conn`（其下所有订阅 channel 随之关闭）。
pub struct AmqpSubscriber {
    conn: Arc<Connection>,
    channels: std::sync::Mutex<Vec<Channel>>,
    operational: AtomicBool,
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
        // reason: 订阅 channel 由 subscribe_ackable 按需 per-subscription 新开（F4）；connect 借
        // connect helper 拿连接 + redaction 日志，其返回的初始 channel 不用于订阅，drop 即可。
        let (conn, _channel) = conn::connect_with_webpki_for_test(endpoint, &name, false).await?;
        Ok(Self {
            conn,
            channels: std::sync::Mutex::new(Vec::new()),
            operational: AtomicBool::new(true),
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
            name,
            broker_queue_limits: BrokerQueueLimits::PRODUCTION,
        })
    }

    pub(crate) fn readiness_snapshot(&self) -> bool {
        self.operational.load(Ordering::Acquire)
            && self.conn.status().connected()
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
        topic: &Topic,
    ) -> Result<u32, SubscriberError> {
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

    /// Remove only the broker quarantine after the full topology has been declared. This narrow
    /// fault seam lets a live test prove that the source quorum queue retains a rejected message
    /// while its target is unavailable; the next typed declaration restores the same topology.
    #[cfg(feature = "integration-test-support")]
    pub async fn delete_broker_dead_letter_for_test(
        &self,
        topic: &Topic,
    ) -> Result<(), SubscriberError> {
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        let topology = self.broker_queue_topology(topic)?;
        declare_broker_queue_topology(&channel, &topology, &self.name).await?;
        channel
            .queue_delete(
                topology.dead_letter_queue().into(),
                QueueDeleteOptions::default(),
            )
            .await
            .map_err(SubscriberError::new)?;
        channel
            .close(REPLY_SUCCESS, "test DLQ target removal complete".into())
            .await
            .map_err(SubscriberError::new)?;
        Ok(())
    }

    #[cfg(feature = "integration-test-support")]
    pub async fn broker_dead_letter_depth_for_test(
        &self,
        topic: &Topic,
    ) -> Result<u32, SubscriberError> {
        let topology = self.broker_queue_topology(topic)?;
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        let dead_letter_message_count =
            declare_broker_queue_topology(&channel, &topology, &self.name).await?;
        channel
            .close(REPLY_SUCCESS, "test DLQ depth complete".into())
            .await
            .map_err(SubscriberError::new)?;
        Ok(dead_letter_message_count)
    }

    #[cfg(feature = "integration-test-support")]
    pub async fn take_broker_dead_letter_for_test(
        &self,
        topic: &Topic,
    ) -> Result<Option<BrokerDeadLetterObservation>, SubscriberError> {
        let topology = self.broker_queue_topology(topic)?;
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        declare_broker_queue_topology(&channel, &topology, &self.name).await?;
        let observation = take_broker_dead_letter(&channel, &topology).await;
        let close = channel
            .close(REPLY_SUCCESS, "test DLQ observation complete".into())
            .await;
        match observation {
            Ok(observation) => {
                close.map_err(SubscriberError::new)?;
                Ok(observation)
            }
            Err(error) => {
                // Closing a channel with an unsettled basic.get delivery makes RabbitMQ requeue
                // malformed evidence. Preserve the primary observation error if close also fails.
                let _ = close;
                Err(error)
            }
        }
    }

    /// Fixed negative ACL probe: attempts one publish through RabbitMQ's default exchange and uses
    /// an ordered RPC as the broker-response barrier. No exchange/channel or payload is exposed to
    /// callers; a correctly provisioned subscriber credential must return `true`.
    #[cfg(feature = "integration-test-support")]
    pub async fn default_exchange_publish_is_denied_for_test(
        &self,
        routing_key: &Topic,
    ) -> Result<bool, SubscriberError> {
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        let publish = channel
            .basic_publish(
                "".into(),
                routing_key.as_str().into(),
                BasicPublishOptions::default(),
                b"acl-negative-probe",
                lapin::BasicProperties::default(),
            )
            .await;
        let denied = match publish {
            Err(_) => true,
            Ok(_) => channel
                .basic_qos(PREFETCH, BasicQosOptions::default())
                .await
                .is_err(),
        };
        let _ = channel
            .close(REPLY_SUCCESS, "default exchange ACL probe complete".into())
            .await;
        Ok(denied)
    }

    fn broker_queue_topology(&self, topic: &Topic) -> Result<BrokerQueueTopology, SubscriberError> {
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

/// Narrow integration receipt for one broker-quarantined message. Raw lapin connection/channel
/// handles and arbitrary broker operations remain private to the adapter.
#[cfg(feature = "integration-test-support")]
pub struct BrokerDeadLetterObservation {
    message_id: Option<String>,
    payload: Vec<u8>,
    death_reason: String,
    death_count: u64,
    source_queue: String,
    source_exchange: String,
}

#[cfg(feature = "integration-test-support")]
impl BrokerDeadLetterObservation {
    pub fn message_id(&self) -> Option<&str> {
        self.message_id.as_deref()
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn death_reason(&self) -> &str {
        &self.death_reason
    }

    pub fn death_count(&self) -> u64 {
        self.death_count
    }

    pub fn source_queue(&self) -> &str {
        &self.source_queue
    }

    pub fn source_exchange(&self) -> &str {
        &self.source_exchange
    }

    fn try_from(message: &lapin::message::BasicGetMessage) -> Result<Self, SubscriberError> {
        let headers = message
            .properties
            .headers()
            .as_ref()
            .ok_or_else(|| invalid_topology("broker dead-letter is missing x-death headers"))?;
        let deaths = match headers.inner().get("x-death") {
            Some(AMQPValue::FieldArray(deaths)) => deaths,
            _ => {
                return Err(invalid_topology(
                    "broker dead-letter has invalid x-death headers",
                ));
            }
        };
        let death = match deaths.as_slice().first() {
            Some(AMQPValue::FieldTable(death)) => death,
            _ => return Err(invalid_topology("broker dead-letter has no x-death entry")),
        };
        let death_reason = x_death_string(death, "reason")?;
        let source_queue = x_death_string(death, "queue")?;
        let source_exchange = x_death_string(death, "exchange")?;
        let death_count = match death.inner().get("count") {
            Some(AMQPValue::LongLongInt(count)) if *count >= 0 => *count as u64,
            Some(AMQPValue::LongUInt(count)) => u64::from(*count),
            _ => {
                return Err(invalid_topology(
                    "broker dead-letter has invalid x-death count",
                ));
            }
        };
        Ok(Self {
            message_id: message
                .properties
                .message_id()
                .as_ref()
                .map(ToString::to_string),
            payload: message.data.clone(),
            death_reason,
            death_count,
            source_queue,
            source_exchange,
        })
    }
}

#[cfg(feature = "integration-test-support")]
async fn take_broker_dead_letter(
    channel: &Channel,
    topology: &BrokerQueueTopology,
) -> Result<Option<BrokerDeadLetterObservation>, SubscriberError> {
    let Some(message) = channel
        .basic_get(
            topology.dead_letter_queue().into(),
            BasicGetOptions { no_ack: false },
        )
        .await
        .map_err(SubscriberError::new)?
    else {
        return Ok(None);
    };
    let observation = BrokerDeadLetterObservation::try_from(&message)?;
    message
        .acker
        .ack(BasicAckOptions::default())
        .await
        .map_err(SubscriberError::new)?;
    Ok(Some(observation))
}

#[cfg(feature = "integration-test-support")]
fn x_death_string(table: &FieldTable, key: &'static str) -> Result<String, SubscriberError> {
    match table.inner().get(key) {
        Some(AMQPValue::LongString(value)) => Ok(value.to_string()),
        Some(AMQPValue::ShortString(value)) => Ok(value.to_string()),
        _ => Err(invalid_topology(
            "broker dead-letter has invalid x-death text",
        )),
    }
}

/// Declare the terminal quarantine first, then the source queue that routes rejected messages to
/// it through the existing topic exchange and an exact `<topic>.dlq` routing key. Topic permissions
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
async fn cancel_ackable(channel: Channel, consumer_tag: String) {
    if let Err(error) = channel
        .basic_cancel(consumer_tag.into(), BasicCancelOptions::default())
        .await
    {
        tracing::warn!(target: "amqp", error = %secure::redact_error(&error), "amqp ackable basic.cancel error");
        close_failed_subscription(&channel, "basic.cancel failed").await;
    }
}

async fn close_failed_subscription(channel: &Channel, reason: &'static str) {
    if let Err(error) = channel.close(REPLY_SUCCESS, reason.into()).await {
        tracing::warn!(target: "amqp", error = %secure::redact_error(&error), "amqp failed subscription channel close error");
    }
}

impl ManagedResource for AmqpSubscriber {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.operational.store(false, Ordering::Release);
        self.conn
            .close(REPLY_SUCCESS, "subscriber resource shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp connection close error");
            })
            .map_err(ShutdownError::new)
    }
}

/// AMQP [`lapin::BasicProperties`] → [`diport::EnvelopeMetadata`] rehydrate（adapter 透传路径）。
/// - `timestamp` → `occurred_at`（unix 秒，十进制 string）。
/// - transport-safe `headers` LongString pair → metadata pair（LongString 以 utf8_lossy Display 转 string）。
/// - 非 LongString header 值跳过（不是本 adapter `build_properties` 产出的；透传外部生产者时静默忽略）。
///
/// 纯函数——无 broker 依赖；integration-gated（lapin 类型只在 integration feature 链接）。
fn extract_metadata(props: &lapin::BasicProperties) -> EnvelopeMetadata {
    let mut md = EnvelopeMetadata::empty();
    if let Some(ts) = props.timestamp() {
        // reason: u64 unix secs 转 string；消费侧 occurred_at_secs() 再 parse 回 i64。
        md.insert_wire_pair(KEY_OCCURRED_AT, ts.to_string());
    }
    if let Some(table) = props.headers() {
        for (k, v) in table.inner() {
            if let AMQPValue::LongString(ls) = v {
                // reason: LongString Display 用 String::from_utf8_lossy——非 utf8 字节以 U+FFFD 替换，
                // 不 panic。仅本 adapter build_properties 产出 LongString，外部生产者的非 LongString
                // header 在此跳过（非本 adapter 控制路径，不可信 roundtrip）。persisted-only
                // subjectId/principal/actor 即使由外部 producer 伪造到 header，也不得进入消费侧 metadata。
                if EnvelopeMetadata::is_transport_header_key(k.as_str()) {
                    md.insert_wire_pair(k.as_str(), ls.to_string());
                }
            }
        }
    }
    md
}

/// lapin `Delivery` → `diport::Delivery`（携 [`AmqpAcker`] 结算句柄 + envelope metadata）。
/// 先取出 `acker`（lapin `Acker` 是 Arc handle，cheap clone）再 move `data`/`properties` 构造 Message，
/// 避免借用冲突。clone 出的句柄随 `Delivery` owned 交给 driver——driver 须保证最终只一方 settle
/// （settle-once；二次 settle 在 lapin 层返 Err、由 eventexec 的 settle 失败日志承接，不 panic）。
fn delivery_to_ackable(
    delivery: Delivery,
    channel: Channel,
    subscription_rpc: Arc<SubscriptionRpc>,
) -> DiDelivery {
    let acker = delivery.acker.clone();
    let producer_id = delivery
        .properties
        .message_id()
        .as_ref()
        .map(ToString::to_string);
    let id = pick_message_id(producer_id.as_deref(), delivery.delivery_tag);
    let metadata = extract_metadata(&delivery.properties);
    let message = Message::new_with_metadata(id, delivery.data, metadata);
    DiDelivery::new(
        message,
        diport::DynAcker::new_box(AmqpAcker {
            inner: acker,
            channel,
            subscription_rpc,
        }),
    )
}

/// 派生 message id：优先 producer 设置的 `message_id`（非空白），否则用 broker 的 `delivery_tag`。
/// 纯函数——无 broker 单元可测。纯空白 `message_id` 视同缺失（退 delivery_tag）。
fn pick_message_id(message_id: Option<&str>, delivery_tag: u64) -> String {
    message_id
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| delivery_tag.to_string())
}

// ── AmqpAcker（impl diport::Acker）──────────────────────────────────────────

/// lapin broker 结算句柄的 adapter 包装（impl [`diport::Acker`]）。
///
/// 映射逻辑（`AckAction → SettleMode`）抽到 feature-agnostic 的 [`crate::settle`]（默认 build 可测、进 verify
/// gate）；本 impl 仅把 [`SettleMode`] 翻成 lapin `basic_ack` / `basic_nack(requeue)`。内部 lapin error 经
/// `AckError::new` 包装（source 脱敏，不进 wire——见 `diport::AckError` PII 边界）。
pub(crate) struct AmqpAcker {
    inner: lapin::Acker,
    channel: Channel,
    subscription_rpc: Arc<SubscriptionRpc>,
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

impl diport::Acker for AmqpAcker {
    async fn settle(&self, action: AckAction) -> Result<(), AckError> {
        // If cancellation was requested before settlement acquires the gate, wait for cancel-ok
        // (or the failure-path channel close) before Ack/Nack can reopen the prefetch window. A
        // settlement already holding the gate remains linearized before cancellation.
        let _rpc = self.subscription_rpc.settlement_guard().await;
        let result = match settle_mode(action) {
            SettleMode::Ack => self.inner.ack(BasicAckOptions::default()).await,
            SettleMode::Nack { requeue } => {
                self.inner
                    .nack(BasicNackOptions {
                        multiple: false,
                        requeue,
                    })
                    .await
            }
        };
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                let error = AckError::new(error);
                close_failed_subscription(&self.channel, "delivery settle failed").await;
                Err(error)
            }
        }
    }
}

// ── impl AckableSubscriber for AmqpSubscriber（P7 manual-ack）──────────────

impl AckableSubscriber for AmqpSubscriber {
    async fn prepare_ackable(&self, topic: Topic) -> Result<(), SubscriberError> {
        let channel = self
            .conn
            .create_channel()
            .await
            .map_err(SubscriberError::new)?;
        let topology = self.broker_queue_topology(&topic)?;
        declare_broker_queue_topology(&channel, &topology, &self.name).await?;
        channel
            .close(REPLY_SUCCESS, "durable topology prepared".into())
            .await
            .map_err(SubscriberError::new)?;
        Ok(())
    }

    async fn subscribe_ackable(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<DeliveryStream, SubscriberError> {
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
        let topology = self.broker_queue_topology(&topic)?;
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
            cancel_ackable(cancel_channel, consumer_tag).await;
            cancel_rpc.admission_stopped.cancel();
        });
        let delivery_rpc = Arc::clone(&subscription_rpc);
        // A delivery can already be buffered client-side when token cancellation races the
        // in-flight Ack that reopens the prefetch window. Once cancellation is requested, never
        // expose that raced delivery to ConsumerTx. Dropping it leaves it unsettled; the later
        // subscriber channel shutdown requeues it for the replacement consumer.
        let stream = consumer
            .filter_map(move |res| {
                let delivery_channel = channel.clone();
                let delivery_rpc = Arc::clone(&delivery_rpc);
                async move {
                    match res {
                        Ok(_delivery) if delivery_rpc.cancel_requested.is_cancelled() => None,
                        Ok(delivery) => Some(delivery_to_ackable(
                            delivery,
                            delivery_channel,
                            delivery_rpc,
                        )),
                        Err(error) => {
                            tracing::warn!(
                                target: "amqp",
                                error = %secure::redact_error(&error),
                                "amqp ackable delivery error; skipping",
                            );
                            None
                        }
                    }
                }
            })
            .take_until(async move {
                cancel_confirmation.cancelled().await;
            });
        tracing::info!(target: "amqp", resource = %self.name, topic = topic_name, "amqp ackable subscribe started");
        Ok(Box::pin(stream))
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // subscriber 级关闭：关整个 connection（其下所有 per-subscription channel 随之关闭 → broker requeue
        // 各 channel 上仍未 settle 的 in-flight delivery）。token cancel 只完成 consumer admission stop。
        self.operational.store(false, Ordering::Release);
        self.conn
            .close(REPLY_SUCCESS, "ackable subscriber shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp connection close error (ackable)");
            })
            .map_err(SubscriberError::new)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use lapin::types::AMQPValue;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt as _};

    use super::{
        BROKER_DLQ_TTL_MS, BrokerQueueTopology, BrokerTopologyFailureKind, BrokerTopologyStage,
        classify_topology_failure, pick_message_id, topology_rpc_error,
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
            BrokerQueueTopology::production("rss.events.settings").expect("valid topic topology");

        assert_eq!(topology.source_queue(), "rss.events.settings");
        assert_eq!(topology.dead_letter_queue(), "rss.events.settings.dlq");
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
                b"rss.events.settings.dlq".to_vec().into()
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
        assert!(BrokerQueueTopology::production("rss.events.settings.dlq").is_err());
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
            let topology = BrokerQueueTopology::production("rss.events.settings")
                .expect("valid topic topology");
            let _ = topology_rpc_error(
                "settings-subscriber",
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
            Some("settings-subscriber")
        );
        assert_eq!(
            fields.get("source_queue").map(String::as_str),
            Some("rss.events.settings")
        );
        assert_eq!(
            fields.get("dead_letter_queue").map(String::as_str),
            Some("rss.events.settings.dlq")
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
    fn prefers_non_empty_message_id() {
        assert_eq!(pick_message_id(Some("evt-7"), 42), "evt-7");
    }

    #[test]
    fn falls_back_to_delivery_tag_when_absent() {
        assert_eq!(pick_message_id(None, 42), "42");
    }

    #[test]
    fn falls_back_to_delivery_tag_when_empty() {
        assert_eq!(pick_message_id(Some(""), 7), "7");
    }

    #[test]
    fn falls_back_to_delivery_tag_when_whitespace() {
        assert_eq!(pick_message_id(Some("   "), 9), "9");
    }

    // AckAction → broker 结算模式映射的表驱动测试迁至 feature-agnostic `crate::settle`（默认 build 可测、
    // 进 verify gate），不再绑 lapin / integration feature。
}

/// `extract_metadata` 纯函数单测（integration-gated：lapin 类型只在 integration feature 链接）。
#[cfg(test)]
mod extract_metadata_tests {
    use diport::{
        KEY_ACTOR, KEY_CORRELATION, KEY_PRINCIPAL, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
        KEY_SUBJECT_ID,
    };
    use lapin::BasicProperties;
    use lapin::types::{AMQPValue, FieldTable};

    use super::extract_metadata;

    #[test]
    fn empty_properties_gives_empty_metadata() {
        let props = BasicProperties::default();
        let md = extract_metadata(&props);
        assert!(md.is_empty());
    }

    #[test]
    fn timestamp_maps_to_occurred_at() {
        let props = BasicProperties::default().with_timestamp(1_700_000_000_u64);
        let md = extract_metadata(&props);
        assert_eq!(md.occurred_at_secs(), Some(1_700_000_000_i64));
    }

    #[test]
    fn transport_long_string_headers_transferred() {
        let mut table = FieldTable::default();
        table.insert(
            KEY_CORRELATION.into(),
            AMQPValue::LongString(b"corr-9".to_vec().into()),
        );
        table.insert(
            KEY_SCHEMA_VERSION.into(),
            AMQPValue::LongString(b"v1".to_vec().into()),
        );
        table.insert(
            KEY_SCHEMA_HASH.into(),
            AMQPValue::LongString(
                b"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_vec()
                    .into(),
            ),
        );
        let props = BasicProperties::default().with_headers(table);
        let md = extract_metadata(&props);
        assert_eq!(md.get(KEY_CORRELATION), Some("corr-9"));
        assert_eq!(md.get(KEY_SCHEMA_VERSION), Some("v1"));
        assert_eq!(
            md.get(KEY_SCHEMA_HASH),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn persisted_only_headers_are_dropped_on_rehydrate() {
        let mut table = FieldTable::default();
        table.insert(
            KEY_SUBJECT_ID.into(),
            AMQPValue::LongString(b"spoofed-subject".to_vec().into()),
        );
        table.insert(
            KEY_PRINCIPAL.into(),
            AMQPValue::LongString(b"spoofed-principal".to_vec().into()),
        );
        table.insert(
            KEY_ACTOR.into(),
            AMQPValue::LongString(b"spoofed-actor".to_vec().into()),
        );
        table.insert(
            KEY_CORRELATION.into(),
            AMQPValue::LongString(b"corr-safe".to_vec().into()),
        );
        let props = BasicProperties::default().with_headers(table);
        let md = extract_metadata(&props);

        assert_eq!(md.get(KEY_CORRELATION), Some("corr-safe"));
        assert_eq!(md.get(KEY_SUBJECT_ID), None);
        assert_eq!(md.get(KEY_PRINCIPAL), None);
        assert_eq!(md.get(KEY_ACTOR), None);
    }

    #[test]
    fn non_long_string_headers_skipped() {
        // 非 LongString（非本 adapter 产出路径）应静默跳过，不 panic。
        let mut table = FieldTable::default();
        table.insert("bool-field".into(), AMQPValue::Boolean(true));
        let props = BasicProperties::default().with_headers(table);
        let md = extract_metadata(&props);
        assert_eq!(md.get("bool-field"), None);
    }

    #[test]
    fn full_roundtrip_timestamp_and_headers() {
        let mut table = FieldTable::default();
        table.insert(
            KEY_CORRELATION.into(),
            AMQPValue::LongString(b"corr-full".to_vec().into()),
        );
        let props = BasicProperties::default()
            .with_timestamp(1_700_000_001_u64)
            .with_headers(table);
        let md = extract_metadata(&props);
        assert_eq!(md.occurred_at_secs(), Some(1_700_000_001_i64));
        assert_eq!(md.get(KEY_CORRELATION), Some("corr-full"));
    }
}
