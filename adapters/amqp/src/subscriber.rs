//! amqp — RSS AMQP 事件订阅 adapter——impl `diport::AckableSubscriber` + `diport::ManagedResource`。
//!
//! `basic_consume` 的 `Consumer`（`Stream<Item = Result<Delivery>>`）适配成 `diport::DeliveryStream`
//! （manual-ack，`AckableSubscriber`）：`token` 取消即流终止（对标 `adapters/memory` 的 `take_until`）。
//! P7 manual-ack：`no_ack=false` + `basic_qos(PREFETCH)`，每条 [`diport::Delivery`] 携 [`AmqpAcker`] 句柄。
//! AMQP 仅 at-least-once（manual-ack）：经 `AckableSubscriber::subscribe_ackable`；
//! at-most-once 仅 demo 拓扑的 MemBus。
//! ref: lapin examples/pubsub.rs@main；rabbitmq docs/confirms。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use diport::{
    AckAction, AckError, AckableSubscriber, Delivery as DiDelivery, DeliveryStream,
    EnvelopeMetadata, KEY_OCCURRED_AT, ManagedResource, Message, ShutdownError, SubscriberError,
    Topic,
};
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
use tokio_util::sync::CancellationToken;

use crate::conn::{self, REPLY_SUCCESS};
use crate::settle::{SettleMode, settle_mode};

/// channel 上最多 unacked 消息上限（限 channel 级 unacked window；at-least-once 背压）。
/// 取值依据：RabbitMQ 推荐 100–300（ref: rabbitmq docs/confirms §prefetch / consumer-prefetch）。
// ConsumerTx is deliberately sequential. A window of one prevents a second delivery from becoming
// in-flight while the first transaction is blocked during graceful shutdown.
const PREFETCH: u16 = 1;

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
}

impl AmqpSubscriber {
    /// 从单个 per-domain AMQP URL 连接（URL 含 `user:pass@host/vhost`）。`name` 是 `ManagedResource`
    /// 可读名。连接失败日志只经 redaction funnel，URL 原文绝不进日志。
    pub async fn connect(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
    ) -> Result<Self, conn::AmqpConnectError> {
        let name = name.into();
        // confirm=false：subscriber 不需 publisher confirms。
        // reason: 订阅 channel 由 subscribe_ackable 按需 per-subscription 新开（F4）；connect 借
        // conn::connect 拿连接 + redaction 日志，其返回的初始 channel 不用于订阅，drop 即可。
        let (conn, _channel) = conn::connect(endpoint, &name, false).await?;
        Ok(Self {
            conn,
            channels: std::sync::Mutex::new(Vec::new()),
            operational: AtomicBool::new(true),
            name,
        })
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
        })
    }

    pub(crate) fn readiness_snapshot(&self) -> bool {
        self.operational.load(Ordering::Acquire)
            && self.conn.status().connected()
            && self.channels.lock().is_ok_and(|channels| {
                !channels.is_empty() && channels.iter().all(|channel| channel.status().connected())
            })
    }

    /// Purge the durable queue owned by one generated topic before an integration run.
    ///
    /// Long-lived test brokers retain durable messages, and closing a manual-ack channel
    /// requeues every unsettled delivery. Fault-injection tests use this typed, test-only seam
    /// before subscribing so a failed prior run cannot enter the next run's ConsumerTx.
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
        declare_durable_queue(&channel, topic.as_str()).await?;
        let purged = channel
            .queue_purge(topic.as_str().into(), QueuePurgeOptions::default())
            .await
            .map_err(SubscriberError::new)?;
        channel
            .close(REPLY_SUCCESS, "test queue purge complete".into())
            .await
            .map_err(SubscriberError::new)?;
        Ok(purged)
    }
}

/// 在给定 channel 上声明 durable queue，并绑定 production topic exchange 的 exact routing key。
/// `subscribe_ackable`（manual-ack）在其 per-subscription channel 上调用。
async fn declare_durable_queue(channel: &Channel, topic_name: &str) -> Result<(), SubscriberError> {
    channel
        .queue_declare(
            topic_name.into(),
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(SubscriberError::new)?;
    channel
        .queue_bind(
            topic_name.into(),
            crate::EVENT_EXCHANGE.into(),
            topic_name.into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map(|_| ())
        .map_err(SubscriberError::new)
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
    async fn subscribe_ackable(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<DeliveryStream, SubscriberError> {
        let topic_name = topic.as_str();
        // 稳定 consumer tag（按 name+topic 派生）：重连/重订阅复用同一 tag，不变成新消费者
        // （eventbus.md §DLX「consumer group 命名稳定」）。
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
        declare_durable_queue(&channel, topic_name).await?;
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
        let stream = consumer
            .filter_map(move |res| {
                let delivery_channel = channel.clone();
                let delivery_rpc = Arc::clone(&delivery_rpc);
                async move {
                    match res {
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
    use super::pick_message_id;

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
