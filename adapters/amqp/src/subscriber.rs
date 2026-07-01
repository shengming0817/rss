//! amqp — RSS AMQP 事件订阅 adapter——impl `diport::AckableSubscriber` + `diport::ManagedResource`。
//!
//! `basic_consume` 的 `Consumer`（`Stream<Item = Result<Delivery>>`）适配成 `diport::DeliveryStream`
//! （manual-ack，`AckableSubscriber`）：`token` 取消即流终止（对标 `adapters/memory` 的 `take_until`）。
//! P7 manual-ack：`no_ack=false` + `basic_qos(PREFETCH)`，每条 [`diport::Delivery`] 携 [`AmqpAcker`] 句柄。
//! AMQP 仅 at-least-once（manual-ack）：经 `AckableSubscriber::subscribe_ackable`；
//! at-most-once 仅 demo 拓扑的 MemBus。
//! ref: lapin examples/pubsub.rs@main；rabbitmq docs/confirms。

use std::sync::Arc;

use diport::{
    AckAction, AckError, AckableSubscriber, Delivery as DiDelivery, DeliveryStream,
    EnvelopeMetadata, KEY_OCCURRED_AT, ManagedResource, Message, ShutdownError, SubscriberError,
    Topic,
};
use futures::StreamExt;
use lapin::message::Delivery;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions, QueueDeclareOptions,
};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{Channel, Connection};
use tokio_util::sync::CancellationToken;

use crate::conn::{self, REPLY_SUCCESS};
use crate::settle::{SettleMode, settle_mode};

/// channel 上最多 unacked 消息上限（限 channel 级 unacked window；at-least-once 背压）。
/// 取值依据：RabbitMQ 推荐 100–300（ref: rabbitmq docs/confirms §prefetch / consumer-prefetch）。
const PREFETCH: u16 = 100;

/// AMQP 事件订阅 adapter（lapin）。raw `Arc<Connection>` **私有**——仅本 adapter 内部使用，不向 crate 内
/// 其它模块暴露 raw 连接。impl `AckableSubscriber` + `ManagedResource`。
///
/// **每订阅独立 channel**（review #274 F4/C4）：`subscribe_ackable` 每次从 `conn` 新开一个 channel 承载该
/// 订阅，token cancel 只关**本订阅** channel，不连带终止同实例其它 topic 的 consumer；subscriber 级 shutdown
/// 关闭整个 `conn`（其下所有订阅 channel 随之关闭）。
pub struct AmqpSubscriber {
    conn: Arc<Connection>,
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
        Ok(Self { conn, name })
    }
}

/// 在给定 channel 上声明 durable queue（与默认 exchange routing key=topic 对齐，见 publisher）。
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
        .map(|_| ())
        .map_err(SubscriberError::new)
}

/// at-least-once 取消（`AckableSubscriber::subscribe_ackable` 专用）：token cancel → **关闭本订阅 channel**。
/// manual-ack（`no_ack=false`）下，已投递未 settle 的消息是 channel 上的 in-flight unacked；`basic_cancel`
/// 仅停**新**投递、**不**动 in-flight，会致其滞留至 channel 关闭才重投。关 channel 令 broker 立即 requeue
/// 该 channel 上全部 unacked 投递（RabbitMQ channel-close 语义），保证取消即可被其它 consumer 重收（review
/// #265 F2/C2）。**每订阅独立 channel**（review #274 F4/C4，见 `AmqpSubscriber`）⇒ 关的是**本订阅**的
/// channel，不连带终止同 subscriber 其它 topic 的 consumer；`channel` 是 Clone（cheap handle）。
async fn cancel_ackable_on_token(channel: Channel, token: CancellationToken) {
    token.cancelled().await;
    if let Err(error) = channel
        .close(REPLY_SUCCESS, "ackable subscribe cancelled".into())
        .await
    {
        tracing::warn!(target: "amqp", error = %secure::redact_error(&error), "amqp ackable cancel channel close error");
    }
}

impl ManagedResource for AmqpSubscriber {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
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
fn delivery_to_ackable(delivery: Delivery) -> DiDelivery {
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
        diport::DynAcker::new_box(AmqpAcker { inner: acker }),
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
}

impl diport::Acker for AmqpAcker {
    async fn settle(&self, action: AckAction) -> Result<(), AckError> {
        match settle_mode(action) {
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
        .map(|_| ())
        .map_err(AckError::new)
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
        // 每订阅独立 channel（review #274 F4/C4）：token cancel 关本 channel 不连带停掉同 subscriber 其它
        // topic 的 consumer。channel 由本订阅的 consumer stream + cancel future 持有（owned），随流终止释放。
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

        // Consumer → Delivery（携 acker）。取消经 take_until(cancel_ackable_on_token)：token cancel → 关本订阅
        // channel 令 broker requeue in-flight unacked（at-least-once 取消语义），不影响同 subscriber 其它订阅。
        // consumer_tag 已用于 basic_consume（稳定 tag）；关 channel 取消该 channel 上 consumer，cancel future 不再需 tag。
        let stream = consumer
            .filter_map(|res| async move {
                match res {
                    Ok(delivery) => Some(delivery_to_ackable(delivery)),
                    Err(error) => {
                        tracing::warn!(
                            target: "amqp",
                            error = %secure::redact_error(&error),
                            "amqp ackable delivery error; skipping",
                        );
                        None
                    }
                }
            })
            .take_until(cancel_ackable_on_token(channel.clone(), token));
        tracing::info!(target: "amqp", resource = %self.name, topic = topic_name, "amqp ackable subscribe started");
        Ok(Box::pin(stream))
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // subscriber 级关闭：关整个 connection（其下所有 per-subscription channel 随之关闭 → broker requeue
        // 各 channel 上 in-flight unacked）。每订阅 channel 已由各自 token cancel 独立关闭（F4/C4）。
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
