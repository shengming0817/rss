//! lapin AMQP 订阅 adapter——impl `diport::Subscriber` + `diport::AckableSubscriber` +
//! `diport::ManagedResource`。
//!
//! `basic_consume` 的 `Consumer`（`Stream<Item = Result<Delivery>>`）适配成 `diport::MessageStream`
//! （auto-ack，`Subscriber`）或 `diport::DeliveryStream`（manual-ack，`AckableSubscriber`）：
//! `token` 取消即流终止（对标 `adapters/memory` 的 `take_until`）。
//! P7 manual-ack：`no_ack=false` + `basic_qos(PREFETCH)`，每条 [`diport::Delivery`] 携 [`AmqpAcker`] 句柄。
//! ref: lapin examples/pubsub.rs@main；rabbitmq docs/confirms。

use std::sync::Arc;

use diport::{
    AckAction, AckError, AckableSubscriber, Delivery as DiDelivery, DeliveryStream,
    ManagedResource, Message, MessageStream, ShutdownError, Subscriber, SubscriberError, Topic,
};
use futures::StreamExt;
use lapin::message::Delivery;
use lapin::options::{
    BasicAckOptions, BasicCancelOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions,
    QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{Channel, Connection};
use tokio_util::sync::CancellationToken;

use crate::conn::{self, REPLY_SUCCESS};
use crate::settle::{SettleMode, settle_mode};

/// channel 上最多 unacked 消息上限（限 channel 级 unacked window；at-least-once 背压）。
/// 取值依据：RabbitMQ 推荐 100–300（ref: rabbitmq docs/confirms §prefetch / consumer-prefetch）。
const PREFETCH: u16 = 100;

/// AMQP 事件订阅 adapter（lapin）。raw client（`Arc<Connection>` + `Channel`）**私有**——仅本 adapter
/// 内部（subscribe / shutdown）使用，不向 crate 内其它模块暴露 raw 连接。
/// 同时 impl `Subscriber` 与 `ManagedResource`。
pub struct AmqpSubscriber {
    conn: Arc<Connection>,
    channel: Channel,
    name: String,
}

impl AmqpSubscriber {
    /// 从单个 per-domain AMQP URL 连接（URL 含 `user:pass@host/vhost`）。`name` 是 `ManagedResource`
    /// 可读名。连接失败日志只经 redaction funnel，URL 原文绝不进日志。
    pub async fn connect(
        url: &str,
        name: impl Into<String>,
    ) -> Result<Self, conn::AmqpConnectError> {
        let name = name.into();
        // confirm=false：subscriber 不需 publisher confirms。
        let (conn, channel) = conn::connect(url, &name, false).await?;
        Ok(Self {
            conn,
            channel,
            name,
        })
    }

    /// 声明 durable queue（与默认 exchange routing key=topic 对齐，见 publisher）。
    /// `subscribe`（auto-ack）与 `subscribe_ackable`（manual-ack）共用，去重二者同构声明块。
    async fn declare_durable_queue(&self, topic_name: &str) -> Result<(), SubscriberError> {
        self.channel
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
}

/// at-most-once 取消（`Subscriber::subscribe` 专用）：token cancel → `basic_cancel` 停新投递。
/// auto-ack（`no_ack=true`）无 in-flight unacked（broker 投递即出队），故停新投递即可、不需关 channel。
/// `channel` 是 Clone（cheap handle）。
async fn cancel_on_token(channel: Channel, consumer_tag: String, token: CancellationToken) {
    token.cancelled().await;
    if let Err(error) = channel
        .basic_cancel(consumer_tag.as_str().into(), BasicCancelOptions::default())
        .await
    {
        tracing::warn!(target: "amqp", error = %secure::redact_error(&error), "amqp basic_cancel error");
    }
}

/// at-least-once 取消（`AckableSubscriber::subscribe_ackable` 专用）：token cancel → **关闭 channel**。
/// manual-ack（`no_ack=false`）下，已投递未 settle 的消息是 channel 上的 in-flight unacked；`basic_cancel`
/// 仅停**新**投递、**不**动 in-flight，会致其滞留至 channel 关闭才重投。关 channel 令 broker 立即 requeue
/// 该 channel 上全部 unacked 投递（RabbitMQ channel-close 语义），保证取消即可被其它 consumer 重收（review
/// #265 F2/C2）。单 subscriber 单 channel（见 `AmqpSubscriber`）⇒ 关 channel 即终止本订阅，`shutdown` 二次
/// 关闭幂等降级（warn）。`channel` 是 Clone（cheap handle）。
async fn cancel_ackable_on_token(channel: Channel, token: CancellationToken) {
    token.cancelled().await;
    if let Err(error) = channel
        .close(REPLY_SUCCESS, "ackable subscribe cancelled".into())
        .await
    {
        tracing::warn!(target: "amqp", error = %secure::redact_error(&error), "amqp ackable cancel channel close error");
    }
}

impl Subscriber for AmqpSubscriber {
    async fn subscribe(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<MessageStream, SubscriberError> {
        let topic_name = topic.as_str();
        // 稳定 consumer tag（按 name+topic 派生）：重连/重订阅复用同一 tag，不变成新消费者
        // （eventbus.md §DLX「consumer group 命名稳定」）。P7 ConsumerBase 手工 ack 沿用此 tag。
        let consumer_tag = format!("{}-{}", self.name, topic_name);
        self.declare_durable_queue(topic_name).await?;
        let consumer = self
            .channel
            .basic_consume(
                topic_name.into(),
                consumer_tag.as_str().into(),
                // no_ack=true（auto-ack，at-most-once）——遗留/brokerless 对偶。手工 ack/Disposition/DLX 走
                // AckableSubscriber::subscribe_ackable（no_ack=false，at-least-once，见 crate rustdoc「P7 传输边界」）。
                BasicConsumeOptions {
                    no_ack: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(SubscriberError::new)?;

        // Consumer: Stream<Item = Result<Delivery>> → Message。delivery 错误侧记后跳过（不 kill 流）。
        // 取消经 take_until(cancel_on_token)：token cancel → basic_cancel 停投递再终止流。
        let stream = consumer
            .filter_map(|res| async move {
                match res {
                    Ok(delivery) => Some(delivery_to_message(delivery)),
                    Err(error) => {
                        tracing::warn!(
                            target: "amqp",
                            error = %secure::redact_error(&error),
                            "amqp delivery error; skipping",
                        );
                        None
                    }
                }
            })
            .take_until(cancel_on_token(self.channel.clone(), consumer_tag, token));
        tracing::info!(target: "amqp", resource = %self.name, topic = topic_name, "amqp subscribe started");
        Ok(Box::pin(stream))
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        self.channel
            .close(REPLY_SUCCESS, "subscriber shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp channel close error");
            })
            .map_err(SubscriberError::new)
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

/// lapin `Delivery` → `diport::Message`。metadata 冻结期无 setter ⇒ 空（reserved key 由 outbox
/// envelope 注入，业务不伪造，见 `diport::MessageMetadata`）。
fn delivery_to_message(delivery: Delivery) -> Message {
    let producer_id = delivery
        .properties
        .message_id()
        .as_ref()
        .map(ToString::to_string);
    let id = pick_message_id(producer_id.as_deref(), delivery.delivery_tag);
    Message::new(id, delivery.data)
}

/// lapin `Delivery` → `diport::Delivery`（携 [`AmqpAcker`] 结算句柄）。
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
    let message = Message::new(id, delivery.data);
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
        // 稳定 consumer tag（与 Subscriber::subscribe 同派生逻辑，P7 manual-ack 对偶）。
        let consumer_tag = format!("{}-ack-{}", self.name, topic_name);
        // prefetch：限 channel 上 unacked 消息上限（P7 at-least-once 背压，RabbitMQ 推荐 100–300）。
        self.channel
            .basic_qos(PREFETCH, BasicQosOptions::default())
            .await
            .map_err(SubscriberError::new)?;
        self.declare_durable_queue(topic_name).await?;
        let consumer = self
            .channel
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

        // Consumer → Delivery（携 acker）。取消经 take_until(cancel_ackable_on_token)：token cancel → 关 channel
        // 令 broker requeue in-flight unacked（at-least-once 取消语义，区别于 auto-ack 的 basic_cancel）。
        // consumer_tag 已用于 basic_consume（稳定 tag）；关 channel 取消全 consumer，cancel future 不再需 tag。
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
            .take_until(cancel_ackable_on_token(self.channel.clone(), token));
        tracing::info!(target: "amqp", resource = %self.name, topic = topic_name, "amqp ackable subscribe started");
        Ok(Box::pin(stream))
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // 复用 Subscriber::shutdown 的 channel close 逻辑。
        self.channel
            .close(REPLY_SUCCESS, "ackable subscriber shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp channel close error (ackable)");
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
