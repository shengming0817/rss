//! lapin AMQP 订阅 adapter——impl `diport::Subscriber` + `diport::ManagedResource`。
//!
//! `basic_consume` 的 `Consumer`（`Stream<Item = Result<Delivery>>`）适配成 `diport::MessageStream`：
//! `token` 取消即流终止（对标 `adapters/memory` 的 `take_until`）。P6 用 `no_ack=true`（auto-ack，
//! 见 crate rustdoc「P6 传输边界」）。ref: lapin examples/pubsub.rs@main。

use std::sync::Arc;

use diport::{
    ManagedResource, Message, MessageStream, ShutdownError, Subscriber, SubscriberError, Topic,
};
use futures::StreamExt;
use lapin::message::Delivery;
use lapin::options::{BasicCancelOptions, BasicConsumeOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{Channel, Connection};
use tokio_util::sync::CancellationToken;

use crate::conn::{self, REPLY_SUCCESS};

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
        // 声明 durable queue（与默认 exchange routing key=topic 对齐，见 publisher）。
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
            .map_err(SubscriberError::new)?;
        let consumer = self
            .channel
            .basic_consume(
                topic_name.into(),
                consumer_tag.as_str().into(),
                // P6: no_ack=true（auto-ack，at-most-once）——手工 ack/Disposition/DLX 由 P7 ConsumerBase
                // 接管（深层 ack-capable delivery seam = P7，见 crate rustdoc「P6 传输边界」）。
                BasicConsumeOptions {
                    no_ack: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(SubscriberError::new)?;

        // 取消时显式 basic_cancel（停 broker 投递）再终止流；channel 是 Clone（cheap handle）。
        let cancel_channel = self.channel.clone();
        // Consumer: Stream<Item = Result<Delivery>> → Message。delivery 错误侧记后跳过（不 kill 流）。
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
            .take_until(async move {
                token.cancelled().await;
                if let Err(error) = cancel_channel
                    .basic_cancel(consumer_tag.as_str().into(), BasicCancelOptions::default())
                    .await
                {
                    tracing::warn!(target: "amqp", error = %secure::redact_error(&error), "amqp basic_cancel error");
                }
            });
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

/// 派生 message id：优先 producer 设置的 `message_id`（非空白），否则用 broker 的 `delivery_tag`。
/// 纯函数——无 broker 单元可测。纯空白 `message_id` 视同缺失（退 delivery_tag）。
fn pick_message_id(message_id: Option<&str>, delivery_tag: u64) -> String {
    message_id
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| delivery_tag.to_string())
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
}
