//! lapin AMQP 发布 adapter——impl `diport::Publisher` + `diport::ManagedResource`。
//!
//! ref: lapin examples/pubsub.rs@main（basic_publish 默认 exchange + routing key=topic + 双 await confirm）。

use std::sync::Arc;

use diport::{ManagedResource, PublishRequest, Publisher, PublisherError, ShutdownError};
use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Channel, Connection};

use crate::conn::{self, REPLY_SUCCESS};

/// publish 被 broker 拒绝（durable publish-ok 语义失败）。internal source（不进 Display 凭据边界）。
#[derive(Debug, thiserror::Error)]
enum PublishRejected {
    /// broker nack（队列错误 / 资源不足等）。
    #[error("amqp broker nacked the message")]
    Nack,
    /// 消息不可路由（mandatory=true 下无绑定 queue，被 broker 退回）。
    #[error("amqp message was unroutable (no bound queue)")]
    Unroutable,
}

/// AMQP 事件发布 adapter（lapin）。raw client（`Arc<Connection>` + `Channel`）**私有**——仅本 adapter
/// 内部（publish / shutdown）使用，不向 crate 内其它模块暴露 raw 连接。
/// 同时 impl `Publisher` 与 `ManagedResource`（各有 `shutdown`）；消费经 `DynPublisher` /
/// `Box<DynManagedResource>` 无歧义，直接操作 raw struct 时用 UFCS 消歧。
pub struct AmqpPublisher {
    conn: Arc<Connection>,
    channel: Channel,
    name: String,
}

impl AmqpPublisher {
    /// 从单个 per-domain AMQP URL 连接（URL 含 `user:pass@host/vhost`）。`name` 是 `ManagedResource`
    /// 可读名（kebab/snake 稳定标识）。连接失败日志只经 redaction funnel，URL 原文绝不进日志。
    pub async fn connect(
        url: &str,
        name: impl Into<String>,
    ) -> Result<Self, conn::AmqpConnectError> {
        let name = name.into();
        // confirm=true：启用 publisher confirms，使 publish 能检测 broker ack/nack（durable publish-ok）。
        let (conn, channel) = conn::connect(url, &name, true).await?;
        Ok(Self {
            conn,
            channel,
            name,
        })
    }
}

impl Publisher for AmqpPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        // 默认 exchange（""）+ routing key = topic：消息路由到同名 queue（consumer 声明）。
        // per-domain 隔离经 vhost（连接 URL），非 exchange 命名。MessageMetadata 冻结期无 setter
        // ⇒ 不注入 header（reserved key 由 outbox envelope 注入，业务不伪造，见 diport）。
        // mandatory=true + publisher confirms：不可路由（无绑定 queue）消息被 broker **退回**而非静默丢弃，
        // 经 confirm 检测为失败——durable publish-ok 语义闭合（不再依赖「subscriber 先启动」运行顺序约定）。
        let confirmation = self
            .channel
            .basic_publish(
                "".into(),
                request.topic.as_str().into(),
                BasicPublishOptions {
                    mandatory: true,
                    ..Default::default()
                },
                &request.payload,
                BasicProperties::default(),
            )
            .await
            .map_err(PublisherError::new)?
            // confirm_select 已启用 ⇒ await PublisherConfirm 拿到真实 Ack/Nack/返回消息。
            .await
            .map_err(PublisherError::new)?;
        if confirmation.is_nack() {
            return Err(PublisherError::new(PublishRejected::Nack));
        }
        // unroutable（mandatory 退回）⇒ 发布失败（take_message 消费 confirmation，置于末尾）。
        if confirmation.take_message().is_some() {
            return Err(PublisherError::new(PublishRejected::Unroutable));
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // port-local 关 channel；connection 由 ManagedResource::shutdown 关（ShutdownStack 编排）。
        self.channel
            .close(REPLY_SUCCESS, "publisher shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp channel close error");
            })
            .map_err(PublisherError::new)
    }
}

impl ManagedResource for AmqpPublisher {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.conn
            .close(REPLY_SUCCESS, "publisher resource shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp connection close error");
            })
            .map_err(ShutdownError::new)
    }
}
