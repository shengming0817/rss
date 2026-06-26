//! lapin AMQP 发布 adapter——impl `diport::Publisher` + `diport::ManagedResource`。
//!
//! ref: lapin examples/pubsub.rs@main（basic_publish 默认 exchange + routing key=topic + 双 await confirm）。

use std::sync::Arc;

use diport::{ManagedResource, PublishRequest, Publisher, PublisherError, ShutdownError};
use lapin::options::BasicPublishOptions;
use lapin::protocol::{AMQPErrorKind, AMQPSoftError};
use lapin::{BasicProperties, Channel, Connection, ErrorKind};

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

/// `lapin::Error` → [`PublisherError`]，按瞬态/永久分类（#1212：永久错误首投即 DLX，不熬满重试预算）。
///
/// 分类策略（ref: amqp-rs/lapin src/error.rs@v4.10.0 `Error::can_be_recovered`）：
/// - **AMQP soft（channel-level）非自愈错误** → permanent：重试同一消息必然再失败（权限拒绝、声明参数冲突、
///   消息超限——非启动时序问题），见 [`is_permanent_soft_error`]。
/// - 其余按 lapin 内建 `can_be_recovered()` 兜底：可恢复（IOError / channel·connection state /
///   MissingHeartbeat / hard ProtocolError / **路由目标尚未声明类 soft 错误 NOROUTE·NOTFOUND**）→ **transient**
///   退避重连/等拓扑收敛；不可恢复（SerialisationError / ParsingError / InvalidProtocolVersion /
///   AuthProviderError / ChannelsLimitReached / ...）→ **permanent**。`ErrorKind` 是 `#[non_exhaustive]`——
///   `can_be_recovered()` 兜底，无需在此穷尽 match。
///
/// **default-transient 取向（review #278 F1）**：「路由目标当前不存在」（NOROUTE/NOTFOUND/`basic.return`
/// unroutable）**不**判永久——AMQP queue 由 `AmqpSubscriber::subscribe_ackable` 声明、无组合根级硬屏障保证
/// relay 发布前队列已就绪，启动/重启窗口的 unroutable 可经退避重试等订阅完成收敛。瞬态误判永久会跳过 outbox
/// 自愈、破坏 L2 最终送达（代价高于「永久错误慢 DLX」）。彻底解（启动期声明 active subscriber 队列 + relay
/// readiness 屏障 / topology provisioning port）属组合根，OOS follow-up。
fn classify_publish(e: lapin::Error) -> PublisherError {
    if is_permanent_lapin(&e) {
        PublisherError::permanent(e)
    } else {
        PublisherError::transient(e)
    }
}

/// 该 lapin 错误是否永久（重试同一消息必然再失败）。
fn is_permanent_lapin(e: &lapin::Error) -> bool {
    if let ErrorKind::ProtocolError(amqp) = e.kind()
        && let AMQPErrorKind::Soft(soft) = amqp.kind()
        && is_permanent_soft_error(soft)
    {
        return true;
    }
    !e.can_be_recovered()
}

/// AMQP soft（channel-level）错误中「重试同一消息必然再失败」的**非自愈**类——首投即 DLX。
///
/// 仅含 message/config-intrinsic 因（权限 / 声明参数冲突 / 消息超限）：退避重试同一消息不会改变结果。
/// **不含**「路由目标尚未声明」类（NOROUTE / NOTFOUND）与「可随生命周期自愈」类（NOCONSUMERS 消费者上线 /
/// RESOURCELOCKED 锁释放）——后者归 transient，由 [`classify_publish`] 的 `can_be_recovered()` 兜底（review
/// #278 F1：拓扑/路由尚未收敛 ≠ 永久非法）。
fn is_permanent_soft_error(soft: &AMQPSoftError) -> bool {
    matches!(
        soft,
        AMQPSoftError::ACCESSREFUSED        // 403 权限拒绝（ACL 非启动时序问题）
            | AMQPSoftError::PRECONDITIONFAILED // 406 声明参数冲突
            | AMQPSoftError::CONTENTTOOLARGE // 311 消息超 broker 限制（消息固有）
    )
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
        // message_id = event_id（去重锚点）：经 broker envelope 流到订阅侧 `Message.id`（subscriber 的
        // `pick_message_id` 优先读 message_id 再回退 delivery_tag），实现跨进程「至少一次 + 幂等去重」。
        let properties =
            BasicProperties::default().with_message_id(request.event_id.as_str().into());
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
                properties,
            )
            .await
            .map_err(classify_publish)?
            // confirm_select 已启用 ⇒ await PublisherConfirm 拿到真实 Ack/Nack/返回消息。
            .await
            .map_err(classify_publish)?;
        if confirmation.is_nack() {
            // broker nack（队列错误 / 资源压力等）→ transient：退避后可能恢复，不首投即 DLX。
            return Err(PublisherError::transient(PublishRejected::Nack));
        }
        // unroutable（mandatory 退回，无绑定 queue）→ transient（review #278 F1）：queue 由
        // AmqpSubscriber::subscribe_ackable 声明、无组合根级硬屏障保证 relay 发布前队列已就绪，启动/重启窗口
        // 「当前无绑定 queue」可经退避重试等订阅完成收敛。判永久会跳过 outbox 自愈、破坏 L2 最终送达——「路由
        // 目标当前不存在」≠ 永久非法（RabbitMQ basic.return 语义；与 NOROUTE/NOTFOUND 一致归 transient）。
        if confirmation.take_message().is_some() {
            return Err(PublisherError::transient(PublishRejected::Unroutable));
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
            // shutdown 不经 relay settle，kind 无关——transient benign 默认（不夸大为永久）。
            .map_err(PublisherError::transient)
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

#[cfg(test)]
mod classify_tests {
    //! #1212 lapin 错误瞬态/永久分类表驱动：永久错误首投即 DLX，瞬态退避重试。无需真实 broker——
    //! 仅构造 `lapin::Error` 值检验分类逻辑（`Error::from(ErrorKind::..)` + `AMQPError::new(..)`）。
    use std::sync::Arc;

    use diport::PublishErrorKind;
    use lapin::ErrorKind;
    use lapin::protocol::{AMQPError, AMQPErrorKind, AMQPHardError, AMQPSoftError};

    use super::{PublishRejected, classify_publish, is_permanent_lapin};

    fn io() -> lapin::Error {
        lapin::Error::from(ErrorKind::IOError(Arc::new(std::io::Error::other("reset"))))
    }
    fn soft(s: AMQPSoftError) -> lapin::Error {
        lapin::Error::from(ErrorKind::ProtocolError(AMQPError::new(
            AMQPErrorKind::Soft(s),
            "test".into(),
        )))
    }
    fn hard(h: AMQPHardError) -> lapin::Error {
        lapin::Error::from(ErrorKind::ProtocolError(AMQPError::new(
            AMQPErrorKind::Hard(h),
            "test".into(),
        )))
    }

    #[test]
    fn classify_table() {
        // (lapin 错误, 期望 permanent?, 标签)
        let cases: Vec<(lapin::Error, bool, &str)> = vec![
            (io(), false, "IOError→transient"),
            (
                lapin::Error::from(ErrorKind::ChannelsLimitReached),
                true,
                "ChannelsLimitReached→permanent",
            ),
            (
                lapin::Error::from(ErrorKind::AuthProviderError("bad".into())),
                true,
                "AuthProviderError→permanent",
            ),
            // 路由目标尚未声明类 → transient（review #278 F1：拓扑未收敛 ≠ 永久非法）。
            (
                soft(AMQPSoftError::NOTFOUND),
                false,
                "soft404 NOTFOUND→transient (target not declared yet)",
            ),
            (
                soft(AMQPSoftError::NOROUTE),
                false,
                "soft312 NOROUTE→transient (no route yet)",
            ),
            // 非自愈类（权限 / 参数 / 大小）→ permanent。
            (
                soft(AMQPSoftError::ACCESSREFUSED),
                true,
                "soft403 ACCESSREFUSED→permanent",
            ),
            (
                soft(AMQPSoftError::PRECONDITIONFAILED),
                true,
                "soft406 PRECONDITIONFAILED→permanent",
            ),
            (
                soft(AMQPSoftError::CONTENTTOOLARGE),
                true,
                "soft311 CONTENTTOOLARGE",
            ),
            (
                soft(AMQPSoftError::NOCONSUMERS),
                false,
                "soft313 NOCONSUMERS→transient",
            ),
            (
                soft(AMQPSoftError::RESOURCELOCKED),
                false,
                "soft405 RESOURCELOCKED→transient",
            ),
            (
                hard(AMQPHardError::CONNECTIONFORCED),
                false,
                "hard320 CONNECTIONFORCED→transient",
            ),
            (
                hard(AMQPHardError::RESOURCEERROR),
                false,
                "hard506 RESOURCEERROR→transient",
            ),
        ];
        for (err, want_permanent, label) in cases {
            assert_eq!(
                is_permanent_lapin(&err),
                want_permanent,
                "is_permanent_lapin: {label}"
            );
            let want = if want_permanent {
                PublishErrorKind::Permanent
            } else {
                PublishErrorKind::Transient
            };
            assert_eq!(
                classify_publish(err).kind(),
                want,
                "classify_publish: {label}"
            );
        }
    }

    // 我方 PublishRejected 在 publish() 调用点直接分类（不经 classify_publish）——锁定 disposition 接线意图：
    // Nack（资源压力）→ transient 退避；Unroutable（无绑定 queue，路由目标尚未声明）→ transient 退避等订阅
    // 完成收敛（review #278 F1：不首投即 DLX，保 L2 最终送达）。
    #[test]
    fn publish_rejected_dispositions() {
        assert!(diport::PublisherError::transient(PublishRejected::Nack).is_transient());
        assert!(diport::PublisherError::transient(PublishRejected::Unroutable).is_transient());
    }
}
