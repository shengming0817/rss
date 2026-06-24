//! rumqttc v5 MQTT 发布 adapter——impl `diport::Publisher` + `diport::ManagedResource`。
//!
//! rumqttc 须持续 poll `EventLoop` 才能驱动出站 publish + 收 PUBACK，故 [`MqttPublisher::connect`] spawn
//! 一个 driver task 泵 eventloop。`publish` 经 `conn::Confirmations::submit` 入队 + **等 broker PUBACK** 才
//! 返回 Ok（真 at-least-once：消费方〔outbox relay〕据 Ok 结算 published；崩溃/拒绝/超时则 Err、可重试，
//! 对标 amqp publisher confirms）。event_id 经 v5 `correlation_data` 盖章，订阅侧读回填入 `Message.id`。
//! 关停经 `conn::teardown`（幂等）→ driver 自身 `graceful_disconnect` 发 DISCONNECT 后退出。
//!
//! ref: bytebeamio/rumqtt rumqttc/examples/asyncpubsub_v5.rs@main（poll 驱动 + Outgoing::Publish/PubAck）。

use std::sync::{Arc, Mutex};

use diport::{ManagedResource, PublishRequest, Publisher, PublisherError, ShutdownError};
use rumqttc::Outgoing;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Packet, PublishProperties};
use rumqttc::v5::{AsyncClient, ConnectionError, Event, EventLoop};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::conn::{self, Confirmations};

/// MQTT 事件发布 adapter（rumqttc v5）。raw client（`AsyncClient`）**私有**——仅本 adapter 内部
/// （publish / shutdown）使用。同时 impl `Publisher` 与 `ManagedResource`（各有 `shutdown`）；消费经
/// `DynPublisher` / `Box<DynManagedResource>` 无歧义，直接操作 raw struct 时用 UFCS 消歧。
pub struct MqttPublisher {
    client: AsyncClient,
    name: String,
    /// PUBACK 确认簿（publish 等 broker ACK，driver 结算）。
    confirm: Arc<Confirmations>,
    /// driver task 关停 token——shutdown cancel 后 driver select 命中 break → 优雅断连 → 退出。
    token: CancellationToken,
    /// driver task 句柄。`Option`：`teardown` take 走后置 `None`，使第二次 shutdown 成 no-op（幂等 guard）。
    driver: Mutex<Option<JoinHandle<()>>>,
}

impl MqttPublisher {
    /// 从单个 per-domain MQTT URL（`mqtt://host[:port]`，v1 禁 userinfo）连接。`name` 是 `ManagedResource`
    /// 可读名（operator 设，勿含租户/业务语义——会进 MQTT client-id wire）。连接失败日志只经 redaction
    /// funnel，URL 原文绝不进日志。
    pub async fn connect(
        url: &str,
        name: impl Into<String>,
    ) -> Result<Self, conn::MqttConnectError> {
        let name = name.into();
        let (client, eventloop) = conn::connect(url, &name).await?;
        let confirm = Arc::new(Confirmations::new());
        let token = CancellationToken::new();
        let handle = tokio::spawn(drive(
            eventloop,
            token.clone(),
            client.clone(),
            name.clone(),
            Arc::clone(&confirm),
        ));
        Ok(Self {
            client,
            name,
            confirm,
            token,
            driver: Mutex::new(Some(handle)),
        })
    }
}

/// publisher driver：poll eventloop 驱动出站 + 结算 PUBACK 确认；token cancel → 优雅断连退出。
async fn drive(
    mut eventloop: EventLoop,
    token: CancellationToken,
    client: AsyncClient,
    name: String,
    confirm: Arc<Confirmations>,
) {
    let mut degraded = false;
    loop {
        tokio::select! {
            // biased：优先检查 token（确定性关停；poll 进行中 future 被 drop 仅发生在关停路径，安全）。
            biased;
            _ = token.cancelled() => break,
            polled = eventloop.poll() => {
                handle_pub_event(&polled, &confirm);
                conn::note_poll_health(&polled, &mut degraded, &name).await;
            }
        }
    }
    // 关停：driver 自身发 DISCONNECT 并泵出（同一 task 拥有 eventloop ⇒ DISCONNECT 真正写出）。
    conn::graceful_disconnect(&name, &client, &mut eventloop).await;
}

/// 结算 PUBACK 确认：`Outgoing::Publish(pkid)` 关联 pending、`Incoming::PubAck` 结算、连接错误 fanout。
fn handle_pub_event(polled: &Result<Event, ConnectionError>, confirm: &Confirmations) {
    match polled {
        Ok(Event::Outgoing(Outgoing::Publish(pkid))) => confirm.on_sent(*pkid),
        Ok(Event::Incoming(Packet::PubAck(ack))) => {
            confirm.on_ack(ack.pkid, conn::puback_result(&ack.reason));
        }
        Err(_) => confirm.fail_all(),
        _ => {}
    }
}

impl Publisher for MqttPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        // event_id 盖进 v5 correlation_data（去重锚点）：经 broker 流到订阅侧 `Message.id`，实现跨进程
        // 「至少一次 + 幂等去重」。MessageMetadata 冻结期无 setter ⇒ 不注入 user properties。
        let correlation: Vec<u8> = request.event_id.as_str().as_bytes().to_vec();
        let properties = PublishProperties {
            correlation_data: Some(correlation.into()),
            ..Default::default()
        };
        let topic = request.topic.as_str().to_string();
        // submit：入队 + 等 broker PUBACK 才返回 Ok（QoS1 真 at-least-once；broker 拒绝/断连/超时 ⇒ Err，
        // 消费方据此可重试，不会把未确认 publish 当成功结算）。
        self.confirm
            .submit(self.client.publish_with_properties(
                topic,
                QoS::AtLeastOnce,
                false,
                request.payload,
                properties,
            ))
            .await
            .map_err(PublisherError::new)
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // port-local 与 ManagedResource 共用 teardown（幂等：driver 唯一执行优雅断连，两条路径不重复断连）。
        conn::teardown(&self.name, &self.token, &self.driver).await;
        Ok(())
    }
}

impl ManagedResource for MqttPublisher {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // cancel driver token + await driver 退出（driver 自身优雅断连）；ShutdownStack 外层有超时。
        conn::teardown(&self.name, &self.token, &self.driver).await;
        Ok(())
    }
}
