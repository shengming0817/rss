//! rumqttc v5 MQTT 订阅 adapter——impl `diport::Subscriber` + `diport::ManagedResource`。
//!
//! rumqttc 单连接单 `EventLoop`，须调用方持续 poll 才收消息。故 [`MqttSubscriber::connect`] spawn 一个
//! driver task 泵 eventloop，把 incoming `Publish` 按 topic 路由到 per-subscribe 的**有界** mpsc（routing
//! table），并结算 SUBACK 确认。`subscribe` 注册 sender + `client.subscribe`，**等 SUBACK** 才返回（broker
//! 已建订阅 ⇒ 后续 publish 不丢首条）；返回的流由 `token` 取消即终止（`take_until` → unsubscribe + 注销）。
//!
//! P6 传输边界（同 amqp）：QoS1 auto-ack（rumqttc 自动 PUBACK）；不暴露手工 ack。入站有界队列满则 drop+warn
//! （不阻塞 driver，避免 HoL 殃及其它 topic）。app-level `$dead` DLT / `SupportsRequeue=false` / poison =
//! follow-up（P1-8 #1265，含背压 metric）。
//!
//! ref: bytebeamio/rumqtt rumqttc/examples/asyncpubsub_v5.rs@main（poll 取 Packet::{Publish,SubAck}）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use diport::{
    ManagedResource, Message, MessageStream, ShutdownError, Subscriber, SubscriberError, Topic,
};
use futures::StreamExt;
// reason: 用 futures::channel::mpsc 而非 tokio::sync::mpsc——其 `Receiver` 本身即 `Stream`，可直接
// `take_until` 返回 `MessageStream`，无需再引 tokio-stream 的 ReceiverStream wrapper。
use futures::channel::mpsc::{Receiver, Sender, channel};
use rumqttc::Outgoing;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Packet, Publish};
use rumqttc::v5::{AsyncClient, ConnectionError, Event, EventLoop};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::conn::{self, Confirmations};

/// 每条订阅流的入站缓冲上限（**有界**，防慢 consumer 把 broker 入站流量打到 OOM）。满则 drop+warn。
const INBOUND_QUEUE_CAP: usize = 1024;

/// 精确 topic → 该订阅流的消息发送端（driver 据此路由 incoming Publish）。有界 `Sender`。
type RoutingTable = Arc<Mutex<HashMap<String, Sender<Message>>>>;

/// routing table 锁中毒（罕见——仅持锁者 panic 才发生）。
#[derive(Debug, thiserror::Error)]
#[error("mqtt routing table poisoned")]
struct RoutingPoisoned;

/// MQTT 事件订阅 adapter（rumqttc v5）。raw client **私有**——仅本 adapter 内部使用。
/// 同时 impl `Subscriber` 与 `ManagedResource`。
pub struct MqttSubscriber {
    client: AsyncClient,
    name: String,
    /// SUBACK 确认簿（subscribe 等 broker ACK，driver 结算）。
    confirm: Arc<Confirmations>,
    /// driver task 关停 token。
    token: CancellationToken,
    /// topic → 流 sender 路由表（driver 写入 incoming；subscribe 注册、取消时注销、send 断开时 self-heal）。
    routing: RoutingTable,
    /// driver task 句柄。`Option`：`teardown` take 走后置 `None`，使第二次 shutdown 成 no-op（幂等 guard）。
    driver: Mutex<Option<JoinHandle<()>>>,
}

impl MqttSubscriber {
    /// 从单个 per-domain MQTT URL（`mqtt://host[:port]`，v1 禁 userinfo）连接。`name` 是 `ManagedResource`
    /// 可读名（operator 设，勿含租户/业务语义——会进 MQTT client-id wire）。连接失败日志只经 redaction
    /// funnel，URL 原文绝不进日志。
    pub async fn connect(
        url: &str,
        name: impl Into<String>,
    ) -> Result<Self, conn::MqttConnectError> {
        let name = name.into();
        let (client, eventloop) = conn::connect(url, &name).await?;
        let routing: RoutingTable = Arc::new(Mutex::new(HashMap::new()));
        let confirm = Arc::new(Confirmations::new());
        let token = CancellationToken::new();
        let handle = tokio::spawn(drive(
            eventloop,
            token.clone(),
            client.clone(),
            Arc::clone(&routing),
            name.clone(),
            Arc::clone(&confirm),
        ));
        Ok(Self {
            client,
            name,
            confirm,
            token,
            routing,
            driver: Mutex::new(Some(handle)),
        })
    }

    /// 在 routing table 注册一条 topic 流 sender，返回其有界 receiver。已有同 topic entry 则替换（前一流
    /// 静默停收，记 `warn`——见 [`Subscriber::subscribe`] # Contract）。锁中毒 ⇒ `RoutingPoisoned`。
    fn register_sender(&self, topic: &str) -> Result<Receiver<Message>, SubscriberError> {
        let (sender, receiver) = channel::<Message>(INBOUND_QUEUE_CAP);
        let mut map = self
            .routing
            .lock()
            .map_err(|_| SubscriberError::new(RoutingPoisoned))?;
        if map.insert(topic.to_string(), sender).is_some() {
            tracing::warn!(target: "mqtt", resource = %self.name, topic = %topic, "mqtt re-subscribe replaces prior stream for topic");
        }
        Ok(receiver)
    }
}

/// subscriber driver：poll eventloop，路由 incoming Publish + 结算 SUBACK；token cancel → 优雅断连退出。
async fn drive(
    mut eventloop: EventLoop,
    token: CancellationToken,
    client: AsyncClient,
    routing: RoutingTable,
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
                handle_sub_event(&polled, &routing, &name, &confirm);
                conn::note_poll_health(&polled, &mut degraded, &name).await;
            }
        }
    }
    conn::graceful_disconnect(&name, &client, &mut eventloop).await;
}

/// 路由 incoming Publish + 结算 SUBACK 确认 + 连接错误 fanout。
fn handle_sub_event(
    polled: &Result<Event, ConnectionError>,
    routing: &RoutingTable,
    name: &str,
    confirm: &Confirmations,
) {
    match polled {
        Ok(Event::Incoming(Packet::Publish(publish))) => route_incoming(publish, routing, name),
        Ok(Event::Outgoing(Outgoing::Subscribe(pkid))) => confirm.on_sent(*pkid),
        Ok(Event::Incoming(Packet::SubAck(ack))) => {
            confirm.on_ack(ack.pkid, conn::suback_result(&ack.return_codes));
        }
        Err(_) => confirm.fail_all(),
        _ => {}
    }
}

/// 把一条 incoming `Publish` 转成 `diport::Message` 投递到该 topic 的流 sender。
/// - 非 UTF-8 topic：drop + warn（不经 `from_utf8_lossy` 的 U+FFFD 替换——避免不同字节序列撞同一 key 造成
///   跨 topic 消息混淆/劫持）。
/// - send 失败：满队列 drop+warn（不阻塞 driver，避免 HoL）；receiver 已 drop（disconnected）→ self-heal 移除 entry。
fn route_incoming(publish: &Publish, routing: &RoutingTable, name: &str) {
    let Ok(topic) = std::str::from_utf8(&publish.topic) else {
        tracing::warn!(target: "mqtt", resource = name, "mqtt dropped publish on non-utf8 topic");
        return;
    };
    let message = publish_to_message(publish);
    deliver_to_topic(routing, topic, message, name);
}

/// 投递 `Message` 到 `topic` 流 sender：满 → drop+warn（不阻塞 driver）；断开 → self-heal 移除 entry。
fn deliver_to_topic(routing: &RoutingTable, topic: &str, message: Message, name: &str) {
    let Ok(mut map) = routing.lock() else {
        tracing::error!(target: "mqtt", resource = name, "mqtt routing table poisoned");
        return;
    };
    let disconnected = match map.get_mut(topic) {
        Some(sender) => try_send_classify(sender, message, topic, name),
        None => false,
    };
    if disconnected {
        // receiver 已 drop（流被取消或未取消即 drop）→ self-heal 移除 entry（须在 sender 借用结束后）。
        map.remove(topic);
    }
}

/// 向 sender 投递并分类结果：`Ok`/满（drop+warn）→ `false`（保留 entry）；断开 → `true`（caller self-heal）。
fn try_send_classify(
    sender: &mut Sender<Message>,
    message: Message,
    topic: &str,
    name: &str,
) -> bool {
    match sender.try_send(message) {
        Ok(()) => false,
        Err(e) if e.is_full() => {
            // 满队列：drop + warn（慢 consumer 自负；不阻塞 driver 避免 HoL 殃及其它 topic）。
            tracing::warn!(target: "mqtt", resource = name, topic = topic, "mqtt inbound queue full; dropping message");
            false
        }
        Err(_) => true,
    }
}

/// incoming `Publish` → `diport::Message`：id 经 [`pick_message_id`]（correlation_data 优先，退 pkid）；
/// metadata 经 [`crate::envelope::from_user_properties`] 从 v5 `user_properties` rehydrate。
fn publish_to_message(publish: &Publish) -> Message {
    let correlation = publish
        .properties
        .as_ref()
        .and_then(|p| p.correlation_data.as_ref())
        .map(|b| b.as_ref());
    let id = pick_message_id(correlation, &publish.pkid.to_string());
    let user_props = publish
        .properties
        .as_ref()
        .map(|p| p.user_properties.as_slice())
        .unwrap_or(&[]);
    let metadata = crate::envelope::from_user_properties(user_props);
    Message::new_with_metadata(id, publish.payload.to_vec(), metadata)
}

/// 派生 message id：优先 v5 correlation_data（非空白 utf8，= publisher 盖的 event_id），否则用 broker 的
/// pkid。纯函数——无 broker 单元可测。非 utf8 / 纯空白 correlation_data 视同缺失（退 pkid）。
///
/// **幂等语义**：RSS publisher 始终盖 correlation_data，故 fallback 仅命中外部（非 RSS）生产者。pkid 仅
/// MQTT 会话内唯一、断连后重置、QoS0 为 0 ⇒ 作幂等键弱（可碰撞）。依赖去重的消费方须有 correlation_data。
fn pick_message_id(correlation_data: Option<&[u8]>, fallback: &str) -> String {
    correlation_data
        .and_then(|b| std::str::from_utf8(b).ok())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| fallback.to_string())
}

/// 流取消（`token`）后的 cleanup：unsubscribe broker（停投递）+ 注销 routing entry。作为 `take_until`
/// 的终止 future——`token` cancel 即触发。
async fn cancel_cleanup(
    client: AsyncClient,
    routing: RoutingTable,
    topic: String,
    name: String,
    token: CancellationToken,
) {
    token.cancelled().await;
    if let Err(e) = client.unsubscribe(topic.clone()).await {
        tracing::warn!(target: "mqtt", resource = %name, topic = %topic, error = %secure::redact_error(&e), "mqtt unsubscribe error");
    }
    if let Ok(mut map) = routing.lock() {
        map.remove(&topic);
    }
}

impl Subscriber for MqttSubscriber {
    /// 订阅 `topic`，返回消息流；`token` 取消即终止（unsubscribe + 注销 routing）。
    ///
    /// **等 SUBACK 才返回**：broker 确认订阅建立后才 `Ok`（后续 publish 不丢首条；broker 拒绝/断连/超时 ⇒ Err）。
    ///
    /// # Contract
    /// - 取消方式：cancel `token` 触发完整 cleanup（unsubscribe + 注销）。直接 drop 流而不 cancel 也安全
    ///   ——routing entry 在下一条该 topic 消息路由时 self-heal 移除（send disconnected 即清），不会无限泄漏。
    /// - 同一 subscriber 对**同一 topic 重复 subscribe**：后者替换前者（前一流静默停收），会记 `warn`。
    ///   v1 设计为单连接每 topic 一条活跃流；需多消费者用多个 subscriber 实例。
    /// - 入站队列**有界**（[`INBOUND_QUEUE_CAP`]）：慢 consumer 致满则 drop+warn（不阻塞其它 topic）。
    async fn subscribe(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<MessageStream, SubscriberError> {
        let topic_name = topic.as_str().to_string();
        // 先注册 sender，再向 broker subscribe——避免 SUBACK 后、注册前的投递窗口丢消息。
        let receiver = self.register_sender(&topic_name)?;
        // submit：subscribe 入队 + 等 SUBACK 才返回（broker 已建订阅；拒绝/断连/超时 ⇒ Err，回滚 routing）。
        if let Err(e) = self
            .confirm
            .submit(self.client.subscribe(topic_name.clone(), QoS::AtLeastOnce))
            .await
        {
            if let Ok(mut map) = self.routing.lock() {
                map.remove(&topic_name);
            }
            return Err(SubscriberError::new(e));
        }
        let stream = receiver.take_until(cancel_cleanup(
            self.client.clone(),
            Arc::clone(&self.routing),
            topic_name.clone(),
            self.name.clone(),
            token,
        ));
        tracing::info!(target: "mqtt", resource = %self.name, topic = %topic_name, "mqtt subscribe started");
        Ok(Box::pin(stream))
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // port-local 与 ManagedResource 共用 teardown（幂等：driver 唯一执行优雅断连，两条路径不重复断连）。
        conn::teardown(&self.name, &self.token, &self.driver).await;
        Ok(())
    }
}

impl ManagedResource for MqttSubscriber {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        conn::teardown(&self.name, &self.token, &self.driver).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use diport::Message;
    use rumqttc::v5::mqttbytes::QoS;
    use rumqttc::v5::mqttbytes::v5::Publish;

    use super::{INBOUND_QUEUE_CAP, RoutingTable, pick_message_id, route_incoming};

    #[test]
    fn prefers_non_empty_correlation_data() {
        assert_eq!(pick_message_id(Some(b"evt-7"), "42"), "evt-7");
    }

    #[test]
    fn falls_back_to_pkid_when_absent() {
        assert_eq!(pick_message_id(None, "42"), "42");
    }

    #[test]
    fn falls_back_to_pkid_when_empty() {
        assert_eq!(pick_message_id(Some(b""), "7"), "7");
    }

    #[test]
    fn falls_back_to_pkid_when_whitespace() {
        assert_eq!(pick_message_id(Some(b"   "), "9"), "9");
    }

    #[test]
    fn falls_back_to_pkid_when_non_utf8() {
        // 0xFF 非法 utf8 起始字节 → from_utf8 失败 → 退 pkid。
        assert_eq!(pick_message_id(Some(&[0xFF]), "5"), "5");
    }

    fn publish(topic: &str, payload: &[u8]) -> Publish {
        Publish::new(topic, QoS::AtLeastOnce, payload.to_vec(), None)
    }

    #[test]
    #[allow(clippy::expect_used)] // 测试断言：item-level carve-out（workspace lints 约定）
    fn route_incoming_delivers_to_registered_stream() {
        let routing: RoutingTable = Arc::new(Mutex::new(HashMap::new()));
        let (tx, mut rx) = futures::channel::mpsc::channel::<Message>(INBOUND_QUEUE_CAP);
        routing
            .lock()
            .expect("lock")
            .insert("rss/t".to_string(), tx);

        route_incoming(&publish("rss/t", b"hi"), &routing, "test");

        let msg = rx.try_recv().expect("stream has a message");
        assert_eq!(msg.payload, b"hi".to_vec());
        // 投递成功后 entry 仍在（receiver 存活）。
        assert!(routing.lock().expect("lock").contains_key("rss/t"));
    }

    #[test]
    #[allow(clippy::expect_used)] // 测试断言：item-level carve-out（workspace lints 约定）
    fn route_incoming_self_heals_entry_when_receiver_dropped() {
        let routing: RoutingTable = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = futures::channel::mpsc::channel::<Message>(INBOUND_QUEUE_CAP);
        routing
            .lock()
            .expect("lock")
            .insert("rss/gone".to_string(), tx);
        drop(rx); // 模拟 caller drop 流而未 cancel token

        route_incoming(&publish("rss/gone", b"x"), &routing, "test");

        // send disconnected（receiver 已 drop）→ self-heal 移除 entry，防泄漏。
        assert!(!routing.lock().expect("lock").contains_key("rss/gone"));
    }

    #[test]
    #[allow(clippy::expect_used)] // 测试断言：item-level carve-out（workspace lints 约定）
    fn route_incoming_drops_non_utf8_topic_without_panic() {
        let routing: RoutingTable = Arc::new(Mutex::new(HashMap::new()));
        let (tx, _rx) = futures::channel::mpsc::channel::<Message>(INBOUND_QUEUE_CAP);
        routing
            .lock()
            .expect("lock")
            .insert("rss/ok".to_string(), tx);
        let mut p = publish("rss/ok", b"x");
        p.topic = vec![0xFF, 0xFE].into(); // 非 utf8 topic

        route_incoming(&p, &routing, "test");

        // 非 utf8 topic 被 drop（不路由、不 panic）；合法 entry 不受影响。
        assert!(routing.lock().expect("lock").contains_key("rss/ok"));
    }
}
