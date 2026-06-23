//! memory — in-mem DI port provider（RW-G1 追踪弹验接缝）。
//!
//! impl `diport` 的可替换-provider DI port（`Publisher` / `Subscriber` / `AuditSink` / `Clock`），
//! 供 `journeys` 组合根注入，证明冻结接缝能拼成闭环（identity 登录 → in-mem outbox → 分发 → audit）。
//! 生产替身走真实 broker / sink adapter（amqp / postgres…）；本 crate 仅测试 / demo 用。
//!
//! 设计对标 watermill 的 in-mem pub/sub（gochannel）：per-topic 订阅者列表 + 缓冲 channel fan-out，
//! `CancellationToken` 取消即流终止（替代 watermill `close(g.closing)` 广播）。
//! ref: watermill pubsub/gochannel/pubsub.go@fbce4d6cd13c8657c668c7e7990fef90d2471b8a
//!
//! RSS 偏离（与对标分析一致）：fire-and-forget publish（不阻塞等 subscriber Ack，对标
//! `BlockPublishUntilSubscriberAck=false`）；无 `Persistent` 重放（订阅须先于发布）；async `Stream` +
//! `take_until(token)` 替代 Go channel + `<-closing`。runtime-agnostic：用 `futures::channel::mpsc`
//! （receiver 即 `Stream`），不绑 tokio runtime。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use diport::{
    AuditEvent, AuditSink, AuditSinkError, Clock, Message, MessageStream, PublishRequest,
    Publisher, PublisherError, Subscriber, SubscriberError, Topic,
};
use futures::StreamExt;
use futures::channel::mpsc::{self, UnboundedSender};
use tokio_util::sync::CancellationToken;

// 锁中毒（仅当持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，
// 且 lib 代码禁 unwrap/expect（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean。

// ── MemBus：publisher / subscriber 共享的 in-mem 事件总线 ──────────────────────

#[derive(Default)]
struct BusInner {
    /// topic → 活跃订阅者 sender 列表（per-topic fan-out，对标 gochannel `subscribers map`）。
    topics: HashMap<String, Vec<UnboundedSender<Message>>>,
    /// 单调消息序号，派生 in-mem 消息 id（无系统时钟 / 随机）。
    seq: u64,
}

/// in-mem 事件总线（克隆共享同一底座）。经 [`MemBus::publisher`] / [`MemBus::subscriber`] 取端口。
#[derive(Clone, Default)]
pub struct MemBus {
    inner: Arc<Mutex<BusInner>>,
}

impl MemBus {
    /// 新建空总线。
    pub fn new() -> Self {
        Self::default()
    }

    /// 取发布端口（impl [`diport::Publisher`]）。
    pub fn publisher(&self) -> MemPublisher {
        MemPublisher { bus: self.clone() }
    }

    /// 取订阅端口（impl [`diport::Subscriber`]）。
    pub fn subscriber(&self) -> MemSubscriber {
        MemSubscriber { bus: self.clone() }
    }
}

/// in-mem 发布端口。
pub struct MemPublisher {
    bus: MemBus,
}

impl Publisher for MemPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        let mut inner = self.bus.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.seq += 1;
        let id = format!("mem-{}", inner.seq);
        let payload = request.payload;
        let senders = inner
            .topics
            .entry(request.topic.as_str().to_string())
            .or_default();
        // 投递 clone 给每个订阅者；receiver 已 drop（unbounded_send Err）则剔除（对标 gochannel 退订清理）。
        senders.retain(|tx| {
            tx.unbounded_send(Message::new(id.clone(), payload.clone()))
                .is_ok()
        });
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

/// in-mem 订阅端口。
pub struct MemSubscriber {
    bus: MemBus,
}

impl Subscriber for MemSubscriber {
    async fn subscribe(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<MessageStream, SubscriberError> {
        let (tx, rx) = mpsc::unbounded::<Message>();
        self.bus
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .topics
            .entry(topic.as_str().to_string())
            .or_default()
            .push(tx);
        // token 取消即流终止（对标 gochannel `<-g.closing` 广播）。
        let stream = rx.take_until(async move { token.cancelled().await });
        Ok(Box::pin(stream))
    }

    async fn shutdown(&self) -> Result<(), SubscriberError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemAuditSink：累积 AuditEvent 供 journey 断言 ─────────────────────────────

/// in-mem 审计 sink：把 [`diport::AuditEvent`] 累积进 vec，供 journey 测试断言。
#[derive(Clone, Default)]
pub struct MemAuditSink {
    records: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MemAuditSink {
    /// 新建空 sink。
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前累积的审计事件快照（克隆）。
    pub fn records(&self) -> Vec<AuditEvent> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 已记录条数。
    pub fn len(&self) -> usize {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for MemAuditSink {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), AuditSinkError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── FixedClock：确定性测试时钟 ────────────────────────────────────────────────

/// 固定时刻时钟（impl [`diport::Clock`]）：测试 / demo 确定性，不取系统时钟（不触 clippy disallowed-methods）。
pub struct FixedClock {
    at: SystemTime,
}

impl FixedClock {
    /// 由指定时刻构造。
    pub fn new(at: SystemTime) -> Self {
        Self { at }
    }

    /// 由 UNIX epoch 秒构造。
    pub fn at_unix_secs(secs: u64) -> Self {
        Self {
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diport::AuditOutcome;
    use vocab::TenantId;

    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TOPIC: &str = "identity.session-created";

    // 测试构造 / 断言用 expect：item-level carve-out（error-handling.md §Carve-out 要求 item-level）。
    #[allow(clippy::expect_used)]
    fn sample_event() -> AuditEvent {
        AuditEvent {
            occurred_at: SystemTime::UNIX_EPOCH,
            principal_id: "alice".to_string(),
            tenant_id: TenantId::parse(CANON_TENANT).expect("canonical tenant"),
            resource_kind: "session",
            resource_id: "sess-1".to_string(),
            action: "login",
            outcome: AuditOutcome::Success,
            request_id: None,
            correlation_id: None,
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_then_subscribe_roundtrip() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        // 订阅须先于发布（in-mem 无重放）。
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        bus.publisher()
            .publish(PublishRequest {
                topic: Topic::new(TOPIC),
                payload: b"hello".to_vec(),
            })
            .await
            .expect("publish");
        let msg = stream.next().await.expect("message delivered");
        assert_eq!(msg.payload, b"hello".to_vec());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn fan_out_to_multiple_subscribers() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        let mut a = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe a");
        let mut b = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe b");
        bus.publisher()
            .publish(PublishRequest {
                topic: Topic::new(TOPIC),
                payload: b"x".to_vec(),
            })
            .await
            .expect("publish");
        assert_eq!(a.next().await.expect("a msg").payload, b"x".to_vec());
        assert_eq!(b.next().await.expect("b msg").payload, b"x".to_vec());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn other_topic_not_delivered() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new("other.topic"), token.clone())
            .await
            .expect("subscribe");
        bus.publisher()
            .publish(PublishRequest {
                topic: Topic::new(TOPIC),
                payload: b"x".to_vec(),
            })
            .await
            .expect("publish");
        // 取消后流终止：不同 topic 无投递 ⇒ None。
        token.cancel();
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cancel_terminates_stream() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        token.cancel();
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn audit_sink_records_event() {
        let sink = MemAuditSink::new();
        assert!(sink.is_empty());
        sink.record(sample_event()).await.expect("record");
        assert_eq!(sink.len(), 1);
        let records = sink.records();
        assert_eq!(records[0].action, "login");
        assert_eq!(records[0].principal_id, "alice");
    }

    #[test]
    fn fixed_clock_is_deterministic() {
        let clock = FixedClock::at_unix_secs(1_000);
        assert_eq!(
            clock.now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
        );
        assert_eq!(clock.now(), clock.now());
    }
}
