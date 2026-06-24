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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use consistency::{ConsumerGroup, EngineError, Entry, IdemKey, IdempotencyStore, SeenState};

use diport::{
    AuditEvent, AuditSink, AuditSinkError, Clock, Message, MessageId, MessageStream,
    OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts, PublishRequest, Publisher, PublisherError,
    Subscriber, SubscriberError, Topic,
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
        // event_id（去重锚点 / EventId）作 Message.id，使消费侧 `run_consumer` 的幂等键与 durable
        // 路径一致（重投同一 EventId → Duplicate 短路）。event_id 空才回退单调 seq（保旧 demo 行为）。
        let id = if request.event_id.as_str().is_empty() {
            format!("mem-{}", inner.seq)
        } else {
            request.event_id.as_str().to_string()
        };
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

// ── MemEmitter：in-mem durable outbox 发射替身（demo 拓扑）──────────────────────

/// in-mem outbox 发射端口（impl [`diport::OutboxEmitter`]）：把 [`Entry`] 直接 fan-out 到 [`MemBus`]，
/// **不持久化**——demo / 单进程 / 测试用；生产走 postgres `PgEmitter`（durable outbox + relay CAS）。
///
/// 经 `MemBus::publisher()` 复用 [`MemPublisher`] 的发布路径：`Message.id = entry.idem_key()`（EventId），
/// 闭合 demo 侧 EventId 传播（消费侧 `run_consumer` 据此幂等去重）。
pub struct MemEmitter {
    bus: MemBus,
}

impl MemEmitter {
    /// 绑定 [`MemBus`] 构造（与 publisher / subscriber 共享同一总线底座）。
    pub fn new(bus: MemBus) -> Self {
        Self { bus }
    }
}

impl OutboxEmitter for MemEmitter {
    async fn emit(
        &self,
        entry: Entry,
        _envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        // reason: in-mem 替身无持久化载体，envelope（domain/contract_id/subject_id）无落库处——
        // 消费侧从 payload 解码 subject/tenant，故 demo 路径忽略 envelope（durable PgEmitter 才落 metadata）。
        let request = PublishRequest {
            topic: Topic::new(entry.topic().as_str()),
            event_id: MessageId::new(entry.idem_key().as_str()),
            payload: entry.payload().to_vec(),
        };
        self.bus
            .publisher()
            .publish(request)
            .await
            .map_err(OutboxEmitError::new)
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

// ── InMemClaimer：进程内幂等去重替身（demo 拓扑）─────────────────────────────

/// in-mem 幂等 claimer（impl [`consistency::IdempotencyStore`]）：以 `(group, key)` 记首见集合，
/// 首见 `Fresh`、再见 `Duplicate`。demo / 单进程 / 测试用；生产走 redis/pg claimer。
pub struct InMemClaimer {
    seen: Arc<Mutex<HashSet<(String, String)>>>,
    group: ConsumerGroup,
}

impl InMemClaimer {
    /// 新建空 claimer，绑定消费者组。
    ///
    /// 构造仅 crate 内可见（`pub(crate)`）——`InMemClaimer` 是 demo/test 替身，
    /// 当前无已知跨 crate 消费方。跨 crate dev-root demo 装配（如 replaydeps 拓扑）
    /// 随消费方落地时再经决策 token factory 暴露；勿现在引入该 factory。
    #[allow(dead_code)]
    // reason: InMemClaimer::new 当前仅在 #[cfg(test)] 中调用；非测试 lib 代码无消费方，
    // 故 rustc dead_code lint 误报。待 replaydeps demo 消费方落地时一并去掉本 allow。
    pub(crate) fn new(group: ConsumerGroup) -> Self {
        Self {
            seen: Arc::new(Mutex::new(HashSet::new())),
            group,
        }
    }
}

impl IdempotencyStore for InMemClaimer {
    async fn check(&self, key: &IdemKey) -> Result<SeenState, EngineError> {
        let fresh = self
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((self.group.as_str().to_string(), key.as_str().to_string()));
        // reason: in-mem 集合插入不会失败，恒 Ok；首次插入=Fresh，已存在=Duplicate。
        Ok(if fresh {
            SeenState::Fresh
        } else {
            SeenState::Duplicate
        })
    }

    /// claimed→done（幂等 no-op：in-mem HashSet 语义中 claimed/done 均视为"已见"，
    /// commit 后 check 仍返 Duplicate，符合永久去重语义）。
    async fn commit(&self, _key: &IdemKey) -> Result<(), EngineError> {
        // reason: InMemClaimer 以 HashSet 记首见集合，absent/claimed/done 三态在此简化为
        // absent / seen（seen 包含 claimed 与 done）。commit 不改集合内容（已 seen 保持 seen，
        // 故 check 仍 Duplicate），满足「commit 后永久去重」不变式。demo/test 替身无需完整三态。
        Ok(())
    }

    /// claimed→absent（从 HashSet 删除，使后续 check 可重得 Fresh）。
    async fn release(&self, key: &IdemKey) -> Result<(), EngineError> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(self.group.as_str().to_string(), key.as_str().to_string()));
        // reason: in-mem 删除不会失败，恒 Ok；absent 时 remove 是幂等 no-op。
        Ok(())
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
                event_id: MessageId::new("evt-roundtrip"),
                payload: b"hello".to_vec(),
            })
            .await
            .expect("publish");
        let msg = stream.next().await.expect("message delivered");
        assert_eq!(msg.payload, b"hello".to_vec());
        // EventId 传播：event_id 须作 Message.id（消费侧幂等键源）。
        assert_eq!(
            msg.id.as_str(),
            "evt-roundtrip",
            "event_id 应作 Message.id 传播到消费侧"
        );
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
                event_id: MessageId::new("evt-fanout"),
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
                event_id: MessageId::new("evt-other"),
                payload: b"x".to_vec(),
            })
            .await
            .expect("publish");
        // 取消后流终止：不同 topic 无投递 ⇒ None。
        token.cancel();
        assert!(stream.next().await.is_none());
    }

    // MemEmitter（OutboxEmitter 替身）：emit 一条 Entry → 订阅者收到 Message，且 id = entry.idem_key()
    // （EventId），证明 demo 侧 EventId 传播闭合（消费侧 run_consumer 幂等键源）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_emitter_uses_eventid_as_message_id() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        let entry = Entry::new(
            consistency::Topic::parse(TOPIC).expect("topic"),
            IdemKey::parse("evt-session-77").expect("idem"),
            b"payload".to_vec(),
        );
        let env = OutboxEnvelopeParts {
            domain: "identity".to_string(),
            contract_id: TOPIC.to_string(),
            subject_id: "subj-opaque".to_string(),
        };
        MemEmitter::new(bus.clone())
            .emit(entry, env)
            .await
            .expect("emit");
        let msg = stream.next().await.expect("message delivered");
        assert_eq!(msg.id.as_str(), "evt-session-77", "EventId 应作 Message.id");
        assert_eq!(msg.payload, b"payload".to_vec());
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

    // ── InMemClaimer L0 表驱动测试 ───────────────────────────────────────────

    /// 同一 key 连续 check 3 次：第 1 次 Fresh，第 2、3 次 Duplicate。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果及 check，item-level carve-out（error-handling.md §Carve-out）。
    async fn claimer_first_fresh_then_duplicate() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group = consistency::ConsumerGroup::parse("audit").expect("group");
        let claimer = InMemClaimer::new(group);
        let key = IdemKey::parse("session.created:tenant-1:evt-1").expect("key");

        let states: Vec<SeenState> = vec![
            claimer.check(&key).await.expect("check 1"),
            claimer.check(&key).await.expect("check 2"),
            claimer.check(&key).await.expect("check 3"),
        ];

        assert_eq!(states[0], SeenState::Fresh, "第 1 次应为 Fresh");
        assert_eq!(states[1], SeenState::Duplicate, "第 2 次应为 Duplicate");
        assert_eq!(states[2], SeenState::Duplicate, "第 3 次应为 Duplicate");
    }

    /// 两个不同 group 的 claimer，同一 key 各自 Fresh——证明去重按组隔离，组漂移→去重失效。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果及 check，item-level carve-out（error-handling.md §Carve-out）。
    async fn consumer_group_drift_breaks_dedup() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group_a = consistency::ConsumerGroup::parse("audit").expect("group-a");
        let group_b = consistency::ConsumerGroup::parse("settings").expect("group-b");
        let claimer_a = InMemClaimer::new(group_a);
        let claimer_b = InMemClaimer::new(group_b);
        let key = IdemKey::parse("session.created:tenant-1:evt-1").expect("key");

        let state_a = claimer_a.check(&key).await.expect("check a");
        let state_b = claimer_b.check(&key).await.expect("check b");

        assert_eq!(state_a, SeenState::Fresh, "group-a 首见应为 Fresh");
        assert_eq!(
            state_b,
            SeenState::Fresh,
            "group-b 独立首见应为 Fresh（组隔离）"
        );
    }
}
