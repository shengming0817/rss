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

use consistency::{ConsumerGroup, EngineError, Entry, IdemKey, IdempotencyStore, Lsn, SeenState};

use diport::{
    AuditEvent, AuditSink, AuditSinkError, Checkpoint, CheckpointId, CheckpointOwner,
    CheckpointStoreError, CheckpointVersion, Clock, DeadLetterRecord, DeadLetterStore,
    DeadLetterStoreError, FencedWriteKey, FencedWriteRequest, FencedWriter, FencedWriterError,
    JournalEntry, LeaderElector, LeaderElectorError, LeaderId, LeaseToken, Message, MessageId,
    MessageStream, OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts, OwnerCheckpointStore,
    PublishRequest, Publisher, PublisherError, SagaId, SagaJournal, SagaJournalError, SaveOutcome,
    SecretCoordinate, SecretMaterial, SecretResolver, SecretResolverError, Subscriber,
    SubscriberError, Topic, WriteOutcome,
};
use futures::StreamExt;
use futures::channel::mpsc::{self, UnboundedSender};
use identity::ports::{Session, SessionUnitOfWork};
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

// ── MemSessionUnitOfWork：in-mem 会话 co-tx 替身（demo 拓扑）────────────────────

/// in-mem 会话 co-tx Unit-of-Work（impl [`identity::ports::SessionUnitOfWork`]）：把 [`Entry`] fan-out 到
/// [`MemBus`]——demo / 单进程 / 测试用；生产走 postgres `PgSessionUnitOfWork`（单事务 session + outbox co-tx）。
///
/// # WARNING / DEMO-ONLY
///
/// **不持久化 session**（同 [`MemEmitter`] 的 demo 哲学）：in-mem 单进程无 durable 会话存储——**登录后 session
/// 不可被后续鉴权 / 登出查回**（与 postgres 路径产品行为不同）。demo 验证的只是**接缝路由**（登录 → UoW →
/// 事件流到 audit）。需验「session 可读」的验收**勿用本替身**——走 postgres 路径或在 journey 内自存。
///
/// session 持久化与 co-tx 原子性（both-or-neither）由 postgres `PgSessionUnitOfWork`（INVARIANT
/// OUTBOX-COTX-SESSION-01）+ 集成测试守。envelope 同 `MemEmitter` 忽略（消费侧从 payload 解码）。
pub struct MemSessionUnitOfWork {
    bus: MemBus,
}

impl MemSessionUnitOfWork {
    /// 绑定 [`MemBus`] 构造（与 publisher / subscriber 共享同一总线底座）。
    pub fn new(bus: MemBus) -> Self {
        Self { bus }
    }
}

impl SessionUnitOfWork for MemSessionUnitOfWork {
    async fn persist_session_and_emit(
        &self,
        _session: Session,
        entry: Entry,
        _envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        // reason: in-mem 替身不持久化 session（demo 无 durable 存储，同 MemEmitter；真实 co-tx 持久化语义由
        // PgSessionUnitOfWork 的 OUTBOX-COTX-SESSION-01 守）；只复用 MemPublisher 路径把 entry fan 到总线
        // （`Message.id = entry.idem_key()` = EventId，闭合 demo 侧幂等传播）。
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

// ── MemDeadLetterStore：累积 DeadLetterRecord 供 journey 断言 ─────────────────────────────

/// in-mem 死信 sink（impl [`diport::DeadLetterStore`]）：把 [`diport::DeadLetterRecord`] 累积进 vec，
/// 供 demo journey 断言 DLX 分支。生产走 postgres `PgDeadLetterStore`；本替身仅测试 / demo 用。
#[derive(Clone, Default)]
pub struct MemDeadLetterStore {
    records: Arc<Mutex<Vec<DeadLetterRecord>>>,
}

impl MemDeadLetterStore {
    /// 新建空 store。
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前累积的死信记录快照（克隆）。
    pub fn records(&self) -> Vec<DeadLetterRecord> {
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

impl DeadLetterStore for MemDeadLetterStore {
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
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
    /// `pub`：供 dev-root demo 组合根（`journeys` / `examples`）跨 crate 构造（生产 bin 经 cargo-deny 连
    /// `memory` 都依赖不到 ⇒ in-mem 生产不可达，TOPO-INMEM-SEAL-01 主守卫 Hard）。dev root **须**经
    /// `bootstrap::replaydeps::resolve(Topology::Demo, ..)` 决策臂构造、**不**直接 raw-new——把 in-mem 构造
    /// 收束到已校验的拓扑决策（决策绑定纪律 Medium，review #274 F6/C6）；生产走 redis/pg claimer。
    pub fn new(group: ConsumerGroup) -> Self {
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

// ── MemLeaseStore / MemLeaderElector：进程内 leader 选举替身（reconcile harness 测试 / demo）──────────

/// 共享 lease 底座：多个 [`MemLeaderElector`]（模拟多副本）克隆共享同一底座竞争 leadership。
///
/// 确定性、无时钟（不触 clippy disallowed-methods）：lease TTL 过期 / holder crash 由测试显式
/// [`MemLeaseStore::evict`] 模拟；生产替身走真实 redis/pg leader-elect adapter。
#[derive(Default)]
struct LeaseInner {
    /// 当前持有者 + 其任期 epoch；`None` = 无人持有（可被首个 acquire 接管）。
    holder: Option<(LeaderId, vocab::Epoch)>,
    /// 下一个**全新**任期 epoch（每次易手 / 首次获得单调 `+1`；同一持有者续租不动）。
    next_epoch: u64,
}

/// in-mem leader 选举底座（克隆共享同一底座）。经 [`MemLeaseStore::elector`] 取每个副本的端口。
#[derive(Clone, Default)]
pub struct MemLeaseStore {
    inner: Arc<Mutex<LeaseInner>>,
}

impl MemLeaseStore {
    /// 新建空底座（无人持有 leadership，next_epoch 从 0 起）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 取一个副本的 [`MemLeaderElector`]（`id` = 该副本 holder identity，须经 `LeaderId::parse` canonical 校验）。
    pub fn elector(&self, id: LeaderId) -> MemLeaderElector {
        MemLeaderElector {
            store: self.clone(),
            id,
        }
    }

    /// 测试钩子：模拟 lease TTL 过期 / holder crash——清当前持有者，使他副本下次 `acquire` 可接管
    /// （接管获**新**任期 epoch，单调递增）。不重置 `next_epoch`（保跨任期单调）。
    pub fn evict(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).holder = None;
    }
}

/// 单副本 in-mem leader 选举端口（impl [`diport::LeaderElector`]）。
pub struct MemLeaderElector {
    store: MemLeaseStore,
    id: LeaderId,
}

impl LeaderElector for MemLeaderElector {
    async fn acquire(&self, _lease: Duration) -> Result<Option<LeaseToken>, LeaderElectorError> {
        // reason: in-mem 无 TTL，`lease` 时长被忽略（过期由测试 evict 模拟）；锁内同步无 await。
        let mut g = self.store.inner.lock().unwrap_or_else(|e| e.into_inner());
        match &g.holder {
            // 无人持有 → 接管全新任期（epoch 单调 +1）。
            None => {
                let epoch = vocab::Epoch::new(g.next_epoch);
                g.next_epoch = g.next_epoch.saturating_add(1);
                g.holder = Some((self.id.clone(), epoch));
                Ok(Some(LeaseToken {
                    holder: self.id.clone(),
                    epoch,
                }))
            }
            // 本副本续租 → 同任期 epoch 不变。
            Some((holder, epoch)) if *holder == self.id => Ok(Some(LeaseToken {
                holder: holder.clone(),
                epoch: *epoch,
            })),
            // 他副本持有 → 本副本非 leader。
            Some(_) => Ok(None),
        }
    }

    async fn release(&self, token: LeaseToken) -> Result<(), LeaderElectorError> {
        let mut g = self.store.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是**当前任期**持有者时让出：holder + epoch **双校验**（已易手或旧任期 stale token
        // 则幂等 no-op）。仅校验 holder 不够——同 holder 重启后持旧 epoch token 会误让出自己续租后的新任期。
        if matches!(&g.holder, Some((holder, epoch)) if *holder == token.holder && *epoch == token.epoch)
        {
            g.holder = None;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LeaderElectorError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemFencedWriter：进程内防护写替身（单调 epoch CAS）─────────────────────────────────────────────

/// in-mem 防护写端口（impl [`diport::FencedWriter`]）：**按 `key` 各自**记已接受 epoch 高水位，
/// `epoch < 该 key 高水位` 的写被 [`WriteOutcome::Fenced`]（旧 leader 跨任期 stale 写被挡）；`epoch ≥` 提交并
/// 推进该 key 高水位（**同任期多写 / 不同 key 互不 fence**，幂等由消费方负责）。
///
/// 仅校验 fencing CAS 语义，不持久化 `data`。INVARIANT: RECONCILE-FENCE-MONO-01（per-key 单调，回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemFencedWriter {
    high_water: Arc<Mutex<HashMap<FencedWriteKey, vocab::Epoch>>>,
}

impl MemFencedWriter {
    /// 新建空 writer（各 key 高水位未设，每个 key 首写恒提交）。
    pub fn new() -> Self {
        Self::default()
    }
}

impl FencedWriter for MemFencedWriter {
    async fn write(&self, request: FencedWriteRequest) -> Result<WriteOutcome, FencedWriterError> {
        let mut hw = self.high_water.lock().unwrap_or_else(|e| e.into_inner());
        // per-key 单调：该 key 首写（absent）或 epoch ≥ 该 key 高水位 → 提交并推进；否则 fence（跨任期 stale）。
        match hw.get(&request.key) {
            Some(&seen) if request.epoch < seen => Ok(WriteOutcome::Fenced),
            _ => {
                hw.insert(request.key, request.epoch);
                Ok(WriteOutcome::Committed)
            }
        }
    }

    async fn shutdown(&self) -> Result<(), FencedWriterError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemSagaJournal：saga 执行日志 in-mem 替身 ────────────────────────────────────

/// in-mem saga journal（impl [`diport::SagaJournal`]）：按 `(saga_id, seq)` 主键幂等 append，
/// `read` 返回按 `seq` 升序排列的条目（`output`/`error_summary` 恒 `None`，符合 port 契约）。
///
/// 对标 oxidecomputer/steno `SagaLog`（append-only journal，crash-replay 幂等）。
/// 生产替身走 postgres adapter（`ON CONFLICT (saga_id,seq) DO NOTHING`）；本 crate 仅测试/demo 用。
#[derive(Clone, Default)]
pub struct MemSagaJournal {
    // (saga_id_bytes, entry) — saga_id 以 uuid::Uuid 字节存储，entry 携带 seq/step_name/status。
    inner: Arc<Mutex<Vec<(uuid::Uuid, JournalEntry)>>>,
}

impl MemSagaJournal {
    /// 新建空 journal。
    pub fn new() -> Self {
        Self::default()
    }
}

impl SagaJournal for MemSagaJournal {
    async fn append(&self, saga_id: &SagaId, entry: JournalEntry) -> Result<(), SagaJournalError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 幂等：同 (saga_id, seq) 已存在则 no-op（对标 postgres ON CONFLICT DO NOTHING）。
        let id = saga_id.as_uuid();
        let seq = entry.seq;
        let already_exists = g.iter().any(|(sid, e)| *sid == id && e.seq == seq);
        if !already_exists {
            g.push((id, entry));
        }
        Ok(())
    }

    async fn read(&self, saga_id: &SagaId) -> Result<Vec<JournalEntry>, SagaJournalError> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = saga_id.as_uuid();
        // 过滤本 saga、按 seq 升序（resume 据此重建执行栈）；strip output/error_summary（port 契约）。
        let mut entries: Vec<JournalEntry> = g
            .iter()
            .filter(|(sid, _)| *sid == id)
            .map(|(_, e)| JournalEntry {
                seq: e.seq,
                step_name: e.step_name.clone(),
                status: e.status,
                output: None,
                error_summary: None,
            })
            .collect();
        entries.sort_by_key(|e| e.seq);
        Ok(entries)
    }

    async fn shutdown(&self) -> Result<(), SagaJournalError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemCheckpointStore：owner 断点续投 in-mem 替身 ─────────────────────────────

/// checkpoint store 内部 HashMap 类型别名（规避 clippy::type_complexity）。
type CheckpointMap = HashMap<(String, String), (Lsn, CheckpointVersion)>;

/// in-mem owner checkpoint store（impl [`diport::OwnerCheckpointStore`]）：
/// `(owner, id)` 主键 + `(offset, version)` CAS——`expected` 版本不符即 [`SaveOutcome::StaleVersion`]。
///
/// 对标 oxidecomputer/steno saga checkpoint + eventbus.md §Projection 断点续投 offset CAS。
/// 生产替身走 postgres adapter；本 crate 仅测试/demo 用。
#[derive(Clone, Default)]
pub struct MemCheckpointStore {
    // key: (owner.as_str(), id.as_str())；value: (offset, current_version)
    inner: Arc<Mutex<CheckpointMap>>,
}

impl MemCheckpointStore {
    /// 新建空 store。
    pub fn new() -> Self {
        Self::default()
    }
}

impl OwnerCheckpointStore for MemCheckpointStore {
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (owner.as_str().to_string(), id.as_str().to_string());
        Ok(g.get(&key)
            .map(|&(offset, version)| Checkpoint { offset, version }))
    }

    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (owner.as_str().to_string(), id.as_str().to_string());
        match g.get(&key) {
            // 首存：仅当 expected == version 0 时插入（约定「期望无既存行」用 version 0 表达）。
            None if expected == CheckpointVersion::new(0) => {
                g.insert(key, (offset, CheckpointVersion::new(1)));
                Ok(SaveOutcome::Saved)
            }
            // 版本 CAS 成功：存储版本 == expected → 存 offset 并推进版本。
            Some(&(_, stored_ver)) if stored_ver == expected => {
                g.insert(key, (offset, expected.next()));
                Ok(SaveOutcome::Saved)
            }
            // 其余（首存但 expected != 0，或版本失配）→ StaleVersion。
            _ => Ok(SaveOutcome::StaleVersion),
        }
    }

    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemSecretResolver：in-mem secret 解析替身（journey / e2e / 单测用）─────────────────────────

/// `MemSecretResolver` 内部 store 类型别名（key = (tenant_uuid_str, store_id, key)；value = raw bytes）。
type SecretStoreMap = std::collections::HashMap<(String, String, String), Vec<u8>>;

/// in-mem secret 解析端口（impl [`diport::SecretResolver`]）：按 `(tenant_uuid, store_id, key)` 命中
/// 返 [`SecretMaterial`]，未命中返 [`SecretResolverError::NotFound`]。
///
/// 仅供测试 / journey 使用——不在生产组合根注入（provider 为 Vault / AWS SM 等 adapter）。
///
/// 附调试旋钮（[`MemSecretResolver::set_unreachable`]）：置位后所有 resolve 返回
/// [`SecretResolverError::StoreUnreachable`]，用于验证 fail-closed 路径。
///
/// 附调试旋钮（[`MemSecretResolver::set_forbidden`]）：置位后所有 resolve 返回
/// [`SecretResolverError::Forbidden`]，用于验证 IAM 拒绝路径。
///
/// # 安全语义
///
/// 设计与 [`diport::SecretMaterial`] 同边界：材料字节写入 store 后不存在 owned clone 路径（HashMap
/// 存储 `Vec<u8>`，`resolve` 经 `SecretMaterial::new(bytes.clone())` 新建，drop 触发 `ZeroizeOnDrop`）。
#[derive(Default)]
pub struct MemSecretResolver {
    /// key = (tenant_uuid_str, store_id, secret_key)；value = raw bytes。
    store: Arc<Mutex<SecretStoreMap>>,
    /// 旋钮：置位后所有 resolve 返 `StoreUnreachable`。
    unreachable: Arc<std::sync::atomic::AtomicBool>,
    /// 旋钮：置位后所有 resolve 返 `Forbidden`。
    forbidden: Arc<std::sync::atomic::AtomicBool>,
}

impl MemSecretResolver {
    /// 新建空 resolver（无预设 secret，默认可达且未 forbidden）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 向 store 注入一条 secret（覆盖写）。调用方持有字节，resolver 存 clone。
    ///
    /// `tenant`：租户隔离键（`store_id` + `key` 同 tenant 不同值互不干扰）。
    pub fn insert(&self, tenant: vocab::TenantId, store_id: &str, key: &str, bytes: Vec<u8>) {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).insert(
            (
                tenant.as_uuid().to_string(),
                store_id.to_string(),
                key.to_string(),
            ),
            bytes,
        );
    }

    /// 打开 `StoreUnreachable` 旋钮（置位后所有 resolve 返 Err）。
    pub fn set_unreachable(&self, v: bool) {
        self.unreachable
            .store(v, std::sync::atomic::Ordering::Relaxed);
    }

    /// 打开 `Forbidden` 旋钮（置位后所有 resolve 返 Err）。
    pub fn set_forbidden(&self, v: bool) {
        self.forbidden
            .store(v, std::sync::atomic::Ordering::Relaxed);
    }
}

impl SecretResolver for MemSecretResolver {
    async fn resolve(
        &self,
        tenant: vocab::TenantId,
        coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        // 旋钮检查（fail-closed 优先于命中查询）。
        if self.unreachable.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SecretResolverError::store_unreachable(
                std::io::Error::other("mem-resolver: store marked unreachable"),
            ));
        }
        if self.forbidden.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SecretResolverError::Forbidden);
        }
        let g = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let lookup_key = (
            tenant.as_uuid().to_string(),
            coord.store_id().to_string(),
            coord.key().to_string(),
        );
        match g.get(&lookup_key) {
            Some(bytes) => Ok(SecretMaterial::new(bytes.clone())),
            None => Err(SecretResolverError::NotFound),
        }
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

    // ── MemLeaderElector：leader 互斥 + 接管 epoch 单调 ───────────────────────

    #[allow(clippy::expect_used)]
    // reason: 测试用 canonical literal 构造 LeaderId，item-level carve-out（error-handling.md §Carve-out）。
    fn lid(s: &str) -> LeaderId {
        LeaderId::parse(s).expect("canonical leader id")
    }

    /// 2 副本共享同一底座并发争夺：仅一成功（Some），他者 None。
    ///
    /// 注：`MemLeaseStore` 内部同步 `Mutex`，顺序 `acquire`（无 await 间隙）等价于并发争夺；
    /// 异步后端（redis/pg）需重写为 `tokio::join!` 并发变体以捕获真实竞态。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn two_replicas_only_one_acquires() {
        let store = MemLeaseStore::new();
        let a = store.elector(lid("pod-a"));
        let b = store.elector(lid("pod-b"));

        let a_lease = a.acquire(Duration::from_secs(30)).await.expect("a acquire");
        let b_lease = b.acquire(Duration::from_secs(30)).await.expect("b acquire");

        assert!(a_lease.is_some(), "pod-a 应当选");
        assert!(b_lease.is_none(), "pod-b 应非 leader（已被 pod-a 持有）");
        // 首任期 epoch 从 0 起（next_epoch 从 0），固定绝对起始值（非仅相对单调序）。
        assert_eq!(
            a_lease.as_ref().map(|t| t.epoch),
            Some(vocab::Epoch::new(0)),
            "首次当选 epoch 应为 0"
        );

        // 持有者续租：同任期 epoch 不变。
        let a_renew = a.acquire(Duration::from_secs(30)).await.expect("a renew");
        assert_eq!(
            a_renew.map(|t| t.epoch),
            a_lease.map(|t| t.epoch),
            "续租 epoch 不变（同任期）"
        );
    }

    /// holder release → 他副本接管，接管任期 epoch 单调递增（旧任期 < 新任期）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn release_then_takeover_bumps_epoch() {
        let store = MemLeaseStore::new();
        let a = store.elector(lid("pod-a"));
        let b = store.elector(lid("pod-b"));

        let a_lease = a
            .acquire(Duration::from_secs(30))
            .await
            .expect("a acquire")
            .expect("a is leader");
        let e0 = a_lease.epoch;
        assert_eq!(
            e0,
            vocab::Epoch::new(0),
            "首任期 epoch 应为 0（next_epoch 从 0 起）"
        );
        a.release(a_lease).await.expect("a release");

        let b_lease = b
            .acquire(Duration::from_secs(30))
            .await
            .expect("b acquire")
            .expect("b takes over");
        assert!(
            b_lease.epoch > e0,
            "接管任期 epoch 应单调递增：{:?} !> {e0:?}",
            b_lease.epoch
        );
        assert_eq!(b_lease.holder.as_str(), "pod-b");
    }

    /// evict（模拟 TTL 过期 / crash）→ 他副本接管，epoch 同样单调递增。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn evict_lets_other_replica_take_over() {
        let store = MemLeaseStore::new();
        let a = store.elector(lid("pod-a"));
        let b = store.elector(lid("pod-b"));

        let a_lease = a
            .acquire(Duration::from_secs(30))
            .await
            .expect("a acquire")
            .expect("a is leader");
        // evict 前 b 抢不到。
        assert!(
            b.acquire(Duration::from_secs(30))
                .await
                .expect("b1")
                .is_none()
        );

        store.evict(); // 模拟 a 的 lease 过期 / a crash

        let b_lease = b
            .acquire(Duration::from_secs(30))
            .await
            .expect("b acquire")
            .expect("b takes over after evict");
        assert!(b_lease.epoch > a_lease.epoch, "evict 接管 epoch 应递增");
    }

    // ── MemFencedWriter：per-key 单调 CAS（跨任期 stale 拒、同任期多写受）INVARIANT RECONCILE-FENCE-MONO-01 ──

    /// per-key 单调：同 key 跨任期 stale（epoch< 高水位）被 fence；同/新 epoch 受（同任期多写合法）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn fenced_write_per_key_stale_rejected_same_or_new_accepted() {
        let writer = MemFencedWriter::new();
        let req = |k: &str, e: u64| FencedWriteRequest {
            key: FencedWriteKey::new(k),
            epoch: vocab::Epoch::new(e),
            data: b"state".to_vec(),
        };

        // key A 首写（高水位未设）→ 提交，高水位=2。
        assert_eq!(
            writer.write(req("A", 2)).await.expect("a-w2"),
            WriteOutcome::Committed
        );
        // 同任期多写（同 epoch=2）→ 放行（同任期合法，幂等交消费方；anti-vacuity 见下旧 epoch fence）。
        assert_eq!(
            writer.write(req("A", 2)).await.expect("a-w2-again"),
            WriteOutcome::Committed,
            "同任期同 epoch 多写应放行"
        );
        // 旧 epoch=1 < 高水位 2 → fence（跨任期 stale，旧 leader 写被挡）。
        assert_eq!(
            writer.write(req("A", 1)).await.expect("a-w1"),
            WriteOutcome::Fenced,
            "跨任期 stale 写应被 fence"
        );
        // 新 epoch=3 → 提交，推进高水位。
        assert_eq!(
            writer.write(req("A", 3)).await.expect("a-w3"),
            WriteOutcome::Committed
        );
    }

    /// per-key 隔离：不同 key 各自高水位，key A 推进不 fence key B 的同/低 epoch 写。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn fenced_write_keys_are_isolated() {
        let writer = MemFencedWriter::new();
        let req = |k: &str, e: u64| FencedWriteRequest {
            key: FencedWriteKey::new(k),
            epoch: vocab::Epoch::new(e),
            data: b"x".to_vec(),
        };
        // key A 推到 epoch 5。
        assert_eq!(
            writer.write(req("A", 5)).await.expect("a5"),
            WriteOutcome::Committed
        );
        // key B 首写 epoch 1 不受 A 高水位影响 → 提交（per-key 隔离，非全局）。
        assert_eq!(
            writer.write(req("B", 1)).await.expect("b1"),
            WriteOutcome::Committed,
            "不同 key 应各自高水位、互不 fence"
        );
    }

    /// PhantomData freeze：MemLeaderElector / MemFencedWriter 冻结 impl diport 端口（anti-vacuity）。
    #[test]
    fn fakes_impl_reconcile_ports() {
        use core::marker::PhantomData;
        fn assert_leader_elector<T: LeaderElector>(_: PhantomData<T>) {}
        fn assert_fenced_writer<T: FencedWriter>(_: PhantomData<T>) {}
        assert_leader_elector(PhantomData::<MemLeaderElector>);
        assert_fenced_writer(PhantomData::<MemFencedWriter>);
    }

    // ── MemSagaJournal 测试 ───────────────────────────────────────────────────

    /// append 幂等 + read 按 seq 升序 + output 恒 None（port 契约）。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试用 canonical literal 构造 StepName/SagaId，item-level carve-out（error-handling.md §Carve-out）。
    async fn mem_saga_journal_append_idempotent_and_read_order() {
        use diport::{JournalEntry, SagaId};
        use uuid::Uuid;

        let journal = MemSagaJournal::new();
        let saga_id = SagaId::new(Uuid::from_u128(1));
        let step0 = consistency::StepName::parse("step0").unwrap();
        let step1 = consistency::StepName::parse("step1").unwrap();
        let step2 = consistency::StepName::parse("step2").unwrap();

        // append seq 0, 1, 2（seq 2 携带 output 字节，read 应剥离）。
        journal
            .append(&saga_id, JournalEntry::executing(0, step0.clone()))
            .await
            .unwrap();
        journal
            .append(&saga_id, JournalEntry::executing(1, step1.clone()))
            .await
            .unwrap();
        journal
            .append(
                &saga_id,
                JournalEntry::completed(2, step2.clone(), b"output_data".to_vec()),
            )
            .await
            .unwrap();

        // 重复 append (saga_id, seq=0) → no-op（幂等）。
        journal
            .append(&saga_id, JournalEntry::executing(0, step0.clone()))
            .await
            .unwrap();

        let entries = journal.read(&saga_id).await.unwrap();
        assert_eq!(entries.len(), 3, "重复 append 后应仍为 3 条");
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[1].seq, 1);
        assert_eq!(entries[2].seq, 2);
        // read 路径 output 恒 None（port 契约：resume 只需 seq/step_name/status）。
        assert!(entries[2].output.is_none(), "read 回传 output 须为 None");
        assert!(entries[2].error_summary.is_none());
    }

    // ── MemCheckpointStore 测试 ───────────────────────────────────────────────

    /// CAS 语义：首存 Saved、旧版重存 StaleVersion、下一版 Saved；get 返回正确 offset+version。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path，item-level carve-out（error-handling.md §Carve-out）。
    async fn mem_checkpoint_cas_rejects_stale_version() {
        use diport::{CheckpointId, CheckpointOwner, CheckpointVersion, SaveOutcome};

        let store = MemCheckpointStore::new();
        let owner = CheckpointOwner::new("saga-executor");
        let id = CheckpointId::new("saga-uuid-1");
        let v0 = CheckpointVersion::new(0);
        let v1 = CheckpointVersion::new(1);

        // 首存（expected = v0）→ Saved，存储版本推进到 1。
        let r1 = store
            .save_checkpoint(&owner, &id, Lsn::new(10), v0)
            .await
            .unwrap();
        assert_eq!(r1, SaveOutcome::Saved, "首存应 Saved");

        // 旧版重存（expected = v0，但存储已是 v1）→ StaleVersion。
        let r2 = store
            .save_checkpoint(&owner, &id, Lsn::new(20), v0)
            .await
            .unwrap();
        assert_eq!(r2, SaveOutcome::StaleVersion, "旧版重存应 StaleVersion");

        // 正确下一版（expected = v1）→ Saved，版本推进到 2。
        let r3 = store
            .save_checkpoint(&owner, &id, Lsn::new(20), v1)
            .await
            .unwrap();
        assert_eq!(r3, SaveOutcome::Saved, "正确版本应 Saved");

        // get 读出 offset 20、version 2。
        let cp = store
            .get_checkpoint(&owner, &id)
            .await
            .unwrap()
            .expect("checkpoint 应存在");
        assert_eq!(cp.offset, Lsn::new(20));
        assert_eq!(cp.version, CheckpointVersion::new(2));
    }

    // ── MemDeadLetterStore 测试 ────────────────────────────────────────────────

    /// new→is_empty；write_dead_letter 一条→len==1，断言 domain/topic/num_attempts/error_summary。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言，item-level carve-out（error-handling.md §Carve-out）。
    async fn dead_letter_store_records_entry() {
        use diport::DeadLetterSummary;

        let store = MemDeadLetterStore::new();
        assert!(store.is_empty());

        let record = DeadLetterRecord::new(
            "identity",
            "contract-session",
            "session.created",
            b"payload".to_vec(),
            DeadLetterSummary::new("max retries exhausted"),
            3,
        );
        store
            .write_dead_letter(record)
            .await
            .expect("write_dead_letter");

        assert_eq!(store.len(), 1);
        let records = store.records();
        assert_eq!(records[0].domain(), "identity");
        assert_eq!(records[0].topic(), "session.created");
        assert_eq!(records[0].num_attempts(), 3);
        assert_eq!(records[0].error_summary(), "max retries exhausted");
    }

    // ── MemSecretResolver smoke ───────────────────────────────────────────────

    const STORE_ID: &str = "mem-store";
    const SECRET_KEY: &str = "db/password";

    #[allow(clippy::expect_used)]
    fn resolver_tenant() -> TenantId {
        TenantId::parse(CANON_TENANT).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn sample_coord() -> SecretCoordinate {
        SecretCoordinate::new(STORE_ID, SECRET_KEY, None)
    }

    /// 命中返回 material bytes（happy path）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_secret_resolver_hit_returns_material() {
        let r = MemSecretResolver::new();
        r.insert(
            resolver_tenant(),
            STORE_ID,
            SECRET_KEY,
            b"secret-value".to_vec(),
        );
        let mat = r
            .resolve(resolver_tenant(), &sample_coord())
            .await
            .expect("resolve ok");
        assert_eq!(mat.expose(), b"secret-value");
    }

    /// 未命中返回 NotFound。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_secret_resolver_miss_returns_not_found() {
        let r = MemSecretResolver::new();
        let err = r
            .resolve(resolver_tenant(), &sample_coord())
            .await
            .expect_err("not found");
        assert!(matches!(err, SecretResolverError::NotFound));
    }

    /// `set_unreachable(true)` 后返回 StoreUnreachable（fail-closed 旋钮）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_secret_resolver_unreachable_toggle() {
        let r = MemSecretResolver::new();
        r.insert(resolver_tenant(), STORE_ID, SECRET_KEY, b"x".to_vec());
        r.set_unreachable(true);
        let err = r
            .resolve(resolver_tenant(), &sample_coord())
            .await
            .expect_err("unreachable");
        assert!(matches!(err, SecretResolverError::StoreUnreachable { .. }));
        // 关闭旋钮 → 恢复正常命中。
        r.set_unreachable(false);
        let mat = r
            .resolve(resolver_tenant(), &sample_coord())
            .await
            .expect("ok after reset");
        assert_eq!(mat.expose(), b"x");
    }

    /// `set_forbidden(true)` 后返回 Forbidden（IAM 拒绝旋钮）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_secret_resolver_forbidden_toggle() {
        let r = MemSecretResolver::new();
        r.insert(resolver_tenant(), STORE_ID, SECRET_KEY, b"x".to_vec());
        r.set_forbidden(true);
        let err = r
            .resolve(resolver_tenant(), &sample_coord())
            .await
            .expect_err("forbidden");
        assert!(matches!(err, SecretResolverError::Forbidden));
    }

    /// 租户隔离：tenant_a 的 secret 不被 tenant_b resolve。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_secret_resolver_tenant_isolation() {
        let tenant_b = TenantId::parse("00000000-0000-4000-8000-000000000abc").expect("tenant b");
        let r = MemSecretResolver::new();
        r.insert(
            resolver_tenant(),
            STORE_ID,
            SECRET_KEY,
            b"tenant-a-secret".to_vec(),
        );
        let err = r
            .resolve(tenant_b, &sample_coord())
            .await
            .expect_err("tenant b not found");
        assert!(matches!(err, SecretResolverError::NotFound));
    }

    /// 编译锁：MemSecretResolver impl SecretResolver（trait 约束满足）。
    #[test]
    fn mem_secret_resolver_impl_secret_resolver() {
        fn _assert<T: SecretResolver>() {}
        _assert::<MemSecretResolver>();
    }
}
