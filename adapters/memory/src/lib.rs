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
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use consistency::{
    ConsumerGroup, EngineError, Entry, IdemKey, InboxStore, LeaseOutcome,
    LeaseToken as IdemLeaseToken, Lsn, SagaId, SagaJournalAppendRecord, SagaJournalRecord,
    SeenState,
};

use diport::{
    AuditEvent, AuditSink, AuditSinkError, CasStore, CasStoreError, CasStoreKey, CasStoreOutcome,
    CasStoreRequest, Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError,
    CheckpointVersion, Clock, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError,
    FencedWriteKey, FencedWriteRequest, FencedWriter, FencedWriterError, LeaderElector,
    LeaderElectorError, LeaderId, LeaseToken, LockAcquireOutcome, LockRenewOutcome, LockStore,
    LockStoreError, LockStoreKey, Message, MessageId, MessageStream, OutboxEmitError,
    OutboxEmitter, OutboxEnvelopeParts, OwnerCheckpointStore, PublishRequest, Publisher,
    PublisherError, SagaJournal, SagaJournalError, SaveOutcome, SecretCoordinate, SecretMaterial,
    SecretResolver, SecretResolverError, Subscriber, SubscriberError, Topic, WriteOutcome,
};
use futures::StreamExt;
use futures::channel::mpsc::{self, UnboundedSender};
use identity::ports::{IdentityError, Session, SessionId, SessionLifecycle, TenantId};
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
        let id = if request.event_id().as_str().is_empty() {
            format!("mem-{}", inner.seq)
        } else {
            request.event_id().as_str().to_string()
        };
        let topic = request.topic().as_str().to_string();
        // Memory bus is a broker substitute: expose only transport-safe metadata
        // to consumers, matching AMQP/MQTT header semantics.
        let metadata = transport_metadata(request.metadata());
        let payload = request.into_payload();
        let senders = inner.topics.entry(topic).or_default();
        // 投递 clone 给每个订阅者；receiver 已 drop（unbounded_send Err）则剔除（对标 gochannel 退订清理）。
        senders.retain(|tx| {
            tx.unbounded_send(Message::new_with_metadata(
                id.clone(),
                payload.clone(),
                metadata.clone(),
            ))
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
    tenant_signer: Option<Arc<dyn TenantMetadataSigner>>,
}

impl MemEmitter {
    /// 绑定 [`MemBus`] 构造（与 publisher / subscriber 共享同一总线底座）。
    pub fn new(bus: MemBus) -> Self {
        Self {
            bus,
            tenant_signer: None,
        }
    }

    /// 绑定 tenant metadata signer，供 demo/journey provider 演练 consumer fail-closed tenantAuthority 语义。
    pub fn with_tenant_metadata_signer(bus: MemBus, signer: Arc<dyn TenantMetadataSigner>) -> Self {
        Self {
            bus,
            tenant_signer: Some(signer),
        }
    }
}

/// tenantAuthority signing adapter for memory providers. The trait is defined in this adapter so
/// `memory` does not depend on `eventexec`; composition roots bridge it to the real authority.
pub trait TenantMetadataSigner: Send + Sync {
    /// Sign the tenant/topic/message binding as broker-visible tenant authority metadata.
    fn sign_tenant_metadata(
        &self,
        binding: TenantMetadataBinding<'_>,
    ) -> Result<String, Box<dyn Error + Send + Sync>>;
}

#[derive(Debug)]
struct TenantMetadataSignFailure {
    source: Box<dyn Error + Send + Sync>,
}

impl std::fmt::Display for TenantMetadataSignFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tenant metadata signing failed")
    }
}

impl Error for TenantMetadataSignFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Tenant authority binding passed to [`TenantMetadataSigner`].
#[derive(Debug, Clone, Copy)]
pub struct TenantMetadataBinding<'a> {
    tenant: vocab::TenantId,
    domain: &'a str,
    contract_id: &'a str,
    topic: &'a str,
    message_id: &'a str,
}

impl<'a> TenantMetadataBinding<'a> {
    /// Construct a transport tenant metadata binding.
    pub fn new(
        tenant: vocab::TenantId,
        domain: &'a str,
        contract_id: &'a str,
        topic: &'a str,
        message_id: &'a str,
    ) -> Self {
        Self {
            tenant,
            domain,
            contract_id,
            topic,
            message_id,
        }
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn domain(&self) -> &'a str {
        self.domain
    }

    pub fn contract_id(&self) -> &'a str {
        self.contract_id
    }

    pub fn topic(&self) -> &'a str {
        self.topic
    }

    pub fn message_id(&self) -> &'a str {
        self.message_id
    }
}

/// Broker-visible envelope metadata emitted by in-mem outbox paths. Keep `MemEmitter` and
/// `MemSessionLifecycle` aligned so demo providers exercise transport-safe tenant metadata.
fn envelope_metadata(
    envelope: &OutboxEnvelopeParts,
    topic: &str,
    message_id: &str,
    signer: Option<&dyn TenantMetadataSigner>,
) -> Result<diport::EnvelopeMetadata, Box<dyn Error + Send + Sync>> {
    let mut metadata = diport::EnvelopeMetadata::empty();
    metadata.insert_wire_pair(diport::KEY_TENANT_ID, envelope.tenant().to_string());
    metadata.insert_wire_pair(diport::KEY_SCHEMA_VERSION, envelope.contract().version());
    metadata.insert_wire_pair(diport::KEY_SCHEMA_HASH, envelope.contract().schema_hash());
    if let Some(signer) = signer {
        let token = signer.sign_tenant_metadata(TenantMetadataBinding::new(
            envelope.tenant(),
            envelope.contract().domain(),
            envelope.contract().contract_id(),
            topic,
            message_id,
        ))?;
        metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
    }
    Ok(metadata)
}

fn transport_metadata(source: &diport::EnvelopeMetadata) -> diport::EnvelopeMetadata {
    let mut metadata = diport::EnvelopeMetadata::empty();
    for (key, value) in source.iter_transport_headers() {
        metadata.insert_wire_pair(key, value);
    }
    metadata
}

impl OutboxEmitter for MemEmitter {
    async fn emit(
        &self,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        let topic = entry.topic().as_str();
        let message_id = entry.idem_key().as_str();
        let request = PublishRequest::new(
            Topic::new(topic),
            MessageId::new(message_id),
            entry.payload().to_vec(),
        )
        .with_metadata(
            envelope_metadata(&envelope, topic, message_id, self.tenant_signer.as_deref())
                .map_err(|source| OutboxEmitError::new(TenantMetadataSignFailure { source }))?,
        );
        self.bus
            .publisher()
            .publish(request)
            .await
            .map_err(OutboxEmitError::new)
    }
}

// ── MemSessionLifecycle：in-mem 会话生命周期替身（demo 拓扑）────────────────────

/// in-mem 会话生命周期 provider（impl [`identity::ports::SessionLifecycle`]，合并原 `MemSessionUnitOfWork`，
/// #1278）：`persist_session_and_emit` 把 session 存入进程内 store 并把 [`Entry`] fan-out 到 [`MemBus`]，
/// `find` / `revoke` 在同一 store 操作——demo / 单进程 / 测试用；生产走 postgres `PgSessionLifecycle`
/// （单事务 session + outbox co-tx）。
///
/// # WARNING / DEMO-ONLY
///
/// session store 是**进程内 in-mem**（同 [`MemEmitter`] 的 demo 哲学）：单进程内 login 写入的会话可被
/// 后续 logout / 查询查回（合并端口后 demo 也能验 logout 闭环），但**重启即丢、多实例不共享**——不是
/// durable 会话存储。需验 durable「session 跨进程可读 / 撤销」的验收**勿用本替身**——走 postgres 路径。
///
/// co-tx 原子性（both-or-neither：session 行 + outbox 行同事务）与 durable 持久化由 postgres
/// `PgSessionLifecycle`（INVARIANT OUTBOX-COTX-SESSION-01）+ 集成测试守。envelope metadata 经 `MemEmitter`
/// 同一 helper 注入，保证 demo consumer DLX 路径也能读取 tenantId。
pub struct MemSessionLifecycle {
    bus: MemBus,
    tenant_signer: Option<Arc<dyn TenantMetadataSigner>>,
    /// `SessionId` → `(Session, revoked_flag)`：进程内会话 store（demo logout/查询可见 login 写入）。
    sessions: Arc<Mutex<HashMap<SessionId, (Session, bool)>>>,
}

impl MemSessionLifecycle {
    /// 绑定 [`MemBus`] 构造（与 publisher / subscriber 共享同一总线底座）；session store 初始为空。
    pub fn new(bus: MemBus) -> Self {
        Self {
            bus,
            tenant_signer: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 绑定 tenant metadata signer，供 demo/journey provider 演练 consumer fail-closed tenantAuthority 语义。
    pub fn with_tenant_metadata_signer(bus: MemBus, signer: Arc<dyn TenantMetadataSigner>) -> Self {
        Self {
            bus,
            tenant_signer: Some(signer),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl SessionLifecycle for MemSessionLifecycle {
    async fn persist_session_and_emit(
        &self,
        session: Session,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        // demo：把 session 存入进程内 store（demo logout/查询可见），再复用 MemPublisher 把 entry fan 到总线
        // （`Message.id = entry.idem_key()` = EventId，闭合 demo 侧幂等传播）。
        // reason: 真实 co-tx both-or-neither + durable 持久化由 PgSessionLifecycle 的 OUTBOX-COTX-SESSION-01
        // 守；本替身重启即丢，envelope 只作为 Message metadata 透传，DEMO-ONLY。
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session.id().clone(), (session, false));
        let topic = entry.topic().as_str();
        let message_id = entry.idem_key().as_str();
        let request = PublishRequest::new(
            Topic::new(topic),
            MessageId::new(message_id),
            entry.payload().to_vec(),
        )
        .with_metadata(
            envelope_metadata(&envelope, topic, message_id, self.tenant_signer.as_deref())
                .map_err(|source| OutboxEmitError::new(TenantMetadataSignFailure { source }))?,
        );
        self.bus
            .publisher()
            .publish(request)
            .await
            .map_err(OutboxEmitError::new)
    }

    async fn find(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        Ok(guard
            .get(&session_id)
            .filter(|(s, revoked)| !*revoked && s.tenant() == tenant) // 跨租/已撤销 → None
            .map(|(s, _)| s.clone()))
    }

    async fn revoke(&self, tenant: TenantId, session_id: SessionId) -> Result<(), IdentityError> {
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(&session_id)
            && entry.0.tenant() == tenant
        {
            entry.1 = true; // 跨租 no-op；幂等
        }
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

/// 单个 claim 行：租约令牌 + 是否已 done。
///
/// 三态：absent（map 中无键）/ claimed(token)（`done = false`）/ done(token)（`done = true`）。
struct ClaimEntry {
    token: String,
    done: bool,
}

/// in-mem 幂等 claimer（impl [`consistency::InboxStore`]）：以 `(group, key)` 为复合主键，
/// 记 token-CAS 三态（absent / claimed(token) / done(token)），忠实实现 lease-CAS 围栏语义。
/// demo / 单进程 / 测试用；生产走 redis/pg claimer。
///
/// TTL 重捞有意省略（无时间源）——crash-recovery + 重捞正确性由 PG adapter 集成测试守；
/// in-mem 仅需忠实 token-CAS 语义，使 hard-fence 在 demo/test 中可行使。
///
/// INVARIANT: TOPO-INMEM-SEAL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（拓扑封闭：生产 bin 经 cargo-deny 连 `memory` 都依赖不到 ⇒
/// in-mem claimer 不可达生产；仅 demo/dev/journeys 组合根可构造）。
pub struct InMemClaimer {
    seen: Arc<Mutex<HashMap<(String, String), ClaimEntry>>>,
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
            seen: Arc::new(Mutex::new(HashMap::new())),
            group,
        }
    }
}

impl InboxStore for InMemClaimer {
    async fn try_claim(
        &self,
        key: &IdemKey,
        lease: &IdemLeaseToken,
    ) -> Result<SeenState, EngineError> {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // reason: in-mem 操作恒成功，unwrap_or_else 处理 poisoned lock 后继续。
        let map_key = (self.group.as_str().to_string(), key.as_str().to_string());
        match map.entry(map_key) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(ClaimEntry {
                    token: lease.as_str().to_string(),
                    done: false,
                });
                Ok(SeenState::Fresh)
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                // 已 claimed/done（无 TTL 重捞）→ Duplicate。
                // reason: TTL 重捞在此 in-mem demo 替身中有意省略——crash-recovery + 重捞正确性由
                // PG adapter 集成测试守；in-mem 仅需忠实 token-CAS 语义，使 hard-fence 在 demo/test
                // 中可行使。
                Ok(SeenState::Duplicate)
            }
        }
    }

    async fn extend(
        &self,
        key: &IdemKey,
        lease: &IdemLeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        // reason: in-mem 恒 Ok；仅 claimed 且 token 匹配 → Held，否则（absent / done / token 不符）→ Lost。
        let map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let map_key = (self.group.as_str().to_string(), key.as_str().to_string());
        let held = matches!(
            map.get(&map_key),
            Some(e) if !e.done && e.token == lease.as_str()
        );
        Ok(if held {
            LeaseOutcome::Held
        } else {
            LeaseOutcome::Lost
        })
    }

    async fn commit(
        &self,
        key: &IdemKey,
        lease: &IdemLeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        // reason: in-mem commit 恒 Ok；token 匹配 → done(Held)，不符/absent → Lost（hard-fence）。
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let map_key = (self.group.as_str().to_string(), key.as_str().to_string());
        match map.get_mut(&map_key) {
            Some(e) if e.token == lease.as_str() => {
                e.done = true;
                Ok(LeaseOutcome::Held)
            }
            _ => Ok(LeaseOutcome::Lost),
        }
    }

    async fn release(&self, key: &IdemKey, lease: &IdemLeaseToken) -> Result<(), EngineError> {
        // reason: in-mem release 恒 Ok；仅 token 匹配的 claimed 行删除（CAS），否则 no-op（不误删他人 claim）。
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let map_key = (self.group.as_str().to_string(), key.as_str().to_string());
        if matches!(map.get(&map_key), Some(e) if !e.done && e.token == lease.as_str()) {
            map.remove(&map_key);
        }
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
/// 仅校验 fencing CAS 语义，不持久化 `data`。INVARIANT: RECONCILE-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key 单调，回归见本 crate 单测）。
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

// ── MemCasStore：in-mem state-CAS 替身（etcd-revision 条件写）──────────────────────────────────────

/// `MemCasStore` 内部 HashMap 类型别名（规避 clippy::type_complexity）。
type CasStateMap = HashMap<CasStoreKey, (Vec<u8>, vocab::Epoch)>;

/// in-mem state-CAS 替身（impl [`diport::CasStore`]）：per-key `(value, revision token)`，etcd-revision 条件写。
/// 生产替身走 etcd/redis/postgres adapter；本 crate 仅测试/demo 用。
/// INVARIANT: CAS-REVISION-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key token 单调 + etcd-revision CAS；回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemCasStore {
    state: Arc<Mutex<CasStateMap>>,
}

impl MemCasStore {
    /// 新建空 store（各 key 无值无 token，首写 create-if-absent 恒 Applied）。
    pub fn new() -> Self {
        Self::default()
    }
}

impl CasStore for MemCasStore {
    async fn compare_and_swap(
        &self,
        request: CasStoreRequest,
    ) -> Result<CasStoreOutcome, CasStoreError> {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 克隆现有条目（释放不可变借用），避免与后续 map.insert 的可变借用冲突。
        let existing = map.get(&request.key).map(|(v, t)| (v.clone(), *t));
        match existing {
            None => {
                // 仅 expected==None（create-if-absent）命中；否则期望某值但键不存在 → Conflict{None}。
                if request.expected.is_none() {
                    let token = vocab::Epoch::new(1);
                    map.insert(request.key, (request.new_value.into_bytes(), token));
                    Ok(CasStoreOutcome::Applied { token })
                } else {
                    Ok(CasStoreOutcome::Conflict { current: None })
                }
            }
            Some((current, current_token)) => {
                // 先判 fencing：expected_token 低于当前 token → stale，拒写。
                if matches!(request.expected_token, Some(t) if t < current_token) {
                    return Ok(CasStoreOutcome::Fenced { current_token });
                }
                // 再判值：匹配 → 写入 + token.next()；不符 → Conflict{当前值}。
                if request.expected.as_ref().map(|b| b.as_bytes()) == Some(current.as_slice()) {
                    let token = current_token.next();
                    map.insert(request.key, (request.new_value.into_bytes(), token));
                    Ok(CasStoreOutcome::Applied { token })
                } else {
                    Ok(CasStoreOutcome::Conflict {
                        current: Some(current.into()),
                    })
                }
            }
        }
    }

    async fn shutdown(&self) -> Result<(), CasStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemLockStore：in-mem 分布式互斥锁替身（per-key 单调 fencing token）────────────────────────────────

/// `MemLockStore` 内部 per-key 锁条目：`held`=当前持有 token（`None`=空闲），`minted`=该 key 已发最高
/// token（单调；下次授予 = `minted+1`，跨 acquire/release/evict **不回退**）。
#[derive(Default)]
struct LockEntry {
    held: Option<vocab::Epoch>,
    minted: u64,
}

/// in-mem 分布式互斥锁替身（impl [`diport::LockStore`]）：per-key fencing token、token-as-capability 互斥。
/// **无时钟**——`ttl` 入参被忽略（TTL 过期 / holder crash 由 [`MemLockStore::evict`] 显式模拟，照
/// [`MemLeaseStore::evict`] 先例，不触 clippy disallowed-methods 系统时钟）。生产替身走 etcd/redis/consul
/// adapter；本 crate 仅测试/demo 用。INVARIANT: DISTLOCK-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（per-key token 单调 + 互斥；回归见本 crate 单测）。
#[derive(Clone, Default)]
pub struct MemLockStore {
    state: Arc<Mutex<HashMap<LockStoreKey, LockEntry>>>,
}

impl MemLockStore {
    /// 新建空 store（各 key 无持有者、minted 从 0 起，首 acquire 授 token=1）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 测试钩子：模拟 lock TTL 过期 / holder crash——清该 key 持有者，使下次 `acquire` 可接管
    /// （接管获**新**单调 token，不回退 `minted`）。照 [`MemLeaseStore::evict`]；生产走真实 TTL 过期。
    pub fn evict(&self, key: &LockStoreKey) {
        if let Some(entry) = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(key)
        {
            entry.held = None;
        }
    }
}

impl LockStore for MemLockStore {
    async fn acquire(
        &self,
        key: LockStoreKey,
        _ttl: Duration,
    ) -> Result<LockAcquireOutcome, LockStoreError> {
        // reason: in-mem 无 TTL，`ttl` 被忽略（过期由测试 evict 模拟）；锁内同步无 await。
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(key).or_default();
        if entry.held.is_some() {
            Ok(LockAcquireOutcome::Held)
        } else {
            let token = vocab::Epoch::new(entry.minted.saturating_add(1));
            entry.minted = token.get();
            entry.held = Some(token);
            Ok(LockAcquireOutcome::Acquired { token })
        }
    }

    async fn renew(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
        _ttl: Duration,
    ) -> Result<LockRenewOutcome, LockStoreError> {
        let map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是当前持有者才续租（同任期 token 不变）；否则已易手 / 过期被接管 → Lost。
        match map.get(&key) {
            Some(entry) if entry.held == Some(token) => Ok(LockRenewOutcome::Renewed { token }),
            _ => Ok(LockRenewOutcome::Lost),
        }
    }

    async fn release(&self, key: LockStoreKey, token: vocab::Epoch) -> Result<(), LockStoreError> {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 仅当 token 是当前持有者才放锁（幂等：stale / 已释放 → no-op，不误释他人锁）。
        if let Some(entry) = map.get_mut(&key)
            && entry.held == Some(token)
        {
            entry.held = None;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LockStoreError> {
        // reason: in-mem 无 infra 资源，关闭无需释放。
        Ok(())
    }
}

// ── MemSagaJournal：saga 执行日志 in-mem 替身 ────────────────────────────────────

/// in-mem saga journal（impl [`diport::SagaJournal`]）：按 `(saga_id, seq)` 主键幂等 append，
/// `read` 返回按 `seq` 升序排列的条目（`error_summary` 恒 `None`，符合 port 契约）。
///
/// 对标 oxidecomputer/steno `SagaLog`（append-only journal，crash-replay 幂等）。
/// 生产替身走 postgres adapter（`ON CONFLICT (saga_id,seq) DO NOTHING`）；本 crate 仅测试/demo 用。
#[derive(Clone, Default)]
pub struct MemSagaJournal {
    // (saga_id_bytes, entry) — saga_id 以 uuid::Uuid 字节存储，entry 携带 seq/step_name/status。
    inner: Arc<Mutex<Vec<(uuid::Uuid, SagaJournalAppendRecord)>>>,
}

impl MemSagaJournal {
    /// 新建空 journal。
    pub fn new() -> Self {
        Self::default()
    }
}

impl SagaJournal for MemSagaJournal {
    async fn append(
        &self,
        saga_id: &SagaId,
        entry: SagaJournalAppendRecord,
    ) -> Result<(), SagaJournalError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 幂等：同 (saga_id, seq) 已存在则 no-op（对标 postgres ON CONFLICT DO NOTHING）。
        let id = saga_id.as_uuid();
        let seq = entry.seq();
        let already_exists = g.iter().any(|(sid, e)| *sid == id && e.seq() == seq);
        if !already_exists {
            g.push((id, entry));
        }
        Ok(())
    }

    async fn read(&self, saga_id: &SagaId) -> Result<Vec<SagaJournalRecord>, SagaJournalError> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = saga_id.as_uuid();
        // 过滤本 saga、按 seq 升序（resume 据此重建执行栈）；strip error_summary（port 契约）。
        let mut entries: Vec<SagaJournalRecord> = g
            .iter()
            .filter(|(sid, _)| *sid == id)
            .map(|(_, e)| SagaJournalRecord::replayed(e.seq(), e.step_name().clone(), e.status()))
            .collect();
        entries.sort_by_key(SagaJournalRecord::seq);
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
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct RecordingTenantSigner {
        calls: Mutex<Vec<String>>,
    }

    impl RecordingTenantSigner {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl TenantMetadataSigner for RecordingTenantSigner {
        fn sign_tenant_metadata(
            &self,
            binding: TenantMetadataBinding<'_>,
        ) -> Result<String, Box<dyn Error + Send + Sync>> {
            let call = format!(
                "{}|{}|{}|{}|{}",
                binding.tenant(),
                binding.domain(),
                binding.contract_id(),
                binding.topic(),
                binding.message_id()
            );
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(call);
            Ok("signed-tenant-authority".to_string())
        }
    }

    // 测试构造 / 断言用 expect：item-level carve-out（error-handling.md §Carve-out 要求 item-level）。
    #[allow(clippy::expect_used)]
    fn sample_event() -> AuditEvent {
        AuditEvent {
            occurred_at: SystemTime::UNIX_EPOCH,
            principal_id: "alice".to_string(),
            principal_kind: vocab::PrincipalKind::User,
            tenant_id: Some(TenantId::parse(CANON_TENANT).expect("canonical tenant")),
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
            .publish(PublishRequest::new(
                Topic::new(TOPIC),
                MessageId::new("evt-roundtrip"),
                b"hello".to_vec(),
            ))
            .await
            .expect("publish");
        let msg = stream.next().await.expect("message delivered");
        assert_eq!(msg.payload.as_bytes(), b"hello");
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
            .publish(PublishRequest::new(
                Topic::new(TOPIC),
                MessageId::new("evt-fanout"),
                b"x".to_vec(),
            ))
            .await
            .expect("publish");
        assert_eq!(a.next().await.expect("a msg").payload.as_bytes(), b"x");
        assert_eq!(b.next().await.expect("b msg").payload.as_bytes(), b"x");
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
            .publish(PublishRequest::new(
                Topic::new(TOPIC),
                MessageId::new("evt-other"),
                b"x".to_vec(),
            ))
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
            consistency::OutboxPayload::from_reviewed_event_bytes(b"payload".to_vec()),
        );
        let tenant =
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let env = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", TOPIC, "v1", HASH),
            tenant,
            diport::EnvelopeSubjectId::from_opaque("subj-opaque").expect("subject"),
            diport::OutboxActor::scoped(
                vocab::PrincipalKind::User,
                diport::OpaqueActorId::from_opaque("actor-opaque").expect("actor"),
                tenant,
                vocab::ScopedTenant::SelfOnly,
            ),
        );
        MemEmitter::new(bus.clone())
            .emit(entry, env)
            .await
            .expect("emit");
        let msg = stream.next().await.expect("message delivered");
        assert_eq!(msg.id.as_str(), "evt-session-77", "EventId 应作 Message.id");
        assert_eq!(msg.payload.as_bytes(), b"payload");
        assert_eq!(
            msg.metadata.tenant_id(),
            Some(vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")),
            "MemEmitter 应透传 tenantId metadata"
        );
        assert_eq!(msg.metadata.get(diport::KEY_SCHEMA_VERSION), Some("v1"));
        assert_eq!(msg.metadata.get(diport::KEY_SCHEMA_HASH), Some(HASH));
        assert_eq!(
            msg.metadata.get(diport::KEY_SUBJECT_ID),
            None,
            "MemEmitter 不应把 persisted-only subjectId 投递给 consumer"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_ACTOR),
            None,
            "MemEmitter 不应把 persisted-only actor 投递给 consumer"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_emitter_signed_path_adds_tenant_authority() {
        let bus = MemBus::new();
        let signer = Arc::new(RecordingTenantSigner::default());
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        let entry = Entry::new(
            consistency::Topic::parse(TOPIC).expect("topic"),
            IdemKey::parse("evt-signed-tenant").expect("idem"),
            consistency::OutboxPayload::from_reviewed_event_bytes(b"payload".to_vec()),
        );
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let env = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", TOPIC, "v1", HASH),
            tenant,
            diport::EnvelopeSubjectId::from_opaque("subj-opaque").expect("subject"),
            diport::OutboxActor::scoped(
                vocab::PrincipalKind::User,
                diport::OpaqueActorId::from_opaque("actor-opaque").expect("actor"),
                tenant,
                vocab::ScopedTenant::SelfOnly,
            ),
        );

        MemEmitter::with_tenant_metadata_signer(bus.clone(), signer.clone())
            .emit(entry, env)
            .await
            .expect("emit");

        let msg = stream.next().await.expect("message delivered");
        assert_eq!(msg.metadata.tenant_id(), Some(tenant));
        assert_eq!(
            msg.metadata.get(diport::KEY_TENANT_AUTHORITY),
            Some("signed-tenant-authority"),
            "signed memory emit path must carry tenantAuthority"
        );
        assert_eq!(
            signer.calls(),
            vec![format!(
                "{CANON_TENANT}|identity|{TOPIC}|{TOPIC}|evt-signed-tenant"
            )],
            "tenantAuthority binding must match durable relay binding fields"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_session_lifecycle_emits_tenant_metadata() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let session = Session::hydrate(
            "sess-mem-tenant",
            "subj-opaque-session",
            tenant,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3600),
            SystemTime::UNIX_EPOCH,
        );
        let entry = Entry::new(
            consistency::Topic::parse(TOPIC).expect("topic"),
            IdemKey::parse("evt-session-mem-tenant").expect("idem"),
            consistency::OutboxPayload::from_reviewed_event_bytes(b"payload".to_vec()),
        );
        let envelope = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", TOPIC, "v1", HASH),
            tenant,
            diport::EnvelopeSubjectId::from_opaque("subj-opaque-session").expect("subject"),
            diport::OutboxActor::scoped(
                vocab::PrincipalKind::User,
                diport::OpaqueActorId::from_opaque("actor-opaque-session").expect("actor"),
                tenant,
                vocab::ScopedTenant::SelfOnly,
            ),
        );

        let signer = Arc::new(RecordingTenantSigner::default());
        MemSessionLifecycle::with_tenant_metadata_signer(bus.clone(), signer)
            .persist_session_and_emit(session, entry, envelope)
            .await
            .expect("persist session and emit");

        let msg = stream.next().await.expect("message delivered");
        assert_eq!(
            msg.metadata.tenant_id(),
            Some(tenant),
            "MemSessionLifecycle co-tx path must carry tenantId metadata"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_TENANT_AUTHORITY),
            Some("signed-tenant-authority"),
            "signed MemSessionLifecycle path must carry tenantAuthority metadata"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_SUBJECT_ID),
            None,
            "MemSessionLifecycle co-tx path must not expose persisted-only subjectId"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_ACTOR),
            None,
            "MemSessionLifecycle co-tx path must not expose persisted-only actor"
        );
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

    /// metadata passthrough：publish 携 envelope metadata → subscriber 端 Message.metadata 保真。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_metadata_propagates_to_subscriber() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        let mut md = diport::EnvelopeMetadata::empty();
        md.insert_wire_pair(diport::KEY_OCCURRED_AT, "1700000003");
        md.insert_wire_pair(diport::KEY_CORRELATION, "corr-mem-1");
        md.insert_wire_pair(diport::KEY_SUBJECT_ID, "subj-mem");
        md.insert_wire_pair(diport::KEY_ACTOR, "actor-mem");
        bus.publisher()
            .publish(
                PublishRequest::new(
                    Topic::new(TOPIC),
                    MessageId::new("evt-meta"),
                    b"with-meta".to_vec(),
                )
                .with_metadata(md),
            )
            .await
            .expect("publish");
        let msg = stream.next().await.expect("message delivered");
        assert_eq!(msg.payload.as_bytes(), b"with-meta");
        assert_eq!(
            msg.metadata.occurred_at_secs(),
            Some(1_700_000_003_i64),
            "occurred_at 应透传到 Message.metadata"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_CORRELATION),
            Some("corr-mem-1"),
            "correlation 应透传到 Message.metadata"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_SUBJECT_ID),
            None,
            "memory broker must filter persisted-only subjectId"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_ACTOR),
            None,
            "memory broker must filter persisted-only actor"
        );
        token.cancel();
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

    /// 令牌测试 helper（`IdemLeaseToken` = `consistency::LeaseToken` 别名）。
    fn tok() -> IdemLeaseToken {
        IdemLeaseToken::mint()
    }

    /// 同一 key 连续 try_claim 3 次：第 1 次 Fresh，第 2、3 次 Duplicate。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果及 try_claim，item-level carve-out（error-handling.md §Carve-out）。
    async fn claimer_first_fresh_then_duplicate() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group = consistency::ConsumerGroup::parse("audit").expect("group");
        let claimer = InMemClaimer::new(group);
        let key = IdemKey::parse("session.created:tenant-1:evt-1").expect("key");
        let t = tok();

        let states: Vec<SeenState> = vec![
            claimer.try_claim(&key, &t).await.expect("try_claim 1"),
            claimer.try_claim(&key, &t).await.expect("try_claim 2"),
            claimer.try_claim(&key, &t).await.expect("try_claim 3"),
        ];

        assert_eq!(states[0], SeenState::Fresh, "第 1 次应为 Fresh");
        assert_eq!(states[1], SeenState::Duplicate, "第 2 次应为 Duplicate");
        assert_eq!(states[2], SeenState::Duplicate, "第 3 次应为 Duplicate");
    }

    /// 两个不同 group 的 claimer，同一 key 各自 Fresh——证明去重按组隔离，组漂移→去重失效。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果及 try_claim，item-level carve-out（error-handling.md §Carve-out）。
    async fn consumer_group_drift_breaks_dedup() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group_a = consistency::ConsumerGroup::parse("audit").expect("group-a");
        let group_b = consistency::ConsumerGroup::parse("settings").expect("group-b");
        let claimer_a = InMemClaimer::new(group_a);
        let claimer_b = InMemClaimer::new(group_b);
        let key = IdemKey::parse("session.created:tenant-1:evt-1").expect("key");

        let state_a = claimer_a
            .try_claim(&key, &tok())
            .await
            .expect("try_claim a");
        let state_b = claimer_b
            .try_claim(&key, &tok())
            .await
            .expect("try_claim b");

        assert_eq!(state_a, SeenState::Fresh, "group-a 首见应为 Fresh");
        assert_eq!(
            state_b,
            SeenState::Fresh,
            "group-b 独立首见应为 Fresh（组隔离）"
        );
    }

    /// 续租：持有期间 extend = Held；token 不符 = Lost（他人令牌或已被重捞）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 token-CAS 续租语义断言——in-mem claimer 方法恒 Ok，item-level carve-out。
    async fn claimer_extend_held_while_owned_lost_on_token_mismatch() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group = consistency::ConsumerGroup::parse("audit").expect("group");
        let claimer = InMemClaimer::new(group);
        let key = IdemKey::parse("evt-extend-1").expect("key");
        let mine = tok();
        assert_eq!(
            claimer.try_claim(&key, &mine).await.expect("try_claim"),
            SeenState::Fresh
        );
        // 持有者续租成功
        assert_eq!(
            claimer.extend(&key, &mine).await.expect("extend"),
            LeaseOutcome::Held
        );
        // 他人令牌续租 → Lost
        assert_eq!(
            claimer.extend(&key, &tok()).await.expect("extend-other"),
            LeaseOutcome::Lost
        );
    }

    /// hard-fence：stale token commit = Lost；正确 token commit = Held。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 hard-fence 语义断言——in-mem claimer 方法恒 Ok，item-level carve-out。
    async fn claimer_commit_with_stale_token_is_lost_hard_fence() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group = consistency::ConsumerGroup::parse("audit").expect("group");
        let claimer = InMemClaimer::new(group);
        let key = IdemKey::parse("evt-fence-1").expect("key");
        let mine = tok();
        assert_eq!(
            claimer.try_claim(&key, &mine).await.expect("try_claim"),
            SeenState::Fresh
        );
        // stale holder（错误 token）commit → Lost（hard-fence：不可降级为 done）
        assert_eq!(
            claimer.commit(&key, &tok()).await.expect("commit-stale"),
            LeaseOutcome::Lost
        );
        // 真持有者 commit → Held
        assert_eq!(
            claimer.commit(&key, &mine).await.expect("commit"),
            LeaseOutcome::Held
        );
    }

    /// commit 正确 token → Held；再 try_claim → Duplicate（done 行永久去重）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 commit 后永久去重语义断言——in-mem claimer 方法恒 Ok，item-level carve-out。
    async fn claimer_commit_correct_token_then_duplicate() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group = consistency::ConsumerGroup::parse("audit").expect("group");
        let claimer = InMemClaimer::new(group);
        let key = IdemKey::parse("evt-commit-dup").expect("key");
        let t = tok();
        assert_eq!(
            claimer.try_claim(&key, &t).await.expect("try_claim"),
            SeenState::Fresh
        );
        assert_eq!(
            claimer.commit(&key, &t).await.expect("commit"),
            LeaseOutcome::Held
        );
        assert_eq!(
            claimer.try_claim(&key, &tok()).await.expect("re-try_claim"),
            SeenState::Duplicate,
            "done 行永久 Duplicate"
        );
    }

    /// release token CAS：他人 token release 为 no-op（不误删 claim，仍 Duplicate）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 release CAS no-op 语义断言——in-mem claimer 方法恒 Ok，item-level carve-out。
    async fn claimer_release_with_stale_token_is_noop() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let group = consistency::ConsumerGroup::parse("audit").expect("group");
        let claimer = InMemClaimer::new(group);
        let key = IdemKey::parse("evt-release-cas").expect("key");
        let mine = tok();
        assert_eq!(
            claimer.try_claim(&key, &mine).await.expect("try_claim"),
            SeenState::Fresh
        );
        // stale token release → no-op（不误删他人 claim）
        claimer.release(&key, &tok()).await.expect("release-stale");
        // claim 仍在（未被误删）→ Duplicate
        assert_eq!(
            claimer.try_claim(&key, &tok()).await.expect("re-try_claim"),
            SeenState::Duplicate,
            "stale token release 不误删 claim"
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
            data: b"state".to_vec().into(),
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
            data: b"x".to_vec().into(),
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

    // ── MemCasStore 测试（INVARIANT: CAS-REVISION-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）──────────────────────────────────────────

    /// 建空键 create-if-absent：expected=None → Applied{token=Epoch(1)}。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn absent_create_applies() {
        let store = MemCasStore::new();
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: CasStoreKey::new("k1"),
                expected: None,
                new_value: b"v1".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(1)
            }
        );
    }

    /// 值匹配 CAS：Applied，token 从 Epoch(1) 推进到 Epoch(2)（bump 验证）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn match_applies_and_bumps_token() {
        let store = MemCasStore::new();
        let key = CasStoreKey::new("k2");
        // 首写
        store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"v1".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("create ok");
        // 值匹配 swap
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"v1".to_vec().into()),
                new_value: b"v2".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(2)
            },
            "token 应从 1 推进到 2"
        );
    }

    /// 值不符：expected=错误值 → Conflict{current=Some(实际当前值)}。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mismatch_conflicts() {
        let store = MemCasStore::new();
        let key = CasStoreKey::new("k3");
        store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"actual".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("create ok");
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"wrong".to_vec().into()),
                new_value: b"new".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Conflict {
                current: Some(b"actual".to_vec().into())
            }
        );
    }

    /// 键已存在但 expected=None → Conflict（不是覆盖写；create-if-absent 仅对不存在键有效）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn expected_none_on_existing_conflicts() {
        let store = MemCasStore::new();
        let key = CasStoreKey::new("k4");
        store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"v1".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("create ok");
        // expected=None 对已存在键 → Conflict（None 不匹配 Some("v1")）
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"v2".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Conflict {
                current: Some(b"v1".to_vec().into())
            }
        );
    }

    /// stale token：expected_token=Epoch(0) < 当前 Epoch(1) → Fenced{current_token=Epoch(1)}。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn stale_token_fenced() {
        let store = MemCasStore::new();
        let key = CasStoreKey::new("k5");
        store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"v1".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("create ok");
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"v1".to_vec().into()),
                new_value: b"v2".to_vec().into(),
                expected_token: Some(vocab::Epoch::new(0)), // stale < 当前 Epoch(1)
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Fenced {
                current_token: vocab::Epoch::new(1)
            }
        );
    }

    /// 连续多次成功 swap：token 严格单调递增 1→2→3。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn token_monotonic_across_swaps() {
        let store = MemCasStore::new();
        let key = CasStoreKey::new("k6");
        // 首写 → token=1
        let r1 = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"v1".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("create");
        assert_eq!(
            r1,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(1)
            }
        );
        // 第二次 → token=2
        let r2 = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"v1".to_vec().into()),
                new_value: b"v2".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("swap 2");
        assert_eq!(
            r2,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(2)
            }
        );
        // 第三次 → token=3
        let r3 = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"v2".to_vec().into()),
                new_value: b"v3".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("swap 3");
        assert_eq!(
            r3,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(3)
            }
        );
    }

    /// anti-vacuity：写新值后，用旧 expected 再 CAS 必 Conflict（证 CAS 真比较、非恒 Applied）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn anti_vacuity_old_expected_after_write() {
        let store = MemCasStore::new();
        let key = CasStoreKey::new("k7");
        // 首写 v1
        store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"v1".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("create");
        // 写入 v2（覆盖 v1）
        store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"v1".to_vec().into()),
                new_value: b"v2".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("swap to v2");
        // 用旧 expected=v1 再 CAS → Conflict（当前是 v2）
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"v1".to_vec().into()),
                new_value: b"v3".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("stale cas");
        assert_eq!(
            outcome,
            CasStoreOutcome::Conflict {
                current: Some(b"v2".to_vec().into())
            },
            "写新值后旧 expected 必 Conflict"
        );
    }

    /// Fix 4：expected=Some + 键不存在 → Conflict{current:None}（CAS-REVISION-MONO-01 边界——None 路径）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn expected_some_on_absent_key_returns_conflict_none() {
        let store = MemCasStore::new();
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: CasStoreKey::new("absent-key"),
                expected: Some(b"something".to_vec().into()),
                new_value: b"new".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Conflict { current: None },
            "expected=Some 但键不存在 → Conflict{{current:None}}"
        );
    }

    /// Fix 5：expected_token == current_token（相等=不 stale，应放行 Applied 非 Fenced）——anti-mutation：防误改 < 为 <=。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn equal_token_is_not_fenced() {
        let store = MemCasStore::new();
        let key = CasStoreKey::new("k-equal-token");
        // create → token=Epoch(1)
        store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: None,
                new_value: b"v1".to_vec().into(),
                expected_token: None,
            })
            .await
            .expect("create ok");
        // expected_token=Some(Epoch(1)) == 当前 token → Applied（非 Fenced）
        let outcome = store
            .compare_and_swap(CasStoreRequest {
                key: key.clone(),
                expected: Some(b"v1".to_vec().into()),
                new_value: b"v2".to_vec().into(),
                expected_token: Some(vocab::Epoch::new(1)),
            })
            .await
            .expect("cas ok");
        assert_eq!(
            outcome,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(2)
            },
            "expected_token == current_token 应 Applied，而非 Fenced"
        );
    }

    /// 编译锁：MemCasStore impl CasStore（trait 约束满足）。
    #[test]
    fn mem_cas_store_impl_cas_store() {
        use core::marker::PhantomData;
        fn assert_cas_store<T: CasStore>(_: PhantomData<T>) {}
        assert_cas_store(PhantomData::<MemCasStore>);
    }

    // ── MemLockStore 测试（INVARIANT: DISTLOCK-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）────────────────────────────────────────

    fn lock_ttl() -> Duration {
        Duration::from_secs(30)
    }

    /// 空闲 key acquire → Acquired{token=Epoch(1)}（首授 token=1）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out（error-handling.md §Carve-out）。
    async fn mem_lock_absent_acquires() {
        let store = MemLockStore::new();
        let outcome = store
            .acquire(LockStoreKey::new("lock-1"), lock_ttl())
            .await
            .expect("acquire ok");
        assert_eq!(
            outcome,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(1)
            }
        );
    }

    /// 已持有 key 再 acquire → Held（互斥）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out。
    async fn mem_lock_held_returns_held() {
        let store = MemLockStore::new();
        let key = LockStoreKey::new("lock-2");
        store
            .acquire(key.clone(), lock_ttl())
            .await
            .expect("first acquire ok");
        let outcome = store
            .acquire(key, lock_ttl())
            .await
            .expect("second acquire ok");
        assert_eq!(outcome, LockAcquireOutcome::Held);
    }

    /// 持有者 renew → Renewed，token 不变（同任期）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out。
    async fn mem_lock_renew_keeps_same_token() {
        let store = MemLockStore::new();
        let key = LockStoreKey::new("lock-3");
        store
            .acquire(key.clone(), lock_ttl())
            .await
            .expect("acquire ok");
        let outcome = store
            .renew(key, vocab::Epoch::new(1), lock_ttl())
            .await
            .expect("renew ok");
        assert_eq!(
            outcome,
            LockRenewOutcome::Renewed {
                token: vocab::Epoch::new(1)
            },
            "续租同任期 token 不变"
        );
    }

    /// release 后 key 空闲：可被再次 acquire，token 单调 +1。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out。
    async fn mem_lock_release_frees_and_reacquire_bumps_token() {
        let store = MemLockStore::new();
        let key = LockStoreKey::new("lock-4");
        store
            .acquire(key.clone(), lock_ttl())
            .await
            .expect("acquire ok");
        store
            .release(key.clone(), vocab::Epoch::new(1))
            .await
            .expect("release ok");
        let outcome = store.acquire(key, lock_ttl()).await.expect("reacquire ok");
        assert_eq!(
            outcome,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(2)
            },
            "释放后重获 token 单调递增到 2"
        );
    }

    /// anti-vacuity：evict（模拟过期）后他者 acquire 获单调 +1 token；旧 token renew→Lost、release→no-op。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out。
    async fn mem_lock_evicted_old_token_loses_renew_and_release_is_noop() {
        let store = MemLockStore::new();
        let key = LockStoreKey::new("lock-5");
        store
            .acquire(key.clone(), lock_ttl())
            .await
            .expect("acquire token=1");

        // 模拟 TTL 过期 → 清持有者。
        store.evict(&key);

        // 他者接管 → token 单调 +1（=2），证明 evict 不回退 minted。
        let second = store
            .acquire(key.clone(), lock_ttl())
            .await
            .expect("reacquire token=2");
        assert_eq!(
            second,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(2)
            }
        );

        // 旧 token(1) renew → Lost（已易手）。
        let lost = store
            .renew(key.clone(), vocab::Epoch::new(1), lock_ttl())
            .await
            .expect("renew ok");
        assert_eq!(lost, LockRenewOutcome::Lost);

        // 旧 token(1) release → no-op：锁仍被 token=2 持有。
        store
            .release(key.clone(), vocab::Epoch::new(1))
            .await
            .expect("release ok");
        let still_held = store.acquire(key, lock_ttl()).await.expect("acquire ok");
        assert_eq!(
            still_held,
            LockAcquireOutcome::Held,
            "旧 token release 应 no-op，锁仍被 token=2 持有"
        );
    }

    /// renew 不存在的 key → Lost（无持有者）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out。
    async fn mem_lock_renew_absent_key_is_lost() {
        let store = MemLockStore::new();
        let outcome = store
            .renew(
                LockStoreKey::new("never-acquired"),
                vocab::Epoch::new(1),
                lock_ttl(),
            )
            .await
            .expect("renew ok");
        assert_eq!(outcome, LockRenewOutcome::Lost);
    }

    /// release 不存在的 key → no-op（Ok）+ 不向 map 插入残留条目（之后首 acquire 仍得 token=1）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path assert，item-level carve-out。
    async fn mem_lock_release_absent_key_is_noop() {
        let store = MemLockStore::new();
        let key = LockStoreKey::new("never-acquired");
        // 从未 acquire 的 key release → Ok（幂等 no-op）。
        store
            .release(key.clone(), vocab::Epoch::new(1))
            .await
            .expect("release ok");
        // 之后仍可正常首 acquire 得 token=1——证明 release-on-absent 未插入残留条目。
        let outcome = store.acquire(key, lock_ttl()).await.expect("acquire ok");
        assert_eq!(
            outcome,
            LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(1)
            },
            "release-on-absent 不应插入残留条目"
        );
    }

    /// 编译锁：MemLockStore impl LockStore（trait 约束满足）。
    #[test]
    fn mem_lock_store_impl_lock_store() {
        use core::marker::PhantomData;
        fn assert_lock_store<T: LockStore>(_: PhantomData<T>) {}
        assert_lock_store(PhantomData::<MemLockStore>);
    }

    // ── MemSagaJournal 测试 ───────────────────────────────────────────────────

    /// append 幂等 + read 按 seq 升序。
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试用 canonical literal 构造 StepName/SagaId，item-level carve-out（error-handling.md §Carve-out）。
    async fn mem_saga_journal_append_idempotent_and_read_order() {
        use consistency::{SagaId, SagaJournalStatus};
        use uuid::Uuid;

        let journal = MemSagaJournal::new();
        let saga_id = SagaId::new(Uuid::from_u128(1));
        let steps = [
            consistency::StepName::parse("step0").unwrap(),
            consistency::StepName::parse("step1").unwrap(),
            consistency::StepName::parse("step2").unwrap(),
            consistency::StepName::parse("step3").unwrap(),
            consistency::StepName::parse("step4").unwrap(),
        ];

        // append 全 status 集合（Failed 携带 error_summary，read 应剥离）。
        for (seq, (status, step)) in SagaJournalStatus::ALL
            .into_iter()
            .zip(steps.iter().cloned())
            .enumerate()
        {
            let record = match status {
                SagaJournalStatus::Executing => {
                    SagaJournalAppendRecord::executing(seq as u64, step)
                }
                SagaJournalStatus::Completed => {
                    SagaJournalAppendRecord::completed(seq as u64, step)
                }
                SagaJournalStatus::Compensating => {
                    SagaJournalAppendRecord::compensating(seq as u64, step)
                }
                SagaJournalStatus::Compensated => {
                    SagaJournalAppendRecord::compensated(seq as u64, step)
                }
                SagaJournalStatus::Failed => {
                    SagaJournalAppendRecord::failed(seq as u64, step, "compensation failed")
                }
                _ => unreachable!("SagaJournalStatus::ALL contains only known statuses"),
            };
            journal.append(&saga_id, record).await.unwrap();
        }

        // 重复 append (saga_id, seq=0) → no-op（幂等）。
        journal
            .append(
                &saga_id,
                SagaJournalAppendRecord::executing(0, steps[0].clone()),
            )
            .await
            .unwrap();

        let entries = journal.read(&saga_id).await.unwrap();
        assert_eq!(
            entries.len(),
            SagaJournalStatus::ALL.len(),
            "重复 append 后条数不变"
        );
        for (idx, entry) in entries.iter().enumerate() {
            assert_eq!(entry.seq(), idx as u64);
            assert_eq!(entry.step_name(), &steps[idx]);
            assert_eq!(entry.status(), SagaJournalStatus::ALL[idx]);
            // read record 类型不暴露 runtime-only error_summary；resume 只需 seq/step_name/status。
        }
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
        use diport::{DeadLetterSummary, EnvelopeMetadata, WritableDeadLetterSource};

        let store = MemDeadLetterStore::new();
        assert!(store.is_empty());

        let record = DeadLetterRecord::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
            "msg-1",
            "identity",
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("max retries exhausted"),
            3,
            WritableDeadLetterSource::Consumer,
            EnvelopeMetadata::empty(),
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
