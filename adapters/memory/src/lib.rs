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
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use authn::{AuthGrant, AuthGrantId, AuthGrantStatus};
#[cfg(test)]
use consistency::EventTopic;
use consistency::{
    EngineError, EventEntry, IdemKey, InboxReceiptContext, InboxStore, LeaseOutcome,
    LeaseToken as IdemLeaseToken, Lsn, SagaCompensationCause, SagaIdempotencyKey,
    SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaJournalRecord, SagaJournalStatus,
    SagaLease, SagaLeaseOutcome, SagaOperatorReason, SagaReceiptScope, SeenState,
};
use diport::{
    AuditEvent, AuditSink, AuditSinkError, CasStore, CasStoreError, CasStoreKey, CasStoreOutcome,
    CasStoreRequest, Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError,
    CheckpointVersion, Clock, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError,
    FencedWriteKey, FencedWriteRequest, FencedWriter, FencedWriterError, LeaderElector,
    LeaderElectorError, LeaderId, LeaseToken, LockAcquireOutcome, LockRenewOutcome, LockStore,
    LockStoreError, LockStoreKey, Message, MessageId, MessageStream, OutboxEmitError,
    OutboxEmitter, OutboxEnvelopeParts, OwnerCheckpointStore, PublishRequest, Publisher,
    PublisherError, SagaClaimOutcome, SagaClaimRequest, SagaCompensationProgress,
    SagaDurableMutation, SagaDurableMutationOutcome, SagaDurableStore, SagaDurableStoreError,
    SagaDurableStoreErrorKind, SagaForwardProgress, SagaInstanceRegistration, SagaLeaseHolder,
    SagaLeaseTtl, SagaOperatorAuthorization, SagaOperatorCasOutcome, SagaOperatorClaimOutcome,
    SagaOperatorJournalExpectation, SagaOperatorRepair, SagaOperatorRepairClaim,
    SagaOperatorRepairReason, SagaOperatorStatusOutcome, SagaOperatorStatusSnapshot,
    SagaOperatorStore, SagaRecoveryOutcome, SagaRecoveryRequest, SagaRecoverySnapshot,
    SagaRunnableInstance, SagaTenantCursor, SagaTenantPage, SagaTenantSource,
    SagaTerminalReceiptOutcome, SagaTerminalReceiptRequest, SagaUnresolvedObservation,
    SagaVerifiedTerminalReceipt, SagaWorkerIdentity, SaveOutcome, SecretCoordinate, SecretMaterial,
    SecretResolver, SecretResolverError, StoredSagaReceipt, Subscriber, SubscriberError, Topic,
    WriteOutcome, saga_operator_action,
};
use futures::StreamExt;
use futures::channel::mpsc::{self, UnboundedSender};
use identity::ports::{
    AuthGrantLifecycle, IdentityError, IdentitySecurityLifecycle, LoginGrantMutation,
    RefreshExecutionCommand, RefreshExecutionOutcome, RefreshStatus, RefreshTokenHash,
    RefreshTokenId, RefreshTokenRecord, RefreshTokenStore, TenantRepoScope,
};
use tokio_util::sync::CancellationToken;

// 锁中毒（仅当持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，
// 且 lib 代码禁 unwrap/expect（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean。

// ── MemBus：publisher / subscriber 共享的 in-mem 事件总线 ──────────────────────

#[cfg(test)]
struct PublishProbe {
    enqueued: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(test)]
impl PublishProbe {
    fn new() -> Self {
        Self {
            enqueued: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        }
    }
}

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
    #[cfg(test)]
    publish_probe: Option<Arc<PublishProbe>>,
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

    #[cfg(test)]
    fn with_publish_probe(mut self, probe: Arc<PublishProbe>) -> Self {
        self.publish_probe = Some(probe);
        self
    }

    fn publish_sync(&self, request: PublishRequest) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.seq += 1;
        let id = if request.event_id().as_str().is_empty() {
            format!("mem-{}", inner.seq)
        } else {
            request.event_id().as_str().to_string()
        };
        let topic = request.topic().as_str().to_string();
        let metadata = transport_metadata(request.metadata());
        let payload = request.into_payload();
        inner.topics.entry(topic).or_default().retain(|tx| {
            tx.unbounded_send(Message::new_with_metadata(
                id.clone(),
                payload.clone(),
                metadata.clone(),
            ))
            .is_ok()
        });
        #[cfg(test)]
        if let Some(probe) = &self.publish_probe {
            probe.enqueued.wait();
            probe.release.wait();
        }
    }
}

/// in-mem 发布端口。
pub struct MemPublisher {
    bus: MemBus,
}

impl Publisher for MemPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        self.bus.publish_sync(request);
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
/// **不持久化**——demo / 单进程 / 测试用；不能作为 durable production event writer。
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
/// `MemAuthGrantStore` aligned so demo providers exercise transport-safe tenant metadata.
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
        entry: EventEntry,
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

// ── MemAuthGrantStore：统一认证授权根 / refresh family provider（demo 拓扑）─────

#[derive(Default)]
struct AuthGrantStoreState {
    grants: HashMap<AuthGrantId, AuthGrant>,
    refresh: HashMap<RefreshTokenId, RefreshTokenRecord>,
}

/// Demo-only unified provider. One shared state implements both [`AuthGrantLifecycle`] and
/// [`RefreshTokenStore`], so login cannot persist an initial refresh token into an unrelated store.
///
/// # WARNING / DEMO-ONLY
///
/// State is process-local and disappears on restart. Durable grant/refresh/outbox guarantees are
/// provided by PostgreSQL; this provider exists for journeys and single-process demos.
#[derive(Clone)]
pub struct MemAuthGrantStore {
    bus: MemBus,
    tenant_signer: Option<Arc<dyn TenantMetadataSigner>>,
    state: Arc<Mutex<AuthGrantStoreState>>,
}

impl MemAuthGrantStore {
    /// Bind the provider to the same in-memory bus and clock used by the demo composition.
    pub fn new(bus: MemBus, _clock: Arc<dyn Clock>) -> Self {
        Self {
            bus,
            tenant_signer: None,
            state: Arc::new(Mutex::new(AuthGrantStoreState::default())),
        }
    }

    /// Bind a tenant metadata signer and authoritative writer clock for fail-closed journey coverage.
    pub fn with_tenant_metadata_signer(
        bus: MemBus,
        signer: Arc<dyn TenantMetadataSigner>,
        _clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            bus,
            tenant_signer: Some(signer),
            state: Arc::new(Mutex::new(AuthGrantStoreState::default())),
        }
    }
}

fn auth_grant_binding_matches(grant: &AuthGrant, refresh: &RefreshTokenRecord) -> bool {
    grant.status() == AuthGrantStatus::Active
        && refresh.status() == RefreshStatus::Active
        && refresh.auth_grant_status() == AuthGrantStatus::Active
        && refresh.tenant() == grant.tenant()
        && refresh.auth_grant_id() == grant.id()
        && refresh.user_id() == grant.user_id()
        && refresh.issuance_epoch() == grant.authn_epoch_at_issue()
        && refresh.expires_at() <= grant.expires_at()
}

fn identity_storage_error(message: &'static str) -> IdentityError {
    IdentityError::Storage(Box::new(std::io::Error::other(message)))
}

impl AuthGrantLifecycle for MemAuthGrantStore {
    async fn persist_login_grant(
        &self,
        receipt: identity::ports::LoginProducerReceipt,
        scope: TenantRepoScope,
        mutation: LoginGrantMutation,
        event: eventexec::event::ReviewedEvent,
    ) -> Result<identity::ports::PersistedLoginGrantReceipt, OutboxEmitError> {
        let (grant, initial_refresh, persistence) = mutation.into_parts();
        if grant.tenant() != scope.tenant()
            || !auth_grant_binding_matches(&grant, &initial_refresh)
            || initial_refresh.parent_id().is_some()
            || initial_refresh.lineage_id() != initial_refresh.id()
        {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "login grant binding mismatch",
            )));
        }
        if event.envelope().tenant() != scope.tenant() {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "login grant envelope tenant scope mismatch",
            )));
        }
        let _authorization = receipt
            .authorize(event.fact(), *event.envelope().contract())
            .ok_or_else(|| {
                OutboxEmitError::new(std::io::Error::other(
                    "login producer does not authorize session-created envelope",
                ))
            })?;
        let (entry, envelope, _fact) = event.into_parts();
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
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.grants.contains_key(grant.id())
            || state.refresh.contains_key(initial_refresh.id())
            || state.refresh.values().any(|record| {
                record.tenant() == initial_refresh.tenant()
                    && record.token_hash() == initial_refresh.token_hash()
            })
        {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "login grant already exists",
            )));
        }
        state
            .refresh
            .insert(initial_refresh.id().clone(), initial_refresh);
        state.grants.insert(grant.id().clone(), grant);
        drop(state);
        // In-memory publish is infallible. Make aggregate state visible before an asynchronous
        // subscriber can observe the corresponding session-created event.
        self.bus.publish_sync(request);
        Ok(persistence.confirm())
    }

    async fn find_active(
        &self,
        scope: TenantRepoScope,
        grant_id: AuthGrantId,
        observed_at: SystemTime,
    ) -> Result<Option<AuthGrant>, IdentityError> {
        let tenant = scope.tenant();
        Ok(self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .grants
            .get(&grant_id)
            .filter(|grant| {
                grant.tenant() == tenant
                    && grant.status() == AuthGrantStatus::Active
                    && grant.expires_at() > observed_at
            })
            .cloned())
    }
}

impl RefreshTokenStore for MemAuthGrantStore {
    async fn find_by_hash(
        &self,
        scope: TenantRepoScope,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
        Ok(self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .refresh
            .values()
            .find(|record| record.tenant() == scope.tenant() && record.token_hash() == &hash)
            .cloned())
    }
}

impl IdentitySecurityLifecycle for MemAuthGrantStore {
    async fn execute_refresh(
        &self,
        _receipt: identity::ports::RefreshProducerReceipt,
        _scope: TenantRepoScope,
        _command: RefreshExecutionCommand,
    ) -> Result<RefreshExecutionOutcome, IdentityError> {
        Err(identity_storage_error(
            "demo memory provider does not persist security-event outbox facts",
        ))
    }

    async fn execute_password_change(
        &self,
        _receipt: identity::ports::PasswordChangeProducerReceipt,
        _scope: TenantRepoScope,
        _command: identity::PasswordChangeCommand,
    ) -> Result<identity::CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error(
            "unsupported memory security lifecycle",
        ))
    }

    async fn execute_account_status_set(
        &self,
        _receipt: identity::ports::AccountStatusSetProducerReceipt,
        _scope: TenantRepoScope,
        _command: identity::AccountStatusSetCommand,
    ) -> Result<identity::CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error(
            "unsupported memory security lifecycle",
        ))
    }

    async fn execute_logout_current(
        &self,
        _receipt: identity::ports::LogoutCurrentProducerReceipt,
        _scope: TenantRepoScope,
        _command: identity::LogoutCurrentCommand,
    ) -> Result<identity::CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error(
            "unsupported memory security lifecycle",
        ))
    }

    async fn execute_logout_all(
        &self,
        _receipt: identity::ports::LogoutAllProducerReceipt,
        _scope: TenantRepoScope,
        _command: identity::LogoutAllCommand,
    ) -> Result<identity::CredentialSecurityReceipt, IdentityError> {
        Err(identity_storage_error(
            "unsupported memory security lifecycle",
        ))
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

type InboxMapKey = (String, String, String);
type ClaimMap = HashMap<InboxMapKey, ClaimEntry>;
type SharedClaimMap = Arc<Mutex<ClaimMap>>;

/// in-mem 幂等 claimer（impl [`consistency::InboxStore`]）：以 `(tenant, group, key)` 为复合主键，
/// 记 token-CAS 三态（absent / claimed(token) / done(token)），忠实实现 lease-CAS 围栏语义。
/// demo / 单进程 / 测试用；生产走 redis/pg claimer。
///
/// TTL 重捞有意省略（无时间源）——crash-recovery + 重捞正确性由 PG adapter 集成测试守；
/// in-mem 仅需忠实 token-CAS 语义，使 hard-fence 在 demo/test 中可行使。
///
/// INVARIANT: TOPO-INMEM-SEAL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（拓扑封闭：生产 bin 经 cargo-deny 连 `memory` 都依赖不到 ⇒
/// in-mem claimer 不可达生产；仅 demo/dev/journeys 组合根可构造）。
pub struct InMemClaimer {
    seen: SharedClaimMap,
}

impl InMemClaimer {
    /// 新建空 claimer。
    ///
    /// `pub`：供 dev-root demo 组合根（`journeys` / `examples`）跨 crate 构造（生产 bin 经 cargo-deny 连
    /// `memory` 都依赖不到 ⇒ in-mem 生产不可达，TOPO-INMEM-SEAL-01 主守卫 Hard）。dev root **须**经
    /// `bootstrap::replaydeps::resolve(Topology::Demo, ..)` 决策臂构造、**不**直接 raw-new——把 in-mem 构造
    /// 收束到已校验的拓扑决策（决策绑定纪律 Medium，review #274 F6/C6）；生产走 redis/pg claimer。
    pub fn new() -> Self {
        Self {
            seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemClaimer {
    fn default() -> Self {
        Self::new()
    }
}

fn inbox_map_key(ctx: &InboxReceiptContext, key: &IdemKey) -> InboxMapKey {
    (
        ctx.tenant_id().to_string(),
        ctx.consumer_group().as_str().to_string(),
        key.as_str().to_string(),
    )
}

impl InboxStore for InMemClaimer {
    async fn try_claim(
        &self,
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &IdemLeaseToken,
    ) -> Result<SeenState, EngineError> {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // reason: in-mem 操作恒成功，unwrap_or_else 处理 poisoned lock 后继续。
        let map_key = inbox_map_key(ctx, key);
        match map.entry(map_key) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(ClaimEntry {
                    token: lease.as_str().to_string(),
                    done: false,
                });
                Ok(SeenState::Fresh)
            }
            std::collections::hash_map::Entry::Occupied(e) if e.get().done => {
                // 只有 durable done 才可幂等短路并 Ack。
                Ok(SeenState::Duplicate)
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                // active claimed 必须保留 broker 投递；typed outcome 由 consumer lease-aware 延迟 Requeue。
                // reason: TTL 重捞在此 in-mem demo 替身中有意省略——crash-recovery + 重捞正确性由
                // PG adapter 集成测试守；in-mem 仅需忠实 token-CAS 语义，使 hard-fence 在 demo/test
                // 中可行使。
                Ok(SeenState::InProgress)
            }
        }
    }

    async fn extend(
        &self,
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &IdemLeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        // reason: in-mem 恒 Ok；仅 claimed 且 token 匹配 → Held，否则（absent / done / token 不符）→ Lost。
        let map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let map_key = inbox_map_key(ctx, key);
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
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &IdemLeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        // reason: in-mem commit 恒 Ok；token 匹配 → done(Held)，不符/absent → Lost（hard-fence）。
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let map_key = inbox_map_key(ctx, key);
        match map.get_mut(&map_key) {
            Some(e) if e.token == lease.as_str() => {
                e.done = true;
                Ok(LeaseOutcome::Held)
            }
            _ => Ok(LeaseOutcome::Lost),
        }
    }

    async fn release(
        &self,
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &IdemLeaseToken,
    ) -> Result<(), EngineError> {
        // reason: in-mem release 恒 Ok；仅 token 匹配的 claimed 行删除（CAS），否则 no-op（不误删他人 claim）。
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let map_key = inbox_map_key(ctx, key);
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

// ── MemSagaDurableStore：closed saga durable aggregate ────────────────────────

#[derive(Clone)]
struct MemSagaInstanceState {
    status: SagaInstanceStatus,
    identity: SagaWorkerIdentity,
    definition: consistency::SagaDefinitionIdentity,
    holder_id: Option<String>,
    lease_token: Option<uuid::Uuid>,
    epoch: u64,
    expires_at: Option<SystemTime>,
    operator_reason: Option<SagaOperatorReason>,
    compensation_cause: Option<SagaCompensationCause>,
}

impl MemSagaInstanceState {
    fn record(
        &self,
        instance: SagaInstanceRef,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
        let record = SagaInstanceRecord::new(
            instance,
            self.status,
            self.identity.clone(),
            self.definition.clone(),
        )
        .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        match (self.status, self.operator_reason) {
            (SagaInstanceStatus::OperatorRequired, Some(reason)) => record
                .with_operator_reason(reason)
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error)),
            (SagaInstanceStatus::OperatorRequired, None) => Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("operator-required saga has no reason"),
            )),
            (_, Some(_)) => Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("non-operator saga retains an operator reason"),
            )),
            (_, None) => Ok(record),
        }
    }

    fn lease_is_free(&self, now: SystemTime) -> bool {
        self.lease_token.is_none() || self.expires_at.is_some_and(|expires| expires <= now)
    }

    fn is_runnable(&self, now: SystemTime) -> bool {
        matches!(
            self.status,
            SagaInstanceStatus::Ready
                | SagaInstanceStatus::Running
                | SagaInstanceStatus::Compensating
        ) && self.lease_is_free(now)
    }

    fn lease_matches(&self, lease: &SagaLease, now: SystemTime) -> bool {
        self.lease_token == Some(lease.lease_token())
            && self.epoch == lease.epoch()
            && self.holder_id.as_deref() == Some(lease.holder_id())
            && self.expires_at.is_some_and(|expires| expires > now)
    }
}

type SagaInstanceMap = HashMap<(String, uuid::Uuid), MemSagaInstanceState>;

#[derive(Clone, PartialEq, Eq)]
struct MemSagaJournalEntry {
    seq: u64,
    step_name: vocab::StepName,
    status: SagaJournalStatus,
    attempt: consistency::SagaAttempt,
    effect_key: SagaIdempotencyKey,
    error_summary: Option<&'static str>,
    compensation_cause: Option<consistency::SagaCompensationCause>,
}

impl MemSagaJournalEntry {
    fn new(
        seq: u64,
        step_name: vocab::StepName,
        status: SagaJournalStatus,
        attempt: consistency::SagaAttempt,
        effect_key: SagaIdempotencyKey,
        error_summary: Option<&'static str>,
        compensation_cause: Option<consistency::SagaCompensationCause>,
    ) -> Self {
        Self {
            seq,
            step_name,
            status,
            attempt,
            effect_key,
            error_summary,
            compensation_cause,
        }
    }
}

struct MemSagaReceiptRow {
    scope: SagaReceiptScope,
    attempt: consistency::SagaAttempt,
    format: consistency::SagaReceiptFormatVersion,
    plaintext: zeroize::Zeroizing<Vec<u8>>,
    completed_seq: u64,
}

#[derive(Default)]
struct MemSagaState {
    instances: SagaInstanceMap,
    journal: Vec<(SagaInstanceRef, MemSagaJournalEntry)>,
    receipts: Vec<MemSagaReceiptRow>,
    operator_decisions: Vec<MemSagaOperatorDecision>,
}

// The in-memory adapter persists the complete audit tuple; adapter conformance tests inspect it
// directly because this provider intentionally exposes no production audit-query surface.
#[allow(dead_code)]
struct MemSagaOperatorDecision {
    instance: SagaInstanceRef,
    reason: Option<SagaOperatorReason>,
    reason_text: String,
    decision: &'static str,
    actor: String,
    change_ticket: String,
    start_audit_id: String,
    seq: Option<u64>,
}

/// In-memory implementation of the single closed durable Saga writer boundary.
#[derive(Clone, Default)]
pub struct MemSagaDurableStore {
    inner: Arc<Mutex<MemSagaState>>,
}

impl MemSagaDurableStore {
    /// Construct an empty durable Saga aggregate.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SagaDurableStore for MemSagaDurableStore {
    async fn register(
        &self,
        authorization: diport::SagaStartAuthorization,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
        let instance = registration.instance();
        if authorization.instance() != instance
            || authorization.identity() != registration.identity()
        {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::IdentityConflict,
                MemSagaInvariant("saga start authorization target mismatch"),
            ));
        }
        let key = saga_instance_key(instance);
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = durable.instances.get(&key) {
            if state.identity != *registration.identity()
                || state.definition != *registration.definition()
            {
                return Err(mem_saga_error(
                    SagaDurableStoreErrorKind::IdentityConflict,
                    MemSagaInvariant("saga instance definition identity conflict"),
                ));
            }
            return state.record(instance);
        }
        let state = durable
            .instances
            .entry(key)
            .or_insert_with(|| MemSagaInstanceState {
                status: SagaInstanceStatus::Ready,
                identity: registration.identity().clone(),
                definition: registration.definition().clone(),
                holder_id: None,
                lease_token: None,
                epoch: 0,
                expires_at: None,
                operator_reason: None,
                compensation_cause: None,
            });
        state.record(instance)
    }

    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError> {
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        durable
            .instances
            .get(&saga_instance_key(*instance))
            .map(|state| state.record(*instance))
            .transpose()
    }

    async fn list_runnable(
        &self,
        identity: &SagaWorkerIdentity,
        tenant: vocab::TenantId,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaDurableStoreError> {
        let now = saga_now();
        let tenant_key = tenant.to_string();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut rows = Vec::new();
        for ((row_tenant, saga_id), state) in &durable.instances {
            if row_tenant != &tenant_key || state.identity != *identity || !state.is_runnable(now) {
                continue;
            }
            let instance = SagaInstanceRef::new(tenant, consistency::SagaId::new(*saga_id))
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
            rows.push(
                SagaRunnableInstance::new(
                    instance,
                    state.status,
                    state.identity.clone(),
                    state.definition.clone(),
                )
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?,
            );
        }
        rows.sort_by_key(|row| row.instance().saga_id().as_uuid());
        rows.truncate(limit.get());
        Ok(rows)
    }

    async fn claim(
        &self,
        request: SagaClaimRequest,
    ) -> Result<SagaClaimOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let expires_at = checked_expiry(now, request.ttl().as_duration())?;
        let expected = request.expected();
        let instance = expected.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get_mut(&saga_instance_key(instance)) else {
            return Ok(SagaClaimOutcome::Missing);
        };
        if state.identity != *expected.identity() || state.definition != *expected.definition() {
            return Ok(SagaClaimOutcome::IdentityConflict);
        }
        match state.status {
            SagaInstanceStatus::OperatorRequired => {
                return state
                    .operator_reason
                    .map(SagaClaimOutcome::OperatorRequired)
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("operator-required saga has no reason"),
                        )
                    });
            }
            SagaInstanceStatus::Degraded => return Ok(SagaClaimOutcome::Degraded),
            status @ (SagaInstanceStatus::Succeeded
            | SagaInstanceStatus::Compensated
            | SagaInstanceStatus::Expired
            | SagaInstanceStatus::Terminated) => {
                return Ok(SagaClaimOutcome::Terminal(status));
            }
            SagaInstanceStatus::CompensationFailed => return Ok(SagaClaimOutcome::Degraded),
            _ => {}
        }
        if !state.lease_is_free(now) {
            return Ok(SagaClaimOutcome::Busy);
        }
        if state.status != expected.status() {
            return Ok(SagaClaimOutcome::Stale(state.status));
        }
        let token = uuid::Uuid::new_v4();
        state.epoch = state.epoch.saturating_add(1);
        state.lease_token = Some(token);
        state.holder_id = Some(request.holder_id().to_string());
        state.expires_at = Some(expires_at);
        if state.status == SagaInstanceStatus::Ready {
            state.status = SagaInstanceStatus::Running;
        }
        SagaLease::new(instance, request.holder_id(), token, state.epoch)
            .map(SagaClaimOutcome::Acquired)
            .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))
    }

    async fn renew(
        &self,
        lease: &SagaLease,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let expires_at = checked_expiry(now, ttl.as_duration())?;
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable
            .instances
            .get_mut(&saga_instance_key(lease.instance()))
        else {
            return Ok(SagaLeaseOutcome::Lost);
        };
        if !state.lease_matches(lease, now) {
            return Ok(SagaLeaseOutcome::Lost);
        }
        state.expires_at = Some(expires_at);
        Ok(SagaLeaseOutcome::Held)
    }

    async fn release(&self, lease: &SagaLease) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable
            .instances
            .get_mut(&saga_instance_key(lease.instance()))
        else {
            return Ok(SagaLeaseOutcome::Lost);
        };
        if !state.lease_matches(lease, now) {
            return Ok(SagaLeaseOutcome::Lost);
        }
        clear_saga_lease(state);
        Ok(SagaLeaseOutcome::Held)
    }

    async fn recovery_snapshot(
        &self,
        request: SagaRecoveryRequest,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let (lease, scopes) = request.into_parts();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(lease.instance())) else {
            return Ok(SagaRecoveryOutcome::LeaseLost);
        };
        if !state.lease_matches(&lease, now) {
            return Ok(SagaRecoveryOutcome::LeaseLost);
        }
        let instance = state.record(lease.instance())?;
        let mut journal = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == lease.instance())
            .map(|(_, entry)| {
                SagaJournalRecord::replayed(entry.seq, entry.step_name.clone(), entry.status)
            })
            .collect::<Vec<_>>();
        journal.sort_by_key(SagaJournalRecord::seq);
        let mut receipts = Vec::new();
        for scope in scopes {
            if let Some(row) = durable.receipts.iter().find(|row| row.scope == scope) {
                receipts.push(StoredSagaReceipt::new(
                    row.scope.clone(),
                    row.attempt,
                    row.format,
                    secure::Plaintext::new(row.plaintext.to_vec()),
                    row.completed_seq,
                ));
            }
        }
        Ok(SagaRecoveryOutcome::Available(SagaRecoverySnapshot::new(
            instance,
            journal,
            receipts,
            state.operator_reason,
            state.compensation_cause,
        )))
    }

    async fn terminal_receipt(
        &self,
        request: SagaTerminalReceiptRequest,
    ) -> Result<SagaTerminalReceiptOutcome, SagaDurableStoreError> {
        let scope = request.into_scope();
        let instance = scope.instance();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaTerminalReceiptOutcome::Missing);
        };
        if state.status != SagaInstanceStatus::Succeeded {
            return Ok(SagaTerminalReceiptOutcome::NotSucceeded(state.status));
        }
        let record = state.record(instance)?;
        if record.identity() != scope.worker() || record.definition() != scope.definition() {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("terminal saga receipt identity mismatch"),
            ));
        }
        let mut journal = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == instance)
            .map(|(_, entry)| {
                SagaJournalRecord::replayed(entry.seq, entry.step_name.clone(), entry.status)
            })
            .collect::<Vec<_>>();
        journal.sort_by_key(SagaJournalRecord::seq);
        let Some(last) = journal.last() else {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("succeeded saga has no journal"),
            ));
        };
        let Some(row) = durable.receipts.iter().find(|row| row.scope == scope) else {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("succeeded saga final receipt is missing"),
            ));
        };
        if last.status() != SagaJournalStatus::ForwardCompleted
            || last.seq() != row.completed_seq
            || last.step_name() != scope.step_name()
        {
            return Err(mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("succeeded saga final receipt is not the terminal transition"),
            ));
        }
        let receipt = StoredSagaReceipt::new(
            row.scope.clone(),
            row.attempt,
            row.format,
            secure::Plaintext::new(row.plaintext.to_vec()),
            row.completed_seq,
        );
        Ok(SagaTerminalReceiptOutcome::Verified(Box::new(
            SagaVerifiedTerminalReceipt::new(record, journal, receipt),
        )))
    }

    async fn mutate(
        &self,
        lease: &SagaLease,
        mutation: SagaDurableMutation,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let instance = lease.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !durable
            .instances
            .get(&saga_instance_key(instance))
            .is_some_and(|state| state.lease_matches(lease, now))
        {
            return Ok(SagaDurableMutationOutcome::LeaseLost);
        }
        match mutation {
            SagaDurableMutation::ForwardIntent(intent) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Running
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let entry = MemSagaJournalEntry::new(
                    intent.seq(),
                    intent.step().clone(),
                    SagaJournalStatus::ForwardIntent,
                    intent.attempt(),
                    intent.effect_key().clone(),
                    None,
                    None,
                );
                Ok(insert_mem_intent(&mut durable, instance, entry))
            }
            SagaDurableMutation::ForwardCompleted(completed) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Running
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let progress = completed.progress();
                let (completion, _) = completed.into_parts();
                let (scope, attempt, format, plaintext, completed_seq) = completion.into_parts();
                if scope.instance() != instance {
                    return Err(mem_saga_error(
                        SagaDurableStoreErrorKind::Integrity,
                        MemSagaInvariant("memory saga receipt lease scope mismatch"),
                    ));
                }
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    completed_seq,
                    scope.step_name(),
                    SagaJournalStatus::ForwardIntent,
                    attempt,
                    scope.effect_key(),
                    None,
                ) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let plaintext = zeroize::Zeroizing::new(plaintext.expose().to_vec());
                let journal_entry = MemSagaJournalEntry::new(
                    completed_seq,
                    scope.step_name().clone(),
                    SagaJournalStatus::ForwardCompleted,
                    attempt,
                    scope.effect_key().clone(),
                    None,
                    None,
                );
                let journal_match = durable
                    .journal
                    .iter()
                    .find(|(stored, row)| *stored == instance && row.seq == completed_seq)
                    .map(|(_, row)| row == &journal_entry);
                let receipt_match =
                    durable
                        .receipts
                        .iter()
                        .find(|row| row.scope == scope)
                        .map(|row| {
                            row.attempt == attempt
                                && row.format == format
                                && row.completed_seq == completed_seq
                                && primitives::constant_time_eq(&row.plaintext, &plaintext)
                        });
                if journal_match == Some(true) && receipt_match == Some(true) {
                    return Ok(if progress == SagaForwardProgress::Continue {
                        SagaDurableMutationOutcome::IdempotentDuplicate
                    } else {
                        SagaDurableMutationOutcome::Conflict
                    });
                }
                if journal_match.is_some() || receipt_match.is_some() {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                if durable.receipts.iter().any(|row| {
                    row.scope.instance().tenant() == scope.instance().tenant()
                        && primitives::constant_time_eq(
                            row.scope.effect_key().as_bytes(),
                            scope.effect_key().as_bytes(),
                        )
                }) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                durable.journal.push((instance, journal_entry));
                durable.receipts.push(MemSagaReceiptRow {
                    scope,
                    attempt,
                    format,
                    plaintext,
                    completed_seq,
                });
                if progress == SagaForwardProgress::Succeeded {
                    let state = durable
                        .instances
                        .get_mut(&saga_instance_key(instance))
                        .ok_or_else(|| {
                            mem_saga_error(
                                SagaDurableStoreErrorKind::Integrity,
                                MemSagaInvariant("memory saga instance disappeared"),
                            )
                        })?;
                    state.status = SagaInstanceStatus::Succeeded;
                    clear_saga_lease(state);
                }
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::CompensationIntent(intent) => {
                let state = durable
                    .instances
                    .get(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                if !matches!(
                    state.status,
                    SagaInstanceStatus::Running | SagaInstanceStatus::Compensating
                ) || state
                    .compensation_cause
                    .is_some_and(|cause| cause != intent.cause())
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let entry = MemSagaJournalEntry::new(
                    intent.seq(),
                    intent.step().clone(),
                    SagaJournalStatus::CompensationIntent,
                    intent.attempt(),
                    intent.effect_key().clone(),
                    None,
                    Some(intent.cause()),
                );
                let outcome = insert_mem_intent(&mut durable, instance, entry);
                if outcome == SagaDurableMutationOutcome::Conflict {
                    return Ok(outcome);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Compensating;
                state.compensation_cause = Some(intent.cause());
                Ok(outcome)
            }
            SagaDurableMutation::CompensationCompleted(completed) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Compensating
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let cause = durable.instances[&saga_instance_key(instance)].compensation_cause;
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    completed.seq(),
                    completed.step(),
                    SagaJournalStatus::CompensationIntent,
                    completed.attempt(),
                    completed.effect_key(),
                    cause,
                ) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let progress = completed.progress();
                let entry = MemSagaJournalEntry::new(
                    completed.seq(),
                    completed.step().clone(),
                    SagaJournalStatus::CompensationCompleted,
                    completed.attempt(),
                    completed.effect_key().clone(),
                    None,
                    None,
                );
                let outcome = insert_mem_journal(&mut durable, instance, entry);
                if outcome != SagaDurableMutationOutcome::Applied {
                    return Ok(
                        if outcome == SagaDurableMutationOutcome::IdempotentDuplicate
                            && progress != SagaCompensationProgress::Continue
                        {
                            SagaDurableMutationOutcome::Conflict
                        } else {
                            outcome
                        },
                    );
                }
                if progress != SagaCompensationProgress::Continue {
                    let state = durable
                        .instances
                        .get_mut(&saga_instance_key(instance))
                        .ok_or_else(|| {
                            mem_saga_error(
                                SagaDurableStoreErrorKind::Integrity,
                                MemSagaInvariant("memory saga instance disappeared"),
                            )
                        })?;
                    state.status = match progress {
                        SagaCompensationProgress::Continue => SagaInstanceStatus::Compensating,
                        SagaCompensationProgress::Compensated => SagaInstanceStatus::Compensated,
                        SagaCompensationProgress::Expired => SagaInstanceStatus::Expired,
                        _ => return Ok(SagaDurableMutationOutcome::Conflict),
                    };
                    clear_saga_lease(state);
                }
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::CompensationFailed(failure) => {
                if durable.instances[&saga_instance_key(instance)].status
                    != SagaInstanceStatus::Compensating
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let cause = durable.instances[&saga_instance_key(instance)].compensation_cause;
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    failure.seq(),
                    failure.step(),
                    SagaJournalStatus::CompensationIntent,
                    failure.attempt(),
                    failure.effect_key(),
                    cause,
                ) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                let entry = MemSagaJournalEntry::new(
                    failure.seq(),
                    failure.step().clone(),
                    SagaJournalStatus::CompensationFailed,
                    failure.attempt(),
                    failure.effect_key().clone(),
                    Some(failure.error_summary()),
                    None,
                );
                let outcome = insert_mem_journal(&mut durable, instance, entry);
                if outcome != SagaDurableMutationOutcome::Applied {
                    return Ok(outcome);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::CompensationFailed;
                clear_saga_lease(state);
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::OperatorRequired(reason) => {
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                if reason.preserves_compensation_cause()
                    && (state.status != SagaInstanceStatus::Compensating
                        || state.compensation_cause.is_none())
                {
                    return Ok(SagaDurableMutationOutcome::Conflict);
                }
                state.status = SagaInstanceStatus::OperatorRequired;
                state.operator_reason = Some(reason);
                if !reason.preserves_compensation_cause() {
                    state.compensation_cause = None;
                }
                clear_saga_lease(state);
                Ok(SagaDurableMutationOutcome::Applied)
            }
            SagaDurableMutation::Degraded => {
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Degraded;
                state.operator_reason = None;
                state.compensation_cause = None;
                clear_saga_lease(state);
                Ok(SagaDurableMutationOutcome::Applied)
            }
            _ => Ok(SagaDurableMutationOutcome::Conflict),
        }
    }

    async fn shutdown(&self) -> Result<(), SagaDurableStoreError> {
        Ok(())
    }
}

/// Move-only operator claim minted exclusively by [`MemSagaDurableStore`].
pub struct MemSagaOperatorClaim {
    lease: SagaLease,
    authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
}

impl SagaOperatorRepairClaim for MemSagaOperatorClaim {
    fn instance(&self) -> SagaInstanceRef {
        self.authorization.instance()
    }

    fn expected_reason(&self) -> SagaOperatorRepairReason {
        self.authorization.evidence().reason()
    }
}

impl SagaOperatorStore for MemSagaDurableStore {
    type RepairClaim = MemSagaOperatorClaim;

    async fn operator_status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> Result<SagaOperatorStatusOutcome, SagaDurableStoreError> {
        let instance = authorization.instance();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorStatusOutcome::Missing);
        };
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorStatusOutcome::IdentityConflict);
        }
        let latest = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == instance)
            .map(|(_, entry)| entry)
            .max_by_key(|entry| entry.seq)
            .map(|entry| {
                SagaOperatorJournalExpectation::new(
                    SagaJournalRecord::replayed(entry.seq, entry.step_name.clone(), entry.status),
                    entry.attempt,
                    entry.effect_key.clone(),
                )
                .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))
            })
            .transpose()?;
        let has_effect_intent = durable.journal.iter().any(|(stored, entry)| {
            *stored == instance
                && matches!(
                    entry.status,
                    SagaJournalStatus::ForwardIntent | SagaJournalStatus::CompensationIntent
                )
        });
        Ok(SagaOperatorStatusOutcome::Found(Box::new(
            SagaOperatorStatusSnapshot::new(
                state.record(instance)?,
                latest,
                has_effect_intent,
                None,
            ),
        )))
    }

    async fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let instance = authorization.instance();
        let expected = authorization.evidence().journal();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorCasOutcome::Missing);
        };
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorCasOutcome::IdentityConflict);
        }
        if state.status != SagaInstanceStatus::CompensationFailed {
            return Ok(SagaOperatorCasOutcome::StaleStatus(state.status));
        }
        if !state.lease_is_free(now) {
            return Ok(SagaOperatorCasOutcome::Busy);
        }
        let latest = durable
            .journal
            .iter()
            .filter(|(stored, _)| *stored == instance)
            .map(|(_, entry)| entry)
            .max_by_key(|entry| entry.seq);
        if !latest.is_some_and(|entry| {
            entry.seq == expected.record().seq()
                && entry.step_name == *expected.record().step_name()
                && entry.status == expected.record().status()
                && entry.attempt == expected.attempt()
                && entry.effect_key == *expected.effect_key()
        }) {
            return Ok(SagaOperatorCasOutcome::StaleJournal);
        }
        let state = durable
            .instances
            .get_mut(&saga_instance_key(instance))
            .ok_or_else(|| {
                mem_saga_error(
                    SagaDurableStoreErrorKind::Integrity,
                    MemSagaInvariant("memory saga instance disappeared"),
                )
            })?;
        state.status = SagaInstanceStatus::Compensating;
        state.operator_reason = None;
        clear_saga_lease(state);
        durable.operator_decisions.push(MemSagaOperatorDecision {
            instance,
            reason: None,
            reason_text: authorization.evidence().reason_text().as_str().to_owned(),
            decision: "retry_compensation",
            actor: authorization.caller().as_str().to_owned(),
            change_ticket: authorization.evidence().change_ticket().as_str().to_owned(),
            start_audit_id: authorization.start_audit_id().as_str().to_owned(),
            seq: Some(expected.record().seq()),
        });
        Ok(SagaOperatorCasOutcome::Applied)
    }

    async fn claim_repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
        holder: SagaLeaseHolder,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaOperatorClaimOutcome<Self::RepairClaim>, SagaDurableStoreError> {
        let now = saga_now();
        let expires_at = checked_expiry(now, ttl.as_duration())?;
        let instance = authorization.instance();
        let holder_id = holder.as_str().to_string();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get_mut(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorClaimOutcome::Missing);
        };
        if state.status != SagaInstanceStatus::OperatorRequired {
            return Ok(SagaOperatorClaimOutcome::StaleStatus(state.status));
        }
        let reason = state.operator_reason.ok_or_else(|| {
            mem_saga_error(
                SagaDurableStoreErrorKind::Integrity,
                MemSagaInvariant("operator-required saga has no reason"),
            )
        })?;
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorClaimOutcome::StaleReason(reason));
        }
        if reason != authorization.evidence().reason().as_operator_reason() {
            return Ok(SagaOperatorClaimOutcome::StaleReason(reason));
        }
        if !state.lease_is_free(now) {
            return Ok(SagaOperatorClaimOutcome::Busy);
        }
        let token = uuid::Uuid::new_v4();
        state.epoch = state.epoch.saturating_add(1);
        state.lease_token = Some(token);
        state.holder_id = Some(holder_id.clone());
        state.expires_at = Some(expires_at);
        let lease = SagaLease::new(instance, holder_id, token, state.epoch)
            .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        Ok(SagaOperatorClaimOutcome::Acquired(MemSagaOperatorClaim {
            lease,
            authorization,
        }))
    }

    async fn repair_snapshot(
        &self,
        claim: &Self::RepairClaim,
        scopes: Vec<SagaReceiptScope>,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let request = SagaRecoveryRequest::new(claim.lease.clone(), scopes)
            .map_err(|error| mem_saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        SagaDurableStore::recovery_snapshot(self, request).await
    }

    async fn release_repair(
        &self,
        claim: Self::RepairClaim,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        SagaDurableStore::release(self, &claim.lease).await
    }

    async fn commit_repair(
        &self,
        operator: Self::RepairClaim,
        decision: SagaOperatorRepair,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let lease = &operator.lease;
        let instance = lease.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorCasOutcome::LeaseLost);
        };
        if !state.lease_matches(lease, now)
            || state.status != SagaInstanceStatus::OperatorRequired
            || state.operator_reason != Some(operator.expected_reason().as_operator_reason())
            || state.identity != *operator.authorization.identity()
        {
            return Ok(SagaOperatorCasOutcome::LeaseLost);
        }
        let reason = operator.expected_reason().as_operator_reason();
        let actor = operator.authorization.caller().as_str().to_owned();
        let reason_text = operator
            .authorization
            .evidence()
            .reason_text()
            .as_str()
            .to_owned();
        let ticket = operator
            .authorization
            .evidence()
            .change_ticket()
            .as_str()
            .to_owned();
        let start_audit_id = operator.authorization.start_audit_id().as_str().to_owned();
        let (outcome, label, seq) = match decision {
            SagaOperatorRepair::ForwardApplied(completed) => {
                if !matches!(
                    reason,
                    SagaOperatorReason::ForwardOutcomeUnknown
                        | SagaOperatorReason::CompletionCommitUnknown
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                let progress = completed.progress();
                let (completion, _) = completed.into_parts();
                let (scope, attempt, format, plaintext, completed_seq) = completion.into_parts();
                if scope.instance() != instance
                    || !has_exact_prior_mem_intent(
                        &durable,
                        instance,
                        completed_seq,
                        scope.step_name(),
                        SagaJournalStatus::ForwardIntent,
                        attempt,
                        scope.effect_key(),
                        None,
                    )
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let entry = MemSagaJournalEntry::new(
                    completed_seq,
                    scope.step_name().clone(),
                    SagaJournalStatus::ForwardCompleted,
                    attempt,
                    scope.effect_key().clone(),
                    None,
                    None,
                );
                let journal_conflict = durable
                    .journal
                    .iter()
                    .any(|(stored, row)| *stored == instance && row.seq == completed_seq);
                let receipt_conflict = durable.receipts.iter().any(|row| {
                    row.scope == scope
                        || (row.scope.instance().tenant() == scope.instance().tenant()
                            && primitives::constant_time_eq(
                                row.scope.effect_key().as_bytes(),
                                scope.effect_key().as_bytes(),
                            ))
                });
                if journal_conflict || receipt_conflict {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                durable.journal.push((instance, entry));
                durable.receipts.push(MemSagaReceiptRow {
                    scope,
                    attempt,
                    format,
                    plaintext: zeroize::Zeroizing::new(plaintext.expose().to_vec()),
                    completed_seq,
                });
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = if progress == SagaForwardProgress::Succeeded {
                    SagaInstanceStatus::Succeeded
                } else {
                    SagaInstanceStatus::Running
                };
                state.operator_reason = None;
                clear_saga_lease(state);
                (
                    SagaOperatorCasOutcome::Applied,
                    "confirmed_applied",
                    completed_seq,
                )
            }
            SagaOperatorRepair::ForwardNotApplied(not_applied) => {
                if !matches!(
                    reason,
                    SagaOperatorReason::ForwardOutcomeUnknown
                        | SagaOperatorReason::CompletionCommitUnknown
                ) || !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    not_applied.seq(),
                    not_applied.step(),
                    SagaJournalStatus::ForwardIntent,
                    not_applied.attempt(),
                    not_applied.effect_key(),
                    None,
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let seq = not_applied.seq();
                let entry = MemSagaJournalEntry::new(
                    seq,
                    not_applied.step().clone(),
                    SagaJournalStatus::ForwardNotApplied,
                    not_applied.attempt(),
                    not_applied.effect_key().clone(),
                    None,
                    None,
                );
                if insert_mem_journal(&mut durable, instance, entry)
                    != SagaDurableMutationOutcome::Applied
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Running;
                state.operator_reason = None;
                clear_saga_lease(state);
                (
                    SagaOperatorCasOutcome::Applied,
                    "confirmed_not_applied",
                    seq,
                )
            }
            SagaOperatorRepair::CompensationApplied(completed) => {
                if reason != SagaOperatorReason::CompensationOutcomeUnknown {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                let cause = durable.instances[&saga_instance_key(instance)].compensation_cause;
                if !has_exact_prior_mem_intent(
                    &durable,
                    instance,
                    completed.seq(),
                    completed.step(),
                    SagaJournalStatus::CompensationIntent,
                    completed.attempt(),
                    completed.effect_key(),
                    cause,
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let seq = completed.seq();
                let progress = completed.progress();
                let target_status = match progress {
                    SagaCompensationProgress::Continue => SagaInstanceStatus::Compensating,
                    SagaCompensationProgress::Compensated => SagaInstanceStatus::Compensated,
                    SagaCompensationProgress::Expired => SagaInstanceStatus::Expired,
                    _ => return Ok(SagaOperatorCasOutcome::StaleJournal),
                };
                let entry = MemSagaJournalEntry::new(
                    seq,
                    completed.step().clone(),
                    SagaJournalStatus::CompensationCompleted,
                    completed.attempt(),
                    completed.effect_key().clone(),
                    None,
                    None,
                );
                if insert_mem_journal(&mut durable, instance, entry)
                    != SagaDurableMutationOutcome::Applied
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = target_status;
                state.operator_reason = None;
                clear_saga_lease(state);
                (SagaOperatorCasOutcome::Applied, "confirmed_applied", seq)
            }
            SagaOperatorRepair::CompensationNotApplied(not_applied) => {
                if reason != SagaOperatorReason::CompensationOutcomeUnknown
                    || durable.instances[&saga_instance_key(instance)].compensation_cause
                        != Some(not_applied.cause())
                    || !has_exact_prior_mem_intent(
                        &durable,
                        instance,
                        not_applied.seq(),
                        not_applied.step(),
                        SagaJournalStatus::CompensationIntent,
                        not_applied.attempt(),
                        not_applied.effect_key(),
                        Some(not_applied.cause()),
                    )
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let seq = not_applied.seq();
                let entry = MemSagaJournalEntry::new(
                    seq,
                    not_applied.step().clone(),
                    SagaJournalStatus::CompensationNotApplied,
                    not_applied.attempt(),
                    not_applied.effect_key().clone(),
                    None,
                    Some(not_applied.cause()),
                );
                if insert_mem_journal(&mut durable, instance, entry)
                    != SagaDurableMutationOutcome::Applied
                {
                    return Ok(SagaOperatorCasOutcome::StaleJournal);
                }
                let state = durable
                    .instances
                    .get_mut(&saga_instance_key(instance))
                    .ok_or_else(|| {
                        mem_saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            MemSagaInvariant("memory saga instance disappeared"),
                        )
                    })?;
                state.status = SagaInstanceStatus::Compensating;
                state.operator_reason = None;
                clear_saga_lease(state);
                (
                    SagaOperatorCasOutcome::Applied,
                    "confirmed_not_applied",
                    seq,
                )
            }
            _ => return Ok(SagaOperatorCasOutcome::StaleJournal),
        };
        durable.operator_decisions.push(MemSagaOperatorDecision {
            instance,
            reason: Some(reason),
            reason_text,
            decision: label,
            actor,
            change_ticket: ticket,
            start_audit_id,
            seq: Some(seq),
        });
        Ok(outcome)
    }
}

impl MemSagaDurableStore {
    /// Apply the in-memory control-plane termination used by tests and local tooling.
    pub async fn terminate(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Terminate>,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let now = saga_now();
        let instance = authorization.instance();
        let mut durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = durable.instances.get(&saga_instance_key(instance)) else {
            return Ok(SagaOperatorCasOutcome::Missing);
        };
        if state.identity != *authorization.identity() {
            return Ok(SagaOperatorCasOutcome::IdentityConflict);
        }
        if state.status != SagaInstanceStatus::Ready {
            return Ok(SagaOperatorCasOutcome::StaleStatus(state.status));
        }
        if !state.lease_is_free(now) {
            return Ok(SagaOperatorCasOutcome::Busy);
        }
        if durable.journal.iter().any(|(stored, entry)| {
            *stored == instance
                && matches!(
                    entry.status,
                    SagaJournalStatus::ForwardIntent | SagaJournalStatus::CompensationIntent
                )
        }) {
            return Ok(SagaOperatorCasOutcome::EffectAlreadyStarted);
        }
        let state = durable
            .instances
            .get_mut(&saga_instance_key(instance))
            .ok_or_else(|| {
                mem_saga_error(
                    SagaDurableStoreErrorKind::Integrity,
                    MemSagaInvariant("memory saga instance disappeared"),
                )
            })?;
        state.status = SagaInstanceStatus::Terminated;
        state.operator_reason = None;
        state.compensation_cause = None;
        clear_saga_lease(state);
        durable.operator_decisions.push(MemSagaOperatorDecision {
            instance,
            reason: None,
            reason_text: authorization.evidence().reason_text().as_str().to_owned(),
            decision: "terminate",
            actor: authorization.caller().as_str().to_owned(),
            change_ticket: authorization.evidence().change_ticket().as_str().to_owned(),
            start_audit_id: authorization.start_audit_id().as_str().to_owned(),
            seq: None,
        });
        Ok(SagaOperatorCasOutcome::Applied)
    }
}

impl SagaTenantSource for MemSagaDurableStore {
    async fn list_runnable_tenants(
        &self,
        identity: &SagaWorkerIdentity,
        cursor: Option<SagaTenantCursor>,
        limit: NonZeroUsize,
    ) -> Result<SagaTenantPage, SagaDurableStoreError> {
        let now = saga_now();
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut seen = HashSet::new();
        let mut tenants = Vec::new();
        for ((tenant, _), state) in &durable.instances {
            if state.identity != *identity
                || !state.is_runnable(now)
                || !seen.insert(tenant.clone())
            {
                continue;
            }
            tenants
                .push(vocab::TenantId::parse(tenant).map_err(|error| {
                    mem_saga_error(SagaDurableStoreErrorKind::Integrity, error)
                })?);
        }
        tenants.sort_by_key(|tenant| tenant.to_string());
        if let Some(cursor) = cursor {
            let after = cursor.tenant().to_string();
            tenants.retain(|tenant| tenant.to_string() > after);
        }
        let has_more = tenants.len() > limit.get();
        tenants.truncate(limit.get());
        let next = has_more
            .then(|| tenants.last().copied().map(SagaTenantCursor::new))
            .flatten();
        Ok(SagaTenantPage::new(tenants, next))
    }

    async fn observe_unresolved(
        &self,
        identity: &SagaWorkerIdentity,
    ) -> Result<SagaUnresolvedObservation, SagaDurableStoreError> {
        let durable = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut operator_required = 0;
        let mut degraded = 0;
        let mut compensation_failed = 0;
        for state in durable
            .instances
            .values()
            .filter(|state| state.identity == *identity)
        {
            match state.status {
                SagaInstanceStatus::OperatorRequired => operator_required += 1,
                SagaInstanceStatus::Degraded => degraded += 1,
                SagaInstanceStatus::CompensationFailed => compensation_failed += 1,
                _ => {}
            }
        }
        let present = operator_required + degraded + compensation_failed > 0;
        Ok(SagaUnresolvedObservation::new(
            operator_required,
            degraded,
            compensation_failed,
            present.then(saga_now),
        ))
    }
}

fn saga_instance_key(instance: SagaInstanceRef) -> (String, uuid::Uuid) {
    (instance.tenant().to_string(), instance.saga_id().as_uuid())
}

fn checked_expiry(now: SystemTime, ttl: Duration) -> Result<SystemTime, SagaDurableStoreError> {
    if ttl.is_zero() {
        return Err(mem_saga_error(
            SagaDurableStoreErrorKind::Integrity,
            MemSagaInvariant("saga lease ttl is zero"),
        ));
    }
    now.checked_add(ttl).ok_or_else(|| {
        mem_saga_error(
            SagaDurableStoreErrorKind::Integrity,
            MemSagaInvariant("saga lease ttl overflow"),
        )
    })
}

fn saga_now() -> SystemTime {
    // reason: memory saga store owns an ephemeral process-local lease clock; durable PG uses DB/CAS.
    #[allow(clippy::disallowed_methods)]
    {
        SystemTime::now()
    }
}

#[derive(Debug)]
struct MemSagaInvariant(&'static str);

impl std::fmt::Display for MemSagaInvariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl Error for MemSagaInvariant {}

fn clear_saga_lease(state: &mut MemSagaInstanceState) {
    state.lease_token = None;
    state.holder_id = None;
    state.expires_at = None;
}

fn insert_mem_journal(
    durable: &mut MemSagaState,
    instance: SagaInstanceRef,
    entry: MemSagaJournalEntry,
) -> SagaDurableMutationOutcome {
    if let Some((_, existing)) = durable
        .journal
        .iter()
        .find(|(stored, row)| *stored == instance && row.seq == entry.seq)
    {
        return if existing == &entry {
            SagaDurableMutationOutcome::IdempotentDuplicate
        } else {
            SagaDurableMutationOutcome::Conflict
        };
    }
    durable.journal.push((instance, entry));
    SagaDurableMutationOutcome::Applied
}

fn insert_mem_intent(
    durable: &mut MemSagaState,
    instance: SagaInstanceRef,
    entry: MemSagaJournalEntry,
) -> SagaDurableMutationOutcome {
    if let Some((_, existing)) = durable
        .journal
        .iter()
        .find(|(stored, row)| *stored == instance && row.seq == entry.seq)
    {
        return if existing == &entry {
            SagaDurableMutationOutcome::IdempotentDuplicate
        } else {
            SagaDurableMutationOutcome::Conflict
        };
    }
    let prior_attempts = durable
        .journal
        .iter()
        .filter(|(stored, row)| {
            *stored == instance
                && row.seq < entry.seq
                && row.step_name == entry.step_name
                && row.status == entry.status
        })
        .count();
    let attempt_already_used = durable.journal.iter().any(|(stored, row)| {
        *stored == instance
            && row.step_name == entry.step_name
            && row.status == entry.status
            && row.attempt == entry.attempt
    });
    if attempt_already_used
        || usize::try_from(entry.attempt.get()).ok() != prior_attempts.checked_add(1)
    {
        return SagaDurableMutationOutcome::Conflict;
    }
    durable.journal.push((instance, entry));
    SagaDurableMutationOutcome::Applied
}

#[allow(clippy::too_many_arguments)]
fn has_exact_prior_mem_intent(
    durable: &MemSagaState,
    instance: SagaInstanceRef,
    before_seq: u64,
    step: &vocab::StepName,
    status: SagaJournalStatus,
    attempt: consistency::SagaAttempt,
    effect_key: &SagaIdempotencyKey,
    compensation_cause: Option<consistency::SagaCompensationCause>,
) -> bool {
    compensation_cause.is_some() == (status == SagaJournalStatus::CompensationIntent)
        && durable.journal.iter().any(|(stored, row)| {
            *stored == instance
                && row.seq.checked_add(1) == Some(before_seq)
                && row.step_name == *step
                && row.status == status
                && row.attempt == attempt
                && primitives::constant_time_eq(row.effect_key.as_bytes(), effect_key.as_bytes())
                && row.compensation_cause == compensation_cause
        })
}

fn mem_saga_error<E>(kind: SagaDurableStoreErrorKind, error: E) -> SagaDurableStoreError
where
    E: Error + Send + Sync + 'static,
{
    SagaDurableStoreError::new(kind, error)
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
    use authn::AuthnEpoch;
    use diport::{AuditOutcome, SagaStepCompletion};
    use identity::ports::RefreshTokenSnapshot;
    use vocab::TenantId;

    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000abc";
    const TOPIC: &str = "identity.session-created";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn login_receipt() -> identity::ports::LoginProducerReceipt {
        identity::test_support::login_producer_receipt()
    }

    fn test_grant(id: &str, tenant: TenantId) -> AuthGrant {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        identity::test_support::auth_grant(
            id,
            identity::test_support::user_id("11111111-2222-4333-8444-555555555555"),
            tenant,
            now,
            AuthnEpoch::ZERO,
            now + Duration::from_secs(3_600),
            now,
        )
    }

    #[allow(clippy::expect_used)]
    fn initial_refresh(grant: &AuthGrant, id: &str, hash: [u8; 32]) -> RefreshTokenRecord {
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let id = RefreshTokenId::hydrate(id);
        RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
            id: id.clone(),
            tenant: grant.tenant(),
            auth_grant_id: grant.id().clone(),
            user_id: grant.user_id(),
            authn_epoch_at_issue: grant.authn_epoch_at_issue(),
            auth_grant_status: AuthGrantStatus::Active,
            token_hash: RefreshTokenHash::hydrate(hash),
            parent_id: None,
            lineage_id: id,
            status: RefreshStatus::Active,
            issued_at: issued,
            expires_at: issued + Duration::from_secs(3_600),
        })
        .expect("valid initial refresh")
    }

    async fn session_created_event(id: &str, grant: &AuthGrant) -> eventexec::event::ReviewedEvent {
        identity::test_support::session_created_event(id, grant).await
    }

    fn login_grant_mutation(grant: AuthGrant, refresh: RefreshTokenRecord) -> LoginGrantMutation {
        LoginGrantMutation::for_test(grant, refresh)
    }

    #[allow(clippy::unwrap_used)]
    fn saga_identity(contract_id: &str) -> SagaWorkerIdentity {
        SagaWorkerIdentity::new(
            "billing",
            diport::SagaContractId::parse(contract_id).unwrap(),
        )
        .unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn saga_registration(instance: SagaInstanceRef, contract_id: &str) -> SagaInstanceRegistration {
        let definition = consistency::SagaDefinitionIdentity::new(
            contract_id,
            "v1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        SagaInstanceRegistration::new(instance, saga_identity(contract_id), definition).unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn saga_start_authorization(
        instance: SagaInstanceRef,
        contract_id: &str,
    ) -> diport::SagaStartAuthorization {
        diport::test_support::saga_start_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            saga_identity(contract_id),
            instance,
            diport::SagaStartAuditId::parse("memory-saga-start").unwrap(),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn saga_claim_request(candidate: SagaRunnableInstance, holder: &str) -> SagaClaimRequest {
        SagaClaimRequest::new(
            candidate,
            diport::SagaLeaseHolder::parse(holder).unwrap(),
            diport::SagaLeaseTtl::new(Duration::from_secs(30)).unwrap(),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn saga_operator_authorization(
        instance: SagaInstanceRef,
        reason: SagaOperatorReason,
        ticket: &str,
    ) -> SagaOperatorAuthorization<saga_operator_action::Repair> {
        let reason = SagaOperatorRepairReason::try_from(reason).unwrap();
        diport::test_support::saga_operator_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            saga_identity("billing.checkout"),
            instance,
            diport::SagaOperatorRepairExpectation::new(
                reason,
                diport::SagaOperatorReasonText::parse("provider evidence reviewed").unwrap(),
                diport::SagaOperatorChangeTicket::parse(ticket).unwrap(),
            ),
            diport::SagaOperatorStartAuditId::parse(format!("audit-{ticket}")).unwrap(),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn saga_operator_status_authorization(
        instance: SagaInstanceRef,
    ) -> SagaOperatorAuthorization<saga_operator_action::Status> {
        diport::test_support::saga_operator_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            saga_identity("billing.checkout"),
            instance,
            (),
            diport::SagaOperatorStartAuditId::parse("audit-status").unwrap(),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn saga_retry_compensation_authorization(
        instance: SagaInstanceRef,
        journal: SagaOperatorJournalExpectation,
        ticket: &str,
    ) -> SagaOperatorAuthorization<saga_operator_action::RetryCompensation> {
        let evidence = diport::SagaRetryCompensationExpectation::new(
            journal,
            diport::SagaOperatorReasonText::parse("dependency restored").unwrap(),
            diport::SagaOperatorChangeTicket::parse(ticket).unwrap(),
        )
        .unwrap();
        diport::test_support::saga_operator_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            saga_identity("billing.checkout"),
            instance,
            evidence,
            diport::SagaOperatorStartAuditId::parse(format!("audit-{ticket}")).unwrap(),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn saga_terminate_authorization(
        instance: SagaInstanceRef,
        ticket: &str,
    ) -> SagaOperatorAuthorization<saga_operator_action::Terminate> {
        diport::test_support::saga_operator_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            saga_identity("billing.checkout"),
            instance,
            diport::SagaTerminateExpectation::new(
                diport::SagaOperatorReasonText::parse("request withdrawn").unwrap(),
                diport::SagaOperatorChangeTicket::parse(ticket).unwrap(),
            ),
            diport::SagaOperatorStartAuditId::parse(format!("audit-{ticket}")).unwrap(),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn saga_operator_holder() -> SagaLeaseHolder {
        SagaLeaseHolder::parse("maintenance-runner").unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn saga_operator_ttl() -> SagaLeaseTtl {
        SagaLeaseTtl::new(Duration::from_secs(30)).unwrap()
    }

    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn saga_durable_fixture(
        saga_id: u128,
    ) -> (MemSagaDurableStore, SagaLease, SagaReceiptScope) {
        use consistency::{SagaDefinitionIdentity, SagaEffectPhase, SagaId, SagaIdempotencyKey};

        let store = MemSagaDurableStore::new();
        let tenant = vocab::TenantId::parse(CANON_TENANT).unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(saga_id))).unwrap();
        let definition = SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC);
        let identity = saga_identity("billing.checkout");
        store
            .register(
                saga_start_authorization(instance, "billing.checkout"),
                SagaInstanceRegistration::new(instance, identity.clone(), definition.clone())
                    .unwrap(),
            )
            .await
            .unwrap();
        let candidate = SagaRunnableInstance::new(
            instance,
            SagaInstanceStatus::Ready,
            identity.clone(),
            definition.clone(),
        )
        .unwrap();
        let lease = store
            .claim(saga_claim_request(candidate, "runner"))
            .await
            .unwrap();
        let SagaClaimOutcome::Acquired(lease) = lease else {
            panic!("fixture claim was not acquired")
        };
        let step = generated::saga::billing_v1::STEP_0;
        let scope = SagaReceiptScope::new(
            instance,
            identity,
            definition.clone(),
            step,
            SagaIdempotencyKey::derive(instance, &definition, step, SagaEffectPhase::Forward),
        )
        .unwrap();
        (store, lease, scope)
    }

    #[allow(clippy::unwrap_used)]
    fn saga_completion(scope: &SagaReceiptScope, body: &[u8]) -> SagaStepCompletion {
        SagaStepCompletion::new(
            scope.clone(),
            consistency::SagaAttempt::new(1).unwrap(),
            consistency::SagaReceiptFormatVersion::V1,
            secure::Plaintext::new(body.to_vec()),
            1,
        )
    }

    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn saga_compensating_fixture(
        saga_id: u128,
    ) -> (
        MemSagaDurableStore,
        SagaLease,
        consistency::SagaDefinitionIdentity,
        consistency::SagaIdempotencyKey,
    ) {
        let (store, lease, scope) = saga_durable_fixture(saga_id).await;
        let forward_attempt = consistency::SagaAttempt::new(1).unwrap();
        let forward_intent = diport::SagaForwardIntent::new(
            0,
            scope.step_name().clone(),
            forward_attempt,
            scope.effect_key().clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardIntent(forward_intent),)
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        assert_eq!(
            store
                .mutate(
                    &lease,
                    SagaDurableMutation::ForwardCompleted(diport::SagaForwardCompletion::new(
                        saga_completion(&scope, br#"{"ok":true}"#),
                        SagaForwardProgress::Continue,
                    )),
                )
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let definition =
            consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC);
        let step = generated::saga::billing_v1::STEP_0;
        let compensation_key = consistency::SagaIdempotencyKey::derive(
            scope.instance(),
            &definition,
            step,
            consistency::SagaEffectPhase::Compensation,
        );
        let compensation_intent = diport::SagaCompensationIntent::new(
            2,
            scope.step_name().clone(),
            consistency::SagaAttempt::new(1).unwrap(),
            compensation_key.clone(),
            consistency::SagaCompensationCause::BusinessFailure,
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(
                    &lease,
                    SagaDurableMutation::CompensationIntent(compensation_intent),
                )
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        (store, lease, definition, compensation_key)
    }

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
        let entry = EventEntry::new(
            EventTopic::parse(TOPIC).expect("topic"),
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
        let entry = EventEntry::new(
            EventTopic::parse(TOPIC).expect("topic"),
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
    async fn mem_auth_grant_store_persists_refresh_and_emits_tenant_metadata() {
        let bus = MemBus::new();
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let grant = test_grant("7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8", tenant);
        let refresh = initial_refresh(&grant, "refresh-mem-tenant", [7; 32]);
        let refresh_hash = refresh.token_hash().clone();
        let event = session_created_event("evt-session-mem-tenant", &grant).await;

        let signer = Arc::new(RecordingTenantSigner::default());
        let store = MemAuthGrantStore::with_tenant_metadata_signer(
            bus.clone(),
            signer,
            Arc::new(FixedClock::at_unix_secs(1_000)),
        );
        let _persisted = store
            .persist_login_grant(
                login_receipt(),
                identity::ports::TenantRepoScope::for_test(tenant),
                login_grant_mutation(grant, refresh),
                event,
            )
            .await
            .expect("persist grant and emit");

        let msg = stream.next().await.expect("message delivered");
        assert_eq!(
            msg.metadata.tenant_id(),
            Some(tenant),
            "MemAuthGrantStore co-tx path must carry tenantId metadata"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_TENANT_AUTHORITY),
            Some("signed-tenant-authority"),
            "signed MemAuthGrantStore path must carry tenantAuthority metadata"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_SUBJECT_ID),
            None,
            "MemAuthGrantStore co-tx path must not expose persisted-only subjectId"
        );
        assert_eq!(
            msg.metadata.get(diport::KEY_ACTOR),
            None,
            "MemAuthGrantStore co-tx path must not expose persisted-only actor"
        );
        assert!(
            store
                .find_by_hash(
                    identity::ports::TenantRepoScope::for_test(tenant),
                    refresh_hash,
                )
                .await
                .expect("find refresh")
                .is_some()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::expect_used)]
    async fn mem_auth_grant_store_makes_state_visible_before_publishing_login_event() {
        let probe = Arc::new(PublishProbe::new());
        let bus = MemBus::new().with_publish_probe(Arc::clone(&probe));
        let token = CancellationToken::new();
        let mut stream = bus
            .subscriber()
            .subscribe(Topic::new(TOPIC), token.clone())
            .await
            .expect("subscribe");
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let scope = identity::ports::TenantRepoScope::for_test(tenant);
        let grant = test_grant("d8dbe849-1d7e-49aa-b68a-a7b41ed252df", tenant);
        let grant_id = grant.id().clone();
        let refresh = initial_refresh(&grant, "refresh-mem-publish-order", [17; 32]);
        let refresh_hash = refresh.token_hash().clone();
        let store = MemAuthGrantStore::new(bus, Arc::new(FixedClock::at_unix_secs(1_000)));
        let writer = {
            let store = store.clone();
            let grant = grant.clone();
            tokio::spawn(async move {
                store
                    .persist_login_grant(
                        login_receipt(),
                        scope,
                        login_grant_mutation(grant.clone(), refresh),
                        session_created_event("evt-session-mem-publish-order", &grant).await,
                    )
                    .await
            })
        };

        probe.enqueued.wait();
        let message = stream.next().await.expect("event must already be enqueued");
        assert_eq!(message.id.as_str(), "evt-session-mem-publish-order");

        let visible_while_publish_is_paused = store
            .state
            .try_lock()
            .map(|state| {
                state.grants.contains_key(&grant_id)
                    && state
                        .refresh
                        .values()
                        .any(|record| record.token_hash() == &refresh_hash)
            })
            .unwrap_or(false);

        probe.release.wait();
        let _persisted = writer
            .await
            .expect("writer task")
            .expect("persist grant and publish");

        assert!(
            visible_while_publish_is_paused,
            "grant and refresh must be readable after the event is enqueued, before publish returns"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_auth_grant_store_rejects_grant_tenant_mismatch_without_write_or_emit() {
        let tenant_a = vocab::TenantId::parse(CANON_TENANT).expect("tenant a");
        let tenant_b = vocab::TenantId::parse(OTHER_TENANT).expect("tenant b");
        let grant = test_grant("6e3b6c98-2d14-4862-83d7-35f5333a76e3", tenant_b);
        let grant_id = grant.id().clone();
        let refresh = initial_refresh(&grant, "refresh-mem-mismatch", [8; 32]);
        let event = session_created_event("evt-session-mem-mismatch", &grant).await;

        let signer = Arc::new(RecordingTenantSigner::default());
        let store = MemAuthGrantStore::with_tenant_metadata_signer(
            MemBus::new(),
            signer.clone(),
            Arc::new(FixedClock::at_unix_secs(1_000)),
        );
        let result = store
            .persist_login_grant(
                login_receipt(),
                identity::ports::TenantRepoScope::for_test(tenant_a),
                login_grant_mutation(grant, refresh),
                event,
            )
            .await;

        assert!(result.is_err(), "tenant mismatch must fail closed");
        assert_eq!(signer.calls(), Vec::<String>::new());
        assert!(
            store
                .find_active(
                    identity::ports::TenantRepoScope::for_test(tenant_b),
                    grant_id,
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .expect("find")
                .is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mem_auth_grant_store_rejects_envelope_tenant_mismatch_without_write_or_emit() {
        let tenant_a = vocab::TenantId::parse(CANON_TENANT).expect("tenant a");
        let tenant_b = vocab::TenantId::parse(OTHER_TENANT).expect("tenant b");
        let grant = test_grant("315ba1e6-5831-4683-b8ec-fdf535c90cd6", tenant_a);
        let grant_id = grant.id().clone();
        let refresh = initial_refresh(&grant, "refresh-mem-envelope-mismatch", [9; 32]);
        let other_grant = test_grant("315ba1e6-5831-4683-b8ec-fdf535c90cd6", tenant_b);
        let event = session_created_event("evt-session-mem-envelope-mismatch", &other_grant).await;

        let signer = Arc::new(RecordingTenantSigner::default());
        let store = MemAuthGrantStore::with_tenant_metadata_signer(
            MemBus::new(),
            signer.clone(),
            Arc::new(FixedClock::at_unix_secs(1_000)),
        );
        let result = store
            .persist_login_grant(
                login_receipt(),
                identity::ports::TenantRepoScope::for_test(tenant_a),
                login_grant_mutation(grant, refresh),
                event,
            )
            .await;

        assert!(result.is_err(), "envelope tenant mismatch must fail closed");
        assert_eq!(signer.calls(), Vec::<String>::new());
        assert!(
            store
                .find_active(
                    identity::ports::TenantRepoScope::for_test(tenant_a),
                    grant_id,
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .expect("find")
                .is_none()
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

    #[allow(clippy::expect_used)]
    // reason: 测试 fixture 使用固定合法 receipt metadata，构造失败即测试配置错误。
    fn receipt_ctx_for(tenant: &str, group: &str) -> consistency::InboxReceiptContext {
        consistency::InboxReceiptContext::new(
            TenantId::parse(tenant).expect("canonical tenant"),
            consistency::ConsumerGroup::parse(group).expect("consumer group"),
            "identity",
            TOPIC,
            "identity.session-created",
            "v1",
            HASH,
            None,
            None,
        )
        .expect("valid inbox receipt context")
    }

    fn receipt_ctx(group: &str) -> consistency::InboxReceiptContext {
        receipt_ctx_for(CANON_TENANT, group)
    }

    /// 同一 key 连续 try_claim：第 1 次 Fresh，active claim 必须返回 InProgress，不能伪装成 done Duplicate。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果及 try_claim，item-level carve-out（error-handling.md §Carve-out）。
    async fn claimer_active_claim_is_in_progress_not_duplicate() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let ctx = receipt_ctx("audit");
        let claimer = InMemClaimer::new();
        let key = IdemKey::parse("session.created:tenant-1:evt-1").expect("key");
        let t = tok();

        assert_eq!(
            claimer
                .try_claim(&ctx, &key, &t)
                .await
                .expect("try_claim 1"),
            SeenState::Fresh,
            "第 1 次应为 Fresh"
        );
        for attempt in 2..=3 {
            assert_eq!(
                claimer
                    .try_claim(&ctx, &key, &tok())
                    .await
                    .expect("active contention is an outcome"),
                SeenState::InProgress,
                "attempt={attempt}"
            );
        }
    }

    /// 同一个 claimer 内，同一 key 在不同 tenant/group scope 各自 Fresh。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果及 try_claim，item-level carve-out（error-handling.md §Carve-out）。
    async fn claimer_scopes_by_tenant_and_consumer_group() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let ctx_a = receipt_ctx("audit");
        let ctx_group_b = receipt_ctx("settings");
        let ctx_tenant_b = receipt_ctx_for("00000000-0000-4000-8000-000000000abc", "audit");
        let claimer = InMemClaimer::new();
        let key = IdemKey::parse("session.created:tenant-1:evt-1").expect("key");

        let state_a = claimer
            .try_claim(&ctx_a, &key, &tok())
            .await
            .expect("try_claim a");
        let active_state = claimer
            .try_claim(&ctx_a, &key, &tok())
            .await
            .expect("active contention is an outcome");
        let state_group_b = claimer
            .try_claim(&ctx_group_b, &key, &tok())
            .await
            .expect("try_claim group b");
        let state_tenant_b = claimer
            .try_claim(&ctx_tenant_b, &key, &tok())
            .await
            .expect("try_claim tenant b");

        assert_eq!(state_a, SeenState::Fresh, "group-a 首见应为 Fresh");
        assert_eq!(
            active_state,
            SeenState::InProgress,
            "同 scope active claim 应可重投"
        );
        assert_eq!(
            state_group_b,
            SeenState::Fresh,
            "group-b 独立首见应为 Fresh（组隔离）"
        );
        assert_eq!(
            state_tenant_b,
            SeenState::Fresh,
            "tenant-b 独立首见应为 Fresh（租户隔离）"
        );
    }

    /// 续租：持有期间 extend = Held；token 不符 = Lost（他人令牌或已被重捞）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 token-CAS 续租语义断言——in-mem claimer 方法恒 Ok，item-level carve-out。
    async fn claimer_extend_held_while_owned_lost_on_token_mismatch() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let ctx = receipt_ctx("audit");
        let claimer = InMemClaimer::new();
        let key = IdemKey::parse("evt-extend-1").expect("key");
        let mine = tok();
        assert_eq!(
            claimer
                .try_claim(&ctx, &key, &mine)
                .await
                .expect("try_claim"),
            SeenState::Fresh
        );
        // 持有者续租成功
        assert_eq!(
            claimer.extend(&ctx, &key, &mine).await.expect("extend"),
            LeaseOutcome::Held
        );
        // 他人令牌续租 → Lost
        assert_eq!(
            claimer
                .extend(&ctx, &key, &tok())
                .await
                .expect("extend-other"),
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

        let ctx = receipt_ctx("audit");
        let claimer = InMemClaimer::new();
        let key = IdemKey::parse("evt-fence-1").expect("key");
        let mine = tok();
        assert_eq!(
            claimer
                .try_claim(&ctx, &key, &mine)
                .await
                .expect("try_claim"),
            SeenState::Fresh
        );
        // stale holder（错误 token）commit → Lost（hard-fence：不可降级为 done）
        assert_eq!(
            claimer
                .commit(&ctx, &key, &tok())
                .await
                .expect("commit-stale"),
            LeaseOutcome::Lost
        );
        // 真持有者 commit → Held
        assert_eq!(
            claimer.commit(&ctx, &key, &mine).await.expect("commit"),
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

        let ctx = receipt_ctx("audit");
        let claimer = InMemClaimer::new();
        let key = IdemKey::parse("evt-commit-dup").expect("key");
        let t = tok();
        assert_eq!(
            claimer.try_claim(&ctx, &key, &t).await.expect("try_claim"),
            SeenState::Fresh
        );
        assert_eq!(
            claimer.commit(&ctx, &key, &t).await.expect("commit"),
            LeaseOutcome::Held
        );
        assert_eq!(
            claimer
                .try_claim(&ctx, &key, &tok())
                .await
                .expect("re-try_claim"),
            SeenState::Duplicate,
            "done 行永久 Duplicate"
        );
    }

    /// release token CAS：他人 token release 为 no-op（不误删 claim，仍返回 transient）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试 release CAS no-op 语义断言——in-mem claimer 方法恒 Ok，item-level carve-out。
    async fn claimer_release_with_stale_token_is_noop() {
        use crate::InMemClaimer;
        use consistency::IdemKey;

        let ctx = receipt_ctx("audit");
        let claimer = InMemClaimer::new();
        let key = IdemKey::parse("evt-release-cas").expect("key");
        let mine = tok();
        assert_eq!(
            claimer
                .try_claim(&ctx, &key, &mine)
                .await
                .expect("try_claim"),
            SeenState::Fresh
        );
        // stale token release → no-op（不误删他人 claim）
        claimer
            .release(&ctx, &key, &tok())
            .await
            .expect("release-stale");
        // claim 仍在（未被误删）→ InProgress，使 broker 保留投递而不是 ACK 丢消息。
        assert_eq!(
            claimer
                .try_claim(&ctx, &key, &tok())
                .await
                .expect("active contention is an outcome"),
            SeenState::InProgress
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

    // ── MemSagaDurableStore tests ─

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_exact_claim_fences_busy_and_terminal_instances() {
        use consistency::SagaId;

        let store = MemSagaDurableStore::new();
        let tenant = vocab::TenantId::parse(CANON_TENANT).unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(1925))).unwrap();
        let record = store
            .register(
                saga_start_authorization(instance, "billing.checkout"),
                saga_registration(instance, "billing.checkout"),
            )
            .await
            .unwrap();
        let candidate = SagaRunnableInstance::new(
            instance,
            record.status(),
            record.identity().clone(),
            record.definition().clone(),
        )
        .unwrap();
        let first = store
            .claim(saga_claim_request(candidate.clone(), "runner-a"))
            .await
            .unwrap();
        let SagaClaimOutcome::Acquired(lease) = first else {
            panic!("first exact claim was not acquired")
        };
        assert_eq!(
            store
                .claim(saga_claim_request(candidate, "runner-b"))
                .await
                .unwrap(),
            SagaClaimOutcome::Busy,
        );
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::Degraded)
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let stale_running = SagaRunnableInstance::new(
            instance,
            SagaInstanceStatus::Running,
            record.identity().clone(),
            record.definition().clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .claim(saga_claim_request(stale_running, "runner-c"))
                .await
                .unwrap(),
            SagaClaimOutcome::Degraded,
            "sticky degraded state must never be resurrected by claim",
        );
    }

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_runnable_tenants_exclude_operator_backlog() {
        use consistency::SagaId;

        let store = MemSagaDurableStore::new();
        let tenant = vocab::TenantId::parse(CANON_TENANT).unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(19_250))).unwrap();
        let record = store
            .register(
                saga_start_authorization(instance, "billing.checkout"),
                saga_registration(instance, "billing.checkout"),
            )
            .await
            .unwrap();
        let candidate = SagaRunnableInstance::new(
            instance,
            record.status(),
            record.identity().clone(),
            record.definition().clone(),
        )
        .unwrap();
        let SagaClaimOutcome::Acquired(lease) = store
            .claim(saga_claim_request(candidate, "runner-a"))
            .await
            .unwrap()
        else {
            panic!("exact claim was not acquired")
        };
        assert_eq!(
            store
                .mutate(
                    &lease,
                    SagaDurableMutation::OperatorRequired(
                        SagaOperatorReason::ForwardOutcomeUnknown,
                    ),
                )
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );

        let candidates = store
            .list_runnable_tenants(record.identity(), None, NonZeroUsize::new(10).unwrap())
            .await
            .unwrap();
        assert!(candidates.tenants().is_empty());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn mem_saga_runnable_tenant_cursor_pages_two_two_one_and_wraps() {
        use consistency::SagaId;

        let store = MemSagaDurableStore::new();
        let identity = saga_identity("billing.checkout");
        let mut expected = Vec::new();
        for ordinal in 1_u128..=5 {
            let tenant =
                vocab::TenantId::parse(&uuid::Uuid::from_u128(ordinal).to_string()).unwrap();
            let instance =
                SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(20_000 + ordinal)))
                    .unwrap();
            store
                .register(
                    saga_start_authorization(instance, "billing.checkout"),
                    saga_registration(instance, "billing.checkout"),
                )
                .await
                .unwrap();
            expected.push(tenant);
        }

        let first = store
            .list_runnable_tenants(&identity, None, NonZeroUsize::new(2).unwrap())
            .await
            .unwrap();
        assert_eq!(first.tenants(), &expected[..2]);
        let second = store
            .list_runnable_tenants(&identity, first.next(), NonZeroUsize::new(2).unwrap())
            .await
            .unwrap();
        assert_eq!(second.tenants(), &expected[2..4]);
        let third = store
            .list_runnable_tenants(&identity, second.next(), NonZeroUsize::new(2).unwrap())
            .await
            .unwrap();
        assert_eq!(third.tenants(), &expected[4..]);
        assert_eq!(third.next(), None);

        let wrapped = store
            .list_runnable_tenants(&identity, third.next(), NonZeroUsize::new(2).unwrap())
            .await
            .unwrap();
        assert_eq!(wrapped.tenants(), &expected[..2]);
    }

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_completion_and_recovery_snapshot_are_one_atomic_view() {
        let (store, lease, scope) = saga_durable_fixture(1926).await;
        let attempt = consistency::SagaAttempt::new(1).unwrap();
        let intent = diport::SagaForwardIntent::new(
            0,
            scope.step_name().clone(),
            attempt,
            scope.effect_key().clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardIntent(intent))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let completion = diport::SagaForwardCompletion::new(
            saga_completion(&scope, br#"{"ok":true}"#),
            SagaForwardProgress::Continue,
        );
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardCompleted(completion))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let snapshot = store
            .recovery_snapshot(
                SagaRecoveryRequest::new(lease.clone(), vec![scope.clone()]).unwrap(),
            )
            .await
            .unwrap();
        let SagaRecoveryOutcome::Available(snapshot) = snapshot else {
            panic!("held lease must produce a recovery snapshot")
        };
        assert_eq!(snapshot.instance().status(), SagaInstanceStatus::Running);
        assert_eq!(snapshot.journal().len(), 2);
        assert_eq!(
            snapshot.journal()[0].status(),
            SagaJournalStatus::ForwardIntent
        );
        assert_eq!(
            snapshot.journal()[1].status(),
            SagaJournalStatus::ForwardCompleted
        );
        assert_eq!(snapshot.receipts().len(), 1);
        assert_eq!(snapshot.receipts()[0].completed_seq(), 1);
        assert_eq!(
            snapshot.receipts()[0].plaintext().expose(),
            br#"{"ok":true}"#
        );

        let duplicate = diport::SagaForwardCompletion::new(
            saga_completion(&scope, br#"{"ok":true}"#),
            SagaForwardProgress::Continue,
        );
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardCompleted(duplicate))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::IdempotentDuplicate,
        );
        assert_eq!(store.release(&lease).await.unwrap(), SagaLeaseOutcome::Held);
        assert!(matches!(
            store
                .recovery_snapshot(SagaRecoveryRequest::new(lease, vec![scope]).unwrap())
                .await
                .unwrap(),
            SagaRecoveryOutcome::LeaseLost
        ));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn mem_saga_completion_requires_exact_prior_phase_intent() {
        let (store, lease, scope) = saga_durable_fixture(1927).await;
        let orphan_completion = diport::SagaForwardCompletion::new(
            saga_completion(&scope, br#"{"orphan":true}"#),
            SagaForwardProgress::Continue,
        );
        assert_eq!(
            store
                .mutate(
                    &lease,
                    SagaDurableMutation::ForwardCompleted(orphan_completion),
                )
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Conflict,
        );

        let (store, lease, _definition, compensation_key) = saga_compensating_fixture(1928).await;
        let wrong_cause = diport::SagaCompensationIntent::new(
            3,
            vocab::StepName::parse(generated::saga::billing_v1::STEP_0.name()).unwrap(),
            consistency::SagaAttempt::new(2).unwrap(),
            compensation_key.clone(),
            consistency::SagaCompensationCause::Expired,
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::CompensationIntent(wrong_cause),)
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Conflict,
        );
        let mismatched_attempt = diport::SagaCompensationCompletion::new(
            3,
            vocab::StepName::parse(generated::saga::billing_v1::STEP_0.name()).unwrap(),
            consistency::SagaAttempt::new(2).unwrap(),
            compensation_key,
            SagaCompensationProgress::Continue,
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(
                    &lease,
                    SagaDurableMutation::CompensationCompleted(mismatched_attempt),
                )
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Conflict,
        );

        let (store, lease, definition, _) = saga_compensating_fixture(1929).await;
        let other_step = generated::saga::billing_v1::STEP_1;
        let other_key = consistency::SagaIdempotencyKey::derive(
            lease.instance(),
            &definition,
            other_step,
            consistency::SagaEffectPhase::Compensation,
        );
        let mismatched_step = diport::SagaCompensationFailure::new(
            3,
            vocab::StepName::parse(other_step.name()).unwrap(),
            consistency::SagaAttempt::new(1).unwrap(),
            other_key,
            "compensation failed",
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(
                    &lease,
                    SagaDurableMutation::CompensationFailed(mismatched_step),
                )
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Conflict,
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn mem_saga_intent_attempts_are_contiguous_and_completion_is_adjacent() {
        let (store, lease, scope) = saga_durable_fixture(1930).await;
        let step = scope.step_name().clone();
        let effect_key = scope.effect_key().clone();
        let skipped_first = diport::SagaForwardIntent::new(
            0,
            step.clone(),
            consistency::SagaAttempt::new(2).unwrap(),
            effect_key.clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardIntent(skipped_first))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Conflict,
        );
        let first = diport::SagaForwardIntent::new(
            0,
            step.clone(),
            consistency::SagaAttempt::new(1).unwrap(),
            effect_key.clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardIntent(first))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let skipped_retry = diport::SagaForwardIntent::new(
            1,
            step.clone(),
            consistency::SagaAttempt::new(3).unwrap(),
            effect_key.clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardIntent(skipped_retry),)
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Conflict,
        );
        let second = diport::SagaForwardIntent::new(
            1,
            step,
            consistency::SagaAttempt::new(2).unwrap(),
            effect_key,
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardIntent(second))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let non_adjacent = diport::SagaForwardCompletion::new(
            diport::SagaStepCompletion::new(
                scope,
                consistency::SagaAttempt::new(2).unwrap(),
                consistency::SagaReceiptFormatVersion::V1,
                secure::Plaintext::new(br#"{"ok":true}"#.to_vec()),
                3,
            ),
            SagaForwardProgress::Continue,
        );
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardCompleted(non_adjacent),)
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Conflict,
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn mem_saga_terminal_interruptions_clear_pinned_compensation_cause() {
        let (store, lease, _, _) = saga_compensating_fixture(1931).await;
        assert_eq!(
            store
                .mutate(
                    &lease,
                    SagaDurableMutation::OperatorRequired(
                        consistency::SagaOperatorReason::ReceiptIntegrity,
                    ),
                )
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        {
            let durable = store
                .inner
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let state = &durable.instances[&saga_instance_key(lease.instance())];
            assert_eq!(state.status, SagaInstanceStatus::OperatorRequired);
            assert_eq!(
                state.operator_reason,
                Some(consistency::SagaOperatorReason::ReceiptIntegrity)
            );
            assert_eq!(state.compensation_cause, None);
        }

        let (store, lease, _, _) = saga_compensating_fixture(1932).await;
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::Degraded)
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let durable = store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let state = &durable.instances[&saga_instance_key(lease.instance())];
        assert_eq!(state.status, SagaInstanceStatus::Degraded);
        assert_eq!(state.operator_reason, None);
        assert_eq!(state.compensation_cause, None);
    }

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_compensation_not_applied_reopens_with_cause_and_audit() {
        let (store, lease, definition, compensation_key) = saga_compensating_fixture(1933).await;
        let instance = lease.instance();
        let reason = SagaOperatorReason::CompensationOutcomeUnknown;
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::OperatorRequired(reason))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let record = store.get(&instance).await.unwrap().unwrap();
        assert_eq!(record.status(), SagaInstanceStatus::OperatorRequired);
        assert_eq!(record.operator_reason(), Some(reason));
        let unresolved = store
            .observe_unresolved(&saga_identity("billing.checkout"))
            .await
            .unwrap();
        assert_eq!(unresolved.operator_required(), 1);
        assert!(!unresolved.is_clear());
        let status = store
            .operator_status(saga_operator_status_authorization(instance))
            .await
            .unwrap();
        let SagaOperatorStatusOutcome::Found(status) = status else {
            panic!("exact operator status was not found")
        };
        assert_eq!(status.record().instance(), instance);
        assert_eq!(status.record().operator_reason(), Some(reason));
        assert!(status.has_effect_intent());

        let claimed = store
            .claim_repair(
                saga_operator_authorization(instance, reason, "CHG-1933"),
                saga_operator_holder(),
                saga_operator_ttl(),
            )
            .await
            .unwrap();
        let SagaOperatorClaimOutcome::Acquired(operator) = claimed else {
            panic!("operator claim was not acquired")
        };
        let decision = diport::SagaCompensationNotApplied::new(
            3,
            vocab::StepName::parse(generated::saga::billing_v1::STEP_0.name()).unwrap(),
            consistency::SagaAttempt::new(1).unwrap(),
            compensation_key,
            SagaCompensationCause::BusinessFailure,
        )
        .unwrap();
        assert_eq!(
            store
                .commit_repair(
                    operator,
                    SagaOperatorRepair::CompensationNotApplied(decision),
                )
                .await
                .unwrap(),
            SagaOperatorCasOutcome::Applied,
        );
        assert!(
            store
                .observe_unresolved(&saga_identity("billing.checkout"))
                .await
                .unwrap()
                .is_clear()
        );
        {
            let durable = store
                .inner
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let state = &durable.instances[&saga_instance_key(instance)];
            assert_eq!(state.status, SagaInstanceStatus::Compensating);
            assert_eq!(state.operator_reason, None);
            assert_eq!(
                state.compensation_cause,
                Some(SagaCompensationCause::BusinessFailure)
            );
            let audit = durable.operator_decisions.last().unwrap();
            assert_eq!(audit.instance, instance);
            assert_eq!(audit.reason, Some(reason));
            assert_eq!(audit.reason_text, "provider evidence reviewed");
            assert_eq!(audit.decision, "confirmed_not_applied");
            assert_eq!(
                audit.actor,
                vocab::ServiceCallerDomain::MaintenanceOperator.as_str()
            );
            assert_eq!(audit.change_ticket, "CHG-1933");
            assert_eq!(audit.seq, Some(3));
        }

        let runnable = SagaRunnableInstance::new(
            instance,
            SagaInstanceStatus::Compensating,
            saga_identity("billing.checkout"),
            definition,
        )
        .unwrap();
        let SagaClaimOutcome::Acquired(recovery_lease) = store
            .claim(saga_claim_request(runnable, "recovery-runner"))
            .await
            .unwrap()
        else {
            panic!("repaired compensation was not runnable")
        };
        let snapshot = store
            .recovery_snapshot(SagaRecoveryRequest::new(recovery_lease, Vec::new()).unwrap())
            .await
            .unwrap();
        let SagaRecoveryOutcome::Available(snapshot) = snapshot else {
            panic!("repaired compensation did not produce a recovery snapshot")
        };
        assert_eq!(
            snapshot.instance().status(),
            SagaInstanceStatus::Compensating
        );
        assert_eq!(snapshot.operator_reason(), None);
        assert_eq!(
            snapshot.compensation_cause(),
            Some(SagaCompensationCause::BusinessFailure)
        );
        assert_eq!(
            snapshot.journal().last().unwrap().status(),
            SagaJournalStatus::CompensationNotApplied
        );
    }

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_compensation_applied_reopens_with_cause_and_audit() {
        let (store, lease, definition, compensation_key) = saga_compensating_fixture(1934).await;
        let instance = lease.instance();
        let reason = SagaOperatorReason::CompensationOutcomeUnknown;
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::OperatorRequired(reason))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let SagaOperatorClaimOutcome::Acquired(operator) = store
            .claim_repair(
                saga_operator_authorization(instance, reason, "CHG-1934"),
                saga_operator_holder(),
                saga_operator_ttl(),
            )
            .await
            .unwrap()
        else {
            panic!("operator claim was not acquired")
        };
        let decision = diport::SagaCompensationCompletion::new(
            3,
            vocab::StepName::parse(generated::saga::billing_v1::STEP_0.name()).unwrap(),
            consistency::SagaAttempt::new(1).unwrap(),
            compensation_key,
            SagaCompensationProgress::Continue,
        )
        .unwrap();
        assert_eq!(
            store
                .commit_repair(operator, SagaOperatorRepair::CompensationApplied(decision))
                .await
                .unwrap(),
            SagaOperatorCasOutcome::Applied,
        );
        let runnable = SagaRunnableInstance::new(
            instance,
            SagaInstanceStatus::Compensating,
            saga_identity("billing.checkout"),
            definition,
        )
        .unwrap();
        assert!(matches!(
            store
                .claim(saga_claim_request(runnable, "applied-recovery-runner"))
                .await
                .unwrap(),
            SagaClaimOutcome::Acquired(_)
        ));
        let durable = store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let state = &durable.instances[&saga_instance_key(instance)];
        assert_eq!(state.status, SagaInstanceStatus::Compensating);
        assert_eq!(
            state.compensation_cause,
            Some(SagaCompensationCause::BusinessFailure)
        );
        let audit = durable.operator_decisions.last().unwrap();
        assert_eq!(audit.reason, Some(reason));
        assert_eq!(audit.reason_text, "provider evidence reviewed");
        assert_eq!(audit.decision, "confirmed_applied");
        assert_eq!(audit.change_ticket, "CHG-1934");
        assert_eq!(audit.seq, Some(3));
    }

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_retry_compensation_requires_the_exact_latest_failure_basis() {
        let (store, lease, _, compensation_key) = saga_compensating_fixture(19_340).await;
        let instance = lease.instance();
        let step = vocab::StepName::parse(generated::saga::billing_v1::STEP_0.name()).unwrap();
        let attempt = consistency::SagaAttempt::new(1).unwrap();
        let failure = diport::SagaCompensationFailure::new(
            3,
            step.clone(),
            attempt,
            compensation_key.clone(),
            "compensation failed",
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::CompensationFailed(failure))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );

        let SagaOperatorStatusOutcome::Found(status) = store
            .operator_status(saga_operator_status_authorization(instance))
            .await
            .unwrap()
        else {
            panic!("compensation failure status was not found")
        };
        assert_eq!(
            status.record().status(),
            SagaInstanceStatus::CompensationFailed
        );
        let latest = status
            .latest_journal()
            .unwrap_or_else(|| panic!("latest failure journal is required"));
        assert_eq!(latest.record().seq(), 3);
        assert_eq!(
            latest.record().status(),
            SagaJournalStatus::CompensationFailed
        );

        let stale = SagaOperatorJournalExpectation::new(
            latest.record().clone(),
            consistency::SagaAttempt::new(2).unwrap(),
            compensation_key.clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .retry_compensation(saga_retry_compensation_authorization(
                    instance,
                    stale,
                    "CHG-19340-S",
                ))
                .await
                .unwrap(),
            SagaOperatorCasOutcome::StaleJournal,
        );

        assert_eq!(
            store
                .retry_compensation(saga_retry_compensation_authorization(
                    instance,
                    latest.clone(),
                    "CHG-19340",
                ))
                .await
                .unwrap(),
            SagaOperatorCasOutcome::Applied,
        );
        let durable = store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            durable.instances[&saga_instance_key(instance)].status,
            SagaInstanceStatus::Compensating
        );
        let audit = durable.operator_decisions.last().unwrap();
        assert_eq!(audit.reason, None);
        assert_eq!(audit.reason_text, "dependency restored");
        assert_eq!(audit.decision, "retry_compensation");
        assert_eq!(audit.change_ticket, "CHG-19340");
        assert_eq!(audit.seq, Some(3));
    }

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_terminate_accepts_only_ready_instances_without_effect_intent() {
        let store = MemSagaDurableStore::new();
        let tenant = vocab::TenantId::parse(CANON_TENANT).unwrap();
        let instance = SagaInstanceRef::new(
            tenant,
            consistency::SagaId::new(uuid::Uuid::from_u128(19_341)),
        )
        .unwrap();
        store
            .register(
                saga_start_authorization(instance, "billing.checkout"),
                saga_registration(instance, "billing.checkout"),
            )
            .await
            .unwrap();
        let definition =
            consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC);
        let binding = generated::saga::billing_v1::STEP_0;
        let effect_key = consistency::SagaIdempotencyKey::derive(
            instance,
            &definition,
            binding,
            consistency::SagaEffectPhase::Forward,
        );
        {
            let mut durable = store
                .inner
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            durable.journal.push((
                instance,
                MemSagaJournalEntry::new(
                    0,
                    vocab::StepName::parse(binding.name()).unwrap(),
                    SagaJournalStatus::ForwardIntent,
                    consistency::SagaAttempt::new(1).unwrap(),
                    effect_key,
                    None,
                    None,
                ),
            ));
        }
        assert_eq!(
            store
                .terminate(saga_terminate_authorization(instance, "CHG-19341-S"))
                .await
                .unwrap(),
            SagaOperatorCasOutcome::EffectAlreadyStarted,
        );
        store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .journal
            .clear();
        assert_eq!(
            store
                .terminate(saga_terminate_authorization(instance, "CHG-19341"))
                .await
                .unwrap(),
            SagaOperatorCasOutcome::Applied,
        );
        let durable = store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            durable.instances[&saga_instance_key(instance)].status,
            SagaInstanceStatus::Terminated
        );
        let audit = durable.operator_decisions.last().unwrap();
        assert_eq!(audit.reason, None);
        assert_eq!(audit.reason_text, "request withdrawn");
        assert_eq!(audit.decision, "terminate");
        assert_eq!(audit.change_ticket, "CHG-19341");
        assert_eq!(audit.seq, None);
    }

    #[tokio::test]
    #[allow(clippy::panic, clippy::unwrap_used)]
    async fn mem_saga_terminal_receipt_is_a_store_verified_aggregate_proof() {
        let (store, lease, scope) = saga_durable_fixture(1935).await;
        let attempt = consistency::SagaAttempt::new(1).unwrap();
        let intent = diport::SagaForwardIntent::new(
            0,
            scope.step_name().clone(),
            attempt,
            scope.effect_key().clone(),
        )
        .unwrap();
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardIntent(intent))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let completion = diport::SagaForwardCompletion::new(
            saga_completion(&scope, br#"{"terminal":true}"#),
            SagaForwardProgress::Succeeded,
        );
        assert_eq!(
            store
                .mutate(&lease, SagaDurableMutation::ForwardCompleted(completion))
                .await
                .unwrap(),
            SagaDurableMutationOutcome::Applied,
        );
        let proof = store
            .terminal_receipt(SagaTerminalReceiptRequest::new(scope.clone()))
            .await
            .unwrap();
        let SagaTerminalReceiptOutcome::Verified(proof) = proof else {
            panic!("succeeded saga did not return a verified terminal proof")
        };
        assert_eq!(proof.instance().status(), SagaInstanceStatus::Succeeded);
        assert_eq!(proof.journal().len(), 2);
        assert_eq!(
            proof.journal().last().unwrap().status(),
            SagaJournalStatus::ForwardCompleted
        );
        assert_eq!(proof.receipt().scope(), &scope);
        assert_eq!(proof.receipt().completed_seq(), 1);
        assert_eq!(
            proof.receipt().plaintext().expose(),
            br#"{"terminal":true}"#
        );
        assert!(matches!(
            store
                .recovery_snapshot(SagaRecoveryRequest::new(lease, vec![scope]).unwrap())
                .await
                .unwrap(),
            SagaRecoveryOutcome::LeaseLost
        ));
    }

    #[test]
    fn mem_saga_durable_store_implements_shared_port() {
        fn assert_port<T: SagaDurableStore + SagaTenantSource + Send + Sync>() {}
        assert_port::<MemSagaDurableStore>();
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
        use diport::{DeadLetterProvenance, DeadLetterSummary, EnvelopeMetadata};

        let store = MemDeadLetterStore::new();
        assert!(store.is_empty());

        let record = DeadLetterRecord::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
            "msg-1",
            DeadLetterProvenance::consumer("identity", "audit"),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("max retries exhausted"),
            3,
            EnvelopeMetadata::empty(),
        );
        store
            .write_dead_letter(record)
            .await
            .expect("write_dead_letter");

        assert_eq!(store.len(), 1);
        let records = store.records();
        assert_eq!(records[0].producer_domain(), "identity");
        assert_eq!(records[0].consumer_domain(), Some("audit"));
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
