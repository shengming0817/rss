//! ConsumerBase —— 幂等消费驱动（claim→handle→commit/dlx）。
//!
//! 单消息流程：`IdemKey::parse` → `InboxStore::try_claim` → handler bounded 重投 →
//! `Ack` commit / `Reject` dlx / `Requeue` 预算耗尽后 dlx。
//! DLX 路径对标 watermill PoisonQueue：原消息 ack 收口，死信另写持久化。
//!
//! ref: watermill message/router/middleware/poison.go（PoisonQueue=DLX）
//!      watermill message/router/middleware/retry.go（重投预算 MaxRetries+1 次尝试）

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use consistency::idempotency::{ConsumerGroup, IdemKey, LeaseOutcome, LeaseToken, SeenState};
use consistency::{HandleResult, InboxReceiptContext, InboxReceiptContextError};
use diport::dead_letter_store::{
    DeadLetterRecord, DeadLetterStore as _, DeadLetterStoreError, DeadLetterSummary,
    DynDeadLetterStore,
};
use diport::{
    Acker as _, DeadLetterProvenance, EnvelopeCausationId, EnvelopeHeader, EnvelopeHeaderError,
    Message, MessageStream,
};
// #1224：consume span `.instrument()` handler loop，使 handler span 挂回 producer trace。
use tracing::Instrument as _;

use primitives::{AdmissionError, ConsumerAdmission};

use crate::MAX_REDELIVERY;
use crate::tenant_authority::{TenantAuthority, TenantAuthorityBinding, TenantAuthorityError};

/// Upper bound for holding an active broker delivery before requeueing a contended claim.
/// The normal delay is the provider-derived lease renewal interval (`ttl / 3`); the cap prevents
/// unusually large provider TTLs from monopolizing a consumer lane indefinitely.
const MAX_CLAIM_IN_PROGRESS_DELAY: Duration = Duration::from_secs(30);

// ── LeaseConfig（消费侧租约续租配置，#1213）────────────────────────────────────

/// 消费侧租约续租配置：续租间隔 = 后端 claim lease TTL / 3（对标 gocell ConsumerBase `LeaseTTL/3`）。
///
/// 组合根经 [`LeaseConfig::from_ttl`] 由**后端 claim TTL**（`PgInboxStore` 的 `INBOX_LEASE_TTL_SECONDS` /
/// `RedisInboxStore` 句柄 TTL）派生并注入 `run_consumer*` / `spawn_consumer*`——保证续租周期短于后端 TTL，
/// 长 handler 的 claim 在过期重捞前被刷新（必填位置参，缺失即编译错误，不静默默认）。
#[derive(Debug, Clone, Copy)]
pub struct LeaseConfig {
    renew_interval: Duration,
}

impl LeaseConfig {
    /// 由后端 claim lease TTL 派生续租配置：续租间隔 = `ttl/3`（下限 1ms，避免 0 间隔忙轮询）。
    pub fn from_ttl(ttl: Duration) -> Self {
        Self {
            renew_interval: (ttl / 3).max(Duration::from_millis(1)),
        }
    }

    /// 续租间隔（后台每隔此时长调一次 [`consistency::InboxStore::extend`]）。
    pub fn renew_interval(&self) -> Duration {
        self.renew_interval
    }
}

// ── DLX 摘要：requeue 耗尽路径取循环内最后一次 Settled::Requeue 摘要（#1125/#1285）──────────────

// ── ConsumerMeta（消费契约元数据）─────────────────────────────────────────────

/// 消费契约元数据（注册期绑定；私有字段 + `new()` funnel）。
///
/// 用于 DLX 记录与结构化日志归因（domain / contract_id / topic 三元组稳定标识消费场景）。
#[derive(Clone)]
pub struct ConsumerMeta {
    domain: String,
    authority_domain: String,
    contract_id: String,
    topic: String,
    consumer_group: String,
    expected_schema_version: Option<String>,
    expected_schema_hash: Option<String>,
    tenant_authority: Arc<TenantAuthority>,
}

impl ConsumerMeta {
    /// 构造消费契约元数据。
    pub fn new(
        domain: impl Into<String>,
        authority_domain: impl Into<String>,
        contract_id: impl Into<String>,
        topic: impl Into<String>,
        consumer_group: impl Into<String>,
        tenant_authority: Arc<TenantAuthority>,
    ) -> Self {
        Self {
            domain: domain.into(),
            authority_domain: authority_domain.into(),
            contract_id: contract_id.into(),
            topic: topic.into(),
            consumer_group: consumer_group.into(),
            expected_schema_version: None,
            expected_schema_hash: None,
            tenant_authority,
        }
    }

    pub fn with_expected_schema(
        mut self,
        schema_version: impl Into<String>,
        schema_hash: impl Into<String>,
    ) -> Self {
        self.expected_schema_version = Some(schema_version.into());
        self.expected_schema_hash = Some(schema_hash.into());
        self
    }

    #[doc(hidden)]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    #[doc(hidden)]
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    #[doc(hidden)]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    #[doc(hidden)]
    pub fn consumer_group(&self) -> &str {
        &self.consumer_group
    }

    #[doc(hidden)]
    pub fn verify_tenant_authority(
        &self,
        msg: &Message,
    ) -> Result<rss_request_context::TenantId, TenantAuthorityError> {
        let tenant = msg
            .metadata()
            .tenant_id()
            .ok_or(TenantAuthorityError::TenantMissing)?;
        self.tenant_authority.verify(
            TenantAuthorityBinding::new(
                tenant,
                self.authority_domain(),
                self.contract_id(),
                self.topic(),
                msg.id().as_str(),
            ),
            msg.metadata(),
        )
    }

    #[doc(hidden)]
    pub fn verify_envelope_header(
        &self,
        msg: &Message,
    ) -> Result<EnvelopeHeader, EnvelopeHeaderError> {
        let header = msg.try_header()?;
        if self
            .expected_schema_version
            .as_deref()
            .is_some_and(|expected| header.schema_version().as_str() != expected)
        {
            return Err(EnvelopeHeaderError::SchemaVersionMismatch);
        }
        if self
            .expected_schema_hash
            .as_deref()
            .is_some_and(|expected| header.schema_hash().as_str() != expected)
        {
            return Err(EnvelopeHeaderError::SchemaHashMismatch);
        }
        Ok(header)
    }

    #[doc(hidden)]
    pub fn receipt_context(
        &self,
        tenant_id: rss_request_context::TenantId,
        header: &EnvelopeHeader,
    ) -> Result<InboxReceiptContext, ReceiptContextBuildError> {
        let consumer_group = ConsumerGroup::parse(self.consumer_group())
            .map_err(|_| ReceiptContextBuildError::ConsumerGroup)?;
        InboxReceiptContext::new(
            tenant_id,
            consumer_group,
            self.domain(),
            self.topic(),
            self.contract_id(),
            header.schema_version().as_str(),
            header.schema_hash().as_str(),
            header.trace().map(str::to_string),
            header.correlation().map(str::to_string),
        )
        .map_err(ReceiptContextBuildError::Receipt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ReceiptContextBuildError {
    ConsumerGroup,
    Receipt(InboxReceiptContextError),
}

// ── run_consumer（消费驱动入口）─────────────────────────────────────────────

/// 消费驱动：逐条 claim→handle→commit/dlx（bounded 重投，幂等去重）。
///
/// consumer group 由 [`ConsumerMeta::consumer_group`] 承载并写入 DLX；`InboxStore` 实现在构造时
/// 已绑 group，try_claim/commit/release 以 `IdemKey` 为维度。
/// 下游事件经 handler 自持 Publisher 发，不经本驱动中转（对齐 RSS DI port 隔离）。
///
/// **重投次数**：handler 最多被调用 [`MAX_REDELIVERY`] 次（含首投），耗尽后消息进 DLX
/// 而非再次 Requeue，防无限重投。
///
/// **类型形态差异**：
/// - `idempotency: Arc<S>`：try_claim/commit/release 可被多次调用（bounded 循环），
///   `Arc` 允许跨 spawn 共享同一 store 实例。
/// - `dlx: Box<DynDeadLetterStore>`：每条消息至多调用一次 write_dead_letter，
///   one-shot 写入语义不需要共享，owned 注入更自然（类型层明确消费权）。
///
/// **worker 生命周期豁免**：本驱动是 plain async fn（对齐 `run_dispatch` 范式），
/// `ManagedResource` / probe / `ShutdownStack` 两阶段关闭接入随组合根 spawn 落地，
/// 属 consumer worker 生命周期 follow-up（#1142 派生，组合根 spawn + ManagedResource/ShutdownStack + probe）；
/// 与 relay.rs 的 `RelayWorker` 不同，本任务只交付驱动函数本体。
///
/// ref: watermill message/router/middleware/poison.go（DLX ack 收口）
///      watermill message/router/middleware/retry.go（MaxRetries+1 次尝试首投）
pub async fn run_consumer<S, H>(
    mut stream: MessageStream,
    idempotency: Arc<S>,
    dlx: Box<DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
    lease_cfg: LeaseConfig,
    admission: ConsumerAdmission,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    while let Some((msg, _permit)) = next_admitted(&mut stream, &admission).await {
        consume_one(&idempotency, &dlx, &meta, &handler, msg, None, lease_cfg).await;
    }
}

/// at-least-once 消费驱动：消费 [`diport::DeliveryStream`]，解构每条 [`diport::Delivery`]，
/// 把 broker 结算句柄传给 `consume_one` 在终态调 [`diport::AckAction`]。
///
/// 与 [`run_consumer`] 对偶：`run_consumer` 消费 `MessageStream`（brokerless / MemBus，acker=None），
/// 本函数消费 `DeliveryStream`（AMQP 等支持 broker 确认的 provider），每条消息终态恰向 broker settle 一次。
///
/// **终态→AckAction 映射**（见 `consume_one`/`handle_fresh`/`dead_letter` 的 acker 传递）：
/// - handler Ack / DLX 写成功 → broker `Ack`
/// - DLX 写失败且 release 成功 / try_claim 返 transient Err → broker `Requeue`
/// - active claim `InProgress` → lease-aware bounded delay, then broker `Requeue`
/// - DLX 写失败且 release 失败 → broker `Reject`
/// - Duplicate → broker `Ack`（仅 durable done 可幂等短路）
/// - IdemKey parse 失败 → broker `Reject`（malformed，不重投）
///
/// **settle 失败语义（不丢失）**：`settle` 失败仅结构化 error 日志、**不中断**消费循环。终态 `Ack` 走
/// commit→settle 顺序（handler 副作用在 `handler()` 内已持久 + 幂等键已 `commit` 标记 done **先于** broker
/// ack）；故 `settle(Ack)` 失败时，消息在 broker channel close 后被自动重投、再经幂等 `try_claim` 去重
/// （`Duplicate`→`Ack`）——副作用恰一次、消息不丢失（最坏仅滞留队列直至 ack 成功）。broker channel 错误致
/// stream 终止后的有监督重订阅由 [`crate::run_ackable_subscription_loop`] 收口（#1605）。
///
/// ref: lapin message::Delivery.acker（AMQP 手工 ack 范式）
///      watermill-amqp pkg/amqp/subscriber.go@master（Ack/Nack 驱动模型）
pub async fn run_consumer_ackable<S, H>(
    mut stream: diport::DeliveryStream,
    idempotency: Arc<S>,
    dlx: &DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &H,
    lease_cfg: LeaseConfig,
    admission: ConsumerAdmission,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    while let Some((d, _permit)) = next_admitted(&mut stream, &admission).await {
        let diport::Delivery { message, acker } = d;
        consume_one(
            &idempotency,
            dlx,
            meta,
            handler,
            message,
            Some(acker.as_ref()),
            lease_cfg,
        )
        .await;
    }
}

async fn next_admitted<T>(
    stream: &mut (impl futures::Stream<Item = T> + Unpin),
    admission: &ConsumerAdmission,
) -> Option<(T, primitives::AdmissionPermit<primitives::ConsumerLane>)> {
    loop {
        if admission.wait_open().await.is_err() {
            return None;
        }
        let permit = match admission.try_enter() {
            Ok(permit) => permit,
            Err(AdmissionError::Paused) => continue,
            Err(AdmissionError::Stopped) => return None,
            Err(error) => {
                tracing::error!(error = %error, "consumer: admission invariant failed");
                return None;
            }
        };
        tokio::select! {
            biased;
            closed = admission.wait_closed() => {
                drop(permit);
                if matches!(closed, Err(AdmissionError::Stopped)) {
                    return None;
                }
            }
            item = stream.next() => return item.map(|item| (item, permit)),
        }
    }
}

/// 处理单条消息：parse key → envelope header gate → try_claim → handle_fresh 或幂等短路。
/// 从 `run_consumer` 抽出，控制各自认知复杂度 ≤15（rust-standards §工程护栏）。
async fn consume_one<S, H>(
    idempotency: &Arc<S>,
    dlx: &DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &H,
    msg: Message,
    acker: Option<&diport::DynAcker<'static>>,
    lease_cfg: LeaseConfig,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    // parse 失败 → 结构化 warn + 丢弃（不 panic；key 漂移即等价新消费者，fail-closed）。
    let key = match IdemKey::parse(msg.id().as_str()) {
        Ok(k) => k,
        Err(_) => {
            log_parse_failed(&msg);
            // malformed id：broker Reject（不重投）。
            settle(
                acker,
                diport::AckAction::Reject,
                meta.domain(),
                msg.id().as_str(),
            )
            .await;
            return;
        }
    };
    let parent_causation = match EnvelopeCausationId::from_opaque(msg.id().as_str()) {
        Ok(causation_id) => causation_id,
        Err(_) => {
            log_parse_failed(&msg);
            settle(
                acker,
                diport::AckAction::Reject,
                meta.domain(),
                msg.id().as_str(),
            )
            .await;
            return;
        }
    };

    let header = match meta.verify_envelope_header(&msg) {
        Ok(header) => header,
        Err(error) => {
            reject_invalid_envelope_header(meta, &msg, acker, &error).await;
            return;
        }
    };

    let tenant = match meta.verify_tenant_authority(&msg) {
        Ok(tenant) => tenant,
        Err(error) => {
            reject_invalid_tenant_authority(meta, &msg, acker, error).await;
            return;
        }
    };

    let receipt_context = match meta.receipt_context(tenant, &header) {
        Ok(ctx) => ctx,
        Err(error) => {
            reject_invalid_receipt_context(meta, &msg, acker, error).await;
            return;
        }
    };

    // 本次 claim 的租约令牌（消费方铸，uuid v4 内置于 mint）：try_claim 在 claimed 行 stamp，extend/commit/release 凭它 CAS。
    let lease = LeaseToken::mint();

    // 日志收口到 helper 控制本函数认知复杂度 ≤15（tracing 宏展开计入复杂度，同 lib.rs::dispatch_one 范式）。
    match idempotency.try_claim(&receipt_context, &key, &lease).await {
        // 后端故障：结构化 warn，不 commit；disposition 按 EngineErrorKind 分流（见 try_claim_err_action）。
        Err(e) => {
            log_try_claim_failed(&msg, &e);
            settle(
                acker,
                try_claim_err_action(&e),
                meta.domain(),
                msg.id().as_str(),
            )
            .await;
        }
        // Expected contention is not a backend error: keep it out of warn/health signals and hold
        // the delivery for a provider-derived bounded interval before requeueing.
        Ok(SeenState::InProgress) => {
            settle_claim_in_progress(acker, meta, &msg, lease_cfg).await;
        }
        // 幂等短路：不调 handler、不 commit；broker Ack（已处理过，无需再投）。
        Ok(SeenState::Duplicate) => {
            log_duplicate(&msg, meta);
            settle(
                acker,
                diport::AckAction::Ack,
                meta.domain(),
                msg.id().as_str(),
            )
            .await;
        }
        Ok(SeenState::Fresh) => {
            crate::event::scope_verified_event_origin(
                crate::event::VerifiedEventOrigin::new(parent_causation),
                handle_fresh(
                    idempotency,
                    dlx,
                    meta,
                    handler,
                    msg,
                    &receipt_context,
                    &key,
                    &lease,
                    acker,
                    lease_cfg,
                ),
            )
            .await;
        }
    }
}

#[doc(hidden)]
pub async fn settle_claim_in_progress(
    acker: Option<&diport::DynAcker<'static>>,
    meta: &ConsumerMeta,
    msg: &Message,
    lease_cfg: LeaseConfig,
) {
    let delay = claim_in_progress_delay(lease_cfg);
    metrics::counter!(
        "consumer_claim_in_progress_total",
        "domain" => meta.domain().to_owned(),
    )
    .increment(1);
    tracing::debug!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
        "consumer: active inbox claim, delaying broker requeue"
    );
    if acker.is_some() {
        tokio::time::sleep(delay).await;
    }
    settle(
        acker,
        diport::AckAction::Requeue,
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

fn claim_in_progress_delay(lease_cfg: LeaseConfig) -> Duration {
    lease_cfg.renew_interval().min(MAX_CLAIM_IN_PROGRESS_DELAY)
}

/// 首见消息：后台续租 + bounded 重投**并发**驱动（#1213，对标 gocell ConsumerBase runWithRenewal）。
///
/// `select!` 同任务并发两条 future（**无 `tokio::spawn`**——consumer future 是 `!Send`、跑在专用 OS 线程的
/// current-thread runtime，spawn 不可用；race-then-drop 即取消，契合 `!Send` 形态）：
/// - [`run_handler_loop`]：handler bounded 重投 + 终态结算（Ack→commit / Reject·耗尽→DLX）。
/// - [`renewal_loop`]：按 `lease_cfg.renew_interval` 调 `extend` 续租；租约丢失（`Lost`）即返回。
///
/// **leaseLost hard-fence**：续租侧先返回（claim 被他人 TTL 重捞）⇒ `select!` drop handler future（cancel 执行
/// 上下文）⇒ 结算 `Requeue`、**不** commit（stale holder 不双写 done，对标 gocell leaseLost→Requeue）。handler
/// 先完成 ⇒ renewal future 被 drop（停止续租）。commit 侧另有 CAS 兜底（[`commit_key`] 返 `Lost` 也降级 Requeue），
/// 覆盖「续租未及时探测、但 commit 时租约已失」的竞态窗口。
#[allow(clippy::too_many_arguments)]
// reason: 9 参数是 fresh 处理的最小必要集（idempotency/dlx/meta/handler/msg/key/lease/acker/lease_cfg 各自语义
// 独立）；聚合 struct 增间接层且不适用本模块借用生命周期，item-level carve-out。
async fn handle_fresh<S, H>(
    idempotency: &Arc<S>,
    dlx: &DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &H,
    msg: Message,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
    acker: Option<&diport::DynAcker<'static>>,
    lease_cfg: LeaseConfig,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    // owned message_id：run_handler_loop 取 msg 所有权，续租 / hard-fence 日志用 owned 串避免借用冲突。
    let message_id = msg.id().as_str().to_owned();
    // #1224：从 producer 经 outbox metadata → broker header 透传的 W3C traceparent 还原消费 span 的 remote
    // parent，使 handler span 与 producer 同 trace_id（端到端 trace 续传）。trace 键须在 msg 移入
    // run_handler_loop 前读出（同 message_id 既有范式）；缺 / 畸形 → span 保持 root（fail-open，不阻消费）。
    let consume_span = build_consume_span(meta, &message_id, msg.metadata().get(diport::KEY_TRACE));
    tokio::select! {
        // biased：双侧同时就绪时优先 handler 分支——handler 已完成（终态正确）时不误触 hard-fence；
        // commit 侧 CAS 仍兜底「续租未及时探测、commit 时租约已失」的竞态（review #279 DX）。
        biased;
        // handler 先完成：终态已在 loop 内结算；renewal future 被 drop（停止续租）。
        // `.instrument(consume_span)`：handler 全程在消费 span 内，其内部 span 挂回 producer trace（#1224）。
        () = run_handler_loop(idempotency, dlx, meta, handler, msg, ctx, key, lease, acker)
            .instrument(consume_span) => {}
        // 续租侧判租约丢失：handler future 被 drop（cancel 执行上下文），hard-fence 结算 Requeue、不 commit。
        () = renewal_loop(idempotency, meta, ctx, key, lease, lease_cfg, &message_id) => {
            log_lease_lost(meta, &message_id);
            emit_lease_lost(meta.domain());
            settle(acker, diport::AckAction::Requeue, meta.domain(), &message_id).await;
        }
    }
}

/// 构造消费 span 并（若 producer 透传了 W3C `traceparent`）还原 remote parent，使 handler span 与 producer
/// 同 `trace_id`（#1224）。`traceparent` 缺失（`None`）/ 畸形 → span 保持 root（fail-open，
/// parse rejection 不阻消费）。抽出为 helper 控制 [`handle_fresh`] 认知复杂度 ≤15。
#[doc(hidden)]
pub fn build_consume_span(
    meta: &ConsumerMeta,
    message_id: &str,
    traceparent: Option<&str>,
) -> tracing::Span {
    // OTel Messaging Semantic Conventions：consumer「process」span 用标准 `messaging.*` 属性，便于 backend
    // service-map / `messaging.operation` 过滤识别（span name 在 tracing 是静态字面量，故 destination 落字段
    // 而非 semconv 的 `{destination} {operation}` 动态名）。
    let span = tracing::info_span!(
        "outbox.consume",
        messaging.operation = "process",
        messaging.destination.name = meta.domain(),
        messaging.message.id = message_id,
    );
    if let Some(tp) = traceparent {
        restore_consume_parent(&span, tp);
    }
    span
}

fn restore_consume_parent(span: &tracing::Span, traceparent: &str) {
    match tracewire::TraceParent::parse(traceparent)
        .map(|parent| tracewire::restore_remote_parent(span, &parent, None))
    {
        Ok(tracewire::RestoreOutcome::Restored) => {}
        Ok(tracewire::RestoreOutcome::Unavailable) => observe_consume_trace_attach_unavailable(),
        Err(reason) => observe_consume_trace_rejection(reason),
    }
}

fn observe_consume_trace_attach_unavailable() {
    tracing::debug!(
        target: "rss.trace_context",
        transport = "broker",
        operation = "process",
        reason = "attach_unavailable",
        "remote trace parent attach unavailable"
    );
}

fn observe_consume_trace_rejection(reason: tracewire::TraceParentError) {
    tracing::debug!(
        target: "rss.trace_context",
        transport = "broker",
        operation = "process",
        reason = %reason,
        "remote trace parent rejected"
    );
}

/// 续租循环（#1213）：每 `lease_cfg.renew_interval` 调 [`consistency::InboxStore::extend`]。
///
/// `Held`→继续持有（**不返回**，由 `select!` 在 handler 完成时 drop）；`Lost`→**返回**（claim 被他人重捞，触发
/// [`handle_fresh`] 的 hard-fence 分支取消 handler）；`Err`（瞬态后端故障）→结构化 warn + 续命（不误判丢租，
/// handler 完成时由 commit 侧 CAS 兜底判终态）。
#[doc(hidden)]
pub async fn renewal_loop<S>(
    idempotency: &Arc<S>,
    meta: &ConsumerMeta,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
    lease_cfg: LeaseConfig,
    message_id: &str,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
{
    loop {
        tokio::time::sleep(lease_cfg.renew_interval()).await;
        match idempotency.extend(ctx, key, lease).await {
            // 续租成功：继续持有租约。
            Ok(LeaseOutcome::Held) => {}
            // 租约丢失：返回 → select hard-fence 分支取消 handler。
            Ok(LeaseOutcome::Lost) => return,
            // 瞬态续租故障：续命重试（commit 侧 CAS 兜底，不误判丢租）。
            Err(e) => log_extend_failed(meta, message_id, &e),
            // reason: LeaseOutcome 是 #[non_exhaustive]；未知变体保守续命（同 Err 路径，commit 侧 CAS 兜底）+
            // warn 可观测；commit 侧 CAS 继续提供最终围栏。
            Ok(_) => log_unknown_lease_outcome(meta, message_id),
        }
    }
}

/// handler bounded 重投 + 终态结算（原 `handle_fresh` 主体，#1213 抽出为 `select!` 一臂）。
///
/// bounded 重投：handler 至多 [`MAX_REDELIVERY`] 次；`Ack`→commit（CAS）成功才 broker Ack、否则 Requeue
/// （守「ack only after durable commit」review #265 F1/C1，且 commit `Lost` 即 leaseLost hard-fence）；
/// `Reject`→DLX；`Requeue` 耗尽→DLX。
#[allow(clippy::too_many_arguments)]
// reason: 8 参数语义独立（idempotency/dlx/meta/handler/msg/key/lease/acker），聚合 struct 增间接层，item-level carve-out。
async fn run_handler_loop<S, H>(
    idempotency: &Arc<S>,
    dlx: &DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &H,
    msg: Message,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
    acker: Option<&diport::DynAcker<'static>>,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync,
{
    // requeue 路径记下最近一次 error kind 摘要，耗尽时随 DLX 落日志（#1125/#1285）。
    // Settled 闭合穷尽：仅 `Requeue` 续循环，故耗尽出口恒有摘要（Hard）。
    let mut last_requeue_summary: Option<&'static str> = None;
    // 含首投在内至多 MAX_REDELIVERY 次（bounded，对齐 watermill retry.go MaxRetries+1 次尝试）。
    for attempt in 1..=MAX_REDELIVERY {
        let result = handler(msg.clone()).await;
        match result.as_settled() {
            consistency::Settled::Ack => {
                // 仅 commit（幂等 done 标记，CAS 守租约）成功才 broker Ack；commit 失败 / 租约丢失 → Requeue
                // （不移除投递，待 broker 重投后幂等去重收口），守「ack only after durable commit」（review #265 F1/C1）。
                let action =
                    if commit_key(idempotency, meta, ctx, key, lease, msg.id().as_str()).await {
                        diport::AckAction::Ack
                    } else {
                        diport::AckAction::Requeue
                    };
                settle(acker, action, meta.domain(), msg.id().as_str()).await;
                return;
            }
            consistency::Settled::Reject { kind } => {
                dead_letter(
                    dlx,
                    idempotency,
                    ctx,
                    key,
                    lease,
                    meta,
                    &msg,
                    attempt,
                    kind.message(),
                    acker,
                    None,
                )
                .await;
                return;
            }
            consistency::Settled::Requeue { summary } => {
                // 记下本轮 requeue 的 error kind 摘要；耗尽时随 DLX 落日志（#1125/#1285）。
                last_requeue_summary = Some(summary);
            }
        }
    }
    // Requeue 预算耗尽 → DLX（num_attempts = MAX_REDELIVERY 次全部尝试）。
    // INVARIANT: Settled 闭合 + 仅 Requeue 续循环 ⇒ 此处 `last_requeue_summary` 恒 Some。
    #[allow(clippy::expect_used)]
    // reason: 穷尽 Settled 下不可达 None；expect 守逻辑 bug，非业务 fallback（error-handling.md §Carve-out）。
    let exhausted_summary =
        last_requeue_summary.expect("requeue budget exit implies Settled::Requeue summary");
    dead_letter(
        dlx,
        idempotency,
        ctx,
        key,
        lease,
        meta,
        &msg,
        MAX_REDELIVERY,
        exhausted_summary,
        acker,
        None,
    )
    .await;
}

/// commit key（claimed→done，token CAS）：返回 commit 是否成功（`true` 仅当 `LeaseOutcome::Held`）。
///
/// 返回值 gate broker Ack 决策（review #265 F1/C1）：commit 失败**不可**移除 broker 投递——
/// handler-Ack / DLX-写成功两条终态仅在 commit `Held` 后 broker `Ack`，否则转 `Requeue`：
/// - `Ok(Lost)`：**leaseLost hard-fence**——claim 已被他人 TTL 重捞（CAS 0 行），不双写 done，降级 Requeue（#1213）。
/// - `Err`：瞬态后端故障——done 标记未持久，降级 Requeue，待 broker 重投经幂等去重收口。
// 日志收口到 helper 控制 commit_key 认知复杂度 ≤15（tracing 宏展开计入复杂度，同 dead_letter 范式）。
pub(crate) async fn commit_key<S>(
    idempotency: &Arc<S>,
    meta: &ConsumerMeta,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
    message_id: &str,
) -> bool
where
    S: consistency::InboxStore + Send + Sync + 'static,
{
    match idempotency.commit(ctx, key, lease).await {
        Ok(LeaseOutcome::Held) => true,
        // leaseLost hard-fence：commit 期租约已被重捞 → 不 Ack、降级 Requeue（stale holder 不双写 done）。
        Ok(LeaseOutcome::Lost) => {
            log_commit_lost(meta, message_id);
            emit_lease_lost(meta.domain());
            false
        }
        Err(e) => {
            log_commit_failed(meta, message_id, &e);
            false
        }
        // reason: LeaseOutcome 是 #[non_exhaustive]；未知变体保守降级 Requeue（不 Ack 未确认的 done）。
        Ok(_) => false,
    }
}

/// release key（claimed→absent，token CAS）：dlx 写失败时调用，使 broker 重投时 try_claim 回 Fresh。
/// 令牌不符（claim 已被重捞）为 no-op（不误删他人 claim）。错误结构化 error 日志（不 panic）。
pub(crate) async fn release_key<S>(
    idempotency: &Arc<S>,
    meta: &ConsumerMeta,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
    message_id: &str,
) -> bool
where
    S: consistency::InboxStore + Send + Sync + 'static,
{
    match idempotency.release(ctx, key, lease).await {
        Ok(()) => true,
        Err(e) => {
            emit_release_failed(meta.domain());
            tracing::error!(
                message_id,
                domain = meta.domain(),
                contract_id = meta.contract_id(),
                topic = meta.topic(),
                error = %e,
                "consumer: idempotency release failed after dlx write error"
            );
            false
        }
    }
}

/// 死信路径：
/// 1. 结构化 `error!`（T007.5：domain/contract_id/topic/num_attempts/error_summary 五字段，含 message_id）。
/// 2. `dlx.write_dead_letter(record)`。
/// 3. dlx **写成功** → `idempotency.commit(key)`（标记 done，终态收口）+ broker `Ack`；
///    dlx **写失败** → `idempotency.release(key)`（claimed→absent，使 broker 重投时 try_claim 回 Fresh）；
///    release 成功才 broker `Requeue`，release 也失败则按 eventbus fail-closed 真源 broker `Reject`。
///
/// 各步错误结构化 error 日志（不 panic）。
///
/// `error_summary` 是安全摘要：`&'static str` const（Requeue 直接携带；Reject 由 typed kind 在
/// ConsumerBase funnel 映射为稳定 message），不含 handler error/payload 原文。PII-safe（const literal，无 runtime 数据），下游
/// `DeadLetterSummary::new` 仍强制 const 收口。
#[allow(clippy::too_many_arguments)]
// reason: 9 参数是 DLX 路径的最小必要集合（dlx/idempotency/key/lease/meta/msg/attempts/summary/acker 各自语义独立）；
// 引入聚合 struct 会增加间接层且不适用于本模块的借用生命周期，item-level carve-out。
#[doc(hidden)]
pub async fn dead_letter<S>(
    dlx: &DynDeadLetterStore<'static>,
    idempotency: &Arc<S>,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
    meta: &ConsumerMeta,
    msg: &Message,
    num_attempts: u32,
    error_summary: &'static str,
    acker: Option<&diport::DynAcker<'static>>,
    terminal: Option<&tokio_util::sync::CancellationToken>,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
{
    // T007.5：结构化 error，五字段全部出现（domain/contract_id/topic/num_attempts/error_summary）；
    // message_id 额外提供关联维度（DLX 表无该列，log 是唯一关联路径）。
    // 日志收口到 helper 控制本函数认知复杂度 ≤15（tracing 宏展开计入复杂度，同 lib.rs 范式）。
    log_dead_lettered(meta, num_attempts, error_summary, msg.id().as_str());

    let record = DeadLetterRecord::new(
        ctx.tenant_id(),
        msg.id().as_str(),
        DeadLetterProvenance::consumer(meta.authority_domain(), meta.domain()),
        meta.contract_id(),
        meta.topic(),
        Some(meta.consumer_group().to_string()),
        msg.payload().as_bytes().to_vec(),
        // 类型层收口：摘要只能是编译期 const literal（SUMMARY_* 常量），不可由 runtime 数据伪造
        // （review #216 F7，INVARIANT DIPORT-DLX-SUMMARY-STATIC-01）。
        DeadLetterSummary::new(error_summary),
        num_attempts,
        msg.metadata().clone(),
    );

    match dlx.write_dead_letter(record).await {
        Ok(()) => {
            // dlx 写成功 → commit（标记 done）。仅 commit 成功才 broker Ack；commit 失败 → Requeue
            // （DLX 已落但 done 标记未持久，重投经幂等 Duplicate 收口，守「ack only after durable commit」F1/C1）。
            let action = if commit_key(idempotency, meta, ctx, key, lease, msg.id().as_str()).await
            {
                if let Some(terminal) = terminal {
                    terminal.cancel();
                }
                diport::AckAction::Ack
            } else {
                diport::AckAction::Requeue
            };
            settle(acker, action, meta.domain(), msg.id().as_str()).await;
        }
        Err(e) => {
            // dlx 写失败 → release（claimed→absent，token CAS），使 broker 重投时 try_claim 回 Fresh、
            // 重新尝试 DLX，避免静默丢失（消息进 done + 死信未落 DB = 不可恢复审计盲点）。
            log_dlx_write_failed(meta, &e);
            // release 失败时无法证明后续重投能重新取得 claim；按 eventbus 真源 fail closed 到 Reject，
            // 并由 release-failed 指标告警，避免围绕 60s active lease 热循环。
            let released = release_key(idempotency, meta, ctx, key, lease, msg.id().as_str()).await;
            settle(
                acker,
                if released {
                    diport::AckAction::Requeue
                } else {
                    diport::AckAction::Reject
                },
                meta.domain(),
                msg.id().as_str(),
            )
            .await;
        }
    }
}

/// 向 broker settle 本条投递（ack / requeue / reject）+ 发结算 metric。
///
/// `acker = None` 是 brokerless / MemBus 路径（`run_consumer`），noop（无 broker、不发 metric）。
/// `acker = Some(a)` 是 at-least-once 路径（`run_consumer_ackable`）：结算失败仅结构化 error 日志（不 panic），
/// 并发 `consumer_settle_total{domain,action,outcome}` counter 供告警（review #265 F3/C3）——闭值集 label：
/// `action`=[`diport::AckAction::as_label`]、`outcome`=`ok|error`、`domain` 由 [`ConsumerMeta`] 封边。
///
/// metric 形态：minimal 直发 `metrics` facade（无 recorder 即 no-op，对齐 `relay_metrics::MetricsOutboxMetrics`
/// 的底层发射）；注入式 `ConsumerMetrics` port（与 `OutboxMetrics` 同形、组合根注入）属重构，随 consumer worker
/// 生命周期落地（follow-up #1301）。
///
/// `error = %e` 安全前提：`AckError::Display` 是 const literal `"ack settle failed"`，不携 runtime 数据
/// （见 `diport::AckError` rustdoc，INVARIANT DIPORT-ERR-SOURCE-REDACT-01）。
#[doc(hidden)]
pub async fn settle(
    acker: Option<&diport::DynAcker<'static>>,
    action: diport::AckAction,
    domain: &str,
    message_id: &str,
) {
    let Some(a) = acker else { return };
    let outcome = match a.settle(action).await {
        Ok(()) => "ok",
        Err(e) => {
            tracing::error!(
                message_id,
                action = action.as_label(),
                error = %e,
                "consumer: broker settle failed"
            );
            "error"
        }
    };
    // 闭值集 label：domain 由 ConsumerMeta 封边、action/outcome 编译期闭集；domain 在发射处才降 owned String。
    metrics::counter!(
        "consumer_settle_total",
        "domain" => domain.to_owned(),
        "action" => action.as_label(),
        "outcome" => outcome,
    )
    .increment(1);
}

/// DLX skip metric for fail-closed paths where the app DLX write is intentionally suppressed.
///
/// Closed labels: `reason` is emitted from module-owned literals; `domain` is bounded by `ConsumerMeta`.
/// This keeps alerts separate from broker settle metrics, which only describe final broker disposition.
#[doc(hidden)]
pub fn record_dead_letter_skip(meta: &ConsumerMeta, reason: &'static str) {
    metrics::counter!(
        "consumer_dlx_skip_total",
        "domain" => meta.domain().to_owned(),
        "reason" => reason,
    )
    .increment(1);
}

async fn reject_invalid_envelope_header(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
    error: &EnvelopeHeaderError,
) {
    let reason = envelope_header_error_reason(error);
    record_dead_letter_skip(meta, reason);
    log_invalid_envelope_header(meta, msg, reason, error);
    settle(
        acker,
        diport::AckAction::Reject,
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

async fn reject_invalid_tenant_authority(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
    error: TenantAuthorityError,
) {
    record_dead_letter_skip(meta, error.skip_reason());
    log_dead_letter_tenant_authority_failed(meta, msg.id().as_str(), error);
    settle(
        acker,
        diport::AckAction::Reject,
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

async fn reject_invalid_receipt_context(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
    error: ReceiptContextBuildError,
) {
    let reason = receipt_context_error_reason(error);
    record_dead_letter_skip(meta, reason);
    log_invalid_receipt_context(meta, msg, reason);
    settle(
        acker,
        diport::AckAction::Reject,
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

#[doc(hidden)]
pub fn envelope_header_error_reason(error: &EnvelopeHeaderError) -> &'static str {
    match error {
        EnvelopeHeaderError::MissingTenantId => "envelope_missing_tenant_id",
        EnvelopeHeaderError::InvalidTenantId => "envelope_invalid_tenant_id",
        EnvelopeHeaderError::MissingSchemaVersion => "envelope_missing_schema_version",
        EnvelopeHeaderError::InvalidSchemaVersion => "envelope_invalid_schema_version",
        EnvelopeHeaderError::MissingSchemaHash => "envelope_missing_schema_hash",
        EnvelopeHeaderError::InvalidSchemaHash => "envelope_invalid_schema_hash",
        EnvelopeHeaderError::SchemaVersionMismatch => "envelope_schema_version_mismatch",
        EnvelopeHeaderError::SchemaHashMismatch => "envelope_schema_hash_mismatch",
    }
}

#[doc(hidden)]
pub fn receipt_context_error_reason(error: ReceiptContextBuildError) -> &'static str {
    match error {
        ReceiptContextBuildError::ConsumerGroup => "inbox_receipt_invalid_consumer_group",
        ReceiptContextBuildError::Receipt(InboxReceiptContextError::EmptyDomain) => {
            "inbox_receipt_empty_domain"
        }
        ReceiptContextBuildError::Receipt(InboxReceiptContextError::EmptyTopic) => {
            "inbox_receipt_empty_topic"
        }
        ReceiptContextBuildError::Receipt(InboxReceiptContextError::EmptyContractId) => {
            "inbox_receipt_empty_contract_id"
        }
        ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidContractVersion) => {
            "inbox_receipt_invalid_contract_version"
        }
        ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidSchemaHash) => {
            "inbox_receipt_invalid_schema_hash"
        }
        ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidTrace) => {
            "inbox_receipt_invalid_trace"
        }
        ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidCorrelationId) => {
            "inbox_receipt_invalid_correlation_id"
        }
        ReceiptContextBuildError::Receipt(_) => "inbox_receipt_invalid_context",
    }
}

// ── 日志 helper（tracing 宏收口，控制调用方认知复杂度 ≤15；同 lib.rs::log_dropped_* 范式）──

/// IdemKey parse 失败（malformed id，fail-closed 不重投）。
fn log_parse_failed(msg: &Message) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        // 处置随路径：ackable 路径 settle(Reject)（→broker DLX，不无限重投）；brokerless 路径丢弃。
        "consumer: IdemKey parse failed (malformed), rejected to broker DLX (dropped if brokerless)"
    );
}

/// 幂等 try_claim 后端故障（不 commit；disposition 由 [`try_claim_err_action`] 按 kind 决定）。
///
/// `error = %error` 安全前提：`consistency::EngineError` 的 `Display` 实现恒为 const literal
/// （不携 runtime 数据，见 `consistency::error` invariant）。若未来 `EngineError` 新增携
/// runtime 数据的变体，此处须改走 `secure::redact_error` funnel。
fn log_try_claim_failed(msg: &Message, error: &consistency::error::EngineError) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        error = %error,
        "consumer: idempotency try_claim failed"
    );
}

/// try_claim 后端故障 → broker 结算动作：`Transient` 重投（`Requeue`），其余（`Permanent`/`Invariant`）
/// hard-fence 到 DLX（`Reject`）。避免永久错误（如 redis 鉴权/协议配置错，`classify_redis_error` 归
/// `Permanent`）无限重投不收敛（#1354 review F2）。`is_transient` 是「可重试」单一判据
/// （`consistency::error`），非-Transient 一律 fail-closed 到 `Reject`。
fn try_claim_err_action(error: &consistency::error::EngineError) -> diport::AckAction {
    if error.is_transient() {
        diport::AckAction::Requeue
    } else {
        diport::AckAction::Reject
    }
}

/// 幂等短路（已见，跳过）。
fn log_duplicate(msg: &Message, meta: &ConsumerMeta) {
    tracing::debug!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        "consumer: duplicate message, skipping"
    );
}

fn log_invalid_envelope_header(
    meta: &ConsumerMeta,
    msg: &Message,
    reason: &'static str,
    error: &EnvelopeHeaderError,
) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        reason,
        error = %error,
        "consumer: standard envelope header invalid, rejected before handler"
    );
}

fn log_invalid_receipt_context(meta: &ConsumerMeta, msg: &Message, reason: &'static str) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        reason,
        "consumer: inbox receipt context invalid, rejected before claim"
    );
}

/// T007.5：死信结构化 error（五字段：domain/contract_id/topic/num_attempts/error_summary；
/// 加 message_id 提供关联维度——DLX 表无该列，log 是唯一关联路径）。
fn log_dead_lettered(
    meta: &ConsumerMeta,
    num_attempts: u32,
    error_summary: &'static str,
    message_id: &str,
) {
    tracing::error!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        num_attempts,
        error_summary,
        "consumer: message dead-lettered"
    );
}

/// DLX tenant authority 缺失 / 非法：不写 app DLX，避免把不可信 tenant 落入持久层。
fn log_dead_letter_tenant_authority_failed(
    meta: &ConsumerMeta,
    message_id: &str,
    error: TenantAuthorityError,
) {
    tracing::warn!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        reason = error.skip_reason(),
        "consumer: dead-letter skipped because tenant authority is missing or invalid"
    );
}

/// DLX 写入失败（结构化 error，原始错误经 Display 安全摘要）。
fn log_dlx_write_failed(meta: &ConsumerMeta, error: &DeadLetterStoreError) {
    tracing::error!(
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        error = %error,
        "consumer: dead letter write failed"
    );
}

/// leaseLost hard-fence（#1213）：续租侧探测租约被他人 TTL 重捞 → handler 被取消、结算降级 Requeue。
#[doc(hidden)]
pub fn log_lease_lost(meta: &ConsumerMeta, message_id: &str) {
    tracing::warn!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        "consumer: lease lost during handler, cancelled and requeued (hard-fence)"
    );
}

/// 续租瞬态故障（#1213）：`extend` 返 `Err`（后端暂不可用）→ 续命重试（不误判丢租，commit 侧 CAS 兜底）。
///
/// `error = %error` 安全前提同 [`log_try_claim_failed`]：`EngineError` 的 `Display` 恒为 const literal。
fn log_extend_failed(
    meta: &ConsumerMeta,
    message_id: &str,
    error: &consistency::error::EngineError,
) {
    tracing::warn!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        error = %error,
        "consumer: lease extend failed (transient), will retry next interval"
    );
}

/// 续租返回未知 `LeaseOutcome` 变体（`#[non_exhaustive]` 兜底 warn，保守续命；commit 侧 CAS 判终态，#1213）。
fn log_unknown_lease_outcome(meta: &ConsumerMeta, message_id: &str) {
    tracing::warn!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        "consumer: unknown LeaseOutcome variant in renewal, conservatively continuing (commit CAS backstops)"
    );
}

/// commit 期租约丢失 warn（hard-fence → stale holder 不双写 done，降级 Requeue，#1213）。
///
/// `message_id` 无 PII（不携 payload）；收口到 helper 控制 [`commit_key`] 认知复杂度 ≤15。
fn log_commit_lost(meta: &ConsumerMeta, message_id: &str) {
    tracing::warn!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        "consumer: idempotency commit lost lease (hard-fence → requeue)"
    );
}

/// commit 瞬态后端故障 error（done 标记未持久 → 降级 Requeue，待 broker 重投经幂等去重收口）。
///
/// `error = %error` 安全前提同 [`log_try_claim_failed`]：`EngineError` 的 `Display` 恒为 const literal。
fn log_commit_failed(
    meta: &ConsumerMeta,
    message_id: &str,
    error: &consistency::error::EngineError,
) {
    tracing::error!(
        message_id,
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        error = %error,
        "consumer: idempotency commit failed"
    );
}

/// leaseLost 事件 counter（#1213，review #279 运维）：续租侧 + commit 侧 hard-fence 触发点均 +1，供独立
/// 告警（与聚合的 `consumer_settle_total{action=requeue}` 区分——后者混合多种 requeue 原因）。
///
/// 闭值集 label：`domain` 由 [`ConsumerMeta`] 封边（发射处才降 owned String）。minimal 直发 `metrics` facade
/// （无 recorder 即 no-op，同 `consumer_settle_total` 范式；注入式 port 随 consumer worker 生命周期 #1301）。
#[doc(hidden)]
pub fn emit_lease_lost(domain: &str) {
    metrics::counter!(
        "consumer_lease_lost_total",
        "domain" => domain.to_owned(),
    )
    .increment(1);
}

/// release 失败事件 counter：DLX 写失败后 claim 可能仍存活，该指标驱动告警；
/// 该双失败路径按 eventbus 真源 Reject，指标驱动持久化/DLX 故障告警。
fn emit_release_failed(domain: &str) {
    metrics::counter!(
        "consumer_release_failed_total",
        "domain" => domain.to_owned(),
    )
    .increment(1);
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use consistency::HandleResult;
    use consistency::idempotency::{IdemKey, LeaseOutcome, LeaseToken, SeenState};
    use consistency::{InboxReceiptContext, InboxReceiptContextError, InboxStore};
    use diport::dead_letter_store::{
        DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore,
    };
    use diport::{AckAction, Acker, DeliveryStream, DynAcker};
    use diport::{
        EnvelopeMetadata, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_TENANT_AUTHORITY, KEY_TENANT_ID,
        Message,
    };
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

    use super::{
        ConsumerMeta, LeaseConfig, ReceiptContextBuildError, claim_in_progress_delay,
        receipt_context_error_reason, record_dead_letter_skip, run_consumer, run_consumer_ackable,
    };
    use crate::MAX_REDELIVERY;
    use crate::tenant_authority::{TenantAuthority, TenantAuthorityBinding};

    /// 测试用 lease 配置：续租间隔大（60s/3=20s），普通快测中续租永不触发（不干扰原终态断言）。
    fn lease_cfg_test() -> LeaseConfig {
        LeaseConfig::from_ttl(Duration::from_secs(60))
    }

    /// 测试用 lease 配置（快续租）：续租间隔小，长 handler 测试中续租可在毫秒级触发。
    fn lease_cfg_fast() -> LeaseConfig {
        LeaseConfig::from_ttl(Duration::from_millis(15))
    }

    fn consumer_admission() -> primitives::ConsumerAdmission {
        let (control, _, consumer, _) = primitives::prepare_dr_admission_controls().into_parts();
        assert!(control.start_running().is_ok());
        consumer
    }

    #[test]
    fn in_progress_delay_is_provider_derived_and_capped() {
        assert_eq!(
            claim_in_progress_delay(LeaseConfig::from_ttl(Duration::from_secs(60))),
            Duration::from_secs(20)
        );
        assert_eq!(
            claim_in_progress_delay(LeaseConfig::from_ttl(Duration::from_secs(300))),
            Duration::from_secs(30)
        );
    }

    // ── 工厂 helper ──────────────────────────────────────────────────────────

    const SCHEMA_HASH: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// 构造单条消息流（复用 lib.rs 范式）。
    fn stream_of(payloads: &[(&str, &[u8])]) -> diport::MessageStream {
        let msgs: Vec<Message> = payloads.iter().map(|(id, p)| message(id, p)).collect();
        Box::pin(futures::stream::iter(msgs))
    }

    #[derive(Debug)]
    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut tag = Vec::from(key.as_bytes());
            tag.extend_from_slice(message);
            Mac::from_bytes(tag)
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn tenant_authority() -> Arc<TenantAuthority> {
        Arc::new(
            TenantAuthority::new(
                Arc::new(TestMac),
                MacKey::from_bytes(vec![0x42; 32]),
                60,
                5,
                Arc::new(|| 1_700_000_000),
            )
            .expect("valid tenant authority"),
        )
    }

    fn insert_schema_header(md: &mut EnvelopeMetadata) {
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, SCHEMA_HASH);
    }

    #[allow(clippy::expect_used)]
    fn tenant_authority_metadata_for(
        message_id: &str,
        domain: &str,
        contract_id: &str,
        topic: &str,
    ) -> EnvelopeMetadata {
        let mut md = EnvelopeMetadata::empty();
        let authority = tenant_authority();
        let token = authority
            .sign(TenantAuthorityBinding::new(
                tenant(),
                domain,
                contract_id,
                topic,
                message_id,
            ))
            .expect("tenant authority test signing cannot fail");
        md.insert_wire_pair(KEY_TENANT_ID, tenant().to_string());
        md.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
        md
    }

    fn tenant_authority_metadata(message_id: &str) -> EnvelopeMetadata {
        tenant_authority_metadata_for(
            message_id,
            "identity",
            "contract-session",
            "session.created",
        )
    }

    fn tenant_metadata_for(
        message_id: &str,
        domain: &str,
        contract_id: &str,
        topic: &str,
    ) -> EnvelopeMetadata {
        let mut md = tenant_authority_metadata_for(message_id, domain, contract_id, topic);
        insert_schema_header(&mut md);
        md
    }

    fn tenant_metadata(message_id: &str) -> EnvelopeMetadata {
        tenant_metadata_for(
            message_id,
            "identity",
            "contract-session",
            "session.created",
        )
    }

    fn message(id: &str, payload: &[u8]) -> Message {
        Message::new_with_metadata(id, payload.to_vec(), tenant_metadata(id))
    }

    fn meta() -> ConsumerMeta {
        ConsumerMeta::new(
            "identity",
            "identity",
            "contract-session",
            "session.created",
            "identity.session.consumer",
            tenant_authority(),
        )
        .with_expected_schema("v1", SCHEMA_HASH)
    }

    fn cross_domain_meta() -> ConsumerMeta {
        ConsumerMeta::new(
            "audit",
            "identity",
            "contract-session",
            "session.created",
            "audit.session-created",
            tenant_authority(),
        )
        .with_expected_schema("v1", SCHEMA_HASH)
    }

    // ── FakeInboxStore ─────────────────────────────────────────────────

    /// 三态 fake store（Arc<Mutex> + Atomic，Send 友好，不跨 await 持锁——relay.rs FakeStore 范式）。
    /// 可配 try_claim 返 Fresh / InProgress / Duplicate / Err；commit 可配 Err / Lost；extend 可配 N 次后 Lost；
    /// 记录 try_claim / commit / release / extend 调用计数。
    #[derive(Clone, Copy)]
    enum CheckResult {
        Fresh,
        InProgress,
        Duplicate,
        Err(consistency::error::EngineErrorKind),
    }

    struct FakeInboxStore {
        check_result: CheckResult,
        claim_count: AtomicU32,
        commit_count: AtomicU32,
        release_count: AtomicU32,
        extend_count: AtomicU32,
        /// commit 恒失败 Err（F1：测 commit 瞬态失败 → broker Requeue 不 Ack）。
        commit_fails: bool,
        /// commit 恒返 `LeaseOutcome::Lost`（#1213 commit 侧 hard-fence：租约丢失 → Requeue 不 Ack）。
        commit_loses_lease: bool,
        /// release 恒失败 Err（DLX 写失败 + release 失败按真源 Reject，并发射告警指标）。
        release_fails: bool,
        /// extend 在前 N 次返 `Held`、第 N+1 次起返 `Lost`（#1213 续租侧 hard-fence：模拟 handler 执行中租约被重捞）。
        extend_lost_after: Option<u32>,
        /// extend 前 N 次返 `Err`（瞬态后端故障，模拟续租抖动）；之后按 `extend_lost_after` 判定。
        extend_errs_before: u32,
        captured_contexts: Mutex<Vec<InboxReceiptContext>>,
    }

    impl FakeInboxStore {
        fn with(check_result: CheckResult, commit_fails: bool) -> Arc<Self> {
            Arc::new(Self {
                check_result,
                claim_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
                extend_count: AtomicU32::new(0),
                commit_fails,
                commit_loses_lease: false,
                release_fails: false,
                extend_lost_after: None,
                extend_errs_before: 0,
                captured_contexts: Mutex::new(Vec::new()),
            })
        }

        fn fresh() -> Arc<Self> {
            Self::with(CheckResult::Fresh, false)
        }

        fn duplicate() -> Arc<Self> {
            Self::with(CheckResult::Duplicate, false)
        }

        fn in_progress() -> Arc<Self> {
            Self::with(CheckResult::InProgress, false)
        }

        fn err() -> Arc<Self> {
            Self::with(
                CheckResult::Err(consistency::error::EngineErrorKind::Transient),
                false,
            )
        }

        /// try_claim 返**永久** Err（Permanent，如 redis 鉴权/协议错误经 `classify_redis_error`）——
        /// 验消费侧按 `EngineError::is_transient` 分流到 `Reject`（→DLX，不无限重投），C2/#1354 review F2。
        fn err_permanent() -> Arc<Self> {
            Self::with(
                CheckResult::Err(consistency::error::EngineErrorKind::Permanent),
                false,
            )
        }

        /// Fresh try_claim + commit 恒 Err（F1/C1：commit 瞬态失败终态须 broker Requeue、不可 Ack）。
        fn fresh_commit_fails() -> Arc<Self> {
            Self::with(CheckResult::Fresh, true)
        }

        /// Fresh try_claim + commit 恒 `Lost`（#1213：commit 侧 leaseLost hard-fence → Requeue 不 Ack）。
        fn fresh_commit_loses_lease() -> Arc<Self> {
            Arc::new(Self {
                check_result: CheckResult::Fresh,
                claim_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
                extend_count: AtomicU32::new(0),
                commit_fails: false,
                commit_loses_lease: true,
                release_fails: false,
                extend_lost_after: None,
                extend_errs_before: 0,
                captured_contexts: Mutex::new(Vec::new()),
            })
        }

        /// Fresh try_claim + extend 第 `n+1` 次起返 `Lost`（#1213：续租侧 leaseLost hard-fence）。
        fn fresh_lease_lost_after(n: u32) -> Arc<Self> {
            Arc::new(Self {
                check_result: CheckResult::Fresh,
                claim_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
                extend_count: AtomicU32::new(0),
                commit_fails: false,
                commit_loses_lease: false,
                release_fails: false,
                extend_lost_after: Some(n),
                extend_errs_before: 0,
                captured_contexts: Mutex::new(Vec::new()),
            })
        }

        /// Fresh try_claim + extend 前 `n` 次返 `Err`（瞬态续租故障），之后 `Held`（#1213：续租 Err 臂续命语义）。
        fn fresh_extend_errs_then_held(n: u32) -> Arc<Self> {
            Arc::new(Self {
                check_result: CheckResult::Fresh,
                claim_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
                extend_count: AtomicU32::new(0),
                commit_fails: false,
                commit_loses_lease: false,
                release_fails: false,
                extend_lost_after: None,
                extend_errs_before: n,
                captured_contexts: Mutex::new(Vec::new()),
            })
        }

        #[allow(dead_code)]
        // reason: test helper 对称于 commit_count / release_count / extend_count；cfg(test) 内未用但保留
        // 供后续 try_claim 次数断言测试用。
        fn claim_count(&self) -> u32 {
            self.claim_count.load(Ordering::Acquire)
        }

        fn commit_count(&self) -> u32 {
            self.commit_count.load(Ordering::Acquire)
        }

        fn release_count(&self) -> u32 {
            self.release_count.load(Ordering::Acquire)
        }

        fn fresh_release_fails() -> Arc<Self> {
            Arc::new(Self {
                check_result: CheckResult::Fresh,
                claim_count: AtomicU32::new(0),
                commit_count: AtomicU32::new(0),
                release_count: AtomicU32::new(0),
                extend_count: AtomicU32::new(0),
                commit_fails: false,
                commit_loses_lease: false,
                release_fails: true,
                extend_lost_after: None,
                extend_errs_before: 0,
                captured_contexts: Mutex::new(Vec::new()),
            })
        }

        fn extend_count(&self) -> u32 {
            self.extend_count.load(Ordering::Acquire)
        }

        fn capture_context(&self, ctx: &InboxReceiptContext) {
            self.captured_contexts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ctx.clone());
        }

        fn captured_contexts(&self) -> Vec<InboxReceiptContext> {
            self.captured_contexts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl InboxStore for FakeInboxStore {
        async fn try_claim(
            &self,
            ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<SeenState, consistency::error::EngineError> {
            self.capture_context(ctx);
            self.claim_count.fetch_add(1, Ordering::Release);
            match self.check_result {
                CheckResult::Fresh => Ok(SeenState::Fresh),
                CheckResult::InProgress => Ok(SeenState::InProgress),
                CheckResult::Duplicate => Ok(SeenState::Duplicate),
                CheckResult::Err(kind) => Err(consistency::error::EngineError::new(kind)),
            }
        }

        async fn extend(
            &self,
            ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, consistency::error::EngineError> {
            self.capture_context(ctx);
            let n = self.extend_count.fetch_add(1, Ordering::Release) + 1;
            // 前 extend_errs_before 次返 Err（瞬态续租故障：不误判丢租，续命重试）。
            if n <= self.extend_errs_before {
                return Err(consistency::error::EngineError::new(
                    consistency::error::EngineErrorKind::Transient,
                ));
            }
            // 前 N 次 Held，第 N+1 次起 Lost（模拟 handler 执行中租约被他人 TTL 重捞）。
            match self.extend_lost_after {
                Some(threshold) if n > threshold => Ok(LeaseOutcome::Lost),
                _ => Ok(LeaseOutcome::Held),
            }
        }

        async fn commit(
            &self,
            ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, consistency::error::EngineError> {
            self.capture_context(ctx);
            self.commit_count.fetch_add(1, Ordering::Release);
            if self.commit_fails {
                return Err(consistency::error::EngineError::new(
                    consistency::error::EngineErrorKind::Transient,
                ));
            }
            // commit 侧 leaseLost hard-fence：租约已被重捞 → Lost（消费方降级 Requeue）。
            if self.commit_loses_lease {
                return Ok(LeaseOutcome::Lost);
            }
            Ok(LeaseOutcome::Held)
        }

        async fn release(
            &self,
            ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<(), consistency::error::EngineError> {
            self.capture_context(ctx);
            self.release_count.fetch_add(1, Ordering::Release);
            if self.release_fails {
                return Err(consistency::error::EngineError::new(
                    consistency::error::EngineErrorKind::Transient,
                ));
            }
            Ok(())
        }
    }

    // ── FakeDeadLetterStore ──────────────────────────────────────────────────

    /// fake DLX store：捕获写入的 DeadLetterRecord 字段。
    #[derive(Clone)]
    struct CapturedDlxRecord {
        tenant_id: String,
        message_id: String,
        producer_domain: String,
        consumer_domain: Option<String>,
        consumer_group: Option<String>,
        error_summary: String,
        num_attempts: u32,
    }

    struct FakeDeadLetterStore {
        written: Mutex<Vec<CapturedDlxRecord>>,
    }

    impl FakeDeadLetterStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                written: Mutex::new(vec![]),
            })
        }

        fn write_count(&self) -> usize {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 happy-path，item-level carve-out
            self.written.lock().unwrap().len()
        }

        fn last_record(&self) -> Option<CapturedDlxRecord> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 happy-path，item-level carve-out
            self.written.lock().unwrap().last().cloned()
        }
    }

    impl DeadLetterStore for FakeDeadLetterStore {
        async fn write_dead_letter(
            &self,
            record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 happy-path，item-level carve-out
            self.written.lock().unwrap().push(CapturedDlxRecord {
                tenant_id: record.tenant().to_string(),
                message_id: record.message_id().to_string(),
                producer_domain: record.producer_domain().to_string(),
                consumer_domain: record.consumer_domain().map(str::to_string),
                consumer_group: record.consumer_group().map(str::to_string),
                error_summary: record.error_summary().to_string(),
                num_attempts: record.num_attempts(),
            });
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    /// fake DLX store（恒写失败版）：write_dead_letter 总返回 Err。
    struct AlwaysErrDeadLetterStore {
        write_count: AtomicU32,
    }

    impl AlwaysErrDeadLetterStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                write_count: AtomicU32::new(0),
            })
        }

        fn write_count(&self) -> u32 {
            self.write_count.load(Ordering::Acquire)
        }
    }

    impl DeadLetterStore for AlwaysErrDeadLetterStore {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            self.write_count.fetch_add(1, Ordering::Release);
            Err(DeadLetterStoreError::new(std::io::Error::other(
                "dlx write always fails",
            )))
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    /// 构造 DynDeadLetterStore box（注入 always-err fake store）。
    fn fake_dlx_always_err(
        store: Arc<AlwaysErrDeadLetterStore>,
    ) -> Box<DynDeadLetterStore<'static>> {
        struct ArcProxy(Arc<AlwaysErrDeadLetterStore>);
        impl DeadLetterStore for ArcProxy {
            async fn write_dead_letter(
                &self,
                record: DeadLetterRecord,
            ) -> Result<(), DeadLetterStoreError> {
                self.0.write_dead_letter(record).await
            }
            async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
                Ok(())
            }
        }
        DynDeadLetterStore::new_box(ArcProxy(store))
    }

    /// 构造 DynDeadLetterStore box（注入 fake store）。
    fn fake_dlx(store: Arc<FakeDeadLetterStore>) -> Box<DynDeadLetterStore<'static>> {
        // FakeDeadLetterStore impl DeadLetterStore（Send 变体），可经 DynDeadLetterStore::new_box 装箱。
        // Arc 实现 DeadLetterStore 需要 Arc<T>: DeadLetterStore；用包装 struct 代理。
        struct ArcProxy(Arc<FakeDeadLetterStore>);
        impl DeadLetterStore for ArcProxy {
            async fn write_dead_letter(
                &self,
                record: DeadLetterRecord,
            ) -> Result<(), DeadLetterStoreError> {
                self.0.write_dead_letter(record).await
            }
            async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
                Ok(())
            }
        }
        DynDeadLetterStore::new_box(ArcProxy(store))
    }

    // ── FakeAcker ────────────────────────────────────────────────────────────

    /// fake broker acker：记录每次 settle 的 AckAction（Arc<Mutex<Vec>> 范式）。
    ///
    /// 用法：
    /// 1. `FakeAcker::new()` 得到 `(Arc<FakeAcker>, Box<DynAcker<'static>>)`；
    /// 2. 把 box 装入 Delivery 流驱动；
    /// 3. 测试后从 `Arc<FakeAcker>` 读 `settled_actions()` 断言。
    struct FakeAcker {
        actions: Mutex<Vec<AckAction>>,
    }

    impl FakeAcker {
        /// 构造 FakeAcker + 对应 Box<DynAcker<'static>>（Arc 代理范式，与 fake_dlx 同构）。
        fn new() -> (Arc<Self>, Box<DynAcker<'static>>) {
            let arc = Arc::new(Self {
                actions: Mutex::new(vec![]),
            });
            struct ArcProxy(Arc<FakeAcker>);
            impl Acker for ArcProxy {
                async fn settle(&self, action: AckAction) -> Result<(), diport::AckError> {
                    #[allow(clippy::unwrap_used)]
                    // reason: 测试 happy-path，item-level carve-out
                    self.0.actions.lock().unwrap().push(action);
                    Ok(())
                }
            }
            let boxed = DynAcker::new_box(ArcProxy(arc.clone()));
            (arc, boxed)
        }

        /// 读取已记录的 settle action 序列（克隆快照）。
        fn settled_actions(&self) -> Vec<AckAction> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 happy-path，item-level carve-out
            self.actions.lock().unwrap().clone()
        }
    }

    /// 构造 DeliveryStream（每条消息配独立 FakeAcker）。
    /// 返回 (stream, Vec<Arc<FakeAcker>>)——acker 句柄与消息顺序一一对应。
    fn delivery_stream_of(payloads: &[(&str, &[u8])]) -> (DeliveryStream, Vec<Arc<FakeAcker>>) {
        let mut ackers = Vec::with_capacity(payloads.len());
        let mut deliveries = Vec::with_capacity(payloads.len());
        for (id, p) in payloads {
            let (arc, boxed) = FakeAcker::new();
            let msg = message(id, p);
            deliveries.push(diport::Delivery::new(msg, boxed));
            ackers.push(arc);
        }
        let stream: DeliveryStream = Box::pin(futures::stream::iter(deliveries));
        (stream, ackers)
    }

    // ── handler 工厂 ─────────────────────────────────────────────────────────

    /// 恒 Ack handler（计数调用次数）。
    fn handler_ack(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::ack()
            })
        }
    }

    /// 恒 Requeue handler（计数调用次数）。
    fn handler_requeue(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::requeue(consistency::error::EngineError::new(
                    consistency::error::EngineErrorKind::Transient,
                ))
            })
        }
    }

    /// 恒 Reject handler（计数调用次数）。
    fn handler_reject(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::reject(consistency::outbox::PermanentError::new(
                    consistency::outbox::PermanentErrorKind::Permanent,
                ))
            })
        }
    }

    /// 恒 Reject handler（`Invariant` kind；用于核 error kind 摘要随 HandleResult 流到 DLX，#1125）。
    fn handler_reject_invariant(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                HandleResult::reject(consistency::outbox::PermanentError::new(
                    consistency::outbox::PermanentErrorKind::Invariant,
                ))
            })
        }
    }

    // ── TC1：handler 恒 Ack ──────────────────────────────────────────────────

    /// TC1：handler 恒 Ack → handler 调 1 次、commit 1 次、无 dlx 写。
    #[tokio::test]
    async fn tc1_handler_ack_commit_once_no_dlx() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-1", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(idem.commit_count(), 1, "commit 应调 1 次");
        assert_eq!(dlx_store.write_count(), 0, "无 dlx 写");
        let contexts = idem.captured_contexts();
        assert_eq!(
            contexts.len(),
            2,
            "Ack happy path 应向 try_claim 和 commit 传入 receipt context"
        );
        for ctx in contexts {
            assert_eq!(ctx.tenant_id(), tenant());
            assert_eq!(ctx.consumer_group().as_str(), "identity.session.consumer");
            assert_eq!(ctx.domain(), "identity");
            assert_eq!(ctx.topic(), "session.created");
            assert_eq!(ctx.contract_id(), "contract-session");
            assert_eq!(ctx.contract_version(), "v1");
            assert_eq!(ctx.schema_hash(), SCHEMA_HASH);
        }
    }

    // ── TC2：handler 恒 Requeue ──────────────────────────────────────────────

    /// TC2：handler 恒 Requeue → handler 调 MAX_REDELIVERY 次、dlx 写 1 次（exhausted）、commit 1 次。
    #[tokio::test]
    async fn tc2_handler_requeue_exhausted_dlx() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-requeue", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_requeue(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            MAX_REDELIVERY,
            "handler 应调 MAX_REDELIVERY 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx 应写 1 次");
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言前置 assert_eq 已验证 write_count==1，last_record 必然 Some；item-level carve-out。
        let record = dlx_store.last_record().unwrap();
        // #1125：requeue 耗尽后 DLX 摘要反映 handler 的 EngineError kind（Transient），
        // 而非旧通用常量 "requeue budget exhausted"。
        assert_eq!(
            record.error_summary, "transient engine error",
            "summary 应为 requeue kind 的 const message: {}",
            record.error_summary
        );
        assert_eq!(
            record.num_attempts, MAX_REDELIVERY,
            "num_attempts 应 == MAX_REDELIVERY"
        );
        assert_eq!(
            record.message_id, "msg-requeue",
            "message_id 应来自 Message::id()"
        );
        assert_eq!(
            record.tenant_id, "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "tenant_id 应来自 Message::metadata().tenantId"
        );
        assert_eq!(
            record.consumer_group.as_deref(),
            Some("identity.session.consumer"),
            "consumer_group 应来自 ConsumerMeta"
        );
        assert_eq!(idem.commit_count(), 1, "commit 应调 1 次（dlx 终态收口）");
    }

    // ── TC3：handler 恒 Reject ───────────────────────────────────────────────

    /// TC3：handler 恒 Reject → handler 调 1 次、dlx 写 1 次（permanent rejection）、commit 1 次。
    #[tokio::test]
    async fn tc3_handler_reject_dlx_once() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-reject", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_reject(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx 应写 1 次");
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言前置 assert_eq 已验证 write_count==1，last_record 必然 Some；item-level carve-out。
        let record = dlx_store.last_record().unwrap();
        // #1125：DLX 摘要为 handler 的 PermanentError kind（Permanent）const message，
        // 而非旧通用常量 "permanent rejection"。
        assert_eq!(
            record.error_summary, "permanent error",
            "summary 应为 reject kind 的 const message: {}",
            record.error_summary
        );
        assert_eq!(idem.commit_count(), 1, "commit 应调 1 次");
    }

    #[tokio::test]
    async fn tc3_cross_domain_authority_uses_producer_domain_but_records_consumer_domain() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-cross-domain", b"payload")]),
            idem.clone(),
            dlx,
            cross_domain_meta(),
            handler_reject(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(dlx_store.write_count(), 1, "cross-domain DLX must verify");
        #[allow(clippy::unwrap_used)]
        let record = dlx_store.last_record().unwrap();
        assert_eq!(
            record.producer_domain, "identity",
            "DLX attribution preserves the producer domain"
        );
        assert_eq!(
            record.consumer_domain.as_deref(),
            Some("audit"),
            "DLX attribution records the consumer domain independently"
        );
        assert_eq!(idem.commit_count(), 1, "verified DLX should commit");
    }

    #[tokio::test]
    async fn tc3b_reject_missing_tenant_skips_app_dlx_and_settles_reject() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (acker, boxed) = FakeAcker::new();
        let stream: DeliveryStream = Box::pin(futures::stream::iter(vec![diport::Delivery::new(
            Message::new("msg-no-tenant", b"payload".to_vec()),
            boxed,
        )]));

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_reject(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            0,
            "缺标准头应在 handler 前拒绝"
        );
        assert_eq!(idem.claim_count(), 0, "缺标准头不得 try_claim");
        assert_eq!(dlx_store.write_count(), 0, "缺 tenant 不得写 app DLX");
        assert_eq!(idem.commit_count(), 0, "缺标准头不得 commit done");
        assert_eq!(
            idem.release_count(),
            0,
            "缺标准头发生在 claim 前，无需 release"
        );
        assert_eq!(
            acker.settled_actions(),
            vec![AckAction::Reject],
            "ackable 缺 tenant 应 settle Reject"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn tc3d_invalid_standard_header_rejects_before_claim() {
        const OTHER_SCHEMA_HASH: &str =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let cases: [(&str, EnvelopeMetadata, &str); 6] = [
            (
                "msg-no-schema",
                tenant_authority_metadata("msg-no-schema"),
                "envelope_missing_schema_version",
            ),
            {
                let mut md = tenant_authority_metadata("msg-invalid-version");
                md.insert_wire_pair(KEY_SCHEMA_VERSION, "1");
                md.insert_wire_pair(KEY_SCHEMA_HASH, SCHEMA_HASH);
                ("msg-invalid-version", md, "envelope_invalid_schema_version")
            },
            {
                let mut md = tenant_authority_metadata("msg-wrong-version");
                md.insert_wire_pair(KEY_SCHEMA_VERSION, "v2");
                md.insert_wire_pair(KEY_SCHEMA_HASH, SCHEMA_HASH);
                ("msg-wrong-version", md, "envelope_schema_version_mismatch")
            },
            {
                let mut md = tenant_authority_metadata("msg-missing-hash");
                md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
                ("msg-missing-hash", md, "envelope_missing_schema_hash")
            },
            {
                let mut md = tenant_metadata("msg-invalid-hash");
                md.insert_wire_pair(KEY_SCHEMA_HASH, "sha256:ABC");
                ("msg-invalid-hash", md, "envelope_invalid_schema_hash")
            },
            {
                let mut md = tenant_metadata("msg-wrong-hash");
                md.insert_wire_pair(KEY_SCHEMA_HASH, OTHER_SCHEMA_HASH);
                ("msg-wrong-hash", md, "envelope_schema_hash_mismatch")
            },
        ];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for (message_id, metadata, reason) in cases {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            let idem = FakeInboxStore::fresh();
            let dlx_store = FakeDeadLetterStore::new();
            let dlx = fake_dlx(dlx_store.clone());
            let handler_count = Arc::new(AtomicU32::new(0));
            let (acker, boxed) = FakeAcker::new();
            let stream: DeliveryStream =
                Box::pin(futures::stream::iter(vec![diport::Delivery::new(
                    Message::new_with_metadata(message_id, b"payload".to_vec(), metadata),
                    boxed,
                )]));

            metrics::with_local_recorder(&recorder, || {
                rt.block_on(run_consumer_ackable(
                    stream,
                    idem.clone(),
                    (dlx).as_ref(),
                    &(meta()),
                    &(handler_ack(handler_count.clone())),
                    lease_cfg_test(),
                    consumer_admission(),
                ));
            });

            assert_eq!(
                handler_count.load(Ordering::Relaxed),
                0,
                "{message_id}: invalid standard header 不得进入 handler"
            );
            assert_eq!(idem.claim_count(), 0, "{message_id}: 不得 try_claim");
            assert_eq!(idem.commit_count(), 0, "{message_id}: 不得 commit");
            assert_eq!(idem.release_count(), 0, "{message_id}: 不得 release");
            assert_eq!(
                dlx_store.write_count(),
                0,
                "{message_id}: header gate 不写 app DLX"
            );
            assert_eq!(acker.settled_actions(), vec![AckAction::Reject]);
            let rendered = handle.render();
            assert!(
                rendered.contains("consumer_dlx_skip_total"),
                "{message_id}: 缺 skip metric: {rendered}"
            );
            assert!(
                rendered.contains(&format!("reason=\"{reason}\"")),
                "{message_id}: 缺 reason={reason}: {rendered}"
            );
        }
    }

    #[test]
    fn receipt_context_error_reasons_are_closed_labels() {
        let cases = [
            (
                ReceiptContextBuildError::ConsumerGroup,
                "inbox_receipt_invalid_consumer_group",
            ),
            (
                ReceiptContextBuildError::Receipt(InboxReceiptContextError::EmptyDomain),
                "inbox_receipt_empty_domain",
            ),
            (
                ReceiptContextBuildError::Receipt(InboxReceiptContextError::EmptyTopic),
                "inbox_receipt_empty_topic",
            ),
            (
                ReceiptContextBuildError::Receipt(InboxReceiptContextError::EmptyContractId),
                "inbox_receipt_empty_contract_id",
            ),
            (
                ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidContractVersion),
                "inbox_receipt_invalid_contract_version",
            ),
            (
                ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidSchemaHash),
                "inbox_receipt_invalid_schema_hash",
            ),
            (
                ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidTrace),
                "inbox_receipt_invalid_trace",
            ),
            (
                ReceiptContextBuildError::Receipt(InboxReceiptContextError::InvalidCorrelationId),
                "inbox_receipt_invalid_correlation_id",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(receipt_context_error_reason(error), expected);
        }
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    // reason: table-driven test fixtures use known-valid authority inputs; failures should panic loudly.
    fn tc3c_invalid_authority_tokens_skip_app_dlx_and_settle_reject() {
        let cases: [(&str, EnvelopeMetadata, &str); 3] = [
            {
                let mut md = tenant_metadata("msg-bad-mac");
                let mut token = md.get(KEY_TENANT_AUTHORITY).unwrap().to_string();
                token.push('x');
                md.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
                ("msg-bad-mac", md, "tenant_authority_invalid")
            },
            {
                let signer = TenantAuthority::new(
                    Arc::new(TestMac),
                    MacKey::from_bytes(vec![0x42; 32]),
                    60,
                    5,
                    Arc::new(|| 1_699_999_900),
                )
                .expect("valid expired signer");
                let mut md = EnvelopeMetadata::empty();
                let token = signer
                    .sign(TenantAuthorityBinding::new(
                        tenant(),
                        "identity",
                        "contract-session",
                        "session.created",
                        "msg-expired",
                    ))
                    .expect("sign expired token");
                md.insert_wire_pair(KEY_TENANT_ID, tenant().to_string());
                md.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
                insert_schema_header(&mut md);
                ("msg-expired", md, "tenant_authority_expired")
            },
            {
                let mut md = EnvelopeMetadata::empty();
                let token = tenant_authority()
                    .sign(TenantAuthorityBinding::new(
                        tenant(),
                        "settings",
                        "contract-session",
                        "session.created",
                        "msg-binding",
                    ))
                    .expect("sign mismatched token");
                md.insert_wire_pair(KEY_TENANT_ID, tenant().to_string());
                md.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
                insert_schema_header(&mut md);
                ("msg-binding", md, "tenant_authority_binding_mismatch")
            },
        ];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for (message_id, metadata, reason) in cases {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            let idem = FakeInboxStore::fresh();
            let dlx_store = FakeDeadLetterStore::new();
            let dlx = fake_dlx(dlx_store.clone());
            let handler_count = Arc::new(AtomicU32::new(0));
            let (acker, boxed) = FakeAcker::new();
            let stream: DeliveryStream =
                Box::pin(futures::stream::iter(vec![diport::Delivery::new(
                    Message::new_with_metadata(message_id, b"payload".to_vec(), metadata),
                    boxed,
                )]));

            metrics::with_local_recorder(&recorder, || {
                rt.block_on(run_consumer_ackable(
                    stream,
                    idem.clone(),
                    (dlx).as_ref(),
                    &(meta()),
                    &(handler_reject(handler_count.clone())),
                    lease_cfg_test(),
                    consumer_admission(),
                ));
            });

            assert_eq!(
                handler_count.load(Ordering::Relaxed),
                0,
                "{message_id}: invalid authority 应在 handler 前拒绝"
            );
            assert_eq!(
                idem.claim_count(),
                0,
                "{message_id}: invalid authority 不得 try_claim"
            );
            assert_eq!(
                dlx_store.write_count(),
                0,
                "{message_id}: invalid authority 不得写 DLX"
            );
            assert_eq!(
                idem.commit_count(),
                0,
                "{message_id}: invalid authority 不得 commit"
            );
            assert_eq!(
                idem.release_count(),
                0,
                "{message_id}: invalid authority 发生在 claim 前，无需 release"
            );
            assert_eq!(acker.settled_actions(), vec![AckAction::Reject]);
            let rendered = handle.render();
            assert!(
                rendered.contains("consumer_dlx_skip_total"),
                "{message_id}: 缺 skip metric: {rendered}"
            );
            assert!(
                rendered.contains(&format!("reason=\"{reason}\"")),
                "{message_id}: 缺 reason={reason}: {rendered}"
            );
        }
    }

    // ── TC9：reject(Invariant) → DLX 摘要反映 Invariant kind（#1125 anti-vacuity）──

    /// TC9：handler reject(Invariant) → DLX 摘要 == "invariant violated"（≠ TC3 的 "permanent error"），
    /// 证 error kind 真实随 HandleResult 流到 DLX（摘要非硬编码、随 kind 变化）。
    #[tokio::test]
    async fn tc9_reject_invariant_surfaces_kind_summary() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-reject-inv", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_reject_invariant(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(dlx_store.write_count(), 1, "dlx 应写 1 次");
        #[allow(clippy::unwrap_used)]
        // reason: 前置 assert_eq 已验证 write_count==1，last_record 必然 Some；item-level carve-out。
        let record = dlx_store.last_record().unwrap();
        assert_eq!(
            record.error_summary, "invariant violated",
            "Invariant kind 摘要应为 'invariant violated'（随 kind 变化，非硬编码）: {}",
            record.error_summary
        );
    }

    // ── TC4：try_claim 返 Duplicate ──────────────────────────────────────────────

    /// TC4：try_claim 返 Duplicate → handler 0 次、commit 0 次、dlx 0 次。
    #[tokio::test]
    async fn tc4_duplicate_skips_handler_and_commit() {
        let idem = FakeInboxStore::duplicate();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-dup", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 0, "handler 应 0 次");
        assert_eq!(idem.commit_count(), 0, "commit 应 0 次");
        assert_eq!(dlx_store.write_count(), 0, "dlx 应 0 次");
    }

    // ── TC6：try_claim 返 Err ────────────────────────────────────────────────────

    /// TC6：try_claim 返 Err（瞬态后端故障）→ handler 0 次、commit 0 次、dlx 0 次（不做任何终态动作）。
    #[tokio::test]
    async fn tc6_check_err_skips_handler_and_commit() {
        let idem = FakeInboxStore::err();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-try_claim-err", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            0,
            "try_claim Err 时 handler 应 0 次"
        );
        assert_eq!(idem.commit_count(), 0, "try_claim Err 时 commit 应 0 次");
        assert_eq!(dlx_store.write_count(), 0, "try_claim Err 时 dlx 应 0 次");
    }

    // ── TC7：IdemKey parse 失败 ──────────────────────────────────────────────

    /// TC7：IdemKey parse 失败（空 id）→ handler 0 次、commit 0 次、dlx 0 次（fail-closed 丢弃）。
    #[tokio::test]
    async fn tc7_parse_failed_drops_message() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        // 空 id → IdemKey::parse 失败
        run_consumer(
            stream_of(&[("", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_ack(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            0,
            "parse 失败时 handler 应 0 次"
        );
        assert_eq!(idem.commit_count(), 0, "parse 失败时 commit 应 0 次");
        assert_eq!(dlx_store.write_count(), 0, "parse 失败时 dlx 应 0 次");
    }

    // ── TC8：DLX 写失败 → release 而非 commit ───────────────────────────────

    /// TC8：handler reject + DLX 写总失败 → commit 0 次、release 1 次、dlx write 尝试 1 次。
    /// 守住「静默丢失」修复语义：DLX 写失败后 release（而非 commit），使 broker 可重投重试 DLX。
    #[tokio::test]
    async fn tc8_dlx_write_fails_releases_key() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = AlwaysErrDeadLetterStore::new();
        let dlx = fake_dlx_always_err(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));

        run_consumer(
            stream_of(&[("msg-dlx-fail", b"payload")]),
            idem.clone(),
            dlx,
            meta(),
            handler_reject(handler_count.clone()),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "reject handler 应调 1 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx write 应尝试 1 次");
        assert_eq!(idem.commit_count(), 0, "dlx 写失败时 commit 应 0 次");
        assert_eq!(idem.release_count(), 1, "dlx 写失败时 release 应 1 次");
    }

    // ── TC5：T007.5 tracing 字段断言 ────────────────────────────────────────

    /// TC5（T007.5）：reject 触发 DLX 时，tracing error! 必须含六字段：
    /// domain / contract_id / topic / num_attempts / error_summary / message_id。
    /// 且字段值不含 payload 字节原文（anti-PII）。
    ///
    /// anti-vacuity 加固：
    /// - 使用唯一 meta（domain="tc5-domain"），与 TC2/TC3 的 "identity" 区分，
    ///   防并发写入污染聚合导致「六字段存在」断言恒真。
    /// - CapVisit 捕获 per-event 字段 map（Vec<HashMap<String,String>>），
    ///   每个 ERROR 事件一条，断言「存在某条 event 其 domain=="tc5-domain" 且含全部六字段」。
    ///
    /// 实现：自定义轻量 `tracing::Subscriber` + `block_on`；线程局部 subscriber
    /// 隔离并行测试，并以 `Interest::always()` 避免 callsite interest cache 导致 flake。
    #[test]
    fn tc5_dlx_tracing_fields_and_no_payload_leak() {
        use std::collections::HashMap;
        use tracing::field::{Field, Visit};
        use tracing::subscriber::Interest;
        use tracing::{Event, Id, Metadata, span};

        // 每个 ERROR 事件捕获为独立 HashMap<fieldname, value>。
        struct Captured {
            events: Mutex<Vec<HashMap<String, String>>>,
        }

        impl Captured {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    events: Mutex::new(vec![]),
                })
            }
        }

        struct CapVisit {
            current: HashMap<String, String>,
        }

        impl Visit for CapVisit {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.current
                    .insert(field.name().to_string(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.current
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_u64(&mut self, field: &Field, value: u64) {
                self.current
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_i64(&mut self, field: &Field, value: i64) {
                self.current
                    .insert(field.name().to_string(), value.to_string());
            }
        }

        // 极简 Subscriber——只捕获 ERROR 事件，其余方法 noop。
        struct CapSubscriber {
            captured: Arc<Captured>,
        }

        impl tracing::Subscriber for CapSubscriber {
            fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
                Interest::always()
            }

            fn enabled(&self, meta: &Metadata<'_>) -> bool {
                let _ = meta;
                true
            }

            fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
                Id::from_u64(1)
            }

            fn record(&self, _span: &Id, _values: &span::Record<'_>) {}
            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
            fn enter(&self, _span: &Id) {}
            fn exit(&self, _span: &Id) {}

            fn event(&self, event: &Event<'_>) {
                if *event.metadata().level() != tracing::Level::ERROR {
                    return;
                }
                let mut visitor = CapVisit {
                    current: HashMap::new(),
                };
                event.record(&mut visitor);
                #[allow(clippy::unwrap_used)]
                // reason: 测试 Mutex，item-level carve-out
                self.captured.events.lock().unwrap().push(visitor.current);
            }
        }

        let captured = Captured::new();
        let subscriber = CapSubscriber {
            captured: captured.clone(),
        };

        #[allow(clippy::unwrap_used)]
        // reason: 测试 runtime 构造，item-level carve-out
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                let idem = FakeInboxStore::fresh();
                let dlx_store = FakeDeadLetterStore::new();
                let dlx = fake_dlx(dlx_store.clone());
                let handler_count = Arc::new(AtomicU32::new(0));

                // 唯一 meta（domain="tc5-domain"），与 TC2/TC3 "identity" 区分——anti-vacuity 核心。
                let tc5_meta = ConsumerMeta::new(
                    "tc5-domain",
                    "tc5-domain",
                    "tc5-contract",
                    "tc5-topic",
                    "tc5-group",
                    tenant_authority(),
                );
                let payload = b"SENSITIVE_PAYLOAD_BYTES";
                let msg = Message::new_with_metadata(
                    "msg-t007-tc5",
                    payload.to_vec(),
                    tenant_metadata_for("msg-t007-tc5", "tc5-domain", "tc5-contract", "tc5-topic"),
                );
                run_consumer(
                    Box::pin(futures::stream::iter(vec![msg])),
                    idem,
                    dlx,
                    tc5_meta,
                    handler_reject(handler_count),
                    lease_cfg_test(),
                    consumer_admission(),
                )
                .await;
            });
        });

        // 找到 domain=="tc5-domain" 的 event（排除并发 TC2/TC3 的 "identity" 污染）。
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言，item-level carve-out
        let events = captured.events.lock().unwrap();
        let tc5_event = events
            .iter()
            .find(|ev| ev.get("domain").map(|d| d == "tc5-domain").unwrap_or(false));
        assert!(
            tc5_event.is_some(),
            "未找到 domain==tc5-domain 的 ERROR event；捕获的全部 events: {events:?}"
        );
        #[allow(clippy::unwrap_used)]
        // reason: 上方 assert! 已确保 Some，item-level carve-out
        let ev = tc5_event.unwrap();

        // 断言六字段全部出现（含新增 message_id）。
        let required = [
            "domain",
            "contract_id",
            "topic",
            "num_attempts",
            "error_summary",
            "message_id",
        ];
        for field in &required {
            assert!(
                ev.contains_key(*field),
                "tracing error! 缺字段 {field}；tc5 event 字段集: {ev:?}"
            );
        }

        // 断言 event 字段值不含 payload 原文。
        let all_values: String = ev.values().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !all_values.contains("SENSITIVE_PAYLOAD_BYTES"),
            "字段值不得含 payload 原文: {all_values}"
        );
    }

    // ── 七个 ackable 终态测试 ────────────────────────────────────────────────

    /// ACK-1：handler 恒 Ack → settle=[Ack]，commit 1 次，dlx 0 次。
    #[tokio::test]
    async fn ack1_handler_ack_settles_ack() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack1", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_ack(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(idem.commit_count(), 1, "commit 应 1 次");
        assert_eq!(dlx_store.write_count(), 0, "dlx 应 0 次");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Ack],
            "settle 应为 [Ack]"
        );
    }

    /// ACK-2：handler 恒 Reject + DLX 写成功 → settle=[Ack]，dlx 1 次，commit 1 次。
    #[tokio::test]
    async fn ack2_handler_reject_dlx_ok_settles_ack() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack2", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_reject(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx 应 1 次");
        assert_eq!(idem.commit_count(), 1, "commit 应 1 次");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Ack],
            "DLX 写成功后 settle 应为 [Ack]"
        );
    }

    /// ACK-3：handler 恒 Requeue（耗尽）+ DLX 写成功 → settle=[Ack]，dlx 1 次，commit 1 次。
    #[tokio::test]
    async fn ack3_handler_requeue_exhausted_dlx_ok_settles_ack() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack3", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_requeue(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            MAX_REDELIVERY,
            "handler 应调 MAX_REDELIVERY 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx 应 1 次");
        assert_eq!(idem.commit_count(), 1, "commit 应 1 次（dlx 终态收口）");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Ack],
            "Requeue 耗尽 DLX 成功后 settle 应为 [Ack]"
        );
    }

    /// ACK-4：handler 恒 Reject + DLX 写失败 → settle=[Requeue]，release 1，commit 0。
    #[tokio::test]
    async fn ack4_handler_reject_dlx_fail_settles_requeue() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = AlwaysErrDeadLetterStore::new();
        let dlx = fake_dlx_always_err(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack4", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_reject(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(dlx_store.write_count(), 1, "dlx write 应尝试 1 次");
        assert_eq!(idem.commit_count(), 0, "dlx 写失败时 commit 应 0");
        assert_eq!(idem.release_count(), 1, "dlx 写失败时 release 应 1");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Requeue],
            "DLX 写失败后 settle 应为 [Requeue]"
        );
    }

    /// ACK-4b：handler Reject + DLX 写失败 + release 失败按 eventbus 真源 Reject。
    #[test]
    #[allow(clippy::unwrap_used)]
    fn ack4b_dlx_fail_and_release_fail_settles_reject() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let idem = FakeInboxStore::fresh_release_fails();
        let dlx_store = AlwaysErrDeadLetterStore::new();
        let dlx = fake_dlx_always_err(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack-4b", b"payload")]);

        metrics::with_local_recorder(&recorder, || {
            rt.block_on(run_consumer_ackable(
                stream,
                idem.clone(),
                (dlx).as_ref(),
                &(meta()),
                &(handler_reject(handler_count)),
                lease_cfg_test(),
                consumer_admission(),
            ));
        });

        assert_eq!(dlx_store.write_count(), 1, "dlx write 应尝试 1 次");
        assert_eq!(idem.commit_count(), 0, "双重失败时 commit 应 0");
        assert_eq!(idem.release_count(), 1, "release 应尝试 1 次");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Reject],
            "DLX write + claim release 双失败必须 fail closed 到 Reject"
        );
        let rendered = handle.render();
        assert!(
            rendered.contains("consumer_release_failed_total"),
            "缺 consumer_release_failed_total: {rendered}"
        );
        assert!(
            rendered.contains("domain=\"identity\""),
            "缺 domain label: {rendered}"
        );
    }

    /// ACK-5：幂等 try_claim 返 Err → settle=[Requeue]，handler 0，commit 0。
    #[tokio::test]
    async fn ack5_check_err_settles_requeue() {
        let idem = FakeInboxStore::err();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack5", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_ack(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 0, "handler 应 0 次");
        assert_eq!(idem.commit_count(), 0, "commit 应 0");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Requeue],
            "try_claim Err 后 settle 应为 [Requeue]"
        );
    }

    /// ACK-5b：幂等 try_claim 返**永久** Err（Permanent）→ settle=[Reject]（→DLX，不无限重投），handler 0，commit 0。
    /// C2/#1354 review F2：permanent claim 错误（如 redis 鉴权/协议，`classify_redis_error`）须 hard-fence 到
    /// DLX，区别于 `Transient` 的 Requeue——否则配置/协议错误下消息无限重投不收敛。
    #[tokio::test]
    async fn ack5b_permanent_check_err_settles_reject() {
        let idem = FakeInboxStore::err_permanent();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack5b", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_ack(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 0, "handler 应 0 次");
        assert_eq!(idem.commit_count(), 0, "commit 应 0");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Reject],
            "永久 try_claim Err 应 hard-fence 到 [Reject]（→DLX，不无限重投）"
        );
    }

    /// ACK-5c：active claim 是 typed InProgress；不调 handler、不发 backend warn，按 lease 周期延迟后 Requeue。
    #[test]
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::disallowed_methods)]
    // reason: 本测断言墙钟延迟下界（InProgress 不得立即 churn）；不注入 Clock 避免改 #1142 接缝。
    fn ack5c_in_progress_delays_then_requeues_with_low_cardinality_metric() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let idem = FakeInboxStore::in_progress();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack5c", b"payload")]);

        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let consumer_meta = meta();
                let handler = handler_ack(handler_count.clone());
                let mut run = Box::pin(run_consumer_ackable(
                    stream,
                    idem.clone(),
                    dlx.as_ref(),
                    &consumer_meta,
                    &handler,
                    lease_cfg_fast(),
                    consumer_admission(),
                ));
                let delayed = tokio::time::timeout(Duration::from_millis(1), &mut run)
                    .await
                    .is_err();
                assert!(
                    delayed,
                    "InProgress must not immediately churn broker requeue"
                );
                run.await;
            });
        });

        assert_eq!(handler_count.load(Ordering::Relaxed), 0);
        assert_eq!(idem.commit_count(), 0);
        assert_eq!(dlx_store.write_count(), 0);
        assert_eq!(ackers[0].settled_actions(), vec![AckAction::Requeue]);
        let rendered = handle.render();
        assert!(rendered.contains("consumer_claim_in_progress_total"));
        assert!(rendered.contains("domain=\"identity\""));
        assert!(
            !rendered.contains("message_id"),
            "metric must stay low-cardinality"
        );
    }

    /// ACK-6：try_claim 返 Duplicate → settle=[Ack]，handler 0，commit 0。
    #[tokio::test]
    async fn ack6_duplicate_settles_ack() {
        let idem = FakeInboxStore::duplicate();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("msg-ack6", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_ack(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 0, "handler 应 0 次");
        assert_eq!(idem.commit_count(), 0, "commit 应 0");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Ack],
            "Duplicate 后 settle 应为 [Ack]"
        );
    }

    /// ACK-7：空 id（parse 失败）→ settle=[Reject]，handler 0，commit 0。
    #[tokio::test]
    async fn ack7_parse_failed_settles_reject() {
        let idem = FakeInboxStore::fresh();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        // 空 id → IdemKey::parse 失败
        let (stream, ackers) = delivery_stream_of(&[("", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_ack(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 0, "handler 应 0 次");
        assert_eq!(idem.commit_count(), 0, "commit 应 0");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Reject],
            "parse 失败后 settle 应为 [Reject]"
        );
    }

    // ── F1（review #265 C1）：commit 失败终态须 broker Requeue、不可 Ack ──────────

    /// F1a：handler Ack + commit 失败 → settle 序列 [Requeue]（非 Ack）、commit 尝试 1 次。
    /// 守「ack only after durable commit」——done 标记未持久不可移除 broker 投递。
    #[tokio::test]
    async fn ack_commit_fail_requeues_not_ack() {
        let idem = FakeInboxStore::fresh_commit_fails();
        let dlx = fake_dlx(FakeDeadLetterStore::new());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("m-cf", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_ack(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            handler_count.load(Ordering::Relaxed),
            1,
            "handler 应调 1 次"
        );
        assert_eq!(idem.commit_count(), 1, "commit 应尝试 1 次");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Requeue],
            "commit 失败时 settle 应为 [Requeue]（非 Ack）"
        );
    }

    /// F1b：handler Reject + DLX 写成功 + commit 失败 → settle [Requeue]、dlx 写 1 次、commit 尝试 1 次。
    /// DLX 已落但 done 标记未持久 ⇒ 不 Ack，重投经幂等 Duplicate 收口。
    #[tokio::test]
    async fn reject_dlx_ok_commit_fail_requeues() {
        let idem = FakeInboxStore::fresh_commit_fails();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("m-cf-dlx", b"payload")]);

        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_reject(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(dlx_store.write_count(), 1, "dlx 应写 1 次");
        assert_eq!(idem.commit_count(), 1, "commit 应尝试 1 次");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Requeue],
            "DLX 成功但 commit 失败时 settle 应为 [Requeue]（非 Ack）"
        );
    }

    // ── F3（review #265 C3）：settle 发 consumer_settle_total metric ──────────────

    /// F3：ackable Ack settle 成功 → 发 `consumer_settle_total{domain,action,outcome}`
    /// （domain=identity / action=ack / outcome=ok）。with_local_recorder + block_on 单线程捕获（同 TC5 范式）。
    #[test]
    fn settle_emits_consumer_settle_total_metric() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        #[allow(clippy::unwrap_used)]
        // reason: 测试 runtime 构造，item-level carve-out
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let idem = FakeInboxStore::fresh();
                let dlx = fake_dlx(FakeDeadLetterStore::new());
                let handler_count = Arc::new(AtomicU32::new(0));
                let (stream, _ackers) = delivery_stream_of(&[("m-metric", b"payload")]);
                run_consumer_ackable(
                    stream,
                    idem,
                    (dlx).as_ref(),
                    &(meta()),
                    &(handler_ack(handler_count)),
                    lease_cfg_test(),
                    consumer_admission(),
                )
                .await;
            });
        });
        let rendered = handle.render();
        assert!(
            rendered.contains("consumer_settle_total"),
            "缺 metric consumer_settle_total: {rendered}"
        );
        assert!(
            rendered.contains("domain=\"identity\""),
            "缺 domain label: {rendered}"
        );
        assert!(
            rendered.contains("action=\"ack\""),
            "缺 action=ack label: {rendered}"
        );
        assert!(
            rendered.contains("outcome=\"ok\""),
            "缺 outcome=ok label: {rendered}"
        );
    }

    /// Missing/invalid tenant on DLX path emits a dedicated skip metric so it is visible independently from Reject settle.
    #[test]
    fn dead_letter_tenant_authority_binding_mismatch_emits_skip_metric() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            record_dead_letter_skip(&meta(), "tenant_authority_binding_mismatch");
        });
        let rendered = handle.render();
        assert!(
            rendered.contains("consumer_dlx_skip_total"),
            "缺 metric consumer_dlx_skip_total: {rendered}"
        );
        assert!(
            rendered.contains("domain=\"identity\""),
            "缺 domain label: {rendered}"
        );
        assert!(
            rendered.contains("reason=\"tenant_authority_binding_mismatch\""),
            "缺 reason=tenant_authority_binding_mismatch label: {rendered}"
        );
    }

    // ── 租约续租 + leaseLost hard-fence（#1213）─────────────────────────────────

    /// 慢 handler：进入即 +started，sleep 后 +finished 再 Ack（验续租 / 取消语义）。
    fn handler_slow_ack(
        started: Arc<AtomicU32>,
        finished: Arc<AtomicU32>,
        sleep: Duration,
    ) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
        move |_msg| {
            let started = started.clone();
            let finished = finished.clone();
            Box::pin(async move {
                started.fetch_add(1, Ordering::SeqCst);
                testkit::await_delay(sleep).await;
                finished.fetch_add(1, Ordering::SeqCst);
                HandleResult::ack()
            })
        }
    }

    /// LEASE-1：长 handler 执行期间后台续租（extend 被周期调用），handler 完成后正常 commit + settle Ack。
    #[tokio::test]
    async fn lease1_long_handler_renews_then_commits() {
        let idem = FakeInboxStore::fresh(); // extend 恒 Held
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let started = Arc::new(AtomicU32::new(0));
        let finished = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("evt-lease1", b"payload")]);

        // handler 睡 50ms，续租间隔 5ms（lease_cfg_fast）→ 执行期间 extend 触发多次。
        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_slow_ack(started.clone(), finished.clone(), Duration::from_millis(50))),
            lease_cfg_fast(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            finished.load(Ordering::SeqCst),
            1,
            "handler 应跑完（未被取消）"
        );
        // handler 睡 50ms / 续租 5ms ≈ 10 次续租，阈值 3 留足 CI 抖动余量（探测续租退化成单次的回归）。
        assert!(idem.extend_count() >= 3, "执行期间应多次续租（>=3）");
        assert_eq!(idem.commit_count(), 1, "完成后 commit 1 次");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Ack],
            "续租保活 → 正常 settle [Ack]"
        );
    }

    /// LEASE-2：handler 执行中租约被重捞（extend→Lost）→ handler 被取消（未跑完）、settle [Requeue]、commit 0
    /// 次（续租侧 leaseLost hard-fence）。
    #[tokio::test]
    async fn lease2_lost_during_handler_cancels_and_requeues() {
        let idem = FakeInboxStore::fresh_lease_lost_after(0); // 首次 extend 即 Lost
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let started = Arc::new(AtomicU32::new(0));
        let finished = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("evt-lease2", b"payload")]);

        // handler 睡 5s（远超续租间隔 5ms）：续租侧在 ~5ms 判 Lost → 取消 handler、hard-fence Requeue。
        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_slow_ack(started.clone(), finished.clone(), Duration::from_secs(5))),
            lease_cfg_fast(),
            consumer_admission(),
        )
        .await;

        assert_eq!(started.load(Ordering::SeqCst), 1, "handler 已进入");
        assert_eq!(
            finished.load(Ordering::SeqCst),
            0,
            "租约丢失 → handler 被取消（未跑完）"
        );
        assert_eq!(idem.commit_count(), 0, "hard-fence：不 commit");
        assert_eq!(
            dlx_store.write_count(),
            0,
            "hard-fence 不进 DLX（Requeue 重投）"
        );
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Requeue],
            "leaseLost hard-fence → settle [Requeue]"
        );
    }

    /// LEASE-3：handler Ack 但 commit 期租约已丢（commit→Lost）→ settle [Requeue] 不 Ack（commit 侧 hard-fence）。
    #[tokio::test]
    async fn lease3_commit_lost_downgrades_ack_to_requeue() {
        let idem = FakeInboxStore::fresh_commit_loses_lease();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("evt-lease3", b"payload")]);

        // handler 即时 Ack；lease_cfg_test 续租间隔大（不触发续租）→ 仅 commit 侧 CAS 判 Lost。
        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_ack(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 1, "handler 调 1 次");
        assert_eq!(idem.commit_count(), 1, "commit 被尝试 1 次（返 Lost）");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Requeue],
            "commit 侧 leaseLost → 降级 settle [Requeue]"
        );
    }

    /// LEASE-4：续租瞬态 Err（extend 前 2 次 Err，之后 Held）**不**误判丢租——handler 跑完后正常 commit + Ack
    /// （续租 `Err` 臂续命语义，非 hard-fence）。
    #[tokio::test]
    async fn lease4_transient_extend_err_does_not_fence() {
        let idem = FakeInboxStore::fresh_extend_errs_then_held(2); // 前 2 次 extend Err，之后 Held
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let started = Arc::new(AtomicU32::new(0));
        let finished = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("evt-lease4", b"payload")]);

        // handler 睡 100ms / 续租 5ms：前 2 次 extend Err（续命），后续 Held；handler 跑完 → 正常 commit Ack。
        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_slow_ack(
                started.clone(),
                finished.clone(),
                Duration::from_millis(100),
            )),
            lease_cfg_fast(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            finished.load(Ordering::SeqCst),
            1,
            "瞬态续租 Err 不取消 handler（续命）"
        );
        assert!(
            idem.extend_count() >= 3,
            "extend 被多次调用（含 2 次 Err + 后续 Held）"
        );
        assert_eq!(idem.commit_count(), 1, "handler 跑完后 commit 1 次");
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Ack],
            "续租 Err 续命 → 终态正常 [Ack]（非 hard-fence）"
        );
    }

    /// LEASE-5：handler Reject + DLX 写成功，但 commit 期租约已丢（commit→Lost）→ settle [Requeue] 不 Ack
    /// （DLX 路径的 commit 侧 hard-fence；与 F1b 的 commit-Err 路径对偶）。
    #[tokio::test]
    async fn lease5_dlx_ok_commit_lost_requeues() {
        let idem = FakeInboxStore::fresh_commit_loses_lease();
        let dlx_store = FakeDeadLetterStore::new();
        let dlx = fake_dlx(dlx_store.clone());
        let handler_count = Arc::new(AtomicU32::new(0));
        let (stream, ackers) = delivery_stream_of(&[("evt-lease5", b"payload")]);

        // handler Reject → dead_letter 写 DLX 成功 → commit_key 返 Lost → settle Requeue（不 Ack）。
        run_consumer_ackable(
            stream,
            idem.clone(),
            (dlx).as_ref(),
            &(meta()),
            &(handler_reject(handler_count.clone())),
            lease_cfg_test(),
            consumer_admission(),
        )
        .await;

        assert_eq!(handler_count.load(Ordering::Relaxed), 1, "handler 调 1 次");
        assert_eq!(dlx_store.write_count(), 1, "DLX 写成功 1 次");
        assert_eq!(
            idem.commit_count(),
            1,
            "DLX 后 commit 被尝试 1 次（返 Lost）"
        );
        assert_eq!(
            ackers[0].settled_actions(),
            vec![AckAction::Requeue],
            "DLX-ok + commit leaseLost → 降级 settle [Requeue]"
        );
    }

    /// LeaseConfig::from_ttl 表驱动：续租间隔 = ttl/3，下限 1ms（避免 0 间隔忙轮询）。
    #[test]
    fn lease_config_from_ttl_derives_third_with_floor() {
        let cases: &[(Duration, Duration)] = &[
            // (输入 ttl, 期望 renew_interval)
            (Duration::from_secs(60), Duration::from_secs(20)), // 60/3 = 20s
            (Duration::from_millis(30), Duration::from_millis(10)), // 30/3 = 10ms
            (Duration::from_millis(2), Duration::from_millis(1)), // 2/3 = 0 → clamp 1ms
            (Duration::ZERO, Duration::from_millis(1)),         // 0/3 = 0 → clamp 1ms
        ];
        for (ttl, expected) in cases {
            assert_eq!(
                LeaseConfig::from_ttl(*ttl).renew_interval(),
                *expected,
                "ttl={ttl:?}"
            );
        }
    }

    // ── #1224：consumer trace 还原（build_consume_span 双分支）──────────────────

    /// W3C traceparent → trace_id 段（`00-<32hex traceid>-<16hex spanid>-<2hex flags>` 的第 2 段）。
    fn trace_id_of(traceparent: &str) -> String {
        traceparent.split('-').nth(1).unwrap_or("").to_owned()
    }

    // round-trip：producer 透传 traceparent → build_consume_span 还原 → 消费 span 与 producer 同 trace_id
    //（#1224 验收：handler 经 `.instrument(consume_span)` 在该 span 内执行 ⇒ 其 span 挂回原 trace）。otel
    // subscriber 经 tracewire 脚手架装配（本 crate 不直接 import otel）。
    // reason(expect): 测试断言——`with_test_subscriber` 内采样 span 的 capture 恒 Some。
    #[allow(clippy::expect_used)]
    #[test]
    fn build_consume_span_restores_producer_trace_id() {
        tracewiretest::with_test_subscriber(|| {
            let producer_tp = tracing::info_span!("producer")
                .in_scope(tracewire::capture_current)
                .expect("producer traceparent")
                .into_traceparent();
            // 消费侧：用透传的 traceparent 建消费 span，其 trace_id 应等于 producer。
            let consume =
                super::build_consume_span(&meta(), "msg-trace-1", Some(producer_tp.as_str()));
            let restored = consume
                .in_scope(tracewire::capture_current)
                .expect("consume span traceparent after restore")
                .into_traceparent();
            assert_eq!(
                trace_id_of(restored.as_str()),
                trace_id_of(producer_tp.as_str()),
                "build_consume_span(Some) 还原 outbox 透传 traceparent ⇒ 消费 span 与 producer 同 trace_id"
            );
        });
    }

    // fail-open 分支：无透传 trace（`None`）→ build_consume_span 不挂 parent、不 panic，消费 span 仍可用
    //（自生 root trace；tc1_handler_ack 等无 metadata 用例并行佐证消费正常）。
    // reason(expect): 测试断言——otel 下消费 span 自身恒有 root trace_id。
    #[allow(clippy::expect_used)]
    #[test]
    fn build_consume_span_without_trace_is_root() {
        tracewiretest::with_test_subscriber(|| {
            let consume = super::build_consume_span(&meta(), "msg-trace-2", None);
            let tp = consume
                .in_scope(tracewire::capture_current)
                .expect("consume span 自身在 otel 下有 root traceparent")
                .into_traceparent();
            // 自生 root：版本前缀合法、不 panic（未挂任何畸形/外来 parent）。
            assert!(
                tp.as_str().starts_with("00-"),
                "root 消费 span traceparent 形态合法: {}",
                tp.as_str()
            );
        });
    }

    // broker metadata 是未受信任边界：畸形 traceparent 只能丢弃，不能阻塞消费或传入 OTel。
    #[allow(clippy::expect_used)]
    #[test]
    fn build_consume_span_with_malformed_trace_is_root() {
        tracewiretest::with_test_subscriber(|| {
            let consume =
                super::build_consume_span(&meta(), "msg-trace-malformed", Some("not-traceparent"));
            let tp = consume
                .in_scope(tracewire::capture_current)
                .expect("malformed remote parent must fail open to a usable root span")
                .into_traceparent();
            assert!(tp.as_str().starts_with("00-"));
        });
    }

    #[test]
    fn broker_trace_rejections_preserve_closed_reasons_without_raw_values() {
        const MALFORMED: &str = "SENSITIVE-not-a-traceparent";
        const UNSUPPORTED: &str = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let oversized = "a".repeat(513);
        let (_, events) = tracewiretest::with_test_event_capture(|| {
            for value in [MALFORMED, oversized.as_str(), UNSUPPORTED] {
                let _ =
                    super::build_consume_span(&meta(), "message-must-not-be-logged", Some(value));
            }
        });

        let trace_events = events
            .iter()
            .filter(|event| event.target == "rss.trace_context")
            .collect::<Vec<_>>();
        assert_eq!(trace_events.len(), 3);
        assert!(trace_events.iter().all(|event| {
            event.fields.get("transport").map(String::as_str) == Some("broker")
                && event.fields.get("operation").map(String::as_str) == Some("process")
        }));
        let reasons = trace_events
            .iter()
            .filter_map(|event| event.fields.get("reason").map(String::as_str))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            reasons,
            std::collections::BTreeSet::from([
                "malformed traceparent",
                "traceparent exceeds 512 bytes",
                "unsupported traceparent version",
            ])
        );
        assert!(
            trace_events
                .iter()
                .flat_map(|event| event.fields.values())
                .all(|value| !value.contains(MALFORMED)
                    && !value.contains("message-must-not-be-logged"))
        );
    }

    // 端到端（review #298 F#2）：Message 带 broker 透传的 KEY_TRACE → run_consumer → handle_fresh 读
    // msg.metadata().get(KEY_TRACE) → build_consume_span 还原 → `.instrument` → handler 内 trace_id 与
    // producer 一致。覆盖「键名 + instrument 接线」整链（build_consume_span 直测覆盖不到 handle_fresh 取值/挂载）。
    // `insert_wire_pair` 在 #[cfg(test)] 子树调用：dylint rss_diport_envelope_reserved_writer 默认不扫 test，合规。
    // reason(unwrap/expect): 测试断言——采样 span capture 恒 Some、runtime build / Mutex lock 测试期不失败。
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    #[test]
    fn run_consumer_restores_trace_from_message_metadata() {
        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let seen_handler = seen.clone();

        let producer_trace_id = tracewiretest::with_test_subscriber(|| {
            let producer_tp = tracing::info_span!("producer")
                .in_scope(tracewire::capture_current)
                .expect("producer traceparent")
                .into_traceparent();

            // broker 透传等价物：subscriber 从 header rehydrate 出带 trace 键的 Message。
            let mut md = tenant_metadata("msg-e2e-trace");
            md.insert_wire_pair(diport::KEY_TRACE, producer_tp.as_str().to_owned());
            let msg = Message::new_with_metadata("msg-e2e-trace", b"payload".to_vec(), md);

            let handler = move |_m: Message| -> futures::future::BoxFuture<'static, HandleResult> {
                let seen = seen_handler.clone();
                Box::pin(async move {
                    // handler 经 `.instrument(consume_span)` 在还原后的消费 span 内执行。
                    *seen.lock().unwrap() = tracewire::capture_current()
                        .map(|context| trace_id_of(context.traceparent().as_str()));
                    HandleResult::ack()
                })
            };

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(run_consumer(
                Box::pin(futures::stream::iter(vec![msg])),
                FakeInboxStore::fresh(),
                fake_dlx(FakeDeadLetterStore::new()),
                meta(),
                handler,
                lease_cfg_test(),
                consumer_admission(),
            ));
            trace_id_of(producer_tp.as_str())
        });

        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some(producer_trace_id.as_str()),
            "run_consumer 经 handle_fresh 读 KEY_TRACE → 还原 → instrument ⇒ handler 与 producer 同 trace_id"
        );
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    #[test]
    fn verified_consumer_parent_is_the_generated_event_causation() {
        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let seen_handler = seen.clone();
        let message_id = "verified-parent-event-1";
        let msg = message(message_id, b"payload");

        let handler = move |_m: Message| -> futures::future::BoxFuture<'static, HandleResult> {
            let seen = seen_handler.clone();
            Box::pin(async move {
                let tenant = tenant();
                let payload = generated::event::settings_v1::SettingsConfigVersionChangedPayload {
                    change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Published,
                    key: "consumer.child".to_owned(),
                    occurred_at: 1,
                    source_version: None,
                    tenant_id: tenant.to_string(),
                    version: 1,
                };
                let event = generated::event::settings_v1::emit(
                    &crate::event::GeneratedEventEncoder,
                    payload,
                    tenant,
                    diport::EnvelopeSubjectId::from_opaque("consumer.child").expect("subject"),
                    diport::OutboxActor::scoped(
                        rss_request_context::PrincipalKind::Service,
                        diport::OpaqueActorId::from_opaque("consumer-service").expect("actor"),
                        tenant,
                        rss_request_context::RowScope::Tenant,
                    ),
                    IdemKey::parse("child-event-1").expect("idempotency key"),
                )
                .await
                .expect("generated event");
                *seen.lock().unwrap() = event
                    .envelope()
                    .causation_id()
                    .map(|id| id.as_str().to_owned());
                HandleResult::ack()
            })
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run_consumer(
            Box::pin(futures::stream::iter(vec![msg])),
            FakeInboxStore::fresh(),
            fake_dlx(FakeDeadLetterStore::new()),
            meta(),
            handler,
            lease_cfg_test(),
            consumer_admission(),
        ));

        assert_eq!(seen.lock().unwrap().as_deref(), Some(message_id));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn oversized_parent_identity_is_rejected_before_the_handler() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_handler = calls.clone();
        let message_id = "x".repeat(257);
        let msg = message(&message_id, b"payload");
        let handler = move |_m: Message| -> futures::future::BoxFuture<'static, HandleResult> {
            let calls = calls_handler.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                HandleResult::ack()
            })
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run_consumer(
            Box::pin(futures::stream::iter(vec![msg])),
            FakeInboxStore::fresh(),
            fake_dlx(FakeDeadLetterStore::new()),
            meta(),
            handler,
            lease_cfg_test(),
            consumer_admission(),
        ));

        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
