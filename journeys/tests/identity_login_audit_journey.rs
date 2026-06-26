//! #1100 / #1171 journey：identity 登录 → durable outbox 发射 → ConsumerBase 幂等消费 → audit append，
//! 组装在 bootstrap（compose + ShutdownStack）+ eventexec（ConsumerWorker 驱动 run_consumer）+ memory
//! （in-mem DI port 替身）上，端到端证明 L2 OutboxFact 闭环（登录 → outbox → 受监督 worker 分发 → audit，
//! 以 EventId 幂等去重）。
//!
//! 接缝覆盖：
//! - bootstrap 组装：`compose` 跑 identity/audit 的 `Domain::init` → Registry 收集 route_group + subscriber。
//! - DI 注入：identity 经 `Box<DynSessionLifecycle>`（`MemSessionLifecycle`）co-tx 写 session + 发射 outbox
//!   fact（demo 拓扑）；audit 经注入的链 `MacVerifier`（journey 捕获 verifier）落**域内哈希链**（W：无外部
//!   sink）；幂等 store 经 `memory::InMemClaimer` 注入、DLX 经 `memory::MemDeadLetterStore` 注入。
//! - 跨域事件：identity emit `identity.session-created` → MemBus（Message.id = EventId）→ audit 订阅消费。
//! - **消费（#1171 实交付）**：bootstrap `SubscriberHandler` 经 `bootstrap::adapt_subscriber_handler` 适配成
//!   `run_consumer` 的 `HandleResult` handler，再经 `eventexec::ConsumerWorker`（专用线程驱动 `run_consumer`、
//!   impl `ManagedResource`）接 `bootstrap::shutdown::ShutdownStack` 两阶段关闭——闭合「`run_consumer` 0 个
//!   真实调用点」缺口：ConsumerBase 由真实受监督后台 worker 驱动，而非内联 `tokio::join!`。
//! - 幂等（acc #2）：relay 重投同一 EventId → audit 仅 append 一次（`relay_redelivery_audits_once`）。
//! - DLX：handler 永久失败 → ConsumerBase 写死信到 `MemDeadLetterStore`（`demo_handler_error_writes_dead_letter`）。
//!
//! 订阅顺序：MemBus 无重放（订阅须先于发布），故 journey **先**同步 `subscribe(topic, token)` 得 stream、**再**
//! spawn `ConsumerWorker` 驱动该 stream（subscribe-at-callsite，token 与 stream 同源；worker 在
//! `ManagedResource::shutdown` 自取消 token 终止流——经 `register_detached` 注册）。
//!
//! 边界（W）：服务层闭环——登录服务直接调用，不逐字节跑 axum（admin 读 handler 经 axum oneshot 单测覆盖，
//! 见 audit crate）；envelope 的 trace/correlation reserved-key sealed setter 已建（#1193），但注入源留 W（待 #1296）；audit
//! domain 哈希链 #1014 已写实——append 落每租户 keyed HMAC 链（journey 经捕获 verifier 端到端验链 append）。
//! durable（postgres/amqp）拓扑闭环见 `identity_login_audit_durable_journey.rs`（`--features integration`，#1171 §6：ackable consumer 真 broker）。
//!
//! ref: watermill message/router/middleware/poison.go（ConsumerBase DLX）
//! ref: uber-go/fx app.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（组合根装配 + lifecycle 关闭）
//!
//! 注：本 journey **不** feature-gate——全程 in-process（in-mem DI 替身、确定性、毫秒级），是 `cargo test` /
//! `cargo xtask verify` 默认跑的验收门，故有意不隔离。

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::Result;
use bootstrap::replaydeps::resolve;
use bootstrap::shutdown::ShutdownStack;
use bootstrap::{
    IdempotencyConfig, ResolvedIdempotency, SubscriberBinding, SubscriberHandler, Topology,
    adapt_subscriber_handler,
};
use common::{
    CANON_TENANT, CANON_USER, LOGIN_USERNAME, NOW_SECS, PASSWORD, SESSION_CREATED_TOPIC, TTL_SECS,
    audit_domain, single_subscription,
};
use consistency::{
    EngineError, Entry, HandleResult, IdemKey, IdempotencyStore, LeaseOutcome, LeaseToken,
    PermanentError, PermanentErrorKind, SeenState,
};
use diport::{
    DynDeadLetterStore, DynManagedResource, Message, OutboxEmitter, OutboxEnvelopeParts,
    Subscriber, Topic,
};
use eventexec::{ConsumerMeta, EVENT_CONSUMER_PROBE, LeaseConfig, WorkerHealth, spawn_consumer};
use futures::future::BoxFuture;
use generated::http::identity_v1::IdentityLoginRequest;
use identity::ports::DynSessionLifecycle;
use identity::{IdentityDomain, LoginService};
use memory::{
    FixedClock, InMemClaimer, MemBus, MemDeadLetterStore, MemEmitter, MemSessionLifecycle,
};
use primitives::ListenerKind;
use primitives::healthz::HealthStatus;
use tokio_util::sync::CancellationToken;
use vocab::TenantId;

/// 手造 relay payload 的 session_id——审计 resource id 是 typed `ids::SessionId`（canonical uuid）。
const CANON_SESSION: &str = "22222222-3333-4444-8555-666666666666";

/// 有界等待断言条件成立（防消费未跑挂死）；超时即 `Err`。
async fn wait_until(mut pred: impl FnMut() -> bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !pred() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

/// dev-root 决策绑定构造 demo in-mem claimer（TOPO-INMEM-SEAL-01 dev-root discipline）：经
/// `bootstrap::replaydeps::resolve(Topology::Demo, ..)` 决策臂构造，**不**直接 raw-new——把 in-mem 构造收束到
/// 已校验的拓扑决策（review #274 F6/C6：原 journey 直接 `InMemClaimer::new` 旁路了 resolve 决策绑定）。
fn demo_claimer(group: consistency::ConsumerGroup) -> Result<InMemClaimer> {
    match resolve(Topology::Demo, IdempotencyConfig::default())? {
        ResolvedIdempotency::Demo => Ok(InMemClaimer::new(group)),
        other => anyhow::bail!("demo journey 须解析为 Demo 幂等决策，实得 {other:?}"),
    }
}

/// 记录型幂等 claimer（F5 可观测替身）：包内层 claimer，计 `try_claim` 调用次数 + `Duplicate` 命中次数，
/// 让重投测试可等待「第二条同 EventId 已被 consumer 读取并判 Duplicate」这一**中间事实**（claim_count==2 &&
/// duplicate_count==1），替代固定 sleep 的假阳性（review #274 F5/C5）。
struct RecordingClaimer<S> {
    inner: S,
    claim_count: Arc<AtomicU32>,
    duplicate_count: Arc<AtomicU32>,
}

impl<S> RecordingClaimer<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            claim_count: Arc::new(AtomicU32::new(0)),
            duplicate_count: Arc::new(AtomicU32::new(0)),
        }
    }
    fn claim_count(&self) -> Arc<AtomicU32> {
        self.claim_count.clone()
    }
    fn duplicate_count(&self) -> Arc<AtomicU32> {
        self.duplicate_count.clone()
    }
}

impl<S: IdempotencyStore + Send + Sync> IdempotencyStore for RecordingClaimer<S> {
    async fn try_claim(&self, key: &IdemKey, lease: &LeaseToken) -> Result<SeenState, EngineError> {
        let state = self.inner.try_claim(key, lease).await?;
        self.claim_count.fetch_add(1, Ordering::SeqCst);
        if matches!(state, SeenState::Duplicate) {
            self.duplicate_count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(state)
    }
    async fn extend(&self, key: &IdemKey, lease: &LeaseToken) -> Result<LeaseOutcome, EngineError> {
        self.inner.extend(key, lease).await
    }
    async fn commit(&self, key: &IdemKey, lease: &LeaseToken) -> Result<LeaseOutcome, EngineError> {
        self.inner.commit(key, lease).await
    }
    async fn release(&self, key: &IdemKey, lease: &LeaseToken) -> Result<(), EngineError> {
        self.inner.release(key, lease).await
    }
}

/// Demo 拓扑 consumer worker 接线（#1171）：MemBus **先**订阅（先于发布，token 与 stream 同源）→ spawn
/// `ConsumerWorker`（专用线程驱动 `run_consumer`）→ `register_detached` 进 `ShutdownStack`。返回 worker 的
/// health 句柄供断言（worker 已 move 进 stack）。`claimer` 由调用方经 [`demo_claimer`] 决策绑定构造（F6），
/// 重投测试可传 [`RecordingClaimer`] 观测幂等中间事实（F5）。
///
/// `register_detached`（非 `register_with_token`）：subscribe 在 callsite 先于 spawn、token 须与 stream 同源，
/// worker 后台线程监听自持 token、于 `ManagedResource::shutdown` 自取消（不依赖 stack 阶段 1 广播）。
#[allow(clippy::too_many_arguments)]
// reason: journey 接线 helper 的参数集（bus/claimer/contract_id/topic/dlx/handler/token/stack 各自语义独立）；
// 聚合 struct 仅此 4 测试复用、收益低，item-level carve-out（error-handling.md §Carve-out）。
async fn wire_demo_consumer<H, S>(
    bus: &MemBus,
    claimer: Arc<S>,
    contract_id: &'static str,
    topic: &'static str,
    dlx: MemDeadLetterStore,
    handler: H,
    token: CancellationToken,
    stack: &mut ShutdownStack,
) -> Result<Arc<WorkerHealth>>
where
    H: Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static,
    S: IdempotencyStore + Send + Sync + 'static,
{
    // 订阅须先于发布（in-mem 无重放）：同步 subscribe 得 stream，再 spawn worker 驱动。
    let stream = bus
        .subscriber()
        .subscribe(Topic::new(topic), token.clone())
        .await?;
    let meta = ConsumerMeta::new("audit", contract_id, topic);
    let health = Arc::new(WorkerHealth::healthy());
    let name = format!("{EVENT_CONSUMER_PROBE}:audit:{topic}");
    // reason: demo InMemClaimer 无后端 TTL；占位续租间隔（生产 wiring 用 store.lease_ttl() 派生，#1213 review #3）。
    let lease_cfg = LeaseConfig::from_ttl(std::time::Duration::from_secs(60));
    let worker = spawn_consumer(
        name,
        stream,
        claimer,
        DynDeadLetterStore::new_box(dlx),
        meta,
        handler,
        lease_cfg,
        token,
        health.clone(),
    );
    stack.register_detached(DynManagedResource::new_box(worker));
    Ok(health)
}

/// 登录服务（注入 MemSessionLifecycle co-tx 替身 + 固定时钟 + 种子凭据）。
#[allow(clippy::expect_used)]
fn login_service(bus: &MemBus, tenant: TenantId) -> Result<LoginService> {
    Ok(LoginService::with_seed_credential(
        DynSessionLifecycle::new_box(MemSessionLifecycle::new(bus.clone())),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        tenant,
    )?)
}

#[tokio::test(flavor = "multi_thread")]
async fn login_emits_event_audited_end_to_end() -> Result<()> {
    let bus = MemBus::new();

    // bootstrap 组装：identity 声明登录路由组，audit 声明 session-created 订阅 + admin 读路由组。
    let (audit_domain, audit) = audit_domain();
    let registry = bootstrap::compose(&[&IdentityDomain, &audit_domain])?;

    let route_groups = registry.route_groups();
    assert_eq!(
        route_groups.len(),
        2,
        "identity 登录路由组 + audit admin 读路由组"
    );
    assert!(
        route_groups.contains(&(ListenerKind::Primary, "/api/v1/identity")),
        "identity 登录路由组: {route_groups:?}"
    );
    assert!(
        route_groups.contains(&(ListenerKind::Admin, "/api/v1/audit")),
        "audit admin 读路由组: {route_groups:?}"
    );
    assert_eq!(registry.probe_count(), 0, "未注册探针");

    // #1171：经受监督 ConsumerWorker（专用线程驱动 run_consumer）+ ShutdownStack 驱动订阅消费。
    let binding = single_subscription(registry)?;
    assert_eq!(binding.topic, SESSION_CREATED_TOPIC);
    let SubscriberBinding {
        contract_id,
        topic,
        group,
        handler,
    } = binding;
    let token = CancellationToken::new();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    let claimer = Arc::new(demo_claimer(group)?);
    let health = wire_demo_consumer(
        &bus,
        claimer,
        contract_id,
        topic,
        MemDeadLetterStore::new(),
        adapt_subscriber_handler(handler),
        token.clone(),
        &mut stack,
    )
    .await?;

    // 登录（emit）+ 等 audit；worker 在独立线程并发消费，无需同任务 `tokio::join!`。
    let tenant = TenantId::parse(CANON_TENANT)?;
    let login = login_service(&bus, tenant)?;
    let response = login
        .login(
            tenant,
            IdentityLoginRequest {
                // 非 uuid 登录标识——旧实现会把 "alice" 当 subject 写 wire，audit 断链（#1277 F1 证伪点）。
                username: LOGIN_USERNAME.to_string(),
                password: PASSWORD.to_string(),
            },
        )
        .await?;
    wait_until(|| !audit.is_empty()).await?;

    // 两阶段关闭：ConsumerWorker 经 ManagedResource::shutdown 自取消 token → stream 终止 → join。
    let failures = stack.shutdown().await;
    assert!(
        failures.is_empty(),
        "ShutdownStack 关闭无失败: {failures:?}"
    );
    assert_eq!(
        health.status(),
        HealthStatus::Unhealthy,
        "worker 退出后 health Unhealthy（readyz 翻）"
    );

    assert!(!response.data.session_id.is_empty(), "返回会话 id");
    assert_eq!(
        response.data.expires_at,
        i64::try_from(NOW_SECS + TTL_SECS)?,
        "到期 = now + ttl"
    );

    // W：审计落域内哈希链（无外部 sink）——经捕获 verifier 验恰一次 append + 登录产物贯穿到链 canonical 输入。
    let audited = audit.audited();
    assert_eq!(audited.len(), 1, "恰一次审计链 append 闭环");
    let message = &audited[0];
    let contains = |needle: &[u8]| message.windows(needle.len()).any(|w| w == needle);
    assert!(
        contains(response.data.session_id.as_bytes()),
        "会话 id 贯穿闭环（进审计链 canonical 输入）"
    );
    assert!(contains(b"identity:login"), "登录动作贯穿闭环");
    // F9：tenant / actor 的 16B 原始 UUID 字节贯穿到审计链 canonical 输入。#1277 F1：actor = canonical
    // CANON_USER（credential.user_id），**非**登录标识 "alice"。
    let tenant_uuid_bytes = uuid::Uuid::parse_str(CANON_TENANT)?.into_bytes();
    let actor_uuid_bytes = uuid::Uuid::parse_str(CANON_USER)?.into_bytes();
    assert!(contains(&tenant_uuid_bytes), "tenant UUID 16B 贯穿闭环");
    assert!(
        contains(&actor_uuid_bytes),
        "actor = canonical user id 16B 贯穿闭环（非登录标识 \"alice\"，#1277 F1）"
    );
    assert!(
        !contains(LOGIN_USERNAME.as_bytes()),
        "登录标识 \"alice\" 不得进审计链 canonical 输入（准 PII，#1277 F1）"
    );
    Ok(())
}

/// acc #2（L2 consumer 幂等）：relay 重投同一 EventId 的 session.created → audit 仅 append 一次。
/// 经 `MemEmitter` 发同一 `Entry`（同 idem_key）两次，共享同一 `InMemClaimer` 经受监督 ConsumerWorker 消费——
/// 首次 `Fresh`（handler 跑、append）、二次 `Duplicate`（短路）。
#[tokio::test(flavor = "multi_thread")]
async fn relay_redelivery_audits_once() -> Result<()> {
    let bus = MemBus::new();
    let (audit_domain, audit) = audit_domain();
    let registry = bootstrap::compose(&[&audit_domain])?;

    let SubscriberBinding {
        contract_id,
        topic,
        group,
        handler,
    } = single_subscription(registry)?;

    // anti-vacuity（acc #2）：计数器包装 handler，证明内层 handler 恰调用一次——ConsumerBase 幂等短路
    // 第二条投递（不执行 handler），而非 sink 自身去重。
    let handler_call_count = Arc::new(AtomicU32::new(0));
    let counter = handler_call_count.clone();
    let inner: Arc<dyn SubscriberHandler> = Arc::from(handler);
    let counted = move |message: Message| -> BoxFuture<'static, HandleResult> {
        let inner = inner.clone();
        let counter = counter.clone();
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            match inner.handle(message).await {
                Ok(()) => HandleResult::ack(),
                Err(e) => {
                    tracing::warn!(error = %e, "journey: counted handler errored, rejecting");
                    HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent))
                }
            }
        })
    };

    let token = CancellationToken::new();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    // F5：RecordingClaimer 包决策绑定的 demo claimer，暴露 try_claim/duplicate 计数供可观测等待（去固定 sleep）。
    let recording = Arc::new(RecordingClaimer::new(demo_claimer(group)?));
    let claim_count = recording.claim_count();
    let duplicate_count = recording.duplicate_count();
    wire_demo_consumer(
        &bus,
        recording,
        contract_id,
        topic,
        MemDeadLetterStore::new(),
        counted,
        token.clone(),
        &mut stack,
    )
    .await?;

    // 同一 EventId（idem_key）的 entry 发两次 = relay 崩溃重启重投同一 outbox entry。
    const EVENT_ID: &str = "evt-redeliver-fixed";
    let payload = format!(
        r#"{{"sessionId":"{CANON_SESSION}","subject":"{CANON_USER}","tenantId":"{CANON_TENANT}","occurredAt":{NOW_SECS}}}"#
    )
    .into_bytes();
    let emitter = MemEmitter::new(bus.clone());
    for _ in 0..2 {
        let entry = Entry::new(
            consistency::Topic::parse(SESSION_CREATED_TOPIC)
                .map_err(|_| anyhow::anyhow!("topic parse"))?,
            IdemKey::parse(EVENT_ID).map_err(|_| anyhow::anyhow!("idem parse"))?,
            payload.clone(),
        );
        emitter
            .emit(
                entry,
                OutboxEnvelopeParts::new(generated::event::identity_v1::CONTRACT, CANON_USER),
            )
            .await
            .map_err(|_| anyhow::anyhow!("emit"))?;
    }
    // F5：等可观测中间事实——第二条同 EventId 已被 consumer 读取（claim_count==2）且判 Duplicate
    // （duplicate_count==1），证「第二条已消费并幂等短路」，替代固定 sleep 的假阳性（review #274 F5/C5）。
    wait_until(|| {
        claim_count.load(Ordering::SeqCst) >= 2 && duplicate_count.load(Ordering::SeqCst) >= 1
    })
    .await?;

    let failures = stack.shutdown().await;
    assert!(
        failures.is_empty(),
        "ShutdownStack 关闭无失败: {failures:?}"
    );

    assert_eq!(
        claim_count.load(Ordering::SeqCst),
        2,
        "两条投递均被 consumer 读取（idempotency try_claim 各一次）"
    );
    assert_eq!(
        duplicate_count.load(Ordering::SeqCst),
        1,
        "第二条同 EventId 判 Duplicate 恰一次（幂等短路可观测证据，替代 sleep 假阳性，F5/C5）"
    );
    assert_eq!(
        audit.audited().len(),
        1,
        "重投同一 EventId → audit 链仅 append 一次（L2 consumer 幂等）"
    );
    assert_eq!(
        handler_call_count.load(Ordering::SeqCst),
        1,
        "ConsumerBase 幂等：handler 恰调用一次，第二次投递被 Duplicate 短路"
    );
    Ok(())
}

/// 负路径：未知用户登录被拒，不发射事件 ⇒ audit 保持空（闭环不被错误触发）。
#[tokio::test(flavor = "multi_thread")]
async fn rejected_login_does_not_audit() -> Result<()> {
    let bus = MemBus::new();
    let (audit_domain, audit) = audit_domain();
    let registry = bootstrap::compose(&[&IdentityDomain, &audit_domain])?;

    let SubscriberBinding {
        contract_id,
        topic,
        group,
        handler,
    } = single_subscription(registry)?;
    let token = CancellationToken::new();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    let claimer = Arc::new(demo_claimer(group)?);
    wire_demo_consumer(
        &bus,
        claimer,
        contract_id,
        topic,
        MemDeadLetterStore::new(),
        adapt_subscriber_handler(handler),
        token.clone(),
        &mut stack,
    )
    .await?;

    let tenant = TenantId::parse(CANON_TENANT)?;
    let login = login_service(&bus, tenant)?;
    let result = login
        .login(
            tenant,
            IdentityLoginRequest {
                username: "mallory".to_string(),
                password: PASSWORD.to_string(),
            },
        )
        .await;
    // 给任何误发射的事件被消费的时间，随后关闭。
    tokio::time::sleep(Duration::from_millis(20)).await;
    let failures = stack.shutdown().await;
    assert!(
        failures.is_empty(),
        "ShutdownStack 关闭无失败: {failures:?}"
    );

    assert!(result.is_err(), "未知用户登录被拒");
    assert!(audit.is_empty(), "登录失败不产生审计链 append");
    Ok(())
}

/// Demo DLX 分支：handler 永久失败 → ConsumerBase 写死信到 `MemDeadLetterStore`（重投预算后落库收口）。
/// 证 demo 拓扑 consumer worker 的死信路径接线（生产走 `PgDeadLetterStore`，逻辑同源）。
#[tokio::test(flavor = "multi_thread")]
async fn demo_handler_error_writes_dead_letter() -> Result<()> {
    let bus = MemBus::new();
    let (audit_domain, _audit) = audit_domain();
    let registry = bootstrap::compose(&[&audit_domain])?;

    let SubscriberBinding {
        contract_id,
        topic,
        group,
        handler: _,
    } = single_subscription(registry)?;

    // 永久失败 handler（绕过真实 audit handler）：恒 reject → ConsumerBase 写 DLX。
    let erroring = move |_msg: Message| -> BoxFuture<'static, HandleResult> {
        Box::pin(
            async move { HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent)) },
        )
    };

    let dlx = MemDeadLetterStore::new();
    let token = CancellationToken::new();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    let claimer = Arc::new(demo_claimer(group)?);
    wire_demo_consumer(
        &bus,
        claimer,
        contract_id,
        topic,
        dlx.clone(),
        erroring,
        token.clone(),
        &mut stack,
    )
    .await?;

    // 发一条 session-created → handler reject → DLX 写一条。
    let entry = Entry::new(
        consistency::Topic::parse(SESSION_CREATED_TOPIC)
            .map_err(|_| anyhow::anyhow!("topic parse"))?,
        IdemKey::parse("evt-dlx-fixed").map_err(|_| anyhow::anyhow!("idem parse"))?,
        b"{}".to_vec(),
    );
    MemEmitter::new(bus.clone())
        .emit(
            entry,
            OutboxEnvelopeParts::new(generated::event::identity_v1::CONTRACT, CANON_USER),
        )
        .await
        .map_err(|_| anyhow::anyhow!("emit"))?;
    wait_until(|| dlx.len() == 1).await?;

    let failures = stack.shutdown().await;
    assert!(
        failures.is_empty(),
        "ShutdownStack 关闭无失败: {failures:?}"
    );

    let records = dlx.records();
    assert_eq!(
        records.len(),
        1,
        "永久失败 → 死信落 MemDeadLetterStore 一条"
    );
    assert_eq!(
        records[0].topic(),
        SESSION_CREATED_TOPIC,
        "死信记录归因 topic"
    );
    assert_eq!(
        records[0].domain(),
        "audit",
        "死信记录 domain 归因（ConsumerMeta domain）"
    );
    assert_eq!(
        records[0].num_attempts(),
        1,
        "handler 恒 reject：首次即终态（Reject 路径不重投，num_attempts = 1）"
    );
    assert_eq!(
        records[0].error_summary(),
        "permanent error",
        "PermanentErrorKind::Permanent 的 error_summary"
    );
    Ok(())
}
