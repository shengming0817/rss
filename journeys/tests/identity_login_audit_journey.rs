//! #1100 / T008 journey：identity 登录 → durable outbox 发射 → ConsumerBase 幂等消费 → audit append，
//! 组装在 bootstrap（compose）+ eventexec（run_consumer）+ memory（in-mem DI port 替身）上，
//! 端到端证明 L2 OutboxFact 闭环（登录 → outbox → relay/分发 → audit，以 EventId 幂等去重）。
//!
//! 接缝覆盖：
//! - bootstrap 组装：`compose` 跑 identity/audit 的 `Domain::init` → Registry 收集 route_group + subscriber。
//! - DI 注入：identity 经 `Box<DynOutboxEmitter>`（`MemEmitter`）发射 durable outbox fact；audit 经
//!   `Arc<MemAuditSink>` 落审计；幂等 store 经 `run_consumer` 注入。
//! - 跨域事件：identity emit `identity.session-created` → MemBus（Message.id = EventId）→ audit 订阅消费。
//! - 消费：bootstrap `SubscriberHandler` 经组合根 adapt 成 `run_consumer` 的 `HandleResult` handler，
//!   `ConsumerBase` 自持 claim→handle→commit/release 幂等生命周期（键 = msg.id = EventId）。
//! - 幂等（acc #2）：relay 重投同一 EventId → audit 仅 append 一次（`relay_redelivery_audits_once`）。
//!
//! 并发形态：`run_consumer` future 持 `&DynDeadLetterStore`（Send-非-Sync）跨 await ⇒ **!Send**、不可
//! `tokio::spawn`（与 eventexec 单测「直接 await」一致）。journey 用 `tokio::join!` 同任务并发驱动
//! 消费 future 与「登录 emit + 等 sink + cancel」驱动 future——无跨线程 Send 约束。
//!
//! 边界（W）：服务层闭环——登录服务直接调用，不逐字节跑 axum（httpserve mount 留 W）；envelope 的
//! trace/correlation reserved-key 注入留 W（funnel 现无 sealed setter）；audit domain 哈希链保持冻结。
//! durable（postgres/amqp）拓扑闭环见 `identity_login_audit_durable_journey.rs`（`--features integration`）。
//!
//! ref: watermill message/router/middleware/poison.go（ConsumerBase DLX）
//! ref: uber-go/fx app.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（组合根装配）
//!
//! 注：本 journey **不** feature-gate——全程 in-process（in-mem DI 替身、确定性、毫秒级），是 `cargo test` /
//! `cargo xtask verify` 默认跑的验收门，故有意不隔离。

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use audit::AuditDomain;
use bootstrap::SubscriberHandler;
use consistency::{
    EngineError, Entry, HandleResult, IdemKey, IdempotencyStore, PermanentError,
    PermanentErrorKind, SeenState,
};
use diport::{
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore, DynOutboxEmitter,
    Message, OutboxEmitter, OutboxEnvelopeParts, Subscriber, Topic,
};
use eventexec::{ConsumerMeta, run_consumer};
use futures::future::BoxFuture;
use generated::http::identity_v1::IdentityLoginRequest;
use identity::{IdentityDomain, LoginService};
use memory::{FixedClock, MemAuditSink, MemBus, MemEmitter};
use primitives::ListenerKind;
use tokio_util::sync::CancellationToken;

/// canonical UUID 种子租户（TenantId::parse 接受形态）。
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
/// session-created event 契约 topic（identity 发布 / audit 订阅）。
const SESSION_CREATED_TOPIC: &str = "identity.session-created";
/// 登录种子凭据。
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct-horse";
const SUBJECT: &str = "alice-subject";
/// 固定登录时刻 + 会话 ttl（确定性断言）。
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;

// ── 测试替身：demo 拓扑的幂等 store + DLX（生产经 topology 选型 postgres/redis）──────────

/// 进程内幂等 store（impl `consistency::IdempotencyStore`）：以 key 集合记首见，首见 `Fresh`、再见
/// `Duplicate`。等价 demo 拓扑的 in-mem claimer；journey-local 替身（`memory::InMemClaimer::new` 是
/// `pub(crate)`、仅经 sealed resolver 可达，journey 用本地替身验幂等语义，不破坏 sealing）。
#[derive(Default)]
struct JourneyClaimer {
    seen: Mutex<HashSet<String>>,
}

impl IdempotencyStore for JourneyClaimer {
    async fn check(&self, key: &IdemKey) -> Result<SeenState, EngineError> {
        let fresh = self
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.as_str().to_string());
        Ok(if fresh {
            SeenState::Fresh
        } else {
            SeenState::Duplicate
        })
    }

    async fn commit(&self, _key: &IdemKey) -> Result<(), EngineError> {
        // reason: HashSet 记首见集合（absent / seen），commit 不改集合 ⇒ check 仍 Duplicate，满足永久去重。
        Ok(())
    }

    async fn release(&self, key: &IdemKey) -> Result<(), EngineError> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key.as_str());
        Ok(())
    }
}

/// noop DLX（impl `diport::DeadLetterStore`）：journey 不验死信路径（eventexec consumer.rs 已覆盖），写入恒 Ok。
struct NoopDlx;

impl DeadLetterStore for NoopDlx {
    async fn write_dead_letter(
        &self,
        _record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        // reason: journey 不触发死信（handler happy-path Ack）；DLX 三路径由 eventexec consumer 单测覆盖。
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

/// 把 bootstrap `SubscriberHandler` 适配成 `run_consumer` 的 `HandleResult` handler（组合根职责：
/// bootstrap 与 eventexec 是兄弟服务、互不依赖，handler 类型在此跨接）。Ok→`ack`；Err→`reject`（永久——
/// 解码 / 租户非法不可重试，对齐 audit handler 语义），由 ConsumerBase 收口到 DLX。
fn consumer_handler(
    handler: Box<dyn SubscriberHandler>,
) -> impl Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync {
    let handler: Arc<dyn SubscriberHandler> = Arc::from(handler);
    move |message: Message| {
        let handler = handler.clone();
        Box::pin(async move {
            match handler.handle(message).await {
                Ok(()) => HandleResult::ack(),
                Err(e) => {
                    tracing::warn!(error = %e, "journey: subscriber handler errored, rejecting (permanent)");
                    HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent))
                }
            }
        })
    }
}

/// 等待 sink 非空（有界超时，防消费未跑挂死）。超时即 `Err`，由调用方在 cancel 后再传播（避免悬挂）。
async fn wait_until_audited(sink: &MemAuditSink) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while sink.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

/// 取唯一 session-created 订阅绑定（断言恰一个）。
fn single_subscription(
    registry: bootstrap::Registry,
) -> anyhow::Result<bootstrap::SubscriberBinding> {
    let mut subs = registry.into_subscribers();
    anyhow::ensure!(subs.len() == 1, "恰一个 session-created 订阅");
    subs.pop().ok_or_else(|| anyhow::anyhow!("订阅缺失"))
}

#[tokio::test(flavor = "multi_thread")]
async fn login_emits_event_audited_end_to_end() -> Result<()> {
    let bus = MemBus::new();
    let sink = Arc::new(MemAuditSink::new());

    // bootstrap 组装：identity 声明登录路由组，audit 声明 session-created 订阅。
    let audit_domain = AuditDomain::new(sink.clone());
    let registry = bootstrap::compose(&[&IdentityDomain, &audit_domain])?;

    let route_groups = registry.route_groups();
    assert_eq!(route_groups.len(), 1, "identity 登录路由组已声明");
    assert_eq!(route_groups[0], (ListenerKind::Primary, "/api/v1/identity"));
    assert_eq!(registry.probe_count(), 0, "未注册探针");

    // 订阅经 run_consumer（幂等消费驱动）接线（订阅须先于发布——in-mem 无重放）。
    let token = CancellationToken::new();
    let claimer = Arc::new(JourneyClaimer::default());
    let binding = single_subscription(registry)?;
    assert_eq!(binding.topic, SESSION_CREATED_TOPIC);
    let stream = bus
        .subscriber()
        .subscribe(Topic::new(binding.topic), token.clone())
        .await?;
    let meta = ConsumerMeta::new("audit", binding.contract_id, binding.topic);
    let consume = run_consumer(
        stream,
        claimer.clone(),
        DynDeadLetterStore::new_box(NoopDlx),
        meta,
        consumer_handler(binding.handler),
    );

    // 登录：注入 MemEmitter（durable outbox 发射替身）+ 固定时钟。emit + 等 audit + cancel 收口。
    let login = LoginService::with_seed_user(
        DynOutboxEmitter::new_box(MemEmitter::new(bus.clone())),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        USERNAME,
        PASSWORD,
        SUBJECT,
        CANON_TENANT,
    );
    let drive = async {
        let response = login
            .login(IdentityLoginRequest {
                username: USERNAME.to_string(),
                password: PASSWORD.to_string(),
            })
            .await;
        let waited = wait_until_audited(&sink).await;
        token.cancel(); // 无条件 cancel：consume future 终止，join! 不悬挂。
        let response = response?;
        waited?;
        anyhow::Ok(response)
    };

    // 同任务并发：consume future（!Send，不可 spawn）与 drive future。
    let (_, response) = tokio::join!(consume, drive);
    let response = response?;

    assert!(!response.data.session_id.is_empty(), "返回会话 id");
    assert_eq!(
        response.data.expires_at,
        i64::try_from(NOW_SECS + TTL_SECS)?,
        "到期 = now + ttl"
    );

    let records = sink.records();
    assert_eq!(records.len(), 1, "恰一条审计记录闭环");
    let record = &records[0];
    assert_eq!(record.action, "login");
    assert_eq!(record.resource_kind, "session");
    assert_eq!(
        record.resource_id, response.data.session_id,
        "会话 id 贯穿闭环"
    );
    assert_eq!(record.principal_id, SUBJECT);
    assert_eq!(record.tenant_id.to_string(), CANON_TENANT, "租户贯穿闭环");
    Ok(())
}

/// acc #2（L2 consumer 幂等）：relay 重投同一 EventId 的 session.created → audit 仅 append 一次。
/// 模拟：经 `MemEmitter` 发同一 `Entry`（同 EventId / idem_key）两次，共享同一幂等 claimer 经 `run_consumer`
/// 消费——首次 `Fresh`（handler 跑、append）、二次 `Duplicate`（短路）。
#[tokio::test(flavor = "multi_thread")]
async fn relay_redelivery_audits_once() -> Result<()> {
    let bus = MemBus::new();
    let sink = Arc::new(MemAuditSink::new());
    let registry = bootstrap::compose(&[&AuditDomain::new(sink.clone())])?;

    let token = CancellationToken::new();
    let claimer = Arc::new(JourneyClaimer::default());
    let binding = single_subscription(registry)?;

    // anti-vacuity（acc #2）：用计数器包装 handler，证明内层 handler 恰调用一次——
    // ConsumerBase 幂等短路第二条投递（不执行 handler），而非 sink 自身去重。
    let handler_call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter = handler_call_count.clone();
    let inner_handler: Arc<dyn SubscriberHandler> = Arc::from(binding.handler);
    let counted_handler = {
        let inner = inner_handler.clone();
        move |message: Message| -> futures::future::BoxFuture<'static, HandleResult> {
            let inner = inner.clone();
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match inner.handle(message).await {
                    Ok(()) => HandleResult::ack(),
                    Err(e) => {
                        tracing::warn!(error = %e, "journey: counted handler errored, rejecting");
                        HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent))
                    }
                }
            })
        }
    };

    let stream = bus
        .subscriber()
        .subscribe(Topic::new(binding.topic), token.clone())
        .await?;
    let meta = ConsumerMeta::new("audit", binding.contract_id, binding.topic);
    let consume = run_consumer(
        stream,
        claimer.clone(),
        DynDeadLetterStore::new_box(NoopDlx),
        meta,
        counted_handler,
    );

    // 同一 EventId（idem_key）的 entry 发两次 = relay 崩溃重启重投同一 outbox entry。payload 为合法
    // session-created JSON（camelCase）；EventId 与 payload.sessionId 解耦（去重锚点是 EventId）。
    const EVENT_ID: &str = "evt-redeliver-fixed";
    let payload = format!(
        r#"{{"sessionId":"sess-redeliver","subject":"{SUBJECT}","tenantId":"{CANON_TENANT}","occurredAt":{NOW_SECS}}}"#
    )
    .into_bytes();
    let emitter = MemEmitter::new(bus.clone());
    let drive = async {
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
                    OutboxEnvelopeParts {
                        domain: "identity".to_string(),
                        contract_id: SESSION_CREATED_TOPIC.to_string(),
                        subject_id: SUBJECT.to_string(),
                    },
                )
                .await
                .map_err(|_| anyhow::anyhow!("emit"))?;
        }
        let waited = wait_until_audited(&sink).await;
        // 等二次投递被消费并去重短路，再 cancel。
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
        waited?;
        anyhow::Ok(())
    };

    let (_, driven) = tokio::join!(consume, drive);
    driven?;

    assert_eq!(
        sink.records().len(),
        1,
        "重投同一 EventId → audit 仅 append 一次（L2 consumer 幂等）"
    );
    // anti-vacuity（acc #2）：handler 仅被调用一次（ConsumerBase Duplicate 短路第二条投递）。
    assert_eq!(
        handler_call_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "ConsumerBase 幂等：handler 恰调用一次，第二次投递被 Duplicate 短路"
    );
    Ok(())
}

/// 负路径：未知用户登录被拒，不发射事件 ⇒ audit sink 保持空（闭环不被错误触发）。
#[tokio::test(flavor = "multi_thread")]
async fn rejected_login_does_not_audit() -> Result<()> {
    let bus = MemBus::new();
    let sink = Arc::new(MemAuditSink::new());
    let registry = bootstrap::compose(&[&IdentityDomain, &AuditDomain::new(sink.clone())])?;

    let token = CancellationToken::new();
    let claimer = Arc::new(JourneyClaimer::default());
    let binding = single_subscription(registry)?;
    let stream = bus
        .subscriber()
        .subscribe(Topic::new(binding.topic), token.clone())
        .await?;
    let meta = ConsumerMeta::new("audit", binding.contract_id, binding.topic);
    let consume = run_consumer(
        stream,
        claimer.clone(),
        DynDeadLetterStore::new_box(NoopDlx),
        meta,
        consumer_handler(binding.handler),
    );

    let login = LoginService::with_seed_user(
        DynOutboxEmitter::new_box(MemEmitter::new(bus.clone())),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        USERNAME,
        PASSWORD,
        SUBJECT,
        CANON_TENANT,
    );
    let drive = async {
        let result = login
            .login(IdentityLoginRequest {
                username: "mallory".to_string(),
                password: PASSWORD.to_string(),
            })
            .await;
        // 给任何误发射的事件被消费的时间，随后 cancel。
        tokio::time::sleep(Duration::from_millis(20)).await;
        token.cancel();
        result
    };

    let (_, result) = tokio::join!(consume, drive);
    assert!(result.is_err(), "未知用户登录被拒");
    assert!(sink.is_empty(), "登录失败不产生审计事件");
    Ok(())
}
