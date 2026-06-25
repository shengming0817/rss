//! #1100 / T008 journey：identity 登录 → durable outbox 发射 → ConsumerBase 幂等消费 → audit append，
//! 组装在 bootstrap（compose）+ eventexec（run_consumer）+ memory（in-mem DI port 替身）上，
//! 端到端证明 L2 OutboxFact 闭环（登录 → outbox → relay/分发 → audit，以 EventId 幂等去重）。
//!
//! 接缝覆盖：
//! - bootstrap 组装：`compose` 跑 identity/audit 的 `Domain::init` → Registry 收集 route_group + subscriber。
//! - DI 注入：identity 经 `Box<DynSessionUnitOfWork>`（`MemSessionUnitOfWork`）co-tx 写 session + 发射 outbox
//!   fact（demo 拓扑）；audit 经注入的链 `MacVerifier`（journey 捕获 verifier）落**域内哈希链**（W：无外部
//!   sink）；幂等 store 经 `run_consumer` 注入。
//! - 跨域事件：identity emit `identity.session-created` → MemBus（Message.id = EventId）→ audit 订阅消费。
//! - 消费：bootstrap `SubscriberHandler` 经组合根 adapt 成 `run_consumer` 的 `HandleResult` handler，
//!   `ConsumerBase` 自持 claim→handle→commit/release 幂等生命周期（键 = msg.id = EventId）。
//! - 幂等（acc #2）：relay 重投同一 EventId → audit 仅 append 一次（`relay_redelivery_audits_once`）。
//!
//! 并发形态：`run_consumer` future 持 `&DynDeadLetterStore`（Send-非-Sync）跨 await ⇒ **!Send**、不可
//! `tokio::spawn`（与 eventexec 单测「直接 await」一致）。journey 用 `tokio::join!` 同任务并发驱动
//! 消费 future 与「登录 emit + 等 sink + cancel」驱动 future——无跨线程 Send 约束。
//!
//! 边界（W）：服务层闭环——登录服务直接调用，不逐字节跑 axum（admin 读 handler 经 axum oneshot 单测覆盖，
//! 见 audit crate）；envelope 的 trace/correlation reserved-key sealed setter 已建（#1193），但注入源留 W（待 #1296）；audit
//! domain 哈希链 #1014 已写实——append 落每租户 keyed HMAC 链（journey 经捕获 verifier 端到端验链 append）。
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
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore, Message,
    OutboxEmitter, OutboxEnvelopeParts, Subscriber, Topic,
};
use eventexec::{ConsumerMeta, run_consumer};
use futures::future::BoxFuture;
use generated::http::identity_v1::IdentityLoginRequest;
use identity::ports::DynSessionUnitOfWork;
use identity::{IdentityDomain, LoginService};
use memory::{FixedClock, MemBus, MemEmitter, MemSessionUnitOfWork};
use primitives::{ListenerKind, Mac, MacAlgorithm, MacKey, MacVerifier};
use tokio_util::sync::CancellationToken;
use vocab::TenantId;

/// canonical UUID 种子租户（TenantId::parse 接受形态）。
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
/// session-created event 契约 topic（identity 发布 / audit 订阅）。
const SESSION_CREATED_TOPIC: &str = "identity.session-created";
/// 登录种子密码。
const PASSWORD: &str = "correct-horse";
/// 登录标识（`request.username`）——#1277 F1：可为**任意非 uuid 用户名**（email/UPN/username），仅作凭据
/// 查找键（CredentialRepo 按 `(tenant, login)` 索引），永不写进 wire / audit。
const LOGIN_USERNAME: &str = "alice";
/// canonical actor subject（credential 携带的 `ids::UserId`）——登录成功后**仅**此写 payload / envelope /
/// session subject + 审计 actor。与登录标识解耦：旧实现把 username 直接当 subject 写 wire，真实用户名
/// （非 uuid）会让 audit `ids::UserId::parse` fail-closed 断链——本 journey 用非 uuid 登录标识端到端证伪（#1277 F1）。
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
/// 手造 relay payload 的 session_id——审计 resource id 是 typed `ids::SessionId`（canonical uuid），
/// 非 uuid 会被 handler fail-closed 拒（F3）；故 session_id 须为 uuid。
const CANON_SESSION: &str = "22222222-3333-4444-8555-666666666666";
/// journey 审计链 HMAC key（固定 32B）。
const AUDIT_KEY: [u8; 32] = [0x5a; 32];
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

/// 审计链 HMAC 测试 verifier：捕获每次 `sign` 的 message（= 每次链 append 的 canonical 输入），并以确定性
/// 折叠产出 32B 标签（链一致）。W 阶段审计落**域内哈希链**（无外部 sink），journey 经注入此 verifier
/// 端到端断言审计 append 次数 + 内容贯穿（session_id / tenant / actor 进 canonical 链输入）。非加密——
/// journey 只需确定性 + 可计数/可检视。
#[derive(Clone, Default)]
struct CapturingVerifier {
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CapturingVerifier {
    fn audited(&self) -> Vec<Vec<u8>> {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn is_empty(&self) -> bool {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

impl MacVerifier for CapturingVerifier {
    fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message.to_vec());
        // 确定性折叠（FNV-1a 变体；journey 只需链一致）。
        let mut acc = FNV_OFFSET;
        for &b in key.as_bytes().iter().chain(message) {
            acc ^= u64::from(b);
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&acc.to_be_bytes());
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        Mac::from_bytes(out.to_vec())
    }

    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
        // journey 不走 list（不触发链 verify）；提供一致实现满足 trait 契约。
        primitives::constant_time_eq(
            self.sign(key, algorithm, message).as_bytes(),
            tag.as_bytes(),
        )
    }
}

/// 构造 journey 用 audit 域 + 共享捕获句柄（注入捕获 verifier + 固定 32B key）。
#[allow(clippy::expect_used)]
fn audit_domain() -> (AuditDomain<CapturingVerifier>, CapturingVerifier) {
    let verifier = CapturingVerifier::default();
    let domain = AuditDomain::new(verifier.clone(), MacKey::from_bytes(AUDIT_KEY.to_vec()))
        .expect("audit domain: 32B key satisfies MIN_KEY_LEN");
    (domain, verifier)
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

/// 等待审计链非空（有界超时，防消费未跑挂死）。超时即 `Err`，由调用方在 cancel 后再传播（避免悬挂）。
async fn wait_until_audited(audit: &CapturingVerifier) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while audit.is_empty() {
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

    // 登录：注入 MemSessionUnitOfWork（co-tx demo 替身：session + outbox fan-out）+ 固定时钟。emit + 等 audit + cancel 收口。
    // tenant 经 X-Tenant-ID header 解析（组合根职责）；此处 journey 直接 parse 注入 login 位置参。
    let tenant = TenantId::parse(CANON_TENANT)?;
    let login = LoginService::with_seed_credential(
        DynSessionUnitOfWork::new_box(MemSessionUnitOfWork::new(bus.clone())),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        tenant,
    )?;
    let drive = async {
        let response = login
            .login(
                tenant,
                IdentityLoginRequest {
                    // 非 uuid 登录标识——旧实现会把 "alice" 当 subject 写 wire，audit 断链（#1277 F1 证伪点）。
                    username: LOGIN_USERNAME.to_string(),
                    password: PASSWORD.to_string(),
                },
            )
            .await;
        let waited = wait_until_audited(&audit).await;
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
    // F9：tenant / actor 的 16B 原始 UUID 字节贯穿到审计链 canonical 输入（防 audit 漏写关键 actor/tenant
    // 字段而 journey 不报）。canonical_message 内 tenant/actor 是 uuid bytes（非字符串），故用 uuid 字节断言。
    // #1277 F1：actor = canonical CANON_USER（credential.user_id），**非**登录标识 LOGIN_USERNAME="alice"——
    // 用非 uuid 登录标识端到端证明 login 写的是 canonical subject、audit 不再断链（旧实现此处必失败）。
    let tenant_uuid_bytes = uuid::Uuid::parse_str(CANON_TENANT)?.into_bytes();
    let actor_uuid_bytes = uuid::Uuid::parse_str(CANON_USER)?.into_bytes();
    assert!(
        contains(&tenant_uuid_bytes),
        "tenant UUID 16B 贯穿闭环（进审计链 canonical 输入）"
    );
    assert!(
        contains(&actor_uuid_bytes),
        "actor = canonical user id（credential.user_id）16B 贯穿闭环（非登录标识 \"alice\"，#1277 F1）"
    );
    // 反证：非 uuid 登录标识不得出现在审计链输入（旧实现把 username 当 subject 写 wire 会命中此串）。
    // 前提（已人工核验）：CANON_USER 的 16B UUID 字节序列不含 LOGIN_USERNAME（"alice"）的 ASCII 编码，
    // 故本字节搜索无假阳性——选取测试常量时须维持此前提（二者无字节子串包含）。
    assert!(
        !contains(LOGIN_USERNAME.as_bytes()),
        "登录标识 \"alice\" 不得进审计链 canonical 输入（准 PII，#1277 F1）"
    );
    Ok(())
}

/// acc #2（L2 consumer 幂等）：relay 重投同一 EventId 的 session.created → audit 仅 append 一次。
/// 模拟：经 `MemEmitter` 发同一 `Entry`（同 EventId / idem_key）两次，共享同一幂等 claimer 经 `run_consumer`
/// 消费——首次 `Fresh`（handler 跑、append）、二次 `Duplicate`（短路）。
#[tokio::test(flavor = "multi_thread")]
async fn relay_redelivery_audits_once() -> Result<()> {
    let bus = MemBus::new();
    let (audit_domain, audit) = audit_domain();
    let registry = bootstrap::compose(&[&audit_domain])?;

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
        r#"{{"sessionId":"{CANON_SESSION}","subject":"{CANON_USER}","tenantId":"{CANON_TENANT}","occurredAt":{NOW_SECS}}}"#
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
                    OutboxEnvelopeParts::new(generated::event::identity_v1::CONTRACT, CANON_USER),
                )
                .await
                .map_err(|_| anyhow::anyhow!("emit"))?;
        }
        let waited = wait_until_audited(&audit).await;
        // 等二次投递被消费并去重短路，再 cancel。
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
        waited?;
        anyhow::Ok(())
    };

    let (_, driven) = tokio::join!(consume, drive);
    driven?;

    assert_eq!(
        audit.audited().len(),
        1,
        "重投同一 EventId → audit 链仅 append 一次（L2 consumer 幂等）"
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
    let (audit_domain, audit) = audit_domain();
    let registry = bootstrap::compose(&[&IdentityDomain, &audit_domain])?;

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

    let tenant = TenantId::parse(CANON_TENANT)?;
    let login = LoginService::with_seed_credential(
        DynSessionUnitOfWork::new_box(MemSessionUnitOfWork::new(bus.clone())),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        tenant,
    )?;
    let drive = async {
        let result = login
            .login(
                tenant,
                IdentityLoginRequest {
                    username: "mallory".to_string(),
                    password: PASSWORD.to_string(),
                },
            )
            .await;
        // 给任何误发射的事件被消费的时间，随后 cancel。
        tokio::time::sleep(Duration::from_millis(20)).await;
        token.cancel();
        result
    };

    let (_, result) = tokio::join!(consume, drive);
    assert!(result.is_err(), "未知用户登录被拒");
    assert!(audit.is_empty(), "登录失败不产生审计链 append");
    Ok(())
}
