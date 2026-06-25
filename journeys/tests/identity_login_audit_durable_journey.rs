//! #1100 / T008 durable 拓扑 journey：identity 登录 → **postgres durable outbox** → relay CAS 中继 →
//! **PgInboxStore 幂等**消费 → audit append。demo 拓扑变体见 `identity_login_audit_journey.rs`。
//!
//! `#![cfg(feature = "integration")]`：需真实 postgres，默认 build / `cargo xtask verify` 不编译本文件。
//! postgres 经 `testkit::env_or_postgres()` self-provision（testcontainers，#1137）——无需手工预置；设 libpq
//! env（`PGHOST`/`PGPORT`/`PGDATABASE`(含 `test`)/`PGUSER`/`PGPASSWORD`）则对接长存外部 pg（不起容器）。
//! **fail-closed**：`PGDATABASE` 不含 `test` → 测试失败（破坏性 DDL 防护；容器路径 db=`rss_test` 恒满足）。
//! 本地运行：`cargo nextest run -p journeys --features integration`（docker 在场自起容器）或经 `cargo xtask integration`。
//!
//! 拓扑：relay 用进程内 `MemBus` 作 in-test broker（per-broker amqp 隔离由 amqp adapter 集成测试覆盖；
//! 本 journey 聚焦 producer durable 落库 + relay CAS + 消费侧 PgInbox 幂等的端到端贯通）。
//!
//! 无清表：每次登录 mint **独立 EventId**（opaque UUID，非 session_id；payload.sessionId 仅用于关联本轮 entry），
//! outbox/inbox_dedup 以 event_id 为键，跨轮次不冲突；relay 仅中继本轮 event_id 的 entry（不碰他轮 pending 行），
//! 故消费侧只收本轮事件。

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use audit::AuditDomain;
use bootstrap::SubscriberHandler;
use consistency::{HandleResult, OutboxRelay, OutboxSource, PermanentError, PermanentErrorKind};
use diport::{
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore, DynPublisher,
    Message, MessageId, PublishRequest, Publisher, Subscriber, Topic,
};
use eventexec::{ConsumerMeta, run_consumer};
use futures::future::BoxFuture;
use generated::event::identity_v1::IdentitySessionCreatedPayload;
use generated::http::identity_v1::IdentityLoginRequest;
use identity::ports::DynSessionUnitOfWork;
use identity::{IdentityDomain, LoginService};
use memory::{FixedClock, MemBus};
use postgres::{PgConfig, PgOutbox, PgPassword, PgSessionUnitOfWork, PgSslMode, PgStore};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;
use vocab::TenantId;

const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const SESSION_CREATED_TOPIC: &str = "identity.session-created";
const IDENTITY_DOMAIN: &str = "identity";
const PASSWORD: &str = "correct-horse";
/// 登录标识（`request.username`）——#1277 F1：可为任意非 uuid 用户名，仅作凭据查找键，不写 wire/audit。
const LOGIN_USERNAME: &str = "alice";
/// canonical actor subject（credential 携带的 `ids::UserId`）——登录成功后写 payload/envelope/session subject
/// + 审计 actor（audit `ids::UserId::parse` 必通）。与登录标识解耦（#1277 F1）。
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;
/// durable journey 审计链 HMAC key（固定 32B）。
const AUDIT_KEY: [u8; 32] = [0x5a; 32];

/// 审计链 HMAC 测试 verifier：捕获每次 `sign` 的 message（= 每次链 append）。W 阶段审计落域内哈希链
/// （无外部 sink），journey 经注入此 verifier 端到端断言 audit append 次数。非加密——只需确定性 + 可计数。
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
        primitives::constant_time_eq(
            self.sign(key, algorithm, message).as_bytes(),
            tag.as_bytes(),
        )
    }
}

/// 构造 durable journey 用 audit 域 + 共享捕获句柄（固定 32B key）。
#[allow(clippy::expect_used)]
fn audit_domain() -> (AuditDomain<CapturingVerifier>, CapturingVerifier) {
    let verifier = CapturingVerifier::default();
    let domain = AuditDomain::new(verifier.clone(), MacKey::from_bytes(AUDIT_KEY.to_vec()))
        .expect("audit domain: 32B key satisfies MIN_KEY_LEN");
    (domain, verifier)
}

/// 由 testkit fixture 参数构造配置。
/// 库名严格校验已由 `testkit::env_or_postgres` 单源执行（外部路径须 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES`
/// + `PGDATABASE` 以 `_test` 结尾或 `== "test"`），此处不重复。
fn pg_config(p: &testkit::PgConnParams) -> Result<PgConfig> {
    Ok(PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5)))
}

/// noop DLX（journey 不验死信路径；eventexec consumer.rs 已覆盖三路径）。
struct NoopDlx;
impl DeadLetterStore for NoopDlx {
    async fn write_dead_letter(
        &self,
        _record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        // reason: journey 不验死信路径（eventexec consumer.rs 已覆盖三路径）；handler happy-path Ack。
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        // reason: journey 结束由 CancellationToken 驱动，无需 DLX 资源释放。
        Ok(())
    }
}

/// 取唯一 session-created 订阅绑定（断言恰一个）。
fn single_subscription(
    registry: bootstrap::Registry,
) -> anyhow::Result<bootstrap::SubscriberBinding> {
    let mut subs = registry.into_subscribers();
    anyhow::ensure!(subs.len() == 1, "恰一个 session-created 订阅");
    subs.pop().ok_or_else(|| anyhow::anyhow!("订阅缺失"))
}

/// SubscriberHandler → run_consumer HandleResult handler（Ok→ack；Err→reject 永久）。
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
                    tracing::warn!(error = %e, "durable journey: handler errored, rejecting");
                    HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent))
                }
            }
        })
    }
}

async fn wait_until_audited(audit: &CapturingVerifier) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while audit.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

/// durable 端到端：login → PgSessionUnitOfWork co-tx（session 行 + outbox(pending) 同事务）→ relay CAS →
/// MemBus(message_id=EventId) → run_consumer(PgInbox 幂等) → audit append；再投递同一 EventId → PgInbox
/// Duplicate → audit 仍 1（acc #2）。session 行持久化/原子性由 postgres t11/t12 守（见上方 with_seed_user 注释）。
///
/// F4：无 `#[ignore]`——`#![cfg(feature = "integration")]` 门控；postgres 经 `testkit::env_or_postgres()`
/// self-provision（testcontainers，#1137；设 `PGHOST` 等则对接长存外部 pg）。需 docker（容器路径）。
/// `pg` fixture guard **须绑定到测试结束**（其 `Drop` 停容器）。
#[tokio::test(flavor = "multi_thread")]
async fn login_audit_durable_topology() -> Result<()> {
    let pg = testkit::env_or_postgres().await?;
    let store = PgStore::connect(&pg_config(pg.params())?).await?;
    store.run_migrations().await?;

    let bus = MemBus::new();
    let (audit_domain, audit) = audit_domain();

    // 组装 audit 订阅（contract_id/topic/group 单源自 generated SUBSCRIPTIONS）。
    let registry = bootstrap::compose(&[&IdentityDomain, &audit_domain])?;
    let binding = single_subscription(registry)?;
    anyhow::ensure!(binding.topic == SESSION_CREATED_TOPIC);

    // 消费侧：PgInboxStore 幂等 claimer（durable，group 自 binding 单源）。
    let claimer = Arc::new(store.inbox(binding.group.clone()));
    let token = CancellationToken::new();
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

    // 生产侧：login → PgSessionUnitOfWork **co-tx**（session 行 + outbox 行同事务）durable 落库；relay
    // （MemBus 作 in-test broker）CAS 中继。session 行持久化 + co-tx 原子性由 postgres 集成测试 t11/t12 守
    // （pool 为 pub(crate)，journey 不直查 sessions 表）；本 journey 验 co-tx provider 端到端贯通到 audit。
    let tenant = TenantId::parse(CANON_TENANT)?;
    let login = LoginService::with_seed_credential(
        DynSessionUnitOfWork::new_box(PgSessionUnitOfWork::new(
            &store,
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        )),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        tenant,
    )?;
    let relay = PgOutbox::new(&store, DynPublisher::new_box(bus.publisher()));

    let drive = async {
        let response = login
            .login(
                tenant,
                IdentityLoginRequest {
                    username: LOGIN_USERNAME.to_string(),
                    password: PASSWORD.to_string(),
                },
            )
            .await?;
        // F1 后：idem_key = 独立 EventId（非 session_id）；以 payload.sessionId 关联本轮 entry（F6）。
        let session_id = response.data.session_id.clone();

        // F6：bounded 轮询（最多 50 次 × 100ms），经 payload 解码匹配本轮 session_id——
        // 对抗 stale pending 行，不依赖 pending 数量/顺序。
        let our = {
            let mut found = None;
            for _ in 0..50 {
                let pending = OutboxSource::poll_pending(&relay, IDENTITY_DOMAIN, 64).await?;
                for entry in &pending {
                    let Ok(pl) =
                        serde_json::from_slice::<IdentitySessionCreatedPayload>(entry.payload())
                    else {
                        continue;
                    };
                    if pl.session_id == session_id {
                        found = Some(entry.clone());
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            found.ok_or_else(|| {
                anyhow::anyhow!("outbox 缺本轮 session-created entry（session_id={session_id}）")
            })?
        };
        // relay CAS 中继 → MemBus（message_id = entry 自身的独立 EventId）。
        let event_id = our.idem_key().as_str().to_string();
        let payload = our.payload().to_vec();
        OutboxRelay::relay(&relay, &our).await?;
        wait_until_audited(&audit).await?;

        // 重投同一 EventId（模拟 broker 重投）→ PgInbox Duplicate → audit 不重复。
        bus.publisher()
            .publish(PublishRequest {
                topic: Topic::new(SESSION_CREATED_TOPIC),
                event_id: MessageId::new(event_id.as_str()),
                payload,
            })
            .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
        anyhow::Ok(())
    };

    let (_, driven) = tokio::join!(consume, drive);
    driven?;

    assert_eq!(
        audit.audited().len(),
        1,
        "durable：登录 emit + 重投同一 EventId → audit 链仅 append 一次（PgInbox 幂等）"
    );
    Ok(())
}
