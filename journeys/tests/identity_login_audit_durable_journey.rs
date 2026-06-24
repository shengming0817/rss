//! #1100 / T008 durable 拓扑 journey：identity 登录 → **postgres durable outbox** → relay CAS 中继 →
//! **PgInboxStore 幂等**消费 → audit append。demo 拓扑变体见 `identity_login_audit_journey.rs`。
//!
//! `#![cfg(feature = "integration")]`：需真实 postgres，默认 build / `cargo xtask verify` 不编译本文件。
//! **fail-closed**：缺 libpq env / `PGDATABASE` 不含 `test` → 测试**失败**（非静默跳过），杜绝无 DB 假绿、
//! 防破坏性 DDL 打到非测试库（对齐 adapters/postgres 集成测试约定）。
//! 本地运行：设 libpq env（`PGHOST`/`PGPORT`/`PGDATABASE`(含 test)/`PGUSER`/`PGPASSWORD`）后跑
//! `cargo test -p journeys --features integration`（fail-closed：缺 DB env 即失败）。
//!
//! 拓扑：relay 用进程内 `MemBus` 作 in-test broker（per-broker amqp 隔离由 amqp adapter 集成测试覆盖；
//! 本 journey 聚焦 producer durable 落库 + relay CAS + 消费侧 PgInbox 幂等的端到端贯通）。
//!
//! 无清表：每次登录 mint 新 session_id（= 唯一 EventId），outbox/inbox_dedup 以 event_id 为键，跨轮次不冲突；
//! relay 仅中继本轮 event_id 的 entry（不碰他轮 pending 行），故消费侧只收本轮事件。

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use audit::AuditDomain;
use bootstrap::SubscriberHandler;
use consistency::{HandleResult, OutboxRelay, OutboxSource, PermanentError, PermanentErrorKind};
use diport::{
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore, DynOutboxEmitter,
    DynPublisher, Message, MessageId, PublishRequest, Publisher, Subscriber, Topic,
};
use eventexec::{ConsumerMeta, run_consumer};
use futures::future::BoxFuture;
use generated::event::identity_v1::IdentitySessionCreatedPayload;
use generated::http::identity_v1::IdentityLoginRequest;
use identity::{IdentityDomain, LoginService};
use memory::{FixedClock, MemAuditSink, MemBus};
use postgres::{PgConfig, PgEmitter, PgOutbox, PgPassword, PgSslMode, PgStore};
use tokio_util::sync::CancellationToken;

const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const SESSION_CREATED_TOPIC: &str = "identity.session-created";
const IDENTITY_DOMAIN: &str = "identity";
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct-horse";
const SUBJECT: &str = "alice-subject";
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;

/// 由 libpq 标准 env 构造配置。fail-closed：缺 env / 非测试库名 → `Err`（测试失败，非跳过）。
fn config_from_env() -> Result<PgConfig> {
    let var = |k: &str| -> Result<String> {
        std::env::var(k).map_err(|_| anyhow::anyhow!("integration 测试需设置 {k}（libpq env）"))
    };
    let host = var("PGHOST")?;
    let port: u16 = var("PGPORT")?
        .parse()
        .map_err(|_| anyhow::anyhow!("PGPORT 非 u16"))?;
    let database = var("PGDATABASE")?;
    anyhow::ensure!(
        database.contains("test"),
        "PGDATABASE='{database}' 不含 'test'——集成测试执行破坏性 DDL，拒绝打到非测试库"
    );
    let username = var("PGUSER")?;
    let password = var("PGPASSWORD")?;
    Ok(
        PgConfig::new(host, port, database, username, PgPassword::new(password))
            .with_ssl_mode(PgSslMode::Prefer)
            .with_acquire_timeout(Duration::from_secs(5)),
    )
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

async fn wait_until_audited(sink: &MemAuditSink) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while sink.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

/// durable 端到端：login → PgEmitter → outbox(pending) → relay CAS → MemBus(message_id=EventId) →
/// run_consumer(PgInbox 幂等) → audit append；再投递同一 EventId → PgInbox Duplicate → audit 仍 1（acc #2）。
///
/// F4：无 `#[ignore]`——`#![cfg(feature = "integration")]` + `config_from_env()` fail-closed 是唯一门控
/// （对齐 adapters/postgres 集成测试约定，缺 DB env 即失败，非静默跳过）。
#[tokio::test(flavor = "multi_thread")]
async fn login_audit_durable_topology() -> Result<()> {
    let store = PgStore::connect(&config_from_env()?).await?;
    store.run_migrations().await?;

    let bus = MemBus::new();
    let sink = Arc::new(MemAuditSink::new());

    // 组装 audit 订阅（contract_id/topic/group 单源自 generated SUBSCRIPTIONS）。
    let registry = bootstrap::compose(&[&IdentityDomain, &AuditDomain::new(sink.clone())])?;
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

    // 生产侧：login → PgEmitter durable 落 outbox；relay（MemBus 作 in-test broker）CAS 中继。
    let login = LoginService::with_seed_user(
        DynOutboxEmitter::new_box(PgEmitter::new(&store)),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        USERNAME,
        PASSWORD,
        SUBJECT,
        CANON_TENANT,
    );
    let relay = PgOutbox::new(&store, DynPublisher::new_box(bus.publisher()));

    let drive = async {
        let response = login
            .login(IdentityLoginRequest {
                username: USERNAME.to_string(),
                password: PASSWORD.to_string(),
            })
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
        wait_until_audited(&sink).await?;

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
        sink.records().len(),
        1,
        "durable：登录 emit + 重投同一 EventId → audit 仅 append 一次（PgInbox 幂等）"
    );
    Ok(())
}
