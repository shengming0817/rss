//! #1251/#1434 durable e2e journey：`wire_event_transport` → postgres + RabbitMQ 真容器
//! 贯通 outbox → relay → AMQP → consumer → PG inbox 幂等去重 → audit 审计链。
//!
//! 断言 A（至少一次）：登录触发 outbox 落库 → relay 中继 → AMQP consumer 消费 → audit append
//! 仅一次（20s timeout）。
//!
//! 断言 B（PG inbox 幂等去重，tracer 正向见证）：重投同一 event_id（duplicate）+ 一条新 event_id（tracer，
//! 同 payload → Fresh → append）。FIFO 单 consumer：tracer 被 audit（len→2）证明其之前的 duplicate 已被
//! 真实消费+settle；稳定 len==2（original + tracer）证明 duplicate 命中 Duplicate 去重（升到 3 即去重失效）。
//!
//! `#![cfg(feature = "integration")]`：需真实 docker 容器；`cargo test -p runtime --features
//! integration --no-run` 仅要求编译通过（无 docker 时可用）。
//! `cargo nextest run -p runtime --features integration` 或 `cargo xtask integration` 运行实际测试。

#![cfg(feature = "integration")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result};
use audit::ports::{AuditChainHasher, DynAuditRepo};
use audit::{AuditDomain, InMemAuditRepo};
use base64::Engine as _;
use consistency::OutboxSource;
use diport::{DynPublisher, MessageId, PublishRequest, Publisher, Topic};
use generated::event::identity_v1::session_created::IdentitySessionCreatedPayload;
use generated::http::identity_v1::login::IdentityLoginRequest;
use identity::ports::{DynRoleBindingLifecycle, DynRoleRepo, DynSessionLifecycle, TenantId};
use identity::{IdentityDomain, LoginService};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, caps};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tokio_util::sync::CancellationToken;

use runtime::event_transport::{
    bridge_generated_subscriptions, build_event_transport_config_from, wire_event_transport,
};
use runtime::{
    SharedRuntimeDeps, build_redis_runtime_deps, build_vault_runtime_deps, wire_distributed,
};

// ── 共用常量（自 journeys/tests/common/mod.rs 复制，runtime 测试不能 mod common）────────────

const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const SESSION_CREATED_TOPIC: &str = "identity.session-created";
const PASSWORD: &str = "correct-horse";
const LOGIN_USERNAME: &str = "alice";
const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
const AUDIT_KEY: [u8; 32] = [0x5a; 32];
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

// ── FixedClock（inline；memory crate 被 deny.toml 限定 journeys/xtask，runtime 不可用）─────────

/// 确定性测试时钟——固定 unix_secs，impl `diport::Clock`（非 `SystemTime::now`，符合 clock 注入纪律）。
struct FixedClock(SystemTime);

impl FixedClock {
    fn at_unix_secs(secs: u64) -> Self {
        Self(std::time::UNIX_EPOCH + Duration::from_secs(secs))
    }
}

impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

// ── NoopPublisher（outbox read-only poll view；publish 从不调用）────────────────────────────

/// outbox 只读 poll 视图所用的占位 publisher——`id.outbox(DynPublisher::new_box(NoopPublisher))`
/// 创建 `PgOutbox` 实例仅用于 `OutboxSource::poll_pending`，从不调 `publish`。
struct NoopPublisher;

// reason: NoopPublisher 仅供 e2e 测试中的 outbox read-only poll view；runtime（assemblies/runtime）
// 是合法组合根（DIPORT-IMPL-ALLOWLIST-01 组合根例外），unknown_lints 防 clippy 报 dylint lint 未知。
#[allow(unknown_lints, rss_diport_impl_allowlist)]
impl diport::Publisher for NoopPublisher {
    async fn publish(
        &self,
        _request: diport::PublishRequest,
    ) -> Result<(), diport::PublisherError> {
        // reason: e2e 只读 outbox poll view；publish 设计上不被调用（relay worker 才是真发布路径）。
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::PublisherError> {
        // reason: 无后端连接资源，shutdown 为空操作。
        Ok(())
    }
}

// ── CapturingVerifier（自 journeys/tests/common/mod.rs 复制）──────────────────────────────

/// 审计链 HMAC 测试 verifier：捕获每次 `sign` 调用的 message，确定性折叠产出 32B 标签（链一致）。
/// `audited().len()` 含 append + verify 全部 sign 调用次数。
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

impl MacVerifier for CapturingVerifier {
    fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message.to_vec());
        // 确定性折叠（FNV-1a 变体；journey 只需链一致，非加密）。
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

// ── audit_domain helper（自 journeys/tests/common/mod.rs 复制）───────────────────────────

#[allow(clippy::expect_used)]
// reason: 32B audit key 满足 AuditChainHasher MIN_KEY_LEN（失败意味测试常量有误），panic 正当。
fn audit_domain() -> (AuditDomain, CapturingVerifier) {
    let verifier = CapturingVerifier::default();
    let hasher = AuditChainHasher::new(verifier.clone(), MacKey::from_bytes(AUDIT_KEY.to_vec()))
        .expect("32B audit key satisfies MIN_KEY_LEN");
    let repo: Arc<DynAuditRepo<'static>> =
        Arc::from(DynAuditRepo::new_box(InMemAuditRepo::new(hasher)));
    let domain = AuditDomain::new(repo);
    (domain, verifier)
}

// ── pg_config helper（自 journeys/tests/identity_login_audit_durable_journey.rs 复制）──────

async fn connect_pg() -> Result<(testkit::PgFixture, PgRuntimeDeps)> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let owner_config = pg_config(p, &p.username, &p.password);
    provision_rss_app_login(p).await?;
    let deps = PgRuntimeDeps::setup(
        &owner_config,
        &pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
    )
    .await?;
    Ok((fixture, deps))
}

fn pg_config(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

async fn provision_rss_app_login(p: &testkit::PgConnParams) -> Result<()> {
    let options = PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    sqlx::query(&format!(
        r#"
        DO $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtext('{TEST_APP_ROLE}'));
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{TEST_APP_ROLE}') THEN
                CREATE ROLE {TEST_APP_ROLE} LOGIN PASSWORD '{TEST_APP_PASSWORD}' NOBYPASSRLS;
            ELSE
                ALTER ROLE {TEST_APP_ROLE} LOGIN PASSWORD '{TEST_APP_PASSWORD}' NOBYPASSRLS;
            END IF;
        END
        $$;
        "#
    ))
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}

fn pg_owner_connect_options(p: &testkit::PgConnParams) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
}

async fn inbox_done_count(pool: &sqlx::PgPool, event_id: &str, group: &str) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_dedup WHERE event_id = $1 AND consumer_group = $2 AND status = 'done'",
    )
    .bind(event_id)
    .bind(group)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

// ── e2e 测试主体 ───────────────────────────────────────────────────────────────────────────

/// durable e2e：`wire_event_transport` 真容器贯通验收（#1251 task 6）。
///
/// - 断言 A：login → PgOutbox(pending) → relay → AMQP → consumer → PG inbox(Fresh) → audit append（至少一次）。
/// - 断言 B：重投同一 event_id（duplicate）+ tracer（新 event_id）→ tracer 被消费正向见证 duplicate 已消费；
///   稳定 audit len==2 + `inbox_dedup` done 行证明 duplicate 命中 PG inbox Duplicate 去重。
///
/// 需 docker：`cargo test -p runtime --features integration event_transport_durable -- --nocapture`
/// 或 `cargo nextest run -p runtime --features integration`。无 docker 时只需通过
/// `cargo test -p runtime --features integration --no-run`（编译门）。
#[tokio::test(flavor = "multi_thread")]
async fn event_transport_durable_e2e() -> Result<()> {
    // ── 步骤 1：启动两个真实容器 fixture（guard 绑到测试结束，Drop 停容器）─────────────────────

    let (pgfix, pg) = connect_pg().await?;
    let rmq = testkit::env_or_rabbitmq().await?;

    // ── 步骤 2：postgres capability bundle（connect + run_migrations + RLS 能力门）──────────────

    let assertion_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pg_owner_connect_options(pgfix.params()))
        .await?;
    let id = pg.for_domain::<caps::Identity>();

    // ── 步骤 3：域装配（identity + audit）────────────────────────────────────────────────────

    let (audit_domain_inst, audit) = audit_domain();

    // identity 域：with_seed_credential 注入 in-mem 凭据 + PgSessionLifecycle durable co-tx。
    let refresh_identity = identity::seed_refresh_service(
        || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
    );
    let login_identity = Arc::new(LoginService::with_seed_credential(
        Arc::from(DynSessionLifecycle::new_box(
            id.session_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
        )),
        Arc::clone(&refresh_identity),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        TenantId::parse(CANON_TENANT)?,
    )?);
    let roles_for_admin = Arc::from(DynRoleRepo::new_box(id.role_repo()));
    let roles_for_list = Arc::from(DynRoleRepo::new_box(id.role_repo()));
    let bindings = Arc::from(DynRoleBindingLifecycle::new_box(
        id.role_binding_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
    ));
    let rbac_admin = Arc::new(identity::RbacAdminService::new(
        roles_for_admin,
        Arc::clone(&bindings),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let identity_domain = IdentityDomain::new(
        login_identity,
        refresh_identity,
        rbac_admin,
        roles_for_list,
        bindings,
    );

    // ── 步骤 4：compose + drain subscribers（audit 的 session-created 订阅绑定）────────────────

    let mut registry = bootstrap::compose(&[&identity_domain, &audit_domain_inst])?;
    let subscribers = bridge_generated_subscriptions(registry.drain_subscribers())?;
    let consumer_group = generated::event::SUBSCRIPTIONS
        .iter()
        .find(|spec| {
            spec.contract_id == generated::event::identity_v1::session_created::CONTRACT_ID
                && spec.consumer == "audit"
        })
        .map(|spec| spec.group.to_owned())
        .context("e2e must declare audit session-created subscriber")?;

    // ── 步骤 5：构造 EventTransportConfig（注入式 env builder，无 ambient env 侧效应）────────────

    let vhost_url = rmq.vhost_url("rss_evt_e2e").await?;

    // relay_poll_interval=2s：在 [100ms, 300s] 范围内；2s 窗口使步骤 6 poll 能赢过 relay 第二次轮询。
    // relay_sample_interval=30s：在 [1s, 60s] 范围内。
    let hmac_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    let cfg = build_event_transport_config_from(|name| match name {
        "RSS_TOPOLOGY" => Some("durable-shared".to_string()),
        "RSS_AMQP_URL" => Some(vhost_url.clone()),
        "RSS_RELAY_POLL_INTERVAL_MS" => Some("2000".to_string()),
        "RSS_RELAY_BATCH_SIZE" => Some("16".to_string()),
        "RSS_RELAY_SAMPLE_INTERVAL_MS" => Some("30000".to_string()),
        "RSS_OUTBOX_SWEEP_INTERVAL_MS" => Some("60000".to_string()),
        "RSS_OUTBOX_RETAIN_SECONDS" => Some("604800".to_string()),
        "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL" => Some(hmac_key.clone()),
        "RSS_DLX_PAYLOAD_KEY_NAME" => Some("dlx-payload".to_string()),
        "RSS_VAULT_ADDR" => Some("https://vault.example:8200".to_string()),
        "RSS_VAULT_TOKEN" => Some("s.testtoken".to_string()),
        "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_string()),
        _ => None,
    })?;
    let poll_tenant_authority = cfg
        .tenant_authority
        .clone()
        .context("durable e2e tenant authority missing")?;
    let poll_dlx_payload_protector = cfg
        .dlx_payload_protector
        .clone()
        .context("durable e2e dlx payload protector missing")?;

    // ── 步骤 6：wire_event_transport → EventRuntime（relay OS 线程 + consumer worker 启动）──────

    let redis_fixture = testkit::env_or_redis().await?;
    let redis = build_redis_runtime_deps(|name| {
        (name == "RSS_REDIS_URL").then(|| redis_fixture.url().to_string())
    })
    .await?;
    let vault = build_vault_runtime_deps(|name| match name {
        "RSS_VAULT_ADDR" => Some("https://vault.example:8200".to_string()),
        "RSS_VAULT_TOKEN" => Some("s.testtoken".to_string()),
        "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_string()),
        _ => None,
    })?;
    let deps = SharedRuntimeDeps {
        pg: pg.clone(),
        redis,
        vault,
        settings_config_value_key_name: diport::KeyName::try_new("settings-config")?,
    };
    let distributed = wire_distributed(&deps)?;
    let event_runtime = wire_event_transport(&pg, distributed, subscribers, cfg).await?;
    assert!(
        event_runtime.module.resources.is_empty(),
        "event transport workers must drain through DomainModuleResult::workers"
    );
    assert_eq!(
        event_runtime.module.workers.len(),
        6,
        "identity relay + consumer + sampler + outbox sweeper + dead_letter sweeper + inbox sweeper"
    );
    let probe_names: Vec<&str> = event_runtime
        .module
        .probes
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    for expected in ["outbox_sampler", "outbox_sweeper"] {
        assert!(
            probe_names.contains(&expected),
            "durable module probes must include {expected}; got {probe_names:?}"
        );
    }
    assert!(
        !probe_names.contains(&"outbox_relay_settings"),
        "draft settings event has no consumer queue; production AMQP relay must not be wired"
    );

    // ── 步骤 7：注册 ShutdownStack（infra_guards 先注册 → LIFO 最后关；workers 后注册 → LIFO 最先 drain）

    let mut stack = bootstrap::shutdown::ShutdownStack::new(CancellationToken::new());
    for guard in event_runtime.infra_guards {
        stack.register_detached(guard);
    }
    let module = event_runtime.module;
    for resource in module.resources {
        stack.register_detached(resource);
    }
    for worker in module.workers {
        stack.register_with_token(worker);
    }

    // ── 步骤 8：生产侧登录（PgSessionLifecycle co-tx：session 行 + outbox(pending) 同事务落库）──

    let tenant = TenantId::parse(CANON_TENANT)?;
    // 第二个 LoginService 实例（同种子凭据），用于直接调用 .login()。
    let refresh_for_login = identity::seed_refresh_service(
        || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
    );
    let login_svc = LoginService::with_seed_credential(
        Arc::from(DynSessionLifecycle::new_box(
            id.session_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
        )),
        refresh_for_login,
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        LOGIN_USERNAME,
        ids::UserId::parse(CANON_USER)?,
        PASSWORD,
        tenant,
    )?;
    let response = login_svc
        .login(
            tenant,
            IdentityLoginRequest {
                username: LOGIN_USERNAME.to_string(),
                password: PASSWORD.to_string(),
            },
        )
        .await?;
    let session_id = response.data.session_id.clone();

    // ── 步骤 9：只读 poll outbox（NoopPublisher；relay 2s 间隔给足 poll 窗口）─────────────────

    // 独立 PgOutbox 实例（只读 poll 视图；relay worker 已持有另一实例负责实际发布）。
    // NoopPublisher 的 publish 设计上不被调用——此 outbox 句柄仅 OutboxSource::poll_pending 用。
    let poll_view = id.outbox(
        DynPublisher::new_box(NoopPublisher),
        poll_tenant_authority,
        poll_dlx_payload_protector,
    );

    // bounded 轮询（最多 50 次 × 100ms = 5s），按 payload.sessionId 关联本轮 entry。
    // 2s relay 间隔保证：登录后立即 poll 时，relay 的下一次轮询还未到来，pending entry 仍存在。
    let (captured_event_id, captured_payload) = {
        let mut found = None;
        for _ in 0..50u8 {
            let pending = OutboxSource::poll_pending(&poll_view, "identity", 64).await?;
            for entry in &pending {
                let Ok(pl) =
                    serde_json::from_slice::<IdentitySessionCreatedPayload>(entry.payload())
                else {
                    continue;
                };
                if pl.session_id == session_id {
                    found = Some((
                        entry.idem_key().as_str().to_string(),
                        entry.payload().to_vec(),
                    ));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        found.ok_or_else(|| {
            anyhow::anyhow!(
                "outbox 缺本轮 session-created pending entry（session_id={session_id}）"
            )
        })?
    };

    // ── 步骤 10：断言 A（至少一次）────────────────────────────────────────────────────────────

    // relay（后台 OS 线程）会在下次 2s 轮询时拾起 pending entry → AMQP publish → consumer → PG inbox
    // Fresh → audit append。20s timeout 覆盖 2s relay 间隔 + AMQP 投递 + consumer 处理延迟。
    tokio::time::timeout(Duration::from_secs(20), async {
        while audit.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("timeout 20s 内 audit 未收到 session-created 事件（至少一次断言 A 失败）")
    })?;

    // 新鲜 audit repo 单事件 append 恰触发 1 次 MacVerifier::sign（verify_integrity 读路径未在此触发）；
    // 故 len()==1 == 恰一次审计 append（对齐 journeys identity_login_audit_journey）。
    assert_eq!(
        audit.audited().len(),
        1,
        "断言 A：login → outbox → relay → AMQP → consumer → audit，仅 append 一次"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &captured_event_id, &consumer_group).await?,
        1,
        "断言 A：original event 必须在 PG inbox_dedup 标记 done"
    );

    // ── 步骤 11：断言 B（PG inbox 幂等去重）──────────────────────────────────────────────────

    // 仅「重投后 len 不增」是假阴性（重投未投递/未及处理也会通过）。改用 **tracer 正向见证**：先重投同一
    // event_id（duplicate，期望 PG inbox `try_claim` 返回 Duplicate、不 append），再投一条**新 event_id**
    // （tracer，同 payload → Fresh → append）。单 queue 单 consumer FIFO 顺序消费：tracer 被 audit（len 达 2）
    // 即证明其之前的 duplicate 已被 consumer 真实消费+settle（而非未投递）。去重生效 → 最终稳定 len==2
    // （original + tracer）；去重失效 → duplicate 也 append、升到 3，被下方 fail-fast 捕获。
    let pubr = amqp::AmqpPublisher::connect(&vhost_url, "e2e-redeliver").await?;
    pubr.publish(PublishRequest::new(
        Topic::new(SESSION_CREATED_TOPIC),
        MessageId::new(&captured_event_id),
        captured_payload.clone(),
    ))
    .await?;
    let tracer_id = format!("{captured_event_id}-tracer");
    pubr.publish(PublishRequest::new(
        Topic::new(SESSION_CREATED_TOPIC),
        MessageId::new(&tracer_id),
        captured_payload,
    ))
    .await?;

    // 正向见证：等 audit 至少再 append 一次（len>=2）——证明重投流被 consumer 真实消费（消除假阴性）。
    tokio::time::timeout(Duration::from_secs(20), async {
        while audit.audited().len() < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("timeout 20s 内重投流（duplicate/tracer）未被消费——断言 B 无法正向见证")
    })?;

    // 去重生效 → 稳定 len==2；去重失效 → duplicate 也 append、升到 3。再观察 2s：升到 3 即 fail-fast。
    let leaked_dup = tokio::time::timeout(Duration::from_secs(2), async {
        while audit.audited().len() < 3 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        leaked_dup.is_err(),
        "断言 B 失败：duplicate 被重复 append（audit len 升到 3），PG inbox 幂等去重未生效"
    );
    assert_eq!(
        audit.audited().len(),
        2,
        "断言 B：original + tracer 各 append 一次，duplicate 命中 PG inbox Duplicate 被去重（共 2）"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &captured_event_id, &consumer_group).await?,
        1,
        "断言 B：duplicate 不得新增 original 的 inbox_dedup done 行"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &tracer_id, &consumer_group).await?,
        1,
        "断言 B：tracer 新 event 必须在 PG inbox_dedup 标记 done"
    );

    pubr.shutdown().await?;

    // ── 步骤 12：关停（LIFO：workers 先 drain，infra_guards 后断连）────────────────────────────

    let failures = stack.shutdown().await;
    assert!(failures.is_empty(), "shutdown 存在失败项: {failures:?}");

    // fixture guard drop：停两个容器（pg / rmq）。
    drop(poll_view);
    drop(id);
    drop(assertion_pool);
    drop(pg);
    drop(pgfix);
    drop(rmq);

    Ok(())
}
