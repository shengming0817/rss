//! #1100 / T008 durable 拓扑 journey：identity 登录 → **postgres durable outbox** → relay CAS 中继 →
//! **PgInboxStore 幂等**消费 → audit append。demo 拓扑变体见 `identity_login_audit_journey.rs`。
//!
//! `#![cfg(feature = "integration")]`：需真实 postgres，默认 build / `cargo xtask verify` 不编译本文件。
//! postgres 经 `testkit::env_or_postgres()` self-provision（testcontainers，#1137）——无需手工预置；设 libpq
//! env（`PGHOST`/`PGPORT`/`PGDATABASE`(含 `test`)/`PGUSER`/`PGPASSWORD`）则对接长存外部 pg（不起容器）。
//! **fail-closed**：`PGDATABASE` 不含 `test` → 测试失败（破坏性 DDL 防护；容器路径 db=`rss_test` 恒满足）。
//! 本地运行：`cargo nextest run -p journeys --features integration`（docker 在场自起容器）或经
//! `cargo xtask ci run --job integration/event-transport/1-of-2` 与 `2-of-2`。
//!
//! 拓扑：relay 用进程内 `MemBus` 作 in-test broker（per-broker amqp 隔离由 amqp adapter 集成测试覆盖；
//! 本 journey 聚焦 producer durable 落库 + relay CAS + 消费侧 PgInbox 幂等的端到端贯通）。
//!
//! 无清表：每次登录 mint **独立 EventId**（opaque UUID，非 session_id；payload.sessionId 仅用于关联本轮 entry），
//! outbox/inbox_receipts 以 event_id 为键，跨轮次不冲突；relay 仅中继本轮 event_id 的 entry（不碰他轮 pending 行），
//! 故消费侧只收本轮事件。

#![cfg(feature = "integration")]

mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context as _, Result};
use audit::ports::{
    AuditEventKind, AuditWriteRepo as _, DynAuditWriteRepo, TenantRepoScope,
    audit_record_from_event_message,
};
use bootstrap::SubscriberCapability;
use common::{
    CANON_TENANT, CANON_USER, CapturingVerifier, LOGIN_USERNAME, NOW_SECS, PASSWORD,
    SESSION_CREATED_TOPIC, TTL_SECS, audit_domain, dlx_payload_protector, identity_domain,
    password_policy, session_created_subscription,
};
use consistency::{
    Disposition, EngineError, EngineErrorKind, HandleResult, OutboxRelay, PermanentError,
    PermanentErrorKind,
};
use diagctx::{CorrelationId, DiagnosticCtx};
use diport::{
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore, DynPublisher,
    EnvelopeMetadata, KEY_CORRELATION, KEY_SUBJECT_ID, ManagedResource, Message, MessageId,
    PublishRequest, Publisher, Subscriber, Topic,
};
use eventexec::{
    ConsumerMeta, LeaseConfig, RelayBudget, TenantAuthority, TenantAuthorityBinding, run_consumer,
};
use futures::future::BoxFuture;
use generated::event::identity_v1::session_created::IdentitySessionCreatedPayload;
use generated::http::identity_v1::login::{IdentityLoginRequest, PRODUCER as LOGIN_PRODUCER};
use httpserve::ProducerMarker;
use identity::ports::{
    Credential, CredentialRepo as _, DynAccountSecurityReadRepo, DynCredentialRepo,
    LoginProducerReceipt, TenantRepoScope as IdentityTenantRepoScope,
};
use identity::{CredentialSecurityService, LoginService};
use memory::{FixedClock, MemBus};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig, caps};
use primitives::MacKey;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use testkit::{await_condition, await_delay};
use tokio_util::sync::CancellationToken;
use vocab::TenantId;

const IDENTITY_DOMAIN: &str = "identity";
const RSS_APP_ROLE: &str = "rss_app";
const RSS_APP_PASSWORD: &str = "rss_app_test_pw";
const RSS_APP_READ_ROLE: &str = "rss_app_read";
const RSS_APP_READ_PASSWORD: &str = "rss_app_read_test_pw";
/// #1160：注入的 correlation——经 diagctx ambient → PgAuthGrantLifecycle emit → outbox.metadata 列 → relay
/// hydrate → MemBus → consumer `Message.metadata` 端到端保真断言（白名单字符，CorrelationId::parse 必通）。
const JOURNEY_CORR: &str = "journey-corr-1160";

fn login_producer_receipt() -> LoginProducerReceipt {
    ProducerMarker::for_test(LOGIN_PRODUCER).into_receipt()
}

fn finish_with_pg_cleanup(body: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(body), Ok(())) => Err(body),
        (Ok(()), Err(cleanup)) => Err(cleanup).context("shut down durable-journey postgres"),
        (Err(body), Err(cleanup)) => {
            Err(body).context(format!("postgres cleanup also failed: {cleanup:#}"))
        }
    }
}

fn durable_tenant_authority(database_now_epoch: i64) -> Result<Arc<TenantAuthority>> {
    let now_epoch_secs = Arc::new(move || database_now_epoch);
    Ok(Arc::new(TenantAuthority::new(
        Arc::new(CapturingVerifier::default()),
        MacKey::from_bytes(vec![0x42; 32]),
        3600,
        60,
        now_epoch_secs,
    )?))
}

fn signed_metadata_at(
    authority: &TenantAuthority,
    domain: &str,
    contract_id: &str,
    topic: &str,
    message_id: &str,
) -> Result<EnvelopeMetadata> {
    let tenant = TenantId::parse(CANON_TENANT)?;
    let token = authority.sign(TenantAuthorityBinding::new(
        tenant,
        domain,
        contract_id,
        topic,
        message_id,
    ))?;
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(diport::KEY_TENANT_ID, CANON_TENANT);
    metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_VERSION,
        generated::event::identity_v1::session_created::CONTRACT.version(),
    );
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_HASH,
        generated::event::identity_v1::session_created::CONTRACT.schema_hash(),
    );
    Ok(metadata)
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

fn pg_config_for(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
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

async fn database_now_epoch(p: &testkit::PgConnParams) -> Result<i64> {
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
    let now_epoch =
        sqlx::query_scalar::<_, i64>("SELECT extract(epoch FROM clock_timestamp())::bigint")
            .fetch_one(&pool)
            .await?;
    pool.close().await;
    Ok(now_epoch)
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

#[derive(Clone)]
struct CapturedBrokerMessage {
    event_id: String,
    payload: Vec<u8>,
    metadata: EnvelopeMetadata,
}

/// Journey-local audit decode/repo append → run_consumer HandleResult handler。
/// `captured` 记录 broker-visible 消息（#1160 端到端 payload/event id/metadata 保真断言），不旁路读取
/// provider-owned opaque outbox claim 的 durable/lease context。
fn consumer_handler(
    repo: Arc<DynAuditWriteRepo<'static>>,
    captured: Arc<Mutex<Vec<CapturedBrokerMessage>>>,
) -> impl Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync {
    move |message: Message| {
        let repo = Arc::clone(&repo);
        let captured = captured.clone();
        Box::pin(async move {
            captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(CapturedBrokerMessage {
                    event_id: message.id.as_str().to_string(),
                    payload: message.payload.as_bytes().to_vec(),
                    metadata: message.metadata.clone(),
                });
            let record =
                match audit_record_from_event_message(AuditEventKind::SessionCreated, &message) {
                    Ok(record) => record,
                    Err(_) => {
                        return HandleResult::reject(PermanentError::new(
                            PermanentErrorKind::Permanent,
                        ));
                    }
                };
            let scope = TenantRepoScope::for_test(record.tenant);
            match repo.append(scope, record).await {
                Ok(()) => HandleResult::ack(),
                Err(_) => HandleResult::requeue(EngineError::new(EngineErrorKind::Transient)),
            }
        })
    }
}

async fn wait_until_audited(audit: &CapturingVerifier) -> Result<()> {
    await_condition(Duration::from_secs(5), || !audit.is_empty()).await?;
    Ok(())
}

/// durable 端到端：login → PgAuthGrantLifecycle co-tx（grant + initial refresh + outbox 同事务）→ relay CAS →
/// MemBus(message_id=EventId) → run_consumer(PgInbox 幂等) → audit append；再投递同一 EventId → PgInbox
/// Duplicate → audit 仍 1（acc #2）。session 行持久化/原子性由 postgres t11/t12 守（见上方 with_seed_user 注释）。
///
/// F4：无 `#[ignore]`——`#![cfg(feature = "integration")]` 门控；postgres 经 `testkit::env_or_postgres()`
/// self-provision（testcontainers，#1137；设 `PGHOST` 等则对接长存外部 pg）。需 docker（容器路径）。
/// `pg` fixture guard **须绑定到测试结束**（其 `Drop` 停容器）。
#[tokio::test(flavor = "multi_thread")]
async fn login_audit_durable_topology() -> Result<()> {
    let pg = testkit::env_or_postgres().await?;
    testkit::provision_postgres_test_logins(
        pg.params(),
        &[
            testkit::PostgresTestLogin::new(RSS_APP_ROLE, RSS_APP_PASSWORD),
            testkit::PostgresTestLogin::new(RSS_APP_READ_ROLE, RSS_APP_READ_PASSWORD),
        ],
    )
    .await?;
    let authority_epoch = database_now_epoch(pg.params()).await?;
    let owner_config = pg_config(pg.params())?;
    let app_config = pg_config_for(pg.params(), RSS_APP_ROLE, RSS_APP_PASSWORD);
    let tenant_read_config = PgTenantReadConfig::new(pg_config_for(
        pg.params(),
        RSS_APP_READ_ROLE,
        RSS_APP_READ_PASSWORD,
    ));
    // test-only fixture owns migration setup; serving APIs cannot reach migration capability.
    let workflow = eventexec::WorkflowRuntimePlan::disabled_fixture();
    let deps = PgRuntimeDeps::setup_test_fixture(
        &owner_config,
        &app_config,
        &tenant_read_config,
        None,
        workflow.projection_capture(),
    )
    .await?;
    let body_result: Result<()> = async {
        let pg_handle = deps.handle();
        let id = pg_handle.for_domain::<caps::Identity>();
        let tenant = TenantId::parse(CANON_TENANT)?;
        id.credential_repo()
            .insert(
                IdentityTenantRepoScope::for_test(tenant),
                Credential::hydrate(
                    LOGIN_USERNAME,
                    ids::UserId::parse(CANON_USER)?,
                    tenant,
                    secure::PasswordHash::for_test(secure::RawPassword::new(PASSWORD.to_owned()))?,
                    1,
                ),
            )
            .await?;

        let bus = MemBus::new();
        let (audit_domain, audit, audit_repo) = audit_domain();
        // relay 的 iat 来自 PostgreSQL `now()`；consumer 必须以实时钟验证同一 authority，不能复用
        // payload 的固定业务时钟（NOW_SECS），否则所有真实 durable 消息都会被误判为未来 token。
        let durable_authority = durable_tenant_authority(authority_epoch)?;

        // 组装 audit 订阅（contract/topic/group 单源自 generated SPEC.subscriptions()）。
        let mut refresh_identity = None;
        let mut credential_security_grants = None;
        let mut credential_security_lifecycle = None;
        let login_identity = Arc::new(LoginService::with_seed_credential(
            |accounts| {
                let services = identity::seed_auth_grant_services(
                    id.auth_grant_provider(
                        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                        postgres::identity_pseudonym_keys_for_test(),
                    ),
                    accounts,
                    || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                    Duration::from_secs(TTL_SECS),
                );
                refresh_identity = Some(services.refresh_service());
                credential_security_grants = Some(services.lifecycle());
                credential_security_lifecycle = Some(services.security_lifecycle());
                services
            },
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
            Duration::from_secs(TTL_SECS),
            LOGIN_USERNAME,
            ids::UserId::parse(CANON_USER)?,
            PASSWORD,
            TenantId::parse(CANON_TENANT)?,
        )?);
        let refresh_identity = refresh_identity
            .ok_or_else(|| anyhow::anyhow!("seed refresh service was not constructed"))?;
        let credential_security = Arc::new(CredentialSecurityService::new_with_shared_lifecycle(
            Arc::from(DynCredentialRepo::new_box(id.credential_repo())),
            credential_security_grants
                .ok_or_else(|| anyhow::anyhow!("seed grant lifecycle was not constructed"))?,
            DynAccountSecurityReadRepo::new_box(id.account_security_repo()),
            credential_security_lifecycle
                .ok_or_else(|| anyhow::anyhow!("seed security lifecycle was not constructed"))?,
            id.account_reactivation_lifecycle(),
            password_policy(),
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        ));
        let identity_domain =
            identity_domain(login_identity, refresh_identity, credential_security);
        let registry = bootstrap::compose(&[&identity_domain, &audit_domain])?;
        let binding = session_created_subscription(registry)?;
        anyhow::ensure!(binding.topic() == SESSION_CREATED_TOPIC);
        let (event_contract_id, event_topic, _, group, execution) = binding.into_parts();
        anyhow::ensure!(matches!(
            execution,
            SubscriberCapability::AdapterNativeTransactional
        ));
        let event_domain = event_topic.split('.').next().unwrap_or(event_topic);

        // 消费侧：PgInboxStore 幂等 claimer（durable，group 自 binding 单源；非 identity 域资源）。
        let claimer = Arc::new(pg_handle.infra().inbox());
        let token = CancellationToken::new();
        let stream = bus
            .subscriber()
            .subscribe(Topic::new(event_topic), token.clone())
            .await?;
        let meta = ConsumerMeta::new(
            "audit",
            event_topic.split('.').next().unwrap_or(event_topic),
            event_contract_id,
            event_topic,
            group.as_str(),
            Arc::clone(&durable_authority),
        );
        // #1160：捕获 broker-visible 消息，端到端断言 outbox→relay→MemBus→consumer 全链保真。
        let captured: Arc<Mutex<Vec<CapturedBrokerMessage>>> = Arc::new(Mutex::new(Vec::new()));
        let consume = run_consumer(
            stream,
            claimer.clone(),
            DynDeadLetterStore::new_box(NoopDlx),
            meta,
            consumer_handler(audit_repo, captured.clone()),
            // 续租间隔派生自 PgInboxStore 后端 claim TTL（同源，杜绝 mismatch footgun，#1213 review #3）。
            LeaseConfig::from_ttl(claimer.lease_ttl()),
        );

        // 生产侧：login → PgAuthGrantLifecycle **co-tx**（grant + initial refresh + outbox）durable 落库；relay
        // （MemBus 作 in-test broker）CAS 中继。持久化 + co-tx 原子性由 postgres 集成测试守；
        // 本 journey 验 co-tx provider 端到端贯通到 audit。
        let tenant = TenantId::parse(CANON_TENANT)?;
        let login = LoginService::with_seed_credential(
            |accounts| {
                identity::seed_auth_grant_services(
                    id.auth_grant_provider(
                        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                        postgres::identity_pseudonym_keys_for_test(),
                    ),
                    accounts,
                    || Box::new(FixedClock::at_unix_secs(NOW_SECS)),
                    Duration::from_secs(TTL_SECS),
                )
            },
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
            Duration::from_secs(TTL_SECS),
            LOGIN_USERNAME,
            ids::UserId::parse(CANON_USER)?,
            PASSWORD,
            tenant,
        )?;
        let relay = id.outbox(
            DynPublisher::new_box(bus.publisher()),
            RelayBudget::new(
                Duration::from_secs(60),
                Duration::from_secs(40),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )?,
            Arc::clone(&durable_authority),
            dlx_payload_protector(),
        );
        anyhow::ensure!(
            OutboxRelay::claim_domain(&relay).as_str() == IDENTITY_DOMAIN,
            "identity relay 必须绑定 identity claim domain"
        );

        let drive = async {
            // #1160：login emit（PgAuthGrantLifecycle co-tx）在 diagctx scope 内执行 ⇒ correlation 经 ambient
            // 信道盖进 outbox.metadata 列（fail-open；scope 外则省略）。
            let response = diagctx::scope(
                DiagnosticCtx::new(CorrelationId::parse(JOURNEY_CORR)?),
                login.login(
                    login_producer_receipt(),
                    tenant,
                    IdentityLoginRequest {
                        username: LOGIN_USERNAME.to_string(),
                        password: PASSWORD.to_string(),
                    },
                ),
            )
            .await?;
            // F1 后：idem_key = 独立 EventId（非 session_id）；以 payload.sessionId 关联本轮 entry（F6）。
            let session_id = response.data.session_id.clone();

            // bounded claim（最多 50 次 × 100ms），逐条按值 relay 后从 broker-visible capture 解码匹配
            // 本轮 session_id。对抗其它可投递行且不依赖批次数量/顺序；opaque claim 不暴露观察 accessor。
            let (event_id, payload) = {
                let mut found = None;
                for _ in 0..50 {
                    let claimed = OutboxRelay::claim_batch(&relay, 64).await?;
                    for entry in claimed {
                        let disposition = OutboxRelay::relay(&relay, entry).await?;
                        anyhow::ensure!(
                            disposition == Disposition::Ack,
                            "outbox relay 未发布：{disposition:?}"
                        );
                    }
                    found = captured
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .iter()
                        .find(|message| {
                            serde_json::from_slice::<IdentitySessionCreatedPayload>(
                                &message.payload,
                            )
                            .is_ok_and(|decoded| decoded.session_id == session_id)
                        })
                        .map(|message| (message.event_id.clone(), message.payload.clone()));
                    if found.is_some() {
                        break;
                    }
                    await_delay(Duration::from_millis(100)).await;
                }
                found.ok_or_else(|| {
                    anyhow::anyhow!(
                        "outbox 缺本轮 session-created entry（session_id={session_id}）"
                    )
                })?
            };
            // claim batch 已逐条按值 relay → MemBus（message_id = entry 自身的独立 EventId）。
            wait_until_audited(&audit).await.with_context(|| {
                let consumed = captured.lock().unwrap_or_else(|e| e.into_inner()).len();
                format!("audit 未落链；consumer 已观察 {consumed} 条消息")
            })?;

            // 重投同一 EventId（模拟 broker 重投）→ PgInbox Duplicate → audit 不重复。
            bus.publisher()
                .publish(
                    PublishRequest::new(
                        Topic::new(SESSION_CREATED_TOPIC),
                        MessageId::new(event_id.as_str()),
                        payload,
                    )
                    .with_metadata(signed_metadata_at(
                        &durable_authority,
                        event_domain,
                        event_contract_id,
                        event_topic,
                        event_id.as_str(),
                    )?),
                )
                .await?;
            await_delay(Duration::from_millis(50)).await;
            anyhow::Ok(())
        };

        tokio::pin!(consume);
        tokio::pin!(drive);
        let driven = tokio::select! {
            result = &mut drive => {
                // drive 任一路径（含 `?` 提前失败）都终止 consumer，避免永久等待并吞掉原始诊断。
                token.cancel();
                consume.await;
                result
            }
            () = &mut consume => Err(anyhow::anyhow!("consumer 在 durable drive 完成前退出")),
        };
        driven?;

        anyhow::ensure!(
            audit.audited().len() == 1,
            "durable：登录 emit + 重投同一 EventId → audit 链仅 append 一次（PgInbox 幂等）"
        );

        // #1160 端到端 envelope metadata 保真：取首条携 metadata 的消费消息（重投是 metadata 空的 PublishRequest），
        // 断言 broker-visible occurred_at / correlation 经 emit→outbox.metadata 列→relay hydrate→MemBus→consumer 全链保真。
        let seen = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let md = seen
            .iter()
            .map(|message| &message.metadata)
            .find(|metadata| !metadata.is_empty())
            .ok_or_else(|| anyhow::anyhow!("consumer 未收到任何携 envelope metadata 的消息"))?;
        anyhow::ensure!(
            md.occurred_at_secs() == Some(NOW_SECS as i64),
            "occurred_at（注入 Clock）应经 outbox.metadata→relay→broker→consumer 全链保真"
        );
        anyhow::ensure!(
            md.get(KEY_CORRELATION) == Some(JOURNEY_CORR),
            "correlation 应经 diagctx ambient→emit→outbox.metadata→relay→broker→consumer 全链保真"
        );
        anyhow::ensure!(
            md.get(KEY_SUBJECT_ID).is_none(),
            "subjectId 是 persisted-only metadata，不应经 relay→broker→consumer 外发"
        );
        Ok(())
    }
    .await;

    let cleanup_result: Result<()> = async {
        let (resources, _sampler_factory) = deps.into_runtime_parts(Duration::from_secs(1));
        for resource in resources.into_iter().rev() {
            resource.shutdown().await?;
        }
        Ok(())
    }
    .await;
    finish_with_pg_cleanup(body_result, cleanup_result)
}

#[test]
fn pg_cleanup_result_preserves_body_error_and_reports_cleanup_failure() -> Result<()> {
    let err = finish_with_pg_cleanup(
        Err(anyhow::anyhow!("body failed")),
        Err(anyhow::anyhow!("cleanup failed")),
    )
    .err()
    .ok_or_else(|| anyhow::anyhow!("both failures must remain an error"))?;
    let rendered = format!("{err:#}");
    assert!(rendered.contains("body failed"));
    assert!(rendered.contains("cleanup failed"));
    Ok(())
}

#[test]
fn pg_cleanup_result_returns_cleanup_only_failure() -> Result<()> {
    let err = finish_with_pg_cleanup(Ok(()), Err(anyhow::anyhow!("cleanup failed")))
        .err()
        .ok_or_else(|| anyhow::anyhow!("cleanup failure must be returned"))?;
    assert!(format!("{err:#}").contains("cleanup failed"));
    Ok(())
}

#[test]
fn pg_cleanup_result_preserves_success_and_body_only_failure() -> Result<()> {
    finish_with_pg_cleanup(Ok(()), Ok(()))?;
    let err = finish_with_pg_cleanup(Err(anyhow::anyhow!("body failed")), Ok(()))
        .err()
        .ok_or_else(|| anyhow::anyhow!("body failure must be returned"))?;
    assert_eq!(format!("{err:#}"), "body failed");
    Ok(())
}
