//! #1251/#1434 durable e2e journey：`wire_event_transport` → postgres + RabbitMQ 真容器
//! 贯通 outbox → relay → AMQP → consumer → PG inbox 幂等去重 → audit 审计链。
//!
//! 断言 A（至少一次）：登录触发 outbox 落库 → relay 中继 → AMQP consumer 消费 → audit append
//! 仅一次（20s timeout）。
//!
//! 断言 B（PG inbox 幂等去重，tracer 正向见证）：重投同一 event_id（duplicate）+ 一条新 event_id（tracer，
//! 同 payload → Fresh → append）。FIFO 单 consumer：tracer 被 audit（PG count→2）证明其之前的 duplicate
//! 已被真实消费+settle；稳定 count==2（original + tracer）证明 duplicate 命中 Duplicate 去重（升到 3 即去重失效）。
//!
//! `#![cfg(feature = "integration")]`：需真实 docker 容器；`cargo test -p runtime --features
//! integration --no-run` 仅要求编译通过（无 docker 时可用）。
//! `cargo nextest run -p runtime --features integration` 或
//! `cargo xtask ci run --job integration/event-transport/1-of-2` 与 `2-of-2` 运行实际测试。

#![cfg(feature = "integration")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result};
use audit::ports::{
    AuditChainHasher, AuditListTenantAppend, AuditListTenantAppender, DynAuditReadRepo,
};
use audit::{AuditDomain, InMemAuditRepo};
use base64::Engine as _;
use consistency::{EventEntry, EventTopic, IdemKey, OutboxPayload};
use diport::{
    DynKeyProvider, EncryptOutput, EnvelopeMetadata, EnvelopeSubjectId, KeyName, KeyProvider,
    KeyProviderError, KeyRef, KeyVersion, MessageId, OpaqueActorId, OutboxActor, PublishRequest,
    Publisher, RedactedBytes, Topic,
};
use eventexec::TenantAuthorityBinding;
use generated::event::identity_v1::{
    policy_updated::{self, IdentityPolicyUpdatedPayload},
    session_created::{self, IdentitySessionCreatedPayload},
};
use generated::event::settings_v1;
use generated::http::identity_v1::login::IdentityLoginRequest;
use generated::http::settings_v1::SettingsConfigPublishRequest;
use identity::ports::{
    AttributeKey, AttributeValue, DynPolicyLifecycle, DynPolicyRepo, DynResourceAttributeRepo,
    DynRoleBindingLifecycle, DynRoleReadRepo, DynSessionLifecycle, Operator,
    POLICY_ATTR_PRINCIPAL_KIND, Policy, PolicyCondition, PolicyEffect, PolicyLifecycle,
    PolicyObligations, PolicyRouteScope, PolicyRule, TenantId, TenantRepoScope,
};
use identity::{IdentityDomain, IdentityDomainDeps, LoginService};
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, caps};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tokio_util::sync::CancellationToken;

use runtime::event_transport::{bridge_generated_subscriptions, build_event_transport_config_from};
use runtime::test_support::wire_event_transport;
use runtime::{
    SharedRuntimeDeps, SystemClock, build_redis_runtime_deps, build_vault_runtime_deps,
    wire_distributed,
};
use settings::{SettingsDomain, SettingsService, empty_flag_store};

const TEST_PUBLISH_TIMEOUT: Duration = Duration::from_secs(40);

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

struct NoopDomainTransport;

impl distributed::DomainTransport for NoopDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::DomainRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<distributed::DomainResponse, distributed::DomainTransportError>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async {
            Ok(distributed::DomainResponse::new(
                204,
                Vec::new(),
                Vec::new(),
            ))
        })
    }
}

fn noop_domain_transport() -> Arc<dyn distributed::DomainTransport> {
    Arc::new(NoopDomainTransport)
}

fn amqp_endpoint(url: &str) -> Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

fn signed_session_metadata(
    authority: &eventexec::TenantAuthority,
    message_id: &str,
) -> Result<EnvelopeMetadata> {
    let tenant = TenantId::parse(CANON_TENANT)?;
    let token = authority.sign(TenantAuthorityBinding::new(
        tenant,
        session_created::CONTRACT.domain(),
        session_created::CONTRACT.contract_id(),
        session_created::TOPIC,
        message_id,
    ))?;
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(diport::KEY_TENANT_ID, CANON_TENANT);
    metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_VERSION,
        session_created::CONTRACT.version(),
    );
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_HASH,
        session_created::CONTRACT.schema_hash(),
    );
    Ok(metadata)
}

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

#[derive(Clone)]
struct TestKeyProvider;

impl KeyProvider for TestKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let ciphertext: Vec<u8> = plaintext.expose().iter().map(|byte| byte ^ 0xA5).collect();
        Ok(EncryptOutput::new(
            ciphertext,
            KeyRef::new(key, KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, KeyProviderError> {
        let plaintext: Vec<u8> = ciphertext
            .into_bytes()
            .into_iter()
            .map(|byte| byte ^ 0xA5)
            .collect();
        Ok(secure::Plaintext::new(plaintext))
    }

    async fn rewrap(
        &self,
        _ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Err(KeyProviderError::new(
            diport::key_provider::KeyProviderErrorKind::Forbidden,
            std::io::Error::other("test key provider does not rewrap"),
        ))
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

fn config_value_protections() -> Result<postgres::ConfigValueProtections> {
    let key = KeyName::try_new("settings-config")?;
    Ok(postgres::ConfigValueProtections::new(
        DynKeyProvider::new_box(TestKeyProvider),
        DynKeyProvider::new_box(TestKeyProvider),
        key,
    ))
}

// ── CapturingVerifier（自 journeys/tests/common/mod.rs 复制）──────────────────────────────

/// 审计链 HMAC 测试 verifier：捕获每次 `sign` 调用的 message，确定性折叠产出 32B 标签（链一致）。
#[derive(Clone, Default)]
struct CapturingVerifier {
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
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

#[derive(Clone, Default)]
struct TestAuditListTenantAppender;

impl AuditListTenantAppender for TestAuditListTenantAppender {
    async fn append(&self, _command: AuditListTenantAppend) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }
}

#[allow(clippy::expect_used)]
// reason: 32B audit key 满足 AuditChainHasher MIN_KEY_LEN（失败意味测试常量有误），panic 正当。
fn audit_domain() -> (AuditDomain<TestAuditListTenantAppender>, CapturingVerifier) {
    let verifier = CapturingVerifier::default();
    let hasher = AuditChainHasher::new(verifier.clone(), MacKey::from_bytes(AUDIT_KEY.to_vec()))
        .expect("32B audit key satisfies MIN_KEY_LEN");
    let provider = Arc::new(InMemAuditRepo::new(hasher));
    let read_repo: Arc<DynAuditReadRepo<'static>> = Arc::from(DynAuditReadRepo::new_box(provider));
    let domain = AuditDomain::new(
        read_repo,
        None,
        TestAuditListTenantAppender,
        Arc::new(SystemClock),
    );
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
        generated::event::PROJECTION_INPUT_GENERATION,
        generated::event::PROJECTION_INPUTS,
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
        "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2 AND status = 'done'",
    )
    .bind(event_id)
    .bind(group)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

async fn wait_inbox_done(pool: &sqlx::PgPool, event_id: &str, group: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if inbox_done_count(pool, event_id, group)
                .await
                .is_ok_and(|count| count == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("timeout 20s 内 event {event_id} 未被 consumer group {group} 消费")
    })
}

async fn latest_outbox_event_id(pool: &sqlx::PgPool, domain: &str, topic: &str) -> Result<String> {
    let (event_id,): (String,) = sqlx::query_as(
        r#"
        SELECT event_id
        FROM outbox
        WHERE domain = $1 AND topic = $2
        ORDER BY created_at DESC, event_id DESC
        LIMIT 1
        "#,
    )
    .bind(domain)
    .bind(topic)
    .fetch_one(pool)
    .await?;
    Ok(event_id)
}

/// 测试专用只读观察：不经过生产 outbox API，因此不会夺取后台 relay 的租约。
/// tenant/domain/topic 均为必填过滤条件；bounded 查询后在 Rust 解码本轮 session payload。
async fn outbox_session_event(
    pool: &sqlx::PgPool,
    tenant: TenantId,
    domain: &str,
    topic: &str,
    session_id: &str,
) -> Result<Option<(String, Vec<u8>)>> {
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT event_id, payload
        FROM outbox
        WHERE tenant_id = $1::uuid AND domain = $2 AND topic = $3
        ORDER BY created_at DESC, event_id DESC
        LIMIT 64
        "#,
    )
    .bind(tenant.to_string())
    .bind(domain)
    .bind(topic)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().find(|(_, payload)| {
        serde_json::from_slice::<IdentitySessionCreatedPayload>(payload)
            .is_ok_and(|decoded| decoded.session_id == session_id)
    }))
}

async fn audit_login_count(pool: &sqlx::PgPool, tenant: TenantId, session_id: &str) -> Result<i64> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let (count,): (i64,) = sqlx::query_as(
        r#"
        SELECT count(*)
        FROM audit_entries
        WHERE tenant_id = $1::uuid
          AND action = 'identity:login'
          AND resource_kind = 'session'
          AND resource_id = $2
          AND outcome = 'success'
        "#,
    )
    .bind(tenant.to_string())
    .bind(session_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count)
}

async fn audit_policy_count(
    pool: &sqlx::PgPool,
    tenant: TenantId,
    resource_id: &str,
) -> Result<i64> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let (count,): (i64,) = sqlx::query_as(
        r#"
        SELECT count(*)
        FROM audit_entries
        WHERE tenant_id = $1::uuid
          AND action = 'identity:policy_create'
          AND resource_kind = 'policy'
          AND resource_id = $2
          AND outcome = 'success'
        "#,
    )
    .bind(tenant.to_string())
    .bind(resource_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count)
}

fn policy_updated_entry_and_envelope(
    tenant: TenantId,
    policy_id: &str,
    contract_id: &str,
    permission: &str,
    event_id: &str,
) -> Result<(EventEntry, diport::OutboxEnvelopeParts)> {
    let payload = IdentityPolicyUpdatedPayload {
        policy_id: policy_id.to_string(),
        change_kind: policy_updated::IdentityPolicyUpdatedPayloadChangeKind::Created,
        version: std::num::NonZeroU32::new(1).context("policy version is non-zero")?,
        contract_id: contract_id.to_string(),
        permission: permission.to_string(),
        updated_by: uuid::Uuid::parse_str(CANON_USER)?,
        actor_kind: policy_updated::IdentityPolicyUpdatedPayloadActorKind::Admin,
        tenant_id: tenant.to_string(),
        occurred_at: i64::try_from(NOW_SECS)?,
    };
    let entry = EventEntry::new(
        EventTopic::parse(policy_updated::TOPIC)?,
        IdemKey::parse(event_id)?,
        OutboxPayload::from_reviewed_event_bytes(serde_json::to_vec(&payload)?),
    );
    let actor = OutboxActor::scoped(
        vocab::PrincipalKind::Admin,
        OpaqueActorId::from_opaque(CANON_USER)?,
        tenant,
        vocab::ScopedTenant::Tenant,
    );
    let envelope = diport::OutboxEnvelopeParts::new(
        policy_updated::CONTRACT,
        tenant,
        EnvelopeSubjectId::from_opaque(CANON_USER)?,
        actor,
    );
    Ok((entry, envelope))
}

// ── e2e 测试主体 ───────────────────────────────────────────────────────────────────────────

/// durable e2e：`wire_event_transport` 真容器贯通验收（#1251 task 6）。
///
/// - 断言 A：login → PgOutbox(pending) → relay → AMQP → consumer → PG inbox(Fresh) → audit append（至少一次）。
/// - 断言 B：重投同一 event_id（duplicate）+ tracer（新 event_id）→ tracer 被消费正向见证 duplicate 已消费；
///   稳定 PG audit count==2 + `inbox_receipts` done 行证明 duplicate 命中 PG inbox Duplicate 去重。
///
/// 需 docker：`cargo test -p runtime --features integration event_transport_durable -- --nocapture`
/// 或 `cargo nextest run -p runtime --features integration`。无 docker 时只需通过
/// `cargo test -p runtime --features integration --no-run`（编译门）。
#[tokio::test(flavor = "multi_thread")]
async fn event_transport_durable_e2e() -> Result<()> {
    // ── 步骤 1：启动两个真实容器 fixture（guard 绑到测试结束，Drop 停容器）─────────────────────

    let (pgfix, pg_owner) = connect_pg().await?;
    let pg = pg_owner.handle();
    let rmq = testkit::env_or_rabbitmq().await?;

    // ── 步骤 2：postgres capability bundle（connect + run_migrations + RLS 能力门）──────────────

    let assertion_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pg_owner_connect_options(pgfix.params()))
        .await?;
    let id = pg.for_domain::<caps::Identity>();
    let settings_pg = pg.for_domain::<caps::Settings>();

    // ── 步骤 3：域装配（identity + settings + audit）────────────────────────────────────────

    let (audit_domain_inst, _audit) = audit_domain();

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
    let roles_for_admin = Arc::from(DynRoleReadRepo::new_box(id.role_repo()));
    let roles_for_list = Arc::from(DynRoleReadRepo::new_box(id.role_repo()));
    let policies = Arc::from(DynPolicyRepo::new_box(id.policy_repo()));
    let resource_attrs = Arc::from(DynResourceAttributeRepo::new_box(
        id.resource_attribute_repo(),
    ));
    let policy_lifecycle = Arc::from(DynPolicyLifecycle::new_box(
        id.policy_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
    ));
    let policy_lifecycle_for_service = Arc::clone(&policy_lifecycle);
    let bindings = Arc::from(DynRoleBindingLifecycle::new_box(
        id.role_binding_lifecycle(Box::new(FixedClock::at_unix_secs(NOW_SECS))),
    ));
    let rbac_admin = Arc::new(identity::RbacAdminService::new(
        roles_for_admin,
        Arc::clone(&bindings),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let policy_manage = Arc::new(identity::PolicyManageService::new(
        Arc::clone(&policies),
        policy_lifecycle_for_service,
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let identity_domain = IdentityDomain::new(IdentityDomainDeps {
        login: login_identity,
        refresh: refresh_identity,
        rbac_admin,
        policy_manage,
        roles: roles_for_list,
        bindings,
        policies,
        resource_attrs,
        clock: Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
    });
    let (settings_configs, settings_writer, settings_secrets, settings_secret_writer) = settings_pg
        .settings_bundle(
            Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
            config_value_protections()?,
        )
        .into_parts();
    let subscriber_settings_service = Arc::new(SettingsService::with_postgres(
        settings_configs,
        settings_writer,
        empty_flag_store(),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let settings_domain = SettingsDomain::new(
        Arc::clone(&subscriber_settings_service),
        Arc::from(settings_secrets),
        Arc::from(settings_secret_writer),
    );
    let (
        publisher_settings_configs,
        publisher_settings_writer,
        _publisher_settings_secrets,
        _publisher_settings_secret_writer,
    ) = settings_pg
        .settings_bundle(
            Arc::new(FixedClock::at_unix_secs(NOW_SECS)),
            config_value_protections()?,
        )
        .into_parts();
    let publisher_settings_service = Arc::new(SettingsService::with_postgres(
        publisher_settings_configs,
        publisher_settings_writer,
        empty_flag_store(),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    ));

    let tenant = TenantId::parse(CANON_TENANT)?;
    let settings_key = "app.runtime-e2e";
    let settings_actor = OutboxActor::scoped(
        vocab::PrincipalKind::Admin,
        OpaqueActorId::from_opaque("settings-event-transport-e2e")?,
        tenant,
        vocab::ScopedTenant::Tenant,
    );
    publisher_settings_service
        .publish_config(
            tenant,
            settings_actor.clone(),
            SettingsConfigPublishRequest {
                key: settings_key.to_string(),
                value: "disabled".to_string(),
            },
        )
        .await?;
    let initial_settings_event_id =
        latest_outbox_event_id(&assertion_pool, "settings", settings_v1::TOPIC).await?;
    assert_eq!(
        subscriber_settings_service
            .config_query_service()
            .get_config(tenant, settings_key)
            .await?
            .as_ref()
            .map(|entry| entry.value()),
        Some("disabled"),
        "subscriber settings cache must start with the old value before the ConsumerTx refresh"
    );

    // ── 步骤 4：compose + drain subscribers（generated event topology 对应的订阅绑定）────────────

    let mut registry =
        bootstrap::compose(&[&identity_domain, &settings_domain, &audit_domain_inst])?;
    let subscribers = bridge_generated_subscriptions(registry.drain_subscribers())?;
    let generated_group = |contract_id: &str, consumer: &str| {
        generated::event::EVENTS
            .iter()
            .find(|event| event.contract_id() == contract_id)
            .and_then(|event| {
                event
                    .subscriptions()
                    .iter()
                    .find(|spec| spec.consumer() == consumer)
            })
            .map(|spec| spec.group().to_owned())
    };
    let consumer_group = generated_group(
        generated::event::identity_v1::session_created::SPEC.contract_id(),
        "audit",
    )
    .context("e2e must declare audit session-created subscriber")?;
    let settings_consumer_group = generated_group(settings_v1::SPEC.contract_id(), "settings")
        .context("e2e must declare settings config-version-changed subscriber")?;
    let policy_consumer_group = generated_group(policy_updated::SPEC.contract_id(), "audit")
        .context("e2e must declare audit policy-updated subscriber")?;

    // ── 步骤 5：构造 EventTransportConfig（注入式 env builder，无 ambient env 侧效应）────────────

    let vhost_url = rmq.vhost_url("rss_evt_e2e").await?;

    // relay_poll_interval=2s：在 [100ms, 300s] 范围内；2s 窗口使步骤 6 poll 能赢过 relay 第二次轮询。
    // relay_sample_interval=30s：在 [1s, 60s] 范围内。
    let hmac_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    let cfg = build_event_transport_config_from(|name| match name {
        "RSS_TOPOLOGY" => Some("durable-shared".to_string()),
        "RSS_AMQP_URL" => Some(vhost_url.clone()),
        "RSS_AMQP_ALLOW_PLAINTEXT" => Some("true".to_string()),
        "RSS_RELAY_POLL_INTERVAL_MS" => Some("2000".to_string()),
        "RSS_RELAY_MAX_IN_FLIGHT" => Some("16".to_string()),
        "RSS_RELAY_SAMPLE_INTERVAL_MS" => Some("30000".to_string()),
        "RSS_OUTBOX_SWEEP_INTERVAL_MS" => Some("60000".to_string()),
        "RSS_OUTBOX_RETAIN_SECONDS" => Some("604800".to_string()),
        "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL" => Some(hmac_key.clone()),
        "RSS_DLX_PAYLOAD_KEY_NAME" => Some("dlx-payload".to_string()),
        "RSS_VAULT_ADDR" => Some("https://vault.example:8200".to_string()),
        "RSS_VAULT_TOKEN" => Some("s.testtoken".to_string()),
        "RSS_DLX_HOT_VAULT_TOKEN" => Some("s.dlx-hot-testtoken".to_string()),
        "RSS_DLX_ARCHIVE_VAULT_TOKEN" => Some("s.dlx-archive-testtoken".to_string()),
        "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_string()),
        _ => None,
    })?;
    let redeliver_tenant_authority = cfg
        .tenant_authority
        .clone()
        .context("durable e2e tenant authority missing")?;

    // ── 步骤 6：wire_event_transport → DomainModuleResult（relay OS 线程 + consumer worker 启动）────

    let redis_fixture = testkit::env_or_redis().await?;
    let redis = build_redis_runtime_deps(|name| match name {
        "RSS_REDIS_URL" => Some(redis_fixture.url().to_string()),
        "RSS_REDIS_ALLOW_PLAINTEXT" => Some("true".to_string()),
        _ => None,
    })
    .await?;
    let s3 = runtime::build_s3_runtime_deps_from(|name| match name {
        "RSS_S3_ENDPOINT_URL" => Some("http://127.0.0.1:1".to_string()),
        "RSS_S3_ALLOW_PLAINTEXT" => Some("true".to_string()),
        "RSS_S3_BUCKET" => Some("rss-test-bucket".to_string()),
        "RSS_S3_ACCESS_KEY_ID" => Some("access-key".to_string()),
        "RSS_S3_SECRET_ACCESS_KEY" => Some("secret-key".to_string()),
        "RSS_S3_FORCE_PATH_STYLE" => Some("true".to_string()),
        _ => None,
    })?;
    let vault = build_vault_runtime_deps(|name| match name {
        "RSS_VAULT_ADDR" => Some("https://vault.example:8200".to_string()),
        "RSS_VAULT_TOKEN" => Some("s.testtoken".to_string()),
        "RSS_DLX_HOT_VAULT_TOKEN" => Some("s.dlx-hot-testtoken".to_string()),
        "RSS_DLX_ARCHIVE_VAULT_TOKEN" => Some("s.dlx-archive-testtoken".to_string()),
        "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_string()),
        _ => None,
    })?;
    let deps = SharedRuntimeDeps {
        pg: pg.clone(),
        redis,
        s3,
        vault,
        settings_config_value_key_name: diport::KeyName::try_new("settings-config")?,
        domain_transport: noop_domain_transport(),
    };
    let demo_cfg = build_event_transport_config_from(|name| {
        (name == "RSS_TOPOLOGY").then(|| "demo".to_string())
    })?;
    let demo_module =
        wire_event_transport(&pg, wire_distributed(&deps)?, Vec::new(), demo_cfg).await?;
    assert!(demo_module.probes.is_empty());
    assert!(demo_module.resources.is_empty());
    assert!(demo_module.workers.is_empty());

    let distributed = wire_distributed(&deps)?;
    let event_module = wire_event_transport(&pg, distributed, subscribers, cfg).await?;
    let resource_names = event_module
        .resources
        .iter()
        .map(|resource| diport::ManagedResource::name(resource.as_ref()))
        .collect::<Vec<_>>();
    assert_eq!(
        resource_names,
        [
            "identity-pub",
            "identity-sub",
            "settings-pub",
            "settings-sub"
        ],
        "durable event infra must leave through DomainModuleResult::resources"
    );
    let generated_subscription_count = generated::event::EVENTS
        .iter()
        .map(|event| event.subscriptions().len())
        .sum::<usize>();
    let expected_worker_count = generated_subscription_count + 5;
    assert_eq!(
        event_module.workers.len(),
        expected_worker_count,
        "identity/settings relays + generated consumers + sampler + outbox sweeper + inbox sweeper"
    );
    let probe_names: Vec<&str> = event_module
        .probes
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        probe_names,
        [
            "outbox_relay_identity",
            "outbox_relay_settings",
            "outbox_sampler",
            "outbox_sweeper",
            "event_consumer:settings_config-version-changed__settings__settings_config-version-changed",
            "event_consumer:identity_session-created__audit__audit_session-created",
            "event_consumer:identity_role-assigned__audit__audit_role-assigned",
            "event_consumer:identity_role-revoked__audit__audit_role-revoked",
            "event_consumer:identity_policy-updated__audit__audit_policy-updated",
            "inbox_sweeper",
        ],
        "durable event probes must preserve generated topology order"
    );

    // ── 步骤 7：统一注册 ShutdownStack（resources 先注册，workers 后注册）────────

    let mut stack = bootstrap::shutdown::ShutdownStack::new(CancellationToken::new());
    for resource in event_module.resources {
        stack.register_detached(resource);
    }
    for worker in event_module.workers {
        stack.register_with_token(worker);
    }
    assert_eq!(
        stack.registered_names().collect::<Vec<_>>(),
        [
            "identity-pub",
            "identity-sub",
            "settings-pub",
            "settings-sub",
            "outbox-relay-identity",
            "outbox-relay-settings",
            "outbox-sampler",
            "outbox-sweeper",
            "event-consumer:settings:settings.config-version-changed",
            "event-consumer:audit:identity.session-created",
            "event-consumer:audit:identity.role-assigned",
            "event-consumer:audit:identity.role-revoked",
            "event-consumer:audit:identity.policy-updated",
            "inbox-sweeper",
        ],
        "resources must register before workers so LIFO drains workers first"
    );

    // ── 步骤 8a：settings active event 走生产 relay + AMQP consumer bridge ───────────────────

    wait_inbox_done(
        &assertion_pool,
        &initial_settings_event_id,
        &settings_consumer_group,
    )
    .await?;
    publisher_settings_service
        .publish_config(
            tenant,
            settings_actor,
            SettingsConfigPublishRequest {
                key: settings_key.to_string(),
                value: "enabled".to_string(),
            },
        )
        .await?;
    let settings_event_id =
        latest_outbox_event_id(&assertion_pool, "settings", settings_v1::TOPIC).await?;
    wait_inbox_done(
        &assertion_pool,
        &settings_event_id,
        &settings_consumer_group,
    )
    .await?;
    assert_eq!(
        subscriber_settings_service
            .config_query_service()
            .get_config(tenant, settings_key)
            .await?
            .as_ref()
            .map(|entry| entry.value()),
        Some("enabled"),
        "settings ConsumerTx must refresh the subscriber service cache from the old value"
    );

    // ── 步骤 8b：identity.policy-updated active event 走生产 relay + audit ConsumerTx ─────────────

    let policy_id = "policy-runtime-e2e";
    let policy_contract_id = "identity.policies-get";
    let policy_permission = "identity:policy:read";
    let policy = Policy::build(
        policy_id,
        tenant,
        PolicyRouteScope::parse(policy_contract_id, policy_permission)?,
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS),
        None,
        vec![PolicyRule::with_obligations(
            PolicyCondition::new(
                AttributeKey::parse(POLICY_ATTR_PRINCIPAL_KIND)?,
                Operator::Eq(AttributeValue::new("admin")),
            ),
            PolicyEffect::Allow,
            PolicyObligations::empty(),
        )],
    )?;
    let policy_event_id = "policy-runtime-e2e-created-v1";
    let (policy_entry, policy_envelope) = policy_updated_entry_and_envelope(
        tenant,
        policy_id,
        policy_contract_id,
        policy_permission,
        policy_event_id,
    )?;
    policy_lifecycle
        .create_and_emit(
            TenantRepoScope::for_test(tenant),
            policy,
            policy_entry,
            policy_envelope,
        )
        .await?;
    let policy_outbox_event_id =
        latest_outbox_event_id(&assertion_pool, "identity", policy_updated::TOPIC).await?;
    assert_eq!(
        policy_outbox_event_id, policy_event_id,
        "policy lifecycle must write the generated identity.policy-updated outbox event"
    );
    wait_inbox_done(
        &assertion_pool,
        &policy_outbox_event_id,
        &policy_consumer_group,
    )
    .await?;
    let policy_resource_id = format!(
        "tenant/{tenant}/policy/{policy_id}/contract/{policy_contract_id}/permission/{policy_permission}"
    );
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if audit_policy_count(&assertion_pool, tenant, &policy_resource_id)
                .await
                .is_ok_and(|count| count == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("timeout 20s 内 audit 未收到 policy-updated 事件（policy_id={policy_id}）")
    })?;

    // ── 步骤 8：生产侧登录（PgSessionLifecycle co-tx：session 行 + outbox(pending) 同事务落库）──

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

    // ── 步骤 9：测试专用 PostgreSQL 只读观察（不 claim，不干扰后台 relay）────────────────────

    // bounded 轮询（最多 50 次 × 100ms = 5s），以 tenant/domain/topic 限定后按
    // payload.sessionId 关联本轮 entry；published 行仍保留，因此无需抢在 relay 前读取。
    let (captured_event_id, captured_payload) = {
        let mut found = None;
        for _ in 0..50u8 {
            found = outbox_session_event(
                &assertion_pool,
                tenant,
                "identity",
                SESSION_CREATED_TOPIC,
                &session_id,
            )
            .await?;
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        found.ok_or_else(|| {
            anyhow::anyhow!("outbox 缺本轮 session-created entry（session_id={session_id}）")
        })?
    };

    // ── 步骤 10：断言 A（至少一次）────────────────────────────────────────────────────────────

    // relay（后台 OS 线程）会在下次 2s 轮询时拾起 pending entry → AMQP publish → consumer → PG inbox
    // Fresh → audit append。20s timeout 覆盖 2s relay 间隔 + AMQP 投递 + consumer 处理延迟。
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if audit_login_count(&assertion_pool, tenant, &session_id)
                .await
                .is_ok_and(|count| count >= 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("timeout 20s 内 audit 未收到 session-created 事件（至少一次断言 A 失败）")
    })?;

    assert_eq!(
        audit_login_count(&assertion_pool, tenant, &session_id).await?,
        1,
        "断言 A：login → outbox → relay → AMQP → consumer → audit，仅 append 一次"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &captured_event_id, &consumer_group).await?,
        1,
        "断言 A：original event 必须在 PG inbox_receipts 标记 done"
    );

    // ── 步骤 11：断言 B（PG inbox 幂等去重）──────────────────────────────────────────────────

    // 仅「重投后 len 不增」是假阴性（重投未投递/未及处理也会通过）。改用 **tracer 正向见证**：先重投同一
    // event_id（duplicate，期望 PG inbox `try_claim` 返回 Duplicate、不 append），再投一条**新 event_id**
    // （tracer，同 payload → Fresh → append）。单 queue 单 consumer FIFO 顺序消费：tracer 被 audit（len 达 2）
    // 即证明其之前的 duplicate 已被 consumer 真实消费+settle（而非未投递）。去重生效 → 最终稳定 len==2
    // （original + tracer）；去重失效 → duplicate 也 append、升到 3，被下方 fail-fast 捕获。
    let redeliver_endpoint = amqp_endpoint(&vhost_url)?;
    let pubr =
        amqp::AmqpPublisher::connect(&redeliver_endpoint, "e2e-redeliver", TEST_PUBLISH_TIMEOUT)
            .await?;
    pubr.publish(
        PublishRequest::new(
            Topic::new(SESSION_CREATED_TOPIC),
            MessageId::new(&captured_event_id),
            captured_payload.clone(),
        )
        .with_metadata(signed_session_metadata(
            &redeliver_tenant_authority,
            &captured_event_id,
        )?),
    )
    .await?;
    let tracer_id = format!("{captured_event_id}-tracer");
    pubr.publish(
        PublishRequest::new(
            Topic::new(SESSION_CREATED_TOPIC),
            MessageId::new(&tracer_id),
            captured_payload,
        )
        .with_metadata(signed_session_metadata(
            &redeliver_tenant_authority,
            &tracer_id,
        )?),
    )
    .await?;

    // 正向见证：等 audit 至少再 append 一次（count>=2）——证明重投流被 consumer 真实消费（消除假阴性）。
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if audit_login_count(&assertion_pool, tenant, &session_id)
                .await
                .is_ok_and(|count| count >= 2)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("timeout 20s 内重投流（duplicate/tracer）未被消费——断言 B 无法正向见证")
    })?;

    // 去重生效 → 稳定 len==2；去重失效 → duplicate 也 append、升到 3。再观察 2s：升到 3 即 fail-fast。
    let leaked_dup = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if audit_login_count(&assertion_pool, tenant, &session_id)
                .await
                .is_ok_and(|count| count >= 3)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        leaked_dup.is_err(),
        "断言 B 失败：duplicate 被重复 append（audit len 升到 3），PG inbox 幂等去重未生效"
    );
    assert_eq!(
        audit_login_count(&assertion_pool, tenant, &session_id).await?,
        2,
        "断言 B：original + tracer 各 append 一次，duplicate 命中 PG inbox Duplicate 被去重（共 2）"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &captured_event_id, &consumer_group).await?,
        1,
        "断言 B：duplicate 不得新增 original 的 inbox_receipts done 行"
    );
    assert_eq!(
        inbox_done_count(&assertion_pool, &tracer_id, &consumer_group).await?,
        1,
        "断言 B：tracer 新 event 必须在 PG inbox_receipts 标记 done"
    );

    pubr.shutdown().await?;

    // ── 步骤 12：关停（LIFO：workers 先 drain，infra_guards 后断连）────────────────────────────

    let failures = stack.shutdown().await;
    assert!(failures.is_empty(), "shutdown 存在失败项: {failures:?}");

    // fixture guard drop：停两个容器（pg / rmq）。
    drop(id);
    drop(assertion_pool);
    drop(pg);
    drop(pgfix);
    drop(rmq);

    Ok(())
}
