//! postgres adapter 集成测试（crate-internal；需真实 postgres，`integration` feature 门控；#1116 review F2/F5/F6）。
//!
//! crate-internal（非 `tests/`）以行使 `pub(crate)` 的 [`crate::PgStore::run_global_transaction`]（裸事务非公开
//! API，review F2）。容器经 `testkit::env_or_postgres()` self-provision（testcontainers，#1137）——无需手工预置。
//! **外部 PG 路径（快速本地迭代）**：须设 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES`（显式 opt-in）+
//! 5 元组 `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER`/`PGPASSWORD`；`PGDATABASE` 须以 `_test` 结尾或 `== "test"`
//! （严格库名，单源校验在 testkit）。需 docker（容器路径）。跑 `cargo nextest run -p postgres --features integration`。
//!
//! **fail-closed（review F5/F6）**：连不上 → 测试**失败**（非静默跳过）；
//! 库名校验由 `testkit::env_or_postgres` 单源执行，此处无需重复。
//! 连接配置由 [`crate::test_pg::connect_pg`] 统一管理，不在各测试内分散。

use consistency::{
    CommandErrorSummary, CommandJournalOutcome, CommandJournalTerminalSummary,
    CommandResultSummary, ConsumerGroup, ConvergeAction, IdemKey, InboxBacklog, InboxBacklogScope,
    InboxReceiptContext, InboxStore, LeaseToken, OutboxPayload, Outcome, SeenState,
};
use diport::ManagedResource;
use eventexec::command::{
    CommandAliasKey, CommandIdempotencyKeyring, CommandJournalStore, CommandStoreError,
    JournaledCommandDispatcher, ReviewedCommandJournal,
};
use eventexec::{
    AttemptResult, AttemptTrigger, OperatorReconcileCapability, ReconcileOperatorStore,
    ReconcileQuarantineReason, ReconcileScheduleErrorKind, ReconcileScheduleStore,
    ReconcileTargetStatus, ReviewedCommand, ScheduleActionOutcome, ScheduleAttemptOutcome,
};
use futures::future::BoxFuture;

use crate::{
    PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgStore, ReconcileLeaseOutcome,
    ReconcileTargetKey,
};

// 统一 Send+Sync 错误（= testkit::FixtureError）：sqlx::Error / PgError / FixtureError 均 Send+Sync，
// 全 `?` 无跨界转换（避免 Box<dyn Error+Send+Sync> → Box<dyn Error> 的 ? 转换 papercut）。
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";

use crate::test_pg::{
    connect_pg, connect_pg_audit_admin_role, connect_pg_nobypass_role, connect_pg_rss_app_role,
};

#[allow(clippy::unwrap_used)]
fn test_tenant() -> vocab::TenantId {
    vocab::TenantId::parse(COTX_TENANT_A).unwrap()
}

#[allow(clippy::unwrap_used)]
fn test_inbox_ctx(group: &str) -> InboxReceiptContext {
    InboxReceiptContext::new(
        test_tenant(),
        ConsumerGroup::parse(group).unwrap(),
        "identity",
        "identity.session-created",
        "identity.session-created",
        "v1",
        TEST_SCHEMA_HASH,
        None,
        None,
    )
    .unwrap()
}

#[allow(clippy::unwrap_used)]
fn test_inbox_scope(group: &str) -> InboxBacklogScope {
    InboxBacklogScope::new(test_tenant(), ConsumerGroup::parse(group).unwrap())
}

#[allow(clippy::unwrap_used)]
fn reviewed_payload(bytes: &[u8]) -> OutboxPayload {
    OutboxPayload::from_reviewed_event_bytes(bytes.to_vec())
}

#[allow(clippy::unwrap_used)]
fn subject_id(raw: &str) -> diport::EnvelopeSubjectId {
    diport::EnvelopeSubjectId::from_opaque(raw).unwrap()
}

#[allow(clippy::unwrap_used)]
fn actor_for(tenant: vocab::TenantId) -> diport::OutboxActor {
    diport::OutboxActor::scoped(
        vocab::PrincipalKind::Admin,
        diport::OpaqueActorId::from_opaque("pg-integration-actor").unwrap(),
        tenant,
        vocab::ScopedTenant::Tenant,
    )
}

fn identity_scope(tenant: vocab::TenantId) -> identity::ports::TenantRepoScope {
    identity::ports::TenantRepoScope::for_test(tenant)
}

fn settings_scope(tenant: vocab::TenantId) -> settings::ports::TenantRepoScope {
    settings::ports::TenantRepoScope::for_test(tenant)
}

fn audit_scope(tenant: vocab::TenantId) -> audit::ports::TenantRepoScope {
    audit::ports::TenantRepoScope::for_test(tenant)
}

/// 测试用固定事件发生时刻（unix 秒）——t10/t11 断言 envelope `occurred_at`（#1129）。
const TEST_OCCURRED_SECS: u64 = 1_700_000_000;
const TEST_SCHEMA_HASH: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EMPTY_PROJECTION_INPUT_GENERATION: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const TEST_PROJECTION_INPUT_GENERATION: &str =
    "sha256:d2f216c0cc464fc7dfb74706795762c31ef39443528ceb2f988b33beb70c5175";
static TEST_PROJECTION_INPUTS: &[vocab::ProjectionInputBinding] =
    &[vocab::ProjectionInputBinding::from_static(
        "test-projection",
        "test",
        "projection.bound",
        "v1",
        TEST_SCHEMA_HASH,
        "test.event",
    )];

fn test_contract() -> vocab::ContractBinding {
    vocab::ContractBinding::from_static("test", "test.contract", "v1", TEST_SCHEMA_HASH)
}

fn reviewed_reconcile_command(
    tenant: vocab::TenantId,
    idempotency_key: &str,
    subject: &str,
    target_id: impl Into<String>,
    amount: i64,
) -> Result<ReviewedCommand, eventexec::command::CommandEmitError> {
    ReviewedCommand::from_spec(
        generated::command::_seed_v1::reconcile_command(
            generated::command::_seed_v1::SeedDoThingRequest {
                amount,
                target_id: target_id.into(),
            },
            tenant,
            subject_id(subject),
            actor_for(tenant),
            idempotency_key.to_string(),
        ),
        command_keyring().as_ref(),
    )
}

#[allow(clippy::unwrap_used)]
fn command_keyring() -> std::sync::Arc<CommandIdempotencyKeyring> {
    std::sync::Arc::new(
        CommandIdempotencyKeyring::new(
            CommandAliasKey::new("k2", vec![0x42; 32]).unwrap(),
            vec![CommandAliasKey::new("k1", vec![0x24; 32]).unwrap()],
        )
        .unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
fn command_keyring_k1_only() -> std::sync::Arc<CommandIdempotencyKeyring> {
    std::sync::Arc::new(
        CommandIdempotencyKeyring::new(CommandAliasKey::new("k1", vec![0x24; 32]).unwrap(), vec![])
            .unwrap(),
    )
}

fn session_contract() -> vocab::ContractBinding {
    vocab::ContractBinding::from_static("identity", SESSION_CREATED_TOPIC, "v1", TEST_SCHEMA_HASH)
}

fn config_contract() -> vocab::ContractBinding {
    vocab::ContractBinding::from_static(
        "settings",
        CONFIG_VERSION_CHANGED_TOPIC,
        "v1",
        TEST_SCHEMA_HASH,
    )
}

#[allow(clippy::unwrap_used)]
fn projection_control_selector(
    raw_projection: &str,
    version: &str,
) -> eventexec::ProjectionSelector {
    eventexec::ProjectionSelector::new(
        test_tenant(),
        eventexec::ProjectionId::parse(raw_projection).unwrap(),
        eventexec::ProjectionVersion::parse(version).unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
fn projection_maintenance_receipt(
    action: authn::ProjectionMaintenanceAction,
    tenant: vocab::TenantId,
    projection: &str,
) -> authn::ProjectionMaintenanceReceipt {
    let principal =
        authn::test_support::principal(vocab::PrincipalKind::Service, "test-operator", None);
    let grants = authn::ProjectionMaintenanceGrantSet::new(vec![
        authn::ProjectionMaintenanceGrant::new("test-operator", action, tenant, projection)
            .unwrap(),
    ])
    .unwrap();
    grants
        .authorize(&principal, action, tenant, projection)
        .unwrap()
}

async fn insert_projection_shadow_checkpoint(
    store: &PgStore,
    selector: &eventexec::ProjectionSelector,
    offset: u64,
) -> TestResult {
    sqlx::query(
        r#"
        INSERT INTO checkpoint (owner, checkpoint_id, offset_lsn, version)
        VALUES ($1, $2, $3, 1)
        ON CONFLICT (owner, checkpoint_id)
        DO UPDATE SET offset_lsn = EXCLUDED.offset_lsn, version = checkpoint.version + 1
        "#,
    )
    .bind(selector.shadow_checkpoint_owner().as_str())
    .bind(selector.shadow_checkpoint_id().as_str())
    .bind(i64::try_from(offset)?)
    .execute(&store.pool)
    .await?;
    Ok(())
}

/// 固定时钟时刻（`Duration::from_secs` 取 `u64`）。
fn fixed_clock_time() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(TEST_OCCURRED_SECS)
}

/// DB 中 `occurred_at` 的期望编码值——经与生产**同一** `crate::outbox::unix_secs` 编码路径求得（`i64`），
/// 避免断言端 `u64` 字面量与写入端 `i64` 在边界值上漂移（review F4）。
fn expected_occurred_at() -> i64 {
    crate::outbox::unix_secs(fixed_clock_time())
}

fn assert_metadata_text_has_standard_schema_header(metadata: &str, context: &str) {
    let compact = metadata.replace(' ', "");
    assert!(
        compact.contains(r#""schemaVersion":"v1""#),
        "{context} metadata 应含 schemaVersion: {metadata}"
    );
    assert!(
        compact.contains(&format!(r#""schemaHash":"{TEST_SCHEMA_HASH}""#)),
        "{context} metadata 应含 schemaHash: {metadata}"
    );
}

/// 集成测试固定时钟（impl [`diport::Clock`]）：确定性 `occurred_at`，不取系统时钟（#1129）。
/// 本地定义——**不**引 `memory` adapter 作 dev-dep（避免 adapter→adapter 依赖），同 oidc/relay 各自定义替身范式。
struct FixedClock(std::time::SystemTime);
impl diport::Clock for FixedClock {
    fn now(&self) -> std::time::SystemTime {
        self.0
    }
}

/// 构造注入用 clock（`Box<dyn Clock>`，emitter / session lifecycle 注入约定，固定 [`fixed_clock_time`]）。
fn fixed_clock() -> Box<dyn diport::Clock> {
    Box::new(FixedClock(fixed_clock_time()))
}

/// 构造注入用 clock（`Arc<dyn Clock>`，`PgConfigRepo` 共享扇出约定，固定 [`fixed_clock_time`]，#1424）。
fn fixed_clock_arc() -> std::sync::Arc<dyn diport::Clock> {
    std::sync::Arc::new(FixedClock(fixed_clock_time()))
}

fn runtime_pg_config(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(std::time::Duration::from_secs(5))
}

async fn provision_runtime_rss_app_login(p: &testkit::PgConnParams) -> TestResult {
    let options = sqlx::postgres::PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(sqlx::postgres::PgSslMode::Prefer);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?;
    sqlx::query(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app LOGIN PASSWORD 'rss_app_test_pw' NOBYPASSRLS;
            ELSE
                ALTER ROLE rss_app LOGIN PASSWORD 'rss_app_test_pw' NOBYPASSRLS;
            END IF;
        END
        $$;
        "#,
    )
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}

async fn setup_runtime_deps_with_projection_inputs(
    projection_input_generation: &'static str,
    projection_inputs: &'static [vocab::ProjectionInputBinding],
) -> Result<(testkit::PgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    provision_runtime_rss_app_login(p).await?;
    let owner_config = runtime_pg_config(p, &p.username, &p.password);
    let deps = PgRuntimeDeps::setup(
        &owner_config,
        &runtime_pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
        projection_input_generation,
        projection_inputs,
    )
    .await?;
    Ok((fixture, deps))
}

async fn runtime_assertion_pool(
    p: &testkit::PgConnParams,
) -> Result<sqlx::PgPool, Box<dyn std::error::Error + Send + Sync>> {
    let options = sqlx::postgres::PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(sqlx::postgres::PgSslMode::Prefer);
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_connects_and_shuts_down() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    assert_eq!(store.name(), "postgres");
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migrator_applies_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?; // 应用 0001 占位
    store.run_migrations().await?; // 再跑：checksum 命中 → 幂等 no-op
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_config_plaintext_policy_rejects_existing_scheme_zero_rows() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("DELETE FROM config_entries")
        .execute(&store.pool)
        .await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(COTX_TENANT_A)
    .bind("legacy.startup.block")
    .bind("plain")
    .execute(&store.pool)
    .await?;

    let verdict = store
        .verify_config_legacy_plaintext_policy(crate::LegacyConfigPlaintextPolicy::Deny)
        .await;
    assert!(
        matches!(
            verdict,
            Err(crate::PgError::LegacyConfigPlaintextPresent { count: 1 })
        ),
        "scheme=0 row must block default startup policy, got: {verdict:?}"
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0028_rejects_non_empty_dead_letter() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::query(
        r#"
        CREATE TABLE dead_letter (
            tenant_id uuid NOT NULL,
            message_id text NOT NULL,
            original_entry jsonb NOT NULL
        )
        "#,
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO dead_letter (tenant_id, message_id, original_entry)
        VALUES ($1::uuid, 'legacy-dlx-row', '{"bytes":[1,2,3]}'::jsonb)
        "#,
    )
    .bind(COTX_TENANT_A)
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../migrations/0028_encrypt_dead_letter_original_entry.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err(std::io::Error::other("0028 must reject non-empty dead_letter").into());
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("dead_letter must be empty before enabling encrypted original_entry"),
        "unexpected migration error: {rendered}"
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_config_plaintext_policy_allows_temporary_override() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("DELETE FROM config_entries")
        .execute(&store.pool)
        .await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(COTX_TENANT_A)
    .bind("legacy.startup.allow")
    .bind("plain")
    .execute(&store.pool)
    .await?;

    store
        .verify_config_legacy_plaintext_policy(crate::LegacyConfigPlaintextPolicy::AllowTemporary)
        .await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例：superuser/owner 连接不能作为 durable serving pool。该路径同时不是固定 `rss_app`
/// serving role 且会绕过 RLS，能力门须 fail-fast；当前以 role mismatch 先命中。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_owner_serving_role() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let verdict = store.verify_rls_capability().await; // owner/superuser 不能作为 serving pool
    assert!(
        matches!(verdict, Err(crate::PgError::RlsUnexpectedServingRole)),
        "owner/superuser 连接应使 serving role gate fail-fast，实得: {verdict:?}"
    );
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例：即使某个测试角色是 NOBYPASSRLS，也不能替代生产固定 serving role `rss_app`。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_non_rss_app_nobypass_role() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_nobypass_role(&pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsUnexpectedServingRole)),
        "non-rss_app NOBYPASSRLS 角色不得作为 serving pool，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例：owner/superuser session 即使 `SET ROLE rss_app` 也不是长期 serving 直连。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_owner_session_set_role_rss_app() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let p = pg.params();
    let switched_config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_max_connections(1)
    .with_acquire_timeout(std::time::Duration::from_secs(5));
    let switched = PgStore::connect(&switched_config).await?;

    sqlx::query("SET ROLE rss_app")
        .execute(&switched.pool)
        .await?;
    let (session_user, current_user): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&switched.pool)
            .await?;
    assert_ne!(
        session_user, current_user,
        "test must prove SET ROLE made current_user differ from login session"
    );
    assert_eq!(current_user, "rss_app");

    let verdict = switched.verify_rls_capability().await;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsUnexpectedServingRole)),
        "SET ROLE rss_app must not satisfy direct serving login gate, got: {verdict:?}"
    );
    switched.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门正例：迁移后所有 tenant 表均 FORCE RLS + 规范 policy + GUC roundtrip，且以真实 `rss_app`
/// serving role 连接 → `verify_rls_capability` 放行。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_ok_after_migrations() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?; // 迁移经 owner/superuser
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let (session_user, current_user): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(session_user, "rss_app", "serving pool 必须直连 rss_app");
    assert_eq!(current_user, "rss_app", "serving pool 必须直连 rss_app");
    app.verify_rls_capability().await?; // rss_app + FORCE RLS + 规范 policy + GUC roundtrip 全通过
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn service_token_replay_guard_rejects_duplicate_nonce_after_migrations() -> TestResult {
    use diport::{ServiceTokenReplayError, ServiceTokenReplayGuard as _};
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let store = Arc::new(store);
    let guard = crate::PgServiceTokenReplayGuard::new(Arc::clone(&store));
    let nonce = format!("nonce-{}", uuid::Uuid::new_v4().simple());
    let now_epoch: i64 = sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
        .fetch_one(&store.pool)
        .await?;
    let expires_at = UNIX_EPOCH + Duration::from_secs(u64::try_from(now_epoch)?.saturating_add(60));

    guard.check_and_record(&nonce, expires_at)?;
    assert!(
        matches!(
            guard.check_and_record(&nonce, expires_at),
            Err(ServiceTokenReplayError::Replayed)
        ),
        "same service-token jti must be rejected across guard calls"
    );

    store.shutdown().await?;
    Ok(())
}

/// audit admin pool 角色必须是可直连 LOGIN role；部署只需注入密码，不应再把权限组 NOLOGIN 当连接身份。
#[tokio::test(flavor = "multi_thread")]
async fn audit_admin_role_is_login_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let (can_login, bypass_rls): (bool, bool) = sqlx::query_as(
        "SELECT rolcanlogin, rolbypassrls FROM pg_roles WHERE rolname = 'rss_audit_admin'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(can_login, "rss_audit_admin must be a LOGIN role");
    assert!(!bypass_rls, "rss_audit_admin must remain NOBYPASSRLS");
    store.shutdown().await?;
    Ok(())
}

/// audit admin 正例：迁移后注入密码即可直连，并通过 exact read-only capability gate。
#[tokio::test(flavor = "multi_thread")]
async fn verify_audit_admin_capability_ok_after_migrations() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    audit_admin.verify_audit_admin_capability().await?;
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// audit admin 负例：除 `audit_entries:SELECT` 外，任一 public table privilege 都必须启动期 fail-fast。
#[tokio::test(flavor = "multi_thread")]
async fn verify_audit_admin_capability_rejects_extra_table_privilege() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS _audit_admin_extra_privilege (id int)")
        .execute(&store.pool)
        .await?;
    sqlx::query("GRANT SELECT ON _audit_admin_extra_privilege TO rss_audit_admin")
        .execute(&store.pool)
        .await?;
    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;

    let verdict = audit_admin.verify_audit_admin_capability().await;

    sqlx::query("DROP TABLE IF EXISTS _audit_admin_extra_privilege")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::AuditAdminPrivileges)),
        "rss_audit_admin extra table privilege must fail startup gate, got: {verdict:?}"
    );
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// 真实 serving pool 覆盖：不用 `SET LOCAL ROLE` 模拟，直接以 `rss_app` 登录连接验证 tenant A/B 隔离。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid v4 与固定 SQL happy-path；集成测试构造值均合法。
async fn rss_app_serving_pool_enforces_tenant_ab_isolation() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;

    let (session_user, current_user): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(session_user, "rss_app", "serving pool 必须直连 rss_app");
    assert_eq!(current_user, "rss_app", "serving pool 必须直连 rss_app");

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let session_a = uuid::Uuid::new_v4().to_string();

    {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at) \
             VALUES ($1, $2, $3::uuid, now() + interval '1 hour', now())",
        )
        .bind(&session_a)
        .bind("rss-app-serving-test")
        .bind(&tenant_a)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(cnt.0, 1, "tenant A scope 应能看到 tenant A session");
        tx.rollback().await?;
    }

    {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(cnt.0, 0, "tenant B scope 不得看到 tenant A session");
        tx.rollback().await?;
    }

    {
        let mut tx = app.pool.begin().await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(cnt.0, 0, "未设 rss.tenant_id 时必须 fail-closed");
        tx.rollback().await?;
    }

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例（fail-closed）：存在含 `tenant_id` 列却**无** RLS 的表 → `Err(RlsNotEnforced)`。
/// throwaway 表经 owner 建，能力门经**非绕过角色**判定（pg_catalog 不受权限过滤、仍可见该表）；DROP 还原。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_tenant_table_without_rls() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS _rls_probe_bad (tenant_id uuid NOT NULL, x int)")
        .execute(&store.pool)
        .await?;
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_bad")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced)),
        "含 tenant_id 列却无 FORCE RLS 的表应使能力门 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例（policy 内容校验 + OR-widening）：tenant 表有 canonical policy，但第二条 permissive
/// policy 为 `USING/WITH CHECK (true)` → 仍 `Err(RlsNotEnforced)`。守「至少一条正确但另一条放宽」
/// 的运行时隔离静默失效路径（能力门校验 policy 内容、非仅存在性；与 xtask schema-rls 静态扫描互补）。
/// 经**非绕过角色**判定；throwaway 表隔离 + DROP 还原。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_permissive_policy() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_permissive (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_permissive ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE _rls_probe_permissive FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON _rls_probe_permissive USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
        "CREATE POLICY allow_all ON _rls_probe_permissive USING (true) WITH CHECK (true)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_permissive")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced)),
        "canonical policy 加第二条 allow-all permissive policy 应 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// 写侧缺 WITH CHECK 必须被运行时 capability gate 拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_missing_with_check() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_missing_check (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_missing_check ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE _rls_probe_missing_check FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON _rls_probe_missing_check USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_missing_check")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced)),
        "缺 WITH CHECK 应 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// 仅含 tenant/GUC token、但没有等值绑定的 policy 必须被 runtime gate 拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_token_stuffing_without_tenant_equality() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_token_stuffing (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_token_stuffing ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE _rls_probe_token_stuffing FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON _rls_probe_token_stuffing USING (tenant_id IS NOT NULL AND current_setting('rss.tenant_id', true) IS NOT NULL) WITH CHECK (tenant_id IS NOT NULL AND current_setting('rss.tenant_id', true) IS NOT NULL)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_token_stuffing")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced)),
        "token stuffing without tenant equality must fail closed, got: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_commit_persists_and_rollback_discards() -> TestResult {
    let (_pg, store) = connect_pg().await?;

    // setup：干净表 + 1 行，commit（committed 数据对所有池连接可见）。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("DROP TABLE IF EXISTS rss_tx_probe")
                    .execute(cap.conn())
                    .await?;
                sqlx::query("CREATE TABLE rss_tx_probe (id int)")
                    .execute(cap.conn())
                    .await?;
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (1)")
                    .execute(cap.conn())
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 1);

    // rollback 路径：插入后强制 Err → run_global_transaction 回滚。
    let rolled_back = store
        .run_global_transaction::<_, (), sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (2)")
                    .execute(cap.conn())
                    .await?;
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(rolled_back.is_err());
    assert_eq!(probe_count(&store).await?, 1); // 回滚 → 行数不变

    // commit 路径：插入后 Ok → 持久化。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (3)")
                    .execute(cap.conn())
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 2);

    // cleanup
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("DROP TABLE rss_tx_probe")
                    .execute(cap.conn())
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    store.shutdown().await?;
    Ok(())
}

/// inbox_receipts claim-or-skip + 多组/租户隔离集成验证（#1118/#1650）。
///
/// 唯一 event_id 法——每次运行生成新 UUID key，跨轮次无需清理旧数据，且可重复安全运行。
/// 验证三个语义断言：
/// 1. 同组同 key 首见 → Fresh；
/// 2. 同组同 key 再见 → Duplicate（幂等短路）；
/// 3. 不同组同 key → Fresh（去重按组隔离，两组独立 PK）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path —— uuid v4 生成不失败、测试专用固定组名非空、IdemKey 非空 parse 不失败；
// 函数级 item-level carve-out（error-handling.md §Carve-out）。
async fn inbox_receipts_claims_then_duplicates_and_scopes_by_group() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 唯一 event_id：每次生成新 UUID，跨轮次不冲突，无需 DELETE 清理。
    let evt = format!("test-evt-{}", uuid::Uuid::new_v4());

    let inbox = store.inbox();
    let ctx_a = test_inbox_ctx("test-grp-a");
    let ctx_b = test_inbox_ctx("test-grp-b");
    let key = IdemKey::parse(&evt).unwrap();

    // 断言 1：同组同 key 首见 → Fresh。
    let lease_a = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx_a, &key, &lease_a).await?,
        SeenState::Fresh,
        "首次 claim 应返回 Fresh"
    );

    // 断言 2：同组同 key 再见 → Duplicate（claimed_at 仍在 TTL 内，DO UPDATE WHERE false）。
    let lease_a2 = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx_a, &key, &lease_a2).await?,
        SeenState::Duplicate,
        "同 key 再见应返回 Duplicate"
    );

    // 断言 3：不同消费者组同 key → Fresh（PK = (event_id, consumer_group)，组间去重独立）。
    let lease_b = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx_b, &key, &lease_b).await?,
        SeenState::Fresh,
        "不同组同 key 应返回 Fresh（group drift 隔离）"
    );

    store.shutdown().await?;
    Ok(())
}

/// inbox_receipts target schema catalog lock (#1626).
///
/// The tenant-scoped mutable receipt table must exist with its target columns,
/// tenant-first primary key, indexes, and DB-level CHECK constraints.
#[tokio::test(flavor = "multi_thread")]
async fn inbox_receipts_schema_catalog_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name, data_type, is_nullable \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'inbox_receipts' \
         ORDER BY ordinal_position",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        columns,
        vec![
            (
                "tenant_id".to_string(),
                "uuid".to_string(),
                "NO".to_string()
            ),
            ("event_id".to_string(), "text".to_string(), "NO".to_string()),
            (
                "consumer_group".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("domain".to_string(), "text".to_string(), "NO".to_string()),
            ("topic".to_string(), "text".to_string(), "NO".to_string()),
            (
                "contract_id".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "contract_version".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "schema_hash".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("trace".to_string(), "text".to_string(), "YES".to_string()),
            (
                "correlation_id".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            ("status".to_string(), "text".to_string(), "NO".to_string()),
            (
                "lease_token".to_string(),
                "uuid".to_string(),
                "NO".to_string()
            ),
            (
                "receive_count".to_string(),
                "integer".to_string(),
                "NO".to_string()
            ),
            (
                "claimed_at".to_string(),
                "timestamp with time zone".to_string(),
                "NO".to_string()
            ),
            (
                "committed_at".to_string(),
                "timestamp with time zone".to_string(),
                "YES".to_string()
            ),
            (
                "updated_at".to_string(),
                "timestamp with time zone".to_string(),
                "NO".to_string()
            ),
        ],
        "inbox_receipts columns must match the target runtime replacement shape"
    );

    let pk_columns: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'inbox_receipts'::regclass AND c.contype = 'p'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        pk_columns.0, "tenant_id,event_id,consumer_group",
        "inbox_receipts primary key must be tenant-first"
    );

    let indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT indexname, lower(indexdef) \
         FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'inbox_receipts' \
         ORDER BY indexname",
    )
    .fetch_all(&store.pool)
    .await?;
    let index_text = indexes
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "idx_inbox_receipts_stale_claims",
        "tenant_id, consumer_group, claimed_at",
        "where (status = 'claimed'::text)",
        "idx_inbox_receipts_done_retention",
        "status, committed_at",
        "where (status = 'done'::text)",
        "idx_inbox_receipts_contract_schema",
        "tenant_id, domain, contract_id, contract_version, schema_hash",
    ] {
        assert!(
            index_text.contains(needle),
            "missing inbox_receipts index shape `{needle}` in:\n{index_text}"
        );
    }

    let constraints: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid = 'inbox_receipts'::regclass \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraints
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "inbox_receipts_contract_version_valid",
        "inbox_receipts_schema_hash_valid",
        "inbox_receipts_status_valid",
        "inbox_receipts_trace_valid",
        "inbox_receipts_correlation_id_valid",
        "inbox_receipts_receive_count_positive",
        "inbox_receipts_commit_timestamp_matches_status",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing inbox_receipts constraint `{name}` in:\n{constraint_text}"
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// inbox_receipts RLS/grant lock (#1626).
///
/// The table is mutable claim state, so rss_app needs DML privileges, but every
/// row must still be scoped by FORCE RLS and the standard tenant isolation policy.
#[tokio::test(flavor = "multi_thread")]
async fn inbox_receipts_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'inbox_receipts', 'SELECT'), \
                has_table_privilege('rss_app', 'inbox_receipts', 'INSERT'), \
                has_table_privilege('rss_app', 'inbox_receipts', 'UPDATE'), \
                has_table_privilege('rss_app', 'inbox_receipts', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'inbox_receipts'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "inbox_receipts must ENABLE RLS");
    assert!(rls_forced, "inbox_receipts must FORCE RLS");
    assert!(can_select, "rss_app must SELECT inbox_receipts");
    assert!(can_insert, "rss_app must INSERT inbox_receipts");
    assert!(can_update, "rss_app must UPDATE inbox_receipts");
    assert!(
        can_delete,
        "rss_app must DELETE inbox_receipts for release/sweep mutable state paths"
    );

    let (qual, with_check): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename = 'inbox_receipts' \
           AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&store.pool)
    .await?;
    for body in [qual.as_deref(), with_check.as_deref()] {
        let body = body.ok_or_else(|| {
            std::io::Error::other("tenant_isolation policy must define both USING and WITH CHECK")
        })?;
        assert!(
            body.to_lowercase().contains("nullif(current_setting"),
            "tenant_isolation policy must use NULLIF(current_setting(...)): {body}"
        );
        assert!(
            body.contains("rss.tenant_id"),
            "tenant_isolation policy must reference rss.tenant_id: {body}"
        );
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let event_id = format!("receipt-{}", uuid::Uuid::new_v4());
    let group = format!("receipt-group-{}", uuid::Uuid::new_v4());

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO inbox_receipts \
             (tenant_id, event_id, consumer_group, domain, topic, contract_id, \
              contract_version, schema_hash, trace, correlation_id, status, lease_token, receive_count) \
             VALUES \
             ($1::uuid, $2, $3, 'identity', 'identity.session-created', \
              'identity.session-created', 'v1', $4, '00-00000000000000000000000000000000-0000000000000000-00', \
              'corr-receipt', 'claimed', gen_random_uuid(), 1)",
        )
        .bind(&tenant_a)
        .bind(&event_id)
        .bind(&group)
        .bind(TEST_SCHEMA_HASH)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2",
        )
        .bind(&event_id)
        .bind(&group)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 1, "tenant A scope must see tenant A receipt");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2",
        )
        .bind(&event_id)
        .bind(&group)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 0, "tenant B scope must not see tenant A receipt");

        let denied = sqlx::query(
            "INSERT INTO inbox_receipts \
             (tenant_id, event_id, consumer_group, domain, topic, contract_id, \
              contract_version, schema_hash, status, lease_token, receive_count) \
             VALUES \
             ($1::uuid, 'receipt-denied', 'receipt-denied-group', 'identity', \
              'identity.session-created', 'identity.session-created', 'v1', $2, \
              'claimed', gen_random_uuid(), 1)",
        )
        .bind(&tenant_a)
        .bind(TEST_SCHEMA_HASH)
        .execute(&mut *tx)
        .await;
        assert!(
            denied.is_err(),
            "tenant B scope must not insert a tenant A receipt"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2",
        )
        .bind(&event_id)
        .bind(&group)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must fail closed for inbox_receipts"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// ── command_journal foundation (#1441) ───────────────────────────────────────

fn command_journal_fingerprint(nibble: char) -> String {
    format!("sha256:{}", nibble.to_string().repeat(64))
}

fn command_journal_command_id(nibble: char) -> String {
    format!(
        "command:v2:{}-{}-4{}-8{}-{}",
        nibble.to_string().repeat(8),
        nibble.to_string().repeat(4),
        nibble.to_string().repeat(3),
        nibble.to_string().repeat(3),
        nibble.to_string().repeat(12),
    )
}

#[derive(Clone, Default)]
struct CaptureReviewedCommand {
    command: std::sync::Arc<std::sync::Mutex<Option<ReviewedCommandJournal>>>,
}

impl CommandJournalStore for CaptureReviewedCommand {
    async fn record_command(
        &self,
        command: ReviewedCommandJournal,
        _result_summary: CommandResultSummary,
    ) -> Result<CommandJournalOutcome, CommandStoreError> {
        *self
            .command
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(command);
        Ok(CommandJournalOutcome::Recorded)
    }
}

async fn command_journal_command(
    tenant: vocab::TenantId,
    key: &str,
    payload: &[u8],
) -> Result<ReviewedCommandJournal, TestError> {
    command_journal_command_with_keyring(tenant, key, payload, command_keyring()).await
}

async fn command_journal_command_with_keyring(
    tenant: vocab::TenantId,
    key: &str,
    payload: &[u8],
    keyring: std::sync::Arc<CommandIdempotencyKeyring>,
) -> Result<ReviewedCommandJournal, TestError> {
    let capture = CaptureReviewedCommand::default();
    let dispatcher = JournaledCommandDispatcher::new(capture.clone(), keyring);
    generated::command::_seed_v1::journal_async(
        &dispatcher,
        generated::command::_seed_v1::SeedDoThingRequest {
            amount: i64::try_from(payload.len()).unwrap_or(i64::MAX),
            target_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload),
        },
        tenant,
        subject_id("command-journal-subject"),
        actor_for(tenant),
        key.to_string(),
    )
    .await?;
    capture
        .command
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
        .ok_or_else(|| "generated journal dispatcher did not submit a reviewed command".into())
}

fn reviewed_command_fingerprint(command: &ReviewedCommandJournal) -> String {
    command.intent().request_fingerprint().as_str().to_owned()
}

async fn persisted_command_id(
    pool: &sqlx::PgPool,
    tenant: vocab::TenantId,
    fingerprint: &str,
) -> Result<String, TestError> {
    let (command_id,): (String,) = sqlx::query_as(
        "SELECT command_id FROM command_journal \
         WHERE tenant_id=$1::uuid AND request_fingerprint=$2",
    )
    .bind(tenant.to_string())
    .bind(fingerprint)
    .fetch_one(pool)
    .await?;
    Ok(command_id)
}

async fn prepare_command_journal_markers(store: &PgStore) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS command_journal_test_markers \
         (marker text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now())",
    )
    .execute(&store.pool)
    .await?;
    Ok(())
}

async fn command_journal_marker_count(store: &PgStore, marker: &str) -> Result<i64, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_journal_test_markers WHERE marker = $1")
            .bind(marker)
            .fetch_one(&store.pool)
            .await?;
    Ok(count.0)
}

async fn command_journal_outbox_count(
    store: &PgStore,
    command_id: &str,
) -> Result<i64, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(command_id)
        .fetch_one(&store.pool)
        .await?;
    Ok(count.0)
}

async fn command_journal_row_count(store: &PgStore, command_id: &str) -> Result<i64, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_journal WHERE command_id = $1")
            .bind(command_id)
            .fetch_one(&store.pool)
            .await?;
    Ok(count.0)
}

#[tokio::test(flavor = "multi_thread")]
async fn command_outbox_semantic_match_ignores_only_volatile_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let tenant = test_tenant();
    let event_id = unique_event_id("direct-command-stable-replay");
    let payload = br#"{"amount":7,"targetId":"target-1"}"#;
    let first = serde_json::json!({
        "tenantId": tenant.to_string(),
        "schemaVersion": generated::command::_seed_v1::CONTRACT.version(),
        "schemaHash": generated::command::_seed_v1::CONTRACT.schema_hash(),
        "subjectId": "command-subject",
        "actor": {
            "kind": "admin",
            "id": "command-actor",
            "tenantId": tenant.to_string(),
            "scope": "tenant"
        },
        "occurredAt": 1,
        "trace": "00-old",
        "correlation": "corr-old"
    });
    let mut retried = first.clone();
    retried["occurredAt"] = serde_json::json!(2);
    retried["trace"] = serde_json::json!("00-new");
    retried["correlation"] = serde_json::json!("corr-new");

    let fingerprint = |metadata: serde_json::Value| {
        let pool = store.pool.clone();
        let event_id = event_id.clone();
        async move {
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT rss_outbox_fact_fingerprint($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
            )
            .bind(event_id)
            .bind(tenant.to_string())
            .bind(generated::command::_seed_v1::CONTRACT.domain())
            .bind(generated::command::_seed_v1::TOPIC)
            .bind(generated::command::_seed_v1::CONTRACT_ID)
            .bind(generated::command::_seed_v1::CONTRACT.version())
            .bind(generated::command::_seed_v1::CONTRACT.schema_hash())
            .bind(payload.as_slice())
            .bind("partition-a")
            .bind("cause-a")
            .bind(metadata.to_string())
            .fetch_one(&pool)
            .await
        }
    };

    let first_fingerprint = fingerprint(first).await?;
    assert_eq!(first_fingerprint, fingerprint(retried.clone()).await?);
    retried["actor"]["id"] = serde_json::json!("different-actor");
    assert_ne!(first_fingerprint, fingerprint(retried).await?);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_schema_rls_grants_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'command_journal', 'SELECT'), \
                has_table_privilege('rss_app', 'command_journal', 'INSERT'), \
                has_table_privilege('rss_app', 'command_journal', 'UPDATE'), \
                has_table_privilege('rss_app', 'command_journal', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'command_journal'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "command_journal must ENABLE RLS");
    assert!(rls_forced, "command_journal must FORCE RLS");
    assert!(can_select, "rss_app must SELECT command_journal");
    assert!(can_insert, "rss_app must INSERT command_journal");
    assert!(can_update, "rss_app must UPDATE command_journal");
    assert!(!can_delete, "rss_app must not DELETE command_journal");

    let pk_columns: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'command_journal'::regclass AND c.contype = 'p'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        pk_columns.0, "tenant_id,command_id",
        "command_journal primary key must be tenant-first"
    );

    let constraint_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid = 'command_journal'::regclass \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraint_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "command_journal_command_id_valid",
        "command_journal_fingerprint_valid",
        "command_journal_outbox_event_id_valid",
        "command_journal_status_valid",
        "command_journal_attempt_positive",
        "command_journal_terminal_summary_matches_status",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing command_journal constraint `{name}` in:\n{constraint_text}"
        );
    }
    let legacy_key_column: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'command_journal' \
           AND column_name = 'idempotency_key'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        legacy_key_column.0, 0,
        "raw idempotency keys must not be persisted"
    );

    let alias_constraints: Vec<(String,)> = sqlx::query_as(
        "SELECT conname FROM pg_constraint \
         WHERE conrelid = 'command_idempotency_aliases'::regclass ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let alias_constraints = alias_constraints
        .into_iter()
        .map(|(name,)| name)
        .collect::<Vec<_>>();
    for name in [
        "command_idempotency_aliases_pkey",
        "command_alias_topic_nonempty",
        "command_alias_key_id_valid",
        "command_alias_digest_256bit",
        "command_alias_command_id_valid",
    ] {
        assert!(
            alias_constraints.iter().any(|actual| actual == name),
            "missing command alias constraint `{name}` in {alias_constraints:?}"
        );
    }
    let alias_pk: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'command_idempotency_aliases'::regclass AND c.contype = 'p'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(alias_pk.0, "tenant_id,topic,key_id,alias_digest");

    let (qual, with_check): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename = 'command_journal' \
           AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&store.pool)
    .await?;
    for body in [qual.as_deref(), with_check.as_deref()] {
        let body = body.ok_or_else(|| {
            std::io::Error::other("command_journal tenant policy missing USING/WITH CHECK")
        })?;
        assert!(
            body.to_lowercase().contains("nullif(current_setting"),
            "command_journal policy must use NULLIF(current_setting(...)): {body}"
        );
        assert!(
            body.contains("rss.tenant_id"),
            "command_journal policy must reference rss.tenant_id: {body}"
        );
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;
    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let command_id = command_journal_command_id('a');
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO command_journal \
             (tenant_id, command_id, topic, contract_id, contract_version, \
              schema_hash, request_fingerprint, outbox_event_id) \
             VALUES ($1::uuid, $2, $3, 'test.contract', 'v1', $4, $5, $2)",
        )
        .bind(&tenant_a)
        .bind(&command_id)
        .bind(generated::command::_seed_v1::TOPIC)
        .bind(TEST_SCHEMA_HASH)
        .bind(command_journal_fingerprint('1'))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    for (tenant, expected, label) in [(&tenant_a, 1_i64, "tenant A"), (&tenant_b, 0, "tenant B")] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM command_journal WHERE command_id = $1")
                .bind(&command_id)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, expected,
            "{label} command_journal visibility mismatch"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let denied = sqlx::query(
            "INSERT INTO command_journal \
             (tenant_id, command_id, topic, contract_id, contract_version, \
              schema_hash, request_fingerprint, outbox_event_id) \
             VALUES ($1::uuid, $2, $3, 'test.contract', 'v1', $4, $5, $2)",
        )
        .bind(&tenant_a)
        .bind(command_journal_command_id('c'))
        .bind(generated::command::_seed_v1::TOPIC)
        .bind(TEST_SCHEMA_HASH)
        .bind(command_journal_fingerprint('3'))
        .execute(&mut *tx)
        .await;
        assert!(
            denied.is_err(),
            "tenant B scope must not insert tenant A command_journal rows"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_records_business_marker_and_outbox_atomically() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let command = command_journal_command(
        tenant,
        &unique_event_id("command-journal-key"),
        br#"{"op":"recorded"}"#,
    )
    .await?;
    let fingerprint = reviewed_command_fingerprint(&command);
    let marker = unique_event_id("command-journal-marker");
    let marker_for_write = marker.clone();

    let outcome = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(command, move |tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
                    .bind(marker_for_write)
                    .execute(tx.conn())
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(outcome, CommandJournalOutcome::Recorded);
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 1);
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);
    let row: (String, Option<String>, i32) = sqlx::query_as(
        "SELECT status, result_summary, attempt \
         FROM command_journal WHERE tenant_id = $1::uuid AND command_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        row,
        (
            "completed".to_string(),
            Some("command enqueued".to_string()),
            1
        )
    );
    let outbox_metadata: (serde_json::Value,) =
        sqlx::query_as("SELECT metadata FROM outbox WHERE event_id = $1")
            .bind(&command_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        outbox_metadata.0.get("occurredAt").and_then(|v| v.as_i64()),
        Some(expected_occurred_at()),
        "command journal outbox metadata must use the injected producer clock"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_runtime_deps_serving_role_records_and_replays() -> TestResult {
    let (pg, deps) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let owner_pool = runtime_assertion_pool(pg.params()).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-serving-key");
    let first = command_journal_command(tenant, &idempotency_key, br#"{"op":"serving"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let journal = deps.infra().command_journal(fixed_clock());

    assert_eq!(
        CommandJournalStore::record_command(&journal, first, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&owner_pool, tenant, &fingerprint).await?;

    let replay = command_journal_command(tenant, &idempotency_key, br#"{"op":"serving"}"#).await?;
    assert_eq!(
        CommandJournalStore::record_command(&journal, replay, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
    );

    let count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM command_journal WHERE tenant_id = $1::uuid AND command_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(count.0, 1, "serving role path must persist one journal row");
    owner_pool.close().await;
    deps.store_guard().shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_business_error_rolls_back_journal_marker_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let command = command_journal_command(
        tenant,
        &unique_event_id("command-journal-rollback-key"),
        br#"{"op":"rollback"}"#,
    )
    .await?;
    let fingerprint = reviewed_command_fingerprint(&command);
    let marker = unique_event_id("command-journal-rollback-marker");
    let marker_for_write = marker.clone();

    let result = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(command, move |tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
                    .bind(marker_for_write)
                    .execute(tx.conn())
                    .await
                    .map_err(CommandStoreError::internal)?;
                Err(CommandStoreError::internal(std::io::Error::other(
                    "forced command journal rollback",
                )))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await;

    assert!(result.is_err(), "business error must surface to caller");
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 0);
    let journal_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM command_journal \
         WHERE tenant_id=$1::uuid AND request_fingerprint=$2",
    )
    .bind(tenant.to_string())
    .bind(&fingerprint)
    .fetch_one(&store.pool)
    .await?;
    let alias_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_idempotency_aliases WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(journal_count.0, 0);
    assert_eq!(
        alias_count.0, 0,
        "alias claim must roll back with business failure"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_outbox_conflict_rolls_back_journal_and_marker() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let command = command_journal_command(
        tenant,
        &unique_event_id("command-journal-outbox-conflict-key"),
        br#"{"op":"outbox-conflict"}"#,
    )
    .await?;
    let command_id = format!("command:v2:{}", uuid::Uuid::new_v4());
    let current_alias = command
        .intent()
        .aliases()
        .current()
        .ok_or("journal command must carry current alias")?;
    sqlx::query(
        "INSERT INTO command_idempotency_aliases \
         (tenant_id,topic,key_id,alias_digest,command_id) VALUES ($1::uuid,$2,$3,$4,$5)",
    )
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(current_alias.key_id())
    .bind(current_alias.digest())
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    let marker = unique_event_id("command-journal-outbox-conflict-marker");
    let marker_for_write = marker.clone();

    sqlx::query(
        "INSERT INTO outbox (
             event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
             payload, metadata, status
         ) VALUES ($1, $2::uuid, 'test', $3, 'test.contract', 'v1', $4, $5, $6::jsonb, 'pending')",
    )
    .bind(&command_id)
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(TEST_SCHEMA_HASH)
    .bind(b"conflicting-payload".as_slice())
    .bind(serde_json::json!({ "tenantId": tenant.to_string() }).to_string())
    .execute(&store.pool)
    .await?;

    let result = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(command, move |tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
                    .bind(marker_for_write)
                    .execute(tx.conn())
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await;

    assert!(
        result.is_err(),
        "outbox event_id conflict with different row must fail the UoW"
    );
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 0);
    assert_eq!(command_journal_row_count(&store, &command_id).await?, 0);
    assert_eq!(
        command_journal_outbox_count(&store, &command_id).await?,
        1,
        "pre-existing conflicting outbox row remains, but journal/marker must roll back"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_duplicate_replays_completed_summary_without_business_write() -> TestResult
{
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-replay-key");
    let first = command_journal_command(tenant, &idempotency_key, br#"{"op":"replay"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let first_marker = unique_event_id("command-journal-replay-first");
    let first_marker_for_write = first_marker.clone();
    assert_eq!(
        store
            .command_journal(fixed_clock())
            .record_command_with_business_write(first, move |tx| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
                        .bind(first_marker_for_write)
                        .execute(tx.conn())
                        .await
                        .map_err(CommandStoreError::internal)?;
                    Ok(CommandJournalTerminalSummary::Completed(
                        CommandResultSummary::ENQUEUED,
                    ))
                })
                    as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
            },)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let second = command_journal_command(tenant, &idempotency_key, br#"{"op":"replay"}"#).await?;
    let second_marker = unique_event_id("command-journal-replay-second");
    let second_marker_for_write = second_marker.clone();
    let replay = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(second, move |tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
                    .bind(second_marker_for_write)
                    .execute(tx.conn())
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(
        replay,
        CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
    );
    assert_eq!(
        command_journal_marker_count(&store, &first_marker).await?,
        1
    );
    assert_eq!(
        command_journal_marker_count(&store, &second_marker).await?,
        0,
        "duplicate must not re-run business write"
    );
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_key_rotation_backfills_current_alias_without_changing_command_id()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let raw_key = unique_event_id("command-journal-rotation-key");
    let payload = br#"{"op":"rotate"}"#;
    let first =
        command_journal_command_with_keyring(tenant, &raw_key, payload, command_keyring_k1_only())
            .await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let journal = store.command_journal(fixed_clock());
    assert_eq!(
        CommandJournalStore::record_command(&journal, first, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let rotated =
        command_journal_command_with_keyring(tenant, &raw_key, payload, command_keyring()).await?;
    assert_eq!(
        CommandJournalStore::record_command(&journal, rotated, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
    );
    let aliases: Vec<(String, String)> = sqlx::query_as(
        "SELECT key_id, command_id FROM command_idempotency_aliases \
         WHERE tenant_id = $1::uuid ORDER BY key_id",
    )
    .bind(tenant.to_string())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        aliases,
        vec![
            ("k1".to_string(), command_id.clone()),
            ("k2".to_string(), command_id.clone()),
        ],
        "the rotation window must converge both aliases on the original random canonical id"
    );
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_concurrent_same_request_writes_once() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let raw_key = unique_event_id("command-journal-concurrent-key");
    let payload = br#"{"op":"concurrent"}"#;
    let first = command_journal_command(tenant, &raw_key, payload).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let second = command_journal_command(tenant, &raw_key, payload).await?;
    let journal_a = store.command_journal(fixed_clock());
    let journal_b = store.command_journal(fixed_clock());
    let (outcome_a, outcome_b) = tokio::join!(
        CommandJournalStore::record_command(&journal_a, first, CommandResultSummary::ENQUEUED,),
        CommandJournalStore::record_command(&journal_b, second, CommandResultSummary::ENQUEUED,),
    );
    let outcomes = [outcome_a?, outcome_b?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, CommandJournalOutcome::Recorded))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
            ))
            .count(),
        1
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;
    assert_eq!(command_journal_row_count(&store, &command_id).await?, 1);
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_duplicate_replays_failed_summary_without_business_write() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-failed-replay-key");
    let first =
        command_journal_command(tenant, &idempotency_key, br#"{"op":"failed-replay"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    assert_eq!(
        store
            .command_journal(fixed_clock())
            .record_command_with_business_write(first, |_tx| {
                Box::pin(async move {
                    Ok(CommandJournalTerminalSummary::Failed(
                        CommandErrorSummary::FAILED,
                    ))
                })
                    as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
            },)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let row: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, result_summary, error_summary \
         FROM command_journal WHERE tenant_id = $1::uuid AND command_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        row,
        (
            "failed".to_string(),
            None,
            Some("command failed".to_string())
        )
    );
    assert_eq!(
        command_journal_outbox_count(&store, &command_id).await?,
        0,
        "failed terminal command must not enqueue outbox"
    );

    let second =
        command_journal_command(tenant, &idempotency_key, br#"{"op":"failed-replay"}"#).await?;
    let marker = unique_event_id("command-journal-failed-replay-marker");
    let marker_for_write = marker.clone();
    let replay = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(second, move |tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
                    .bind(marker_for_write)
                    .execute(tx.conn())
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(
        replay,
        CommandJournalOutcome::AlreadyFailed(CommandErrorSummary::FAILED)
    );
    assert_eq!(
        command_journal_marker_count(&store, &marker).await?,
        0,
        "failed duplicate must not re-run business write"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_same_key_different_fingerprint_conflicts() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-conflict-key");
    let first = command_journal_command(tenant, &idempotency_key, br#"{"op":"a"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    assert_eq!(
        CommandJournalStore::record_command(
            &store.command_journal(fixed_clock()),
            first,
            CommandResultSummary::ENQUEUED,
        )
        .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let conflicting = command_journal_command(tenant, &idempotency_key, br#"{"op":"b"}"#).await?;
    let marker = unique_event_id("command-journal-conflict-marker");
    let marker_for_write = marker.clone();
    let outcome = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(conflicting, move |tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO command_journal_test_markers (marker) VALUES ($1)")
                    .bind(marker_for_write)
                    .execute(tx.conn())
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(outcome, CommandJournalOutcome::Conflict);
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 0);
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_same_key_isolated_by_tenant() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let idempotency_key = unique_event_id("command-journal-cross-tenant-key");

    let first =
        command_journal_command(tenant_a, &idempotency_key, br#"{"op":"tenant-a"}"#).await?;
    let first_fingerprint = reviewed_command_fingerprint(&first);
    let second =
        command_journal_command(tenant_b, &idempotency_key, br#"{"op":"tenant-b"}"#).await?;
    let second_fingerprint = reviewed_command_fingerprint(&second);
    assert_eq!(
        CommandJournalStore::record_command(
            &store.command_journal(fixed_clock()),
            first,
            CommandResultSummary::ENQUEUED,
        )
        .await?,
        CommandJournalOutcome::Recorded
    );
    let first_id = persisted_command_id(&store.pool, tenant_a, &first_fingerprint).await?;
    assert_eq!(
        CommandJournalStore::record_command(
            &store.command_journal(fixed_clock()),
            second,
            CommandResultSummary::ENQUEUED,
        )
        .await?,
        CommandJournalOutcome::Recorded
    );
    let second_id = persisted_command_id(&store.pool, tenant_b, &second_fingerprint).await?;
    assert_ne!(
        first_id, second_id,
        "canonical command ids must be random per tenant"
    );
    assert_eq!(command_journal_outbox_count(&store, &first_id).await?, 1);
    assert_eq!(command_journal_outbox_count(&store, &second_id).await?, 1);

    let command_ids = vec![first_id.clone(), second_id.clone()];
    let row_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_journal WHERE command_id = ANY($1::text[])")
            .bind(command_ids.as_slice())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row_count.0, 2, "same raw key must be tenant-scoped");

    store.shutdown().await?;
    Ok(())
}

// ── outbox_log CDC schema (#1630) ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn outbox_log_schema_catalog_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name, data_type, is_nullable \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'outbox_log' \
         ORDER BY ordinal_position",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        columns,
        vec![
            ("event_id".to_string(), "text".to_string(), "NO".to_string()),
            (
                "tenant_id".to_string(),
                "uuid".to_string(),
                "NO".to_string()
            ),
            (
                "aggregate_type".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "aggregate_id".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("topic".to_string(), "text".to_string(), "NO".to_string()),
            (
                "contract_id".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "contract_version".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "schema_hash".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("payload".to_string(), "bytea".to_string(), "NO".to_string()),
            (
                "metadata".to_string(),
                "jsonb".to_string(),
                "NO".to_string()
            ),
            (
                "causation_id".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            (
                "created_at".to_string(),
                "timestamp with time zone".to_string(),
                "NO".to_string()
            ),
            (
                "occurred_at".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            ("trace".to_string(), "text".to_string(), "YES".to_string()),
            (
                "correlation_id".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            (
                "partition_key".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            (
                "fact_fingerprint".to_string(),
                "bytea".to_string(),
                "NO".to_string()
            ),
        ],
        "outbox_log columns must match the CDC append-only contract"
    );

    let generated_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT attname, attgenerated::text \
         FROM pg_attribute \
         WHERE attrelid = 'outbox_log'::regclass \
           AND attname IN ('occurred_at', 'trace', 'correlation_id', 'fact_fingerprint') \
         ORDER BY attname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        generated_columns,
        vec![
            ("correlation_id".to_string(), "s".to_string()),
            ("fact_fingerprint".to_string(), "s".to_string()),
            ("occurred_at".to_string(), "s".to_string()),
            ("trace".to_string(), "s".to_string()),
        ],
        "CDC header projection columns must be stored generated columns"
    );

    let fingerprint_functions: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT p.proname, pg_get_userbyid(p.proowner), \
                has_function_privilege('rss_app', p.oid, 'EXECUTE'), \
                has_function_privilege('rss_outbox_maintenance', p.oid, 'EXECUTE') \
         FROM pg_proc p \
         JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'public' \
           AND p.proname IN ( \
               'rss_outbox_fact_frame', \
               'rss_outbox_canonical_number', \
               'rss_outbox_canonical_json', \
               'rss_outbox_fact_fingerprint' \
           ) \
         ORDER BY p.proname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(fingerprint_functions.len(), 4);
    for (function, owner, rss_app_can_execute, maintenance_can_execute) in fingerprint_functions {
        assert_ne!(
            owner, "rss_app",
            "serving role must not own generated-column helper `{function}`"
        );
        assert!(
            rss_app_can_execute,
            "serving role must retain EXECUTE on `{function}`"
        );
        assert!(
            maintenance_can_execute,
            "relay maintenance role needs only EXECUTE on generated-column helper `{function}`"
        );
    }

    let constraint_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid = 'outbox_log'::regclass \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraint_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "outbox_log_event_id_unique",
        "outbox_log_event_id_nonempty",
        "outbox_log_aggregate_type_nonempty",
        "outbox_log_aggregate_id_nonempty",
        "outbox_log_contract_version_valid",
        "outbox_log_schema_hash_valid",
        "outbox_log_metadata_object",
        "outbox_log_metadata_tenant_matches_column",
        "outbox_log_metadata_schema_matches_columns",
        "outbox_log_metadata_occurred_at_present",
        "outbox_log_trace_valid",
        "outbox_log_correlation_id_valid",
        "outbox_log_causation_id_valid",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing outbox_log constraint `{name}` in:\n{constraint_text}"
        );
    }

    let indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT indexname, indexdef \
         FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'outbox_log' \
         ORDER BY indexname",
    )
    .fetch_all(&store.pool)
    .await?;
    let indexes = indexes
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        indexes.contains("idx_outbox_log_contract_schema"),
        "outbox_log contract/schema lookup index missing in:\n{indexes}"
    );

    store.shutdown().await?;
    Ok(())
}

async fn insert_outbox_log_with_metadata(
    store: &PgStore,
    event_id: &str,
    tenant: vocab::TenantId,
    metadata: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let mut tx = store.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO outbox_log \
         (event_id, tenant_id, aggregate_type, aggregate_id, topic, contract_id, \
          contract_version, schema_hash, payload, metadata, causation_id) \
         VALUES \
         ($1, $2::uuid, 'identity', $1, 'identity.session-created', \
          'identity.session-created', 'v1', $3, decode('70', 'hex'), $4::jsonb, NULL)",
    )
    .bind(event_id)
    .bind(tenant.to_string())
    .bind(TEST_SCHEMA_HASH)
    .bind(metadata.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_log_rejects_missing_or_mismatched_schema_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let good_metadata = serde_json::json!({
        "tenantId": tenant.to_string(),
        "schemaVersion": "v1",
        "schemaHash": TEST_SCHEMA_HASH,
        "occurredAt": 0,
    });
    insert_outbox_log_with_metadata(
        &store,
        &unique_event_id("outbox-log-good-schema"),
        tenant,
        good_metadata,
    )
    .await?;

    for (label, metadata) in [
        (
            "missing schemaVersion",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaHash": TEST_SCHEMA_HASH,
                "occurredAt": 0,
            }),
        ),
        (
            "missing schemaHash",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "occurredAt": 0,
            }),
        ),
        (
            "wrong schemaHash",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "schemaHash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "occurredAt": 0,
            }),
        ),
        (
            "non-string schemaVersion",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": 1,
                "schemaHash": TEST_SCHEMA_HASH,
                "occurredAt": 0,
            }),
        ),
    ] {
        let err = match insert_outbox_log_with_metadata(
            &store,
            &unique_event_id("outbox-log-bad-schema"),
            tenant,
            metadata,
        )
        .await
        {
            Err(err) => err,
            Ok(()) => {
                return Err(std::io::Error::other(format!(
                    "{label} unexpectedly satisfied schema metadata CHECK"
                ))
                .into());
            }
        };
        assert!(
            err.as_database_error().is_some_and(|db| db
                .message()
                .contains("outbox_log_metadata_schema_matches_columns")),
            "{label} should fail the schema metadata CHECK, got: {err:?}"
        );
    }

    for (label, metadata) in [
        (
            "missing occurredAt",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "schemaHash": TEST_SCHEMA_HASH,
            }),
        ),
        (
            "string occurredAt",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "schemaHash": TEST_SCHEMA_HASH,
                "occurredAt": "0",
            }),
        ),
    ] {
        let err = match insert_outbox_log_with_metadata(
            &store,
            &unique_event_id("outbox-log-bad-occurred-at"),
            tenant,
            metadata,
        )
        .await
        {
            Err(err) => err,
            Ok(()) => {
                return Err(std::io::Error::other(format!(
                    "{label} unexpectedly satisfied occurredAt metadata CHECK"
                ))
                .into());
            }
        };
        assert!(
            err.as_database_error().is_some_and(|db| db
                .message()
                .contains("outbox_log_metadata_occurred_at_present")),
            "{label} should fail the occurredAt metadata CHECK, got: {err:?}"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_log_append_only_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'outbox_log', 'SELECT'), \
                has_table_privilege('rss_app', 'outbox_log', 'INSERT'), \
                has_table_privilege('rss_app', 'outbox_log', 'UPDATE'), \
                has_table_privilege('rss_app', 'outbox_log', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'outbox_log'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "outbox_log must ENABLE RLS");
    assert!(rls_forced, "outbox_log must FORCE RLS");
    assert!(can_select, "rss_app must SELECT outbox_log");
    assert!(can_insert, "rss_app must INSERT outbox_log");
    assert!(
        !can_update,
        "rss_app must not UPDATE append-only outbox_log"
    );
    assert!(
        !can_delete,
        "rss_app must not DELETE append-only outbox_log"
    );

    let (qual, with_check): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename = 'outbox_log' \
           AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&store.pool)
    .await?;
    for body in [qual.as_deref(), with_check.as_deref()] {
        let body = body.ok_or_else(|| {
            std::io::Error::other("outbox_log tenant policy must define USING and WITH CHECK")
        })?;
        assert!(
            body.to_lowercase().contains("nullif(current_setting"),
            "tenant policy must use NULLIF(current_setting(...)): {body}"
        );
        assert!(
            body.contains("rss.tenant_id"),
            "tenant policy must reference rss.tenant_id: {body}"
        );
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("outbox-log-rls");
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO outbox_log \
             (event_id, tenant_id, aggregate_type, aggregate_id, topic, contract_id, \
              contract_version, schema_hash, payload, metadata, causation_id) \
             VALUES \
             ($1, $2::uuid, 'identity', $1, 'identity.session-created', \
              'identity.session-created', 'v1', $3, decode('70', 'hex'), \
              jsonb_build_object('tenantId', $2, 'schemaVersion', 'v1', 'schemaHash', $3, \
                                 'occurredAt', 0), NULL)",
        )
        .bind(&event_id)
        .bind(&tenant_a)
        .bind(TEST_SCHEMA_HASH)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let update =
            sqlx::query("UPDATE outbox_log SET aggregate_id = 'mutated' WHERE event_id = $1")
                .bind(&event_id)
                .execute(&mut *tx)
                .await;
        assert!(
            update.is_err(),
            "rss_app must not update append-only outbox_log"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let delete = sqlx::query("DELETE FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .execute(&mut *tx)
            .await;
        assert!(
            delete.is_err(),
            "rss_app must not delete append-only outbox_log"
        );
        tx.rollback().await?;
    }

    for (tenant, expected, label) in [(&tenant_a, 1_i64, "tenant A"), (&tenant_b, 0, "tenant B")] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(cnt.0, expected, "{label} outbox_log visibility mismatch");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must fail closed for outbox_log"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// ── reconcile target/attempt/action/lease schema (#1629) ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_schema_catalog_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name \
         FROM information_schema.tables \
         WHERE table_schema = 'public' \
           AND table_name IN ( \
             'reconcile_targets', 'reconcile_leases', \
             'reconcile_attempts', 'reconcile_actions', 'reconcile_attempt_results' \
           ) \
         ORDER BY table_name",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            ("reconcile_actions".to_string(),),
            ("reconcile_attempt_results".to_string(),),
            ("reconcile_attempts".to_string(),),
            ("reconcile_leases".to_string(),),
            ("reconcile_targets".to_string(),),
        ],
        "all reconcile schema tables must exist"
    );

    let target_unique: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'reconcile_targets'::regclass \
           AND c.conname = 'reconcile_targets_tenant_resource_unique'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        target_unique.0, "tenant_id,reconciler_id,resource_kind,resource_id",
        "target uniqueness must include tenant and full resource identity"
    );
    let disabled_reason: (String, String) = sqlx::query_as(
        "SELECT data_type, is_nullable FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'reconcile_targets' \
           AND column_name = 'disabled_reason'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(disabled_reason, ("text".to_string(), "YES".to_string()));

    let fk_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid IN ( \
             'reconcile_leases'::regclass, \
             'reconcile_attempts'::regclass, \
             'reconcile_actions'::regclass, \
             'reconcile_attempt_results'::regclass \
           ) \
           AND contype = 'f' \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let fk_text = fk_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "FOREIGN KEY (tenant_id, target_id) REFERENCES reconcile_targets(tenant_id, target_id)",
        "FOREIGN KEY (tenant_id, attempt_id, target_id) REFERENCES reconcile_attempts(tenant_id, attempt_id, target_id)",
    ] {
        assert!(
            fk_text.contains(needle),
            "missing reconcile composite tenant FK `{needle}` in:\n{fk_text}"
        );
    }

    let constraint_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid IN ( \
             'reconcile_targets'::regclass, \
             'reconcile_leases'::regclass, \
             'reconcile_attempts'::regclass, \
             'reconcile_actions'::regclass, \
             'reconcile_attempt_results'::regclass \
           ) \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraint_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "reconcile_targets_status_valid",
        "reconcile_targets_disabled_reason_valid",
        "reconcile_leases_state_valid",
        "reconcile_leases_epoch_non_negative",
        "reconcile_attempts_trigger_kind_valid",
        "reconcile_actions_action_kind_valid",
        "reconcile_actions_result_label_valid",
        "reconcile_attempt_results_result_label_valid",
        "reconcile_attempt_results_error_consistent",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing reconcile CHECK `{name}` in:\n{constraint_text}"
        );
    }

    let index_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT indexname, indexdef \
         FROM pg_indexes \
         WHERE schemaname = 'public' \
           AND tablename = 'reconcile_attempt_results' \
         ORDER BY indexname",
    )
    .fetch_all(&store.pool)
    .await?;
    let index_text = index_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        index_text.contains("idx_reconcile_attempt_results_latest_target")
            && index_text.contains("(tenant_id, target_id, completed_at DESC, attempt_id DESC)"),
        "missing latest-result target covering index:\n{index_text}"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_target_unique_key_includes_tenant_resource() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let resource = format!("device-{}", uuid::Uuid::new_v4());

    sqlx::query(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'cert-reconciler', 'device-cert', $2)",
    )
    .bind(&tenant_a)
    .bind(&resource)
    .execute(&store.pool)
    .await?;

    let duplicate = sqlx::query(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'cert-reconciler', 'device-cert', $2)",
    )
    .bind(&tenant_a)
    .bind(&resource)
    .execute(&store.pool)
    .await;
    assert!(
        duplicate.is_err(),
        "same tenant/reconciler/resource must be rejected by DB UNIQUE"
    );

    sqlx::query(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'cert-reconciler', 'device-cert', $2)",
    )
    .bind(&tenant_b)
    .bind(&resource)
    .execute(&store.pool)
    .await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let grants: Vec<(String, bool, bool, bool, bool, bool, bool)> = sqlx::query_as(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', c.oid, 'SELECT'), \
                has_table_privilege('rss_app', c.oid, 'INSERT'), \
                has_table_privilege('rss_app', c.oid, 'UPDATE'), \
                has_table_privilege('rss_app', c.oid, 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' \
           AND c.relname IN ( \
             'reconcile_targets', 'reconcile_leases', \
             'reconcile_attempts', 'reconcile_actions', 'reconcile_attempt_results' \
           ) \
         ORDER BY c.relname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(grants.len(), 5, "all reconcile tables must be inspected");
    for (table, rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete) in grants {
        assert!(rls_enabled, "{table} must ENABLE RLS");
        assert!(rls_forced, "{table} must FORCE RLS");
        assert!(can_select, "rss_app must SELECT {table}");
        assert!(can_insert, "rss_app must INSERT {table}");
        match table.as_str() {
            "reconcile_targets" | "reconcile_leases" => {
                assert!(can_update, "rss_app must UPDATE mutable {table}");
                assert!(!can_delete, "rss_app must not DELETE mutable {table}");
            }
            "reconcile_attempts" | "reconcile_actions" | "reconcile_attempt_results" => {
                assert!(!can_update, "rss_app must not UPDATE append-only {table}");
                assert!(!can_delete, "rss_app must not DELETE append-only {table}");
            }
            _ => unreachable!("query filters table list"),
        }
    }

    let policies: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT tablename, qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename IN ( \
             'reconcile_targets', 'reconcile_leases', \
             'reconcile_attempts', 'reconcile_actions', 'reconcile_attempt_results' \
           ) \
           AND policyname = 'tenant_isolation' \
         ORDER BY tablename",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(policies.len(), 5, "all reconcile tables need tenant policy");
    for (table, qual, with_check) in policies {
        for body in [qual.as_deref(), with_check.as_deref()] {
            let body = body.ok_or_else(|| {
                std::io::Error::other(format!("{table} tenant policy missing USING/WITH CHECK"))
            })?;
            assert!(
                body.to_lowercase().contains("nullif(current_setting"),
                "{table} tenant policy must use NULLIF(current_setting(...)): {body}"
            );
            assert!(
                body.contains("rss.tenant_id"),
                "{table} tenant policy must reference rss.tenant_id: {body}"
            );
        }
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let resource = format!("rls-device-{}", uuid::Uuid::new_v4());

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO reconcile_targets \
             (tenant_id, reconciler_id, resource_kind, resource_id) \
             VALUES ($1::uuid, 'rls-reconciler', 'device', $2)",
        )
        .bind(&tenant_a)
        .bind(&resource)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    for (tenant, expected, label) in [(&tenant_a, 1_i64, "tenant A"), (&tenant_b, 0, "tenant B")] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM reconcile_targets \
             WHERE reconciler_id = 'rls-reconciler' AND resource_id = $1",
        )
        .bind(&resource)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, expected, "{label} visibility mismatch");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM reconcile_targets \
             WHERE reconciler_id = 'rls-reconciler' AND resource_id = $1",
        )
        .bind(&resource)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must fail closed for reconcile_targets"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_lease_cas_rejects_stale_token_and_epoch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("lease-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("lease-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    let first = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-a",
            std::time::Duration::from_secs(60),
        )
        .await?
        .ok_or_else(|| std::io::Error::other("first acquire must win"))?;

    let blocked = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-b",
            std::time::Duration::from_secs(60),
        )
        .await?;
    assert!(blocked.is_none(), "active lease must block another holder");

    sqlx::query(
        "UPDATE reconcile_leases \
         SET acquired_at = now() - make_interval(secs => 120), \
             heartbeat_at = now() - make_interval(secs => 120), \
             expires_at = now() - make_interval(secs => 60) \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&store.pool)
    .await?;

    let second = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-b",
            std::time::Duration::from_secs(60),
        )
        .await?
        .ok_or_else(|| std::io::Error::other("expired lease must be reclaimed"))?;
    assert!(
        second.epoch() > first.epoch(),
        "lease reclaim must advance epoch high-water"
    );

    assert_eq!(
        reconcile
            .extend_lease(
                tenant,
                target.target_id(),
                first.lease_token(),
                first.epoch(),
                std::time::Duration::from_secs(60)
            )
            .await?,
        ReconcileLeaseOutcome::Lost,
        "stale token/epoch must not extend a reclaimed lease"
    );
    assert_eq!(
        reconcile
            .release_lease(
                tenant,
                target.target_id(),
                first.lease_token(),
                first.epoch()
            )
            .await?,
        ReconcileLeaseOutcome::Lost,
        "stale token/epoch must not release a reclaimed lease"
    );
    assert_eq!(
        reconcile
            .extend_lease(
                tenant,
                target.target_id(),
                second.lease_token(),
                second.epoch(),
                std::time::Duration::from_secs(60)
            )
            .await?,
        ReconcileLeaseOutcome::Held,
        "current token/epoch must extend"
    );
    assert_eq!(
        reconcile
            .release_lease(
                tenant,
                target.target_id(),
                second.lease_token(),
                second.epoch()
            )
            .await?,
        ReconcileLeaseOutcome::Held,
        "current token/epoch must release"
    );

    let third = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-c",
            std::time::Duration::from_secs(60),
        )
        .await?
        .ok_or_else(|| std::io::Error::other("released lease must be acquirable"))?;
    assert!(
        third.epoch() > second.epoch(),
        "released lease must retain and advance epoch high-water"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_attempts_and_actions_are_append_only_for_rss_app() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant = uuid::Uuid::new_v4().to_string();
    let target_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'append-reconciler', 'device', $2) \
         RETURNING target_id::text",
    )
    .bind(&tenant)
    .bind(format!("append-device-{}", uuid::Uuid::new_v4()))
    .fetch_one(&store.pool)
    .await?;
    let attempt_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_attempts \
         (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind) \
         VALUES ($1::uuid, $2::uuid, gen_random_uuid(), 1, 'holder-a', 'targeted') \
         RETURNING attempt_id::text",
    )
    .bind(&tenant)
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;
    let action_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_actions \
         (tenant_id, attempt_id, target_id, action_kind, result_label) \
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'noop', 'recorded') \
         RETURNING action_id::text",
    )
    .bind(&tenant)
    .bind(&attempt_id.0)
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;
    let result_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_attempt_results \
         (tenant_id, attempt_id, target_id, result_label, error_kind) \
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'transient', 'transient') \
         RETURNING attempt_id::text",
    )
    .bind(&tenant)
    .bind(&attempt_id.0)
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;

    for (table, update_sql, delete_sql, id) in [
        (
            "reconcile_attempts",
            "UPDATE reconcile_attempts SET holder_id = 'tampered' \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            "DELETE FROM reconcile_attempts \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            &attempt_id.0,
        ),
        (
            "reconcile_actions",
            "UPDATE reconcile_actions SET result_label = 'transient' \
             WHERE tenant_id = $1::uuid AND action_id = $2::uuid",
            "DELETE FROM reconcile_actions \
             WHERE tenant_id = $1::uuid AND action_id = $2::uuid",
            &action_id.0,
        ),
        (
            "reconcile_attempt_results",
            "UPDATE reconcile_attempt_results SET result_label = 'settled' \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            "DELETE FROM reconcile_attempt_results \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            &result_id.0,
        ),
    ] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant)
            .execute(&mut *tx)
            .await?;
        let update = sqlx::query(update_sql)
            .bind(&tenant)
            .bind(id)
            .execute(&mut *tx)
            .await;
        assert!(update.is_err(), "rss_app must not UPDATE {table}");
        let delete = sqlx::query(delete_sql)
            .bind(&tenant)
            .bind(id)
            .execute(&mut *tx)
            .await;
        assert!(delete.is_err(), "rss_app must not DELETE {table}");
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_store_claim_result_action_and_outbox_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("scheduler-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("scheduler-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    ReconcileScheduleStore::pause_target(&reconcile, tenant, target.target_id()).await?;
    let paused = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "scheduler-reconciler",
        "holder-a",
        4,
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert!(paused.is_empty(), "disabled target must not be claimed");

    ReconcileScheduleStore::resume_target(&reconcile, tenant, target.target_id()).await?;
    let claimed = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "scheduler-reconciler",
        "holder-a",
        4,
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(claimed.len(), 1, "resumed due target should be claimed");
    let claimed = &claimed[0];
    assert_eq!(claimed.target_id(), target.target_id());
    assert_eq!(claimed.trigger(), AttemptTrigger::Resync);

    let attempt = match ReconcileScheduleStore::append_attempt(&reconcile, claimed, "holder-a")
        .await?
    {
        ScheduleAttemptOutcome::Started(attempt) => attempt,
        ScheduleAttemptOutcome::Lost => {
            return Err(std::io::Error::other("fresh claim should allow append_attempt").into());
        }
    };
    let dispatch_key = format!("reconcile-command-{}", uuid::Uuid::new_v4());
    let command = reviewed_reconcile_command(tenant, &dispatch_key, &dispatch_key, "create", 1)?;
    assert_eq!(
        ReconcileScheduleStore::record_action_and_enqueue_command(
            &reconcile,
            &attempt,
            ConvergeAction::Create,
            command,
        )
        .await?,
        eventexec::ScheduleActionOutcome::Enqueued,
        "current lease should atomically record action and outbox row"
    );
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &attempt,
            AttemptResult::from_outcome(
                &Outcome::requeue_after(std::time::Duration::from_millis(250)),
                std::time::Duration::from_secs(60),
            ),
        )
        .await?,
        eventexec::ScheduleLeaseOutcome::Held,
        "current lease should record terminal attempt result"
    );
    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, claimed).await?,
        eventexec::ScheduleLeaseOutcome::Held
    );

    let action: (String, String) = sqlx::query_as(
        "SELECT action_kind, result_label \
         FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(action, ("create".to_string(), "recorded".to_string()));

    let result: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT result_label, requeue_after_ms, error_kind \
         FROM reconcile_attempt_results \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        result,
        ("requeue_after".to_string(), Some(250), None),
        "terminal result should live outside reconcile_actions"
    );

    let outbox_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM outbox \
         WHERE tenant_id = $1::uuid \
           AND topic = $2 \
           AND metadata->>'subjectId' = $3 \
           AND status = 'pending'",
    )
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(&dispatch_key)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        outbox_count.0, 1,
        "stable dispatch key must enqueue one outbox row"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_command_dispatch_key_is_tenant_scoped() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let reconcile = store.reconcile();
    let raw_key = format!("shared-reconcile-command-{}", uuid::Uuid::new_v4());
    let mut dispatched = Vec::new();
    for (tenant, resource) in [
        (
            vocab::TenantId::parse("11111111-1111-1111-1111-111111111111")?,
            format!("scoped-device-a-{}", uuid::Uuid::new_v4()),
        ),
        (
            vocab::TenantId::parse("22222222-2222-2222-2222-222222222222")?,
            format!("scoped-device-b-{}", uuid::Uuid::new_v4()),
        ),
    ] {
        let key = ReconcileTargetKey::parse("scoped-command-reconciler", "device", &resource)?;
        let target = reconcile.upsert_target(tenant, &key).await?;
        let claimed = ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "scoped-command-reconciler",
            "holder-a",
            1,
            std::time::Duration::from_secs(30),
        )
        .await?;
        assert_eq!(claimed.len(), 1);
        let attempt =
            match ReconcileScheduleStore::append_attempt(&reconcile, &claimed[0], "holder-a")
                .await?
            {
                ScheduleAttemptOutcome::Started(attempt) => attempt,
                ScheduleAttemptOutcome::Lost => {
                    return Err(std::io::Error::other("fresh claim should append attempt").into());
                }
            };
        let command = reviewed_reconcile_command(
            tenant,
            &raw_key,
            target.target_id(),
            target.target_id(),
            1,
        )?;
        assert_eq!(
            ReconcileScheduleStore::record_action_and_enqueue_command(
                &reconcile,
                &attempt,
                ConvergeAction::Create,
                command,
            )
            .await?,
            eventexec::ScheduleActionOutcome::Enqueued
        );
        dispatched.push((tenant, target.target_id().to_string()));
    }

    let mut event_ids = Vec::new();
    for (tenant, subject_id) in dispatched {
        let event_id: (String,) = sqlx::query_as(
            "SELECT event_id FROM outbox \
             WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
        )
        .bind(tenant.to_string())
        .bind(generated::command::_seed_v1::TOPIC)
        .bind(subject_id)
        .fetch_one(&store.pool)
        .await?;
        assert!(
            !event_id.0.contains(&raw_key),
            "raw idempotency key must not be persisted as the dispatch identity"
        );
        event_ids.push(event_id.0);
    }
    assert_ne!(
        event_ids[0], event_ids[1],
        "same raw key must derive distinct dispatch ids across tenants"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_rejects_same_scoped_key_with_different_payload() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("conflict-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("conflict-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let _target = reconcile.upsert_target(tenant, &key).await?;
    let claimed = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "conflict-reconciler",
        "holder-a",
        1,
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(claimed.len(), 1);
    let attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &claimed[0], "holder-a").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => {
                return Err(std::io::Error::other("fresh claim should append attempt").into());
            }
        };
    let raw_key = format!("conflicting-command-{}", uuid::Uuid::new_v4());

    let first = reviewed_reconcile_command(tenant, &raw_key, &raw_key, "first", 1)?;
    assert_eq!(
        ReconcileScheduleStore::record_action_and_enqueue_command(
            &reconcile,
            &attempt,
            ConvergeAction::Create,
            first,
        )
        .await?,
        ScheduleActionOutcome::Enqueued
    );
    let first_fact: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, fact_fingerprint FROM outbox \
         WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
    )
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(&raw_key)
    .fetch_one(&store.pool)
    .await?;
    let second = reviewed_reconcile_command(tenant, &raw_key, &raw_key, "second", 1)?;
    let conflict = ReconcileScheduleStore::record_action_and_enqueue_command(
        &reconcile,
        &attempt,
        ConvergeAction::Create,
        second,
    )
    .await;
    assert!(
        matches!(
            conflict,
            Err(ref error) if error.kind() == ReconcileScheduleErrorKind::FactConflict
        ),
        "same scoped dispatch key must remain typed Err after quarantine: {conflict:?}"
    );

    let action_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        action_count.0, 1,
        "failed command conflict must roll back the action insert"
    );

    let outbox: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, fact_fingerprint FROM outbox \
             WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
    )
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(&raw_key)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(outbox.0, br#"{"amount":1,"targetId":"first"}"#);
    assert_eq!(
        outbox, first_fact,
        "quarantine must preserve the first fact"
    );

    let target_status: (String,) = sqlx::query_as(
        "SELECT status FROM reconcile_targets WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        target_status.0, "disabled",
        "fact conflict quarantine must persistently disable automatic reclaim"
    );

    let capability = OperatorReconcileCapability::issue_for_authorized_operator();
    let inspected = ReconcileOperatorStore::inspect_target(
        &reconcile,
        tenant,
        attempt.target().target_id(),
        capability,
    )
    .await?;
    assert_eq!(inspected.status(), ReconcileTargetStatus::Disabled);
    assert_eq!(
        inspected.disabled_reason(),
        Some(ReconcileQuarantineReason::FactConflict)
    );

    let wrong_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    for result in [
        ReconcileOperatorStore::inspect_target(
            &reconcile,
            wrong_tenant,
            attempt.target().target_id(),
            capability,
        )
        .await,
        ReconcileOperatorStore::resume_target(
            &reconcile,
            wrong_tenant,
            attempt.target().target_id(),
            capability,
        )
        .await,
    ] {
        let Err(error) = result else {
            return Err("cross-tenant reconcile operator access must fail closed".into());
        };
        assert_eq!(error.kind(), ReconcileScheduleErrorKind::Infrastructure);
        assert_eq!(
            error.to_string(),
            "reconcile schedule store operation failed"
        );
    }

    let resumed = ReconcileOperatorStore::resume_target(
        &reconcile,
        tenant,
        attempt.target().target_id(),
        capability,
    )
    .await?;
    assert_eq!(resumed.status(), ReconcileTargetStatus::Active);
    assert_eq!(resumed.disabled_reason(), None);
    let resumed_db: (String, Option<String>, bool) = sqlx::query_as(
        "SELECT status, disabled_reason, next_run_at <= now() \
         FROM reconcile_targets WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(resumed_db, ("active".to_string(), None, true));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_rejects_stale_attempt_writes_after_lease_reclaim() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("stale-lease-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("stale-lease-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    let first_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "stale-lease-reconciler",
        "holder-a",
        1,
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(first_claim.len(), 1);
    let stale_claim = &first_claim[0];
    let stale_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, stale_claim, "holder-a").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => {
                return Err(std::io::Error::other("fresh claim should append attempt").into());
            }
        };

    sqlx::query(
        "UPDATE reconcile_leases \
         SET expires_at = acquired_at + interval '1 microsecond' \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&store.pool)
    .await?;

    let second_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "stale-lease-reconciler",
        "holder-b",
        1,
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(second_claim.len(), 1);
    assert_eq!(second_claim[0].trigger(), AttemptTrigger::LeaseReclaim);
    assert!(
        second_claim[0].epoch() > stale_claim.epoch(),
        "lease reclaim must advance target-local epoch"
    );

    let dispatch_key = format!("stale-reconcile-command-{}", uuid::Uuid::new_v4());
    let stale_command =
        reviewed_reconcile_command(tenant, &dispatch_key, &dispatch_key, "stale", 1)?;

    assert_eq!(
        ReconcileScheduleStore::record_action_and_enqueue_command(
            &reconcile,
            &stale_attempt,
            ConvergeAction::Update,
            stale_command,
        )
        .await?,
        eventexec::ScheduleActionOutcome::Lost,
        "stale token+epoch must not record action or outbox"
    );
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &stale_attempt,
            AttemptResult::from_error(
                &consistency::ReconcileError::new(consistency::EngineErrorKind::Transient),
                std::time::Duration::from_secs(1),
            ),
        )
        .await?,
        eventexec::ScheduleLeaseOutcome::Lost,
        "stale token+epoch must not record terminal result"
    );

    let action_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(stale_attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    let result_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM reconcile_attempt_results \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(stale_attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    let outbox_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM outbox \
         WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
    )
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(&dispatch_key)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(action_count.0, 0);
    assert_eq!(result_count.0, 0);
    assert_eq!(outbox_count.0, 0);

    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, &second_claim[0]).await?,
        eventexec::ScheduleLeaseOutcome::Held
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_claims_requeue_after_attempt_as_requeue_trigger() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("requeue-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("requeue-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    let first_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "requeue-reconciler",
        "holder-a",
        1,
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(first_claim.len(), 1);
    let attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &first_claim[0], "holder-a")
            .await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => {
                return Err(std::io::Error::other("fresh claim should append attempt").into());
            }
        };
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &attempt,
            AttemptResult::from_outcome(
                &Outcome::requeue_after(std::time::Duration::ZERO),
                std::time::Duration::from_secs(60),
            ),
        )
        .await?,
        eventexec::ScheduleLeaseOutcome::Held
    );
    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, &first_claim[0]).await?,
        eventexec::ScheduleLeaseOutcome::Held
    );

    let requeue_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "requeue-reconciler",
        "holder-b",
        1,
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(requeue_claim.len(), 1);
    assert_eq!(requeue_claim[0].target_id(), target.target_id());
    assert_eq!(requeue_claim[0].trigger(), AttemptTrigger::Requeue);

    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, &requeue_claim[0]).await?,
        eventexec::ScheduleLeaseOutcome::Held
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_target_pause_resume_missing_target_fails_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let missing_target = uuid::Uuid::new_v4().to_string();
    let reconcile = store.reconcile();

    assert!(
        ReconcileScheduleStore::pause_target(&reconcile, tenant, &missing_target)
            .await
            .is_err(),
        "pause must fail when the target row is missing"
    );
    assert!(
        ReconcileScheduleStore::resume_target(&reconcile, tenant, &missing_target)
            .await
            .is_err(),
        "resume must fail when the target row is missing"
    );

    store.shutdown().await?;
    Ok(())
}

/// 在独立事务内读 `rss_tx_probe` 行数（committed 数据跨池连接可见）。
async fn probe_count(store: &PgStore) -> Result<i64, sqlx::Error> {
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                let row: (i64,) = sqlx::query_as("SELECT count(*) FROM rss_tx_probe")
                    .fetch_one(cap.conn())
                    .await?;
                Ok(row.0)
            }) as BoxFuture<'_, Result<i64, sqlx::Error>>
        })
        .await
}

// ── outbox integration tests ───────────────────────────────────────────────────
//
// T1: OUTBOX-ATOMIC-IDEM-01 回滚→无 entry（L1 原子性，INVARIANT）
// T2: 提交→恰 1 行 pending（T1 anti-vacuity 配对）
// T3: relay→published（Ack）
// T4: relay→pending+retry_after（Requeue）
// T5: relay→dlx（Reject）
// T6: 崩溃重投（stale publishing → poll_pending 重捞 → relay → published；幂等 Ack）+ 跨域隔离负向
// T7: 并发 CAS fencing（两连接各 relay → 至多 publish 一次）
// T8: sweep 删超保留期 published、保留 dlx + 保留期内 published/pending anti-vacuity
// T9: lease_token CAS fencing（stale token 不能结算被新租约接管的行）

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use consistency::{
    BacklogMetricSample, BacklogSample, Disposition, EngineErrorKind, EventEntry, EventTopic,
    HandleResult, OutboxAppendOutcome, OutboxBacklog, OutboxContractId, OutboxFactIdentity,
    OutboxMetricSubject, OutboxRelay, OutboxSource, PendingEntry, RetentionSweeper,
};
use diport::{
    AckAction, Acker, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, Delivery,
    DeliveryStream, DynAcker, DynDeadLetterStore, DynPublisher, EnvelopeMetadata, KEY_ACTOR,
    KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
    KEY_SUBJECT_ID, KEY_TENANT_AUTHORITY, KEY_TENANT_ID, KEY_TRACE, Message, OutboxEmitErrorKind,
    PublishRequest, Publisher, PublisherError,
};
use eventexec::{
    ConsumerMeta, LeaseConfig, MAX_REDELIVERY, TenantAuthority, TenantAuthorityBinding,
    run_consumer_ackable,
};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use testkit::eventing_conformance as eventconf;

use crate::dead_letter_payload::tests::test_protector;
use crate::outbox::{
    MAX_PUBLISH_ATTEMPTS, OutboxAppendError, OutboxEnvelope, OutboxMetadata, PgOutbox,
    STATUS_PUBLISHED, SettleOutcome, append_outbox, append_outbox_with_projection,
};
use crate::outbox_cdc::append_outbox_log;

static OUTBOX_SWEEP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn test_append_error(_: OutboxAppendError) -> sqlx::Error {
    sqlx::Error::Protocol("outbox append test failed".to_string())
}

/// setup 阶段：应用 migration（含 outbox 表）。**不**全表 DELETE——每个 outbox 用例按唯一 `event_id`
/// （[`unique_event_id`]）+ 唯一 domain 命名空间自隔离断言（`WHERE event_id = $1` / domain-scoped 查询用各自
/// 专属 domain），故无需净表起点。去掉全表清后用例 correct-by-construction：在并发执行下亦互不污染——既覆盖
/// 官方串行 lane（`cargo nextest run --profile integration`，`.config/nextest.toml` `integration` test-group
/// `max-threads=1`），也覆盖直接 `cargo test -p postgres --features integration`（libtest 并行、绕过 nextest
/// 串行组）这条残留路径，隔离不再依赖调度器串行（#1194；nextest 串行组保留作 defense-in-depth）。
async fn setup_outbox(store: &PgStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    store
        .register_projection_input_bindings(
            TEST_PROJECTION_INPUT_GENERATION,
            TEST_PROJECTION_INPUTS,
        )
        .await?;
    Ok(())
}

/// 测试专用 terminal fixture：状态、对应终态时间与 updated_at 必须在同一 UPDATE 中保持一致。
async fn set_outbox_terminal_for_test(
    store: &PgStore,
    event_id: &str,
    status: &str,
    age_seconds: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE outbox
        SET status = $1,
            published_at = CASE
                WHEN $1 = 'published' THEN now() - make_interval(secs => $2::double precision)
                ELSE NULL
            END,
            dlx_at = CASE
                WHEN $1 = 'dlx' THEN now() - make_interval(secs => $2::double precision)
                ELSE NULL
            END,
            created_at = now() - make_interval(secs => $2::double precision),
            updated_at = now() - make_interval(secs => $2::double precision)
        WHERE event_id = $3
        "#,
    )
    .bind(status)
    .bind(age_seconds)
    .bind(event_id)
    .execute(&store.pool)
    .await?;
    Ok(())
}

/// 产生唯一 event_id（防并发测试冲突）。
#[allow(clippy::disallowed_methods)]
// reason: SystemTime::now() 仅用于测试隔离产生唯一 id，非时钟注入场景；item-level carve-out（error-handling.md §Carve-out）。
fn unique_event_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}-{nanos}-{}", uuid_like())
}

/// 简单递增计数器生成伪唯一后缀（不引 uuid crate）。
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!("{:x}", CTR.fetch_add(1, Ordering::Relaxed))
}

/// 产生唯一 domain（防 **domain-scoped 聚合断言**被跨轮 / 并发旧行污染）——与 [`unique_event_id`] 同源唯一性。
///
/// INVARIANT：按 domain 聚合且断言**精确 depth/计数**的用例（t16–t19 的 `sample_backlog`）必须用 **per-run 唯一**
/// domain。`outbox.event_id` UNIQUE + `ON CONFLICT (event_id) DO NOTHING` 只隔离**单行** `WHERE event_id` 查询；
/// 对 `sample_backlog(domain)` 这种**按 domain 聚合**的查询不够——外部持久库重复跑时，上一轮同 domain 旧行会被
/// 计入，使精确 depth 累加而 flaky（#1194 review F1）。去全表 DELETE 后唯一隔离手段即「event_id + domain 双唯一」。
fn unique_domain(prefix: &str) -> String {
    unique_event_id(prefix)
}

/// 构造测试用 EventEntry + Envelope。
fn make_entry(event_id: &str) -> EventEntry {
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 构造已知合法值，item-level carve-out（error-handling.md §Carve-out）。
    EventEntry::new(
        EventTopic::parse("test.event").unwrap(),
        IdemKey::parse(event_id).unwrap(),
        reviewed_payload(b"payload"),
    )
}

fn make_pending_entry(
    entry: EventEntry,
    tenant: vocab::TenantId,
    contract_id: &str,
) -> PendingEntry {
    #[allow(clippy::unwrap_used)]
    // reason: integration fixture uses known-valid contract ids.
    PendingEntry::new(
        consistency::StoredOutboxEntry::hydrate(
            entry.topic().as_str(),
            entry.idem_key().clone(),
            OutboxPayload::from_reviewed_event_bytes(entry.payload().to_vec()),
        )
        .unwrap(),
        OutboxMetricSubject::new(tenant, OutboxContractId::parse(contract_id).unwrap()),
    )
}

async fn pending_entry_for_event(store: &PgStore, event_id: &str) -> Result<PendingEntry, String> {
    let row: (String, String, String, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT tenant_id::text, contract_id, topic, payload
        FROM outbox
        WHERE event_id = $1
        "#,
    )
    .bind(event_id)
    .fetch_one(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;

    let (tenant_id, contract_id, topic, payload) = row;
    let tenant = vocab::TenantId::parse(&tenant_id).map_err(|e| format!("{e:?}"))?;
    let topic = EventTopic::parse(&topic).map_err(|e| format!("{e:?}"))?;
    let idem_key = IdemKey::parse(event_id).map_err(|e| format!("{e:?}"))?;
    let entry = EventEntry::new(
        topic,
        idem_key,
        OutboxPayload::from_reviewed_event_bytes(payload),
    );
    Ok(make_pending_entry(entry, tenant, &contract_id))
}

fn summarize_backlog(samples: &[BacklogMetricSample]) -> BacklogSample {
    let depth = samples.iter().map(|s| s.sample().depth()).sum();
    let oldest_age_seconds = samples
        .iter()
        .map(|s| s.sample().oldest_age_seconds())
        .max()
        .unwrap_or(0);
    BacklogSample::new(depth, oldest_age_seconds)
}

/// 测试用简化 envelope（占位 `occurred_at=0`）：仅供原子性 / relay 路径验证（T1–T2 等直调 `append_outbox`
/// 的用例，不断言 occurred_at 值）。`occurred_at` 构造期必填（#262 F1），此处取占位 0；envelope occurred_at 的
/// 生产注入路径（从注入 Clock）由 t10（`PgEmitter`）/ t11（`PgSessionLifecycle`）/ config co-tx 专门覆盖（#1129）。
fn make_envelope(domain: &str, event_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        "contract-1".to_string(),
        OutboxMetadata::new(0, test_tenant(), test_contract())
            .with_subject_id(subject_id(event_id)),
    )
}

/// 构造测试 envelope（routing domain + contract_id；metadata 带标准 schema header，仅占位 `occurred_at=0`）——去重 `OutboxEnvelope::new` 内联重复。
fn make_test_env(domain: &str, contract_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0, test_tenant(), test_contract()),
    )
}

fn make_test_env_with_contract_metadata(
    domain: &str,
    contract_id: &str,
    metadata_contract: vocab::ContractBinding,
) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0, test_tenant(), metadata_contract),
    )
}

/// 构造指定租户的测试 envelope，用于跨租 outbox partition/RLS 用例。
fn make_test_env_for_tenant(
    domain: &str,
    contract_id: &str,
    tenant: vocab::TenantId,
) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0, tenant, test_contract()),
    )
}

struct SeedFactSnapshot {
    payload: Vec<u8>,
    fingerprint: Vec<u8>,
}

async fn seed_conflicting_outbox_fact(
    store: &PgStore,
    tenant: vocab::TenantId,
    event_id: &str,
) -> Result<SeedFactSnapshot, TestError> {
    let entry = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(event_id)?,
        reviewed_payload(b"preexisting-conflicting-fact"),
    );
    let env = OutboxEnvelope::new(
        "test".to_string(),
        "test.contract".to_string(),
        OutboxMetadata::new(0, tenant, test_contract())
            .with_subject_id(subject_id("conflict-seed")),
    );
    let outcome = store
        .run_global_transaction::<_, _, OutboxAppendError>(|cap| {
            Box::pin(async move { append_outbox(cap, &entry, &env).await })
        })
        .await?;
    assert_eq!(outcome, OutboxAppendOutcome::Inserted);
    let (payload, fingerprint): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT payload, fact_fingerprint FROM outbox WHERE event_id = $1")
            .bind(event_id)
            .fetch_one(&store.pool)
            .await?;
    Ok(SeedFactSnapshot {
        payload,
        fingerprint,
    })
}

async fn assert_seed_fact_unchanged(
    store: &PgStore,
    event_id: &str,
    expected: &SeedFactSnapshot,
) -> Result<(), TestError> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT payload, fact_fingerprint FROM outbox WHERE event_id = $1")
            .bind(event_id)
            .fetch_all(&store.pool)
            .await?;
    assert_eq!(rows.len(), 1, "seed fact must remain the sole event row");
    assert_eq!(rows[0].0, expected.payload);
    assert_eq!(rows[0].1, expected.fingerprint);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_append_distinguishes_same_fact_from_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let event_id = unique_event_id("outbox-fact-conflict");
    let entry = make_entry(&event_id);
    let first_env = OutboxEnvelope::new(
        "identity".to_string(),
        "identity.session-created".to_string(),
        OutboxMetadata::new(1, test_tenant(), test_contract())
            .with_subject_id(subject_id("stable-subject"))
            .with_trace("trace-a")
            .with_correlation("correlation-a"),
    );
    let retried_env = OutboxEnvelope::new(
        "identity".to_string(),
        "identity.session-created".to_string(),
        OutboxMetadata::new(2, test_tenant(), test_contract())
            .with_subject_id(subject_id("stable-subject"))
            .with_trace("trace-b")
            .with_correlation("correlation-b"),
    );

    let first = store
        .run_global_transaction::<_, _, OutboxAppendError>(|cap| {
            Box::pin(async move { append_outbox(cap, &entry, &first_env).await })
        })
        .await?;
    assert_eq!(first, OutboxAppendOutcome::Inserted);

    let retry_entry = make_entry(&event_id);
    let retry = store
        .run_global_transaction::<_, _, OutboxAppendError>(|cap| {
            Box::pin(async move { append_outbox(cap, &retry_entry, &retried_env).await })
        })
        .await?;
    assert_eq!(retry, OutboxAppendOutcome::SameFact);

    let conflicting_entry = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&event_id)?,
        OutboxPayload::from_reviewed_event_bytes(b"SECRET_CONFLICT_PAYLOAD".to_vec()),
    );
    let conflict_env = OutboxEnvelope::new(
        "identity".to_string(),
        "identity.session-created".to_string(),
        OutboxMetadata::new(3, test_tenant(), test_contract())
            .with_subject_id(subject_id("stable-subject")),
    );
    let conflict = store
        .run_global_transaction::<_, _, OutboxAppendError>(|cap| {
            Box::pin(async move { append_outbox(cap, &conflicting_entry, &conflict_env).await })
        })
        .await;
    assert!(matches!(conflict, Err(OutboxAppendError::Conflict(_))));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?,
        1
    );
    let tamper = sqlx::query("UPDATE outbox SET fact_fingerprint = $2 WHERE event_id = $1")
        .bind(&event_id)
        .bind(vec![0_u8; 32])
        .execute(&store.pool)
        .await;
    assert!(
        tamper.is_err(),
        "stored generated fingerprint must reject explicit writes"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_outbox_append_serializes_same_fact_and_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let same_id = unique_event_id("outbox-concurrent-same");
    let same_entry_a = make_entry(&same_id);
    let same_entry_b = same_entry_a.clone();
    let same_env_a = make_test_env("test", "projection.bound");
    let same_env_b = same_env_a.clone();
    let projection_registry_a =
        crate::projection_events::ProjectionWriteRegistry::from_generated(TEST_PROJECTION_INPUTS);
    let projection_registry_b = projection_registry_a;
    let same_a = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move {
            append_outbox_with_projection(cap, &same_entry_a, &same_env_a, &projection_registry_a)
                .await
        })
    });
    let same_b = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move {
            append_outbox_with_projection(cap, &same_entry_b, &same_env_b, &projection_registry_b)
                .await
        })
    });
    let (same_a, same_b) = tokio::join!(same_a, same_b);
    let same_outcomes = [same_a?, same_b?];
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::Inserted)
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM projection_events WHERE event_id = $1",)
            .bind(&same_id)
            .fetch_one(&store.pool)
            .await?,
        1,
        "concurrent same-fact retries must mirror exactly one projection row"
    );
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::SameFact)
            .count(),
        1
    );

    let conflict_id = unique_event_id("outbox-concurrent-conflict");
    let conflict_entry_a = make_entry(&conflict_id);
    let conflict_entry_b = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(b"different-payload".to_vec()),
    );
    let conflict_env_a = make_test_env("identity", "identity.session-created");
    let conflict_env_b = conflict_env_a.clone();
    let conflict_a = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move { append_outbox(cap, &conflict_entry_a, &conflict_env_a).await })
    });
    let conflict_b = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move { append_outbox(cap, &conflict_entry_b, &conflict_env_b).await })
    });
    let (conflict_a, conflict_b) = tokio::join!(conflict_a, conflict_b);
    let inserted = usize::from(matches!(
        conflict_a.as_ref(),
        Ok(OutboxAppendOutcome::Inserted)
    )) + usize::from(matches!(
        conflict_b.as_ref(),
        Ok(OutboxAppendOutcome::Inserted)
    ));
    let conflicts = usize::from(matches!(
        conflict_a.as_ref(),
        Err(OutboxAppendError::Conflict(_))
    )) + usize::from(matches!(
        conflict_b.as_ref(),
        Err(OutboxAppendError::Conflict(_))
    ));
    assert_eq!(inserted, 1);
    assert_eq!(conflicts, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_cdc_append_serializes_same_fact_and_typed_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let same_id = unique_event_id("cdc-concurrent-same");
    let same_entry_a = make_entry(&same_id);
    let same_entry_b = same_entry_a.clone();
    let same_env_a = make_test_env("identity", "identity.session-created");
    let same_env_b = same_env_a.clone();
    let same_a = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move {
            append_outbox_log(cap, &same_entry_a, &same_env_a, "aggregate-same").await
        })
    });
    let same_b = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move {
            append_outbox_log(cap, &same_entry_b, &same_env_b, "aggregate-same").await
        })
    });
    let (same_a, same_b) = tokio::join!(same_a, same_b);
    let same_outcomes = [same_a?, same_b?];
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::Inserted)
            .count(),
        1
    );
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::SameFact)
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_log WHERE event_id = $1")
            .bind(&same_id)
            .fetch_one(&store.pool)
            .await?,
        1
    );

    let conflict_id = unique_event_id("cdc-concurrent-conflict");
    let first_payload = b"cdc-first".to_vec();
    let second_payload = b"cdc-second".to_vec();
    let conflict_entry_a = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(first_payload.clone()),
    );
    let conflict_entry_b = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(second_payload.clone()),
    );
    let conflict_env_a = make_test_env("identity", "identity.session-created");
    let conflict_env_b = conflict_env_a.clone();
    let conflict_a = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move {
            append_outbox_log(
                cap,
                &conflict_entry_a,
                &conflict_env_a,
                "aggregate-conflict",
            )
            .await
        })
    });
    let conflict_b = store.run_global_transaction::<_, _, OutboxAppendError>(|cap| {
        Box::pin(async move {
            append_outbox_log(
                cap,
                &conflict_entry_b,
                &conflict_env_b,
                "aggregate-conflict",
            )
            .await
        })
    });
    let (conflict_a, conflict_b) = tokio::join!(conflict_a, conflict_b);
    assert_eq!(
        usize::from(matches!(
            conflict_a.as_ref(),
            Ok(OutboxAppendOutcome::Inserted)
        )) + usize::from(matches!(
            conflict_b.as_ref(),
            Ok(OutboxAppendOutcome::Inserted)
        )),
        1
    );
    assert_eq!(
        usize::from(matches!(
            conflict_a.as_ref(),
            Err(OutboxAppendError::Conflict(_))
        )) + usize::from(matches!(
            conflict_b.as_ref(),
            Err(OutboxAppendError::Conflict(_))
        )),
        1
    );

    let original: (i64, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT count(*) OVER (), payload, fact_fingerprint FROM outbox_log WHERE event_id = $1",
    )
    .bind(&conflict_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(original.0, 1);
    assert!(original.1 == first_payload || original.1 == second_payload);
    let retry_payload = if original.1 == first_payload {
        second_payload
    } else {
        first_payload
    };
    let retry_entry = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(retry_payload),
    );
    let retry_env = make_test_env("identity", "identity.session-created");
    let retry = store
        .run_global_transaction::<_, _, OutboxAppendError>(|cap| {
            Box::pin(async move {
                append_outbox_log(cap, &retry_entry, &retry_env, "aggregate-conflict").await
            })
        })
        .await;
    assert!(matches!(retry, Err(OutboxAppendError::Conflict(_))));
    let after: (i64, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT count(*) OVER (), payload, fact_fingerprint FROM outbox_log WHERE event_id = $1",
    )
    .bind(&conflict_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after, original,
        "typed conflicts must preserve the original CDC fact"
    );

    store.shutdown().await?;
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutboxFactGoldenFixture {
    schema_version: u32,
    cases: Vec<OutboxFactGoldenCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutboxFactGoldenCase {
    label: String,
    event_id: String,
    tenant_id: String,
    domain: String,
    topic: String,
    contract_id: String,
    contract_version: String,
    schema_hash: String,
    payload: Vec<u8>,
    partition_key: Option<String>,
    causation_id: Option<String>,
    metadata: serde_json::Value,
    expected_digest: [u8; 32],
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_fact_sql_matches_rust_known_vectors() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let fixture: OutboxFactGoldenFixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/consistency/outbox-fact-v1-vectors.json"
    )))?;
    assert_eq!(fixture.schema_version, 1);
    assert!(!fixture.cases.is_empty());
    for case in fixture.cases {
        let actual = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT rss_outbox_fact_fingerprint($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
        )
        .bind(&case.event_id)
        .bind(&case.tenant_id)
        .bind(&case.domain)
        .bind(&case.topic)
        .bind(&case.contract_id)
        .bind(&case.contract_version)
        .bind(&case.schema_hash)
        .bind(case.payload.as_slice())
        .bind(case.partition_key.as_deref())
        .bind(case.causation_id.as_deref())
        .bind(case.metadata.to_string())
        .fetch_one(&store.pool)
        .await?;
        let rust = OutboxFactIdentity::new(
            &case.event_id,
            &case.tenant_id,
            &case.domain,
            &case.topic,
            &case.contract_id,
            &case.contract_version,
            &case.schema_hash,
            &case.payload,
            case.partition_key.as_deref(),
            case.causation_id.as_deref(),
            &case.metadata,
        )
        .fingerprint();
        assert_eq!(
            actual.as_slice(),
            rust.as_bytes(),
            "Rust/SQL parity: {}",
            case.label
        );
        assert_eq!(
            actual.as_slice(),
            case.expected_digest,
            "fixed digest: {}",
            case.label
        );
    }
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_writer_funnel_mirrors_only_generated_bound_insert_once() -> TestResult {
    use crate::projection_events::ProjectionWriteRegistry;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let registry = ProjectionWriteRegistry::from_generated(TEST_PROJECTION_INPUTS);
    let domain = unique_domain("projection-funnel");
    let bound_event_id = unique_event_id("projection-bound");
    let unbound_event_id = unique_event_id("projection-unbound");
    let schema_mismatch_event_id = unique_event_id("projection-schema-mismatch");
    let bound_entry = make_entry(&bound_event_id);
    let unbound_entry = make_entry(&unbound_event_id);
    let schema_mismatch_entry = make_entry(&schema_mismatch_event_id);
    let bound_env = make_test_env(&domain, "projection.bound");
    let unbound_env = make_test_env(&domain, "projection.unbound");
    let schema_mismatch_env = make_test_env_with_contract_metadata(
        &domain,
        "projection.bound",
        vocab::ContractBinding::from_static("test", "projection.bound", "v2", TEST_SCHEMA_HASH),
    );

    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let bound_entry = bound_entry.clone();
            let unbound_entry = unbound_entry.clone();
            let bound_env = bound_env.clone();
            let unbound_env = unbound_env.clone();
            Box::pin(async move {
                let _outcome =
                    append_outbox_with_projection(cap, &bound_entry, &bound_env, &registry)
                        .await
                        .map_err(test_append_error)?;
                let _outcome =
                    append_outbox_with_projection(cap, &bound_entry, &bound_env, &registry)
                        .await
                        .map_err(test_append_error)?;
                let _outcome =
                    append_outbox_with_projection(cap, &unbound_entry, &unbound_env, &registry)
                        .await
                        .map_err(test_append_error)?;
                let _outcome = append_outbox_with_projection(
                    cap,
                    &schema_mismatch_entry,
                    &schema_mismatch_env,
                    &registry,
                )
                .await
                .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let projection_rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT event_id, contract_id, contract_version, schema_hash, metadata ->> 'tenantId'
        FROM projection_events
        WHERE event_id = ANY($1)
        ORDER BY event_id
        "#,
    )
    .bind(vec![
        bound_event_id.clone(),
        unbound_event_id.clone(),
        schema_mismatch_event_id.clone(),
    ])
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        projection_rows.len(),
        1,
        "only generated-bound outbox inserts should mirror to projection_events"
    );
    assert_eq!(projection_rows[0].0, bound_event_id);
    assert_eq!(projection_rows[0].1, "projection.bound");
    assert_eq!(projection_rows[0].2, "v1");
    assert_eq!(projection_rows[0].3, TEST_SCHEMA_HASH);
    assert_eq!(projection_rows[0].4, COTX_TENANT_A);

    let outbox_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = ANY($1)")
            .bind(vec![
                bound_event_id,
                unbound_event_id,
                schema_mismatch_event_id,
            ])
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(outbox_count.0, 3, "all outbox rows should exist");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_writer_funnel_runtime_setup_mirrors_generated_bound_emit() -> TestResult {
    use diport::{OutboxEmitter, OutboxEnvelopeParts};

    let (pg, deps) = setup_runtime_deps_with_projection_inputs(
        TEST_PROJECTION_INPUT_GENERATION,
        TEST_PROJECTION_INPUTS,
    )
    .await?;
    let emitter = deps.infra().emitter(fixed_clock());
    let event_id = unique_event_id("projection-runtime-bound");

    emitter
        .emit(
            make_entry(&event_id),
            OutboxEnvelopeParts::new(
                vocab::ContractBinding::from_static(
                    "test",
                    "projection.bound",
                    "v1",
                    TEST_SCHEMA_HASH,
                ),
                test_tenant(),
                subject_id(&event_id),
                actor_for(test_tenant()),
            ),
        )
        .await?;

    let pool = runtime_assertion_pool(pg.params()).await?;
    let binding_count: (i64,) = sqlx::query_as(
        r#"
        SELECT count(*)
        FROM projection_input_bindings
        WHERE contract_id = 'projection.bound'
          AND contract_version = 'v1'
          AND schema_hash = $1
          AND topic = 'test.event'
        "#,
    )
    .bind(TEST_SCHEMA_HASH)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        binding_count.0, 1,
        "PgRuntimeDeps::setup must refresh DB-side projection bindings"
    );

    let projection_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT event_id, contract_id, contract_version, schema_hash
        FROM projection_events
        WHERE event_id = $1
        "#,
    )
    .bind(&event_id)
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        projection_rows,
        vec![(
            event_id,
            "projection.bound".to_string(),
            "v1".to_string(),
            TEST_SCHEMA_HASH.to_string(),
        )],
        "runtime emitter must mirror generated-bound outbox facts to projection_events"
    );

    pool.close().await;
    deps.store_guard().shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_writer_funnel_serializes_lsn_with_commit_order() -> TestResult {
    use crate::cotx::TxCapability;
    use crate::projection_events::ProjectionWriteRegistry;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let registry = ProjectionWriteRegistry::from_generated(TEST_PROJECTION_INPUTS);
    let domain = unique_domain("projection-order");
    let first_event_id = unique_event_id("projection-order-first");
    let second_event_id = unique_event_id("projection-order-second");
    let first_entry = make_entry(&first_event_id);
    let second_entry = make_entry(&second_event_id);
    let first_env = make_test_env(&domain, "projection.bound");
    let second_env = make_test_env(&domain, "projection.bound");

    let pool_a = store.pool.clone();
    let pool_b = store.pool.clone();
    let (first_appended_tx, first_appended_rx) = tokio::sync::oneshot::channel();
    let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();
    let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();

    let first = tokio::spawn(async move {
        let mut tx = pool_a.begin().await?;
        let mut cap = TxCapability::from_transaction(&mut tx);
        let _outcome = append_outbox_with_projection(&mut cap, &first_entry, &first_env, &registry)
            .await
            .map_err(test_append_error)?;
        let _ = first_appended_tx.send(());
        release_first_rx.await.map_err(|err| {
            Box::new(std::io::Error::other(format!(
                "release channel closed: {err}"
            ))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        tx.commit().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    first_appended_rx.await?;

    let second = tokio::spawn(async move {
        let mut tx = pool_b.begin().await?;
        let mut cap = TxCapability::from_transaction(&mut tx);
        let _ = second_started_tx.send(());
        let _outcome =
            append_outbox_with_projection(&mut cap, &second_entry, &second_env, &registry)
                .await
                .map_err(test_append_error)?;
        tx.commit().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut second = second;

    second_started_rx.await?;
    let completed_before_first_commit =
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut second).await;
    assert!(
        completed_before_first_commit.is_err(),
        "second projection-bound append must wait for first transaction's append advisory lock"
    );

    release_first_tx
        .send(())
        .map_err(|()| std::io::Error::other("first transaction task exited before release"))?;
    first.await??;
    second.await??;

    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT event_id, id
        FROM projection_events
        WHERE event_id = ANY($1)
        ORDER BY id
        "#,
    )
    .bind(vec![first_event_id.clone(), second_event_id.clone()])
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(rows.len(), 2, "both bound events should be projected");
    assert_eq!(rows[0].0, first_event_id);
    assert_eq!(rows[1].0, second_event_id);
    assert!(
        rows[0].1 < rows[1].1,
        "projection LSN order must match commit order for concurrent bound writes"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_events_runtime_uses_fixed_functions_not_direct_table_privileges() -> TestResult
{
    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let event_id = unique_event_id("projection-fn");

    for sql in [
        "SELECT count(*) FROM projection_events",
        "INSERT INTO projection_events \
             (event_id, domain, aggregate_id, event_type, payload, contract_id, contract_version, schema_hash, metadata) \
         VALUES ('forbidden', 'test', 'agg', 'test.event', '\\x00'::bytea, 'projection.bound', 'v1', \
                 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', \
                 '{\"tenantId\":\"f47ac10b-58cc-4372-a567-0e02b2c3d479\"}'::jsonb)",
        "UPDATE projection_events SET domain = domain",
        "DELETE FROM projection_events",
    ] {
        let result = sqlx::query(sql).execute(&app.pool).await;
        assert!(
            result.is_err(),
            "rss_app must not have direct projection_events table privilege for: {sql}"
        );
    }

    for sql in [
        "SELECT count(*) FROM projection_input_bindings",
        "INSERT INTO projection_input_bindings \
             (contract_id, contract_version, schema_hash, topic) \
         VALUES ('projection.bound', 'v1', \
                 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', \
                 'test.event')",
        "UPDATE projection_input_bindings SET topic = topic",
        "DELETE FROM projection_input_bindings",
    ] {
        let result = sqlx::query(sql).execute(&app.pool).await;
        assert!(
            result.is_err(),
            "rss_app must not have direct projection_input_bindings table privilege for: {sql}"
        );
    }

    let entry = make_entry(&event_id);
    let env = make_test_env("test", "projection.bound");
    let metadata = env.metadata_json();
    let unbound_event_id = unique_event_id("projection-fn-unbound");
    let unbound_entry = make_entry(&unbound_event_id);
    let unbound_env = make_test_env("test", "projection.unbound");
    let unbound_metadata = unbound_env.metadata_json();
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = env.clone();
            let unbound_entry = unbound_entry.clone();
            let unbound_env = unbound_env.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                let _outcome = append_outbox(cap, &unbound_entry, &unbound_env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (lsn,): (i64,) = sqlx::query_as(
        r#"
        SELECT rss_append_projection_event(
            $1, 'test', $1, 'test.event', $2, NULL,
            'projection.bound', 'v1', $3, $4::jsonb, NULL, NULL
        )
        "#,
    )
    .bind(&event_id)
    .bind(b"payload".as_slice())
    .bind(TEST_SCHEMA_HASH)
    .bind(&metadata)
    .fetch_one(&app.pool)
    .await?;
    assert!(lsn > 0, "fixed append function must return projection lsn");

    let no_outbox_event_id = unique_event_id("projection-fn-no-outbox");
    let no_outbox_result = sqlx::query(
        r#"
        SELECT rss_append_projection_event(
            $1, 'test', $1, 'test.event', $2, NULL,
            'projection.bound', 'v1', $3, $4::jsonb, NULL, NULL
        )
        "#,
    )
    .bind(&no_outbox_event_id)
    .bind(b"payload".as_slice())
    .bind(TEST_SCHEMA_HASH)
    .bind(&metadata)
    .execute(&app.pool)
    .await;
    assert!(
        no_outbox_result.is_err(),
        "fixed append function must reject raw writes without a matching outbox row"
    );

    let unbound_result = sqlx::query(
        r#"
        SELECT rss_append_projection_event(
            $1, 'test', $1, 'test.event', $2, NULL,
            'projection.unbound', 'v1', $3, $4::jsonb, NULL, NULL
        )
        "#,
    )
    .bind(&unbound_event_id)
    .bind(b"payload".as_slice())
    .bind(TEST_SCHEMA_HASH)
    .bind(&unbound_metadata)
    .execute(&app.pool)
    .await;
    assert!(
        unbound_result.is_err(),
        "fixed append function must reject outbox rows absent from generated projection bindings"
    );

    let read_rows: Vec<(i64, String, String)> = sqlx::query_as(
        r#"
        SELECT id, event_id, metadata ->> 'tenantId'
        FROM rss_read_projection_events(0, 10)
        WHERE event_id = $1
        "#,
    )
    .bind(&event_id)
    .fetch_all(&app.pool)
    .await?;
    assert_eq!(read_rows, vec![(lsn, event_id, COTX_TENANT_A.to_string())]);

    for (label, sql) in [
        (
            "null-limit",
            "SELECT * FROM rss_read_projection_events(0, NULL::integer)",
        ),
        (
            "zero-limit",
            "SELECT * FROM rss_read_projection_events(0, 0)",
        ),
        (
            "too-large-limit",
            "SELECT * FROM rss_read_projection_events(0, 1001)",
        ),
        (
            "negative-after",
            "SELECT * FROM rss_read_projection_events(-1, 10)",
        ),
        (
            "null-after",
            "SELECT * FROM rss_read_projection_events(NULL::bigint, 10)",
        ),
    ] {
        let result = sqlx::query(sql).execute(&app.pool).await;
        assert!(
            result.is_err(),
            "rss_app direct projection read must reject invalid {label} at the fixed function boundary"
        );
    }

    for (label, tenant_id) in [
        ("invalid", "not-a-uuid"),
        ("nil", "00000000-0000-0000-0000-000000000000"),
        ("uppercase", "F47AC10B-58CC-4372-A567-0E02B2C3D479"),
    ] {
        let result = sqlx::query(
            r#"
            SELECT rss_append_projection_event(
                $1, 'test', $1, 'test.event', $2, NULL,
                'projection.bound', 'v1', $3, $4::jsonb, NULL, NULL
            )
            "#,
        )
        .bind(unique_event_id(&format!("projection-fn-{label}")))
        .bind(b"payload".as_slice())
        .bind(TEST_SCHEMA_HASH)
        .bind(serde_json::json!({ "tenantId": tenant_id }).to_string())
        .execute(&app.pool)
        .await;
        assert!(
            result.is_err(),
            "fixed append function must reject non-canonical tenantId case {label}"
        );
    }

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_active_pointer_promote_requires_exact_precondition_and_supports_rollback()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let raw_projection = format!("audit.session-projection-{}", uuid::Uuid::new_v4().simple());
    let v1 = projection_control_selector(&raw_projection, "v1");
    let v2 = projection_control_selector(&raw_projection, "v2");

    let store = std::sync::Arc::new(store);
    let status_receipt = projection_maintenance_receipt(
        authn::ProjectionMaintenanceAction::Status,
        v1.tenant(),
        v1.projection().as_str(),
    );
    let swap_receipt = projection_maintenance_receipt(
        authn::ProjectionMaintenanceAction::Swap,
        v1.tenant(),
        v1.projection().as_str(),
    );
    let status_control =
        crate::PgStore::projection_control(std::sync::Arc::clone(&store), &status_receipt);
    let swap_control =
        crate::PgStore::projection_control(std::sync::Arc::clone(&store), &swap_receipt);
    let source_high_water = status_control
        .status(&v1)
        .await?
        .source_high_water_lsn()
        .map(|lsn| lsn.get())
        .unwrap_or(0);
    let v1_high_water = source_high_water.max(10);
    let v2_high_water = source_high_water.max(20);
    insert_projection_shadow_checkpoint(&store, &v1, v1_high_water).await?;
    insert_projection_shadow_checkpoint(&store, &v2, v2_high_water).await?;
    assert!(status_control.status(&v1).await?.pointer().is_none());

    let first = swap_control
        .promote(&v1, crate::ProjectionPointerPrecondition::ExpectUnset)
        .await?;
    assert!(first.previous().is_none());
    assert_eq!(first.active().version().as_str(), "v1");
    assert_eq!(
        first.active().high_water_lsn(),
        Some(consistency::Lsn::new(v1_high_water))
    );

    let stale = swap_control
        .promote(&v2, crate::ProjectionPointerPrecondition::ExpectUnset)
        .await;
    assert!(matches!(
        stale,
        Err(crate::ProjectionControlError::PreconditionFailed)
    ));

    let second = swap_control
        .promote(
            &v2,
            crate::ProjectionPointerPrecondition::ExpectedActiveVersion(
                eventexec::ProjectionVersion::parse("v1")?,
            ),
        )
        .await?;
    assert_eq!(second.previous().map(|p| p.version().as_str()), Some("v1"));
    assert_eq!(second.active().version().as_str(), "v2");
    assert_eq!(
        second.active().high_water_lsn(),
        Some(consistency::Lsn::new(v2_high_water))
    );

    let rollback = swap_control
        .promote(
            &v1,
            crate::ProjectionPointerPrecondition::ExpectedActiveVersion(
                eventexec::ProjectionVersion::parse("v2")?,
            ),
        )
        .await?;
    assert_eq!(rollback.active().version().as_str(), "v1");
    assert_eq!(
        status_control
            .status(&v1)
            .await?
            .pointer()
            .map(|p| p.version().as_str()),
        Some("v1")
    );

    store.shutdown().await?;
    Ok(())
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
fn test_tenant_authority() -> Arc<TenantAuthority> {
    Arc::new(
        TenantAuthority::new(
            Arc::new(TestMac),
            MacKey::from_bytes(vec![0x42; 32]),
            3600,
            60,
            Arc::new(|| 1_700_000_000),
        )
        .expect("valid test tenant authority"),
    )
}

fn test_dlx_payload_protector() -> crate::DlxPayloadProtector {
    test_protector()
}

/// Fake publisher：记录调用次数，返回可控 Result。
struct RecordingPublisher {
    result: fn() -> Result<(), PublisherError>,
    calls: Arc<Mutex<u32>>,
}

impl RecordingPublisher {
    fn always_ok() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || Ok(()),
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    fn always_transient() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || {
                    Err(PublisherError::transient(std::io::Error::other(
                        "fake transient publish error",
                    )))
                },
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    fn always_permanent() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || {
                    Err(PublisherError::permanent(std::io::Error::other(
                        "fake permanent publish error",
                    )))
                },
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl Publisher for RecordingPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
        #[allow(clippy::unwrap_used)]
        // reason: 测试内部 Mutex 不存在 poisoning 来源（无 panic 在 lock 持有期间），item-level carve-out。
        {
            *self.calls.lock().unwrap() += 1;
        }
        (self.result)()
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

fn make_pg_outbox(store: &PgStore, pub_result_fn: fn() -> Result<(), PublisherError>) -> PgOutbox {
    // 临时构造 RecordingPublisher（calls 丢弃；调用方只需验证 DB 状态时用这个）
    let pub_ = RecordingPublisher {
        result: pub_result_fn,
        calls: Arc::new(Mutex::new(0)),
    };
    make_pg_outbox_with_publisher(store, pub_)
}

fn make_pg_outbox_with_publisher(
    store: &PgStore,
    publisher: impl Publisher + Sync + 'static,
) -> PgOutbox {
    PgOutbox::new(
        store,
        DynPublisher::new_box(publisher),
        test_tenant_authority(),
        test_dlx_payload_protector(),
    )
}

/// Conformance publisher：记录 broker-visible message_id，并按脚本返回 publish 结果。
struct ConformancePublisher {
    mode: eventconf::PublishMode,
    messages: Arc<Mutex<Vec<String>>>,
}

impl ConformancePublisher {
    fn new(mode: eventconf::PublishMode) -> (Self, Arc<Mutex<Vec<String>>>) {
        let messages = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                mode,
                messages: Arc::clone(&messages),
            },
            messages,
        )
    }
}

impl Publisher for ConformancePublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.event_id().as_str().to_string());
        match self.mode {
            eventconf::PublishMode::Ok => Ok(()),
            eventconf::PublishMode::Transient => Err(PublisherError::transient(
                std::io::Error::other("eventing conformance transient publish"),
            )),
            eventconf::PublishMode::Permanent => Err(PublisherError::permanent(
                std::io::Error::other("eventing conformance permanent publish"),
            )),
            _ => Err(PublisherError::permanent(std::io::Error::other(
                "eventing conformance unknown publish mode",
            ))),
        }
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

struct CapturedPublishRequestPublisher {
    requests: Arc<Mutex<Vec<PublishRequest>>>,
}

impl CapturedPublishRequestPublisher {
    fn new() -> (Self, Arc<Mutex<Vec<PublishRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                requests: Arc::clone(&requests),
            },
            requests,
        )
    }
}

impl Publisher for CapturedPublishRequestPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CommonBrokerEnvelope {
    event_id: String,
    key: String,
    topic: String,
    payload: Vec<u8>,
    headers: BTreeMap<String, String>,
}

fn common_transport_headers(metadata: &EnvelopeMetadata) -> BTreeMap<String, String> {
    metadata
        .iter_transport_headers()
        .filter(|(key, _)| *key != KEY_TENANT_AUTHORITY)
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn assert_no_persisted_only_broker_headers(headers: &BTreeMap<String, String>) {
    for key in [
        KEY_TENANT_AUTHORITY,
        KEY_SUBJECT_ID,
        KEY_ACTOR,
        KEY_PRINCIPAL,
        "causation_id",
        "aggregate_id",
        "contract_id",
    ] {
        assert!(
            !headers.contains_key(key),
            "broker common envelope must not leak persisted-only header {key}"
        );
    }
}

fn relay_common_envelope(request: &PublishRequest) -> CommonBrokerEnvelope {
    assert!(
        request.metadata().get(KEY_TENANT_AUTHORITY).is_some(),
        "tenantAuthority is relay-only and must be signed before exclusion"
    );
    let headers = common_transport_headers(request.metadata());
    assert_no_persisted_only_broker_headers(&headers);
    CommonBrokerEnvelope {
        event_id: request.event_id().as_str().to_string(),
        key: request.event_id().as_str().to_string(),
        topic: request.topic().as_str().to_string(),
        payload: request.payload().to_vec(),
        headers,
    }
}

#[derive(Debug)]
struct DebeziumModeledOutboxLog {
    event_id: String,
    topic: String,
    payload: Vec<u8>,
    tenant_id: String,
    contract_version: String,
    schema_hash: String,
    occurred_at: String,
    aggregate_id: String,
    contract_id: String,
    metadata: serde_json::Value,
}

impl DebeziumModeledOutboxLog {
    fn common_envelope(&self) -> CommonBrokerEnvelope {
        let headers = BTreeMap::from([
            (KEY_TENANT_ID.to_string(), self.tenant_id.clone()),
            (
                KEY_SCHEMA_VERSION.to_string(),
                self.contract_version.clone(),
            ),
            (KEY_SCHEMA_HASH.to_string(), self.schema_hash.clone()),
            (KEY_OCCURRED_AT.to_string(), self.occurred_at.clone()),
        ]);
        assert_no_persisted_only_broker_headers(&headers);
        CommonBrokerEnvelope {
            event_id: self.event_id.clone(),
            key: self.event_id.clone(),
            topic: self.topic.clone(),
            payload: self.payload.clone(),
            headers,
        }
    }
}

async fn modeled_debezium_eventrouter_outbox_log(
    store: &PgStore,
    event_id: &str,
) -> Result<DebeziumModeledOutboxLog, sqlx::Error> {
    let row: (
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
        String,
        String,
        String,
        serde_json::Value,
    ) = sqlx::query_as(
        r#"
        SELECT event_id, topic, payload, tenant_id::text, contract_version, schema_hash,
               occurred_at, aggregate_id, contract_id, metadata
        FROM outbox_log
        WHERE event_id = $1
        "#,
    )
    .bind(event_id)
    .fetch_one(&store.pool)
    .await?;
    Ok(DebeziumModeledOutboxLog {
        event_id: row.0,
        topic: row.1,
        payload: row.2,
        tenant_id: row.3,
        contract_version: row.4,
        schema_hash: row.5,
        occurred_at: row.6,
        aggregate_id: row.7,
        contract_id: row.8,
        metadata: row.9,
    })
}

async fn conf_seed_pending(
    store: &PgStore,
    event_id: String,
    domain: String,
) -> Result<(), String> {
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = make_entry(&event_id);
            let env = make_test_env(&domain, "eventing-conf");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await
        .map_err(|e| format!("{e:?}"))
}

async fn conf_relay(
    store: &PgStore,
    event_id: String,
    mode: eventconf::PublishMode,
) -> Result<eventconf::RelayObservation, String> {
    let (publisher, messages) = ConformancePublisher::new(mode);
    let outbox = make_pg_outbox_with_publisher(store, publisher);
    let pending = pending_entry_for_event(store, &event_id).await?;
    let disposition = outbox.relay(&pending).await.map_err(|e| format!("{e:?}"))?;
    let messages = messages.lock().unwrap_or_else(|e| e.into_inner());
    let message_id = messages.last().cloned();
    let publish_count = messages.len() as u64;
    Ok(eventconf::RelayObservation {
        disposition: match disposition {
            Disposition::Ack => eventconf::RelayDisposition::Ack,
            Disposition::Requeue => eventconf::RelayDisposition::Requeue,
            Disposition::Reject => eventconf::RelayDisposition::Reject,
            _ => {
                return Err("unknown relay disposition".to_string());
            }
        },
        message_id,
        publish_count,
    })
}

async fn conf_poll_pending(store: &PgStore, domain: String) -> Result<Vec<String>, String> {
    let outbox = make_pg_outbox(store, || Ok(()));
    outbox
        .poll_pending(&domain, 100)
        .await
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| entry.idem_key().as_str().to_string())
                .collect()
        })
        .map_err(|e| format!("{e:?}"))
}

async fn conf_outbox_state(
    store: &PgStore,
    event_id: String,
) -> Result<eventconf::OutboxState, String> {
    let row: Option<(String, i32, bool)> = sqlx::query_as(
        "SELECT status, retry_count, retry_after IS NOT NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_optional(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    let dlx_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await
            .map_err(|e| format!("{e:?}"))?;
    Ok(match row {
        Some((status, retry_count, retry_after_set)) => eventconf::OutboxState {
            exists: true,
            status: conf_outbox_status(&status)?,
            retry_count: i64::from(retry_count),
            retry_after_set,
            dlx_count: dlx_count.0 as u64,
        },
        None => eventconf::OutboxState {
            exists: false,
            status: eventconf::OutboxStatus::Absent,
            retry_count: 0,
            retry_after_set: false,
            dlx_count: dlx_count.0 as u64,
        },
    })
}

fn conf_outbox_status(status: &str) -> Result<eventconf::OutboxStatus, String> {
    match status {
        crate::outbox::STATUS_PENDING => Ok(eventconf::OutboxStatus::Pending),
        crate::outbox::STATUS_PUBLISHING => Ok(eventconf::OutboxStatus::Publishing),
        crate::outbox::STATUS_PUBLISHED => Ok(eventconf::OutboxStatus::Published),
        crate::outbox::STATUS_DLX => Ok(eventconf::OutboxStatus::Dlx),
        other => Err(format!("unknown outbox status {other:?}")),
    }
}

async fn conf_backdate_publishing(store: &PgStore, event_id: String) -> Result<(), String> {
    sqlx::query(
        "UPDATE outbox \
         SET status='publishing', lease_token = gen_random_uuid(), \
             created_at = now() - make_interval(secs => $1), \
             updated_at = now() - make_interval(secs => $1) \
         WHERE event_id = $2",
    )
    .bind(crate::outbox::LEASE_TTL_SECONDS + 10)
    .bind(&event_id)
    .execute(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

async fn conf_sample_backlog(
    store: &PgStore,
    domain: String,
) -> Result<eventconf::BacklogSample, String> {
    let outbox = make_pg_outbox(store, || Ok(()));
    outbox
        .sample_backlog(&domain)
        .await
        .map(|samples| {
            let summary = summarize_backlog(&samples);
            eventconf::BacklogSample {
                depth: summary.depth(),
                oldest_age_seconds: summary.oldest_age_seconds(),
            }
        })
        .map_err(|e| format!("{e:?}"))
}

async fn conf_sweep_outbox(store: &PgStore, retain_seconds: u64) -> Result<u64, String> {
    let outbox = make_pg_outbox(store, || Ok(()));
    outbox
        .sweep(retain_seconds)
        .await
        .map_err(|e| format!("{e:?}"))
}

async fn conf_seed_terminal(
    store: &PgStore,
    event_id: String,
    domain: String,
    status: eventconf::TerminalStatus,
) -> Result<(), String> {
    conf_seed_pending(store, event_id.clone(), domain).await?;
    let status = match status {
        eventconf::TerminalStatus::PublishedOld => "published",
        eventconf::TerminalStatus::DlxOld => "dlx",
        _ => "dlx",
    };
    set_outbox_terminal_for_test(store, &event_id, status, 7200)
        .await
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn eventing_conformance_outbox_enrolls_postgres() -> TestResult {
    let _sweep_guard = OUTBOX_SWEEP_TEST_LOCK.lock().await;
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let domain = unique_domain("eventing-conf-domain");
    let other_domain = unique_domain("eventing-conf-other-domain");
    let event_id = unique_event_id("eventing-conf-outbox");

    eventconf::assert_outbox_relay_conformance(eventconf::OutboxRelayCase {
        ids: eventconf::EventingIds::new(
            event_id.clone(),
            event_id.clone(),
            "eventing-conf-group",
            "lease-a",
        ),
        domain,
        other_domain,
        max_attempts: MAX_PUBLISH_ATTEMPTS as u32,
        seed_pending: Box::new(|args| {
            Box::pin(conf_seed_pending(&store, args.event_id, args.domain))
        }),
        relay: Box::new(|args| Box::pin(conf_relay(&store, args.event_id, args.mode))),
        poll_pending: Box::new(|args| Box::pin(conf_poll_pending(&store, args.domain))),
        state: Box::new(|args| Box::pin(conf_outbox_state(&store, args.event_id))),
        backdate_publishing: Box::new(|args| {
            Box::pin(conf_backdate_publishing(&store, args.event_id))
        }),
        sample_backlog: Box::new(|args| Box::pin(conf_sample_backlog(&store, args.domain))),
        sweep: Box::new(|retain_seconds| Box::pin(conf_sweep_outbox(&store, retain_seconds))),
        seed_terminal: Box::new(|args| {
            Box::pin(conf_seed_terminal(
                &store,
                args.event_id,
                args.domain,
                args.status,
            ))
        }),
    })
    .await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn outbox_relay_and_cdc_envelope_parity_conformance() -> TestResult {
    use consistency::PartitionKey;
    use diport::EnvelopeCausationId;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("relay-cdc-parity");
    let tenant = test_tenant();
    let subject = "parity-subject-opaque";
    let entry = EventEntry::new(
        EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        reviewed_payload(br#"{"sessionId":"parity"}"#),
    );
    let env = OutboxEnvelope::new(
        "identity".to_string(),
        SESSION_CREATED_TOPIC.to_string(),
        OutboxMetadata::new(expected_occurred_at(), tenant, session_contract())
            .with_subject_id(subject_id(subject))
            .with_actor(actor_for(tenant)),
    )
    .with_partition_key_opt(Some(PartitionKey::parse("tenant-7:session-9").unwrap()))
    .with_causation_id_opt(Some(
        EnvelopeCausationId::from_opaque("cause-parity-1645").unwrap(),
    ));

    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = env.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    {
        let mut cap = crate::cotx::TxCapability::from_transaction(&mut tx);
        let _outcome = append_outbox_log(&mut cap, &entry, &env, subject).await?;
    }
    tx.commit().await?;

    let (relay_fingerprint, cdc_fingerprint): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT o.fact_fingerprint, l.fact_fingerprint \
         FROM outbox o JOIN outbox_log l USING (event_id) WHERE o.event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        relay_fingerprint, cdc_fingerprint,
        "mutable and CDC modes must share one canonical fingerprint"
    );

    let (publisher, captured_requests) = CapturedPublishRequestPublisher::new();
    let outbox = make_pg_outbox_with_publisher(&store, publisher);
    let pending = pending_entry_for_event(&store, &event_id)
        .await
        .map_err(std::io::Error::other)?;
    let disposition = outbox.relay(&pending).await?;
    assert_eq!(disposition, Disposition::Ack);

    let relay_request = {
        let mut requests = captured_requests.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            requests.len(),
            1,
            "relay should publish the logical fact exactly once"
        );
        requests
            .pop()
            .ok_or_else(|| std::io::Error::other("missing captured relay publish request"))?
    };
    let relay_envelope = relay_common_envelope(&relay_request);

    let cdc_row = modeled_debezium_eventrouter_outbox_log(&store, &event_id).await?;
    assert_eq!(cdc_row.aggregate_id, subject, "CDC aggregate_id");
    assert_ne!(
        cdc_row.aggregate_id, "tenant-7:session-9",
        "CDC aggregate_id must not be the relay partition key"
    );
    assert_eq!(cdc_row.contract_id, SESSION_CREATED_TOPIC);
    assert_eq!(
        cdc_row
            .metadata
            .get(KEY_SUBJECT_ID)
            .and_then(serde_json::Value::as_str),
        Some(subject),
        "subjectId stays persisted in metadata"
    );
    assert!(
        cdc_row.metadata.get(KEY_ACTOR).is_some(),
        "actor stays persisted in metadata"
    );
    assert!(cdc_row.metadata.get(KEY_TRACE).is_none());
    assert!(cdc_row.metadata.get(KEY_CORRELATION).is_none());
    assert_eq!(
        cdc_row
            .metadata
            .get(KEY_OCCURRED_AT)
            .and_then(serde_json::Value::as_i64),
        Some(expected_occurred_at())
    );

    let cdc_envelope = cdc_row.common_envelope();
    assert_eq!(
        relay_envelope, cdc_envelope,
        "relay PublishRequest and modeled Debezium EventRouter output must share the common broker envelope"
    );

    store.shutdown().await?;
    Ok(())
}

fn conf_lease_for(leases: &Arc<Mutex<HashMap<String, LeaseToken>>>, alias: String) -> LeaseToken {
    let mut guard = leases.lock().unwrap_or_else(|e| e.into_inner());
    guard.entry(alias).or_insert_with(LeaseToken::mint).clone()
}

async fn conf_try_claim(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<eventconf::InboxSeen, String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .try_claim(&ctx, &key, &lease)
        .await
        .map(|seen| match seen {
            SeenState::Fresh => eventconf::InboxSeen::Fresh,
            SeenState::Duplicate => eventconf::InboxSeen::Duplicate,
            _ => eventconf::InboxSeen::Duplicate,
        })
        .map_err(|e| format!("{e:?}"))
}

async fn conf_extend(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<eventconf::LeaseOutcome, String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .extend(&ctx, &key, &lease)
        .await
        .map(|outcome| match outcome {
            consistency::LeaseOutcome::Held => eventconf::LeaseOutcome::Held,
            consistency::LeaseOutcome::Lost => eventconf::LeaseOutcome::Lost,
            _ => eventconf::LeaseOutcome::Lost,
        })
        .map_err(|e| format!("{e:?}"))
}

async fn conf_commit(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<eventconf::LeaseOutcome, String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .commit(&ctx, &key, &lease)
        .await
        .map(|outcome| match outcome {
            consistency::LeaseOutcome::Held => eventconf::LeaseOutcome::Held,
            consistency::LeaseOutcome::Lost => eventconf::LeaseOutcome::Lost,
            _ => eventconf::LeaseOutcome::Lost,
        })
        .map_err(|e| format!("{e:?}"))
}

async fn conf_release(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<(), String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .release(&ctx, &key, &lease)
        .await
        .map_err(|e| format!("{e:?}"))
}

async fn conf_backdate_claim(store: &PgStore, key: String, group: String) -> Result<(), String> {
    let ctx = test_inbox_ctx(&group);
    sqlx::query(
        "UPDATE inbox_receipts \
         SET claimed_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(crate::inbox::INBOX_LEASE_TTL_SECONDS + 10)
    .bind(ctx.tenant_id().to_string())
    .bind(&key)
    .bind(&group)
    .execute(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn eventing_conformance_inbox_enrolls_postgres() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let event_id = unique_event_id("eventing-conf-inbox");
    let group = unique_domain("eventing-conf-inbox-group");
    let group_b = unique_domain("eventing-conf-inbox-group-b");
    let leases: Arc<Mutex<HashMap<String, LeaseToken>>> = Arc::new(Mutex::new(HashMap::new()));

    let try_leases = Arc::clone(&leases);
    let extend_leases = Arc::clone(&leases);
    let commit_leases = Arc::clone(&leases);
    let release_leases = Arc::clone(&leases);
    eventconf::assert_inbox_conformance(eventconf::InboxConformanceCase {
        ids: eventconf::EventingIds::new(event_id.clone(), event_id.clone(), group, "lease-a"),
        second_group: group_b,
        try_claim: Box::new(|args| {
            Box::pin(conf_try_claim(
                &store,
                &try_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        extend: Box::new(|args| {
            Box::pin(conf_extend(
                &store,
                &extend_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        commit: Box::new(|args| {
            Box::pin(conf_commit(
                &store,
                &commit_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        release: Box::new(|args| {
            Box::pin(conf_release(
                &store,
                &release_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        backdate_claim: Box::new(|args| {
            Box::pin(conf_backdate_claim(
                &store,
                args.inbox_key,
                args.consumer_group,
            ))
        }),
    })
    .await?;

    store.shutdown().await?;
    Ok(())
}

struct ConformanceAcker {
    actions: Mutex<Vec<AckAction>>,
}

impl ConformanceAcker {
    fn new() -> (Arc<Self>, Box<DynAcker<'static>>) {
        let acker = Arc::new(Self {
            actions: Mutex::new(Vec::new()),
        });
        struct ArcAcker(Arc<ConformanceAcker>);
        impl Acker for ArcAcker {
            async fn settle(&self, action: AckAction) -> Result<(), diport::AckError> {
                self.0
                    .actions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(action);
                Ok(())
            }
        }
        (Arc::clone(&acker), DynAcker::new_box(ArcAcker(acker)))
    }

    fn exactly_one_action(&self) -> Result<AckAction, String> {
        let actions = self.actions.lock().unwrap_or_else(|e| e.into_inner());
        match actions.as_slice() {
            [action] => Ok(*action),
            [] => Err("missing settle action".to_string()),
            many => Err(format!(
                "expected exactly one settle action, got {}",
                many.len()
            )),
        }
    }
}

struct FailingDlx {
    captured: Arc<Mutex<Option<DeadLetterRecord>>>,
}

impl FailingDlx {
    fn new(captured: Arc<Mutex<Option<DeadLetterRecord>>>) -> Self {
        Self { captured }
    }
}

impl DeadLetterStore for FailingDlx {
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        *self.captured.lock().unwrap_or_else(|e| e.into_inner()) = Some(record);
        Err(DeadLetterStoreError::new(std::io::Error::other(
            "eventing conformance dlx failure",
        )))
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

#[allow(clippy::expect_used)]
fn conf_consumer_metadata(event_id: &str) -> EnvelopeMetadata {
    let authority = test_tenant_authority();
    let tenant = test_tenant();
    let token = authority
        .sign(TenantAuthorityBinding::new(
            tenant,
            "eventing-conf-consumer-domain",
            "eventing-conf-consumer-contract",
            "eventing.conf.consumer",
            event_id,
        ))
        .expect("tenant authority test signing cannot fail");
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(KEY_TENANT_ID, COTX_TENANT_A);
    metadata.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
    metadata.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
    metadata.insert_wire_pair(KEY_SCHEMA_HASH, TEST_SCHEMA_HASH);
    metadata
}

fn conf_delivery_stream(event_id: &str) -> (DeliveryStream, Arc<ConformanceAcker>) {
    let (acker, boxed) = ConformanceAcker::new();
    let message = Message::new_with_metadata(
        event_id,
        b"eventing-conformance-payload".to_vec(),
        conf_consumer_metadata(event_id),
    );
    (
        Box::pin(futures::stream::iter(vec![Delivery::new(message, boxed)])),
        acker,
    )
}

fn conf_consumer_meta(group: &str) -> ConsumerMeta {
    ConsumerMeta::new(
        "eventing-conf-consumer-domain",
        "eventing-conf-consumer-domain",
        "eventing-conf-consumer-contract",
        "eventing.conf.consumer",
        group,
        test_tenant_authority(),
    )
    .with_expected_schema("v1", TEST_SCHEMA_HASH)
}

#[allow(clippy::unwrap_used)]
fn conf_consumer_ctx(group: &str) -> InboxReceiptContext {
    InboxReceiptContext::new(
        test_tenant(),
        ConsumerGroup::parse(group).unwrap(),
        "eventing-conf-consumer-domain",
        "eventing.conf.consumer",
        "eventing-conf-consumer-contract",
        "v1",
        TEST_SCHEMA_HASH,
        None,
        None,
    )
    .unwrap()
}

fn conf_expected_dlx() -> eventconf::DlxFields {
    eventconf::DlxFields {
        source_kind: "consumer".to_string(),
        domain: "eventing-conf-consumer-domain".to_string(),
        contract_id: "eventing-conf-consumer-contract".to_string(),
        topic: "eventing.conf.consumer".to_string(),
        num_attempts: MAX_REDELIVERY,
    }
}

fn conf_lease_cfg() -> LeaseConfig {
    LeaseConfig::from_ttl(std::time::Duration::from_secs(
        crate::inbox::INBOX_LEASE_TTL_SECONDS as u64,
    ))
}

fn conf_requeue_handler(
    calls: Arc<AtomicU32>,
) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
    move |_message| {
        let calls = Arc::clone(&calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            HandleResult::requeue(consistency::EngineError::new(
                consistency::EngineErrorKind::Transient,
            ))
        })
    }
}

fn conf_ack_handler(
    calls: Arc<AtomicU32>,
) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
    move |_message| {
        let calls = Arc::clone(&calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            HandleResult::ack()
        })
    }
}

fn action_to_settle(action: AckAction) -> Result<eventconf::SettleAction, String> {
    match action {
        AckAction::Ack => Ok(eventconf::SettleAction::Ack),
        AckAction::Requeue => Ok(eventconf::SettleAction::Requeue),
        AckAction::Reject => Ok(eventconf::SettleAction::Reject),
        _ => Err("unknown ack action".to_string()),
    }
}

fn conf_settle_action(acker: &ConformanceAcker) -> Result<eventconf::SettleAction, String> {
    action_to_settle(acker.exactly_one_action()?)
}

fn conf_dlx_fields_from_record(record: &DeadLetterRecord) -> eventconf::DlxFields {
    eventconf::DlxFields {
        source_kind: record.source().as_str().to_string(),
        domain: record.producer_domain().to_string(),
        contract_id: record.contract_id().to_string(),
        topic: record.topic().to_string(),
        num_attempts: record.num_attempts(),
    }
}

async fn conf_inbox_status(
    store: &PgStore,
    event_id: &str,
    group: &str,
) -> Result<Option<String>, String> {
    let ctx = test_inbox_ctx(group);
    sqlx::query_as::<_, (String,)>(
        "SELECT status FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(event_id)
    .bind(group)
    .fetch_optional(&store.pool)
    .await
    .map(|row| row.map(|(status,)| status))
    .map_err(|e| format!("{e:?}"))
}

async fn conf_dlx_fields(
    store: &PgStore,
    event_id: &str,
) -> Result<(u64, eventconf::DlxFields), String> {
    let row: Option<(String, String, String, String, i32)> = sqlx::query_as(
        "SELECT source_kind, producer_domain, contract_id, topic, num_attempts \
         FROM dead_letter WHERE message_id = $1 ORDER BY last_attempt_at DESC LIMIT 1",
    )
    .bind(event_id)
    .fetch_optional(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    let Some((source_kind, domain, contract_id, topic, num_attempts)) = row else {
        return Ok((
            0,
            eventconf::DlxFields {
                source_kind: String::new(),
                domain: String::new(),
                contract_id: String::new(),
                topic: String::new(),
                num_attempts: 0,
            },
        ));
    };
    Ok((
        1,
        eventconf::DlxFields {
            source_kind,
            domain,
            contract_id,
            topic,
            num_attempts: u32::try_from(num_attempts).unwrap_or(0),
        },
    ))
}

async fn conf_duplicate_delivery(
    store: &PgStore,
    event_id: String,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let key = IdemKey::parse(&event_id).map_err(|e| format!("{e:?}"))?;
    let meta = conf_consumer_meta(&group);
    let ctx = conf_consumer_ctx(&group);
    let lease = LeaseToken::mint();
    let inbox = store.inbox();
    inbox
        .try_claim(&ctx, &key, &lease)
        .await
        .map_err(|e| format!("{e:?}"))?;
    inbox
        .commit(&ctx, &key, &lease)
        .await
        .map_err(|e| format!("{e:?}"))?;

    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream(&event_id);
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector())),
        meta,
        conf_ack_handler(Arc::clone(&calls)),
        conf_lease_cfg(),
    )
    .await;

    let (_, dlx) = conf_dlx_fields(store, &event_id).await?;
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 1,
        committed: false,
        released: false,
        dlx_count: 0,
        settle: conf_settle_action(&acker)?,
        num_attempts: dlx.num_attempts,
        source_kind: dlx.source_kind,
        domain: dlx.domain,
        contract_id: dlx.contract_id,
        topic: dlx.topic,
    })
}

async fn conf_poison_delivery(
    store: &PgStore,
    event_id: String,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream(&event_id);
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector())),
        conf_consumer_meta(&group),
        conf_requeue_handler(Arc::clone(&calls)),
        conf_lease_cfg(),
    )
    .await;

    let (dlx_count, dlx) = conf_dlx_fields(store, &event_id).await?;
    let committed = conf_inbox_status(store, &event_id, &group).await? == Some("done".to_string());
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 1,
        committed,
        released: false,
        dlx_count,
        settle: conf_settle_action(&acker)?,
        num_attempts: dlx.num_attempts,
        source_kind: dlx.source_kind,
        domain: dlx.domain,
        contract_id: dlx.contract_id,
        topic: dlx.topic,
    })
}

async fn conf_dlx_failure(
    store: &PgStore,
    event_id: String,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream(&event_id);
    let captured = Arc::new(Mutex::new(None));
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        DynDeadLetterStore::new_box(FailingDlx::new(Arc::clone(&captured))),
        conf_consumer_meta(&group),
        conf_requeue_handler(Arc::clone(&calls)),
        conf_lease_cfg(),
    )
    .await;

    let released = conf_inbox_status(store, &event_id, &group).await?.is_none();
    let captured = captured
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or_else(|| "missing failed dlx write record".to_string())?;
    let dlx = conf_dlx_fields_from_record(&captured);
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 1,
        committed: false,
        released,
        dlx_count: 0,
        settle: conf_settle_action(&acker)?,
        num_attempts: dlx.num_attempts,
        source_kind: dlx.source_kind,
        domain: dlx.domain,
        contract_id: dlx.contract_id,
        topic: dlx.topic,
    })
}

async fn conf_malformed_delivery(
    store: &PgStore,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream("");
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector())),
        conf_consumer_meta(&group),
        conf_ack_handler(Arc::clone(&calls)),
        conf_lease_cfg(),
    )
    .await;

    let expected = conf_expected_dlx();
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 0,
        committed: false,
        released: false,
        dlx_count: 0,
        settle: conf_settle_action(&acker)?,
        num_attempts: expected.num_attempts,
        source_kind: expected.source_kind,
        domain: expected.domain,
        contract_id: expected.contract_id,
        topic: expected.topic,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn eventing_conformance_consumer_enrolls_postgres() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let base_id = unique_event_id("eventing-conf-consumer");
    let group = unique_domain("eventing-conf-consumer-group");

    eventconf::assert_consumer_conformance(eventconf::ConsumerConformanceCase {
        ids: eventconf::EventingIds::new(
            base_id.clone(),
            base_id.clone(),
            group.clone(),
            "lease-a",
        ),
        expected_dlx: conf_expected_dlx(),
        duplicate_delivery: Box::new(|| {
            Box::pin(conf_duplicate_delivery(
                &store,
                format!("{base_id}-duplicate"),
                group.clone(),
            ))
        }),
        poison_delivery: Box::new(|| {
            Box::pin(conf_poison_delivery(
                &store,
                format!("{base_id}-poison"),
                group.clone(),
            ))
        }),
        dlx_failure: Box::new(|| {
            Box::pin(conf_dlx_failure(
                &store,
                format!("{base_id}-dlx-failure"),
                group.clone(),
            ))
        }),
        malformed_message_id: Box::new(|| Box::pin(conf_malformed_delivery(&store, group.clone()))),
    })
    .await?;

    store.shutdown().await?;
    Ok(())
}

// ── T1: INVARIANT OUTBOX-ATOMIC-IDEM-01：回滚→无 entry ──────────────────────

/// INVARIANT: OUTBOX-ATOMIC-IDEM-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
/// L1 原子性：append_outbox 在事务内，业务返回 Err → 回滚 → outbox 无该行。
#[tokio::test(flavor = "multi_thread")]
async fn t1_rollback_leaves_no_outbox_entry() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t1");
    let entry = make_entry(&event_id);
    let env = make_envelope("t1-domain", &event_id);

    // 事务内 append_outbox，然后返回 Err → 回滚。
    let result = store
        .run_global_transaction::<_, (), sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract())
                    .with_subject_id(subject_id(event_id.as_str())),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                // 强制回滚。
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(result.is_err(), "should have rolled back");

    // 验证 outbox 无该行。
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        count.0, 0,
        "rollback must leave no outbox entry (OUTBOX-ATOMIC-IDEM-01)"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T2: 提交→恰 1 行 pending（T1 anti-vacuity 配对）─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t2_commit_creates_exactly_one_pending_row() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t2");
    let entry = make_entry(&event_id);
    let env = make_envelope("t2-domain", &event_id);

    // 事务内 append_outbox + Ok → commit。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract())
                    .with_subject_id(subject_id(event_id.as_str())),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 验证恰 1 行，status=pending，字段正确。
    let row: (i64, String, String, String) = sqlx::query_as(
        "SELECT count(*), status, domain, topic FROM outbox WHERE event_id = $1 GROUP BY status, domain, topic",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;

    assert_eq!(row.0, 1, "should have exactly 1 row");
    assert_eq!(row.1, "pending", "status should be pending");
    assert_eq!(row.2, "t2-domain", "domain should match");
    assert_eq!(row.3, "test.event", "topic should match");

    store.shutdown().await?;
    Ok(())
}

// ── T3: relay→published（Ack）────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t3_relay_ok_publishes_and_acks() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t3");
    let entry = make_entry(&event_id);
    // t3 仅验 relay 路径、不断言 metadata；用 make_test_env（无 subject_id），避免 make_envelope 的
    // subject_id 在下方闭包重建时被丢弃的冗余（#1194 review F3）。
    let env = make_test_env("t3-domain", "contract-1");

    // seed: 1 行 pending。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract()),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, calls) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_with_publisher(&store, pub_);

    let pending = pending_entry_for_event(&store, &event_id).await?;
    let disposition = outbox.relay(&pending).await?;
    assert_eq!(disposition, Disposition::Ack, "should Ack on publish Ok");

    // DB 状态 published。
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    // publisher 确实被调用了一次。
    #[allow(clippy::unwrap_used)]
    let call_count = *calls.lock().unwrap();
    assert_eq!(call_count, 1, "publisher should be called once");

    store.shutdown().await?;
    Ok(())
}

// ── T4: relay→pending+retry_after（Requeue）──────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t4_relay_err_requeues_with_retry_after() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t4");
    let entry = make_entry(&event_id);

    // seed: 1 行 pending，retry_count=0。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "t4-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract()),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, _) = RecordingPublisher::always_transient();
    let outbox = make_pg_outbox_with_publisher(&store, pub_);

    let pending = pending_entry_for_event(&store, &event_id).await?;
    let disposition = outbox.relay(&pending).await?;
    assert_eq!(
        disposition,
        Disposition::Requeue,
        "should Requeue on publish Err"
    );

    // DB 状态回 pending，retry_count=1，retry_after 非空且在将来，lease_token NULL。
    let row: (String, i32, bool, bool) = sqlx::query_as(
        r#"SELECT status, retry_count,
                  retry_after IS NOT NULL AS has_retry_after,
                  lease_token IS NULL     AS lease_cleared
           FROM outbox WHERE event_id = $1"#,
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;

    assert_eq!(row.0, "pending", "status should be pending after requeue");
    assert_eq!(row.1, 1, "retry_count should be incremented");
    assert!(row.2, "retry_after should be set");
    assert!(row.3, "lease_token should be cleared");

    // retry_after 在当前时间之后（退避，不应立即重试）。
    let future_check: (bool,) =
        sqlx::query_as("SELECT retry_after > now() FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(future_check.0, "retry_after should be in the future");

    // 退避负向：retry_after 在将来 → poll_pending 本轮不应重新捞回该行（L2 退避可靠性闭环）。
    let re = outbox.poll_pending("t4-domain", 10).await?;
    assert!(
        !re.iter().any(|e| e.idem_key().as_str() == event_id),
        "requeued entry must not be re-polled within backoff window"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T5: relay→dlx（Reject）──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t5_relay_err_at_budget_exhaustion_dlxes() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t5");
    let entry = make_entry(&event_id);

    // seed: 1 行 pending，手动置 retry_count=MAX-1。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "t5-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract()),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 直接 UPDATE retry_count 到 MAX-1（seed entry + sqlx query）。
    sqlx::query("UPDATE outbox SET retry_count = $1 WHERE event_id = $2")
        .bind(MAX_PUBLISH_ATTEMPTS - 1)
        .bind(&event_id)
        .execute(&store.pool)
        .await?;

    let (pub_, _) = RecordingPublisher::always_transient();
    let outbox = make_pg_outbox_with_publisher(&store, pub_);

    let pending = pending_entry_for_event(&store, &event_id).await?;
    let disposition = outbox.relay(&pending).await?;
    assert_eq!(
        disposition,
        Disposition::Reject,
        "should Reject when budget exhausted"
    );

    // DB 状态 dlx。
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        status.0, "dlx",
        "status should be dlx after budget exhaustion"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T5b: permanent 错误首投即 dlx（#1212：跳过重试预算）─────────────────────────

/// #1212：permanent publish 错误在 retry_count=0（首投）即 → dlx（Reject），**不**熬满 MAX_PUBLISH_ATTEMPTS。
/// 对照 T5（transient 需预算耗尽才 dlx）：本测试 entry 全新（retry_count=0）、publisher 仅调 1 次。
#[tokio::test(flavor = "multi_thread")]
async fn t5b_relay_permanent_err_dlxes_on_first_attempt() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t5b");
    let entry = make_entry(&event_id);

    // seed: 1 行 pending，retry_count 保持默认 0（首投）。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "t5b-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract()),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, calls) = RecordingPublisher::always_permanent();
    let outbox = make_pg_outbox_with_publisher(&store, pub_);

    let pending = pending_entry_for_event(&store, &event_id).await?;
    let disposition = outbox.relay(&pending).await?;
    assert_eq!(
        disposition,
        Disposition::Reject,
        "permanent error should Reject (dlx) on first attempt"
    );

    // DB 状态 dlx，retry_count=1（首投失败累计，非耗尽到 MAX）。
    let row: (String, i32) =
        sqlx::query_as("SELECT status, retry_count FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row.0, "dlx", "permanent error → dlx on first attempt");
    assert_eq!(
        row.1, 1,
        "retry_count=1 (first attempt), not exhausted to MAX"
    );

    // anti-vacuity：permanent 首投即 DLX ⇒ publisher 仅调 1 次（未走退避重试预算）。
    #[allow(clippy::unwrap_used)]
    // reason: 测试内部 Mutex 无 poisoning 来源，item-level carve-out（同 RecordingPublisher::publish）。
    let call_count = *calls.lock().unwrap();
    assert_eq!(call_count, 1, "publisher called exactly once (no retry)");

    store.shutdown().await?;
    Ok(())
}

// ── T6: 崩溃重投（stale publishing → poll_pending 重捞 → relay → published）──

#[tokio::test(flavor = "multi_thread")]
async fn t6_crash_recovery_stale_lease_redelivered() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t6");
    let entry = make_entry(&event_id);

    // seed: 1 行，手动置为 status='publishing' 且 updated_at 早于 LEASE_TTL+10s 前（模拟崩溃残留）。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = make_test_env("crash-domain", "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 模拟崩溃：把行置 publishing + updated_at 很久之前。
    let lease_ttl = crate::outbox::LEASE_TTL_SECONDS;
    sqlx::query(
        "UPDATE outbox SET status='publishing', updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
    )
    .bind(lease_ttl + 10)
    .bind(&event_id)
    .execute(&store.pool)
    .await?;

    // 跨域隔离负向：另插一条 other-domain 的 stale publishing 行；poll("crash-domain") 不应返回它
    //（令下方 entries.len()==1 断言具 anti-vacuity 意义）。
    let other_id = unique_event_id("t6-other");
    let other_entry = make_entry(&other_id);
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = other_entry.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &make_test_env("other-domain", "c"))
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET status='publishing', updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
    )
    .bind(lease_ttl + 10)
    .bind(&other_id)
    .execute(&store.pool)
    .await?;

    // poll_pending 能捞回 stale publishing 行。
    let (pub_, calls) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_with_publisher(&store, pub_);

    let entries = outbox.poll_pending("crash-domain", 10).await?;
    assert_eq!(
        entries.len(),
        1,
        "stale publishing row should be returned by poll_pending"
    );
    assert_eq!(entries[0].idem_key().as_str(), event_id);

    // relay → published。
    let disposition = outbox.relay(&entries[0]).await?;
    assert_eq!(disposition, Disposition::Ack);

    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    // 再 relay 一次（已 published）→ acquire 0 行 → 幂等 Ack，publisher 不再被调用（calls = 1）。
    let outbox2 = make_pg_outbox(&store, || Ok(()));
    let disposition2 = outbox2.relay(&entries[0]).await?;
    assert_eq!(
        disposition2,
        Disposition::Ack,
        "second relay of published entry should be Ack"
    );

    #[allow(clippy::unwrap_used)]
    let call_count = *calls.lock().unwrap();
    assert_eq!(
        call_count, 1,
        "publisher should only be called once (at-least-once idempotent)"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T7: 并发 CAS fencing（两连接各 relay → 至多 publish 一次）────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t7_concurrent_relay_publishes_at_most_once() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t7");
    let entry = make_entry(&event_id);

    // seed 1 行 pending。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = make_test_env("t7-domain", "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 两个独立 PgOutbox 各自 relay 同一行——共享 calls 计数器。
    let calls = Arc::new(Mutex::new(0u32));
    let calls_clone = Arc::clone(&calls);

    let pub1 = RecordingPublisher {
        result: || Ok(()),
        calls: Arc::clone(&calls),
    };
    let pub2 = RecordingPublisher {
        result: || Ok(()),
        calls: calls_clone,
    };

    let outbox1 = make_pg_outbox_with_publisher(&store, pub1);
    let outbox2 = make_pg_outbox_with_publisher(&store, pub2);

    // 两个 relay 并发执行：只有一个能 CAS acquire 成功，另一个返回 Ack（0 行更新）。
    let pending = pending_entry_for_event(&store, &event_id).await?;
    let pending_clone = pending.clone();
    let (d1, d2) = tokio::join!(outbox1.relay(&pending), outbox2.relay(&pending_clone));

    assert!(d1.is_ok() && d2.is_ok(), "both relay should return Ok");
    let d1 = d1?;
    let d2 = d2?;

    // 两个都返回 Ack（一个真正 publish，另一个 CAS 0 行 → 幂等 Ack）。
    assert_eq!(d1, Disposition::Ack);
    assert_eq!(d2, Disposition::Ack);

    // publisher 至多调用一次。
    #[allow(clippy::unwrap_used)]
    let total_calls = *calls.lock().unwrap();
    assert_eq!(
        total_calls, 1,
        "publisher should be called at most once across concurrent relays"
    );

    // 行终态 published。
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    store.shutdown().await?;
    Ok(())
}

// ── sweep 基础验证 ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t8_sweep_removes_old_published_keeps_dlx() -> TestResult {
    let _sweep_guard = OUTBOX_SWEEP_TEST_LOCK.lock().await;
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // 回归 #1740：长期 pending 的行刚发布后，retention 必须从 publish 终态起算，
    // 不能继续沿用已经老化的 created_at。
    let delayed_event = unique_event_id("t8-delayed-publish");
    let delayed_entry = make_entry(&delayed_event);
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let delayed_entry = delayed_entry.clone();
            Box::pin(async move {
                let _outcome =
                    append_outbox(cap, &delayed_entry, &make_test_env("sweep-domain", "c"))
                        .await
                        .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET created_at = now() - make_interval(secs=>7200) WHERE event_id=$1",
    )
    .bind(&delayed_event)
    .execute(&store.pool)
    .await?;
    let delayed_outbox = make_pg_outbox(&store, || Ok(()));
    let delayed_pending = delayed_outbox.poll_pending("sweep-domain", 100).await?;
    let delayed_pending = delayed_pending
        .iter()
        .find(|entry| entry.idem_key().as_str() == delayed_event)
        .ok_or("delayed pending row must be pollable")?;
    assert_eq!(
        delayed_outbox.relay(delayed_pending).await?,
        Disposition::Ack
    );

    let event_pub = unique_event_id("t8-pub");
    let event_dlx = unique_event_id("t8-dlx");
    let entry_pub = make_entry(&event_pub);
    let entry_dlx = make_entry(&event_dlx);

    // seed 2 行。
    for (entry, env_id) in [(&entry_pub, &event_pub), (&entry_dlx, &event_dlx)] {
        let entry_c = (*entry).clone();
        let env_id_c = env_id.to_string();
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                Box::pin(async move {
                    let env = make_test_env("sweep-domain", "c");
                    let _outcome = append_outbox(cap, &entry_c, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        // 置旧 terminal timestamp + 目标 status。
        let new_status = if env_id == &event_pub {
            "published"
        } else {
            "dlx"
        };
        set_outbox_terminal_for_test(&store, &env_id_c, new_status, 7200).await?;
    }

    // anti-vacuity：保留期内的 published（created_at=now）与 pending 行不应被 sweep 删。
    let event_fresh = unique_event_id("t8-fresh");
    let event_pending = unique_event_id("t8-pending");
    for (eid, new_status) in [(&event_fresh, "published"), (&event_pending, "pending")] {
        let entry_c = make_entry(eid);
        let eid_c = eid.to_string();
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry_c, &make_test_env("sweep-domain", "c"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if new_status == STATUS_PUBLISHED {
            set_outbox_terminal_for_test(&store, &eid_c, new_status, 0).await?;
        }
    }

    let event_within_cutoff = unique_event_id("t8-within-cutoff");
    let event_beyond_cutoff = unique_event_id("t8-beyond-cutoff");
    for (event_id, age_seconds) in [
        (&event_within_cutoff, 3599_i64),
        (&event_beyond_cutoff, 3601_i64),
    ] {
        let entry = make_entry(event_id);
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &make_test_env("sweep-domain", "c"))
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        set_outbox_terminal_for_test(&store, event_id, STATUS_PUBLISHED, age_seconds).await?;
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    // 保留期 3600s = 1h；本用例的旧 published 行 published_at 早于 2h 前 → 必被删。
    // 注：`sweep` 是**全表** DELETE（无 domain 过滤），故**不**断言精确全局计数——去掉 `setup_outbox` 全表 DELETE
    // 后本用例的 `event_fresh`（in-retention published，published_at≈now()）本轮不被删而遗留；外部持久库下若跨轮
    // 间隔 > 保留期，遗留行老化后会被本轮 sweep 多删，使 `== 1` flaky（#1194 review F1）。改为：
    //   ① 全局只断言「至少删 ≥1」(anti-vacuity，本用例 aged 行必被删)；
    //   ② 精确性由下方 **event_id-scoped** 断言（被删的确是 event_pub）承载——跨轮 / 并发稳健。
    let deleted = outbox.sweep(3600).await?;
    assert!(
        deleted >= 1,
        "sweep should delete at least the aged published row"
    );
    // 被删的确是本用例的 aged published 行（event_pub）——event_id-scoped，非全局计数。
    let pub_gone: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
        .bind(&event_pub)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        pub_gone.0, 0,
        "aged published row (event_pub) must be swept"
    );

    // dlx 行应保留。
    let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
        .bind(&event_dlx)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(remaining.0, 1, "dlx row should not be swept");

    let delayed_remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
        .bind(&delayed_event)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        delayed_remaining.0, 1,
        "just-published row must survive even when created_at is outside retention"
    );

    for (event_id, expected, message) in [
        (
            &event_within_cutoff,
            1_i64,
            "3599s published row must survive",
        ),
        (
            &event_beyond_cutoff,
            0_i64,
            "3601s published row must be swept",
        ),
    ] {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox WHERE event_id=$1")
            .bind(event_id)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(count, expected, "{message}");
    }

    // anti-vacuity：保留期内的 published 与 pending 行仍在（sweep 只删超保留期的 published）。
    for eid in [&event_fresh, &event_pending] {
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
            .bind(eid)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(cnt.0, 1, "in-retention row must survive sweep: {eid}");
    }

    store.shutdown().await?;
    Ok(())
}

// ── #1210 inbox_receipts 保留期清理：done 超期被删；claimed + 保留期内 done 存活（anti-vacuity）。──
// sweep 是**全表** DELETE（无 group 过滤），故全局只断言「≥1」+ per-row event_id-scoped 精确断言（跨轮/并发稳健，同 t8）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweep_removes_old_done_keeps_claimed_and_recent() -> TestResult {
    use consistency::LeaseOutcome;
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let grp = unique_domain("inbox-sweep-grp");
    let inbox = store.inbox();
    let ctx = test_inbox_ctx(&grp);

    // 回拨 receipt 时间锚（2h 前）：done 用 committed_at，claimed 用 claimed_at。
    async fn backdate(store: &PgStore, event_id: &str, grp: &str) -> TestResult {
        let ctx = test_inbox_ctx(grp);
        sqlx::query(
            "UPDATE inbox_receipts \
             SET claimed_at = now() - make_interval(secs => $1), \
                 committed_at = CASE WHEN status = 'done' THEN now() - make_interval(secs => $1) ELSE committed_at END, \
                 updated_at = now() - make_interval(secs => $1) \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
        )
        .bind(7200i64)
        .bind(ctx.tenant_id().to_string())
        .bind(event_id)
        .bind(grp)
        .execute(&store.pool)
        .await?;
        Ok(())
    }

    // 1) old done：claim → commit（done）→ 回拨过期。
    let key_old = unique_event_id("inbox-sweep-old");
    let k_old = IdemKey::parse(&key_old).unwrap();
    let lease_old = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx, &k_old, &lease_old).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &k_old, &lease_old).await.unwrap(),
        LeaseOutcome::Held
    );
    backdate(&store, &key_old, &grp).await?;

    // 2) recent done（anti-vacuity）：claim → commit，不回拨。
    let key_recent = unique_event_id("inbox-sweep-recent");
    let k_recent = IdemKey::parse(&key_recent).unwrap();
    let lease_recent = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx, &k_recent, &lease_recent)
            .await
            .unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &k_recent, &lease_recent).await.unwrap(),
        LeaseOutcome::Held
    );

    // 3) claimed（anti-vacuity）：claim 但不 commit，回拨过期——sweep 只删 done，不删 claimed。
    let key_claimed = unique_event_id("inbox-sweep-claimed");
    let k_claimed = IdemKey::parse(&key_claimed).unwrap();
    let lease_claimed = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx, &k_claimed, &lease_claimed)
            .await
            .unwrap(),
        SeenState::Fresh
    );
    backdate(&store, &key_claimed, &grp).await?;

    // sweep 保留期 1h：仅 old done（2h 前）被删。
    let deleted = store.inbox_sweeper().sweep(3600).await?;
    assert!(deleted >= 1, "至少删除老 done 行: deleted={deleted}");

    let cnt = |event_id: String| {
        let pool = store.pool.clone();
        let grp = grp.clone();
        async move {
            let row: (i64,) = sqlx::query_as(
                "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
            )
            .bind(test_tenant().to_string())
            .bind(event_id)
            .bind(grp)
            .fetch_one(&pool)
            .await?;
            Ok::<i64, Box<dyn std::error::Error + Send + Sync>>(row.0)
        }
    };
    assert_eq!(cnt(key_old).await?, 0, "超保留期 done 行必须被 sweep 删");
    assert_eq!(cnt(key_recent).await?, 1, "保留期内 done 行不应被 sweep 删");
    assert_eq!(
        cnt(key_claimed).await?,
        1,
        "claimed 行（非 done）不应被 sweep 删"
    );

    store.shutdown().await?;
    Ok(())
}

/// InboxBacklog：只统计当前 group 的 stale claimed；active claim / done / 其它 group 均不计，空时零值。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_backlog_counts_only_stale_claimed_for_bound_group() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let group_a = unique_domain("inbox-backlog-a");
    let group_b = unique_domain("inbox-backlog-b");
    let inbox = store.inbox();
    let ctx_a = test_inbox_ctx(&group_a);
    let ctx_b = test_inbox_ctx(&group_b);
    let scope_a = test_inbox_scope(&group_a);
    let scope_b = test_inbox_scope(&group_b);

    async fn backdate_claim(store: &PgStore, event_id: &str, group: &str) -> TestResult {
        let ctx = test_inbox_ctx(group);
        sqlx::query(
            "UPDATE inbox_receipts SET claimed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
        )
        .bind(crate::inbox::INBOX_LEASE_TTL_SECONDS + 30)
        .bind(ctx.tenant_id().to_string())
        .bind(event_id)
        .bind(group)
        .execute(&store.pool)
        .await?;
        Ok(())
    }

    assert_eq!(
        inbox.sample_backlog(&scope_a).await?,
        consistency::BacklogSample::empty(),
        "无行时 inbox backlog 应为规范零值"
    );

    let active_key = unique_event_id("inbox-backlog-active");
    let active = IdemKey::parse(&active_key).unwrap();
    let active_lease = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx_a, &active, &active_lease)
            .await
            .unwrap(),
        SeenState::Fresh
    );

    let done_key = unique_event_id("inbox-backlog-done");
    let done = IdemKey::parse(&done_key).unwrap();
    let done_lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx_a, &done, &done_lease).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx_a, &done, &done_lease).await.unwrap(),
        consistency::LeaseOutcome::Held
    );
    backdate_claim(&store, &done_key, &group_a).await?;

    let other_group_key = unique_event_id("inbox-backlog-other-group");
    let other_group = IdemKey::parse(&other_group_key).unwrap();
    let other_group_lease = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx_b, &other_group, &other_group_lease)
            .await
            .unwrap(),
        SeenState::Fresh
    );
    backdate_claim(&store, &other_group_key, &group_b).await?;

    assert_eq!(
        inbox.sample_backlog(&scope_a).await?,
        consistency::BacklogSample::empty(),
        "active、done 和其它 group 的 stale claim 都不应计入当前 group"
    );
    assert_eq!(
        inbox.sample_backlog(&scope_b).await?.depth(),
        1,
        "其它 group 自身应能看到自己的 stale claim"
    );

    let stale_key = unique_event_id("inbox-backlog-stale");
    let stale = IdemKey::parse(&stale_key).unwrap();
    let stale_lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx_a, &stale, &stale_lease).await.unwrap(),
        SeenState::Fresh
    );
    backdate_claim(&store, &stale_key, &group_a).await?;

    let sample = inbox.sample_backlog(&scope_a).await?;
    assert_eq!(sample.depth(), 1, "仅当前 group 的 stale claimed 行计数");
    assert!(
        sample.oldest_age_seconds() >= crate::inbox::INBOX_LEASE_TTL_SECONDS as u64,
        "oldest_age_seconds 应来自 stale claimed 的 claimed_at"
    );

    store.shutdown().await?;
    Ok(())
}

/// Inbox sweeper 是全局维护端口：按表清理所有 consumer groups 的超期 done，而不是绑定单个 group。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweeper_removes_old_done_across_consumer_groups() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let groups = [
        unique_domain("inbox-sweep-global-a"),
        unique_domain("inbox-sweep-global-b"),
    ];
    let mut old_done_keys = Vec::new();

    for group in &groups {
        let inbox = store.inbox();
        let ctx = test_inbox_ctx(group);
        let event_id = unique_event_id("inbox-sweep-global-done");
        let key = IdemKey::parse(&event_id).unwrap();
        let lease = LeaseToken::mint();
        assert_eq!(
            inbox.try_claim(&ctx, &key, &lease).await.unwrap(),
            SeenState::Fresh
        );
        assert_eq!(
            inbox.commit(&ctx, &key, &lease).await.unwrap(),
            consistency::LeaseOutcome::Held
        );
        sqlx::query(
            "UPDATE inbox_receipts SET committed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
        )
        .bind(7200i64)
        .bind(ctx.tenant_id().to_string())
        .bind(&event_id)
        .bind(group)
        .execute(&store.pool)
        .await?;
        old_done_keys.push((event_id, group.clone()));
    }

    let claimed_event = unique_event_id("inbox-sweep-global-claimed");
    let inbox = store.inbox();
    let claimed_ctx = test_inbox_ctx(&groups[0]);
    let claimed_key = IdemKey::parse(&claimed_event).unwrap();
    assert_eq!(
        inbox
            .try_claim(&claimed_ctx, &claimed_key, &LeaseToken::mint())
            .await
            .unwrap(),
        SeenState::Fresh
    );
    sqlx::query(
        "UPDATE inbox_receipts SET claimed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(7200i64)
    .bind(claimed_ctx.tenant_id().to_string())
    .bind(&claimed_event)
    .bind(&groups[0])
    .execute(&store.pool)
    .await?;

    let deleted = store.inbox_sweeper().sweep(3600).await?;
    assert!(deleted >= 2, "至少删除两个 group 的 old done 行");

    for (event_id, group) in old_done_keys {
        let ctx = test_inbox_ctx(&group);
        let row: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
        )
        .bind(ctx.tenant_id().to_string())
        .bind(event_id)
        .bind(group)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(row.0, 0, "所有 group 的 old done 都应被全局 sweeper 清理");
    }

    let claimed_row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(claimed_ctx.tenant_id().to_string())
    .bind(&claimed_event)
    .bind(&groups[0])
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        claimed_row.0, 1,
        "stale claimed 行不应被 retention sweeper 删除"
    );

    store.shutdown().await?;
    Ok(())
}

/// 非法 retain_seconds 必须 fail-closed，且不触发删除。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweeper_invalid_retain_preserves_rows() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let group = unique_domain("inbox-sweep-invalid-retain");
    let inbox = store.inbox();
    let ctx = test_inbox_ctx(&group);
    let event_id = unique_event_id("inbox-sweep-invalid-retain-done");
    let key = IdemKey::parse(&event_id).unwrap();
    let lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx, &key, &lease).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &key, &lease).await.unwrap(),
        consistency::LeaseOutcome::Held
    );
    sqlx::query(
        "UPDATE inbox_receipts SET committed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(7200i64)
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .execute(&store.pool)
    .await?;

    let invalid_retain = crate::outbox::max_redelivery_window_secs() as u64;
    let err = match store.inbox_sweeper().sweep(invalid_retain).await {
        Ok(_) => {
            return Err(std::io::Error::other(
                "retain_seconds 等于 redelivery floor 应 fail-closed",
            )
            .into());
        }
        Err(err) => err,
    };
    assert_eq!(err.kind(), consistency::EngineErrorKind::Invariant);

    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, 1, "fail-closed 后 old done 行必须保留");

    store.shutdown().await?;
    Ok(())
}

/// `rss_app` 直调固定 SECURITY DEFINER 函数也必须被 DB 侧保留期下限挡住。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweeper_rss_app_direct_call_rejects_retain_below_floor() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let group = unique_domain("inbox-sweep-sql-retain-floor");
    let inbox = store.inbox();
    let ctx = test_inbox_ctx(&group);
    let event_id = unique_event_id("inbox-sweep-sql-retain-floor-done");
    let key = IdemKey::parse(&event_id).unwrap();
    let lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx, &key, &lease).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &key, &lease).await.unwrap(),
        consistency::LeaseOutcome::Held
    );
    sqlx::query(
        "UPDATE inbox_receipts SET committed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(7200i64)
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .execute(&store.pool)
    .await?;

    let invalid_retain = crate::outbox::max_redelivery_window_secs();
    let result = sqlx::query("SELECT rss_sweep_inbox_receipts($1)")
        .bind(invalid_retain)
        .execute(&app.pool)
        .await;
    let Err(err) = result else {
        return Err("rss_app direct inbox sweep must reject retain at redelivery floor".into());
    };
    assert!(
        err.to_string()
            .contains("rss_sweep_inbox_receipts retain seconds"),
        "unexpected rss_app direct sweep error: {err}"
    );

    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, 1, "DB guard 拒绝后 old done row 必须保留");

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

// ── #1210 dead_letter 保留期清理：超期死信被删；保留期内死信存活（anti-vacuity）。──
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
async fn t_dead_letter_sweep_rss_app_removes_old_keeps_recent() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
        EnvelopeMetadata,
    };
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let dl = app.dead_letter(test_dlx_payload_protector());
    let domain = unique_domain("dl-sweep");
    let (owner, owner_can_login, owner_bypass, rss_app_can_execute): (String, bool, bool, bool) =
        sqlx::query_as(
            r#"
            SELECT pg_get_userbyid(p.proowner),
                   r.rolcanlogin,
                   r.rolbypassrls,
                   has_function_privilege('rss_app', 'rss_sweep_dead_letter(bigint)', 'EXECUTE')
            FROM pg_proc p
            JOIN pg_roles r ON r.oid = p.proowner
            WHERE p.proname = 'rss_sweep_dead_letter'
            "#,
        )
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(owner, "rss_dead_letter_maintenance");
    assert!(
        !owner_can_login,
        "dead-letter maintenance definer must be NOLOGIN"
    );
    assert!(
        owner_bypass,
        "FORCE RLS global sweep must be owned by explicit BYPASSRLS maintenance role"
    );
    assert!(
        rss_app_can_execute,
        "rss_app must only receive EXECUTE on the fixed sweep function"
    );

    // old 死信：写入 → 回拨 last_attempt_at 过默认保留期。
    dl.write_dead_letter(DeadLetterRecord::new(
        vocab::TenantId::parse(COTX_TENANT_A).unwrap(),
        "msg-dl-old",
        DeadLetterProvenance::consumer(domain.as_str(), "dl-sweep-consumer"),
        "contract-x",
        "dl.old",
        Some("dl-sweep-consumer".to_string()),
        b"payload".to_vec(),
        DeadLetterSummary::new("aged dead letter"),
        10,
        EnvelopeMetadata::empty(),
    ))
    .await?;
    sqlx::query(
        "UPDATE dead_letter SET last_attempt_at = now() - make_interval(secs => $1) \
         WHERE producer_domain = $2 AND topic = $3",
    )
    .bind((crate::DEAD_LETTER_RETENTION_SECONDS + 3600) as i64)
    .bind(&domain)
    .bind("dl.old")
    .execute(&store.pool)
    .await?;

    // recent 死信（anti-vacuity）：写入，不回拨。
    dl.write_dead_letter(DeadLetterRecord::new(
        vocab::TenantId::parse(COTX_TENANT_A).unwrap(),
        "msg-dl-recent",
        DeadLetterProvenance::consumer(domain.as_str(), "dl-sweep-consumer"),
        "contract-x",
        "dl.recent",
        Some("dl-sweep-consumer".to_string()),
        b"payload".to_vec(),
        DeadLetterSummary::new("recent dead letter"),
        10,
        EnvelopeMetadata::empty(),
    ))
    .await?;

    // sweep 默认保留期：仅 old（超过 30 天）被删。
    let deleted = dl.sweep(crate::DEAD_LETTER_RETENTION_SECONDS).await?;
    assert!(deleted >= 1, "至少删除老死信: deleted={deleted}");

    let cnt_old: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM dead_letter WHERE producer_domain = $1 AND topic = $2",
    )
    .bind(&domain)
    .bind("dl.old")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(cnt_old.0, 0, "超保留期死信必须被 sweep 删");

    let cnt_recent: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM dead_letter WHERE producer_domain = $1 AND topic = $2",
    )
    .bind(&domain)
    .bind("dl.recent")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(cnt_recent.0, 1, "保留期内死信不应被 sweep 删");

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

// ── #1233 sessions 过期清理：SECURITY DEFINER 全域删除 expired-only。──
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试构造固定 UUID / 时间值；item-level carve-out（error-handling.md §Carve-out）。
async fn t_session_sweeper_rss_app_deletes_only_expired_sessions() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let sweeper = app.session_sweeper();

    let tenant_a = COTX_TENANT_A;
    let tenant_b = "00000000-0000-4000-8000-0000000000bb";
    let expired_a = unique_event_id("session-sweep-expired-a");
    let expired_b = unique_event_id("session-sweep-expired-b");
    let future = unique_event_id("session-sweep-future");
    let revoked_future = unique_event_id("session-sweep-revoked-future");

    for (session_id, tenant, expires_offset_secs, revoked) in [
        (expired_a.as_str(), tenant_a, -3600_i64, false),
        (expired_b.as_str(), tenant_b, -60_i64, false),
        (future.as_str(), tenant_a, 3600_i64, false),
        (revoked_future.as_str(), tenant_a, 7200_i64, true),
    ] {
        sqlx::query(
            r#"
            INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at, revoked)
            VALUES ($1, $2, $3::uuid, now() + make_interval(secs => $4), now(), $5)
            "#,
        )
        .bind(session_id)
        .bind("subject-for-session-sweep")
        .bind(tenant)
        .bind(expires_offset_secs)
        .bind(revoked)
        .execute(&owner.pool)
        .await?;
    }

    let deleted = sweeper.sweep_expired().await?;
    assert!(
        deleted >= 2,
        "至少删除两个本测试插入的过期 session，实际={deleted}"
    );

    for (session_id, expected_count) in [
        (expired_a.as_str(), 0_i64),
        (expired_b.as_str(), 0_i64),
        (future.as_str(), 1_i64),
        (revoked_future.as_str(), 1_i64),
    ] {
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
                .bind(session_id)
                .fetch_one(&owner.pool)
                .await?;
        assert_eq!(
            count, expected_count,
            "session_sweeper expired-only mismatch for {session_id}"
        );
    }

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试批量构造固定行数；item-level carve-out。
async fn t_session_sweeper_deletes_one_bounded_batch_per_call() -> TestResult {
    const SESSION_SWEEP_BATCH_LIMIT: usize = 1_000;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let sweeper = app.session_sweeper();
    let prefix = unique_event_id("session-sweep-batch");
    let inserted = SESSION_SWEEP_BATCH_LIMIT + 1;

    sqlx::query(
        r#"
        INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at, revoked)
        SELECT $1 || '-' || gs::text,
               'subject-for-session-sweep-batch',
               $2::uuid,
               TIMESTAMPTZ '1970-01-01 00:00:00+00' + make_interval(secs => gs),
               TIMESTAMPTZ '1970-01-01 00:00:00+00',
               false
        FROM generate_series(0, $3::int - 1) AS gs
        "#,
    )
    .bind(&prefix)
    .bind(COTX_TENANT_A)
    .bind(i32::try_from(inserted).unwrap())
    .execute(&owner.pool)
    .await?;

    let deleted = sweeper.sweep_expired().await?;
    assert!(
        deleted <= u64::try_from(SESSION_SWEEP_BATCH_LIMIT).unwrap(),
        "session sweeper must delete at most one bounded batch per call, deleted={deleted}"
    );

    let (remaining,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id LIKE $1 || '-%'")
            .bind(&prefix)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(
        remaining, 1,
        "one over-limit expired session must remain for the next tick"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t_session_sweeper_function_is_narrow_rss_app_capability() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;

    let (
        function_owner,
        owner_can_login,
        owner_bypass,
        rss_app_can_execute,
        rss_app_can_delete_sessions,
        function_sql,
    ): (String, bool, bool, bool, bool, String) = sqlx::query_as(
        r#"
        SELECT pg_get_userbyid(p.proowner),
               r.rolcanlogin,
               r.rolbypassrls,
               has_function_privilege('rss_app', 'rss_sweep_expired_sessions()', 'EXECUTE'),
               has_table_privilege('rss_app', 'sessions', 'DELETE'),
               pg_get_functiondef(p.oid)
        FROM pg_proc p
        JOIN pg_roles r ON r.oid = p.proowner
        WHERE p.proname = 'rss_sweep_expired_sessions'
        "#,
    )
    .fetch_one(&owner.pool)
    .await?;

    assert_eq!(function_owner, "rss_session_maintenance");
    assert!(
        !owner_can_login,
        "session maintenance definer must be NOLOGIN"
    );
    assert!(
        owner_bypass,
        "FORCE RLS global session sweep requires explicit BYPASSRLS maintenance role"
    );
    assert!(
        rss_app_can_execute,
        "rss_app must receive EXECUTE on the fixed session sweep function"
    );
    assert!(
        !rss_app_can_delete_sessions,
        "rss_app must not retain direct sessions DELETE after the fixed sweep function exists"
    );
    assert!(
        function_sql.contains("DELETE FROM sessions")
            && function_sql.contains("expires_at <= now()")
            && !function_sql.contains("p_retain_seconds"),
        "session sweep function must be fixed-shape expired-only SQL: {function_sql}"
    );

    let protected_future = unique_event_id("session-sweep-direct-delete-proof");
    sqlx::query(
        r#"
        INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at, revoked)
        VALUES ($1, $2, $3::uuid, now() + make_interval(secs => 3600), now(), false)
        "#,
    )
    .bind(&protected_future)
    .bind("subject-for-session-sweep-direct-delete-proof")
    .bind(COTX_TENANT_A)
    .execute(&owner.pool)
    .await?;

    let direct_delete = sqlx::query("DELETE FROM sessions").execute(&app.pool).await;
    assert!(
        direct_delete.is_err(),
        "rss_app must not have any direct sessions DELETE path"
    );
    let (remaining,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&protected_future)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(
        remaining, 1,
        "direct rss_app DELETE must leave the proof row"
    );

    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(COTX_TENANT_A)
        .execute(&mut *tx)
        .await?;
    let tenant_scoped_direct_delete = sqlx::query("DELETE FROM sessions WHERE session_id = $1")
        .bind(&protected_future)
        .execute(&mut *tx)
        .await;
    assert!(
        tenant_scoped_direct_delete.is_err(),
        "rss_app must not have a tenant-scoped direct sessions DELETE path"
    );
    tx.rollback().await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// dead_letter store enrollment：统一 tenant conformance 覆盖 round-trip / cross-tenant invisible / non-interference。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 fixture 构造已知合法 tenant；item-level carve-out。
async fn dead_letter_tenant_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let dl = store.dead_letter(test_dlx_payload_protector());
    let domain = unique_domain("dead-letter-conf");
    let message_id = unique_event_id("dead-letter-conf-msg");
    let tenant_a = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B).unwrap();

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let dl = &dl;
            let domain = domain.clone();
            let message_id = message_id.clone();
            async move {
                dl.write_dead_letter(DeadLetterRecord::new(
                    tenant,
                    &message_id,
                    diport::DeadLetterProvenance::consumer(domain.as_str(), "tenant-conf-consumer"),
                    "contract-conf",
                    "test.event",
                    Some("tenant-conf-consumer".to_string()),
                    b"payload".to_vec(),
                    diport::DeadLetterSummary::new("tenant conformance"),
                    1,
                    EnvelopeMetadata::empty(),
                ))
                .await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            }
        },
        |tenant| {
            let pool = store.pool.clone();
            let message_id = message_id.clone();
            async move {
                let mut tx = pool.begin().await?;
                sqlx::query("SET LOCAL ROLE rss_app")
                    .execute(&mut *tx)
                    .await?;
                crate::cotx::set_local_tenant(&mut tx, tenant).await?;
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
                        .bind(&message_id)
                        .fetch_one(&mut *tx)
                        .await?;
                tx.rollback().await?;
                Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(cnt.0 > 0)
            }
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_dead_letter_replay_inserts_new_outbox_id() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterSource, DeadLetterStore,
        DeadLetterSummary, EnvelopeMetadata, KEY_CORRELATION, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
        KEY_TENANT_ID,
    };
    use eventexec::{
        DeadLetterId, DlqCursor, DlqEntryKind, DlqError, DlqListQuery, DlqReplayOutcome,
        DlqReplayRequest, DlqStore as _, OperatorDlqCapability,
    };

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let dl = store.dead_letter(test_dlx_payload_protector());
    let dlq = store.dlq_with_projection_registry(
        test_dlx_payload_protector(),
        crate::projection_events::ProjectionWriteRegistry::from_generated(TEST_PROJECTION_INPUTS),
    );
    let domain = unique_domain("dlq-replay");
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let message_id = unique_event_id("consumer-msg");
    let replay_contract_id = "projection.bound";
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(KEY_TENANT_ID, COTX_TENANT_A);
    metadata.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
    metadata.insert_wire_pair(KEY_SCHEMA_HASH, TEST_SCHEMA_HASH);
    metadata.insert_wire_pair(KEY_CORRELATION, "corr-dlq-replay");

    dl.write_dead_letter(DeadLetterRecord::new(
        tenant,
        &message_id,
        DeadLetterProvenance::consumer(domain.as_str(), "dlq-replay-consumer"),
        replay_contract_id,
        "test.event",
        Some("dlq-replay-consumer".to_string()),
        b"consumer-payload".to_vec(),
        DeadLetterSummary::new("consumer exhausted"),
        3,
        metadata,
    ))
    .await?;

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (dead_letter_id,): (String,) = sqlx::query_as(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    let replay_id = IdemKey::parse(&unique_event_id("replay")).unwrap();
    let cap = OperatorDlqCapability::issue_for_authorized_operator();

    sqlx::query("UPDATE dead_letter SET contract_id = $1 WHERE id = $2::uuid")
        .bind("contract-dlq-tampered")
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;
    let tampered_contract = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            IdemKey::parse(&unique_event_id("replay-contract-tampered")).unwrap(),
            cap,
        ))
        .await;
    assert!(
        matches!(tampered_contract, Err(DlqError::InvalidPayload)),
        "contract_id tamper must fail closed during decrypt"
    );
    sqlx::query("UPDATE dead_letter SET contract_id = $1 WHERE id = $2::uuid")
        .bind(replay_contract_id)
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;

    sqlx::query("UPDATE dead_letter SET consumer_group = $1 WHERE id = $2::uuid")
        .bind("dlq-replay-consumer-tampered")
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;
    let tampered_group = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            IdemKey::parse(&unique_event_id("replay-group-tampered")).unwrap(),
            cap,
        ))
        .await;
    assert!(
        matches!(tampered_group, Err(DlqError::InvalidPayload)),
        "consumer_group tamper must fail closed during decrypt"
    );
    sqlx::query("UPDATE dead_letter SET consumer_group = $1 WHERE id = $2::uuid")
        .bind("dlq-replay-consumer")
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;

    sqlx::query("UPDATE dead_letter SET metadata = metadata - $1 WHERE id = $2::uuid")
        .bind(KEY_SCHEMA_HASH)
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;
    let missing_schema_hash = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            IdemKey::parse(&unique_event_id("replay-missing-schema")).unwrap(),
            cap,
        ))
        .await;
    assert!(
        matches!(missing_schema_hash, Err(DlqError::InvalidSchemaHeaders)),
        "missing schema replay header must not be reported as an invalid payload"
    );
    sqlx::query(
        "UPDATE dead_letter \
         SET metadata = jsonb_set(metadata, '{schemaHash}', to_jsonb($1::text), true) \
         WHERE id = $2::uuid",
    )
    .bind(TEST_SCHEMA_HASH)
    .bind(&dead_letter_id)
    .execute(&store.pool)
    .await?;

    let outcome = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
            cap,
        ))
        .await?;
    assert_eq!(outcome, DlqReplayOutcome::Inserted);

    let row: (
        String,
        String,
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
    ) = sqlx::query_as(
        r#"
        SELECT domain,
               contract_id,
               contract_version,
               schema_hash,
               payload,
               metadata ->> 'tenantId',
               metadata ->> 'deadLetterId',
               metadata ->> 'originalMessageId'
        FROM outbox
        WHERE event_id = $1
        "#,
    )
    .bind(replay_id.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, domain);
    assert_eq!(row.1, replay_contract_id);
    assert_eq!(row.2, "v1");
    assert_eq!(row.3, TEST_SCHEMA_HASH);
    assert_eq!(row.4, b"consumer-payload".to_vec());
    assert_eq!(row.5, COTX_TENANT_A);
    assert_eq!(row.6, dead_letter_id);
    assert_eq!(row.7, message_id);

    let projection_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT event_id, contract_id, contract_version, schema_hash
        FROM projection_events
        WHERE event_id = $1
        "#,
    )
    .bind(replay_id.as_str())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        projection_rows,
        vec![(
            replay_id.as_str().to_string(),
            replay_contract_id.to_string(),
            "v1".to_string(),
            TEST_SCHEMA_HASH.to_string(),
        )],
        "generated-bound DLQ replay must mirror exactly one projection event"
    );

    let duplicate = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
            cap,
        ))
        .await?;
    assert_eq!(duplicate, DlqReplayOutcome::AlreadyExists);
    let projection_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM projection_events WHERE event_id = $1")
            .bind(replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        projection_count.0, 1,
        "duplicate DLQ replay must not insert a second projection event"
    );

    let conflict_replay_id = IdemKey::parse(&unique_event_id("dlq-replay-fact-conflict")).unwrap();
    let seed = seed_conflicting_outbox_fact(&store, tenant, conflict_replay_id.as_str()).await?;
    let conflict = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            conflict_replay_id.clone(),
            cap,
        ))
        .await;
    assert!(
        matches!(conflict, Err(DlqError::FactConflict(_))),
        "DLQ replay must preserve typed outbox fact conflict: {conflict:?}"
    );
    assert_seed_fact_unchanged(&store, conflict_replay_id.as_str(), &seed).await?;
    let conflict_projection_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM projection_events WHERE event_id = $1")
            .bind(conflict_replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        conflict_projection_count.0, 0,
        "conflicting DLQ replay must not mirror a projection row"
    );

    let missing_id = uuid::Uuid::new_v4().to_string();
    let missing_replay_id = IdemKey::parse(&unique_event_id("missing-replay")).unwrap();
    let missing = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&missing_id)?,
            missing_replay_id,
            cap,
        ))
        .await;
    assert!(
        matches!(missing, Err(DlqError::NotFound)),
        "missing dead_letter id must map to NotFound"
    );

    let saga_message_id = unique_event_id("saga-msg");
    let saga_replay_id = IdemKey::parse(&unique_event_id("saga-replay")).unwrap();
    dl.write_dead_letter(DeadLetterRecord::new(
        tenant,
        &saga_message_id,
        DeadLetterProvenance::saga(domain.as_str()),
        "contract-dlq",
        "test.saga",
        None,
        b"saga-payload".to_vec(),
        DeadLetterSummary::new("saga compensation failed"),
        2,
        EnvelopeMetadata::empty(),
    ))
    .await?;
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (saga_dead_letter_id,): (String,) = sqlx::query_as(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&saga_message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let saga_replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&saga_dead_letter_id)?,
            saga_replay_id.clone(),
            cap,
        ))
        .await;
    assert!(
        matches!(saga_replay, Err(DlqError::NotReplayable)),
        "saga dead_letter replay must be explicitly unsupported"
    );
    let saga_outbox_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(saga_replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        saga_outbox_count.0, 0,
        "not-replayable saga dead_letter must not write outbox"
    );

    let projection_message_id = format!("projection:test-owner:test-proj:{}", 77);
    let projection_replay_id = IdemKey::parse(&unique_event_id("projection-replay")).unwrap();
    let mut projection_metadata = EnvelopeMetadata::empty();
    projection_metadata.insert_wire_pair(KEY_TENANT_ID, COTX_TENANT_A);
    projection_metadata.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
    projection_metadata.insert_wire_pair(KEY_SCHEMA_HASH, TEST_SCHEMA_HASH);
    for _ in 0..2 {
        dl.write_dead_letter(DeadLetterRecord::new(
            tenant,
            &projection_message_id,
            DeadLetterProvenance::projection(domain.as_str(), "test-proj"),
            "contract-dlq",
            "test.projection",
            Some("test-proj".to_string()),
            b"projection-payload".to_vec(),
            DeadLetterSummary::new("projection apply permanent"),
            1,
            projection_metadata.clone(),
        ))
        .await?;
    }
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (projection_dead_letter_id, projection_count): (String, i64) = sqlx::query_as(
        "SELECT min(id::text), count(*) FROM dead_letter \
         WHERE tenant_id = $1::uuid AND source_kind = 'projection' AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&projection_message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    assert_eq!(
        projection_count, 1,
        "projection DLQ poison rows must be idempotent"
    );
    let projection_replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&projection_dead_letter_id)?,
            projection_replay_id.clone(),
            cap,
        ))
        .await;
    assert!(
        matches!(projection_replay, Err(DlqError::NotReplayable)),
        "projection dead_letter replay must be explicitly unsupported"
    );
    let projection_outbox_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(projection_replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        projection_outbox_count.0, 0,
        "not-replayable projection dead_letter must not write outbox"
    );
    let projection_list = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_producer_domain(domain.as_str())
                .with_source(DeadLetterSource::Projection),
        )
        .await?;
    assert_eq!(projection_list.data().len(), 1);
    assert_eq!(projection_list.data()[0].kind(), DlqEntryKind::DeadLetter);
    assert_eq!(
        projection_list.data()[0].source(),
        DeadLetterSource::Projection
    );
    assert_eq!(
        projection_list.data()[0].message_id(),
        projection_message_id
    );
    assert_eq!(
        projection_list.data()[0].consumer_group(),
        Some("test-proj")
    );

    let invalid_payload_id = unique_event_id("invalid-payload-dl");
    let invalid_entry = serde_json::json!({"ciphertext": true});
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (invalid_dead_letter_id,): (String,) = sqlx::query_as(
        r#"
        INSERT INTO dead_letter
            (tenant_id, message_id, producer_domain, consumer_domain, contract_id, topic,
             original_entry, original_entry_key_ref, original_entry_payload_len,
             original_entry_encoding, error_summary, num_attempts, source_kind, metadata)
        VALUES ($1::uuid, $2, $3, 'dlq-replay-consumer', $4, $5,
                $6, 'dlx-test:1', 3, $7, $8, $9, 'consumer', '{}'::jsonb)
        RETURNING id::text
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&invalid_payload_id)
    .bind(domain.as_str())
    .bind("contract-dlq")
    .bind("test.invalid")
    .bind(sqlx::types::Json(&invalid_entry))
    .bind(crate::dead_letter_payload::DLX_ORIGINAL_ENTRY_ENCODING)
    .bind("invalid payload row")
    .bind(1_i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let invalid_payload = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&invalid_dead_letter_id)?,
            IdemKey::parse(&unique_event_id("invalid-payload-replay")).unwrap(),
            cap,
        ))
        .await;
    assert!(
        matches!(invalid_payload, Err(DlqError::InvalidPayload)),
        "malformed original_entry must map to InvalidPayload"
    );

    let first_page = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_producer_domain(domain.as_str())
                .with_source(DeadLetterSource::Consumer)
                .with_limit(1),
        )
        .await?;
    assert!(
        first_page.has_more(),
        "limit=1 over 2 consumer rows must page"
    );
    let cursor = first_page.next_cursor().unwrap();
    let second_page = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_producer_domain(domain.as_str())
                .with_source(DeadLetterSource::Consumer)
                .with_limit(1)
                .with_cursor(DlqCursor::parse(cursor)?),
        )
        .await?;
    assert_eq!(
        second_page.data().len(),
        1,
        "cursor must advance to next row"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_outbox_dlx_registers_dead_letter_and_redrive_is_tenant_scoped() -> TestResult {
    use consistency::PartitionKey;
    use eventexec::{
        DeadLetterId, DlqCursor, DlqEntryKind, DlqError, DlqInspectRequest, DlqInspectTarget,
        DlqListQuery, DlqRedriveOutcome, DlqRedriveRequest, DlqReplayRequest, DlqStore as _,
        OperatorDlqCapability,
    };

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B).unwrap();
    let domain = unique_domain("dlq-outbox");
    let event_id = unique_event_id("outbox-dlx");
    let partition_key = PartitionKey::parse("outbox-dlx-partition").unwrap();
    let entry = make_entry(&event_id);

    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            let env = make_test_env(&domain, "contract-dlq")
                .with_partition_key_opt(Some(partition_key.clone()));
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (publisher, calls) = RecordingPublisher::always_permanent();
    let outbox = make_pg_outbox_with_publisher(&store, publisher);
    let pending = pending_entry_for_event(&store, &event_id).await?;
    let disposition = outbox.relay(&pending).await?;
    assert_eq!(disposition, Disposition::Reject);
    assert_eq!(*calls.lock().unwrap(), 1);

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let row: (String, String, String, i32, serde_json::Value) = sqlx::query_as(
        r#"
        SELECT id::text, source_kind, message_id, num_attempts, metadata
        FROM dead_letter
        WHERE tenant_id = $1::uuid
          AND message_id = $2
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&event_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    assert_eq!(row.1, "outbox_relay");
    assert_eq!(row.2, event_id);
    assert_eq!(row.3, 1);
    assert_eq!(row.4["tenantId"], COTX_TENANT_A);
    assert_eq!(row.4["schemaVersion"], "v1");
    assert_eq!(row.4["schemaHash"], TEST_SCHEMA_HASH);

    sqlx::query(
        "UPDATE dead_letter \
         SET metadata = jsonb_set(metadata, '{relayFailureReason}', to_jsonb($1::text), true) \
         WHERE id = $2::uuid",
    )
    .bind("envelope_invalid_schema_hash")
    .bind(&row.0)
    .execute(&store.pool)
    .await?;

    let dlq = app.dlq_with_projection_registry(
        test_dlx_payload_protector(),
        crate::projection_events::ProjectionWriteRegistry::from_generated(TEST_PROJECTION_INPUTS),
    );
    let cap = OperatorDlqCapability::issue_for_authorized_operator();
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let replay_id = IdemKey::parse(&unique_event_id("bad-replay")).unwrap();
    let replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&row.0)?,
            replay_id,
            cap,
        ))
        .await;
    assert!(matches!(replay, Err(DlqError::NotReplayable)));

    let older_event_id = unique_event_id("outbox-dlx-older-terminal");
    let older_entry = make_entry(&older_event_id);
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let env = make_test_env(&domain, "contract-dlq");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &older_entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    for (id, dlx_epoch, updated_epoch) in [
        (&event_id, 1_700_000_200_i64, 1_700_000_000_i64),
        (&older_event_id, 1_700_000_100_i64, 1_700_000_300_i64),
    ] {
        sqlx::query(
            "UPDATE outbox \
             SET status = 'dlx', published_at = NULL, \
                 dlx_at = to_timestamp($2), updated_at = to_timestamp($3) \
             WHERE event_id = $1",
        )
        .bind(id)
        .bind(dlx_epoch)
        .bind(updated_epoch)
        .execute(&store.pool)
        .await?;
    }

    let listed = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_producer_domain(domain.as_str())
                .with_limit(1),
        )
        .await?;
    assert_eq!(
        listed.data().len(),
        1,
        "current outbox dlx should be listed"
    );
    assert_eq!(listed.data()[0].kind(), DlqEntryKind::OutboxDlx);
    assert_eq!(listed.data()[0].id(), event_id);
    assert_eq!(listed.data()[0].message_id(), event_id);
    assert_eq!(
        listed.data()[0].last_attempt_epoch_secs(),
        1_700_000_200,
        "DLQ display and ordering must use dlx_at, not updated_at"
    );
    assert_eq!(
        listed.data()[0].error_summary(),
        "envelope_invalid_schema_hash",
        "outbox DLQ list must expose the relay failure reason from dead_letter metadata"
    );
    assert!(listed.has_more(), "two DLX rows with limit=1 must paginate");
    let continuation = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_producer_domain(domain.as_str())
                .with_limit(1)
                .with_cursor(DlqCursor::parse(listed.next_cursor().unwrap())?),
        )
        .await?;
    assert_eq!(continuation.data().len(), 1);
    assert_eq!(continuation.data()[0].id(), older_event_id);
    assert_eq!(
        continuation.data()[0].last_attempt_epoch_secs(),
        1_700_000_100,
        "cursor predicate must use the same dlx_at key as display and ordering"
    );

    let event_key = IdemKey::parse(&event_id).unwrap();
    let inspected = dlq
        .inspect_dlq(DlqInspectRequest::new(
            tenant,
            DlqInspectTarget::OutboxDlx(event_key.clone()),
        ))
        .await?;
    assert_eq!(inspected.kind(), DlqEntryKind::OutboxDlx);
    assert_eq!(inspected.id(), event_id);
    assert_eq!(inspected.error_summary(), "envelope_invalid_schema_hash");
    assert_eq!(
        inspected.last_attempt_epoch_secs(),
        1_700_000_200,
        "inspect must expose the authoritative DLX transition timestamp"
    );

    let before_redrive: (Vec<u8>, i64, String, Option<String>, serde_json::Value, String, String) =
        sqlx::query_as(
            "SELECT payload, seq, partition_key, lease_token::text, metadata, contract_version, schema_hash \
             FROM outbox WHERE event_id = $1",
        )
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert!(
        before_redrive.3.is_some(),
        "dlx row should retain the failed relay lease before redrive"
    );
    let terminal_before_redrive: (bool, bool, i64, i64) = sqlx::query_as(
        "SELECT published_at IS NULL, dlx_at IS NOT NULL, \
                EXTRACT(EPOCH FROM dlx_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        terminal_before_redrive,
        (true, true, 1_700_000_200, 1_700_000_000),
        "fixture must prove DLQ reads do not alias updated_at"
    );

    let wrong_tenant =
        metrics::with_local_recorder(&recorder, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    dlq.redrive_outbox(DlqRedriveRequest::new(tenant_b, event_key.clone(), cap)),
                )
            })
        })?;
    assert_eq!(wrong_tenant, DlqRedriveOutcome::NotFound);

    let status_after_wrong: (String, bool, bool) = sqlx::query_as(
        "SELECT status, published_at IS NULL, dlx_at IS NOT NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(status_after_wrong.0, STATUS_DLX);
    assert!(status_after_wrong.1);
    assert!(status_after_wrong.2);

    let redriven =
        metrics::with_local_recorder(&recorder, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    dlq.redrive_outbox(DlqRedriveRequest::new(tenant, event_key.clone(), cap)),
                )
            })
        })?;
    assert_eq!(redriven, DlqRedriveOutcome::Redriven);
    type RedrivenOutboxState = (
        String,
        i32,
        bool,
        Option<String>,
        bool,
        bool,
        Vec<u8>,
        i64,
        String,
        serde_json::Value,
        String,
        String,
    );
    let status_after_redrive: RedrivenOutboxState = sqlx::query_as(
        "SELECT status, retry_count, retry_after IS NULL, lease_token::text, \
                published_at IS NULL, dlx_at IS NULL, payload, seq, partition_key, metadata, contract_version, schema_hash \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(status_after_redrive.0, STATUS_PENDING);
    assert_eq!(status_after_redrive.1, 0);
    assert!(status_after_redrive.2);
    assert_eq!(status_after_redrive.3, None);
    assert!(status_after_redrive.4);
    assert!(status_after_redrive.5);
    assert_eq!(status_after_redrive.6, before_redrive.0);
    assert_eq!(status_after_redrive.7, before_redrive.1);
    assert_eq!(status_after_redrive.8, before_redrive.2);
    assert_eq!(status_after_redrive.9, before_redrive.4);
    assert_eq!(status_after_redrive.10, "v1");
    assert_eq!(status_after_redrive.11, TEST_SCHEMA_HASH);

    let pending_redrive = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(dlq.redrive_outbox(DlqRedriveRequest::new(tenant, event_key, cap)))
        })
    })?;
    assert_eq!(
        pending_redrive,
        DlqRedriveOutcome::NotFound,
        "redrive must only mutate current dlx rows"
    );
    let rendered = metrics_handle.render();
    assert!(rendered.contains("dlq_redrive_total"), "{rendered}");
    assert!(rendered.contains("outbox_dlx_redrive"), "{rendered}");
    assert!(rendered.contains("redriven"), "{rendered}");
    assert!(rendered.contains("not_found"), "{rendered}");

    let listed_after_redrive = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_producer_domain(domain.as_str()),
        )
        .await?;
    assert_eq!(listed_after_redrive.data().len(), 1);
    assert_eq!(
        listed_after_redrive.data()[0].id(),
        older_event_id,
        "the redriven row must disappear while unrelated current DLX rows remain"
    );

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

// ── T9: lease_token CAS fencing（stale token 不能结算被新租约接管的行）─────────
//
// spec data-model §outbox 强制「CAS：status 转移以 lease_token 比对（防并发双发）」。

#[tokio::test(flavor = "multi_thread")]
async fn t9_settle_rejects_stale_lease_token() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t9");
    let entry = make_entry(&event_id);

    // seed 1 行 pending。
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &make_test_env("t9-domain", "c"))
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // A 取租约 → tokenA（行置 publishing）。
    let lease = crate::outbox::acquire_lease(&store.pool, &event_id).await?;
    let (
        _rc,
        token_a,
        _tenant_id,
        _metadata_json,
        _domain,
        _contract_id,
        _topic,
        _contract_version,
        _schema_hash,
        _now_epoch,
    ) = lease.ok_or("acquire_lease should return a lease for pending row")?;

    // 模拟 B 重新 acquire：覆盖 lease_token = tokenB，A 的 tokenA 变 stale。
    sqlx::query("UPDATE outbox SET lease_token = gen_random_uuid() WHERE event_id = $1")
        .bind(&event_id)
        .execute(&store.pool)
        .await?;

    // A 用 stale tokenA 结算 → WHERE lease_token 不匹配 → 0 行 → 行不变（仍 publishing）且返 LostLease（F3）。
    let stale_outcome = crate::outbox::settle_published(&store.pool, &event_id, &token_a).await?;
    assert_eq!(
        stale_outcome,
        SettleOutcome::LostLease,
        "stale lease token settle must report LostLease (0-row CAS fencing miss)"
    );
    let status: (String, bool, bool) = sqlx::query_as(
        "SELECT status, published_at IS NULL, dlx_at IS NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        status.0, "publishing",
        "stale lease token must not settle the row (CAS fencing)"
    );
    assert!(
        status.1 && status.2,
        "stale settle must not write terminal timestamps"
    );

    // B 用正确 tokenB 结算 → published；返 Settled（F3）。
    let token_b: (String,) =
        sqlx::query_as("SELECT lease_token::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    let settled_outcome =
        crate::outbox::settle_published(&store.pool, &event_id, &token_b.0).await?;
    assert_eq!(
        settled_outcome,
        SettleOutcome::Settled,
        "valid lease token must report Settled"
    );
    let status2: (String, bool, bool, bool) = sqlx::query_as(
        "SELECT status, published_at IS NOT NULL, dlx_at IS NULL, published_at = updated_at \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        status2.0, "published",
        "valid lease token must settle the row"
    );
    assert!(status2.1 && status2.2 && status2.3);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn generated_fingerprint_allows_real_relay_acquire_settle_and_redrive() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let settled_id = unique_event_id("generated-permission-settle");
    let dlx_id = unique_event_id("generated-permission-redrive");
    for event_id in [&settled_id, &dlx_id] {
        let entry = make_entry(event_id);
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry, &make_test_env("generated-permission", "event"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let settled_lease = crate::outbox::acquire_lease(&store.pool, &settled_id)
        .await?
        .ok_or("relay acquire must update a generated-fingerprint row")?;
    assert_eq!(
        crate::outbox::settle_published(&store.pool, &settled_id, &settled_lease.1).await?,
        SettleOutcome::Settled
    );

    let dlx_lease = crate::outbox::acquire_lease(&store.pool, &dlx_id)
        .await?
        .ok_or("relay acquire before redrive must succeed")?;
    let marked: Option<(String,)> =
        sqlx::query_as("SELECT tenant_id FROM rss_outbox_mark_dlx($1, 1, $2::uuid)")
            .bind(&dlx_id)
            .bind(&dlx_lease.1)
            .fetch_optional(&store.pool)
            .await?;
    assert!(
        marked.is_some(),
        "mark DLX must update the generated column row"
    );
    let redriven: i64 = sqlx::query_scalar("SELECT rss_outbox_redrive($1, $2::uuid)")
        .bind(&dlx_id)
        .bind(test_tenant().to_string())
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        redriven, 1,
        "redrive must update exactly one generated column row"
    );

    let states: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT event_id, status, retry_count FROM outbox WHERE event_id = ANY($1) ORDER BY event_id",
    )
    .bind(vec![settled_id, dlx_id])
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(states.len(), 2);
    assert!(states.iter().any(|(_, status, _)| status == "published"));
    assert!(
        states
            .iter()
            .any(|(_, status, retry_count)| status == "pending" && *retry_count == 0)
    );

    store.shutdown().await?;
    Ok(())
}

// ── T10: PgEmitter durable emit（#1100/T008）──────────────────────────────────
//
// 原子性回滚（acc #3）由 T1（append_outbox in rolled-back tx → 无 entry）守——PgEmitter::emit 复用
// append_outbox + 事务，故原子性结构上同源。本测覆盖 emit commit 路径的写正确性（acc #1 的 entry 形态）。

/// PgEmitter::emit 落 durable outbox：恰 1 行 pending，event_id(=EventId)/domain/topic 正确，
/// metadata 含标准 header + opaque subjectId（无完整 PII，FR-020）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——EventTopic/IdemKey parse 已知合法值；函数级 item-level carve-out（error-handling.md §Carve-out）。
async fn t10_pg_emitter_commits_one_pending_with_eventid_and_subject() -> TestResult {
    use diport::{OutboxEmitter, OutboxEnvelopeParts};

    let (_pg, store) = connect_pg().await?;
    // F5(#1194)：仅建表、不全表 DELETE——本用例按 unique `event_id` 隔离断言（`WHERE event_id = $1`），不需
    // 净表起点。#1194 现已全量收口：`setup_outbox` 亦不再全表 DELETE，全部 outbox 用例按 event_id + 专属
    // domain 自隔离（correct-by-construction，并发下亦不互污染）；此处直接 `run_migrations` 与之一致。
    store.run_migrations().await?;

    let event_id = unique_event_id("t10-emit");
    let entry = EventEntry::new(
        EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        reviewed_payload(br#"{"sessionId":"s"}"#),
    );
    let tenant = test_tenant();
    crate::PgEmitter::new(&store, fixed_clock())
        .emit(
            entry,
            OutboxEnvelopeParts::new(
                session_contract(),
                tenant,
                subject_id("subj-opaque-77"),
                actor_for(tenant),
            ),
        )
        .await?;

    let row: (
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT event_id, domain, topic, contract_id, contract_version, schema_hash, causation_id, status, metadata FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, event_id, "event_id = EventId");
    assert_eq!(row.1, "identity", "domain");
    assert_eq!(row.2, SESSION_CREATED_TOPIC, "topic");
    // contract_id 列 = ContractBinding.contract_id()（#1193 typed 绑定经 adapter 落库的 drift-lock）。
    assert_eq!(row.3, "identity.session-created", "contract_id");
    assert_eq!(row.4, "v1", "contract_version 物理列");
    assert_eq!(row.5, TEST_SCHEMA_HASH, "schema_hash 物理列");
    assert_eq!(row.6, None, "默认 causation_id 为 NULL");
    assert_eq!(row.7, "pending", "新 entry pending 待 relay");
    // metadata 含标准 header + opaque subjectId + actor + sealed 注入的 reserved occurred_at（#1129/#1618）；无完整 PII（FR-020 funnel）。
    assert_eq!(
        row.8.get("subjectId").and_then(serde_json::Value::as_str),
        Some("subj-opaque-77"),
        "metadata 应含 opaque subjectId: {}",
        row.8
    );
    assert_eq!(
        row.8.get("occurredAt").and_then(serde_json::Value::as_i64),
        Some(expected_occurred_at()),
        "metadata 应含 sealed 注入的 occurred_at（unix 秒，来自注入 Clock）: {}",
        row.8
    );
    assert_eq!(
        row.8
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str),
        Some("v1"),
        "metadata 应含 schemaVersion: {}",
        row.8
    );
    assert_eq!(
        row.8.get("schemaHash").and_then(serde_json::Value::as_str),
        Some(TEST_SCHEMA_HASH),
        "metadata 应含 schemaHash: {}",
        row.8
    );
    let Some(actor) = row.8.get("actor") else {
        return Err(
            std::io::Error::other(format!("metadata should include actor: {}", row.8)).into(),
        );
    };
    assert_eq!(
        actor.get("kind").and_then(serde_json::Value::as_str),
        Some("admin"),
        "metadata.actor.kind 应落库: {}",
        row.8
    );
    assert_eq!(
        actor.get("id").and_then(serde_json::Value::as_str),
        Some("pg-integration-actor"),
        "metadata.actor.id 应落库: {}",
        row.8
    );
    let tenant_text = tenant.to_string();
    assert_eq!(
        actor.get("tenantId").and_then(serde_json::Value::as_str),
        Some(tenant_text.as_str()),
        "metadata.actor.tenantId 应落库: {}",
        row.8
    );
    assert_eq!(
        actor.get("scope").and_then(serde_json::Value::as_str),
        Some("tenant"),
        "metadata.actor.scope 应落库: {}",
        row.8
    );
    // trace / correlation / principal 为后续 follow-up 空接缝，本 PR 不写。
    for reserved in ["trace", "correlation", "principal"] {
        assert!(
            row.8.get(reserved).is_none(),
            "空接缝 reserved key {reserved} 本 PR 不应写入: {}",
            row.8
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// PgOutboxCdcEmitter::emit writes the opt-in append-only CDC table only.
///
/// It must not fallback to relay `outbox`, and duplicate event_id emits remain idempotent.
type OutboxCdcEmitterRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Vec<u8>,
    serde_json::Value,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn outbox_cdc_emitter_appends_once_without_relay_outbox_fallback() -> TestResult {
    use consistency::PartitionKey;
    use diport::{EnvelopeCausationId, OutboxEmitter, OutboxEnvelopeParts};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let event_id = unique_event_id("outbox-cdc-emit");
    let tenant = test_tenant();
    let make_entry = || {
        EventEntry::new(
            EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
            IdemKey::parse(&event_id).unwrap(),
            reviewed_payload(br#"{"sessionId":"cdc"}"#),
        )
    };
    let make_envelope = || {
        OutboxEnvelopeParts::new(
            session_contract(),
            tenant,
            subject_id("cdc-subj-opaque-77"),
            actor_for(tenant),
        )
        .with_partition_key(PartitionKey::parse("tenant-7:session-9").unwrap())
        .with_causation_id(EnvelopeCausationId::from_opaque("cdc-cause-1").unwrap())
    };
    let emitter = crate::PgOutboxCdcEmitter::new(&store, fixed_clock());
    emitter.emit(make_entry(), make_envelope()).await?;
    emitter.emit(make_entry(), make_envelope()).await?;

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox_log WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(count.0, 1, "CDC emitter should append idempotently once");

    let row: OutboxCdcEmitterRow = sqlx::query_as(
        "SELECT tenant_id::text, aggregate_type, aggregate_id, topic, contract_id, \
                contract_version, schema_hash, payload, metadata, causation_id, \
                occurred_at, trace, correlation_id \
         FROM outbox_log \
         WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    let tenant_text = tenant.to_string();
    assert_eq!(row.0, tenant.to_string(), "tenant_id");
    assert_eq!(row.1, "identity", "aggregate_type");
    assert_eq!(row.2, "cdc-subj-opaque-77", "aggregate_id");
    assert_ne!(
        row.2, "tenant-7:session-9",
        "CDC aggregate_id must not expose partition_key"
    );
    assert_eq!(row.3, SESSION_CREATED_TOPIC, "topic");
    assert_eq!(row.4, "identity.session-created", "contract_id");
    assert_eq!(row.5, "v1", "contract_version");
    assert_eq!(row.6, TEST_SCHEMA_HASH, "schema_hash");
    assert_eq!(row.7, br#"{"sessionId":"cdc"}"#, "payload");
    assert_eq!(
        row.8.get("tenantId").and_then(serde_json::Value::as_str),
        Some(tenant_text.as_str()),
        "metadata tenantId"
    );
    assert_eq!(
        row.8
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str),
        Some("v1"),
        "metadata schemaVersion"
    );
    assert_eq!(
        row.8.get("schemaHash").and_then(serde_json::Value::as_str),
        Some(TEST_SCHEMA_HASH),
        "metadata schemaHash"
    );
    assert_eq!(row.9.as_deref(), Some("cdc-cause-1"), "causation_id");
    let expected_occurred_at_header = expected_occurred_at().to_string();
    assert_eq!(
        row.10.as_deref(),
        Some(expected_occurred_at_header.as_str()),
        "occurred_at generated column"
    );
    assert_eq!(row.11, None, "trace generated column");
    assert_eq!(row.12, None, "correlation_id generated column");

    let relay_count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        relay_count.0, 0,
        "CDC emitter must not fallback to relay outbox"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn outbox_cdc_emitter_rejects_event_id_conflict_with_different_payload() -> TestResult {
    use diport::{OutboxEmitter, OutboxEnvelopeParts};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let event_id = unique_event_id("outbox-cdc-conflict");
    let tenant = test_tenant();
    let make_entry = |payload: &'static [u8]| {
        EventEntry::new(
            EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
            IdemKey::parse(&event_id).unwrap(),
            reviewed_payload(payload),
        )
    };
    let make_envelope = || {
        OutboxEnvelopeParts::new(
            session_contract(),
            tenant,
            subject_id("cdc-conflict-subject"),
            actor_for(tenant),
        )
    };
    let emitter = crate::PgOutboxCdcEmitter::new(&store, fixed_clock());
    emitter
        .emit(make_entry(br#"{"sessionId":"first"}"#), make_envelope())
        .await?;
    let conflict = emitter
        .emit(make_entry(br#"{"sessionId":"second"}"#), make_envelope())
        .await;
    let Err(conflict) = conflict else {
        return Err("same event_id with different immutable CDC payload must fail".into());
    };
    assert_eq!(conflict.kind(), OutboxEmitErrorKind::FactConflict);
    let rendered = format!("{conflict:?} {conflict}");
    for secret in ["first", "second", "cdc-conflict-subject", "fingerprint"] {
        assert!(
            !rendered.contains(secret),
            "typed CDC fact conflict must redact `{secret}`: {rendered}"
        );
    }

    let row: (i64, Vec<u8>) =
        sqlx::query_as("SELECT count(*) OVER (), payload FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row.0, 1, "event_id conflict must not append a second row");
    assert_eq!(
        row.1, br#"{"sessionId":"first"}"#,
        "event_id conflict must preserve the original immutable row"
    );

    store.shutdown().await?;
    Ok(())
}

/// PgEmitter::emit 可选 causation_id 落物理列；metadata 不承载该值（persisted-only）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn t10_pg_emitter_persists_nonempty_causation_id() -> TestResult {
    use diport::{EnvelopeCausationId, OutboxEmitter, OutboxEnvelopeParts};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let event_id = unique_event_id("t10-causation");
    let entry = EventEntry::new(
        EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        reviewed_payload(br#"{"sessionId":"s-cause"}"#),
    );
    let tenant = test_tenant();
    crate::PgEmitter::new(&store, fixed_clock())
        .emit(
            entry,
            OutboxEnvelopeParts::new(
                session_contract(),
                tenant,
                subject_id("subj-cause"),
                actor_for(tenant),
            )
            .with_causation_id(EnvelopeCausationId::from_opaque("upstream-event-1").unwrap()),
        )
        .await?;

    let row: (Option<String>, String) =
        sqlx::query_as("SELECT causation_id, metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row.0.as_deref(), Some("upstream-event-1"));
    assert!(
        !row.1.contains("upstream-event-1"),
        "causation_id persisted-only，不应进入 metadata: {}",
        row.1
    );

    store.shutdown().await?;
    Ok(())
}

// ── T11–T14: PgSessionLifecycle co-tx（session 持久化 + outbox append 同一事务，#1083/#1192）─────────
//
// OUTBOX-COTX-SESSION-01 anti-vacuity：t11 证真实 method commit 两行皆在（含 tenant-correct）、t13 证幂等
// 重写各恰一行；负向 rollback 双覆盖——t12 在单事务内复刻 co-tx SQL 序列后强制 Err 证两写共回滚，**t14 驱动
// 真实 `persist_session_and_emit` 的 rollback 分支**（to_timestamp 溢出使 session INSERT 失败）证两行皆无
// （review #1192 F1：补 t12 仅复刻序列的盲区，直测真实 method 的错误→rollback 路径）。

use std::time::{Duration, SystemTime};

use diport::{OutboxEmitError, OutboxEnvelopeParts};
use identity::ports::{SessionLifecycle, TenantId};

/// co-tx 测试用 canonical 租户 UUID。
const COTX_TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

/// session-created 契约 topic / contract_id 局部单源（本文件内 topic parse / contract_id / 断言统一引用，
/// 避免同义字面量重复——review #244 F4）。
const SESSION_CREATED_TOPIC: &str = "identity.session-created";

/// 构造 session-created EventEntry（topic/event_id/payload）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——EventTopic/IdemKey parse 已知合法值；item-level carve-out（error-handling.md §Carve-out）。
fn session_entry(event_id: &str) -> EventEntry {
    EventEntry::new(
        EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(event_id).unwrap(),
        reviewed_payload(br#"{"sessionId":"s"}"#),
    )
}

/// 构造 session-created envelope（opaque subject）。
fn session_envelope() -> OutboxEnvelopeParts {
    OutboxEnvelopeParts::new(
        session_contract(),
        test_tenant(),
        subject_id("subj-opaque-cotx"),
        actor_for(test_tenant()),
    )
}

/// t11：`persist_session_and_emit` commit → session 行 + outbox 行皆在，且 session tenant-correct。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t11_cotx_commits_session_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t11-sess");
    let event_id = unique_event_id("t11-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);

    crate::PgSessionLifecycle::new(&store, fixed_clock())
        .persist_session_and_emit(
            identity_scope(tenant),
            session,
            session_entry(&event_id),
            session_envelope().with_causation_id(
                diport::EnvelopeCausationId::from_opaque("session-upstream-event").unwrap(),
            ),
        )
        .await?;

    // session 行：恰 1，subject / tenant_id（tenant-correct）正确。
    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 1, "session 行应写入");
    let srow: (String, String) =
        sqlx::query_as("SELECT subject, tenant_id::text FROM sessions WHERE session_id = $1")
            .bind(&session_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(srow.0, "subj-opaque-cotx", "session subject");
    assert_eq!(srow.1, COTX_TENANT_A, "session tenant_id（tenant-correct）");

    // outbox 行：恰 1，pending。
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 1, "outbox 行应写入");
    let outbox_cols: (String, String, String, Option<String>) = sqlx::query_as(
        "SELECT status, contract_version, schema_hash, causation_id FROM outbox WHERE event_id = $1",
    )
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(outbox_cols.0, "pending", "新 outbox entry pending 待 relay");
    assert_eq!(outbox_cols.1, "v1", "co-tx contract_version 物理列");
    assert_eq!(outbox_cols.2, TEST_SCHEMA_HASH, "co-tx schema_hash 物理列");
    assert_eq!(
        outbox_cols.3.as_deref(),
        Some("session-upstream-event"),
        "session co-tx 应透传非空 causation_id"
    );

    // co-tx 路径（第二装配点）同样经构造期 OutboxMetadata::new 从注入 Clock 注入 reserved occurred_at（#1129）。
    let meta: (String,) = sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert!(
        meta.0
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "co-tx outbox metadata 应含 sealed 注入的 occurred_at: {}",
        meta.0
    );
    assert_metadata_text_has_standard_schema_header(&meta.0, "co-tx outbox");

    store.shutdown().await?;
    Ok(())
}

/// t11b：session tenant 与 envelope tenant 不一致 → fail-closed，session / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn t11b_cotx_rejects_envelope_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t11b-sess");
    let event_id = unique_event_id("t11b-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let envelope_tenant = TenantId::parse("00000000-0000-4000-8000-000000000abc").unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);
    let envelope = OutboxEnvelopeParts::new(
        session_contract(),
        envelope_tenant,
        subject_id("subj-opaque-cotx"),
        actor_for(envelope_tenant),
    );

    let result = crate::PgSessionLifecycle::new(&store, fixed_clock())
        .persist_session_and_emit(
            identity_scope(tenant),
            session,
            session_entry(&event_id),
            envelope,
        )
        .await;
    assert!(
        result.is_err(),
        "session/envelope tenant mismatch must fail closed"
    );

    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 0, "mismatch 不得写 session 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "mismatch 不得写 outbox 行");

    store.shutdown().await?;
    Ok(())
}

/// t11c：session tenant 与 repo scope tenant 不一致 → fail-closed，session / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn t11c_cotx_rejects_scope_session_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t11c-sess");
    let event_id = unique_event_id("t11c-evt");
    let scope_tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let session_tenant = TenantId::parse(COTX_TENANT_B).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session = identity::test_support::session(
        &session_id,
        "subj-opaque-cotx",
        session_tenant,
        expires,
        created,
    );
    let envelope = OutboxEnvelopeParts::new(
        session_contract(),
        session_tenant,
        subject_id("subj-opaque-cotx"),
        actor_for(session_tenant),
    );

    let result = crate::PgSessionLifecycle::new(&store, fixed_clock())
        .persist_session_and_emit(
            identity_scope(scope_tenant),
            session,
            session_entry(&event_id),
            envelope,
        )
        .await;
    assert!(
        result.is_err(),
        "session/scope tenant mismatch must fail closed"
    );

    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 0, "scope mismatch 不得写 session 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "scope mismatch 不得写 outbox 行");

    store.shutdown().await?;
    Ok(())
}

/// t12：co-tx 写序列在单事务内执行后强制 Err → session 行 + outbox 行**共**回滚（both-or-neither）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t12_cotx_rollback_leaves_neither() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t12-sess");
    let event_id = unique_event_id("t12-evt");
    let entry = session_entry(&event_id);
    let env = OutboxEnvelope::new(
        "identity".to_string(),
        SESSION_CREATED_TOPIC.to_string(),
        OutboxMetadata::new(0, test_tenant(), test_contract())
            .with_subject_id(subject_id("subj-12")),
    );
    let tenant = COTX_TENANT_A.to_string();
    let sid = session_id.clone();

    // 同 PgSessionLifecycle 写序列（SET LOCAL + INSERT session + append_outbox）在单事务内执行后强制 Err →
    // run_global_transaction 回滚。证明两写**共**回滚（真实 method rollback 路径结构同源，见本节注释 + T10）。
    let rolled = store
        .run_global_transaction::<_, (), sqlx::Error>(move |cap| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
                    .bind(&tenant)
                    .execute(cap.conn())
                    .await?;
                sqlx::query(
                    r#"INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at)
                       VALUES ($1, $2, $3::uuid, to_timestamp($4), to_timestamp($5))
                       ON CONFLICT (session_id) DO NOTHING"#,
                )
                .bind(&sid)
                .bind("subj-12")
                .bind(&tenant)
                .bind(1_700_003_600_i64)
                .bind(1_700_000_000_i64)
                .execute(cap.conn())
                .await?;
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                // 模拟 commit 前任一步失败 → 整体回滚（both-or-neither）。
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(rolled.is_err(), "事务应回滚");

    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        sess_cnt.0, 0,
        "回滚后 session 行不应存在（co-tx both-or-neither）"
    );
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "回滚后 outbox 行不应存在（co-tx both-or-neither）"
    );

    store.shutdown().await?;
    Ok(())
}

/// t13：同 session + 同 event_id 调两次 → session / outbox 各恰 1 行（ON CONFLICT DO NOTHING 幂等）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t13_cotx_idempotent_reemit() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t13-sess");
    let event_id = unique_event_id("t13-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let uow = crate::PgSessionLifecycle::new(&store, fixed_clock());

    for _ in 0..2 {
        let session = identity::test_support::session(
            &session_id,
            "subj-opaque-cotx",
            tenant,
            expires,
            created,
        );
        uow.persist_session_and_emit(
            identity_scope(tenant),
            session,
            session_entry(&event_id),
            session_envelope(),
        )
        .await?;
    }

    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 1, "幂等：session 行恰 1");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 1, "幂等：outbox 行恰 1");
    // 幂等重写不覆盖 metadata（ON CONFLICT DO NOTHING）：occurred_at 仍是首次写入值（规约固化，review F5）。
    let meta: (String,) = sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert!(
        meta.0
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "幂等重写不应覆盖首次 occurred_at: {}",
        meta.0
    );
    assert_metadata_text_has_standard_schema_header(&meta.0, "idempotent rewrite outbox");

    store.shutdown().await?;
    Ok(())
}

// ── T15–T18: OutboxBacklog::sample_backlog（#1209）────────────────────────────
//
// T15: 专属 domain 无行 → BacklogSample::empty()（depth=0, age=0；domain-scoped，不依赖全表净起点）。
// T16: pending 行计入 depth；published/dlx/publishing 行不计。
// T17: oldest_age_seconds 来自 min(created_at)（最老 pending 行；允许小容差）。
// T18: retry_after > now() 的行排除在 depth 之外（与 poll_pending pending 谓词同源）。

/// T15: 对一个无任何用例写入的专属 domain（`t15-domain`）采样 → 无 scoped sample。
/// domain-scoped 断言：不依赖全表净起点，去掉 `setup_outbox` 全表 DELETE 后仍恒空（#1194）。
#[tokio::test(flavor = "multi_thread")]
async fn t15_sample_backlog_empty_domain_returns_empty() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    // 用 t15 专属 domain（无任何其它用例写入）→ domain-scoped 采样恒空，断言不依赖全表净起点（#1194）。
    let samples = outbox.sample_backlog("t15-domain").await?;
    let sample = summarize_backlog(&samples);

    assert!(
        samples.is_empty(),
        "从未观测的专属 domain 不应造假输出 metric scope"
    );
    assert_eq!(
        sample,
        BacklogSample::empty(),
        "无写入的专属 domain 聚合后应为 BacklogSample::empty()"
    );
    assert_eq!(sample.depth(), 0);
    assert_eq!(sample.oldest_age_seconds(), 0);

    store.shutdown().await?;
    Ok(())
}

/// T15b: 已观测 scope 当前无可投递 backlog 时输出 depth=0/age=0；从未出现的 scope 不补 label。
#[tokio::test(flavor = "multi_thread")]
async fn t15b_sample_backlog_observed_scope_without_backlog_returns_zero() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t15b-domain");
    let event_id = unique_event_id("t15b-published");
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = make_entry(&event_id);
            let env = make_test_env(&domain, "metrics.zero");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    set_outbox_terminal_for_test(&store, &event_id, STATUS_PUBLISHED, 0).await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = outbox.sample_backlog(&domain).await?;

    assert_eq!(
        samples.len(),
        1,
        "已观测 scope 当前无 backlog 时仍应输出 zero sample"
    );
    let sample = samples[0].sample();
    assert_eq!(sample.depth(), 0);
    assert_eq!(sample.oldest_age_seconds(), 0);
    assert_eq!(samples[0].subject().tenant_id(), test_tenant());
    assert_eq!(samples[0].subject().contract_id().as_str(), "metrics.zero");

    store.shutdown().await?;
    Ok(())
}

/// T15c: DB 中非法 contract_id 回读到 typed metric subject 时 fail-closed 为 Invariant。
#[tokio::test(flavor = "multi_thread")]
async fn t15c_poll_pending_rejects_invalid_persisted_contract_id() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t15c-domain");
    let event_id = unique_event_id("t15c-invalid-contract");
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = make_entry(&event_id);
            let env = make_test_env(&domain, "metrics.valid");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query("UPDATE outbox SET contract_id = 'Metrics.Invalid' WHERE event_id = $1")
        .bind(&event_id)
        .execute(&store.pool)
        .await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let Err(err) = outbox.poll_pending(&domain, 10).await else {
        return Err("poll_pending must reject invalid persisted contract_id".into());
    };
    assert_eq!(
        err.kind(),
        EngineErrorKind::Invariant,
        "invalid persisted contract_id should be an invariant failure"
    );

    store.shutdown().await?;
    Ok(())
}

/// T16: pending 行计入 depth；published/dlx/**非-stale** publishing 行**不**计
/// （此处 publishing 行 updated_at≈now()、lease 仍有效，属正常 in-flight，正确排除；stale publishing 见 T19）。
#[tokio::test(flavor = "multi_thread")]
async fn t16_sample_backlog_counts_only_pending_rows() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t16-domain");
    let domain = domain.as_str();

    // seed：1 pending + 1 published + 1 dlx + 1 publishing。
    for (prefix, target_status) in [
        ("t16-pend", "pending"),
        ("t16-pub", "published"),
        ("t16-dlx", "dlx"),
        ("t16-pubing", "publishing"),
    ] {
        let eid = unique_event_id(prefix);
        let entry = make_entry(&eid);
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                let env = make_test_env(domain, "c");
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if target_status != "pending" {
            set_outbox_terminal_for_test(&store, &eid, target_status, 0).await?;
        }
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = outbox.sample_backlog(domain).await?;
    let sample = summarize_backlog(&samples);

    assert_eq!(sample.depth(), 1, "仅 pending 行计入 depth，应为 1");

    store.shutdown().await?;
    Ok(())
}

/// T17: oldest_age_seconds 来自最老 pending 行的 created_at（min(created_at)）。
///
/// 插两行，旧行 created_at 人工回拨 10s；断言 oldest_age_seconds >= 10（允许 ±3s 容差）。
#[tokio::test(flavor = "multi_thread")]
async fn t17_sample_backlog_age_tracks_oldest_pending() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t17-domain");
    let domain = domain.as_str();

    // 先插"新" pending 行（created_at = now()）。
    let new_id = unique_event_id("t17-new");
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = make_entry(&new_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 插"旧" pending 行，并把 created_at 回拨 10s（模拟 10 秒前写入）。
    let old_id = unique_event_id("t17-old");
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = make_entry(&old_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET created_at = now() - make_interval(secs => 10) WHERE event_id = $1",
    )
    .bind(&old_id)
    .execute(&store.pool)
    .await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = outbox.sample_backlog(domain).await?;
    let sample = summarize_backlog(&samples);

    assert_eq!(sample.depth(), 2, "两条 pending 行");
    // oldest_age_seconds 须 ≥ 10（旧行回拨 10s）；上限放宽容差至 20s 吸收 testcontainer/CI round-trip
    // 抖动（断言意图是「取最老行龄」而非精确计时，宽上限避免慢 CI 偶发 flaky）。
    assert!(
        sample.oldest_age_seconds() >= 10,
        "oldest_age_seconds 应 ≥ 10，实际={}",
        sample.oldest_age_seconds()
    );
    assert!(
        sample.oldest_age_seconds() < 20,
        "oldest_age_seconds 不应超过 20（宽容差吸收 CI round-trip），实际={}",
        sample.oldest_age_seconds()
    );

    store.shutdown().await?;
    Ok(())
}

/// T18: retry_after > now() 的行**不**计入 depth（与 poll_pending pending 谓词同源）。
#[tokio::test(flavor = "multi_thread")]
async fn t18_sample_backlog_excludes_future_retry_after() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t18-domain");
    let domain = domain.as_str();

    // seed：1 到期 pending（retry_after IS NULL）+ 1 未到期 pending（retry_after = now()+3600）。
    let due_id = unique_event_id("t18-due");
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = make_entry(&due_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let future_id = unique_event_id("t18-future");
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = make_entry(&future_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    // 把 future 行的 retry_after 置未来（3600s 后），status 保持 pending。
    sqlx::query(
        "UPDATE outbox SET retry_after = now() + make_interval(secs => 3600) WHERE event_id = $1",
    )
    .bind(&future_id)
    .execute(&store.pool)
    .await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = outbox.sample_backlog(domain).await?;
    let sample = summarize_backlog(&samples);

    // 仅 due_id（retry_after IS NULL）计入；future_id（retry_after > now()）排除。
    assert_eq!(
        sample.depth(),
        1,
        "retry_after > now() 的行不应计入 depth，应为 1"
    );

    store.shutdown().await?;
    Ok(())
}

/// T19: **stale** publishing（lease 过期、poll_pending 会重捞）计入 depth + oldest-age；**非-stale**
/// publishing（lease 仍有效）排除。锁定 sample_backlog 与 poll_pending 可投递集合同源（#1209 review F1）。
#[tokio::test(flavor = "multi_thread")]
async fn t19_sample_backlog_counts_stale_publishing() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t19-domain");
    let domain = domain.as_str();
    let lease_ttl = crate::outbox::LEASE_TTL_SECONDS;

    // seed 两行 publishing：stale（updated_at 回拨 LEASE_TTL+10s）+ fresh（updated_at≈now()）。
    for (prefix, stale) in [("t19-stale", true), ("t19-fresh", false)] {
        let eid = unique_event_id(prefix);
        let entry = make_entry(&eid);
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                let env = make_test_env(domain, "c");
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if stale {
            sqlx::query(
                "UPDATE outbox SET status='publishing', created_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
            )
            .bind(lease_ttl + 10)
            .bind(&eid)
            .execute(&store.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE outbox SET status='publishing', updated_at = now() WHERE event_id = $1",
            )
            .bind(&eid)
            .execute(&store.pool)
            .await?;
        }
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = outbox.sample_backlog(domain).await?;
    let sample = summarize_backlog(&samples);

    // 仅 stale publishing 计入（fresh 行 lease 有效、属正常 in-flight 排除）。
    assert_eq!(
        sample.depth(),
        1,
        "stale publishing 应计入 depth、fresh publishing 排除，应为 1"
    );
    // stale 行存在 ⇒ oldest-age 反映其积压龄（> 0）。
    assert!(
        sample.oldest_age_seconds() > 0,
        "stale publishing 的 oldest_age_seconds 应 > 0，实际={}",
        sample.oldest_age_seconds()
    );

    store.shutdown().await?;
    Ok(())
}

// ── t24-t29: outbox partition-key + seq 集成验证（#1211 Batch 2a）──────────────
//
// t24: seq 单调且应用不可伪造（GENERATED ALWAYS 拒绝显式写入）
// t25: 同 partition 串行有序（head-of-partition gating：H→S2→S3 按序投递）
// t26: 跨 partition 不互阻 + NULL-partition 无序并行路径不变
// t27: dlx 队头阻塞 partition，re-drive 后恢复
// t28: crash recovery 保持 partition 顺序（stale publishing 头 gate 后继）
// t29: sample_backlog 计入 gated 后继（backlog poll-only by design）

use crate::outbox::{LEASE_TTL_SECONDS, STATUS_DLX, STATUS_PENDING};

/// t24：append 3 行（同 domain，无 partition）→ SELECT seq 严格递增、互异、非空；
/// 尝试 INSERT 显式写 seq 被 GENERATED ALWAYS 拒（应用不可伪造）。
///
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t24_seq_monotonic_and_app_cannot_forge() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t24");
    let ids: Vec<_> = (0..3)
        .map(|i| unique_event_id(&format!("t24-{i}")))
        .collect();

    // append 3 行，无 partition。
    for eid in &ids {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c");
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // SELECT seq 并验证严格递增、互异、非空。
    let seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM outbox WHERE event_id = ANY($1::text[]) ORDER BY seq ASC",
    )
    .bind(ids.as_slice())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(seqs.len(), 3, "t24: 应有 3 行 seq");
    for w in seqs.windows(2) {
        assert!(
            w[0] < w[1],
            "t24: seq 应严格递增，实际 {} >= {}",
            w[0],
            w[1]
        );
    }

    // GENERATED ALWAYS 拒绝应用显式写入 seq。
    let fake_seq: i64 = 999_999_999;
    let forge_id = unique_event_id("t24-forge");
    let forge_env = make_test_env(&domain, "c");
    let forge_result = sqlx::query(
        "INSERT INTO outbox (
             event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
             payload, metadata, status, seq
         ) VALUES ($1, $2::uuid, $3, 'test.event', 'c', $4, $5, $6, $7::jsonb, 'pending', $8)",
    )
    .bind(&forge_id)
    .bind(forge_env.tenant().to_string())
    .bind(&domain)
    .bind(forge_env.contract_version())
    .bind(forge_env.schema_hash())
    .bind(b"p".as_slice())
    .bind(forge_env.metadata_json())
    .bind(fake_seq)
    .execute(&store.pool)
    .await;
    let Err(forge_err) = forge_result else {
        return Err("t24: GENERATED ALWAYS 应拒绝应用写入 seq（反真空：伪造尝试必须失败）".into());
    };
    let rendered = forge_err.to_string();
    assert!(
        rendered.contains("non-DEFAULT value") || rendered.contains("GENERATED ALWAYS"),
        "t24: 伪造 seq 必须由 GENERATED ALWAYS 拒绝，而不是被其它约束挡住: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// t25：同 (domain, 'p1') partition → `poll_pending` 仅返队头；relay → published → poll → 后继。
///
/// 反真空：S2/S3 在 H 未 published 前缺席（head-of-partition gating 生效）。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t25_partition_serial_in_order() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t25");
    let key = PartitionKey::parse("p1").unwrap();

    let h_id = unique_event_id("t25-H");
    let s2_id = unique_event_id("t25-S2");
    let s3_id = unique_event_id("t25-S3");

    // append H, S2, S3 同 (domain, 'p1')——顺序由 seq 的 IDENTITY 单调递增保证。
    for eid in [&h_id, &s2_id, &s3_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let (pub_ok, _) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_with_publisher(&store, pub_ok);

    // poll → 仅 H（S2/S3 被 gate）。
    let entries = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries.len(), 1, "t25: 首轮 poll 应仅返队头 H");
    assert_eq!(
        entries[0].idem_key().as_str(),
        h_id,
        "t25: 首轮 poll 必须是 H"
    );
    // 反真空：S2/S3 确实缺席。
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t25: S2 不应出现（被 gate）"
    );
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s3_id),
        "t25: S3 不应出现（被 gate）"
    );

    // relay H → published。
    let h_entry = entries.into_iter().next().unwrap();
    let disp = outbox.relay(&h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t25: relay H 应返 Ack");

    // poll → S2（H 已 published，S2 现在是队头）。
    let entries2 = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries2.len(), 1, "t25: 第二轮 poll 应仅返 S2");
    assert_eq!(
        entries2[0].idem_key().as_str(),
        s2_id,
        "t25: 第二轮 poll 必须是 S2"
    );
    // 反真空：S3 第二轮仍被 gate（与首轮 S3 缺席对称）。
    assert!(
        !entries2.iter().any(|e| e.idem_key().as_str() == s3_id),
        "t25: S3 第二轮仍被 gate 不应出现"
    );

    // relay S2 → published。
    let s2_entry = entries2.into_iter().next().unwrap();
    outbox.relay(&s2_entry).await?;

    // poll → S3。
    let entries3 = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries3.len(), 1, "t25: 第三轮 poll 应仅返 S3");
    assert_eq!(
        entries3[0].idem_key().as_str(),
        s3_id,
        "t25: 第三轮 poll 必须是 S3"
    );

    store.shutdown().await?;
    Ok(())
}

/// t26：跨 partition 不互阻 + NULL-partition 无序并行路径不变。
///
/// 同 domain 下：p1-head + p2-head + 2 个 NULL-partition 行 → 一轮 poll 返 4 行。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t26_cross_partition_and_null_parallel() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t26");

    let p1_key = PartitionKey::parse("p1").unwrap();
    let p2_key = PartitionKey::parse("p2").unwrap();

    // p1-head, p2-head, null1, null2。
    let p1_id = unique_event_id("t26-p1");
    let p2_id = unique_event_id("t26-p2");
    let n1_id = unique_event_id("t26-null1");
    let n2_id = unique_event_id("t26-null2");

    // p1-head
    {
        let entry = make_entry(&p1_id);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(p1_key));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    // p2-head
    {
        let entry = make_entry(&p2_id);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(p2_key));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    // null1, null2（无 partition）。
    for nid in [&n1_id, &n2_id] {
        let entry = make_entry(nid);
        let env = make_test_env(&domain, "c");
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let entries = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(
        entries.len(),
        4,
        "t26: p1-head + p2-head + null1 + null2 = 4 行（跨 partition 不互阻，NULL 不约束）"
    );

    // 验证四个预期 ID 都在返回集合中。
    let ids_in: Vec<&str> = entries.iter().map(|e| e.idem_key().as_str()).collect();
    for expected in [
        p1_id.as_str(),
        p2_id.as_str(),
        n1_id.as_str(),
        n2_id.as_str(),
    ] {
        assert!(
            ids_in.contains(&expected),
            "t26: {expected} 应在 poll 结果中"
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// t27：dlx 队头阻塞 partition，re-drive 后恢复。
///
/// append H, S2 同 partition；强制 H→dlx；poll 该 partition 空；
/// re-drive H → relay → published → poll → S2。
/// 反真空：NULL-partition dlx 行不阻塞任何东西。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t27_dlx_head_blocks_then_unblocks() -> TestResult {
    use consistency::PartitionKey;
    use eventexec::{DlqRedriveOutcome, DlqRedriveRequest, DlqStore as _, OperatorDlqCapability};

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t27");
    let key = PartitionKey::parse("part-dlx").unwrap();

    let h_id = unique_event_id("t27-H");
    let s2_id = unique_event_id("t27-S2");

    // append H, S2 同 (domain, 'part-dlx')。
    for eid in [&h_id, &s2_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // 强制 H → dlx（直接 UPDATE status）。
    set_outbox_terminal_for_test(&store, &h_id, STATUS_DLX, 0).await?;

    // poll → 该 partition 空（H 在 dlx，S2 被 gate）。
    let outbox = make_pg_outbox(&store, || Ok(()));
    let blocked = outbox.poll_pending(&domain, 10).await?;
    assert!(
        blocked.is_empty(),
        "t27: dlx 队头必须完全阻塞 partition（blocked={blocked:?}）"
    );

    // 反真空：NULL-partition dlx 行不阻塞任何东西。
    let null_dlx_id = unique_event_id("t27-null-dlx");
    let null_live_id = unique_event_id("t27-null-live");
    for eid in [&null_dlx_id, &null_live_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c"); // no partition
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    set_outbox_terminal_for_test(&store, &null_dlx_id, STATUS_DLX, 0).await?;

    let after_null_dlx = outbox.poll_pending(&domain, 10).await?;
    assert!(
        after_null_dlx
            .iter()
            .any(|e| e.idem_key().as_str() == null_live_id),
        "t27: NULL-partition dlx 不阻塞 null_live 行（反真空）"
    );

    // re-drive H：经 DLQ store 固定函数把 H 从 dlx 重置回 pending。
    let dlq = store.dlq_without_payload_replay();
    let redrive = dlq
        .redrive_outbox(DlqRedriveRequest::new(
            test_tenant(),
            IdemKey::parse(&h_id).unwrap(),
            OperatorDlqCapability::issue_for_authorized_operator(),
        ))
        .await?;
    assert_eq!(redrive, DlqRedriveOutcome::Redriven);

    // relay H → published。
    let redriven = outbox.poll_pending(&domain, 10).await?;
    let h_entry = redriven
        .iter()
        .find(|e| e.idem_key().as_str() == h_id)
        .expect("t27: re-drive 后 H 应出现在 poll 结果中");
    let disp = outbox.relay(h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t27: relay H 应返 Ack");

    // poll → S2 现在可见。
    let unblocked = outbox.poll_pending(&domain, 10).await?;
    assert!(
        unblocked.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t27: H published 后 S2 应解除阻塞"
    );

    store.shutdown().await?;
    Ok(())
}

/// t27b：跨租户同 `(domain, partition_key)` 不互阻。
///
/// tenant A 队头进 dlx 后，只能阻塞 tenant A 同 partition 后继；tenant B 使用相同业务 key 的行仍可投递。
/// INVARIANT: OUTBOX-TENANT-PARTITION-ORDER-01 { level = "Hard", exec = "native-compile", source = "code", native = "migration 0031 tenant-scopes outbox partition ordering keys" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t27b_outbox_cross_tenant_partition_dlx_does_not_block() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t27b");
    let key = PartitionKey::parse("shared-business-key").unwrap();
    let tenant_a = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B).unwrap();
    let a_head = unique_event_id("t27b-a-head");
    let a_tail = unique_event_id("t27b-a-tail");
    let b_head = unique_event_id("t27b-b-head");

    for (tenant, eid) in [
        (tenant_a, &a_head),
        (tenant_a, &a_tail),
        (tenant_b, &b_head),
    ] {
        let entry = make_entry(eid);
        let env = make_test_env_for_tenant(&domain, "c", tenant)
            .with_partition_key_opt(Some(key.clone()));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    set_outbox_terminal_for_test(&store, &a_head, STATUS_DLX, 0).await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let polled = outbox.poll_pending(&domain, 10).await?;
    let ids: Vec<&str> = polled
        .iter()
        .map(|entry| entry.idem_key().as_str())
        .collect();
    assert!(
        ids.contains(&b_head.as_str()),
        "tenant B same partition key must remain pollable; got {ids:?}"
    );
    assert!(
        !ids.contains(&a_tail.as_str()),
        "tenant A tail must stay blocked by tenant A dlx head; got {ids:?}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0031：tenant_id backfill 必须 fail-closed 拒绝缺失 metadata.tenantId 的历史 outbox 行。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0031_rejects_outbox_rows_missing_tenant_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'test.event', 'contract-1', $2, '{}'::jsonb, 'pending')",
    )
    .bind(unique_event_id("bad-outbox-tenant"))
    .bind(b"payload".as_slice())
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../migrations/0031_harden_outbox_tenant_scope.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err("0031 must reject outbox rows without metadata tenantId".into());
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox tenant_id backfill requires metadata.tenantId"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0040：旧 projection_events 行不做 backfill，必须 fail-fast。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0040_rejects_non_empty_legacy_projection_events() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0013_create_projection_events.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO projection_events (domain, aggregate_id, event_type, payload) \
         VALUES ('test', 'agg-1', 'test.event', $1)",
    )
    .bind(b"payload".as_slice())
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../migrations/0040_projection_events_funnel_and_projection_dlx.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err("0040 must reject non-empty legacy projection_events".into());
    };
    let rendered = err.to_string();
    assert!(
        rendered
            .contains("projection_events must be empty before enabling projection writer funnel"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0055_backfills_legacy_mutable_outbox_with_rust_parity() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    create_rss_app_role_for_migration_test(&store).await?;
    sqlx::raw_sql(
        "CREATE TABLE outbox ( \
             event_id text NOT NULL, tenant_id uuid NOT NULL, domain text NOT NULL, \
             topic text NOT NULL, contract_id text NOT NULL, contract_version text NOT NULL, \
             schema_hash text NOT NULL, payload bytea NOT NULL, metadata jsonb NOT NULL, \
             partition_key text NULL, causation_id text NULL \
         ); \
         CREATE TABLE outbox_log ( \
             event_id text NOT NULL, tenant_id uuid NOT NULL, aggregate_type text NOT NULL, \
             topic text NOT NULL, contract_id text NOT NULL, contract_version text NOT NULL, \
             schema_hash text NOT NULL, payload bytea NOT NULL, metadata jsonb NOT NULL, \
             causation_id text NULL \
         ); \
         CREATE TABLE reconcile_targets (target_id uuid PRIMARY KEY DEFAULT gen_random_uuid())",
    )
    .execute(&store.pool)
    .await?;
    let tenant = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let schema_hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let metadata = serde_json::json!({
        "actor": {"kind": "user", "id": "legacy-actor"},
        "occurredAt": 17,
        "subjectId": "legacy-subject"
    });
    sqlx::query(
        "INSERT INTO outbox ( \
             event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash, \
             payload, metadata, partition_key, causation_id \
         ) VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)",
    )
    .bind("legacy-mutable-event")
    .bind(tenant)
    .bind("identity")
    .bind("identity.session-created")
    .bind("identity.session-created")
    .bind("v1")
    .bind(schema_hash)
    .bind(b"legacy-payload".as_slice())
    .bind(metadata.to_string())
    .bind("legacy-partition")
    .bind("legacy-cause")
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../migrations/0055_outbox_fact_fingerprint.sql"
    ))
    .execute(&store.pool)
    .await?;

    let stored = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT fact_fingerprint FROM outbox WHERE event_id = 'legacy-mutable-event'",
    )
    .fetch_one(&store.pool)
    .await?;
    let rust = OutboxFactIdentity::new(
        "legacy-mutable-event",
        tenant,
        "identity",
        "identity.session-created",
        "identity.session-created",
        "v1",
        schema_hash,
        b"legacy-payload",
        Some("legacy-partition"),
        Some("legacy-cause"),
        &metadata,
    )
    .fingerprint();
    assert_eq!(stored.len(), 32);
    assert_eq!(stored.as_slice(), rust.as_bytes());

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0055_rejects_non_empty_legacy_outbox_log() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(
        "CREATE TABLE outbox_log (event_id text NOT NULL); \
         INSERT INTO outbox_log (event_id) VALUES ('legacy-cdc-event')",
    )
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../migrations/0055_outbox_fact_fingerprint.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(error) = result else {
        return Err("0055 must reject non-empty legacy outbox_log".into());
    };
    assert!(
        error
            .to_string()
            .contains("outbox_log must be empty before canonical fact fingerprint migration")
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0056_backfills_terminal_timestamps_from_updated_at() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    create_rss_app_role_for_migration_test(&store).await?;
    sqlx::raw_sql(
        r#"
        CREATE TABLE outbox (
            event_id text PRIMARY KEY,
            tenant_id uuid NOT NULL,
            domain text NOT NULL,
            topic text NOT NULL,
            contract_id text NOT NULL,
            contract_version text NOT NULL,
            schema_hash text NOT NULL,
            payload bytea NOT NULL,
            metadata jsonb NOT NULL,
            status text NOT NULL,
            retry_count int NOT NULL DEFAULT 0,
            retry_after timestamptz,
            lease_token uuid,
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL
        );
        CREATE INDEX idx_outbox_sweep ON outbox (status, created_at);
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, contract_version,
            schema_hash, payload, metadata, status, created_at, updated_at
        )
        SELECT status,
               '11111111-1111-1111-1111-111111111111'::uuid,
               'migration', 'migration.event', 'migration.contract', 'v1',
               'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
               'payload'::bytea, '{}'::jsonb, status,
               TIMESTAMPTZ '2024-01-01 00:00:00+00',
               TIMESTAMPTZ '2024-01-02 00:00:00+00' + ordinal * INTERVAL '1 hour'
        FROM (VALUES
            ('pending', 1), ('publishing', 2), ('published', 3), ('dlx', 4)
        ) AS states(status, ordinal);
        "#,
    )
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../migrations/0056_add_outbox_terminal_timestamps.sql"
    ))
    .execute(&store.pool)
    .await?;

    let rows: Vec<(String, bool, bool, bool, bool)> = sqlx::query_as(
        r#"
        SELECT status,
               published_at IS NULL,
               dlx_at IS NULL,
               published_at IS NOT DISTINCT FROM updated_at,
               dlx_at IS NOT DISTINCT FROM updated_at
        FROM outbox
        ORDER BY status
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        rows,
        vec![
            ("dlx".to_string(), true, false, false, true),
            ("pending".to_string(), true, true, false, false),
            ("published".to_string(), false, true, true, false),
            ("publishing".to_string(), true, true, false, false),
        ]
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_terminal_timestamp_checks_reject_invalid_state_combinations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    for (suffix, status) in [
        ("legal-pending", "pending"),
        ("legal-publishing", "publishing"),
        ("legal-published", "published"),
        ("legal-dlx", "dlx"),
    ] {
        let event_id = unique_event_id(suffix);
        let entry = make_entry(&event_id);
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry, &make_test_env("terminal-check", "event"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        set_outbox_terminal_for_test(&store, &event_id, status, 0).await?;
    }

    let invalid = [
        (
            "pending-with-published",
            "pending",
            true,
            false,
            "outbox_published_at_matches_status",
        ),
        (
            "publishing-with-dlx",
            "publishing",
            false,
            true,
            "outbox_dlx_at_matches_status",
        ),
        (
            "published-without-time",
            "published",
            false,
            false,
            "outbox_published_at_matches_status",
        ),
        (
            "published-with-dlx",
            "published",
            true,
            true,
            "outbox_dlx_at_matches_status",
        ),
        (
            "dlx-without-time",
            "dlx",
            false,
            false,
            "outbox_dlx_at_matches_status",
        ),
        (
            "dlx-with-published",
            "dlx",
            true,
            true,
            "outbox_published_at_matches_status",
        ),
    ];
    for (suffix, status, has_published_at, has_dlx_at, constraint) in invalid {
        let event_id = unique_event_id(suffix);
        let entry = make_entry(&event_id);
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry, &make_test_env("terminal-check", "event"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        let result = sqlx::query(
            r#"
            UPDATE outbox
            SET status = $1,
                published_at = CASE WHEN $2 THEN now() ELSE NULL END,
                dlx_at = CASE WHEN $3 THEN now() ELSE NULL END
            WHERE event_id = $4
            "#,
        )
        .bind(status)
        .bind(has_published_at)
        .bind(has_dlx_at)
        .bind(&event_id)
        .execute(&store.pool)
        .await;
        let Err(error) = result else {
            return Err(
                format!("invalid terminal fixture unexpectedly persisted: {suffix}").into(),
            );
        };
        assert!(
            error.to_string().contains(constraint),
            "unexpected constraint for {suffix}: {error}"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_terminal_timestamp_catalog_matches_current_authority() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let indexdef: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_outbox_sweep'",
    )
    .fetch_one(&store.pool)
    .await?;
    let normalized_index = indexdef.to_ascii_lowercase();
    assert!(normalized_index.contains("(published_at)"));
    assert!(normalized_index.contains("where (status = 'published'::text)"));
    assert!(!normalized_index.contains("created_at"));

    let sweep_def: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('rss_sweep_outbox_published(bigint)'::regprocedure)",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(sweep_def.contains("p_retain_seconds <= 0"));
    assert!(sweep_def.contains("published_at <="));
    assert!(!sweep_def.contains("created_at"));

    type FunctionSecurity = (String, String, bool, bool, bool, bool, bool);
    let functions: Vec<FunctionSecurity> = sqlx::query_as(
        r#"
        SELECT p.oid::regprocedure::text,
               owner.rolname,
               owner.rolcanlogin,
               p.prosecdef,
               COALESCE('search_path=public, pg_temp' = ANY(p.proconfig), false),
               NOT EXISTS (
                   SELECT 1
                   FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
                   WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
               ),
               has_function_privilege('rss_app', p.oid, 'EXECUTE')
        FROM pg_proc p
        JOIN pg_roles owner ON owner.oid = p.proowner
        WHERE p.oid IN (
            'rss_outbox_settle_published(text, uuid)'::regprocedure,
            'rss_outbox_mark_dlx(text, integer, uuid)'::regprocedure,
            'rss_outbox_redrive(text, uuid)'::regprocedure,
            'rss_sweep_outbox_published(bigint)'::regprocedure
        )
        ORDER BY p.oid::regprocedure::text
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(functions.len(), 4);
    for (signature, owner, owner_can_login, security_definer, fixed_path, no_public, app_exec) in
        functions
    {
        assert_eq!(owner, "rss_outbox_maintenance", "owner drift: {signature}");
        assert!(
            !owner_can_login,
            "function owner must be NOLOGIN: {signature}"
        );
        assert!(security_definer, "SECURITY DEFINER drift: {signature}");
        assert!(fixed_path, "search_path drift: {signature}");
        assert!(no_public, "PUBLIC execute drift: {signature}");
        assert!(app_exec, "rss_app execute drift: {signature}");
    }

    store.shutdown().await?;
    Ok(())
}

/// 0045：legacy reconcile_actions 的 terminal result 必须先 backfill 到 reconcile_attempt_results。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0045_backfills_legacy_reconcile_action_results() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    create_rss_app_role_for_migration_test(&store).await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0041_create_reconcile_schema.sql"
    ))
    .execute(&store.pool)
    .await?;

    let tenant = vocab::TenantId::parse("11111111-1111-1111-1111-111111111111")?;
    let target_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_targets (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'migration-reconciler', 'device', 'migration-device') \
         RETURNING target_id::text",
    )
    .bind(tenant.to_string())
    .fetch_one(&store.pool)
    .await?;
    let attempt_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_attempts \
         (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind) \
         VALUES ($1::uuid, $2::uuid, gen_random_uuid(), 1, 'holder-a', 'resync') \
         RETURNING attempt_id::text",
    )
    .bind(tenant.to_string())
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO reconcile_actions \
         (tenant_id, attempt_id, target_id, action_kind, result_label, requeue_after_ms, error_kind) \
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'update', 'transient', NULL, NULL)",
    )
    .bind(tenant.to_string())
    .bind(&attempt_id.0)
    .bind(&target_id.0)
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../migrations/0044_create_reconcile_attempt_results.sql"
    ))
    .execute(&store.pool)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0045_reconcile_actions_recorded_label.sql"
    ))
    .execute(&store.pool)
    .await?;

    let result: (String, Option<String>) = sqlx::query_as(
        "SELECT result_label, error_kind \
         FROM reconcile_attempt_results \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&attempt_id.0)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        result,
        ("transient".to_string(), Some("transient".to_string())),
        "0045 must preserve legacy terminal result before action rows become recorded"
    );

    let action: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT result_label, requeue_after_ms, error_kind \
         FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&attempt_id.0)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(action, ("recorded".to_string(), None, None));

    store.shutdown().await?;
    Ok(())
}

async fn create_rss_app_role_for_migration_test(store: &PgStore) -> TestResult {
    sqlx::raw_sql(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app NOLOGIN NOBYPASSRLS;
            END IF;
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_outbox_maintenance') THEN
                CREATE ROLE rss_outbox_maintenance NOLOGIN BYPASSRLS;
            END IF;
        END
        $$;
        GRANT USAGE ON SCHEMA public TO rss_app;
        "#,
    )
    .execute(&store.pool)
    .await?;
    Ok(())
}

async fn apply_outbox_legacy_prereqs_through_0031(store: &PgStore) -> TestResult {
    create_rss_app_role_for_migration_test(store).await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0031_harden_outbox_tenant_scope.sql"
    ))
    .execute(&store.pool)
    .await?;
    Ok(())
}

/// 0036：已知 legacy contract 行按 0035 同源 map 回填物理列；legacy causation 为 NULL。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_backfills_known_legacy_contract_columns() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    let event_id = unique_event_id("known-0036");
    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'identity.session-created', 'identity.session-created', $2, $3::jsonb, 'pending')",
    )
    .bind(&event_id)
    .bind(b"payload".as_slice())
    .bind(serde_json::json!({ "tenantId": COTX_TENANT_A }).to_string())
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await?;

    let row: (String, String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT contract_version, schema_hash, causation_id, metadata->>'schemaVersion', metadata->>'schemaHash' \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, "v1");
    assert_eq!(
        row.1,
        "sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516"
    );
    assert_eq!(row.2, None, "legacy row causation_id 应为 NULL");
    assert_eq!(row.3.as_deref(), Some(row.0.as_str()));
    assert_eq!(row.4.as_deref(), Some(row.1.as_str()));

    store.shutdown().await?;
    Ok(())
}

/// 0036：未知 legacy contract 且缺 schema header 时 fail-fast，不写 `unknown` 兼容值。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_rejects_unknown_legacy_schema_headers() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'unknown', 'unknown.event', 'unknown.contract', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("unknown-0036"))
    .bind(b"payload".as_slice())
    .bind(serde_json::json!({ "tenantId": COTX_TENANT_A }).to_string())
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    let result = sqlx::raw_sql(include_str!(
        "../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err("0036 must reject unknown legacy outbox schema headers".into());
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox schema column backfill requires generated known contract map"),
        "unexpected migration error: {rendered}"
    );
    assert!(
        rendered.contains("bad_rows=1") && rendered.contains("domain=unknown"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0036：未知 legacy contract 即便带格式合法 schema headers 也 fail-fast；不信任 metadata 自证契约。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_rejects_unknown_legacy_even_with_valid_schema_headers() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'unknown', 'unknown.event', 'unknown.contract', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("unknown-valid-0036"))
    .bind(b"payload".as_slice())
    .bind(
        serde_json::json!({
            "tenantId": COTX_TENANT_A,
            "schemaVersion": "v1",
            "schemaHash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })
        .to_string(),
    )
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    let result = sqlx::raw_sql(include_str!(
        "../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err(
            "0036 must reject unknown legacy rows even with valid metadata schema headers".into(),
        );
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox schema column backfill requires generated known contract map"),
        "unexpected migration error: {rendered}"
    );
    assert!(
        rendered.contains("bad_rows=1") && rendered.contains("domain=unknown"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0036：已知 legacy contract 的 schema metadata 必须匹配 generated map，不能被历史 metadata 覆盖。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_rejects_known_contract_schema_metadata_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'identity.session-created', 'identity.session-created', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("known-mismatch-0036"))
    .bind(b"payload".as_slice())
    .bind(
        serde_json::json!({
            "tenantId": COTX_TENANT_A,
            "schemaVersion": "v2",
            "schemaHash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        })
        .to_string(),
    )
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    let result = sqlx::raw_sql(include_str!(
        "../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err(
            "0036 must reject known contract metadata that mismatches generated map".into(),
        );
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox known contract schema headers mismatch generated map"),
        "unexpected migration error: {rendered}"
    );
    assert!(
        rendered.contains("bad_rows=1") && rendered.contains("identity.session-created"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0031：tenant_id backfill 接受 typed TenantId 契约允许的 canonical UUIDv7。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0031_accepts_canonical_uuid_v7_tenant_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;
    sqlx::raw_sql(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app NOLOGIN NOBYPASSRLS;
            END IF;
        END
        $$;
        GRANT USAGE ON SCHEMA public TO rss_app;
        "#,
    )
    .execute(&store.pool)
    .await?;

    let tenant_v7 = "01890f9d-7bb3-7cc0-98c4-dc0c0c07398f";
    assert!(
        vocab::TenantId::parse(tenant_v7).is_ok(),
        "anti-vacuity: fixture must be a valid typed TenantId"
    );
    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'test.event', 'contract-1', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("uuid-v7-outbox-tenant"))
    .bind(b"payload".as_slice())
    .bind(serde_json::json!({ "tenantId": tenant_v7 }).to_string())
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../migrations/0031_harden_outbox_tenant_scope.sql"
    ))
    .execute(&store.pool)
    .await?;

    let row: (String,) =
        sqlx::query_as("SELECT tenant_id::text FROM outbox WHERE metadata->>'tenantId' = $1")
            .bind(tenant_v7)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row.0, tenant_v7);

    store.shutdown().await?;
    Ok(())
}

/// 0031 权限面：rss_app 不能直接全域 UPDATE/DELETE outbox，只能 EXECUTE 固定 relay/maintenance 函数。
#[tokio::test(flavor = "multi_thread")]
async fn outbox_rss_app_uses_fixed_functions_not_direct_global_dml() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let event_id = unique_event_id("outbox-rss-app-perm");
    let entry = make_entry(&event_id);
    let env = make_test_env("outbox-perm", "c");
    store
        .run_global_transaction::<_, _, sqlx::Error>(|cap| {
            let entry = entry.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let mut tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *tx)
        .await?;
    crate::cotx::set_local_tenant(&mut tx, test_tenant()).await?;
    let direct_update = sqlx::query("UPDATE outbox SET status = 'published' WHERE event_id = $1")
        .bind(&event_id)
        .execute(&mut *tx)
        .await;
    assert!(
        direct_update.is_err(),
        "rss_app must not directly mutate outbox relay state"
    );
    tx.rollback().await?;

    for (limit_sql, expected) in [
        ("NULL::bigint", "poll limit must be non-null"),
        ("0", "poll limit must be in range"),
        ("10001", "poll limit must be in range"),
    ] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        crate::cotx::set_local_tenant(&mut tx, test_tenant()).await?;
        let result = sqlx::query(&format!(
            "SELECT * FROM rss_outbox_poll_pending('outbox-perm', {limit_sql})"
        ))
        .execute(&mut *tx)
        .await;
        let Err(err) = result else {
            return Err("rss_app poll_pending must reject invalid limits".into());
        };
        assert!(
            err.to_string().contains(expected),
            "unexpected poll_pending limit error for {limit_sql}: {err}"
        );
        tx.rollback().await?;
    }

    set_outbox_terminal_for_test(&store, &event_id, STATUS_PUBLISHED, 0).await?;
    for (invalid_retain, label) in [(Some(0_i64), "0"), (Some(-1_i64), "-1"), (None, "NULL")] {
        let invalid_sweep = sqlx::query("SELECT rss_sweep_outbox_published($1)")
            .bind(invalid_retain)
            .execute(&store.pool)
            .await;
        let Err(invalid_sweep_error) = invalid_sweep else {
            return Err(
                format!("rss_sweep_outbox_published must reject retain seconds {label}").into(),
            );
        };
        assert!(
            invalid_sweep_error
                .to_string()
                .contains("retain seconds must be positive"),
            "unexpected invalid sweep error: {invalid_sweep_error}"
        );
        let remains: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(remains, 1, "invalid retention {label} must not delete rows");
    }

    let can_execute: (bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT has_function_privilege('rss_app', 'rss_outbox_poll_pending(text, bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_acquire_lease(text)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_settle_published(text, uuid)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_mark_dlx(text, int, uuid)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_redrive(text, uuid)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_sweep_outbox_published(bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_sample_backlog(text)', 'EXECUTE')
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        can_execute,
        (true, true, true, true, true, true, true),
        "rss_app should only receive the fixed outbox function surface"
    );

    store.shutdown().await?;
    Ok(())
}

/// t28：crash recovery 保持 partition 顺序（stale publishing 头 gate 后继）。
///
/// append H, S2 同 partition；置 H status='publishing', updated_at 很久之前（模拟崩溃）；
/// poll → 仅 H（stale publishing 被重捞，S2 被 gate）；relay H→published → poll → S2。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t28_crash_recovery_preserves_partition_order() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t28");
    let key = PartitionKey::parse("part-crash").unwrap();

    let h_id = unique_event_id("t28-H");
    let s2_id = unique_event_id("t28-S2");

    // append H, S2 同 partition。
    for eid in [&h_id, &s2_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // 模拟 H 崩溃：status=publishing, updated_at 回拨超 LEASE_TTL。
    sqlx::query(
        "UPDATE outbox SET status='publishing', updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
    )
    .bind(LEASE_TTL_SECONDS + 10)
    .bind(&h_id)
    .execute(&store.pool)
    .await?;

    let (pub_ok, _) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_with_publisher(&store, pub_ok);

    // poll → 仅 H（stale publishing 可捞，S2 被 gate）。
    let entries = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries.len(), 1, "t28: crash recovery 仅应返回 H");
    assert_eq!(entries[0].idem_key().as_str(), h_id, "t28: 返回的必须是 H");
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t28: S2 被 stale-publishing H gate，不应出现"
    );

    // relay H → published。
    let h_entry = entries.into_iter().next().unwrap();
    let disp = outbox.relay(&h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t28: relay H 应返 Ack");

    // poll → S2（H published 后解锁）。
    let entries2 = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries2.len(), 1, "t28: 第二轮 poll 应仅返 S2");
    assert_eq!(
        entries2[0].idem_key().as_str(),
        s2_id,
        "t28: 第二轮 poll 必须是 S2"
    );

    store.shutdown().await?;
    Ok(())
}

/// t29：sample_backlog 计入 gated 后继（backlog poll-only by design）。
///
/// H + 3 后继同 partition → `sample_backlog.depth()==4`（gate 不减 depth）；
/// `poll_pending` 返 1（仅队头）。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t29_sample_backlog_counts_gated_successors() -> TestResult {
    use consistency::PartitionKey;
    use eventexec::{DlqRedriveOutcome, DlqRedriveRequest, DlqStore as _, OperatorDlqCapability};

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t29");
    let key = PartitionKey::parse("part-backlog").unwrap();

    // append H + 3 后继同 partition。
    let ids: Vec<_> = (0..4)
        .map(|i| unique_event_id(&format!("t29-{i}")))
        .collect();
    for eid in &ids {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let outbox = make_pg_outbox(&store, || Ok(()));

    // sample_backlog depth = 4（全部计入，gate 不减少 backlog 深度）。
    let samples = outbox.sample_backlog(&domain).await?;
    assert_eq!(
        samples.len(),
        1,
        "t29: 单 contract backlog 应产生一个 metric sample"
    );
    assert_eq!(
        samples[0].partition_blocked_depth(),
        3,
        "t29: H 后 3 个同 partition 后继必须计入 blocked depth"
    );
    let sample = summarize_backlog(&samples);
    assert_eq!(
        sample.depth(),
        4,
        "t29: backlog depth 应计入所有 4 行（含 gated 后继），实际={}",
        sample.depth()
    );
    assert_eq!(
        sample.oldest_age_seconds(),
        0,
        "t29: fresh rows，gate 不扭曲 age（age 应为 0 秒），实际={}",
        sample.oldest_age_seconds()
    );

    // poll_pending 仅返 1（队头）——反真空：gate 确实生效。
    let polled = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(
        polled.len(),
        1,
        "t29: poll_pending 应仅返队头（1 行），gate 生效"
    );
    assert_eq!(
        polled[0].idem_key().as_str(),
        ids[0],
        "t29: poll_pending 返回的必须是 H（最小 seq 的队头）"
    );

    let dlx_domain = unique_domain("t29-dlx");
    let dlx_key = PartitionKey::parse("part-backlog-dlx").unwrap();
    let dlx_ids: Vec<_> = (0..3)
        .map(|i| unique_event_id(&format!("t29-dlx-{i}")))
        .collect();
    for eid in &dlx_ids {
        let entry = make_entry(eid);
        let env = make_test_env(&dlx_domain, "c").with_partition_key_opt(Some(dlx_key.clone()));
        store
            .run_global_transaction::<_, _, sqlx::Error>(|cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    set_outbox_terminal_for_test(&store, &dlx_ids[0], STATUS_DLX, 0).await?;

    let dlx_samples = outbox.sample_backlog(&dlx_domain).await?;
    assert_eq!(
        dlx_samples[0].partition_blocked_depth(),
        2,
        "t29: DLX 队头后 2 个同 partition 后继必须计入 blocked depth"
    );
    assert_eq!(
        summarize_backlog(&dlx_samples).depth(),
        2,
        "t29: DLX 队头本身不计入 pending backlog depth，后继仍计入"
    );
    assert!(
        outbox.poll_pending(&dlx_domain, 10).await?.is_empty(),
        "t29: DLX 队头必须阻塞同 partition 后继投递"
    );

    let dlq = store.dlq_without_payload_replay();
    let redrive = dlq
        .redrive_outbox(DlqRedriveRequest::new(
            test_tenant(),
            IdemKey::parse(&dlx_ids[0]).unwrap(),
            OperatorDlqCapability::issue_for_authorized_operator(),
        ))
        .await?;
    assert_eq!(redrive, DlqRedriveOutcome::Redriven);

    let redriven_head = outbox.poll_pending(&dlx_domain, 10).await?;
    assert_eq!(redriven_head.len(), 1, "t29: redrive 后仅队头可投递");
    assert_eq!(redriven_head[0].idem_key().as_str(), dlx_ids[0]);
    let disp = outbox.relay(&redriven_head[0]).await?;
    assert_eq!(disp, Disposition::Ack, "t29: redriven 队头应成功发布");

    let unblocked = outbox.poll_pending(&dlx_domain, 10).await?;
    assert_eq!(unblocked.len(), 1, "t29: 队头发布后仅第一后继可投递");
    assert_eq!(
        unblocked[0].idem_key().as_str(),
        dlx_ids[1],
        "t29: DLX 队头发布后必须按 partition 顺序解除第一后继"
    );

    store.shutdown().await?;
    Ok(())
}

/// t30：partition_key 经**真实 public port** `OutboxEnvelopeParts::with_partition_key` → `PgEmitter::emit`
/// 落库（F5，#1211 review）。t24-t29 直调 adapter-private `OutboxEnvelope::with_partition_key_opt` 验 gating；
/// 本用例补最易漏接的 **public port → adapter envelope 映射层**：经 `PgEmitter::emit` 写入后 `SELECT
/// partition_key` 应等于传入 key（证 `into_parts` → `with_partition_key_opt` → INSERT $8 全链路透传）。
#[tokio::test]
#[allow(clippy::unwrap_used)]
// reason: 集成测试构造已知合法输入，item-level carve-out。
async fn t30_with_partition_key_persists_via_real_emit_port() -> TestResult {
    use consistency::PartitionKey;
    use diport::{OutboxEmitter, OutboxEnvelopeParts};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let event_id = unique_event_id("t30-pk-port");
    let entry = EventEntry::new(
        EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        reviewed_payload(br#"{"sessionId":"s"}"#),
    );
    // tenant-scoped key（推荐形态 <tenantId>:<aggregateId>）经 public builder 传入。
    let pk = "tenant-7:session-42";
    crate::PgEmitter::new(&store, fixed_clock())
        .emit(
            entry,
            OutboxEnvelopeParts::new(
                session_contract(),
                test_tenant(),
                subject_id("subj-opaque-30"),
                actor_for(test_tenant()),
            )
            .with_partition_key(PartitionKey::parse(pk).unwrap()),
        )
        .await?;

    let row: (Option<String>,) =
        sqlx::query_as("SELECT partition_key FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        row.0.as_deref(),
        Some(pk),
        "t30: public port with_partition_key 应经 into_parts → adapter envelope → INSERT 透传落库"
    );

    store.shutdown().await?;
    Ok(())
}

/// t14：驱动**真实** `persist_session_and_emit` 的 rollback 分支——session INSERT 因 `to_timestamp` 溢出失败
/// → co-tx 整体回滚 → session/outbox 两行皆无（OUTBOX-COTX-SESSION-01 负向 anti-vacuity，直测真实 method；
/// review #1192 F1：补 t12 仅复刻 SQL 序列的盲区）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t14_cotx_real_method_rollback_on_session_insert_failure() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t14-sess");
    let event_id = unique_event_id("t14-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    // expires_at 远超 Postgres timestamptz 上界（年 ~294277）：`to_timestamp(1e13 秒 ≈ 年 ~318850)` 溢出报错
    // → session INSERT 失败，驱动真实 `PgSessionLifecycle` 的 `write_session_and_outbox`→Err→rollback 分支。
    let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000_000_000);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);

    let result = crate::PgSessionLifecycle::new(&store, fixed_clock())
        .persist_session_and_emit(
            identity_scope(tenant),
            session,
            session_entry(&event_id),
            session_envelope(),
        )
        .await;
    assert!(
        result.is_err(),
        "session INSERT 溢出应使真实 co-tx method 返 Err"
    );

    // 真实 method rollback → 两行皆无（both-or-neither）。
    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 0, "真实 method 回滚后 session 行不应存在");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "真实 method 回滚后 outbox 行不应存在");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn session_fact_conflict_rolls_back_session_insert() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = TenantId::parse(COTX_TENANT_A)?;
    let event_id = unique_event_id("session-fact-conflict");
    let session_id = unique_event_id("session-fact-conflict-row");
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);

    let conflict = crate::PgSessionLifecycle::new(&store, fixed_clock())
        .persist_session_and_emit(
            identity_scope(tenant),
            session,
            session_entry(&event_id),
            session_envelope(),
        )
        .await;
    let Err(conflict) = conflict else {
        return Err("session write must fail on a conflicting outbox fact".into());
    };
    assert_eq!(conflict.kind(), OutboxEmitErrorKind::FactConflict);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_id)
            .fetch_one(&store.pool)
            .await?,
        0,
        "outbox conflict must roll back the session insert"
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;

    store.shutdown().await?;
    Ok(())
}

/// t14b：`PgSessionLifecycle` 接入 L2 co-tx conformance：成功两边皆在，真实写失败两边皆无。
/// tenant mismatch 拒绝语义由 t11b 专项覆盖；`OutboxEmitError` 的 source 脱敏边界不暴露错误 kind，
/// 因此不把 tenant mismatch 放进需要精确错误分类的 rejected 分支。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t14b_session_lifecycle_cotx_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let overflow_expires = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000_000_000);

    let ok_session_id = unique_event_id("t14b-ok-sess");
    let ok_event_id = unique_event_id("t14b-ok-evt");
    let fail_session_id = unique_event_id("t14b-fail-sess");
    let fail_event_id = unique_event_id("t14b-fail-evt");
    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());

    testkit::repo_conformance::assert_cotx_commit_and_failure_both_or_neither(
        testkit::repo_conformance::CotxCase {
            action: || async {
                let session = identity::test_support::session(
                    &ok_session_id,
                    "subj-cotx-ok",
                    tenant,
                    expires,
                    created,
                );
                lifecycle
                    .persist_session_and_emit(
                        identity_scope(tenant),
                        session,
                        session_entry(&ok_event_id),
                        session_envelope(),
                    )
                    .await
            },
            business_exists: || async {
                session_row_exists(&store, &ok_session_id)
                    .await
                    .map_err(OutboxEmitError::new)
            },
            outbox_exists: || async {
                outbox_row_exists(&store, &ok_event_id)
                    .await
                    .map_err(OutboxEmitError::new)
            },
        },
        testkit::repo_conformance::CotxCase {
            action: || async {
                let session = identity::test_support::session(
                    &fail_session_id,
                    "subj-cotx-fail",
                    tenant,
                    overflow_expires,
                    created,
                );
                lifecycle
                    .persist_session_and_emit(
                        identity_scope(tenant),
                        session,
                        session_entry(&fail_event_id),
                        session_envelope(),
                    )
                    .await
            },
            business_exists: || async {
                session_row_exists(&store, &fail_session_id)
                    .await
                    .map_err(OutboxEmitError::new)
            },
            outbox_exists: || async {
                outbox_row_exists(&store, &fail_event_id)
                    .await
                    .map_err(OutboxEmitError::new)
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

async fn session_row_exists(store: &PgStore, session_id: &str) -> Result<bool, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(session_id)
        .fetch_one(&store.pool)
        .await?;
    Ok(count.0 == 1)
}

async fn outbox_row_exists(store: &PgStore, event_id: &str) -> Result<bool, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(event_id)
        .fetch_one(&store.pool)
        .await?;
    Ok(count.0 == 1)
}

// ── T20–T22: PgSessionLifecycle durable find/revoke（合并端口后完整生命周期，#1278；原 #1116）──────────
//
// 第二租户（跨租隔离 t22）——与 config/secret 测试 TENANT_B 同值。
const COTX_TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

/// t20：persist → `find` 命中，重建 session 字段（subject/tenant/时刻）与持久化一致。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t20_find_returns_persisted_session() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t15-sess");
    let event_id = unique_event_id("t15-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-find", tenant, expires, created);
    let sid = session.id().clone();

    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());
    lifecycle
        .persist_session_and_emit(
            identity_scope(tenant),
            session,
            session_entry(&event_id),
            session_envelope(),
        )
        .await?;

    // find 命中：经 Session::hydrate 重建，字段（含 epoch 时刻 roundtrip）与持久化一致。
    let s = lifecycle
        .find(identity_scope(tenant), sid)
        .await?
        .expect("persisted session should be found");
    assert_eq!(s.id().as_str(), session_id, "session_id roundtrip");
    assert_eq!(s.subject(), "subj-find", "subject roundtrip");
    assert_eq!(s.tenant(), tenant, "tenant roundtrip");
    assert_eq!(s.expires_at(), expires, "expires_at epoch roundtrip");
    assert_eq!(s.created_at(), created, "created_at epoch roundtrip");

    store.shutdown().await?;
    Ok(())
}

/// t21：`revoke` → `find` 返回 None（软撤销）；重复 / 未知 sid revoke 仍 Ok（幂等）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t21_revoke_soft_deletes_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t16-sess");
    let event_id = unique_event_id("t16-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-revoke", tenant, expires, created);
    let sid = session.id().clone();

    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());
    lifecycle
        .persist_session_and_emit(
            identity_scope(tenant),
            session,
            session_entry(&event_id),
            session_envelope(),
        )
        .await?;
    assert!(
        lifecycle
            .find(identity_scope(tenant), sid.clone())
            .await?
            .is_some(),
        "revoke 前应能 find 到"
    );

    // 软撤销 → find None（行仍在、revoked=true）。
    lifecycle
        .revoke(identity_scope(tenant), sid.clone())
        .await?;
    assert!(
        lifecycle
            .find(identity_scope(tenant), sid.clone())
            .await?
            .is_none(),
        "revoke 后 find 应 None"
    );
    let row_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(row_cnt.0, 1, "软撤销不删行（行仍在、revoked=true）");

    // 幂等：重复 revoke + 未知 sid revoke 均 Ok。
    lifecycle.revoke(identity_scope(tenant), sid).await?;
    let ghost = identity::test_support::session(
        &unique_event_id("t16-ghost"),
        "x",
        tenant,
        expires,
        created,
    );
    lifecycle
        .revoke(identity_scope(tenant), ghost.id().clone())
        .await?;

    store.shutdown().await?;
    Ok(())
}

/// t22：跨租 revoke no-op（不撤销他租会话）+ 跨租 find None；同租 revoke 生效。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t22_cross_tenant_revoke_and_find_isolated() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t17-sess");
    let event_id = unique_event_id("t17-evt");
    let tenant_a = TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = TenantId::parse(COTX_TENANT_B).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-iso", tenant_a, expires, created);
    let sid = session.id().clone();

    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());
    lifecycle
        .persist_session_and_emit(
            identity_scope(tenant_a),
            session,
            session_entry(&event_id),
            session_envelope(),
        )
        .await?;

    // 跨租 find（tenant B 查 tenant A sid）→ None（不泄露存在性）。
    assert!(
        lifecycle
            .find(identity_scope(tenant_b), sid.clone())
            .await?
            .is_none(),
        "跨租 find 应 None"
    );
    // 跨租 revoke（tenant B）→ no-op：tenant A 会话仍 find 到。
    lifecycle
        .revoke(identity_scope(tenant_b), sid.clone())
        .await?;
    assert!(
        lifecycle
            .find(identity_scope(tenant_a), sid.clone())
            .await?
            .is_some(),
        "跨租 revoke 不应撤销 tenant A 的会话"
    );
    // 同租 revoke → find None（隔离正确、撤销生效）。
    lifecycle
        .revoke(identity_scope(tenant_a), sid.clone())
        .await?;
    assert!(
        lifecycle
            .find(identity_scope(tenant_a), sid)
            .await?
            .is_none(),
        "同租 revoke 后 find 应 None"
    );

    store.shutdown().await?;
    Ok(())
}

/// t22b：`PgSessionLifecycle` 接入 tenant no-op conformance：跨租 find 不可见、跨租 revoke 不影响 owner。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn t22b_session_lifecycle_tenant_noop_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t22b-sess");
    let event_id = unique_event_id("t22b-evt");
    let tenant_a = TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = TenantId::parse(COTX_TENANT_B).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-iso", tenant_a, expires, created);
    let sid = session.id().clone();
    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());

    testkit::repo_conformance::assert_cross_tenant_noop(
        || async {
            lifecycle
                .persist_session_and_emit(
                    identity_scope(tenant_a),
                    session,
                    session_entry(&event_id),
                    session_envelope(),
                )
                .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                lifecycle
                    .find(identity_scope(tenant_a), sid.clone())
                    .await?
                    .is_some(),
            )
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                lifecycle
                    .find(identity_scope(tenant_b), sid.clone())
                    .await?
                    .is_some(),
            )
        },
        || async {
            lifecycle
                .revoke(identity_scope(tenant_b), sid.clone())
                .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                lifecycle
                    .find(identity_scope(tenant_a), sid.clone())
                    .await?
                    .is_some(),
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// t22c：`PgSessionLifecycle` 接入 storage error conformance：底座关闭后 `find` 映射为
/// `IdentityError::Storage`。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn t22c_session_lifecycle_storage_error_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let session = identity::test_support::session(
        &unique_event_id("t22c-sess"),
        "subj-storage",
        tenant,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_003_600),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    );
    let sid = session.id().clone();
    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async {
            lifecycle
                .find(identity_scope(tenant), sid)
                .await
                .map(|_| ())
        },
        |e| matches!(e, identity::ports::IdentityError::Storage(_)),
    )
    .await?;

    Ok(())
}

// ── PgConfigRepo / PgConfigUnitOfWork：配置仓储 + co-tx 集成测试（#1249）─────────────
//
// OUTBOX-COTX-CONFIG-01 anti-vacuity：正向 `tc5` 证真实 method commit 两行皆在 ↔ 负向双覆盖——`tc6` 经真实
// `co_tx_with_outbox`（业务写真插一行后强制 Err）证两写共回滚，`tc7` 驱动真实 `commit` 的 CAS
// 冲突分支证「冲突 → 无 outbox 行」（write-without-event 不发生）。

use settings::ports::{
    ConfigEntry, ConfigHead, ConfigMutation, ConfigRepo, ConfigRepoError, ConfigTombstone,
    ConfigUnitOfWork, SettingKey, TenantRepoScope,
};

use crate::config_repo::{arm_config_retry_failpoint, config_retry_failpoint_hits};
use crate::cotx::PgTenantPool;
use crate::tx_retry::{classify_config_repo_error, classify_identity_error};
use crate::{
    ConfigValueMaintenanceCapability, ConfigValueMaintenanceOperation,
    ConfigValueMaintenanceOptions, ConfigValueProtection, ConfigValueProtections, PgConfigRepo,
    PgConfigValueMaintenance,
};

/// config 测试用 canonical 租户 UUID（复用 co-tx 段 [`COTX_TENANT_A`] 同值，避免两 const 漂移）。
const CONFIG_TENANT: &str = COTX_TENANT_A;
/// 第二租户（跨租户隔离测试 tc9）——与 `application.rs` 单测 TENANT_B 同值。
const CONFIG_TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";
/// config-version-changed 契约 topic 局部单源。
const CONFIG_VERSION_CHANGED_TOPIC: &str = "settings.config-version-changed";

#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
fn config_tenant() -> TenantId {
    TenantId::parse(CONFIG_TENANT).unwrap()
}

#[allow(clippy::unwrap_used)]
fn config_maintenance_capability() -> ConfigValueMaintenanceCapability {
    ConfigValueMaintenanceCapability::new("test-operator").unwrap()
}

/// 构造 ConfigEntry（经 `ConfigEntry::hydrate` 跨 crate pub funnel）。
#[allow(clippy::unwrap_used)]
fn config_entry(key: &str, value: &str, version: u64) -> ConfigEntry {
    config_entry_for(config_tenant(), key, value, version)
}

#[allow(clippy::unwrap_used)]
fn config_entry_for(tenant: TenantId, key: &str, value: &str, version: u64) -> ConfigEntry {
    ConfigEntry::hydrate(SettingKey::parse(key).unwrap(), value, tenant, version)
}

struct AadBoundKeyProvider;

impl diport::KeyProvider for AadBoundKeyProvider {
    async fn encrypt(
        &self,
        key: diport::KeyName,
        plaintext: secure::Plaintext,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        let aad_bytes = aad.as_canonical_bytes();
        let mut ciphertext = Vec::with_capacity(4 + aad_bytes.len() + plaintext.expose().len());
        ciphertext.extend_from_slice(&(aad_bytes.len() as u32).to_be_bytes());
        ciphertext.extend_from_slice(aad_bytes);
        ciphertext.extend(plaintext.expose().iter().map(|b| b ^ 0xA5));
        Ok(diport::EncryptOutput::new(
            ciphertext,
            diport::KeyRef::new(key, diport::KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        let raw = ciphertext.as_bytes();
        if raw.len() < 4 {
            return Err(config_key_rejected());
        }
        let aad_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if raw.len() < 4 + aad_len {
            return Err(config_key_rejected());
        }
        let (stored_aad, plaintext) = raw[4..].split_at(aad_len);
        if stored_aad != aad.as_canonical_bytes() {
            return Err(config_key_rejected());
        }
        Ok(secure::Plaintext::new(
            plaintext.iter().map(|b| b ^ 0xA5).collect(),
        ))
    }

    async fn rewrap(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Ok(diport::EncryptOutput::new(ciphertext.into_bytes(), key))
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

struct RejectingKeyProvider;

impl diport::KeyProvider for RejectingKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn rewrap(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

struct UnavailableKeyProvider;

impl diport::KeyProvider for UnavailableKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_unavailable())
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_unavailable())
    }

    async fn rewrap(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_unavailable())
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

struct RewrappingKeyProvider;

impl diport::KeyProvider for RewrappingKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn rewrap(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Ok(diport::EncryptOutput::new(
            ciphertext.into_bytes(),
            diport::KeyRef::new(key.name().clone(), diport::KeyVersion::new(2)),
        ))
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

struct MutatingBackfillKeyProvider {
    pool: sqlx::PgPool,
}

impl diport::KeyProvider for MutatingBackfillKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        sqlx::query("UPDATE config_entries SET value = $1 WHERE config_key = $2")
            .bind("plain-v2")
            .bind("legacy.cas")
            .execute(&self.pool)
            .await
            .map_err(|_| config_key_unavailable())?;
        let key_name =
            diport::KeyName::try_new("settings-config").map_err(|_| config_key_rejected())?;
        Ok(diport::EncryptOutput::new(
            b"stale-ciphertext".to_vec(),
            diport::KeyRef::new(key_name, diport::KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn rewrap(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

fn config_key_rejected() -> diport::KeyProviderError {
    diport::KeyProviderError::new(
        diport::key_provider::KeyProviderErrorKind::Rejected,
        std::io::Error::other("test key provider rejected"),
    )
}

fn config_key_unavailable() -> diport::KeyProviderError {
    diport::KeyProviderError::new(
        diport::key_provider::KeyProviderErrorKind::Unavailable,
        std::io::Error::other("test key provider unavailable"),
    )
}

#[allow(clippy::unwrap_used)]
fn config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(AadBoundKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
fn config_protections() -> ConfigValueProtections {
    ConfigValueProtections::new(
        diport::DynKeyProvider::new_box(AadBoundKeyProvider),
        diport::DynKeyProvider::new_box(AadBoundKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
fn rejecting_config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(RejectingKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
fn unavailable_config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(UnavailableKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
fn rewrapping_config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(RewrappingKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
fn mutating_backfill_config_protection(pool: sqlx::PgPool) -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(MutatingBackfillKeyProvider { pool }),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

/// 构造 config-version-changed outbox EventEntry。
#[allow(clippy::unwrap_used)]
fn config_outbox_entry(event_id: &str) -> EventEntry {
    EventEntry::new(
        EventTopic::parse(CONFIG_VERSION_CHANGED_TOPIC).unwrap(),
        IdemKey::parse(event_id).unwrap(),
        reviewed_payload(br#"{"key":"app.k","version":1}"#),
    )
}

#[allow(clippy::unwrap_used)]
fn config_deleted_outbox_entry(event_id: &str, key: &str, version: u64) -> EventEntry {
    EventEntry::new(
        EventTopic::parse(CONFIG_VERSION_CHANGED_TOPIC).unwrap(),
        IdemKey::parse(event_id).unwrap(),
        reviewed_payload(
            &serde_json::to_vec(&serde_json::json!({
                "key": key,
                "version": version,
                "changeKind": "deleted"
            }))
            .unwrap(),
        ),
    )
}

/// 构造 config-version-changed envelope（opaque subject = 配置 key）。
fn config_envelope(subject: &str) -> OutboxEnvelopeParts {
    config_envelope_for(config_tenant(), subject)
}

fn config_envelope_for(tenant: TenantId, subject: &str) -> OutboxEnvelopeParts {
    OutboxEnvelopeParts::new(
        config_contract(),
        tenant,
        subject_id(subject),
        actor_for(tenant),
    )
}

trait ConfigTestWrite {
    async fn test_put(
        &self,
        scope: TenantRepoScope,
        entry: ConfigEntry,
    ) -> Result<(), ConfigRepoError>;

    async fn test_delete(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<(), ConfigRepoError>;
}

impl ConfigTestWrite for PgConfigRepo {
    async fn test_put(
        &self,
        scope: TenantRepoScope,
        entry: ConfigEntry,
    ) -> Result<(), ConfigRepoError> {
        let tenant = entry.tenant();
        let subject = entry.key().as_str().to_string();
        self.commit(
            scope,
            ConfigMutation::Put(entry),
            config_outbox_entry(&unique_event_id("config-test-put")),
            config_envelope_for(tenant, &subject),
        )
        .await
    }

    async fn test_delete(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<(), ConfigRepoError> {
        let tenant = scope.tenant();
        let Some(ConfigHead::Active(version)) = self.head(scope, key).await? else {
            return Ok(());
        };
        let result = self
            .commit(
                scope,
                ConfigMutation::Delete(ConfigTombstone::hydrate(
                    key.clone(),
                    tenant,
                    version.saturating_add(1),
                )),
                config_outbox_entry(&unique_event_id("config-test-delete")),
                config_envelope_for(tenant, key.as_str()),
            )
            .await;
        match result {
            Err(ConfigRepoError::VersionConflict)
                if matches!(self.head(scope, key).await?, Some(ConfigHead::Deleted(_))) =>
            {
                Ok(())
            }
            other => other,
        }
    }
}

/// setup：应用 migration（含 config_entries 表），清空 config_entries（防测试间污染）。outbox 用唯一
/// event_id 隔离断言，无需全表清。integration profile 串行执行（`.config/nextest.toml` `integration`
/// group `max-threads = 1` + self-provision 容器每轮独占），故全表 DELETE 无并发竞态。
async fn setup_config(store: &PgStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    sqlx::query("DELETE FROM config_entries")
        .execute(&store.pool)
        .await?;
    Ok(())
}

/// tc1：save → find round-trip（未写 → None；写后 getter 全字段正确）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1_config_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.timeout").unwrap();

    assert!(
        repo.find(settings_scope(tenant), &key).await?.is_none(),
        "未写入 → None"
    );

    repo.test_put(
        settings_scope(tenant),
        config_entry("app.timeout", "30s", 1),
    )
    .await?;
    let found = repo.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(found.value(), "30s", "find 取回值");
    assert_eq!(found.version(), 1, "find 取回版本");
    assert_eq!(found.key().as_str(), "app.timeout", "find 取回 key");
    assert_eq!(found.tenant(), tenant, "find 取回 tenant（tenant-correct）");
    let raw: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND version = 1",
    )
    .bind(CONFIG_TENANT)
    .bind("app.timeout")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(raw.0, None, "新写不得持久化 plaintext value");
    assert_eq!(raw.1, 1, "新写必须使用 encrypted scheme");
    assert!(raw.2.is_some(), "encrypted ciphertext present");
    let ciphertext = raw.2.unwrap();
    assert!(
        !ciphertext.windows(b"30s".len()).any(|w| w == b"30s"),
        "raw ciphertext must not contain plaintext"
    );
    assert_eq!(raw.3.as_deref(), Some("settings-config:1"));

    store.shutdown().await?;
    Ok(())
}

/// tc1a：legacy plaintext 行在 serving 读路径 fail-closed；只有 maintenance backfill 可读取。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1a_config_legacy_plaintext_read_fails_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, $3, $4, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.value")
    .bind(1_i64)
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), rejecting_config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("legacy.value").unwrap();
    let result = repo.find(settings_scope(tenant), &key).await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionAuthFailure(_))),
        "serving read path must reject legacy plaintext rows"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1c：fresh schema 不再给 `protection_scheme` 默认值，旧 INSERT 形态不能继续写明文。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1c_config_plaintext_insert_without_scheme_is_rejected() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;

    let result = sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value) \
         VALUES ($1::uuid, $2, $3, $4)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.default.rejected")
    .bind(1_i64)
    .bind("plain-v1")
    .execute(&store.pool)
    .await;

    assert!(
        result.is_err(),
        "old plaintext INSERT shape must fail after 0029 drops protection_scheme default"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1d：复制 encrypted row 到另一租户后，tenant 维度 AAD mismatch → fail-closed。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1d_config_encrypted_row_cross_tenant_copy_rejected() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.aad").unwrap();

    repo.test_put(
        settings_scope(tenant_a),
        config_entry("app.aad", "tenant-a-value", 1),
    )
    .await?;
    sqlx::query(
        "INSERT INTO config_entries (
             tenant_id, config_key, version, value, deleted, protection_scheme, value_enc, key_id
         )
         SELECT $1::uuid, config_key, version, value, deleted, protection_scheme, value_enc, key_id
         FROM config_entries
         WHERE tenant_id = $2::uuid AND config_key = $3 AND version = 1",
    )
    .bind(CONFIG_TENANT_B)
    .bind(CONFIG_TENANT)
    .bind("app.aad")
    .execute(&store.pool)
    .await?;

    let result = repo.find(settings_scope(tenant_b), &key).await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionAuthFailure(_))),
        "copied ciphertext under another tenant must fail AAD authentication"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1e：encrypted 行读取时 KeyProvider 不可用 → ProtectionUnavailable，且不回退明文。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1e_config_encrypted_read_provider_unavailable() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let reader = PgConfigRepo::new(&store, fixed_clock_arc(), unavailable_config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.kms").unwrap();

    writer
        .test_put(
            settings_scope(tenant),
            config_entry("app.kms", "encrypted-value", 1),
        )
        .await?;
    let result = reader.find(settings_scope(tenant), &key).await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionUnavailable(_))),
        "provider unavailable on encrypted read must surface ProtectionUnavailable"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1f：encrypted row 元数据损坏（bad key_id）→ ProtectionAuthFailure fail-closed。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1f_config_corrupt_encrypted_metadata_fails_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (
             tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
         )
         VALUES ($1::uuid, $2, $3, NULL, 1, $4, $5)",
    )
    .bind(CONFIG_TENANT)
    .bind("app.corrupt")
    .bind(1_i64)
    .bind(&b"ciphertext"[..])
    .bind("not-a-key-ref")
    .execute(&store.pool)
    .await?;

    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let result = repo
        .find(
            settings_scope(config_tenant()),
            &SettingKey::parse("app.corrupt").unwrap(),
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionAuthFailure(_))),
        "corrupt encrypted metadata must fail closed as auth failure"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1g：maintenance dry-run 只统计 legacy plaintext，不写库、不调用 KeyProvider。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1g_config_maintenance_dry_run_counts_legacy_without_provider() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.dry-run")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        rejecting_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(
            &ConfigValueMaintenanceOptions::new(ConfigValueMaintenanceOperation::Backfill)
                .with_dry_run(true),
        )
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 0);
    assert_eq!(report.failed, 0);
    assert_eq!(report.remaining_plaintext, 1);
    let row: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.dry-run")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0.as_deref(), Some("plain-v1"));
    assert_eq!(row.1, 0);
    assert!(row.2.is_none());
    assert!(row.3.is_none());

    store.shutdown().await?;
    Ok(())
}

/// tc1h：maintenance backfill 把 legacy plaintext 转为 encrypted scheme，随后普通读路径可读回原值。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1h_config_maintenance_backfills_legacy_plaintext() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.backfill")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Backfill,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 1);
    assert_eq!(report.remaining_plaintext, 0);
    let raw: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.backfill")
    .fetch_one(&store.pool)
    .await?;
    assert!(
        raw.0.is_none(),
        "backfill must remove plaintext column value"
    );
    assert_eq!(raw.1, 1);
    assert!(raw.2.is_some());
    assert_eq!(raw.3.as_deref(), Some("settings-config:1"));

    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let found = repo
        .find(
            settings_scope(config_tenant()),
            &SettingKey::parse("legacy.backfill").unwrap(),
        )
        .await?
        .unwrap();
    assert_eq!(found.value(), "plain-v1");

    store.shutdown().await?;
    Ok(())
}

/// tc1i：maintenance rewrap 更新 encrypted 行 key_id 到 provider current-primary，不调用 decrypt。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1i_config_maintenance_rewrap_updates_key_ref() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.rewrap", "v1", 1),
        )
        .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        rewrapping_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Rewrap,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.rewrapped, 1);
    assert_eq!(report.failed, 0);
    let key_id: (String,) =
        sqlx::query_as("SELECT key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.rewrap")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(key_id.0, "settings-config:2");

    let second = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Rewrap,
        ))
        .await?;
    assert_eq!(second.selected, 1);
    assert_eq!(second.unchanged, 1, "repeated rewrap is idempotent");

    store.shutdown().await?;
    Ok(())
}

/// tc1j：maintenance backfill provider failure leaves legacy row intact and reports failure.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1j_config_maintenance_backfill_failure_preserves_row() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.failure")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        unavailable_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Backfill,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(report.remaining_plaintext, 1);
    let row: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.failure")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0.as_deref(), Some("plain-v1"));
    assert_eq!(row.1, 0);
    assert!(row.2.is_none());
    assert!(row.3.is_none());

    store.shutdown().await?;
    Ok(())
}

/// tc1l：backfill update 带原 plaintext CAS；选中后被改动的行不会被 stale ciphertext 覆盖。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1l_config_maintenance_backfill_stale_row_is_unchanged() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.cas")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let pool = store.pool.clone();
    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        mutating_backfill_config_protection(pool),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Backfill,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 0);
    assert_eq!(report.unchanged, 1);
    assert_eq!(report.failed, 0);
    let row: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.cas")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0.as_deref(), Some("plain-v2"));
    assert_eq!(row.1, 0);
    assert!(row.2.is_none());
    assert!(row.3.is_none());

    store.shutdown().await?;
    Ok(())
}

/// tc1m：maintenance rewrap provider failure leaves encrypted row intact and reports failure.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1m_config_maintenance_rewrap_failure_preserves_row() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.rewrap_failure", "v1", 1),
        )
        .await?;
    let before: (Option<Vec<u8>>, Option<String>) =
        sqlx::query_as("SELECT value_enc, key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.rewrap_failure")
            .fetch_one(&store.pool)
            .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        unavailable_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Rewrap,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.rewrapped, 0);
    assert_eq!(report.failed, 1);
    let after: (Option<Vec<u8>>, Option<String>) =
        sqlx::query_as("SELECT value_enc, key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.rewrap_failure")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(after, before);

    store.shutdown().await?;
    Ok(())
}

/// tc1o：rewrap 遇到 malformed key_id 时计入 selected/failed，且消耗 max_rows 预算。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1o_config_maintenance_rewrap_invalid_key_ref_counts_as_failed_selected_row() -> TestResult
{
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme, value_enc, key_id) \
         VALUES ($1::uuid, $2, 1, NULL, 1, $3, $4)",
    )
    .bind(CONFIG_TENANT)
    .bind("encrypted.invalid_key_ref")
    .bind(b"ciphertext".as_slice())
    .bind("not-a-key-ref")
    .execute(&store.pool)
    .await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.valid_after_invalid", "v1", 1),
        )
        .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        rewrapping_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(
            &ConfigValueMaintenanceOptions::new(ConfigValueMaintenanceOperation::Rewrap)
                .with_max_rows(Some(1)),
        )
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.failed, 1);
    assert_eq!(report.rewrapped, 0);
    let key_id: (String,) =
        sqlx::query_as("SELECT key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.valid_after_invalid")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        key_id.0, "settings-config:1",
        "malformed selected row must consume the max_rows budget"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1k：tenant/max_rows 限制只处理指定租户内的限定行数。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1k_config_maintenance_tenant_and_max_rows_limit_scope() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    for key in ["legacy.scope_a", "legacy.scope_b"] {
        sqlx::query(
            "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
             VALUES ($1::uuid, $2, 1, $3, 0)",
        )
        .bind(CONFIG_TENANT)
        .bind(key)
        .bind("plain")
        .execute(&store.pool)
        .await?;
    }
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT_B)
    .bind("legacy.scope.other")
    .bind("plain")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(
            &ConfigValueMaintenanceOptions::new(ConfigValueMaintenanceOperation::Backfill)
                .with_tenant(config_tenant())
                .with_max_rows(Some(1)),
        )
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 1);
    assert_eq!(report.remaining_plaintext, 1);
    let all_remaining: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE protection_scheme = 0")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        all_remaining.0, 2,
        "one same-tenant row and one other-tenant row remain"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1n：默认 both 操作共享 `max_rows` 预算，不会 backfill N 行后再额外 rewrap N 行。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1n_config_maintenance_both_max_rows_is_shared() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.both_budget")
    .bind("plain")
    .execute(&store.pool)
    .await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.both_budget", "v1", 1),
        )
        .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::default().with_max_rows(Some(1)))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 1);
    assert_eq!(report.rewrapped, 0);
    let key_id: (String,) =
        sqlx::query_as("SELECT key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.both_budget")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(key_id.0, "settings-config:1");

    store.shutdown().await?;
    Ok(())
}

/// tc1b：经 `settings_bundle` funnel 解包的 `DynConfigRepo` 在真实 DB 上 save→find 闭合——验证 bundle
/// 预包装的 config 读写路径（非散装 `PgConfigRepo::new`）端到端可用（PG-BUNDLE-SETTINGS-04 集成覆盖，#1424）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1b_bundle_config_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    // 经 funnel：PgRuntimeDeps → for_domain::<Settings> → settings_bundle → into_parts（取 read config box）。
    let deps = crate::PgRuntimeDeps::from_store_for_test(std::sync::Arc::new(store));
    let (configs, writer, _secrets) = deps
        .for_domain::<crate::caps::Settings>()
        .settings_bundle(fixed_clock_arc(), config_protections())
        .into_parts();
    let tenant = config_tenant();
    let key = SettingKey::parse("bundle.timeout").unwrap();

    assert!(
        configs.find(settings_scope(tenant), &key).await?.is_none(),
        "未写入 → None"
    );
    writer
        .commit(
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("bundle.timeout", "30s", 1)),
            config_outbox_entry(&unique_event_id("bundle-read-write")),
            config_envelope("bundle.timeout"),
        )
        .await?;
    let found = configs.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(found.value(), "30s", "bundle DynConfigRepo find 取回值");
    assert_eq!(found.version(), 1, "bundle DynConfigRepo find 取回版本");
    Ok(())
}

/// tc1c：经 `settings_bundle` funnel 解包的 `writer`（`DynConfigUnitOfWork`）在真实 DB 上 `commit`
/// co-tx 落 config 行 + outbox 行 + 构造期注入 occurred_at——证 bundle write lane 与 direct co-tx（tc5）语义等价
/// （F2，#1424；补 tc1b 只覆盖 read lane 的缺口）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1c_bundle_writer_cotx_commits_config_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    // store 即将移入 deps（PG-BUNDLE-POOL-03 无 pool accessor）→ 先 clone pool 供验证查询。
    let pool = store.pool.clone();
    let deps = crate::PgRuntimeDeps::from_store_for_test(std::sync::Arc::new(store));
    let (_configs, writer, _secrets) = deps
        .for_domain::<crate::caps::Settings>()
        .settings_bundle(fixed_clock_arc(), config_protections())
        .into_parts();
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc1c-evt");

    writer
        .commit(
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("bundle.cotx", "v1", 1)),
            config_outbox_entry(&event_id),
            config_envelope("bundle.cotx"),
        )
        .await?;

    // config 行 + outbox 行 co-tx 两行皆在（tenant-correct）。
    let crow: (i64, String) = sqlx::query_as(
        "SELECT count(*), max(tenant_id::text) FROM config_entries WHERE config_key = $1 AND version = 1",
    )
    .bind("bundle.cotx")
    .fetch_one(&pool)
    .await?;
    assert_eq!(crow.0, 1, "bundle writer：config 行应写入");
    assert_eq!(crow.1, CONFIG_TENANT, "bundle writer：config 行 tenant_id");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 1,
        "bundle writer：outbox 行应写入（co-tx 两行皆在）"
    );
    // occurred_at 来自 bundle 构造期注入的 Arc clock（write lane 经 commit 用）。
    let cfg_meta: (String,) =
        sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&pool)
            .await?;
    assert!(
        cfg_meta
            .0
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "bundle writer co-tx outbox metadata 应含注入 clock 的 occurred_at: {}",
        cfg_meta.0
    );
    assert_metadata_text_has_standard_schema_header(&cfg_meta.0, "bundle writer co-tx outbox");
    Ok(())
}

/// tc2：版本历史——find = max(version)；find_version 取精确历史版本；缺失版本 → None。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc2_config_find_version_returns_history() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    repo.test_put(settings_scope(tenant), config_entry("app.k", "v1", 1))
        .await?;
    repo.test_put(settings_scope(tenant), config_entry("app.k", "v2", 2))
        .await?;

    assert_eq!(
        repo.find(settings_scope(tenant), &key)
            .await?
            .unwrap()
            .value(),
        "v2",
        "find = 最高版本"
    );
    assert_eq!(
        repo.find_version(settings_scope(tenant), &key, 1)
            .await?
            .unwrap()
            .value(),
        "v1",
        "find_version(1) = 历史 v1"
    );
    assert_eq!(
        repo.find_version(settings_scope(tenant), &key, 2)
            .await?
            .unwrap()
            .value(),
        "v2"
    );
    assert!(
        repo.find_version(settings_scope(tenant), &key, 9)
            .await?
            .is_none(),
        "缺失版本 → None"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc3：CAS——陈旧版本（重复）与跳版（gap）均 VersionConflict；恰 max+1 成功。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc3_config_save_cas_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_versioned_cas_repo(
        "v1".to_string(),
        "v1b".to_string(),
        "v3".to_string(),
        "v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.test_put(
                    settings_scope(tenant),
                    config_entry("app.k", &marker, version),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(settings_scope(tenant), key)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        |e| matches!(e, ConfigRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc3b：写前 seal 失败（provider unavailable）→ 不打开业务写事务、不落 config 行。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc3b_config_save_provider_unavailable_persists_nothing() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), unavailable_config_protection());
    let tenant = config_tenant();

    let result = repo
        .test_put(
            settings_scope(tenant),
            config_entry("app.kms-down", "no-write", 1),
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionUnavailable(_))),
        "write-time provider unavailable must surface ProtectionUnavailable"
    );
    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.kms-down")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "seal failure happens before DB write");

    store.shutdown().await?;
    Ok(())
}

/// tc4：delete 软删（tombstone）——find 返 None；历史值行**保留**（find_version 可读）；幂等。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc4_config_delete_tombstones_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_tombstone_repo(
        "v1".to_string(),
        "v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.test_put(
                    settings_scope(tenant),
                    config_entry("app.k", &marker, version),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.test_delete(settings_scope(tenant), key).await }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(settings_scope(tenant), key)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        |version| {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find_version(settings_scope(tenant), key, version)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.head(settings_scope(tenant), key)
                    .await
                    .map(|head| head.map(ConfigHead::version))
            }
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc4b：delete no-op（不存在 / 已 tombstone）不得依赖 KeyProvider 可用性。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc4b_config_delete_noop_does_not_call_unavailable_provider() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let missing = SettingKey::parse("app.missing").unwrap();
    let key = SettingKey::parse("app.deleted").unwrap();

    let unavailable_repo =
        PgConfigRepo::new(&store, fixed_clock_arc(), unavailable_config_protection());
    unavailable_repo
        .test_delete(settings_scope(tenant), &missing)
        .await?;
    let missing_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.missing")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(missing_cnt.0, 0, "missing-key delete no-op writes nothing");

    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(settings_scope(tenant), config_entry("app.deleted", "v1", 1))
        .await?;
    writer.test_delete(settings_scope(tenant), &key).await?;
    unavailable_repo
        .test_delete(settings_scope(tenant), &key)
        .await?;

    let latest: (Option<i64>,) =
        sqlx::query_as("SELECT max(version) FROM config_entries WHERE config_key = $1")
            .bind("app.deleted")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        latest.0,
        Some(2),
        "already-deleted no-op must not append another tombstone"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc4c：并发 delete/delete 应保持幂等——唯一键抢占 tombstone 版本时，失败方重读 latest tombstone 后 no-op。
#[tokio::test(flavor = "multi_thread")]
async fn tc4c_config_concurrent_delete_is_idempotent() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = Arc::new(PgConfigRepo::new(
        &store,
        fixed_clock_arc(),
        config_protection(),
    ));
    let tenant = config_tenant();
    let key = Arc::new(SettingKey::parse("app.concurrent-delete")?);

    repo.test_put(
        settings_scope(tenant),
        config_entry("app.concurrent-delete", "v1", 1),
    )
    .await?;

    let workers = 12;
    let barrier = Arc::new(tokio::sync::Barrier::new(workers));
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let repo = Arc::clone(&repo);
        let key = Arc::clone(&key);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.test_delete(settings_scope(tenant), &key).await
        }));
    }
    for handle in handles {
        handle.await??;
    }

    assert!(
        repo.find(settings_scope(tenant), &key).await?.is_none(),
        "concurrent delete leaves key deleted"
    );
    assert_eq!(
        repo.head(settings_scope(tenant), &key).await?,
        Some(ConfigHead::Deleted(2)),
        "only one tombstone version is appended"
    );
    let tombstones: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND deleted",
    )
    .bind(CONFIG_TENANT)
    .bind(key.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(tombstones.0, 1, "delete/delete race creates one tombstone");

    store.shutdown().await?;
    Ok(())
}

/// tc5：co-tx commit → config 行 + outbox 行皆在（OUTBOX-COTX-CONFIG-01 正向）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5_config_cotx_commits_config_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc5-evt");
    let plain_value = "settings-value-must-not-leak";

    repo.commit(
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.k", plain_value, 1)),
        config_outbox_entry(&event_id),
        config_envelope("app.k").with_causation_id(
            diport::EnvelopeCausationId::from_opaque("config-upstream-event").unwrap(),
        ),
    )
    .await?;

    // config 行：恰 1（v1），且 tenant_id 正确落库（tenant-correct，co-tx SET LOCAL + 显式列写入；对齐 t11）。
    let crow: (i64, String) = sqlx::query_as(
        "SELECT count(*), max(tenant_id::text) FROM config_entries WHERE config_key = $1 AND version = 1",
    )
    .bind("app.k")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(crow.0, 1, "config 行应写入");
    assert_eq!(
        crow.1, CONFIG_TENANT,
        "config 行 tenant_id（tenant-correct）"
    );
    // outbox 行：恰 1。
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 1, "outbox 行应写入（co-tx 两行皆在）");
    let outbox_shape: (Vec<u8>, String, String, String, Option<String>) =
        sqlx::query_as(
            "SELECT payload, metadata::text, contract_version, schema_hash, causation_id FROM outbox WHERE event_id = $1",
        )
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(outbox_shape.2, "v1", "config co-tx contract_version 物理列");
    assert_eq!(
        outbox_shape.3, TEST_SCHEMA_HASH,
        "config co-tx schema_hash 物理列"
    );
    assert_eq!(
        outbox_shape.4.as_deref(),
        Some("config-upstream-event"),
        "config co-tx 应透传非空 causation_id"
    );
    assert!(
        !outbox_shape
            .0
            .windows(plain_value.len())
            .any(|window| window == plain_value.as_bytes()),
        "config publish payload 不得包含 ConfigValue plaintext: {}",
        String::from_utf8_lossy(&outbox_shape.0)
    );
    assert!(
        !outbox_shape.1.contains(plain_value),
        "config publish metadata 不得包含 ConfigValue plaintext: {}",
        outbox_shape.1
    );
    // #262 F1：settings config co-tx outbox metadata 含构造期注入的 occurred_at（第三装配点，从注入 Clock）。
    let cfg_meta: (String,) =
        sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(
        cfg_meta
            .0
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "config co-tx outbox metadata 应含构造期注入的 occurred_at: {}",
        cfg_meta.0
    );
    assert_metadata_text_has_standard_schema_header(&cfg_meta.0, "config co-tx outbox");
    // 值经 find 取回正确。
    assert_eq!(
        repo.find(settings_scope(tenant), &SettingKey::parse("app.k").unwrap())
            .await?
            .unwrap()
            .value(),
        plain_value
    );

    store.shutdown().await?;
    Ok(())
}

/// Delete 分支同样必须原子提交 tombstone 与唯一 deletion fact；CAS 失败时两者皆不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5d_config_delete_cotx_is_both_or_neither() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.delete-cotx").unwrap();
    repo.test_put(
        settings_scope(tenant),
        config_entry("app.delete-cotx", "v1", 1),
    )
    .await?;

    let deleted_event = unique_event_id("cfg-tc5d-deleted");
    repo.commit(
        settings_scope(tenant),
        ConfigMutation::Delete(ConfigTombstone::hydrate(key.clone(), tenant, 2)),
        config_deleted_outbox_entry(&deleted_event, key.as_str(), 2),
        config_envelope(key.as_str()),
    )
    .await?;
    assert_eq!(
        repo.head(settings_scope(tenant), &key).await?,
        Some(ConfigHead::Deleted(2))
    );
    let deleted_rows: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND version = 2 AND deleted",
    )
    .bind(CONFIG_TENANT)
    .bind(key.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(deleted_rows.0, 1, "delete commit writes one tombstone");
    let deletion_fact: (Vec<u8>,) =
        sqlx::query_as("SELECT payload FROM outbox WHERE event_id = $1")
            .bind(&deleted_event)
            .fetch_one(&store.pool)
            .await?;
    let payload: serde_json::Value = serde_json::from_slice(&deletion_fact.0)?;
    assert_eq!(payload["changeKind"], "deleted");
    assert_eq!(payload["key"], key.as_str());
    assert_eq!(payload["version"], 2);

    let conflict_event = unique_event_id("cfg-tc5d-conflict");
    let conflict = repo
        .commit(
            settings_scope(tenant),
            ConfigMutation::Delete(ConfigTombstone::hydrate(key.clone(), tenant, 3)),
            config_deleted_outbox_entry(&conflict_event, key.as_str(), 3),
            config_envelope(key.as_str()),
        )
        .await;
    assert!(matches!(conflict, Err(ConfigRepoError::VersionConflict)));
    let conflict_rows: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&conflict_event)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(conflict_rows.0, 0, "failed delete writes no outbox fact");
    assert_eq!(
        repo.head(settings_scope(tenant), &key).await?,
        Some(ConfigHead::Deleted(2)),
        "failed delete appends no tombstone"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc5b：config 事务 tenant 与 envelope tenant 不一致 → fail-closed，config / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5b_config_cotx_rejects_envelope_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc5b-evt");
    let envelope = OutboxEnvelopeParts::new(
        config_contract(),
        TenantId::parse(CONFIG_TENANT_B).unwrap(),
        subject_id("app.mismatch"),
        actor_for(TenantId::parse(CONFIG_TENANT_B).unwrap()),
    );

    let result = repo
        .commit(
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("app.mismatch", "v1", 1)),
            config_outbox_entry(&event_id),
            envelope,
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::Storage(_))),
        "config/envelope tenant mismatch must fail closed as storage boundary error"
    );

    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.mismatch")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "mismatch 不得写 config 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "mismatch 不得写 outbox 行");

    store.shutdown().await?;
    Ok(())
}

/// tc5c：config entry tenant 与 repo scope tenant 不一致 → fail-closed，config / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5c_config_cotx_rejects_scope_entry_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let scope_tenant = config_tenant();
    let entry_tenant = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let event_id = unique_event_id("cfg-tc5c-evt");
    let key = "app.scope-entry-mismatch";

    let result = repo
        .commit(
            settings_scope(scope_tenant),
            ConfigMutation::Put(config_entry_for(entry_tenant, key, "v1", 1)),
            config_outbox_entry(&event_id),
            config_envelope(key),
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::Storage(_))),
        "config entry/scope tenant mismatch must fail closed as storage boundary error"
    );

    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind(key)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "scope mismatch 不得写 config 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "scope mismatch 不得写 outbox 行");

    store.shutdown().await?;
    Ok(())
}

/// tc6：co-tx 业务写后强制 Err → config 行 + outbox 行**共回滚**（both-or-neither，真实 `co_tx_with_outbox`）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc6_config_cotx_business_failure_rolls_back_both() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc6-evt");
    let entry = config_outbox_entry(&event_id);
    let env = OutboxEnvelope::new(
        "settings".to_string(),
        CONFIG_VERSION_CHANGED_TOPIC.to_string(),
        OutboxMetadata::new(0, test_tenant(), test_contract())
            .with_subject_id(subject_id("app.rollback")),
    );
    let tenant_pool = PgTenantPool::new(&store);

    // 业务写：真插一行 config（成功）后强制 Err（模拟「配置写后、后续步骤失败」= emit/commit 失败等价物）。
    let result = tenant_pool
        .co_tx_with_outbox(settings_scope(tenant),
            &entry,
            &env,
            move |conn| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO config_entries (
                             tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
                         ) VALUES ($1::uuid, $2, $3, NULL, 1, $4, $5)",
                    )
                    .bind(CONFIG_TENANT)
                    .bind("app.rollback")
                    .bind(1_i64)
                    .bind(&b"ciphertext"[..])
                    .bind("settings-config:1")
                    .execute(conn.conn())
                    .await
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    Err::<(), ConfigRepoError>(ConfigRepoError::VersionConflict)
                })
            },
            |e| ConfigRepoError::Storage(Box::new(e)),
        )
        .await;
    assert!(matches!(result, Err(ConfigRepoError::VersionConflict)));

    // both-or-neither：config 行回滚（不落库）+ outbox 行不落库。
    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.rollback")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "业务写失败 → 配置行回滚（不落库）");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "业务写失败 → outbox 行不落库（both-or-neither）"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn config_fact_conflict_rolls_back_mutation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let event_id = unique_event_id("config-fact-conflict");
    let key = "app.fact-conflict";
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());

    let conflict = repo
        .commit(
            settings_scope(tenant),
            ConfigMutation::Put(config_entry(key, "must-rollback", 1)),
            config_outbox_entry(&event_id),
            config_envelope(key),
        )
        .await;
    assert!(
        matches!(conflict, Err(ConfigRepoError::OutboxFactConflict(_))),
        "config adapter must preserve typed fact conflict: {conflict:?}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind(key)
            .fetch_one(&store.pool)
            .await?,
        0,
        "outbox conflict must roll back the config mutation"
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;

    store.shutdown().await?;
    Ok(())
}

/// tc7：**真实 method** `commit` 的 CAS 冲突分支 → VersionConflict 且**无 outbox 行**
/// （write-without-event 不发生）；原版本不被覆盖。
///
/// 与 tc6（直测 `co_tx_with_outbox` 骨架的业务写失败回滚）互补：tc7 驱动**真实 method** 的 rollback 路径
/// （CAS Err → 整事务回滚 → outbox 不落库），对齐 session t14「直测真实 method rollback 分支」范式，消除 tc6
/// 仅测骨架的盲区——OUTBOX-COTX-CONFIG-01 anti-vacuity（正向 tc5 ↔ 负向 tc6+tc7）由此闭合。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7_config_cotx_cas_conflict_emits_no_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();

    repo.test_put(settings_scope(tenant), config_entry("app.k", "v1", 1))
        .await?;

    // 以陈旧 v1 走 co-tx → CAS 冲突 → 整事务回滚（无 outbox 行）。
    let event_id = unique_event_id("cfg-tc7-evt");
    let result = repo
        .commit(
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("app.k", "v1-stale", 1)),
            config_outbox_entry(&event_id),
            config_envelope("app.k"),
        )
        .await;
    assert!(matches!(result, Err(ConfigRepoError::VersionConflict)));

    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "CAS 冲突 → 无 outbox 行（write-without-event 不发生）"
    );
    // 原 v1 不被覆盖。
    assert_eq!(
        repo.find(settings_scope(tenant), &SettingKey::parse("app.k").unwrap())
            .await?
            .unwrap()
            .value(),
        "v1",
        "冲突写不覆盖原值"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc7b：`PgConfigRepo` 接入 L2 co-tx conformance：commit 两边皆在；业务失败两边皆无；CAS 冲突无 outbox。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7b_config_cotx_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let ok_event = unique_event_id("cfg-tc7b-ok");
    let rollback_event = unique_event_id("cfg-tc7b-rollback");
    let conflict_event = unique_event_id("cfg-tc7b-conflict");
    let tenant_pool = PgTenantPool::new(&store);

    repo.test_put(
        settings_scope(tenant),
        config_entry("app.cotx-conflict", "v1", 1),
    )
    .await?;

    testkit::repo_conformance::assert_cotx_both_or_neither(
        testkit::repo_conformance::CotxCase {
            action: || async {
                repo.commit(settings_scope(tenant),
                    ConfigMutation::Put(config_entry("app.cotx-ok", "v1", 1)),
                    config_outbox_entry(&ok_event),
                    config_envelope("app.cotx-ok"),
                )
                .await
            },
            business_exists: || async {
                let key = SettingKey::parse("app.cotx-ok")
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                repo.find(settings_scope(tenant), &key)
                    .await
                    .map(|entry| entry.is_some_and(|entry| entry.value() == "v1"))
            },
            outbox_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&ok_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        testkit::repo_conformance::CotxCase {
            action: || async {
                let entry = config_outbox_entry(&rollback_event);
                let env = OutboxEnvelope::new(
                    "settings".to_string(),
                    CONFIG_VERSION_CHANGED_TOPIC.to_string(),
                    OutboxMetadata::new(0, test_tenant(), test_contract())
                        .with_subject_id(subject_id("app.cotx-rollback")),
                );
                tenant_pool
                    .co_tx_with_outbox(settings_scope(tenant),
                        &entry,
                        &env,
                        move |conn| {
                            Box::pin(async move {
                                sqlx::query(
                                    "INSERT INTO config_entries (
                                         tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
                                     ) VALUES ($1::uuid, $2, $3, NULL, 1, $4, $5)",
                                )
                                .bind(CONFIG_TENANT)
                                .bind("app.cotx-rollback")
                                .bind(1_i64)
                                .bind(&b"ciphertext"[..])
                                .bind("settings-config:1")
                                .execute(conn.conn())
                                .await
                                .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                                Err::<(), ConfigRepoError>(ConfigRepoError::VersionConflict)
                            })
                        },
                        |e| ConfigRepoError::Storage(Box::new(e)),
                    )
                    .await
            },
            business_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                        .bind("app.cotx-rollback")
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
            outbox_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&rollback_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        testkit::repo_conformance::CotxCase {
            action: || async {
                repo.commit(settings_scope(tenant),
                    ConfigMutation::Put(config_entry("app.cotx-conflict", "stale", 1)),
                    config_outbox_entry(&conflict_event),
                    config_envelope("app.cotx-conflict"),
                )
                .await
            },
            business_exists: || async {
                let key = SettingKey::parse("app.cotx-conflict")
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                repo.find(settings_scope(tenant), &key)
                    .await
                    .map(|entry| entry.is_some_and(|entry| entry.value() == "stale"))
            },
            outbox_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&conflict_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        |e| matches!(e, ConfigRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc7c：settings config 的 Postgres retry 边界 conformance。
///
/// transient：第一轮事务内写 config + outbox 后返回 transient storage error，必须整体 rollback；第二轮重建
/// 事务后提交，最终 config/outbox 各 1 行。conflict/permanent：不重试、不提交副作用。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7c_config_retry_boundary_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let transient_event = unique_event_id("cfg-tc7c-transient");
    let conflict_event = unique_event_id("cfg-tc7c-conflict");
    let permanent_event = unique_event_id("cfg-tc7c-permanent");

    repo.test_put(
        settings_scope(tenant),
        config_entry("app.retry-conflict", "v1", 1),
    )
    .await?;

    testkit::repo_conformance::assert_retry_boundary_policy(
        testkit::repo_conformance::RetryBoundaryCase {
            transient_then_success: || {
                let repo = &repo;
                let transient_event = transient_event.clone();
                arm_config_retry_failpoint("app.retry-transient", 1);
                async move {
                    repo.commit(
                        settings_scope(tenant),
                        ConfigMutation::Put(config_entry("app.retry-transient", "v1", 1)),
                        config_outbox_entry(&transient_event),
                        config_envelope("app.retry-transient"),
                    )
                    .await
                }
            },
            transient_attempts: config_retry_failpoint_hits,
            expected_transient_attempts: 2,
            transient_visible: || async {
                let cfg: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                        .bind("app.retry-transient")
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                let outbox: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&transient_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(
                    cfg.0 == 1 && outbox.0 == 1 && config_retry_failpoint_hits() == 2,
                )
            },
            conflict_action: || async {
                repo.commit(
                    settings_scope(tenant),
                    ConfigMutation::Put(config_entry("app.retry-conflict", "stale", 1)),
                    config_outbox_entry(&conflict_event),
                    config_envelope("app.retry-conflict"),
                )
                .await
            },
            conflict_visible: || async {
                let cfg: (i64,) = sqlx::query_as(
                    "SELECT count(*) FROM config_entries WHERE config_key = $1 AND value = $2",
                )
                .bind("app.retry-conflict")
                .bind("stale")
                .fetch_one(&store.pool)
                .await
                .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                let outbox: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&conflict_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cfg.0 != 0 || outbox.0 != 0)
            },
            permanent_action: || async {
                repo.commit(
                    settings_scope(tenant),
                    ConfigMutation::Put(config_entry("app.retry-permanent", "v1", 1)),
                    config_outbox_entry(&permanent_event),
                    OutboxEnvelopeParts::new(
                        config_contract(),
                        TenantId::parse(CONFIG_TENANT_B).unwrap(),
                        subject_id("app.retry-permanent"),
                        actor_for(TenantId::parse(CONFIG_TENANT_B).unwrap()),
                    ),
                )
                .await
            },
            permanent_visible: || async {
                let cfg: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                        .bind("app.retry-permanent")
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                let outbox: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&permanent_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cfg.0 != 0 || outbox.0 != 0)
            },
        },
        |e| {
            matches!(
                classify_config_repo_error(e),
                consistency::TxRetryClass::Conflict
            )
        },
        |e| {
            matches!(
                classify_config_repo_error(e),
                consistency::TxRetryClass::Permanent
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc8：storage 错误通道——关池后 find 返回 `ConfigRepoError::Storage`（基础设施错误分层映射，保留 source）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc8_config_find_maps_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async { repo.find(settings_scope(tenant), &key).await.map(|_| ()) },
        |e| matches!(e, ConfigRepoError::Storage(_)),
    )
    .await?;

    Ok(())
}

/// tc9：**跨租户隔离**——tenant A 的配置对 tenant B 不可见，独立版本空间，delete 互不影响。
///
/// tc9 以 owner/superuser 连接（绕过 RLS）验证显式 `WHERE tenant_id` 子句隔离；0009 落地后
/// config_entries 已有 RLS policy，DB 层 RLS 强制力由 t21（rss_app 角色）专门覆盖，二者互补
/// （in-mem 路径由 `application.rs::cross_tenant_isolation` 守，实现不同）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc9_config_cross_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_tenant_scoped_repo(
        testkit::repo_conformance::TenantScopedCase {
            tenant_a,
            tenant_b,
            a_marker: "a-secret".to_string(),
            b_marker: "b-value".to_string(),
            save: |tenant, version, marker: String| {
                let repo = &repo;
                async move {
                    repo.test_put(
                        settings_scope(tenant),
                        ConfigEntry::hydrate(
                            SettingKey::parse("app.k").unwrap(),
                            &marker,
                            tenant,
                            version,
                        ),
                    )
                    .await
                }
            },
            delete: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.test_delete(settings_scope(tenant), key).await }
            },
            current: |tenant| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find(settings_scope(tenant), key)
                        .await
                        .map(|entry| entry.map(|entry| entry.value().to_string()))
                }
            },
            history: |tenant, version| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find_version(settings_scope(tenant), key, version)
                        .await
                        .map(|entry| entry.map(|entry| entry.value().to_string()))
                }
            },
            latest_version: |tenant| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.head(settings_scope(tenant), key)
                        .await
                        .map(|head| head.map(ConfigHead::version))
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc9b：`PgConfigRepo` 接入 #1437 最小 tenant-scope **conformance 骨架**（#1426 种子的首个 enroll
/// 消费方 + anti-vacuity 真实 repo 驱动）：round-trip / 跨租不可见 / 跨租不干扰 三断言一次过。
/// 与 tc9（手写逐断言）互补——本测试证骨架对真实 RLS-scoped repo 可用，#1426 在骨架上扩 CAS/rollback 等。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc9b_config_repo_tenant_isolation_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.conformance").unwrap();

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |t| {
            let repo = &repo;
            async move {
                let entry =
                    ConfigEntry::hydrate(SettingKey::parse("app.conformance").unwrap(), "v1", t, 1);
                repo.test_put(settings_scope(t), entry).await
            }
        },
        |t| {
            let repo = &repo;
            let key = &key;
            async move { repo.find(settings_scope(t), key).await.map(|o| o.is_some()) }
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// 构造 application 同款 event_id（`{topic}:{tenant}:{key}:v{version}`）——tc10 验 delete+republish 不复用。
fn config_event_id(tenant: TenantId, key: &str, version: u64) -> String {
    format!("{CONFIG_VERSION_CHANGED_TOPIC}:{tenant}:{key}:v{version}")
}

/// tc10：**F1 回归（postgres 层，exercises ON CONFLICT dedup）**——delete 软删后 republish 不复用 event_id，
/// outbox 事件不被吞（write-without-event 不重现）。
///
/// 旧 bug：delete 物理清历史 → republish 经 `latest_version` 回 v1 → event_id `...:v1` 复用 → outbox
/// `append_outbox` 的 `ON CONFLICT (event_id) DO NOTHING` 吞掉新事件（config 写入但事件丢失）。tombstone 软删
/// 使 version 单调（v1 → tombstone v2 → republish v3）→ event_id 不复用 → 两次 publish 各落一条 outbox 行。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc10_config_delete_republish_no_event_id_reuse() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    // publish v1 经 co-tx（content-派生 event_id ...:v1）。
    let ev1 = config_event_id(tenant, "app.k", 1);
    repo.commit(
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.k", "v1", 1)),
        config_outbox_entry(&ev1),
        config_envelope("app.k"),
    )
    .await?;

    // delete → tombstone v2（version 不重置）。
    repo.test_delete(settings_scope(tenant), &key).await?;

    // republish：下一版本 = latest_version(含 tombstone) + 1 = 3（**非**重置回 1，旧 bug 的根因）。
    let next = repo
        .head(settings_scope(tenant), &key)
        .await?
        .map_or(1, |head| head.version().saturating_add(1));
    assert_eq!(next, 3, "delete 软删后下一版本 = 3，不重置回 1");
    let ev3 = config_event_id(tenant, "app.k", next);
    assert_ne!(ev1, ev3, "republish event_id 不复用（v1 ≠ v3）");
    repo.commit(
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.k", "v1-again", next)),
        config_outbox_entry(&ev3),
        config_envelope("app.k"),
    )
    .await?;

    // 两次 publish 各落一条 outbox 行——republish 事件未被 ON CONFLICT 吞。
    let ob1: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&ev1)
        .fetch_one(&store.pool)
        .await?;
    let ob3: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&ev3)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob1.0, 1, "v1 outbox 行存在");
    assert_eq!(
        ob3.0, 1,
        "republish (v3) outbox 行存在——event_id 不复用，事件未被吞"
    );
    // 活跃值恢复。
    assert_eq!(
        repo.find(settings_scope(tenant), &key)
            .await?
            .unwrap()
            .value(),
        "v1-again",
        "republish 后活跃值恢复"
    );

    store.shutdown().await?;
    Ok(())
}

// ── PgSecretRepo：secret 引用坐标仓储集成测试（#1274）──────────────────────────
//
// ts1:  save → find round-trip（全字段回环）
// ts1b: ref_version=None round-trip
// ts2:  find_version 历史（精确版本）
// ts3:  CAS 冲突（陈旧 + 跳版 → VersionConflict；恰 max+1 成功）
// ts4:  delete tombstone + 幂等（latest_version 含 tombstone；历史行保留；不存在 key → no-op）
// ts5:  storage 错误通道（关池 → SecretRepoError::Storage）
// ts6:  跨租户隔离（find / find_version / delete 互不影响）
// ts7:  delete + republish 版本不重置（version 单调）
// ts8:  material-never-persisted 断言（information_schema.columns 列集校验）

use settings::ports::{SecretEntry, SecretKey, SecretRepo, SecretRepoError, StoreId};

use crate::PgSecretRepo;

/// secret 测试用 canonical 租户 UUID（复用 co-tx 段 [`COTX_TENANT_A`] 同值）。
const SECRET_TENANT_A: &str = COTX_TENANT_A;
/// 第二租户（跨租户隔离 ts6）。
const SECRET_TENANT_B: &str = CONFIG_TENANT_B;

/// setup：应用 migration（含 secret_refs 表），清空 secret_refs（防测试间污染）。
async fn setup_secret(store: &PgStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    sqlx::query("DELETE FROM secret_refs")
        .execute(&store.pool)
        .await?;
    Ok(())
}

#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
fn secret_tenant_a() -> TenantId {
    TenantId::parse(SECRET_TENANT_A).unwrap()
}

/// 构造 SecretEntry（经 `SecretEntry::hydrate` 跨 crate pub funnel）。
#[allow(clippy::unwrap_used)]
fn make_secret_entry(
    key: &str,
    store_id: &str,
    ref_key: &str,
    ref_version: Option<&str>,
    version: u64,
    tenant: TenantId,
) -> SecretEntry {
    SecretEntry::hydrate(
        SecretKey::parse(key).unwrap(),
        StoreId::parse(store_id).unwrap(),
        ref_key,
        ref_version.map(|s| s.to_string()),
        tenant,
        version,
    )
}

/// ts1：save → find round-trip（store_id / ref_key / ref_version / version / tenant 全字段正确）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts1_secret_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.db-password").unwrap();

    // 未写入 → None。
    assert!(
        repo.find(settings_scope(tenant), &key).await?.is_none(),
        "未写入 → None"
    );

    repo.save(
        settings_scope(tenant),
        make_secret_entry(
            "myapp.db-password",
            "vault",
            "secret/data/myapp",
            Some("v2"),
            1,
            tenant,
        ),
    )
    .await?;

    let found = repo.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(found.key().as_str(), "myapp.db-password", "key 回环");
    assert_eq!(
        found.secret_ref().store_id().as_str(),
        "vault",
        "store_id 回环"
    );
    assert_eq!(
        found.secret_ref().ref_key(),
        "secret/data/myapp",
        "ref_key 回环"
    );
    assert_eq!(
        found.secret_ref().ref_version(),
        Some("v2"),
        "ref_version 回环"
    );
    assert_eq!(found.version(), 1, "version 回环");
    assert_eq!(found.tenant(), tenant, "tenant 回环（tenant-correct）");

    store.shutdown().await?;
    Ok(())
}

/// ts1b：ref_version=None（NULL=latest）round-trip。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts1b_secret_save_find_ref_version_null() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();

    repo.save(
        settings_scope(tenant),
        make_secret_entry(
            "myapp.api-key",
            "k8s-secrets",
            "ns/my-secret",
            None,
            1,
            tenant,
        ),
    )
    .await?;

    let found = repo
        .find(
            settings_scope(tenant),
            &SecretKey::parse("myapp.api-key").unwrap(),
        )
        .await?
        .unwrap();
    assert_eq!(
        found.secret_ref().ref_version(),
        None,
        "ref_version=None 回环"
    );

    store.shutdown().await?;
    Ok(())
}

/// ts2：find_version 历史（精确版本；缺失版本 → None）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts2_secret_find_version_history() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.db-pass").unwrap();

    repo.save(
        settings_scope(tenant),
        make_secret_entry("myapp.db-pass", "vault", "secret/v1", None, 1, tenant),
    )
    .await?;
    repo.save(
        settings_scope(tenant),
        make_secret_entry(
            "myapp.db-pass",
            "vault",
            "secret/v2",
            Some("rev-2"),
            2,
            tenant,
        ),
    )
    .await?;

    // find 取最高版本。
    let latest = repo.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(latest.version(), 2, "find = max version");
    assert_eq!(latest.secret_ref().ref_key(), "secret/v2");

    // find_version 精确历史。
    let v1 = repo
        .find_version(settings_scope(tenant), &key, 1)
        .await?
        .unwrap();
    assert_eq!(v1.secret_ref().ref_key(), "secret/v1", "find_version(1)");
    let v2 = repo
        .find_version(settings_scope(tenant), &key, 2)
        .await?
        .unwrap();
    assert_eq!(
        v2.secret_ref().ref_version(),
        Some("rev-2"),
        "find_version(2)"
    );

    // 缺失版本 → None。
    assert!(
        repo.find_version(settings_scope(tenant), &key, 9)
            .await?
            .is_none(),
        "缺失版本 → None"
    );

    store.shutdown().await?;
    Ok(())
}

/// ts3：CAS——陈旧版本与跳版均 VersionConflict；恰 max+1 成功。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts3_secret_save_cas_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.token").unwrap();

    testkit::repo_conformance::assert_versioned_cas_repo(
        "secret/tok".to_string(),
        "secret/tok-b".to_string(),
        "secret/tok-c".to_string(),
        "secret/tok-v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.save(
                    settings_scope(tenant),
                    make_secret_entry("myapp.token", "vault", &marker, None, version, tenant),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(settings_scope(tenant), key)
                    .await
                    .map(|entry| entry.map(|entry| entry.secret_ref().ref_key().to_string()))
            }
        },
        |e| matches!(e, SecretRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// ts4：delete tombstone + 幂等（find → None；latest_version 含 tombstone；历史行保留；再删 no-op；
/// 不存在 key → no-op）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts4_secret_delete_tombstones_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.cred").unwrap();

    testkit::repo_conformance::assert_tombstone_repo(
        "secret/cred".to_string(),
        "secret/cred-v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.save(
                    settings_scope(tenant),
                    make_secret_entry("myapp.cred", "vault", &marker, None, version, tenant),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.delete(settings_scope(tenant), key).await }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(settings_scope(tenant), key)
                    .await
                    .map(|entry| entry.map(|entry| entry.secret_ref().ref_key().to_string()))
            }
        },
        |version| {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find_version(settings_scope(tenant), key, version)
                    .await
                    .map(|entry| entry.map(|entry| entry.secret_ref().ref_key().to_string()))
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.latest_version(settings_scope(tenant), key).await }
        },
    )
    .await?;

    // 不存在 key → no-op（无 panic / 无错误）。
    let phantom = SecretKey::parse("myapp.nonexistent").unwrap();
    repo.delete(settings_scope(tenant), &phantom).await?;

    store.shutdown().await?;
    Ok(())
}

/// ts5：storage 错误通道——关池后 find 返回 `SecretRepoError::Storage`（基础设施错误分层映射）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts5_secret_find_maps_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.k").unwrap();

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async { repo.find(settings_scope(tenant), &key).await.map(|_| ()) },
        |e| matches!(e, SecretRepoError::Storage(_)),
    )
    .await?;

    Ok(())
}

/// ts6：跨租户隔离——tenant A 的 secret 对 tenant B 不可见；各自独立版本空间；delete 互不影响。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts6_secret_cross_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant_a = secret_tenant_a();
    let tenant_b = TenantId::parse(SECRET_TENANT_B).unwrap();
    let key = SecretKey::parse("shared.key").unwrap();

    testkit::repo_conformance::assert_tenant_scoped_repo(
        testkit::repo_conformance::TenantScopedCase {
            tenant_a,
            tenant_b,
            a_marker: "vault-a".to_string(),
            b_marker: "vault-b".to_string(),
            save: |tenant, version, marker: String| {
                let repo = &repo;
                async move {
                    repo.save(
                        settings_scope(tenant),
                        make_secret_entry(
                            "shared.key",
                            &marker,
                            "secret/ref",
                            None,
                            version,
                            tenant,
                        ),
                    )
                    .await
                }
            },
            delete: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.delete(settings_scope(tenant), key).await }
            },
            current: |tenant| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find(settings_scope(tenant), key).await.map(|entry| {
                        entry.map(|entry| entry.secret_ref().store_id().as_str().to_string())
                    })
                }
            },
            history: |tenant, version| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find_version(settings_scope(tenant), key, version)
                        .await
                        .map(|entry| {
                            entry.map(|entry| entry.secret_ref().store_id().as_str().to_string())
                        })
                }
            },
            latest_version: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.latest_version(settings_scope(tenant), key).await }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// ts7：delete + republish 版本不重置——delete 软删后 republish 取 latest_version+1（非重置回 1）。
///
/// 对标 tc10 config 同款回归防护：tombstone 使 version 单调，防止版本号复用。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts7_secret_delete_republish_version_not_reset() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.rotate-key").unwrap();

    // 写 v1。
    repo.save(
        settings_scope(tenant),
        make_secret_entry(
            "myapp.rotate-key",
            "vault",
            "secret/rotate",
            None,
            1,
            tenant,
        ),
    )
    .await?;

    // delete → tombstone v2。
    repo.delete(settings_scope(tenant), &key).await?;
    assert_eq!(
        repo.latest_version(settings_scope(tenant), &key).await?,
        Some(2),
        "tombstone v2"
    );

    // republish：下一版本 = latest+1 = 3（不是重置回 1）。
    let next = repo
        .latest_version(settings_scope(tenant), &key)
        .await?
        .map_or(1, |v| v + 1);
    assert_eq!(next, 3, "delete 软删后下一版本 = 3，不重置回 1");

    repo.save(
        settings_scope(tenant),
        make_secret_entry(
            "myapp.rotate-key",
            "vault",
            "secret/rotate-new",
            Some("v3"),
            next,
            tenant,
        ),
    )
    .await?;

    // 活跃值恢复，版本 = 3。
    let active = repo.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(active.version(), 3, "republish 后版本 = 3");
    assert_eq!(active.secret_ref().ref_key(), "secret/rotate-new");

    store.shutdown().await?;
    Ok(())
}

/// ts8：material-never-persisted 断言——`information_schema.columns` 校验 secret_refs 列集
/// 恰为 {created_at, deleted, ref_key, ref_version, secret_key, store_id, tenant_id, version}，
/// 无任何 secret 材料列（review-critical）。
#[tokio::test(flavor = "multi_thread")]
async fn ts8_secret_refs_table_has_no_material_column() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 从 information_schema.columns 取 secret_refs 的全部列名（ORDER BY 确定顺序）。
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name = 'secret_refs' AND table_schema = 'public' \
         ORDER BY column_name",
    )
    .fetch_all(&store.pool)
    .await?;

    let cols: Vec<&str> = rows.iter().map(|(s,)| s.as_str()).collect();

    // 期望的列集（字母序排列后）：坐标列 + 版本标记列，无任何材料列。
    let expected = [
        "created_at",
        "deleted",
        "ref_key",
        "ref_version",
        "secret_key",
        "store_id",
        "tenant_id",
        "version",
    ];
    assert_eq!(
        cols, expected,
        "secret_refs 列集应恰为坐标列（无材料列），实际：{cols:?}"
    );

    store.shutdown().await?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// PgRoleRepo（identity 角色仓储）集成测试（#1250）：CRUD / upsert / tenant 行级隔离 / 并发收敛。
//
// 构造 `Role` 经 `Role::hydrate`（pub funnel，无需 identity test-support）；`RoleId` 经 `role.id().clone()`
// 取得——RoleId 构造封闭（`pub(crate)` parse/new），测试不可裸 mint，符合 funnel 设计（外部可读不可伪造）。
// ───────────────────────────────────────────────────────────────────────────

use identity::ports::{
    AttributeKey, AttributeValue, DynRoleBindingLifecycle, DynRoleReadRepo, IdentityError,
    Operator, POLICY_ATTR_PRINCIPAL_KIND, Policy, PolicyCondition, PolicyEffect, PolicyId,
    PolicyLifecycle, PolicyObligations, PolicyPage, PolicyRepo, PolicyRouteScope, PolicyRule,
    PolicyVersion, ResourceAttribute, ResourceAttributeKey, ResourceAttributeRepo,
    ResourceAttributeResolution, ResourceAttributeResourceId, ResourceAttributeVersion, Role,
    RoleBinding, RoleBindingLifecycle, RolePage, RoleReadRepo, RoleWriteRepo,
};

use crate::{
    PgPolicyLifecycle, PgPolicyRepo, PgResourceAttributeRepo, PgRoleBindingLifecycle, PgRoleRepo,
};

const ROLE_TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const ROLE_TENANT_B: &str = "550e8400-e29b-41d4-a716-446655440000";

fn role_tenant(raw: &str) -> Result<TenantId, Box<dyn std::error::Error + Send + Sync>> {
    Ok(TenantId::parse(raw)?)
}

const POLICY_CONTRACT_ID: &str = "identity.roles";
const POLICY_PERMISSION: &str = "identity:role:read";
const RESOURCE_ATTRIBUTE_ID: &str = "11111111-2222-4333-8444-555555555555";
const POLICY_UPDATED_TOPIC: &str = "identity.policy-updated";
const POLICY_UPDATED_CONTRACT: vocab::ContractBinding = vocab::ContractBinding::from_static(
    "identity",
    "identity.policy-updated",
    "v1",
    "sha256:47b84018a53fa99bd8674f8b3344b11da69a9964e569b57de821483c8b2d0de2",
);

fn policy_time(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn policy_scope() -> Result<PolicyRouteScope, IdentityError> {
    PolicyRouteScope::parse(POLICY_CONTRACT_ID, POLICY_PERMISSION)
}

fn resource_attribute_id() -> Result<ResourceAttributeResourceId, IdentityError> {
    ResourceAttributeResourceId::parse(RESOURCE_ATTRIBUTE_ID)
}

fn resource_attribute_key(raw: &str) -> Result<ResourceAttributeKey, IdentityError> {
    ResourceAttributeKey::parse(raw).map_err(|_| IdentityError::InvalidPolicy)
}

fn resource_attribute_fixture(
    tenant: TenantId,
    key: &str,
    value: &str,
    effective_from: u64,
    effective_until: Option<u64>,
) -> Result<ResourceAttribute, IdentityError> {
    ResourceAttribute::build(
        tenant,
        policy_scope()?,
        resource_attribute_id()?,
        resource_attribute_key(key)?,
        AttributeValue::new(value),
        policy_time(effective_from),
        effective_until.map(policy_time),
    )
}

fn policy_id(raw: &str) -> Result<PolicyId, IdentityError> {
    PolicyId::parse(raw).map_err(|_| IdentityError::InvalidPolicy)
}

fn policy_version(raw: u32) -> Result<PolicyVersion, IdentityError> {
    PolicyVersion::new(raw)
}

fn policy_rule(
    effect: PolicyEffect,
    obligations: PolicyObligations,
) -> Result<PolicyRule, IdentityError> {
    Ok(PolicyRule::with_obligations(
        PolicyCondition::new(
            AttributeKey::parse(POLICY_ATTR_PRINCIPAL_KIND)
                .map_err(|_| IdentityError::InvalidPolicy)?,
            Operator::Eq(AttributeValue::new("admin")),
        ),
        effect,
        obligations,
    ))
}

fn policy_fixture(
    id: &str,
    tenant: TenantId,
    version: u32,
    effective_from: u64,
    effective_until: Option<u64>,
    effect: PolicyEffect,
    obligations: PolicyObligations,
) -> Result<Policy, IdentityError> {
    let scope = policy_scope()?;
    let rules = vec![policy_rule(effect, obligations)?];
    if version == 1 {
        Policy::build(
            id,
            tenant,
            scope,
            policy_time(effective_from),
            effective_until.map(policy_time),
            rules,
        )
    } else {
        Policy::hydrate(
            id,
            tenant,
            scope,
            version,
            policy_time(effective_from),
            effective_until.map(policy_time),
            rules,
        )
    }
}

fn first_policy_obligations(policy: &Policy) -> PolicyObligations {
    policy
        .rules()
        .first()
        .map(|rule| rule.obligations().clone())
        .unwrap_or_else(PolicyObligations::empty)
}

fn policy_rejection(err: &IdentityError) -> bool {
    matches!(err, IdentityError::InvalidPolicy)
}

fn principal_kind_rule_json(operator_json: &str) -> String {
    format!(
        r#"{{"rules":[{{"condition":{{"attribute":"{POLICY_ATTR_PRINCIPAL_KIND}","operator":{operator_json}}},"effect":"allow"}}]}}"#
    )
}

fn policy_lifecycle_event(
    tenant: TenantId,
    policy_id: &str,
    change_kind: &'static str,
    version: PolicyVersion,
) -> Result<(EventEntry, diport::OutboxEnvelopeParts), IdentityError> {
    policy_lifecycle_event_with_id(
        tenant,
        policy_id,
        change_kind,
        version,
        &uuid::Uuid::new_v4().to_string(),
    )
}

fn policy_lifecycle_event_with_id(
    tenant: TenantId,
    policy_id: &str,
    change_kind: &'static str,
    version: PolicyVersion,
    event_id: &str,
) -> Result<(EventEntry, diport::OutboxEnvelopeParts), IdentityError> {
    let actor = uuid::Uuid::from_u128(0xA11CE);
    let payload = serde_json::json!({
        "policyId": policy_id,
        "changeKind": change_kind,
        "version": version.get(),
        "contractId": POLICY_CONTRACT_ID,
        "permission": POLICY_PERMISSION,
        "updatedBy": actor,
        "actorKind": "admin",
        "tenantId": tenant.to_string(),
        "occurredAt": expected_occurred_at(),
    });
    let payload = serde_json::to_vec(&payload).map_err(|e| IdentityError::Storage(Box::new(e)))?;
    let entry = EventEntry::new(
        EventTopic::parse(POLICY_UPDATED_TOPIC).map_err(|_| IdentityError::InvalidPolicy)?,
        IdemKey::parse(event_id).map_err(|_| IdentityError::InvalidPolicy)?,
        OutboxPayload::from_reviewed_event_bytes(payload),
    );
    let actor_subject = actor.hyphenated().to_string();
    let envelope = diport::OutboxEnvelopeParts::new(
        POLICY_UPDATED_CONTRACT,
        tenant,
        diport::EnvelopeSubjectId::from_opaque(actor_subject.clone())
            .map_err(|_| IdentityError::InvalidPolicy)?,
        diport::OutboxActor::scoped(
            vocab::PrincipalKind::Admin,
            diport::OpaqueActorId::from_opaque(actor_subject)
                .map_err(|_| IdentityError::InvalidPolicy)?,
            tenant,
            vocab::ScopedTenant::Tenant,
        ),
    );
    Ok((entry, envelope))
}

async fn policy_create_and_emit(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    policy: Policy,
) -> Result<Policy, IdentityError> {
    let (entry, envelope) =
        policy_lifecycle_event(tenant, policy.id().as_str(), "created", policy.version())?;
    lifecycle
        .create_and_emit(identity_scope(tenant), policy, entry, envelope)
        .await
}

async fn policy_update_and_emit(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    policy: Policy,
    expected: PolicyVersion,
) -> Result<Policy, IdentityError> {
    let (entry, envelope) = policy_lifecycle_event(
        tenant,
        policy.id().as_str(),
        "updated",
        expected.next_checked()?,
    )?;
    lifecycle
        .update_and_emit(identity_scope(tenant), policy, expected, entry, envelope)
        .await
}

async fn policy_deactivate_and_emit(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    id: PolicyId,
    expected: PolicyVersion,
) -> Result<bool, IdentityError> {
    let (entry, envelope) =
        policy_lifecycle_event(tenant, id.as_str(), "deactivated", expected.next_checked()?)?;
    lifecycle
        .deactivate_and_emit(identity_scope(tenant), id, expected, entry, envelope)
        .await
}

async fn policy_update_and_emit_event(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    policy: Policy,
    expected: PolicyVersion,
    event_id: &str,
) -> Result<Policy, IdentityError> {
    let (entry, envelope) = policy_lifecycle_event_with_id(
        tenant,
        policy.id().as_str(),
        "updated",
        expected.next_checked()?,
        event_id,
    )?;
    lifecycle
        .update_and_emit(identity_scope(tenant), policy, expected, entry, envelope)
        .await
}

async fn policy_deactivate_and_emit_event(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    id: PolicyId,
    expected: PolicyVersion,
    event_id: &str,
) -> Result<bool, IdentityError> {
    let (entry, envelope) = policy_lifecycle_event_with_id(
        tenant,
        id.as_str(),
        "deactivated",
        expected.next_checked()?,
        event_id,
    )?;
    lifecycle
        .deactivate_and_emit(identity_scope(tenant), id, expected, entry, envelope)
        .await
}

async fn policy_outbox_exists(store: &PgStore, event_id: &str) -> Result<bool, IdentityError> {
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(event_id)
        .fetch_one(&store.pool)
        .await
        .map_err(|e| IdentityError::Storage(Box::new(e)))?;
    Ok(count.0 == 1)
}

// CRUD：save 新角色 → find 往返一致；同 id 二次 save → upsert 覆盖 name+permissions（非新增行）；查无 → None。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
// reason: 已保存/upserted role 必定可查到；集成测试 happy-path；item-level carve-out（error-handling.md §Carve-out）。
async fn role_repo_save_find_roundtrip_and_upsert() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::new(&store);
    let tenant = role_tenant(ROLE_TENANT_A)?;

    // 未保存 → None（fail-closed，anti-vacuity 的负例基线）。
    let admin = Role::hydrate("role-admin", "Admin", &["identity:policy:read".to_string()])?;
    let admin_id = admin.id().clone();
    assert!(
        repo.find(identity_scope(tenant), admin_id.clone())
            .await?
            .is_none(),
        "未保存 → None"
    );

    // save → find 往返一致（id / name / permissions）。
    repo.save(identity_scope(tenant), admin).await?;
    let got = repo
        .find(identity_scope(tenant), admin_id.clone())
        .await?
        .expect("saved role visible");
    assert_eq!(got.id().as_str(), "role-admin");
    assert_eq!(got.name(), "Admin");
    assert_eq!(
        got.permission_ids().collect::<Vec<_>>(),
        vec!["identity:policy:read"]
    );

    // 同 id 二次 save → upsert 覆盖 name + permissions。
    let admin_v2 = Role::hydrate(
        "role-admin",
        "Administrator",
        &[
            "identity:policy:read".to_string(),
            "identity:policy:update".to_string(),
        ],
    )?;
    repo.save(identity_scope(tenant), admin_v2).await?;
    let got2 = repo
        .find(identity_scope(tenant), admin_id)
        .await?
        .expect("upserted role visible");
    assert_eq!(got2.name(), "Administrator", "upsert 覆盖 name");
    assert_eq!(
        got2.permission_ids().collect::<Vec<_>>(),
        vec!["identity:policy:read", "identity:policy:update"],
        "upsert 覆盖 permissions"
    );
    // upsert 不新增行（DO UPDATE，非 INSERT）。
    let n: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
            .bind(ROLE_TENANT_A)
            .bind("role-admin")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(n.0, 1, "upsert 不新增行");

    store.shutdown().await?;
    Ok(())
}

// tenant 行级隔离：A 保存的角色 B 查不到（负例）；A 自己可见（正例 anti-vacuity）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
// reason: 同租 find 必定可见（anti-vacuity 正例）；item-level carve-out（error-handling.md §Carve-out）。
async fn role_repo_tenant_row_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::new(&store);
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;

    let role = Role::hydrate(
        "shared-id",
        "OnlyInA",
        &["identity:policy:read".to_string()],
    )?;
    let id = role.id().clone();
    repo.save(identity_scope(tenant_a), role).await?;

    // 跨租不可见（负例）：tenant B 查同 id → None（行级隔离，不泄露存在性）。
    assert!(
        repo.find(identity_scope(tenant_b), id.clone())
            .await?
            .is_none(),
        "跨租 find → None（tenant 行级隔离）"
    );
    // 同租可见（正例，证明上面 None 非因数据未写入 = anti-vacuity）。
    assert_eq!(
        repo.find(identity_scope(tenant_a), id)
            .await?
            .expect("visible in own tenant")
            .name(),
        "OnlyInA"
    );

    store.shutdown().await?;
    Ok(())
}

/// role repo enrollment：统一 tenant conformance 覆盖 round-trip / cross-tenant invisible / non-interference。
#[tokio::test(flavor = "multi_thread")]
async fn role_repo_tenant_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::new(&store);
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;
    let role_id = Role::hydrate("tenant-conf-role", "seed", &[])?.id().clone();

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let repo = &repo;
            async move {
                repo.save(
                    identity_scope(tenant),
                    Role::hydrate(
                        "tenant-conf-role",
                        "TenantConf",
                        &["identity:policy:read".to_string()],
                    )?,
                )
                .await
            }
        },
        |tenant| {
            let repo = &repo;
            let role_id = role_id.clone();
            async move {
                repo.find(identity_scope(tenant), role_id)
                    .await
                    .map(|role| role.is_some())
            }
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy repo enrollment：统一 conformance 覆盖 create/find/list/update/delete。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_lifecycle_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::new(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let created = policy_fixture(
        "policy-lifecycle",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let updated = policy_fixture(
        "policy-lifecycle",
        tenant,
        2,
        10,
        None,
        PolicyEffect::Deny,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_store_lifecycle(
        testkit::policy_conformance::PolicyLifecycleCase {
            tenant,
            key: "policy-lifecycle",
            created_policy: created,
            updated_policy: updated,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            list: |tenant| {
                let repo = &repo;
                async move {
                    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
                        .await
                }
            },
            update: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_update_and_emit(lifecycle, tenant, policy, policy_version(1)?)
                        .await
                        .map(|_| ())
                }
            },
            delete: |tenant, key| {
                let lifecycle = &lifecycle;
                async move {
                    policy_deactivate_and_emit(
                        lifecycle,
                        tenant,
                        policy_id(key)?,
                        policy_version(2)?,
                    )
                    .await
                    .map(|_| ())
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy repo delete tombstone：删除后同 id 不允许通过普通 create 重建并重置 version。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_delete_leaves_tombstone_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::new(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let created = policy_fixture(
        "policy-delete-tombstone",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let recreated = policy_fixture(
        "policy-delete-tombstone",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Deny,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_delete_leaves_tombstone(
        testkit::policy_conformance::PolicyDeleteTombstoneCase {
            tenant,
            key: "policy-delete-tombstone",
            created_policy: created,
            recreated_policy: recreated,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            list: |tenant| {
                let repo = &repo;
                async move {
                    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
                        .await
                }
            },
            delete: |tenant, key| {
                let lifecycle = &lifecycle;
                async move {
                    policy_deactivate_and_emit(
                        lifecycle,
                        tenant,
                        policy_id(key)?,
                        policy_version(1)?,
                    )
                    .await
                    .map(|_| ())
                }
            },
            is_recreate_rejected: |err: &IdentityError| {
                matches!(err, IdentityError::PolicyAlreadyExists)
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy repo tenant isolation：同 id 在不同 tenant 下互不可见，B 的 update/delete 不影响 A。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_tenant_isolation_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::new(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;
    let tenant_a_policy = policy_fixture(
        "policy-tenant-isolation",
        tenant_a,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let tenant_b_policy = policy_fixture(
        "policy-tenant-isolation",
        tenant_b,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let tenant_b_updated_policy = policy_fixture(
        "policy-tenant-isolation",
        tenant_b,
        2,
        10,
        None,
        PolicyEffect::Deny,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_store_tenant_isolation(
        testkit::policy_conformance::PolicyTenantIsolationCase {
            tenant_a,
            tenant_b,
            key: "policy-tenant-isolation",
            tenant_a_policy,
            tenant_b_policy,
            tenant_b_updated_policy,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            list: |tenant| {
                let repo = &repo;
                async move {
                    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
                        .await
                }
            },
            update: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_update_and_emit(lifecycle, tenant, policy, policy_version(1)?)
                        .await
                        .map(|_| ())
                }
            },
            delete: |tenant, key| {
                let lifecycle = &lifecycle;
                async move {
                    policy_deactivate_and_emit(
                        lifecycle,
                        tenant,
                        policy_id(key)?,
                        policy_version(2)?,
                    )
                    .await
                    .map(|_| ())
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy repo CAS：update/delete 必须使用 current-row version；错版冲突，不回退成 blind write。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_cas_update_delete_conflicts() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let created = policy_fixture(
        "policy-cas",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    policy_create_and_emit(&lifecycle, tenant, created).await?;

    let stale_update_event = unique_event_id("policy-cas-stale-update");
    let stale_update = policy_update_and_emit_event(
        &lifecycle,
        tenant,
        policy_fixture(
            "policy-cas",
            tenant,
            2,
            10,
            None,
            PolicyEffect::Deny,
            PolicyObligations::empty(),
        )?,
        policy_version(2)?,
        &stale_update_event,
    )
    .await;
    assert!(
        matches!(stale_update, Err(IdentityError::VersionConflict)),
        "wrong expected version must conflict, got: {stale_update:?}"
    );
    assert!(
        !policy_outbox_exists(&store, &stale_update_event).await?,
        "stale update must not write policy-updated outbox"
    );

    let stale_delete_event = unique_event_id("policy-cas-stale-delete");
    let stale_delete = policy_deactivate_and_emit_event(
        &lifecycle,
        tenant,
        policy_id("policy-cas")?,
        policy_version(2)?,
        &stale_delete_event,
    )
    .await;
    assert!(
        matches!(stale_delete, Err(IdentityError::VersionConflict)),
        "delete with wrong expected version must conflict, got: {stale_delete:?}"
    );
    assert!(
        !policy_outbox_exists(&store, &stale_delete_event).await?,
        "stale delete must not write policy-updated outbox"
    );

    let update_event = unique_event_id("policy-cas-update");
    let updated = policy_update_and_emit_event(
        &lifecycle,
        tenant,
        policy_fixture(
            "policy-cas",
            tenant,
            2,
            10,
            None,
            PolicyEffect::Deny,
            PolicyObligations::empty(),
        )?,
        policy_version(1)?,
        &update_event,
    )
    .await?;
    assert_eq!(updated.version().get(), 2, "CAS update increments version");
    assert!(
        policy_outbox_exists(&store, &update_event).await?,
        "successful update writes policy-updated outbox"
    );

    let stale_delete_after_update_event = unique_event_id("policy-cas-stale-delete-after-update");
    let stale_delete_after_update = policy_deactivate_and_emit_event(
        &lifecycle,
        tenant,
        policy_id("policy-cas")?,
        policy_version(1)?,
        &stale_delete_after_update_event,
    )
    .await;
    assert!(
        matches!(
            stale_delete_after_update,
            Err(IdentityError::VersionConflict)
        ),
        "stale delete after update must conflict, got: {stale_delete_after_update:?}"
    );
    assert!(
        !policy_outbox_exists(&store, &stale_delete_after_update_event).await?,
        "stale delete after update must not write policy-updated outbox"
    );

    let delete_event = unique_event_id("policy-cas-delete");
    assert!(
        policy_deactivate_and_emit_event(
            &lifecycle,
            tenant,
            policy_id("policy-cas")?,
            policy_version(2)?,
            &delete_event,
        )
        .await?,
        "delete at current version succeeds"
    );
    assert!(
        policy_outbox_exists(&store, &delete_event).await?,
        "successful delete writes policy-updated outbox"
    );

    let missing_delete_event = unique_event_id("policy-cas-delete-missing");
    assert!(
        !policy_deactivate_and_emit_event(
            &lifecycle,
            tenant,
            policy_id("policy-cas")?,
            policy_version(2)?,
            &missing_delete_event,
        )
        .await?,
        "delete of missing policy is idempotent false"
    );
    assert!(
        !policy_outbox_exists(&store, &missing_delete_event).await?,
        "idempotent missing delete must not write policy-updated outbox"
    );

    store.shutdown().await?;
    Ok(())
}

/// policy L2 co-tx：policy 行写入后若事务失败，policy 与 outbox 必须一起回滚。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_cotx_rolls_back_policy_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let tenant_pool = PgTenantPool::new(&store);
    let event_id = unique_event_id("policy-cotx-rollback");
    let (entry, _) = policy_lifecycle_event_with_id(
        tenant,
        "policy-cotx-rollback",
        "created",
        policy_version(1)?,
        &event_id,
    )?;
    let env = OutboxEnvelope::new(
        POLICY_UPDATED_CONTRACT.domain().to_string(),
        POLICY_UPDATED_CONTRACT.contract_id().to_string(),
        OutboxMetadata::new(expected_occurred_at(), tenant, POLICY_UPDATED_CONTRACT)
            .with_subject_id(subject_id("policy-cotx-rollback")),
    );

    let result = tenant_pool
        .co_tx_with_outbox(identity_scope(tenant),
            &entry,
            &env,
            move |conn| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO abac_policies \
                         (tenant_id, id, version, contract_id, permission, effective_from, effective_until, rules) \
                         VALUES ($1::uuid, $2, 1, $3, $4, to_timestamp(10), NULL, $5::jsonb)",
                    )
                    .bind(ROLE_TENANT_A)
                    .bind("policy-cotx-rollback")
                    .bind(POLICY_CONTRACT_ID)
                    .bind(POLICY_PERMISSION)
                    .bind(principal_kind_rule_json(r#"{"kind":"eq","value":"admin"}"#))
                    .execute(conn.conn())
                    .await
                    .map_err(|e| IdentityError::Storage(Box::new(e)))?;
                    Err::<(), IdentityError>(IdentityError::VersionConflict)
                })
            },
            |e| IdentityError::Storage(Box::new(e)),
        )
        .await;
    assert!(
        matches!(result, Err(IdentityError::VersionConflict)),
        "forced business failure must bubble"
    );

    let policy_count: (i64,) = sqlx::query_as("SELECT count(*) FROM abac_policies WHERE id = $1")
        .bind("policy-cotx-rollback")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(policy_count.0, 0, "rolled back policy row must not exist");
    assert!(
        !policy_outbox_exists(&store, &event_id).await?,
        "rolled back transaction must not write outbox"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_fact_conflict_rolls_back_policy_create() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let policy_name = format!("policy-fact-conflict-{}", uuid_like());
    let policy = policy_fixture(
        &policy_name,
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let event_id = unique_event_id("policy-fact-conflict");
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let (entry, envelope) = policy_lifecycle_event_with_id(
        tenant,
        policy.id().as_str(),
        "created",
        policy.version(),
        &event_id,
    )?;

    let conflict = PgPolicyLifecycle::new(&store, fixed_clock())
        .create_and_emit(identity_scope(tenant), policy, entry, envelope)
        .await;
    assert!(
        matches!(conflict, Err(IdentityError::OutboxFactConflict(_))),
        "policy adapter must preserve typed fact conflict: {conflict:?}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM abac_policies WHERE id = $1")
            .bind(&policy_name)
            .fetch_one(&store.pool)
            .await?,
        0,
        "outbox conflict must roll back policy creation"
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;

    store.shutdown().await?;
    Ok(())
}

/// policy manage read side：list_active 按 policy id 稳定分页，deactivate 后 get/list 均不可见。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_list_active_paginates_and_hides_deactivated() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::new(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;

    for id in ["policy-list-c", "policy-list-a", "policy-list-b"] {
        policy_create_and_emit(
            &lifecycle,
            tenant,
            policy_fixture(
                id,
                tenant,
                1,
                10,
                None,
                PolicyEffect::Allow,
                PolicyObligations::empty(),
            )?,
        )
        .await?;
    }

    let first = repo
        .list_active(
            identity_scope(tenant),
            PolicyPage {
                limit: vocab::Limit::new(2)?,
                after: None,
            },
        )
        .await?;
    assert_eq!(
        first
            .policies
            .iter()
            .map(|policy| policy.id().as_str())
            .collect::<Vec<_>>(),
        vec!["policy-list-a", "policy-list-b"],
        "list_active must sort by policy id"
    );
    assert!(first.has_more, "over-fetch must report has_more");

    let second = repo
        .list_active(
            identity_scope(tenant),
            PolicyPage {
                limit: vocab::Limit::new(2)?,
                after: Some(policy_id("policy-list-b")?),
            },
        )
        .await?;
    assert_eq!(
        second
            .policies
            .iter()
            .map(|policy| policy.id().as_str())
            .collect::<Vec<_>>(),
        vec!["policy-list-c"],
        "cursor must resume strictly after the last policy id"
    );
    assert!(!second.has_more, "last page must not report has_more");

    assert!(
        policy_deactivate_and_emit(
            &lifecycle,
            tenant,
            policy_id("policy-list-b")?,
            policy_version(1)?,
        )
        .await?,
        "deactivate existing policy"
    );
    assert!(
        repo.find(identity_scope(tenant), policy_id("policy-list-b")?)
            .await?
            .is_none(),
        "deactivated policy must be hidden from get"
    );

    let after_deactivate = repo
        .list_active(
            identity_scope(tenant),
            PolicyPage {
                limit: vocab::Limit::new(10)?,
                after: None,
            },
        )
        .await?;
    assert_eq!(
        after_deactivate
            .policies
            .iter()
            .map(|policy| policy.id().as_str())
            .collect::<Vec<_>>(),
        vec!["policy-list-a", "policy-list-c"],
        "deactivated policy must be hidden from list"
    );

    store.shutdown().await?;
    Ok(())
}

/// policy repo active-window：effective_from <= at < effective_until；NULL until 表示不过期。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_active_window_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::new(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let expired = policy_fixture(
        "policy-window-expired",
        tenant,
        1,
        10,
        Some(20),
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let active = policy_fixture(
        "policy-window-active",
        tenant,
        1,
        20,
        Some(40),
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let future = policy_fixture(
        "policy-window-future",
        tenant,
        1,
        50,
        Some(80),
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_active_window(
        testkit::policy_conformance::PolicyActiveWindowCase {
            tenant,
            expired_key: "policy-window-expired",
            active_key: "policy-window-active",
            future_key: "policy-window-future",
            expired_policy: expired.clone(),
            active_policy: active.clone(),
            future_policy: future,
            instant_before: 15,
            instant_during: 30,
            instant_after: 90,
            expected_before: vec![expired],
            expected_during: vec![active],
            expected_after: Vec::new(),
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            active_at: |tenant, at| {
                let repo = &repo;
                async move {
                    repo.list_effective(
                        identity_scope(tenant),
                        policy_scope()?,
                        policy_time(at as u64),
                    )
                    .await
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// resource attribute repo：Known/Missing/Stale 是闭枚举，CAS 写入与 tombstone 均 fail-closed。
#[tokio::test(flavor = "multi_thread")]
async fn resource_attribute_repo_resolve_and_cas_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgResourceAttributeRepo::new(&store);
    let tenant = role_tenant(ROLE_TENANT_A)?;

    let created = repo
        .upsert(
            identity_scope(tenant),
            resource_attribute_fixture(tenant, "resource.owner", "owner-a", 10, None)?,
            None,
        )
        .await?;
    assert_eq!(
        created.version(),
        ResourceAttributeVersion::first(),
        "new resource attribute version starts at 1"
    );

    let known = repo
        .resolve_effective(
            identity_scope(tenant),
            policy_scope()?,
            resource_attribute_id()?,
            vec![resource_attribute_key("resource.owner")?],
            policy_time(20),
        )
        .await?;
    let ResourceAttributeResolution::Known(attrs) = known else {
        return Err(std::io::Error::other(format!(
            "expected known resource attribute, got {known:?}"
        ))
        .into());
    };
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].value().as_str(), "owner-a");

    let missing = repo
        .resolve_effective(
            identity_scope(tenant),
            policy_scope()?,
            resource_attribute_id()?,
            vec![resource_attribute_key("resource.missing")?],
            policy_time(20),
        )
        .await?;
    assert!(
        matches!(missing, ResourceAttributeResolution::Missing(key) if key.as_str() == "resource.missing")
    );

    repo.upsert(
        identity_scope(tenant),
        resource_attribute_fixture(tenant, "resource.stale_owner", "owner-a", 1, Some(5))?,
        None,
    )
    .await?;
    let stale = repo
        .resolve_effective(
            identity_scope(tenant),
            policy_scope()?,
            resource_attribute_id()?,
            vec![resource_attribute_key("resource.stale_owner")?],
            policy_time(20),
        )
        .await?;
    assert!(
        matches!(stale, ResourceAttributeResolution::Stale(key) if key.as_str() == "resource.stale_owner")
    );

    let conflict = repo
        .upsert(
            identity_scope(tenant),
            resource_attribute_fixture(tenant, "resource.owner", "owner-b", 10, None)?,
            Some(ResourceAttributeVersion::new(99)?),
        )
        .await;
    assert!(matches!(conflict, Err(IdentityError::VersionConflict)));

    let updated = repo
        .upsert(
            identity_scope(tenant),
            resource_attribute_fixture(tenant, "resource.owner", "owner-b", 10, None)?,
            Some(created.version()),
        )
        .await?;
    assert_eq!(updated.version().get(), 2);

    let stale_expire = repo
        .expire(
            identity_scope(tenant),
            policy_scope()?,
            resource_attribute_id()?,
            resource_attribute_key("resource.owner")?,
            ResourceAttributeVersion::first(),
        )
        .await;
    assert!(matches!(stale_expire, Err(IdentityError::VersionConflict)));

    assert!(
        repo.expire(
            identity_scope(tenant),
            policy_scope()?,
            resource_attribute_id()?,
            resource_attribute_key("resource.owner")?,
            updated.version(),
        )
        .await?,
        "expire at current version succeeds"
    );
    let after_expire = repo
        .resolve_effective(
            identity_scope(tenant),
            policy_scope()?,
            resource_attribute_id()?,
            vec![resource_attribute_key("resource.owner")?],
            policy_time(20),
        )
        .await?;
    assert!(matches!(
        after_expire,
        ResourceAttributeResolution::Missing(_)
    ));

    store.shutdown().await?;
    Ok(())
}

/// migration 0046：resource_attributes 必须授予 rss_app 窄 DML 权限，并由 FORCE RLS 执行 tenant isolation。
#[tokio::test(flavor = "multi_thread")]
async fn resource_attribute_repo_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'resource_attributes', 'SELECT'), \
                has_table_privilege('rss_app', 'resource_attributes', 'INSERT'), \
                has_table_privilege('rss_app', 'resource_attributes', 'UPDATE'), \
                has_table_privilege('rss_app', 'resource_attributes', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'resource_attributes'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "resource_attributes must ENABLE RLS");
    assert!(rls_forced, "resource_attributes must FORCE RLS");
    assert!(can_select, "rss_app must SELECT resource_attributes");
    assert!(can_insert, "rss_app must INSERT resource_attributes");
    assert!(can_update, "rss_app must UPDATE resource_attributes");
    assert!(
        !can_delete,
        "rss_app must not DELETE resource_attributes; expire is versioned tombstone UPDATE"
    );

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let resource_id = uuid::Uuid::new_v4().to_string();

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO resource_attributes \
             (tenant_id, contract_id, permission, resource_id, attribute_key, attribute_value, version, effective_from, effective_until) \
             VALUES ($1::uuid, $2, $3, $4::uuid, 'resource.owner', 'owner-a', 1, now(), NULL)",
        )
        .bind(&tenant_a)
        .bind(POLICY_CONTRACT_ID)
        .bind(POLICY_PERMISSION)
        .bind(&resource_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM resource_attributes WHERE attribute_key = 'resource.owner'",
        )
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 1, "tenant A scope must see tenant A attribute");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM resource_attributes WHERE attribute_key = 'resource.owner'",
        )
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 0, "tenant B scope must not see tenant A attribute");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO resource_attributes \
             (tenant_id, contract_id, permission, resource_id, attribute_key, attribute_value, version, effective_from, effective_until) \
             VALUES ($1::uuid, $2, $3, $4::uuid, 'resource.owner', 'owner-b', 1, now(), NULL)",
        )
        .bind(&tenant_b)
        .bind(POLICY_CONTRACT_ID)
        .bind(POLICY_PERMISSION)
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "WITH CHECK must reject tenant B row while rss.tenant_id is tenant A"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM resource_attributes")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must make resource_attributes invisible"
        );
        tx.rollback().await?;
    }

    {
        let result = sqlx::query(
            "INSERT INTO resource_attributes \
             (tenant_id, contract_id, permission, resource_id, attribute_key, attribute_value, version, effective_from, effective_until) \
             VALUES ($1::uuid, $2, $3, $4::uuid, 'resource.id', 'reserved', 1, now(), NULL)",
        )
        .bind(&tenant_a)
        .bind(POLICY_CONTRACT_ID)
        .bind(POLICY_PERMISSION)
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&store.pool)
        .await;
        assert!(result.is_err(), "resource.id is synthetic and reserved");
    }

    store.shutdown().await?;
    Ok(())
}

async fn insert_raw_policy_and_load(
    store: &PgStore,
    repo: &PgPolicyRepo,
    id: &str,
    rules_json: &str,
) -> Result<(), IdentityError> {
    let tenant = TenantId::parse(ROLE_TENANT_A).map_err(|_| IdentityError::InvalidPolicy)?;
    sqlx::query("DELETE FROM abac_policies WHERE tenant_id = $1::uuid")
        .bind(ROLE_TENANT_A)
        .execute(&store.pool)
        .await
        .map_err(|e| IdentityError::Storage(Box::new(e)))?;
    sqlx::query(
        "INSERT INTO abac_policies \
         (tenant_id, id, version, contract_id, permission, effective_from, effective_until, rules) \
         VALUES ($1::uuid, $2, 1, $3, $4, to_timestamp(10), NULL, $5::jsonb)",
    )
    .bind(ROLE_TENANT_A)
    .bind(id)
    .bind(POLICY_CONTRACT_ID)
    .bind(POLICY_PERMISSION)
    .bind(rules_json)
    .execute(&store.pool)
    .await
    .map_err(|e| IdentityError::Storage(Box::new(e)))?;

    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
        .await
        .map(|_| ())
}

/// policy repo decode is strict：语义非法与未知 JSON 字段都会使 active load fail-closed。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_rejects_malformed_persisted_json() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::new(&store);

    testkit::policy_conformance::assert_policy_rejects_malformed(
        (
            "policy-malformed",
            principal_kind_rule_json(r#"{"kind":"like","pattern":""}"#),
        ),
        ("policy-unknown-field", r#"{"rules":[],"unexpected":true}"#),
        |(id, rules_json)| {
            let store = &store;
            let repo = &repo;
            async move { insert_raw_policy_and_load(store, repo, id, &rules_json).await }
        },
        |(id, rules_json)| {
            let store = &store;
            let repo = &repo;
            async move { insert_raw_policy_and_load(store, repo, id, rules_json).await }
        },
        policy_rejection,
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy obligations：row scope 与 field mask 必须经 JSONB 原样 round-trip。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_obligation_round_trip_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::new(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let obligations = PolicyObligations::new(
        Some(vocab::ScopedTenant::Tenant),
        vec![AttributeKey::parse("email").map_err(|_| IdentityError::InvalidPolicy)?],
    );
    let policy = policy_fixture(
        "policy-obligations",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        obligations.clone(),
    )?;

    testkit::policy_conformance::assert_policy_obligation_round_trip(
        testkit::policy_conformance::PolicyObligationCase {
            tenant,
            key: "policy-obligations",
            policy,
            expected_obligations: obligations,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            obligations: first_policy_obligations,
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// route gate conformance：durable allow 携带非空 obligations 时，当前 HTTP route gate 必须 deny。
#[tokio::test(flavor = "multi_thread")]
async fn policy_route_gate_conformance_denies_nonempty_obligations() -> TestResult {
    testkit::policy_conformance::assert_route_gate_denies_nonempty_obligations(
        PolicyObligations::empty(),
        PolicyObligations::new(Some(vocab::ScopedTenant::Tenant), Vec::new()),
        |obligations| async move { Ok::<bool, IdentityError>(obligations.is_empty()) },
    )
    .await?;
    Ok(())
}

/// migration 0034：abac_policies 必须授予 rss_app 窄 DML 权限，并由 FORCE RLS 执行 tenant isolation。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 与固定测试 JSON 均为合法构造；item-level carve-out。
async fn policy_repo_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'abac_policies', 'SELECT'), \
                has_table_privilege('rss_app', 'abac_policies', 'INSERT'), \
                has_table_privilege('rss_app', 'abac_policies', 'UPDATE'), \
                has_table_privilege('rss_app', 'abac_policies', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'abac_policies'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "abac_policies must ENABLE RLS");
    assert!(rls_forced, "abac_policies must FORCE RLS");
    assert!(can_select, "rss_app must SELECT abac_policies");
    assert!(can_insert, "rss_app must INSERT abac_policies");
    assert!(can_update, "rss_app must UPDATE abac_policies");
    assert!(
        !can_delete,
        "rss_app must not DELETE abac_policies; policy delete is versioned tombstone UPDATE"
    );

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let rules_json = principal_kind_rule_json(r#"{"kind":"eq","value":"admin"}"#);

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO abac_policies \
             (tenant_id, id, version, contract_id, permission, effective_from, effective_until, rules) \
             VALUES ($1::uuid, 'rls-policy-a', 1, $2, $3, now(), NULL, $4::jsonb)",
        )
        .bind(&tenant_a)
        .bind(POLICY_CONTRACT_ID)
        .bind(POLICY_PERMISSION)
        .bind(&rules_json)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM abac_policies WHERE id = 'rls-policy-a'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(cnt.0, 1, "tenant A scope must see tenant A policy");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM abac_policies WHERE id = 'rls-policy-a'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(cnt.0, 0, "tenant B scope must not see tenant A policy");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO abac_policies \
             (tenant_id, id, version, contract_id, permission, effective_from, effective_until, rules) \
             VALUES ($1::uuid, 'rls-policy-b', 1, $2, $3, now(), NULL, $4::jsonb)",
        )
        .bind(&tenant_b)
        .bind(POLICY_CONTRACT_ID)
        .bind(POLICY_PERMISSION)
        .bind(&rules_json)
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "WITH CHECK must reject tenant B row while rss.tenant_id is tenant A"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM abac_policies")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must make abac_policies invisible"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// 并发：同 (tenant,id) 并发 save → ON CONFLICT 收敛、全 Ok（无 PK 错逃逸）、终态单行；不同 id 并发 → 各自落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: tokio::spawn join 必定成功（task 正常 Ok）；converged role 必定可查到；item-level carve-out（error-handling.md §Carve-out）。
async fn role_repo_concurrent_save_converges() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgRoleRepo::new(&store));
    let tenant = role_tenant(ROLE_TENANT_A)?;

    // 同 id 并发 upsert：8 个 task 竞写同一 (tenant,id)。
    let mut handles = Vec::new();
    for i in 0..8 {
        let repo = Arc::clone(&repo);
        handles.push(tokio::spawn(async move {
            let permission = if i % 2 == 0 {
                "identity:policy:read"
            } else {
                "identity:policy:update"
            };
            let role = Role::hydrate("contended", "C", &[permission.to_string()])?;
            repo.save(identity_scope(tenant), role).await
        }));
    }
    for h in handles {
        // 每个 save 必 Ok——并发 PK 冲突由 ON CONFLICT DO UPDATE 收敛，不逃逸为 unique violation。
        h.await.expect("join")?;
    }
    // throwaway role 取 contended 的 RoleId（不 save，仅为 mint id 查终态）。
    let contended_id = Role::hydrate("contended", "x", &[])?.id().clone();
    let got = repo
        .find(identity_scope(tenant), contended_id)
        .await?
        .expect("contended role converged");
    assert_eq!(got.id().as_str(), "contended");
    // name 在所有 writer 间确定（恒 "C"）→ 终态 name 一致；permissions 因 writer 非确定（read/update）不断言具体值。
    assert_eq!(got.name(), "C", "并发收敛终态 name 一致");
    let n: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
            .bind(ROLE_TENANT_A)
            .bind("contended")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(n.0, 1, "并发同 id → 终态单行");

    // 不同 id 并发 save → 各自落库（无相互干扰）。
    let mut handles2 = Vec::new();
    for i in 0..8 {
        let repo = Arc::clone(&repo);
        handles2.push(tokio::spawn(async move {
            let role = Role::hydrate(&format!("role-{i}"), "N", &[])?;
            repo.save(identity_scope(tenant), role).await
        }));
    }
    for h in handles2 {
        h.await.expect("join")?;
    }
    let n2: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id LIKE 'role-%'",
    )
    .bind(ROLE_TENANT_A)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(n2.0, 8, "8 个不同 id 各落一行");

    store.shutdown().await?;
    Ok(())
}

// list：按 id 升序稳定分页，cursor after 语义，且 tenant scoped。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn role_repo_list_paginates_and_is_tenant_scoped() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::new(&store);
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;

    for (id, name) in [("role-a", "A"), ("role-b", "B"), ("role-c", "C")] {
        repo.save(
            identity_scope(tenant_a),
            Role::hydrate(id, name, &["identity:policy:read".to_string()])?,
        )
        .await?;
    }
    repo.save(
        identity_scope(tenant_b),
        Role::hydrate("role-aa", "TenantB", &["identity:policy:read".to_string()])?,
    )
    .await?;

    let page1 = repo
        .list(
            identity_scope(tenant_a),
            RolePage {
                limit: vocab::Limit::new(2)?,
                after: None,
            },
        )
        .await?;
    assert!(page1.has_more);
    assert_eq!(
        page1
            .roles
            .iter()
            .map(|role| role.id().as_str())
            .collect::<Vec<_>>(),
        vec!["role-a", "role-b"]
    );

    let after = page1.roles[1].id().clone();
    let page2 = repo
        .list(
            identity_scope(tenant_a),
            RolePage {
                limit: vocab::Limit::new(2)?,
                after: Some(after),
            },
        )
        .await?;
    assert!(!page2.has_more);
    assert_eq!(
        page2
            .roles
            .iter()
            .map(|role| role.id().as_str())
            .collect::<Vec<_>>(),
        vec!["role-c"]
    );

    let tenant_b_page = repo
        .list(
            identity_scope(tenant_b),
            RolePage {
                limit: vocab::Limit::new(10)?,
                after: None,
            },
        )
        .await?;
    assert_eq!(
        tenant_b_page
            .roles
            .iter()
            .map(|role| role.id().as_str())
            .collect::<Vec<_>>(),
        vec!["role-aa"],
        "tenant B 只看到自己的角色"
    );

    store.shutdown().await?;
    Ok(())
}

// RoleBindingLifecycle：经 RbacAdminService 驱动生产 Pg impl，验证 binding + outbox both-or-neither 正向路径与
// revoke 未命中不发事件。
#[tokio::test(flavor = "multi_thread")]
async fn role_binding_lifecycle_assign_revoke_writes_binding_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;
    let role = Role::hydrate("role-admin", "Admin", &["identity:role:assign".to_string()])?;
    let role_id = role.id().clone();
    let repo = PgRoleRepo::new(&store);
    repo.save(identity_scope(tenant), role.clone()).await?;
    repo.save(identity_scope(tenant_b), role).await?;

    let svc = identity::RbacAdminService::new(
        Arc::from(DynRoleReadRepo::new_box(PgRoleRepo::new(&store))),
        Arc::from(DynRoleBindingLifecycle::new_box(
            PgRoleBindingLifecycle::new(&store, fixed_clock()),
        )),
        fixed_clock(),
    );
    let actor = ids::UserId::parse("11111111-2222-4333-8444-555555555555")?;

    svc.assign_role(
        tenant,
        actor,
        vocab::PrincipalKind::Admin,
        "target-user".to_string(),
        role_id.clone(),
    )
    .await?;
    let binding_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .bind("target-user")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(binding_count.0, 1, "assign 写入 binding");
    let assigned_events: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE contract_id = $1")
            .bind("identity.role-assigned")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(assigned_events.0, 1, "assign 写入 role-assigned outbox");

    let cross_tenant_revoked = svc
        .revoke_role(
            tenant_b,
            actor,
            vocab::PrincipalKind::Admin,
            role_id.clone(),
            "target-user".to_string(),
        )
        .await?;
    assert!(
        !cross_tenant_revoked,
        "tenant B revoke 隐藏 tenant A binding"
    );
    let binding_after_cross_tenant_revoke: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .bind("target-user")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        binding_after_cross_tenant_revoke.0, 1,
        "tenant B revoke 不应删除 tenant A binding"
    );
    let revoked_events_before_hit: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE contract_id = $1")
            .bind("identity.role-revoked")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        revoked_events_before_hit.0, 0,
        "tenant B revoke 未命中不写 role-revoked outbox"
    );

    let revoked = svc
        .revoke_role(
            tenant,
            actor,
            vocab::PrincipalKind::Admin,
            role_id.clone(),
            "target-user".to_string(),
        )
        .await?;
    assert!(revoked);
    let binding_after_revoke: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .bind("target-user")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(binding_after_revoke.0, 0, "revoke 删除 binding");

    let revoked_again = svc
        .revoke_role(
            tenant,
            actor,
            vocab::PrincipalKind::Admin,
            role_id,
            "target-user".to_string(),
        )
        .await?;
    assert!(!revoked_again, "重复 revoke 幂等 false");
    let revoked_events: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE contract_id = $1")
            .bind("identity.role-revoked")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(revoked_events.0, 1, "未命中 revoke 不追加 outbox");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn role_binding_lifecycle_persists_nonempty_causation_id() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let role = Role::hydrate(
        "role-causation",
        "Causation",
        &["identity:role:assign".to_string()],
    )?;
    PgRoleRepo::new(&store)
        .save(identity_scope(tenant), role)
        .await?;

    let event_id = unique_event_id("role-causation");
    let role_assigned_contract = vocab::ContractBinding::from_static(
        "identity",
        "identity.role-assigned",
        "v1",
        "sha256:7c7a931a40c99329cfd172d834191fdbc47c5d7f3307a4f09f4320693d7722e9",
    );
    let entry = EventEntry::new(
        EventTopic::parse("identity.role-assigned").unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        reviewed_payload(br#"{"subject":"target-user","roleId":"role-causation"}"#),
    );
    let envelope = OutboxEnvelopeParts::new(
        role_assigned_contract,
        tenant,
        subject_id("target-user"),
        actor_for(tenant),
    )
    .with_causation_id(diport::EnvelopeCausationId::from_opaque("role-upstream-event").unwrap());
    let binding = RoleBinding::hydrate("target-user", "role-causation", tenant)?;

    PgRoleBindingLifecycle::new(&store, fixed_clock())
        .assign_and_emit(identity_scope(tenant), binding, entry, envelope)
        .await?;

    let outbox: (Option<String>, String) =
        sqlx::query_as("SELECT causation_id, metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        outbox.0.as_deref(),
        Some("role-upstream-event"),
        "role binding co-tx 应透传非空 causation_id"
    );
    assert!(
        !outbox.1.contains("role-upstream-event"),
        "role binding causation_id persisted-only，不得进入 metadata: {}",
        outbox.1
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn role_binding_fact_conflict_rolls_back_assignment() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let role_name = format!("role-fact-conflict-{}", uuid_like());
    let subject = format!("subject-fact-conflict-{}", uuid_like());
    PgRoleRepo::new(&store)
        .save(
            identity_scope(tenant),
            Role::hydrate(
                &role_name,
                "Fact conflict",
                &["identity:role:assign".to_string()],
            )?,
        )
        .await?;
    let event_id = unique_event_id("role-binding-fact-conflict");
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let entry = EventEntry::new(
        EventTopic::parse("identity.role-assigned")?,
        IdemKey::parse(&event_id)?,
        reviewed_payload(
            serde_json::to_vec(&serde_json::json!({
                "subject": subject,
                "roleId": role_name
            }))?
            .as_slice(),
        ),
    );
    let envelope = OutboxEnvelopeParts::new(
        vocab::ContractBinding::from_static(
            "identity",
            "identity.role-assigned",
            "v1",
            "sha256:7c7a931a40c99329cfd172d834191fdbc47c5d7f3307a4f09f4320693d7722e9",
        ),
        tenant,
        subject_id(&subject),
        actor_for(tenant),
    );
    let binding = RoleBinding::hydrate(&subject, &role_name, tenant)?;

    let conflict = PgRoleBindingLifecycle::new(&store, fixed_clock())
        .assign_and_emit(identity_scope(tenant), binding, entry, envelope)
        .await;
    let Err(conflict) = conflict else {
        return Err("role binding write must fail on a conflicting outbox fact".into());
    };
    assert_eq!(conflict.kind(), OutboxEmitErrorKind::FactConflict);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM role_bindings \
             WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
        )
        .bind(tenant.to_string())
        .bind(&role_name)
        .bind(&subject)
        .fetch_one(&store.pool)
        .await?,
        0,
        "outbox conflict must roll back role assignment"
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;

    store.shutdown().await?;
    Ok(())
}

// ── T20–T23: RLS 强制力证明（#1298）────────────────────────────────────────────
//
// 0009 迁移落地 ENABLE ROW LEVEL SECURITY + FORCE ROW LEVEL SECURITY + tenant_isolation policy（四表：
// sessions / config_entries / roles / secret_refs）+ rss_app serving role；本组测试以 SET LOCAL ROLE
// rss_app 切换到非 owner 角色，验证 RLS 对 rss_app 生效（superuser 永远绕过 RLS，不适合做验证角色）。
//
// 测试结构：
//   • Tx1（rss_app + tenant_a scope）：INSERT tenant_a 行 → 成功（WITH CHECK pass）。
//   • Tx2（rss_app + tenant_a scope）：SELECT → tenant_a 行可见（USING pass）。
//   • Tx3（rss_app + tenant_b scope）：SELECT 同行 → 不可见（USING 过滤，跨租读被阻）。
//   • Tx4（rss_app + tenant_a scope）：INSERT tenant_b 行 → 错误（WITH CHECK 拒绝，跨租写被阻）。
//
// 前置：`GRANT rss_app TO CURRENT_USER`——testcontainer 连接角色（superuser）需先 member of rss_app
// 才能执行 `SET LOCAL ROLE rss_app`；幂等，不影响后续 superuser 权限。

/// T20：RLS 强制力证明 — sessions 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 和固定 UUID 格式化不会失败；函数级 item-level carve-out。
async fn t20_rls_sessions_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等（已是 member 则 no-op）。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let session_a = uuid::Uuid::new_v4().to_string();

    // Tx1：rss_app + tenant_a scope → INSERT tenant_a session → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at) \
             VALUES ($1, $2, $3::uuid, now() + interval '1 hour', now())",
        )
        .bind(&session_a)
        .bind("rls-test-subject")
        .bind(&tenant_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a session failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT session_a → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 1,
            "t20: rss_app + tenant_a scope — session_a 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT session_a → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t20: rss_app + tenant_b scope — session_a 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b session → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at) \
             VALUES ($1, $2, $3::uuid, now() + interval '1 hour', now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("rls-test-subject")
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t20: WITH CHECK 应拒绝 tenant_b 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT sessions → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t20: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T21：RLS 强制力证明 — config_entries 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t21_rls_config_entries_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let cfg_key = format!("rls.test.key.{}", uuid::Uuid::new_v4());

    // Tx1：rss_app + tenant_a scope → INSERT config_entry → 成功。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO config_entries (
                 tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
             ) VALUES ($1::uuid, $2, 1, NULL, 1, $3, $4)",
        )
        .bind(&tenant_a)
        .bind(&cfg_key)
        .bind(&b"ciphertext"[..])
        .bind("settings-config:1")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a config failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
        )
        .bind(&tenant_a)
        .bind(&cfg_key)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 1,
            "t21: rss_app + tenant_a scope — config_entry 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 key → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                .bind(&cfg_key)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t21: rss_app + tenant_b scope — tenant_a config_entry 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b config → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO config_entries (
                 tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
             ) VALUES ($1::uuid, $2, 1, NULL, 1, $3, $4)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(format!("{cfg_key}.cross"))
        .bind(&b"ciphertext"[..])
        .bind("settings-config:1")
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t21: WITH CHECK 应拒绝 tenant_b config 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT config_entries → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                .bind(&cfg_key)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t21: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T22：RLS 强制力证明 — roles 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t22_rls_roles_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let role_id = format!("rls-role-{}", uuid::Uuid::new_v4());

    // Tx1：rss_app + tenant_a scope → INSERT role → 成功。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO roles (tenant_id, id, name, permissions) \
             VALUES ($1::uuid, $2, $3, $4)",
        )
        .bind(&tenant_a)
        .bind(&role_id)
        .bind("RlsTestRole")
        .bind(vec!["identity:policy:read".to_string()])
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a role failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
                .bind(&tenant_a)
                .bind(&role_id)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 1,
            "t22: rss_app + tenant_a scope — role 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 role_id → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
            .bind(&role_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t22: rss_app + tenant_b scope — tenant_a role 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b role → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO roles (tenant_id, id, name, permissions) \
             VALUES ($1::uuid, $2, $3, $4)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(format!("{role_id}-cross"))
        .bind("CrossTenantRole")
        .bind(vec!["identity:policy:read".to_string()])
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t22: WITH CHECK 应拒绝 tenant_b role 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT roles → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
            .bind(&role_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t22: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T22b：RLS 强制力证明 — role_bindings 表（#1190 PR5b）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT/SELECT binding 成功；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b binding → WITH CHECK 拒绝；未设 rss.tenant_id → fail-closed（0 行）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t22b_rls_role_bindings_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let role_id = format!("rls-binding-role-{}", uuid::Uuid::new_v4());
    let subject = format!("rls-binding-subject-{}", uuid::Uuid::new_v4());

    // FK 前置：两个租户各有同 id role，避免 Tx4 被 FK 失败遮蔽 RLS WITH CHECK。
    sqlx::query(
        "INSERT INTO roles (tenant_id, id, name, permissions) \
         VALUES ($1::uuid, $2, $3, $4), ($5::uuid, $2, $6, $4)",
    )
    .bind(&tenant_a)
    .bind(&role_id)
    .bind("RlsBindingRoleA")
    .bind(vec!["identity:role:read".to_string()])
    .bind(&tenant_b)
    .bind("RlsBindingRoleB")
    .execute(&store.pool)
    .await?;

    // Tx1：rss_app + tenant_a scope → INSERT tenant_a binding → 成功。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO role_bindings (tenant_id, role_id, subject) \
             VALUES ($1::uuid, $2, $3)",
        )
        .bind(&tenant_a)
        .bind(&role_id)
        .bind(&subject)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a role_binding failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
        )
        .bind(&tenant_a)
        .bind(&role_id)
        .bind(&subject)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 1,
            "t22b: rss_app + tenant_a scope — role_binding 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 binding → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM role_bindings WHERE role_id = $1 AND subject = $2",
        )
        .bind(&role_id)
        .bind(&subject)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "t22b: rss_app + tenant_b scope — tenant_a role_binding 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b binding → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO role_bindings (tenant_id, role_id, subject) \
             VALUES ($1::uuid, $2, $3)",
        )
        .bind(&tenant_b)
        .bind(&role_id)
        .bind(format!("{subject}-cross"))
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t22b: WITH CHECK 应拒绝 tenant_b role_binding 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT role_bindings → 0 行。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM role_bindings WHERE role_id = $1 AND subject = $2",
        )
        .bind(&role_id)
        .bind(&subject)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "t22b: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T23：RLS 强制力证明 — secret_refs 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝；未设 rss.tenant_id → fail-closed（0 行）。
/// 同 config_entries t21 范式（secret_refs 版本历史模型同 config_entries 0005 范式，#1298）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t23_secret_refs_rls_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等（已是 member 则 no-op）。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    // 唯一 secret_key（防并发测试污染）。
    let secret_key = format!("rls.test.secret.{}", uuid::Uuid::new_v4());

    // Tx1：rss_app + tenant_a scope → INSERT secret_refs 行 → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key) \
             VALUES ($1::uuid, $2, 1, $3, $4)",
        )
        .bind(&tenant_a)
        .bind(&secret_key)
        .bind("vault-a")
        .bind("secret/rls-test")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a secret_ref failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
        )
        .bind(&tenant_a)
        .bind(&secret_key)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 1,
            "t23: rss_app + tenant_a scope — secret_ref 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 key → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM secret_refs WHERE secret_key = $1")
            .bind(&secret_key)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t23: rss_app + tenant_b scope — tenant_a secret_ref 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b secret_ref → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key) \
             VALUES ($1::uuid, $2, 1, $3, $4)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(format!("{secret_key}.cross"))
        .bind("vault-b")
        .bind("secret/cross-tenant")
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t23: WITH CHECK 应拒绝 tenant_b secret_ref 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT secret_refs → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM secret_refs WHERE secret_key = $1")
            .bind(&secret_key)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t23: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// ── RT: PgRefreshTokenStore 集成验证（#1325）────────────────────────────────────
//
// 覆盖：insert→find_by_hash 往返；rotate CAS（Active→true, 再次 rotate same old→false）；
// rotate 后 old 变 consumed（find 仍可查到，status=consumed）；revoke_lineage 整条谱系变 revoked；
// 跨租隔离（tenant B 查 tenant A 的 hash → None）。

use identity::ports::{RefreshTokenStore, TenantId as RtTenantId};
use vocab::PrincipalKind;

use crate::PgRefreshTokenStore;

/// 构造测试用固定 hash（32 字节全 0xAB 填充，可识别但不冲突）。
fn test_hash_for(suffix: u8) -> [u8; 32] {
    [suffix; 32]
}

/// RT-1：insert → find_by_hash 往返——record 各字段正确重建。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 是已知合法值；find_by_hash 结果必定 Some；集成测试 happy-path；item-level carve-out（error-handling.md §Carve-out）。
async fn rt1_insert_then_find_by_hash_roundtrip() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let lineage = id.clone(); // 签发根：lineage_id == id
    let hash_bytes = test_hash_for(0xA1);
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = issued + Duration::from_secs(3_600);

    let record = RefreshTokenRecord::hydrate(
        id.clone(),
        tenant,
        "alice-subject",
        PrincipalKind::User,
        hash_bytes,
        None, // 签发根 parent_id = None
        lineage.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    // RefreshTokenHash::new は pub(crate)——hydrate した record から clone して取り出す（外部 crate 直接构造不可）。
    let hash_to_find = record.token_hash().clone();

    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(identity_scope(tenant), record).await?;

    let found = rt_store
        .find_by_hash(identity_scope(tenant), hash_to_find)
        .await?;
    let found = found.expect("rt1: 应能按 hash 找到刚写入的 record");

    assert_eq!(found.id().as_str(), id, "rt1: id 往返");
    assert_eq!(found.subject(), "alice-subject", "rt1: subject 往返");
    assert_eq!(found.kind(), PrincipalKind::User, "rt1: kind 往返");
    assert_eq!(found.status(), RefreshStatus::Active, "rt1: status=active");
    assert!(found.parent_id().is_none(), "rt1: 签发根 parent_id=None");
    assert_eq!(found.lineage_id().as_str(), lineage, "rt1: lineage_id 往返");
    // 时间精度：epoch 秒往返，millisecond sub-second 被截断，断言到秒粒度。
    assert_eq!(
        found
            .issued_at()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        issued
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "rt1: issued_at 往返"
    );
    assert_eq!(
        found
            .expires_at()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        expires
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "rt1: expires_at 往返"
    );

    store.shutdown().await?;
    Ok(())
}

/// RT-2：rotate CAS（Active → consumed + new 写入）返 true；再次 rotate 同 old → false（already consumed）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 已知合法值；old/new record 必定可查到；集成测试 happy-path；item-level carve-out。
async fn rt2_rotate_cas_active_then_consumed() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let old_id_str = uuid::Uuid::new_v4().to_string();
    let lineage_str = old_id_str.clone();
    let hash_old = test_hash_for(0xB1);
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_100_000);
    let expires = issued + Duration::from_secs(3_600);

    // 写入 old（Active）——clone id 和 hash 供后续调用（RefreshTokenId::new / RefreshTokenHash::new 是 pub(crate)）。
    let old_record = RefreshTokenRecord::hydrate(
        old_id_str.clone(),
        tenant,
        "bob",
        PrincipalKind::User,
        hash_old,
        None,
        lineage_str.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_old_typed = old_record.token_hash().clone();
    // sealed command: clone 源 record 供 begin_rotation（移动前保留引用，rotate 不再接受裸 id/record）。
    let old_for_rotate = old_record.clone();
    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(identity_scope(tenant), old_record).await?;

    // 构造 new record（rotation 子节点），clone hash 供后续 find 使用。
    let new_id_str = uuid::Uuid::new_v4().to_string();
    let hash_new = test_hash_for(0xB2);
    let new_record = RefreshTokenRecord::hydrate(
        new_id_str.clone(),
        tenant,
        "bob",
        PrincipalKind::User,
        hash_new,
        Some(old_id_str.clone()),
        lineage_str.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let hash_new_typed = new_record.token_hash().clone();

    // 首次 rotate：old Active → CAS 命中 → true，new 已写入。
    // begin_rotation 从 old_for_rotate（同一 tenant）派生 sealed 命令（REFRESH-ROTATE-LINEAGE-01）。
    let rotation1 = old_for_rotate.begin_rotation(
        new_record.id().clone(),
        new_record.token_hash().clone(),
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let result = rt_store.rotate(identity_scope(tenant), rotation1).await?;
    assert!(result, "rt2: 首次 rotate 应返回 true（CAS 命中）");

    // 验证 old 变 consumed。
    let old_found = rt_store
        .find_by_hash(identity_scope(tenant), hash_old_typed)
        .await?
        .expect("rt2: old 仍可查到");
    assert_eq!(
        old_found.status(),
        RefreshStatus::Consumed,
        "rt2: old 应为 consumed"
    );

    // 验证 new 可查到且为 Active。
    let new_found = rt_store
        .find_by_hash(identity_scope(tenant), hash_new_typed)
        .await?
        .expect("rt2: new 应可查到");
    assert_eq!(
        new_found.status(),
        RefreshStatus::Active,
        "rt2: new 应为 active"
    );

    // 再次 rotate 同 old（已 consumed）→ CAS miss → false，new2 不写入。
    let new2_record = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "bob",
        PrincipalKind::User,
        test_hash_for(0xB3),
        Some(old_id_str.clone()),
        lineage_str.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );
    let hash_new2_typed = new2_record.token_hash().clone();
    let rotation2 = old_for_rotate.begin_rotation(
        new2_record.id().clone(),
        new2_record.token_hash().clone(),
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );
    let result2 = rt_store.rotate(identity_scope(tenant), rotation2).await?;
    assert!(
        !result2,
        "rt2: 再次 rotate consumed old 应返回 false（CAS miss）"
    );

    // new2 不应被写入。
    let new2_found = rt_store
        .find_by_hash(identity_scope(tenant), hash_new2_typed)
        .await?;
    assert!(new2_found.is_none(), "rt2: CAS miss 时 new2 不应写入");

    store.shutdown().await?;
    Ok(())
}

/// RT-3：revoke_lineage 把整条谱系（multiple records）全部置 Revoked；幂等（再次调用也 Ok）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 已知合法值；revoked records 仍可按 hash 查到；集成测试 happy-path；item-level carve-out。
async fn rt3_revoke_lineage_revokes_all_and_is_idempotent() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let lineage_str = uuid::Uuid::new_v4().to_string();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_200_000);
    let expires = issued + Duration::from_secs(3_600);
    let rt_store = PgRefreshTokenStore::new(&store);

    // 插入同一 lineage 的两条记录（root + child）——clone 类型值供后续 revoke/find 使用。
    // RefreshTokenId::new / RefreshTokenHash::new 是 pub(crate)，从 hydrate 后的 record clone 取出。
    let root_id = uuid::Uuid::new_v4().to_string();
    let root_record = RefreshTokenRecord::hydrate(
        root_id.clone(),
        tenant,
        "carol",
        PrincipalKind::Admin,
        test_hash_for(0xC1),
        None,
        lineage_str.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let lineage_id = root_record.lineage_id().clone();
    let hash_root_typed = root_record.token_hash().clone();
    rt_store.insert(identity_scope(tenant), root_record).await?;

    let child_record = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "carol",
        PrincipalKind::Admin,
        test_hash_for(0xC2),
        Some(root_id.clone()),
        lineage_str.clone(),
        RefreshStatus::Consumed,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let hash_child_typed = child_record.token_hash().clone();
    rt_store
        .insert(identity_scope(tenant), child_record)
        .await?;

    // revoke_lineage → 整条谱系置 Revoked。
    rt_store
        .revoke_lineage(identity_scope(tenant), lineage_id.clone())
        .await?;

    // root 变 revoked。
    let root_found = rt_store
        .find_by_hash(identity_scope(tenant), hash_root_typed)
        .await?
        .expect("rt3: root 仍可查到");
    assert_eq!(
        root_found.status(),
        RefreshStatus::Revoked,
        "rt3: root 应为 revoked"
    );

    // child 变 revoked。
    let child_found = rt_store
        .find_by_hash(identity_scope(tenant), hash_child_typed)
        .await?
        .expect("rt3: child 仍可查到");
    assert_eq!(
        child_found.status(),
        RefreshStatus::Revoked,
        "rt3: child 应为 revoked"
    );

    // 幂等：再次 revoke_lineage 也 Ok（0 行 UPDATE）。
    rt_store
        .revoke_lineage(identity_scope(tenant), lineage_id)
        .await?;

    store.shutdown().await?;
    Ok(())
}

/// RT-4：跨租隔离——tenant B 查 tenant A 的 hash → None（不泄露存在性）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid / TenantId parse 已知合法值；集成测试 happy-path；item-level carve-out。
async fn rt4_cross_tenant_isolation() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a_str = uuid::Uuid::new_v4().to_string();
    let tenant_b_str = uuid::Uuid::new_v4().to_string();
    let tenant_a = RtTenantId::parse(&tenant_a_str).unwrap();
    let tenant_b = RtTenantId::parse(&tenant_b_str).unwrap();

    let id_a = uuid::Uuid::new_v4().to_string();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_300_000);
    let expires = issued + Duration::from_secs(3_600);

    // tenant A 写入一条 record，clone hash 供后续 find 使用（RefreshTokenHash::new 是 pub(crate)）。
    let record_a = RefreshTokenRecord::hydrate(
        id_a.clone(),
        tenant_a,
        "dave",
        PrincipalKind::User,
        test_hash_for(0xD1),
        None,
        id_a.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_a_typed = record_a.token_hash().clone();

    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(identity_scope(tenant_a), record_a).await?;

    // tenant A 查自己 hash → 可以找到（anti-vacuity：record 确实存在）。
    let found_a = rt_store
        .find_by_hash(identity_scope(tenant_a), hash_a_typed.clone())
        .await?;
    assert!(found_a.is_some(), "rt4: tenant A 应能查到自己的 record");

    // tenant B 查 tenant A 的 hash → None（跨租 WHERE tenant_id 隔离，fail-closed）。
    let found_b = rt_store
        .find_by_hash(identity_scope(tenant_b), hash_a_typed)
        .await?;
    assert!(
        found_b.is_none(),
        "rt4: tenant B 不应查到 tenant A 的 record（跨租隔离）"
    );

    store.shutdown().await?;
    Ok(())
}

/// RT-5：nonexistent old_id → rotate CAS miss → Ok(false)，new 不写入。
///
/// sealed [`RefreshRotation`] 命令（`begin_rotation` 从源 record 派生）使跨租 rotate 在类型层不可表达
/// （REFRESH-ROTATE-LINEAGE-01）——直接 rotate 未入库的"幽灵" old_id 是 DB 层 CAS miss 的正规路径。
/// 验证：`do_rotate_tx` 在找不到匹配的 `(tenant_id, old_id, status=active)` 行时正确返回 false。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid / TenantId parse 是已知合法值；集成测试 happy-path；item-level carve-out。
async fn rt5_rotate_nonexistent_old_id_returns_false() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_500_000);
    let expires = issued + Duration::from_secs(3_600);

    // 构造"幽灵"源 record（从未入库）——begin_rotation 仍可调用，old_id 在 DB 中不存在。
    let phantom = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "ghost-subj",
        PrincipalKind::User,
        test_hash_for(0xE1),
        None,
        uuid::Uuid::new_v4().to_string(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    // 新 record 用于提取 RefreshTokenId / RefreshTokenHash 类型值（pub(crate) ctor 不可直接用）。
    let new_seed = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "ghost-subj",
        PrincipalKind::User,
        test_hash_for(0xE2),
        None,
        uuid::Uuid::new_v4().to_string(),
        RefreshStatus::Active,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let new_hash_typed = new_seed.token_hash().clone();

    // phantom 未插入 DB → CAS UPDATE 0 行 → rotate 返 false，new_seed 不写入。
    let rotation = phantom.begin_rotation(
        new_seed.id().clone(),
        new_seed.token_hash().clone(),
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let rt_store = PgRefreshTokenStore::new(&store);
    let result = rt_store.rotate(identity_scope(tenant), rotation).await?;
    assert!(
        !result,
        "rt5: 未入库 old_id → CAS miss → rotate 应返回 false"
    );

    // new_seed 也未被写入（CAS miss 不写 new）。
    let new_found = rt_store
        .find_by_hash(identity_scope(tenant), new_hash_typed)
        .await?;
    assert!(new_found.is_none(), "rt5: CAS miss 时 new 不应写入");

    store.shutdown().await?;
    Ok(())
}

/// RT-6：跨租 revoke_lineage no-op——tenant B 调用 → tenant A 的记录不被撤销。
///
/// 验证 `revoke_lineage` 的 SQL WHERE `tenant_id = $1` 保证跨租级联撤销为空操作（0 行受影响，仍 Ok）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 是已知合法值；集成测试 happy-path；item-level carve-out。
async fn rt6_revoke_lineage_cross_tenant_noop() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a_str = uuid::Uuid::new_v4().to_string();
    let tenant_b_str = uuid::Uuid::new_v4().to_string();
    let tenant_a = RtTenantId::parse(&tenant_a_str).unwrap();
    let tenant_b = RtTenantId::parse(&tenant_b_str).unwrap();

    let id_str = uuid::Uuid::new_v4().to_string();
    let lineage = id_str.clone();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_600_000);
    let expires = issued + Duration::from_secs(3_600);

    let record_a = RefreshTokenRecord::hydrate(
        id_str.clone(),
        tenant_a,
        "revoke-subj",
        PrincipalKind::User,
        test_hash_for(0xF1),
        None,
        lineage.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_a_typed = record_a.token_hash().clone();
    let lineage_id_typed = record_a.lineage_id().clone();

    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(identity_scope(tenant_a), record_a).await?;

    // tenant B 用 tenant A 的 lineage_id 调 revoke_lineage → WHERE tenant_id = B 不匹配 → no-op（0 行）
    rt_store
        .revoke_lineage(identity_scope(tenant_b), lineage_id_typed)
        .await?;

    // tenant A 的记录仍 Active（未被跨租撤销）
    let found_a = rt_store
        .find_by_hash(identity_scope(tenant_a), hash_a_typed)
        .await?
        .expect("rt6: tenant A record 仍可查到");
    assert_eq!(
        found_a.status(),
        RefreshStatus::Active,
        "rt6: 跨租 revoke_lineage no-op，tenant A 记录仍 Active"
    );

    store.shutdown().await?;
    Ok(())
}

/// RT-6b：`PgRefreshTokenStore` 接入 tenant no-op conformance。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn rt6b_refresh_token_store_tenant_noop_conformance() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a = RtTenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = RtTenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let id_str = uuid::Uuid::new_v4().to_string();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_650_000);
    let expires = issued + Duration::from_secs(3_600);
    let record_a = RefreshTokenRecord::hydrate(
        id_str.clone(),
        tenant_a,
        "refresh-conformance",
        PrincipalKind::User,
        test_hash_for(0xF6),
        None,
        id_str,
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_a = record_a.token_hash().clone();
    let lineage_a = record_a.lineage_id().clone();
    let rt_store = PgRefreshTokenStore::new(&store);

    testkit::repo_conformance::assert_cross_tenant_noop(
        || async {
            rt_store.insert(identity_scope(tenant_a), record_a).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                rt_store
                    .find_by_hash(identity_scope(tenant_a), hash_a.clone())
                    .await?
                    .is_some_and(|record| record.status() == RefreshStatus::Active),
            )
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                rt_store
                    .find_by_hash(identity_scope(tenant_b), hash_a.clone())
                    .await?
                    .is_some(),
            )
        },
        || async {
            rt_store
                .revoke_lineage(identity_scope(tenant_b), lineage_a.clone())
                .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                rt_store
                    .find_by_hash(identity_scope(tenant_a), hash_a.clone())
                    .await?
                    .is_some_and(|record| record.status() == RefreshStatus::Active),
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// RT-7：并发 rotate CAS fencing——两个 `PgRefreshTokenStore` 实例 `tokio::join!` 并发 rotate 同一 Active 记录。
///
/// 验证：恰一个 rotate 返回 `true`（CAS 命中），一个返回 `false`（miss）；
/// old 变 Consumed，new 恰一条（CAS miss 的 rotate 不写 new）。
/// INVARIANT：`UPDATE ... WHERE ... AND status = $4`（CAS）保证行级互斥（同 fosite `flow_refresh.go`）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 是已知合法值；集成测试并发验证；item-level carve-out。
async fn rt7_concurrent_rotate_cas_fencing() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();

    let old_id_str = uuid::Uuid::new_v4().to_string();
    let lineage = old_id_str.clone();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_700_000);
    let expires = issued + Duration::from_secs(3_600);

    // 插入一条 Active 记录
    let old_record = RefreshTokenRecord::hydrate(
        old_id_str.clone(),
        tenant,
        "concurrent-subj",
        PrincipalKind::User,
        test_hash_for(0xA7),
        None,
        lineage.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let old_hash_typed = old_record.token_hash().clone();
    // sealed command: clone 源 record 供 begin_rotation（两次并发各构造独立 RefreshRotation）。
    let old_for_rotate = old_record.clone();

    let rt_store1 = PgRefreshTokenStore::new(&store);
    rt_store1.insert(identity_scope(tenant), old_record).await?;

    // 两个不同 new record（不同 id + hash 避免 PK / unique 冲突；只有 CAS 命中的会被写入）
    let new_record_1 = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "concurrent-subj",
        PrincipalKind::User,
        test_hash_for(0xB7),
        Some(old_id_str.clone()),
        lineage.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let hash_new1 = new_record_1.token_hash().clone();

    let new_record_2 = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "concurrent-subj",
        PrincipalKind::User,
        test_hash_for(0xC7),
        Some(old_id_str.clone()),
        lineage.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );
    let hash_new2 = new_record_2.token_hash().clone();

    // 各自构造 RefreshRotation（begin_rotation 从同一源 record 派生，CAS key = old_for_rotate.id）。
    let rotation1 = old_for_rotate.begin_rotation(
        new_record_1.id().clone(),
        new_record_1.token_hash().clone(),
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let rotation2 = old_for_rotate.begin_rotation(
        new_record_2.id().clone(),
        new_record_2.token_hash().clone(),
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );

    // 共享 pool 的两个独立 store 实例：并发 rotate 同一 old_id
    let rt_store2 = PgRefreshTokenStore::new(&store);
    let (r1, r2) = tokio::join!(
        rt_store1.rotate(identity_scope(tenant), rotation1),
        rt_store2.rotate(identity_scope(tenant), rotation2),
    );

    let r1 = r1?;
    let r2 = r2?;

    // 恰一个 true（CAS 命中），一个 false（CAS miss）
    assert!(r1 || r2, "rt7: 至少一个 rotate 应成功（CAS 命中）");
    assert!(
        !(r1 && r2),
        "rt7: 两个 rotate 不能都成功（CAS fencing：同一 old_id 只能消费一次）"
    );

    // old 应已变 Consumed
    let old_found = rt_store1
        .find_by_hash(identity_scope(tenant), old_hash_typed)
        .await?
        .expect("rt7: old 仍可查到（status = consumed）");
    assert_eq!(
        old_found.status(),
        RefreshStatus::Consumed,
        "rt7: 并发 rotate CAS 命中后 old 应为 Consumed"
    );

    // new 恰一条（CAS miss 的 rotate 不写 new）
    let new1_found = rt_store1
        .find_by_hash(identity_scope(tenant), hash_new1)
        .await?;
    let new2_found = rt_store1
        .find_by_hash(identity_scope(tenant), hash_new2)
        .await?;
    let new_count = u32::from(new1_found.is_some()) + u32::from(new2_found.is_some());
    assert_eq!(
        new_count, 1,
        "rt7: new 应恰一条（CAS miss 的 rotate 不写 new）"
    );

    store.shutdown().await?;
    Ok(())
}

/// RT-8：rotate CAS 命中后 new insert 失败 → 整事务回滚，old 仍 Active，new 不存在。
///
/// 覆盖 `PgRefreshTokenStore::rotate` 的 `UPDATE old consumed` + `INSERT new` 同事务不变量：new 的
/// `expires_at` 故意超出 Postgres `timestamptz` 上界，触发 insert 失败；若 rollback 漏掉，old 会错误停在
/// Consumed。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 是已知合法值；集成测试 rollback 验证；item-level carve-out。
async fn rt8_refresh_token_rotate_rollback_conformance() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = RtTenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let old_id = uuid::Uuid::new_v4().to_string();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_800_000);
    let expires = issued + Duration::from_secs(3_600);
    let overflow_expires = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000_000_000);

    let old_record = RefreshTokenRecord::hydrate(
        old_id.clone(),
        tenant,
        "rollback-subj",
        PrincipalKind::User,
        test_hash_for(0xD8),
        None,
        old_id,
        RefreshStatus::Active,
        issued,
        expires,
    );
    let old_hash = old_record.token_hash().clone();
    let old_for_rotate = old_record.clone();

    let new_seed = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "rollback-subj",
        PrincipalKind::User,
        test_hash_for(0xE8),
        Some(old_for_rotate.id().as_str().to_string()),
        old_for_rotate.lineage_id().as_str().to_string(),
        RefreshStatus::Active,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let new_hash = new_seed.token_hash().clone();
    let rotation = old_for_rotate.begin_rotation(
        new_seed.id().clone(),
        new_seed.token_hash().clone(),
        issued + Duration::from_secs(1),
        overflow_expires,
    );

    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(identity_scope(tenant), old_record).await?;

    let result = rt_store.rotate(identity_scope(tenant), rotation).await;
    assert!(
        matches!(result, Err(identity::ports::IdentityError::Storage(_))),
        "rt8: new insert 失败应映射为 IdentityError::Storage"
    );

    let old_found = rt_store
        .find_by_hash(identity_scope(tenant), old_hash)
        .await?
        .expect("rt8: rollback 后 old 仍应可查");
    assert_eq!(
        old_found.status(),
        RefreshStatus::Active,
        "rt8: rotate 回滚后 old 必须保持 Active"
    );
    let new_found = rt_store
        .find_by_hash(identity_scope(tenant), new_hash)
        .await?;
    assert!(new_found.is_none(), "rt8: rotate 回滚后失败 new 不应写入");

    store.shutdown().await?;
    Ok(())
}

/// RT-9：`PgRefreshTokenStore` 接入 storage error conformance：底座关闭后 `find_by_hash` 映射为
/// `IdentityError::Storage`。
#[tokio::test(flavor = "multi_thread")]
async fn rt9_refresh_token_store_storage_error_conformance() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = RtTenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let record = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "storage-subj",
        PrincipalKind::User,
        test_hash_for(0xF9),
        None,
        uuid::Uuid::new_v4().to_string(),
        RefreshStatus::Active,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_900_000),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_903_600),
    );
    let hash = record.token_hash().clone();
    let rt_store = PgRefreshTokenStore::new(&store);

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async {
            rt_store
                .find_by_hash(identity_scope(tenant), hash)
                .await
                .map(|_| ())
        },
        |e| matches!(e, identity::ports::IdentityError::Storage(_)),
    )
    .await?;

    Ok(())
}

// ── F8：真实 DB liveness 采样集成验证 ─────────────────────────────────────────

/// t50：真实 DB 连接下 `probe_db_liveness` 返回 Ready。
///
/// 验证：`SELECT 1` 成功 → `PoolReadiness::Ready`（端到端 DB 可达性真实探针）。
#[tokio::test(flavor = "multi_thread")]
async fn probe_db_liveness_returns_ready_with_live_db() -> TestResult {
    use crate::pool::PoolReadiness;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let result = store.probe_db_liveness().await;
    assert_eq!(
        result,
        PoolReadiness::Ready,
        "t50: 真实 DB 连接下 probe_db_liveness 应返回 Ready"
    );

    store.shutdown().await?;
    Ok(())
}

/// t51：起 sampling loop 推进一 tick → health 反映 Ready。
///
/// 验证：`pg_readiness_sampling_loop` 在真实 DB 下一轮 tick 后
/// `PgDbReadiness::snapshot()` 返回 `PoolReadiness::Ready`。
#[tokio::test(flavor = "multi_thread")]
async fn sampling_loop_marks_ready_with_live_db() -> TestResult {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use crate::pool::PoolReadiness;
    use crate::readiness::{PgDbReadiness, pg_readiness_sampling_loop};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let store = Arc::new(store);
    let health = Arc::new(PgDbReadiness::new());
    let token = CancellationToken::new();

    // 短 period 确保首 tick 快速到来（集成测试真实时间，不 pause）。
    let handle = tokio::spawn(pg_readiness_sampling_loop(
        Arc::clone(&store),
        Duration::from_millis(50),
        token.clone(),
        Arc::clone(&health),
    ));

    // 等待至少一轮 tick 完成（period=50ms，sleep 300ms 留足余量）。
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        health.snapshot(),
        PoolReadiness::Ready,
        "t51: 真实 DB 一 tick 后 health 应为 Ready"
    );

    token.cancel();
    assert!(handle.await.is_ok(), "sampling loop 应正常退出");

    // reason: Arc<PgStore> 在此作用域末尾 drop；pool 关闭由 Arc drop 时触发，
    // 集成测试无需显式 shutdown Arc<PgStore>（与 Arc 所有权语义一致）。
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// PgCredentialRepo（identity 凭据仓储）集成测试（#1316）：find/save/upsert · authenticate 三态（含成功清锁）·
// 折叠锁定态原子 RMW（累计→锁→lazy-unlock 持久化）· bump_version CAS · 跨租 fail-closed · F2 未知主体不建行 ·
// information_schema 明文列断言（DoD）。
//
// 构造 `Credential` 经 `Credential::hydrate`（pub funnel + `secure::hash_password`）；`LoginIdentifier` 经
// `identity::test_support::login_identifier`（`pub(crate)` funnel 经 test-support feature 暴露，同
// `test_support::session` 范式）。锁定策略阈值（5 次 / 15min 窗口 / 15min TTL）域 `AccountLockout` 单源，
// adapter 仅 I/O；`now` 由测试直传（确定性，无需 Clock）。known/wrong/correct/lazy-unlock 行为镜像 in-mem
// `InMemCredentialRepo` 单测（crates/identity/src/internal/mem.rs），此处证 postgres provider 行为等价 + durable。
// ───────────────────────────────────────────────────────────────────────────

use identity::ports::{AuthOutcome, Credential, CredentialRepo, LoginIdentifier};

use crate::PgCredentialRepo;
use crate::credential_repo::{arm_credential_retry_failpoint, credential_retry_failpoint_hits};

const CRED_TENANT_A: &str = "a1a2a3a4-b1b2-4c3c-8d4d-e1e2e3e4e5e6";
const CRED_TENANT_B: &str = "b9b8b7b6-c5c4-4a3a-8f2f-d1d2d3d4d5d6";
const CRED_USER_ALICE: &str = "11111111-2222-4333-8444-555555555555";
const CRED_USER_BOB: &str = "22222222-3333-4444-8555-666666666666";
const CRED_USER_RETRY: &str = "33333333-4444-4555-8666-777777777777";
// 锁定 TTL（域 AccountLockout 单源镜像；仅供测试时间步进推算，非生产复刻）。
const LOCK_TTL_SECS: u64 = 15 * 60;
// 测试基准时刻（well-after-epoch，避开 unix_secs 的 epoch 前钳零边界）。
const CRED_BASE_SECS: u64 = 1_700_000_000;

type CredHelperResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn cred_tenant(raw: &str) -> CredHelperResult<TenantId> {
    Ok(TenantId::parse(raw)?)
}

fn cred_uid(raw: &str) -> CredHelperResult<ids::UserId> {
    Ok(ids::UserId::parse(raw)?)
}

// 登录查找键（经 test-support funnel；known 主体亦可 `cred.login().clone()`，未知主体仅经此入口）。
fn login_id(raw: &str) -> LoginIdentifier {
    identity::test_support::login_identifier(raw)
}

fn make_cred(
    login: &str,
    user: &str,
    password: &str,
    version: u32,
    tenant: TenantId,
) -> CredHelperResult<Credential> {
    let hash = secure::hash_password(password)?;
    Ok(Credential::hydrate(
        login,
        cred_uid(user)?,
        tenant,
        hash,
        version,
    ))
}

fn cred_epoch(secs: u64) -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

// 直查持久化 failure_count（断言锁定态原子推进 / 清零）。
async fn db_failure_count(store: &PgStore, tenant: &str, login: &str) -> CredHelperResult<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT failure_count FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant)
    .bind(login)
    .fetch_one(&store.pool)
    .await?;
    Ok(row.0)
}

// 直查持久化 locked_until epoch（NULL → None；断言 lazy-unlock 持久化解锁）。
async fn db_locked_until(
    store: &PgStore,
    tenant: &str,
    login: &str,
) -> CredHelperResult<Option<i64>> {
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT extract(epoch from locked_until)::bigint \
         FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant)
    .bind(login)
    .fetch_one(&store.pool)
    .await?;
    Ok(row.0)
}

// CRUD：未存 → None；save → find_by_user_id 往返一致（user_id/login/version + PHC 列形态）；同 login 二次 save
// → upsert 覆盖 version（非新增行）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_save_find_roundtrip_and_upsert() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;

    // 未保存 → None（fail-closed 基线，anti-vacuity 负例）。
    assert!(
        repo.find_by_user_id(identity_scope(tenant), cred_uid(CRED_USER_ALICE)?)
            .await?
            .is_none(),
        "未保存 → None"
    );

    // save → find_by_user_id 往返一致。
    repo.save(
        identity_scope(tenant),
        make_cred("alice", CRED_USER_ALICE, "pw1", 1, tenant)?,
    )
    .await?;
    let Some(got) = repo
        .find_by_user_id(identity_scope(tenant), cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("saved credential visible".into());
    };
    assert_eq!(
        got.user_id(),
        cred_uid(CRED_USER_ALICE)?,
        "canonical subject 保真"
    );
    assert_eq!(got.login().as_str(), "alice", "login 查找键保真");
    assert_eq!(got.version(), 1, "version 保真");
    assert!(
        got.password_hash().as_str().starts_with("$argon2"),
        "回读 PHC 为 argon2 格式（明文永不落库）"
    );

    // 同 login 二次 save → upsert 覆盖 version（DO UPDATE，非新增行）。
    repo.save(
        identity_scope(tenant),
        make_cred("alice", CRED_USER_ALICE, "pw2", 2, tenant)?,
    )
    .await?;
    let Some(got2) = repo
        .find_by_user_id(identity_scope(tenant), cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("upserted credential visible".into());
    };
    assert_eq!(got2.version(), 2, "upsert 覆盖 version");
    let n: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(CRED_TENANT_A)
    .bind("alice")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(n.0, 1, "upsert 不新增行");

    store.shutdown().await?;
    Ok(())
}

// authenticate 三态：已知+正确 → Authenticated(canonical user_id)；已知+错 → InvalidKnownUser；
// 查无凭据 → InvalidUnknown（恒定成本 KDF 仍跑，不 panic）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_known_wrong_and_unknown() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    repo.save(
        identity_scope(tenant),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?,
    )
    .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    assert_eq!(
        repo.authenticate(
            identity_scope(tenant),
            login_id("alice"),
            "correct".to_string(),
            now
        )
        .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?),
        "已知+正确 → Authenticated(canonical user_id)"
    );
    assert_eq!(
        repo.authenticate(
            identity_scope(tenant),
            login_id("alice"),
            "wrong".to_string(),
            now
        )
        .await?,
        AuthOutcome::InvalidKnownUser,
        "已知+错 → InvalidKnownUser"
    );
    assert_eq!(
        repo.authenticate(
            identity_scope(tenant),
            login_id("ghost"),
            "correct".to_string(),
            now
        )
        .await?,
        AuthOutcome::InvalidUnknown,
        "查无凭据 → InvalidUnknown"
    );

    store.shutdown().await?;
    Ok(())
}

// F2：未知主体登录失败**不建行 / 不建锁**——不可经枚举撑大 credentials 表（折叠列 ⇒ 无行即无锁，结构层成立）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_unknown_subject_creates_no_row() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    repo.save(
        identity_scope(tenant),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?,
    )
    .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    for i in 0..20 {
        assert_eq!(
            repo.authenticate(
                identity_scope(tenant),
                login_id(&format!("ghost-{i}")),
                "x".to_string(),
                now
            )
            .await?,
            AuthOutcome::InvalidUnknown
        );
    }
    // 仅 alice 一行（未知主体未建任何行 ⇒ lockout 表不随枚举增长，F2）。
    let n: (i64,) = sqlx::query_as("SELECT count(*) FROM credentials WHERE tenant_id = $1::uuid")
        .bind(CRED_TENANT_A)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(n.0, 1, "未知主体不建行（F2：lockout 表不随枚举增长）");

    store.shutdown().await?;
    Ok(())
}

// 跨租 fail-closed：A 种入 alice，B 视角 find → None / authenticate → InvalidUnknown / lockout_status → false
// （即使 A 已锁定 alice）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_cross_tenant_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    repo.save(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    // 跨租 find → None（不泄露存在性）。
    assert!(
        repo.find_by_user_id(identity_scope(b), cred_uid(CRED_USER_ALICE)?)
            .await?
            .is_none(),
        "跨租 find → None"
    );
    // 跨租 authenticate → InvalidUnknown（跨租即未知）。
    assert_eq!(
        repo.authenticate(
            identity_scope(b),
            login_id("alice"),
            "correct".to_string(),
            now
        )
        .await?,
        AuthOutcome::InvalidUnknown,
        "跨租 authenticate → InvalidUnknown"
    );
    // 在 A 锁定 alice（5 次错），B 视角 lockout_status 仍 false（隔离）。
    for i in 1..=5 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert!(
        repo.lockout_status(
            identity_scope(a),
            login_id("alice"),
            cred_epoch(CRED_BASE_SECS + 5)
        )
        .await?,
        "A 视角 alice 已锁"
    );
    assert!(
        !repo
            .lockout_status(
                identity_scope(b),
                login_id("alice"),
                cred_epoch(CRED_BASE_SECS + 5)
            )
            .await?,
        "B 视角不受 A 锁定影响（跨租隔离）"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_tenant_noop_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    let alice_uid = cred_uid(CRED_USER_ALICE)?;
    let now = cred_epoch(CRED_BASE_SECS);
    let credential = make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?;

    testkit::repo_conformance::assert_cross_tenant_noop(
        || async {
            repo.save(identity_scope(a), credential).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(identity_scope(a), alice_uid)
                    .await?
                    .is_some(),
            )
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(identity_scope(b), alice_uid)
                    .await?
                    .is_some(),
            )
        },
        || async {
            let outcome = repo
                .authenticate(
                    identity_scope(b),
                    login_id("alice"),
                    "correct".to_string(),
                    now,
                )
                .await?;
            if outcome == AuthOutcome::InvalidUnknown {
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            } else {
                Err(format!("cross-tenant authenticate returned {outcome:?}").into())
            }
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(identity_scope(a), alice_uid)
                    .await?
                    .is_some(),
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

// 原子推进：连续 authenticate(错) 经仓储持久化累计——未达阈值未锁，第 5 次（窗口内）达阈值锁定。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_accumulate_failures_then_locks() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    for i in 1..5 {
        assert_eq!(
            repo.authenticate(
                identity_scope(a),
                login_id("alice"),
                "wrong".to_string(),
                cred_epoch(CRED_BASE_SECS + i)
            )
            .await?,
            AuthOutcome::InvalidKnownUser,
            "第 {i} 次失败"
        );
        assert!(
            !repo
                .lockout_status(
                    identity_scope(a),
                    login_id("alice"),
                    cred_epoch(CRED_BASE_SECS + i)
                )
                .await?,
            "未达阈值仍未锁"
        );
    }
    // 第 5 次（窗口内）→ 达阈值锁定（DB 持久化失败计数 = 5）。
    repo.authenticate(
        identity_scope(a),
        login_id("alice"),
        "wrong".to_string(),
        cred_epoch(CRED_BASE_SECS + 5),
    )
    .await?;
    assert!(
        repo.lockout_status(
            identity_scope(a),
            login_id("alice"),
            cred_epoch(CRED_BASE_SECS + 5)
        )
        .await?,
        "第 5 次达阈值锁定"
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        5,
        "失败计数持久化推进至阈值"
    );

    store.shutdown().await?;
    Ok(())
}

// lazy-unlock：TTL 内仍锁；TTL 后 lockout_status 原子解锁（持久化清 locked_until）+ 计数从 1 重计。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_lockout_lazy_unlocks_after_ttl() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;
    for i in 1..=5 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    let lock_at = CRED_BASE_SECS + 5;

    // TTL 内仍锁。
    assert!(
        repo.lockout_status(
            identity_scope(a),
            login_id("alice"),
            cred_epoch(lock_at + LOCK_TTL_SECS - 1)
        )
        .await?,
        "TTL 内仍锁"
    );
    // TTL 后 lazy-unlock → false + 持久化清 locked_until。
    assert!(
        !repo
            .lockout_status(
                identity_scope(a),
                login_id("alice"),
                cred_epoch(lock_at + LOCK_TTL_SECS + 1)
            )
            .await?,
        "TTL 后 lazy-unlock 解锁"
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_none(),
        "lazy-unlock 持久化清 locked_until"
    );
    // 解锁后再失败从 1 重计（不沿用旧计数）→ InvalidKnownUser、未锁。
    let after = lock_at + LOCK_TTL_SECS + 2;
    assert_eq!(
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(after)
        )
        .await?,
        AuthOutcome::InvalidKnownUser
    );
    assert!(
        !repo
            .lockout_status(identity_scope(a), login_id("alice"), cred_epoch(after))
            .await?,
        "重计未达阈值未锁"
    );

    store.shutdown().await?;
    Ok(())
}

// 成功登录原子清零失败计数（authenticate 内折叠 clear——不需独立 clear 端口）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_success_clears_lockout() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    // 4 次错（未达阈值 5，未锁）→ 失败计数持久化 = 4。
    for i in 1..=4 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        4,
        "失败累积 4"
    );
    // 正确密码 → Authenticated + 原子清零失败计数。
    assert_eq!(
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            "correct".to_string(),
            cred_epoch(CRED_BASE_SECS + 5)
        )
        .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?)
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        0,
        "成功登录清零失败计数"
    );

    store.shutdown().await?;
    Ok(())
}

// bump_version CAS：期望不匹配 → VersionConflict；命中 → 替换 hash+version（authenticate 新密码真）；
// 查无 → CredentialNotFound；跨租（next 在 B）→ CredentialNotFound 且不动 A。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_bump_version_cas() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    repo.save(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "pw1", 1, a)?,
    )
    .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    // 期望版本不匹配 → VersionConflict。
    assert!(
        matches!(
            repo.bump_version(
                identity_scope(a),
                99,
                make_cred("alice", CRED_USER_ALICE, "pw2", 2, a)?
            )
            .await,
            Err(IdentityError::VersionConflict)
        ),
        "期望不匹配 → VersionConflict"
    );
    // 命中 → 替换 hash + version。
    repo.bump_version(
        identity_scope(a),
        1,
        make_cred("alice", CRED_USER_ALICE, "pw2", 2, a)?,
    )
    .await?;
    let Some(got) = repo
        .find_by_user_id(identity_scope(a), cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("credential visible after CAS hit".into());
    };
    assert_eq!(got.version(), 2, "CAS 命中后 version = 2");
    assert_eq!(
        repo.authenticate(identity_scope(a), login_id("alice"), "pw2".to_string(), now)
            .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?),
        "新密码验签真"
    );
    // 查无凭据 → CredentialNotFound。
    assert!(
        matches!(
            repo.bump_version(
                identity_scope(a),
                1,
                make_cred("ghost", CRED_USER_BOB, "x", 1, a)?
            )
            .await,
            Err(IdentityError::CredentialNotFound)
        ),
        "查无 → CredentialNotFound"
    );
    // 跨租 bump（next 在 B）→ CredentialNotFound（key 派生自 next，B 无行），不动 A。
    assert!(
        matches!(
            repo.bump_version(
                identity_scope(b),
                2,
                make_cred("alice", CRED_USER_ALICE, "pw3", 3, b)?
            )
            .await,
            Err(IdentityError::CredentialNotFound)
        ),
        "跨租 bump → CredentialNotFound"
    );
    let Some(still_a) = repo
        .find_by_user_id(identity_scope(a), cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("tenant A credential still present after cross-tenant bump".into());
    };
    assert_eq!(still_a.version(), 2, "跨租 bump 不动 A（仍 v2）");

    store.shutdown().await?;
    Ok(())
}

/// identity credential 的 Postgres retry 边界 conformance。
///
/// transient 用真实 tenant-scoped 事务更新 credentials：第一轮更新后返回 transient storage error，事务回滚；
/// 第二轮重建事务后提交。CAS conflict / permanent 走 production `bump_version`，证明不会盲目重试或提交副作用。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_retry_boundary_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let retry_uid = cred_uid(CRED_USER_RETRY)?;
    let bob_uid = cred_uid(CRED_USER_BOB)?;
    let transient_next = make_cred("retry-alice", CRED_USER_RETRY, "pw-transient", 2, tenant)?;
    let conflict_next = make_cred("retry-alice", CRED_USER_RETRY, "pw-conflict", 3, tenant)?;
    let ghost_next = make_cred("ghost", CRED_USER_BOB, "pw-ghost", 1, tenant)?;

    repo.save(
        identity_scope(tenant),
        make_cred("retry-alice", CRED_USER_RETRY, "pw1", 1, tenant)?,
    )
    .await?;

    testkit::repo_conformance::assert_retry_boundary_policy(
        testkit::repo_conformance::RetryBoundaryCase {
            transient_then_success: || {
                let repo = &repo;
                let transient_next = transient_next.clone();
                arm_credential_retry_failpoint("retry-alice", 1);
                async move {
                    repo.bump_version(identity_scope(tenant), 1, transient_next)
                        .await
                }
            },
            transient_attempts: credential_retry_failpoint_hits,
            expected_transient_attempts: 2,
            transient_visible: || async {
                let Some(got) = repo
                    .find_by_user_id(identity_scope(tenant), retry_uid)
                    .await?
                else {
                    return Ok::<bool, IdentityError>(false);
                };
                Ok::<bool, IdentityError>(
                    got.version() == 2 && credential_retry_failpoint_hits() == 2,
                )
            },
            conflict_action: || async {
                repo.bump_version(identity_scope(tenant), 99, conflict_next.clone())
                    .await
            },
            conflict_visible: || async {
                let Some(got) = repo
                    .find_by_user_id(identity_scope(tenant), retry_uid)
                    .await?
                else {
                    return Ok::<bool, IdentityError>(false);
                };
                Ok::<bool, IdentityError>(got.version() == 3)
            },
            permanent_action: || async {
                repo.bump_version(identity_scope(tenant), 1, ghost_next.clone())
                    .await
            },
            permanent_visible: || async {
                Ok::<bool, IdentityError>(
                    repo.find_by_user_id(identity_scope(tenant), bob_uid)
                        .await?
                        .is_some(),
                )
            },
        },
        |e| {
            matches!(
                classify_identity_error(e),
                consistency::TxRetryClass::Conflict
            )
        },
        |e| {
            matches!(
                classify_identity_error(e),
                consistency::TxRetryClass::Permanent
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// material-never-persisted 断言（DoD review-critical）：`information_schema.columns` 校验 credentials 列集
/// 恰为预期（含 `password_hash`，**无明文 `password` 列**）。
#[tokio::test(flavor = "multi_thread")]
async fn ts_credentials_no_plaintext_password_column() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name = 'credentials' AND table_schema = 'public' \
         ORDER BY column_name",
    )
    .fetch_all(&store.pool)
    .await?;
    let cols: Vec<&str> = rows.iter().map(|(s,)| s.as_str()).collect();

    let expected = [
        "created_at",
        "failure_count",
        "locked_until",
        "lockout_window_start",
        "login",
        "password_hash",
        "tenant_id",
        "user_id",
        "version",
    ];
    assert_eq!(
        cols, expected,
        "credentials 列集应恰为预期（仅 PHC，无明文密码列），实际：{cols:?}"
    );
    // 显式守 DoD：无明文 password 列，仅 argon2 PHC。
    assert!(
        !cols.contains(&"password"),
        "禁止明文 password 列（明文永不落库）"
    );
    assert!(cols.contains(&"password_hash"), "仅持久化 argon2 PHC 列");

    store.shutdown().await?;
    Ok(())
}

// 已锁定（达阈值，locked_until 持久化非 NULL）→ 正确密码 authenticate → Authenticated + 原子清锁。
// （authenticate 成功分支无视锁定态、只负责清锁；「已锁拒绝」由上层 lockout_status 门控承载，#1277）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_correct_clears_active_lock() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    // 5 次错 → 达阈值锁定（locked_until 持久化非 NULL）。
    for i in 1..=5 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_some(),
        "达阈值后 locked_until 持久化"
    );

    // 正确密码 → Authenticated + 原子清锁（locked_until + failure_count 持久化清零）。
    assert_eq!(
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            "correct".to_string(),
            cred_epoch(CRED_BASE_SECS + 6)
        )
        .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?)
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_none(),
        "成功登录清 locked_until（解锁持久化）"
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        0,
        "成功登录清 failure_count"
    );

    store.shutdown().await?;
    Ok(())
}

/// T24：RLS 强制力证明 — credentials 表（#1316，与 T20–T23 同范式补 credentials 表 DB 层隔离）。
///
/// 以 `SET LOCAL ROLE rss_app`（非 owner，superuser 永远绕过 RLS 不适合验证）+ tenant scope 切换，验证
/// `0012` 的 RLS policy 真实生效：tenant_a scope INSERT/SELECT 成功可见；切 tenant_b → 不可见（USING 过滤）；
/// tenant_a scope 写 tenant_b 行 → WITH CHECK 拒绝。
///
/// 注：不含「未设 rss.tenant_id → 0 行」子用例——`set_config(..,is_local=true)` 在 pool 复用连接上 tx 末 revert
/// 为 placeholder GUC 默认值 `''`（非 NULL），`''::uuid` 在 USING 谓词 raise（仍 fail-closed=不泄数据，但非「0 行」），
/// 该 unset-scope 行为依赖连接是否曾被 set（pool 不可控）⇒ 不在本测试断言（T20–T23 的同款 null-scope 子用例有相同
/// 连接态依赖，见 OOS issue）。核心 RLS 强制力由下列 4 步 USING/WITH CHECK 证明已足。
#[tokio::test(flavor = "multi_thread")]
async fn t24_rls_credentials_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let user_a = uuid::Uuid::new_v4().to_string();

    // Tx1：rss_app + tenant_a scope → INSERT tenant_a 凭据 → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
             VALUES ($1::uuid, $2::uuid, 'rls-alice', 'phc-placeholder', 1)",
        )
        .bind(&tenant_a)
        .bind(&user_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a credential failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM credentials WHERE login = 'rls-alice'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(cnt.0, 1, "t24: tenant_a scope — 凭据应可见（USING pass）");
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同行 → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM credentials WHERE login = 'rls-alice'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t24: tenant_b scope — 凭据应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b 凭据 → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
             VALUES ($1::uuid, $2::uuid, 'rls-bob', 'phc-placeholder', 1)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t24: WITH CHECK 应拒绝 tenant_b 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// DB CHECK 约束红用例（#1316 review F2）：0012 的域不变式 CHECK 拒非法行——version/failure_count 越 u32 界、
// 锁定态缺滑窗起点。证 domain `u32` 边界 + 锁定一致性已下沉为 DB 硬约束（坏迁移/外部直写不可绕）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_db_check_constraints_reject_invalid() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let t = CRED_TENANT_A;
    let u = CRED_USER_ALICE;

    // 正例基线（合法行 INSERT 成功 → 证下列拒绝非因其它列约束，anti-vacuity）。
    sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'ok', 'phc', 1)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await?;

    // 非法：version < 0 → credentials_version_u32 拒。
    let neg_ver = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'bad1', 'phc', -1)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(neg_ver.is_err(), "version < 0 应被 CHECK 拒");

    // 非法：version > u32::MAX（4294967296）→ credentials_version_u32 拒。
    let over_ver = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'bad2', 'phc', 4294967296)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(over_ver.is_err(), "version > u32::MAX 应被 CHECK 拒");

    // 非法：failure_count < 0 → credentials_failure_count_u32 拒。
    let neg_fc = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version, failure_count) \
         VALUES ($1::uuid, $2::uuid, 'bad3', 'phc', 1, -1)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(neg_fc.is_err(), "failure_count < 0 应被 CHECK 拒");

    // 非法：locked_until 非空但 lockout_window_start 为空 → credentials_lock_requires_window 拒。
    let lock_no_window = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version, locked_until) \
         VALUES ($1::uuid, $2::uuid, 'bad4', 'phc', 1, now())",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(
        lock_no_window.is_err(),
        "locked_until 非空但 lockout_window_start 为空应被 CHECK 拒"
    );

    store.shutdown().await?;
    Ok(())
}

// 并发行锁 RMW 红用例（#1316 review F1）：同 (tenant, login) 5 路并发 wrong-password authenticate——
// SELECT ... FOR UPDATE 串行化各事务 RMW，全部完成后失败计数恰 = 5（无丢更新）且达阈值锁定。
// 对标 role_repo_concurrent_save_converges（Arc<repo> + tokio::spawn 竞争同行）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_concurrent_failures_no_lost_update() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgCredentialRepo::new(&store));
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    // 5 路并发错密码（同一行）——同一 now，行锁强制串行 RMW（非各自读 stale 副本各 +1 丢更新）。
    let now = cred_epoch(CRED_BASE_SECS);
    let mut handles = Vec::new();
    for _ in 0..5 {
        let repo = Arc::clone(&repo);
        handles.push(tokio::spawn(async move {
            repo.authenticate(
                identity_scope(a),
                login_id("alice"),
                "wrong".to_string(),
                now,
            )
            .await
        }));
    }
    for h in handles {
        // 每路均应返回 InvalidKnownUser（已知主体 + 错），无 task panic / Storage 错。
        let outcome = h.await.map_err(|e| format!("join failed: {e}"))??;
        assert_eq!(
            outcome,
            AuthOutcome::InvalidKnownUser,
            "并发错密码各路 InvalidKnownUser"
        );
    }

    // 行锁串行化 ⇒ 失败计数恰 5（无丢更新）+ 达阈值锁定。
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        5,
        "5 路并发错密码 → 失败计数恰 5（FOR UPDATE 无丢更新）"
    );
    assert!(
        repo.lockout_status(identity_scope(a), login_id("alice"), now)
            .await?,
        "达阈值后锁定"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T24: RLS 强制力证明 — refresh_tokens 表（#1325 review #284 F5）──────────────────
//
// 0013 迁移落地 ENABLE + FORCE ROW LEVEL SECURITY + tenant_isolation policy（同 0009 范式）。
// 本测试以 SET LOCAL ROLE rss_app 切换到非 owner 角色，验证 RLS 对 refresh_tokens 生效。
//
// 测试结构（同 T20–T23 范式）：
//   • Tx1（rss_app + tenant_a scope）：INSERT tenant_a refresh_token → 成功（WITH CHECK pass）。
//   • Tx2（rss_app + tenant_a scope）：SELECT → tenant_a 行可见（USING pass）。
//   • Tx3（rss_app + tenant_b scope）：SELECT 同行 → 不可见（USING 过滤，跨租读被阻）。
//   • Tx4（rss_app + tenant_a scope）：INSERT tenant_b 行 → 错误（WITH CHECK 拒绝，跨租写被阻）。
//   • Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → 行不可见（fail-closed）。

/// T24：RLS 强制力证明 — refresh_tokens 表（#1325 review #284 F5）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝；未设 rss.tenant_id → fail-closed（0 行）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t24_rls_refresh_tokens_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等（已是 member 则 no-op）。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let token_id_a = uuid::Uuid::new_v4().to_string();
    let lineage_id_a = uuid::Uuid::new_v4().to_string();
    // SHA-256 固定 32 字节（满足 CHECK octet_length = 32）。
    let hash_a = vec![0xABu8; 32];

    // Tx1：rss_app + tenant_a scope → INSERT refresh_token → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (id, tenant_id, subject, kind, token_hash, lineage_id, status, issued_at, expires_at) \
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, 'active', now(), now() + interval '1 hour')",
        )
        .bind(&token_id_a)
        .bind(&tenant_a)
        .bind("rls-test-subject")
        .bind("user")
        .bind(&hash_a)
        .bind(&lineage_id_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a refresh_token failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT token_id_a → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE id = $1::uuid")
            .bind(&token_id_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 1,
            "t24: rss_app + tenant_a scope — refresh_token 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT token_id_a → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE id = $1::uuid")
            .bind(&token_id_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t24: rss_app + tenant_b scope — tenant_a refresh_token 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b refresh_token → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cross_hash = vec![0xCDu8; 32];
        let result = sqlx::query(
            "INSERT INTO refresh_tokens \
             (id, tenant_id, subject, kind, token_hash, lineage_id, status, issued_at, expires_at) \
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, 'active', now(), now() + interval '1 hour')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind("rls-test-subject")
        .bind("user")
        .bind(&cross_hash)
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t24: WITH CHECK 应拒绝 tenant_b refresh_token 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT refresh_tokens → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE id = $1::uuid")
            .bind(&token_id_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t24: rss_app + 未設 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// ── audit_entries 集成测试 ────────────────────────────────────────────────────
//
// TA1:  genesis + 单调递增 seq
// TA2:  prev_hash 链接前驱 entry_hash
// TA3:  并发 append——no seq gap/dup（advisory lock 串行）
// TA4:  租户隔离——两租户独立 genesis
// TA5:  RLS 跨租读隔离（rss_app + tenant_b scope → 0 行）
// TA6:  list 分页游标 + has_more（5 条 ÷ page=2 → 3 页）
// TA7:  list InvalidCursor fail-closed（base64url 合法但语义无效）
// TA8:  verify_tail 增量：小窗口不覆盖被篡改 genesis → Ok；大窗口 → HashMismatch
// TA9:  recorded_at 非零 nanos 往返（regression for secs+nanos 两列设计）
// TA10: append-only——rss_app DELETE/UPDATE 被 DB 权限拒绝
// TA11: RLS NULL tenant fail-closed——未设 rss.tenant_id → 0 行
// TA12: 空租户链 list + verify_tail 均 Ok

// read/write/admin traits 须在 scope 才能调用 append / list / verify_tail / verify_tenant 方法。
use audit::ports::{AuditAdminRepo as _, AuditReadRepo as _, AuditWriteRepo as _};
// base64::Engine::encode 须在 scope（URL_SAFE_NO_PAD.encode(...)）。
use base64::Engine as _;

/// 构造审计仓储（共享 pool，固定 0x5a key hasher）。
fn make_audit_repo(
    store: &PgStore,
) -> crate::PgAuditRepo<crate::audit_repo::test_support::TestVerifier> {
    crate::PgAuditRepo::new(store, crate::audit_repo::test_support::test_hasher(0x5a))
}

/// 构造 audit admin 只读仓储（固定 0x5a key hasher）。
fn make_audit_admin_repo(
    store: &PgStore,
) -> crate::PgAuditAdminRepo<crate::audit_repo::test_support::TestVerifier> {
    crate::PgAuditAdminRepo::new(store, crate::audit_repo::test_support::test_hasher(0x5a))
}

/// 构造审计记录（nanos 可变，其余字段固定；actor UUID 硬编码确定性 ID）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 helper——固定格式 UUID / action parse 不失败；item-level carve-out。
fn make_audit_record(tenant: vocab::TenantId, nanos: u32) -> audit::ports::AuditRecord {
    use std::time::{Duration, UNIX_EPOCH};
    audit::ports::AuditRecord {
        tenant,
        actor: ids::UserId::parse("11111111-2222-4333-8444-555555555555").unwrap(),
        actor_kind: vocab::PrincipalKind::User,
        action: vocab::Action::parse("audit:read").unwrap(),
        resource: audit::ports::ResourceRef::new("session", "sess-1"),
        outcome: audit::ports::AuditOutcome::Success,
        recorded_at: UNIX_EPOCH + Duration::new(1_700_000_000, nanos),
    }
}

/// 构造分页请求（limit ≤ 500 不失败）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 helper——limit 值由测试代码控制，均合法；item-level carve-out。
fn audit_page(limit: u16, cursor: Option<vocab::Cursor>) -> audit::ports::AuditPage {
    audit::ports::AuditPage {
        limit: vocab::Limit::new(limit).unwrap(),
        cursor,
    }
}

/// 独立 read/write dyn capability 从同一个 provider 派生后必须观察同一 durable 链状态。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration happy-path uses generated UUIDs and fixed valid test values.
async fn audit_dyn_read_write_wrappers_share_postgres_provider() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let provider = Arc::new(make_audit_repo(&store));
    let write: Arc<audit::ports::DynAuditWriteRepo<'static>> = Arc::from(
        audit::ports::DynAuditWriteRepo::new_box(Arc::clone(&provider)),
    );
    let read: Arc<audit::ports::DynAuditReadRepo<'static>> =
        Arc::from(audit::ports::DynAuditReadRepo::new_box(provider));

    write
        .append(audit_scope(tenant), make_audit_record(tenant, 7))
        .await?;
    let result = read
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].tenant(), tenant);
    read.verify_tail(audit_scope(tenant), 1).await?;

    store.shutdown().await?;
    Ok(())
}

/// TA1: genesis 条目 seq=0，连续 append seq 单调递增。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——UUID v4 生成不失败；item-level carve-out。
async fn ta1_audit_append_genesis_and_monotonic_seq() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    let result = repo
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    assert_eq!(result.entries.len(), 3, "TA1: 应恰有 3 条");
    assert_eq!(result.entries[0].seq(), 0, "TA1: genesis seq=0");
    assert_eq!(result.entries[1].seq(), 1, "TA1: seq 单调+1");
    assert_eq!(result.entries[2].seq(), 2, "TA1: seq 单调+2");
    assert!(!result.has_more);
    assert!(result.next_cursor.is_none());

    store.shutdown().await?;
    Ok(())
}

/// TA2: 每条 prev_hash == 前一条 entry_hash，genesis prev 全零。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta2_audit_prev_links_to_predecessor_entry_hash() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..3 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    let result = repo
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    let e = &result.entries;

    assert_eq!(
        e[0].prev_hash().as_bytes(),
        &[0u8; 32],
        "TA2: genesis prev 须全零"
    );
    assert_eq!(
        e[1].prev_hash().as_bytes(),
        e[0].entry_hash().as_bytes(),
        "TA2: e[1].prev_hash 须 == e[0].entry_hash"
    );
    assert_eq!(
        e[2].prev_hash().as_bytes(),
        e[1].entry_hash().as_bytes(),
        "TA2: e[2].prev_hash 须 == e[1].entry_hash"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA3: 同租户并发 append（5 task）——advisory lock 保证 no seq gap / dup。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta3_audit_concurrent_appends_no_seq_gap() -> TestResult {
    use std::sync::Arc;
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = Arc::new(make_audit_repo(&store));

    const N: usize = 5;
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let r = Arc::clone(&repo);
            tokio::spawn(async move {
                r.append(audit_scope(tenant), make_audit_record(tenant, 0))
                    .await
            })
        })
        .collect();
    for h in handles {
        h.await.map_err(|e| format!("join error: {e}"))??;
    }

    let result = repo
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    assert_eq!(result.entries.len(), N, "TA3: 应恰有 {N} 条");
    let mut seqs: Vec<u64> = result.entries.iter().map(|e| e.seq()).collect();
    seqs.sort_unstable();
    for (i, &s) in seqs.iter().enumerate() {
        assert_eq!(s, i as u64, "TA3: seq 须连续无 gap，i={i} s={s}");
    }

    store.shutdown().await?;
    Ok(())
}

/// TA4: 两租户独立 genesis（seq 各从 0 起），互不干扰。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta4_audit_tenant_isolation_independent_genesis() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;
    repo.append(audit_scope(tenant_b), make_audit_record(tenant_b, 0))
        .await?;

    let a = repo
        .list(audit_scope(tenant_a), audit_page(500, None))
        .await?;
    let b = repo
        .list(audit_scope(tenant_b), audit_page(500, None))
        .await?;
    assert_eq!(a.entries.len(), 2, "TA4: tenant_a 应有 2 条");
    assert_eq!(b.entries.len(), 1, "TA4: tenant_b 应有 1 条");
    assert_eq!(a.entries[0].seq(), 0, "TA4: tenant_a genesis seq=0");
    assert_eq!(b.entries[0].seq(), 0, "TA4: tenant_b 独立 genesis seq=0");

    store.shutdown().await?;
    Ok(())
}

/// TA4b：`PgAuditRepo` 接入统一 tenant conformance。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta4b_audit_tenant_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let repo = &repo;
            async move {
                repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
                    .await
            }
        },
        |tenant| {
            let repo = &repo;
            async move {
                repo.list(audit_scope(tenant), audit_page(500, None))
                    .await
                    .map(|page| !page.entries.is_empty())
            }
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// TA4c：audit record tenant 与 repo scope tenant 不一致 → fail-closed，audit row 不落库。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta4c_audit_rejects_scope_record_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let scope_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let record_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let result = repo
        .append(
            audit_scope(scope_tenant),
            make_audit_record(record_tenant, 0),
        )
        .await;
    assert!(
        result.is_err(),
        "audit scope/record mismatch must fail closed"
    );

    let cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM audit_entries WHERE tenant_id = $1::uuid")
            .bind(record_tenant.to_string())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cnt.0, 0, "scope mismatch 不得写 audit_entries 行");

    store.shutdown().await?;
    Ok(())
}

/// TA5: RLS 跨租读隔离——rss_app + tenant_b scope 下看不到 tenant_a 的审计行。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta5_audit_rls_cross_tenant_read_denied() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a_str = uuid::Uuid::new_v4().to_string();
    let tenant_a = vocab::TenantId::parse(&tenant_a_str).unwrap();
    let tenant_b_str = uuid::Uuid::new_v4().to_string();

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b_str)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM audit_entries WHERE tenant_id = $1::uuid")
                .bind(&tenant_a_str)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "TA5: rss_app + tenant_b scope — tenant_a 行须不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA6: list 分页游标——5 条, page=2 → 3 页（2+2+1），has_more 正确，cursor 续页完整。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta6_audit_list_pagination_cursor_and_has_more() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..5 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    let p1 = repo.list(audit_scope(tenant), audit_page(2, None)).await?;
    assert_eq!(p1.entries.len(), 2, "TA6: p1 应有 2 条");
    assert!(p1.has_more, "TA6: p1 has_more=true");
    assert!(p1.next_cursor.is_some(), "TA6: p1 应有 next_cursor");
    assert_eq!(p1.entries[0].seq(), 0);
    assert_eq!(p1.entries[1].seq(), 1);

    let p2 = repo
        .list(audit_scope(tenant), audit_page(2, p1.next_cursor))
        .await?;
    assert_eq!(p2.entries.len(), 2, "TA6: p2 应有 2 条");
    assert!(p2.has_more, "TA6: p2 has_more=true");
    assert_eq!(p2.entries[0].seq(), 2);
    assert_eq!(p2.entries[1].seq(), 3);

    let p3 = repo
        .list(audit_scope(tenant), audit_page(2, p2.next_cursor))
        .await?;
    assert_eq!(p3.entries.len(), 1, "TA6: p3 应有 1 条");
    assert!(!p3.has_more, "TA6: p3 has_more=false");
    assert!(p3.next_cursor.is_none(), "TA6: p3 无 next_cursor");
    assert_eq!(p3.entries[0].seq(), 4);

    store.shutdown().await?;
    Ok(())
}

/// TA7: list 语义无效游标（base64url 合法但解码后非数字）→ InvalidCursor（fail-closed）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta7_audit_list_invalid_cursor_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
    let cursor = vocab::Cursor::parse(&raw).unwrap();
    let result = repo
        .list(audit_scope(tenant), audit_page(10, Some(cursor)))
        .await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::InvalidCursor)),
        "TA7: 语义无效游标须返回 InvalidCursor"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA8: verify_tail 增量性——篡改 genesis 后，小窗口（不覆盖 seq=0）Ok；大窗口 → HashMismatch。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta8_audit_verify_tail_incremental_and_tamper_detection() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..5 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    // 干净链：verify_tail 均通过。
    repo.verify_tail(audit_scope(tenant), 2).await?;
    repo.verify_tail(audit_scope(tenant), 10).await?;

    // 超级用户篡改 seq=0 的 entry_hash（rss_app 无 UPDATE 权）。
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xAAu8; 32])
        .bind(&tenant_str)
        .execute(&store.pool)
        .await?;

    // 小窗口（末 2 条 = seq 3,4 + 前驱 seq 2）：不覆盖被篡改 seq 0 → 增量验证仍 Ok。
    let tail2 = repo.verify_tail(audit_scope(tenant), 2).await;
    assert!(
        tail2.is_ok(),
        "TA8: 小窗口不覆盖被篡改 genesis → verify_tail(2) 须 Ok，got: {tail2:?}"
    );

    // 大窗口（全 5 条 seq 0-4）：覆盖被篡改 seq 0 → HashMismatch。
    let tail10 = repo.verify_tail(audit_scope(tenant), 10).await;
    assert!(
        matches!(tail10, Err(audit::ports::AuditError::HashMismatch)),
        "TA8: 大窗口覆盖被篡改 genesis → HashMismatch，got: {tail10:?}"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA9: recorded_at 非零 nanos 往返——存储+读取后 nanos 精确保留，且链哈希仍验证通过。
///
/// Regression: 若用 timestamptz 存储则 nanos 被截断 → 重算 entry_hash 不匹配。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试——recorded_at 由 UNIX_EPOCH+Duration 构造，duration_since(UNIX_EPOCH) 不失败；item-level carve-out。
async fn ta9_audit_recorded_at_nanos_roundtrip_and_chain_verifies() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let nanos_input: u32 = 123_456_789;
    repo.append(audit_scope(tenant), make_audit_record(tenant, nanos_input))
        .await?;

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await?;
    assert_eq!(result.entries.len(), 1, "TA9: 应恰有 1 条");

    let e = &result.entries[0];
    let since_epoch = e
        .recorded_at()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("recorded_at >= UNIX_EPOCH");
    assert_eq!(
        since_epoch.subsec_nanos(),
        nanos_input,
        "TA9: nanos 须精确往返（secs+nanos 两列，非 timestamptz）"
    );

    // list 内置增量验证；额外 verify_tail 确认链完整。
    repo.verify_tail(audit_scope(tenant), 10).await?;

    store.shutdown().await?;
    Ok(())
}

/// TA10: append-only——rss_app 对 audit_entries 的 DELETE / UPDATE 被 DB 权限拒绝。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta10_audit_append_only_delete_update_rejected_for_rss_app() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    // rss_app DELETE → permission denied。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let del = sqlx::query("DELETE FROM audit_entries WHERE tenant_id = $1::uuid")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await;
        assert!(
            del.is_err(),
            "TA10: rss_app 应无 DELETE 权限（append-only）"
        );
        tx.rollback().await?;
    }

    // rss_app UPDATE → permission denied。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let upd = sqlx::query(
            "UPDATE audit_entries SET action = 'tampered:value' WHERE tenant_id = $1::uuid",
        )
        .bind(&tenant_str)
        .execute(&mut *tx)
        .await;
        assert!(
            upd.is_err(),
            "TA10: rss_app 应无 UPDATE 权限（append-only）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA11: RLS NULL tenant fail-closed——rss_app 未设 rss.tenant_id → current_setting NULL → 0 行。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta11_audit_rls_null_tenant_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 故意不设 rss.tenant_id → current_setting 返 NULL → RLS USING 全过滤。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_entries")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "TA11: rss_app + 未设 rss.tenant_id → NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA12: 空租户链 list → Ok（空结果），verify_tail → Ok（空链无前驱）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta12_audit_empty_tenant_list_and_verify_tail_ok() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await?;
    assert!(result.entries.is_empty(), "TA12: 空租户 list 须空");
    assert!(!result.has_more);

    repo.verify_tail(audit_scope(tenant), 10).await?;

    store.shutdown().await?;
    Ok(())
}

/// TA15: audit admin full-chain verify 从 genesis 扫到尾，返回已验证条目数。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta15_audit_admin_verify_tenant_clean_chain_success() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);
    for _ in 0..5 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    let admin_repo = make_audit_admin_repo(&audit_admin);
    let report = admin_repo
        .verify_tenant(tenant, vocab::Limit::new(2).unwrap())
        .await?;

    assert_eq!(report.tenant, tenant);
    assert_eq!(report.checked_entries, 5);
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// TA16: audit admin verify 的 tenant scope 精确隔离，A/B 只验证各自链。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta16_audit_admin_verify_tenant_ab_isolation() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;
    repo.append(audit_scope(tenant_b), make_audit_record(tenant_b, 0))
        .await?;

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    let admin_repo = make_audit_admin_repo(&audit_admin);
    let a = admin_repo
        .verify_tenant(tenant_a, vocab::Limit::new(1).unwrap())
        .await?;
    let b = admin_repo
        .verify_tenant(tenant_b, vocab::Limit::new(1).unwrap())
        .await?;

    assert_eq!(a.checked_entries, 2, "tenant A chain only");
    assert_eq!(b.checked_entries, 1, "tenant B chain only");
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// TA17: audit admin full-chain verify 覆盖 tail-verify 漏洞：genesis 篡改与 seq gap 都 fail-closed。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta17_audit_admin_verify_tenant_tamper_and_seq_gap_fail() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tampered_tenant_str = uuid::Uuid::new_v4().to_string();
    let tampered_tenant = vocab::TenantId::parse(&tampered_tenant_str).unwrap();
    let gap_tenant_str = uuid::Uuid::new_v4().to_string();
    let gap_tenant = vocab::TenantId::parse(&gap_tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    for _ in 0..5 {
        repo.append(
            audit_scope(tampered_tenant),
            make_audit_record(tampered_tenant, 0),
        )
        .await?;
        repo.append(audit_scope(gap_tenant), make_audit_record(gap_tenant, 0))
            .await?;
    }
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xAAu8; 32])
        .bind(&tampered_tenant_str)
        .execute(&store.pool)
        .await?;
    sqlx::query("DELETE FROM audit_entries WHERE tenant_id = $1::uuid AND seq = 2")
        .bind(&gap_tenant_str)
        .execute(&store.pool)
        .await?;

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    let admin_repo = make_audit_admin_repo(&audit_admin);
    let tampered = admin_repo
        .verify_tenant(tampered_tenant, vocab::Limit::new(2).unwrap())
        .await;
    let gap = admin_repo
        .verify_tenant(gap_tenant, vocab::Limit::new(2).unwrap())
        .await;

    assert!(
        matches!(tampered, Err(audit::ports::AuditError::HashMismatch)),
        "tampered genesis must fail full-chain verify, got: {tampered:?}"
    );
    assert!(
        matches!(gap, Err(audit::ports::AuditError::SequenceGap)),
        "deleted seq must fail full-chain verify, got: {gap:?}"
    );
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// TA18: rss_audit_admin 是 verify/read-only capability，不得拥有 INSERT/UPDATE/DELETE。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta18_audit_admin_role_dml_is_rejected() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    {
        let mut tx = audit_admin.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let update = sqlx::query(
            "UPDATE audit_entries SET action = 'tampered:value' WHERE tenant_id = $1::uuid",
        )
        .bind(&tenant_str)
        .execute(&mut *tx)
        .await;
        assert!(
            update.is_err(),
            "rss_audit_admin must not UPDATE audit_entries"
        );
        tx.rollback().await.ok();
    }
    {
        let mut tx = audit_admin.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let delete = sqlx::query("DELETE FROM audit_entries WHERE tenant_id = $1::uuid")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await;
        assert!(
            delete.is_err(),
            "rss_audit_admin must not DELETE audit_entries"
        );
        tx.rollback().await.ok();
    }
    {
        let mut tx = audit_admin.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let insert = sqlx::query(
            "INSERT INTO audit_entries \
             (tenant_id, seq, prev_hash, entry_hash, actor, actor_kind, action, resource_kind, resource_id, outcome, recorded_at_secs, recorded_at_nanos) \
             VALUES ($1::uuid, 99, $2, $2, $3::uuid, 'user', 'audit:read', 'session', 'sess-1', 'success', 0, 0)",
        )
        .bind(&tenant_str)
        .bind(vec![0u8; 32])
        .bind("11111111-2222-4333-8444-555555555555")
        .execute(&mut *tx)
        .await;
        assert!(
            insert.is_err(),
            "rss_audit_admin must not INSERT audit_entries"
        );
        tx.rollback().await.ok();
    }

    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

// ── TA13–TA14: hydrate_row 错误臂覆盖 ─────────────────────────────────────────
//
// TA13: entry_hash 错误字节长度（bypasss CHECK 约束后注入短 bytea）→ list 返回 AuditError::Storage
// TA14: 未知 actor_kind（bypass CHECK 约束后注入不在闭值集中的文本）→ list 返回 AuditError::Storage
//
// 以 superuser（store.pool 默认连接角色）DROP IF EXISTS 临时删除列级 CHECK 约束，UPDATE 注入非法值，
// 再通过 repo.list 触发 hydrate_row 的错误臂——复用 TA8 的超级用户篡改模式（FORCE RLS 对 owner 也生效，
// 但 store.pool 是 superuser，superuser 绕过 RLS、能执行 DDL）。
// compile-check only（无 docker）：断言结构正确、类型正确；运行期约束名须与 PostgreSQL 自动生成名匹配。

/// TA13: hydrate_row wrong-length entry_hash — 超级用户临时删 CHECK 约束后注入短 bytea，
/// list 读取时 try_into 失败 → `Err(AuditError::Storage(...))`（bytea-length arm 覆盖）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造——UUID v4 + audit_page 参数已知合法；item-level carve-out。
async fn ta13_audit_hydrate_row_wrong_length_entry_hash_returns_storage() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    // 超级用户临时删 entry_hash 长度 CHECK 约束（PostgreSQL 自动命名 audit_entries_entry_hash_check），
    // 注入错误长度 bytea（10B ≠ 32B）以覆盖 hydrate_row wrong-length arm。
    sqlx::query(
        "ALTER TABLE audit_entries DROP CONSTRAINT IF EXISTS audit_entries_entry_hash_check",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xBBu8; 10]) // 10B != 32B，触发 hydrate_row try_into 失败臂
        .bind(&tenant_str)
        .execute(&store.pool)
        .await?;

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::Storage(_))),
        "TA13: 错误长度 entry_hash 须返回 AuditError::Storage（实际为 Ok 或其它 Err 变体）"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA14: hydrate_row unknown actor_kind — 超级用户临时删 CHECK 约束后注入闭值集外文本，
/// list 读取时 actor_kind_from_db 返回 None → `Err(AuditError::Storage(...))`（unknown-enum arm 覆盖）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造——UUID v4 + audit_page 参数已知合法；item-level carve-out。
async fn ta14_audit_hydrate_row_unknown_actor_kind_returns_storage() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    // 超级用户临时删 actor_kind IN 值集 CHECK 约束（PostgreSQL 自动命名 audit_entries_actor_kind_check），
    // 注入闭值集外的 actor_kind 文本以覆盖 hydrate_row actor_kind_from_db → None 的错误臂。
    sqlx::query(
        "ALTER TABLE audit_entries DROP CONSTRAINT IF EXISTS audit_entries_actor_kind_check",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE audit_entries SET actor_kind = 'robot' WHERE tenant_id = $1::uuid AND seq = 0",
    )
    .bind(&tenant_str)
    .execute(&store.pool)
    .await?;

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::Storage(_))),
        "TA14: 未知 actor_kind 须返回 AuditError::Storage（实际为 Ok 或其它 Err 变体）"
    );

    store.shutdown().await?;
    Ok(())
}
