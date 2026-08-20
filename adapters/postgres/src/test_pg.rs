//! crate-internal 共享 postgres 测试连接单源（`integration` feature + test 门控）。
//!
//! 所有集成测试须经此模块取连接，**不得**在各测试模块内自行重复 `config_from_env` / `connect_pg` 逻辑。
//! 严格库名校验已在 `testkit::env_or_postgres` 单源执行，此处不重复。

use std::time::Duration;

use crate::pool::PgTenantReadConfig;
use crate::{PgConfig, PgPassword, PgStore};
use testkit::{OwnedPgFixture, PgAppRoleSpec};

const RSS_APP_ROLE: &str = "rss_app";
const RSS_APP_PASSWORD: &str = "rss_app_test_pw";
const RSS_APP_READ_ROLE: &str = "rss_app_read";
const RSS_APP_READ_PASSWORD: &str = "rss_app_read_test_pw";
const RSS_AUDIT_ADMIN_ROLE: &str = "rss_audit_admin";
const RSS_AUDIT_ADMIN_PASSWORD: &str = "rss_audit_admin_test_pw";

/// Starts a fixture-owned PostgreSQL container and connects its owner store.
///
/// 回传 `(OwnedPgFixture, PgStore)`；**调用方须绑定 fixture 到测试结束**（其 `Drop` 停容器）。
/// 显式 external opt-in 会在任何 SQL 前返回 `OwnedPostgresRequired`；连接配置使用 TLS `Prefer`，
/// acquire timeout 为 5 秒。
pub(crate) async fn connect_pg()
-> Result<(OwnedPgFixture, PgStore), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::owned_postgres().await?;
    let p = fixture.owner_params();
    let config = PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    // 本地无 TLS docker postgres：显式降级（默认 VerifyFull 对未启 TLS 的 docker pg 连不上）。
    .with_acquire_timeout(Duration::from_secs(5));
    let store = PgStore::connect(&config).await?;
    Ok((fixture, store))
}

/// 在已连接的（owner/superuser）`store` 上创建一个 NOBYPASSRLS LOGIN 角色，并以该角色连一个新 `PgStore`。
///
/// 供 RLS 能力门「非 rss_app 角色仍被拒」负例测试用。serving 连接必须是固定 `rss_app`，其它 non-bypass
/// role 也不得通过 bootstrap gate。
/// 角色名 / 口令为测试固定字面量；角色生命周期完全委托 fixture-owned resolver。
/// 该角色不授任何表 DML——能力门只读 `pg_catalog` / `pg_policies` + set GUC，无需表权限（pg_catalog 不受权限过滤）。
pub(crate) async fn connect_pg_nobypass_role(
    fixture: &OwnedPgFixture,
    _store: &PgStore,
) -> Result<PgStore, Box<dyn std::error::Error + Send + Sync>> {
    const ROLE: &str = "rss_rls_test_app";
    const PW: &str = "rls_test_pw";
    let [role] = fixture
        .resolve_app_roles([PgAppRoleSpec::new(ROLE, PW)])
        .await?;
    let p = role.params();
    let config = PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_acquire_timeout(Duration::from_secs(5));
    Ok(PgStore::connect(&config).await?)
}

/// 将迁移 provision 的 `rss_app` 临时打开 LOGIN，并以真实 serving role 建连接。
///
/// 生产 LOGIN/password 仍由部署 out-of-band 管理；集成测试只在测试 DB 内设置固定密码，直证 bootstrap
/// serving pool 使用 `current_user = rss_app`。
pub(crate) async fn connect_pg_rss_app_role(
    fixture: &OwnedPgFixture,
    store: &PgStore,
) -> Result<PgStore, Box<dyn std::error::Error + Send + Sync>> {
    connect_pg_rss_app_role_with_limits(fixture, store, 10, Duration::from_secs(5)).await
}

/// Build a real `rss_app` pool with deterministic limits for transaction-begin fault tests.
pub(crate) async fn connect_pg_rss_app_role_with_limits(
    fixture: &OwnedPgFixture,
    _store: &PgStore,
    max_connections: u32,
    acquire_timeout: Duration,
) -> Result<PgStore, Box<dyn std::error::Error + Send + Sync>> {
    let [role] = fixture
        .resolve_app_roles([PgAppRoleSpec::new(RSS_APP_ROLE, RSS_APP_PASSWORD)])
        .await?;
    let p = role.params();
    let config = PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_max_connections(max_connections)
    .with_acquire_timeout(acquire_timeout);
    Ok(PgStore::connect(&config).await?)
}

/// Configure the migration-provisioned tenant reader with a test-only password and return its
/// strongly typed runtime configuration.
pub(crate) async fn rss_app_read_config(
    fixture: &OwnedPgFixture,
    _store: &PgStore,
) -> Result<PgTenantReadConfig, Box<dyn std::error::Error + Send + Sync>> {
    let [role] = fixture
        .resolve_app_roles([PgAppRoleSpec::new(RSS_APP_READ_ROLE, RSS_APP_READ_PASSWORD)])
        .await?;
    let p = role.params();
    Ok(PgTenantReadConfig::new(
        PgConfig::new_for_test_plaintext(
            p.host.clone(),
            p.port,
            p.database.clone(),
            p.username.clone(),
            PgPassword::new(p.password.clone()),
        )
        .with_acquire_timeout(Duration::from_secs(5)),
    ))
}

/// Connect a raw test store as `rss_app_read` for catalog/ACL negative-path assertions.
/// Production code cannot obtain this seam; it must use `PgStore::connect_verified_read`.
pub(crate) async fn connect_pg_rss_app_read_role(
    fixture: &OwnedPgFixture,
    store: &PgStore,
) -> Result<PgStore, Box<dyn std::error::Error + Send + Sync>> {
    let config = rss_app_read_config(fixture, store).await?;
    Ok(PgStore::connect(config.as_pg_config()).await?)
}

/// 将迁移 provision 的 `rss_audit_admin` 设置测试密码，并以真实 audit-admin role 建连接。
///
/// migration 负责声明该角色可 LOGIN；测试 helper 仅补本地测试密码，模拟部署时凭据注入。
pub(crate) async fn connect_pg_audit_admin_role(
    fixture: &OwnedPgFixture,
    _store: &PgStore,
) -> Result<PgStore, Box<dyn std::error::Error + Send + Sync>> {
    let [role] = fixture
        .resolve_app_roles([PgAppRoleSpec::new(
            RSS_AUDIT_ADMIN_ROLE,
            RSS_AUDIT_ADMIN_PASSWORD,
        )])
        .await?;
    let p = role.params();
    let config = PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_acquire_timeout(Duration::from_secs(5));
    Ok(PgStore::connect(&config).await?)
}
