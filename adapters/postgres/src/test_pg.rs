//! crate-internal 共享 postgres 测试连接单源（`integration` feature + test 门控）。
//!
//! 所有集成测试须经此模块取连接，**不得**在各测试模块内自行重复 `config_from_env` / `connect_pg` 逻辑。
//! 严格库名校验已在 `testkit::env_or_postgres` 单源执行，此处不重复。

use std::time::Duration;

use crate::{PgConfig, PgPassword, PgSslMode, PgStore};
use testkit::PgFixture;

/// fixture（env 或 self-provision 容器）→ 连接 store。
///
/// 回传 `(PgFixture, PgStore)`；**调用方须绑定 fixture 到测试结束**（其 `Drop` 停容器）。
/// 严格库名校验由 [`testkit::env_or_postgres`] 单源执行（外部路径需 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES`
/// 且 `PGDATABASE` 须以 `_test` 结尾或 `== "test"`）；连接配置：TLS `Prefer`，acquire_timeout 5s。
pub(crate) async fn connect_pg()
-> Result<(PgFixture, PgStore), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    // 本地无 TLS docker postgres：显式降级（默认 VerifyFull 对未启 TLS 的 docker pg 连不上）。
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5));
    let store = PgStore::connect(&config).await?;
    Ok((fixture, store))
}

/// 在已连接的（owner/superuser）`store` 上创建一个 NOBYPASSRLS LOGIN 角色，并以该角色连一个新 `PgStore`。
///
/// 供 RLS 能力门「非绕过角色」路径测试用——serving 连接须为非 superuser（tenancy.md §RLS 与 PG scope），
/// 故能力门的 ok / table-offender 路径只有在非绕过角色下才可达（superuser 会先触发 `RlsBypassRole`）。
/// 角色名 / 口令为测试固定字面量（非注入面）；幂等：先 `DROP ROLE IF EXISTS` 清同库重跑残留。
/// 该角色不授任何表 DML——能力门只读 `pg_catalog` / `pg_policies` + set GUC，无需表权限（pg_catalog 不受权限过滤）。
pub(crate) async fn connect_pg_nobypass_role(
    fixture: &PgFixture,
    store: &PgStore,
) -> Result<PgStore, Box<dyn std::error::Error + Send + Sync>> {
    const ROLE: &str = "rss_rls_test_app";
    const PW: &str = "rls_test_pw";
    sqlx::query(&format!("DROP ROLE IF EXISTS {ROLE}"))
        .execute(&store.pool)
        .await
        .ok();
    sqlx::query(&format!(
        "CREATE ROLE {ROLE} LOGIN PASSWORD '{PW}' NOBYPASSRLS"
    ))
    .execute(&store.pool)
    .await?;
    let p = fixture.params();
    let config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        ROLE.to_string(),
        PgPassword::new(PW.to_string()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5));
    Ok(PgStore::connect(&config).await?)
}
