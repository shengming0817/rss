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
