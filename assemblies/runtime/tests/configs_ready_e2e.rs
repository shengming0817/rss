//! `configs_ready` readiness e2e（#1309 F8 接线：真实 `PgDbReadiness` 采样 → readyz 端到端）。
//!
//! 覆盖路径：
//! - **Down 路径**（fail-closed，不连 DB）：已迁至 `runtime::tests::configs_ready_initial_down_readyz_503`
//!   （`#[cfg(test)]` in lib.rs），azure 非 integration 路径下即可运行。
//! - **Ready 路径**：`PgRuntimeDeps::spawn_readiness_sampler`（短 period）→ 真实 DB tick 后 readiness handle
//!   被标记 Ready → readyz 返 200，JSON body 含 `"overall":"healthy"` + `"name":"configs_ready"`。
//!
//! 区别于 lib 单测的 `HealthyProbe` 替身——此处验真实 `ConfigsReadyProbe.check()` 读 `PgDbReadiness::snapshot()`。
//! 采样驱动经 bundle 的 `spawn_readiness_sampler`（spawn+adopt 收口，#1423）；`pg_readiness_sampling_loop` 已 `pub(crate)`。
//!
//! `integration` feature 门控；无 docker 时经 `testkit::env_or_postgres()` 取 env 外部 pg 或跳过。
//! `cargo test -p runtime --features integration --no-run` 能编译即满足验收。

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
// `ManagedResource` 提供 `PgReadinessSampler::shutdown`（trait 方法，须在 scope 内才可调）。
use diport::ManagedResource as _;
use postgres::{PgConfig, PgError, PgPassword, PgRuntimeDeps, PgSslMode};
use primitives::ProbeName;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const TEST_APP_ROLE: &str = "rss_configs_ready_e2e_app";
const TEST_APP_PASSWORD: &str = "configs_ready_e2e_pw";

// `/metrics` 渲染替身共享自 tests/common——本测试只经 oneshot 验 readyz，metrics 用 noop 替身满足必填参数。
mod common;

/// testkit fixture + postgres capability bundle（`setup` 内含 connect + run_migrations，#1423）。
async fn connect_pg()
-> Result<(testkit::PgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let owner_config = pg_config(p, &p.username, &p.password);
    match PgRuntimeDeps::setup(&owner_config, &owner_config).await {
        Ok(deps) => return Ok((fixture, deps)),
        Err(PgError::RlsBypassRole) => {
            provision_nobypass_app_role(p).await?;
        }
        Err(e) => return Err(Box::new(e)),
    }
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

async fn provision_nobypass_app_role(
    p: &testkit::PgConnParams,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    sqlx::query(&format!(
        "GRANT USAGE, CREATE ON SCHEMA public TO {TEST_APP_ROLE}"
    ))
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {TEST_APP_ROLE}"
    ))
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {TEST_APP_ROLE}"
    ))
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}

/// Ready 路径：`spawn_readiness_sampler`（短 period，真实 DB）→ readyz 200。
///
/// 流程：`setup` 连真实 DB（readiness handle 初值 Down）→ `spawn_readiness_sampler`（50ms period，spawn+adopt
/// 收口进 bundle）→ tokio sleep 200ms 等至少一轮采样 tick 完成 → readyz 200（采样已标 Ready）→ `shutdown` 收敛。
#[tokio::test(flavor = "multi_thread")]
async fn configs_ready_sampling_loop_drives_to_ready_readyz_200() -> TestResult {
    let (_fixture, deps) = connect_pg().await?;

    // 短 period（50ms）确保首 tick 快速到来；spawn+adopt 由 bundle 收口。
    let sampler = deps.spawn_readiness_sampler(Duration::from_millis(50), CancellationToken::new());
    let health = deps.readiness_handle();

    // 等待至少一轮采样（200ms >> 50ms period）。
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 注册 probe（此时 health 已被采样 loop 标为 Ready）。
    // CONFIGS_READY_PROBE_NAME 常量单源：改名即编译期捕获（[D6/D7] #1309 review）。
    let mut reg = bootstrap::compose(&[])?;
    reg.probe(
        ProbeName::parse(runtime::CONFIGS_READY_PROBE_NAME)?,
        Box::new(runtime::ConfigsReadyProbe::new(Arc::clone(&health))),
    )?;
    let reporter = Arc::new(reg.take_health_reporter());

    let (_listener, authed) = runtime::health_listener(reporter, common::noop_metrics())?;
    let resp = authed
        .into_router_for_test()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health/v1/readyz")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "连通 DB → 采样后 health=Ready → readyz 200"
    );

    // 验证 JSON body 含 overall healthy + check 名 configs_ready。
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let body = String::from_utf8(bytes.to_vec())?;
    assert!(
        body.contains(r#""overall":"healthy""#),
        "overall healthy: {body}"
    );
    assert!(
        body.contains(r#""name":"configs_ready""#),
        "check 名 = registry 声明的 configs_ready: {body}"
    );
    assert!(
        body.contains(r#""status":"healthy""#),
        "Ready → healthy: {body}"
    );

    // 清理 sampler task。
    sampler.shutdown().await?;
    Ok(())
}
