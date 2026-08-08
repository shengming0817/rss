//! `configs_ready` readiness e2e（#1309 F8 接线：真实 `PgDbReadiness` 采样 → readyz 端到端）。
//!
//! 覆盖路径：
//! - **Down 路径**（fail-closed，不连 DB）：已迁至 `runtime::tests::configs_ready_initial_down_readyz_503`
//!   （`#[cfg(test)]` in lib.rs），azure 非 integration 路径下即可运行。
//! - **Ready 路径**：owner → handle + consuming runtime parts（短 period）→ 真实 DB tick 后 readiness handle
//!   被标记 Ready → readyz 返 200，JSON body 含 `"overall":"healthy"` + `"name":"configs_ready"`。
//!
//! 区别于 lib 单测的 `HealthyProbe` 替身——此处验真实 `ConfigsReadyProbe.check()` 读 `PgDbReadiness::snapshot()`。
//! 采样驱动经 bundle 的 consuming sampler factory（spawn+adopt 收口，#1423）。
//!
//! `integration` feature 门控；该 migration/owner-SQL 测试只接受 fixture-owned PostgreSQL，
//! external opt-in 会在任何 SQL 前 fail closed。
//! `cargo test -p runtime --features integration --no-run` 能编译即满足验收。

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
// `ManagedResource` 提供 `PgReadinessSampler::shutdown`（trait 方法，须在 scope 内才可调）。
use diport::ManagedResource as _;
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig};
use primitives::ProbeName;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";

// `/metrics` 渲染替身共享自 tests/common——本测试只经 oneshot 验 readyz，metrics 用 noop 替身满足必填参数。
mod common;

/// testkit fixture + postgres capability bundle（`setup` 内含 connect + run_migrations，#1423）。
async fn connect_pg()
-> Result<(testkit::OwnedPgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::owned_postgres().await?;
    let p = fixture.owner_params();
    let owner_config = pg_config(p, &p.username, &p.password);
    let [app, reader] = fixture
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PgAppRoleSpec::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
        ])
        .await?;
    let reader_params = reader.params();
    let tenant_read_config = PgTenantReadConfig::new(pg_config(
        reader_params,
        &reader_params.username,
        &reader_params.password,
    ));
    let workflow = eventexec::WorkflowRuntimePlan::disabled_fixture();
    let deps = PgRuntimeDeps::setup_owned_test_fixture(
        &owner_config,
        &pg_config(app.params(), &app.params().username, &app.params().password),
        &tenant_read_config,
        None,
        workflow.projection_capture(),
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

/// Ready 路径：consuming sampler factory（短 period，真实 DB）→ readyz 200。
///
/// 流程：`setup` 连真实 DB（readiness handle 初值 Down）→ owner 投影 handle 后按值交接 runtime parts
/// → tokio sleep 200ms 等至少一轮采样 tick 完成 → readyz 200（采样已标 Ready）→ `shutdown` 收敛。
#[tokio::test(flavor = "multi_thread")]
async fn configs_ready_sampling_loop_drives_to_ready_readyz_200() -> TestResult {
    let (_fixture, owner) = connect_pg().await?;
    let handle = owner.handle();

    let health = handle.readiness_handle();
    let (resources, sampler_factory) = owner.into_runtime_parts(Duration::from_millis(50));
    let sampler = sampler_factory.spawn(CancellationToken::new());

    // 等待至少一轮采样（200ms >> 50ms period）；固定墙钟走 testkit funnel。
    testkit::await_delay(Duration::from_millis(200)).await;

    // 注册 probe（此时 health 已被采样 loop 标为 Ready）。
    // CONFIGS_READY_PROBE_NAME 常量单源：改名即编译期捕获（[D6/D7] #1309 review）。
    let mut reg = bootstrap::compose(&[])?;
    reg.probe(
        ProbeName::parse(runtime::CONFIGS_READY_PROBE_NAME)?,
        Box::new(runtime::ConfigsReadyProbe::new(Arc::clone(&health))),
    )?;
    let reporter = Arc::new(reg.take_health_reporter());

    let authed = runtime::test_support::finalize_health_listener(reporter, common::noop_metrics())?;
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
    for resource in resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    Ok(())
}
