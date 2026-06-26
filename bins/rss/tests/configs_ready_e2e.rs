//! `configs_ready` readiness e2e（#1320 review F7：真实 probe → readyz 端到端，非 fake HealthyProbe）。
//!
//! 覆盖路径：真 `PgStore`（testkit fixture + run_migrations）→ `rss::ConfigsReadyProbe::new(store)` 注册进
//! registry → `take_health_reporter` → `rss::health_listener` → 经 funnel 出口驱动 `/health/v1/readyz`，
//! 断言 readyz 反映**真实** `configs_ready` 探针（连通池 → Ready → overall healthy + check 名 `configs_ready`）。
//! 区别于 lib 单测的 `HealthyProbe` 替身——此处验真实 `ConfigsReadyProbe.check()`（读 `PgStore::pool_readiness`）。
//!
//! `integration` feature 门控；无 docker 时经 `testkit::env_or_postgres()` 取 env 外部 pg 或跳过。
//! `cargo test -p rss --features integration --no-run` 能编译即满足验收（PoolReadiness→HealthStatus 映射另有 lib 单测）。

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use postgres::{PgConfig, PgPassword, PgSslMode, PgStore};
use primitives::ProbeName;
use tower::ServiceExt as _;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// testkit fixture + PgStore（含 run_migrations）。
async fn connect_pg()
-> Result<(testkit::PgFixture, PgStore), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5));
    let store = PgStore::connect(&config).await?;
    store.run_migrations().await?;
    Ok((fixture, store))
}

/// 真 `configs_ready` 探针经 readyz：连通池 → Ready → overall healthy(200) + check 名 `configs_ready`。
#[tokio::test(flavor = "multi_thread")]
async fn configs_ready_readyz_reflects_real_pool() -> TestResult {
    let (_fixture, store) = connect_pg().await?;
    let store = Arc::new(store);

    // 真实 ConfigsReadyProbe（读 PgStore::pool_readiness），非 fake——注册名权威 configs_ready。
    let mut reg = bootstrap::compose(&[])?;
    reg.probe(
        ProbeName::parse("configs_ready")?,
        Box::new(rss::ConfigsReadyProbe::new(store.clone())),
    )?;
    let reporter = Arc::new(reg.take_health_reporter());

    let (_listener, authed) = rss::health_listener(reporter)?;
    let resp = authed
        .into_router_for_test()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health/v1/readyz")
                .body(Body::empty())?,
        )
        .await?;

    // 连通池 → ConfigsReadyProbe 报 Ready → readyz overall healthy → 200。
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "连通 pg pool → configs_ready Ready → readyz 200"
    );
    // readyz DTO camelCase JSON：{"overall":"healthy","checks":[{"name":"configs_ready","status":"healthy",..}]}
    // 字符串断言（避 serde_json dev-dep）：含 overall healthy + check 名 configs_ready + Ready→healthy。
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
    Ok(())
}
