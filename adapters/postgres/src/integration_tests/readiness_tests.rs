//! Postgres integration tests — readiness seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn readiness_degrades_when_active_projection_generation_drifts() -> TestResult {
    let (fixture, deps) = setup_runtime_deps_with_projection_inputs(
        TEST_PROJECTION_INPUT_GENERATION,
        TEST_PROJECTION_INPUTS,
    )
    .await?;
    let owner = runtime_assertion_pool(fixture.params()).await?;
    let readiness = deps.handle().readiness_handle();
    let (resources, sampler_factory) =
        deps.into_runtime_parts(std::time::Duration::from_millis(20));
    let sampler = sampler_factory.spawn(tokio_util::sync::CancellationToken::new());

    await_map(std::time::Duration::from_secs(2), async || {
        (readiness.snapshot() == crate::PoolReadiness::Ready).then_some(())
    })
    .await
    .map_err(|_| "projection readiness did not become ready for the exact generation")?;

    replace_test_projection_generation(
        &PgStore {
            pool: owner.clone(),
        },
        TEST_PROJECTION_INPUT_GENERATION,
        &[],
    )
    .await?;
    await_map(std::time::Duration::from_secs(2), async || {
        (readiness.snapshot() == crate::PoolReadiness::Down).then_some(())
    })
    .await
    .map_err(|_| "projection registry drift did not degrade postgres readiness")?;

    sampler.shutdown().await?;
    for resource in resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    owner.close().await;
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

/// A reader whose only established connection is in use is capacity pressure, not evidence that
/// PostgreSQL is down. Readiness must stay HTTP-servable through the Saturated state.
#[tokio::test(flavor = "multi_thread")]
async fn probe_db_liveness_marks_full_reader_saturated() -> TestResult {
    use std::time::Duration;

    use crate::pool::{PgTenantReadConfig, PoolReadiness};

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let base_config = rss_app_read_config(&pg, &owner).await?;
    let constrained_config = PgTenantReadConfig::new(
        base_config
            .as_pg_config()
            .clone()
            .with_max_connections(1)
            .with_acquire_timeout(Duration::from_secs(30)),
    );
    let reader = PgStore::connect_verified_read(&constrained_config)
        .await?
        .store_arc();

    let only_connection = reader.pool.acquire().await?;

    assert_eq!(
        reader.probe_db_liveness().await,
        PoolReadiness::Saturated,
        "a fully occupied reader pool must remain degraded-but-ready"
    );

    drop(only_connection);
    reader.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Once the probe owns an idle connection, a backend/query hang is liveness failure rather than
/// capacity pressure. The production path uses `SELECT 1`; this test-only query exercises the same
/// acquired-connection deadline against a real PostgreSQL backend.
#[tokio::test(flavor = "multi_thread")]
async fn probe_db_liveness_marks_hung_idle_backend_down() -> TestResult {
    use std::time::Duration;

    use crate::pool::{PgTenantReadConfig, PoolReadiness};

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let base_config = rss_app_read_config(&pg, &owner).await?;
    let constrained_config = PgTenantReadConfig::new(
        base_config
            .as_pg_config()
            .clone()
            .with_max_connections(1)
            .with_acquire_timeout(Duration::from_secs(30)),
    );
    let reader = PgStore::connect_verified_read(&constrained_config)
        .await?
        .store_arc();
    await_map(Duration::from_secs(1), async || {
        (reader.pool.num_idle() > 0).then_some(())
    })
    .await
    .map_err(|_| "test precondition: the probe must begin with one idle backend")?;
    assert_eq!(
        reader.pool.num_idle(),
        1,
        "test precondition: the probe must begin with one idle backend"
    );

    assert_eq!(
        reader
            .probe_db_liveness_query_for_test("SELECT pg_sleep(4)")
            .await,
        PoolReadiness::Down,
        "a query hang after acquiring an idle backend must fail closed"
    );

    reader.shutdown().await?;
    owner.shutdown().await?;
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
        Arc::clone(&store),
        None,
        Duration::from_millis(50),
        token.clone(),
        Arc::clone(&health),
    ));

    // 等待至少一轮 tick 完成（period=50ms，有界轮询 Ready）。
    await_map(Duration::from_millis(300), async || {
        (health.snapshot() == PoolReadiness::Ready).then_some(())
    })
    .await
    .map_err(|_| "t51: 真实 DB 一 tick 后 health 应为 Ready")?;

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

/// A failed dedicated reader must degrade aggregate PostgreSQL readiness even while the writer
/// remains reachable.
#[tokio::test(flavor = "multi_thread")]
async fn sampling_loop_marks_down_when_reader_pool_is_closed() -> TestResult {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use crate::pool::PoolReadiness;
    use crate::readiness::{PgDbReadiness, pg_readiness_sampling_loop};

    let (pg, writer) = connect_pg().await?;
    writer.run_migrations().await?;
    let reader_config = rss_app_read_config(&pg, &writer).await?;
    let reader = PgStore::connect_verified_read(&reader_config)
        .await?
        .store_arc();
    reader.shutdown().await?;

    let writer = Arc::new(writer);
    let health = Arc::new(PgDbReadiness::new());
    let token = CancellationToken::new();
    let handle = tokio::spawn(pg_readiness_sampling_loop(
        Arc::clone(&writer),
        reader,
        None,
        Duration::from_millis(50),
        token.clone(),
        Arc::clone(&health),
    ));

    await_map(Duration::from_millis(300), async || {
        (health.snapshot() == PoolReadiness::Down).then_some(())
    })
    .await
    .map_err(|_| "closed reader must dominate a healthy writer")?;
    assert_eq!(
        health.snapshot(),
        PoolReadiness::Down,
        "closed reader must dominate a healthy writer"
    );

    token.cancel();
    assert!(handle.await.is_ok(), "sampling loop should stop cleanly");
    writer.shutdown().await?;
    Ok(())
}
