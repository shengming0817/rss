//! postgres adapter 集成测试（crate-internal；需真实 postgres，`integration` feature 门控；#1116 review F2/F5/F6）。
//!
//! crate-internal（非 `tests/`）以行使 `pub(crate)` 的 [`crate::PgStore::run_in_transaction`]（裸事务非公开
//! API，review F2）。本地 docker postgres：设 libpq 标准 env（`PGHOST` / `PGPORT` / `PGDATABASE` / `PGUSER`
//! / `PGPASSWORD`，`PGDATABASE` 须含 `test`），跑 `cargo nextest run -p postgres --features integration`。
//!
//! **fail-closed（review F5）**：缺任一 env / `PGDATABASE` 不含 `test` → 测试**失败**（非静默跳过），杜绝
//! 「未配置 DB 却显示 passed」的假绿，并防破坏性 DDL 打到非测试库（review F6）。

use std::time::Duration;

use diport::ManagedResource;
use futures::future::BoxFuture;

use crate::{PgConfig, PgPassword, PgSslMode, PgStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 由 libpq 标准 env 构造配置。fail-closed：缺 env / 非测试库名 → `Err`（测试失败，非跳过）。
fn config_from_env() -> Result<PgConfig, String> {
    let var = |k: &str| {
        std::env::var(k).map_err(|_| {
            format!("integration 测试需设置 {k}（libpq env）；见 migrations/README.md")
        })
    };
    let host = var("PGHOST")?;
    let port: u16 = var("PGPORT")?
        .parse()
        .map_err(|_| "PGPORT 不是合法 u16".to_string())?;
    let database = var("PGDATABASE")?;
    // review F6：集成测试执行破坏性 DDL（CREATE/DROP TABLE），拒绝打到非测试库。
    if !database.contains("test") {
        return Err(format!(
            "PGDATABASE='{database}' 不含 'test'——集成测试会执行破坏性 DDL，拒绝打到非测试库"
        ));
    }
    let username = var("PGUSER")?;
    let password = var("PGPASSWORD")?;
    Ok(
        PgConfig::new(host, port, database, username, PgPassword::new(password))
            // 本地无 TLS docker postgres：显式降级（默认 VerifyFull 对未启 TLS 的 docker pg 连不上）。
            .with_ssl_mode(PgSslMode::Prefer)
            .with_acquire_timeout(Duration::from_secs(5)),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_connects_and_shuts_down() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    assert_eq!(store.name(), "postgres");
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migrator_applies_and_is_idempotent() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    store.run_migrations().await?; // 应用 0001 占位
    store.run_migrations().await?; // 再跑：checksum 命中 → 幂等 no-op
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_commit_persists_and_rollback_discards() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;

    // setup：干净表 + 1 行，commit（committed 数据对所有池连接可见）。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("DROP TABLE IF EXISTS rss_tx_probe")
                    .execute(&mut *c)
                    .await?;
                sqlx::query("CREATE TABLE rss_tx_probe (id int)")
                    .execute(&mut *c)
                    .await?;
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (1)")
                    .execute(&mut *c)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 1);

    // rollback 路径：插入后强制 Err → run_in_transaction 回滚。
    let rolled_back = store
        .run_in_transaction::<_, (), sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (2)")
                    .execute(&mut *c)
                    .await?;
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(rolled_back.is_err());
    assert_eq!(probe_count(&store).await?, 1); // 回滚 → 行数不变

    // commit 路径：插入后 Ok → 持久化。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (3)")
                    .execute(&mut *c)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 2);

    // cleanup
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("DROP TABLE rss_tx_probe")
                    .execute(&mut *c)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    store.shutdown().await?;
    Ok(())
}

/// 在独立事务内读 `rss_tx_probe` 行数（committed 数据跨池连接可见）。
async fn probe_count(store: &PgStore) -> Result<i64, sqlx::Error> {
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                let row: (i64,) = sqlx::query_as("SELECT count(*) FROM rss_tx_probe")
                    .fetch_one(&mut *c)
                    .await?;
                Ok(row.0)
            }) as BoxFuture<'_, Result<i64, sqlx::Error>>
        })
        .await
}
