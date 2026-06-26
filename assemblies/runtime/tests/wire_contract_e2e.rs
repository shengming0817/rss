//! 接线契约 e2e（[PERSIST-001] #1422）：`wire_settings(&SharedRuntimeDeps) -> DomainModuleResult` 形态。
//!
//! 验新签名两路：
//! - vault env 缺失（CI integration 常态：有 pg testcontainer、无 vault）→ `wire_settings` **fail-closed**
//!   返回 `Err`（不静默产探针）。
//! - vault env 存在 → 产物恰一条 `configs_ready` 探针、`resources` / `workers` 空（证明 result object 出向用
//!   真实域产物落地）。
//!
//! 全局 `unsafe_code = "forbid"` ⇒ 不能在进程内 `set_var` 注入 vault env，故按运行环境二分断言（两路均非空断言、
//! 无 vacuous skip）。`integration` feature 门控；`cargo nextest run -p runtime --features integration --no-run`
//! 能编译即满足验收（#1422 DoD）。

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::Duration;

use postgres::{PgConfig, PgDbReadiness, PgPassword, PgSslMode, PgStore};
use runtime::{CONFIGS_READY_PROBE_NAME, SharedRuntimeDeps, wire_settings};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// testkit fixture + `Arc<PgStore>`（含 run_migrations）。
async fn connect_pg()
-> Result<(testkit::PgFixture, Arc<PgStore>), Box<dyn std::error::Error + Send + Sync>> {
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
    Ok((fixture, Arc::new(store)))
}

/// `wire_settings` 在 vault env 缺失时 fail-closed；vault env 存在时产出恰一条 configs_ready 探针。
#[tokio::test(flavor = "multi_thread")]
async fn wire_settings_failcloses_without_vault_else_emits_configs_ready_probe() -> TestResult {
    let (_fixture, store) = connect_pg().await?;
    let readiness = Arc::new(PgDbReadiness::new());
    let deps = SharedRuntimeDeps { store, readiness };

    let vault_configured =
        std::env::var("RSS_VAULT_ADDR").is_ok() && std::env::var("RSS_VAULT_TOKEN").is_ok();

    match wire_settings(&deps).await {
        Err(e) => {
            // vault env 缺失 → 必 fail-closed（不静默产探针）。
            assert!(
                !vault_configured,
                "vault env 已配置却 fail——非缺配失败，安全回归: {e}"
            );
            // 锁定 Err 来源是 vault 缺配（而非 pg / 其它 bug 通过 anti-vacuity）。
            let chain = format!("{e:#}");
            assert!(
                chain.contains("RSS_VAULT_ADDR") || chain.contains("vault"),
                "Err 应指向 vault 缺配，实得: {chain}"
            );
        }
        Ok(result) => {
            assert!(
                vault_configured,
                "vault env 缺失却成功构造 resolver——fail-closed 回归"
            );
            assert_eq!(result.probes.len(), 1, "settings 仅 configs_ready 一条探针");
            assert_eq!(
                result.probes[0].0.as_str(),
                CONFIGS_READY_PROBE_NAME,
                "探针名 = configs_ready"
            );
            assert!(result.resources.is_empty(), "settings 今无 detached 资源");
            assert!(result.workers.is_empty(), "settings 今无后台 worker");
        }
    }
    Ok(())
}
