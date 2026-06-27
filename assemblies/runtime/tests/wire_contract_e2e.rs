//! 接线契约 e2e（[PERSIST-001] #1422 + 单源装配 #1498）：`wire_settings(&SharedRuntimeDeps) ->
//! DomainModuleResult` 形态 + vault capability bundle 装配出口。
//!
//! **正向集成（常态 CI 必跑，无 ambient env 依赖）**：用测试内固定 addr/token 构造 stub `VaultRuntimeDeps`
//! （`build_vault_runtime_deps`，无外部 vault 也成功），与 pg testcontainer 组 `SharedRuntimeDeps`，验：
//! - `wire_settings`（resolver 经 bundle dispatch 注入，env-独立）产物恰一条 `configs_ready` 探针、
//!   `resources` / `workers` 空（settings wire_X 产物本身无 detached 资源）；
//! - bundle `runtime_resources()` 单源派生恰一条 resolver guard（#1498 D5 单源 rollback）。
//!
//! 对标 `controller-runtime/envtest`：负例查外部 env 缺失，**正向路径用测试内受控依赖继续执行**，不让核心
//! 正向集成依赖 ambient env 才跑（避无 env 时 `return` 空转）。fail-closed（缺 `RSS_VAULT_ADDR`/`TOKEN`）的
//! 负例由 `runtime` 库单测 `build_vault_runtime_deps_missing_{addr,token}_fails_fast` 覆盖（无需真实后端、常态跑），
//! 此处不重复 env 二分（旧址 `return Ok(())` 致正向接线在无 vault env 的常态 CI 被跳过——review F1）。
//!
//! `integration` feature 门控；`cargo nextest run -p runtime --features integration --no-run` 能编译即满足验收。

#![cfg(feature = "integration")]

use std::time::Duration;

use diport::ManagedResource;
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode};
use runtime::{
    CONFIGS_READY_PROBE_NAME, SharedRuntimeDeps, build_vault_runtime_deps, wire_settings,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// testkit fixture + postgres capability bundle（`setup` 内含 connect + run_migrations）。
async fn connect_pg()
-> Result<(testkit::PgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
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
    let deps = PgRuntimeDeps::setup(&config).await?;
    Ok((fixture, deps))
}

/// 正向集成：pg testcontainer + stub vault bundle（测试内固定 addr/token，无 ambient env）→ `wire_settings`
/// 产出恰一条 configs_ready 探针、无 detached 资源 / worker；bundle `runtime_resources()` 单源派生恰一条
/// resolver guard（#1498）。**无 env 二分**——核心正向接线在无外部 vault env 的常态 CI 也必跑（review F1）。
#[tokio::test(flavor = "multi_thread")]
async fn wire_settings_integrates_pg_and_vault_bundle_single_source_resolver() -> TestResult {
    let (_fixture, pg) = connect_pg().await?;

    // stub vault bundle：测试内固定 addr/token（`VaultSecretResolver::new` 仅构造期校验 URL/token + 空
    // allowlist，无真实连接）——正向集成不依赖 ambient vault env。fail-closed 负例见 runtime 库单测。
    let vault = build_vault_runtime_deps(|name| match name {
        "RSS_VAULT_ADDR" => Some("https://vault.example:8200".to_string()),
        "RSS_VAULT_TOKEN" => Some("s.testtoken".to_string()),
        _ => None,
    })?;

    let deps = SharedRuntimeDeps { pg, vault };

    // wire_settings env-独立（resolver 经 bundle dispatch 注入）→ 产物恰一条 configs_ready 探针。
    let result = wire_settings(&deps).await?;
    assert_eq!(result.probes.len(), 1, "settings 仅 configs_ready 一条探针");
    assert_eq!(
        result.probes[0].0.as_str(),
        CONFIGS_READY_PROBE_NAME,
        "探针名 = configs_ready"
    );
    // settings wire_X 产物本身无 detached 资源（vault guard 经 run() 的 deps.vault.runtime_resources() 单源排入）。
    assert!(
        result.resources.is_empty(),
        "settings wire_X 产物无 detached 资源"
    );
    assert!(result.workers.is_empty(), "settings 今无后台 worker");

    // #1498 单源装配：vault bundle runtime_resources 恰一条 resolver guard（组合根 merge 进 module.resources）。
    let vault_resources = deps.vault.runtime_resources();
    assert_eq!(vault_resources.len(), 1, "vault 单源派生 resolver guard");
    assert_eq!(
        vault_resources[0].name(),
        "vault-secret-resolver",
        "vault 单源 resource 即 resolver guard"
    );
    Ok(())
}
