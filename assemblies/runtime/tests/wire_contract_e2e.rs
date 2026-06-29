//! 接线契约 e2e（[PERSIST-001] #1422 + 单源装配 #1498 + #1430 durable module）：`wire_settings(&SharedRuntimeDeps)
//! -> (SettingsDomain, DomainModuleResult)` 形态 + vault capability bundle 装配出口。
//!
//! **正向集成（常态 CI 必跑，无 ambient env 依赖）**：用测试内固定 addr/token 构造 stub `VaultRuntimeDeps`
//! （`build_vault_runtime_deps`，无外部 vault 也成功），与 pg testcontainer 组 `SharedRuntimeDeps`，验：
//! - `wire_settings`（resolver 经 bundle dispatch 注入，env-独立）返回 `(SettingsDomain, DomainModuleResult)`，
//!   module 产物恰一条 `configs_ready` 探针、`resources` / `workers` 空（settings wire_X 产物本身无 detached 资源）；
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
use postgres::{PgConfig, PgError, PgPassword, PgRuntimeDeps, PgSslMode};
use runtime::{
    CONFIGS_READY_PROBE_NAME, SharedRuntimeDeps, build_redis_runtime_deps,
    build_vault_runtime_deps, wire_settings,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const TEST_APP_ROLE: &str = "rss_wire_contract_e2e_app";
const TEST_APP_PASSWORD: &str = "wire_contract_e2e_pw";

/// testkit fixture + postgres capability bundle（`setup` 内含 connect + run_migrations）。
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
            PERFORM pg_advisory_xact_lock(hashtext('{TEST_APP_ROLE}'));
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
    let redis_fixture = testkit::env_or_redis().await?;
    let redis = build_redis_runtime_deps(|name| {
        (name == "RSS_REDIS_URL").then(|| redis_fixture.url().to_string())
    })
    .await?;

    let deps = SharedRuntimeDeps { pg, redis, vault };

    // wire_settings env-独立（resolver 经 bundle dispatch 注入）→ 返回 (SettingsDomain, DomainModuleResult)；
    // module 半边产物恰一条 configs_ready 探针（#1430：domain 半边经 run() compose 挂业务路由，此处只验 module 出向）。
    let (_settings_domain, result) = wire_settings(&deps).await?;
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
    // Redis 为生产硬依赖；取 pool guard 单源验收。
    let redis_resources = deps.redis.runtime_resources();
    assert_eq!(redis_resources.len(), 1, "redis 单源派生 pool guard");
    Ok(())
}
