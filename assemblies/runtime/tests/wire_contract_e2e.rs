//! 接线契约 e2e（[PERSIST-001] #1422 + 单源装配 #1498 + #1430 durable module）：
//! `wire_settings(&SharedRuntimeDeps) -> DomainBinding` 形态 + vault capability bundle 装配出口。
//!
//! **正向集成（常态 CI 必跑，无 ambient env 依赖）**：用测试内 wiremock Vault Transit 构造 stub `VaultRuntimeDeps`
//! （无外部 vault 也成功），与 pg testcontainer 组 `SharedRuntimeDeps`，验：
//! - `wire_settings`（resolver 经 bundle dispatch 注入，env-独立）返回 `DomainBinding`，
//!   module 产物包含 `configs_ready` + `keyprovider_ready`，并注册 keyprovider readiness sampler；
//! - bundle `runtime_resources()` 单源派生 resolver + keyprovider 两个 guard（#1498 D5 单源 rollback）。
//!
//! 对标 `controller-runtime/envtest`：负例查外部 env 缺失，**正向路径用测试内受控依赖继续执行**，不让核心
//! 正向集成依赖 ambient env 才跑（避无 env 时 `return` 空转）。fail-closed（缺 `RSS_VAULT_ADDR`/`TOKEN`/`TRANSIT_MOUNT`）的
//! 负例由 `runtime` 库单测 `build_vault_runtime_deps_missing_*_fails_fast` 覆盖（无需真实后端、常态跑），
//! 此处不重复 env 二分（旧址 `return Ok(())` 致正向接线在无 vault env 的常态 CI 被跳过——review F1）。
//!
//! `integration` feature 门控；`cargo nextest run -p runtime --features integration --no-run` 能编译即满足验收。

#![cfg(feature = "integration")]

use std::time::Duration;

use base64::Engine as _;
use bootstrap::compose_bindings;
use diport::ManagedResource;
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode};
use runtime::test_support::wire_settings;
use runtime::{
    CONFIGS_READY_PROBE_NAME, SharedRuntimeDeps, build_redis_runtime_deps,
    build_s3_runtime_deps_from,
};
use settings_composition::KEYPROVIDER_READY_PROBE_NAME;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use vault::{TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const KEYPROVIDER_CONFIG_FIELD: &str = "settings.config.value";
const KEYPROVIDER_CONFIG_SCHEME: u32 = 1;

struct NoopDomainTransport;

impl distributed::DomainTransport for NoopDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::DomainRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<distributed::DomainResponse, distributed::DomainTransportError>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async {
            Ok(distributed::DomainResponse::new(
                204,
                Vec::new(),
                Vec::new(),
            ))
        })
    }
}

fn noop_domain_transport() -> std::sync::Arc<dyn distributed::DomainTransport> {
    std::sync::Arc::new(NoopDomainTransport)
}

/// testkit fixture + postgres capability bundle（`setup` 内含 connect + run_migrations）。
async fn connect_pg()
-> Result<(testkit::PgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let owner_config = pg_config(p, &p.username, &p.password);
    provision_rss_app_login(p).await?;
    let deps = PgRuntimeDeps::setup(
        &owner_config,
        &pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
        generated::event::PROJECTION_INPUT_GENERATION,
        generated::event::PROJECTION_INPUTS,
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

async fn provision_rss_app_login(
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
    pool.close().await;
    Ok(())
}

#[allow(clippy::expect_used)]
fn readiness_context_b64(tenant: &str) -> String {
    let tenant = vocab::TenantId::parse(tenant).expect("canonical readiness tenant");
    let aad = secure::ProtectionContext::authenticated_request(
        tenant,
        "readiness.probe",
        KEYPROVIDER_CONFIG_FIELD,
        KEYPROVIDER_CONFIG_SCHEME,
    )
    .expect("valid readiness aad")
    .derive();
    base64::engine::general_purpose::STANDARD.encode(aad.as_canonical_bytes())
}

/// 正向集成：pg testcontainer + stub vault bundle（测试内固定 addr/token，无 ambient env）→ `wire_settings`
/// 产出恰一条 configs_ready 探针、无 detached 资源 / worker；bundle `runtime_resources()` 单源派生恰一条
/// resolver guard（#1498）。**无 env 二分**——核心正向接线在无外部 vault env 的常态 CI 也必跑（review F1）。
#[tokio::test(flavor = "multi_thread")]
async fn wire_settings_integrates_pg_and_vault_bundle_single_source_resolver() -> TestResult {
    let (_fixture, pg) = connect_pg().await?;

    let vault_server = MockServer::start().await;
    let readiness_context = readiness_context_b64("00000000-0000-4000-8000-000000000147");
    let mismatch_context = readiness_context_b64("00000000-0000-4000-8000-000000000148");
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/settings-config"))
        .and(body_partial_json(serde_json::json!({
            "context": readiness_context
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ciphertext": "vault:v1:cnNzLWtleXByb3ZpZGVyLXJlYWR5",
                "key_version": 1
            }
        })))
        .mount(&vault_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/settings-config"))
        .and(body_partial_json(serde_json::json!({
            "context": mismatch_context
        })))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["ciphertext verification failed"]
        })))
        .mount(&vault_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/settings-config"))
        .and(body_partial_json(serde_json::json!({
            "context": readiness_context
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "plaintext": base64::engine::general_purpose::STANDARD.encode(b"rss-keyprovider-ready")
            }
        })))
        .mount(&vault_server)
        .await;
    let stores = TenantStoreAllowlist::new(std::iter::empty())?;
    let vault = VaultRuntimeDeps::new(
        VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            vault_server.uri(),
            "s.testtoken",
            Duration::from_secs(5),
            stores,
        )?,
        VaultKeyProvider::new_allow_http(
            reqwest::Client::new(),
            vault_server.uri(),
            "s.testtoken",
            "transit",
            Duration::from_secs(5),
        )?,
    );
    let redis_fixture = testkit::env_or_redis().await?;
    let redis = build_redis_runtime_deps(|name| match name {
        "RSS_REDIS_URL" => Some(redis_fixture.url().to_string()),
        "RSS_REDIS_ALLOW_PLAINTEXT" => Some("true".to_string()),
        _ => None,
    })
    .await?;
    let s3 = build_s3_runtime_deps_from(|name| match name {
        "RSS_S3_ENDPOINT_URL" => Some("http://127.0.0.1:1".to_string()),
        "RSS_S3_ALLOW_PLAINTEXT" => Some("true".to_string()),
        "RSS_S3_BUCKET" => Some("rss-test-bucket".to_string()),
        "RSS_S3_ACCESS_KEY_ID" => Some("access-key".to_string()),
        "RSS_S3_SECRET_ACCESS_KEY" => Some("secret-key".to_string()),
        "RSS_S3_FORCE_PATH_STYLE" => Some("true".to_string()),
        _ => None,
    })?;

    let deps = SharedRuntimeDeps {
        pg: pg.handle(),
        redis,
        s3,
        vault,
        settings_config_value_key_name: diport::KeyName::try_new("settings-config")?,
        domain_transport: noop_domain_transport(),
    };

    // wire_settings env-独立（resolver 经 bundle dispatch 注入）→ 返回唯一 DomainBinding；
    // compose_bindings 是 module output 的唯一转换出口。
    let mut bindings = vec![wire_settings(&deps).await?];
    let (_, result) = compose_bindings(&mut bindings)?;
    assert!(bindings.is_empty(), "compose 后 binding 必须排空");
    assert_eq!(
        result.probes.len(),
        2,
        "settings 暴露 configs_ready + keyprovider_ready"
    );
    assert_eq!(
        result.probes[0].0.as_str(),
        CONFIGS_READY_PROBE_NAME,
        "探针名 = configs_ready"
    );
    assert_eq!(
        result.probes[1].0.as_str(),
        KEYPROVIDER_READY_PROBE_NAME,
        "探针名 = keyprovider_ready"
    );
    // settings wire_X 产物本身无 detached 资源；vault guard 由 runtime-local ProviderOutput 汇入
    // provider_module，再经 assembly 的 DomainModuleResult::merge 单源排入。
    assert!(
        result.resources.is_empty(),
        "settings wire_X 产物无 detached 资源"
    );
    assert_eq!(
        result.workers.len(),
        1,
        "settings 产出 keyprovider readiness worker"
    );

    // #1676 单源装配：vault bundle 的 diport-only runtime_resources 由 runtime-local
    // ProviderOutput 转为 provider_module，再经 DomainModuleResult::merge 统一消费。
    let vault_resources = deps.vault.runtime_resources();
    assert_eq!(vault_resources.len(), 2, "vault 单源派生两条 guard");
    assert_eq!(
        vault_resources[0].name(),
        "vault-secret-resolver",
        "vault 单源 resource 即 resolver guard"
    );
    assert_eq!(vault_resources[1].name(), "vault-key-provider");
    // Redis 为生产硬依赖；取 pool guard 单源验收。
    let redis_resources = deps.redis.runtime_resources();
    assert_eq!(redis_resources.len(), 1, "redis 单源派生 pool guard");
    Ok(())
}
