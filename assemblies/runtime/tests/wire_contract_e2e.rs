//! 接线契约 e2e（[PERSIST-001] #1422 + 单源装配 #1498 + #1430 durable module）：
//! `wire_settings(&SharedRuntimeDeps) -> DomainBinding` 形态 + vault capability bundle 装配出口。
//!
//! **正向集成（常态 CI 必跑，无 ambient env 依赖）**：用测试内 wiremock Vault Transit 构造 stub `VaultRuntimeDeps`
//! （无外部 vault 也成功），与 pg testcontainer 组 `SharedRuntimeDeps`，验：
//! - `wire_settings`（resolver 经 bundle dispatch 注入，env-独立）返回 `DomainBinding`，
//!   domain output 保持为空；同一 readiness generation 产出的 PostgreSQL / Vault typed provider
//!   outputs 分别持有 `configs_ready`、`keyprovider_ready` 与 `vault_secret_resolver_ready`；
//!
//! 对标 `controller-runtime/envtest`：负例查外部 env 缺失，**正向路径用测试内受控依赖继续执行**，不让核心
//! 正向集成依赖 ambient env 才跑（避无 env 时 `return` 空转）。fail-closed（缺 `RSS_VAULT_ADDR`/`TOKEN`/`TRANSIT_MOUNT`）的
//! 负例由 `runtime` 库 `VaultRuntimeConfig` snapshot 单测
//! `runtime_infra_vault_snapshot_missing_values_fail_in_mapping_order` 覆盖（无需真实后端、常态跑），
//! 此处不重复 env 二分（旧址 `return Ok(())` 致正向接线在无 vault env 的常态 CI 被跳过——review F1）。
//!
//! `integration` feature 门控；`cargo nextest run -p runtime --features integration --no-run` 能编译即满足验收。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bootstrap::compose_bindings;
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgTenantReadConfig};
use runtime::CONFIGS_READY_PROBE_NAME;
use runtime::test_support::{
    build_s3_runtime_deps_from_values, build_settings_wire_fixture,
    build_unused_redis_runtime_deps, test_private_ca_pem, wire_settings,
};
use settings_composition::KEYPROVIDER_READY_PROBE_NAME;
use vault::{
    StoreBinding, TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver,
    VaultSigner,
};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";
const KEYPROVIDER_READINESS_FIELD: &str = "settings.key-provider.readiness";
const KEYPROVIDER_READINESS_FORMAT_VERSION: u32 = 1;

fn unused_tenant_store_allowlist() -> TestResult<TenantStoreAllowlist> {
    Ok(TenantStoreAllowlist::new([(
        (
            rss_request_context::TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?,
            "vault".to_owned(),
        ),
        StoreBinding {
            mount: "secret".to_owned(),
            kv_path_prefix: "tenants/a".to_owned(),
        },
    )])?)
}

struct NoopDomainTransport;

impl distributed::HttpContractTransport for NoopDomainTransport {
    fn dispatch(
        &self,
        _request: distributed::HttpContractRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        distributed::HttpContractResponse,
                        distributed::HttpContractTransportError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { distributed::HttpContractResponse::try_new(204, Vec::new()) })
    }
}

fn noop_domain_transport() -> std::sync::Arc<dyn distributed::HttpContractTransport> {
    std::sync::Arc::new(NoopDomainTransport)
}

fn probe_identity_multiset(output: &bootstrap::DomainModuleResult) -> BTreeMap<String, usize> {
    let mut identities = BTreeMap::new();
    for (name, _) in output.probes() {
        *identities.entry(name.as_str().to_owned()).or_default() += 1;
    }
    identities
}

/// testkit fixture + postgres capability bundle（`setup` 内含 connect + run_migrations）。

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
    PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_acquire_timeout(Duration::from_secs(5))
}

#[allow(clippy::expect_used)]
fn readiness_context_b64(tenant: &str) -> String {
    let tenant = rss_request_context::TenantId::parse(tenant).expect("canonical readiness tenant");
    let aad = secure::ProtectionContext::authenticated_request(
        tenant,
        "provider.readiness",
        KEYPROVIDER_READINESS_FIELD,
        KEYPROVIDER_READINESS_FORMAT_VERSION,
    )
    .expect("valid readiness aad")
    .derive();
    base64::engine::general_purpose::STANDARD.encode(aad.as_canonical_bytes())
}

/// 正向集成：pg testcontainer + stub vault bundle（测试内固定 addr/token，无 ambient env）→ `wire_settings`
/// domain output 保持为空；同 generation 的三个 typed provider outputs 持有稳定且唯一的
/// PostgreSQL / Vault probe identity。**无 env 二分**——核心正向接线在无外部 vault env 的常态 CI 也必跑。
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
    let stores = unused_tenant_store_allowlist()?;
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
    let redis_ca = test_private_ca_pem();
    let redis = build_unused_redis_runtime_deps()?;
    let s3 = build_s3_runtime_deps_from_values(
        "https://127.0.0.1:1".to_string(),
        "rss-test-bucket".to_string(),
        "access-key".to_string(),
        "secret-key".to_string(),
        true,
        redis_ca,
    )?;

    let fixture = build_settings_wire_fixture(
        Arc::new(crypto::load_password_blocklist_from_reader(
            std::io::Cursor::new(
                b"sha256:2e2b24f8ee40bb847fe85bb23336a39ef5948e6b49d897419ced68766b16967a\n",
            ),
        )?),
        pg.handle(),
        redis,
        s3,
        vault,
        Arc::new(VaultSigner::new_rss_access_allow_http(
            reqwest::Client::new(),
            vault_server.uri(),
            "s.testtoken",
            "transit",
            Duration::from_secs(5),
            diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-jwt-es256")),
        )?),
        diport::KeyName::try_new("settings-config")?,
        noop_domain_transport(),
    )
    .await?;
    let (deps, postgres_output, key_provider_output, secret_resolver_output) = fixture.into_parts();

    // Domain wiring consumes only readiness handles; provider lifecycle remains in its three
    // non-interchangeable, move-only outputs.
    let mut bindings = vec![wire_settings(&deps).await?];
    let (_, domain_output) = compose_bindings(&mut bindings)?;
    assert!(bindings.is_empty(), "compose 后 binding 必须排空");
    assert!(
        domain_output.probe_count() == 0,
        "domain 不拥有 provider probes"
    );
    assert!(
        domain_output.resource_count() == 0,
        "domain 不拥有 provider resources"
    );
    assert!(
        domain_output.worker_count() == 0,
        "domain 不拥有 provider workers"
    );

    let postgres_output = postgres_output.into_output();
    assert_eq!(
        probe_identity_multiset(&postgres_output),
        BTreeMap::from([(CONFIGS_READY_PROBE_NAME.to_owned(), 1)])
    );
    assert_eq!(postgres_output.resource_count(), 0);
    assert_eq!(postgres_output.worker_count(), 0);

    let key_provider_output = key_provider_output.into_output();
    assert_eq!(
        probe_identity_multiset(&key_provider_output),
        BTreeMap::from([(KEYPROVIDER_READY_PROBE_NAME.to_owned(), 1)])
    );
    assert_eq!(key_provider_output.resource_count(), 0);
    assert_eq!(key_provider_output.worker_count(), 1);

    let secret_resolver_output = secret_resolver_output.into_output();
    assert_eq!(
        probe_identity_multiset(&secret_resolver_output),
        BTreeMap::from([(
            settings_composition::SECRET_RESOLVER_READY_PROBE_NAME.to_owned(),
            1,
        )])
    );
    assert_eq!(secret_resolver_output.resource_count(), 0);
    assert_eq!(secret_resolver_output.worker_count(), 1);

    let expected = BTreeMap::from([
        (CONFIGS_READY_PROBE_NAME.to_owned(), 1),
        (KEYPROVIDER_READY_PROBE_NAME.to_owned(), 1),
        (
            settings_composition::SECRET_RESOLVER_READY_PROBE_NAME.to_owned(),
            1,
        ),
    ]);
    let mut provider_output = bootstrap::DomainModuleResult::default();
    provider_output.extend([postgres_output, key_provider_output, secret_resolver_output]);
    assert_eq!(probe_identity_multiset(&provider_output), expected);
    assert_eq!(provider_output.worker_count(), 2);

    provider_output.merge(domain_output);
    assert_eq!(
        probe_identity_multiset(&provider_output),
        expected,
        "最终 carrier 必须保留每个 provider probe identity 恰好一次"
    );
    assert_eq!(provider_output.worker_count(), 2);
    Ok(())
}
