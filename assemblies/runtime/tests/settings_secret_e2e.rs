//! settings secret e2e 集成测试（`integration` feature 门控；需真实 postgres）。
//!
//! 覆盖路径：`SecretService::with_postgres(PgSecretRepo, PgSecretUnitOfWork,
//! InlineMemResolver, FixedClock)` over 真实 pg：
//! - e2e-s1: publish_secret → find_secret_ref roundtrip
//! - e2e-s2: resolve_secret：mem resolver 命中（材料字节正确）
//! - e2e-s3: rollback_secret → 版本号单调，活跃引用回到旧 ref
//! - e2e-s4: resolve 未命中（no ref）→ NotFound
//!
//! 无 docker 时通过 `testkit::env_or_postgres()` 取 env 外部 pg 或跳过。
//! `cargo test -p rss --features integration --no-run` 能编译即满足验收。
//!
//! # SecretResolver 替身
//!
//! deny.toml 限制 `memory` crate wrappers = ["journeys", "xtask"]，assemblies/runtime 不允许依赖 `memory`。
//! 本文件内 inline `InlineMemResolver` 替代 `MemSecretResolver`，无需 memory crate。

#![cfg(feature = "integration")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use diport::{
    Clock, DynKeyProvider, DynSecretResolver, EncryptOutput, KeyName, KeyProvider,
    KeyProviderError, KeyRef, KeyVersion, RedactedBytes, SecretCoordinate, SecretMaterial,
    SecretResolverError,
};
use postgres::{
    ConfigValueProtections, PgConfig, PgPassword, PgRuntimeDeps, PgSslMode, PgTenantReadConfig,
    caps,
};
use settings::SecretService;
use settings::ports::{SecretKey, SecretRef, StoreId, TenantId};

// ── 测试用常量 ────────────────────────────────────────────────────────────────

const TENANT_STR: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const STORE_ID: &str = "mem-vault";
const TEST_APP_ROLE: &str = "rss_app";
const TEST_APP_PASSWORD: &str = "rss_app_test_pw";
const TEST_READ_ROLE: &str = "rss_app_read";
const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";
static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── inline MemResolver（deny.toml 禁 rss→memory，故在本文件内直接实现）──────────

type InlineSecretKey = (String, String, String);
type InlineSecretStore = Arc<Mutex<HashMap<InlineSecretKey, Vec<u8>>>>;

/// in-test 内存 secret 解析替身（非 memory crate；仅测试使用）。
///
/// 键 = `(tenant_uuid_str, store_id, ref_key)`，命中返 `SecretMaterial`，未命中返 `NotFound`。
struct InlineMemResolver {
    store: InlineSecretStore,
}

impl InlineMemResolver {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn insert(&self, tenant: TenantId, store_id: &str, ref_key: &str, bytes: Vec<u8>) {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).insert(
            (
                tenant.as_uuid().to_string(),
                store_id.to_string(),
                ref_key.to_string(),
            ),
            bytes,
        );
    }
}

impl diport::SecretResolver for InlineMemResolver {
    async fn resolve(
        &self,
        tenant: TenantId,
        coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        let g = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let k = (
            tenant.as_uuid().to_string(),
            coord.store_id().to_string(),
            coord.key().to_string(),
        );
        match g.get(&k) {
            Some(b) => Ok(SecretMaterial::new(b.clone())),
            None => Err(SecretResolverError::NotFound),
        }
    }
}

// ── FixedClock ────────────────────────────────────────────────────────────────

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
}

struct UnusedKeyProvider;

impl KeyProvider for UnusedKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Ok(EncryptOutput::new(
            b"unused".to_vec(),
            KeyRef::new(key, KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        _ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, KeyProviderError> {
        Ok(secure::Plaintext::new(Vec::new()))
    }

    async fn rewrap(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Ok(EncryptOutput::new(ciphertext.into_bytes(), key))
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

#[allow(clippy::expect_used)]
fn unused_config_protections() -> ConfigValueProtections {
    ConfigValueProtections::new(
        DynKeyProvider::new_box(UnusedKeyProvider),
        DynKeyProvider::new_box(UnusedKeyProvider),
        KeyName::try_new("settings-config").expect("valid key name"),
    )
}

// ── 测试辅助 ──────────────────────────────────────────────────────────────────

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[allow(clippy::expect_used)]
fn tenant() -> TenantId {
    TenantId::parse(TENANT_STR).expect("canonical tenant")
}

/// 生成每次测试唯一的 secret key（防跨测试污染，无需 DELETE FROM secret_refs）。
fn unique_key(prefix: &str) -> SecretKey {
    let n = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    #[allow(clippy::expect_used)]
    SecretKey::parse(&format!("e2e.{prefix}-pid{pid}-n{n}")).expect("valid unique key")
}

#[allow(clippy::expect_used)]
fn make_ref(store_id: &str, ref_key: &str) -> SecretRef {
    let sid = StoreId::parse(store_id).expect("valid store id");
    SecretRef::parse(sid, ref_key, None).expect("valid secret ref")
}

/// testkit fixture + postgres capability bundle（`setup` 内含 connect + run_migrations，#1423）。
async fn connect_pg_and_setup()
-> Result<(testkit::PgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_postgres().await?;
    let p = fixture.params();
    let owner_config = pg_config(p, &p.username, &p.password);
    testkit::provision_postgres_test_logins(
        p,
        &[
            testkit::PostgresTestLogin::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PostgresTestLogin::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
        ],
    )
    .await?;
    let tenant_read_config =
        PgTenantReadConfig::new(pg_config(p, TEST_READ_ROLE, TEST_READ_PASSWORD));
    let deps = PgRuntimeDeps::setup_test_fixture(
        &owner_config,
        &pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
        &tenant_read_config,
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

/// 构造 SecretService（真 PgSecretRepo 读端 + PgSecretUnitOfWork 写端 via settings 域受控句柄）。
fn make_service(deps: &PgRuntimeDeps, resolver: InlineMemResolver) -> SecretService {
    // settings bundle 产出 secret box（本 e2e 不消费 read/write config）。
    let (_configs, _writer, secrets, secret_writer) = deps
        .handle()
        .for_domain::<caps::Settings>()
        .settings_bundle(Arc::new(FixedClock), unused_config_protections())
        .into_parts();
    SecretService::with_postgres(
        secrets.into(),
        secret_writer.into(),
        DynSecretResolver::new_box(resolver),
        Box::new(FixedClock),
    )
}

// ── e2e 测试 ─────────────────────────────────────────────────────────────────

/// e2e-s1：publish_secret → find_secret_ref roundtrip（typed UoW 写入 + PgSecretRepo 读取闭合）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path；item-level carve-out（error-handling.md §Carve-out）。
async fn e2e_s1_publish_find_roundtrip() -> TestResult {
    let (_pg, deps) = connect_pg_and_setup().await?;
    let resolver = InlineMemResolver::new();
    let svc = make_service(&deps, resolver);
    let key = unique_key("s1-key");
    let ref_key = "myapp/db-password";

    let v1 = svc
        .publish_secret(tenant(), key.clone(), make_ref(STORE_ID, ref_key))
        .await?;
    assert_eq!(v1, 1, "首次 publish 版本号应为 1");

    let found = svc.find_secret_ref(tenant(), &key).await?;
    assert_eq!(
        found.as_ref().map(|r| r.ref_key()),
        Some(ref_key),
        "ref_key 回环"
    );
    assert_eq!(
        found.as_ref().map(|r| r.store_id().as_str()),
        Some(STORE_ID),
        "store_id 回环"
    );

    Ok(())
}

/// e2e-s2：resolve_secret → mem resolver 命中，材料字节正确（SecretService 端到端）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn e2e_s2_resolve_secret_mem_hit() -> TestResult {
    let (_pg, deps) = connect_pg_and_setup().await?;
    let resolver = InlineMemResolver::new();
    let ref_key = "myapp/api-key";
    // 预置材料（(tenant, store_id, ref_key) 命中路径）。
    resolver.insert(tenant(), STORE_ID, ref_key, b"secret-material-e2e".to_vec());
    let svc = make_service(&deps, resolver);
    let key = unique_key("s2-key");

    svc.publish_secret(tenant(), key.clone(), make_ref(STORE_ID, ref_key))
        .await?;

    let mat = svc.resolve_secret(tenant(), &key).await?;
    assert_eq!(mat.expose(), b"secret-material-e2e", "材料字节应正确");

    Ok(())
}

/// e2e-s3：rollback_secret → 版本号单调递增，且 find_secret_ref 回到旧引用。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn e2e_s3_rollback_version_monotonic() -> TestResult {
    let (_pg, deps) = connect_pg_and_setup().await?;
    let resolver = InlineMemResolver::new();
    let svc = make_service(&deps, resolver);
    let key = unique_key("s3-key");

    svc.publish_secret(tenant(), key.clone(), make_ref(STORE_ID, "ref-v1"))
        .await?;
    svc.publish_secret(tenant(), key.clone(), make_ref(STORE_ID, "ref-v2"))
        .await?;

    // rollback 到 v1 → 生成 v3（版本单调不重置）。
    let v3 = svc.rollback_secret(tenant(), &key, 1).await?;
    assert_eq!(v3, 3, "rollback 应生成新版本 v3");

    // 活跃引用回到 v1 的 ref_key。
    let current = svc.find_secret_ref(tenant(), &key).await?;
    assert_eq!(
        current.as_ref().map(|r| r.ref_key()),
        Some("ref-v1"),
        "rollback 后活跃引用回到 v1 的 ref_key"
    );

    Ok(())
}

/// e2e-s4：resolve 未命中（no ref）→ NotFound。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn e2e_s4_resolve_not_found_when_no_ref() -> TestResult {
    let (_pg, deps) = connect_pg_and_setup().await?;
    let resolver = InlineMemResolver::new();
    let svc = make_service(&deps, resolver);
    let key = unique_key("s4-key");

    let result = svc.resolve_secret(tenant(), &key).await;
    let Err(err) = result else {
        return Err(std::io::Error::other("should fail with NotFound").into());
    };
    assert!(
        matches!(err, settings::SecretServiceError::NotFound),
        "未注册 ref → NotFound，实际得 {err:?}"
    );

    Ok(())
}
