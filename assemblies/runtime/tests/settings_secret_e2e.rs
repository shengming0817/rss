//! settings secret e2e 集成测试（`integration` feature 门控；需真实 postgres）。
//!
//! 覆盖路径：`SecretService::with_postgres(PgSecretRepo, InlineMemResolver, FixedClock)` over 真实 pg：
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use diport::{Clock, DynSecretResolver, SecretCoordinate, SecretMaterial, SecretResolverError};
use postgres::{PgConfig, PgError, PgPassword, PgRuntimeDeps, PgSslMode, caps};
use settings::SecretService;
use settings::ports::{SecretKey, SecretRef, StoreId, TenantId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};

// ── 测试用常量 ────────────────────────────────────────────────────────────────

const TENANT_STR: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const STORE_ID: &str = "mem-vault";
const TEST_APP_ROLE: &str = "rss_settings_secret_e2e_app";
const TEST_APP_PASSWORD: &str = "settings_secret_e2e_pw";

// ── inline MemResolver（deny.toml 禁 rss→memory，故在本文件内直接实现）──────────

/// in-test 内存 secret 解析替身（非 memory crate；仅测试使用）。
///
/// 键 = `(tenant_uuid_str, store_id, ref_key)`，命中返 `SecretMaterial`，未命中返 `NotFound`。
struct InlineMemResolver {
    store: Arc<Mutex<HashMap<(String, String, String), Vec<u8>>>>,
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

// ── 测试辅助 ──────────────────────────────────────────────────────────────────

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[allow(clippy::expect_used)]
fn tenant() -> TenantId {
    TenantId::parse(TENANT_STR).expect("canonical tenant")
}

/// 生成每次测试唯一的 secret key（防跨测试污染，无需 DELETE FROM secret_refs）。
fn unique_key(prefix: &str) -> SecretKey {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    #[allow(clippy::expect_used)]
    SecretKey::parse(&format!("e2e.{prefix}-{nanos}")).expect("valid unique key")
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

/// 构造 SecretService（真 PgSecretRepo via settings 域受控句柄 + InlineMemResolver + FixedClock）。
fn make_service(deps: &PgRuntimeDeps, resolver: InlineMemResolver) -> SecretService {
    // settings bundle 产出 secret box（本 e2e 不消费 read/write config）。
    let (_configs, _writer, secrets) = deps
        .for_domain::<caps::Settings>()
        .settings_bundle(Arc::new(FixedClock))
        .into_parts();
    SecretService::with_postgres(
        secrets,
        DynSecretResolver::new_box(resolver),
        Box::new(FixedClock),
    )
}

// ── e2e 测试 ─────────────────────────────────────────────────────────────────

/// e2e-s1：publish_secret → find_secret_ref roundtrip（PgSecretRepo 读写闭合）。
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

    let err = svc
        .resolve_secret(tenant(), &key)
        .await
        .expect_err("should fail with NotFound");
    assert!(
        matches!(err, settings::SecretServiceError::NotFound),
        "未注册 ref → NotFound，实际得 {err:?}"
    );

    Ok(())
}
