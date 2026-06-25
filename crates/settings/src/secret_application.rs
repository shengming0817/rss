//! settings secret 应用层：secret 引用 CAS CRUD + 按坐标 resolve 材料（L1 本地事务，无 outbox）。
//!
//! [`SecretService`] 持 [`crate::ports::SecretRepo`]（坐标存储）+
//! [`diport::SecretResolver`]（材料解析，fail-closed）+ [`diport::Clock`]（保留供未来扩展，当前未使用）。
//! 版本 CAS 逻辑镜像 [`crate::application::SettingsService`]，差异：L1 无 outbox / 无 UoW。
//!
//! # 安全语义
//!
//! - `resolve_secret`：每次调用均对 resolver 发起一次 fresh 解析，**绝不缓存材料**（fail-closed 契约）。
//! - tombstone 软删使 version 单调不重置（与 ConfigRepo F1 同逻辑）。
//!
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型）
//! ref: external-secrets/external-secrets api/v1beta1/secretstore_types.go（SecretResolver 对标）

use diport::{Clock, DynSecretResolver, SecretMaterial, SecretResolver};
use vocab::TenantId;

use crate::domain::{
    SecretEntry, SecretKey, SecretRef, SecretRepoError, SecretVersion, SettingsError,
};
use crate::ports::{DynSecretRepo, SecretRepo};

#[cfg(test)]
use crate::internal::mem::{InMemSecretRepo, new_secret_store};

/// 错误消息常量（`&'static str` const literal，不拼 runtime 数据，符合 error-handling.md §Message 与 PII）。
const MSG_STORAGE: &str = "secret storage failed";
const MSG_NOT_FOUND: &str = "secret entry not found";
const MSG_VERSION_NOT_FOUND: &str = "secret version not found";
const MSG_FORBIDDEN: &str = "secret access forbidden";
const MSG_STORE_UNAVAILABLE: &str = "secret store unavailable";
const MSG_VERSION_CONFLICT: &str = "secret version conflict";
const MSG_INVALID_KEY: &str = "secret key is invalid";

/// secret 应用层错误（库错误枚举，不含 HTTP 状态码——handler 层映射）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretServiceError {
    /// 键格式非法。
    #[error("{}", MSG_INVALID_KEY)]
    InvalidKey,
    /// 乐观并发写冲突（读后被并发版本超前）。
    #[error("{}", MSG_VERSION_CONFLICT)]
    VersionConflict,
    /// 目标 secret / 版本不存在。
    #[error("{}", MSG_NOT_FOUND)]
    NotFound,
    /// 目标 secret 版本不存在（key 存在但无此版本）。
    #[error("{}", MSG_VERSION_NOT_FOUND)]
    VersionNotFound,
    /// 对 secret 无访问权限（IAM / allowlist 拒绝）。
    #[error("{}", MSG_FORBIDDEN)]
    SecretForbidden,
    /// secret store 不可达 / 超时（5xx 语义，fail-closed）。
    #[error("{}", MSG_STORE_UNAVAILABLE)]
    SecretStoreUnavailable,
    /// 底层仓储持久化失败。
    #[error("{}", MSG_STORAGE)]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<SettingsError> for SecretServiceError {
    fn from(e: SettingsError) -> Self {
        match e {
            SettingsError::SecretKeyInvalid | SettingsError::SecretRefInvalid => Self::InvalidKey,
            // 配置键错误同属 4xx 客户端输入（完整性守卫）。
            SettingsError::KeyInvalid | SettingsError::SensitiveKey => Self::InvalidKey,
            SettingsError::PercentageOutOfRange => Self::InvalidKey,
        }
    }
}

impl From<SecretRepoError> for SecretServiceError {
    fn from(e: SecretRepoError) -> Self {
        match e {
            SecretRepoError::VersionConflict => Self::VersionConflict,
            SecretRepoError::Storage(src) => Self::Storage(src),
        }
    }
}

impl From<diport::SecretResolverError> for SecretServiceError {
    fn from(e: diport::SecretResolverError) -> Self {
        use diport::SecretResolverError as R;
        match e {
            R::StoreUnreachable { .. } | R::Timeout => Self::SecretStoreUnavailable,
            R::NotFound | R::VersionNotFound => Self::NotFound,
            R::Forbidden => Self::SecretForbidden,
            // non_exhaustive 未知变体 → fail-closed 不可达
            _ => Self::SecretStoreUnavailable,
        }
    }
}

/// 将 domain `SecretRef` 坐标转换为 `diport::SecretCoordinate`（应用层 adapter 函数）。
///
/// domain 层不依赖 diport；此自由函数在 application 层完成跨层转换，是 resolver 调用前的唯一桥接点。
/// （Finding 7：从 `SecretRef::to_coordinate` 提升到 application 层，去除 domain→diport 依赖。）
fn secret_ref_to_coordinate(r: &SecretRef) -> diport::SecretCoordinate {
    diport::SecretCoordinate::new(
        r.store_id().as_str(),
        r.ref_key(),
        r.ref_version().map(str::to_owned),
    )
}

/// settings secret 应用服务（L1 本地事务，无 outbox）。
///
/// 必填依赖走构造器位置参（缺失即编译错误）：`secrets`（坐标仓储）、`resolver`（材料解析 provider）、
/// `clock`（保留位置参，未来扩展审计时间戳用，当前未使用）。
///
/// # fail-closed 契约
///
/// `resolve_secret` 每次均发起 fresh resolver 调用，绝不缓存材料——零信任边界要求 secret 读取须 fresh。
pub struct SecretService {
    secrets: Box<DynSecretRepo<'static>>,
    resolver: Box<DynSecretResolver<'static>>,
    // reason: Clock 是构造器必填位置参（rust-standards §Clock 构造器位置参）；当前未使用字段，
    // 保留为未来 publish_secret 审计时间戳扩展点，不删除——删除需改构造器签名（breaking change）。
    #[allow(dead_code)]
    clock: Box<dyn Clock>,
}

impl SecretService {
    /// 生产构造器（非门控 `pub`，组合根注入真实 postgres provider + Vault resolver）。
    ///
    /// `clock` 是构造器位置参（rust-standards §Clock 构造器位置参），生产传 `SystemClock`。
    pub fn with_postgres(
        secrets: Box<DynSecretRepo<'static>>,
        resolver: Box<DynSecretResolver<'static>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            secrets,
            resolver,
            clock,
        }
    }

    /// 测试 / seed-data 构造器（同参数，门控于 `test` / `seed-data`）。
    // reason: 测试场景注入 in-mem 替身用；seed-data 生产模式暂未接线（生产走 with_postgres）。
    #[allow(dead_code)]
    #[cfg(any(test, feature = "seed-data"))]
    pub(crate) fn new(
        secrets: Box<DynSecretRepo<'static>>,
        resolver: Box<DynSecretResolver<'static>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            secrets,
            resolver,
            clock,
        }
    }

    /// 当前 secret key 的下一版本号（无历史 → 1）。
    ///
    /// 与 `SettingsService::next_version` 同逻辑：使用 `latest_version`（含 tombstone）而非 `find`，
    /// 保证 delete 后 version 单调不重置（防 event_id 复用，对齐 #1249 F1）。
    async fn next_version(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<u64, SecretServiceError> {
        let current = self.secrets.latest_version(tenant, key).await?;
        Ok(current.map_or(1, |v| v + 1))
    }

    /// 写入新 secret 引用版本（CAS，L1 本地事务）。
    ///
    /// 返回新版本号。并发冲突冒泡 `VersionConflict`。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn publish_secret(
        &self,
        tenant: TenantId,
        key: SecretKey,
        secret_ref: SecretRef,
    ) -> Result<u64, SecretServiceError> {
        let version = self.next_version(tenant, &key).await?;
        let entry = SecretEntry::new(key, secret_ref, tenant, SecretVersion::new(version));
        self.secrets.save(tenant, entry).await?;
        Ok(version)
    }

    /// 读取当前活跃 secret 引用（不存在返回 `Ok(None)`）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn find_secret_ref(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<Option<SecretRef>, SecretServiceError> {
        Ok(self
            .secrets
            .find(tenant, key)
            .await?
            .map(|entry| entry.secret_ref().clone()))
    }

    /// 读取指定版本的 secret 引用（不存在 / tombstone 返回 `Ok(None)`）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn find_secret_version(
        &self,
        tenant: TenantId,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretRef>, SecretServiceError> {
        Ok(self
            .secrets
            .find_version(tenant, key, version)
            .await?
            .map(|entry| entry.secret_ref().clone()))
    }

    /// 回滚：以 `to_version` 的引用重新发布（生成新版本，无事件）。
    ///
    /// 源版本不存在返回 `SecretServiceError::NotFound`。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn rollback_secret(
        &self,
        tenant: TenantId,
        key: &SecretKey,
        to_version: u64,
    ) -> Result<u64, SecretServiceError> {
        let source_ref = self
            .secrets
            .find_version(tenant, key, to_version)
            .await?
            .ok_or(SecretServiceError::NotFound)?
            .secret_ref()
            .clone();
        self.publish_secret(tenant, key.clone(), source_ref).await
    }

    /// 软删除 secret 引用（tombstone 语义：版本单调不重置；幂等——key 不存在 / 已删 → no-op）。
    ///
    /// 删除后 `find_secret_ref` 返 `None`；历史版本仍可经 `find_secret_version` 查询。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn delete_secret(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<(), SecretServiceError> {
        self.secrets.delete(tenant, key).await.map_err(Into::into)
    }

    /// 按 secret 引用解析材料（每次 fresh 调用 resolver，绝不缓存）。
    ///
    /// fail-closed：找不到引用返 `NotFound`；resolver 返错误经 `From` 映射。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn resolve_secret(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<SecretMaterial, SecretServiceError> {
        let secret_ref = self
            .find_secret_ref(tenant, key)
            .await?
            .ok_or(SecretServiceError::NotFound)?;
        let coord = secret_ref_to_coordinate(&secret_ref);
        // fail-closed：resolver 报错直接冒泡，绝不降级返空材料。
        let material = self.resolver.resolve(tenant, &coord).await?;
        Ok(material)
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use diport::{DynSecretResolver, SecretCoordinate, SecretMaterial, SecretResolverError};
    use vocab::TenantId;

    use super::*;
    use crate::domain::{SecretKey, SecretRef, StoreId};
    use crate::ports::DynSecretRepo;

    const TENANT_STR: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B_STR: &str = "00000000-0000-4000-8000-000000000abc";

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(TENANT_STR).expect("canonical uuid")
    }

    #[allow(clippy::expect_used)]
    fn tenant_b() -> TenantId {
        TenantId::parse(TENANT_B_STR).expect("canonical uuid")
    }

    #[allow(clippy::expect_used)]
    fn make_key(s: &str) -> SecretKey {
        SecretKey::parse(s).expect("valid secret key")
    }

    #[allow(clippy::expect_used)]
    fn make_ref(store: &str, path: &str) -> SecretRef {
        let sid = StoreId::parse(store).expect("valid store id");
        SecretRef::parse(sid, path, None).expect("valid secret ref")
    }

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn fixed_clock() -> Box<dyn Clock> {
        Box::new(FixedClock(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        ))
    }

    // mockall mock for SecretResolver（域 crate 单测不依赖 adapter crate）。
    mockall::mock! {
        pub TestSecretResolver {}
        impl diport::SecretResolver for TestSecretResolver {
            async fn resolve(
                &self,
                tenant: TenantId,
                coord: &SecretCoordinate,
            ) -> Result<SecretMaterial, SecretResolverError>;
        }
    }

    fn service_with_mock_resolver(mock: MockTestSecretResolver) -> SecretService {
        let store = new_secret_store();
        SecretService::new(
            DynSecretRepo::new_box(InMemSecretRepo::from_shared(store)),
            DynSecretResolver::new_box(mock),
            fixed_clock(),
        )
    }

    fn plain_service() -> SecretService {
        let mut mock = MockTestSecretResolver::new();
        // 默认 resolver：happy path 返回固定材料。
        mock.expect_resolve()
            .returning(|_, _| Ok(SecretMaterial::new(b"material".to_vec())));
        service_with_mock_resolver(mock)
    }

    // ── resolve_secret：resolver 恰调一次 ─────────────────────────────────────────────────

    /// resolve_secret 对 resolver 恰好调用一次（`.times(1)`）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_calls_resolver_exactly_once() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .times(1)
            .returning(|_, _| Ok(SecretMaterial::new(b"mat".to_vec())));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("store1", "db/pw"))
            .await
            .expect("publish ok");
        let _mat = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect("resolve ok");
        // mock::times(1) 在 drop 时 assert，无需额外调用。
    }

    /// store 不可达 → `SecretStoreUnavailable`（fail-closed）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_store_unreachable_is_err() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve().returning(|_, _| {
            Err(SecretResolverError::store_unreachable(
                std::io::Error::other("down"),
            ))
        });
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("expect err");
        assert!(
            matches!(err, SecretServiceError::SecretStoreUnavailable),
            "got {err:?}"
        );
    }

    /// resolver 返 NotFound → `SecretServiceError::NotFound` 映射。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_not_found_maps() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Err(SecretResolverError::NotFound));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::NotFound));
    }

    /// resolver 返 Forbidden → `SecretForbidden` 映射。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_forbidden_maps() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Err(SecretResolverError::Forbidden));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::SecretForbidden));
    }

    /// resolver 返 Timeout → `SecretStoreUnavailable` 映射。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_timeout_maps_to_store_unavailable() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Err(SecretResolverError::Timeout));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::SecretStoreUnavailable));
    }

    /// 正常 resolve → 返回 material（happy path）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_happy_returns_material() {
        let expected = b"my-secret-bytes";
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Ok(SecretMaterial::new(expected.to_vec())));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let mat = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect("resolve ok");
        assert_eq!(mat.expose(), expected);
    }

    /// 两次 resolve → resolver 被调用两次（绝不缓存）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_never_caches() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .times(2)
            .returning(|_, _| Ok(SecretMaterial::new(b"mat".to_vec())));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let _ = svc.resolve_secret(tenant(), &make_key("vault.db")).await;
        let _ = svc.resolve_secret(tenant(), &make_key("vault.db")).await;
        // mock::times(2) 在 drop 时 assert。
    }

    // ── publish / find roundtrip ──────────────────────────────────────────────────────────

    /// publish 后 find_secret_ref 能读到已存引用。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_then_find_roundtrip() {
        let svc = plain_service();
        let key = make_key("vault.db");
        let secret_ref = make_ref("store1", "db/password");
        let version = svc
            .publish_secret(tenant(), key.clone(), secret_ref.clone())
            .await
            .expect("publish ok");
        assert_eq!(version, 1, "首次 publish 版本号应为 1");

        let found = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(found, Some(secret_ref));
    }

    /// 找不到 secret key 时 resolve_secret 返 NotFound（非 resolver 调用）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_key_not_found_returns_not_found() {
        // resolver 不应被调用（引用都找不到），故用 times(0) mock。
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve().times(0);
        let svc = service_with_mock_resolver(mock);

        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::NotFound));
    }

    // ── rollback ──────────────────────────────────────────────────────────────────────────

    /// rollback 创建新版本（版本号递增）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_secret_creates_new_version() {
        let svc = plain_service();
        let key = make_key("vault.db");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "v1"))
            .await
            .expect("v1");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "v2"))
            .await
            .expect("v2");

        let v3 = svc
            .rollback_secret(tenant(), &key, 1)
            .await
            .expect("rollback ok");
        assert_eq!(v3, 3, "回滚应生成新版本 v3");

        // 活跃引用回到 v1 的 ref。
        let current_ref = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(current_ref, Some(make_ref("s", "v1")));
    }

    /// rollback 找不到源版本 → NotFound。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_missing_version_is_not_found() {
        let svc = plain_service();
        let key = make_key("vault.db");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("v1");
        let err = svc
            .rollback_secret(tenant(), &key, 99)
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::NotFound));
    }

    // ── 构造器必填参数（编译锁）────────────────────────────────────────────────────────────

    /// 编译锁：`SecretService::with_postgres` 须接受三个必填位置参（类型签名断言）。
    #[test]
    fn secret_service_ctor_required_params() {
        // 绑定函数指针断言签名——缺参 / 类型不符即编译失败（ADR-004 C5）。
        let _ctor: fn(
            Box<DynSecretRepo<'static>>,
            Box<DynSecretResolver<'static>>,
            Box<dyn Clock>,
        ) -> SecretService = SecretService::with_postgres;
        let _ = _ctor;
    }

    // ── cross-tenant 隔离 ─────────────────────────────────────────────────────────────────

    /// tenant_a publish，tenant_b find_secret_ref 返 None。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cross_tenant_isolation() {
        let svc = plain_service();
        let key = make_key("vault.db");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("publish");
        let found = svc.find_secret_ref(tenant_b(), &key).await.expect("find");
        assert_eq!(
            found, None,
            "跨租户隔离：tenant_b 不应读到 tenant_a 的 secret"
        );
    }

    // ── Finding 5 补充测试 ────────────────────────────────────────────────────────────────

    /// `find_secret_version` 返回历史版本引用（非活跃版本）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn find_secret_version_returns_historical() {
        let svc = plain_service();
        let key = make_key("vault.db");
        let ref_v1 = make_ref("store1", "db/v1");
        let ref_v2 = make_ref("store1", "db/v2");

        svc.publish_secret(tenant(), key.clone(), ref_v1.clone())
            .await
            .expect("v1");
        svc.publish_secret(tenant(), key.clone(), ref_v2.clone())
            .await
            .expect("v2");

        // 当前活跃应是 v2。
        let current = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(current, Some(ref_v2), "活跃引用应为 v2");

        // 历史版本 v1 仍可按版本号查询。
        let historical = svc
            .find_secret_version(tenant(), &key, 1)
            .await
            .expect("find v1 ok");
        assert_eq!(historical, Some(ref_v1), "历史版本 v1 应可查");
    }

    /// 同一 key 两次 publish 版本号单调递增；再 publish 与上次引用相同也视为新版本。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_secret_version_monotonic() {
        let svc = plain_service();
        let key = make_key("vault.token");

        let v1 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "tk/v1"))
            .await
            .expect("v1");
        let v2 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "tk/v2"))
            .await
            .expect("v2");
        let v3 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "tk/v2"))
            .await
            .expect("v3 same ref");

        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
        assert_eq!(v3, 3, "再次 publish 应生成新版本（不去重）");
    }

    /// delete 后 find_secret_ref 返 None（tombstone 软删）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_then_find_secret_ref_none() {
        let svc = plain_service();
        let key = make_key("vault.db");

        svc.publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("publish");

        // 验证先能读到。
        let before = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert!(before.is_some(), "删除前应能读到引用");

        svc.delete_secret(tenant(), &key).await.expect("delete ok");

        let after = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(after, None, "删除后 find_secret_ref 应返 None");
    }

    /// delete 后 re-publish → 版本号单调不重置（新版本号 > 删除前版本号）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_then_republish_version_monotonic() {
        let svc = plain_service();
        let key = make_key("vault.db");

        let v1 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("v1");
        svc.delete_secret(tenant(), &key).await.expect("delete");

        let v2 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "k2"))
            .await
            .expect("re-publish");

        assert!(
            v2 > v1,
            "re-publish 版本号应大于删除前版本号（单调不重置）：v1={v1} v2={v2}"
        );
    }
}
