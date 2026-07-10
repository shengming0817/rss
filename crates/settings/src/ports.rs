//! settings::ports — 配置域**专属** repo / UoW DI port（Option 2 / ADR-005）。
//!
//! 归属（ADR-005 category line）：provider-agnostic 基建 port（`Clock`/`Publisher`/`AuditSink`…）在
//! `diport`；**域形** repo / UoW port——签名引用域内实体（`ConfigEntry`/`SettingKey`，域 crate `pub` 类型、
//! 字段私有 + 构造 funnel）——**无法**收敛 `diport`（否则 diport→域 反向依赖、层序倒置、deny 红），故归
//! 本域 crate `ports` 模块。adapter（如 `postgres`）依赖 `settings`、以 native AFIT impl 本 port（DIP 内向边，
//! `adapters→域` 单向）。派发与 diport DI port 同范式：`#[trait_variant::make(X: Send)]` Send 变体 +
//! `#[dynosaur(...)]` `DynX`，构造器注入 `Box<DynConfigRepo>` / `Box<DynConfigUnitOfWork>`（ADR-004 C1/C5）。
//!
//! 跨 crate 可见性：repo / UoW port 须 `pub`（独立 adapter crate impl）；签名实体 `ConfigEntry`/`SettingKey`/
//! `SettingsError`/`ConfigRepoError` 经下方 `pub use` 暴露——字段私有 + 构造经 `pub(crate)` funnel，外部可
//! 命名/收发但**不可伪造**。`ConfigVersion`（pub(crate)）不入签名——版本号在 wire/port 面以裸 `u64` 表达。
//!
//! 错误分层（#1226）：repo / UoW 返回 [`ConfigRepoError`]（业务 `VersionConflict` + 基础设施 `Storage`）；
//! 域**校验**错误 `SettingsError`（key 格式 / 百分比）属构造 funnel，不出现在仓储签名。
//!
//! ref: Cockburn Hexagonal Ports&Adapters / Evans DDD Repository（repo 接口归域核心、adapter 经 DIP 实现）
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型：save 以 version+1 守乐观并发）
//! ref: debezium outbox SMT / MassTransit Bus Outbox（业务写 + outbox 行同一本地事务，producer 侧 durable）

use consistency::EventEntry;
use diport::OutboxEnvelopeParts;
use dynosaur::dynosaur;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造器仍 `pub(crate)` funnel）。
pub use crate::domain::{
    ConfigEntry, ConfigHead, ConfigMutation, ConfigRepoError, ConfigTombstone, SettingKey,
    SettingsError,
};
pub use crate::domain::{SecretEntry, SecretKey, SecretRef, SecretRepoError, StoreId};
pub use vocab::TenantId;

/// Tenant-scoped repo capability for settings storage ports.
///
/// The raw tenant id is readable for SQL/RLS lowering, but construction is kept inside this crate
/// except for test-support builds. External callers cannot pass a bare [`TenantId`] or fabricate a
/// scope with a struct literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantRepoScope {
    tenant: TenantId,
    _seal: (),
}

impl TenantRepoScope {
    /// Domain-internal constructor from an already authenticated tenant claim.
    pub(crate) fn from_authenticated_tenant(tenant: TenantId) -> Self {
        Self { tenant, _seal: () }
    }

    /// Read the tenant carried by this repo capability.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Test/dev-only constructor for downstream adapter conformance tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(tenant: TenantId) -> Self {
        Self { tenant, _seal: () }
    }
}

/// Non-cross-tenant row-scoped repo capability for settings rows.
///
/// It only wraps [`vocab::ScopedTenant`]-derived visibility, so `RowScope::All` cannot enter normal
/// row-scoped repo signatures.
pub struct RowRepoScope {
    visibility: vocab::RowVisibility,
    _seal: (),
}

impl RowRepoScope {
    #[allow(dead_code)]
    pub(crate) fn from_scoped_visibility(
        scope: vocab::ScopedTenant,
        tenant: TenantRepoScope,
    ) -> Self {
        Self {
            visibility: vocab::RowVisibility::new(scope, tenant.tenant()),
            _seal: (),
        }
    }

    pub fn visibility(&self) -> &vocab::RowVisibility {
        &self.visibility
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(scope: vocab::ScopedTenant, tenant: TenantRepoScope) -> Self {
        Self::from_scoped_visibility(scope, tenant)
    }
}

/// 版本化配置仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`ConfigRepo`] 是 **Send 变体**（adapter `impl ConfigRepo for ...`），[`DynConfigRepo`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynConfigRepo>` 注入）。版本以 `u64` 表达（不裸传内部
/// `ConfigVersion`），租户必经 [`TenantRepoScope`] opaque handle 做 RLS / store scope（多租隔离签名承载）。
///
/// 本端口只暴露读取能力；CAS mutation 与同事务 outbox append 只能由 sibling [`ConfigUnitOfWork`] 承载。
#[trait_variant::make(ConfigRepo: Send)]
#[dynosaur(pub DynConfigRepo = dyn(box) ConfigRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `ConfigRepo` 变体 + dynosaur
// `DynConfigRepo` 承载（DI 注入走 Send wrapper）。与 diport DI port 同范式（ADR-003/ADR-004 C1）。
// `Send + Sync` supertrait（#1430）：`SettingsService` 作 axum handler 共享 state（`Arc<SettingsService>`）
// 须跨线程共享 `DynConfigRepo`——identity ports 同约定（跨 handler 共享端口在基 trait 加 Send+Sync）。
pub trait ConfigRepoLocal: Send + Sync {
    /// 取 key 当前活跃配置（最高版本且**非 tombstone**）；不存在 / 已删（latest 为 tombstone）返回 `Ok(None)`。
    async fn find(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError>;

    /// 取指定版本号的历史配置条目；不存在 / 该版本是 tombstone 返回 `Ok(None)`（回滚读取旧值用）。
    async fn find_version(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError>;

    /// 取 key 当前**最高版本号**（含 tombstone，不存在返回 `Ok(None)`）——业务层据此算下一版本（`+1`）。
    ///
    /// 与 [`ConfigRepo::find`] 区别：`find` 返回**活跃值**（tombstone ⇒ `None`），本方法返回**版本计数器**
    /// （含 tombstone）——delete tombstone 使 version 单调不重置（#1249 F1），故 next-version 不能用 `find`
    /// （删后 `find=None` 会误判 v1、复用 event_id），须用本方法的真实最高版本。
    async fn head(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<Option<ConfigHead>, ConfigRepoError>;
}

/// 配置写入 **co-tx** Unit-of-Work DI port（L2 OutboxFact 同事务接缝）。
///
/// [`ConfigUnitOfWork::commit`] 把 CAS 配置 mutation 与
/// `settings.config-version-changed` outbox 行 append **同一本地事务**原子落库（both-or-neither）——消除
/// 「先 save 后 emit」的 write-without-event 窗口（#1232）。`outbox_entry` / `envelope` 由应用层内容派生
/// 构造（topic / IdemKey / opaque subjectId），adapter 仅在事务内复用既有 `append_outbox` 落 durable outbox；
/// relay 异步投递（at-least-once + 幂等去重）。provider 可换：prod postgres co-tx / test in-mem。
///
/// 与 [`ConfigRepo`] 同 native-AFIT + trait_variant Send + dynosaur 范式；组合根经 `Box<DynConfigUnitOfWork>` 注入。
#[trait_variant::make(ConfigUnitOfWork: Send)]
#[dynosaur(pub DynConfigUnitOfWork = dyn(box) ConfigUnitOfWork, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: 同 ConfigRepoLocal——Send 由 trait_variant `ConfigUnitOfWork` 变体 + dynosaur wrapper 承载。
// `Send + Sync` supertrait（#1430）：随 `SettingsService` 作 axum handler 共享 state（同 ConfigRepoLocal 约定）。
pub trait ConfigUnitOfWorkLocal: Send + Sync {
    /// CAS 写新配置版本 + 同事务 append outbox 行（both-or-neither）。CAS 冲突返
    /// [`ConfigRepoError::VersionConflict`]、持久化失败返 [`ConfigRepoError::Storage`]；任一步失败整事务
    /// 回滚（配置写与 outbox 行皆不落库）。
    async fn commit(
        &self,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        outbox_entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError>;
}

/// secret 引用仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`SecretRepo`] 是 **Send 变体**，[`DynSecretRepo`] 是其 dyn-compatible wrapper
/// （组合根经 `Box<DynSecretRepo>` 注入）。租户必经 [`TenantRepoScope`] opaque handle 做 RLS 分隔。
///
/// **无 resolve**：secret 材料解析是 diport seam（`diport::SecretResolver`），不在此 port。
/// **无 UoW**：secret 写入是 L1 本地事务，不需与 outbox 同事务（与 config 的 L2 OutboxFact 分叉）。
///
/// CAS 语义：`save` 要求 `entry.version()` = 当前最高版本 + 1
/// （首版要求 `1`），否则 [`SecretRepoError::VersionConflict`]。tombstone 软删使 version 单调不重置。
#[trait_variant::make(SecretRepo: Send)]
#[dynosaur(pub DynSecretRepo = dyn(box) SecretRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: 同 ConfigRepoLocal——Send 由 trait_variant `SecretRepo` 变体 + dynosaur wrapper 承载。
// `Send + Sync` supertrait（#1430）：随 `SecretService` 作 axum handler 共享 state（同 ConfigRepoLocal 约定）。
pub trait SecretRepoLocal: Send + Sync {
    /// 取 key 当前活跃 secret 引用（最高版本且非 tombstone）；不存在 / 已删返回 `Ok(None)`。
    async fn find(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
    ) -> Result<Option<SecretEntry>, SecretRepoError>;

    /// 取指定版本号的历史条目；不存在 / 该版本是 tombstone 返回 `Ok(None)`。
    async fn find_version(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretEntry>, SecretRepoError>;

    /// 取 key 当前**最高版本号**（含 tombstone，不存在返回 `Ok(None)`）。
    async fn latest_version(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
    ) -> Result<Option<u64>, SecretRepoError>;

    /// CAS 追加新版本（`entry.version()` 须等于当前最高版本 + 1，否则 `VersionConflict`）。
    async fn save(&self, scope: TenantRepoScope, entry: SecretEntry)
    -> Result<(), SecretRepoError>;

    /// 软删除 key（tombstone）：version 单调不重置；幂等（latest 已 tombstone / key 不存在 ⇒ no-op）。
    async fn delete(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<(), SecretRepoError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：域形 async repo / UoW port 可 native-AFIT impl + mockall mock（非 `#[async_trait]`）均经
    //! `Box<DynX>` 装入（PORT-SHAPE-01/02）。不调用方法 → 不依赖具体存储语义。
    use consistency::EventEntry;
    use diport::OutboxEnvelopeParts;

    use super::{
        ConfigEntry, ConfigHead, ConfigMutation, ConfigRepo, ConfigRepoError, ConfigUnitOfWork,
        DynConfigRepo, DynConfigUnitOfWork, SettingKey, TenantRepoScope,
    };

    struct NoopConfigRepo;
    impl ConfigRepo for NoopConfigRepo {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _key: &SettingKey,
        ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
            Ok(None)
        }
        async fn find_version(
            &self,
            _scope: TenantRepoScope,
            _key: &SettingKey,
            _version: u64,
        ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
            Ok(None)
        }
        async fn head(
            &self,
            _scope: TenantRepoScope,
            _key: &SettingKey,
        ) -> Result<Option<ConfigHead>, ConfigRepoError> {
            Ok(None)
        }
    }

    struct NoopConfigUow;
    impl ConfigUnitOfWork for NoopConfigUow {
        async fn commit(
            &self,
            _scope: TenantRepoScope,
            _mutation: ConfigMutation,
            _outbox_entry: EventEntry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<(), ConfigRepoError> {
            Ok(())
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体且 wrapper `Send`。
    #[test]
    fn config_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynConfigRepo> = DynConfigRepo::new_box(NoopConfigRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynConfigRepo> = DynConfigRepo::new_box(MockTestConfigRepo::new());
        assert_send(&from_mock);
    }

    #[test]
    fn config_uow_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynConfigUnitOfWork> = DynConfigUnitOfWork::new_box(NoopConfigUow);
        assert_send(&from_impl);
        let from_mock: Box<DynConfigUnitOfWork> =
            DynConfigUnitOfWork::new_box(MockTestConfigUow::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——test-only service 把 `Box<DynConfigRepo>` /
    // `Box<DynConfigUnitOfWork>` 作必填位置参（非 Option），缺失即编译错误（ADR-004 C5）。
    struct ConfigService {
        _repo: Box<DynConfigRepo<'static>>,
        _writer: Box<DynConfigUnitOfWork<'static>>,
    }
    impl ConfigService {
        fn new(
            repo: Box<DynConfigRepo<'static>>,
            writer: Box<DynConfigUnitOfWork<'static>>,
        ) -> Self {
            Self {
                _repo: repo,
                _writer: writer,
            }
        }
    }

    #[test]
    fn config_ports_are_required_ctor_injectable() {
        let svc = ConfigService::new(
            DynConfigRepo::new_box(NoopConfigRepo),
            DynConfigUnitOfWork::new_box(NoopConfigUow),
        );
        assert_send(&svc._repo);
        assert_send(&svc._writer);
        let svc_mock = ConfigService::new(
            DynConfigRepo::new_box(MockTestConfigRepo::new()),
            DynConfigUnitOfWork::new_box(MockTestConfigUow::new()),
        );
        assert_send(&svc_mock._repo);
        assert_send(&svc_mock._writer);
    }

    // mock 是 native trait impl（`async fn` 直接声明，非 `#[async_trait]`），经 `new_box` 进 dyn wrapper。
    mockall::mock! {
        TestConfigRepo {}
        impl ConfigRepo for TestConfigRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError>;
            async fn find_version(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError>;
            async fn head(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigHead>, ConfigRepoError>;
        }
    }

    mockall::mock! {
        TestConfigUow {}
        impl ConfigUnitOfWork for TestConfigUow {
            async fn commit(
                &self,
                scope: TenantRepoScope,
                mutation: ConfigMutation,
                outbox_entry: EventEntry,
                envelope: OutboxEnvelopeParts,
            ) -> Result<(), ConfigRepoError>;
        }
    }

    // ---------------------------------------------------------------------------
    // SecretRepo smoke
    // ---------------------------------------------------------------------------

    use super::{DynSecretRepo, SecretEntry, SecretKey, SecretRepo, SecretRepoError};

    struct NoopSecretRepo;
    impl SecretRepo for NoopSecretRepo {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
        ) -> Result<Option<SecretEntry>, SecretRepoError> {
            Ok(None)
        }
        async fn find_version(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
            _version: u64,
        ) -> Result<Option<SecretEntry>, SecretRepoError> {
            Ok(None)
        }
        async fn latest_version(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
        ) -> Result<Option<u64>, SecretRepoError> {
            Ok(None)
        }
        async fn save(
            &self,
            _scope: TenantRepoScope,
            _entry: SecretEntry,
        ) -> Result<(), SecretRepoError> {
            Ok(())
        }
        async fn delete(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
        ) -> Result<(), SecretRepoError> {
            Ok(())
        }
    }

    // PORT-SHAPE-03：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体且 wrapper `Send`。
    #[test]
    fn secret_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynSecretRepo> = DynSecretRepo::new_box(NoopSecretRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynSecretRepo> = DynSecretRepo::new_box(MockTestSecretRepo::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-04：消费侧构造器必填位置参注入（ADR-004 C5）。
    struct SecretService {
        _repo: Box<DynSecretRepo<'static>>,
    }
    impl SecretService {
        fn new(repo: Box<DynSecretRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn secret_repo_is_required_ctor_injectable() {
        let svc = SecretService::new(DynSecretRepo::new_box(NoopSecretRepo));
        assert_send(&svc._repo);
        let svc_mock = SecretService::new(DynSecretRepo::new_box(MockTestSecretRepo::new()));
        assert_send(&svc_mock._repo);
    }

    mockall::mock! {
        TestSecretRepo {}
        impl SecretRepo for TestSecretRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                key: &SecretKey,
            ) -> Result<Option<SecretEntry>, SecretRepoError>;
            async fn find_version(
                &self,
                scope: TenantRepoScope,
                key: &SecretKey,
                version: u64,
            ) -> Result<Option<SecretEntry>, SecretRepoError>;
            async fn latest_version(
                &self,
                scope: TenantRepoScope,
                key: &SecretKey,
            ) -> Result<Option<u64>, SecretRepoError>;
            async fn save(&self, scope: TenantRepoScope, entry: SecretEntry) -> Result<(), SecretRepoError>;
            async fn delete(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<(), SecretRepoError>;
        }
    }
}
