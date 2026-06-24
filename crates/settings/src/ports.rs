//! settings::ports — 配置域**专属** repo DI port（Option 2 / ADR-005）。
//!
//! 归属（ADR-005 category line）：provider-agnostic 基建 port（`Clock`/`Publisher`/`AuditSink`…）在
//! `diport`；**域形** repo port——签名引用域内实体（`ConfigEntry`/`SettingKey`，域 crate `pub` 类型、
//! 字段私有 + 构造 funnel）——**无法**收敛 `diport`（否则 diport→域 反向依赖、层序倒置、deny 红），故归
//! 本域 crate `ports` 模块。adapter（如 `postgres`）依赖 `settings`、以 native AFIT impl 本 port（DIP 内向边，
//! `adapters→域` 单向）。派发与 diport DI port 同范式：`#[trait_variant::make(X: Send)]` Send 变体 +
//! `#[dynosaur(...)]` `DynX`，构造器注入 `Box<DynConfigRepo>`（ADR-004 C1/C5）。
//!
//! 跨 crate 可见性：repo port 须 `pub`（独立 adapter crate impl）；签名实体 `ConfigEntry`/`SettingKey`/
//! `SettingsError` 经下方 `pub use` 暴露——字段私有 + 构造经 `pub(crate)` funnel，外部可命名/收发但**不可伪造**。
//! `ConfigVersion`（pub(crate)）不入签名——版本号在 wire/port 面以裸 `u64` 表达，避免泄漏内部 newtype。
//!
//! ref: Cockburn Hexagonal Ports&Adapters / Evans DDD Repository（repo 接口归域核心、adapter 经 DIP 实现）
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型：save 以 version+1 守乐观并发）

use dynosaur::dynosaur;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造器仍 `pub(crate)` funnel）。
pub use crate::domain::{ConfigEntry, SettingKey, SettingsError};
pub use vocab::TenantId;

/// 版本化配置仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`ConfigRepo`] 是 **Send 变体**（adapter `impl ConfigRepo for ...`），[`DynConfigRepo`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynConfigRepo>` 注入）。版本以 `u64` 表达（不裸传内部
/// `ConfigVersion`），租户必经 typed [`TenantId`] 位置参做 RLS / store scope（多租隔离签名承载）。
///
/// CAS 语义（etcd 版本模型）：[`ConfigRepo::save`] 要求 `entry.version()` 恰等于当前最高版本 + 1
/// （首版要求 `1`），否则返回 [`SettingsError::VersionConflict`]——乐观并发写冲突由业务层读后重写重试。
///
/// rollback 读旧版本 + 写新版本须由实现方保证原子（postgres adapter 同事务 find_version+save，防 TOCTOU）。
#[trait_variant::make(ConfigRepo: Send)]
#[dynosaur(pub DynConfigRepo = dyn(box) ConfigRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `ConfigRepo` 变体 + dynosaur
// `DynConfigRepo` 承载（DI 注入走 Send wrapper）。与 diport DI port 同范式（ADR-003/ADR-004 C1）。
pub trait ConfigRepoLocal {
    /// 取 key 当前（最高版本）活跃配置；不存在返回 `Ok(None)`。
    async fn find(
        &self,
        tenant: TenantId,
        key: &SettingKey,
    ) -> Result<Option<ConfigEntry>, SettingsError>;

    /// 取指定版本号的历史配置条目；不存在返回 `Ok(None)`（回滚读取旧值用）。
    async fn find_version(
        &self,
        tenant: TenantId,
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<ConfigEntry>, SettingsError>;

    /// CAS 追加新版本（`entry.version()` 须等于当前最高版本 + 1，否则 `VersionConflict`）。
    async fn save(&self, tenant: TenantId, entry: ConfigEntry) -> Result<(), SettingsError>;

    /// 硬删除 key 及其版本历史（幂等：不存在视为成功）。tombstone / 版本删除事件留订阅缓存单元（#1120）。
    async fn delete(&self, tenant: TenantId, key: &SettingKey) -> Result<(), SettingsError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：域形 async repo port 可 native-AFIT impl + mockall mock（非 `#[async_trait]`）均经
    //! `Box<DynConfigRepo>` 装入（PORT-SHAPE-01/02）。不调用方法 → 不依赖具体存储语义。
    use super::{ConfigEntry, ConfigRepo, DynConfigRepo, SettingKey, SettingsError, TenantId};

    struct NoopConfigRepo;
    impl ConfigRepo for NoopConfigRepo {
        async fn find(
            &self,
            _tenant: TenantId,
            _key: &SettingKey,
        ) -> Result<Option<ConfigEntry>, SettingsError> {
            Ok(None)
        }
        async fn find_version(
            &self,
            _tenant: TenantId,
            _key: &SettingKey,
            _version: u64,
        ) -> Result<Option<ConfigEntry>, SettingsError> {
            Ok(None)
        }
        async fn save(&self, _tenant: TenantId, _entry: ConfigEntry) -> Result<(), SettingsError> {
            Ok(())
        }
        async fn delete(&self, _tenant: TenantId, _key: &SettingKey) -> Result<(), SettingsError> {
            Ok(())
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体
    // `DynConfigRepo` 且 wrapper `Send`（可跨 spawn 注入）。
    #[test]
    fn config_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynConfigRepo> = DynConfigRepo::new_box(NoopConfigRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynConfigRepo> = DynConfigRepo::new_box(MockTestConfigRepo::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——test-only service 把 `Box<DynConfigRepo>` 作必填
    // 位置参（非 Option），缺失即编译错误（ADR-004 C5）。
    struct ConfigService {
        _repo: Box<DynConfigRepo<'static>>,
    }
    impl ConfigService {
        fn new(repo: Box<DynConfigRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn config_repo_is_required_ctor_injectable() {
        let from_impl = ConfigService::new(DynConfigRepo::new_box(NoopConfigRepo));
        assert_send(&from_impl._repo);
        let from_mock = ConfigService::new(DynConfigRepo::new_box(MockTestConfigRepo::new()));
        assert_send(&from_mock._repo);
    }

    // mock 是 native trait impl（`async fn` 直接声明，非 `#[async_trait]`），经 `new_box` 进 `DynConfigRepo`。
    mockall::mock! {
        TestConfigRepo {}
        impl ConfigRepo for TestConfigRepo {
            async fn find(
                &self,
                tenant: TenantId,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, SettingsError>;
            async fn find_version(
                &self,
                tenant: TenantId,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, SettingsError>;
            async fn save(&self, tenant: TenantId, entry: ConfigEntry) -> Result<(), SettingsError>;
            async fn delete(&self, tenant: TenantId, key: &SettingKey) -> Result<(), SettingsError>;
        }
    }
}
