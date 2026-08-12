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

use dynosaur::dynosaur;
use eventexec::event::ReviewedEvent;
use generated::http::settings_v2::{LOCAL_TX as SECRET_LOCAL_TX, ROUTE as SECRET_HTTP_ROUTE};

/// Exact generated fact binding authorized by every config producer receipt.
pub use generated::event::settings_v1::CONTRACT as CONFIG_VERSION_CHANGED_CONTRACT;

/// One-shot producer receipt for `settings.config-publish`.
pub type ConfigPublishReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::settings_v1::RouteMarker>;
/// One-shot producer receipt for `settings.config-delete`.
pub type ConfigDeleteReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::settings_v5::RouteMarker>;
/// One-shot producer receipt for `settings.config-rollback`.
pub type ConfigRollbackReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::settings_v6::RouteMarker>;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造器仍 `pub(crate)` funnel）。
pub use crate::domain::{
    ConfigEntry, ConfigHead, ConfigMutation, ConfigRepoError, ConfigTombstone, SettingKey,
    SettingsError,
};
pub use crate::domain::{SecretEntry, SecretKey, SecretRef, SecretRepoError, StoreId};
pub use crate::projection::{
    ActiveProjectionResolveError, ActiveProjectionSelection, ActiveProjectionSnapshot,
    SETTINGS_CONFIG_PROJECTION_ID, SettingsConfigProjectionRow, SettingsProjectionApplyError,
    SettingsProjectionApplyScope, SettingsProjectionBeginError, SettingsProjectionMetadataQuery,
    SettingsProjectionMutation, SettingsProjectionMutationError, SettingsProjectionQueryRequest,
    SettingsProjectionQueryService, SettingsProjectionReadScope, SettingsProjectionRepoError,
    SettingsProjectionRowError, SettingsProjectionScopeError,
    settings_projection_apply_from_validated,
};
pub use generated::event::settings_v1::SettingsConfigChangeKind;
use rss_request_context::TenantId;

/// Generated route marker retained by the HTTP secret-publish LocalTx command.
pub type SecretPublishRouteMarker = generated::http::settings_v2::RouteMarker;

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
/// It only wraps [`rss_request_context::RowScope`]-derived visibility, so `RowScope::All` cannot enter normal
/// row-scoped repo signatures.
pub struct RowRepoScope {
    visibility: vocab::RowVisibility,
    _seal: (),
}

impl RowRepoScope {
    #[allow(dead_code)]
    pub(crate) fn from_scoped_visibility(
        scope: rss_request_context::RowScope,
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
    pub fn for_test(scope: rss_request_context::RowScope, tenant: TenantRepoScope) -> Self {
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

/// Tenant-scoped current-state Settings metadata projection reader.
#[trait_variant::make(SettingsProjectionReadRepo: Send)]
#[dynosaur(pub DynSettingsProjectionReadRepo = dyn(box) SettingsProjectionReadRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait SettingsProjectionReadRepoLocal: Send + Sync {
    async fn find(
        &self,
        scope: SettingsProjectionReadScope,
        key: &SettingKey,
    ) -> Result<Option<SettingsConfigProjectionRow>, SettingsProjectionRepoError>;
}

/// Resolve the exact active Settings projection generation for one authenticated tenant scope.
#[trait_variant::make(ActiveProjectionResolver: Send)]
#[dynosaur(pub DynActiveProjectionResolver = dyn(box) ActiveProjectionResolver, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait ActiveProjectionResolverLocal: Send + Sync {
    async fn resolve(
        &self,
        scope: TenantRepoScope,
    ) -> Result<ActiveProjectionSelection, ActiveProjectionResolveError>;
}

/// 配置写入 **co-tx** Unit-of-Work DI port（L2 OutboxFact 同事务接缝）。
///
/// 三条 route-specific commit 方法把各自的 generated producer receipt、CAS 配置 mutation 与
/// `settings.config-version-changed` outbox 行 append **同一本地事务**原子落库（both-or-neither）——消除
/// 「先 save 后 emit」的 write-without-event 窗口（#1232）。应用层仅能经 generated sealed carrier
/// 构造 [`ReviewedEvent`]；adapter 在事务内消费其已审查的 fact/envelope primitives 并落 durable outbox；
/// relay 异步投递（at-least-once + 幂等去重）。provider 可换：prod postgres co-tx / test in-mem。
///
/// 与 [`ConfigRepo`] 同 native-AFIT + trait_variant Send + dynosaur 范式；组合根经 `Box<DynConfigUnitOfWork>` 注入。
#[trait_variant::make(ConfigUnitOfWork: Send)]
#[dynosaur(pub DynConfigUnitOfWork = dyn(box) ConfigUnitOfWork, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: 同 ConfigRepoLocal——Send 由 trait_variant `ConfigUnitOfWork` 变体 + dynosaur wrapper 承载。
// `Send + Sync` supertrait（#1430）：随 `SettingsService` 作 axum handler 共享 state（同 ConfigRepoLocal 约定）。
pub trait ConfigUnitOfWorkLocal: Send + Sync {
    /// 从 config-publish receipt 授权唯一 generated fact，再 CAS 写新配置版本 + 同事务 append outbox 行。
    /// CAS 冲突返
    /// [`ConfigRepoError::VersionConflict`]、持久化失败返 [`ConfigRepoError::Storage`]；任一步失败整事务
    /// 回滚（配置写与 outbox 行皆不落库）。
    async fn commit_publish(
        &self,
        receipt: ConfigPublishReceipt,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        event: ReviewedEvent,
    ) -> Result<(), ConfigRepoError>;

    /// Commit a config tombstone and its generated deletion fact through the exact delete route.
    async fn commit_delete(
        &self,
        receipt: ConfigDeleteReceipt,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        event: ReviewedEvent,
    ) -> Result<(), ConfigRepoError>;

    /// Commit a restored config version and its generated rollback fact through the exact route.
    async fn commit_rollback(
        &self,
        receipt: ConfigRollbackReceipt,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        event: ReviewedEvent,
    ) -> Result<(), ConfigRepoError>;
}

/// `settings.secret-publish` HTTP 写命令。
///
/// entry 与 LocalTx observation 一起封装；字段私有，外部 adapter 只能消费，不能伪造 contract / boundary
/// evidence。构造始终经本 crate 从 generated `ROUTE + LOCAL_TX` 取得非可选证据。
pub struct SecretPublishCommand {
    entry: SecretEntry,
    observation: observ::LocalTxObservation<SecretPublishRouteMarker>,
}

impl SecretPublishCommand {
    pub(crate) fn from_entry(entry: SecretEntry) -> Self {
        let observation =
            observ::LocalTxObservation::new(SECRET_HTTP_ROUTE, SECRET_LOCAL_TX.boundary);
        Self { entry, observation }
    }

    /// Adapter 消费命令并取得不可伪造的 LocalTx evidence。
    pub fn into_parts(
        self,
    ) -> (
        SecretEntry,
        observ::LocalTxObservation<SecretPublishRouteMarker>,
    ) {
        (self.entry, self.observation)
    }

    /// 下游 adapter conformance 测试仍经同一 generated evidence funnel 构造。
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(entry: SecretEntry) -> Self {
        Self::from_entry(entry)
    }
}

/// 非 HTTP 的应用内 publish 命令；刻意不携带 HTTP LocalTx observation。
pub struct SecretInternalPublishCommand {
    entry: SecretEntry,
}

impl SecretInternalPublishCommand {
    pub(crate) fn from_entry(entry: SecretEntry) -> Self {
        Self { entry }
    }

    /// Adapter 消费内部 publish entry。
    pub fn into_entry(self) -> SecretEntry {
        self.entry
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(entry: SecretEntry) -> Self {
        Self::from_entry(entry)
    }
}

/// rollback 重新发布历史引用的命令；与 HTTP / internal publish 类型互不可换。
pub struct SecretRepublishCommand {
    entry: SecretEntry,
}

impl SecretRepublishCommand {
    pub(crate) fn from_entry(entry: SecretEntry) -> Self {
        Self { entry }
    }

    /// Adapter 消费 republish entry。
    pub fn into_entry(self) -> SecretEntry {
        self.entry
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(entry: SecretEntry) -> Self {
        Self::from_entry(entry)
    }
}

/// secret 引用只读仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`SecretRepo`] 是 **Send 变体**，[`DynSecretRepo`] 是其 dyn-compatible wrapper
/// （组合根经 `Box<DynSecretRepo>` 注入）。租户必经 [`TenantRepoScope`] opaque handle 做 RLS 分隔。
///
/// **无 resolve**：secret 材料解析是 diport seam（`diport::SecretResolver`），不在此 port。
/// mutation 不进入本 read slot；所有写入只经 sibling [`SecretUnitOfWork`] 的 typed command。
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
}

/// Secret mutation UoW：HTTP publish、应用内 publish 与 rollback republish 由互不可换的 command 区分。
///
/// 三条 active-row 写路径共享相同 CAS 语义：entry version 必须等于当前最高版本 + 1；冲突返回
/// [`SecretRepoError::VersionConflict`]。delete 追加 tombstone，version 单调不重置且幂等。
#[trait_variant::make(SecretUnitOfWork: Send)]
#[dynosaur(pub DynSecretUnitOfWork = dyn(box) SecretUnitOfWork, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: Send 由 trait_variant 变体 + dynosaur wrapper 承载；provider 必须可供 HTTP State 跨线程共享。
pub trait SecretUnitOfWorkLocal: Send + Sync {
    /// HTTP `settings.secret-publish` CAS；command 必带 generated LocalTx evidence。
    async fn publish(
        &self,
        scope: TenantRepoScope,
        command: SecretPublishCommand,
    ) -> Result<(), SecretRepoError>;

    /// 非 HTTP 应用 API publish；不得产生 HTTP contract telemetry。
    async fn publish_internal(
        &self,
        scope: TenantRepoScope,
        command: SecretInternalPublishCommand,
    ) -> Result<(), SecretRepoError>;

    /// rollback republish；不得产生 HTTP publish contract telemetry。
    async fn republish(
        &self,
        scope: TenantRepoScope,
        command: SecretRepublishCommand,
    ) -> Result<(), SecretRepoError>;

    /// 软删除 key（tombstone）：version 单调不重置；幂等（latest 已 tombstone / key 不存在 ⇒ no-op）。
    async fn delete(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<(), SecretRepoError>;
}

mod settings_port_effect_sealed {
    pub trait Sealed {}
}

/// Closed, owner-defined effect classification for settings domain storage ports.
///
/// Only canonical wrappers owned by this module can receive a classification. [`Arc`](std::sync::Arc)
/// and [`Box`] preserve the wrapped port's effect and privilege.
#[allow(private_bounds)]
pub trait SettingsPortEffect: settings_port_effect_sealed::Sealed {
    /// Strongest capability exposed by this port.
    type Effect: diport::PortEffectClass;
    /// Whether the port can cross tenant boundaries.
    type Privilege: diport::PortPrivilegeClass;
}

macro_rules! classify_settings_ports {
    ($($port:ident => $effect:ty),+ $(,)?) => {
        $(
            impl<'a> settings_port_effect_sealed::Sealed for $port<'a> {}
            impl<'a> SettingsPortEffect for $port<'a> {
                type Effect = $effect;
                type Privilege = diport::LocalPrivilege;
            }
        )+

        const _: fn() = || {
            fn assert_effect<T, E>()
            where
                T: SettingsPortEffect<Effect = E, Privilege = diport::LocalPrivilege> + ?Sized,
                E: diport::PortEffectClass,
            {
            }

            $(assert_effect::<$port<'static>, $effect>();)+
        };
    };
}

classify_settings_ports! {
    DynConfigRepo => diport::ReadEffect,
    DynConfigUnitOfWork => diport::OutboxEffect,
    DynSecretRepo => diport::ReadEffect,
    DynSecretUnitOfWork => diport::BusinessWriteEffect,
    DynSettingsProjectionReadRepo => diport::ReadEffect,
    DynActiveProjectionResolver => diport::ReadEffect,
}

impl<T: SettingsPortEffect + ?Sized> settings_port_effect_sealed::Sealed for std::sync::Arc<T> {}
impl<T: SettingsPortEffect + ?Sized> SettingsPortEffect for std::sync::Arc<T> {
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

impl<T: SettingsPortEffect + ?Sized> settings_port_effect_sealed::Sealed for Box<T> {}
impl<T: SettingsPortEffect + ?Sized> SettingsPortEffect for Box<T> {
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

#[cfg(test)]
mod settings_port_effect_tests {
    //! Exact Effect + LocalPrivilege type assertions for the six ports declared by the
    //! production `classify_settings_ports!` block, plus Arc/Box classification propagation.

    use super::{
        DynActiveProjectionResolver, DynConfigRepo, DynConfigUnitOfWork, DynSecretRepo,
        DynSecretUnitOfWork, DynSettingsProjectionReadRepo, SettingsPortEffect,
    };

    fn assert_effect<T, E, P>()
    where
        T: SettingsPortEffect<Effect = E, Privilege = P> + ?Sized,
        E: diport::PortEffectClass,
        P: diport::PortPrivilegeClass,
    {
    }

    #[test]
    fn settings_ports_have_closed_effect_classifications() {
        assert_effect::<DynConfigRepo<'static>, diport::ReadEffect, diport::LocalPrivilege>();
        assert_effect::<DynConfigUnitOfWork<'static>, diport::OutboxEffect, diport::LocalPrivilege>(
        );
        assert_effect::<DynSecretRepo<'static>, diport::ReadEffect, diport::LocalPrivilege>();
        assert_effect::<
            DynSecretUnitOfWork<'static>,
            diport::BusinessWriteEffect,
            diport::LocalPrivilege,
        >();
        assert_effect::<
            DynSettingsProjectionReadRepo<'static>,
            diport::ReadEffect,
            diport::LocalPrivilege,
        >();
        assert_effect::<
            DynActiveProjectionResolver<'static>,
            diport::ReadEffect,
            diport::LocalPrivilege,
        >();
    }

    #[test]
    fn arc_and_box_preserve_settings_port_effect_classifications() {
        assert_effect::<
            std::sync::Arc<DynConfigRepo<'static>>,
            diport::ReadEffect,
            diport::LocalPrivilege,
        >();
        assert_effect::<
            Box<DynConfigUnitOfWork<'static>>,
            diport::OutboxEffect,
            diport::LocalPrivilege,
        >();
        assert_effect::<
            std::sync::Arc<DynSecretRepo<'static>>,
            diport::ReadEffect,
            diport::LocalPrivilege,
        >();
        assert_effect::<
            Box<DynSecretUnitOfWork<'static>>,
            diport::BusinessWriteEffect,
            diport::LocalPrivilege,
        >();
        assert_effect::<
            std::sync::Arc<DynSettingsProjectionReadRepo<'static>>,
            diport::ReadEffect,
            diport::LocalPrivilege,
        >();
        assert_effect::<
            Box<DynActiveProjectionResolver<'static>>,
            diport::ReadEffect,
            diport::LocalPrivilege,
        >();
    }
}
