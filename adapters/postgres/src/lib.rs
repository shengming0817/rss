//! postgres — RSS workspace crate（eventexec 持久化基座；P3/#1116）。See docs/rules/architecture.md.
//!
//! sealed-marker [`PgStore`] 持 `sqlx::PgPool`（`pub(crate)`），提供连接池（`connect`）、事务运行器
//! （`run_global_transaction`）、Migrator（`run_migrations`）——均 `pub(crate)` funnel，外部经
//! [`PgRuntimeDeps::setup`] 构造（#1423，PG-BUNDLE-FUNNEL-01）；并 impl
//! `diport::ManagedResource`（关池接入 `bootstrap::ShutdownStack` 逆序编排）。
//!
//! port 来源两类：provider-agnostic 基建 port 来自 `diport`（`ManagedResource`…）；**域形** repo port 来自
//! 所属域 crate（`identity::ports::RoleRepo`…，Option 2/ADR-005）。事务运行器是**普通 inherent 方法**
//! （非 dynosaur DI port）——签名暴露 crate-private `TxCapability`，该令牌只能由 postgres
//! adapter 从 live `sqlx::Transaction` 铸造；裸 `sqlx::PgConnection` 只在 capability 生命周期内经 `conn()`
//! 借出。放 provider-agnostic 的 `diport` 会破坏其不变式（#1116 决策 1）；且为 `pub(crate)`（未做 tenant
//! scope 的事务 capability 非公开 API，review F2）。
//!
//! adapter→域 DIP 内向边（postgres 依赖 identity、impl 其 `RoleRepo`，经 deny.toml identity wrapper +
//! `allows(Adapter,Domain)` 放行；adapter 仍不被域依赖）由生产 [`PgRoleRepo`]（impl
//! `identity::ports::RoleRepo`，roles 表 + tenant scope，#1250）承载——替换原 `#[cfg(test)]` `RoleRepoEdgeProof`
//! 编译证明（body `todo!()`）。同 DIP 内向边另由 [`PgCredentialRepo`]（impl `identity::ports::CredentialRepo`，
//! credentials 表 + 折叠锁定态 + `SELECT FOR UPDATE` 行锁原子 RMW，#1316）承载——login 密码校验 durable 真依赖。

mod audit_repo;
mod auth_audit_sink;
mod bundle;
mod cas_store;
mod checkpoint;
mod config_repo;
mod consumer_tx;
mod cotx;
mod credential_repo;
mod dead_letter;
mod dead_letter_payload;
mod dlq;
mod emitter;
mod inbox;
mod migrator;
mod outbox;
mod outbox_cdc;
mod policy_repo;
mod pool;
mod projection_control;
mod projection_events;
mod readiness;
mod reconcile;
mod refresh_token_store;
mod resource_attribute_repo;
mod role_binding_lifecycle;
mod role_repo;
mod saga;
mod secret_repo;
mod service_token_replay;
mod session_lifecycle;
mod session_sweeper;
mod tx;
mod tx_retry;

pub use audit_repo::{PgAuditAdminRepo, PgAuditRepo};
pub use auth_audit_sink::PgAuthAuditSink;
// postgres capability bundle（#1423）：connect/migration/readiness/per-domain repo 构造的单一 funnel。
pub use bundle::{
    MaintenanceAuditOutcome, PgDomain, PgDomainDeps, PgInfraDeps, PgMaintenanceDeps, PgRuntimeDeps,
    PgSettingsBundle, caps,
};
pub use cas_store::PgCasStore;
pub use checkpoint::PgCheckpointStore;
pub use config_repo::{
    ConfigValueMaintenanceCapability, ConfigValueMaintenanceOperation,
    ConfigValueMaintenanceOptions, ConfigValueMaintenanceReport, ConfigValueProtection,
    ConfigValueProtections, PgConfigRepo, PgConfigValueMaintenance,
};
pub use consumer_tx::{PgAuditConsumerTx, PgSettingsConsumerTx};
pub use credential_repo::PgCredentialRepo;
pub use dead_letter::{DEAD_LETTER_RETENTION_SECONDS, PgDeadLetterStore};
pub use dead_letter_payload::DlxPayloadProtector;
pub use dlq::PgDlqStore;
pub use emitter::PgEmitter;
pub use outbox::{PgOutbox, PgOutboxMaintenance};
pub use outbox_cdc::PgOutboxCdcEmitter;
pub use policy_repo::{PgPolicyLifecycle, PgPolicyRepo};
pub use projection_control::{
    PgProjectionControl, ProjectionControlError, ProjectionMaintenanceCapability,
    ProjectionPointerPrecondition, ProjectionPointerStatus, ProjectionPromoteOutcome,
};
// Projection writer 不 re-export raw append DTO：写入口经 outbox writer funnel + generated registry +
// DB SECURITY DEFINER function 收口（eventbus.md §Projection sealed 写入）。读路径返回 consistency
// engine-owned ProjectionEventRecord，不公开 adapter DTO。
pub use projection_events::{PgProjectionEvents, ProjectionEventsError};
pub use reconcile::{
    PgReconcileStore, ReconcileActionErrorKind, ReconcileAttemptInsert,
    ReconcileAttemptResultInsert, ReconcileAttemptTrigger, ReconcileKeyError, ReconcileLease,
    ReconcileLeaseOutcome, ReconcileLedgerId, ReconcileStoreError, ReconcileTarget,
    ReconcileTargetKey,
};
pub use refresh_token_store::PgRefreshTokenStore;
pub use resource_attribute_repo::PgResourceAttributeRepo;
pub use role_binding_lifecycle::PgRoleBindingLifecycle;
pub use role_repo::PgRoleRepo;
pub use saga::{PgSagaInstanceStore, PgSagaJournal};
pub use secret_repo::PgSecretRepo;
pub use service_token_replay::PgServiceTokenReplayGuard;
pub use session_lifecycle::PgSessionLifecycle;
pub use session_sweeper::PgSessionSweeper;

#[cfg(all(test, feature = "integration"))]
mod integration_tests;

#[cfg(all(test, feature = "integration"))]
mod test_pg;

pub use inbox::{INBOX_RECEIPT_RETENTION_SECONDS, PgInboxStore, PgInboxSweeper};
pub use pool::{LegacyConfigPlaintextPolicy, PgConfig, PgError, PgPassword, PoolReadiness};
// `pg_readiness_sampling_loop` 降 `pub(crate)`（经 `PgRuntimeDeps::spawn_readiness_sampler` 收口，#1423），
// 不再 re-export；类型 `PgDbReadiness`/`PgReadinessSampler` 仍公开（probe / bundle 返回类型）。
pub use readiness::{PgDbReadiness, PgReadinessSampler};
// re-export sqlx 的 TLS 模式枚举，组合根经 `PgConfig::with_ssl_mode` 配置时无需直接依赖 sqlx。
pub use sqlx::postgres::PgSslMode;

use std::sync::Arc;

use diport::{ManagedResource, ShutdownError};
use sqlx::PgPool;

/// `ManagedResource::name` 稳定标识（日志 / 超时报错用）。
pub(crate) const PG_STORE_NAME: &str = "postgres";

/// PostgreSQL 存储 adapter（sealed-marker）。持 `sqlx::PgPool`（`pub(crate)`，仅 crate 内 repo / tx /
/// migrator impl 取用）。外部经 [`PgRuntimeDeps::setup`](crate::PgRuntimeDeps::setup) 构造
/// （PG-BUNDLE-FUNNEL-01）；`connect`/`run_migrations` 为 `pub(crate)`、不对外暴露。
pub struct PgStore {
    pub(crate) pool: PgPool,
}

impl ManagedResource for PgStore {
    fn name(&self) -> &str {
        PG_STORE_NAME
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: graceful 关池（等连接归还后关闭）；sqlx `Pool::close` 不返错，故恒 Ok。
        self.pool.close().await;
        tracing::info!(target: "postgres", name = PG_STORE_NAME, "postgres pool closed");
        Ok(())
    }
}

/// `Arc<PgStore>` 的 `ManagedResource` 适配——关停末阶段 `pool.close()`。
///
/// `Arc` 非 fundamental ⇒ 不能直接 `impl ManagedResource for Arc<PgStore>`（孤儿规则），
/// 故用 newtype 包装绕孤儿规则。
///
/// # 注册顺序
///
/// 经组合根 [`bootstrap::ShutdownStack::register_detached`] 注入 `ShutdownStack`；注册顺序须在
/// listener/sampler **之前**——LIFO 下 pool 最后关（listener drain → sampler 停 → pool close，
/// 确保 sampler 不会在已关闭的 pool 上发起 probe）。
pub struct PgStoreGuard {
    store: Arc<PgStore>,
    name: &'static str,
}

impl PgStoreGuard {
    /// 包装 `Arc<PgStore>` 为可注册进 `ShutdownStack` 的 guard。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：仅经 [`bundle::PgRuntimeDeps::store_guard`] 构造，
    /// 组合根不直接持 `Arc<PgStore>`。
    pub(crate) fn new(store: Arc<PgStore>) -> Self {
        Self {
            store,
            name: PG_STORE_NAME,
        }
    }

    pub(crate) fn new_named(store: Arc<PgStore>, name: &'static str) -> Self {
        Self { store, name }
    }
}

impl ManagedResource for PgStoreGuard {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.store.shutdown().await
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言冻结的 DI port trait——生产 `PgStore` impl `diport::ManagedResource`；
    //! adapter→域 DIP 内向边（postgres impl `identity::ports::RoleRepo`，命名其 pub 实体 Role/RoleId）由生产
    //! [`super::PgRoleRepo`](真实 impl，roles 表 + tenant scope，#1250)承载——替换原 `RoleRepoEdgeProof`
    //! 编译证明。PhantomData 绑定检查，不构造、不执行 body。
    //! INVARIANT: ADAPTER-PORT-FREEZE-06 { level = "Medium", exec = "manual/opt-in", source = "code" }—— ManagedResource on PgStore + RoleRepo on PgRoleRepo（真实 impl，#1250）+
    //! InboxStore/InboxBacklog on PgInboxStore + SagaJournal on PgSagaJournal + CasStore on PgCasStore +
    //! OwnerCheckpointStore on PgCheckpointStore + SessionLifecycle on PgSessionLifecycle（完整 durable impl：co-tx 创建 #1083/#1192 + find/revoke #1278）+
    //! ConfigRepo/ConfigUnitOfWork on PgConfigRepo（真实 impl，#1249）+
    //! SecretRepo on PgSecretRepo（真实 impl，#1274）+
    //! CredentialRepo on PgCredentialRepo（真实 impl，credentials 表 + 折叠锁定态 + 行锁原子 RMW，#1316）+
    //! RefreshTokenStore on PgRefreshTokenStore（真实 impl：哈希存储 + CAS rotation + RLS，#1325）+
    //! AuditRepo on PgAuditRepo（真实 impl：append-only per-tenant keyed-HMAC chain + RLS，#1230）+
    //! PgSessionSweeper concrete maintenance type（#1233，不新增 identity 域端口）；
    //! 去掉任一即编译失败（anti-vacuity）。
    //! INVARIANT: PG-BUNDLE-DOMAIN-02 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— `caps::Settings` / `caps::Identity` / `caps::Audit` 均满足 sealed `PgDomain`
    //! bound（正向）；跨域 accessor 误用的负向 anti-vacuity = `bundle::PgDomainDeps` 的 `compile_fail` doctest。
    use core::marker::PhantomData;

    fn assert_pg_domain<D: super::PgDomain>(_: PhantomData<D>) {}
    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_role_repo<T: identity::ports::RoleRepo>(_: PhantomData<T>) {}
    fn assert_policy_repo<T: identity::ports::PolicyRepo>(_: PhantomData<T>) {}
    fn assert_credential_repo<T: identity::ports::CredentialRepo>(_: PhantomData<T>) {}
    fn assert_session_lifecycle<T: identity::ports::SessionLifecycle>(_: PhantomData<T>) {}
    fn assert_inbox_store<T: consistency::InboxStore>(_: PhantomData<T>) {}
    fn assert_inbox_backlog<T: consistency::InboxBacklog>(_: PhantomData<T>) {}
    fn assert_outbox_backlog<T: consistency::OutboxBacklog>(_: PhantomData<T>) {}
    fn assert_retention_sweeper<T: consistency::RetentionSweeper>(_: PhantomData<T>) {}
    fn assert_config_repo<T: settings::ports::ConfigRepo>(_: PhantomData<T>) {}
    fn assert_config_uow<T: settings::ports::ConfigUnitOfWork>(_: PhantomData<T>) {}
    fn assert_saga_instance_store<T: diport::SagaInstanceStore>(_: PhantomData<T>) {}
    fn assert_saga_journal<T: diport::SagaJournal>(_: PhantomData<T>) {}
    fn assert_cas_store<T: diport::CasStore>(_: PhantomData<T>) {}
    fn assert_checkpoint_store<T: diport::OwnerCheckpointStore>(_: PhantomData<T>) {}
    fn assert_secret_repo<T: settings::ports::SecretRepo>(_: PhantomData<T>) {}
    fn assert_refresh_token_store<T: identity::ports::RefreshTokenStore>(_: PhantomData<T>) {}
    fn assert_audit_repo<T: audit::ports::AuditRepo>(_: PhantomData<T>) {}
    fn assert_send_sync<T: Send + Sync>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::PgStore>);
        // `PgRoleRepo: RoleRepo` 真实 impl（非 edge proof）——roles 表持久化 + tenant scope（#1250）。
        assert_role_repo(PhantomData::<super::PgRoleRepo>);
        // `PgPolicyRepo: PolicyRepo` 真实 impl——tenant-scoped durable ABAC policy store（#1588）。
        assert_policy_repo(PhantomData::<super::PgPolicyRepo>);
        // `PgCredentialRepo: CredentialRepo` 真实 impl（非 edge proof）——credentials 表 + 折叠锁定态 +
        // SELECT FOR UPDATE 原子 RMW（#1316）；类型级 anti-vacuity 只检查 trait 满足、不执行 body。
        assert_credential_repo(PhantomData::<super::PgCredentialRepo>);
        // `PgSessionLifecycle: SessionLifecycle` 完整 durable impl（非 edge proof）——co-tx 创建（#1083/#1192）
        // + find/revoke（#1278，0009 revoked 列）；类型级 anti-vacuity 只检查 trait 满足、不执行 body。
        assert_session_lifecycle(PhantomData::<super::PgSessionLifecycle>);
        // `PgInboxStore: InboxStore + InboxBacklog` 类型级 anti-vacuity edge proof（不构造、不执行 body）。
        assert_inbox_store(PhantomData::<super::PgInboxStore>);
        assert_inbox_backlog(PhantomData::<super::PgInboxStore>);
        assert_outbox_backlog(PhantomData::<super::PgOutboxMaintenance>);
        assert_retention_sweeper(PhantomData::<super::PgOutboxMaintenance>);
        // `PgConfigRepo: ConfigRepo + ConfigUnitOfWork` 真实 impl（非 edge proof）——配置仓储 + co-tx UoW（#1249）。
        assert_config_repo(PhantomData::<super::PgConfigRepo>);
        assert_config_uow(PhantomData::<super::PgConfigRepo>);
        // `PgSagaInstanceStore: SagaInstanceStore` + `PgSagaJournal: SagaJournal`
        // + `PgCheckpointStore: OwnerCheckpointStore` edge proof。
        assert_saga_instance_store(PhantomData::<super::PgSagaInstanceStore>);
        assert_saga_journal(PhantomData::<super::PgSagaJournal>);
        assert_cas_store(PhantomData::<super::PgCasStore>);
        assert_checkpoint_store(PhantomData::<super::PgCheckpointStore>);
        // `PgSecretRepo: SecretRepo` 真实 impl（非 edge proof）——secret 引用坐标仓储（#1274）。
        assert_secret_repo(PhantomData::<super::PgSecretRepo>);
        // `PgRefreshTokenStore: RefreshTokenStore` 真实 impl——哈希存储 + CAS rotation + 谱系级联撤销 + RLS（#1325）。
        assert_refresh_token_store(PhantomData::<super::PgRefreshTokenStore>);
        // `PgAuditRepo<TestVerifier>: AuditRepo` 真实 impl——append-only per-tenant keyed-HMAC chain + RLS（#1230）。
        // TestVerifier 是本地确定性 FNV-1a verifier（MacVerifier impl），足以证明 trait 满足；不执行 body。
        assert_audit_repo(
            PhantomData::<super::PgAuditRepo<super::audit_repo::test_support::TestVerifier>>,
        );
        // `PgSessionSweeper` 是 concrete postgres maintenance 能力，不 impl identity 域端口；Send+Sync smoke
        // 锁住可进入 runtime worker 的形状。
        assert_send_sync(PhantomData::<super::PgSessionSweeper>);
        // PG-BUNDLE-DOMAIN-02：三个 per-domain marker 均满足 sealed `PgDomain`（去掉任一 impl 即编译失败）。
        assert_pg_domain(PhantomData::<super::caps::Settings>);
        assert_pg_domain(PhantomData::<super::caps::Identity>);
        assert_pg_domain(PhantomData::<super::caps::Audit>);
    }

    #[test]
    fn store_name_is_stable() {
        assert_eq!(super::PG_STORE_NAME, "postgres");
    }

    /// `PgStoreGuard::shutdown()` 对 lazy pool 返 Ok（pool.close 幂等）。
    ///
    /// `connect_lazy_with` 不发真实连接；`close()` 幂等 → `PgStore::shutdown` 恒 Ok
    /// → `PgStoreGuard::shutdown` 代理调用亦恒 Ok（#1309 review A1 单测）。
    #[tokio::test]
    async fn pg_store_guard_shutdown_lazy_pool_ok() {
        use diport::ManagedResource as _;
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::sync::Arc;
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(opts);
        let store = Arc::new(super::PgStore { pool });
        let guard = super::PgStoreGuard::new(Arc::clone(&store));
        assert_eq!(
            guard.name(),
            "postgres",
            "PgStoreGuard::name 委托 PgStore::name"
        );
        assert!(
            guard.shutdown().await.is_ok(),
            "lazy pool close 幂等 → shutdown Ok"
        );
    }
}
