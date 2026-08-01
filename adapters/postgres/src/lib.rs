//! postgres — RSS workspace crate（eventexec 持久化基座；P3/#1116）。See docs/rules/architecture.md.
//!
//! sealed-marker [`PgStore`] 持 `sqlx::PgPool`（`pub(crate)`），提供连接池（`connect`）与只读
//! schema ledger 验证；迁移执行只存在于 operator-only `postgres-migration` crate。外部经
//! [`PgRuntimeDeps::connect_serving`] 构造；并 impl
//! `diport::ManagedResource`（关池接入 `bootstrap::ShutdownStack` 逆序编排）。
//!
//! port 来源两类：provider-agnostic 基建 port 来自 `diport`（`ManagedResource`…）；**域形** repo port 来自
//! 所属域 crate（`identity::ports::RoleReadRepo`…，Option 2/ADR-005）。tenant repository 只持 sealed
//! `TenantDb` exact lane，closure 只获得 tenant-bound `TenantTx` 的 closed store-operation façade，
//! 无法取得 raw pool / connection / executor 或 commit/rollback 生命周期；生产侧非租户事务由各
//! owner 的窄 funnel 承载。物理 PostgreSQL transaction capability 不进入 provider-neutral 层。
//!
//! adapter→域 DIP 内向边（postgres 依赖 identity、impl 其 `RoleReadRepo`，经 deny.toml identity wrapper +
//! `allows(Adapter,Domain)` 放行；adapter 仍不被域依赖）由生产 [`PgRoleRepo`]（impl
//! `identity::ports::RoleReadRepo`，roles 表 + tenant scope，#1250）承载——替换原 `#[cfg(test)]` `RoleRepoEdgeProof`
//! 编译证明（body `todo!()`）。同 DIP 内向边另由 [`PgCredentialRepo`]（impl `identity::ports::CredentialRepo`，
//! credentials 表 + 折叠锁定态 + `SELECT FOR UPDATE` 行锁原子 RMW，#1316）承载——login 密码校验 durable 真依赖。
//!
//! INVARIANT: PG-DOMAIN-FEATURES-01 { level = "Hard", exec = "native-compile", source = "code", native = "Cargo optional dependencies and explicit domain features remove inactive domain APIs from the selected package graph" } ——
//! `domain-settings` / `domain-identity` / `domain-audit` 是无默认值的闭合选择；未启用时对应 dependency、module 与 public API 均不进入 rustc 输入。

#[cfg(feature = "domain-identity")]
mod account_security_repo;
#[cfg(feature = "domain-audit")]
mod audit_repo;
#[cfg(feature = "auth-audit-sink")]
mod auth_audit_sink;
#[cfg(feature = "domain-identity")]
mod auth_grant_lifecycle;
#[cfg(feature = "domain-identity")]
mod auth_grant_provider;
mod auth_grant_sweeper;
#[cfg(feature = "domain-identity")]
mod auth_grant_validator;
mod bundle;
mod cas_store;
mod checkpoint;
mod command_journal;
#[cfg(feature = "domain-settings")]
mod config_repo;
#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
mod consumer_tx;
#[cfg_attr(
    not(any(
        feature = "domain-settings",
        feature = "domain-identity",
        feature = "domain-audit"
    )),
    allow(dead_code, unused_imports)
)]
mod cotx;
#[cfg(feature = "domain-identity")]
mod credential_repo;
mod dead_letter;
mod dead_letter_payload;
mod delivery_policy;
#[cfg(feature = "domain-identity")]
mod device_certificate;
mod device_certificate_scope;
#[cfg(feature = "domain-identity")]
mod device_command;
mod dlq;
mod dlx_lifecycle;
mod emitter;
#[cfg(feature = "fault-matrix-test-support")]
pub mod fault_matrix;
#[cfg(feature = "domain-identity")]
mod identity_security_lifecycle;
mod inbox;
mod outbox;
mod outbox_cdc;
#[cfg(feature = "domain-identity")]
mod policy_repo;
mod pool;
mod projection_control;
mod projection_events;
mod readiness;
mod reconcile;
#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
mod reconcile_test_driver;
#[cfg(feature = "domain-identity")]
mod refresh_token_store;
#[cfg(feature = "domain-identity")]
mod resource_attribute_repo;
mod revocation;
mod revocation_sweeper;
#[cfg(feature = "domain-identity")]
mod role_binding_lifecycle;
#[cfg(feature = "domain-identity")]
mod role_binding_read_repo;
#[cfg(feature = "domain-identity")]
mod role_repo;
mod saga;
mod saga_candidates;
mod saga_receipt_capability;
mod saga_terminal_sweeper;
mod schema_ledger;
#[cfg(feature = "domain-settings")]
mod secret_repo;
mod service_token_replay;
#[cfg(feature = "domain-settings")]
mod settings_projection;
#[cfg_attr(
    not(any(
        feature = "domain-settings",
        feature = "domain-identity",
        feature = "domain-audit"
    )),
    allow(dead_code, unused_imports)
)]
mod tx_retry;

/// Integration-only compile-proof surface over the real transaction type identities.
#[cfg(feature = "integration")]
#[doc(hidden)]
pub mod tx_boundary_proof {
    use futures::future::BoxFuture;

    pub use crate::cotx::eventing::OutboxTx;
    pub use crate::cotx::identity::{IdentityTx, IdentityWrite};
    pub use crate::cotx::reconcile::ReconcileTx;
    pub use crate::cotx::{
        AuditAdminReadLane, MaintenanceReadLane, MaintenanceWriteLane, ServingReadLane,
        ServingWriteLane, TenantDb, TenantTx,
    };

    pub fn require_serving_write_tx(_: &mut TenantTx<'_, ServingWriteLane>) {}

    pub fn require_maintenance_write_tx(_: &mut TenantTx<'_, MaintenanceWriteLane>) {}

    pub fn serving_identity_write<'borrow, 'cap, 'tx>(
        tx: &'borrow mut IdentityTx<'cap, 'tx, ServingWriteLane>,
    ) -> IdentityWrite<'borrow, 'tx> {
        tx.identity()
    }

    pub fn require_identity_write(_: &mut IdentityWrite<'_, '_>) {}

    pub fn require_identity_operation<F>(_: F)
    where
        F: for<'borrow, 'tx> FnOnce(
            IdentityTx<'borrow, 'tx, ServingWriteLane>,
        ) -> BoxFuture<'borrow, Result<(), ()>>,
    {
    }

    pub fn outbox_operation(_: &mut OutboxTx<'_>) {}

    pub fn reconcile_operation(_: &mut ReconcileTx<'_, ServingWriteLane>) {}
}

#[cfg(any(test, feature = "test-support", feature = "fault-matrix-test-support"))]
mod test_migration {
    use crate::{PgError, PgStore};

    impl PgStore {
        pub(crate) async fn run_migrations(&self) -> Result<(), PgError> {
            sqlx::migrate!("./migrations")
                .run(&self.pool)
                .await
                .map_err(PgError::Migrate)
        }
    }
}

#[cfg(feature = "domain-audit")]
pub use audit_repo::{PgAuditAdminRepo, PgAuditRepo};
#[cfg(feature = "auth-audit-sink")]
pub use auth_audit_sink::PgAuthAuditSink;
// postgres capability bundle（#1423）：connect/migration/readiness/per-domain repo 构造的单一 funnel。
#[cfg(feature = "domain-identity")]
pub use account_security_repo::PgAccountSecurityRepo;
#[cfg(feature = "domain-settings")]
pub use bundle::PgSettingsBundle;
#[cfg(all(feature = "domain-identity", any(test, feature = "test-support")))]
pub use bundle::identity_pseudonym_keys_for_test;
pub use bundle::{
    MaintenanceAuditOutcome, PgConsumerRuntimeBundle, PgDomain, PgDomainDeps, PgInfraDeps,
    PgMaintenanceDeps, PgProjectionOperatorAction, PgProjectionOperatorCapability,
    PgProjectionOperatorDeps, PgProjectionReplayStores, PgReadinessSamplerFactory, PgRuntimeDeps,
    PgRuntimeHandle, PgSagaOperatorDeps, ProjectionReplayAction, ProjectionStatusAction,
    ProjectionSwapAction, caps,
};
pub use cas_store::PgCasStore;
pub use checkpoint::PgCheckpointStore;
pub use command_journal::PgCommandJournal;
#[cfg(feature = "domain-settings")]
pub use config_repo::{
    ConfigValueMaintenanceCapability, ConfigValueMaintenanceOperation,
    ConfigValueMaintenanceOptions, ConfigValueMaintenanceReport, ConfigValueProtection,
    ConfigValueProtections, PgConfigRepo, PgConfigValueMaintenance,
};
#[cfg(feature = "domain-audit")]
pub use consumer_tx::PgAuditConsumerTx;
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
pub use consumer_tx::PgConsumerTxCommitProof;
#[cfg(feature = "domain-settings")]
pub use consumer_tx::PgSettingsConsumerTx;
#[cfg(any(feature = "domain-audit", feature = "domain-settings"))]
pub use consumer_tx::{PgConsumerTxOutcome, PgConsumerTxRequeue};
#[cfg(feature = "domain-identity")]
pub use credential_repo::PgCredentialRepo;
pub use dead_letter::PgDeadLetterStore;
pub use dead_letter_payload::DlxPayloadProtector;
#[cfg(feature = "domain-identity")]
pub use device_certificate::PgDeviceCertificateRepository;
#[cfg(feature = "domain-identity")]
pub use device_command::{PgDeviceIngressCommit, PgDeviceIngressCommitProof};
pub use dlq::PgDlqStore;
pub use dlx_lifecycle::{PgDlxArchiveClaim, PgDlxLifecycleRepository, PgDlxLifecycleRuntime};
pub use emitter::PgEmitter;
#[cfg(feature = "domain-identity")]
pub use identity_security_lifecycle::{
    PgAccountReactivationLifecycle, PgIdentitySecurityLifecycle,
};
pub use outbox::{PgOutbox, PgOutboxMaintenance};
pub use outbox_cdc::PgOutboxCdcEmitter;
#[cfg(feature = "domain-identity")]
pub use policy_repo::{PgPolicyLifecycle, PgPolicyRepo};
pub use projection_control::{
    ProjectionControlError, ProjectionPointerPrecondition, ProjectionPointerStatus,
    ProjectionPromoteOutcome,
};
#[cfg(feature = "domain-settings")]
pub(crate) use settings_projection::PgSettingsProjectionApplyStore;
#[cfg(feature = "domain-settings")]
pub use settings_projection::PgSettingsProjectionReadRepo;
// Projection writer 不 re-export raw append DTO：写入口经 outbox writer funnel + generated registry +
// DB SECURITY DEFINER function 收口（eventbus.md §Projection sealed 写入）。读路径返回 consistency
// engine-owned ProjectionEventRecord，不公开 adapter DTO。
#[cfg(feature = "domain-audit")]
pub use audit_repo::AuditChainKeyIdentity;
#[cfg(feature = "domain-identity")]
pub use auth_grant_lifecycle::PgAuthGrantLifecycle;
#[cfg(feature = "domain-identity")]
pub use auth_grant_provider::PgAuthGrantProvider;
pub use auth_grant_sweeper::{AuthGrantSweepDeadline, PgAuthGrantSweeper};
#[cfg(feature = "domain-identity")]
pub use auth_grant_validator::PgAuthGrantValidator;
pub use projection_events::ProjectionEventsError;
pub use reconcile::{PgMaintenanceReconcileStore, PgReconcileStore};
#[cfg(feature = "domain-identity")]
pub use refresh_token_store::PgRefreshTokenStore;
#[cfg(feature = "domain-identity")]
pub use resource_attribute_repo::PgResourceAttributeRepo;
pub use revocation::PgRevocationStore;
pub use revocation_sweeper::{
    PgRevocationSweeper, RevocationRetentionBacklog, RevocationRetentionReport,
    RevocationSweepDeadline,
};
#[cfg(feature = "domain-identity")]
pub use role_binding_lifecycle::PgRoleBindingLifecycle;
#[cfg(feature = "domain-identity")]
pub use role_binding_read_repo::PgRoleBindingReadRepo;
#[cfg(feature = "domain-identity")]
pub use role_repo::PgRoleRepo;
pub use saga::{PgSagaDurableStore, PgSagaReceiptProtection};
pub use saga_terminal_sweeper::{
    PgSagaTerminalSweeper, SagaTerminalSweepDeadline, SagaTerminalSweepReport,
};
#[cfg(feature = "domain-settings")]
pub use secret_repo::{PgSecretRepo, PgSecretUnitOfWork};
pub use service_token_replay::{PgServiceTokenReplayStore, PgServiceTokenReplaySweeper};

#[cfg(all(test, feature = "integration"))]
mod integration_tests;

#[cfg(all(test, feature = "integration"))]
mod test_pg;

pub use inbox::{PgInboxStore, PgInboxSweeper};
pub use pool::{
    PgConfig, PgError, PgPassword, PgProjectionOperatorConfig, PgProjectionSourceReadConfig,
    PgSagaOperatorConfig, PgTenantReadConfig, PoolReadiness,
};
// `pg_readiness_sampling_loop` 保持 `pub(crate)`，仅经 consuming `PgReadinessSamplerFactory::spawn` 收口；
// 类型 `PgDbReadiness`/`PgReadinessSampler` 仍公开（probe / runtime lifecycle output 返回类型）。
pub use readiness::{PgDbReadiness, PgReadinessSampler};
// re-export sqlx 的 TLS 模式枚举，组合根经 `PgConfig::with_ssl_mode` 配置时无需直接依赖 sqlx。
pub use sqlx::postgres::PgSslMode;

use std::sync::Arc;

use diport::{ManagedResource, ShutdownError};
use sqlx::PgPool;

/// `ManagedResource::name` 稳定标识（日志 / 超时报错用）。
pub(crate) const PG_STORE_NAME: &str = "postgres";

/// PostgreSQL 存储 adapter（sealed-marker）。持 `sqlx::PgPool`（`pub(crate)`，仅 crate 内 repo / tx /
/// test fixture 取用）。外部经 [`PgRuntimeDeps::connect_serving`](crate::PgRuntimeDeps::connect_serving)
/// 构造（PG-BUNDLE-FUNNEL-01）；连接与测试迁移 helper 均不对外暴露。
pub(crate) struct PgStore {
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

/// `Arc<PgStore>` 的 runtime `ManagedResource` 适配——关停末阶段同步封闭新连接获取。
///
/// `Arc` 非 fundamental ⇒ 不能直接 `impl ManagedResource for Arc<PgStore>`（孤儿规则），
/// 故用 newtype 包装绕孤儿规则。
///
/// # 注册顺序
///
/// 经组合根 [`bootstrap::ShutdownStack::register_detached`] 注入 `ShutdownStack`；注册顺序须在
/// listener/sampler **之前**——LIFO 下 pool 最后封闭（listener drain → sampler 停 → pool
/// admission fence，确保 sampler 不会在已关闭的 pool 上发起 probe）。底层 TLS transport
/// 随 composition root 的最后一个 pool handle 一并 drop，不属于 runtime drain 的等待边界。
pub struct PgStoreGuard {
    store: Arc<PgStore>,
    name: &'static str,
    shutdown: PgStoreShutdown,
}

#[derive(Clone, Copy)]
enum PgStoreShutdown {
    RuntimeFence,
    SetupRollback,
}

impl PgStoreGuard {
    /// 包装 `Arc<PgStore>` 为可注册进 `ShutdownStack` 的 guard。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：仅经
    /// [`bundle::PgRuntimeDeps::into_runtime_parts`] 构造，
    /// 组合根不直接持 `Arc<PgStore>`。
    pub(crate) fn new(store: Arc<PgStore>) -> Self {
        Self {
            store,
            name: PG_STORE_NAME,
            shutdown: PgStoreShutdown::RuntimeFence,
        }
    }

    /// 构造 serving setup transaction 的 rollback owner。
    ///
    /// 该 canonical constructor 由 startup transaction 注册；初始化失败仍处于 live executor，
    /// 因此必须完整等待连接 teardown 后才返回 primary error。
    pub(crate) fn new_named(store: Arc<PgStore>, name: &'static str) -> Self {
        Self {
            store,
            name,
            shutdown: PgStoreShutdown::SetupRollback,
        }
    }

    /// 构造 runtime shutdown stack 的具名 pool owner，只同步封闭新 acquire。
    pub(crate) fn new_runtime_named(store: Arc<PgStore>, name: &'static str) -> Self {
        Self {
            store,
            name,
            shutdown: PgStoreShutdown::RuntimeFence,
        }
    }

    fn fence_runtime_pool(&self) {
        log_pool_close_start(self.name, &self.store.pool);
        // SQLx marks the pool closed synchronously before returning this future. Runtime shutdown
        // needs that admission fence, but must not await the optional per-idle-connection TLS
        // teardown after every application worker has already drained. Remaining pool handles are
        // dropped with the sealed composition root and close their sockets.
        drop(self.store.pool.close());
        tracing::info!(target: "postgres", name = self.name, "postgres pool fenced closed");
    }

    async fn rollback_setup_pool(&self) {
        self.store.pool.close().await;
        tracing::info!(target: "postgres", name = self.name, "postgres setup pool closed");
    }
}

impl ManagedResource for PgStoreGuard {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        match self.shutdown {
            PgStoreShutdown::RuntimeFence => self.fence_runtime_pool(),
            PgStoreShutdown::SetupRollback => self.rollback_setup_pool().await,
        }
        Ok(())
    }
}

fn log_pool_close_start(name: &'static str, pool: &PgPool) {
    tracing::info!(
        target: "postgres",
        name,
        size = pool.size(),
        idle = pool.num_idle(),
        "postgres pool close starting"
    );
}

#[cfg(all(
    test,
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
mod smoke {
    //! build smoke：编译期断言冻结的 DI port trait——生产 `PgStore` impl `diport::ManagedResource`；
    //! adapter→域 DIP 内向边（postgres impl `identity::ports::RoleReadRepo`，命名其 pub 实体 Role/RoleId）由生产
    //! [`super::PgRoleRepo`](真实 impl，roles 表 + tenant scope，#1250)承载——替换原 `RoleRepoEdgeProof`
    //! 编译证明。PhantomData 绑定检查，不构造、不执行 body。
    //! INVARIANT: ADAPTER-PORT-FREEZE-06 { level = "Medium", exec = "manual/opt-in", source = "code" }—— ManagedResource on PgStore + RoleReadRepo on PgRoleRepo（真实 impl，#1250）+
    //! InboxStore/InboxBacklog on PgInboxStore + SagaDurableStore on PgSagaDurableStore + CasStore on PgCasStore +
    //! OwnerCheckpointStore on PgCheckpointStore + AuthGrantLifecycle on PgAuthGrantLifecycle（login co-tx + find/close）+
    //! ConfigRepo/ConfigUnitOfWork on PgConfigRepo（真实 impl，#1249）+
    //! SecretRepo on PgSecretRepo + SecretUnitOfWork on PgSecretUnitOfWork（真实 impl，#1274）+
    //! CredentialRepo on PgCredentialRepo（真实 impl，credentials 表 + 折叠锁定态 + 行锁原子 RMW，#1316）+
    //! RefreshTokenStore on PgRefreshTokenStore（真实 impl：哈希存储 + CAS rotation + RLS，#1325）+
    //! read/write ports on PgAuditRepo（真实 impl：append-only per-tenant keyed-HMAC chain + RLS，#1230）+
    //! PgAuthGrantSweeper concrete maintenance type（不新增 identity 域端口）；
    //! 去掉任一即编译失败（anti-vacuity）。
    //! INVARIANT: PG-BUNDLE-DOMAIN-02 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— `caps::Settings` / `caps::Identity` / `caps::Audit` 均满足 sealed `PgDomain`
    //! bound（正向）；跨域 accessor 误用的负向 anti-vacuity = `bundle::PgDomainDeps` 的 `compile_fail` doctest。
    use core::marker::PhantomData;

    fn assert_pg_domain<D: super::PgDomain>(_: PhantomData<D>) {}
    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_role_repo<T: identity::ports::RoleReadRepo>(_: PhantomData<T>) {}
    fn assert_role_write_repo<T: identity::ports::RoleWriteRepo>(_: PhantomData<T>) {}
    fn assert_policy_repo<T: identity::ports::PolicyRepo>(_: PhantomData<T>) {}
    fn assert_credential_repo<T: identity::ports::CredentialRepo>(_: PhantomData<T>) {}
    fn assert_auth_grant_lifecycle<T: identity::ports::AuthGrantLifecycle>(_: PhantomData<T>) {}
    fn assert_identity_security_lifecycle<T: identity::ports::IdentitySecurityLifecycle>(
        _: PhantomData<T>,
    ) {
    }
    fn assert_account_reactivation_lifecycle<T: identity::ports::AccountReactivationLifecycle>(
        _: PhantomData<T>,
    ) {
    }
    fn assert_inbox_store<T: consistency::InboxStore>(_: PhantomData<T>) {}
    fn assert_inbox_backlog<T: consistency::InboxBacklog>(_: PhantomData<T>) {}
    fn assert_outbox_backlog<T: consistency::OutboxBacklog>(_: PhantomData<T>) {}
    fn assert_retention_sweeper<T: consistency::RetentionSweeper>(_: PhantomData<T>) {}
    fn assert_config_repo<T: settings::ports::ConfigRepo>(_: PhantomData<T>) {}
    fn assert_config_uow<T: settings::ports::ConfigUnitOfWork>(_: PhantomData<T>) {}
    fn assert_saga_durable_store<T: diport::SagaDurableStore>(_: PhantomData<T>) {}
    fn assert_cas_store<T: diport::CasStore>(_: PhantomData<T>) {}
    fn assert_checkpoint_store<T: diport::OwnerCheckpointStore>(_: PhantomData<T>) {}
    fn assert_command_journal_store<T: eventexec::command::CommandJournalStore>(_: PhantomData<T>) {
    }
    fn assert_secret_repo<T: settings::ports::SecretRepo>(_: PhantomData<T>) {}
    fn assert_secret_uow<T: settings::ports::SecretUnitOfWork>(_: PhantomData<T>) {}
    fn assert_refresh_token_store<T: identity::ports::RefreshTokenStore>(_: PhantomData<T>) {}
    fn assert_audit_repo<T: audit::ports::AuditReadRepo + audit::ports::AuditWriteRepo>(
        _: PhantomData<T>,
    ) {
    }
    fn assert_send_sync<T: Send + Sync>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::PgStore>);
        // `PgRoleRepo: RoleReadRepo` 真实 impl（非 edge proof）——roles 表持久化 + tenant scope（#1250）。
        assert_role_repo(PhantomData::<super::PgRoleRepo>);
        assert_role_write_repo(PhantomData::<super::PgRoleRepo>);
        // `PgPolicyRepo: PolicyRepo` 真实 impl——tenant-scoped durable ABAC policy store（#1588）。
        assert_policy_repo(PhantomData::<super::PgPolicyRepo>);
        // `PgCredentialRepo: CredentialRepo` 真实 impl（非 edge proof）——credentials 表 + 折叠锁定态 +
        // SELECT FOR UPDATE 原子 RMW（#1316）；类型级 anti-vacuity 只检查 trait 满足、不执行 body。
        assert_credential_repo(PhantomData::<super::PgCredentialRepo>);
        // `PgAuthGrantLifecycle: AuthGrantLifecycle` 完整 durable impl；类型级 anti-vacuity
        // 只检查 trait 满足、不执行 body。
        assert_auth_grant_lifecycle(PhantomData::<super::PgAuthGrantLifecycle>);
        assert_identity_security_lifecycle(PhantomData::<super::PgIdentitySecurityLifecycle>);
        assert_account_reactivation_lifecycle(PhantomData::<super::PgAccountReactivationLifecycle>);
        // `PgInboxStore: InboxStore + InboxBacklog` 类型级 anti-vacuity edge proof（不构造、不执行 body）。
        assert_inbox_store(PhantomData::<super::PgInboxStore>);
        assert_inbox_backlog(PhantomData::<super::PgInboxStore>);
        assert_outbox_backlog(PhantomData::<super::PgOutboxMaintenance>);
        assert_retention_sweeper(PhantomData::<super::PgOutboxMaintenance>);
        // `PgConfigRepo: ConfigRepo + ConfigUnitOfWork` 真实 impl（非 edge proof）——配置仓储 + co-tx UoW（#1249）。
        assert_config_repo(PhantomData::<super::PgConfigRepo>);
        assert_config_uow(PhantomData::<super::PgConfigRepo>);
        // Closed durable Saga writer + recovery boundary and checkpoint edge proof.
        assert_saga_durable_store(PhantomData::<super::PgSagaDurableStore>);
        assert_cas_store(PhantomData::<super::PgCasStore>);
        assert_checkpoint_store(PhantomData::<super::PgCheckpointStore>);
        assert_command_journal_store(PhantomData::<super::PgCommandJournal>);
        // secret 读写分槽：read-only repo + mutation UoW（#1274）。
        assert_secret_repo(PhantomData::<super::PgSecretRepo>);
        assert_secret_uow(PhantomData::<super::PgSecretUnitOfWork>);
        // `PgRefreshTokenStore: RefreshTokenStore` 真实 impl——哈希存储 + CAS rotation + 谱系级联撤销 + RLS（#1325）。
        assert_refresh_token_store(PhantomData::<super::PgRefreshTokenStore>);
        // `PgAuditRepo<TestVerifier>` 真实 read/write impl——append-only per-tenant keyed-HMAC chain + RLS（#1230）。
        // TestVerifier 是本地确定性 FNV-1a verifier（MacVerifier impl），足以证明 trait 满足；不执行 body。
        assert_audit_repo(
            PhantomData::<super::PgAuditRepo<super::audit_repo::test_support::TestVerifier>>,
        );
        // 真实 durable audit subscriber 的具体类型只能经 policy-bound `into_handler` 激活。
        assert_send_sync(
            PhantomData::<super::PgAuditConsumerTx<super::audit_repo::test_support::TestVerifier>>,
        );
        // `PgAuthGrantSweeper` 是 concrete postgres maintenance 能力，不 impl identity 域端口；Send+Sync smoke
        // 锁住可进入 runtime worker 的形状。
        assert_send_sync(PhantomData::<super::PgAuthGrantSweeper>);
        // PG-BUNDLE-DOMAIN-02：三个 per-domain marker 均满足 sealed `PgDomain`（去掉任一 impl 即编译失败）。
        assert_pg_domain(PhantomData::<super::caps::Settings>);
        assert_pg_domain(PhantomData::<super::caps::Identity>);
        assert_pg_domain(PhantomData::<super::caps::Audit>);
    }

    #[test]
    fn store_name_is_stable() {
        assert_eq!(super::PG_STORE_NAME, "postgres");
    }
}

#[cfg(test)]
mod runtime_guard_tests {
    use super::{PgStore, PgStoreGuard, PgStoreShutdown};
    use diport::ManagedResource as _;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::Arc;

    fn lazy_store() -> Arc<PgStore> {
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        Arc::new(PgStore {
            pool: PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy_with(opts),
        })
    }

    #[tokio::test]
    async fn constructors_seal_setup_and_runtime_shutdown_modes()
    -> Result<(), diport::ShutdownError> {
        let setup = PgStoreGuard::new_named(lazy_store(), "postgres-writer");
        assert!(matches!(setup.shutdown, PgStoreShutdown::SetupRollback));
        setup.shutdown().await?;

        let runtime = PgStoreGuard::new_runtime_named(lazy_store(), "postgres-tenant-reader");
        assert!(matches!(runtime.shutdown, PgStoreShutdown::RuntimeFence));
        runtime.shutdown().await?;
        Ok(())
    }

    /// `PgStoreGuard::shutdown()` 同步封闭 acquire，且重复 shutdown 幂等。
    ///
    /// `connect_lazy_with` 不发真实连接，允许精确证明 fence 而不依赖外部 PostgreSQL。
    #[tokio::test]
    async fn shutdown_fences_acquire_and_is_idempotent() -> Result<(), diport::ShutdownError> {
        let store = lazy_store();
        let guard = PgStoreGuard::new(Arc::clone(&store));
        assert_eq!(guard.name(), "postgres");
        assert!(!store.pool.is_closed());

        guard.shutdown().await?;

        assert!(store.pool.is_closed());
        assert!(matches!(
            store.pool.acquire().await,
            Err(sqlx::Error::PoolClosed)
        ));

        guard.shutdown().await?;
        assert!(store.pool.is_closed());
        Ok(())
    }
}
