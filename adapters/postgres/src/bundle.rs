//! postgres capability bundle（#1423 / PERSIST-002）：把 serving connect、ledger verification、readiness handle、
//! per-domain repo 构造收口到单一 funnel，对组合根的 wire_X 暴露**受控 per-domain 能力句柄**，
//! 绝不泄漏裸 `sqlx::PgPool`。
//!
//! 六个核心类型：
//! - [`PgRuntimeDeps`]：不可克隆的组合根生命周期 owner。唯一 serving 构造路径 [`PgRuntimeDeps::connect_serving`]；能力只经
//!   [`PgRuntimeDeps::handle`] 投影，生命周期只经 [`PgRuntimeDeps::into_runtime_parts`] 按值交接。
//! - [`PgRuntimeHandle`]：可克隆的运行期能力句柄，派发 [`PgRuntimeHandle::for_domain`] /
//!   [`PgRuntimeHandle::infra`] 与 readiness/RLS probe handle，不拥有生命周期出口；Projection source/control
//!   凭据不进入 serving handle。
//! - [`PgDomainDeps<D>`]：per-domain 受控句柄（`Clone`，私有持 `Arc<PgRuntimeStores>`），只暴露该域的 repo
//!   构造方法。类型参数 `D: PgDomain`（sealed marker）使「settings 的 deps 拿去建 identity repo」=
//!   编译错误 E0599（类型层不可表达）。
//! - [`PgInfraDeps`]：framework/global（provider-agnostic、非单域）基建能力句柄——emitter / inbox /
//!   dead_letter / checkpoint / saga，不绑 `caps::*` 域；不暴露 Projection raw source/control。
//! - [`PgSettingsBundle`]：settings 域 durable 接线包，经 [`PgDomainDeps::settings_bundle`] 单次构造（同一
//!   verified reader/writer capability pair + 单 clock 扇出），内部预包装 config/secret 各自的 read repo + write UoW 域形 DynX port；组合根经
//!   [`PgSettingsBundle::into_parts`] 单次解包注入，不再散装构造 / 手工配对（PERSIST-003）。
//! - Settings metadata projection 只向 serving 组合根暴露 read capability；mutation 只能经 sealed
//!   `ProjectionTargetStore` target funnel。
//!
//! ## INVARIANT
//!
//! - **PG-BUNDLE-FUNNEL-01**（Hard，可见性封装）：公开 store 构造路径只允许按用途分离的受控 funnel：
//!   [`PgRuntimeDeps::connect_serving`]（serving runtime，只读验证 schema ledger）与
//!   [`PgRuntimeDeps::connect_maintenance`]（离线通用维护），以及独立的
//!   [`PgProjectionOperatorDeps`]（receipt-bound Projection source / function-only control）。除此之外
//!   `PgStore::connect` / `run_migrations` 已降 `pub(crate)`，外部无法 mint `PgStore`、也拿不到 `&PgStore`；
//!   且**所有** `&PgStore`-taking repo 构造器（含 credential/role/refresh_token/emitter + dead_letter/
//!   checkpoint/saga/projection）均 `pub(crate)`——serving repo 只能经 `PgDomainDeps` / `PgInfraDeps` 构造，
//!   maintenance 只能拿到限定维护能力，不暴露 pool/store。
//! - **PG-BUNDLE-DOMAIN-02**（Hard，sealed marker + typed function choice）：per-domain 能力隔离。
//!   anti-vacuity = 下方 `PgDomainDeps` 的 `compile_fail` doctest（Settings 句柄调 `auth_grant_lifecycle` 必败）。
//! - **PG-BUNDLE-POOL-03**（Hard）：本模块无任何返回 `&PgStore` / `Arc<PgStore>` / `PgPool` 的公开 accessor；
//!   `store` 字段私有，仅 in-crate repo 构造方法 clone `pub(crate) pool`。
//! - **PG-BUNDLE-SETTINGS-04**（Hard，可见性 + sealed funnel + typed function choice）：settings 四件套
//!   （config read/write + secret read/write）只能经 [`PgDomainDeps::settings_bundle`] 单次构造（funnel，
//!   私有字段 + 唯一公开构造 ⇒ 外部 crate 无法 mint），经 [`PgSettingsBundle::into_parts`] 解包；一次
//!   `into_parts` 产出的四元同源（同一 verified reader/writer capability pair + 同一注入 clock，clock 经 `Arc` 扇出到两个 `PgConfigRepo`）。
//!   四件为互不可换的域形 dyn 类型（`DynConfigRepo`/`DynConfigUnitOfWork`/`DynSecretRepo`/
//!   `DynSecretUnitOfWork`）⇒ 注入 service 时 read/write **角色无法错插**（typed function choice）。
//!   散装 `config_repo()` / `secret_repo()`
//!   accessor 已删除（不留兼容路径）。**强制边界**：funnel 守上游构造 + 角色槽位；`into_parts` 后四件为
//!   owned 值，类型层不阻止把不同 bundle 实例的 box 跨实例重组（单一 `PgRuntimeDeps` ⇒ 同一 capability pair，跨 bundle
//!   重组为 contrived），故不声称该项。anti-vacuity = [`PgSettingsBundle`] 私有字段 `compile_fail` doctest
//!   （须经 `into_parts` 唯一出口，不可旁路直读单字段）。
//!
//! ## 开源对标
//!
//! - `ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/mod.rs@main` —— 两层私有
//!   （`Pool.inner` → `DataStore.pool: Arc<Pool>`）+ `pool_connection_authorized` `pub(super)`；构造器集中 +
//!   schema 门控。本模块对应：连接函数 `pub(crate)` + `PgRuntimeDeps` 私有持 `Arc<PgRuntimeStores>`。
//! - `ref: risingwavelabs/risingwave src/meta/src/manager/env.rs@main` —— `MetaSrvEnv`（`meta_store_impl`
//!   私有）`#[derive(Clone)]` 能力包 + accessor，各 manager 接 `env.clone()`。对应：`PgDomainDeps` Clone 句柄。
//! - `ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main` —— `Controller::run(.., Arc<Ctx>)` 注入
//!   shared context。对应：`for_domain::<D>()` 派发受控句柄。

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use authn::{ProjectionMaintenanceAction, ProjectionMaintenanceReceipt};
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use diport::DynPublisher;
use diport::{Clock, DynCasStore, DynManagedResource, ManagedResource};
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use eventexec::{RelayBudget, TenantAuthority};
#[cfg(feature = "domain-settings")]
use settings::ports::{
    DynConfigRepo, DynConfigUnitOfWork, DynSecretRepo, DynSecretUnitOfWork,
    DynSettingsProjectionReadRepo,
};
#[cfg(feature = "test-support")]
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "auth-audit-sink")]
use crate::PgAuthAuditSink;
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use crate::PgOutbox;
#[cfg(feature = "domain-audit")]
use crate::consumer_tx::PgAuditConsumerTx;
use crate::cotx::eventing::DlqReplayProjection;
use crate::delivery_policy::EventDeliveryPolicy;
use crate::pool::{
    PgRuntimeStores, VerifiedPgAuditAdminStore, VerifiedPgMaintenanceStore,
    VerifiedPgProjectionOperatorStore, VerifiedPgProjectionSourceReadStore,
    VerifiedPgSagaOperatorStore,
};
use crate::projection_events::{
    PgProjectionSourceReader, ProjectionCaptureRegistration, ProjectionWriteRegistry,
};
use crate::revocation::RevocationCapabilityReceipt;
use crate::saga_receipt_capability::SagaReceiptCapabilityReceipt;
#[cfg(feature = "domain-settings")]
use crate::{
    ConfigValueMaintenanceCapability, ConfigValueProtection, ConfigValueProtections, PgConfigRepo,
    PgConfigValueMaintenance, PgSecretRepo, PgSecretUnitOfWork, PgSettingsConsumerTx,
    PgSettingsProjectionApplyStore, PgSettingsProjectionReadRepo,
};
use crate::{
    DlxPayloadProtector, PgAuthGrantSweeper, PgCheckpointStore, PgCommandJournal, PgConfig,
    PgDbReadiness, PgDeadLetterStore, PgDlqStore, PgEmitter, PgError, PgInboxStore, PgInboxSweeper,
    PgMaintenanceReconcileStore, PgOutboxCdcEmitter, PgOutboxMaintenance,
    PgProjectionOperatorConfig, PgProjectionSourceReadConfig, PgReadinessSampler, PgReconcileStore,
    PgRevocationStore, PgRevocationSweeper, PgSagaDurableStore, PgSagaOperatorConfig,
    PgSagaReceiptProtection, PgSagaTerminalSweeper, PgServiceTokenReplayStore,
    PgServiceTokenReplaySweeper, PgStore, PgStoreGuard, PgTenantReadConfig,
};
#[cfg(feature = "domain-audit")]
use crate::{PgAuditAdminRepo, PgAuditRepo};
#[cfg(feature = "domain-identity")]
use crate::{
    PgAuthGrantLifecycle, PgAuthGrantProvider, PgAuthGrantValidator, PgCredentialRepo,
    PgDeviceCertificateRepository, PgIdentitySecurityLifecycle, PgPolicyLifecycle, PgPolicyRepo,
    PgRefreshTokenStore, PgResourceAttributeRepo, PgRoleBindingLifecycle, PgRoleBindingReadRepo,
    PgRoleRepo,
};

/// per-domain 能力 marker 的 sealed 封闭——外部 crate 无法新增域 marker（无法 impl `Sealed`）。
mod sealed {
    pub trait Sealed {}
}

/// postgres capability bundle 的 per-domain marker（sealed）。
///
/// 实现集封闭在本 crate（[`caps`] 下的 ZST）；外部 crate 既不能命名内层 `Sealed`、也不能新增 marker，
/// 故 `PgDomainDeps<D>` 的 `D` 只能是本 crate 声明的域（PG-BUNDLE-DOMAIN-02）。
pub trait PgDomain: sealed::Sealed {
    /// 与 sealed capability marker 一一绑定的 durable event domain。
    const NAME: &'static str;
}

#[allow(clippy::expect_used)]
// reason: NAME 只由本 crate 的 sealed marker 常量提供；解析把 marker 变成 provider-bound typed domain。
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn bound_domain<D: PgDomain>() -> vocab::DomainName {
    vocab::DomainName::parse(D::NAME).expect("sealed postgres domain marker must be valid")
}

/// per-domain 能力 marker ZST。
///
/// `caps` 命名避开 `rss_domain_no_serialize` 的 `domain` 模块启发式，且 `caps::Settings`/`caps::Identity`
/// 不与同名域 crate 冲突。变体随各域 durable 接线切片增加（当前 Settings + Identity + Audit）。
pub mod caps {
    /// settings 域能力 marker。
    #[cfg(feature = "domain-settings")]
    pub struct Settings;
    /// identity 域能力 marker。
    #[cfg(feature = "domain-identity")]
    pub struct Identity;
    /// audit 域能力 marker。
    #[cfg(feature = "domain-audit")]
    pub struct Audit;
}

#[cfg(feature = "domain-settings")]
impl sealed::Sealed for caps::Settings {}
#[cfg(feature = "domain-settings")]
impl PgDomain for caps::Settings {
    const NAME: &'static str = "settings";
}
#[cfg(feature = "domain-identity")]
impl sealed::Sealed for caps::Identity {}
#[cfg(feature = "domain-identity")]
impl PgDomain for caps::Identity {
    const NAME: &'static str = "identity";
}
#[cfg(feature = "domain-audit")]
impl sealed::Sealed for caps::Audit {}
#[cfg(feature = "domain-audit")]
impl PgDomain for caps::Audit {
    const NAME: &'static str = "audit";
}

/// 组合根级 postgres 生命周期 owner：只连接已迁移 schema，并唯一拥有 pool 与 sampler 的关闭权。
///
/// INVARIANT: PG-RUNTIME-OWNER-01 { level = "Hard", exec = "native-compile", source = "code", native = "non-Clone owner and consuming into_runtime_parts self receiver; trybuild rejects clone and double consumption" }
///
/// 该类型刻意不实现 `Clone`。能力经 [`Self::handle`] 克隆为 [`PgRuntimeHandle`]；生命周期经
/// [`Self::into_runtime_parts`] 按值消费，类型层禁止第二次交接。
pub struct PgRuntimeDeps {
    handle: PgRuntimeHandle,
}

/// 可克隆的 postgres 运行期能力句柄。
///
/// INVARIANT: PG-RUNTIME-HANDLE-02 { level = "Hard", exec = "native-compile", source = "code", native = "private capability-only fields and no lifecycle methods; trybuild rejects lifecycle projection" }
///
/// 仅持 capability 投影所需共享状态；owner 直接包这一份 handle，`handle()` 只克隆其中的 Arc，因而权限分离
/// 不会形成第二份数据源。不提供 pool guard、sampler factory 或 lifecycle output API。
#[derive(Clone)]
pub struct PgRuntimeHandle {
    stores: Arc<PgRuntimeStores>,
    revocation_receipt: RevocationCapabilityReceipt,
    saga_receipt: SagaReceiptCapabilityReceipt,
    audit_admin_store: Option<VerifiedPgAuditAdminStore>,
    delivery_policy: EventDeliveryPolicy,
    projection_registry: ProjectionWriteRegistry,
    projection_capture: Option<ProjectionCaptureRegistration>,
    readiness: Arc<PgDbReadiness>,
    rls_ready: Arc<AtomicBool>,
}

/// Single-origin PostgreSQL capability receipt for the DeviceLatent draft pilot.
///
/// All five projections are minted from one [`PgRuntimeHandle`] invocation. The private fields
/// prevent an assembly from combining readiness, reconcile, certificate, command, and revocation
/// capabilities sourced from different PostgreSQL runtimes.
#[cfg(feature = "domain-identity")]
pub struct PgDeviceIdentityDraftRuntime {
    repository:
        PgDeviceCertificateRepository<identity::ports::device_certificate::DraftEligibility>,
    commands: crate::PgDeviceCommandStore<identity::ports::device_certificate::DraftEligibility>,
    revocations: PgRevocationStore,
    reconcile: PgReconcileStore,
    readiness: Arc<PgDbReadiness>,
}

#[cfg(feature = "domain-identity")]
impl PgDeviceIdentityDraftRuntime {
    /// Project the same-origin revocation provider into assembly infrastructure wiring.
    #[must_use]
    pub fn revocation_store(&self) -> PgRevocationStore {
        self.revocations.clone()
    }

    /// Consume the single-origin receipt inside the canonical identity composition root.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PgDeviceCertificateRepository<identity::ports::device_certificate::DraftEligibility>,
        crate::PgDeviceCommandStore<identity::ports::device_certificate::DraftEligibility>,
        PgRevocationStore,
        PgReconcileStore,
        Arc<PgDbReadiness>,
    ) {
        (
            self.repository,
            self.commands,
            self.revocations,
            self.reconcile,
            self.readiness,
        )
    }
}

/// DB readiness sampler 的单次启动工厂。
///
/// `spawn(self, token)` 消费工厂；同一 owner 产生的 factory 无法启动第二个 sampler。
pub struct PgReadinessSamplerFactory {
    writer_store: Arc<PgStore>,
    reader_store: Arc<PgStore>,
    projection_capture: Option<ProjectionCaptureRegistration>,
    readiness: Arc<PgDbReadiness>,
    period: Duration,
}

/// Owns every pool created by one fallible setup segment until that segment either commits the
/// resources to its caller or explicitly closes them.
///
/// Registration order is construction order. [`Self::close`] consumes the transaction and delegates
/// to [`bootstrap::shutdown::ShutdownStack`], making LIFO, continue-on-error, and single-shot cleanup
/// structural rather than conventions repeated at each `?` site.
struct PgSetupTransaction {
    stack: bootstrap::shutdown::ShutdownStack,
}

impl PgSetupTransaction {
    fn new() -> Self {
        Self {
            stack: bootstrap::shutdown::ShutdownStack::new(CancellationToken::new()),
        }
    }

    fn register<R>(&mut self, resource: R)
    where
        R: ManagedResource + 'static,
    {
        self.stack
            .register_detached(DynManagedResource::new_box(resource));
    }

    /// Transfers lifecycle ownership to the typed runtime owner without closing its pools.
    fn commit(self) {}

    /// Closes every resource once in reverse construction order while preserving the setup outcome.
    ///
    /// Cleanup diagnostics are always secondary: in particular, an error returned by a later setup
    /// stage remains the function's primary error even if one or more rollback operations fail.
    async fn close<T, E>(self, outcome: Result<T, E>) -> Result<T, E> {
        for failure in self.stack.shutdown().await {
            tracing::warn!(
                target: "postgres",
                error = %secure::redact_error(&failure),
                "postgres startup cleanup failed; preserving primary setup outcome"
            );
        }
        outcome
    }
}

#[cfg(test)]
mod setup_transaction_tests {
    use std::sync::{Arc, Mutex};

    use diport::{ManagedResource, ShutdownError};

    use super::PgSetupTransaction;

    struct RecordingResource {
        name: &'static str,
        shutdowns: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl ManagedResource for RecordingResource {
        fn name(&self) -> &str {
            self.name
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            self.shutdowns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.name);
            if self.fail {
                Err(ShutdownError::new(std::io::Error::other(
                    "injected setup cleanup failure",
                )))
            } else {
                Ok(())
            }
        }
    }

    fn resource(
        name: &'static str,
        shutdowns: &Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    ) -> RecordingResource {
        RecordingResource {
            name,
            shutdowns: Arc::clone(shutdowns),
            fail,
        }
    }

    #[tokio::test]
    async fn every_migrator_stage_failure_closes_once_and_preserves_primary() {
        for stage in [
            "run-migrations",
            "load-delivery-policy",
            "verify-legacy-plaintext-policy",
            "register-projection-bindings",
        ] {
            let shutdowns = Arc::new(Mutex::new(Vec::new()));
            let mut transaction = PgSetupTransaction::new();
            transaction.register(resource("postgres-migrator", &shutdowns, false));

            let result = transaction.close(Err::<(), _>(stage)).await;

            assert_eq!(result, Err(stage));
            assert_eq!(
                *shutdowns
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                ["postgres-migrator"],
                "stage {stage} must close the migrator exactly once"
            );
        }
    }

    #[tokio::test]
    async fn successful_migrator_setup_still_closes_once() {
        let shutdowns = Arc::new(Mutex::new(Vec::new()));
        let mut transaction = PgSetupTransaction::new();
        transaction.register(resource("postgres-migrator", &shutdowns, false));

        assert_eq!(
            transaction.close(Ok::<_, &'static str>("ready")).await,
            Ok("ready")
        );
        assert_eq!(
            *shutdowns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ["postgres-migrator"]
        );
    }

    #[tokio::test]
    async fn reader_failure_closes_writer_once_and_preserves_primary() {
        let shutdowns = Arc::new(Mutex::new(Vec::new()));
        let mut transaction = PgSetupTransaction::new();
        transaction.register(resource("postgres-writer", &shutdowns, false));

        let result = transaction
            .close(Err::<(), _>("reader-connect-primary"))
            .await;

        assert_eq!(result, Err("reader-connect-primary"));
        assert_eq!(
            *shutdowns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ["postgres-writer"]
        );
    }

    #[tokio::test]
    async fn audit_failure_closes_reader_then_writer_and_cleanup_failure_is_secondary() {
        let shutdowns = Arc::new(Mutex::new(Vec::new()));
        let mut transaction = PgSetupTransaction::new();
        transaction.register(resource("postgres-writer", &shutdowns, false));
        transaction.register(resource("postgres-reader", &shutdowns, true));

        let result = transaction
            .close(Err::<(), _>("audit-admin-connect-primary"))
            .await;

        assert_eq!(result, Err("audit-admin-connect-primary"));
        assert_eq!(
            *shutdowns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ["postgres-reader", "postgres-writer"],
            "cleanup must remain LIFO and continue after a cleanup error"
        );
    }

    #[test]
    fn successful_serving_commit_does_not_close_transferred_resources() {
        let shutdowns = Arc::new(Mutex::new(Vec::new()));
        let mut transaction = PgSetupTransaction::new();
        transaction.register(resource("postgres-writer", &shutdowns, false));
        transaction.register(resource("postgres-reader", &shutdowns, false));
        transaction.register(resource("postgres-audit-admin", &shutdowns, false));

        transaction.commit();

        assert!(
            shutdowns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "commit transfers lifecycle ownership without early shutdown"
        );
    }
}

impl PgReadinessSamplerFactory {
    /// 使用 `ShutdownStack` 注入的 token 启动 sampler，并消费本 factory。
    #[must_use]
    pub fn spawn(self, token: CancellationToken) -> PgReadinessSampler {
        let handle = tokio::spawn(crate::readiness::pg_readiness_sampling_loop(
            self.writer_store,
            self.reader_store,
            self.projection_capture,
            self.period,
            token.clone(),
            Arc::clone(&self.readiness),
        ));
        PgReadinessSampler::adopt(handle, self.readiness, token)
    }
}

/// 离线维护用 postgres 能力包。
///
/// 只用 migrator/owner 连接执行 schema migration 与全库维护扫描；不构造 serving pool、不跑 RLS 能力门、不跑
/// legacy plaintext deny 门，否则 backfill 命令会在最需要运行时被 scheme=0 启动门挡住。
pub struct PgMaintenanceDeps {
    store: VerifiedPgMaintenanceStore,
    audit_admin_store: Option<VerifiedPgAuditAdminStore>,
    _delivery_policy: EventDeliveryPolicy,
    clock: Arc<dyn Clock>,
}

/// Function-only PostgreSQL capabilities for the Saga operator CLI.
pub struct PgSagaOperatorDeps {
    operator: VerifiedPgSagaOperatorStore,
    clock: Arc<dyn Clock>,
}

/// Independent Projection control-plane capability owner.
///
/// The public surface contains only Projection operations. The control credential owns no raw
/// relation privilege; the separately verified source credential can only read a sealed scope.
pub struct PgProjectionOperatorDeps {
    operator: VerifiedPgProjectionOperatorStore,
    source: VerifiedPgProjectionSourceReadStore,
    clock: Arc<dyn Clock>,
}

/// Opaque, single-target Projection operator authority.
///
/// The only mint validates the non-clone authorization receipt, requested action, command
/// selector, and assembly-sealed source scope together. Definition identity and shadow generation
/// are deliberately independent axes: rollback may select an older shadow generation while the
/// source reader remains bound to the current assembly-sealed definition. Private fields make a
/// source from one tenant/projection impossible to pair with another target's checkpoint or
/// dead-letter capability.
/// INVARIANT: PG-PROJECTION-OPERATOR-TARGET-05 { level = "Hard", exec = "native-compile", source = "code", native = "consumed receipt and sealed scope, private target fields, sealed action marker, consuming action-specific methods, opaque replay runner" }.
pub struct PgProjectionOperatorCapability<'a, A> {
    deps: &'a PgProjectionOperatorDeps,
    receipt: ProjectionMaintenanceReceipt,
    target: ProjectionOperatorTarget,
    source: PgProjectionSourceReader,
    _action: PhantomData<A>,
}

mod projection_operator_action {
    pub trait Sealed {
        const ACTION: authn::ProjectionMaintenanceAction;
    }
}

/// Closed action marker accepted by the Projection operator capability mint.
pub trait PgProjectionOperatorAction: projection_operator_action::Sealed {}

/// Status-only Projection operator action marker.
pub struct ProjectionStatusAction;
/// Swap-only Projection operator action marker.
pub struct ProjectionSwapAction;
/// Replay-only Projection operator action marker.
pub struct ProjectionReplayAction;

impl projection_operator_action::Sealed for ProjectionStatusAction {
    const ACTION: ProjectionMaintenanceAction = ProjectionMaintenanceAction::Status;
}
impl PgProjectionOperatorAction for ProjectionStatusAction {}

impl projection_operator_action::Sealed for ProjectionSwapAction {
    const ACTION: ProjectionMaintenanceAction = ProjectionMaintenanceAction::Swap;
}
impl PgProjectionOperatorAction for ProjectionSwapAction {}

impl projection_operator_action::Sealed for ProjectionReplayAction {
    const ACTION: ProjectionMaintenanceAction = ProjectionMaintenanceAction::Replay;
}
impl PgProjectionOperatorAction for ProjectionReplayAction {}

/// In-crate target evidence derived only by the public opaque capability mint.
pub(crate) struct ProjectionOperatorTarget {
    selector: eventexec::ProjectionSelector,
}

impl ProjectionOperatorTarget {
    fn bind(
        selector: &eventexec::ProjectionSelector,
        scope: &eventexec::ProjectionSourceScope,
    ) -> Result<Self, crate::ProjectionControlError> {
        if scope.tenant() != selector.tenant() || scope.projection() != selector.projection() {
            return Err(crate::ProjectionControlError::SourceTargetMismatch);
        }
        Ok(Self {
            selector: selector.clone(),
        })
    }

    pub(crate) fn selector(&self) -> &eventexec::ProjectionSelector {
        &self.selector
    }
}

impl PgProjectionOperatorDeps {
    /// Connect two independent credentials and verify both exact capability surfaces.
    pub async fn connect(
        operator_config: &PgProjectionOperatorConfig,
        source_config: &PgProjectionSourceReadConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PgError> {
        let operator = PgStore::connect_verified_projection_operator(operator_config).await?;
        let source = match PgStore::connect_verified_projection_source_read(source_config).await {
            Ok(source) => source,
            Err(error) => {
                let _ = operator.store_arc().shutdown().await;
                return Err(error);
            }
        };
        Ok(Self {
            operator,
            source,
            clock,
        })
    }

    /// Mint one action- and target-bound operator authority from all four independent proofs.
    pub fn authorize_projection_target<'a, A: PgProjectionOperatorAction>(
        &'a self,
        receipt: ProjectionMaintenanceReceipt,
        _action: A,
        selector: &eventexec::ProjectionSelector,
        scope: eventexec::ProjectionSourceScope,
    ) -> Result<PgProjectionOperatorCapability<'a, A>, crate::ProjectionControlError> {
        crate::projection_control::authorize_receipt(&receipt, A::ACTION, selector)?;
        let target = ProjectionOperatorTarget::bind(selector, &scope)?;
        let source = PgProjectionSourceReader::new(&self.operator, &self.source, scope);
        Ok(PgProjectionOperatorCapability {
            deps: self,
            receipt,
            target,
            source,
            _action: PhantomData,
        })
    }

    #[must_use]
    pub fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(crate::PgServiceTokenReplayStore::new(
            self.operator.store_arc(),
        ))
    }

    pub async fn record_projection_maintenance_audit(
        &self,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> Result<(), PgError> {
        let duration = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| PgError::MaintenanceAudit(sqlx::Error::Decode(Box::new(error))))?;
        let secs = i64::try_from(duration.as_secs())
            .map_err(|error| PgError::MaintenanceAudit(sqlx::Error::Decode(Box::new(error))))?;
        let nanos = i32::try_from(duration.subsec_nanos())
            .map_err(|error| PgError::MaintenanceAudit(sqlx::Error::Decode(Box::new(error))))?;
        let (outcome, failure_reason) = match outcome {
            MaintenanceAuditOutcome::Success => ("success", None),
            MaintenanceAuditOutcome::Failure { reason } => ("failure", Some(reason)),
        };
        sqlx::query(
            r#"
            SELECT public.rss_projection_operator_record_audit($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(secs)
        .bind(nanos)
        .bind(operator_subject)
        .bind(resource_id)
        .bind(action)
        .bind(outcome)
        .bind(failure_reason)
        .execute(&self.operator.store_arc().pool)
        .await
        .map_err(PgError::MaintenanceAudit)?;
        Ok(())
    }

    /// Close source first, then the operator control-plane pool.
    pub async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        let source_result = self.source.store_arc().shutdown().await;
        let operator_result = self.operator.store_arc().shutdown().await;
        source_result?;
        operator_result
    }
}

impl PgProjectionOperatorCapability<'_, ProjectionStatusAction> {
    pub async fn status(
        self,
    ) -> Result<crate::ProjectionPointerStatus, crate::ProjectionControlError> {
        PgStore::projection_control(self.deps.operator.store_arc(), &self.receipt, &self.source)
            .status(self.target.selector())
            .await
    }
}

impl PgProjectionOperatorCapability<'_, ProjectionSwapAction> {
    pub async fn promote(
        self,
        precondition: crate::ProjectionPointerPrecondition,
    ) -> Result<crate::ProjectionPromoteOutcome, crate::ProjectionControlError> {
        PgStore::projection_control(self.deps.operator.store_arc(), &self.receipt, &self.source)
            .promote(self.target.selector(), precondition)
            .await
    }
}

impl PgProjectionOperatorCapability<'_, ProjectionReplayAction> {
    /// Build the canonical Settings target with the already-authorized operator credential.
    /// Production activation remains owned by #1920; this only closes the target/ACL protocol.
    #[cfg(feature = "domain-settings")]
    pub fn into_settings_replay_stores(
        self,
        definition: eventexec::ProjectionTargetDefinition,
        bindings: Vec<vocab::ProjectionInputBinding>,
        payload_protector: DlxPayloadProtector,
    ) -> Result<PgProjectionReplayStores, eventexec::ProjectionTargetConfigError> {
        let store = Arc::new(
            crate::PgSettingsProjectionApplyStore::new_projection_operator(&self.deps.operator),
        );
        let target = Arc::new(eventexec::ConformingProjectionTarget::new(
            definition, bindings, store,
        )?);
        Ok(self.into_replay_stores(target, payload_protector))
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn into_settings_replay_stores_with_test_fault(
        self,
        definition: eventexec::ProjectionTargetDefinition,
        bindings: Vec<vocab::ProjectionInputBinding>,
        payload_protector: DlxPayloadProtector,
        fault: crate::settings_projection::SettingsProjectionTestFault,
    ) -> Result<PgProjectionReplayStores, eventexec::ProjectionTargetConfigError> {
        let store = Arc::new(
            crate::PgSettingsProjectionApplyStore::new_projection_operator(&self.deps.operator),
        );
        store.inject_test_fault(fault);
        let target = Arc::new(eventexec::ConformingProjectionTarget::new(
            definition, bindings, store,
        )?);
        Ok(self.into_replay_stores(target, payload_protector))
    }

    pub fn into_replay_stores(
        self,
        projection_target: Arc<dyn eventexec::ProjectionTarget>,
        payload_protector: DlxPayloadProtector,
    ) -> PgProjectionReplayStores {
        let checkpoint =
            PgCheckpointStore::new_projection_operator(&self.deps.operator, &self.target);
        let dead_letter = PgDeadLetterStore::new_projection_operator(
            &self.deps.operator,
            &self.target,
            payload_protector,
        );
        let selector = self.target.selector().clone();
        let witness = consistency::SerialInOrder::from_source(&self.source);
        let harness = eventexec::ProjectionHarness::new(
            Arc::new(eventexec::ProjectionProjector::new(
                selector.clone(),
                projection_target,
            )),
            Arc::new(checkpoint),
            selector.shadow_checkpoint_owner(),
            selector.shadow_checkpoint_id(),
            Arc::new(dead_letter),
            witness,
        );
        PgProjectionReplayStores {
            events: self.source,
            harness,
        }
    }
}

/// Projection replay 所需的最小 store 集；字段私有，防止 maintenance 获得通用 infra 能力。
pub struct PgProjectionReplayStores {
    events: PgProjectionSourceReader,
    harness: eventexec::ProjectionHarness<
        eventexec::ProjectionProjector,
        PgCheckpointStore,
        PgDeadLetterStore,
    >,
}

impl PgProjectionReplayStores {
    /// Execute one replay batch without exposing independently swappable source/checkpoint/DLX.
    pub async fn run_once(
        &self,
        config: eventexec::ProjectionRunnerConfig,
    ) -> eventexec::ProjectionRun {
        eventexec::projection_runner_once(&self.events, &self.harness, config).await
    }
}

struct PgMaintenanceSystemClock;

impl Clock for PgMaintenanceSystemClock {
    fn now(&self) -> SystemTime {
        // reason: postgres maintenance production clock; adapter-owned Clock impl is a sanctioned system-time boundary.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

impl PgRuntimeDeps {
    #[cfg(any(test, feature = "test-support", feature = "fault-matrix-test-support"))]
    pub async fn setup_test_fixture(
        migrator_config: &PgConfig,
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        audit_admin_config: Option<&PgConfig>,
        projection_capture: eventexec::ProjectionCaptureView<'_>,
    ) -> Result<Self, PgError> {
        let projection_capture = ProjectionCaptureRegistration::from_capture(projection_capture);
        Self::setup_test_fixture_inner(
            migrator_config,
            serving_config,
            tenant_read_config,
            audit_admin_config,
            projection_capture,
        )
        .await
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn setup_test_fixture_with_projection_bindings(
        migrator_config: &PgConfig,
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        audit_admin_config: Option<&PgConfig>,
        projection_generation: &'static str,
        projection_inputs: &[vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        let projection_capture =
            ProjectionCaptureRegistration::from_selected(projection_generation, projection_inputs);
        Self::setup_test_fixture_inner(
            migrator_config,
            serving_config,
            tenant_read_config,
            audit_admin_config,
            projection_capture,
        )
        .await
    }

    #[cfg(any(test, feature = "test-support", feature = "fault-matrix-test-support"))]
    async fn setup_test_fixture_inner(
        migrator_config: &PgConfig,
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        audit_admin_config: Option<&PgConfig>,
        projection_capture: Option<ProjectionCaptureRegistration>,
    ) -> Result<Self, PgError> {
        let migrator = PgStore::connect(migrator_config).await?;
        let migration = migrator.run_migrations().await;
        if let Err(error) = migration {
            let _ = migrator.shutdown().await;
            return Err(error);
        }
        let delivery_policy = migrator.load_event_delivery_policy().await?;
        if let Some(capture) = projection_capture.as_ref() {
            migrator
                .register_projection_capture(capture)
                .await
                .map_err(PgError::ProjectionBindings)?;
        }
        let _ = migrator.shutdown().await;
        Self::connect_serving_inner(
            serving_config,
            tenant_read_config,
            audit_admin_config,
            projection_capture,
            Some(delivery_policy),
        )
        .await
    }

    /// Owner-only projection for serving service-token authentication.
    ///
    /// The cloneable [`PgRuntimeHandle`] deliberately has no replay writer projection, so only the
    /// composition root holding this non-Clone owner can inject the capability into the PDP.
    #[must_use]
    pub fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(PgServiceTokenReplayStore::new(
            self.handle.stores.writer_store_arc(),
        ))
    }

    /// 唯一 serving 构造路径。只读核验 SQLx ledger 与编译进 binary 的 HEAD 完全一致，然后建立
    /// 最小权限 writer/reader pools；本 API 不接受 migrator config，也无法执行 DDL。
    ///
    /// INVARIANT: MIGRATION-CAPABILITY-SEPARATION-01 { level = "Hard", exec = "native-compile", source = "code", native = "serving API has no migration credential or executor and postgres-migration is absent from serving Cargo graphs" }
    pub async fn connect_serving(
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        audit_admin_config: Option<&PgConfig>,
        projection_capture: eventexec::ProjectionCaptureView<'_>,
    ) -> Result<Self, PgError> {
        let projection_capture = ProjectionCaptureRegistration::from_capture(projection_capture);
        Self::connect_serving_inner(
            serving_config,
            tenant_read_config,
            audit_admin_config,
            projection_capture,
            None,
        )
        .await
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn connect_serving_with_projection_bindings(
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        audit_admin_config: Option<&PgConfig>,
        projection_generation: &'static str,
        projection_inputs: &[vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        let projection_capture =
            ProjectionCaptureRegistration::from_selected(projection_generation, projection_inputs);
        Self::connect_serving_inner(
            serving_config,
            tenant_read_config,
            audit_admin_config,
            projection_capture,
            None,
        )
        .await
    }

    // reason: the setup transaction deliberately keeps every capability failure and rollback edge
    // visible in one AST-governed carrier; extracting branches would weaken the fail-closed check.
    #[allow(clippy::cognitive_complexity)]
    async fn connect_serving_inner(
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        audit_admin_config: Option<&PgConfig>,
        projection_capture: Option<ProjectionCaptureRegistration>,
        preloaded_delivery_policy: Option<EventDeliveryPolicy>,
    ) -> Result<Self, PgError> {
        let mut serving_transaction = PgSetupTransaction::new();
        let writer = PgStore::connect_verified_writer(serving_config).await?;
        serving_transaction.register(PgStoreGuard::new_named(
            writer.store_arc(),
            "postgres-writer",
        ));
        let writer_store = writer.store_arc();
        let delivery_policy = match preloaded_delivery_policy {
            Some(policy) => policy,
            None => match writer_store.load_event_delivery_policy().await {
                Ok(policy) => policy,
                Err(primary) => return serving_transaction.close(Err(primary)).await,
            },
        };
        let projection_validation = match projection_capture.as_ref() {
            Some(capture) => writer_store
                .validate_projection_capture_registration(capture)
                .await
                .map_err(PgError::ProjectionBindings),
            None => Ok(()),
        };
        if let Err(primary) = projection_validation {
            return serving_transaction.close(Err(primary)).await;
        }
        let revocation_receipt = match writer.verify_revocation_capability().await {
            Ok(receipt) => receipt,
            Err(primary) => return serving_transaction.close(Err(primary)).await,
        };
        let saga_receipt = match writer.verify_saga_receipt_capability().await {
            Ok(receipt) => receipt,
            Err(primary) => return serving_transaction.close(Err(primary)).await,
        };
        let reader = match PgStore::connect_verified_read(tenant_read_config).await {
            Ok(reader) => reader,
            Err(primary) => return serving_transaction.close(Err(primary)).await,
        };
        serving_transaction.register(PgStoreGuard::new_named(
            reader.store_arc(),
            "postgres-reader",
        ));
        let stores = Arc::new(PgRuntimeStores::new(writer, reader));
        let audit_admin_store = match audit_admin_config {
            Some(config) => {
                let store = match PgStore::connect_verified_audit_admin(config).await {
                    Ok(store) => store,
                    Err(primary) => return serving_transaction.close(Err(primary)).await,
                };
                serving_transaction.register(PgStoreGuard::new_named(
                    store.store_arc(),
                    "postgres-audit-admin",
                ));
                Some(store)
            }
            None => None,
        };
        let owner = Self {
            handle: PgRuntimeHandle {
                stores,
                revocation_receipt,
                saga_receipt,
                audit_admin_store,
                delivery_policy,
                projection_registry: projection_capture
                    .as_ref()
                    .map_or_else(ProjectionWriteRegistry::empty, |capture| capture.registry()),
                projection_capture,
                readiness: Arc::new(PgDbReadiness::new()),
                rls_ready: Arc::new(AtomicBool::new(true)),
            },
        };
        serving_transaction.commit();
        Ok(owner)
    }

    /// 连接离线维护能力包，但绝不运行 migration。
    ///
    /// 破坏式 migration 只能由完成全部外部 capability preflight 的 runtime bootstrap 执行；CLI
    /// maintenance 连接若隐式迁移会绕过该顺序门。schema/policy 缺失时，本入口读取固定 policy 即失败。
    pub async fn connect_maintenance(
        migrator_config: &PgConfig,
    ) -> Result<PgMaintenanceDeps, PgError> {
        let raw_store = Arc::new(PgStore::connect(migrator_config).await?);
        let delivery_policy = raw_store.load_event_delivery_policy().await?;
        let store = VerifiedPgMaintenanceStore::from_maintenance_store(raw_store);
        Ok(PgMaintenanceDeps {
            store,
            audit_admin_store: None,
            _delivery_policy: delivery_policy,
            clock: Arc::new(PgMaintenanceSystemClock),
        })
    }

    /// 构造带 audit-admin 只读池的离线维护能力包；只用于 per-tenant audit ledger verify。
    ///
    /// `migrator_config` 仍只负责 migration / durable audit 写入；`audit_admin_config` 必须直连
    /// `rss_audit_admin`，并通过 exact read-only capability gate。
    pub async fn connect_maintenance_with_audit_admin_config(
        migrator_config: &PgConfig,
        audit_admin_config: &PgConfig,
    ) -> Result<PgMaintenanceDeps, PgError> {
        let raw_store = Arc::new(PgStore::connect(migrator_config).await?);
        let delivery_policy = raw_store.load_event_delivery_policy().await?;
        let store = VerifiedPgMaintenanceStore::from_maintenance_store(raw_store);
        let audit_admin_store = PgStore::connect_verified_audit_admin(audit_admin_config).await?;
        Ok(PgMaintenanceDeps {
            store,
            audit_admin_store: Some(audit_admin_store),
            _delivery_policy: delivery_policy,
            clock: Arc::new(PgMaintenanceSystemClock),
        })
    }

    /// 投影可克隆的运行期能力句柄；生命周期 owner 仍留在调用方并只能交接一次。
    #[must_use]
    pub fn handle(&self) -> PgRuntimeHandle {
        self.handle.clone()
    }

    /// 按值交接全部 runtime 生命周期资源。
    ///
    /// resource 注册顺序固定为 writer → reader → optional audit-admin pool；LIFO shutdown 时 sampler
    /// 先停，随后 audit-admin、reader、writer 依次关池。
    #[must_use]
    pub fn into_runtime_parts(
        self,
        period: Duration,
    ) -> (
        Vec<Box<DynManagedResource<'static>>>,
        PgReadinessSamplerFactory,
    ) {
        let PgRuntimeHandle {
            stores,
            revocation_receipt: _,
            saga_receipt: _,
            audit_admin_store,
            delivery_policy: _,
            projection_registry: _,
            projection_capture,
            readiness,
            rls_ready: _,
        } = self.handle;
        let writer_store = stores.writer_store_arc();
        let reader_store = stores.reader_store_arc();
        let mut resources = vec![DynManagedResource::new_box(PgStoreGuard::new(Arc::clone(
            &writer_store,
        )))];
        resources.push(DynManagedResource::new_box(
            PgStoreGuard::new_runtime_named(Arc::clone(&reader_store), "postgres-tenant-reader"),
        ));
        if let Some(audit_admin_store) = audit_admin_store {
            resources.push(DynManagedResource::new_box(
                PgStoreGuard::new_runtime_named(
                    audit_admin_store.store_arc(),
                    "postgres-audit-admin",
                ),
            ));
        }
        (
            resources,
            PgReadinessSamplerFactory {
                writer_store,
                reader_store,
                projection_capture,
                readiness,
                period,
            },
        )
    }
}

impl PgRuntimeHandle {
    /// Mint the only PostgreSQL provider receipt accepted by the DeviceLatent draft pilot.
    ///
    /// The projections share this handle's verified stores and readiness state. Callers cannot
    /// supply or replace any member independently after the receipt is created.
    #[cfg(feature = "domain-identity")]
    #[must_use]
    pub fn device_identity_draft_runtime(&self) -> PgDeviceIdentityDraftRuntime {
        let identity = self.for_domain::<caps::Identity>();
        let infra = self.infra();
        PgDeviceIdentityDraftRuntime {
            repository: identity.device_certificate_repository(),
            commands: identity.device_command_store(),
            revocations: infra.revocation_store(),
            reconcile: infra.reconcile(),
            readiness: self.readiness_handle(),
        }
    }

    /// Flat durable auth-decision sink for framework HTTP enforcement.
    #[cfg(feature = "auth-audit-sink")]
    #[must_use]
    pub fn auth_audit_sink(&self) -> PgAuthAuditSink {
        PgAuthAuditSink::new(self.stores.writer_capability())
    }

    /// Fail closed unless the runtime budget exactly matches the policy loaded from the
    /// maintenance-owned database singleton during setup. This synchronous gate is intentionally
    /// callable before any AMQP connection is attempted.
    pub fn validate_relay_budget(&self, budget: eventexec::RelayBudget) -> Result<(), PgError> {
        self.delivery_policy.validate_relay_budget(budget)
    }

    /// 派发 per-domain 受控句柄（`Arc<PgRuntimeStores>` clone + `PhantomData<D>`）。
    ///
    /// 对标 kube-rs `Controller::run(.., Arc<Ctx>)` 注入 shared context。
    #[must_use]
    pub fn for_domain<D: PgDomain>(&self) -> PgDomainDeps<D> {
        PgDomainDeps {
            stores: Arc::clone(&self.stores),
            audit_admin_store: self.audit_admin_store.clone(),
            projection_registry: self.projection_registry.clone(),
            #[cfg(any(feature = "journey-fault-support", feature = "test-support"))]
            identity_security_start_barrier: None,
            _marker: PhantomData,
        }
    }

    /// 派发 framework/global（provider-agnostic、非单域）基建能力句柄 [`PgInfraDeps`]——
    /// emitter / dead_letter / checkpoint / saga / projection 不绑单一域，故不进 `PgDomainDeps<D>`。
    #[must_use]
    pub fn infra(&self) -> PgInfraDeps {
        PgInfraDeps {
            stores: Arc::clone(&self.stores),
            revocation_receipt: self.revocation_receipt.clone(),
            saga_receipt: self.saga_receipt.clone(),
            projection_registry: self.projection_registry.clone(),
            delivery_policy: self.delivery_policy,
        }
    }

    /// DB readiness 状态句柄（**非** pool）：`configs_ready` probe 读它，采样 worker 写它。
    #[must_use]
    pub fn readiness_handle(&self) -> Arc<PgDbReadiness> {
        Arc::clone(&self.readiness)
    }

    /// 启动期 RLS 能力门结果句柄（**非** pool）：readyz 兜底探针读它（`rls_ready` probe）。
    /// 当前为 setup 期一次性核验的不变式镜像（`Self` 存在 ⇒ true）；周期性再核验为后续扩展点。
    #[must_use]
    pub fn rls_ready_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.rls_ready)
    }

    /// Construct a hermetic capability handle backed by a lazy pool.
    ///
    /// This test-only funnel never opens a database connection and preserves the production
    /// capability boundary: callers can obtain only typed [`PgDomainDeps`] handles, never the
    /// pool or store. It exists so composition-root factory tests can execute real wiring without
    /// provisioning postgres.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn for_module_test() -> Self {
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_module_test")
            .username("rss_module_test")
            .password("not-a-secret");
        let writer_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options.clone());
        let reader_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options);
        Self {
            stores: Arc::new(PgRuntimeStores::from_unverified_for_test(
                Arc::new(PgStore { pool: writer_pool }),
                Arc::new(PgStore { pool: reader_pool }),
            )),
            revocation_receipt: RevocationCapabilityReceipt::for_test(),
            saga_receipt: SagaReceiptCapabilityReceipt::for_test(),
            audit_admin_store: None,
            delivery_policy: EventDeliveryPolicy::release(),
            projection_registry: ProjectionWriteRegistry::empty(),
            projection_capture: None,
            readiness: Arc::new(PgDbReadiness::new()),
            rls_ready: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Construct the hermetic module-test handle with an explicitly healthy readiness receipt.
    ///
    /// Runtime journeys use this as their provider-factory replacement; production construction
    /// cannot call it because it remains behind the default-off `test-support` feature.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn for_ready_module_test() -> Self {
        let handle = Self::for_module_test();
        handle.readiness.mark(crate::pool::PoolReadiness::Ready);
        handle
    }
}

#[cfg(all(
    test,
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
impl PgRuntimeDeps {
    /// 测试构造：从 lazy store 构造唯一 owner，可选注入 audit-admin store。
    fn from_stores_for_test(store: Arc<PgStore>, audit_admin_store: Option<Arc<PgStore>>) -> Self {
        Self::from_all_stores_for_test(Arc::clone(&store), store, audit_admin_store)
    }

    /// 测试构造：显式注入互异 writer/reader，以验证双 pool 生命周期。
    fn from_all_stores_for_test(
        writer_store: Arc<PgStore>,
        reader_store: Arc<PgStore>,
        audit_admin_store: Option<Arc<PgStore>>,
    ) -> Self {
        Self {
            handle: PgRuntimeHandle {
                stores: Arc::new(PgRuntimeStores::from_unverified_for_test(
                    writer_store,
                    reader_store,
                )),
                revocation_receipt: RevocationCapabilityReceipt::for_test(),
                saga_receipt: SagaReceiptCapabilityReceipt::for_test(),
                audit_admin_store: audit_admin_store
                    .map(VerifiedPgAuditAdminStore::from_unverified_for_test),
                delivery_policy: EventDeliveryPolicy::release(),
                projection_registry: ProjectionWriteRegistry::empty(),
                projection_capture: None,
                readiness: Arc::new(PgDbReadiness::new()),
                rls_ready: Arc::new(AtomicBool::new(true)),
            },
        }
    }
}

#[cfg(all(
    test,
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
impl PgRuntimeHandle {
    /// 从既有 lazy store 构造 crate 内测试 capability handle，不铸造 lifecycle owner。
    pub(crate) fn from_store_for_test(store: Arc<PgStore>) -> Self {
        Self {
            stores: Arc::new(PgRuntimeStores::from_unverified_for_test(
                Arc::clone(&store),
                store,
            )),
            revocation_receipt: RevocationCapabilityReceipt::for_test(),
            saga_receipt: SagaReceiptCapabilityReceipt::for_test(),
            audit_admin_store: None,
            delivery_policy: EventDeliveryPolicy::release(),
            projection_registry: ProjectionWriteRegistry::empty(),
            projection_capture: None,
            readiness: Arc::new(PgDbReadiness::new()),
            rls_ready: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl PgSagaOperatorDeps {
    /// Connect the dedicated `rss_saga_operator` credential and verify its exact function set.
    pub async fn connect(config: &PgSagaOperatorConfig) -> Result<Self, PgError> {
        Ok(Self {
            operator: PgStore::connect_verified_saga_operator(config).await?,
            clock: Arc::new(PgMaintenanceSystemClock),
        })
    }

    /// Replay protection for the operator service token, through its fixed SECURITY DEFINER call.
    #[must_use]
    pub fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(PgServiceTokenReplayStore::new(
            self.operator.store_arc(),
        ))
    }

    /// Append one Saga operator start/finish record through the fixed audit function.
    pub async fn record_saga_maintenance_audit(
        &self,
        operator_subject: &str,
        target_tenant: vocab::TenantId,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
        start_audit_id: &str,
    ) -> Result<(), PgError> {
        let duration = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| PgError::MaintenanceAudit(sqlx::Error::Decode(Box::new(error))))?;
        let secs = i64::try_from(duration.as_secs())
            .map_err(|error| PgError::MaintenanceAudit(sqlx::Error::Decode(Box::new(error))))?;
        let nanos = i32::try_from(duration.subsec_nanos())
            .map_err(|error| PgError::MaintenanceAudit(sqlx::Error::Decode(Box::new(error))))?;
        let (outcome, failure_reason) = match outcome {
            MaintenanceAuditOutcome::Success => ("success", None),
            MaintenanceAuditOutcome::Failure { reason } => ("failure", Some(reason)),
        };
        sqlx::query("SELECT public.rss_saga_operator_record_audit($1, $2, $3, $4::uuid, $5, $6, $7, $8, $9)")
            .bind(secs)
            .bind(nanos)
            .bind(operator_subject)
            .bind(target_tenant.as_uuid().to_string())
            .bind(resource_id)
            .bind(action)
            .bind(outcome)
            .bind(failure_reason)
            .bind(start_audit_id)
            .execute(&self.operator.store_arc().pool)
            .await
            .map_err(PgError::MaintenanceAudit)?;
        Ok(())
    }

    /// Apply the exact compensation retry through the dedicated operator credential.
    pub async fn retry_compensation(
        &self,
        authorization: diport::SagaOperatorAuthorization<
            diport::saga_operator_action::RetryCompensation,
        >,
    ) -> Result<diport::SagaOperatorCasOutcome, PgError> {
        let journal = authorization.evidence().journal();
        let mut tx = self
            .operator
            .store_arc()
            .pool
            .begin()
            .await
            .map_err(PgError::SagaOperatorCapability)?;
        crate::cotx::set_local_tenant(&mut tx, authorization.tenant())
            .await
            .map_err(PgError::SagaOperatorCapability)?;
        let applied: bool = sqlx::query_scalar(
            "SELECT public.rss_saga_retry_compensation(\
             $1::uuid, $2, $3, $4::bigint, $5, $6::integer, $7, $8, $9, $10, $11)",
        )
        .bind(authorization.instance().saga_id().as_uuid().to_string())
        .bind(authorization.identity().owner())
        .bind(authorization.identity().contract_id().as_str())
        .bind(i64::try_from(journal.record().seq()).map_err(|error| {
            PgError::SagaOperatorCapability(sqlx::Error::Decode(Box::new(error)))
        })?)
        .bind(journal.record().step_name().as_str())
        .bind(i32::try_from(journal.attempt().get()).map_err(|error| {
            PgError::SagaOperatorCapability(sqlx::Error::Decode(Box::new(error)))
        })?)
        .bind(journal.effect_key().as_bytes().as_slice())
        .bind(authorization.caller().as_str())
        .bind(authorization.evidence().reason_text().as_str())
        .bind(authorization.evidence().change_ticket().as_str())
        .bind(authorization.start_audit_id().as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(PgError::SagaOperatorCapability)?;
        tx.commit().await.map_err(PgError::SagaOperatorCapability)?;
        Ok(if applied {
            diport::SagaOperatorCasOutcome::Applied
        } else {
            diport::SagaOperatorCasOutcome::StaleJournal
        })
    }

    /// Apply the exact pre-effect termination through the dedicated operator credential.
    pub async fn terminate(
        &self,
        authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Terminate>,
    ) -> Result<diport::SagaOperatorCasOutcome, PgError> {
        let mut tx = self
            .operator
            .store_arc()
            .pool
            .begin()
            .await
            .map_err(PgError::SagaOperatorCapability)?;
        crate::cotx::set_local_tenant(&mut tx, authorization.tenant())
            .await
            .map_err(PgError::SagaOperatorCapability)?;
        let applied: bool = sqlx::query_scalar(
            "SELECT public.rss_saga_terminate($1::uuid, $2, $3, $4, $5, $6, $7)",
        )
        .bind(authorization.instance().saga_id().as_uuid().to_string())
        .bind(authorization.identity().owner())
        .bind(authorization.identity().contract_id().as_str())
        .bind(authorization.caller().as_str())
        .bind(authorization.evidence().reason_text().as_str())
        .bind(authorization.evidence().change_ticket().as_str())
        .bind(authorization.start_audit_id().as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(PgError::SagaOperatorCapability)?;
        tx.commit().await.map_err(PgError::SagaOperatorCapability)?;
        Ok(if applied {
            diport::SagaOperatorCasOutcome::Applied
        } else {
            diport::SagaOperatorCasOutcome::StaleJournal
        })
    }

    /// Close the dedicated operator pool.
    pub async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.operator.store_arc().shutdown().await
    }
}

impl PgMaintenanceDeps {
    /// Durable replay store for one-shot maintenance operator service tokens.
    #[must_use]
    pub fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(PgServiceTokenReplayStore::new(
            self.store.store_arc(),
        ))
    }

    /// settings `ConfigValue` 存量 backfill/rewrap 执行器。
    #[must_use]
    #[cfg(feature = "domain-settings")]
    pub fn config_value_maintenance(
        &self,
        protection: ConfigValueProtection,
        capability: ConfigValueMaintenanceCapability,
    ) -> PgConfigValueMaintenance {
        PgConfigValueMaintenance::new(self.store.store_arc(), protection, capability)
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_maintenance_audit(
        &self,
        resource_kind: &str,
        operator_subject: &str,
        tenant_context: Option<vocab::TenantId>,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
        request_id: Option<&str>,
    ) -> Result<(), PgError> {
        let now = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let nanos = i32::try_from(now.subsec_nanos()).unwrap_or(0);
        let (outcome, failure_reason) = match outcome {
            MaintenanceAuditOutcome::Success => ("success", None),
            MaintenanceAuditOutcome::Failure { reason } => ("failure", Some(reason)),
        };
        sqlx::query(
            r#"
            INSERT INTO auth_audit_events (
                occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
                resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id
            )
            VALUES ($1, $2, $3, 'service', $4::uuid, $5, $6, $7, $8, $9, $10, NULL)
            "#,
        )
        .bind(secs)
        .bind(nanos)
        .bind(operator_subject)
        .bind(tenant_context.map(|tenant| tenant.as_uuid().to_string()))
        .bind(resource_kind)
        .bind(resource_id)
        .bind(action)
        .bind(outcome)
        .bind(failure_reason)
        .bind(request_id)
        .execute(&self.store.store_arc().pool)
        .await
        .map_err(PgError::MaintenanceAudit)?;
        Ok(())
    }

    /// Durable audit record for settings ConfigValue maintenance jobs.
    pub async fn record_config_value_maintenance_audit(
        &self,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> Result<(), PgError> {
        self.record_maintenance_audit(
            "settings.config-values.maintenance",
            operator_subject,
            None,
            action,
            outcome,
            resource_id,
            None,
        )
        .await
    }

    /// Durable audit record for DLQ inspection / replay / redrive jobs.
    pub async fn record_dlq_maintenance_audit(
        &self,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> Result<(), PgError> {
        self.record_maintenance_audit(
            "dlq.maintenance",
            operator_subject,
            None,
            action,
            outcome,
            resource_id,
            None,
        )
        .await
    }

    /// Durable audit record for reconcile target inspection / recovery.
    pub async fn record_reconcile_maintenance_audit(
        &self,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> Result<(), PgError> {
        self.record_maintenance_audit(
            "reconcile.target.maintenance",
            operator_subject,
            None,
            action,
            outcome,
            resource_id,
            None,
        )
        .await
    }

    /// Durable audit record for Saga operator commands.
    ///
    /// `start_audit_id` is shared by the start and finish records, so durable authorization and
    /// transition evidence can be joined to the complete operator audit pair without parsing the
    /// resource identity.
    pub async fn record_saga_maintenance_audit(
        &self,
        operator_subject: &str,
        target_tenant: vocab::TenantId,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
        start_audit_id: &str,
    ) -> Result<(), PgError> {
        self.record_maintenance_audit(
            "saga.operator",
            operator_subject,
            Some(target_tenant),
            action,
            outcome,
            resource_id,
            Some(start_audit_id),
        )
        .await
    }

    /// Tenant-scoped reconcile target operator store.
    #[must_use]
    pub fn reconcile_store(&self) -> PgMaintenanceReconcileStore {
        PgMaintenanceReconcileStore::new(&self.store)
    }

    /// Durable audit record for per-tenant audit ledger verification jobs.
    pub async fn record_audit_ledger_verify_audit(
        &self,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> Result<(), PgError> {
        self.record_maintenance_audit(
            "audit.ledger.verify",
            operator_subject,
            None,
            action,
            outcome,
            resource_id,
            None,
        )
        .await
    }

    /// audit ledger verify 专用只读 admin repo。未通过 audit-admin setup 时返回 `None`。
    #[must_use]
    #[cfg(feature = "domain-audit")]
    pub fn audit_admin_repo<M>(
        &self,
        hasher: audit::ports::AuditChainHasher<M>,
    ) -> Option<PgAuditAdminRepo<M>>
    where
        M: primitives::MacVerifier + Send + Sync,
    {
        self.audit_admin_store
            .as_ref()
            .map(|store| PgAuditAdminRepo::new(store, hasher))
    }

    /// 带 payload replay 能力的 DLQ maintenance store。
    #[must_use]
    pub fn dlq_store(
        &self,
        payload_protector: DlxPayloadProtector,
        projection_capture: eventexec::ProjectionCaptureView<'_>,
    ) -> PgDlqStore {
        PgDlqStore::with_replay_projection_maintenance(
            &self.store,
            payload_protector,
            DlqReplayProjection::from_capture(projection_capture),
        )
    }

    #[cfg(all(
        test,
        feature = "domain-settings",
        feature = "domain-identity",
        feature = "domain-audit"
    ))]
    fn dlq_store_with_projection_bindings_for_test(
        &self,
        payload_protector: DlxPayloadProtector,
        projection_inputs: &[vocab::ProjectionInputBinding],
    ) -> PgDlqStore {
        PgDlqStore::with_replay_projection_maintenance(
            &self.store,
            payload_protector,
            DlqReplayProjection::from_selected(projection_inputs),
        )
    }

    /// 不允许 consumer payload replay 的 inspection/outbox-redrive store。
    #[must_use]
    pub fn dlq_store_without_payload_replay(&self) -> PgDlqStore {
        PgDlqStore::without_payload_replay_maintenance(&self.store)
    }

    /// 关闭维护连接池。
    pub async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        let audit_admin_result = match self.audit_admin_store.as_ref() {
            Some(store) => store.store_arc().shutdown().await,
            None => Ok(()),
        };
        let primary_result = self.store.store_arc().shutdown().await;
        audit_admin_result?;
        primary_result
    }
}

pub enum MaintenanceAuditOutcome<'a> {
    Success,
    Failure { reason: &'a str },
}

/// per-domain 受控 durable 能力句柄（`Clone`，内部 `Arc` 廉价 clone）。
///
/// 私有持 `Arc<PgRuntimeStores>`，只暴露**所属域 `D`** 的 repo 构造方法（方法体在 crate 内投影已验证 capability
/// clone，返回具体 repo 类型，从不返回 `PgPool`）。`D` 是 sealed marker（[`caps`]），跨域调用编译期被拒：
///
/// `PgDomainDeps<caps::Settings>` 调 identity 能力 = 编译错误（PG-BUNDLE-DOMAIN-02 anti-vacuity）：
#[cfg_attr(
    all(feature = "domain-settings", feature = "domain-identity"),
    doc = r#"
```compile_fail
use postgres::{PgDomainDeps, caps};
fn bad(d: PgDomainDeps<caps::Settings>) {
    // E0599：`auth_grant_provider` 不在 `PgDomainDeps<caps::Settings>` 上（仅 identity 句柄有）。
    let _ = d.auth_grant_provider(unimplemented!(), unimplemented!());
}
```
"#
)]
///
/// 同句柄的本域方法可用（正向）：
#[cfg_attr(
    all(feature = "domain-settings", feature = "domain-identity"),
    doc = r#"
```
use postgres::{PgDomainDeps, caps};
fn settings_ok(
    d: PgDomainDeps<caps::Settings>,
    clock: std::sync::Arc<dyn diport::Clock>,
    protections: postgres::ConfigValueProtections,
) {
    // Arc：单一 clock 经 settings_bundle 扇出到 read/write 两个 config 实例（见 settings_bundle）。
    let _ = d.settings_bundle(clock, protections);
}
fn identity_ok(
    d: PgDomainDeps<caps::Identity>,
    clock: Box<dyn diport::Clock>,
    pseudonym_keys: std::sync::Arc<secure::PseudonymKeyRing>,
) {
    let _ = d.auth_grant_provider(clock, pseudonym_keys);
}
```
"#
)]
pub struct PgDomainDeps<D: PgDomain> {
    stores: Arc<PgRuntimeStores>,
    audit_admin_store: Option<VerifiedPgAuditAdminStore>,
    projection_registry: ProjectionWriteRegistry,
    #[cfg(any(feature = "journey-fault-support", feature = "test-support"))]
    identity_security_start_barrier: Option<Arc<tokio::sync::Barrier>>,
    _marker: PhantomData<D>,
}

// 手写 `Clone`：避免 `#[derive(Clone)]` 引入多余的 `D: Clone` bound（marker 是 ZST，与 Clone 无关）。
impl<D: PgDomain> Clone for PgDomainDeps<D> {
    fn clone(&self) -> Self {
        Self {
            stores: Arc::clone(&self.stores),
            audit_admin_store: self.audit_admin_store.clone(),
            projection_registry: self.projection_registry.clone(),
            #[cfg(any(feature = "journey-fault-support", feature = "test-support"))]
            identity_security_start_barrier: self.identity_security_start_barrier.clone(),
            _marker: PhantomData,
        }
    }
}

#[cfg(feature = "domain-settings")]
impl PgDomainDeps<caps::Settings> {
    /// Build the canonical serving Settings target from an assembly-selected definition and exact
    /// bindings. No domain apply port or raw store escapes this funnel.
    pub fn settings_projection_target(
        &self,
        definition: eventexec::ProjectionTargetDefinition,
        bindings: Vec<vocab::ProjectionInputBinding>,
    ) -> Result<Arc<dyn eventexec::ProjectionTarget>, eventexec::ProjectionTargetConfigError> {
        let store = Arc::new(PgSettingsProjectionApplyStore::new(
            self.stores.writer_capability(),
        ));
        Ok(Arc::new(eventexec::ConformingProjectionTarget::new(
            definition, bindings, store,
        )?))
    }

    /// Tenant-scoped Settings metadata projection reader. Mutation authority is deliberately not
    /// bundled with serving reads; online and replay writes enter through the sealed target.
    pub fn settings_projection_read_repo(&self) -> Box<DynSettingsProjectionReadRepo<'static>> {
        DynSettingsProjectionReadRepo::new_box(PgSettingsProjectionReadRepo::new(
            self.stores.reader_capability(),
        ))
    }

    /// settings 域 durable 接线包：单一 `(store, clock)` → config 与 secret 各自的 read repo + write UoW，
    /// 内部完成域形 DynX 包裹。取代已删除的散装 `config_repo()` / `secret_repo()`（PERSIST-003，不留兼容
    /// 路径，PG-BUNDLE-SETTINGS-04）。
    ///
    /// `clock`（`Arc<dyn Clock>`，构造器位置参，必填、非 `Option`、不默认系统钟）：单一注入 clock 经
    /// `Arc::clone` 扇出到 read/write 两个 [`PgConfigRepo`] 实例（envelope `occurred_at` 源；write lane 经
    /// `commit` 用，read lane 不触）。read/write 各持一个实例——`Box<DynConfigRepo>` 与
    /// `Box<DynConfigUnitOfWork>` 是不同 dyn 类型、各自 own 其值，一个 Box 无法同时充当两者。
    ///
    /// 返回类型 [`PgSettingsBundle`] 自身 `#[must_use]`（drop 而不 `into_parts` 即 lint），故此处无方法级
    /// `#[must_use]`（避免 `clippy::double_must_use`）。
    pub fn settings_bundle(
        &self,
        clock: Arc<dyn Clock>,
        protections: ConfigValueProtections,
    ) -> PgSettingsBundle {
        let (config_read_protection, config_write_protection) = protections.into_parts();
        PgSettingsBundle {
            config_repo: DynConfigRepo::new_box(PgConfigRepo::new_with_projection_registry(
                self.stores.reader_capability(),
                self.stores.writer_capability(),
                Arc::clone(&clock),
                config_read_protection,
                self.projection_registry.clone(),
            )),
            config_uow: DynConfigUnitOfWork::new_box(PgConfigRepo::new_with_projection_registry(
                self.stores.reader_capability(),
                self.stores.writer_capability(),
                clock,
                config_write_protection,
                self.projection_registry.clone(),
            )),
            secret_repo: DynSecretRepo::new_box(PgSecretRepo::new(self.stores.reader_capability())),
            secret_uow: DynSecretUnitOfWork::new_box(PgSecretUnitOfWork::new(
                self.stores.writer_capability(),
            )),
        }
    }

    /// outbox relay（L2 本地事务 + 发布；`settings.config-version-changed`）。`publisher` 必填（构造器位置参）。
    /// `PgOutbox` 在构造时绑定 domain，`claim_batch` 只领取该 domain 的 outbox 表行（与 identity 同形，
    /// #1251 F2：N-域 relay——每个 L2 OutboxFact 发布域各一个 relay，否则该域 outbox 在 durable runtime 静默积压）。
    #[must_use]
    pub fn outbox(
        &self,
        publisher: Box<DynPublisher<'static>>,
        relay_budget: RelayBudget,
        tenant_authority: Arc<TenantAuthority>,
        payload_protector: DlxPayloadProtector,
    ) -> PgOutbox {
        PgOutbox::new(
            self.stores.writer_capability(),
            bound_domain::<caps::Settings>(),
            publisher,
            relay_budget,
            tenant_authority,
            payload_protector,
        )
    }

    /// ConsumerTx handler for `settings.config-version-changed`.
    #[must_use]
    pub fn config_version_changed_consumer_tx(
        &self,
        reconciler: std::sync::Arc<settings::ConfigVersionReconciler>,
    ) -> PgSettingsConsumerTx {
        PgSettingsConsumerTx::config_version_changed(self.stores.writer_capability(), reconciler)
    }
}

/// settings 域 durable 接线包（PERSIST-003 / #1424）：config 与 secret 各自的 read repo + write UoW，全部
/// 源自同一 `(verified reader/writer capability pair, clock)`、预包装为 settings 域 dyn DI port。
///
/// 字段私有 + 唯一构造经 [`PgDomainDeps::settings_bundle`] + 唯一解包经 [`PgSettingsBundle::into_parts`]
/// （PG-BUNDLE-SETTINGS-04，Hard）。**实际强制**（仅声明类型层真成立的）：
/// - 外部 crate 无法 mint（私有字段 + 唯一公开构造 funnel）；
/// - 一次 `into_parts` 产出的四元同源（同一 verified reader/writer capability pair + 同一注入 clock）；
/// - 四件为互不可换的域形 dyn 类型 ⇒ config/secret 的 read/write 角色无法错插（typed function choice）。
///
/// **不声称**：`into_parts` 后四件为 owned 值，类型层不阻止把不同 bundle 实例的 box 跨实例重组（funnel 守
/// 上游构造 + 角色槽位，不守下游跨 bundle 重组；单一 `PgRuntimeDeps` ⇒ 同一 capability pair，跨 bundle 重组为 contrived）。
/// 对标 GoCell `accesspg.Bundle` / `WithPGBundle`（单次解包注入聚合）。
///
/// anti-vacuity（私有字段须经 `into_parts` 唯一出口，不可旁路直读单字段）：
///
/// ```compile_fail
/// use postgres::{PgDomainDeps, caps};
/// fn bad(
///     d: PgDomainDeps<caps::Settings>,
///     clock: std::sync::Arc<dyn diport::Clock>,
///     protections: postgres::ConfigValueProtections,
/// ) {
///     let b = d.settings_bundle(clock, protections);
///     // E0616：字段 `config_repo` 私有——须经 `into_parts` 唯一出口取四元，不可旁路直读单字段（PG-BUNDLE-SETTINGS-04）。
///     let _ = b.config_repo;
/// }
/// ```
#[cfg(feature = "domain-settings")]
#[must_use]
pub struct PgSettingsBundle {
    config_repo: Box<DynConfigRepo<'static>>,
    config_uow: Box<DynConfigUnitOfWork<'static>>,
    secret_repo: Box<DynSecretRepo<'static>>,
    secret_uow: Box<DynSecretUnitOfWork<'static>>,
}

#[cfg(feature = "domain-settings")]
impl PgSettingsBundle {
    /// 受控解包：移出四件已包裹域形 DI box——`(config read, config write, secret read, secret write)`。
    /// 四者类型互不可换，重排即编译错误。本 bundle 唯一对外读取路径（字段私有）。
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Box<DynConfigRepo<'static>>,
        Box<DynConfigUnitOfWork<'static>>,
        Box<DynSecretRepo<'static>>,
        Box<DynSecretUnitOfWork<'static>>,
    ) {
        (
            self.config_repo,
            self.config_uow,
            self.secret_repo,
            self.secret_uow,
        )
    }
}

#[cfg(feature = "domain-identity")]
#[cfg(all(feature = "domain-identity", any(test, feature = "test-support")))]
pub fn identity_pseudonym_keys_for_test() -> std::sync::Arc<secure::PseudonymKeyRing> {
    let key = match secure::RedactionHashKey::from_bytes(vec![0x42; 32]) {
        Ok(key) => key,
        Err(error) => unreachable!("fixed test pseudonym key must be valid: {error}"),
    };
    let ring = match secure::PseudonymKeyRing::new(
        secure::VersionedPseudonymKey::new(
            secure::PseudonymKeyId::new(std::num::NonZeroU16::MIN),
            key,
        ),
        Vec::new(),
    ) {
        Ok(ring) => ring,
        Err(error) => unreachable!("fixed test pseudonym key ring must be valid: {error}"),
    };
    std::sync::Arc::new(ring)
}

#[cfg(feature = "domain-identity")]
impl PgDomainDeps<caps::Identity> {
    /// Device-certificate desired/reported/condition persistence authority.
    ///
    /// This accessor only exposes the repository capability. Runtime assembly and handlers remain
    /// intentionally unwired until their owning PBIs activate them.
    #[must_use]
    pub fn device_certificate_repository<E>(&self) -> PgDeviceCertificateRepository<E>
    where
        E: identity::ports::device_certificate::ArtifactEligibility,
    {
        PgDeviceCertificateRepository::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// Eligibility-bound durable device-command reader. All command mutation remains behind the
    /// PostgreSQL SECURITY DEFINER funnels; this accessor does not expose a raw write lane.
    #[must_use]
    pub fn device_command_store<E>(&self) -> crate::PgDeviceCommandStore<E>
    where
        E: identity::ports::device_certificate::ArtifactEligibility,
    {
        crate::PgDeviceCommandStore::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// Inject a deterministic transaction-start rendezvous for the HTTP concurrency journey.
    #[cfg(any(feature = "journey-fault-support", feature = "test-support"))]
    #[must_use]
    pub fn with_identity_security_start_barrier_for_test(
        mut self,
        barrier: Arc<tokio::sync::Barrier>,
    ) -> Self {
        self.identity_security_start_barrier = Some(barrier);
        self
    }

    /// Request-time durable fence for verified RSS access-token grant bindings.
    #[must_use]
    pub fn auth_grant_validator(&self) -> PgAuthGrantValidator {
        PgAuthGrantValidator::new(self.stores.reader_capability())
    }

    /// Single-owner AuthGrant/refresh provider used by login composition.
    #[must_use]
    pub fn auth_grant_provider(
        &self,
        clock: Box<dyn Clock>,
        pseudonym_keys: std::sync::Arc<secure::PseudonymKeyRing>,
    ) -> PgAuthGrantProvider {
        let security = PgIdentitySecurityLifecycle::new(
            self.stores.writer_capability(),
            self.projection_registry.clone(),
            pseudonym_keys,
        );
        #[cfg(any(feature = "journey-fault-support", feature = "test-support"))]
        let security = match &self.identity_security_start_barrier {
            Some(barrier) => security.with_start_barrier(Arc::clone(barrier)),
            None => security,
        };
        PgAuthGrantProvider::new(
            PgAuthGrantLifecycle::new_with_projection_registry(
                self.stores.reader_capability(),
                self.stores.writer_capability(),
                clock,
                self.projection_registry.clone(),
            ),
            PgRefreshTokenStore::new(self.stores.reader_capability()),
            security,
        )
    }

    /// outbox relay（L2 本地事务 + 发布）。`publisher` 必填（构造器位置参）。
    #[must_use]
    pub fn outbox(
        &self,
        publisher: Box<DynPublisher<'static>>,
        relay_budget: RelayBudget,
        tenant_authority: Arc<TenantAuthority>,
        payload_protector: DlxPayloadProtector,
    ) -> PgOutbox {
        PgOutbox::new(
            self.stores.writer_capability(),
            bound_domain::<caps::Identity>(),
            publisher,
            relay_budget,
            tenant_authority,
            payload_protector,
        )
    }

    /// 凭据仓储（credentials 表 + 折叠锁定态 + 行锁原子 RMW）。
    #[must_use]
    pub fn credential_repo(&self) -> PgCredentialRepo {
        PgCredentialRepo::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// Durable account-security read model for mandatory authentication gates.
    #[must_use]
    pub fn account_security_repo(&self) -> crate::PgAccountSecurityRepo {
        crate::PgAccountSecurityRepo::new(self.stores.reader_capability())
    }

    /// Narrow plain-write account reactivation capability.
    #[must_use]
    pub fn account_reactivation_lifecycle(&self) -> crate::PgAccountReactivationLifecycle {
        crate::PgAccountReactivationLifecycle::new(
            self.stores.writer_capability(),
            self.projection_registry.clone(),
        )
    }

    /// 角色仓储（roles 表 + tenant scope）。
    #[must_use]
    pub fn role_repo(&self) -> PgRoleRepo {
        PgRoleRepo::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// durable ABAC policy store（abac_policies 表 + tenant scope）。
    #[must_use]
    pub fn policy_repo(&self) -> PgPolicyRepo {
        PgPolicyRepo::new(self.stores.reader_capability())
    }

    /// durable resource attribute store / resolver（resource_attributes 表 + tenant scope）。
    #[must_use]
    pub fn resource_attribute_repo(&self) -> PgResourceAttributeRepo {
        PgResourceAttributeRepo::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// 角色绑定只读仓储（无 clock / mutation / outbox 能力）。
    #[must_use]
    pub fn role_binding_read_repo(&self) -> PgRoleBindingReadRepo {
        PgRoleBindingReadRepo::new(self.stores.reader_capability())
    }

    /// durable ABAC policy lifecycle（policy mutation + policy-updated outbox co-tx）。
    #[must_use]
    pub fn policy_lifecycle(&self, clock: Box<dyn Clock>) -> PgPolicyLifecycle {
        PgPolicyLifecycle::new_with_projection_registry(
            self.stores.writer_capability(),
            clock,
            self.projection_registry.clone(),
        )
    }

    /// 角色绑定生命周期（binding co-tx + role event outbox）。
    #[must_use]
    pub fn role_binding_lifecycle(&self, clock: Box<dyn Clock>) -> PgRoleBindingLifecycle {
        PgRoleBindingLifecycle::new_with_projection_registry(
            self.stores.writer_capability(),
            clock,
            self.projection_registry.clone(),
        )
    }
}

#[cfg(feature = "domain-audit")]
impl PgDomainDeps<caps::Audit> {
    /// Pin and verify the closed audit-chain HMAC key before event consumers become reachable.
    ///
    /// The database function initializes only on an empty ledger. Once pinned, both the typed key
    /// generation and the keyed verification tag must match on every restart; rotation requires a
    /// dedicated migration and cannot happen by replacing an environment secret.
    pub async fn verify_audit_chain_key(
        &self,
        identity: crate::AuditChainKeyIdentity,
        verification_tag: &[u8],
    ) -> Result<(), crate::PgError> {
        let matched: bool =
            sqlx::query_scalar("SELECT rss_verify_audit_chain_key_v1($1::smallint, $2::bytea)")
                .bind(identity.as_i16())
                .bind(verification_tag)
                .fetch_one(self.stores.writer_capability().pool())
                .await
                .map_err(crate::PgError::AuditChainKeyProbe)?;
        if !matched {
            return Err(crate::PgError::AuditChainKeyMismatch);
        }
        Ok(())
    }

    /// audit 审计链仓储（append-only per-tenant keyed-HMAC chain + RLS）。
    ///
    /// `hasher` 持 keyed-HMAC verifier + key（构造器必填，无 key 不可造 hasher）。
    #[must_use]
    pub fn audit_repo<M>(&self, hasher: audit::ports::AuditChainHasher<M>) -> PgAuditRepo<M>
    where
        M: primitives::MacVerifier + Send + Sync,
    {
        PgAuditRepo::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
            hasher,
        )
    }

    /// audit 审计链跨租户只读 admin repo。未配置 `rss_audit_admin` pool 时返回 `None`。
    #[must_use]
    pub fn audit_admin_repo<M>(
        &self,
        hasher: audit::ports::AuditChainHasher<M>,
    ) -> Option<PgAuditAdminRepo<M>>
    where
        M: primitives::MacVerifier + Send + Sync,
    {
        self.audit_admin_store
            .as_ref()
            .map(|store| PgAuditAdminRepo::new(store, hasher))
    }

    /// Flat durable auth decision audit sink (`diport::AuditSink`) for httpserve enforcement.
    ///
    /// This deliberately stays outside the hash-chain audit repository actor model because auth principals
    /// are generic subjects, not only `ids::UserId`.
    #[must_use]
    #[cfg(feature = "auth-audit-sink")]
    pub fn auth_audit_sink(&self) -> PgAuthAuditSink {
        PgAuthAuditSink::new(self.stores.writer_capability())
    }

    /// ConsumerTx handler for `identity.session-created` consumed by audit.
    #[must_use]
    pub fn session_created_consumer_tx<M>(
        &self,
        hasher: audit::ports::AuditChainHasher<M>,
    ) -> PgAuditConsumerTx<M>
    where
        M: primitives::MacVerifier + Send + Sync + 'static,
    {
        PgAuditConsumerTx::session_created(self.stores.writer_capability(), hasher)
    }

    /// ConsumerTx handler for `identity.role-assigned` consumed by audit.
    #[must_use]
    pub fn role_assigned_consumer_tx<M>(
        &self,
        hasher: audit::ports::AuditChainHasher<M>,
    ) -> PgAuditConsumerTx<M>
    where
        M: primitives::MacVerifier + Send + Sync + 'static,
    {
        PgAuditConsumerTx::role_assigned(self.stores.writer_capability(), hasher)
    }

    /// ConsumerTx handler for `identity.role-revoked` consumed by audit.
    #[must_use]
    pub fn role_revoked_consumer_tx<M>(
        &self,
        hasher: audit::ports::AuditChainHasher<M>,
    ) -> PgAuditConsumerTx<M>
    where
        M: primitives::MacVerifier + Send + Sync + 'static,
    {
        PgAuditConsumerTx::role_revoked(self.stores.writer_capability(), hasher)
    }

    /// ConsumerTx handler for `identity.policy-updated` consumed by audit.
    #[must_use]
    pub fn policy_updated_consumer_tx<M>(
        &self,
        hasher: audit::ports::AuditChainHasher<M>,
    ) -> PgAuditConsumerTx<M>
    where
        M: primitives::MacVerifier + Send + Sync + 'static,
    {
        PgAuditConsumerTx::policy_updated(self.stores.writer_capability(), hasher)
    }

    #[must_use]
    pub fn security_event_consumer_tx<M>(
        &self,
        hasher: audit::ports::AuditChainHasher<M>,
    ) -> PgAuditConsumerTx<M>
    where
        M: primitives::MacVerifier + Send + Sync + 'static,
    {
        PgAuditConsumerTx::security_event(self.stores.writer_capability(), hasher)
    }
}

/// framework/global postgres 基建能力句柄（`Clone`，provider-agnostic、非单域）。
///
/// 私有持 `Arc<PgRuntimeStores>`，经 [`PgRuntimeHandle::infra`] 派发；只暴露 emitter / dead_letter / checkpoint /
/// saga_journal / projection_events / cas_store / auth_grant_sweeper——这些是跨域基建（非绑某个 `caps::*` 域），
/// 故独立于 [`PgDomainDeps`]。
/// 与 `PgDomainDeps` 一样不返回 `&PgStore` / `PgPool`（PG-BUNDLE-POOL-03）。
///
/// infra/domain 能力面**互斥**（typed function choice）：`PgInfraDeps` 上没有域 repo（编译期被拒）：
///
/// ```compile_fail
/// use postgres::PgInfraDeps;
/// fn bad(i: PgInfraDeps) {
///     // E0599：`credential_repo` 是 `PgDomainDeps<caps::Identity>` 的方法，不在 `PgInfraDeps` 上。
///     let _ = i.credential_repo();
/// }
/// ```
///
/// 本句柄的 infra 方法可用（正向）：
///
/// ```
/// use postgres::PgInfraDeps;
/// fn ok(i: PgInfraDeps) {
///     let _ = i.outbox_maintenance();
/// }
/// ```
#[derive(Clone)]
pub struct PgInfraDeps {
    stores: Arc<PgRuntimeStores>,
    revocation_receipt: RevocationCapabilityReceipt,
    saga_receipt: SagaReceiptCapabilityReceipt,
    projection_registry: ProjectionWriteRegistry,
    delivery_policy: EventDeliveryPolicy,
}

/// Move-only inbox/DLX pair for one generated consumer runtime wiring pass.
pub struct PgConsumerRuntimeBundle {
    inbox: PgInboxStore,
    dead_letter: PgDeadLetterStore,
}

impl PgConsumerRuntimeBundle {
    #[must_use]
    pub fn into_parts(self) -> (PgInboxStore, PgDeadLetterStore) {
        (self.inbox, self.dead_letter)
    }
}

impl PgInfraDeps {
    /// Persistent certificate revocation provider backed by the authoritative writer lane.
    #[must_use]
    pub fn revocation_store(&self) -> PgRevocationStore {
        PgRevocationStore::new(
            self.stores.writer_capability(),
            self.revocation_receipt.clone(),
        )
    }

    /// Fixed, bounded physical retention for expired certificate revocation evidence.
    #[must_use]
    pub fn revocation_sweeper(&self) -> PgRevocationSweeper {
        PgRevocationSweeper::new(
            self.stores.writer_capability(),
            self.revocation_receipt.clone(),
        )
    }

    /// Fixed 30-day, 1,000-row physical retention for terminal Saga aggregates.
    #[must_use]
    pub fn saga_terminal_sweeper(&self) -> PgSagaTerminalSweeper {
        PgSagaTerminalSweeper::new(self.stores.writer_capability(), self.saga_receipt.clone())
    }

    /// Reviewed-event durable writer（envelope `occurred_at` 时间源经 `clock` 注入）。
    #[must_use]
    pub fn emitter(&self, clock: Box<dyn Clock>) -> PgEmitter {
        PgEmitter::new_with_projection_registry(
            self.stores.writer_capability(),
            clock,
            self.projection_registry.clone(),
        )
    }

    /// CDC-facing append-only reviewed-event writer.
    ///
    /// This explicit opt-in mode writes `outbox_log` and does not participate in the relay
    /// `outbox` status machine.
    #[must_use]
    pub fn cdc_emitter(&self, clock: Box<dyn Clock>) -> PgOutboxCdcEmitter {
        PgOutboxCdcEmitter::new_with_store(self.stores.writer_capability(), clock)
    }

    /// outbox backlog/sweeper maintenance 能力（不持 publisher）。
    ///
    /// relay publishing 仍经 per-domain [`PgDomainDeps::outbox`] 构造；sampler/sweeper 只需要 DB pool，归
    /// framework/global infra 句柄，避免为 maintenance worker 注入可发布能力（#1429）。
    #[must_use]
    pub fn outbox_maintenance(&self) -> PgOutboxMaintenance {
        PgOutboxMaintenance::new(&self.stores.writer_store_arc())
    }

    /// consumer inbox 幂等去重 store（runtime consumer resource bundle 使用）。
    ///
    /// `inbox_receipts` key 为 `(tenant_id, event_id, consumer_group)`，不是 identity 域资源；因此归
    /// framework/global infra 句柄，避免组合根为通用 consumer 借用某个业务域句柄。
    #[must_use]
    pub fn inbox(&self) -> PgInboxStore {
        PgInboxStore::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// Tenant-scoped HOT dead-letter writer. Archive/purge is intentionally absent from this
    /// serving capability and lives in the independent [`crate::PgDlxLifecycleRuntime`].
    #[must_use]
    pub fn dead_letter(&self, payload_protector: DlxPayloadProtector) -> PgDeadLetterStore {
        PgDeadLetterStore::new(self.stores.writer_capability(), payload_protector)
    }

    /// Construct the exact move-only resources consumed by a generated ConsumerTx worker.
    #[must_use]
    pub fn consumer_runtime_bundle(
        &self,
        payload_protector: DlxPayloadProtector,
    ) -> PgConsumerRuntimeBundle {
        PgConsumerRuntimeBundle {
            inbox: self.inbox(),
            dead_letter: self.dead_letter(payload_protector),
        }
    }

    /// inbox_receipts 保留期清理 sweeper（**全域**，跨 consumer_group / 域，#1210）。
    ///
    /// impl `consistency::RetentionSweeper`——仅接受启动时从数据库冻结策略加载的保留期，删除超期 `done`
    /// 去重记录。全域语义 ⇒ 归 framework/global infra 句柄（非 per-domain `PgDomainDeps`）。
    #[must_use]
    pub fn inbox_sweeper(&self) -> PgInboxSweeper {
        self.stores
            .writer_store_arc()
            .inbox_sweeper(self.delivery_policy)
    }

    /// AuthGrant 过期根维护清理器（全域，固定 `expires_at <= now()` 谓词）。
    ///
    /// 不返回 tenant/raw pool/SQL/retain 参数；runtime 只拿到具体 [`PgAuthGrantSweeper`] 并调用
    /// `sweep_expired()`。
    #[must_use]
    pub fn auth_grant_sweeper(&self) -> PgAuthGrantSweeper {
        self.stores.writer_store_arc().auth_grant_sweeper()
    }

    /// Bounded service-token replay retention without replay consume authority.
    #[must_use]
    pub fn service_token_replay_sweeper(&self) -> PgServiceTokenReplaySweeper {
        PgServiceTokenReplaySweeper::new(self.stores.writer_store_arc())
    }

    /// owner checkpoint store（reconcile/saga 进度）。
    #[must_use]
    pub fn checkpoint(&self) -> PgCheckpointStore {
        self.stores.writer_store_arc().checkpoint()
    }

    /// reconcile durable target/lease/attempt/action store（schema-level capability，#1629）。
    ///
    /// 本 accessor 只暴露最小 PG schema API，不启动 reconcile runtime worker，也不新增 engine/domain trait。
    #[must_use]
    pub fn reconcile(&self) -> PgReconcileStore {
        PgReconcileStore::new(self.stores.writer_capability())
    }

    /// command journal foundation store（schema-level capability，#1441）。
    ///
    /// This accessor exposes only the reviewed command journal API; it does not start a command
    /// worker or expose raw transaction handles. Its outbox envelope `occurred_at` source is an
    /// injected producer clock, matching [`PgInfraDeps::emitter`].
    #[must_use]
    pub fn command_journal(&self, clock: Box<dyn Clock>) -> PgCommandJournal {
        PgCommandJournal::new(self.stores.writer_capability(), clock)
    }

    /// Closed durable Saga writer and authoritative recovery boundary.
    ///
    /// Protection dependencies are mandatory and move-only; there is no plaintext or unkeyed
    /// constructor path.
    #[must_use]
    pub fn saga_durable_store(&self, protection: PgSagaReceiptProtection) -> PgSagaDurableStore {
        PgSagaDurableStore::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
            protection,
            self.saga_receipt.clone(),
        )
    }

    /// distributed state CAS store（全局 per-key revision token）。
    #[must_use]
    pub fn cas_store(&self) -> Box<DynCasStore<'static>> {
        DynCasStore::new_box(self.stores.writer_store_arc().cas_store())
    }
}

#[cfg(all(
    test,
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
mod tests {
    //! bundle 单元测：lazy pool 旁路 `setup`（免真连 DB），覆盖 funnel 派发 + per-domain accessor 构造。
    //! INVARIANT: PG-BUNDLE-FUNNEL-01 / PG-BUNDLE-DOMAIN-02 / PG-BUNDLE-POOL-03 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }（compile_fail doctest 见
    //! `PgDomainDeps` rustdoc）。

    use super::*;
    use std::time::SystemTime;

    use diport::{
        DynKeyProvider, EncryptOutput, KeyName, KeyProvider, KeyProviderError, KeyRef, KeyVersion,
        PublishRequest, Publisher, PublisherError, RedactedBytes,
    };
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
    use secure::{DerivedAad, Plaintext};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    /// 测试时钟：返回 `UNIX_EPOCH`（const，不触 `disallowed_methods` 的 `SystemTime::now`）。
    /// accessor 构造期不调 `now()`，故任意 Clock 即可。
    struct EpochClock;
    impl Clock for EpochClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    /// 测试发布器：`outbox` accessor 构造期不发布，stub `Ok(())` 即可。
    struct StubPublisher;
    impl Publisher for StubPublisher {
        async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), PublisherError> {
            Ok(())
        }
    }

    struct StubKeyProvider;
    impl KeyProvider for StubKeyProvider {
        async fn encrypt(
            &self,
            key: KeyName,
            _plaintext: Plaintext,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(
                b"ct".to_vec(),
                KeyRef::new(key, KeyVersion::new(1)),
            ))
        }

        async fn decrypt(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            Ok(Plaintext::new(b"pt".to_vec()))
        }

        async fn rewrap(
            &self,
            _ciphertext: RedactedBytes,
            key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(b"ct2".to_vec(), key))
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut tag = Vec::from(key.as_bytes());
            tag.extend_from_slice(message);
            Mac::from_bytes(tag)
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    #[allow(clippy::expect_used)]
    fn protections() -> ConfigValueProtections {
        ConfigValueProtections::new(
            DynKeyProvider::new_box(StubKeyProvider),
            DynKeyProvider::new_box(StubKeyProvider),
            KeyName::try_new("settings-config").expect("valid key name"),
        )
    }

    #[allow(clippy::expect_used)]
    fn tenant_authority() -> Arc<TenantAuthority> {
        Arc::new(
            TenantAuthority::new(
                Arc::new(TestMac),
                MacKey::from_bytes(vec![0x42; 32]),
                3600,
                60,
                Arc::new(|| 1_700_000_000),
            )
            .expect("valid test tenant authority"),
        )
    }

    fn payload_protector() -> DlxPayloadProtector {
        crate::dead_letter_payload::tests::test_protector()
    }

    #[allow(clippy::expect_used)]
    fn relay_budget() -> RelayBudget {
        RelayBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(40),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .expect("test relay budget must be valid")
    }

    /// lazy pool（不发真实连接）构造 `Arc<PgStore>`——单元测专用（免 DB）。
    fn lazy_store() -> Arc<PgStore> {
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(opts);
        Arc::new(PgStore { pool })
    }

    fn deps() -> PgRuntimeDeps {
        PgRuntimeDeps::from_stores_for_test(lazy_store(), None)
    }

    // 这些测试经 lazy pool（`connect_lazy_with`）构造 store——sqlx 池需 Tokio context，故 `#[tokio::test]`
    // （body 不 await；与既有 `smoke::pg_store_guard_shutdown_lazy_pool_ok` 同范式）。

    #[tokio::test]
    async fn for_domain_shares_store_arc() {
        let d = deps();
        let handle = d.handle();
        let s: PgDomainDeps<caps::Settings> = handle.for_domain();
        // owner 只包 handle；权限分离不复制数据源，所有 capability 投影共享同一 Arc。
        assert!(
            Arc::ptr_eq(&s.stores, &d.handle.stores),
            "for_domain clone 共享 runtime stores Arc"
        );
    }

    #[tokio::test]
    async fn domain_deps_clone_shares_store() {
        let s: PgDomainDeps<caps::Settings> = deps().handle().for_domain();
        let c = s.clone();
        assert!(
            Arc::ptr_eq(&s.stores, &c.stores),
            "clone 廉价共享 runtime stores Arc（非深拷贝）"
        );
    }

    #[tokio::test]
    async fn readiness_handle_returns_same_arc() {
        let d = deps();
        assert!(
            Arc::ptr_eq(&d.handle().readiness_handle(), &d.handle.readiness),
            "readiness_handle 返回内部同一 Arc"
        );
    }

    #[tokio::test]
    async fn cloned_handles_share_every_backing_arc() {
        let owner = PgRuntimeDeps::from_stores_for_test(lazy_store(), Some(lazy_store()));
        let first = owner.handle();
        let second = first.clone();
        assert!(Arc::ptr_eq(&first.stores, &second.stores));
        assert!(
            first
                .audit_admin_store
                .as_ref()
                .zip(second.audit_admin_store.as_ref())
                .is_some_and(|(first, second)| {
                    Arc::ptr_eq(&first.store_arc(), &second.store_arc())
                }),
            "audit-admin capability must remain present and Arc-identical"
        );
        assert!(Arc::ptr_eq(&first.readiness, &second.readiness));
        assert!(Arc::ptr_eq(&first.rls_ready, &second.rls_ready));
    }

    #[tokio::test]
    async fn rls_ready_handle_returns_same_arc() {
        let d = deps();
        assert!(
            Arc::ptr_eq(&d.handle().rls_ready_handle(), &d.handle.rls_ready),
            "rls_ready_handle 返回内部同一 Arc"
        );
    }

    #[tokio::test]
    async fn runtime_parts_without_audit_have_writer_and_reader_guards() {
        let (resources, _factory) = deps().into_runtime_parts(Duration::from_secs(1));
        let names: Vec<_> = resources.iter().map(|resource| resource.name()).collect();
        assert_eq!(names, ["postgres", "postgres-tenant-reader"]);
    }

    #[tokio::test]
    async fn runtime_parts_with_audit_preserve_registration_order_and_close_pools() {
        let primary = lazy_store();
        let reader = lazy_store();
        let audit_admin = lazy_store();
        let owner = PgRuntimeDeps::from_all_stores_for_test(
            Arc::clone(&primary),
            Arc::clone(&reader),
            Some(Arc::clone(&audit_admin)),
        );
        let (resources, _factory) = owner.into_runtime_parts(Duration::from_secs(1));
        let names: Vec<_> = resources.iter().map(|resource| resource.name()).collect();
        assert_eq!(
            names,
            ["postgres", "postgres-tenant-reader", "postgres-audit-admin"]
        );

        for resource in resources.into_iter().rev() {
            let result = resource.shutdown().await;
            assert!(result.is_ok(), "lazy pool closes cleanly: {result:?}");
        }
        assert!(primary.pool.is_closed(), "primary pool must close");
        assert!(reader.pool.is_closed(), "tenant reader pool must close");
        assert!(audit_admin.pool.is_closed(), "audit-admin pool must close");
    }

    #[tokio::test]
    async fn settings_bundle_constructs_all_parts() {
        let s: PgDomainDeps<caps::Settings> = deps().handle().for_domain();
        // 单 clock 经 Arc 扇出到 read/write 两个 config 实例；into_parts 解包四件套（纯 pool clone，无 I/O）。
        let (_configs, _config_writer, _secrets, _secret_writer) = s
            .settings_bundle(Arc::new(EpochClock) as Arc<dyn Clock>, protections())
            .into_parts();
    }

    #[tokio::test]
    async fn settings_bundle_fans_out_single_clock() {
        let s: PgDomainDeps<caps::Settings> = deps().handle().for_domain();
        let clock: Arc<dyn Clock> = Arc::new(EpochClock);
        let before = Arc::strong_count(&clock); // 1（仅本地持有）
        let _bundle = s.settings_bundle(Arc::clone(&clock), protections());
        // 单一注入 clock 经 Arc 扇出到 read/write 两个 PgConfigRepo（各持一 clone）⇒ 至少 +2。
        // 回归到「每 lane 各 mint 一个 clock」则只 +1 → 失败（PG-BUNDLE-SETTINGS-04 anti-vacuity）。
        assert!(
            Arc::strong_count(&clock) >= before + 2,
            "single injected clock must fan out to BOTH config repos"
        );
    }

    #[tokio::test]
    async fn identity_accessors_construct() {
        let i: PgDomainDeps<caps::Identity> = deps().handle().for_domain();
        let _ = i.auth_grant_provider(Box::new(EpochClock), identity_pseudonym_keys_for_test());
        let _ = i.outbox(
            DynPublisher::new_box(StubPublisher),
            relay_budget(),
            tenant_authority(),
            payload_protector(),
        );
        // identity domain repos; AuthGrant lifecycle + refresh are exposed only through the
        // single-owner provider above.
        let _ = i.credential_repo();
        let _ = i.role_repo();
        let _ = i.policy_repo();
        let _ = i.resource_attribute_repo();
        let _ = i.role_binding_read_repo();
    }

    #[tokio::test]
    async fn device_certificate_repository_projects_requested_eligibility() {
        let identity_deps: PgDomainDeps<caps::Identity> = deps().handle().for_domain();
        let _: PgDeviceCertificateRepository<
            identity::ports::device_certificate::DraftEligibility,
        > = identity_deps.device_certificate_repository();
        let _: PgDeviceCertificateRepository<
            identity::ports::device_certificate::ProductionEligibility,
        > = identity_deps.device_certificate_repository();
    }

    #[cfg(feature = "domain-identity")]
    #[tokio::test]
    async fn deviceidentity_runtime_is_minted_as_one_move_only_receipt() {
        let handle = PgRuntimeHandle::from_store_for_test(lazy_store());
        let runtime = handle.device_identity_draft_runtime();
        let (_repository, _commands, _revocations, _reconcile, readiness) = runtime.into_parts();
        assert!(Arc::ptr_eq(&readiness, &handle.readiness_handle()));
    }

    #[tokio::test]
    async fn infra_accessors_construct() {
        // PgInfraDeps：framework/global 基建能力（F1 补齐）——纯 pool clone，无 I/O。
        let infra = deps().handle().infra();
        let _ = infra.emitter(Box::new(EpochClock));
        let _ = infra.inbox();
        let _ = infra.outbox_maintenance();
        let _ = infra.dead_letter(payload_protector());
        let _ = infra.inbox_sweeper();
        let _ = infra.auth_grant_sweeper();
        let _ = infra.checkpoint();
        let _ = infra.cas_store();
        let _ = infra.command_journal(Box::new(EpochClock));
    }

    #[tokio::test]
    async fn audit_accessors_construct() {
        let a: PgDomainDeps<caps::Audit> = deps().handle().for_domain();
        let _ = a.auth_audit_sink();
    }

    #[tokio::test]
    async fn maintenance_shutdown_closes_primary_and_audit_admin_stores() {
        let primary = lazy_store();
        let audit_admin = lazy_store();
        let deps = PgMaintenanceDeps {
            store: VerifiedPgMaintenanceStore::from_maintenance_store(Arc::clone(&primary)),
            audit_admin_store: Some(VerifiedPgAuditAdminStore::from_unverified_for_test(
                Arc::clone(&audit_admin),
            )),
            _delivery_policy: EventDeliveryPolicy::release(),
            clock: Arc::new(EpochClock),
        };

        assert!(!primary.pool.is_closed(), "primary starts open");
        assert!(!audit_admin.pool.is_closed(), "audit admin starts open");

        let shutdown_result = deps.shutdown().await;
        assert!(
            shutdown_result.is_ok(),
            "lazy maintenance stores close cleanly: {shutdown_result:?}"
        );

        assert!(primary.pool.is_closed(), "primary store must be closed");
        assert!(
            audit_admin.pool.is_closed(),
            "audit admin store must be closed"
        );
    }

    #[tokio::test]
    async fn maintenance_capabilities_construct_without_general_infra_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let deps = PgMaintenanceDeps {
            store: VerifiedPgMaintenanceStore::from_maintenance_store(lazy_store()),
            audit_admin_store: None,
            _delivery_policy: EventDeliveryPolicy::release(),
            clock: Arc::new(EpochClock),
        };
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let projection = eventexec::ProjectionId::parse("audit.session-projection")?;
        let selector = eventexec::ProjectionSelector::new(
            tenant,
            projection,
            eventexec::ProjectionVersion::parse("v1")?,
        );
        let principal =
            authn::test_support::service_principal(vocab::ServiceCallerDomain::MaintenanceOperator);
        let grants = authn::ProjectionMaintenanceGrantSet::new(vec![
            authn::ProjectionMaintenanceGrant::new(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                ProjectionMaintenanceAction::Replay,
                tenant,
                "audit.session-projection",
            )?,
        ])?;
        let receipt = grants.authorize(
            &principal,
            ProjectionMaintenanceAction::Replay,
            tenant,
            "audit.session-projection",
        )?;
        let _ = (receipt, selector);
        let _ = deps.dlq_store_with_projection_bindings_for_test(
            payload_protector(),
            generated::event::PROJECTION_INPUTS,
        );
        let _ = deps.dlq_store_without_payload_replay();
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn projection_target_keeps_definition_identity_and_shadow_generation_independent()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let projection = eventexec::ProjectionId::parse("audit.session-projection")?;
        let scope = eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
            &projection,
            tenant,
        )
        .ok_or("generated source scope fixture")?;
        let rollback = eventexec::ProjectionSelector::new(
            tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse("rollback-v1")?,
        );
        assert_ne!(scope.definition_version(), rollback.version().as_str());
        assert!(ProjectionOperatorTarget::bind(&rollback, &scope).is_ok());

        let other_tenant = eventexec::ProjectionSelector::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?,
            projection,
            eventexec::ProjectionVersion::parse("rollback-v1")?,
        );
        assert!(matches!(
            ProjectionOperatorTarget::bind(&other_tenant, &scope),
            Err(crate::ProjectionControlError::SourceTargetMismatch)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn infra_clone_shares_store() {
        let infra = deps().handle().infra();
        let c = infra.clone();
        assert!(
            Arc::ptr_eq(&infra.stores, &c.stores),
            "PgInfraDeps clone 廉价共享 runtime stores Arc"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn runtime_handle_relay_budget_gate_is_synchronous_and_exact() {
        let handle = PgRuntimeHandle::from_store_for_test(lazy_store());
        let release = eventexec::RelayBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(40),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .expect("valid release budget");
        let mismatch = eventexec::RelayBudget::new(
            Duration::from_secs(61),
            Duration::from_secs(40),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .expect("valid mismatched budget");
        assert!(handle.validate_relay_budget(release).is_ok());
        assert!(matches!(
            handle.validate_relay_budget(mismatch),
            Err(PgError::EventDeliveryPolicyMismatch)
        ));
    }

    /// consuming factory 立即 cancel → `shutdown` 两阶段收敛 Ok（覆盖 spawn/adopt 接线）。
    #[tokio::test]
    async fn readiness_sampler_factory_clean_shutdown() {
        use diport::ManagedResource as _;
        let d = deps();
        let token = CancellationToken::new();
        let (_resources, factory) = d.into_runtime_parts(Duration::from_millis(50));
        let sampler = factory.spawn(token.clone());
        token.cancel();
        assert!(
            sampler.shutdown().await.is_ok(),
            "cancel 后 sampler 干净收敛"
        );
    }
}
