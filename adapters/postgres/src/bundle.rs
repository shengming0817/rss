//! postgres capability bundle（#1423 / PERSIST-002）：把 connect、migration、readiness handle、
//! per-domain repo 构造收口到单一 funnel，对组合根的 wire_X 暴露**受控 per-domain 能力句柄**，
//! 绝不泄漏裸 `sqlx::PgPool`。
//!
//! 五个核心类型：
//! - [`PgRuntimeDeps`]：不可克隆的组合根生命周期 owner。唯一公开构造路径 [`PgRuntimeDeps::setup`]；能力只经
//!   [`PgRuntimeDeps::handle`] 投影，生命周期只经 [`PgRuntimeDeps::into_runtime_parts`] 按值交接。
//! - [`PgRuntimeHandle`]：可克隆的运行期能力句柄，派发 [`PgRuntimeHandle::for_domain`] /
//!   [`PgRuntimeHandle::infra`] 与 readiness/RLS probe handle，不拥有生命周期出口。
//! - [`PgDomainDeps<D>`]：per-domain 受控句柄（`Clone`，私有持 `Arc<PgRuntimeStores>`），只暴露该域的 repo
//!   构造方法。类型参数 `D: PgDomain`（sealed marker）使「settings 的 deps 拿去建 identity repo」=
//!   编译错误 E0599（类型层不可表达）。
//! - [`PgInfraDeps`]：framework/global（provider-agnostic、非单域）基建能力句柄——emitter / inbox /
//!   dead_letter / checkpoint / saga / projection，不绑 `caps::*` 域。
//! - [`PgSettingsBundle`]：settings 域 durable 接线包，经 [`PgDomainDeps::settings_bundle`] 单次构造（同一
//!   verified reader/writer capability pair + 单 clock 扇出），内部预包装 config/secret 各自的 read repo + write UoW 域形 DynX port；组合根经
//!   [`PgSettingsBundle::into_parts`] 单次解包注入，不再散装构造 / 手工配对（PERSIST-003）。
//!
//! ## INVARIANT
//!
//! - **PG-BUNDLE-FUNNEL-01**（Hard，可见性封装）：公开 store 构造路径只允许三个受控 funnel：
//!   [`PgRuntimeDeps::setup`]（serving runtime）、[`PgRuntimeDeps::migrate_reader_lane_only`]（0067 one-shot）
//!   与 [`PgRuntimeDeps::connect_maintenance`]（离线维护）。三者之外
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
//!   schema 门控。本模块对应：`connect`/`run_migrations` `pub(crate)` + `PgRuntimeDeps` 私有持 `Arc<PgRuntimeStores>`。
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
use settings::ports::{DynConfigRepo, DynConfigUnitOfWork, DynSecretRepo, DynSecretUnitOfWork};
#[cfg(feature = "test-support")]
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio_util::sync::CancellationToken;

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use crate::PgOutbox;
#[cfg(feature = "domain-audit")]
use crate::consumer_tx::PgAuditConsumerTx;
use crate::delivery_policy::EventDeliveryPolicy;
use crate::pool::{PgRuntimeStores, VerifiedPgAuditAdminStore, VerifiedPgMaintenanceStore};
use crate::projection_events::ProjectionWriteRegistry;
#[cfg(feature = "domain-settings")]
use crate::{
    ConfigValueMaintenanceCapability, ConfigValueProtection, ConfigValueProtections, PgConfigRepo,
    PgConfigValueMaintenance, PgSecretRepo, PgSecretUnitOfWork, PgSettingsConsumerTx,
};
use crate::{
    DlxPayloadProtector, LegacyConfigPlaintextPolicy, PgAuthGrantSweeper, PgCheckpointStore,
    PgCommandJournal, PgConfig, PgDbReadiness, PgDeadLetterStore, PgDlqStore, PgEmitter, PgError,
    PgInboxStore, PgInboxSweeper, PgOutboxCdcEmitter, PgOutboxMaintenance, PgProjectionControl,
    PgProjectionEvents, PgReadinessSampler, PgReconcileStore, PgSagaInstanceStore, PgSagaJournal,
    PgServiceTokenReplayStore, PgServiceTokenReplaySweeper, PgStore, PgStoreGuard,
    PgTenantReadConfig,
};
#[cfg(feature = "domain-audit")]
use crate::{PgAuditAdminRepo, PgAuditRepo, PgAuthAuditSink};
#[cfg(feature = "domain-identity")]
use crate::{
    PgAuthGrantLifecycle, PgAuthGrantProvider, PgAuthGrantValidator, PgCredentialRepo,
    PgCredentialSecurityTargetResolver, PgIdentitySecurityLifecycle, PgPolicyLifecycle,
    PgPolicyRepo, PgRefreshTokenStore, PgResourceAttributeRepo, PgRoleBindingLifecycle,
    PgRoleBindingReadRepo, PgRoleRepo,
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

/// 组合根级 postgres 生命周期 owner：集中 connect + migration，并唯一拥有 pool 与 sampler 的关闭权。
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
    audit_admin_store: Option<VerifiedPgAuditAdminStore>,
    delivery_policy: EventDeliveryPolicy,
    projection_registry: ProjectionWriteRegistry,
    readiness: Arc<PgDbReadiness>,
    rls_ready: Arc<AtomicBool>,
}

/// DB readiness sampler 的单次启动工厂。
///
/// `spawn(self, token)` 消费工厂；同一 owner 产生的 factory 无法启动第二个 sampler。
pub struct PgReadinessSamplerFactory {
    writer_store: Arc<PgStore>,
    reader_store: Arc<PgStore>,
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

/// Projection replay 所需的最小 store 集；字段私有，防止 maintenance 获得通用 infra 能力。
pub struct PgProjectionReplayStores<'a> {
    events: PgProjectionEvents,
    checkpoint: PgCheckpointStore,
    dead_letter: PgDeadLetterStore,
    receipt: &'a ProjectionMaintenanceReceipt,
    tenant: vocab::TenantId,
    projection: Box<str>,
}

impl PgProjectionReplayStores<'_> {
    /// 消费式拆出 replay 所需的三个互异能力。
    pub fn into_parts(
        self,
    ) -> Result<
        (PgProjectionEvents, PgCheckpointStore, PgDeadLetterStore),
        crate::ProjectionControlError,
    > {
        if !self.receipt.authorizes(
            ProjectionMaintenanceAction::Replay,
            self.tenant,
            &self.projection,
        ) {
            return Err(crate::ProjectionControlError::ReceiptTargetMismatch);
        }
        Ok((self.events, self.checkpoint, self.dead_letter))
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

    /// Release-only SQLx migration runner for the exact 0066 → 0067 LocalOnly reader cutover.
    ///
    /// This entry does not construct writer/reader serving pools. The adapter verifies both the
    /// embedded migration universe and `_sqlx_migrations` ledger before applying anything, so it
    /// cannot silently become a generic migration bypass when a later migration is added.
    pub async fn migrate_reader_lane_only(migrator_config: &PgConfig) -> Result<(), PgError> {
        let migrator = PgStore::connect_migrator(migrator_config).await?;
        let result = migrator.run_reader_lane_migration_only().await;
        let _ = migrator.shutdown().await;
        result
    }

    /// 唯一公开构造路径：migrator 连接跑迁移，serving 连接建长期 pool 并跑 RLS 能力门。
    ///
    /// `migrator_config` 必须是短生命周期 DDL 角色；`serving_config` 必须是长期最小权限
    /// `rss_app` NOBYPASSRLS 角色。缺配 / 连不上 / 迁移失败 / **RLS 能力缺失**均 fail-fast 返 [`PgError`]
    /// （区分 `Connect` / `Migrate` / `Rls*` 阶段）；组合根在边界 `.context(..)` 成 anyhow。
    /// 对标 omicron `DataStore::new_with_timeout`（构造器集中 + schema/能力门控，对象返回前校验）。
    pub async fn setup(
        migrator_config: &PgConfig,
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        projection_generation: &'static str,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        Self::setup_with_audit_admin_config(
            migrator_config,
            serving_config,
            tenant_read_config,
            None,
            LegacyConfigPlaintextPolicy::Deny,
            projection_generation,
            projection_inputs,
        )
        .await
    }

    /// [`setup`](Self::setup) 的显式 legacy plaintext 策略版本。runtime 组合根只在读取到人工临时豁免 env 时
    /// 传入 [`LegacyConfigPlaintextPolicy::AllowTemporary`]；默认 deny。
    pub async fn setup_with_legacy_config_policy(
        migrator_config: &PgConfig,
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        legacy_config_plaintext_policy: LegacyConfigPlaintextPolicy,
        projection_generation: &'static str,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        Self::setup_with_audit_admin_config(
            migrator_config,
            serving_config,
            tenant_read_config,
            None,
            legacy_config_plaintext_policy,
            projection_generation,
            projection_inputs,
        )
        .await
    }

    /// 显式 audit admin pool 版本：admin config 缺省时仅 scoped audit read 可用；提供时启动期验证
    /// `rss_audit_admin` 直连、NOBYPASSRLS、只读权限。
    pub async fn setup_with_audit_admin_config(
        migrator_config: &PgConfig,
        serving_config: &PgConfig,
        tenant_read_config: &PgTenantReadConfig,
        audit_admin_config: Option<&PgConfig>,
        legacy_config_plaintext_policy: LegacyConfigPlaintextPolicy,
        projection_generation: &'static str,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        let migrator = Arc::new(PgStore::connect_migrator(migrator_config).await?);
        let mut migrator_transaction = PgSetupTransaction::new();
        migrator_transaction.register(PgStoreGuard::new_named(
            Arc::clone(&migrator),
            "postgres-migrator",
        ));
        let migration_result = async {
            migrator.run_migrations().await?;
            let delivery_policy = migrator.load_event_delivery_policy().await?;
            migrator
                .verify_config_legacy_plaintext_policy(legacy_config_plaintext_policy)
                .await?;
            migrator
                .register_projection_input_bindings(projection_generation, projection_inputs)
                .await
                .map_err(PgError::ProjectionBindings)?;
            Ok(delivery_policy)
        }
        .await;
        let delivery_policy = migrator_transaction.close(migration_result).await?;

        let mut serving_transaction = PgSetupTransaction::new();
        let writer = PgStore::connect_verified_writer(serving_config).await?;
        serving_transaction.register(PgStoreGuard::new_named(
            writer.store_arc(),
            "postgres-writer",
        ));
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
                audit_admin_store,
                delivery_policy,
                projection_registry: ProjectionWriteRegistry::from_generated(projection_inputs),
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
            audit_admin_store,
            delivery_policy: _,
            projection_registry: _,
            readiness,
            rls_ready: _,
        } = self.handle;
        let writer_store = stores.writer_store_arc();
        let reader_store = stores.reader_store_arc();
        let mut resources = vec![DynManagedResource::new_box(PgStoreGuard::new(Arc::clone(
            &writer_store,
        )))];
        resources.push(DynManagedResource::new_box(PgStoreGuard::new_named(
            Arc::clone(&reader_store),
            "postgres-tenant-reader",
        )));
        if let Some(audit_admin_store) = audit_admin_store {
            resources.push(DynManagedResource::new_box(PgStoreGuard::new_named(
                audit_admin_store.store_arc(),
                "postgres-audit-admin",
            )));
        }
        (
            resources,
            PgReadinessSamplerFactory {
                writer_store,
                reader_store,
                readiness,
                period,
            },
        )
    }
}

impl PgRuntimeHandle {
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
            projection_registry: self.projection_registry,
            _marker: PhantomData,
        }
    }

    /// 派发 framework/global（provider-agnostic、非单域）基建能力句柄 [`PgInfraDeps`]——
    /// emitter / dead_letter / checkpoint / saga / projection 不绑单一域，故不进 `PgDomainDeps<D>`。
    #[must_use]
    pub fn infra(&self) -> PgInfraDeps {
        PgInfraDeps {
            stores: Arc::clone(&self.stores),
            projection_registry: self.projection_registry,
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
            audit_admin_store: None,
            delivery_policy: EventDeliveryPolicy::release(),
            projection_registry: ProjectionWriteRegistry::empty(),
            readiness: Arc::new(PgDbReadiness::new()),
            rls_ready: Arc::new(AtomicBool::new(true)),
        }
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
                audit_admin_store: audit_admin_store
                    .map(VerifiedPgAuditAdminStore::from_unverified_for_test),
                delivery_policy: EventDeliveryPolicy::release(),
                projection_registry: ProjectionWriteRegistry::empty(),
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
            audit_admin_store: None,
            delivery_policy: EventDeliveryPolicy::release(),
            projection_registry: ProjectionWriteRegistry::empty(),
            readiness: Arc::new(PgDbReadiness::new()),
            rls_ready: Arc::new(AtomicBool::new(true)),
        }
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

    async fn record_maintenance_audit(
        &self,
        resource_kind: &str,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
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
            VALUES ($1, $2, $3, 'service', NULL, $4, $5, $6, $7, $8, NULL, NULL)
            "#,
        )
        .bind(secs)
        .bind(nanos)
        .bind(operator_subject)
        .bind(resource_kind)
        .bind(resource_id)
        .bind(action)
        .bind(outcome)
        .bind(failure_reason)
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
            action,
            outcome,
            resource_id,
        )
        .await
    }

    /// Durable audit record for projection replay / shadow-swap jobs.
    pub async fn record_projection_maintenance_audit(
        &self,
        operator_subject: &str,
        action: &str,
        outcome: MaintenanceAuditOutcome<'_>,
        resource_id: &str,
    ) -> Result<(), PgError> {
        self.record_maintenance_audit(
            "projection.maintenance",
            operator_subject,
            action,
            outcome,
            resource_id,
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
            action,
            outcome,
            resource_id,
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
            action,
            outcome,
            resource_id,
        )
        .await
    }

    /// Tenant-scoped reconcile target operator store.
    #[must_use]
    pub fn reconcile_store(&self) -> PgReconcileStore {
        PgReconcileStore::new_maintenance(&self.store)
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
            action,
            outcome,
            resource_id,
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

    /// Projection replay / shadow-swap control store.
    #[must_use]
    pub fn projection_control<'a>(
        &self,
        receipt: &'a ProjectionMaintenanceReceipt,
    ) -> PgProjectionControl<'a> {
        PgStore::projection_control(self.store.store_arc(), receipt)
    }

    /// Projection replay 所需的精确 capability bundle。
    pub fn projection_replay_stores<'a>(
        &self,
        receipt: &'a ProjectionMaintenanceReceipt,
        selector: &eventexec::ProjectionSelector,
        payload_protector: DlxPayloadProtector,
    ) -> Result<PgProjectionReplayStores<'a>, crate::ProjectionControlError> {
        crate::projection_control::authorize_receipt(
            receipt,
            ProjectionMaintenanceAction::Replay,
            selector,
        )?;
        Ok(PgProjectionReplayStores {
            events: self.store.store_arc().projection_events(),
            checkpoint: self.store.store_arc().checkpoint(),
            dead_letter: PgDeadLetterStore::new_maintenance(&self.store, payload_protector),
            receipt,
            tenant: selector.tenant(),
            projection: selector.projection().as_str().into(),
        })
    }

    /// 带 payload replay 能力的 DLQ maintenance store。
    #[must_use]
    pub fn dlq_store(
        &self,
        payload_protector: DlxPayloadProtector,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> PgDlqStore {
        PgDlqStore::with_projection_registry_maintenance(
            &self.store,
            payload_protector,
            ProjectionWriteRegistry::from_generated(projection_inputs),
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
    let _ = d.auth_grant_provider(unimplemented!());
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
fn identity_ok(d: PgDomainDeps<caps::Identity>, clock: Box<dyn diport::Clock>) {
    let _ = d.auth_grant_provider(clock);
}
```
"#
)]
pub struct PgDomainDeps<D: PgDomain> {
    stores: Arc<PgRuntimeStores>,
    audit_admin_store: Option<VerifiedPgAuditAdminStore>,
    projection_registry: ProjectionWriteRegistry,
    _marker: PhantomData<D>,
}

// 手写 `Clone`：避免 `#[derive(Clone)]` 引入多余的 `D: Clone` bound（marker 是 ZST，与 Clone 无关）。
impl<D: PgDomain> Clone for PgDomainDeps<D> {
    fn clone(&self) -> Self {
        Self {
            stores: Arc::clone(&self.stores),
            audit_admin_store: self.audit_admin_store.clone(),
            projection_registry: self.projection_registry,
            _marker: PhantomData,
        }
    }
}

#[cfg(feature = "domain-settings")]
impl PgDomainDeps<caps::Settings> {
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
                self.projection_registry,
            )),
            config_uow: DynConfigUnitOfWork::new_box(PgConfigRepo::new_with_projection_registry(
                self.stores.reader_capability(),
                self.stores.writer_capability(),
                clock,
                config_write_protection,
                self.projection_registry,
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
impl PgDomainDeps<caps::Identity> {
    /// Request-time durable fence for verified RSS access-token grant bindings.
    #[must_use]
    pub fn auth_grant_validator(&self) -> PgAuthGrantValidator {
        PgAuthGrantValidator::new(self.stores.reader_capability())
    }

    /// Single-owner AuthGrant/refresh provider used by login composition.
    #[must_use]
    pub fn auth_grant_provider(&self, clock: Box<dyn Clock>) -> PgAuthGrantProvider {
        PgAuthGrantProvider::new(
            PgAuthGrantLifecycle::new_with_projection_registry(
                self.stores.reader_capability(),
                self.stores.writer_capability(),
                clock,
                self.projection_registry,
            ),
            PgRefreshTokenStore::new(
                self.stores.reader_capability(),
                self.stores.writer_capability(),
            ),
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

    /// Durable account-security state provider for mandatory auth gates and sealed lifecycle CAS.
    #[must_use]
    pub fn account_security_repo(&self) -> crate::PgAccountSecurityRepo {
        crate::PgAccountSecurityRepo::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// Draft credential-security projection + OutboxFact lifecycle.
    ///
    /// This constructor does not wire a production producer; callers must already hold the
    /// domain's sealed command.
    #[must_use]
    pub fn identity_security_lifecycle(&self) -> PgIdentitySecurityLifecycle {
        PgIdentitySecurityLifecycle::new(self.stores.writer_capability(), self.projection_registry)
    }

    /// Read-only resolver for the opaque target reference carried by credential-security facts.
    #[must_use]
    pub fn credential_security_target_resolver(&self) -> PgCredentialSecurityTargetResolver {
        PgCredentialSecurityTargetResolver::new(self.stores.reader_capability())
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
            self.projection_registry,
        )
    }

    /// 角色绑定生命周期（binding co-tx + role event outbox）。
    #[must_use]
    pub fn role_binding_lifecycle(&self, clock: Box<dyn Clock>) -> PgRoleBindingLifecycle {
        PgRoleBindingLifecycle::new_with_projection_registry(
            self.stores.writer_capability(),
            clock,
            self.projection_registry,
        )
    }

    /// Journey-only refresh store that loses the commit acknowledgement for one named token
    /// rotation after PostgreSQL accepts the commit.
    ///
    /// The narrow seam is absent from default builds and exposes neither generic fault selection
    /// nor raw transaction/pool access.
    #[cfg(feature = "journey-fault-support")]
    #[must_use]
    pub fn refresh_token_store_with_commit_unknown_once(
        &self,
        old_id: &str,
    ) -> PgRefreshTokenStore {
        PgRefreshTokenStore::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
        .with_rotation_fault(
            old_id,
            crate::refresh_token_store::RefreshRotationFault::CommitUnknown,
            1,
        )
    }
}

#[cfg(feature = "domain-audit")]
impl PgDomainDeps<caps::Audit> {
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
///     let _ = i.projection_events();
/// }
/// ```
#[derive(Clone)]
pub struct PgInfraDeps {
    stores: Arc<PgRuntimeStores>,
    projection_registry: ProjectionWriteRegistry,
    delivery_policy: EventDeliveryPolicy,
}

impl PgInfraDeps {
    /// outbox emitter（envelope `occurred_at` 时间源经 `clock` 注入，构造器位置参）。
    #[must_use]
    pub fn emitter(&self, clock: Box<dyn Clock>) -> PgEmitter {
        PgEmitter::new_with_projection_registry(
            self.stores.writer_capability(),
            clock,
            self.projection_registry,
        )
    }

    /// CDC-facing append-only outbox emitter.
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
        PgReconcileStore::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
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

    /// saga instance/lease store（L3 saga claim/fencing）。
    #[must_use]
    pub fn saga_instance_store(&self) -> PgSagaInstanceStore {
        PgSagaInstanceStore::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// saga journal（L3 saga 状态）。
    #[must_use]
    pub fn saga_journal(&self) -> PgSagaJournal {
        PgSagaJournal::new(
            self.stores.reader_capability(),
            self.stores.writer_capability(),
        )
    }

    /// projection events 读路径（全局 projection journal）。
    #[must_use]
    pub fn projection_events(&self) -> PgProjectionEvents {
        self.stores.writer_store_arc().projection_events()
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
        let _ = i.auth_grant_provider(Box::new(EpochClock));
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
        let _ = infra.saga_instance_store();
        let _ = infra.saga_journal();
        let _ = infra.projection_events();
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
        let (_events, _checkpoint, _dead_letter) = deps
            .projection_replay_stores(&receipt, &selector, payload_protector())?
            .into_parts()?;
        let _ = deps.dlq_store(payload_protector(), generated::event::PROJECTION_INPUTS);
        let _ = deps.dlq_store_without_payload_replay();
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
