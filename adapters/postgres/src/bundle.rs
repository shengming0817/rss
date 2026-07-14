//! postgres capability bundle（#1423 / PERSIST-002）：把 connect、migration、readiness handle、
//! per-domain repo 构造收口到单一 funnel，对组合根的 wire_X 暴露**受控 per-domain 能力句柄**，
//! 绝不泄漏裸 `sqlx::PgPool`。
//!
//! 五个核心类型：
//! - [`PgRuntimeDeps`]：不可克隆的组合根生命周期 owner。唯一公开构造路径 [`PgRuntimeDeps::setup`]；能力只经
//!   [`PgRuntimeDeps::handle`] 投影，生命周期只经 [`PgRuntimeDeps::into_runtime_parts`] 按值交接。
//! - [`PgRuntimeHandle`]：可克隆的运行期能力句柄，派发 [`PgRuntimeHandle::for_domain`] /
//!   [`PgRuntimeHandle::infra`] 与 readiness/RLS probe handle，不拥有生命周期出口。
//! - [`PgDomainDeps<D>`]：per-domain 受控句柄（`Clone`，私有持 `Arc<PgStore>`），只暴露该域的 repo
//!   构造方法。类型参数 `D: PgDomain`（sealed marker）使「settings 的 deps 拿去建 identity repo」=
//!   编译错误 E0599（类型层不可表达）。
//! - [`PgInfraDeps`]：framework/global（provider-agnostic、非单域）基建能力句柄——emitter / inbox /
//!   dead_letter / checkpoint / saga / projection，不绑 `caps::*` 域。
//! - [`PgSettingsBundle`]：settings 域 durable 接线包，经 [`PgDomainDeps::settings_bundle`] 单次构造（同
//!   store + 单 clock 扇出），内部预包装 config/secret 各自的 read repo + write UoW 域形 DynX port；组合根经
//!   [`PgSettingsBundle::into_parts`] 单次解包注入，不再散装构造 / 手工配对（PERSIST-003）。
//!
//! ## INVARIANT
//!
//! - **PG-BUNDLE-FUNNEL-01**（Hard，可见性封装）：公开 store 构造路径只允许两个受控 funnel：
//!   [`PgRuntimeDeps::setup`]（serving runtime）与 [`PgRuntimeDeps::connect_maintenance`]（离线维护）。二者之外
//!   `PgStore::connect` / `run_migrations` 已降 `pub(crate)`，外部无法 mint `PgStore`、也拿不到 `&PgStore`；
//!   且**所有** `&PgStore`-taking repo 构造器（含 credential/role/refresh_token/emitter + dead_letter/
//!   checkpoint/saga/projection）均 `pub(crate)`——serving repo 只能经 `PgDomainDeps` / `PgInfraDeps` 构造，
//!   maintenance 只能拿到限定维护能力，不暴露 pool/store。
//! - **PG-BUNDLE-DOMAIN-02**（Hard，sealed marker + typed function choice）：per-domain 能力隔离。
//!   anti-vacuity = 下方 `PgDomainDeps` 的 `compile_fail` doctest（Settings 句柄调 `session_lifecycle` 必败）。
//! - **PG-BUNDLE-POOL-03**（Hard）：本模块无任何返回 `&PgStore` / `Arc<PgStore>` / `PgPool` 的公开 accessor；
//!   `store` 字段私有，仅 in-crate repo 构造方法 clone `pub(crate) pool`。
//! - **PG-BUNDLE-SETTINGS-04**（Hard，可见性 + sealed funnel + typed function choice）：settings 四件套
//!   （config read/write + secret read/write）只能经 [`PgDomainDeps::settings_bundle`] 单次构造（funnel，
//!   私有字段 + 唯一公开构造 ⇒ 外部 crate 无法 mint），经 [`PgSettingsBundle::into_parts`] 解包；一次
//!   `into_parts` 产出的四元同源（同一 store + 同一注入 clock，clock 经 `Arc` 扇出到两个 `PgConfigRepo`）。
//!   四件为互不可换的域形 dyn 类型（`DynConfigRepo`/`DynConfigUnitOfWork`/`DynSecretRepo`/
//!   `DynSecretUnitOfWork`）⇒ 注入 service 时 read/write **角色无法错插**（typed function choice）。
//!   散装 `config_repo()` / `secret_repo()`
//!   accessor 已删除（不留兼容路径）。**强制边界**：funnel 守上游构造 + 角色槽位；`into_parts` 后四件为
//!   owned 值，类型层不阻止把不同 bundle 实例的 box 跨实例重组（单一 `PgRuntimeDeps` ⇒ 同 store，跨 bundle
//!   重组为 contrived），故不声称该项。anti-vacuity = [`PgSettingsBundle`] 私有字段 `compile_fail` doctest
//!   （须经 `into_parts` 唯一出口，不可旁路直读单字段）。
//!
//! ## 开源对标
//!
//! - `ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/mod.rs@main` —— 两层私有
//!   （`Pool.inner` → `DataStore.pool: Arc<Pool>`）+ `pool_connection_authorized` `pub(super)`；构造器集中 +
//!   schema 门控。本模块对应：`connect`/`run_migrations` `pub(crate)` + `PgRuntimeDeps` 私有持 `Arc<PgStore>`。
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
use crate::projection_events::ProjectionWriteRegistry;
#[cfg(feature = "domain-settings")]
use crate::{
    ConfigValueMaintenanceCapability, ConfigValueProtection, ConfigValueProtections, PgConfigRepo,
    PgConfigValueMaintenance, PgSecretRepo, PgSecretUnitOfWork, PgSettingsConsumerTx,
};
use crate::{
    DlxPayloadProtector, LegacyConfigPlaintextPolicy, PgCheckpointStore, PgCommandJournal,
    PgConfig, PgDbReadiness, PgDeadLetterStore, PgDlqStore, PgEmitter, PgError, PgInboxStore,
    PgInboxSweeper, PgOutboxCdcEmitter, PgOutboxMaintenance, PgProjectionControl,
    PgProjectionEvents, PgReadinessSampler, PgReconcileStore, PgSagaInstanceStore, PgSagaJournal,
    PgServiceTokenReplayGuard, PgSessionSweeper, PgStore, PgStoreGuard,
};
#[cfg(feature = "domain-audit")]
use crate::{PgAuditAdminRepo, PgAuditRepo, PgAuthAuditSink};
#[cfg(feature = "domain-identity")]
use crate::{
    PgCredentialRepo, PgPolicyLifecycle, PgPolicyRepo, PgRefreshTokenStore,
    PgResourceAttributeRepo, PgRoleBindingLifecycle, PgRoleRepo, PgSessionLifecycle,
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
    store: Arc<PgStore>,
    audit_admin_store: Option<Arc<PgStore>>,
    delivery_policy: EventDeliveryPolicy,
    projection_registry: ProjectionWriteRegistry,
    readiness: Arc<PgDbReadiness>,
    rls_ready: Arc<AtomicBool>,
}

/// DB readiness sampler 的单次启动工厂。
///
/// `spawn(self, token)` 消费工厂；同一 owner 产生的 factory 无法启动第二个 sampler。
pub struct PgReadinessSamplerFactory {
    store: Arc<PgStore>,
    readiness: Arc<PgDbReadiness>,
    period: Duration,
}

impl PgReadinessSamplerFactory {
    /// 使用 `ShutdownStack` 注入的 token 启动 sampler，并消费本 factory。
    #[must_use]
    pub fn spawn(self, token: CancellationToken) -> PgReadinessSampler {
        let handle = tokio::spawn(crate::readiness::pg_readiness_sampling_loop(
            self.store,
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
    store: Arc<PgStore>,
    audit_admin_store: Option<Arc<PgStore>>,
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
    /// 唯一公开构造路径：migrator 连接跑迁移，serving 连接建长期 pool 并跑 RLS 能力门。
    ///
    /// `migrator_config` 必须是短生命周期 DDL 角色；`serving_config` 必须是长期最小权限
    /// `rss_app` NOBYPASSRLS 角色。缺配 / 连不上 / 迁移失败 / **RLS 能力缺失**均 fail-fast 返 [`PgError`]
    /// （区分 `Connect` / `Migrate` / `Rls*` 阶段）；组合根在边界 `.context(..)` 成 anyhow。
    /// 对标 omicron `DataStore::new_with_timeout`（构造器集中 + schema/能力门控，对象返回前校验）。
    pub async fn setup(
        migrator_config: &PgConfig,
        serving_config: &PgConfig,
        projection_generation: &'static str,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        Self::setup_with_audit_admin_config(
            migrator_config,
            serving_config,
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
        legacy_config_plaintext_policy: LegacyConfigPlaintextPolicy,
        projection_generation: &'static str,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        Self::setup_with_audit_admin_config(
            migrator_config,
            serving_config,
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
        audit_admin_config: Option<&PgConfig>,
        legacy_config_plaintext_policy: LegacyConfigPlaintextPolicy,
        projection_generation: &'static str,
        projection_inputs: &'static [vocab::ProjectionInputBinding],
    ) -> Result<Self, PgError> {
        let migrator = PgStore::connect(migrator_config).await?;
        migrator.run_migrations().await?;
        let delivery_policy = migrator.load_event_delivery_policy().await?;
        migrator
            .verify_config_legacy_plaintext_policy(legacy_config_plaintext_policy)
            .await?;
        migrator
            .register_projection_input_bindings(projection_generation, projection_inputs)
            .await
            .map_err(PgError::ProjectionBindings)?;
        migrator.shutdown().await.ok();

        let store = Arc::new(PgStore::connect(serving_config).await?);
        // durable RLS 能力门（fail-fast）：tenant 表须 FORCE RLS + policy 且 GUC roundtrip 通过，否则拒绝启动。
        store.verify_rls_capability().await?;
        let audit_admin_store = match audit_admin_config {
            Some(config) => {
                let store = Arc::new(PgStore::connect(config).await?);
                store.verify_audit_admin_capability().await?;
                Some(store)
            }
            None => None,
        };
        Ok(Self {
            handle: PgRuntimeHandle {
                store,
                audit_admin_store,
                delivery_policy,
                projection_registry: ProjectionWriteRegistry::from_generated(projection_inputs),
                readiness: Arc::new(PgDbReadiness::new()),
                rls_ready: Arc::new(AtomicBool::new(true)),
            },
        })
    }

    /// 连接离线维护能力包，但绝不运行 migration。
    ///
    /// 破坏式 migration 只能由完成全部外部 capability preflight 的 runtime bootstrap 执行；CLI
    /// maintenance 连接若隐式迁移会绕过该顺序门。schema/policy 缺失时，本入口读取固定 policy 即失败。
    pub async fn connect_maintenance(
        migrator_config: &PgConfig,
    ) -> Result<PgMaintenanceDeps, PgError> {
        let store = Arc::new(PgStore::connect(migrator_config).await?);
        let delivery_policy = store.load_event_delivery_policy().await?;
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
        let store = Arc::new(PgStore::connect(migrator_config).await?);
        let delivery_policy = store.load_event_delivery_policy().await?;
        let audit_admin_store = Arc::new(PgStore::connect(audit_admin_config).await?);
        audit_admin_store.verify_audit_admin_capability().await?;
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
    /// resource 注册顺序固定为 primary pool → optional audit-admin pool；LIFO shutdown 时 sampler 先停，
    /// 随后 audit-admin、primary 依次关池。sampler factory 也不可克隆并由调用方单次启动。
    #[must_use]
    pub fn into_runtime_parts(
        self,
        period: Duration,
    ) -> (
        Vec<Box<DynManagedResource<'static>>>,
        PgReadinessSamplerFactory,
    ) {
        let PgRuntimeHandle {
            store,
            audit_admin_store,
            delivery_policy: _,
            projection_registry: _,
            readiness,
            rls_ready: _,
        } = self.handle;
        let mut resources = vec![DynManagedResource::new_box(PgStoreGuard::new(Arc::clone(
            &store,
        )))];
        if let Some(audit_admin_store) = audit_admin_store {
            resources.push(DynManagedResource::new_box(PgStoreGuard::new_named(
                audit_admin_store,
                "postgres-audit-admin",
            )));
        }
        (
            resources,
            PgReadinessSamplerFactory {
                store,
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

    /// 派发 per-domain 受控句柄（`Arc<PgStore>` clone + `PhantomData<D>`）。
    ///
    /// 对标 kube-rs `Controller::run(.., Arc<Ctx>)` 注入 shared context。
    #[must_use]
    pub fn for_domain<D: PgDomain>(&self) -> PgDomainDeps<D> {
        PgDomainDeps {
            store: Arc::clone(&self.store),
            audit_admin_store: self.audit_admin_store.as_ref().map(Arc::clone),
            projection_registry: self.projection_registry,
            _marker: PhantomData,
        }
    }

    /// 派发 framework/global（provider-agnostic、非单域）基建能力句柄 [`PgInfraDeps`]——
    /// emitter / dead_letter / checkpoint / saga / projection 不绑单一域，故不进 `PgDomainDeps<D>`。
    #[must_use]
    pub fn infra(&self) -> PgInfraDeps {
        PgInfraDeps {
            store: Arc::clone(&self.store),
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
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options);
        Self {
            store: Arc::new(PgStore { pool }),
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
        Self {
            handle: PgRuntimeHandle {
                store,
                audit_admin_store,
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
            store,
            audit_admin_store: None,
            delivery_policy: EventDeliveryPolicy::release(),
            projection_registry: ProjectionWriteRegistry::empty(),
            readiness: Arc::new(PgDbReadiness::new()),
            rls_ready: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl PgMaintenanceDeps {
    /// Durable replay guard for one-shot maintenance operator service tokens.
    #[must_use]
    pub fn service_token_replay_guard(&self) -> Arc<dyn diport::ServiceTokenReplayGuard> {
        Arc::new(PgServiceTokenReplayGuard::new(Arc::clone(&self.store)))
    }

    /// settings `ConfigValue` 存量 backfill/rewrap 执行器。
    #[must_use]
    #[cfg(feature = "domain-settings")]
    pub fn config_value_maintenance(
        &self,
        protection: ConfigValueProtection,
        capability: ConfigValueMaintenanceCapability,
    ) -> PgConfigValueMaintenance {
        PgConfigValueMaintenance::new(Arc::clone(&self.store), protection, capability)
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
        .execute(&self.store.pool)
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
        self.store.reconcile()
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
        PgStore::projection_control(Arc::clone(&self.store), receipt)
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
            events: self.store.projection_events(),
            checkpoint: self.store.checkpoint(),
            dead_letter: self.store.dead_letter(payload_protector),
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
        self.store.dlq_with_projection_registry(
            payload_protector,
            ProjectionWriteRegistry::from_generated(projection_inputs),
        )
    }

    /// 不允许 consumer payload replay 的 inspection/outbox-redrive store。
    #[must_use]
    pub fn dlq_store_without_payload_replay(&self) -> PgDlqStore {
        self.store.dlq_without_payload_replay()
    }

    /// 关闭维护连接池。
    pub async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        let audit_admin_result = match self.audit_admin_store.as_ref() {
            Some(store) => store.shutdown().await,
            None => Ok(()),
        };
        let primary_result = self.store.shutdown().await;
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
/// 私有持 `Arc<PgStore>`，只暴露**所属域 `D`** 的 repo 构造方法（方法体在 crate 内走 `pub(crate) pool`
/// clone，返回具体 repo 类型，从不返回 `PgPool`）。`D` 是 sealed marker（[`caps`]），跨域调用编译期被拒：
///
/// `PgDomainDeps<caps::Settings>` 调 identity 能力 = 编译错误（PG-BUNDLE-DOMAIN-02 anti-vacuity）：
///
/// ```compile_fail
/// use postgres::{PgDomainDeps, caps};
/// fn bad(d: PgDomainDeps<caps::Settings>) {
///     // E0599：`session_lifecycle` 不在 `PgDomainDeps<caps::Settings>` 上（仅 identity 句柄有）。
///     let _ = d.session_lifecycle(unimplemented!());
/// }
/// ```
///
/// 同句柄的本域方法可用（正向）：
///
/// ```
/// use postgres::{PgDomainDeps, caps};
/// fn settings_ok(
///     d: PgDomainDeps<caps::Settings>,
///     clock: std::sync::Arc<dyn diport::Clock>,
///     protections: postgres::ConfigValueProtections,
/// ) {
///     // Arc：单一 clock 经 settings_bundle 扇出到 read/write 两个 config 实例（见 settings_bundle）。
///     let _ = d.settings_bundle(clock, protections);
/// }
/// fn identity_ok(d: PgDomainDeps<caps::Identity>, clock: Box<dyn diport::Clock>) {
///     let _ = d.session_lifecycle(clock);
/// }
/// ```
pub struct PgDomainDeps<D: PgDomain> {
    store: Arc<PgStore>,
    audit_admin_store: Option<Arc<PgStore>>,
    projection_registry: ProjectionWriteRegistry,
    _marker: PhantomData<D>,
}

// 手写 `Clone`：避免 `#[derive(Clone)]` 引入多余的 `D: Clone` bound（marker 是 ZST，与 Clone 无关）。
impl<D: PgDomain> Clone for PgDomainDeps<D> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            audit_admin_store: self.audit_admin_store.as_ref().map(Arc::clone),
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
                &self.store,
                Arc::clone(&clock),
                config_read_protection,
                self.projection_registry,
            )),
            config_uow: DynConfigUnitOfWork::new_box(PgConfigRepo::new_with_projection_registry(
                &self.store,
                clock,
                config_write_protection,
                self.projection_registry,
            )),
            secret_repo: DynSecretRepo::new_box(PgSecretRepo::new(&self.store)),
            secret_uow: DynSecretUnitOfWork::new_box(PgSecretUnitOfWork::new(&self.store)),
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
            &self.store,
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
        effect: bootstrap::SubscriberEffect,
    ) -> PgSettingsConsumerTx {
        PgSettingsConsumerTx::config_version_changed(&self.store, effect)
    }
}

/// settings 域 durable 接线包（PERSIST-003 / #1424）：config 与 secret 各自的 read repo + write UoW，全部
/// 源自同一 `(store, clock)`、预包装为 settings 域 dyn DI port。
///
/// 字段私有 + 唯一构造经 [`PgDomainDeps::settings_bundle`] + 唯一解包经 [`PgSettingsBundle::into_parts`]
/// （PG-BUNDLE-SETTINGS-04，Hard）。**实际强制**（仅声明类型层真成立的）：
/// - 外部 crate 无法 mint（私有字段 + 唯一公开构造 funnel）；
/// - 一次 `into_parts` 产出的四元同源（同一 store + 同一注入 clock）；
/// - 四件为互不可换的域形 dyn 类型 ⇒ config/secret 的 read/write 角色无法错插（typed function choice）。
///
/// **不声称**：`into_parts` 后四件为 owned 值，类型层不阻止把不同 bundle 实例的 box 跨实例重组（funnel 守
/// 上游构造 + 角色槽位，不守下游跨 bundle 重组；单一 `PgRuntimeDeps` ⇒ 同 store，跨 bundle 重组为 contrived）。
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
    /// 会话生命周期仓储（co-tx 创建 + durable find/revoke）。`clock` 为 envelope 时间源（构造器位置参）。
    #[must_use]
    pub fn session_lifecycle(&self, clock: Box<dyn Clock>) -> PgSessionLifecycle {
        PgSessionLifecycle::new_with_projection_registry(
            &self.store,
            clock,
            self.projection_registry,
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
            &self.store,
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
        PgCredentialRepo::new(&self.store)
    }

    /// 角色仓储（roles 表 + tenant scope）。
    #[must_use]
    pub fn role_repo(&self) -> PgRoleRepo {
        PgRoleRepo::new(&self.store)
    }

    /// durable ABAC policy store（abac_policies 表 + tenant scope）。
    #[must_use]
    pub fn policy_repo(&self) -> PgPolicyRepo {
        PgPolicyRepo::new(&self.store)
    }

    /// durable resource attribute store / resolver（resource_attributes 表 + tenant scope）。
    #[must_use]
    pub fn resource_attribute_repo(&self) -> PgResourceAttributeRepo {
        PgResourceAttributeRepo::new(&self.store)
    }

    /// durable ABAC policy lifecycle（policy mutation + policy-updated outbox co-tx）。
    #[must_use]
    pub fn policy_lifecycle(&self, clock: Box<dyn Clock>) -> PgPolicyLifecycle {
        PgPolicyLifecycle::new_with_projection_registry(
            &self.store,
            clock,
            self.projection_registry,
        )
    }

    /// 角色绑定生命周期（binding co-tx + role event outbox）。
    #[must_use]
    pub fn role_binding_lifecycle(&self, clock: Box<dyn Clock>) -> PgRoleBindingLifecycle {
        PgRoleBindingLifecycle::new_with_projection_registry(
            &self.store,
            clock,
            self.projection_registry,
        )
    }

    /// refresh token store（哈希存储 + CAS rotation + 谱系级联撤销 + RLS）。
    #[must_use]
    pub fn refresh_token_store(&self) -> PgRefreshTokenStore {
        PgRefreshTokenStore::new(&self.store)
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
        PgAuditRepo::new(&self.store, hasher)
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
        PgAuthAuditSink::new(&self.store)
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
        PgAuditConsumerTx::session_created(&self.store, hasher)
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
        PgAuditConsumerTx::role_assigned(&self.store, hasher)
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
        PgAuditConsumerTx::role_revoked(&self.store, hasher)
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
        PgAuditConsumerTx::policy_updated(&self.store, hasher)
    }
}

/// framework/global postgres 基建能力句柄（`Clone`，provider-agnostic、非单域）。
///
/// 私有持 `Arc<PgStore>`，经 [`PgRuntimeHandle::infra`] 派发；只暴露 emitter / dead_letter / checkpoint /
/// saga_journal / projection_events / cas_store / session_sweeper——这些是跨域基建（非绑某个 `caps::*` 域），
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
    store: Arc<PgStore>,
    projection_registry: ProjectionWriteRegistry,
    delivery_policy: EventDeliveryPolicy,
}

impl PgInfraDeps {
    /// outbox emitter（envelope `occurred_at` 时间源经 `clock` 注入，构造器位置参）。
    #[must_use]
    pub fn emitter(&self, clock: Box<dyn Clock>) -> PgEmitter {
        PgEmitter::new_with_projection_registry(&self.store, clock, self.projection_registry)
    }

    /// CDC-facing append-only outbox emitter.
    ///
    /// This explicit opt-in mode writes `outbox_log` and does not participate in the relay
    /// `outbox` status machine.
    #[must_use]
    pub fn cdc_emitter(&self, clock: Box<dyn Clock>) -> PgOutboxCdcEmitter {
        PgOutboxCdcEmitter::new_with_store(&self.store, clock)
    }

    /// outbox backlog/sweeper maintenance 能力（不持 publisher）。
    ///
    /// relay publishing 仍经 per-domain [`PgDomainDeps::outbox`] 构造；sampler/sweeper 只需要 DB pool，归
    /// framework/global infra 句柄，避免为 maintenance worker 注入可发布能力（#1429）。
    #[must_use]
    pub fn outbox_maintenance(&self) -> PgOutboxMaintenance {
        PgOutboxMaintenance::new(&self.store)
    }

    /// consumer inbox 幂等去重 store（runtime consumer resource bundle 使用）。
    ///
    /// `inbox_receipts` key 为 `(tenant_id, event_id, consumer_group)`，不是 identity 域资源；因此归
    /// framework/global infra 句柄，避免组合根为通用 consumer 借用某个业务域句柄。
    #[must_use]
    pub fn inbox(&self) -> PgInboxStore {
        self.store.inbox()
    }

    /// Tenant-scoped HOT dead-letter writer. Archive/purge is intentionally absent from this
    /// serving capability and lives in the independent [`crate::PgDlxLifecycleRuntime`].
    #[must_use]
    pub fn dead_letter(&self, payload_protector: DlxPayloadProtector) -> PgDeadLetterStore {
        self.store.dead_letter(payload_protector)
    }

    /// inbox_receipts 保留期清理 sweeper（**全域**，跨 consumer_group / 域，#1210）。
    ///
    /// impl `consistency::RetentionSweeper`——仅接受启动时从数据库冻结策略加载的保留期，删除超期 `done`
    /// 去重记录。全域语义 ⇒ 归 framework/global infra 句柄（非 per-domain `PgDomainDeps`）。
    #[must_use]
    pub fn inbox_sweeper(&self) -> PgInboxSweeper {
        self.store.inbox_sweeper(self.delivery_policy)
    }

    /// sessions 过期行维护清理器（全域，固定 `expires_at <= now()` 谓词，#1233）。
    ///
    /// 不返回 tenant/raw pool/SQL/retain 参数；runtime 只拿到具体 [`PgSessionSweeper`] 并调用
    /// `sweep_expired()`。
    #[must_use]
    pub fn session_sweeper(&self) -> PgSessionSweeper {
        self.store.session_sweeper()
    }

    /// owner checkpoint store（reconcile/saga 进度）。
    #[must_use]
    pub fn checkpoint(&self) -> PgCheckpointStore {
        self.store.checkpoint()
    }

    /// reconcile durable target/lease/attempt/action store（schema-level capability，#1629）。
    ///
    /// 本 accessor 只暴露最小 PG schema API，不启动 reconcile runtime worker，也不新增 engine/domain trait。
    #[must_use]
    pub fn reconcile(&self) -> PgReconcileStore {
        self.store.reconcile()
    }

    /// command journal foundation store（schema-level capability，#1441）。
    ///
    /// This accessor exposes only the reviewed command journal API; it does not start a command
    /// worker or expose raw transaction handles. Its outbox envelope `occurred_at` source is an
    /// injected producer clock, matching [`PgInfraDeps::emitter`].
    #[must_use]
    pub fn command_journal(&self, clock: Box<dyn Clock>) -> PgCommandJournal {
        self.store.command_journal(clock)
    }

    /// saga instance/lease store（L3 saga claim/fencing）。
    #[must_use]
    pub fn saga_instance_store(&self) -> PgSagaInstanceStore {
        self.store.saga_instance_store()
    }

    /// saga journal（L3 saga 状态）。
    #[must_use]
    pub fn saga_journal(&self) -> PgSagaJournal {
        self.store.saga_journal()
    }

    /// projection events 读路径（全局 projection journal）。
    #[must_use]
    pub fn projection_events(&self) -> PgProjectionEvents {
        self.store.projection_events()
    }

    /// distributed state CAS store（全局 per-key revision token）。
    #[must_use]
    pub fn cas_store(&self) -> Box<DynCasStore<'static>> {
        DynCasStore::new_box(self.store.cas_store())
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
            Arc::ptr_eq(&s.store, &d.handle.store),
            "for_domain clone 共享 store Arc"
        );
    }

    #[tokio::test]
    async fn domain_deps_clone_shares_store() {
        let s: PgDomainDeps<caps::Settings> = deps().handle().for_domain();
        let c = s.clone();
        assert!(
            Arc::ptr_eq(&s.store, &c.store),
            "clone 廉价共享 store Arc（非深拷贝）"
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
        assert!(Arc::ptr_eq(&first.store, &second.store));
        assert!(
            first
                .audit_admin_store
                .as_ref()
                .zip(second.audit_admin_store.as_ref())
                .is_some_and(|(first, second)| Arc::ptr_eq(first, second)),
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
    async fn runtime_parts_without_audit_have_only_primary_guard() {
        let (resources, _factory) = deps().into_runtime_parts(Duration::from_secs(1));
        let names: Vec<_> = resources.iter().map(|resource| resource.name()).collect();
        assert_eq!(names, ["postgres"]);
    }

    #[tokio::test]
    async fn runtime_parts_with_audit_preserve_registration_order_and_close_pools() {
        let primary = lazy_store();
        let audit_admin = lazy_store();
        let owner = PgRuntimeDeps::from_stores_for_test(
            Arc::clone(&primary),
            Some(Arc::clone(&audit_admin)),
        );
        let (resources, _factory) = owner.into_runtime_parts(Duration::from_secs(1));
        let names: Vec<_> = resources.iter().map(|resource| resource.name()).collect();
        assert_eq!(names, ["postgres", "postgres-audit-admin"]);

        for resource in resources.into_iter().rev() {
            let result = resource.shutdown().await;
            assert!(result.is_ok(), "lazy pool closes cleanly: {result:?}");
        }
        assert!(primary.pool.is_closed(), "primary pool must close");
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
        let _ = i.session_lifecycle(Box::new(EpochClock));
        let _ = i.outbox(
            DynPublisher::new_box(StubPublisher),
            relay_budget(),
            tenant_authority(),
            payload_protector(),
        );
        // F1 补齐的 identity 域 repo（credentials / roles / refresh tokens）——纯 pool clone，无 I/O。
        let _ = i.credential_repo();
        let _ = i.role_repo();
        let _ = i.policy_repo();
        let _ = i.resource_attribute_repo();
        let _ = i.refresh_token_store();
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
        let _ = infra.session_sweeper();
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
            store: Arc::clone(&primary),
            audit_admin_store: Some(Arc::clone(&audit_admin)),
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
            store: lazy_store(),
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
            authn::test_support::principal(vocab::PrincipalKind::Service, "test-operator", None);
        let grants = authn::ProjectionMaintenanceGrantSet::new(vec![
            authn::ProjectionMaintenanceGrant::new(
                "test-operator",
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
            Arc::ptr_eq(&infra.store, &c.store),
            "PgInfraDeps clone 廉价共享 store Arc"
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
