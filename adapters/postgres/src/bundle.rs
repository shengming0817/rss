//! postgres capability bundle（#1423 / PERSIST-002）：把 connect、migration、readiness handle、
//! per-domain repo 构造收口到单一 funnel，对组合根的 wire_X 暴露**受控 per-domain 能力句柄**，
//! 绝不泄漏裸 `sqlx::PgPool`。
//!
//! 四个类型：
//! - [`PgRuntimeDeps`]：组合根级集中 funnel。唯一公开构造路径 [`PgRuntimeDeps::setup`]（connect →
//!   run_migrations → 新建 readiness handle）；派发 [`PgRuntimeDeps::for_domain`] / [`PgRuntimeDeps::infra`]、
//!   产出 shutdown 资源（[`PgRuntimeDeps::store_guard`]）+ 采样 worker（[`PgRuntimeDeps::spawn_readiness_sampler`]）。
//! - [`PgDomainDeps<D>`]：per-domain 受控句柄（`Clone`，私有持 `Arc<PgStore>`），只暴露该域的 repo
//!   构造方法。类型参数 `D: PgDomain`（sealed marker）使「settings 的 deps 拿去建 identity repo」=
//!   编译错误 E0599（类型层不可表达）。
//! - [`PgInfraDeps`]：framework/global（provider-agnostic、非单域）基建能力句柄——emitter / dead_letter /
//!   checkpoint / saga / projection，不绑 `caps::*` 域。
//! - [`PgSettingsBundle`]：settings 域 durable 接线包，经 [`PgDomainDeps::settings_bundle`] 单次构造（同
//!   store + 单 clock 扇出），内部预包装 read config + write co-tx UoW + secret 域形 DynX port；组合根经
//!   [`PgSettingsBundle::into_parts`] 单次解包注入，不再散装构造 / 手工配对（PERSIST-003）。
//!
//! ## INVARIANT
//!
//! - **PG-BUNDLE-FUNNEL-01**（Hard，可见性封装）：`PgRuntimeDeps::setup` 是唯一公开 store 构造路径——
//!   `PgStore::connect` / `run_migrations` 已降 `pub(crate)`，外部无法 mint `PgStore`、也拿不到 `&PgStore`；
//!   且**所有** `&PgStore`-taking repo 构造器（含 credential/role/refresh_token/emitter + dead_letter/
//!   checkpoint/saga/projection）均 `pub(crate)`——repo 只能经 `PgDomainDeps` / `PgInfraDeps` 构造，无
//!   public-but-unreachable 残留（#1423 review F1）。
//! - **PG-BUNDLE-DOMAIN-02**（Hard，sealed marker + typed function choice）：per-domain 能力隔离。
//!   anti-vacuity = 下方 `PgDomainDeps` 的 `compile_fail` doctest（Settings 句柄调 `session_lifecycle` 必败）。
//! - **PG-BUNDLE-POOL-03**（Hard）：本模块无任何返回 `&PgStore` / `Arc<PgStore>` / `PgPool` 的公开 accessor；
//!   `store` 字段私有，仅 in-crate repo 构造方法 clone `pub(crate) pool`。
//! - **PG-BUNDLE-SETTINGS-04**（Hard，可见性 + sealed funnel + typed function choice）：settings 三件套
//!   （read config / write co-tx UoW / secret）只能经 [`PgDomainDeps::settings_bundle`] 单次构造（funnel，
//!   私有字段 + 唯一公开构造 ⇒ 外部 crate 无法 mint），经 [`PgSettingsBundle::into_parts`] 解包；一次
//!   `into_parts` 产出的三元同源（同一 store + 同一注入 clock，clock 经 `Arc` 扇出到两个 `PgConfigRepo`）。
//!   三件为互不可换的域形 dyn 类型（`DynConfigRepo`/`DynConfigUnitOfWork`/`DynSecretRepo`）⇒ 注入两 service
//!   时 read/write/secret **角色无法错插**（typed function choice）。散装 `config_repo()` / `secret_repo()`
//!   accessor 已删除（不留兼容路径）。**强制边界**：funnel 守上游构造 + 角色槽位；`into_parts` 后三件为
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
use std::time::Duration;

use diport::{Clock, DynCasStore, DynPublisher};
use settings::ports::{DynConfigRepo, DynConfigUnitOfWork, DynSecretRepo};
use tokio_util::sync::CancellationToken;

use crate::{
    PgAuditRepo, PgAuthAuditSink, PgCheckpointStore, PgConfig, PgConfigRepo, PgCredentialRepo,
    PgDbReadiness, PgDeadLetterStore, PgDlqStore, PgEmitter, PgError, PgInboxStore, PgInboxSweeper,
    PgOutbox, PgProjectionEvents, PgReadinessSampler, PgRefreshTokenStore, PgRoleRepo,
    PgSagaJournal, PgSecretRepo, PgSessionLifecycle, PgStore, PgStoreGuard,
};

/// per-domain 能力 marker 的 sealed 封闭——外部 crate 无法新增域 marker（无法 impl `Sealed`）。
mod sealed {
    pub trait Sealed {}
}

/// postgres capability bundle 的 per-domain marker（sealed）。
///
/// 实现集封闭在本 crate（[`caps`] 下的 ZST）；外部 crate 既不能命名内层 `Sealed`、也不能新增 marker，
/// 故 `PgDomainDeps<D>` 的 `D` 只能是本 crate 声明的域（PG-BUNDLE-DOMAIN-02）。
pub trait PgDomain: sealed::Sealed {}

/// per-domain 能力 marker ZST。
///
/// `caps` 命名避开 `rss_domain_no_serialize` 的 `domain` 模块启发式，且 `caps::Settings`/`caps::Identity`
/// 不与同名域 crate 冲突。变体随各域 durable 接线切片增加（当前 Settings + Identity + Audit）。
pub mod caps {
    /// settings 域能力 marker。
    pub struct Settings;
    /// identity 域能力 marker。
    pub struct Identity;
    /// audit 域能力 marker。
    pub struct Audit;
}

impl sealed::Sealed for caps::Settings {}
impl PgDomain for caps::Settings {}
impl sealed::Sealed for caps::Identity {}
impl PgDomain for caps::Identity {}
impl sealed::Sealed for caps::Audit {}
impl PgDomain for caps::Audit {}

/// 组合根级 postgres 能力包：集中 connect + migration + readiness handle，派发 per-domain 受控句柄，
/// 并产出 shutdown 资源 / 采样 worker。
///
/// 字段私有（`store` / `readiness`）；不暴露 `&PgStore` / `PgPool`（PG-BUNDLE-POOL-03）。经
/// [`PgRuntimeDeps::setup`] 构造（PG-BUNDLE-FUNNEL-01）。
#[derive(Clone)]
pub struct PgRuntimeDeps {
    store: Arc<PgStore>,
    readiness: Arc<PgDbReadiness>,
    /// 启动期 RLS 能力门结果（true = `verify_rls_capability` 通过）；供 readyz 兜底探针读。setup 失败时进程
    /// 根本不返回 `Self`（fail-fast），故 `Self` 存在即此值为 true——探针把该不变式显式暴露到 readyz。
    rls_ready: Arc<AtomicBool>,
}

impl PgRuntimeDeps {
    /// 唯一公开构造路径：连接 + 跑迁移 + RLS 能力门 + 新建 readiness handle（初值 `Down`，fail-closed）。
    ///
    /// 缺配 / 连不上 / 迁移失败 / **RLS 能力缺失**均 fail-fast 返 [`PgError`]（区分 `Connect` / `Migrate` /
    /// `Rls*` 阶段）；组合根在边界 `.context(..)` 成 anyhow。对标 omicron `DataStore::new_with_timeout`
    /// （构造器集中 + schema/能力门控，对象返回前校验）。
    pub async fn setup(config: &PgConfig) -> Result<Self, PgError> {
        let store = Arc::new(PgStore::connect(config).await?);
        store.run_migrations().await?;
        // durable RLS 能力门（fail-fast）：tenant 表须 FORCE RLS + policy 且 GUC roundtrip 通过，否则拒绝启动。
        store.verify_rls_capability().await?;
        Ok(Self {
            store,
            readiness: Arc::new(PgDbReadiness::new()),
            rls_ready: Arc::new(AtomicBool::new(true)),
        })
    }

    /// 派发 per-domain 受控句柄（`Arc<PgStore>` clone + `PhantomData<D>`）。
    ///
    /// 对标 kube-rs `Controller::run(.., Arc<Ctx>)` 注入 shared context。
    #[must_use]
    pub fn for_domain<D: PgDomain>(&self) -> PgDomainDeps<D> {
        PgDomainDeps {
            store: Arc::clone(&self.store),
            _marker: PhantomData,
        }
    }

    /// 派发 framework/global（provider-agnostic、非单域）基建能力句柄 [`PgInfraDeps`]——
    /// emitter / dead_letter / checkpoint / saga / projection 不绑单一域，故不进 `PgDomainDeps<D>`。
    #[must_use]
    pub fn infra(&self) -> PgInfraDeps {
        PgInfraDeps {
            store: Arc::clone(&self.store),
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

    /// 包装私有 `Arc<PgStore>` 为可注册进 `ShutdownStack` 的 guard——**不**泄漏 `Arc<PgStore>` 本身。
    ///
    /// LIFO 注册：guard 先注册 ⇒ 最后关池（listener drain → sampler 停 → pool close）。
    #[must_use]
    pub fn store_guard(&self) -> PgStoreGuard {
        PgStoreGuard::new(Arc::clone(&self.store))
    }

    /// spawn DB readiness 采样 worker 并 adopt 为 `ManagedResource`（收口 spawn + adopt 仪式，
    /// 私有持有 `Arc<PgStore>` 不外泄）。`token` 由 `ShutdownStack` 注入；采样 loop 写 readiness handle。
    #[must_use]
    pub fn spawn_readiness_sampler(
        &self,
        period: Duration,
        token: CancellationToken,
    ) -> PgReadinessSampler {
        let handle = tokio::spawn(crate::readiness::pg_readiness_sampling_loop(
            Arc::clone(&self.store),
            period,
            token.clone(),
            Arc::clone(&self.readiness),
        ));
        PgReadinessSampler::adopt(handle, Arc::clone(&self.readiness), token)
    }

    /// 测试构造：从已建 `Arc<PgStore>`（lazy pool）旁路 `setup`（免真连 DB）。
    /// reason: 旁路 `verify_rls_capability`，测试假定能力已就绪（`rls_ready = true`）。
    #[cfg(test)]
    pub(crate) fn from_store_for_test(store: Arc<PgStore>) -> Self {
        Self {
            store,
            readiness: Arc::new(PgDbReadiness::new()),
            rls_ready: Arc::new(AtomicBool::new(true)),
        }
    }
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
/// fn settings_ok(d: PgDomainDeps<caps::Settings>, clock: std::sync::Arc<dyn diport::Clock>) {
///     // Arc：单一 clock 经 settings_bundle 扇出到 read/write 两个 config 实例（见 settings_bundle）。
///     let _ = d.settings_bundle(clock);
/// }
/// fn identity_ok(d: PgDomainDeps<caps::Identity>, clock: Box<dyn diport::Clock>) {
///     let _ = d.session_lifecycle(clock);
/// }
/// ```
pub struct PgDomainDeps<D: PgDomain> {
    store: Arc<PgStore>,
    _marker: PhantomData<D>,
}

// 手写 `Clone`：避免 `#[derive(Clone)]` 引入多余的 `D: Clone` bound（marker 是 ZST，与 Clone 无关）。
impl<D: PgDomain> Clone for PgDomainDeps<D> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            _marker: PhantomData,
        }
    }
}

impl PgDomainDeps<caps::Settings> {
    /// settings 域 durable 接线包：单一 `(store, clock)` → read config 仓储（`DynConfigRepo`）+ write co-tx
    /// UoW（`DynConfigUnitOfWork`）+ secret 坐标仓储（`DynSecretRepo`），内部完成域形 DynX 包裹。取代已删除的
    /// 散装 `config_repo()` / `secret_repo()`（PERSIST-003，不留兼容路径，PG-BUNDLE-SETTINGS-04）。
    ///
    /// `clock`（`Arc<dyn Clock>`，构造器位置参，必填、非 `Option`、不默认系统钟）：单一注入 clock 经
    /// `Arc::clone` 扇出到 read/write 两个 [`PgConfigRepo`] 实例（envelope `occurred_at` 源；write lane 经
    /// `save_and_append_outbox` 用，read lane 不触）。read/write 各持一个实例——`Box<DynConfigRepo>` 与
    /// `Box<DynConfigUnitOfWork>` 是不同 dyn 类型、各自 own 其值，一个 Box 无法同时充当两者。
    ///
    /// 返回类型 [`PgSettingsBundle`] 自身 `#[must_use]`（drop 而不 `into_parts` 即 lint），故此处无方法级
    /// `#[must_use]`（避免 `clippy::double_must_use`）。
    pub fn settings_bundle(&self, clock: Arc<dyn Clock>) -> PgSettingsBundle {
        PgSettingsBundle {
            config_repo: DynConfigRepo::new_box(PgConfigRepo::new(&self.store, Arc::clone(&clock))),
            config_uow: DynConfigUnitOfWork::new_box(PgConfigRepo::new(&self.store, clock)),
            secret_repo: DynSecretRepo::new_box(PgSecretRepo::new(&self.store)),
        }
    }

    /// outbox relay（L2 本地事务 + 发布；`settings.config-version-changed`）。`publisher` 必填（构造器位置参）。
    /// `PgOutbox` 经 `RelayConfig` 的 domain 过滤 outbox 表行，故构造仅需 store + publisher（与 identity 同形，
    /// #1251 F2：N-域 relay——每个 L2 OutboxFact 发布域各一个 relay，否则该域 outbox 在 durable runtime 静默积压）。
    #[must_use]
    pub fn outbox(&self, publisher: Box<DynPublisher<'static>>) -> PgOutbox {
        PgOutbox::new(&self.store, publisher)
    }
}

/// settings 域 durable 接线包（PERSIST-003 / #1424）：read config 仓储 + write co-tx UoW + secret 坐标仓储，
/// 全部源自同一 `(store, clock)`、预包装为 settings 域 dyn DI port。
///
/// 字段私有 + 唯一构造经 [`PgDomainDeps::settings_bundle`] + 唯一解包经 [`PgSettingsBundle::into_parts`]
/// （PG-BUNDLE-SETTINGS-04，Hard）。**实际强制**（仅声明类型层真成立的）：
/// - 外部 crate 无法 mint（私有字段 + 唯一公开构造 funnel）；
/// - 一次 `into_parts` 产出的三元同源（同一 store + 同一注入 clock）；
/// - 三件为互不可换的域形 dyn 类型 ⇒ 注入两 service 时 read/write/secret 角色无法错插（typed function choice）。
///
/// **不声称**：`into_parts` 后三件为 owned 值，类型层不阻止把不同 bundle 实例的 box 跨实例重组（funnel 守
/// 上游构造 + 角色槽位，不守下游跨 bundle 重组；单一 `PgRuntimeDeps` ⇒ 同 store，跨 bundle 重组为 contrived）。
/// 对标 GoCell `accesspg.Bundle` / `WithPGBundle`（单次解包注入聚合）。
///
/// anti-vacuity（私有字段须经 `into_parts` 唯一出口，不可旁路直读单字段）：
///
/// ```compile_fail
/// use postgres::{PgDomainDeps, caps};
/// fn bad(d: PgDomainDeps<caps::Settings>, clock: std::sync::Arc<dyn diport::Clock>) {
///     let b = d.settings_bundle(clock);
///     // E0616：字段 `config_repo` 私有——须经 `into_parts` 唯一出口取三元，不可旁路直读单字段（PG-BUNDLE-SETTINGS-04）。
///     let _ = b.config_repo;
/// }
/// ```
#[must_use]
pub struct PgSettingsBundle {
    config_repo: Box<DynConfigRepo<'static>>,
    config_uow: Box<DynConfigUnitOfWork<'static>>,
    secret_repo: Box<DynSecretRepo<'static>>,
}

impl PgSettingsBundle {
    /// 受控解包：移出三件已包裹域形 DI box——`(read config, write co-tx UoW, secret)`，typed 位置逐参注入
    /// 两个 service 构造器。三者类型互不可换（`DynConfigRepo` / `DynConfigUnitOfWork` / `DynSecretRepo`）⇒
    /// 重排即编译错误。本 bundle 唯一对外读取路径（字段私有）。对标 GoCell `WithPGBundle(b)` 单次解包注入。
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Box<DynConfigRepo<'static>>,
        Box<DynConfigUnitOfWork<'static>>,
        Box<DynSecretRepo<'static>>,
    ) {
        (self.config_repo, self.config_uow, self.secret_repo)
    }
}

impl PgDomainDeps<caps::Identity> {
    /// 幂等 inbox（consumer 去重）。`group` 标识消费组。
    #[must_use]
    pub fn inbox(&self, group: consistency::ConsumerGroup) -> PgInboxStore {
        self.store.inbox(group)
    }

    /// 会话生命周期仓储（co-tx 创建 + durable find/revoke）。`clock` 为 envelope 时间源（构造器位置参）。
    #[must_use]
    pub fn session_lifecycle(&self, clock: Box<dyn Clock>) -> PgSessionLifecycle {
        PgSessionLifecycle::new(&self.store, clock)
    }

    /// outbox relay（L2 本地事务 + 发布）。`publisher` 必填（构造器位置参）。
    #[must_use]
    pub fn outbox(&self, publisher: Box<DynPublisher<'static>>) -> PgOutbox {
        PgOutbox::new(&self.store, publisher)
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

    /// refresh token store（哈希存储 + CAS rotation + 谱系级联撤销 + RLS）。
    #[must_use]
    pub fn refresh_token_store(&self) -> PgRefreshTokenStore {
        PgRefreshTokenStore::new(&self.store)
    }
}

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

    /// Flat durable auth decision audit sink (`diport::AuditSink`) for httpserve enforcement.
    ///
    /// This deliberately stays outside the hash-chain [`audit::ports::AuditRepo`] actor model because auth principals
    /// are generic subjects, not only `ids::UserId`.
    #[must_use]
    pub fn auth_audit_sink(&self) -> PgAuthAuditSink {
        PgAuthAuditSink::new(&self.store)
    }
}

/// framework/global postgres 基建能力句柄（`Clone`，provider-agnostic、非单域）。
///
/// 私有持 `Arc<PgStore>`，经 [`PgRuntimeDeps::infra`] 派发；只暴露 emitter / dead_letter / checkpoint /
/// saga_journal / projection_events / cas_store——这些是跨域基建（非绑某个 `caps::*` 域），故独立于 [`PgDomainDeps`]。
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
///     let _ = i.dead_letter();
///     let _ = i.projection_events();
/// }
/// ```
#[derive(Clone)]
pub struct PgInfraDeps {
    store: Arc<PgStore>,
}

impl PgInfraDeps {
    /// outbox emitter（envelope `occurred_at` 时间源经 `clock` 注入，构造器位置参）。
    #[must_use]
    pub fn emitter(&self, clock: Box<dyn Clock>) -> PgEmitter {
        PgEmitter::new(&self.store, clock)
    }

    /// dead-letter store（DLX 终态）。同时 impl `consistency::RetentionSweeper`——组合根可经此句柄取死信
    /// 保留期 sweeper（`DEAD_LETTER_RETENTION_SECONDS` 默认 30 天，#1210）。
    #[must_use]
    pub fn dead_letter(&self) -> PgDeadLetterStore {
        self.store.dead_letter()
    }

    /// DLQ inspection/replay API（internal Rust surface，#1214）。`dead_letter` replay 与 `outbox` redrive
    /// 由类型分开，避免把 consumer 重放误当 broker redrive。
    #[must_use]
    pub fn dlq(&self) -> PgDlqStore {
        self.store.dlq()
    }

    /// inbox_dedup 保留期清理 sweeper（**全域**，跨 consumer_group / 域，#1210）。
    ///
    /// impl `consistency::RetentionSweeper`——删除超 `INBOX_DEDUP_RETENTION_SECONDS`（默认 7 天）的 `done`
    /// 去重记录。全域语义 ⇒ 归 framework/global infra 句柄（非 per-domain `PgDomainDeps`）。
    #[must_use]
    pub fn inbox_sweeper(&self) -> PgInboxSweeper {
        self.store.inbox_sweeper()
    }

    /// owner checkpoint store（reconcile/saga 进度）。
    #[must_use]
    pub fn checkpoint(&self) -> PgCheckpointStore {
        self.store.checkpoint()
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

#[cfg(test)]
mod tests {
    //! bundle 单元测：lazy pool 旁路 `setup`（免真连 DB），覆盖 funnel 派发 + per-domain accessor 构造。
    //! INVARIANT: PG-BUNDLE-FUNNEL-01 / PG-BUNDLE-DOMAIN-02 / PG-BUNDLE-POOL-03（compile_fail doctest 见
    //! `PgDomainDeps` rustdoc）。

    use super::*;
    use std::time::SystemTime;

    use diport::{PublishRequest, Publisher, PublisherError};
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
        PgRuntimeDeps::from_store_for_test(lazy_store())
    }

    // 这些测试经 lazy pool（`connect_lazy_with`）构造 store——sqlx 池需 Tokio context，故 `#[tokio::test]`
    // （body 不 await；与既有 `smoke::pg_store_guard_shutdown_lazy_pool_ok` 同范式）。

    #[tokio::test]
    async fn for_domain_shares_store_arc() {
        let d = deps();
        let s: PgDomainDeps<caps::Settings> = d.for_domain();
        // PG-BUNDLE-POOL-03：句柄内部 store 与 runtime deps 同一 Arc（in-crate 可读私有字段验证）。
        assert!(
            Arc::ptr_eq(&s.store, &d.store),
            "for_domain clone 共享 store Arc"
        );
    }

    #[tokio::test]
    async fn domain_deps_clone_shares_store() {
        let s: PgDomainDeps<caps::Settings> = deps().for_domain();
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
            Arc::ptr_eq(&d.readiness_handle(), &d.readiness),
            "readiness_handle 返回内部同一 Arc"
        );
    }

    #[tokio::test]
    async fn rls_ready_handle_returns_same_arc() {
        let d = deps();
        assert!(
            Arc::ptr_eq(&d.rls_ready_handle(), &d.rls_ready),
            "rls_ready_handle 返回内部同一 Arc"
        );
    }

    #[tokio::test]
    async fn store_guard_name_is_postgres() {
        use diport::ManagedResource as _;
        assert_eq!(deps().store_guard().name(), "postgres");
    }

    #[tokio::test]
    async fn settings_bundle_constructs_all_parts() {
        let s: PgDomainDeps<caps::Settings> = deps().for_domain();
        // 单 clock 经 Arc 扇出到 read/write 两个 config 实例；into_parts 解包三件套（纯 pool clone，无 I/O）。
        let (_configs, _writer, _secrets) = s
            .settings_bundle(Arc::new(EpochClock) as Arc<dyn Clock>)
            .into_parts();
    }

    #[tokio::test]
    async fn settings_bundle_fans_out_single_clock() {
        let s: PgDomainDeps<caps::Settings> = deps().for_domain();
        let clock: Arc<dyn Clock> = Arc::new(EpochClock);
        let before = Arc::strong_count(&clock); // 1（仅本地持有）
        let _bundle = s.settings_bundle(Arc::clone(&clock));
        // 单一注入 clock 经 Arc 扇出到 read/write 两个 PgConfigRepo（各持一 clone）⇒ 至少 +2。
        // 回归到「每 lane 各 mint 一个 clock」则只 +1 → 失败（PG-BUNDLE-SETTINGS-04 anti-vacuity）。
        assert!(
            Arc::strong_count(&clock) >= before + 2,
            "single injected clock must fan out to BOTH config repos"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: ConsumerGroup::parse const literal 仅字符非法时失败（item-level carve-out）。
    async fn identity_accessors_construct() {
        let i: PgDomainDeps<caps::Identity> = deps().for_domain();
        let group = consistency::ConsumerGroup::parse("identity.projector").expect("valid group");
        let _ = i.inbox(group);
        let _ = i.session_lifecycle(Box::new(EpochClock));
        let _ = i.outbox(DynPublisher::new_box(StubPublisher));
        // F1 补齐的 identity 域 repo（credentials / roles / refresh tokens）——纯 pool clone，无 I/O。
        let _ = i.credential_repo();
        let _ = i.role_repo();
        let _ = i.refresh_token_store();
    }

    #[tokio::test]
    async fn infra_accessors_construct() {
        // PgInfraDeps：framework/global 基建能力（F1 补齐）——纯 pool clone，无 I/O。
        let infra = deps().infra();
        let _ = infra.emitter(Box::new(EpochClock));
        let _ = infra.dead_letter();
        let _ = infra.inbox_sweeper();
        let _ = infra.checkpoint();
        let _ = infra.saga_journal();
        let _ = infra.projection_events();
        let _ = infra.cas_store();
    }

    #[tokio::test]
    async fn audit_accessors_construct() {
        let a: PgDomainDeps<caps::Audit> = deps().for_domain();
        let _ = a.auth_audit_sink();
    }

    #[tokio::test]
    async fn infra_clone_shares_store() {
        let infra = deps().infra();
        let c = infra.clone();
        assert!(
            Arc::ptr_eq(&infra.store, &c.store),
            "PgInfraDeps clone 廉价共享 store Arc"
        );
    }

    /// `spawn_readiness_sampler` 立即 cancel → `shutdown` 两阶段收敛 Ok（覆盖 spawn/adopt 接线）。
    #[tokio::test]
    async fn spawn_readiness_sampler_clean_shutdown() {
        use diport::ManagedResource as _;
        let d = deps();
        let token = CancellationToken::new();
        let sampler = d.spawn_readiness_sampler(Duration::from_millis(50), token.clone());
        token.cancel();
        assert!(
            sampler.shutdown().await.is_ok(),
            "cancel 后 sampler 干净收敛"
        );
    }
}
