//! bootstrap — RSS 进程组合根（composition / config / shutdown / worker）。
//!
//! 当前提供：
//!
//! - [`shutdown`]：关闭逆序编排范式（无 async Drop）——进程关闭时由 bootstrap
//!   显式按注册逆序（LIFO）await 每个 `diport::ManagedResource` 关干净，替代 Rust
//!   缺失的 async `Drop`（port trait 归 `diport`，编排归本 crate）。设计决策与不变式见
//!   `docs/architecture/202606212024-001-shutdown-reverse-order-orchestration.md`。
//!
//! - [`domain`] / [`registry`] / [`module`]：域 crate 生命周期 trait + init 阶段声明
//!   收集器 + 域装配单元。`compose` 聚合各域 [`Domain::init`] 声明到单一 [`Registry`]；W 阶段
//!   finalize driver 已落地——[`Registry::readyz_report`] 驱动探针 worst-of 聚合，
//!   [`Registry::admit_writes`] 消费 process gate 后由 [`WriteAdmittedRegistry::finalize_routes`]
//!   按 listener 分组折叠路由组 register 闭包。HTTP mount + auth
//!   finalize（httpserve）、subscriber dispatch（eventexec）、socket bind / 信号 / config 归组合根（assemblies/runtime launch）。
//!   对标：kube-rs controller lifecycle、uber-go/fx Lifecycle.Append、omicron nexus 分 listener 隔离。
//!
//! - [`eventtransport`]：topology-gated 事件传输选型（单源策略）——[`resolve`] 按 [`Topology`]
//!   选 demo（in-mem bus）/ durable（per-domain amqp），durable 缺 broker fail-closed。纯策略函数、
//!   零 adapter 依赖；adapter 构造 + in-mem sealing 落组合根（见模块 rustdoc，INVARIANT
//!   TOPO-FAILCLOSED-01 / TOPO-INMEM-SEAL-01）。
//!
//! - [`domaintransport`]：topology-gated 同步 domain transport 选型——复用 [`Topology`]，但使用独立
//!   typed config / [`secure::DomainHttpEndpoint`]，防事件传输配置和同步 RPC endpoint 混用。
//!
//! - [`replaydeps`]：topology-gated 幂等 claimer 选型——demo 拓扑用 in-mem claimer，
//!   durable 拓扑用 Redis claimer；[`replaydeps::resolve`] 是纯策略函数，不构造 adapter。
//!
//! - [`refreshstoredeps`]：topology-gated refresh token store 选型——demo 拓扑用 in-mem 替身，
//!   durable 拓扑用 postgres；[`refreshstoredeps::resolve`] 是纯策略函数，不构造 adapter。
//!   resolver 仍无组合根消费方；login/refresh 现经 AuthGrant 路径，不经本 resolver。
//!
//! - [`topology`]：部署拓扑词汇单源（[`Topology`] 枚举），被 replaydeps / eventtransport /
//!   sagaprojectiondeps / refreshstoredeps 等 resolver 共用。
//!
//! [`Domain::init`]: domain::Domain::init
//! [`Registry::readyz_report`]: registry::Registry::readyz_report
//! [`WriteAdmittedRegistry::finalize_routes`]: registry::WriteAdmittedRegistry::finalize_routes

pub mod domain;
pub mod domaintransport;
pub mod eventtransport;
pub mod framework;
pub mod module;
pub mod refreshstoredeps;
pub mod registry;
pub mod replaydeps;
pub mod sagaprojectiondeps;
pub mod shutdown;
pub mod topology;

pub use domain::{Domain, KernelError, compose};
pub use domaintransport::{
    DomainTransportConfig, DomainTransportResolveError, ResolvedDomainTransport,
};
pub use eventtransport::{AmqpUrl, ResolvedTransport, TransportConfig, TransportResolveError};
pub use framework::{
    FrameworkHttpRoute, FrameworkRoutes, FrameworkServingError, validate_framework_serving,
};
pub use module::{
    DomainBinding, DomainLifecycleOutput, DomainModuleResult, ExpectedWorkerInventory,
    WorkerAdmissionLane, WorkerDescriptor, WorkerInventory, WorkerInventoryError,
    WorkerRegistration, WorkerSpec, compose_bindings, drain_binding_outputs,
    validate_worker_inventory, validate_worker_inventory_exact,
};
pub use primitives::ListenerKind;
pub use refreshstoredeps::{RefreshStoreConfig, RefreshStoreResolveError, ResolvedRefreshStore};
pub use registry::DomainListenerBinding;
pub use registry::{
    HealthProbe, HealthReporter, ReconcileSubscriberOwner, Registry, SubscriberBinding,
    SubscriberCapability, WriteAdmittedRegistry,
};
pub use replaydeps::{IdempotencyConfig, IdempotencyResolveError, RedisUrl, ResolvedIdempotency};
pub use sagaprojectiondeps::{
    PostgresUrl, ResolvedSagaProjection, SagaProjectionConfig, SagaProjectionResolveError,
};
pub use topology::Topology;
