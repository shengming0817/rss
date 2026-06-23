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
//!   [`Registry::finalize_routes`] 按 listener 分组折叠路由组 register 闭包。HTTP mount + auth
//!   finalize（httpserve）、subscriber dispatch（eventexec）、socket bind / 信号 / config 归组合根（Join #1017）。
//!   对标：kube-rs controller lifecycle、uber-go/fx Lifecycle.Append、omicron nexus 分 listener 隔离。
//!
//! - [`eventtransport`]：topology-gated 事件传输选型（单源策略）——[`resolve`] 按 [`Topology`]
//!   选 demo（in-mem bus）/ durable（per-domain amqp），durable 缺 broker fail-closed。纯策略函数、
//!   零 adapter 依赖；adapter 构造 + in-mem sealing 落组合根（见模块 rustdoc，INVARIANT
//!   TOPO-FAILCLOSED-01 / TOPO-INMEM-SEAL-01）。
//!
//! [`Domain::init`]: domain::Domain::init
//! [`Registry::readyz_report`]: registry::Registry::readyz_report
//! [`Registry::finalize_routes`]: registry::Registry::finalize_routes

pub mod domain;
pub mod eventtransport;
pub mod module;
pub mod registry;
pub mod shutdown;

pub use domain::{Domain, KernelError, compose};
pub use eventtransport::{
    AmqpUrl, ResolvedTransport, Topology, TransportConfig, TransportResolveError, resolve,
};
pub use module::{DomainModule, ModuleFactory};
pub use registry::{HealthProbe, Registry, SubscriberHandler, SubscriberHandlerError};
