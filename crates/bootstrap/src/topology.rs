//! topology —— 部署拓扑单源词汇（topology-gated resolver 家族共享选型输入）。
//!
//! 本模块是 `replaydeps` / `eventtransport` / `sagaprojectiondeps` 等 topology-gated resolver
//! 的共享选型输入单源——三个 resolver 均以 [`Topology`] 作为第一参数决策基础设施层级。
//!
//! 各 resolver 语义：
//! - [`crate::replaydeps::resolve`]：topology-gated 幂等 claimer 选型（Redis 或 in-mem demo）。
//! - `eventtransport::resolve`（#1119）：topology-gated 事件传输选型（AMQP per-domain 或 in-mem）。
//! - `sagaprojectiondeps::resolve`（未来）：saga / projection 依赖选型。
//!
//! 把 [`Topology`] 抽到独立模块，避免每个 resolver 各自定义同义枚举（单一事实源，防漂移）。

/// 部署拓扑——topology-gated resolver 的单源选型输入。
///
/// durable 拆 **shared** / **isolated** 是不同安全策略：共享基础设施允许 per-domain 缺配置时
/// 回退公共凭据；per-domain 隔离则**禁回退**（每域独立实例/凭据，缺即 fail-closed）。
/// `#[non_exhaustive]`：未来加新拓扑（如 mqtt、multi-region）不破坏下游 `match`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Topology {
    /// 单进程 / 测试 / 样例：进程内 in-mem 实现（无外部依赖）。
    Demo,
    /// 生产（**共享 / 非隔离** 基础设施）：per-domain 缺配置时允许回退共享凭据。
    DurableShared,
    /// 生产（**per-domain 隔离** 基础设施）：每域独立实例/凭据；
    /// **禁回退**共享凭据，缺 per-domain 配置即 fail-closed。
    DurableIsolated,
}
