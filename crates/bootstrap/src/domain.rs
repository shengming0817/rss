//! 域 crate 生命周期 trait。
//!
//! 设计对标：kube-rs `Controller` 生命周期（`kube-runtime/src/controller/mod.rs`）+
//! uber-go/fx `Lifecycle.Append` push 式注册 + omicron nexus `close(self)` 单次关闭。
//!
//! `Domain` trait 是 bootstrap 驱动所有域 crate 初始化的统一入口：
//! - `init` 纯同步声明，不做 I/O、不 spawn tokio task。
//! - 注册失败返回 `Err`，不得 `panic!` / `unwrap`。
//! - 组合根收集所有 [`DomainBinding`] → 交 [`compose_bindings`] 借用 domain 逐个调 `init` → 成功后消费 output。
//!
//! [`DomainBinding`]: crate::module::DomainBinding
//! [`compose_bindings`]: crate::module::compose_bindings

use crate::registry::Registry;

/// 域 crate 生命周期 trait。
///
/// 实现方（域 crate）在 `init` 中通过 [`Registry`] 声明路由组、事件订阅和健康探针。
///
/// # 约束
///
/// - `init` 必须是幂等纯声明：只调 `reg.route_group` / `reg.subscriber` / `reg.probe`。
/// - 不在 `init` 中做外部 I/O（数据库、网络、文件系统）。
/// - 不在 `init` 中 `tokio::spawn`。
/// - 必填服务依赖走构造器必填参数（缺失即编译错误），不在 `init` 中 fail-fast。
///
/// # 失败语义
///
/// 注册声明失败（如 prefix 冲突）返回 `Err(KernelError)`；bootstrap 在收到
/// 任何 `Err` 时 fail-fast，拒绝启动。
pub trait Domain: Send + Sync + 'static {
    /// 声明本域 crate 的路由组、事件订阅和健康探针。
    ///
    /// 失败返回 `Err`——bootstrap 将 fail-fast，拒绝启动。
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError>;
}

/// 驱动一组域 crate 的 `init`，聚合声明到单一 [`Registry`]（组合根 composition 入口）。
///
/// 对标 uber-go/fx `New`（构造期执行各 module 的 provide/invoke 聚合）。任一域 `init` 返回 `Err`
/// 即 fail-fast 冒泡——拒绝部分组装。纯声明聚合：不做 I/O、不 spawn（[`Domain::init`] 约束）。
/// ref: uber-go/fx app.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（New 聚合 module）
pub fn compose(domains: &[&dyn Domain]) -> Result<Registry, KernelError> {
    let mut reg = Registry::new();
    for domain in domains {
        domain.init(&mut reg)?;
    }
    Ok(reg)
}

/// 组合根 / init 失败语义。
///
/// 本 crate 局部错误类型（对标 kube-rs 把 `Error` 放 `kube-runtime` 而非 `kube-core`）。
/// 域 crate `init` 实现中通过 [`Registry`] 方法传播此错误，bootstrap 聚合后 fail-fast。
///
/// `#[non_exhaustive]`：允许将来在不破坏下游 match 的前提下添加变体。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KernelError {
    /// 健康探针注册失败（如探针名重复等）。
    #[error("probe registration failed")]
    Probe,
    /// 必填依赖缺失（仅用于运行时可选依赖注入失败；优先用构造器必填参数在编译期强制）。
    #[error("required dependency missing")]
    MissingDependency,
    /// bootstrap 不变式被违反（如重复 init、声明冲突等）。
    #[error("bootstrap invariant violated")]
    Invariant,
}
