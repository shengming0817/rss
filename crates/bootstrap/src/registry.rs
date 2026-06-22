//! init 阶段声明收集器（纯声明，无 I/O）。
//!
//! 对标 uber-go/fx `Lifecycle.Append`：push 式注册，闭包延迟到 `finalize`
//! 统一执行（组合根驱动，不在 init 中执行）。
//!
//! [`Registry`] 由 bootstrap 在调用每个 [`Domain::init`] 前构造并传入；
//! `init` 返回后，bootstrap 把收集到的声明交给 httpserve / eventexec 等服务层驱动。
//!
//! [`Domain::init`]: crate::domain::Domain::init

use crate::domain::KernelError;
use primitives::ListenerKind;

/// 路由组注册的延迟闭包类型。
///
/// 接受 axum `Router`，追加本组 routes 后返回更新后的 `Router`；
/// 失败时返回 `Err(KernelError)` 冒泡到 bootstrap。
type RouteRegisterFn =
    Box<dyn FnOnce(axum::Router) -> Result<axum::Router, KernelError> + Send + 'static>;

/// 路由组声明（由 [`Registry::route_group`] 收集）。
// reason: 签名冻结阶段（ADR-004 C8）——字段在 todo!() 体实现前不被读取，待 W 阶段 finalize 驱动时使用。
#[allow(dead_code)]
pub(crate) struct RouteGroupDecl {
    pub(crate) listener: ListenerKind,
    pub(crate) prefix: &'static str,
    pub(crate) register: RouteRegisterFn,
}

/// 事件订阅声明（由 [`Registry::subscriber`] 收集）。
// reason: 签名冻结阶段（ADR-004 C8）——字段在 todo!() 体实现前不被读取，待 W 阶段 finalize 驱动时使用。
#[allow(dead_code)]
pub(crate) struct SubscriberDecl {
    pub(crate) topic: &'static str,
    pub(crate) handler: Box<dyn SubscriberHandler>,
}

/// 健康探针声明（由 [`Registry::probe`] 收集）。
// reason: 签名冻结阶段（ADR-004 C8）——字段在 todo!() 体实现前不被读取，待 W 阶段 finalize 驱动时使用。
#[allow(dead_code)]
pub(crate) struct ProbeDecl {
    pub(crate) name: primitives::ProbeName,
    pub(crate) probe: Box<dyn HealthProbe>,
}

/// bootstrap-local subscriber handler 擦除接缝。
///
/// 不引 `eventexec`（兄弟服务 crate 禁依赖）；真实 handler 类型在 W 阶段（wire-up）接线。
pub trait SubscriberHandler: Send + Sync {}

/// bootstrap-local 健康探针擦除接缝。
///
/// 实现者在 `check` 中执行探针逻辑并返回单条 [`primitives::HealthCheck`]（纯值，含探针名 +
/// 严重度 + const detail）。由 bootstrap readyz 聚合为 [`primitives::HealthReport`]。
///
/// # dyn-compatible
///
/// `check` 为同步方法（无 `async`、无 `Self` 位置参），满足 object-safety；可装箱为
/// `Box<dyn HealthProbe>`，由 [`Registry::probe`] 收集。
pub trait HealthProbe: Send + Sync {
    /// 执行探针并返回单条健康报告。
    fn check(&self) -> primitives::HealthCheck;
}

/// init 阶段声明收集器（纯声明，无 I/O）。
///
/// 由 bootstrap 在调用 [`Domain::init`] 前构造并以 `&mut Registry` 传入。
/// `init` 结束后，bootstrap 取出所有声明，交给服务层统一驱动。
///
/// register 闭包延迟到 `finalize` 统一执行（对标 fx `Lifecycle.Append`），
/// 不在 `init` 中立即生效。
///
/// [`Domain::init`]: crate::domain::Domain::init
pub struct Registry {
    // reason: 签名冻结阶段（ADR-004 C8）——字段在 todo!() 体实现前不被读取。
    #[allow(dead_code)]
    route_groups: Vec<RouteGroupDecl>,
    #[allow(dead_code)]
    subscribers: Vec<SubscriberDecl>,
    #[allow(dead_code)]
    probes: Vec<ProbeDecl>,
}

impl Registry {
    /// 由 bootstrap 构造空收集器。
    pub fn new() -> Self {
        todo!()
    }

    /// 声明路由组。
    ///
    /// `register` 是同步闭包：接受 axum `Router`，追加本组 routes 后返回；
    /// 失败时返回 `Err` 冒泡为 [`KernelError`]。
    ///
    /// 闭包延迟到 finalize 阶段由 bootstrap 统一执行，不在 `init` 中立即调用。
    pub fn route_group(
        &mut self,
        _listener: ListenerKind,
        _prefix: &'static str,
        _register: impl FnOnce(axum::Router) -> Result<axum::Router, KernelError> + Send + 'static,
    ) -> Result<(), KernelError> {
        todo!()
    }

    /// 声明事件订阅。
    ///
    /// `handler` 为 bootstrap-local 擦除对象；真实 handler 类型在 W 阶段（wire-up）接线。
    pub fn subscriber(
        &mut self,
        _topic: &'static str,
        _handler: Box<dyn SubscriberHandler>,
    ) -> Result<(), KernelError> {
        todo!()
    }

    /// 声明健康探针。
    ///
    /// `name` 为已校验的强类型探针名（[`primitives::ProbeName`]），消除裸 `&'static str` 的格式漂移风险。
    /// `probe` 实现 [`HealthProbe::check`]，由 bootstrap readyz 驱动聚合。
    pub fn probe(
        &mut self,
        _name: primitives::ProbeName,
        _probe: Box<dyn HealthProbe>,
    ) -> Result<(), KernelError> {
        todo!()
    }
}

impl Default for Registry {
    fn default() -> Self {
        todo!()
    }
}

#[cfg(test)]
mod smoke {
    // Finding#6: Registry smoke——通过 method-item / fn 指针绑定验证各方法签名可解析。
    // Finding#F2: HealthProbe 可执行契约 + ProbeName 强类型 smoke。
    // 只验证类型与 trait 契约，不调用 todo!() body（调用会 panic）。
    use super::{HealthProbe, Registry};

    #[test]
    fn registry_new_signature_resolvable() {
        // 绑定 Registry::new 函数指针——签名不匹配即编译失败。
        let _new: fn() -> Registry = Registry::new;
        fn _assert_new_exists(_f: fn() -> Registry) {}
        _assert_new_exists(Registry::new);
    }

    /// F2: HealthProbe trait 必须有返回 `primitives::HealthCheck` 的 `check` 方法。
    ///
    /// 通过实现 HealthProbe 来断言契约：若 trait 缺失 `check` 方法或签名不匹配，编译失败。
    #[test]
    fn health_probe_check_method_contract() {
        struct _NullProbe;

        impl HealthProbe for _NullProbe {
            fn check(&self) -> primitives::HealthCheck {
                todo!("smoke only — body never called")
            }
        }

        // 验证可装箱为 trait object（满足 dyn-compatible）
        let _: Box<dyn HealthProbe> = Box::new(_NullProbe);
    }

    /// F2: Registry::probe 接受 `primitives::ProbeName`（强类型），不接受裸 `&'static str`。
    ///
    /// 通过构造函数指针（泛型参数绑定）断言签名；`ProbeName` 未实例化不调用 todo!() body。
    #[test]
    fn registry_probe_accepts_probe_name() {
        use super::super::domain::KernelError;
        // 抽 type 别名消除 clippy::type_complexity。
        type ProbeFn = fn(
            &mut Registry,
            primitives::ProbeName,
            Box<dyn HealthProbe>,
        ) -> Result<(), KernelError>;
        // 断言 probe 方法的第一个参数是 primitives::ProbeName。
        // 取函数指针时若类型不匹配或方法不存在即编译错误。
        fn _check_probe_sig(_f: ProbeFn) {}
        _check_probe_sig(Registry::probe);
    }
}
