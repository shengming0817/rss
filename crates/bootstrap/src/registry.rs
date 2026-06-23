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
use diport::Message;
use futures::future::BoxFuture;
use primitives::ListenerKind;

/// 路由组注册的延迟闭包类型。
///
/// 接受 axum `Router`，追加本组 routes 后返回更新后的 `Router`；
/// 失败时返回 `Err(KernelError)` 冒泡到 bootstrap。
type RouteRegisterFn =
    Box<dyn FnOnce(axum::Router) -> Result<axum::Router, KernelError> + Send + 'static>;

/// 路由组声明（由 [`Registry::route_group`] 收集）。
// reason: listener/prefix 经 [`Registry::route_groups`] 已读；`register` 闭包在 RW-G1 追踪弹（服务层
//   闭环、不逐字节跑 axum）不执行，待 W httpserve mount 驱动——故 `register` 字段保留 dead_code 例外。
#[allow(dead_code)]
pub(crate) struct RouteGroupDecl {
    pub(crate) listener: ListenerKind,
    pub(crate) prefix: &'static str,
    pub(crate) register: RouteRegisterFn,
}

/// 事件订阅声明（由 [`Registry::subscriber`] 收集）。
/// topic + handler 在 finalize 经 [`Registry::into_subscribers`] 交组合根接 eventexec 分发驱动。
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
/// 不引 `eventexec`（兄弟服务 crate 禁依赖）：handler 消费 [`diport::Message`]（DI-infra，服务可下行
/// 依赖），返回 [`BoxFuture`]（手写 box——bootstrap 不用 dynosaur，dynosaur 收敛于 `diport`）。组合根
/// （`journeys`）把本 handler 适配成 `eventexec::HandlerFn`（`Ok`→Ack / `Err`→Nack）接到 eventexec 分发
/// 驱动——既证 subscriber 声明流到分发闭环，又不在 bootstrap↔eventexec 间建兄弟服务依赖。
///
/// RW-G1 追踪弹完成 G0 刻意桩住的 handler 调用接缝（freeze→tracer 序列本意）；真实 handler 注册的
/// 服务层 finalize 驱动（替代组合根手工 adapt）留 W。
pub trait SubscriberHandler: Send + Sync {
    /// 消费一条订阅消息。
    ///
    /// 返回 future 须 `'static`（不借 `&self`）——实现者把所需依赖（如 `Arc<DynAuditSink>`）clone 进
    /// future。`Ok` ⇒ 驱动侧 Ack；`Err` ⇒ Nack（驱动按 [`crate`] 消费方的 `Disposition` 映射收口）。
    fn handle(&self, message: Message) -> BoxFuture<'static, Result<(), SubscriberHandlerError>>;
}

/// subscriber handler 处理失败。
///
/// PII 边界（与 `diport` 各 port error 同范式）：`Display` 仅安全摘要常量；原始错误经
/// [`SubscriberHandlerError::new`] 包成 [`std::error::Error::source`] 内部保留，不进默认日志。
#[derive(Debug, thiserror::Error)]
#[error("subscriber handler failed")]
pub struct SubscriberHandlerError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl SubscriberHandlerError {
    /// 把 handler 内部错误包成处理失败。原始错误仅作 internal source 保留（不进 `Display`）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

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
    route_groups: Vec<RouteGroupDecl>,
    subscribers: Vec<SubscriberDecl>,
    probes: Vec<ProbeDecl>,
}

impl Registry {
    /// 由 bootstrap 构造空收集器。
    pub fn new() -> Self {
        Self {
            route_groups: Vec::new(),
            subscribers: Vec::new(),
            probes: Vec::new(),
        }
    }

    /// 声明路由组。
    ///
    /// `register` 是同步闭包：接受 axum `Router`，追加本组 routes 后返回；
    /// 失败时返回 `Err` 冒泡为 [`KernelError`]。
    ///
    /// 闭包延迟到 finalize 阶段由 bootstrap 统一执行，不在 `init` 中立即调用。
    pub fn route_group(
        &mut self,
        listener: ListenerKind,
        prefix: &'static str,
        register: impl FnOnce(axum::Router) -> Result<axum::Router, KernelError> + Send + 'static,
    ) -> Result<(), KernelError> {
        self.route_groups.push(RouteGroupDecl {
            listener,
            prefix,
            register: Box::new(register),
        });
        Ok(())
    }

    /// 声明事件订阅。
    ///
    /// `handler` 为 bootstrap-local 擦除对象（[`SubscriberHandler`]）；组合根 finalize 经
    /// [`Registry::into_subscribers`] 取出接 eventexec 分发驱动。
    pub fn subscriber(
        &mut self,
        topic: &'static str,
        handler: Box<dyn SubscriberHandler>,
    ) -> Result<(), KernelError> {
        self.subscribers.push(SubscriberDecl { topic, handler });
        Ok(())
    }

    /// 声明健康探针。
    ///
    /// `name` 为已校验的强类型探针名（[`primitives::ProbeName`]），消除裸 `&'static str` 的格式漂移风险。
    /// `probe` 实现 [`HealthProbe::check`]，由 bootstrap readyz 驱动聚合。
    pub fn probe(
        &mut self,
        name: primitives::ProbeName,
        probe: Box<dyn HealthProbe>,
    ) -> Result<(), KernelError> {
        self.probes.push(ProbeDecl { name, probe });
        Ok(())
    }

    /// 已声明的路由组（listener + prefix）。
    ///
    /// 组合根 finalize 驱动 httpserve mount 用；RW-G1 journey 据此断言登录路由已经 bootstrap 组装声明
    /// （register 闭包此阶段不执行，见 [`RouteGroupDecl`]）。
    pub fn route_groups(&self) -> Vec<(ListenerKind, &'static str)> {
        self.route_groups
            .iter()
            .map(|d| (d.listener, d.prefix))
            .collect()
    }

    /// 已声明的健康探针数（探针聚合 readyz 驱动留 W；供 journey 断言收集计数）。
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// 取出订阅声明（topic + handler），交组合根接 eventexec 分发驱动。
    ///
    /// 消费 `self`（声明在 finalize 阶段交出，Registry 不再复用）。
    pub fn into_subscribers(self) -> Vec<(&'static str, Box<dyn SubscriberHandler>)> {
        self.subscribers
            .into_iter()
            .map(|d| (d.topic, d.handler))
            .collect()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
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

#[cfg(test)]
mod collect {
    //! Registry 声明收集 + 取出（RW-G1 已写实）：route_group / subscriber 收集，
    //! route_groups() / into_subscribers() 取出，compose 跨域聚合。
    use super::{Message, Registry, SubscriberHandler, SubscriberHandlerError};
    use crate::domain::{Domain, KernelError, compose};
    use futures::future::BoxFuture;
    use primitives::ListenerKind;

    struct OkHandler;
    impl SubscriberHandler for OkHandler {
        fn handle(
            &self,
            _message: Message,
        ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
            Box::pin(async { Ok(()) })
        }
    }

    // 测试断言用 expect：item-level carve-out（error-handling.md §Carve-out 要求 item-level）。
    #[test]
    #[allow(clippy::expect_used)]
    fn registry_collects_and_exposes_declarations() {
        let mut reg = Registry::new();
        reg.route_group(ListenerKind::Primary, "/api/v1/identity", Ok)
            .expect("route group declared");
        reg.subscriber("identity.session-created", Box::new(OkHandler))
            .expect("subscriber declared");

        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, "/api/v1/identity");
        assert_eq!(reg.probe_count(), 0);

        let subs = reg.into_subscribers();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].0, "identity.session-created");
    }

    struct TwoGroupDomain;
    impl Domain for TwoGroupDomain {
        fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
            reg.route_group(ListenerKind::Primary, "/api/v1/a", Ok)?;
            reg.subscriber("topic.a", Box::new(OkHandler))?;
            Ok(())
        }
    }
    struct OneSubDomain;
    impl Domain for OneSubDomain {
        fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
            reg.subscriber("topic.b", Box::new(OkHandler))?;
            Ok(())
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn compose_aggregates_all_domains() {
        let reg = compose(&[&TwoGroupDomain, &OneSubDomain]).expect("compose ok");
        assert_eq!(reg.route_groups().len(), 1);
        let subs = reg.into_subscribers();
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].0, "topic.a");
        assert_eq!(subs[1].0, "topic.b");
    }

    struct FailingDomain;
    impl Domain for FailingDomain {
        fn init(&self, _reg: &mut Registry) -> Result<(), KernelError> {
            Err(KernelError::Subscriber)
        }
    }

    #[test]
    fn compose_fail_fast_on_domain_err() {
        let result = compose(&[&TwoGroupDomain, &FailingDomain]);
        assert!(matches!(result, Err(KernelError::Subscriber)));
    }
}
