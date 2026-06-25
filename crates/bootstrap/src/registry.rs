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
///
/// `FnOnce`——一次性执行，finalize 后不可重入；多次 finalize 见幂等 drain 说明。
type RouteRegisterFn =
    Box<dyn FnOnce(axum::Router) -> Result<axum::Router, KernelError> + Send + 'static>;

/// 路由组声明（由 [`Registry::route_group`] 收集）。
/// `listener`/`prefix` 经 [`Registry::route_groups`] 暴露；`register` 闭包（`FnOnce`，一次性执行，
/// finalize 后不可重入；多次 finalize 见幂等 drain 说明）由
/// [`Registry::finalize_routes`] 在 W 阶段按 listener 分组折叠驱动（auth finalize / socket bind 归组合根）。
pub(crate) struct RouteGroupDecl {
    pub(crate) listener: ListenerKind,
    pub(crate) prefix: &'static str,
    pub(crate) register: RouteRegisterFn,
}

/// 事件订阅声明（由 [`Registry::subscriber`] 收集）。
///
/// contract_id、topic、consumer group、handler 四元组；经 [`Registry::into_subscribers`]
/// 转为 [`SubscriberBinding`] 交组合根接 eventexec 分发驱动。
pub(crate) struct SubscriberDecl {
    pub(crate) contract_id: &'static str,
    pub(crate) topic: &'static str,
    pub(crate) group: consistency::ConsumerGroup,
    pub(crate) handler: Box<dyn SubscriberHandler>,
}

/// finalize 后交组合根的订阅绑定（从 [`SubscriberDecl`] 展开）。
///
/// 组合根据此把 handler 接到 eventexec 分发驱动：`topic` 用于 broker 订阅；
/// `group` 传 ConsumerBase；`contract_id` 提供契约来源（审计/追踪）；
/// `handler` 经 `adapt` 转为 `eventexec::HandlerFn`。
pub struct SubscriberBinding {
    /// 契约 ID（对应 `generated` 中的 `CONTRACT_ID` 常量）。
    pub contract_id: &'static str,
    /// broker topic（对应 `generated` 中的 `TOPIC` 常量）。
    pub topic: &'static str,
    /// 消费者组（稳定标识，幂等去重 PK 的第二维度）。
    pub group: consistency::ConsumerGroup,
    /// bootstrap-local 擦除 handler（由组合根 adapt 为 `eventexec::HandlerFn`）。
    pub handler: Box<dyn SubscriberHandler>,
}

/// 健康探针声明（由 [`Registry::probe`] 收集）。
/// `name`（声明权威名）+ `probe` 由 [`Registry::readyz_report`] 在 W 阶段求值 + worst-of 聚合驱动。
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

/// 已适配的 consumer handler：`run_consumer` / `run_consumer_ackable` 的 handler 形态
/// （`Fn(Message) -> BoxFuture<'static, consistency::HandleResult>`）。
///
/// 由 [`adapt_subscriber_handler`] 从 bootstrap-local [`SubscriberHandler`] 适配产出，供组合根
/// （`journeys` / `bins`）接 `eventexec` 消费驱动——既证 subscriber 声明流到分发闭环，又不在
/// bootstrap↔eventexec 间建兄弟服务依赖（返回 `consistency::HandleResult`，非 `eventexec` 类型）。
pub type ConsumerHandlerFn =
    std::sync::Arc<dyn Fn(Message) -> BoxFuture<'static, consistency::HandleResult> + Send + Sync>;

/// 把 bootstrap-local [`SubscriberHandler`] 适配成 consumer 驱动的 [`ConsumerHandlerFn`]。
///
/// 映射：`Ok(())` → [`consistency::HandleResult::ack`]；`Err(_)` → `reject`（永久——解码 / 租户非法
/// 不可重试，对齐 audit handler 语义），由 ConsumerBase 收口到 DLX。瞬态→requeue 的 typed 分流是
/// 独立 error-taxonomy 关注点（follow-up），本适配器不区分。
pub fn adapt_subscriber_handler(handler: Box<dyn SubscriberHandler>) -> ConsumerHandlerFn {
    let handler: std::sync::Arc<dyn SubscriberHandler> = std::sync::Arc::from(handler);
    std::sync::Arc::new(move |message: Message| {
        let handler = handler.clone();
        Box::pin(async move {
            match handler.handle(message).await {
                Ok(()) => consistency::HandleResult::ack(),
                Err(e) => {
                    tracing::warn!(error = %e, "consumer: subscriber handler errored, rejecting (permanent)");
                    consistency::HandleResult::reject(consistency::PermanentError::new(
                        consistency::PermanentErrorKind::Permanent,
                    ))
                }
            }
        }) as BoxFuture<'static, consistency::HandleResult>
    })
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
/// # Finalize order
///
/// 组合根推荐的调用顺序：
/// 1. [`readyz_report`](Self::readyz_report)（`&self`，可随时调、含 finalize 后）——驱动所有探针求值聚合。
/// 2. [`finalize_routes`](Self::finalize_routes)（`&mut self`，drain routes）——按 listener 分组折叠路由组。
/// 3. [`into_subscribers`](Self::into_subscribers)（`self`，消费）——取出订阅声明交 eventexec 分发驱动。
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

    /// 声明事件订阅（ContractId + topic + ConsumerGroup + handler 四元组绑定）。
    ///
    /// - `contract_id`：契约 ID，取自 `generated::event::<domain_v1>::CONTRACT_ID`。
    /// - `topic`：broker routing key，取自 `generated::event::<domain_v1>::TOPIC`。
    /// - `group`：消费者组（[`consistency::ConsumerGroup`]），幂等去重 PK 的第二维度；
    ///   取自消费域 const，经 `ConsumerGroup::parse(...)` 构造——失败须冒泡为 [`KernelError::Subscriber`]，
    ///   不得在 init 内 `unwrap`/`expect`。
    /// - `handler`：bootstrap-local 擦除对象（[`SubscriberHandler`]）。
    ///
    /// 组合根 finalize 经 [`Registry::into_subscribers`] 取出 [`SubscriberBinding`] 接 eventexec 分发驱动。
    /// DomainId = 注册域，由注册时机隐式记录（不作为参数，避免与 contract owner 语义冲突）。
    pub fn subscriber(
        &mut self,
        contract_id: &'static str,
        topic: &'static str,
        group: consistency::ConsumerGroup,
        handler: Box<dyn SubscriberHandler>,
    ) -> Result<(), KernelError> {
        self.subscribers.push(SubscriberDecl {
            contract_id,
            topic,
            group,
            handler,
        });
        Ok(())
    }

    /// 声明健康探针。
    ///
    /// `name` 为已校验的强类型探针名（[`primitives::ProbeName`]），消除裸 `&'static str` 的格式漂移风险。
    /// `probe` 实现 [`HealthProbe::check`]，由 bootstrap readyz 驱动聚合。
    ///
    /// 探针名在同一 Registry 内必须唯一（声明名是 readyz 报告的权威标识）；重复注册同名探针返回
    /// `Err(KernelError::Probe)`。
    pub fn probe(
        &mut self,
        name: primitives::ProbeName,
        probe: Box<dyn HealthProbe>,
    ) -> Result<(), KernelError> {
        if self.probes.iter().any(|d| d.name == name) {
            return Err(KernelError::Probe);
        }
        self.probes.push(ProbeDecl { name, probe });
        Ok(())
    }

    /// 已声明的路由组（listener + prefix）的只读快照；RW-G1 journey 据此断言路由已经 bootstrap 组装声明。
    ///
    /// 仅 peek 不执行 register 闭包（折叠驱动见 [`finalize_routes`](Self::finalize_routes)）；
    /// `&self` 借用，可在 `finalize_routes` 排空前调用。
    pub fn route_groups(&self) -> Vec<(ListenerKind, &'static str)> {
        self.route_groups
            .iter()
            .map(|d| (d.listener, d.prefix))
            .collect()
    }

    /// 已声明的健康探针数（供 journey 断言收集计数；聚合求值见 [`readyz_report`](Self::readyz_report)）。
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// 驱动所有已注册探针并 worst-of 聚合为 [`primitives::HealthReport`]（readyz 求值入口）。
    ///
    /// 每个探针经 [`HealthProbe::check`] 求值，再用 registry **声明的** [`primitives::ProbeName`]
    /// 重建 [`primitives::HealthCheck`]——声明名权威，覆盖探针自报名（防 impl 自报漂移 / 撞名）。
    /// 空探针 → `Unhealthy`（[`primitives::HealthReport::aggregate`] fail-closed，readyz 不因「没探针」误放行）。
    ///
    /// 借 `&self`、可重复调用：组合根的 readyz handler 每请求调一次（handler 如何长期持有 Registry /
    /// 探针子集属组合根生命周期，归 Join #1017，不在本 crate）。HTTP 端点 mount 由 httpserve 驱动。
    /// ref: uber-go/fx lifecycle.go（Hook 求值=DI port、纯聚合归 primitives，见 `primitives::healthz`）。
    ///
    /// detail 的 PII 安全由 `primitives::HealthCheck::detail() -> &'static str` 编译期类型约束守
    /// （不接受 runtime String），无需运行期 strip。
    ///
    /// **NOTE**：`readyz_report` 是对**当前已注册探针**的纯聚合——它不感知"注册是否已完成"。
    /// 非空探针集若全部 Healthy，结果即为 Healthy，无论是否存在尚未注册的探针。
    /// 注册完整性由 [`compose`](crate::domain::compose) 保证：`compose` 同步运行所有
    /// `Domain::init` 后才返回 `Registry`（全部注册或 fail-fast），由此获得的 `Registry`
    /// 必然是完整注册状态。组合根须在 `compose()` 完成后才暴露 readyz endpoint，且不得对
    /// 手动分步构建的部分 `Registry` 求值。
    pub fn readyz_report(&self) -> primitives::HealthReport {
        let checks = self
            .probes
            .iter()
            .map(|d| {
                let check = d.probe.check();
                primitives::HealthCheck::new(d.name.clone(), check.status(), check.detail())
            })
            .collect();
        primitives::HealthReport::aggregate(checks)
    }

    /// 按 listener 分组折叠路由组 register 闭包，每 listener 产出一个 axum [`Router`](axum::Router)。
    ///
    /// 排空 `route_groups`（`&mut self`，与 [`readyz_report`](Self::readyz_report) /
    /// [`into_subscribers`](Self::into_subscribers) 不争用消费权；消费顺序由组合根定）。同一 listener 的
    /// 多个组折叠进同一 Router；不同 listener 各自独立 Router——`Internal`/`Admin`/`Health` 路由**不可**
    /// 落到 `Primary`（对外）Router 上。register 闭包 Err 原样冒泡（保留变体），并记 listener/prefix/error
    /// 结构化错误日志。
    ///
    /// **挂载语义**：每个路由组的 register 闭包在一个**新鲜 `axum::Router`** 上构建本组路由
    /// （路径相对于 `prefix`），finalize 将该子 Router **nest** 进所属 listener 的累加 Router 的
    /// `prefix` 前缀下——声明 `prefix` 即实际挂载前缀，消除「声明 prefix vs axum 实际路径」漂移。
    ///
    /// 幂等 drain——`route_groups` 排空后再次调用返回空 `Vec`（非错误：routes 已交出，组合根只应调一次）。
    ///
    /// 产出的 per-listener Router 交组合根：再跑 `httpserve::finalize_auth` + 绑各自 socket（Join #1017）——
    /// 本 crate 不引 httpserve、不做 auth、不 bind。
    /// ref: oxidecomputer/omicron nexus/src/lib.rs（internal vs external server 分 listener 隔离）。
    ///
    /// # Finalize order
    ///
    /// 推荐调用顺序见 [`Registry`] struct 文档 §Finalize order。
    ///
    /// INVARIANT: BOOTSTRAP-ROUTE-LISTENER-SEGREGATION-01 —— 不同 listener 的路由进各自 Router，不串台
    /// （Medium：由 `finalize` 测试模块的 `finalize_routes_keeps_listeners_isolated` oneshot 反例守）。
    pub fn finalize_routes(&mut self) -> Result<Vec<(ListenerKind, axum::Router)>, KernelError> {
        let mut by_listener: Vec<(ListenerKind, axum::Router)> = Vec::new();
        for decl in std::mem::take(&mut self.route_groups) {
            let listener = decl.listener;
            let prefix = decl.prefix;
            // 闭包在 fresh Router 上构建本组路由（相对 prefix）；失败原样冒泡 + 记 listener/prefix/error。
            let group = (decl.register)(axum::Router::new()).inspect_err(|e| {
                tracing::error!(
                    listener = ?listener,
                    prefix,
                    error = %e,
                    "route group register closure failed"
                );
            })?;
            let idx = match by_listener.iter().position(|(l, _)| *l == listener) {
                Some(i) => i,
                None => {
                    by_listener.push((listener, axum::Router::new()));
                    by_listener.len() - 1
                }
            };
            // 声明 prefix 即实际挂载前缀：本组 Router nest 进该 listener 累加 Router 的 prefix 下。
            let base = std::mem::take(&mut by_listener[idx].1);
            by_listener[idx].1 = base.nest(prefix, group);
        }
        tracing::info!(
            listener_count = by_listener.len(),
            "route groups finalized into per-listener routers"
        );
        Ok(by_listener)
    }

    /// 取出订阅绑定（contract_id + topic + group + handler），交组合根接 eventexec 分发驱动。
    ///
    /// 消费 `self`（声明在 finalize 阶段交出，Registry 不再复用）。
    /// 返回 [`SubscriberBinding`] 列表；组合根据 `topic` 订阅 broker，据 `group` 接 ConsumerBase，
    /// 据 `handler` 经 `adapt` 转为 `eventexec::HandlerFn`。
    pub fn into_subscribers(self) -> Vec<SubscriberBinding> {
        self.subscribers
            .into_iter()
            .map(|d| SubscriberBinding {
                contract_id: d.contract_id,
                topic: d.topic,
                group: d.group,
                handler: d.handler,
            })
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
        let group =
            consistency::ConsumerGroup::parse("audit.session-created").expect("valid group");
        let mut reg = Registry::new();
        reg.route_group(ListenerKind::Primary, "/api/v1/identity", Ok)
            .expect("route group declared");
        reg.subscriber(
            "identity.session-created",
            "identity.session-created",
            group,
            Box::new(OkHandler),
        )
        .expect("subscriber declared");

        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, "/api/v1/identity");
        assert_eq!(reg.probe_count(), 0);

        let subs = reg.into_subscribers();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].contract_id, "identity.session-created");
        assert_eq!(subs[0].topic, "identity.session-created");
        assert_eq!(subs[0].group.as_str(), "audit.session-created");
    }

    struct TwoGroupDomain;
    impl Domain for TwoGroupDomain {
        fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
            let group = consistency::ConsumerGroup::parse("domain-a.topic-a")
                .map_err(|_| KernelError::Subscriber)?;
            reg.route_group(ListenerKind::Primary, "/api/v1/a", Ok)?;
            reg.subscriber("contract.topic-a", "topic.a", group, Box::new(OkHandler))?;
            Ok(())
        }
    }
    struct OneSubDomain;
    impl Domain for OneSubDomain {
        fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
            let group = consistency::ConsumerGroup::parse("domain-b.topic-b")
                .map_err(|_| KernelError::Subscriber)?;
            reg.subscriber("contract.topic-b", "topic.b", group, Box::new(OkHandler))?;
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
        assert_eq!(subs[0].topic, "topic.a");
        assert_eq!(subs[0].contract_id, "contract.topic-a");
        assert_eq!(subs[0].group.as_str(), "domain-a.topic-a");
        assert_eq!(subs[1].topic, "topic.b");
        assert_eq!(subs[1].contract_id, "contract.topic-b");
        assert_eq!(subs[1].group.as_str(), "domain-b.topic-b");
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

#[cfg(test)]
mod finalize {
    //! W 阶段 finalize driver：`readyz_report`（探针 worst-of 聚合）+ `finalize_routes`
    //! （按 listener 分组折叠 register 闭包）。前者复用 `primitives::HealthReport::aggregate`；
    //! 后者守 INVARIANT BOOTSTRAP-ROUTE-LISTENER-SEGREGATION-01（不同 listener 路由各自 Router）。
    use super::{HealthProbe, Registry};
    use crate::domain::KernelError;
    use primitives::{HealthCheck, HealthStatus, ListenerKind, ProbeName};
    use std::sync::{Arc, Mutex};

    // expect/unwrap 仅测试断言用：item-level carve-out（error-handling.md §Carve-out 要求 item-level）。

    fn probe_name(s: &str) -> ProbeName {
        #[allow(clippy::expect_used)]
        ProbeName::parse(s).expect("valid probe name")
    }

    /// 可配置状态 + 自报名的 mock 探针。`self_name` 用于验证「声明名权威」——
    /// readyz_report 应以 registry 声明的 ProbeName 重建 check，覆盖探针自报的 name。
    struct StubProbe {
        status: HealthStatus,
        self_name: &'static str,
    }

    impl HealthProbe for StubProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(probe_name(self.self_name), self.status, "stub")
        }
    }

    // ── readyz_report ─────────────────────────────────────────────────────────

    #[test]
    fn readyz_empty_is_unhealthy() {
        // fail-closed：未注册任何 probe 不得 fail-open（同 primitives::HealthReport::aggregate）。
        let reg = Registry::new();
        let report = reg.readyz_report();
        assert_eq!(report.overall(), HealthStatus::Unhealthy);
        assert!(report.checks().is_empty());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn readyz_all_healthy_is_healthy() {
        let mut reg = Registry::new();
        reg.probe(
            probe_name("a"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "a",
            }),
        )
        .expect("probe a declared");
        reg.probe(
            probe_name("b"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "b",
            }),
        )
        .expect("probe b declared");

        let report = reg.readyz_report();
        assert_eq!(report.overall(), HealthStatus::Healthy);
        assert_eq!(report.checks().len(), 2);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn readyz_worst_of_is_degraded() {
        let mut reg = Registry::new();
        reg.probe(
            probe_name("a"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "a",
            }),
        )
        .expect("probe a declared");
        reg.probe(
            probe_name("b"),
            Box::new(StubProbe {
                status: HealthStatus::Degraded,
                self_name: "b",
            }),
        )
        .expect("probe b declared");

        assert_eq!(reg.readyz_report().overall(), HealthStatus::Degraded);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn readyz_worst_of_is_unhealthy() {
        let mut reg = Registry::new();
        for (name, status) in [
            ("a", HealthStatus::Healthy),
            ("b", HealthStatus::Degraded),
            ("c", HealthStatus::Unhealthy),
        ] {
            reg.probe(
                probe_name(name),
                Box::new(StubProbe {
                    status,
                    self_name: name,
                }),
            )
            .expect("probe declared");
        }
        assert_eq!(reg.readyz_report().overall(), HealthStatus::Unhealthy);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn readyz_declared_probe_name_is_authoritative() {
        // 探针自报 "self-reported"，registry 声明 "declared"——report 必须用声明名（防探针自报漂移）。
        let mut reg = Registry::new();
        reg.probe(
            probe_name("declared"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "self-reported",
            }),
        )
        .expect("probe declared");

        let report = reg.readyz_report();
        assert_eq!(report.checks().len(), 1);
        assert_eq!(report.checks()[0].name().as_str(), "declared");
    }

    /// `readyz_report` 对当前已注册探针做纯聚合——非空且全部 Healthy 即返回 Healthy，
    /// 不因"注册未完成"而强制 Unhealthy。注册完整性由 `compose()` 保证（compose 同步运行
    /// 所有 `Domain::init` 后才返回 Registry；此测试记录 readyz_report 的语义边界）。
    #[test]
    #[allow(clippy::expect_used)]
    fn readyz_report_aggregates_currently_registered_probes() {
        let mut reg = Registry::new();
        // 手动注册单个 Healthy 探针（模拟 compose 完成前的"部分"状态，或 compose 完成后只有一个探针）。
        reg.probe(
            probe_name("single"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "single",
            }),
        )
        .expect("probe declared");

        // readyz_report 反映当前已注册探针：非空且全部 Healthy → Healthy。
        // 注册完整性由 compose() 契约保证，readyz_report 本身不感知"是否完整"。
        let report = reg.readyz_report();
        assert_eq!(report.overall(), HealthStatus::Healthy);
        assert_eq!(report.checks().len(), 1);
    }

    /// 重复注册同名探针必须返回 `Err(KernelError::Probe)`（声明名唯一性守卫）。
    #[test]
    #[allow(clippy::expect_used)]
    fn probe_duplicate_name_is_rejected() {
        let mut reg = Registry::new();
        reg.probe(
            probe_name("dup"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "dup",
            }),
        )
        .expect("first probe declared");

        let result = reg.probe(
            probe_name("dup"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "dup",
            }),
        );
        assert!(matches!(result, Err(KernelError::Probe)));
    }

    // ── finalize_routes ───────────────────────────────────────────────────────

    type CallLog = Arc<Mutex<Vec<&'static str>>>;

    fn record(log: &CallLog, tag: &'static str) {
        log.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(tag);
    }

    fn calls(log: &CallLog) -> Vec<&'static str> {
        log.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn finalize_routes_empty_yields_no_routers() {
        let mut reg = Registry::new();
        let routers = reg.finalize_routes().expect("finalize ok");
        assert!(routers.is_empty());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn finalize_routes_runs_each_register_closure_once() {
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let mut reg = Registry::new();
        let l = Arc::clone(&log);
        reg.route_group(ListenerKind::Primary, "/api/v1/a", move |r| {
            record(&l, "a");
            Ok(r)
        })
        .expect("route group a declared");

        let routers = reg.finalize_routes().expect("finalize ok");
        assert_eq!(routers.len(), 1);
        assert_eq!(routers[0].0, ListenerKind::Primary);
        assert_eq!(calls(&log), vec!["a"]);
    }

    /// 同一 listener 注册多个路由组（不同 prefix）时，折叠进同一 Router，两闭包均执行。
    /// nest 语义下每个路由组挂在各自 prefix 下，不同 prefix 不冲突。
    #[test]
    #[allow(clippy::expect_used)]
    fn finalize_routes_folds_same_listener_groups_into_one_router() {
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let mut reg = Registry::new();
        let prefixes = [("/api/v1/x", "a"), ("/api/v1/y", "b")];
        for (prefix, tag) in prefixes {
            let l = Arc::clone(&log);
            reg.route_group(ListenerKind::Primary, prefix, move |r| {
                record(&l, tag);
                Ok(r)
            })
            .expect("route group declared");
        }

        let routers = reg.finalize_routes().expect("finalize ok");
        // 同 listener 折叠进单个 Router；两闭包均执行。
        assert_eq!(routers.len(), 1);
        assert_eq!(routers[0].0, ListenerKind::Primary);
        assert_eq!(calls(&log), vec!["a", "b"]);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn finalize_routes_separates_distinct_listeners() {
        let mut reg = Registry::new();
        reg.route_group(ListenerKind::Primary, "/api/v1/p", Ok)
            .expect("primary declared");
        reg.route_group(ListenerKind::Internal, "/internal/v1/i", Ok)
            .expect("internal declared");

        let routers = reg.finalize_routes().expect("finalize ok");
        assert_eq!(routers.len(), 2);
        let kinds: Vec<ListenerKind> = routers.iter().map(|(l, _)| *l).collect();
        assert!(kinds.contains(&ListenerKind::Primary));
        assert!(kinds.contains(&ListenerKind::Internal));
    }

    #[test]
    fn finalize_routes_bubbles_closure_error() {
        let mut reg = Registry::new();
        #[allow(clippy::expect_used)]
        reg.route_group(ListenerKind::Primary, "/api/v1/bad", |_r| {
            Err(KernelError::RouteGroup)
        })
        .expect("route group declared");

        let result = reg.finalize_routes();
        assert!(matches!(result, Err(KernelError::RouteGroup)));
    }

    /// 同一 listener 有两个路由组时，第一个成功（记录 tag）、第二个失败——
    /// finalize_routes 必须返回 Err 且第一个闭包已执行（原样冒泡，不吞 variant）。
    #[test]
    #[allow(clippy::expect_used)]
    fn finalize_routes_bubbles_error_from_later_closure_in_group() {
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let mut reg = Registry::new();

        let l = Arc::clone(&log);
        reg.route_group(ListenerKind::Primary, "/api/v1/ok", move |r| {
            record(&l, "first-ran");
            Ok(r)
        })
        .expect("first route group declared");

        reg.route_group(ListenerKind::Primary, "/api/v1/bad", |_r| {
            Err(KernelError::RouteGroup)
        })
        .expect("second route group declared");

        let result = reg.finalize_routes();
        assert!(matches!(result, Err(KernelError::RouteGroup)));
        // 第一个闭包已执行（finalize 按注册顺序折叠，首先跑 ok 组再遇 err 组）。
        assert_eq!(calls(&log), vec!["first-ran"]);
    }

    /// INVARIANT BOOTSTRAP-ROUTE-LISTENER-SEGREGATION-01 的反例守卫（anti-regression）：
    /// Primary listener 上注册的路由必须只出现在 Primary 的 Router 上，不串到 Internal 的 Router。
    /// 用 sanctioned 的 tower::ServiceExt::oneshot 实发请求断言（rust-standards.md §覆盖率）。
    /// 同时验证第三个 listener（Health）的隔离：N-way segregation。
    ///
    /// F2 回归守卫：路由在 nest 后必须通过**完整前缀路径**访问；裸相对路径（无 prefix）在同一 listener
    /// 上应返回 404——验证声明 prefix 确实参与挂载（不漂移）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalize_routes_keeps_listeners_isolated() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use tower::ServiceExt;

        let mut reg = Registry::new();
        // register 闭包在 fresh Router 上构建相对 prefix 的路由；finalize 将其 nest 到声明 prefix 下。
        reg.route_group(ListenerKind::Primary, "/api/v1/p", |r| {
            Ok(r.route("/primary-only", get(|| async { "p" })))
        })
        .expect("primary declared");
        reg.route_group(ListenerKind::Internal, "/internal/v1/i", |r| {
            Ok(r.route("/internal-only", get(|| async { "i" })))
        })
        .expect("internal declared");
        reg.route_group(ListenerKind::Health, "/health/v1/h", |r| {
            Ok(r.route("/health-only", get(|| async { "h" })))
        })
        .expect("health declared");

        let routers = reg.finalize_routes().expect("finalize ok");
        let primary = routers
            .iter()
            .find(|(l, _)| *l == ListenerKind::Primary)
            .map(|(_, r)| r.clone())
            .expect("primary router present");
        let internal = routers
            .iter()
            .find(|(l, _)| *l == ListenerKind::Internal)
            .map(|(_, r)| r.clone())
            .expect("internal router present");
        let health = routers
            .iter()
            .find(|(l, _)| *l == ListenerKind::Health)
            .map(|(_, r)| r.clone())
            .expect("health router present");

        let req = |uri: &str| {
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request built")
        };

        // primary-only 在 primary Router 的完整路径（prefix + 相对路径）命中。
        let hit = primary
            .clone()
            .oneshot(req("/api/v1/p/primary-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(hit.status(), StatusCode::OK);

        // F2 回归守卫：裸相对路径在同一 listener 应 404（声明 prefix 确实参与挂载）。
        let bare = primary
            .clone()
            .oneshot(req("/primary-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(bare.status(), StatusCode::NOT_FOUND);

        // 跨 listener 串台检查：primary 路由不出现在 internal Router。
        let leaked = internal
            .clone()
            .oneshot(req("/api/v1/p/primary-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(leaked.status(), StatusCode::NOT_FOUND);

        // 反向：internal-only 只在 internal Router（完整路径）。
        let hit = internal
            .clone()
            .oneshot(req("/internal/v1/i/internal-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(hit.status(), StatusCode::OK);

        // F2 回归守卫：裸路径在 internal listener 上 404。
        let bare = internal
            .clone()
            .oneshot(req("/internal-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(bare.status(), StatusCode::NOT_FOUND);

        let leaked = primary
            .clone()
            .oneshot(req("/internal/v1/i/internal-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(leaked.status(), StatusCode::NOT_FOUND);

        // health-only 只在 health Router（完整路径）；primary 和 internal 均缺失（N-way 隔离）。
        let hit = health
            .clone()
            .oneshot(req("/health/v1/h/health-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(hit.status(), StatusCode::OK);

        // F2 回归守卫：裸路径在 health listener 上 404。
        let bare = health
            .clone()
            .oneshot(req("/health-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(bare.status(), StatusCode::NOT_FOUND);

        let leaked_primary = primary
            .oneshot(req("/health/v1/h/health-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(leaked_primary.status(), StatusCode::NOT_FOUND);
        let leaked_internal = internal
            .oneshot(req("/health/v1/h/health-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(leaked_internal.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(test)]
mod handler_adapt {
    //! `adapt_subscriber_handler` 适配器：Ok→Ack / Err→Reject(permanent) 映射验证。
    use super::{Message, SubscriberHandler, SubscriberHandlerError, adapt_subscriber_handler};
    use futures::future::BoxFuture;

    struct OkHandler;
    impl SubscriberHandler for OkHandler {
        fn handle(
            &self,
            _message: Message,
        ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct ErrHandler;
    impl SubscriberHandler for ErrHandler {
        fn handle(
            &self,
            _message: Message,
        ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
            Box::pin(async { Err(SubscriberHandlerError::new(std::io::Error::other("boom"))) })
        }
    }

    #[tokio::test]
    async fn adapt_maps_ok_to_ack() {
        let handler_fn = adapt_subscriber_handler(Box::new(OkHandler));
        let message = diport::Message::new("test-ok", vec![]);
        let result = handler_fn(message).await;
        assert_eq!(result.disposition(), consistency::Disposition::Ack);
        assert_eq!(result.error_summary(), None);
    }

    #[tokio::test]
    async fn adapt_maps_err_to_reject() {
        let handler_fn = adapt_subscriber_handler(Box::new(ErrHandler));
        let message = diport::Message::new("test-err", vec![]);
        let result = handler_fn(message).await;
        assert_eq!(result.disposition(), consistency::Disposition::Reject);
        // anti-vacuity：reject 携 permanent error 摘要，与 ack 的 None 不同。
        assert_eq!(result.error_summary(), Some("permanent error"));
        assert_ne!(result.error_summary(), None);
    }
}
