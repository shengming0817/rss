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
use diport::{Message, RedactedSource};
use futures::future::BoxFuture;
use httpserve::{Listener, ListenerRouter, UnfinalizedRoutes};
use primitives::ListenerKind;

/// 路由组注册的延迟闭包类型（listener-typed，#1103）。
///
/// 接受本 listener 的 [`UnfinalizedRoutes`] 累加器，把本组路由 nest 进去后返回更新后的累加器；
/// 失败时返回 `Err(KernelError)` 冒泡到 bootstrap。listener marker `L` 已在 [`Registry::route_group`]
/// 处擦除（`nest_group::<L>` 捕获进 box），裸 `axum::Router` 不出 httpserve（封印见 `httpserve::routes`）。
///
/// `FnOnce`——一次性执行，finalize 后不可重入；多次 finalize 见幂等 drain 说明。
type RouteRegisterFn =
    Box<dyn FnOnce(UnfinalizedRoutes) -> Result<UnfinalizedRoutes, KernelError> + Send + 'static>;

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
/// contract_id、topic、consumer domain、consumer group、handler 五元组；经 [`Registry::drain_subscribers`]
/// 转为 [`SubscriberBinding`] 交组合根接 eventexec 分发驱动。
pub(crate) struct SubscriberDecl {
    pub(crate) contract_id: &'static str,
    pub(crate) topic: &'static str,
    pub(crate) consumer: &'static str,
    pub(crate) group: consistency::ConsumerGroup,
    pub(crate) handler: Box<dyn SubscriberHandler>,
}

/// finalize 后交组合根的订阅绑定（从 [`SubscriberDecl`] 展开）。
///
/// 组合根据此把 handler 接到 eventexec 分发驱动：`topic` 用于 broker 订阅；
/// `consumer` 用于 ConsumerMeta/DLX/metrics 归因；`group` 传 ConsumerBase；`contract_id` 提供契约来源（审计/追踪）；
/// `handler` 经 `adapt` 转为 `eventexec::HandlerFn`。
pub struct SubscriberBinding {
    /// 契约 ID（对应 `generated` 中的 `CONTRACT_ID` 常量）。
    pub contract_id: &'static str,
    /// broker topic（对应 `generated` 中的 `TOPIC` 常量）。
    pub topic: &'static str,
    /// 消费者域 DomainId（对应 `generated` 中 `SubscriptionSpec::consumer`）。
    pub consumer: &'static str,
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

/// 驱动探针集求值 + worst-of 聚合为 [`primitives::HealthReport`]（[`Registry::readyz_report`] 与
/// [`HealthReporter::report`] 共用单源）。registry **声明的** [`primitives::ProbeName`] 权威，覆盖探针自报名；
/// 空探针 → `Unhealthy`（fail-closed，readyz 不因「没探针」误放行）。
fn aggregate_probes(probes: &[ProbeDecl]) -> primitives::HealthReport {
    let checks = probes
        .iter()
        .map(|d| {
            let check = d.probe.check();
            primitives::HealthCheck::new(d.name.clone(), check.status(), check.detail())
        })
        .collect();
    primitives::HealthReport::aggregate(checks)
}

/// 从 [`Registry`] 取出的 `Send + Sync` 健康报告器（组合根 readyz handler 长期持有，每请求 [`report`](Self::report)）。
///
/// 经 [`Registry::take_health_reporter`] 构造。只含 `Vec<ProbeDecl>`（`Box<dyn HealthProbe>` 的 trait
/// 为 `Send + Sync`）⇒ 本类型 `Send + Sync`，可 `Arc<HealthReporter>` 共享进 axum readyz handler 闭包
/// （`Fn() -> HealthReport + Send + Sync + 'static`）——区别于整体非 `Sync` 的 `Registry`（含 boxed
/// `FnOnce` 路由组）。聚合语义与 [`Registry::readyz_report`] 同源（[`aggregate_probes`]）。
pub struct HealthReporter {
    probes: Vec<ProbeDecl>,
}

impl HealthReporter {
    /// 驱动所持探针求值 + worst-of 聚合（每请求调一次；空探针 → `Unhealthy` fail-closed）。
    pub fn report(&self) -> primitives::HealthReport {
        aggregate_probes(&self.probes)
    }

    /// 所持探针数（供组合根启动日志 / 测试断言）。
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }
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

/// subscriber handler 失败的处置类别——决定 ConsumerBase 是有界重试还是直接 DLX。
///
/// 类型层杜绝「瞬态失败被永久 Reject、绕过 ConsumerBase requeue 预算」（review #274 F2/C2）：handler 须经
/// [`SubscriberHandlerError::permanent`] / [`SubscriberHandlerError::transient`] 二选一显式声明失败语义，
/// 由 [`adapt_subscriber_handler`] 穷尽 `match` 映射到 [`consistency::HandleResult`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberErrorDisposition {
    /// 永久失败（解码 / 校验非法等，重试无意义）→ 直接 DLX（`reject`）。
    Permanent,
    /// 瞬态失败（存储 / append 等可恢复）→ ConsumerBase 有界重试预算（`requeue`）。
    Transient,
}

/// subscriber handler 处理失败（携 [`SubscriberErrorDisposition`] 决定重试 vs DLX）。
///
/// PII 边界（与 `diport` 各 port error 同范式）：`Display` 仅安全摘要常量；原始错误经
/// [`SubscriberHandlerError::permanent`] / [`SubscriberHandlerError::transient`] 包成
/// [`std::error::Error::source`] 内部保留，不进默认日志。
#[derive(Debug, thiserror::Error)]
#[error("subscriber handler failed")]
pub struct SubscriberHandlerError {
    disposition: SubscriberErrorDisposition,
    #[source]
    source: RedactedSource,
}

impl SubscriberHandlerError {
    /// 永久失败（重试无意义，直接 DLX）。原始错误仅作 internal source 保留（不进 `Display`）。
    pub fn permanent<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            disposition: SubscriberErrorDisposition::Permanent,
            source: RedactedSource::new(source),
        }
    }

    /// 瞬态失败（可恢复，ConsumerBase 有界重试）。原始错误仅作 internal source 保留（不进 `Display`）。
    pub fn transient<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            disposition: SubscriberErrorDisposition::Transient,
            source: RedactedSource::new(source),
        }
    }

    /// 失败处置类别（[`adapt_subscriber_handler`] 据此映射 disposition）。
    pub fn disposition(&self) -> SubscriberErrorDisposition {
        self.disposition
    }
}

/// 已适配的 consumer handler：`run_consumer` / `run_consumer_ackable` 的 handler 形态
/// （`Fn(Message) -> BoxFuture<'static, consistency::HandleResult>`）。
///
/// 由 [`adapt_subscriber_handler`] 从 bootstrap-local [`SubscriberHandler`] 适配产出，供组合根
/// （`journeys` / `bins`）接 `eventexec` 消费驱动——既证 subscriber 声明流到分发闭环，又不在
/// bootstrap↔eventexec 间建兄弟服务依赖（返回 `consistency::HandleResult`，非 `eventexec` 类型）。
///
/// `Box<dyn Fn>` 直接 impl `Fn`（std blanket impl），无需调用方桥接即可传给 `eventexec::spawn_consumer`
/// 的 `H: Fn` 约束（`Arc<dyn Fn>` 不 impl `Fn`，需手写桥——Box 消除该桥）。
pub type ConsumerHandlerFn =
    Box<dyn Fn(Message) -> BoxFuture<'static, consistency::HandleResult> + Send + Sync>;

/// 把 bootstrap-local [`SubscriberHandler`] 适配成 consumer 驱动的 [`ConsumerHandlerFn`]。
///
/// 映射（按 [`SubscriberErrorDisposition`] 穷尽分流，review #274 F2/C2）：
/// - `Ok(())` → [`consistency::HandleResult::ack`]。
/// - `Err(Transient)` → [`consistency::HandleResult::requeue`]——可恢复失败（存储 / append 等）走
///   ConsumerBase 有界重试预算，**不**首投即 DLX。
/// - `Err(Permanent)` → [`consistency::HandleResult::reject`]——解码 / 校验非法不可重试，由 ConsumerBase
///   收口到 DLX。
///
/// 返回 `Box<dyn Fn>`，直接满足 `eventexec::spawn_consumer` / `spawn_consumer_ackable` 的
/// `H: Fn` 约束，无需调用方额外桥接。
///
/// # 组合根接线示例（3 步）
///
/// ```ignore
/// // 1. 先订阅得 stream（subscribe-at-callsite，保证先于发布）。
/// let stream = bus.subscriber().subscribe(Topic::new(topic), token.clone()).await?;
/// // 2. adapt handler。
/// let handler_fn = bootstrap::adapt_subscriber_handler(binding.handler);
/// // 3. spawn worker + 注册关闭。
/// let worker = eventexec::spawn_consumer(name, stream, idem, dlx, meta, handler_fn, token, health);
/// stack.register_detached(diport::DynManagedResource::new_box(worker));
/// ```
pub fn adapt_subscriber_handler(handler: Box<dyn SubscriberHandler>) -> ConsumerHandlerFn {
    // 内层保留 Arc：闭包多次调用（Fn，非 FnOnce），每次需 clone handler 进 async block。
    let handler: std::sync::Arc<dyn SubscriberHandler> = std::sync::Arc::from(handler);
    Box::new(move |message: Message| {
        let handler = handler.clone();
        Box::pin(async move {
            match handler.handle(message).await {
                Ok(()) => consistency::HandleResult::ack(),
                Err(e) => match e.disposition() {
                    SubscriberErrorDisposition::Transient => {
                        tracing::warn!(error = %secure::redact_error(&e), "consumer: subscriber handler transient failure, requeueing");
                        consistency::HandleResult::requeue(consistency::EngineError::new(
                            consistency::EngineErrorKind::Transient,
                        ))
                    }
                    SubscriberErrorDisposition::Permanent => {
                        tracing::warn!(error = %secure::redact_error(&e), "consumer: subscriber handler permanent failure, rejecting (DLX)");
                        consistency::HandleResult::reject(consistency::PermanentError::new(
                            consistency::PermanentErrorKind::Permanent,
                        ))
                    }
                },
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
/// 3. [`drain_subscribers`](Self::drain_subscribers)（`&mut self`，drain）——取出订阅声明交 eventexec 分发驱动。
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

    /// 声明路由组——**listener 由类型参数 `L` 携带**（#1103 typed per-listener route-group）。
    ///
    /// `L` 是 httpserve listener marker（[`httpserve::Primary`] / `Internal` / `Admin` / `Health`），
    /// `L::KIND` 给出运行期 listener 值（fold 分组键）。`register` 是同步闭包：接受 listener-typed
    /// [`ListenerRouter<L>`]，经 `mount`(非-Primary) / `mount_primary`(Primary) 追加本组 routes 后返回；
    /// 失败时返回 `Err` 冒泡为 [`KernelError`]。
    ///
    /// INVARIANT: ROUTE-LISTENER-TYPED-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 域 crate 误声明（把 Internal 路由挂 Primary）类型层不可表达：
    /// 路由经 `ListenerRouter<L>` 挂载、随组 fold 进 `L::KIND` listener 的 Router，且非-Primary listener 拿不到
    /// `mount_primary`（opt-out）。取代旧 `route_group(listener: ListenerKind, ..)` 的运行期值传参 + SEGREGATION-01
    /// runtime 守（Medium→Hard）。listener marker `L` 经 [`UnfinalizedRoutes::nest_group`] 擦除进 box。
    ///
    /// 闭包延迟到 finalize 阶段由 bootstrap 统一执行（[`finalize_routes`](Self::finalize_routes)），不在 `init` 中立即调用。
    pub fn route_group<L>(
        &mut self,
        prefix: &'static str,
        register: impl FnOnce(ListenerRouter<L>) -> Result<ListenerRouter<L>, KernelError>
        + Send
        + 'static,
    ) -> Result<(), KernelError>
    where
        L: Listener,
    {
        self.route_groups.push(RouteGroupDecl {
            listener: L::KIND,
            prefix,
            // 擦除 L：box 内 `nest_group::<L>` 把本组路由 nest 进 listener 累加器（裸 Router 不出 httpserve）。
            register: Box::new(move |acc: UnfinalizedRoutes| acc.nest_group(prefix, register)),
        });
        Ok(())
    }

    /// 声明事件订阅（ContractId + topic + ConsumerGroup + handler 四元组绑定）。
    ///
    /// - `contract_id`：契约 ID，取自 `generated::event::<domain_v1>::CONTRACT_ID`。
    /// - `topic`：broker routing key，取自 `generated::event::<domain_v1>::TOPIC`。
    /// - `consumer`：消费者域 DomainId，取自 `generated::event::*::SUBSCRIPTIONS[*].consumer`；
    ///   用于 DLX / metrics / health 归因，不得从 topic owner 反推。
    /// - `group`：消费者组（[`consistency::ConsumerGroup`]），幂等去重 PK 的第二维度；
    ///   取自消费域 const，经 `ConsumerGroup::parse(...)` 构造——失败须冒泡为 [`KernelError::Subscriber`]，
    ///   不得在 init 内 `unwrap`/`expect`。
    /// - `handler`：bootstrap-local 擦除对象（[`SubscriberHandler`]）。
    ///
    /// 组合根 finalize 经 [`Registry::drain_subscribers`] 取出 [`SubscriberBinding`] 接 eventexec 分发驱动。
    /// DomainId = 注册域，由注册时机隐式记录（不作为参数，避免与 contract owner 语义冲突）。
    pub fn subscriber(
        &mut self,
        contract_id: &'static str,
        topic: &'static str,
        consumer: &'static str,
        group: consistency::ConsumerGroup,
        handler: Box<dyn SubscriberHandler>,
    ) -> Result<(), KernelError> {
        self.subscribers.push(SubscriberDecl {
            contract_id,
            topic,
            consumer,
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
        aggregate_probes(&self.probes)
    }

    /// 取出已注册探针，产出 `Send + Sync` 的 [`HealthReporter`]（组合根 readyz handler 长期持有）。
    ///
    /// 落实 [`readyz_report`](Self::readyz_report) 文档「handler 如何长期持有探针子集属组合根生命周期」
    /// 的接缝（#1320）：`Registry` 含 `Vec<RouteGroupDecl>`（boxed `FnOnce` 非 `Sync`）⇒ `Arc<Registry>`
    /// **非 `Sync`**，无法进 axum readyz handler 闭包（需 `Fn + Send + Sync + 'static`）。本 fn `std::mem::take`
    /// 探针装进只含 `Box<dyn HealthProbe>`（trait `Send + Sync`）的 [`HealthReporter`]——`Send + Sync`，可
    /// `Arc` 共享进 handler。`&mut self`：与 [`finalize_routes`](Self::finalize_routes) drain 路由组不争用
    /// （组合根 finalize 路由后取 reporter；探针从 Registry 移出，二次 take 得空 reporter）。
    pub fn take_health_reporter(&mut self) -> HealthReporter {
        HealthReporter {
            probes: std::mem::take(&mut self.probes),
        }
    }

    /// 按 listener 分组折叠路由组 register 闭包，每 listener 产出一个 [`UnfinalizedRoutes`]（未认证安全态）。
    ///
    /// 排空 `route_groups`（`&mut self`，与 [`readyz_report`](Self::readyz_report) /
    /// [`drain_subscribers`](Self::drain_subscribers) 不争用消费权；消费顺序由组合根定）。同一 listener 的
    /// 多个组折叠进同一累加器；不同 listener 各自独立——`Internal`/`Admin`/`Health` 路由**不可**
    /// 落到 `Primary`（对外）listener（由 [`route_group`](Self::route_group) 的 typed `L` 类型层守）。
    /// register 闭包 Err 原样冒泡（保留变体），并记 listener/prefix/error 结构化错误日志。
    ///
    /// **挂载语义**：每个路由组的 register 闭包经 typed `ListenerRouter<L>` 在**新鲜 Router** 上构建本组路由
    /// （路径相对于 `prefix`），[`UnfinalizedRoutes::nest_group`] 将其 **nest** 进所属 listener 累加器的
    /// `prefix` 前缀下——声明 `prefix` 即实际挂载前缀，消除「声明 prefix vs 实际路径」漂移。
    ///
    /// 幂等 drain——`route_groups` 排空后再次调用返回空 `Vec`（非错误：routes 已交出，组合根只应调一次）。
    ///
    /// **结果不变式**：每个 `ListenerKind` 在返回 `Vec` 中**最多出现一次**（同 listener 的多个路由组已折叠进同一
    /// 累加器）；组合根可安全对结果逐项 `into_iter` 按 listener bind，无需去重。
    ///
    /// 产出的 per-listener [`UnfinalizedRoutes`] 交组合根：再跑 `httpserve::finalize_auth` 换
    /// `AuthenticatedRoutes` + 绑各自 socket（Join #1017）。`UnfinalizedRoutes` **无 public bindable 出口**，
    /// 故组合根**不可能**跳过 `finalize_auth` 直接 bind 未认证 router（#1113 funnel Hard）。
    /// 经受控 `bootstrap → httpserve` 编译期路由类型边（ADR-009）：bootstrap 只碰 sealed `UnfinalizedRoutes`，
    /// 裸 `axum::Router` 全程不出 httpserve。
    /// ref: oxidecomputer/omicron nexus/src/lib.rs（internal vs external server 分 listener 隔离）。
    ///
    /// # Finalize order
    ///
    /// 推荐调用顺序见 [`Registry`] struct 文档 §Finalize order。
    ///
    /// INVARIANT: ROUTE-AUTH-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 产出 `UnfinalizedRoutes`（无 bindable 出口），唯有
    /// `httpserve::finalize_auth` 能换出可 bind 的 `AuthenticatedRoutes`（auth-finalize-before-bind，Hard）。
    /// listener 隔离由 [`route_group`](Self::route_group) 的 typed `L`（ROUTE-LISTENER-TYPED-01，#1103
    /// Medium→Hard）守——取代旧 BOOTSTRAP-ROUTE-LISTENER-SEGREGATION-01 runtime 反例测试。
    pub fn finalize_routes(
        &mut self,
    ) -> Result<Vec<(ListenerKind, UnfinalizedRoutes)>, KernelError> {
        let mut by_listener: Vec<(ListenerKind, UnfinalizedRoutes)> = Vec::new();
        for decl in std::mem::take(&mut self.route_groups) {
            let listener = decl.listener;
            let prefix = decl.prefix;
            let idx = match by_listener.iter().position(|(l, _)| *l == listener) {
                Some(i) => i,
                None => {
                    by_listener.push((listener, UnfinalizedRoutes::empty()));
                    by_listener.len() - 1
                }
            };
            // 本组路由 nest 进该 listener 累加器（声明 prefix 即实际挂载前缀）；闭包 Err 原样冒泡 + 记 listener/prefix/error。
            let acc = std::mem::replace(&mut by_listener[idx].1, UnfinalizedRoutes::empty());
            by_listener[idx].1 = (decl.register)(acc).inspect_err(|e| {
                tracing::error!(
                    listener = ?listener,
                    prefix,
                    error = %secure::redact_error(&e),
                    "route group register closure failed"
                );
            })?;
        }
        tracing::info!(
            listener_count = by_listener.len(),
            "route groups finalized into per-listener UnfinalizedRoutes"
        );
        Ok(by_listener)
    }

    /// 取出订阅绑定（contract_id + topic + consumer + group + handler），交组合根接 eventexec 分发驱动。
    ///
    /// 排空 `subscribers`（`&mut self`，与 [`readyz_report`](Self::readyz_report) /
    /// [`finalize_routes`](Self::finalize_routes) 不争用消费权；消费顺序由组合根定）。
    /// 幂等 drain——`subscribers` 排空后再次调用返回空 `Vec`（非错误）。
    /// 返回 [`SubscriberBinding`] 列表；组合根据 `topic` 订阅 broker，据 `consumer` 构造 ConsumerMeta，
    /// 据 `group` 接 ConsumerBase，
    /// 据 `handler` 经 `adapt` 转为 `eventexec::HandlerFn`。
    pub fn drain_subscribers(&mut self) -> Vec<SubscriberBinding> {
        std::mem::take(&mut self.subscribers)
            .into_iter()
            .map(|d| SubscriberBinding {
                contract_id: d.contract_id,
                topic: d.topic,
                consumer: d.consumer,
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
    //! route_groups() / drain_subscribers() 取出，compose 跨域聚合。
    use super::{Message, Registry, SubscriberHandler, SubscriberHandlerError};
    use crate::domain::{Domain, KernelError, compose};
    use futures::future::BoxFuture;
    use httpserve::Primary;
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
        reg.route_group::<Primary>("/api/v1/identity", Ok)
            .expect("route group declared");
        reg.subscriber(
            "identity.session-created",
            "identity.session-created",
            "audit",
            group,
            Box::new(OkHandler),
        )
        .expect("subscriber declared");

        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, "/api/v1/identity");
        assert_eq!(reg.probe_count(), 0);

        let subs = reg.drain_subscribers();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].contract_id, "identity.session-created");
        assert_eq!(subs[0].topic, "identity.session-created");
        assert_eq!(subs[0].consumer, "audit");
        assert_eq!(subs[0].group.as_str(), "audit.session-created");
    }

    struct TwoGroupDomain;
    impl Domain for TwoGroupDomain {
        fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
            let group = consistency::ConsumerGroup::parse("domain-a.topic-a")
                .map_err(|_| KernelError::Subscriber)?;
            reg.route_group::<Primary>("/api/v1/a", Ok)?;
            reg.subscriber(
                "contract.topic-a",
                "topic.a",
                "domain-a",
                group,
                Box::new(OkHandler),
            )?;
            Ok(())
        }
    }
    struct OneSubDomain;
    impl Domain for OneSubDomain {
        fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
            let group = consistency::ConsumerGroup::parse("domain-b.topic-b")
                .map_err(|_| KernelError::Subscriber)?;
            reg.subscriber(
                "contract.topic-b",
                "topic.b",
                "domain-b",
                group,
                Box::new(OkHandler),
            )?;
            Ok(())
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn compose_aggregates_all_domains() {
        let mut reg = compose(&[&TwoGroupDomain, &OneSubDomain]).expect("compose ok");
        assert_eq!(reg.route_groups().len(), 1);
        let subs = reg.drain_subscribers();
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
    //! （按 listener 分组折叠 typed register 闭包为 per-listener `UnfinalizedRoutes`）。前者复用
    //! `primitives::HealthReport::aggregate`；后者经 typed `route_group::<L>` 守 listener 隔离
    //! （ROUTE-LISTENER-TYPED-01 类型层，#1103 Medium→Hard）+ ROUTE-AUTH-FUNNEL-01（无 bindable 出口）。
    use super::{HealthProbe, HealthReporter, Registry};
    use crate::domain::KernelError;
    use httpserve::{Health, Internal, Primary};
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

    /// `drain_subscribers` 取出订阅绑定，drain 后 Registry 订阅列表清空（二次 drain 返回空 Vec）。
    ///
    /// 仿照 `take_health_reporter_extracts_probes_and_reports`：注册一个 subscriber，drain，
    /// 断言绑定已返回 + 二次 drain 幂等返回空。
    #[test]
    #[allow(clippy::expect_used)]
    fn drain_subscribers_extracts_bindings_and_clears() {
        use super::{Message, SubscriberHandler, SubscriberHandlerError};
        use futures::future::BoxFuture;

        struct StubHandler;
        impl SubscriberHandler for StubHandler {
            fn handle(
                &self,
                _message: Message,
            ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
                Box::pin(async { Ok(()) })
            }
        }

        let group =
            consistency::ConsumerGroup::parse("test.drain-group").expect("valid consumer group");
        let mut reg = Registry::new();
        reg.subscriber(
            "test.drain-topic",
            "drain.topic",
            "test-consumer",
            group,
            Box::new(StubHandler),
        )
        .expect("subscriber declared");

        let bindings = reg.drain_subscribers();
        assert_eq!(bindings.len(), 1, "drain 取出一个绑定");
        assert_eq!(bindings[0].contract_id, "test.drain-topic");
        assert_eq!(bindings[0].topic, "drain.topic");
        assert_eq!(bindings[0].consumer, "test-consumer");
        assert_eq!(bindings[0].group.as_str(), "test.drain-group");

        // 二次 drain 幂等返回空（subscribers 已被 std::mem::take 清空）。
        let second = reg.drain_subscribers();
        assert!(second.is_empty(), "二次 drain 返回空 Vec");
    }

    /// `take_health_reporter` 取出探针产出 `Send + Sync` reporter，`report` 聚合语义同 `readyz_report`；
    /// take 后 Registry 探针清空（二次聚合空 → fail-closed Unhealthy）。
    #[test]
    #[allow(clippy::expect_used)]
    fn take_health_reporter_extracts_probes_and_reports() {
        let mut reg = Registry::new();
        reg.probe(
            probe_name("a"),
            Box::new(StubProbe {
                status: HealthStatus::Healthy,
                self_name: "a",
            }),
        )
        .expect("probe a declared");
        assert_eq!(reg.probe_count(), 1);

        let reporter = reg.take_health_reporter();
        assert_eq!(reporter.probe_count(), 1, "探针移入 reporter");
        assert_eq!(
            reporter.report().overall(),
            HealthStatus::Healthy,
            "reporter.report 聚合语义同 readyz_report"
        );

        // 探针已从 Registry 移出：probe_count 归零，再聚合 → 空 fail-closed Unhealthy。
        assert_eq!(reg.probe_count(), 0, "take 后 Registry 探针清空");
        assert_eq!(reg.readyz_report().overall(), HealthStatus::Unhealthy);

        // reporter 是 Send + Sync（可进 axum readyz handler 闭包）——静态断言。
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HealthReporter>();
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
        reg.route_group::<Primary>("/api/v1/a", move |r| {
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
            reg.route_group::<Primary>(prefix, move |r| {
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
        reg.route_group::<Primary>("/api/v1/p", Ok)
            .expect("primary declared");
        reg.route_group::<Internal>("/internal/v1/i", Ok)
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
        reg.route_group::<Primary>("/api/v1/bad", |_r| Err(KernelError::RouteGroup))
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
        reg.route_group::<Primary>("/api/v1/ok", move |r| {
            record(&l, "first-ran");
            Ok(r)
        })
        .expect("first route group declared");

        reg.route_group::<Primary>("/api/v1/bad", |_r| Err(KernelError::RouteGroup))
            .expect("second route group declared");

        let result = reg.finalize_routes();
        assert!(matches!(result, Err(KernelError::RouteGroup)));
        // 第一个闭包已执行（finalize 按注册顺序折叠，首先跑 ok 组再遇 err 组）。
        assert_eq!(calls(&log), vec!["first-ran"]);
    }

    /// ROUTE-LISTENER-TYPED-01 的**行为**补充测试（类型层已守误声明，本测试守 fold/nest 运行期机制）：
    /// 经 typed `route_group::<L>` + `mount`/`mount_primary` 声明的路由，finalize 后必须只出现在 `L::KIND`
    /// listener 的 Router 上，不串台。用 sanctioned 的 tower::ServiceExt::oneshot 实发请求断言
    /// （rust-standards.md §覆盖率）。N-way（Primary/Internal/Health）隔离 + 裸路径 404 守 prefix 参与挂载。
    ///
    /// 裸 Router 经 `UnfinalizedRoutes::into_router_for_test`（`#[doc(hidden)]` 测试入口）取回做 oneshot——
    /// 生产路径无此 bindable 出口（ROUTE-AUTH-FUNNEL-01）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalize_routes_keeps_listeners_isolated() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use axum::routing::get;
        use httpserve::{PrimaryRoute, Route, RoutePermission, RouteResourceScope};
        use tower::ServiceExt;

        let mut reg = Registry::new();
        // register 闭包经 typed builder 在 fresh Router 上 mount 相对 prefix 的路由；finalize nest 到声明 prefix 下。
        reg.route_group::<Primary>("/api/v1/p", |rb| {
            Ok(rb.mount_primary(
                PrimaryRoute::permission(
                    Method::GET,
                    "/primary-only",
                    "test.primary",
                    RoutePermission {
                        permission: vocab::RoutePermissionId::IdentityPolicyRead,
                        scope: RouteResourceScope::None,
                    },
                ),
                get(|| async { "p" }),
            ))
        })
        .expect("primary declared");
        reg.route_group::<Internal>("/internal/v1/i", |rb| {
            Ok(rb.mount(
                Route {
                    method: Method::GET,
                    path: "/internal-only",
                    contract_id: "test.internal",
                },
                get(|| async { "i" }),
            ))
        })
        .expect("internal declared");
        reg.route_group::<Health>("/health/v1/h", |rb| {
            Ok(rb.mount(
                Route {
                    method: Method::GET,
                    path: "/health-only",
                    contract_id: "test.health",
                },
                get(|| async { "h" }),
            ))
        })
        .expect("health declared");

        // 取回各 listener 的裸 Router（测试专用入口）做 oneshot 断言。
        let (mut primary, mut internal, mut health) = (None, None, None);
        for (listener, routes) in reg.finalize_routes().expect("finalize ok") {
            match listener {
                ListenerKind::Primary => primary = Some(routes.into_router_for_test()),
                ListenerKind::Internal => internal = Some(routes.into_router_for_test()),
                ListenerKind::Health => health = Some(routes.into_router_for_test()),
                _ => {}
            }
        }
        let primary = primary.expect("primary router present");
        let internal = internal.expect("internal router present");
        let health = health.expect("health router present");

        let req = |uri: &str| {
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request built")
        };

        // primary-only 在 primary Router 的完整路径（prefix + 相对路径）命中：matched ⇒ 路由的 enforce
        // layer 运行。本 fold-only 测试未跑 finalize_auth（无 AuthPlan extension），故 enforce fail-closed
        // 403——403（matched + enforce 守）vs 404（未挂载）即区分「路由挂在本 listener」，正是隔离断言。
        let hit = primary
            .clone()
            .oneshot(req("/api/v1/p/primary-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(hit.status(), StatusCode::FORBIDDEN);

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

        // 反向：internal-only 只在 internal Router（完整路径）——matched ⇒ enforce fail-closed 403（见上）。
        let hit = internal
            .clone()
            .oneshot(req("/internal/v1/i/internal-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(hit.status(), StatusCode::FORBIDDEN);

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

        // health-only 只在 health Router（完整路径）；primary 和 internal 均缺失（N-way 隔离）。matched ⇒ 403（见上）。
        let hit = health
            .clone()
            .oneshot(req("/health/v1/h/health-only"))
            .await
            .expect("oneshot ok");
        assert_eq!(hit.status(), StatusCode::FORBIDDEN);

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
    //! `adapt_subscriber_handler` 适配器：Ok→Ack / Err(Permanent)→Reject / Err(Transient)→Requeue 映射验证
    //! （F2/C2：瞬态失败走 ConsumerBase 有界重试预算，不首投即 DLX）。
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

    struct PermanentErrHandler;
    impl SubscriberHandler for PermanentErrHandler {
        fn handle(
            &self,
            _message: Message,
        ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
            Box::pin(async {
                Err(SubscriberHandlerError::permanent(std::io::Error::other(
                    "boom",
                )))
            })
        }
    }

    struct TransientErrHandler;
    impl SubscriberHandler for TransientErrHandler {
        fn handle(
            &self,
            _message: Message,
        ) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
            Box::pin(async {
                Err(SubscriberHandlerError::transient(std::io::Error::other(
                    "io",
                )))
            })
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
    async fn adapt_maps_permanent_to_reject() {
        let handler_fn = adapt_subscriber_handler(Box::new(PermanentErrHandler));
        let message = diport::Message::new("test-err", vec![]);
        let result = handler_fn(message).await;
        assert_eq!(result.disposition(), consistency::Disposition::Reject);
        // anti-vacuity：reject 携 permanent error 摘要，与 ack 的 None 不同。
        assert_eq!(result.error_summary(), Some("permanent error"));
        assert_ne!(result.error_summary(), None);
    }

    #[tokio::test]
    async fn adapt_maps_transient_to_requeue() {
        // F2/C2：瞬态失败 → Requeue（ConsumerBase 有界重试），**非** Reject（不首投即 DLX）。
        let handler_fn = adapt_subscriber_handler(Box::new(TransientErrHandler));
        let message = diport::Message::new("test-transient", vec![]);
        let result = handler_fn(message).await;
        assert_eq!(result.disposition(), consistency::Disposition::Requeue);
        assert_ne!(
            result.disposition(),
            consistency::Disposition::Reject,
            "瞬态失败不得绕过 requeue 预算被永久 Reject"
        );
        assert_eq!(result.error_summary(), Some("transient engine error"));
    }

    #[test]
    fn subscriber_handler_error_redacts_source_debug_and_chain() {
        let err =
            SubscriberHandlerError::permanent(std::io::Error::other("postgres://user:hunter2@db"));
        assert_eq!(err.to_string(), "subscriber handler failed");
        let dbg = format!("{err:?}");
        assert!(!dbg.contains("hunter2"), "Debug 泄漏 source: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "first source is RedactedSource");
        let Some(source) = source else {
            return;
        };
        assert_eq!(source.to_string(), "<redacted>");
        assert!(
            std::error::Error::source(source).is_none(),
            "source chain must stop at RedactedSource"
        );
    }
}
