# Contract: 服务层接缝（PR-3）

> httpserve / authn / bootstrap / eventexec / observ / distributed / deviceloop。范式见 conventions.md（单源 ADR-004），对标见 research.md D3/D4/D5。
>
> **重排（ADR-003）**：本层的 **DI 注入 port trait**（PDP/Publisher/Subscriber/session store/distlock/transport/signer…）已收敛到 `diport` crate（PR-diport，dynosaur）。PR-3 只冻服务层**非 DI 接缝**——type / 穷尽 enum / sync `Fn` / 生命周期编排。

| crate | 冻结接缝（非 DI 部分） | 派发范式 | spike/对标 |
|---|---|---|---|
| **httpserve** | typed route funnel（**ADR-009**，#1113/#1103）：`Listener`(sealed marker `Primary`/`Internal`/`Admin`/`Health`，`KIND` 落值) + `ListenerRouter<L>`(`mount`/`mount_primary` 方法，listener-gated) + funnel 三态 `UnfinalizedRoutes`→`finalize_auth`→`AuthenticatedRoutes`(`into_make_service` 唯一 bindable 出口)；`Route{method,path,contract_id}` / `PrimaryRoute{..,opt_out}`、`ListenerKind`(穷尽 enum)、复用 `tower::Layer`/`Service` | route 注册=`route_group::<L>` register 闭包 `FnOnce(ListenerRouter<L>)->Result<..>`；裸 `axum::Router` 不出 httpserve | ref: tower/axum（`Router<S>` 状态类型） |
| **authn** | jwt/session/refresh 值类型、`Principal`（RowScope 派生）类型；ctx 遵 ADR-002 显式传 `&RequestCtx` | type + 函数；**PDP/session store dyn port → diport** | authplan 类型在 primitives::authplan |
| **bootstrap** | `Domain::init(&self,&mut Registry)->Result<(),KernelError>`、`Registry`、私有字段 `DomainBinding` + `DomainBinding::new` + `compose_bindings(&mut Vec<DomainBinding>)`、shutdown 编排（持 `ManagedResource` LIFO）；Phase 4 目标 `module()->DomainBinding` 尚未接 live | init=sync 不 I/O/spawn；成功 compose 后才返回只含 probes/resources/workers 的聚合 result，失败保持 bindings/output；`ManagedResource` 遵 **ADR-001** | shutdown ADR-001；ref: kube-rs/fx/omicron |
| **eventexec** | `Disposition`(Ack/Nack/Requeue 穷尽 enum)、`HandlerFn`/`ConsumerFn` 类型别名、saga executor·tailer/command 接缝 | type/enum/函数；**Publisher dyn port + `Subscriber`/`SubscribeInitializer` dyn port + `Message` 原语已迁 diport（#1075）** | ref: watermill |
| **observ** | metrics label 值类型（`HttpLabel`/`EventLabel`/`CertLabel`/`MetricLabel`，闭值集） | type/enum；**audit sink port（`AuditSink`/`AuditEvent`/`AuditOutcome`）已迁 diport（#1075）**；结构化 tracing 字段脱敏由 `secure::safe`/`#[derive(secure::Redact)]` 承载（本 PR 删除零使用的 `SpanField`） | metrics label 闭值集 |
| **distributed** | distlock/cas/transport 值类型 | **dyn port → diport** | — |
| **deviceloop** | cert lifecycle·signing（L4）状态机类型 | 态机 type；**signer dyn port → diport** | L4 reconcile |

要点：服务层依赖基础+引擎（+ diport 的 DI port trait），**不依赖域/adapters**。**受控例外**（ADR-009）：`bootstrap → httpserve` 编译期路由类型边（取 `ListenerRouter<L>`/`UnfinalizedRoutes` 词汇，非 runtime provider；layers `route_funnel_allows` 守，单向、反向仍禁）。所有 listener auth chain 显式声明（无 `None`）。`finalize_auth` 已落地（消费 `UnfinalizedRoutes` 产 `AuthenticatedRoutes`，#1113）。

```rust
// bootstrap — Domain init（fail-fast，不 panic / 不 I/O）
pub trait Domain: Send + Sync + 'static {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError>;  // body: todo!()
}

// eventexec — 非 DI 接缝：穷尽 enum + 函数类型别名（Publisher/Subscriber/SubscribeInitializer trait + Message 原语见 diport，#1075）
#[derive(Debug)]
#[non_exhaustive]
pub enum Disposition { Ack, Nack, Requeue { /* delay */ } }
pub type HandlerFn = std::sync::Arc<dyn Fn(Message) -> futures::future::BoxFuture<'static, Disposition> + Send + Sync>;

// diport（PR-diport）— DI port 用 dynosaur，非本文件
// #[dynosaur::dynosaur(DynPublisher = dyn(box) Publisher)]
// pub trait Publisher: Send + Sync { async fn publish(&self, topic: &str, events: &[Event]) -> Result<(), BusError>; }
```
