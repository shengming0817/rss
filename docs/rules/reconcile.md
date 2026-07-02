# Reconcile 控制环规则

本文件只保留当前行为约束。完整 invariant 清单、符号、盲区写在各守卫处：`Reconciler` 策略 trait 冻结在
`crates/consistency/src/reconcile.rs`；harness invariant（RECONCILE-TENANCY-REQ-01）在
`crates/eventexec/src/reconcile.rs` 模块级 rustdoc §Enforced invariants；fencing invariant
（RECONCILE-FENCE-MONO-01）在 `crates/diport/src/fenced_writer.rs`——对应 `RECONCILE-*` 守卫（类型系统 /
clippy/dylint lint / `#[test]` 纵深，见 §参考）和 reconcile ADR 中。

## 适用范围

reconcile 是 L4 desired-state 收敛控制环：周期观察一个域 crate **自己 OWN** 的非终态实体
（设备命令、证书行、trust score），把每个驱动趋向 desired。收敛权属于消费域 crate——框架只
提供 Loop harness，域 crate 在 `Reconcile` 内对自己的实体表行使写权。

reconcile **不是业务编排器**（那是 saga），**不是 CQRS 读模型构建器**（那是 projection
harness）。三者正交，边界见下。

## Desired / Actual / Diff / Converge 模型

L4 模型边界冻结在 `consistency::reconcile` 的纯类型：`DesiredState<T>` / `ActualState<T>` /
`ReconcileDiff<T>` / `DriftKind` / `ConvergeAction`。这些类型只表达域 reconciler 已经映射好的比较
snapshot 与闭集分类；真实 observe / write / command emission 仍由消费域 reconciler 在
`reconcile()` 内完成。

- **desired**：域自己持久层中的 intended snapshot，表示实体应存在为何种纯比较值，或应缺失。
- **actual**：域观察不可靠外部 / 设备边界后得到的 observed snapshot，表示实体当前存在为何种纯比较值，或缺失。
- **diff**：`ReconcileDiff::between(desired, actual)` 得出的闭集 drift 分类：`converged` /
  `missing_actual` / `unexpected_actual` / `changed`。
- **converge**：`ConvergeAction` 纯下一步分类：`noop` / `create` / `update` / `delete`；它不是 adapter
  action，不执行 I/O，也不绕过 fencing / 幂等。

`T` 是域映射后的 provider-agnostic 比较值；泛型本身不尝试用 marker trait 证明该语义，域 reconciler
负责在进入 `DesiredState::present` / `ActualState::present` 前完成映射。DB row、adapter handle、
Vault/SoftCA/Redis/PG 类型、HTTP / Kubernetes / MQTT 类型、generated contract DTO、字段级 payload diff
不属于 `consistency` 模型边界。机器可守部分是：`consistency` 不依赖 adapter / runtime / serde、snapshot
字段私有且只能经 presence 构造入口进入、`Debug` 只输出 presence/drift/action 而不展开 `T`、metric label
只来自上述闭集 `as_label()`。

## Reconciler 实现要点

- 签名 `async fn reconcile(&self, ctx: &Context, req: Request) -> Result<Outcome, ReconcileError>`，
  trait 方法集冻结。
- 默认值 `Request::default()`（空 `EntityId`）是 resync pulse——「re-observe 你拥有的全部」，fan out 到每个
  实体；ticker 每 interval 再发，早退的 sweep 下个 tick 被重驱动（level-triggered，不丢）。
- transient error → Loop 退避重试（per-entity 指数退避）。
- `PermanentError` / `is_permanent` 只是不可重试分类，**不**自动把重试改成放弃下一步逻辑。
- `Outcome.requeue_after` 表达健康态稍后复检；result label 值集冻结在
  `ReconcileResultLabel::as_label()`，捕获的 panic（`catch_unwind`）映射 transient。

## Builder 强制

`reconcile::Builder::new(r, tenancy, trigger).with_*().build()` 是**唯一**公开构造入口（`ReconcileLoop`
无公开构造器、Loop config 字段全部 `pub(crate)` / 私有，`build()` infallible）。消费方禁止裸构造 Loop，
禁止旁路 Builder 注入调度逻辑。

`Builder::new` 第二、三参 `tenancy` / `trigger` 是必填位置参（非可漏链的 `with_*`），漏传即编译错（E0061）——
`tenancy` 是 sealed `Tenancy`（`Tenancy::single_tenant()` / `Tenancy::tenant_scoped()`，仿 `Clock` 位置参约定）：
reconciler 在 tenantless system 身份下发射命令（Claimer key 落 `_notenant`），故必须显式声明该命名空间是否正确；
`trigger` 是 `Trigger`（当前仅 `Trigger::interval(period)`，事件驱动 targeted dispatch 后续兑现）：原「`build()` 强制
一个 Trigger」（运行期 fail-fast）已上移到类型系统（ai-robust：能编译期强制不退化运行期）。TenantScoped reconciler
须自行在 command-id 编码 tenant 维度（框架不验证 body，残留盲区）。由类型系统（Hard，构造器必填位置参）强制：
INVARIANT RECONCILE-TENANCY-REQ-01，回归见 `crates/eventexec/tests/ui/reconcile_missing_{tenancy,trigger}_fail.rs`
（trybuild compile_fail）。

## Leader-elect

- 单进程 / 多副本是**运行期形态**，经 `ReconcileLoop::run` / `ReconcileLoop::run_with_leader(Arc<L>, ..)`
  二选一表达（typed function choice，非 builder `with_leader`）。`run` = 单进程（always leader、
  `Context::epoch()` 为 `None`、无 fencing）。
- `run_with_leader` 整环 leader-gated：仅 lease holder dispatch；丢 lease ⇒ `select!` 丢弃在途 dispatch future
  （取消在途 reconcile），回外环重选举（接管任期 epoch 单调递增）。dispatch 与 cancel **同层** select，
  root / lease-scoped 取消均可中断在途 reconcile。
- **leader ≠ fencing**：跨副本正确性靠**单调任期 epoch**（harness 经 `Context::for_harness(epoch)` 注入
  reconciler）传给 `FencedWriter`（写路径 **per-key** CAS：按被保护资源 `FencedWriteKey` 各自高水位，拒
  `epoch < 该 key 高水位` 的跨任期 stale 写；**同任期多写 / 不同 key 放行**，幂等由消费方负责）+ 消费方幂等，
  绝不靠 lease 本身。leader 走泛型静态分发 `Arc<L>`（非 `Box<DynLeaderElector>`：dyn 变体 Send 非 Sync，
  spawn 的 Send future 跨 await 持有不成立，diport DIPORT-ASYNC-ARC-SEND-01）。
- `LeaderElector` / `FencedWriter` trait 实现只允许在 `adapters/{redis,postgres}`（裸后端名，无前缀，真后端）+
  `adapters/memory` in-mem fake（`MemLeaderElector` / `MemFencedWriter`，确定性单测 / demo 替身）；adapter 选型
  Redis vs PG 按部署形态决定。

## 与 saga / projection 边界

- **saga**：边沿触发、有限步前向编排 + 补偿，跑完即终态（对标 Temporal）。
- **reconcile**：水平触发、desired↔actual 无限收敛环（对标 controller-runtime）。
- **projection**：CQRS 读模型构建，事件驱动重放投影。

L3 最终一致可用 projection / saga；reconcile 用于 L4 跨不可靠边界（设备 / 证书）的主动收敛。

## 参考

- 权威 rustdoc：策略 trait `crates/consistency/src/reconcile.rs`；harness `crates/eventexec/src/reconcile.rs`
  模块级文档 §Enforced invariants；fencing `crates/diport/src/fenced_writer.rs`。
- Invariants：`RECONCILE-*` 族完整清单、符号与盲区以对应守卫（类型系统 / clippy·dylint lint / `#[test]`·
  `rstest` 纵深，可执行真源）为准——`RECONCILE-TENANCY-REQ-01` 在 `eventexec::reconcile`（Builder + trybuild）、
  `RECONCILE-FENCE-MONO-01` 在 `diport::fenced_writer` + `adapters/memory` 测试；规则文件不另维护清单。
  能编译期强制的不退化成运行期测试。
