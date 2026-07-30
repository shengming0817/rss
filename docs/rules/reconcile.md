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

## Contract 声明

L4 device-latent 契约必须同时声明 `consistencyLevel = "DeviceLatent"`、`[capabilities.deviceLatent]`
和顶层 `[reconcile]` block：

```toml
[capabilities.deviceLatent]
loop = "reconcile"

[capabilities.deviceLatent.profile]
resourceKind = "device-certificate"

[capabilities.deviceLatent.profile.links]
command = "identity.apply-device-certificate"
ackEvent = "identity.device-command-acked"
reportedEvent = "identity.device-certificate-reported"
ingressReceiptEvent = "identity.device-ingress-receipted"

[reconcile]
tenancy = "tenant-scoped"
trigger = "interval"
fencing = "required"
lateMessagePolicy = "idempotent"
```

`assembly-schema` 将通用 `loop` envelope 与 resource-specific tagged profile 分开解析；profile 的
`resourceKind` 是闭枚举，`device-certificate` variant 要求 nested `links` 四字段齐全。缺字段、未知字段或
未知 resource kind 在进入 validator 前即拒绝。`[capabilities.deviceLatent]` 是 L4 typed capability evidence，
`[reconcile]` 是该能力的治理参数面，二者与 `DeviceLatent` 的组合由
`cargo xtask contract validate` R22 强制。R25 再把设备证书 HTTP 契约对绑定到精确的
`resourceKind = "device-certificate"`、四个 linked contract ID 及其 lifecycle 闭包。L3
`WorkflowEventual` contract（saga / projection）不得声明 `[reconcile]`，也不需要 reconcile block。

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
Vault/SoftCA/Redis/PG 类型、HTTP / external scheduler / MQTT 类型、generated contract DTO、字段级 payload diff
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

## Durable PG schema 边界

Postgres adapter 提供 `reconcile_targets` / `reconcile_leases` / `reconcile_attempts` /
`reconcile_attempt_results` / `reconcile_actions` 五表作为 L4 控制环的 durable schema：target 目录、
当前 lease、attempt ledger、terminal attempt result ledger 与真实 converge action ledger。durable scheduler
API 位于 `eventexec::reconcile`（`ReconcileSchedulerBuilder` / `ReconcileWorker` /
`ReconcileScheduleStore`），但 `eventexec` 不依赖 postgres/sqlx；Postgres 只实现 trait。

- target 唯一性由 DB `UNIQUE (tenant_id, reconciler_id, resource_kind, resource_id)` 承载，避免跨租户或跨
  reconciler 的 resource key 互相阻塞。
- due claim 只允许 `status='active' AND next_run_at <= now()` 的 target；worker pause 停止新 claim、等待
  in-flight attempt drain 后 release lease；target pause/resume 由 `disabled`/`active` 状态表达，resume 必须把
  `next_run_at` 推到 `now()`。
- lease 是 target-local 当前状态，`epoch` 是单调高水位；release 只清 holder/token/expiry，不重置 epoch。
  claim 产生 `ClaimedTarget` 与 lease token；后续 attempt result、action/outbox、extend、release 必须以
  `target_id + lease_token + epoch` 做 CAS，0 row 是 lost lease 控制流。durable worker 注入
  `Context::for_harness(Some(epoch))`，这里的 epoch 是 target-local epoch，不混用 global leader epoch。
- attempt / attempt result / action 是 append-only ledger；运行期 `rss_app` 仅有 SELECT/INSERT，无 UPDATE/DELETE。
  attempt 不做 “start row 再 update finish”；terminal success/error/panic 分类进入
  `reconcile_attempt_results`，`reconcile_actions` 只记录真实 `ConvergeAction`（`action_kind` 保持 NOT NULL，
  `result_label` 固定为 action-local `recorded`）。
- 五表都是 tenant 表，必须同迁移落 `ENABLE ROW LEVEL SECURITY`、`FORCE ROW LEVEL SECURITY` 与标准
`tenant_isolation` policy。普通租户内 CAS 走 `TenantDb<ServingWriteLane>` 注入
`SET LOCAL rss.tenant_id`，并且只调用 `cotx::reconcile` 的 closed façade；不暴露通用 executor，也不使用
`SECURITY DEFINER`。

## Durable command outbox seam

durable scheduler 不暴露 store/emitter 给 domain reconciler。`AttemptScope` 只暴露
`record_action_and_enqueue_command(action, generated_typed_command)`，这是唯一 action + command outbox 写入口。
每个 command contract 生成字段私有的 `ReconcileCommand<Request, Subject, Actor>`；sealed
`TypedCommandSpec` 把 baked `CommandSpec` 与 schema-typed request 绑定，外部无法实现或替换 topic/contract/payload。
`ReviewedCommand::from_spec` 只把该 typed wrapper 转成 provider capability，不存在 raw 构造器或
`StableDispatchKey` 公共模型。最终 durable dispatch id 由 `tenant + topic + raw key` 的长度分隔 SHA-256
派生为 opaque key，同 raw key 跨 tenant/topic 不共享 outbox `event_id`，且 raw key 不落库。Postgres
实现必须在同一 tenant transaction 内先以 `lease_token + epoch` CAS 确认 lease，再 append
`reconcile_actions`，再 append outbox entry；若 outbox fact fingerprint 冲突，事务内 savepoint 必须先回滚
action/command alias 写入，再把 target 原子切为 `disabled`。该终态只暴露闭分类 `fact_conflict`，worker 记录
invariant attempt result 并释放 lease，但 due claim 不会自动 reclaim；仅显式 resume 可恢复。

生产恢复面固定为一次性 operator CLI，不允许直接 SQL：

1. 使用 `ServiceCallerDomain::MaintenanceOperator`（`sub=rss-maintenance-operator`）service token，
   并配置 `RSS_RECONCILE_OPERATOR_GRANTS=inspect|tenant,resume|tenant`，授权精确到动作与 tenant；
   caller 已由 typed token 认证，不得由 grant 字符串选择。
2. 先运行 `rss reconcile-target inspect --operator-service-token <token> --operator-tenant <tenant>
   --tenant <tenant> --target-id <uuid>`，确认 `status=disabled` 且 `disabledReason=fact_conflict`。
3. 修正导致稳定 event id 冲突的配置/事实来源后，运行同参数的 `resume`。恢复操作清除 reason、切回
   `active` 并使 target 立即到期；不得在冲突根因未消除时反复 resume。

inspect/resume 均要求 scoped durable replay store 验证 service token、精确 grant 授权，并在
`auth_audit_events` 写 start/finish 记录；输出不包含 payload、metadata、fingerprint 或 resource id。
`reconcile_actions` 不保存 terminal attempt result；不得 direct publisher/broker，也不得在 `eventexec` 内裸 `append_outbox`。

该 seam 只提供 durable scheduler 的事务边界；首个真实 active command contract 与生产 `CommandEmit` bridge
接线仍由独立 follow-up 处理。

## Builder 强制

`reconcile::Builder::new(r, tenancy, trigger).with_*()?.build()` 是**唯一**公开构造入口（`ReconcileLoop`
无公开构造器、Loop config 字段全部 `pub(crate)` / 私有，`with_*` 对 public 配置 fail-fast）。消费方禁止裸构造 Loop，
禁止旁路 Builder 注入调度逻辑。

`Builder::new` 第二、三参 `tenancy` / `trigger` 是必填位置参（非可漏链的 `with_*`），漏传即编译错（E0061）——
`tenancy` 是 sealed `Tenancy`（`Tenancy::single_tenant()` / `Tenancy::tenant_scoped()`，仿 `Clock` 位置参约定）：
reconciler 在 tenantless system 身份下发射命令（Claimer key 落 `_notenant`），故必须显式声明该命名空间是否正确；
`trigger` 是 `Trigger`（当前仅 `Trigger::interval(period)`，事件驱动 targeted dispatch 后续兑现）：原「`build()` 强制
一个 Trigger」（运行期 fail-fast）已上移到类型系统（ai-robust：能编译期强制不退化运行期）。TenantScoped durable command
dispatch id 的 tenant 维度由 generated typed wrapper 的必填位置参注入。由类型系统（Hard）强制：
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
  `RECONCILE-FENCE-MONO-01` 在 `diport::fenced_writer` + `adapters/memory` 测试；
  `RECONCILE-COMMAND-OUTBOX-SEAM-01` 在 `xtask/src/reconcile_outbox_command_guard.rs`；规则文件不另维护清单。
  能编译期强制的不退化成运行期测试。
