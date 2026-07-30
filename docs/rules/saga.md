# Saga 引擎规则

本文件只保留当前行为约束。完整盲区、符号清单、评级证明写在
`xtask`（saga 不变量校验）、`consistency` crate 的 governance 模块（saga 规则）、
saga ADR 和 runbook 中。

## 架构语义

使用 saga 编排意味着 L3；L3 不等价于 saga。投影型、CQRS 型最终一致可以是 L3
但不使用 saga 引擎。

## Governance

`kind: saga` contract 必须：

- 有非空 `saga:` block。
- 至少一个 step。
- step name 可生成 Rust 标识符且唯一。
- 每个 step 声明 output schema ref。
- compensation order 只能是 reverse。
- consistency level 为 L3。
- retry 和 timeout 是合法非负 duration；字段为 block 级策略，不是 per-step。

编排逻辑落在域 crate 的 saga 模块；其 `kind: saga` 契约的 `consistencyLevel` 必须为 L3。

## Runtime policy

`cargo xtask codegen` 从 `[saga].retryMillis` / `[saga].timeoutMillis` 派生
`vocab::SagaRuntimePolicySpec`；生成的 `SPEC` 同时携带 contract、policy 和 ordered `STEPS`。
组合根从同一个 `SPEC` 构造 `SagaExecutorConfig` 和 `TypedSagaActionFactory`。

- `retryMillis = 0` 且 `timeoutMillis = 0`：禁用 retry/timeout，动作直接 await。
- `retryMillis > 0` 且 `timeoutMillis = 0`：非法，`SagaPolicy::try_from` 拒绝。
- `timeoutMillis > 0`：一个 step phase 的总预算，覆盖一次 `do_it` 或一次 `undo_it`，包含所有重试与 backoff。
- `retryMillis > 0`：固定 retry backoff；重试上限由总预算约束，不另设 `maxAttempts`。
- `SerializeFailed` 不重试。
- 前向 timeout / 预算耗尽触发既有逆序补偿；补偿 timeout / 预算耗尽走既有 saga dead-letter 路径。

## Typed step wrapper

`cargo xtask codegen` 对 saga payload 和每个 step `outputSchema` 生成 DTO，同时生成
`STEP_*: vocab::SagaStepBinding`、`STEPS` 和 `SPEC = SagaSpec::from_parts(CONTRACT, POLICY, STEPS)`。

业务实现 `consistency::SagaStep`：

- `BINDING` 必须指向生成的 step binding。
- `Output` 是该 step 的 typed output DTO；`eventexec` wrapper 负责序列化为 runtime `Vec<u8>`。
- `compensate(ctx)` 是必填 trait method；缺失即编译失败。
- `execute` 返回 `EngineErrorKind::Transient` 时映射为可重试 action error；`Permanent` / `Invariant` 映射为非重试 action failure。

外部组合根只能通过 `eventexec::TypedSagaActionFactory::builder(SPEC)` 按生成顺序注册 typed step factory。
`finish()` 校验 step 数量、顺序、名称和 output schema；缺步、多步或重排均 fail-closed。raw
`SagaAction` / `SagaActionFactory` 是 `eventexec` 内部 erased primitive，不从 crate root re-export。

## Activation 与 backend selection

- contract lifecycle 只描述 Saga definition；assembly manifest v2 `workflowActivations` 才描述 deployment
  activation。AssemblyLock v2 校验 definition identity，RuntimePlan v2 `workflowPlans` 携带 assembly-local
  闭值结果。`Topology`、环境配置和 resolver 均不是 activation/default truth。
- active Saga 的 requirement 集合固定为 typed actions、instance/journal/receipt/checkpoint/dead-letter store、
  lock/fencing、worker 与 probe。组合根必须先从已验证 plan 得到 requirements，再按 exact set 闭合能力。
- `bootstrap::sagaprojectiondeps::resolve` 仅为 requirements 之后的 topology backend selector：它在 demo 与
  durable PostgreSQL + Redis 之间选择 instance/journal/checkpoint/lock backend，不选择 Saga 是否激活，也不
  证明 typed action、receipt、dead-letter、worker 或 probe 已存在。
- production Saga registry/worker 只能消费 sealed `WorkflowRuntimePlan` 借出的 `SagaRuntimeView`；generated
  definition 存在不等于 activation。omitted/disabled Saga 不得注册 action、store、worker 或 probe，active
  Saga 缺少任一 requirement 必须在 provider 初始化前 fail-closed。

## 构造器

`eventexec` crate 的 saga 模块（执行器）必填依赖走构造器**必填位置参**（非 `Option` /
trait 对象），缺失即编译错误。`SagaExecutorDeps::new` 必须接收 `TypedSagaActionFactory`，禁止外部注入
raw erased factory。`SagaExecutorConfig` 必须从同一 generated `SPEC` 派生 `SagaWorkerIdentity`
（owner + `SagaContractId`）和 `SagaPolicy`，禁止无策略 constructor、builder option 或兼容 shim。

## Worker runtime

saga background worker 是生产运行形态，不替代 direct executor primitive：

- worker identity 必须是 `SagaWorkerIdentity`，禁止在组合根分别传裸 owner / contract id。
- worker 只做 polling/orchestration：`SagaTenantSource` 返回候选 tenant，`SagaInstanceStore::list_runnable`
  在 tenant scope 下列 `Ready` / `Running` / `Compensating` 且 lease 空闲或过期的 instance。
- worker 对 `Ready` 调 `run`，对 `Running` / `Compensating` 调 `resume`；正确性仍由 runtime lock +
  instance lease CAS + journal CAS 保证，listing 只是 advisory。
- readyz probe 名从 identity 单源派生：`saga_executor:<owner>__<contract_slug>`，不带 `_ready`。
- 无 live saga contract/factory registration 时不得注册假 worker 或假 probe。
- health 语义：无任务 / 成功 / 业务失败但已 durable 记录为 Healthy；tenant source、store、journal、DLX
  等基础设施错误为 Degraded；worker 停止或 panic 为 Unhealthy。

## 参考

- 扇出规则：`docs/rules/contract-fanout.md`
