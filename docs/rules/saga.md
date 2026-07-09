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

## 构造器

`eventexec` crate 的 saga 模块（执行器）必填依赖走构造器**必填位置参**（非 `Option` /
trait 对象），缺失即编译错误。`SagaExecutorDeps::new` 必须接收 `TypedSagaActionFactory`，禁止外部注入
raw erased factory。`SagaExecutorConfig::new` 必须接收 `SagaPolicy` 位置参，禁止无策略 constructor、builder
option 或兼容 shim。

## 参考

- 扇出规则：`.claude/rules/rss/contract-fanout.md`
