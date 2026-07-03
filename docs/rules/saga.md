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
`vocab::SagaRuntimePolicySpec`；组合根必须把它转换为 `eventexec::saga::SagaPolicy` 后注入执行器。

- `retryMillis = 0` 且 `timeoutMillis = 0`：禁用 retry/timeout，动作直接 await。
- `retryMillis > 0` 且 `timeoutMillis = 0`：非法，`SagaPolicy::try_from` 拒绝。
- `timeoutMillis > 0`：一个 step phase 的总预算，覆盖一次 `do_it` 或一次 `undo_it`，包含所有重试与 backoff。
- `retryMillis > 0`：固定 retry backoff；重试上限由总预算约束，不另设 `maxAttempts`。
- `SerializeFailed` 不重试。
- 前向 timeout / 预算耗尽触发既有逆序补偿；补偿 timeout / 预算耗尽走既有 saga dead-letter 路径。

## 构造器

`eventexec` crate 的 saga 模块（执行器）必填依赖走构造器**必填位置参**（非 `Option` /
trait 对象），缺失即编译错误。`SagaExecutorConfig::new` 必须接收 `SagaPolicy` 位置参，禁止无策略
constructor、builder option 或兼容 shim。

## 参考

- 扇出规则：`.claude/rules/rss/contract-fanout.md`
