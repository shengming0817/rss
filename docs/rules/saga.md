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
- retry 和 timeout 是合法非负 duration。

编排逻辑落在域 crate 的 saga 模块；其 `kind: saga` 契约的 `consistencyLevel` 必须为 L3。

## 构造器

`eventexec` crate 的 saga 模块（执行器）必填依赖走构造器**必填位置参**（非 `Option` /
trait 对象），缺失即编译错误。`Clock` 是构造器
位置参（trait 对象 / 泛型），禁止用 builder option 或 Config 字段传 clock、禁止默认取系统时钟。

## 参考

- 扇出规则：`.claude/rules/rss/contract-fanout.md`
