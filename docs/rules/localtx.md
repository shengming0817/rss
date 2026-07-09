# LocalTx 规则

本文件记录 L1/LocalTx 的当前声明边界。机器真源仍是 `xtask` 的 typed manifest、R22 校验与
`generated::http::LOCAL_TX_SPECS`；后续可执行覆盖率、runner、metrics 与 journey 见
`docs/spec/006-l0-l1-consistency-hardening/` 的 #1697+ 分解。

## Contract evidence

`consistencyLevel = "LocalTx"` 必须是 `kind = "http"`，并声明完整 `[capabilities.localTx]`：

```toml
[capabilities.localTx]
boundary = "single-domain"
txModel = "tenant-scoped-uow"
retry = "bounded-transient"
commitUnknown = "not-retryable"
```

旧的 boundary-only 形态不再接受。字段和取值均为闭集：

- `boundary = "single-domain"`：一个 LocalTx 只覆盖单一域 crate 拥有的本地持久化边界。
- `txModel = "tenant-scoped-uow"`：事务模型是租户作用域 Unit of Work，tenant scope 必须来自上下文/注入边界，
  不从 HTTP body 取得。
- `retry = "bounded-transient"`：只允许有界瞬态重试；每次重试必须重建完整 transaction scope，不复用失败事务。
- `commitUnknown = "not-retryable"`：commit outcome unknown 不能当普通 transient 自动重放副作用。

`serde` typed struct + closed enum + `deny_unknown_fields` 负责 Hard 化缺字段、未知字段和未知枚举；R22 负责
Medium 条件门：只有 L1 允许 localTx block，且 L1 必须声明上述完整证据。

## Runtime meaning

LocalTx 表示一次 HTTP handler 内的单域、租户作用域本地原子写。它不表示跨域事务，不表示 outbox 发布已兑现，
也不表示 saga/reconcile/workflow 已接线。

`commitUnknown = "not-retryable"` 的含义是：当提交结果未知时，不允许按普通 transient path 自动重放整个副作用序列。
后续 runtime/status/metrics 可以把该状态细分，但默认治理语义必须 fail-closed。

## Follow-up boundary

#1687 的边界是 manifest authoring：

- 补齐 LocalTx 三个新增字段。
- 迁移真实 L1 HTTP `contract.toml`。
- R22 守住 L1 完整证据与 stray capability。

#1688 的边界是 generated metadata：

- `generated::http` 暴露 `LocalTxSpec` 与 LocalTx 闭枚举。
- LocalTx active HTTP `SPEC` 必填 `local_tx: Some(...)`，非 LocalTx 为 `None`。
- `LOCAL_TX_SPECS` active-only 派生当前 L1 HTTP contract 子集。
- 不做 LocalTx runner、coverage gate、metrics label 或 domain proof。

#1697 建 LocalTx coverage gate；#1698 收口 LocalTx vocabulary/closed labels；#1699 以后才接 Postgres runner 与真实
域路径证明。
