# L0 一致性规则

本文件记录 L0/LocalOnly 的当前声明边界。机器真源仍是 `xtask` 的 typed manifest、R22 校验与
`generated::http::HttpSpec::effect_profile`；后续可执行证明见
`docs/spec/006-l0-l1-consistency-hardening/` 的 #1689+ 分解。

## Contract carrier

每个 `kind = "http"` 契约必须声明顶层 `[effectProfile]`：

```toml
[effectProfile]
effects = ["auth", "read"]
```

`effects` 是闭值集，只允许：

- `read`
- `auth`
- `projection`
- `write`
- `transaction`
- `outbox`
- `publish`
- `workflow`
- `saga`
- `reconcile`
- `worker`
- `cross-tenant-audit`

`[effectProfile]` 是 HTTP route effect 的声明 carrier，不证明 handler 实际行为。`serde` typed struct +
closed enum + `deny_unknown_fields` 负责 Hard 化未知字段和未知 effect；R22 负责 Medium 条件门：HTTP 必须声明、
非 HTTP 禁止声明、`effects` 必须非空且无重复。

## LocalOnly target

`consistencyLevel = "LocalOnly"` 的目标语义是 L0：不启动本地事务边界、不发布 outbox、不执行 workflow/saga、
不跑 reconcile/worker 控制环。严格 L0 读路径应只声明 `read`，需要鉴权时声明 `auth`，读模型字段投影声明
`projection`。

以下 effect 不属于严格 LocalOnly 读路径：

- `write`
- `transaction`
- `outbox`
- `publish`
- `workflow`
- `saga`
- `reconcile`
- `worker`
- `cross-tenant-audit`

当前 #1688 已把统一声明面生成进 active HTTP `HttpSpec::effect_profile`，并由 generated tests 锁住非空
effect 与 `audit.list-entries` 的混合 profile。上面的 strict-L0 行为证明仍未落到 runner、lint、route
binding 或 metrics；这些可执行门由 #1689/#1690/#1691/#1693 等后续分支实现。

## Known mixed route

`audit.list-entries` 现阶段显式声明 `auth`/`read`/`projection`/`write`/`cross-tenant-audit`。这不是把混合语义
认定为严格 L0，而是把真实行为暴露到 manifest carrier，避免文档声称与 contract 事实不一致。拆分或重分级留给
#1692。

## Follow-up boundary

#1687 的边界是 manifest authoring：

- 新增 `[effectProfile]` carrier。
- 迁移真实 HTTP `contract.toml`。
- R22 守住 HTTP 必填、非 HTTP 禁止、空/重复 effect、未知字段/枚举。

#1688 的边界是 generated metadata：

- `generated::http` 暴露 `EffectProfile` / `EffectKind` 闭 API。
- 每个 active HTTP `SPEC` 必填 `effect_profile`，缺 carrier 时 codegen fail-closed。
- 不做 route binding、lint、runner、metrics 或 journey。

#1689/#1690/#1691/#1693 等在 generated metadata 基础上补实际 L0 可执行证明。
