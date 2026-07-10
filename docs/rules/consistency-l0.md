# L0 一致性规则

本文件记录 L0/LocalOnly 的当前声明边界。机器真源仍是 `xtask` 的 typed manifest、R22 校验与
`generated::http::HttpSpec::route.effect_profile()`；后续可执行证明见
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

统一声明面生成进 active HTTP `HttpSpec::route: HttpRouteEvidence`，并由
`cargo xtask consistency local-only-effects` 扫描全部 active HTTP LocalOnly 契约。该门只允许
`auth`/`read`/`projection`，其余 effect 均阻断，并接入 `verify --fast`、`verify` 与 `ci`。

## Audit route split

`audit.list-entries` 只服务 ambient tenant scoped read，声明 `auth`/`read`/`projection`，不接受
`tenantId` query。跨租户行为由独立 LocalTx `audit.list-tenant-entries` 承载，避免把 durable audit write
藏在 L0 声明下。

## Follow-up boundary

#1687 的边界是 manifest authoring：

- 新增 `[effectProfile]` carrier。
- 迁移真实 HTTP `contract.toml`。
- R22 守住 HTTP 必填、非 HTTP 禁止、空/重复 effect、未知字段/枚举。

#1688 提供了 generated metadata 的初始字段；#1690 已将其破坏式收敛为单一 carrier：

- 闭词汇迁入基础层 `vocab::{HttpConsistencyLevel,HttpEffectKind,HttpEffectProfile}`。
- 每个 active HTTP `SPEC` 只用必填 `route: HttpRouteEvidence` 携带 contract/path/method/auth/scope/
  consistency/effects；旧平行字段与 generated 镜像类型均已删除。
- `GeneratedEndpoint` / `GeneratedPrimaryEndpoint` 把 evidence 与 handler 原子绑定，并原样传播到 `RouteMeta`。

#1691/#1693 等继续在该 route proof 基础上补 port 与运行时的进一步可执行证明。
