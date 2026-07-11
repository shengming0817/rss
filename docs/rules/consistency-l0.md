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

## Port effect classification

Route 声明之外，注入面 port 使用两个正交的闭合轴分类：`Effect` 按其公开方法所能触达的**最强能力**归入
`read` / `auth` / `write` / `outbox` / `workflow`，`Privilege` 则区分普通本地能力与跨租户能力。混合读写
port 不能因为包含读方法就降级为 `read`；需要用于 LocalOnly 的读侧必须拆成独立窄 capability。

分类词汇由 `diport` 的 sealed `PortEffectClass` 与 `PortPrivilegeClass` 闭合；`diport`、`identity`、`audit`
分别用 owner-sealed 分类 trait 为本 crate 当前的 canonical dyn wrapper 固定关联 effect 与 privilege。外部 crate
不能为这些 wrapper 伪造、覆盖或扩展分类，`Arc` / `Box` 只透明继承内层分类。分类绑定 port 接口而非
provider 实现，域形 repo 仍留在所属域，避免 `diport` 反向依赖域 crate。

LocalOnly 注入面只允许 `read` 与 `auth`。`auth` 可包含限流、replay 防护等安全门控所必需的内部状态变化；
业务持久化、撤销写、outbox、直接 publish 与 workflow 不属于该例外。跨租户 read capability 保持准确的
`ReadEffect`，同时携带 `CrossTenantPrivilege`；LocalOnly 准入必须同时要求 `LocalPrivilege`，不能只检查
effect 后把跨租户读取当作普通本地 read。

该 marker 证明的是 canonical port 注入面，不声称覆盖 handler 直接使用文件系统、网络 client 或全局状态的
副作用；route state 的 fail-closed 消费与非 port 副作用检查由 #1693/#1694 继续闭合。

## Audit route split

`audit.list-entries` 只服务 ambient tenant scoped read，声明 `auth`/`read`/`projection`，不接受
`tenantId` query。跨租户行为由独立 LocalTx `audit.list-tenant-entries` 承载，避免把 durable audit write
藏在 L0 声明下。ambient `AuditDomain` 只注入 `AuditReadRepo`；demo/tests 可显式持有窄
`AuditWriteRepo`，生产 durable subscriber 则只能经 postgres-owner-sealed `AuditConsumerTxEffect`
把固定为 `WriteEffect` 的 `PgAuditConsumerTx` 擦除成执行器 handler；擦除方法自身要求关联类型等式，不依赖
旁路 smoke test。该 handler 保持 audit append 与 inbox commit 同一事务。两条路径均不向 ambient route
暴露可同时读写的宽 capability。

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

#1691 已补 owner-sealed port effect 分类与 audit 读写 capability 拆分；#1693 等继续在该 route proof 基础上
补 state 绑定与运行时的进一步可执行证明。
