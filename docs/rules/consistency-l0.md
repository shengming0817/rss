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
副作用；非 port 副作用与实际调用次数由 #1694 conformance testkit 继续闭合。

## Posture report

`cargo xtask consistency report --format json|md` 从 `generated::http::SPECS` 这一 active HTTP Hard 单源
枚举全部 route declaration，并复用 `canonical_serving_evidence` 与本页 LocalOnly state/port 分类器输出
production mount 和 effect proof。route owner 直接来自 generated `HttpRouteEvidence::owner()`，不得从
`ContractBinding::domain()` 反推。Domain source 扫描 canonical `crates/<owner>`；Framework source 由唯一
assembly `frameworkContracts` 声明定位，并扫描同一个 `bootstrap::FrameworkRoutes::register` funnel。
两种 owner 经闭合 `ServingScope::Domain | Framework` 进入同一个 LocalOnly proof evaluator；assembly 名不得
作为 domain owner 或 owner-sealed macro namespace 使用。无状态 route 不要求无关的 port proof；classified
Framework state 只允许 `diport` 全局 sealed capability，不能借用任意 domain-private 分类。JSON v1
面向 CI/PR artifact，Markdown 面向人工 review；两者由同一 typed
model 渲染、稳定排序，且不包含时间、主机、Git SHA、绝对路径或运行态 tenant/device 数据。

报告与 gate 的职责不同：posture finding 会令报告内 `status = "failed"`，但命令仍成功并输出完整 artifact；
采集、结构或序列化失败在 stdout 写入前非零退出；stdout 写入失败本身可能留下截断文件，消费方必须检查退出码
并完整解析 JSON。`consistency local-only-effects` 仍是阻断式 Medium gate，
继续消费相同 LocalOnly proof。非 LocalOnly route 只报告 declaration 与 mount，effect proof 明示
`declarationOnly/notApplicable`，不得解释为实际副作用证明或完整零信任 attest。非 port 副作用、实际调用及
runtime conformance 仍由 #1694 闭合，auth/scope posture 不属于本报告。

## LocalOnly route state funnel

`HttpRouteBinding<M, C>` 的 `C` 由 contract codegen 单源派生。`LocalOnly` endpoint 在类型层不提供普通
`with_state`，只能无状态 mount，或经 `with_classified_state` 注入实现 `ClassifiedRouteState` 的 state；后者的
关联类型必须满足 sealed `LocalOnlyAllowedEffect`（仅 `ReadEffect` / `AuthEffect`）与
`LocalPrivilege`。因此把已分类的 write/outbox/workflow/cross-tenant state 绑定给 LocalOnly route 在 Rust
类型层不可表达（Hard）。

跨域 state 对最强 port effect / privilege 的声明仍需关联其私有字段与 owner-sealed port 分类；Rust orphan
与 crate 依赖方向无法让 `httpserve` 的私有 sealed trait 同时开放给各域实现又禁止域内谎报。因此
`cargo xtask consistency local-only-effects` 对 production serving funnel（`Domain::init` /
`FrameworkRoutes::register`）到 `route_group → mount` 做 type-aware 源码闭环，拒绝普通 `with_state`、
未分类/不透明 state、marker 谎报及不可证明挂载（Medium CI 门；synthetic
red + compiling green anti-vacuity）。该门不从方法名猜能力，混合 port 始终按最强能力判定。

## LocalOnly runtime conformance

`testkit::local_only::assert_local_only` 在完整 await 一次 HTTP operation 前后，比较调用方必须同时提供的
`write` / `outbox` / `publish` 三维证据。存在运行时 seam 时，provider 必须持有维度化
`ProviderCounter<Dimension>`，conformance 只消费其共享只读 handle；任意 `FnMut() -> u64` 入口已删除，三个
marker 不可互换。能力已被 typed route/state funnel 排除时使用显式 `StaticExclusion::from_governed(&proof)`，
proof 必须来自 httpserve 的 canonical classified-state / stateless generated-route constructor。不得拿无关计数器、
恒零闭包、空 owner trait 或任意值冒充观察。跨 crate provenance 由 `consistency local-only-effects` 的 direct-shape
源码门与 synthetic red 验证，仍诚实定级 Medium，不虚称 Rust Hard proof。任一 runtime 计数增长即失败，
计数倒退也 fail-loud；非零 fixture baseline 合法。testkit 自身用
三类 synthetic red 分别证明断言不是恒真，并确保业务失败响应仍经过 post-check。

这里的禁止副作用专指 handler/domain 的业务持久化、业务 outbox 与直接 publish seam。完整 finalized route
生命周期仍会执行认证 finalizer；其 auth security audit 属于上文 `auth` effect 明确允许的安全门控状态变化，
不是业务 write/outbox/publish。conformance 测试必须为 auth finalizer 注入独立、可观测的 audit sink，并按
allow/deny 结果断言事件数量与安全字段，禁止用 Noop sink 隐藏；该 sink 不纳入三项业务副作用零增长 observer。

该断言是 `LOCAL-ONLY-RUNTIME-EFFECTS-01` 的 Medium CI 证据，与上面的 typed route/state Hard funnel
分工：类型层限制 handler 可获得的 capability，conformance 证明真实测试 seam 在成功、鉴权拒绝与合成读取
失败路径上没有发生禁止副作用。它只覆盖调用方接入的 observer，不是进程级 syscall sandbox，也不宣称检测
未插桩的文件系统、网络 client、全局状态或未等待的后台任务。

当前真实 route 覆盖：

- `identity.profile`：经 generated path 与带独立 auth audit sink 的 finalized Primary router 验证默认遮罩、
  显式 projection、未认证及拒绝路径；stateless LocalOnly binding 不提供 side-effect state，三类业务副作用均
  从同一 generated route proof 产生显式 static exclusion，不连接无关的 session capture。
- `audit.list-entries`：经 finalized Admin router 验证 ambient tenant scoped 成功读取、授权拒绝、认证 tenant 与
  ambient tenant 不匹配、非法 `tenantId` query，以及 repo 完整性合成失败；所有路径不写、不追加 outbox、
  不直接 publish，且 scoped route 不调用 admin repo / domain cross-tenant audit sink。finalized 生命周期产生的
  auth audit 由独立 sink 精确断言；Admin LocalOnly permission、ambient tenant binding、PDP 与 audit 在同一
  finalizer 决策中收口，handler 只消费 `AuthorizedSubject`。其中 write counter 由 finalized route 实际持有的
  repo provider 所有，observer 只取得同一 counter 的只读 handle；outbox / publish 从
  `AuditListHandlerState: ClassifiedRouteState<Effect = ReadEffect>` 的 proof 产生 static exclusion。synthetic red
  让该 repo provider 注入一次 write，必须由共享 handle 捕获；decoy provider/handle 与漏 `record()` 形状由源码门拒绝。

独立的 `audit.list-tenant-entries` 是 LocalTx 跨租户 audited read，按设计先写 durable audit，不属于本
LocalOnly conformance suite。

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

#1691 已补 owner-sealed port effect 分类与 audit 读写 capability 拆分；#1693 在 typed route proof 基础上
补齐 LocalOnly state Hard funnel 与 Medium 注入面闭环；`LOCAL-ONLY-RUNTIME-EFFECTS-01` 再补非 port 的
运行时 conformance 证明。
