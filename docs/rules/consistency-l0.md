# L0 一致性规则

本文件只写 L0/LocalOnly 的声明与证明边界。机器真源是 `xtask` typed manifest、R22、generated route
evidence、typed production mount 与 LocalOnly 静态/运行时检查；本文不维护 gate inventory，
也不以文档完成态代替持续 enforcement。

## Proof chain

采用顺序固定为：contract `effectProfile` → generated route evidence → production route/state mount →
owner-sealed port effect/privilege → runtime conformance。

任一层缺失、重复、未知、孤立、歧义或与上一层不一致都 fail-closed；
不得用手写 allowlist、字符串 marker、任意 counter 或报告文本补洞。

各级验证的覆盖面不得互相冒充：

- 固定 9 门的 `verify --fast` 不拥有 LocalOnly 证明。静态闭环由 affected `make ci` 的 Consistency
  domain 选择，或显式运行 `consistency local-only-effects`；两者都不运行 conformance、不连接 Postgres。
- 完整 `verify` 与远端 `test-affected` 都执行 conformance；远端 required evidence 由 `test-affected` producer
  独占成败，唯一公开直接入口是 `cargo xtask ci localonly-evidence --output <path>`。它不声称运行真实 backend。
- 真实 Postgres 只承载相邻 L1 的 adapter/journey 验收；**L0 准入本身不能借 live 环境缺失而宽限**。

跨租户 capability 即使是 read 也必须携带 `CrossTenantPrivilege`，因此不满足 LocalOnly 所需的
`LocalPrivilege`。posture report、命名约定或普通 `ReadEffect` 都不能把跨租户访问升级成零信任 attest。

## Contract carrier

每个 `kind = "http"` 契约必须声明顶层 `[effectProfile]`，`effects` 是闭值集：

```toml
[effectProfile]
effects = ["auth", "read"]
```

闭值集为 `read` / `auth` / `projection` / `business-write` / `business-transaction` / `outbox` /
`publish` / `workflow` / `saga` / `reconcile` / `worker` / `cross-tenant-audit`。

`[effectProfile]` 是 HTTP route effect 的声明 carrier，**不证明 handler 实际行为**。
载体：`serde` typed struct + closed enum + `deny_unknown_fields` 把未知字段与未知 effect Hard 化；
R22 是 Medium 条件门（HTTP 必须声明、非 HTTP 禁止声明、`effects` 非空且无重复）。

## LocalOnly business effect 语义

- LocalOnly 准入只允许 `auth` / `read` / `projection`，其余 effect 一律阻断。
- LocalOnly 证明的是**业务持久化、outbox、publish 为零**；它不表示进程完全无副作用。
- LocalOnly 允许 provider-owned read-path transaction，用于在同一连接上建立 tenant-scoped read context；
  该事务不改变 route 的 business effect 分类。
- provider read-path transaction 必须原子开启只读事务后再设置 tenant scope、执行查询、结束事务；
  不得 fallback 到 writer pool，也不得先开普通事务再补只读声明。
  它保证只读，但**不承诺稳定 snapshot**——隔离级别仍是数据库默认值。
- correctness cache、metrics/trace 与 auth security audit 属于 operational state，不计入 business effect，
  但仍受各自的安全、可观测性与测试约束。
- 跨租户 durable audit 必须声明业务写与跨租户审计 effect 并保持 LocalTx，不得藏在 L0 声明下。
- 严格 L0 读路径应只声明 `read`，需要鉴权时声明 `auth`，读模型字段投影声明 `projection`。
- 载体：`cargo xtask consistency local-only-effects`（接入 affected `make ci`、完整 `verify` 与远端 typed owner）。

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.8.6
ref: launchbadge/sqlx sqlx-postgres/src/transaction.rs@v0.8.6

## Port effect classification

注入面 port 使用两个正交闭合轴分类：`Effect` 按其公开方法所能触达的**最强能力**归类，
`Privilege` 区分普通本地能力与跨租户能力。

- 混合读写 port 不能因为包含读方法就降级为 read；需要用于 LocalOnly 的读侧必须拆成独立窄 capability。
- 分类词汇由 sealed class 闭合，各 owner crate 为本 crate 的 canonical dyn wrapper 固定关联分类。
  外部 crate 不能伪造、覆盖或扩展分类；`Arc` / `Box` 只透明继承内层分类。
- 分类绑定 port 接口而非 provider 实现；域形 repo 仍留在所属域，避免基础层反向依赖域 crate。
- 授权读与 mutation 必须拆成不同 port：读口只暴露读方法，binding / attribute mutation 只由各自的
  lifecycle 或 write port 暴露，不提供 alias、shim 或双路径。
- LocalOnly 注入面只允许 read 与 auth。`auth` 可包含限流、replay 防护等安全门控所必需的内部状态变化；
  业务持久化、撤销写、outbox、直接 publish 与 workflow 不属于该例外。
- 跨租户 read capability 保持准确的 `ReadEffect` 同时携带 `CrossTenantPrivilege`；
  LocalOnly 准入必须同时要求 `LocalPrivilege`，不能只检查 effect 就把跨租户读当作普通本地 read。
- 该 marker 证明的是 canonical port 注入面，**不声称**覆盖 handler 直接使用文件系统、网络 client
  或全局状态的副作用；非 port 副作用与实际调用次数由 runtime conformance 闭合。

## LocalOnly route state funnel

- 路由绑定的一致性级由 contract codegen 单源派生。LocalOnly endpoint 在类型层不提供普通 `with_state`，
  只能无状态 mount，或注入实现 classified state trait 的 state；后者的关联类型必须满足 sealed
  allowed-effect 约束与 `LocalPrivilege`。
- 因此把已分类的 business-write / outbox / workflow / 跨租户 state 绑定给 LocalOnly route
  在 Rust 类型层不可表达（Hard）。
- 跨域 state 对最强 port effect / privilege 的声明仍需关联其私有字段与 owner-sealed 分类。
  Rust orphan 规则与 crate 依赖方向无法让 `httpserve` 的私有 sealed trait 同时开放给各域实现又禁止域内谎报，
  故对生产 serving funnel 到 mount 的路径做 type-aware 源码闭环，拒绝普通 `with_state`、
  未分类或不透明 state、marker 谎报及不可证明挂载（Medium，含 synthetic red 与 compiling green anti-vacuity）。
- 该门不从方法名猜能力，混合 port 始终按最强能力判定。

## Posture report

- report 从 active HTTP generated 单源枚举全部 route declaration，复用同一 LocalOnly 分类器输出
  production mount 与 effect proof。route owner 直接来自 generated evidence，不得从 contract binding 反推。
- 两类 owner scope 经闭合枚举进入同一个 proof evaluator；assembly 名不得作为 domain owner 或
  owner-sealed macro namespace 使用。
- 无状态 route 不要求无关的 port proof；框架侧 classified state 只允许全局 sealed capability，
  不能借用任意 domain-private 分类。
- 输出由同一 typed model 渲染、稳定排序，且不包含时间、主机、Git SHA、绝对路径或运行态 tenant/device 数据。
- report 显式区分「source receipt 已注册」与「本次执行过测试」：registered 只表示 canonical receipt site
  可发现。missing 产生 finding 并令顶层状态失败。不提供旧 schema 的 alias 或双写。
- **报告不是 gate**：posture finding 令报告内状态失败，但命令仍成功并输出完整 artifact；
  采集、结构或序列化失败在写出前非零退出；写出失败可能留下截断文件，消费方必须检查退出码并完整解析。
- 非 LocalOnly route 只报告 declaration 与 mount，effect proof 明示不适用，不得解释为实际副作用证明
  或完整零信任 attest。auth/scope posture 不属于本报告。

## Consistency / effect breaking review

- `cargo xtask contract breaking --against <git-ref>` 直接比较 base 与 working 的 typed manifest projection，
  不读取 posture report artifact。
- LocalOnly 与任一 non-L0 等级的双向变化显式报告；effect 集合增删逐项报告。
  声明重排不产生 finding，替换同时产生 removal 与 addition。
- 这三条规则当前是固定 review-only warn：active/deprecated 都保留 finding，draft 跳过。
  non-L0 等级之间的等级变更及其它 active breaking 仍 deny。
- 纯 review finding 不直接变成 wire deny，但 active finding 未确认时 gate fail-closed。
  确认方式是在承载变更或后续 commit body 中加入精确 `Contract-Review-Ack` trailer；
  任一 finding 或 base 漂移都会使旧 trailer 失效。
- 该窗口不提供 flag、环境变量或时间开关；未来收紧必须显式修改闭枚举 rule policy 与 synthetic red。
- base/working 两侧缺失、空或重复 effect 均 fail-closed，未知 effect 由 typed serde 拒绝。
- 历史关系依赖 Git IO，故执行门评级 Medium；effect/consistency 闭枚举、穷举 wire 映射与默认 deny policy
  构成 Hard 内核。完整 lifecycle 与威胁矩阵见 ADR-008。

## LocalOnly runtime conformance

- active LocalOnly 集合由 codegen 从 active manifest 同源生成，每个 active module 同时获得专用
  conformance marker。route 失活或改为非 L0 时 marker 消失，canonical receipt site 在编译期失败（Hard）。
- opaque conformance receipt 只能由完整 post-check 成功路径铸造，构造器与字段不公开。
- 跨 crate 登记闭环要求每个 receipt 位于无 cfg/ignore 的 canonical test 顶层 fail-loud 语句，
  使用完整限定 marker 与同模块 spec id，并断言 receipt 的 contract id。
  decoy/bait、错 route/path/method/provider、空或错误的 finalized routes、cfg/sibling bait、
  async/closure/spawn、控制流、macro、wrapper/alias 与忽略 Result 的形状均 fail-closed，
  并与 manifest / generated active registry 做 exact-set 对账；缺少 receipt 同样阻断。
- **源码登记与本次执行证据严格分离**：affected `make ci` 或显式 direct gate 只运行静态 source receipt 门，
  不产生运行证据。
  执行证据由 `test-affected` 内的 producer 从静态 typed inventory 单源派生目标与 exact non-empty filter；
  `ci localonly-evidence` 是该 producer 的唯一公开直接入口，
  只有测试全部成功且 active/source/executed 三个 contract ID 集合完全相等，才能原子写出报告。
- marker 必须来自 post-check 成功路径与 runner-owned 私有目录；missing、extra、duplicate、malformed、
  symlink、stale、wrong job/revision 与 equal-count-wrong-set 均拒绝。
  报告不接受旧版本、别名或 count-only fallback。
- 跨进程 marker 与执行事实是带 synthetic red / anti-vacuity 的 Medium 证明，
  **不虚称** syscall sandbox 或 Hard 端到端 attestation。

runtime 断言的形状要求：

- 在完整 await 一次 HTTP operation 前后，比较调用方必须同时提供的业务写 / outbox / publish 三维证据。
- 存在运行时 seam 时，provider 必须持有维度化 counter，conformance 只消费其共享只读 handle；
  三个维度不可互换，不接受任意闭包入口。
- 能力已被 typed route/state funnel 排除时使用显式 static exclusion，其 proof 必须来自对**将要 finalize 的
  同一 routes** 做 exact evidence membership 检查的 canonical constructor。
  不得拿空 routes、另一条 route、无关计数器、恒零闭包、空 owner trait 或任意值冒充观察。
- 任一 runtime 计数增长即失败，计数倒退也 fail-loud；非零 fixture baseline 合法。
- testkit 自身必须用 synthetic red 证明断言不是恒真，并确保业务失败响应仍经过 post-check。
- 禁止的副作用专指 handler/domain 的业务持久化、业务 outbox 与直接 publish seam。
  finalized route 生命周期仍会执行认证 finalizer，其 auth security audit 属于 `auth` effect 明确允许的
  安全门控状态变化。conformance 必须为该 finalizer 注入独立可观测的 audit sink，
  并按 allow/deny 结果断言事件数量与安全字段，禁止用 Noop sink 隐藏；该 sink 不纳入三项业务副作用 observer。
- 载体：`LOCAL-ONLY-RUNTIME-EFFECTS-01`（Medium）与 typed route/state Hard funnel 分工——
  类型层限制 handler 可获得的 capability，conformance 证明真实测试 seam 在成功、鉴权拒绝与合成读取失败
  路径上没有发生禁止副作用。它只覆盖调用方接入的 observer，不是进程级 syscall sandbox。

ref: casbin/casbin-rs src/management_api.rs@fc425d4a2522ab1ee97e3bd8fada8b3ef45dc1a9

## Audit route split

- ambient tenant scoped audit read 声明 `auth` / `read` / `projection`，不接受 tenant query 参数。
- 跨租户行为由独立的 LocalTx 路由承载，避免把 durable audit write 藏在 L0 声明下。
- ambient audit domain 只注入读 repo；生产 durable subscriber 只能经具体 consumer 类型进入 runtime assembly
  私有的 transactional handler，该 handler 保持 audit append 与 inbox commit 同一事务。
- 两条路径均不向 ambient route 暴露可同时读写的宽 capability。

## Failure and adoption semantics

新建或修改 LocalOnly route 的顺序：声明闭合 effect → 生成 route evidence → 通过 generated endpoint 绑定
唯一 production mount → 有状态 handler 使用 classified state、注入 port 按最强 effect 与 privilege 分类 →
补成功、鉴权拒绝与读取失败路径的 runtime conformance。
**不要先写 handler 再用文档或 marker 猜测能力。**

- 静态门拒绝：缺失/空/重复/未知 effect、stray capability、普通 `with_state`、未分类或不透明 state、
  生产 mount 缺失/重复/歧义、owner 或 provenance 不可证，以及伪造 marker。
- 运行时 conformance 拒绝：三维计数增长或倒退，并以 synthetic red 证明 observer 非恒真。
- `consistency report` 的 process success 只表示 artifact 生成成功；verdict 必须从其输出完整解析，
  阻断 verdict 仍由 `local-only-effects` gate 给出。
