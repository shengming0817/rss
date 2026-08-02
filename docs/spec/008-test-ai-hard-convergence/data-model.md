# Data Model: 证明、资格与工作项

## TestTargetEligibility

| 字段 | Owner | 规则 |
|---|---|---|
| package/name/path | Cargo manifest | 精确标识 test target |
| requiredFeatures | Cargo manifest | 决定 target 是否参与构建 |
| runtime environment | target 自身 | 缺失时 fail-closed，不 silent skip |
| execution frequency | canonical ExecutionProfile | 不复制 eligibility |

允许的 `#[ignore]` 仅限被父测试按精确 test name 调用的 subprocess child。

## ConformanceOwnership

| 实体 | 含义 |
|---|---|
| behavior | provider-neutral canonical assertion |
| driver | 实际 provider fixture/闭包 |
| enrollment | provider × capability 的 closed catalog row |
| residual | 只在具体 provider 可观测的失败模式 |

删除 adapter test 的必要条件：同一 failure mode 已由 behavior + 实际 driver 证明，且删除不会丢失 residual。

## ProductionAcceptanceCandidate

本规格不预先改变当前 T3 数据模型。若 policy PBI 接受 product-surface taxonomy，候选只有：

- `ProfileLifecycleJoin`：官方 profile 的真实 artifact lifecycle/critical path join。
- `AcceptedValueStreamJoin`：已接纳 value stream、真实 adopter 与 production artifact 的跨进程 join。

每个 carrier 变更继续使用 `docs/rules/project-scope.md` 定义的 evidence item：稳定 Evidence ID、canonical owner、
精确 assertion、T1/T2 prerequisites 与 candidate receipt、T3 incremental proof、复现入口、成本、change kind 和
完整 transition。运行 receipt 不落入静态 registry。

## AzureWorkItem

### Epic

- Work Item Type：`Epic`
- 标签：`epic,backlog,area-cross,pri-p1`
- 不携带 type/cx。

### PBI

- Work Item Type：`Product Backlog Item`
- 标签：`backlog` + 一个 area + 一个 type + 一个 pri + 一个 cx。
- 条件条目额外携带 `flag-cond` 并填写 Trigger。
- parent 使用 Azure 原生 Parent/Child。
- 依赖在 body 中使用真实 `Blocked-by: #N`；实施顺序由 Epic 的 `pm:epic-wave` 评论生成。

## 状态转换约束

- 外部计划逻辑 ID 只用于规格映射，不替代 Azure Work Item ID。
- 创建时状态保持 forge 默认值；不导入 `Deferred` 自定义状态。
- issue body 是需求真源；spec 只维护稳定 requirement、设计与 Work Item 映射，不维护实时状态。
