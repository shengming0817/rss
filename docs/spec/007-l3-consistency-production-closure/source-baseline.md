# L3 外部 source baseline 与当前差异

本文记录 #1912 吸收外部 delivery pack 时的内容身份、当前仓库比较基准与显式裁决。它是历史/需求证据，
不是当前 runtime inventory 或测试通过回执。

## 输入身份与可核查范围

| 项目 | 值 |
|---|---|
| 外部 snapshot 日期 | 2026-07-14 |
| 原始 archive SHA-256 | `6ca92dbba7b69688a1a7d1f7bee43437906051c9f0f689c8d12e02bf77357194` |
| delivery pack checksum manifest SHA-256 | `f536c7fcb692d4bf3a640116a33f511287683af8ba0474c940e7cadd85164bae` |
| 外部 `spec.md` SHA-256 | `d8a91275fbb555a15792e3b70badfbe5933ac5a7751905d06660912aefca412f` |
| 外部 `research.md` SHA-256 | `d9767ed4841f9db5e15256493b86f8c919b16a165d493abf4f6450b75e9e29ad` |
| 外部 `data-model.md` SHA-256 | `e078accc532f1c586df4c2f686782c2b608ede319635882ce2dae40edaac487e` |
| 外部 `traceability.md` SHA-256 | `ab619a7d67113b83d2e5804f96b8afdd2db63cb2af1d332f1946811cff4ec94e` |
| Git 源码比较锚 | `5fe2fefc854becb775887742c782e24398c9f5da`（近似，非 archive HEAD） |
| 吸收基准 | `origin/develop@24131f14460ecb799133330aed2c204b3317607b` |

外部 archive 不含 `.git`，且仓库未持有可重新下载该 archive 的稳定 URI 或完整 checksum manifest，所以上述 hash
只能标识 #1912 吸收时看到的输入，不能宣称第三方可独立重取或重做比对。Git commit 只作为源码比较锚，
不升级为原 archive 的“精确 HEAD”或可复现来源。delivery pack 制作环境未安装 Rust/Cargo，未运行 `cargo test`、
`cargo xtask verify`、integration shard 或 fault matrix；其中任何“通过”表述都只代表建议验收步骤。

## 当前代码相对 snapshot 的差异

| 主题 | 当前证据 | 2026-07-29 裁决 |
|---|---|---|
| Settings v3 Projection | [`contracts/http/settings/v3/contract.toml`](../../../contracts/http/settings/v3/contract.toml) 仍为 `draft` | 缺口仍成立；#1913–#1921 逐步闭合，#1912 不改 lifecycle |
| Settings v4 authoritative | [`contracts/http/settings/v4/contract.toml`](../../../contracts/http/settings/v4/contract.toml) 为 active LocalOnly | 作为不变 oracle，由 #1921 持有 regression |
| Billing Saga | [`contracts/saga/billing/v1/contract.toml`](../../../contracts/saga/billing/v1/contract.toml) 仍为 draft | #1923 只更新完整 receipt/retry/identity fixture；production assembly/runtime view/DB row/worker/probe/route 继续 omitted，产品 billing 属 External |
| Projection definition catalog | [`generated/src/event/mod.rs`](../../../generated/src/event/mod.rs) 保留由 codegen 派生的 definition/input ledger | #1914 已以 sealed workflow plan 将 definition 与 deployment activation 分离；production 下游不直接消费 raw catalog |
| Assembly 基础 | [`runtime-assembly-plan.md`](../../rules/runtime-assembly-plan.md) 与现有 assembly schema/codegen 已建立 typed plan/lock/catalog | 外部 overlay 的旧 runtime-root 坐标作废；WorkflowActivation 必须扩展现有单源，不另建 runtime truth |
| Blanket unsupported | #1914 删除 production `mark_all_generated_unsupported()` 与 `UnsupportedProjection` 分支 | 缺少 selected target 直接 fail-closed，不再以 blanket marker 伪装闭合 |
| Generation binding | [`0054_generation_bound_projection_registry.sql`](../../../adapters/postgres/migrations/0054_generation_bound_projection_registry.sql) 已在 snapshot 前存在；[`0078_expose_projection_input_generation_probe.sql`](../../../adapters/postgres/migrations/0078_expose_projection_input_generation_probe.sql) 不在 Git 比较锚中 | 后续 source/serving 设计必须复用当前两者，不能按旧 overlay 重建平行 registry |
| Projection source scope | [`projection_events.rs`](../../../adapters/postgres/src/projection_events.rs) 仍未形成 tenant/projection/binding-scoped production reader | 缺口仍成立；#1915/#1916 持有 capability 与 DB-side filtering |
| High-water | [`projection_control.rs`](../../../adapters/postgres/src/projection_control.rs) 当前仍通过分页读取求尾部 | 缺口仍成立；#1916 持有固定查询次数元数据 |
| Projection operator | [`projection replay/shadow/swap runbook`](../../runbooks/202607080828-1638-projection-replay-shadow-swap.md) 已存在 status/replay/swap | #1922 复用既有 surface，只补 pause/resume、SLO、容量与缺失语义 |
| Projection worker | [`crates/eventexec/src/projection.rs`](../../../crates/eventexec/src/projection.rs) 有 primitive，但无 production assembly lifecycle owner | 缺口仍成立；#1920 持有唯一 T3 lifecycle/join 证明 |
| Saga worker | production assembly/runtime view 不包含 billing Saga | 不得误称 billing active；#1923 守 fixture 与零 production adoption，#1926 闭合 production capability startup |
| Saga definition/version | [`docs/rules/saga.md`](../../rules/saga.md) 定义完整 pinned identity、sealed generated typestate、闭合 retry 与 exact registry/resume | #1923 将 identity 固定到 instance store；unknown identity fail-closed，无 latest/fallback/legacy 路径 |
| Saga durable receipt/recovery | #1923 仅在同次 run 内持有 typed receipt；崩溃后 receipt 缺失明确 fail-closed | protected durable receipt store 与 receipt+journal 原子提交仍归 #1924；unknown outcome、probe/repair 与 durable resume 仍归 #1925 |
| L3 fault evidence | 现有 fault journey 没有覆盖 spec 的 Projection/Saga 独立 hazard 集 | #1927/#1928 各持有唯一 T3 fault owner，不做笛卡尔积 |
| CI/验证范围 | [`project-scope.md`](../../rules/project-scope.md) 已新增 T1/T2/T3 最低充分验证矩阵；CI inventory 由 typed registry 派生 | 外部静态 lane/case/required-check 清单作废；#1929 只合并既有 planner/gate |
| Delivery semantics | [`eventbus.md`](../../rules/eventbus.md) 只承诺 at-least-once；active contract 也由 code gate 拒绝 unsupported delivery | “no exactly-once”解释为无 active/runtime 保证，不删除 draft/deprecated 前瞻 enum |

## 外部提案的显式裁决

| 外部提案 | 裁决 | Canonical owner |
|---|---|---|
| 整包运行 `apply-overlay.sh` | 拒绝；会复制旧 SpecKit pointer、GitHub issue、tasks、CI/architecture inventory | 本规范包只吸收需求与 proposal identity |
| `WorkflowDefinition.lifecycle = retired` | 拒绝在 #1912 引入；当前闭值仍是 draft/active/deprecated | contract schema/codegen；未来若需扩展另立 PBI |
| 独立 `kind = projection` | 条件延后 X02；首个 active Projection 稳定且有第二个真实 adopter 后再评估 | Epic #1911 Trigger |
| 新建 workflow/runtime truth | 拒绝；activation 必须进入现有 assembly manifest/plan/codegen | #1913/#1914 |
| 新建 parallel L3 CI gate | 拒绝；evidence 必须合并现有 typed planner/aggregate gate | #1929 |
| same-head GitHub required check 已可用 | 改为条件式：active forge 具备完整 CI 后启用；当前 Azure 只有窄 LocalOnly carrier | #1929 |
| LOC/Markdown/case-count blocking gate | 拒绝；只保留设计拆分与 review 信号 | #1912；[`project-scope.md`](../../rules/project-scope.md) |
| 全局 commit-order lock 立即删除 | 拒绝；容量越阈值后才触发 X01 | #1922 / Epic #1911 Trigger |
| 激活 billing 证明 Saga production-ready | 拒绝；billing 是 External 产品事实，fixture 不是 adopter | #1923（fixture/零 production adoption）/#1926（production capability closure） |
| exactly-once execution/delivery 声明 | 拒绝；只承诺 at-least-once 与 scoped idempotent business effects | [`eventbus.md`](../../rules/eventbus.md)、#1925 |

## 外部 spec/research/data-model/contract 的吸收分流

- spec 的 46 个 FR、10 个 NFR 保留原 ID；逐项 owner 见 [`traceability.md`](traceability.md)。
- research 的 R1–R13 按上表裁决；SpecKit 版本/feature pointer 不属于 L3 runtime requirement，未并入。
- data model 只吸收 identity/state/invariant proposal，见 [`data-model.md`](data-model.md)；精确 SQL/schema 由后续 PBI 的
  migration 与 typed schema 持有。
- `workflow-activation` proposal 归 #1913/#1914，operator proposal 归 #1922，Saga definition identity、
  typed receipt authoring、idempotency key 与 retry policy 归 #1923，durable receipt store/atomic journal 归 #1924，
  unknown-outcome/durable recovery 归 #1925，activation evidence 归 #1929；Markdown contract 不作为 enforcement carrier。
- 外部 142 tasks、GitHub issue/import scripts 和旧 PR roadmap 已由 Azure Epic #1911 与 PBI #1912–#1929 取代，
  不复制进仓库。
