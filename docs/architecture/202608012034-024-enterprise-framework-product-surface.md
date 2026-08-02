# ADR-024：企业开发框架目标、产品面与官方技术栈闭包

- **Status**：Accepted
- **Date**：2026-08-01
- **Last updated**：2026-08-02
- **Scope**：[`project-scope.md`](../rules/project-scope.md) 的项目目标与目标验收边界

## Context

RSS 已具备 contract/codegen、静态 assembly、L0–L4 primitive、多租户、安全、可观测与本地验证能力。项目目标升级为
面向 Rust 企业应用的 AI 友好型企业开发框架后，需要统一公共消费面、官方技术栈闭包和分阶段完成条件。

## Decision

### 产品面

| 产品面 | 版本承诺 | Owner |
|--------|----------|-------|
| Standalone Component | 独立 SemVer | 低依赖基础能力的公开 crate |
| Platform Public | 协调版本 | contract/handler、可信 context、configuration、lifecycle 与 runtime façade |
| Official Integration | 封闭支持矩阵 | 成熟上游之上的 tenant、安全、一致性、health 与 lifecycle 适配 |
| Reference Extension | 第一方纵向 consumer | Identity、Settings、Audit 与已接纳的 L3/L4 slice |
| Internal Implementation | 仓内重构边界 | generated/runtime internals、provider catalog 与 composition detail |
| Tool / Verification | 仓内执行边界 | xtask、lint、testkit、journey 与 fault/recovery evidence |

公开面由 committed public-api baseline、contract/schema artifact 和真实外部 consumer 共同界定。`pub` 可见性只表达 Rust
访问边界，版本承诺由产品面 owner 与 release artifact 确定。

### 官方 profile

首批官方 profile 按依赖关系形成闭包：

1. **core**：runtime lifecycle、HTTP、PostgreSQL LocalTx、external OIDC/verified Principal、TenantContext/RLS/authz、
   tracing/health/readiness。
2. **eventing**：`core` 加 AMQP、outbox/inbox、settlement、DLQ、idempotency 与 recovery。
3. **device-security**：在真实 device/workload identity consumer、credential/replay/fencing、production assembly 与
   operator recovery 闭合后激活。

profile identity、dependency closure、provider capability、typed config 与 runtime inventory 从 assembly/profile metadata
派生。profile 的支持承诺由真实 provider conformance、production join evidence 和 release artifact 共同激活。

本 ADR 决定的 profile → artifact 产品映射如下；它只决定产品 owner，不替代 `assemblies/artifacts.toml` 的当前 artifact
事实，也不在本 policy PBI 中切换 canonical carrier：

| Official profile | Designated assembly | Binary / image artifact | 当前状态 | Journey 边界 |
|------------------|---------------------|-------------------------|----------|--------------|
| `core` | `assemblies/runtime` | `server::server` / Docker `runtime` target | candidate；当前 runtime 尚未形成 core-only closure | 尚无 profile canonical journey；legacy runtime smoke 只作迁移 evidence |
| `eventing` | `assemblies/runtime` | `server::server` / Docker `runtime` target | candidate | 尚无 profile canonical journey；SettingsOnly 四项 evidence 是迁移来源，不是 eventing owner |
| `device-security` | 未指定 | 未指定 | conditional；未满足激活条件 | 零 T3，不得预建 artifact/journey |

`core` 与 `eventing` 可以复用同一 release image，但必须各自通过闭值 profile configuration/plan 证明依赖闭包；不能以同一
binary/image 存在推导两个 profile 均已激活。`identityaudit` 与 `settingsonly` 不映射为 official profile artifact。

### T3 产品授权

T3 从官方 product profile 的产品承诺派生，不从代码结构派生。T3 owner 是闭集：`ProfileLifecycleJoin` 只证明 profile
artifact 的 config/startup/readiness/drain/restart，`AcceptedValueStreamJoin` 只证明该 profile 明确接纳的真实纵向
value stream 在 production process/provider 组合后独有的 join hazard。assembly、domain、contract、provider、adapter、
consistency level、binary/image、`profile = "production"` 或 `supported` lifecycle 都不能单独授权 T3，也不得创造第三类 owner。

GA 主线的可授权产品面只有 `core` 和 `eventing`。profile 状态依次为：ADR 接纳的 `candidate`；scope freeze 后由正式
GA-hardening acceptance trigger 逐项放行的 `hardening-authorized`；designated artifact、真实 provider conformance、
T1/T2 前置和 candidate production join evidence 全部真实通过后原子进入 `active`。candidate evidence 在激活前不是
canonical owner、不能进入普通 PR required selection，也不能替换 legacy carrier；这消除“active 才能建 T3、但激活又需要
T3”的循环。activation transition 必须把该 profile 唯一 designated production artifact 原子提升为唯一 canonical
production artifact，不允许 candidate 与 active artifact 并存为两个 owner。
`device-security` 不属于当前 active T3 范围；激活它必须先经独立 scope/ADR PR。L3 是一致性语义，
不是独立产品 profile；真实 L3 value stream 只能在产品承诺已接纳后，作为 `eventing` 的显式 evidence
item 候选，其 owner 只能是 `AcceptedValueStreamJoin`，不得创建独立 L3 T3 产品面。

每个官方 profile 最多有一个 canonical production artifact 和一个 canonical journey carrier。多个 join hazard
可共享 target、fixture、image 与基础设施，但每个 hazard 必须保持稳定 Evidence ID 和精确可选 selector。
T3 的新增、扩展、替换、重新声明或退役必须使用独立 issue 和独立 PR，并先完成
[`project-scope.md`](../rules/project-scope.md#production-acceptance-evidence-plan-与-carrier-replacement) 要求的必要性证明；
不得与 profile/assembly、domain 功能或 provider 实现混在同一 issue/PR。

### GA maturity 阶段

1. **Hardening trigger 前**：默认禁止成熟度实施；scope freeze 本身不放行 SLO、容量/性能、dashboard/alert、evidence
   聚合、closeout gate、soak/fault matrix 或 T3 扩展。
2. **GA hardening**：只按正式 acceptance trigger 逐项放行 `core`/`eventing` 的最小 SLI、一个固定环境容量测量、必要
   runbook，以及上述两类闭值 owner 的 candidate T3；每项仍需独立 issue/PR 和固定预算。
3. **GA 后**：只基于真实流量调优 RSS 自有指标、error budget、paging threshold、容量与运行参数；autoscaling、多区域
   delivery、商业 tenant 分级和托管监控继续属于 External，不因 GA 完成自动进入 RSS。

Hardening trigger、例外字段与 no-new-work closeout 统一遵循 `project-scope.md`，复用现有 `flag-cond`/`Trigger`，不建立
新的 maturity registry、evidence database、selector 或 gate。candidate revision 的 same-head receipt 只保留在 issue/PR
review evidence，不写入 artifact catalog、generated inventory 或其它 committed static registry。

### Reference Extension 与迁出边界

Identity、Settings 与 Audit 是 RSS 的第一方 Reference Extension，用于验证 Platform Public、Official Integration
和官方 profile 的真实消费边界；它们不是独立官方 production profile，也不因为拥有 assembly 而获得新的
T3 产品面。

`assemblies/identityaudit` 与 `assemblies/settingsonly` 的长期定位是迁出 RSS 核心产品/发布面，成为独立的
第一方外部 reference consumer。迁出不立即执行：在 `core`/`eventing` canonical artifact、稳定 Platform
Public/adapter SPI、外部 consumer build/upgrade baseline 全部闭合前，两个 assembly 作为过渡 reference carrier 保留，
但立即冻结新产品能力、新 provider 组合和独立 T3 扩展。

迁出时必须由单独弃用/迁移决策记录目标仓库、版本边界、consumer build、release ownership 和回退方式。
Identity、Settings、Audit 的 domain/contract 能力不因 assembly 迁出而自动删除或迁仓；它们仍按
[`project-scope.md`](../rules/project-scope.md) 的 `Complete`/`Freeze` 边界处置，后续迁移需另行决策。

### 现有 T3 基线与处置

下表是本 ADR 接纳时的迁移基线，用于阻止现有 carrier 被误解为新产品授权；它不是新 registry、测试调度源或
Markdown enforcement carrier。实际 selector 与运行结果仍由现有 Cargo/CI/artifact carrier 拥有，same-head receipt
只进入 issue/PR review evidence。

| 现有载体 | 已有证明 | 当前成熟度 | 后续处置 |
|----------|----------|------------|----------|
| `RSS_SMOKE_MODE=release ./deploy/smoke.sh`（legacy selector，尚无稳定 Evidence ID） | `runtime` release image、Compose 依赖、readiness、部分 outage 与 drain 组合 | **已完成（legacy runtime 闭环）** | **保留并缩减**；在 `core`/`eventing` carrier 激活前继续是 canonical legacy evidence；profile carrier 激活时把 production lifecycle/join owner 原子切换到有稳定 Evidence ID 的 canonical journey，并将本 selector 降为非 T3 packaging regression，只检查 image build、entrypoint、config load 与进程可启动，不再作为 required production acceptance、不得独立证明 readiness/drain/outage；不追补 T3 ID |
| `settingsonly_production_artifact`：`SETTINGSONLY-T3-INPUT-READY-01`、`SETTINGSONLY-T3-L2-JOIN-01`、`SETTINGSONLY-T3-SIGKILL-01`、`SETTINGSONLY-T3-SIGTERM-01`、`SETTINGSONLY-T3-PROJECTION-SHADOW-START-RESTART-DRAIN-01`、`SETTINGSONLY-T3-PROJECTION-FATAL-EXIT-READINESS-01` | exact image、mount/SPIFFE/readiness、PG→outbox→AMQP→inbox、restart/redelivery 与 drain、projection shadow start/restart/drain 与 fatal-exit readiness | **已完成（六个精确可选 T3 evidence item）** | **冻结后迁移**；不再新增 case/provider/fixture，作为 `eventing` carrier 的迁移来源；候选真实通过后原子切换 owner，删除 SettingsOnly 独立 T3 身份，参考应用按上节条件迁出 |
| `identityaudit_login_audit_ready_sigterm_drain`（legacy selector，尚无稳定 Evidence ID） | 真实 PostgreSQL/RabbitMQ/Redis 上的 login→audit 纵向语义、readiness、inventory 与 drain | **已完成（Reference Extension 纵向验收）** | **冻结、缩减并迁出**；业务语义保留为 T2/reference acceptance，通用 production join 由 `eventing` 接管；不再作为独立 T3 产品 owner，参考应用按上节条件迁出，且不为 legacy selector 追补独立 T3 ID |
| `two_replicas_survive_provider_outage_and_graceful_replacement`（legacy selector，尚无稳定 Evidence ID） | 同代双副本、provider outage、surviving-replica continuity 与 graceful replacement | **已完成的既有 T3，但不是当前 GA 承诺** | **冻结**；不扩展 rolling/mixed-generation/HA matrix，后续从 GA required lane 移出；只有 RSS 明确接纳多副本 SLO 时才可由独立 scope/ADR 恢复，否则随外部 delivery acceptance 迁出，且不为当前 selector 追补 GA T3 ID |
| `production_runtime` Rust test target | manifest 与 shell smoke policy、fail-closed/skip/build identity 的静态行为 | **已完成，但不是 T3** | **缩减为 T1/T2 owner**；保留静态 policy 验证，不再作为独立 production T3；激活前的 legacy runtime evidence 与激活后的 profile canonical journey 按上行 transition 分别拥有 production acceptance，降级后的 packaging smoke 不成为第二 owner |
| `runtime_inventory` Rust test target | assembly/RuntimePlan 形状、授权 route、probe posture 与进程内 listener seam | **已完成，但不是独立 T3** | **缩减为 T1/T2 owner**；保留 contract/authz/probe seam，profile inventory 的真实组合断言并入 `core`/`eventing` journey，不单独拉起一套 T3 |

除上表外，L3/L4 primitive、draft contract、provider conformance、fault matrix、performance、soak 和 chaos 都不是
当前 active T3 产品授权。它们可继续按 T1/T2 或现有 release/nightly 边界维护，但不得自动生成新 T3
target、case、fixture、service 或 image。

### 实施前判定

每个实施 PBI 在编码前完成：

- `ai-robust.md` 的 enforcement 判定；
- `dependency-policy.md` 的依赖与自研判定；
- primary capability owner、真实 consumer、公开面影响和最低充分 T1/T2/T3；
- production acceptance carrier 变更时的 evidence plan。

如果结论需要 T3，能力 PBI 只记录阻塞与前置条件；T3 carrier 另建独立 issue，并通过独立 PR
交付。如果新 hazard 超出当前官方 profile 承诺，先完成独立 scope/ADR PR，不得在实施 issue 中自行扩展。

### 实施顺序

| Wave | Outcome | 主证明 |
|------|---------|--------|
| 1 | 产品面 metadata、Platform Public allowlist、外部 consumer baseline、统一启动入口 | public-api/semver、external consumer compile、T1/T2 |
| 2 | `core` profile 的 config、composition、lifecycle、diagnostic 与 production join 闭环 | provider conformance、assembly identity、readiness/drain/restart T3 |
| 3 | `eventing` profile 的 L2 producer/consumer/recovery 闭环 | LocalTx/outbox/inbox T2、broker/process join T3 |
| 4a | `eventing` 已接纳的真实 L3 value stream | primitive correctness 保持 T2；只有独立接纳的 production join hazard 可进入 `AcceptedValueStreamJoin` T3 |
| 4b（conditional） | `device-security` L4/zero-trust slice | 当前只允许最低充分 T1/T2；artifact、journey 与 restart/takeover/fencing/operator recovery T3 在独立 scope/ADR 接纳前全部 blocked |

实施跟踪采用一个 Epic 与可独立交付的 PBI；默认不建立 Feature 层。每个 PBI 对应一个 primary capability owner、一个
可验证 outcome 和一个 PR 级变更闭包。`core` T3、`eventing` T3 与任何后续条件 T3 分别是独立 issue/
PR；不将多个 profile 的 T3 收敛成一个无法独立审批、执行和回滚的交付单元。

## Scope alignment

- `project-scope.md` 继续拥有能力矩阵、范围状态和 External owner 边界。
- 本 ADR 拥有产品面、官方 profile 闭包和实施顺序。
- `architecture.md` 继续拥有 workspace 分层与 crate dependency 规则。
- `dependency-policy.md` 继续拥有上游组合、wrapper、port 与自研判定。
- production delivery 环境事实继续由
  [`Runtime 与 delivery 仓库边界`](202607280820-1873-runtime-delivery-boundary.md) 的外部系统持有。

## Acceptance

- project target 的每个承诺可映射到现有能力矩阵和唯一产品面。
- Platform Public 与 Official Integration 具有真实外部 consumer、版本边界和升级路径。
- 官方 profile 的 dependency closure、provider posture、runtime inventory 与 release artifact identity 一致。
- 新增或变更 T3 的 issue/PR 与产品实现分离，并对不可下沉至 T1/T2 的 production join hazard 给出可审查的必要性证明。
- `identityaudit`/`settingsonly` 不再扩展独立产品/T3 身份；只在官方 profile 和外部 consumer 边界闭合后按独立迁移决策退出核心发布面。
- L3/L4 primitive 先以最低充分 T1/T2 闭合；`device-security` 的产品激活与任何 T3 只在独立 scope/ADR 接纳后，
  再按其明确承诺的真实纵向 consumer 与 evidence 要求闭合。
- Epic/PBI 拆分保持 capability owner、proof owner 与 production evidence item 一一可追踪。
