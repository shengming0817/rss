# ADR-024：企业开发框架目标、产品面与官方技术栈闭包

- **Status**：Accepted
- **Date**：2026-08-01
- **Last updated**：2026-08-12
- **Scope**：[`project-scope.md`](../rules/project-scope.md) 的项目目标与目标验收边界

## Context

RSS 已具备 contract/codegen、静态 assembly、L0–L4 primitive、多租户、安全、可观测与本地验证能力。项目目标升级为
面向 Rust 企业应用的 AI 友好型企业开发框架后，需要统一公共消费面、官方技术栈闭包和分阶段完成条件。

## Decision

### 2026-08-11 amendment：Platform vNext 唯一 owner 与原子 cutover

本 amendment 取代 2026-08-09 Platform v0.2 实现 amendment 作为 vNext 规范；旧实现只作为迁移基线保留，
不授予兼容入口。Platform vNext 是 breaking 0.x cutover，具体 package 版本从 Cargo metadata 派生。
不得保留 alias、shim、`From`/`TryFrom`、feature flag、双读写、双 dispatch 或旧 baseline fallback。

vNext 的唯一 owner 固定如下：

| 语义 | 唯一 owner | 边界 |
|------|------------|------|
| contract/admission identity | Foundation `rss-contract` | 唯一定义 `ContractId`、`ContractVersion`、`SchemaDigest` 与 descriptor identity；零 internal workspace 依赖 |
| request/security value vocabulary | Foundation `rss-request-context` | 唯一定义 tenant、request、principal reference/kind、deadline、cancellation、obligation 与只读视图；除公开 obligation 签名确需 contract identity 外不依赖 `rss-contract` |
| JWT/JWS/JWKS authority | Official OIDC integration 与 AuthN/AuthZ funnel | OIDC integration 唯一验证签名、claims 与 JWKS freshness；funnel 通过私有 sealed mint capability 唯一构造 `TrustedRequestContext` |
| application waist | Platform | descriptor admission、typed async `Handler<C>`、closed dispatch outcome/error semantics、module/dispatch 与稳定 host-view ports；消费并传播 Foundation deadline/cancellation，不重新定义其值类型；不接收 raw token/JWKS，不 mint identity |
| process lifecycle 与 live inventory | RuntimeExec | startup、signal、readiness、admission stop、总 drain budget、shutdown、inventory mint/reader/publisher；Platform 只读取 internal bridge 投影 |
| composition | assembly/composition root | 唯一接线 owner；RuntimePlan、provider catalog、constructors、inventory publisher 与第三方 SPI 保持 internal |

分层记法是 Foundation ◁ Platform ◁ internal consumers（右侧依赖左侧）；Official Integration、RuntimeExec 和 assembly 只能经
Platform/基础值面消费或实现端口，不能把 internal 类型反向泄漏进 Release API。安全 authority 与请求值类型分离：
公共值类型不授予可信性，只有 AuthN/AuthZ funnel 的私有 mint 能力可以产生 trusted context。

实施采用一个 RSS 原子 cutover：Foundation 提取、ID 迁移、async Platform API、Auth/RuntimeExec bridge、
composition、Release API baseline 与 package proof 由 #2107 在同一次合并切换。外部 candidate receipt 是
必填 merge gate；cutover 增量顺序见 [`Spec 012 plan.md`](../spec/012-platform-application-waist/plan.md)，跨仓
first-green receipt shape 与 artifact lifecycle 继续唯一由
[`ADR-026`](202608111253-026-rss-incubator-ownership-migration.md) 持有。
任何 owner、proof 或 receipt 未闭合都禁止部分合并。

回退遵循 ADR-026 的不可变 artifact lifecycle：未发布 candidate 可拒绝；发布后先阻断产品发布并将 incubator
pin/lock 回上一已知绿色 artifact、重跑 canonical CI，再由 RSS 发布修复版本或按 registry 能力 yank。必要时才整体
revert RSS cutover 到一致的 v0.2 revision/baseline；不得恢复 RSS-owned submodule，也不得在部分 vNext 中恢复旧 API、
兼容层、双 authority 或双 baseline。
完整 backlog 映射只由
[`Spec 012 research.md`](../spec/012-platform-application-waist/research.md) 持有，cutover 增量 DAG 与 AI-HARD carrier
handoff 只由 [`Spec 012 plan.md`](../spec/012-platform-application-waist/plan.md) 持有；它们都不复制 ADR-026 的
canonical receipt schema 或 artifact rollback owner。

四原则复核结论：**彻底**，一次切断重复 ID、Platform crypto/lifecycle 与伪 inventory owner；
**不向后兼容**，旧 API 与 baseline 同步删除；**优雅简洁**，只引入两个必要 Foundation package 并复用既有
Release Surface/package-proof；**AI-HARD**，永久约束交给 Cargo/rustc visibility、私有 mint、分层依赖、Release API
与确定性 T1/T2 proof，Markdown 只记录决策和尚未激活的 carrier handoff。

### 2026-08-09 amendment：Platform Public v0.2 历史实现（已被 vNext 取代）

以下内容仅描述 v0.2 当前实现，不再是 vNext 规范，也不得被解释为兼容承诺。本 amendment 曾取代 Spec 012
旧版的 “thin façade / exact API frozen / 不改变 runtime” 实施解释。
`rss-platform` 0.2.0 是 provider-free、进程内 typed application kernel，原子拥有 canonical contract
admission、静态 federated ES256 authority、typed handler dispatch 与 bounded drain/shutdown。它不是
publish=false internals 的 wrapper，也不提供 DI container、Host/Provider SPI 或第二 composition root。

`core`/`eventing` 仍是候选 official profile，但尚未激活，不进入 Platform v0.2 API；kernel conditions 只报告
自身真实 handler/dispatch/drain/stopped 状态，不映射 provider/runtime readiness。Platform crate 位于新的最低位
`PlatformPublic` layer，无 workspace normal/build dependency；internal layers 只能反向消费其稳定值面。

framework-owned active HTTP manifests 经同一 `cargo xtask codegen` 投影 sealed public contract set；v0.2 exact set
为 `runtime.inventory`。Release Surface、真实 `.crate` local-registry consumer 与 locked/offline T2 是同一合并门。
旧 #2045 fixture、开放 Contract、core/eventing marker 与兼容 path 全部删除，不保留 shim/alias。

### 产品面

| 产品面 | 版本承诺 | Owner |
|--------|----------|-------|
| Standalone Component | 独立 SemVer | 低依赖基础能力的公开 crate |
| Platform Public | 协调版本 | descriptor admission、typed async handler、module/dispatch 与稳定 host-view façade；消费 Foundation/security/runtime 投影，不拥有 contract identity、trusted mint 或 process lifecycle |
| Official Integration | 封闭支持矩阵 | 成熟上游之上的 tenant、安全、一致性、health 与 lifecycle 适配 |
| Reference Extension | 第一方纵向 consumer | Identity、Settings、Audit 与已接纳的 L3/L4 slice |
| Internal Implementation | 仓内重构边界 | generated/runtime internals、provider catalog 与 composition detail |
| Tool / Verification | 仓内执行边界 | xtask、lint、testkit、journey 与 fault/recovery evidence |

公开产品面只由产品面 owner、release artifact 与真实外部 consumer 的明确承诺界定。committed public-api baseline
既可审查 Release API，也可仅审查 internal crate 的 exported-symbol 漂移；baseline 本身不授予公开产品面或 SemVer。
`pub` 可见性只表达 Rust 访问边界。

Provider 产品边界采用三层结构：`diport` 是 `publish = false` 的 Internal Provider Contract；成熟上游的内置 adapter
属于封闭 Official Integration，由静态 composition root 经私有 provider catalog 构造；当前 Platform Public 不发布
通用第三方 Provider SPI。未来只有在真实独立 provider 与 consumer、capability owner、SemVer/支持责任、typed static
bridge 和最低充分 conformance 同时成立后，才能经独立 scope/ADR/PBI 提升 capability-specific extension contract。
package metadata 如在该后续交付中引入，只能是不可信候选声明：它不能自动注册 provider，不能由 provider 自行声明
maturity 或 conformance receipt，且必须汇入既有 assembly governance/compiler 单链，不能成为第二套 registry。
多个真实 capability-specific SPI 证明稳定共同语义前，不预建通用 provider vocabulary crate。

### 官方 profile

首批官方 profile 按依赖关系形成闭包：

1. **core**：runtime lifecycle、HTTP、PostgreSQL LocalTx、external OIDC/verified Principal、TenantContext/RLS/authz、
   tracing/health/readiness。
2. **eventing**：`core` 加 AMQP、outbox/inbox、settlement、DLQ、idempotency 与 recovery。
3. **device-security**：已由
   [`ADR-028`](202608120423-028-device-security-candidate-scope.md) 接纳 candidate scope；以六契约公共窄腰、真实
   external consumer、credential/replay/fencing、federated operator recovery owner/evidence 和原地演进的
   `deviceidentity` assembly 为闭包，当前只授权最低充分 T1/T2。

profile identity、dependency closure、provider capability、typed config 与 runtime inventory 从 assembly/profile metadata
派生。profile 的支持承诺由真实 provider conformance、production join evidence 和 release artifact 共同激活。

本 ADR 决定的 profile → artifact 产品映射如下；它只决定产品 owner，不替代 `assemblies/artifacts.toml` 的当前 artifact
事实，也不在本 policy PBI 中切换 canonical carrier：

| Official profile | Designated assembly | Binary / image artifact | 当前状态 | Journey 边界 |
|------------------|---------------------|-------------------------|----------|--------------|
| `core` | `assemblies/runtime` | `server::server` / Docker `runtime` target | candidate；当前 runtime 尚未形成 core-only closure | 尚无 profile canonical journey；legacy runtime smoke 只作迁移 evidence |
| `eventing` | `assemblies/runtime` | `server::server` / Docker `runtime` target | candidate | 尚无 profile canonical journey；SettingsOnly 四项 evidence 是迁移来源，不是 eventing owner |
| `device-security` | `assemblies/deviceidentity`（原地演进） | 预留 candidate identity：`deviceidentity::deviceidentity-server` / Docker `deviceidentity-runtime`；当前均不存在 | candidate scope；当前 assembly 仍 compile-only draft pilot | 零 T3；无 hardening trigger，不得登记 Evidence ID/selector/journey |

`core` 与 `eventing` 可以复用同一 release image，但必须各自通过闭值 profile configuration/plan 证明依赖闭包；不能以同一
binary/image 存在推导两个 profile 均已激活。`identityaudit` 与 `settingsonly` 不映射为 official profile artifact。

### T3 产品授权

T3 从官方 product profile 的产品承诺派生，不从代码结构派生。T3 owner 是闭集：`ProfileLifecycleJoin` 只证明 profile
artifact 的 config/startup/readiness/drain/restart，`AcceptedValueStreamJoin` 只证明该 profile 明确接纳的真实纵向
value stream 在 production process/provider 组合后独有的 join hazard。assembly、domain、contract、provider、adapter、
consistency level、binary/image、`profile = "production"` 或 `supported` lifecycle 都不能单独授权 T3，也不得创造第三类 owner。

ADR 已接纳、因而未来可以逐项申请 GA-hardening trigger 的 official candidate 闭集只有 `core`、`eventing` 与
`device-security`；其中 `core`/`eventing` 属 GA 主线，`device-security` 服从 ADR-028 的独立候选路径。当前三者均为
`candidate`，当前 `hardening-authorized` 与 `active` 集合均为空。profile 状态依次为：ADR 接纳的 `candidate`；scope freeze 后由正式
GA-hardening acceptance trigger 逐项放行的 `hardening-authorized`；designated artifact、真实 provider conformance、
T1/T2 前置和 candidate production join evidence 全部真实通过后原子进入 `active`。candidate evidence 在激活前不是
canonical owner、不能进入普通 PR required selection，也不能替换 legacy carrier；这消除“active 才能建 T3、但激活又需要
T3”的循环。activation transition 必须把该 profile 唯一 designated production artifact 原子提升为唯一 canonical
production artifact，不允许 candidate 与 active artifact 并存为两个 owner。
`device-security` 已完成独立 scope/ADR 接纳，因此无需再次修改 scope 才能申请未来 trigger；但它仍不属于当前 active 或
hardening-authorized T3 范围。其 candidate
implementation、hardening trigger、T3 evidence plan/carrier 与 activation transition 继续严格按 ADR-028 分离。L3 是
一致性语义，不是独立产品 profile；真实 L3 value stream 只能在产品承诺已接纳后，作为 `eventing` 的显式 evidence
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
第一方外部 reference consumer。迁出不立即执行：在 `core`/`eventing` canonical artifact、稳定 Platform Public、
外部 consumer build/upgrade baseline 全部闭合前，两个 assembly 作为过渡 reference carrier 保留；若迁出后的真实
consumer 确需第三方 Provider 扩展，还必须先接纳相应 capability-specific extension contract。两个 assembly 立即冻结
新产品能力、新 provider 组合和独立 T3 扩展，尚未批准的通用 adapter SPI 不构成迁出前置。

迁出时必须由单独弃用/迁移决策记录目标仓库、版本边界、consumer build、release ownership 和回退方式。
Identity、Settings、Audit 的 domain/contract 能力不因 assembly 迁出而自动删除或迁仓；它们仍按
[`project-scope.md`](../rules/project-scope.md) 的 `Complete`/`Freeze` 边界处置，后续迁移需另行决策。

第一方外部 consumer 孵化仓的 ownership 与 standalone consumer proof cutover 已由
[`ADR-026`](202608111253-026-rss-incubator-ownership-migration.md) 接纳。该决策只建立仓库与消费证据边界；上述
`core`/`eventing` canonical artifact、稳定 Platform Public 和外部 build/upgrade 前置仍未满足，因此不构成
`identityaudit`/`settingsonly` assembly、domain 或 contract 的迁出授权。

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
| 4b（candidate scope） | `device-security` L4/zero-trust slice | 按 ADR-028 只允许最低充分 T1/T2；当前 compile-only pilot 不构成 reserved binary/image 的实现，任何 T3 仍需 hardening trigger 与独立 issue/PR |

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
- L3/L4 primitive 先以最低充分 T1/T2 闭合；`device-security` 已接纳 candidate scope，但产品激活与任何 T3 仍须
  按 ADR-028 的真实纵向 consumer、candidate first-green、独立 hardening/T3 issue 与原子 activation 要求闭合。
- Epic/PBI 拆分保持 capability owner、proof owner 与 production evidence item 一一可追踪。
