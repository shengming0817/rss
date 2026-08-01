# ADR-024：企业开发框架目标、产品面与官方技术栈闭包

- **Status**：Accepted
- **Date**：2026-08-01
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

### 实施前判定

每个实施 PBI 在编码前完成：

- `ai-robust.md` 的 enforcement 判定；
- `dependency-policy.md` 的依赖与自研判定；
- primary capability owner、真实 consumer、公开面影响和最低充分 T1/T2/T3；
- production acceptance carrier 变更时的 evidence plan。

### 实施顺序

| Wave | Outcome | 主证明 |
|------|---------|--------|
| 1 | 产品面 metadata、Platform Public allowlist、外部 consumer baseline、统一启动入口 | public-api/semver、external consumer compile、T1/T2 |
| 2 | `core` profile 的 config、composition、lifecycle、diagnostic 与 production join 闭环 | provider conformance、assembly identity、readiness/drain/restart T3 |
| 3 | `eventing` profile 的 L2 producer/consumer/recovery 闭环 | LocalTx/outbox/inbox T2、broker/process join T3 |
| 4 | 真实 L3 value stream 与 `device-security` L4/zero-trust slice | restart/takeover/fencing/operator recovery T2/T3 |

实施跟踪采用一个 Epic 与可独立交付的 PBI；默认不建立 Feature 层。每个 PBI 对应一个 primary capability owner、一个
可验证 outcome 和一个 PR 级变更闭包。

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
- L3/L4 和 device-security 只在真实纵向 consumer 与对应 T2/T3 evidence 闭合后激活。
- Epic/PBI 拆分保持 capability owner、proof owner 与 production evidence item 一一可追踪。
