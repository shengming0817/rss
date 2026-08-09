# Feature Specification: 首批 Standalone Components 候选发布闭环

**Created**: 2026-08-08
**Status**: Accepted design baseline
**Owner issue**: #2041

## 背景

[`Spec 010`](../010-release-surface-convergence/spec.md) 定义正向 Release Surface 与 Standalone Component waist。
首批工作不应扩张为全 workspace 发布，而应以最低风险的真实组件证明治理、打包、外部消费和人工发布边界。
`diagctx` 与 `tracewire` 是首批候选，但仍是 internal package；本文不把候选身份写成已发布事实。

## 目标

1. 在维护者明确许可证、责任和公开命名后，只为两个已接纳候选闭合最小 Cargo publish closure。
2. 先验证共享 packaging mechanics，再让每个最终候选从同一 revision 生成真实 `.crate`，在 workspace 外验证
   package content、依赖解析、feature、MSRV、文档与禁止依赖。
3. 分别闭合诊断上下文和 trace context 的窄 API 及其 final-artifact proof，再由独立 Plain Rust consumer 证明可消费
   与升级边界。
4. 将 Release Candidate closeout 保持为人工批准的发布决策，而不是自动 registry 上传或 committed receipt database。

## 用户场景与独立验收

### US1 — 维护者先完成发布治理和命名决策

许可证、安全报告、维护责任、版本/弃用/yank/回滚规则以及公开品牌均由明确 owner 决定。规格和自动化不得替
维护者选择法律条款，也不预占未计划发布的名称。

独立验收：只有实际候选名称接受 registry 冲突检查；内部 crate 无需批量重命名。

### US2 — Plain Rust 用户从真实 package 消费诊断上下文

候选 diag-context 提供 correlation/diagnostic context 与 request scope，不依赖 RSS Platform，且诊断数据永远不是
Principal、Tenant 或授权 evidence。

独立验收：workspace 外 consumer 可使用候选 package；缺失或畸形诊断数据 fail-open，授权结果不受影响。

### US3 — Plain Rust 用户消费稳定 trace context

候选 trace-context 以验证后的 W3C TraceParent 边界提供 capture/restore。成功恢复以及 malformed、oversized、
unsupported 输入产生不包含原始输入的闭值诊断 outcome；传播仍 fail-open 且不 panic，OpenTelemetry SDK 与 test-util
不进入默认公开面。

独立验收：roundtrip 与 malformed case 从 tarball consumer 通过，公开签名不泄漏 SDK 类型。

### US4 — 人工批准前只有 candidate

两个候选必须先经过真实独立 consumer、API/MSRV baseline、digest、CHANGELOG、owner 与回滚核对。

独立验收：closeout 前没有 RC 声明或 registry 上传；closeout 只回读 canonical proof，不新增 runner 或 schema。

## 功能需求

- **FR-001**：许可证、贡献、安全、维护者、版本、弃用、yank 和回滚责任必须在 package 候选化前由明确 owner 决定。
- **FR-002**：公开品牌、前缀和两个实际候选名称必须由维护者冻结；不得抢占未来名称或批量重命名 internal crate。
- **FR-003**：只为已接纳候选补齐 Cargo metadata、MSRV、默认 feature、path+version 依赖和最小 publish closure。
- **FR-004**：#2051 只证明可复用的 packaging mechanics；它不得充当最终候选的 canonical artifact proof。
- **FR-005**：每个候选的 canonical package proof 必须由其最终 API owner 从同一 revision 生成实际 `.crate`，在
  workspace 外覆盖 package content、default/no-default/all-features、MSRV、docs 与 forbidden internal path。
- **FR-006**：diag-context 必须保持诊断 context 与授权 context 物理和语义隔离；诊断采集失败必须 fail-open。
- **FR-007**：trace-context 必须使用验证后的 TraceParent 边界、隐藏 OpenTelemetry SDK、隔离 test-util；成功恢复
  以及 malformed、oversized、unsupported 输入必须产生闭值、无敏感原始输入的诊断 outcome，并保持 HTTP、auth、
  tenant 与传播行为 fail-open 且不 panic。
- **FR-008**：独立 consumer 必须拥有独立 repository、lockfile、owner 和候选版本升级入口，只消费通过同一 revision
  canonical proof 的最终候选 artifact，且不依赖 RSS Platform。
- **FR-009**：RC closeout 必须核对真实 consumer、API/MSRV、tarball digest、CHANGELOG、owner 与 yank/rollback，
  publish 保持人工步骤。
- **FR-010**：所有发布证明必须复用 [`Spec 010`](../010-release-surface-convergence/spec.md) 指定的 canonical
  release owner，不得建立发布服务器、第二 runner 或 receipt registry。

## NW-003 规范性窄腰契约

本节是 #2044 的唯一规范性 allowlist。其它研究、计划、tracker 与 public-api snapshot 只能引用本节；未进入
allowlist 的当前 internal `pub` item、feature 或依赖不构成未来 Release API。#2053/#2054 必须直接破坏式迁移，
不得保留旧模块路径、别名、deprecated shim 或双入口。

### diag-context

| 类别 | 唯一允许面 |
|---|---|
| 根级类型 | `CorrelationId`、`CorrelationIdError`、`DiagnosticCtx` |
| `CorrelationId` | `MAX_LEN = 128`、`parse(&str) -> Result<Self, CorrelationIdError>`、`as_str(&self) -> &str` |
| parse error | 闭枚举 `Empty | TooLong | InvalidChar`；不携原始输入 |
| `DiagnosticCtx` | `new(CorrelationId) -> Self`、`correlation(&self) -> &CorrelationId` |
| ambient | `scope(DiagnosticCtx, Future) -> impl Future`、`current() -> Option<DiagnosticCtx>`、`correlation() -> Option<CorrelationId>` |

`ctx`/`local` 模块、`MAX_CORRELATION_ID_LEN` 全局常量以及 Tokio `TaskLocalFuture`/`AccessError` 均不允许公开。
入站构造 fail-closed 拒绝空值、超过 128 bytes 或 ASCII `[A-Za-z0-9._-]` 之外字符；ambient 缺失与传播失败
fail-open 为 `None`，不得 panic、mint Principal/Tenant/receipt 或改变认证授权结果。

### trace-context

| 类别 | 唯一允许面 |
|---|---|
| 根级类型 | `TraceParent`、`TraceParentError`、`W3cTraceContext`、`RestoreOutcome` |
| `TraceParent` | 私有字段；`parse(&str) -> Result<Self, TraceParentError>`、`as_str(&self) -> &str` |
| parse error | 闭枚举 `Malformed | Oversized | UnsupportedVersion`；不携原始输入 |
| carrier | `traceparent(&self) -> &TraceParent`、`tracestate(&self) -> Option<&str>`、`into_traceparent(self) -> TraceParent` |
| capture/restore | `capture_current() -> Option<W3cTraceContext>`；`restore_remote_parent(&tracing::Span, &TraceParent, Option<&str>) -> RestoreOutcome` |
| restore outcome | 闭枚举 `Restored | Unavailable`；`#[must_use]`，不携 SDK error 或原始输入 |

`TraceParent` 上限 512 bytes；version `00` 按 W3C Trace Context 1.1 严格四字段、lowercase hex、非全零
trace/span id 校验，`01..fe` 按 future-version 扩展规则，`ff` 为 `UnsupportedVersion`，其余非法形状为
`Malformed`。`capture_current` 无有效 layer/context 时返回 `None`；restore 只接受已验证 parent，无法 attach 时
返回 `Unavailable` 并保持 root。非法/超长 tracestate 只丢 state，不使合法 parent 失败。`TraceParent` 与 carrier
不得实现 `Debug`、`Display`、serde；raw-string restore 与 `String` carrier return 不允许保留。

### MSRV、feature 与依赖预算

两个候选的 MSRV 固定为 `1.96`，manifest 必须显式 `default = []`。预算分三轴判断，任一超出都不合格：

| 候选 | normal direct exact-set | default closure | 公共签名外部类型 |
|---|---|---|---|
| diag-context | `tokio`（仅 task-local 所需 `rt`）+ `thiserror` | 无可选 feature | 0；仅 core/std 与自身 owned types/opaque future |
| trace-context | `tracing`、`tracing-opentelemetry`、`opentelemetry(trace)`、`opentelemetry_sdk(trace)`，全部 `default-features = false` | 禁 metrics/logs/internal-logs/test helpers | 仅 `tracing::Span` |

两者 normal/default graph 的 RSS internal crate 为 0；trace 公共签名中的 `opentelemetry*` 与
`tracing_opentelemetry` 类型为 0。现有 `test-util` helpers 不属于候选 manifest 或 Release API；#2054 必须将
多 consumer 测试脚手架迁入 `publish = false`、dev-only 的内部载体。当前两个 package 仍 `publish = false` 且未进入
Release Surface；本契约不授予 candidate artifact、RC 或 published 身份。

### 非授权机器边界

`DIAGCTX-NOT-AUTH-SOURCE-01` 由 `rss_diagctx_auth_source` Dylint 承载：真实 `diagctx` item 不得在 `authn`、
任何包含 production `diport::Pdp/PdpLocal` 或 `httpserve::RouteAuthorizer` impl 的 crate，以及
`httpserve::auth` 决策核心中出现。crate-wide owner 边界同时覆盖 impl 的父模块与 sibling helper；HTTP correlation
只在独立 `auth_audit` 模块对已完成的闭值 decision 盖章。
类型/crate 隔离是 Hard 上游，模块/路径约束是接 `cargo dylint --all` 的最强可用 Medium 下游；Markdown 不计作门。

## 非目标

- 不切换全 workspace 版本，不发布 internal crate，不上传 registry。
- 不产品化 `secure`、`consistency`、runtime engine、provider 或 testkit。
- 不创建组件市场、自动发布控制面、通用 SDK 或 package inventory。
- 不在 #2041 选择许可证文本、公开品牌、最终 crate 名或 Release Candidate 版本。

## 成功标准

- **SC-001**：治理、命名、Cargo closure、packaging mechanics、两个 final-artifact proof、独立 consumer 和 closeout
  形成无跳步 DAG。
- **SC-002**：两个候选的 API、依赖和失败语义均有最低充分 Hard/Medium owner。
- **SC-003**：任何 RC 声明都被真实独立 consumer 和人工 closeout 阻塞。
- **SC-004**：规格不包含 package schema、自动上传、动态数量或未来名称占位表。
- **SC-005**：#2043、#2044、#2046、#2048、#2050、#2051、#2053–#2056 完整可追踪。
