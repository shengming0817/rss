# Feature Specification: Platform Application waist 与外部消费证明

**Created**: 2026-08-08
**Status**: Accepted design baseline
**Owner issue**: #2041

## 背景

[`ADR-024`](../../architecture/202608012034-024-enterprise-framework-product-surface.md) 已接纳 Platform Public，
[`Spec 010`](../010-release-surface-convergence/spec.md) 已定义 Platform Application waist 是当前已接纳的两条通用
公共 Rust 窄腰之一。
当前缺口是让应用作者只面对稳定的 contract/handler、可信 context、module、lifecycle 与 diagnostics，而不理解
provider、执行引擎、generated registry 或 assembly ownership。

## 目标

1. 定义 Platform application 作者需要的最小能力类别，并为每类 internal 类型给出隐藏或公开替代策略。
2. 用薄 façade 复用既有类型和行为，不创建 DI container、Provider SPI 或第二 runtime composition owner。
3. 由真实独立 repository 从最终 façade package tarball/local registry 执行有界 T2 应用 seam，建立 Release API、可信
   context/lifecycle 消费与 SemVer baseline。

本文不冻结具体 Rust path、泛型参数或错误枚举；精确 API 设计由 #2045、实现由 #2049 拥有。

## 用户场景与独立验收

### US1 — 应用作者只依赖 Platform façade

应用作者可以声明 contract/handler、读取可信只读 request context、注册 ApplicationModule、按 official profile 构造
应用，并通过 RuntimeHandle 与 Conditions/Diagnostics 观察生命周期和失败。

独立验收：最小 workspace 外应用只依赖 façade package，即可通过 typed builder 启动、执行一次 handler request 并经
`RuntimeHandle` 有界停止，不直接依赖 RSS workspace、internal crate 或真实 provider。

### US2 — 可信 context 只读且不可伪造

Principal、Tenant 与 Request context 来自既有 verified execution path。façade 只提供应用所需的只读视图，不公开
mint、provider client、raw credential 或装配 constructor。

独立验收：T2 request seam 将 verified context 交给 handler，应用可以读取可信值，但无法经公共 façade 构造 verified
identity、tenant authority 或受控 receipt。

### US3 — internal ownership 不经 façade 泄漏

provider catalog、`diport`、generated registry、event execution/runtime execution ownership、`AssemblyLock`、
`RuntimePlan` 和具体 provider client 保持 internal。

独立验收：正向应用编译通过；直接或经 re-export、generic bound、error source、conversion 泄漏 internal 类型的负例失败。

### US4 — 外部 consumer 固定真实升级边界

独立 Platform consumer 拥有自己的 repository、lockfile 与 N-1→N fixture，只从最终 façade 的实际 package 消费完整
最小 waist：contract/handler/module、profile-typed builder、verified context、`RuntimeHandle` 与 diagnostics。

独立验收：Release API 的兼容变化由外部 consumer 和 SemVer proof 发现；Reference Extension 或仓内 example 不得替代。

## 功能需求

- **FR-001**：Platform waist 必须只覆盖 contract/handler authoring、可信只读 context、`ApplicationModule`、
  profile-typed builder、`RuntimeHandle`、Conditions/Diagnostics 和公开错误。
- **FR-002**：façade 必须优先复用窄 re-export、wrapper 或 adapter，不改变 runtime 行为，不创建反射 DI、service
  locator 或第二 composition root。
- **FR-003**：`diport`、provider catalog、generated registry、`eventexec`/`runtimeexec` ownership、
  `AssemblyLock`/`RuntimePlan` constructor 与 raw provider client 必须保持 internal。
- **FR-004**：可信 Principal/Tenant/Request context 必须保持私有构造或 sealed mint；public API 只提供最小只读消费面。
- **FR-005**：internal 泄漏 proof 必须覆盖直接 import、re-export、generic bound、公开错误与 conversion 路径。
- **FR-006**：公开 Conditions/Diagnostics/error 必须只暴露稳定闭值 code、经审查的 public detail 与 retryability；
  raw provider/config/credential、tenant/principal/PII、原始错误文本和 source chain 必须保持 internal，并由 sealed
  public/internal detail funnel、negative fixture 与 external consumer 共同证明。
- **FR-007**：独立 consumer 必须从 façade package 的实际 `.crate`/local registry 消费，拥有独立 repository、
  lockfile、owner 和版本升级 fixture。
- **FR-008**：façade 的 canonical package proof 必须由 #2052 从 #2049 完成后的同一 revision 生成；#2051 只提供共享
  packaging mechanics，不得充当最终 façade artifact verdict。
- **FR-009**：外部 T2 consumer 必须用公开 typed builder 启动有界 application seam、执行 handler 并观察 verified
  context/Conditions/Diagnostics，再经 `RuntimeHandle` 停止；不得启动真实 provider、Reference Extension 或 T3 journey。
- **FR-010**：Release API/SemVer baseline 必须只覆盖 [`Spec 010`](../010-release-surface-convergence/spec.md) 的
  正向发布集合，并复用既有 release-check。
- **FR-011**：Reference Extension、仓内 assembly 或 example 不得充当 Platform 外部 consumer 证明。
- **FR-012**：Markdown 只承载接口意图与 traceability；边界 enforcement 必须由 Cargo/visibility、compile fixture、
  release API baseline 和真实 consumer 承担。

## 非目标

- 不在 #2041 或 #2045 实现 façade；不在 #2041 决定精确 Rust 签名。
- 不接入 `core`/`eventing` 真实 provider，不激活 official profile，不改变 runtime behavior。
- 不创建第三方 Provider SPI、通用 DI、动态模块、插件、registry 或 marketplace。
- 不新增 T3、production journey、artifact selector、SLO、dashboard 或 delivery automation。
- 不迁出 Identity/Settings/Audit 或其 Reference Extension assembly。

## 成功标准

- **SC-001**：应用作者能力类别与 internal 禁止面互斥且完整。
- **SC-002**：可信 context 的读写/mint 边界可映射到 Hard/Medium owner。
- **SC-003**：公开 diagnostics/error 只含稳定、经审查的信息，敏感详情和 source chain 的负例可执行。
- **SC-004**：façade 实现和外部 consumer 分属可独立回滚的 PBI。
- **SC-005**：规格不把仓内 consumer、Reference Extension 或 assembly smoke 计作外部 Release API proof。
- **SC-006**：#2045、#2047、#2048、#2049、#2051、#2052 的依赖和 proof owner 完整可追踪。
- **SC-007**：外部 proof 同时覆盖 authoring、typed startup、verified request、diagnostics 与 bounded shutdown，且不升级为 T3。
