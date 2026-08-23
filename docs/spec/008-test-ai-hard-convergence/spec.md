# Feature Specification: 测试与 AI-Hard 载体收敛

**Feature Branch**: `docs/test-ai-hard-r3`
**Created**: 2026-08-02
**Status**: Draft
**Baseline**: `06d1351019cbe3d2f859290b17e949916329dd04`

## 背景

RSS 已具备 typed gate、provider conformance、production artifact inventory、真实 provider integration 与
T1–T3 验证分层，但测试载体仍存在三类维护风险：只冻结符号形状的 smoke/test-only Noop、依赖
`#[ignore]` 表达资格的 live/artifact target，以及同时承载大量独立 seam 的巨型测试与源码扫描器。

本规格把外部 R2 方案重新基于当前 `develop` 校准。外部快照中的 deviceloop 旧证书 API 已在当前仓库消失；
PostgreSQL/AMQP 已接入 provider conformance catalog，因此后续目标是识别并删除重复断言，而不是重新发明 suite
或声称尚未接入。

## 用户场景与验收

### US1 — AI 实施者只维护最低充分证明（P1）

当一个 invariant 已由类型、Cargo graph、generated fact 或真实 provider behavior 证明时，实施者可以定位唯一
canonical owner，并删除只锁函数名、局部调用形状或符号存在性的重复载体。

独立验收：为每个拟删除 carrier 给出风险、当前 owner、替代证据与回归命令；没有替代证据的 residual scanner 保留。

### US2 — Live 与 artifact 测试可以被标准 Cargo target 精确选择（P1）

Vault、historical migration 与 image acceptance 等测试的 eligibility 由 `[[test]]`、`path` 和
`required-features` 表达；只有由父测试精确调用的 subprocess child 可以继续 `#[ignore]`。

独立验收：每个 live/artifact target 有单一命令、缺 feature 或环境时 fail-closed，不建立 TestInventory。

### US3 — Provider-neutral behavior 与 provider-specific failure 分层（P1）

PostgreSQL、AMQP 与 Vault 的共享行为复用现有 testkit/provider catalog，adapter 只保留 RLS、TLS、broker
ambiguous outcome、provider outage 等特有失效模式。

独立验收：共享行为只定义一次，实际交付 provider 仍运行真实 T2 target，且 provider-specific case 可单独选择。

### US4 — Production acceptance 随产品承诺而非内部数量增长（P1）

项目维护者可以先通过 ADR-024 amendment 决定是否把 T3 owner 从 assembly 收敛到 production product surface；
在决策落地前，不得修改现有 T3 canonical owner 或 artifact journey。

独立验收：任何 carrier activation、redeclaration 或 replacement 都在对应 PBI 中按
ADR-024 提供逐项 evidence plan；静态 registry 不存放 same-head 运行回执或历史切换证明。

### US5 — 外部 companion 只由真实 consumer 激活（P3）

`rss-conformance`、`rss-test-postgres` 与 `rss-test-eventing` 只在真实 workspace 外 consumer owner、独立
fixture 计划、SemVer/MSRV、支持范围和退出路径齐备后启动。候选包可先由 producer 的不可变 file-registry
bundle 生成，不要求或暗示 crates.io 预发布。

独立验收：条件 PBI 带 `flag-cond` 和可验证 Trigger；owner/support/version/exit 是启动条件，外部 consumer
针对精确 producer/consumer revision 的 candidate first-green 是完成与任何 registry 发布的门。未满足完成门
不得发布，也不得以 path/git dependency、兼容 shim 或仓内伪 consumer 绕过。

## 功能需求

- **FR-001**：必须把 AMQP feature-off 现状作为窄 Freeze 候选记录；不得新增 constructor、factory、
  `Default`、`Clone`、deserialize、test-support mint 或 production consumer。
- **FR-002**：T3 product-surface 语义必须先作为 ADR-024 amendment 决策，不能把外部计划中的 ADR 标为仓库已接受。
- **FR-003**：必须删除已在当前 HEAD 不成立的 deviceloop PBI。
- **FR-004**：settings/identity/audit/bootstrap/consistency 的 signature-only smoke 与 test-only `todo!()` Noop
  必须逐条映射到 behavior、compile-fail 或真实 consumer 后再删除。
- **FR-005**：live/artifact test eligibility 必须由 Cargo target/feature 表达；合法 subprocess child 必须与父调用双向可追踪。
- **FR-006**：PostgreSQL 巨型 carrier 必须先做行为不变的 seam 模块拆分，再做 conformance 去重。
- **FR-007**：PostgreSQL 与 AMQP 工作必须基于当前 provider capability enrollment 做差量清查。
- **FR-008**：Vault live T2 必须覆盖 signer、encrypt/decrypt、AAD reject、rewrap、readiness 与 outage；错误配置和
  当前无网络交互的 no-op shutdown 保持 T1，除非未来实现引入独立 provider hazard；secret/token/endpoint 不得进入日志或报告。
- **FR-009**：scanner 收缩必须先有 rule-to-carrier 清单和 synthetic red；跨语言 SQL、credential redaction、
  ambient env 与 production binding 等 residual risk 不得因 LOC 目标被删除。
- **FR-010**：testkit 保持 `publish = false`，provider-neutral behavior 不依赖 RSS adapter，container fixture 继续 feature-gated。
- **FR-011**：Azure Boards 必须使用一个 Epic 与直接子 PBI，PBI 标签包含且仅包含合法的 area/type/pri/cx 轴；
  条件条目额外使用 `flag-cond`。
- **FR-012**：所有 PBI 使用真实 `Blocked-by: #N` 留下依赖；不写 W0–W8 或看板 Wave 字段。
- **FR-013**：每个实现 PR 的最终本地门是 `make ci CI_BASE=origin/develop`；重型 provider/full matrix 留给
  develop/release、显式 full 或 PBI 明确的定向诊断；每日 security-audit 只刷新 advisory，不运行测试。

## 非目标

- 新建 Proof Inventory、TestInventory、Suite/Case/Environment/Report 平台或 CI scheduler。
- 把每个 contract、provider、L3/L4 primitive、fault 或 performance 标签升级为 T3。
- 删除或扩展 AMQP feature-off marker。
- 在没有真实 consumer 时发布测试 companion。
- 以任意文件或仓库 LOC 阈值替代语义审查。
- 修改 `crates/contractreg/**`、`crates/syshealth/**` 或远程 required-check 激活。

## 成功标准

- **SC-001**：Azure Boards 存在 1 个合规 Epic 和 19 个合规 PBI，全部建立原生父子关系。
- **SC-002**：19 个 PBI 中不存在已完成的 deviceloop 旧 API 删除任务。
- **SC-003**：3 个外部 companion PBI 均为 `flag-cond`，且 Trigger 非空。
- **SC-004**：T3 policy 与 carrier convergence 是两个独立 PBI，carrier PBI 具有完整 evidence plan。
- **SC-005**：`spec.md`、`plan.md`、`tasks.md`、`research.md`、`data-model.md`、`quickstart.md` 与需求清单完整且无占位符。
- **SC-006**：本规格 PR 不修改 Rust、Cargo manifest、assembly artifact、migration 或 generated source。
