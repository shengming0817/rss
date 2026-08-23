# 验证范围与 Production Acceptance

本文拥有 T1–T3、最低充分证明、GA trigger、production acceptance 与 carrier transition；它不授权新的产品面。

## 证明层级

| 层 | 独有风险 | 典型 carrier |
|---|---|---|
| T1 | 类型、状态机、schema、组件不变量 | Cargo/rustc、类型、codegen、组件测试 |
| T2 | 真实 provider/transaction/transport seam | conformance、真实 DB/broker/identity integration |
| T3 | production process/config/provider join | canonical artifact journey、startup/restart/drain/recovery |

- Hard/Medium/Soft 是 enforcement 强度，T1–T3 是验证深度，两轴不得互相推导。
- 每个 invariant 只有一个 canonical owner；高层只证明低层无法观察的 join hazard。
- 禁止 domain × provider × assembly × artifact × fault 的笛卡尔积和“多一道保险”重复证明。

## 默认选择

- 普通 PR 运行 affected T1、必要 T2 与已激活 canonical T3；分析失败可扩大 affected scope，但不得自动升级 full。
- 完整 conformance、fault/recovery、coverage、performance/soak 属于 develop/release 或显式 full。
- performance 必须绑定已接纳 SLO；soak 必须绑定生产 SLO 或长时正确性/恢复 hazard。
- Markdown、聚合 receipt 和静态 inventory 不得冒充运行证据。

## T3 default-deny

T3 owner 只有 `ProfileLifecycleJoin` 与 `AcceptedValueStreamJoin`。下列事实都不自动授权 T3：

- domain、contract、provider、adapter 或 consistency level；
- assembly、binary、image、`profile = "production"` 或 supported lifecycle；
- 安全关键标签、已有测试、closeout checklist 或聚合报告。

只有产品 ADR 已接纳的 official profile 可申请 T3。candidate 默认无 T3；hardening-authorized profile
只允许正式 trigger 明列的 Evidence ID、闭值 owner、artifact 与 join hazard。active profile 只有一个
canonical production artifact 和 journey carrier。

## GA trigger

- GA hardening 前禁止以 SLO、容量、dashboard/alert、soak/fault matrix、evidence 平台或 T3 扩展为主要产出。
- trigger 只放行逐项列明的最小 SLI、单环境容量、必要 runbook 与 production acceptance；不扩成矩阵。
- GA 后仍不得吸收 External delivery、托管监控、autoscaling、多区域或商业 tenant 控制面。

## No-new-work closeout

Closeout 只回读既有代码、测试和 JobResult，核对 canonical owner/selector，更新 traceability 并记录缺口。
不得新增产品代码、test carrier、benchmark、schema、selector、CI gate、receipt database 或顺手修实现。
缺 proof 时退回原 implementation owner；没有 owner 时另立实现项，closeout 不接管。

## Production acceptance evidence

新增、扩展、替换、重新声明或退役 T3 carrier，以及切换 canonical production artifact journey，必须独立交付。
每个 evidence item 必须记录：

- stable Evidence ID、official profile、闭值 T3 owner 与唯一 artifact；
- 精确 production-only hazard、canonical target/assertion 与独立 selector；
- same-revision T1/T2 green receipt、T3 receipt、资源和 timeout；
- `activation | extension-or-redeclaration | replacement` 及完整 transition。

lower-layer 未真实通过时不得开始 T3。skip、未执行、developer/non-production receipt 均不是 green evidence。

## Carrier transition

- activation：candidate first-green 后才注册并成为 canonical。
- extension/redeclaration：修改后的 carrier first-green 后才替换 owner/assertion。
- replacement：旧 carrier 保持 canonical 至新 candidate first-green；随后同一交付原子切 selector 并删除旧
  target/harness/script/env，不留 alias、shim 或长期双路径。
- artifact journey replacement 才修改 artifact 指针；其它 replacement 修改其真实 registry/selector。
- final HEAD 重新运行 canonical carrier 与静态 artifact check；same-head receipt 只进 review evidence，
  不写入 committed registry。

`INVARIANT: SECURITY-PRODUCTION-CLOSEOUT-01 { level = "Medium", exec = "check", source = "code" }`：
安全 production closeout 的 canonical machine carrier 由代码与真实 target 承载；本文只定义准入语义。
