# 验证范围

本文拥有 library workspace 的最低充分证明与测试选择边界；它不授权产品进程、部署或生产验收面。

## 证明层级

| 层 | 独有风险 | 典型 carrier |
|---|---|---|
| T1 | 类型、状态机、schema、组件不变量 | Cargo/rustc、类型、codegen、组件测试 |
| T2 | 真实 provider/transaction/transport seam | conformance、真实 DB/broker/identity integration |

- 约束强度与证据归属遵循[AI-robust 规则](ai-robust.md)，不由验证深度推导。
- 高层只证明低层无法观察的接缝风险。
- 按独立风险选择最低充分验证，不做全组合穷举或重复证明。
- 组件恢复决策归 T1，真实后端事务与持久化恢复语义归 T2；使用真实后端或验证进程中断不自动成为产品 T3。
- 产品完整生产闭环归产品 T3；产品进程、应用镜像、部署配置、production profile 与产品级 recovery 不属于本仓验证面。

## 独立消费与组合

- 独立消费、必要 feature 组合与真实 provider 行为分别提供证据，不用其中一种代替其它证明。
- 覆盖基础能力、真实独立选择及有交互风险的支持组合；隔离依赖解析，避免其它消费者补齐缺失能力。
- 构建成功、artifact 可消费和实际发布是不同事实；发布证明绑定被验证的版本与 artifact 身份。
- package 与依赖闭包以构建事实验证；文档不充当包清单、删除完成证明或运行记录。

## 默认选择

- 普通 PR 运行 affected T1 与必要 T2；rename/copy、全局输入、未知路径或分析异常必须 fail-full。
- 完整 conformance、fault/recovery、coverage 与 performance 属于 develop/release 或显式 full。
- candidate/release final-HEAD identity 验证只覆盖已接纳的 package artifact 与 release metadata；
  消费方应用装配、配置和运行计划漂移属于 External。
- performance 必须绑定已接纳的 library SLO；Markdown、聚合 receipt 和静态 inventory 不得冒充运行证据。

## No-new-work closeout

Closeout 只回读既有代码、测试和 JobResult，核对 canonical owner/selector，更新 traceability 并记录缺口。
不得新增产品代码、test carrier、benchmark、schema、selector、CI gate 或 receipt database。
缺 proof 时退回原 implementation owner；没有 owner 时另立实现项，closeout 不接管。
