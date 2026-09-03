# 验证范围

本文拥有 library workspace 的最低充分证明与测试选择边界；它不授权产品进程、部署或生产验收面。

## 证明层级

| 层 | 独有风险 | 典型 carrier |
|---|---|---|
| T1 | 类型、状态机、schema、组件不变量 | Cargo/rustc、类型、codegen、组件测试 |
| T2 | 真实 provider/transaction/transport seam | conformance、真实 DB/broker/identity integration |

- Hard/Medium/Soft 是 enforcement 强度，T1–T2 是验证深度，两轴不得互相推导。
- 每个 invariant 只有一个 canonical owner；高层只证明低层无法观察的 seam hazard。
- 禁止 domain × provider × assembly × fault 的笛卡尔积和“多一道保险”重复证明。
- 产品进程、应用镜像、部署配置、production profile 与产品级 recovery 不属于本仓验证面。

## 默认选择

- 普通 PR 运行 affected T1 与必要 T2；rename/copy、全局输入、未知路径或分析异常必须 fail-full。
- 完整 conformance、fault/recovery、coverage 与 performance 属于 develop/release 或显式 full。
- committed AssemblyLock/RuntimePlan 的 repository raw-byte drift 属于 candidate/release final-HEAD identity
  验证；普通 PR 依赖 assembly build-time repository verification 与 RuntimePlan bound parse。
- performance 必须绑定已接纳的 library SLO；Markdown、聚合 receipt 和静态 inventory 不得冒充运行证据。

## No-new-work closeout

Closeout 只回读既有代码、测试和 JobResult，核对 canonical owner/selector，更新 traceability 并记录缺口。
不得新增产品代码、test carrier、benchmark、schema、selector、CI gate 或 receipt database。
缺 proof 时退回原 implementation owner；没有 owner 时另立实现项，closeout 不接管。
