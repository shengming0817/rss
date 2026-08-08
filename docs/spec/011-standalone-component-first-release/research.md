# Research: Standalone Component 候选边界

## 当前事实

- 产品面与候选/激活语义由 [`ADR-024`](../../architecture/202608012034-024-enterprise-framework-product-surface.md)
  拥有；公共消费和发布范围由 [`project-scope.md`](../../rules/project-scope.md) 拥有。
- [`Spec 010`](../010-release-surface-convergence/research.md) 已决定未进入正向发布集合的 package 默认 internal。
- 当前候选 package 仍使用仓内版本与 `publish = false`；这只证明尚未发布，不构成品牌、SemVer 或支持承诺。
- `diagctx` 已有仓内真实 consumer，并与授权 context 分离；`tracewire` 已承载 traceparent capture/restore，但其 internal
  API 形状不能直接升级为外部承诺。

本规格不复制 package inventory、代码行数或 API 符号快照。实现 PBI 必须重新从当前 Cargo metadata 与源码读取事实。

## 候选选择

首批只选择两个低依赖、框架中立的候选，以验证两类独立价值：

- diag-context：请求/任务范围内的 correlation 与诊断上下文；不参与身份、租户或授权决策。
- trace-context：W3C traceparent 的稳定线语义；具体 telemetry SDK 保持实现细节。

候选名称仅表达能力后缀。公开品牌、前缀、registry 可用性和最终 package 名由 #2046 的维护者决策拥有。

## 发布闭环决策

```text
governance owner
      |
public naming decision
      |
candidate Cargo closure
      |
shared packaging mechanics
      |
diag candidate + final artifact proof || trace candidate + final artifact proof
      |
independent Plain Rust consumer
      |
manual RC closeout
```

临时 workspace 外目录只证明 packaging mechanics，不能替代最终 API 产生后的 artifact proof。每个候选必须从其最终
revision 生成 `.crate` 并在 workspace 外完成 canonical proof；真实 consumer 只能消费这些已证明的 artifact，也不能
替代最终人工发布批准。

## 失败与信任边界

- 诊断和 trace propagation 是可观测信道，缺失或畸形输入 fail-open；它们不能 mint Principal、Tenant 或授权 receipt。
- TraceParent 必须先验证再暴露；成功恢复和各类拒绝结果产生闭值、无原始输入的诊断 outcome，不得把裸 SDK 类型
  变成公共 wire 语义。
- package tarball 必须是验证输入，workspace/path build 不能冒充发布证明。
- package digest 与 same-revision 结果只进入 closeout evidence，不形成 committed receipt database；早于最终 API 的
  mechanics 结果不得晋升为该证据。

## AI-HARD 判定

| 风险 | Owner | 载体 |
|---|---|---|
| 候选依赖 internal crate | Cargo dependency/publish closure | Hard graph + Medium package check |
| SDK/test-util 泄漏 | visibility、public signature、release API baseline | Hard/Medium T1 |
| malformed trace 静默丢失 | 闭值诊断 outcome + tarball consumer | Medium T1 |
| 诊断输入影响授权 | 类型/模块隔离与真实 consumer test | Hard 优先，补充 T1 |
| workspace build 掩盖 tarball 缺陷 | actual `.crate` + external Cargo invocation | Medium T1/T2 接缝 |
| 未经批准宣称发布 | human-owned closeout + release documentation | 人工决策；不伪装为代码 gate |

Markdown 只描述 owner 和失效模式，不承担 enforcement。
