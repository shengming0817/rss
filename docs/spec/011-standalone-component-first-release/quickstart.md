# Quickstart: Standalone Component 规格入口

## 当前规格验证

运行 [`Spec 010 quickstart`](../010-release-surface-convergence/quickstart.md) 中的一次性结构、链接、advisory 和仓库
验证命令。该 smoke 覆盖三份产品化 Spec，本文件不复制第二套命令。

## 开始后续 PBI 前

1. 回读对应 Azure PBI 及其 `Blocked-by`，确认所有前置 outcome 已真实落地。
2. 从当前 Cargo metadata 和候选源码读取 package、依赖、feature、MSRV 与 publish 事实。
3. 确认 [`Spec 010`](../010-release-surface-convergence/spec.md) 的正向发布集合和 release-check owner 已存在。
4. 只运行 PBI 实际检入的 canonical command；本文不预建 package、consumer 或 RC 占位命令。

## 验收顺序

```text
governance approval
-> public naming approval
-> Cargo closure
-> shared packaging mechanics
-> two candidate APIs, each with same-revision final artifact proof
-> independent consumer of those final artifacts
-> manual RC closeout
```

任何阶段缺失都不能由后续 receipt 或人工文字补写为通过；API 改动会使先前 artifact proof 失效。真实 publish 始终在
本规格之外，由维护者单独批准。
