# Quickstart: Standalone Component 规格入口

## 当前候选验证

`rss-diag-context` 与 `rss-trace-context` 已作为 standalone candidates 进入正向 Release Surface。以下命令验证
两者最终窄腰、双 profile Release API 与所有 selected package 的同 HEAD artifact proof：

```bash
cargo test -p rss-diag-context --all-features
cargo test -p rss-diag-context --doc
cargo test -p rss-trace-context --all-features
cargo test -p rss-trace-context --doc
cargo xtask public-api internal --check
cargo xtask public-api release --check
cargo xtask package-proof
```

`package-proof` 从 Release Surface 派生完整执行集合；两个 candidate 的独立 fixture 分别位于
`xtask/tests/fixtures/package_proof/diag-context` 与 `trace-context`，只消费 local registry 中的精确 archive 版本，
不使用 workspace path。该结果表示 candidate eligibility，不表示 RC、published 或 registry upload。

## 开始后续 PBI 前

1. 回读对应 Azure PBI 及其 `Blocked-by`，确认所有前置 outcome 已真实落地。
2. 从当前 Cargo metadata 和候选源码读取 package、依赖、feature、MSRV 与 publish 事实。
3. 确认 [`Spec 010`](../010-release-surface-convergence/spec.md) 的正向发布集合和 release-check owner 已存在。
4. 只运行 PBI 实际检入的 canonical command；不得为独立仓 consumer 或 RC 预建占位结果。

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
