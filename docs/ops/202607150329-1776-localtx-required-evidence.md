# #1776 LocalTx live proof 激活清单

## 代码载体与完成边界

LocalTx 静态 inventory 由 affected `make ci` 选择的 `localtx-coverage`（或显式直接运行该 gate）证明；固定
repository-fast 门不拥有 LocalTx 证据。真实 Postgres 行为由 postgres integration carrier 根据 canonical
`SelectionPlan` 选中 `postgres-domain` units 后执行；稳定 `integration-critical` 只聚合四组结果：

```bash
cargo xtask ci run --job integration-critical --integration-group postgres --selection '<canonical SelectionPlan JSON>'
```

selection 必须来自 preflight 并包含所需稳定 unit ID；只有 `postgres` group 能构造 LocalTx 发布资格。全部 typed batches、active/journey/backend-profile
exact-set 和真实后端断言在该执行单元内 fail-closed。PR 的 result-only gate 只读取固定 Job 最终结果，不下载
或核对额外报告；诊断 artifact 不能把失败执行改写为通过。

`PrComplete` 只会选择 PR 固定图内的 critical units，不等于 `ReleaseCheck`。全部 Postgres/integration catalog
只属于 develop、nightly、release 或显式 `cargo xtask ci full`。

## Post-merge operator checklist

- [ ] 记录 active forge、PR authority、操作者和 UTC 时间；不得只记录显示名称。
- [ ] 若 PR authority 迁移到 GitHub，从 GitHub API 读取稳定 result-only gate context 与 app identity，再配置
      branch protection；不得绑定 shard 或动态显示名。
- [ ] 若继续使用 Azure，为同一固定 Job/result-only 语义部署 Azure build validation 或受信 bridge；不得把
      GitHub Shadow 的可观测状态直接当成 Azure required policy。
- [ ] 建立使一个被选 LocalTx journey 失败的验证 PR，确认 `integration-critical` 为 RED、gate 为 RED 且 PR
      不可合入；记录 PR、run、attempt、HEAD SHA、context 与失败分类。
- [ ] 在同一 policy/context 下仅修复该失败，确认固定 Job 与 gate 为 GREEN；记录相同身份信息和选择摘要。
- [ ] 核对 required context 的 app identity 与两次验证完全一致，且 rerun 不复用旧结果。
- [ ] 将证据链接回填 #1776；全部完成后再关闭 issue。若平台无法绑定 required check，记录阻塞并保持 issue
      打开，不以人工 checklist 替代机器门。

最终记录至少包含：`forge`、`repository`、`branch`、`requiredContext`、`appId`、`policyId`、`operator`、
`configuredAtUtc`，以及 RED/GREEN 的 PR、run、attempt、source revision、selection summary、check URL 与
gate verdict。不得复制日志中的 secret、endpoint 或未知自由文本。
