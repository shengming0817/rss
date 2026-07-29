# #1776 LocalTx required evidence 激活清单

## 代码载体与完成边界

LocalTx 的静态 inventory 由 `verify --fast` / `localtx-coverage` 证明；真实 Postgres 证据只由
`integration/postgres-domain` 全部 typed batches 成功后生成的 v3 receipt 证明。`ci-gate` 成功 envelope
必须输出 `localtxContractCount`，并要求 receipt 的单一 `localtxContractIds` 集合分别与当前
active/journey/backend-profile inventory exact equal。

仓库代码与 workflow 合并不等于 active forge 已具备 required merge boundary。当前 Azure 仍是 forge authority，
GitHub Actions 仍为 Shadow；在下面的 required-check 配置与 RED/GREEN 实证完成前，#1776 保持打开。

## Post-merge operator checklist

- [ ] 记录 active forge、PR authority、操作者和 UTC 时间；不得只记录显示名称。
- [ ] 若 PR authority 迁移到 GitHub，把精确 check-run context `ci-gate` 及其 GitHub App identity 配为 required。
- [ ] 若继续使用 Azure，为同一 typed planner/executor/gate 部署 Azure build validation 或受信 bridge；不得把
      GitHub Shadow 的可观测状态直接当成 Azure required policy。
- [ ] 建立缺少 `integration/localtx-required.json`（或使任一 LocalTx journey 失败）的验证 PR，确认 gate 为 RED
      且 PR 不可合入；记录 PR、run、attempt、HEAD SHA、check URL 与失败分类。
- [ ] 在同一 policy/context 下重跑完整 exact-set same-head 验证，确认 gate 为 GREEN 且只在此时允许合入；记录
      PR、run、attempt、HEAD SHA、artifact URL 与成功 envelope。
- [ ] 核对 required context 的 app identity 与两次验证完全一致，且 rerun attempt 不能复用旧 receipt。
- [ ] 将上述证据链接回填 #1776；全部完成后再关闭 issue。若平台无法绑定 required check，记录阻塞并保持
      issue 打开，不以人工 checklist 勾选替代机器门。

## 取证字段

最终记录至少包含：`forge`、`repository`、`branch`、`requiredContext`、`appId`、`policyId`、`operator`、
`configuredAtUtc`、RED/GREEN 的 `pr`、`runId`、`runAttempt`、`sourceRevision`、`planDigest`、`artifactUrl`、
`checkUrl` 与 gate verdict。不得复制 receipt 内容中的未知自由文本作为安全诊断。
