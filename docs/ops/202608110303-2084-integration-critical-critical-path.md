# #2084 integration-critical 关键路径验收

## 目标与边界

本变更只优化 RSS 项目专属 CI carrier，不减少 canonical T1/T2/T3 证明，也不建立 matrix、动态 scheduler、
通用 cache 平台或 evidence database。验收目标是明显编译/治理错误在 10 分钟内阻止昂贵 integration，
且同 runner/toolchain/cache 条件下冷成功关键路径不超过 45 分钟。

## Carrier replacement

- 旧 `selector`、无 group 的串行 `integration-critical` executor 和 Rust `ci gate` 已删除。
- `preflight` 构建一次 xtask，生成 canonical `SelectionPlan` 并执行有界治理早筛；adaptive 只 check
  affected package 闭包，`PrComplete`/`ReleaseCheck` 才执行 workspace check。
- 七个 canonical shard 的唯一执行分组由 `IntegrationJobGroup` 穷尽投影为 `postgres`、`transport`、
  `runtime`、`artifact`；group 不成为 proof owner。
- 四个 group 具有独立 compiler target/key、container scope、lifecycle/log/archive identity；稳定
  `integration-critical` 只聚合结果。
- LocalTx 只有 postgres group 成功后才能构造 typed publish capability；LocalOnly/LocalTx 均先校验报告，
  producer 未成功时不进入 upload step。

## AI-robust 评级

| Invariant | 强度 | Carrier |
|---|---|---|
| shard 对 group 的 exact-cover 与唯一投影 | Hard | 闭合 enum、穷尽 match、私有 selection |
| LocalTx 唯一 producer | Hard | `PostgresDomainPassed` + `VerifiedLocalTxContractSet` 必填发布参数 |
| workflow DAG、result binding、artifact 条件 | Medium | parsed YAML 结构守卫 + synthetic red |
| compiler/container/artifact partition | Medium | 闭合 shell policy + selftest + workflow 守卫 |

GitHub Actions 是外部运行时状态，按 `docs/rules/ai-robust.md` 不建设 workflow codegen 来伪装 Hard。

## 基线与验收记录

Before 背景 run：GitHub Actions `31324013626`，revision 与缓存状态以 run 页面为准；总耗时 90 分 53 秒，
`integration-critical` 约 86 分钟。早期 integration 失败后其余 shard 继续约 47 分钟，随后缺少 LocalTx
artifact 产生次生失败。该 run 只作为问题证据，不作为修复后全绿 baseline。

PR #790 创建时，激活 forge 的 capability probe `bash hack/automation/forge.sh has-ci` 返回 `false`。
当前激活 forge 为 Azure DevOps，项目流程明确不使用额度受限的 Pipelines 冒充可用 CI；因此本 PR 无法在
当前环境生成真实 runner timestamps。以下远端 SLA receipts 保持未满足，不能用本地 synthetic-red 或旧失败
run 伪造。CI capability 恢复后须在临时验证 ref 按同条件补齐，并在完成后删除临时 ref：

| 样本 | Run URL / SHA | cache restore | preflight | 最慢 group | ci-gate 总时长 | 结论 |
|---|---|---|---:|---:|---:|---|
| cold before full-green | BLOCKED：active forge 无 CI | cold | — | — | — | 外部 capability 待恢复 |
| cold after full-green | BLOCKED：active forge 无 CI | new v7/v4 epochs | — | — | — | 外部 capability 待恢复；仍须 ≤45m |
| warm after | BLOCKED：active forge 无 CI | observable hit | — | — | — | 外部 capability 待恢复 |
| synthetic compile/governance red | BLOCKED：active forge 无 CI | 任意 | — | 四组应 skipped | — | 外部 capability 待恢复；仍须 ≤10m |

每个 receipt 同时记录 runner/toolchain、`CARGO_BUILD_JOBS`、cache primary/matched key、sccache
requests/hits/misses/errors；不能混用 warm 样本证明 cold SLA。

本地可验证的闭环不是远端 SLA 替代品：parsed-YAML synthetic-red 已覆盖 carrier 删除/重复 binding、漏 needs、
gate 恒成功或放行 skipped、raw group identity、evidence upload 条件及 matrix/fromJSON 回退；三个 lifecycle/cache
selftest 验证路径、key 和清理身份隔离。远端 acceptance 仍以本表四个真实 run 为唯一完成条件。
