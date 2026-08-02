# Implementation Plan: 测试与 AI-Hard 载体收敛

**Branch**: `docs/test-ai-hard-r3`
**Date**: 2026-08-02
**Spec**: [spec.md](./spec.md)

## 摘要

本 PR 只入库校准后的 SpecKit 规范并创建 Azure Boards 工作项，不改变运行行为。后续实施按 provider lower-layer
evidence、production acceptance policy 与 scanner replacement 顺序推进。

## Constitution Check

- **项目范围**：PASS。只处理 Domain Governance、DI Port/Adapter、Consistency 与项目专属验证载体，不扩张 CI 平台。
- **事实源**：PASS。Cargo 拥有 eligibility，provider catalog 拥有 enrollment，Azure Boards 拥有 backlog 状态。
- **AI-robust**：PASS。删除重复 Medium carrier 前要求已有 Hard/Medium canonical owner；不把文档当 enforcement。
- **T3**：PASS WITH DECISION. 当前规则不在本 PR 中静默变更，先建独立 ADR amendment PBI。
- **外部能力**：PASS。companion 在真实 consumer 前保持条件状态。
- **代码影响**：PASS。本 PR 不修改 Rust/Cargo/assembly/generated/migration。

## 交付 DAG

```text
AMQP Freeze ───────────────┐
                          ├─ AMQP conformance dedup ─┐
PostgreSQL carrier split ─┼─ PostgreSQL dedup ──────┼─ T3 carrier convergence
                          │                           │
Cargo eligibility ─ Vault live T2 ──────────────────┘

T3 policy ───────────────────────────────────────────┘

PostgreSQL dedup ─ consistency/localtx scanner reduction ─┐
AMQP dedup ─ event transport scanner reduction ──────────┤
PostgreSQL dedup ─ PG tenant scanner bug + reduction ─────┼─ testkit closeout

testkit closeout + external trigger ─ rss-conformance
rss-conformance + provider trigger ─ postgres/eventing companion
```

## 阶段

### Phase A — 决策与可维护性基础

- AMQP feature-off Freeze 决策。
- T3 product-surface ADR-024 amendment。
- signature smoke/test-only Noop 清理。
- Cargo-owned eligibility。
- PostgreSQL carrier 拆分。

### Phase B — Lower-layer provider evidence

- PostgreSQL conformance 差量去重。
- AMQP conformance 差量去重。
- Vault live T2 target。

### Phase C — Production carrier 与治理收缩

- 按 policy 与真实 lower-layer receipts 处置 T3 carrier。
- 分别收缩 runtime、assembly、consistency/localtx、event transport 与 PG tenant scanners。
- 完成 testkit 仓内 ownership closeout。

### Phase D — 条件外部消费

- `rss-conformance`。
- `rss-test-postgres`。
- `rss-test-eventing`。

## PR 约束

- 每个 PBI 对应一个 primary owner、一个可验证 outcome 和一个 PR 级闭包。
- 大规模机械移动只豁免 diff 行数，不允许夹带语义变化。
- scanner PR 必须实际减少规则/fixture/LOC，不能只拆文件。
- provider test 删除必须在同一 candidate revision 运行 canonical conformance。
- production carrier PR 必须满足 evidence plan、candidate-before-cutover 与 final-HEAD receipt。
- 每个 PR 收尾运行 `make ci CI_BASE=origin/develop`；仅按 PBI 需要运行重型 live target。

## 风险

- **误删唯一证明**：先记录 failure mode 与 canonical owner，保留 provider/cross-language residual。
- **T3 元数据膨胀**：policy 与 carrier 分离，运行 receipt 不进入 static registry。
- **巨型机械 diff 混入行为**：PostgreSQL 拆分 PR 禁止语义去重。
- **外部条件被文档伪造**：companion Trigger 必须指向真实 external repository 和通过的 fixture。
- **并行文件冲突**：PostgreSQL、testkit 与 scanner 任务按 Blocked-by 串行。
