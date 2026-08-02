# Research: 当前事实与方案校准

## 基线与边界

- Git baseline：`06d1351019cbe3d2f859290b17e949916329dd04`。
- 外部输入：`rss-test-ai-hard-integrated-plan-20260802-r2`，其源码真源是无 Git commit 对应的 ZIP。
- 外部交付结构校验通过，但没有执行 Cargo、Rust、Docker、PostgreSQL、RabbitMQ、Redis、Vault 或 image smoke。
- 当前 issue 真源是 Azure Boards；仓库不保存 backlog 状态副本。

## 已确认漂移

| 观察 | 当前事实 | 处置 |
|---|---|---|
| deviceloop 旧证书 API | 外部计划列出的符号在当前 HEAD 检索为 0 | 删除原 PBI |
| PostgreSQL carrier | `adapters/postgres/src/integration_tests.rs` 为 49,934 行，且已有一个子模块 | 重新按 seam 设计拆分，不照搬 44K 基线 |
| Provider conformance | PostgreSQL 与 AMQP 已有 catalog enrollment | 把“接入 suite”改为“差量去重与特有失效模式保留” |
| Vault live tests | 四个 live case 仍在 lib 内并依赖 `#[ignore]` | eligibility 与 T2 live target 仍成立 |
| T3 scope | 当前 `project-scope.md` 仍由 production assembly + join hazard 拥有 | product-surface 先走 ADR amendment |
| Official profiles | ADR-024 已声明 core/eventing，device-security 条件激活 | 不再声称实施分支缺少 ADR-024 |
| runtime baseline | baseline 已包含 fixture/builder carrier 缩减（关联 #1886） | 后续新建 rule-to-carrier 语义删除 PBI，不复用旧 issue |
| testkit external PG | baseline 仍含 external PG role provisioning 与 container/fixture lifecycle 耦合（关联 #1769） | 工作纳入新的 testkit closeout PBI，旧 issue 以 superseded 关闭 |

## 既有 issue 边界映射

| 既有 issue | 稳定关系 | R3 边界 |
|---|---|---|
| #1499 | superseded by #1980、#1981 | 全量 provider suite 前提已漂移，只保留 PostgreSQL/AMQP 差量 |
| #1769 | superseded by #1989 | external PG role ownership 与 fixture lifecycle 被完整吸收 |
| #1965 | superseded by #1984 | atomic baseline update 被 runtime baseline 收缩验收完整吸收 |
| #1969 | superseded by #1988 | 精确列识别与 guard 收缩被完整吸收 |
| #1219 | independent from #1981 | 独立跟踪 manual-ack `Reject -> broker DLX`，不属于已有 conformance 去重 |
| #1313 | independent from #1979 | integration clippy 门独立；carrier split 只可能移动载体位置 |
| #1856 | independent from #1979 | elapsed-time clippy 基线独立；carrier split 只可能移动载体位置 |
| #1970 | independent from #1982 | pinned-version 404 taxonomy 独立于 Vault live target |

实际状态与处置评论只保存在 Azure Boards 历史中，不在本规格复制。

## 采用决策

### Cargo 拥有 test eligibility

采用 `[[test]]`、`path` 与 `required-features`；nextest/CI 只决定执行，不复制 target existence。

### 复用现有 conformance

不新建 universal suite 平台。现有 testkit 与 provider capability matrix 是当前载体；每个去重 PBI必须先列出
重复行为、canonical behavior symbol 与 provider-specific residual。

### T3 分两步

1. Policy PBI：修订 ADR-024/project-scope，决定产品面 taxonomy、profile identity 与 CI 选择边界。
2. Carrier PBI：只有 policy 接受且 T1/T2 prerequisites 在 candidate revision 真实运行成功后，才执行
   activation、extension/redeclaration 或 replacement。

静态 `assemblies/artifacts.toml` 可以保存稳定 identity 和 selector，但 same-head receipts、历史 transition 与
产品接纳判断仍由 PBI/PR review evidence 承载。

### 外部 companion 延迟激活

三个 companion 使用独立 `flag-cond` PBI，保持可追踪但不进入实施 wave。Trigger 不是 issue 状态或 Markdown
checkbox，而是真实 external consumer repository + fixture + support policy。

## 已知并发冲突

- PostgreSQL carrier 拆分先于 PostgreSQL/AMQP 涉及该文件的去重。
- testkit closeout 先闭合 external PostgreSQL fixture ownership，再做 containers 模块移动。
- T3 carrier convergence 依赖 policy 与 PostgreSQL/AMQP/Vault lower-layer evidence。
- scanner reduction 只依赖对应 typed/generated/provider proof，不把 T3 当万能替代。
