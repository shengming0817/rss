# Tasks: 测试与 AI-Hard 载体收敛

**Input**: [spec.md](./spec.md)、[plan.md](./plan.md)、[research.md](./research.md)
**Tracking**: Azure Boards 是状态真源；本文件只维护逻辑需求与 Work Item 映射。

## 工作项映射

Epic：[#1973](https://dev.azure.com/shengming0923/rss/_workitems/edit/1973)

| Logical ID | Azure ID | Outcome | Blocked-by |
|---|---:|---|---|
| TAH-R3-01 | [#1974](https://dev.azure.com/shengming0923/rss/_workitems/edit/1974) | AMQP feature-off Freeze 决策 | — |
| TAH-R3-02 | [#1975](https://dev.azure.com/shengming0923/rss/_workitems/edit/1975) | T3 product-surface ADR-024 amendment | — |
| TAH-R3-03 | [#1976](https://dev.azure.com/shengming0923/rss/_workitems/edit/1976) | settings/identity signature smoke 清理 | — |
| TAH-R3-04 | [#1977](https://dev.azure.com/shengming0923/rss/_workitems/edit/1977) | audit/bootstrap/consistency Noop 清理 | — |
| TAH-R3-05 | [#1978](https://dev.azure.com/shengming0923/rss/_workitems/edit/1978) | Cargo-owned live/artifact eligibility | — |
| TAH-R3-06 | [#1979](https://dev.azure.com/shengming0923/rss/_workitems/edit/1979) | PostgreSQL 巨型 carrier seam 拆分 | — |
| TAH-R3-07 | [#1980](https://dev.azure.com/shengming0923/rss/_workitems/edit/1980) | PostgreSQL conformance 差量去重 | TAH-R3-06 |
| TAH-R3-08 | [#1981](https://dev.azure.com/shengming0923/rss/_workitems/edit/1981) | AMQP/eventing conformance 差量去重 | TAH-R3-01, TAH-R3-06 |
| TAH-R3-09 | [#1982](https://dev.azure.com/shengming0923/rss/_workitems/edit/1982) | Vault live T2 target | TAH-R3-05 |
| TAH-R3-10 | [#1983](https://dev.azure.com/shengming0923/rss/_workitems/edit/1983) | T3 carrier convergence | TAH-R3-02, TAH-R3-07, TAH-R3-08, TAH-R3-09 |
| TAH-R3-11 | [#1984](https://dev.azure.com/shengming0923/rss/_workitems/edit/1984) | runtime_assembly_residual semantic reduction | TAH-R3-10 |
| TAH-R3-12 | [#1985](https://dev.azure.com/shengming0923/rss/_workitems/edit/1985) | assembly scanner reduction | TAH-R3-10 |
| TAH-R3-13 | [#1986](https://dev.azure.com/shengming0923/rss/_workitems/edit/1986) | consistency/localtx scanner reduction | TAH-R3-07 |
| TAH-R3-14 | [#1987](https://dev.azure.com/shengming0923/rss/_workitems/edit/1987) | event_transport_guard 逐规则收缩 | TAH-R3-08 |
| TAH-R3-15 | [#1988](https://dev.azure.com/shengming0923/rss/_workitems/edit/1988) | pg_tenant_tx_guard 误判修复与逐规则收缩 | TAH-R3-07 |
| TAH-R3-16 | [#1989](https://dev.azure.com/shengming0923/rss/_workitems/edit/1989) | testkit external PG ownership 与内部 closeout | TAH-R3-07, TAH-R3-08, TAH-R3-09, TAH-R3-13, TAH-R3-14, TAH-R3-15 |
| TAH-R3-17 | [#1990](https://dev.azure.com/shengming0923/rss/_workitems/edit/1990) | 条件发布 rss-conformance | TAH-R3-16 + external consumer trigger |
| TAH-R3-18 | [#1991](https://dev.azure.com/shengming0923/rss/_workitems/edit/1991) | 条件发布 rss-test-postgres | TAH-R3-17 + PostgreSQL consumer trigger |
| TAH-R3-19 | [#1992](https://dev.azure.com/shengming0923/rss/_workitems/edit/1992) | 条件发布 rss-test-eventing | TAH-R3-17 + eventing consumer trigger |

## 本规格 PR

- [x] 基于当前 HEAD 复核外部 R2 事实。
- [x] 删除已失效 deviceloop 工作项并拆开 AMQP/T3 决策。
- [x] 形成 19 个符合当前标签与依赖规则的 PBI 设计。
- [x] 创建 Epic 与 19 个 PBI，建立原生父子关系。
- [x] 用真实 Azure ID 回填工作项映射。
- [x] 验证 spec 结构、链接、占位符与当前 HEAD 一致。

## 后续实施约束

- 每个 PBI 开始前重新读取其 Files 与 candidate revision；行号只作为创建时证据坐标。
- scanner reduction 不跨 PBI 共改同一 owner 文件。
- companion PBI 在 Trigger 未满足时不进入实施 wave。
- Epic 的 Wave 1–4 与超窗分组由 blocked-by DAG 和实时 OPEN 状态生成，不固化在本规格。
- 与本系列重叠的旧 work item 只保留历史链接；完整吸收者关闭为 superseded，独立风险者追加边界评论后保留。
