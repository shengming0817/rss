# RSS 规则目录

本目录是稳定规则的人类可读投影；安全、正确性、兼容性与运行不变量的生产证据只能来自 Cargo/rustc、
类型、schema/codegen、lint/gate、provider conformance 或真实 integration。规则文件不是 enforcement carrier。

## 写作形状

每个文件只拥有一个稳定主题，每节只保留：

- 适用边界；
- MUST / MUST NOT 与失败语义；
- canonical Hard/Medium carrier。

禁止写入交付历史、issue/PR 编号、阶段计划、当前数量、exact inventory、API walkthrough、fixture/runner 教学、
指标目录或 gate 内部算法。可执行精确事实留在代码、manifest、typed catalog 或配置；决策理由留在 ADR。

技术 MUST 必须能定位到既有 Hard/Medium carrier。没有 carrier 的技术愿望不得保留为 active rule，也不得为了
锁 Markdown 新增 gate。产品范围与 owner policy 可以作为规划真源，但不得声称是运行证据。

## 引用纪律

- 本文件是规则发现的唯一索引。
- `CLAUDE.md` 与 `AGENTS.md` 只引用本入口。
- 代码、rustdoc、contract、模板、ADR/spec 与 ops 文件不得引用具体规则文件；应引用 Invariant ID、真实类型、
  manifest、gate、测试 target 或 ADR。
- 规则文件之间不互链、不复制正文；边界通过本索引的 owner 划分表达。

## Owner 索引

### 治理与架构

| 文件 | Canonical owner |
|---|---|
| [`project-scope.md`](project-scope.md) | Evolve/Complete/Freeze/External 与能力边界 |
| [`verification-scope.md`](verification-scope.md) | T1–T3、GA trigger 与 production acceptance |
| [`architecture.md`](architecture.md) | 架构风格、命名与 owner 总图 |
| [`workspace-architecture.md`](workspace-architecture.md) | workspace 职责与分层 |
| [`ai-robust.md`](ai-robust.md) | Hard/Medium/Soft 与 carrier 选择 |
| [`dependency-policy.md`](dependency-policy.md) | 上游优先、依赖与自研准入 |

### Runtime、contract 与域实现

| 文件 | Canonical owner |
|---|---|
| [`runtime-composition.md`](runtime-composition.md) | manifest、RuntimePlan、provider closure 与 lifecycle |
| [`runtime-api.md`](runtime-api.md) | HTTP/runtime route 边界 |
| [`api-versioning.md`](api-versioning.md) | Release API、wire 与 breaking policy |
| [`contract-fanout.md`](contract-fanout.md) | contract owner 与 fanout |
| [`error-handling.md`](error-handling.md) | 错误码、detail 与脱敏 |
| [`domain-patterns.md`](domain-patterns.md) | 域 crate 实现模式 |
| [`rust-standards.md`](rust-standards.md) | Rust 语言与 API 惯例 |

### 一致性与消息

| 文件 | Canonical owner |
|---|---|
| [`local-consistency.md`](local-consistency.md) | L0 LocalOnly 与 L1 LocalTx |
| [`event-transport.md`](event-transport.md) | topology、AMQP/MQTT、envelope 与 subscription |
| [`outbox.md`](outbox.md) | L2 producer/fact、relay 与 same-ID window |
| [`event-delivery.md`](event-delivery.md) | consumer、settlement、ordering 与 dead letter |
| [`command-delivery.md`](command-delivery.md) | command dispatch 与 durable journal |
| [`projection.md`](projection.md) | projection apply、checkpoint 与 rebuild |
| [`saga.md`](saga.md) | Saga identity、step、receipt 与 worker |
| [`reconcile.md`](reconcile.md) | L4 reconcile、fencing 与 durable state |

### 安全与可观测

| 文件 | Canonical owner |
|---|---|
| [`tenant-context.md`](tenant-context.md) | TenantId、authority 与 RowScope |
| [`tenant-persistence.md`](tenant-persistence.md) | tenant transaction、RLS 与 ACL |
| [`authorization.md`](authorization.md) | permission、PDP、obligation 与 resource fact |
| [`certificate-revocation.md`](certificate-revocation.md) | 设备证书撤销 |
| [`audit-ledger.md`](audit-ledger.md) | tamper-evident audit ledger |
| [`observability.md`](observability.md) | logging、redaction、metrics 与 readiness |
