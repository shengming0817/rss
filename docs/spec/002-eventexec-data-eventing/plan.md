# Implementation Plan: eventexec 数据持久化与事件处理

**Branch**: `002-eventexec-data-eventing` | **Date**: 2026-06-23 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/002-eventexec-data-eventing/spec.md`

**Tracking**: Azure Boards Feature #1005 · Epic #991（W 宽扇出）· #1100 折为 P8

## Summary

在 G0/#997 已冻结的 trait/type 签名内，兑现 `consistency` 引擎 body + `eventexec` runtime 驱动 + durable adapters（postgres/redis/amqp）+ topology-gated 接线，覆盖 inbox/outbox/saga/reconcile/cqrs-projection/command 七机制。技术路径已大体由架构决策冻结（ADR-003 派发、ADR-004 签名、对标 watermill/steno/kube-rs）；本计划裁定两个开放项、固定 crate 落位与依赖序，并把工作切成 12 个 ≤2000 行 PR（4 wave）。

## Technical Context

**Language/Version**: Rust（`rust-toolchain.toml` 固定 stable 1.96；lints workspace 自成 nightly workspace，不参与根构建）

**Primary Dependencies**:
- 引擎策略 trait：native AFIT + 泛型静态分发（`#[allow(async_fn_in_trait)]`，不引 dynosaur / async-trait）—— ADR-003 §2 / ADR-004 C1
- DI port：`dynosaur` `=0.3.0` + `trait_variant`（Send 变体）—— ADR-003，收敛于 `diport`
- 持久化：`sqlx`（postgres，编译期查询校验 + `sqlx::migrate!`）、`lapin`（amqp）、`redis`（claimer / distlock）
- 异步：`tokio`（JoinSet + CancellationToken 结构化并发）、`futures`
- 错误：`thiserror`（库枚举，message `&'static str` const，C10）；engine 类型不 derive serde（C6）
- 测试：`cargo-nextest`（进程隔离）、`rstest`（表驱动）、`insta`（golden）、`mockall`（mock）

**Storage**: PostgreSQL（outbox / inbox dedup / dead-letter / saga journal / checkpoint / projection_events）；Redis（leader-elect lease / fencing / CAS 等 runtime 原语）；AMQP broker（per-domain 事件传输）。demo 拓扑全部以 `adapters/memory` in-mem 替身。

**Testing**: 单测 fake/in-mem 替身（`#[cfg(test)]`）；持久化集成测试 `#[cfg(feature = "integration")]` 门控（`tests/`）；L0 表驱动 / L1 事务完整性 / L2 原子性+幂等 / L3 replay+投影重建 / L4 状态机+超时+fencing。

**Target Platform**: Linux server（单进程 demo + 多副本 durable 两拓扑）

**Project Type**: Rust 扁平 workspace（库 crate + adapters + contracts + bins + xtask + generated）

**Performance Goals**: 非本阶段硬指标；relay/sweeper/consumer 后台环须 bounded（无无限重试挂线程，`MAX_REDELIVERY` 已立）；列表/扫描分页有上限。

**Constraints**: 每 PR ≤ 2000 行净增删（例外书面理由）；只填 body 不改冻结签名；durable 拓扑 fail-closed；新增治理 ≥ Medium（严禁 Soft）。

**Scale/Scope**: 12 PR / 4 wave；触及 crate：`consistency`、`eventexec`、`diport`(只消费)、`bootstrap`(resolver)、`adapters/{postgres,redis,amqp,memory}`、`identity`/`audit`(P8)、`xtask`(治理)、`generated`/`contracts`(command/saga kind)。

## Constitution Check

*GATE: 本仓无独立宪法文件——CLAUDE.md 为最高协作规范，docs/rules/* + .claude/rules/rss/* + ADR 为细则。逐条核查：*

- **分层依赖（crate 图 + deny.toml）**：✅ consistency(引擎) 不依赖服务/域/adapter；eventexec(服务) 依赖基础+引擎+diport，不依赖域/adapter；adapter 实现 trait 不被域依赖；resolver 落组合根侧 bootstrap。无新增跨域 crate 依赖。
- **跨域只经 contract**：✅ 新增 command/saga 契约走 `contracts/` 声明 → `generated/`；不新增手写共享 wire crate。
- **一致性等级落 contract.toml**：✅ consistencyLevel 在 contract.toml（command=L2、saga=L3），不入域 crate manifest。
- **AI-robust 三档**：✅ 优先编译期（sealed in-mem 原语、Tenancy 必填 sealed 参、构造器必填依赖、Entry/HandleResult funnel、`#[non_exhaustive]` 穷尽 match）；治理测试仅用于类型系统管不到的边界（active subscriber、L2 原子性+幂等、saga governance、command 双侧对称、append-only DML），均 Medium；append-only DML 守用 dylint（AST 级）。无 Soft 新增。
- **错误/PII**：✅ engine message const literal、broker 凭据 redaction、envelope reserved key 受控注入。
- **Rust 规范**：✅ Clock 构造器位置参（非 Option/Config）；必填依赖非 Option；认知复杂度 ≤15（已见 dispatch_one 拆分范式）；覆盖率 consistency ≥90% / 其余 ≥80%。
- **API 版本**：✅ pre-GA 窗口（至 2026-12-31）内 wire 破坏式原地改 active 版本 + 扇出闭环。
- **迁移规范**：✅ migration 只增不改、新字段默认值/NULL、pre-GA 普通 `CREATE INDEX`、命名 `{序号}_{动词}_{对象}.sql`。

**结论**：无违反，无需 Complexity Tracking 豁免。

## 开放项裁定（plan 决策）

### 决策 1：reconcile Loop harness 落位 → `eventexec`

reconcile 的**引擎策略 trait**（`Reconciler` native AFIT）已在 `consistency::reconcile`。其**运行时 Loop harness**（Builder + Trigger + per-entity 退避 + leader-gated dispatch + panic→transient 映射）是后台环运行时，与 outbox relay / saga executor / command 同属「事件执行与编排运行时」语义。

- **裁定**：落 `eventexec`（新增 `eventexec::reconcile` 模块），与 saga executor·tailer 并列。理由：(a) 1005 = eventexec 是 runtime 单源；(b) 复用 eventexec 已有 tokio 结构化并发（JoinSet + CancellationToken）与 leader/lease 接线点；(c) 避免新建第四类运行时 home。
- **LeaderElector / FencedWriter** 这两个**可替换 provider** 的 trait 走 DI port 范式——定义入 `diport`（dynosaur dyn），impl 入 `adapters/{redis,postgres}` + 测试 fake；Loop harness 经构造器注入 `Option<Box<DynLeaderElector>>`（None=单进程 always-leader）。
- 注：`deviceloop`(#1008，L4 cert) 是 reconcile 的**消费者**（证书续期 reconciler），不是 harness owner；本 feature 只交付通用 harness，不实现 cert reconciler。

### 决策 2：saga 与 projection 共享 `OwnerCheckpointStore` → 拆到先落的 P9，P10 复用

saga journal resume 与 projection 断点续投都需要 `OwnerCheckpointStore`（owner + checkpoint id + offset + CAS 版本）。

- **裁定**：`OwnerCheckpointStore` trait（diport DI port）+ postgres `checkpoint` 表 migration 落 **P9（saga）**；**P10（projection）直接复用**，不重复定义。`sagaprojectiondeps` resolver 的 checkpoint 分支也在 P9 建好，P10 只接 projection 专属的 projection_events 表。
- 理由：避免 P9/P10 同文件（resolver、checkpoint trait）写冲突；checkpoint 是 saga 的硬前置（resume）、projection 的硬前置（续投），先落于 saga 更贴 journal 语义。
- **依赖后果**：P10 blocked-by P9（仅就 checkpoint 接缝；projection 其余逻辑独立）。若要 P9/P10 完全并行，备选是单开「P9a checkpoint store」前置 PR——本计划不采（增 PR 数，checkpoint 体量小，并入 P9 更简洁）。

## Project Structure

### Documentation (this feature)

```text
specs/002-eventexec-data-eventing/
├── plan.md              # 本文件
├── research.md          # Phase 0：技术决策 + 对标 + 两开放项依据
├── data-model.md        # Phase 1：实体 + postgres 表 + 状态机
├── quickstart.md        # Phase 1：双拓扑端到端验证指南
├── contracts/           # Phase 1：新增 command/saga 契约形态说明
└── tasks.md             # Phase 2（/speckit-tasks 产出，≈12 PR）
```

### Source Code (repository root)

```text
crates/consistency/src/         # P1/P2：error/idempotency/outbox/saga/reconcile/projection body
crates/eventexec/src/
├── lib.rs                       # 既有 run_dispatch（已实现）
├── relay.rs                     # P4：relay CAS 循环 + sweeper
├── consumer.rs                  # P7：ConsumerBase（claim→handle→commit/release）+ DLX
├── saga.rs                      # P9：SagaExecutor/SagaTailer body + 逆序补偿
├── projection.rs                # P10：投影 harness + 断点续投
├── reconcile.rs                 # P11（决策1）：Loop harness + Builder + leader-gated
└── command.rs                   # P12：runtime command::emit_async
crates/diport/src/              # P11：leader_elector.rs / fenced_writer.rs；P9：checkpoint_store.rs（DI port）
crates/bootstrap/src/           # P5/P6/P9：eventtransport / replaydeps / sagaprojectiondeps resolver（sealed）
adapters/postgres/              # P3 基座；P4 outbox 表；P5 inbox；P7 dead-letter；P9 saga instance+journal+checkpoint；P10 projection_events
├── migrations/                 # P3 起：{序号}_{动词}_{对象}.sql（sqlx::migrate!）
adapters/redis/                 # P5 claimer；P11 leader-elect/fencing
adapters/amqp/                  # P6：lapin Publisher/Subscriber
contracts/{command,saga}/...    # P12/P9：新契约 kind + schema
generated/                      # P12：command emit/register wrapper（codegen）
crates/identity/, crates/audit/ # P8（#1100）：durable 接线 + consumer 幂等
xtask/                          # P9/P12：saga governance + command 双侧对称 + codegen 完整性
lints/                          # P10：append-only DML dylint（rss_projection_append_only）
```

**Structure Decision**：扁平 workspace 既定；本 feature 不新增 crate（reconcile harness 入 eventexec、DI port 入 diport），只新增模块文件 + adapter 实现 + migrations + 2 个契约 kind + 1 个 dylint。

## 12-PR 分层（4 wave）

| PR | crate/路径 | 一致性等级 | 依赖 | ~行 |
|----|-----------|-----------|------|-----|
| P1 consistency body L0–L2 | consistency: error/idempotency/outbox | L0/L1/L2 | — | 600–900 |
| P2 consistency body L3–L4 | consistency: saga/reconcile/projection | L3/L4 | P1 | 500–700 |
| P3 postgres 基座 | adapters/postgres: Pool/Tx/Migrator+migrations | — | — | 400–700 |
| P4 outbox+relay+sweeper | eventexec/relay.rs + adapters/postgres outbox 表 | L1/L2 | P1,P3 | 1000–1500 |
| P5 idempotency/inbox+replaydeps | adapters/{postgres,redis} + bootstrap replaydeps | L0 | P1,P3 | 700–1000 |
| P6 amqp+eventtransport | adapters/amqp + bootstrap eventtransport | — | diport | 800–1200 |
| P7 ConsumerBase+DLX | eventexec/consumer.rs + dead-letter store | L2 | P4,P5 | 1000–1400 |
| P8 #1100 identity durable | identity/audit + journey + L2 治理 | L2 | P4,P5,P7 | 600–1000 |
| P9 saga instance+journal+checkpoint | eventexec/saga.rs + instance/journal/checkpoint + sagaprojectiondeps + xtask | L3 | P2,P3,P7 | 1200–1800 |
| P10 projection+续投 | eventexec/projection.rs + projection_events + dylint | L3 | P2,P3,P7,P9(checkpoint) | 1000–1500 |
| P11 reconcile+leader+fencing | eventexec/reconcile.rs + diport + adapters | L4 | P2 | 1200–1800 |
| P12 command+codegen | eventexec/command.rs + contracts/command + generated + xtask | L2/L3 | P4,P7 | 1000–1500 |

**Wave 边界**：W1={P1,P2,P3}；W2={P4,P5,P6}（**P6 无 W1 前置依赖**，仅依赖已有 diport，调度上可提前与 W1 并行启动，详见 tasks.md 依赖图）；W3={P7,P8}；W4={P9,P10,P11,P12}。同文件归同 PR（resolver 分散在 P5/P6/P9，各自负责不同 resolver 函数，无同文件冲突——bootstrap 下分 `replaydeps.rs`/`eventtransport.rs`/`sagaprojectiondeps.rs`）。

## Complexity Tracking

无 Constitution 违反，免填。
