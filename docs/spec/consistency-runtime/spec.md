# Feature Specification: Consistency Runtime SpecKit Entry

**Feature Branch**: `docs/1614-consistency-runtime-entry`

**Created**: 2026-07-01

**Status**: Draft

**Input**: User description: "SpecKit consistency-runtime spec/plan/tasks 单一入口。按 SpecKit 的 specify/plan/tasks 结构沉淀本轮一致性目标，明确 L0-L4、outbox、inbox、saga、projection、reconcile、tenant-aware consistency 的边界。"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - 一致性目标有单一阅读入口 (Priority: P1)

AI 实施者、reviewer 和维护者可以从 `docs/spec/consistency-runtime/` 进入，看到 RSS consistency runtime 的目标、边界、验收标准和规则来源，而不需要在多个历史计划中猜测当前语义。

**Why this priority**: consistency runtime 横跨引擎、服务、adapter、domain、contract 和治理门。没有单一入口，后续 N-002..N-029 容易复制旧语义、漏掉 tenant-aware 边界或把计划误读成代码实现。

**Independent Test**: 只阅读 `spec.md`、`plan.md`、`tasks.md` 和链接的规则文件，即可判断一个后续 consistency runtime PR 是否落在正确层级、覆盖正确一致性等级、并具备可验收测试。

**Acceptance Scenarios**:

1. **Given** 一个后续 PR 要改 outbox、inbox、saga、projection 或 reconcile，**When** reviewer 从本 feature 入口查阅，**Then** 能找到该机制所属 L0-L4 等级、边界和验收标准。
2. **Given** 一个文档或实现提到 L3，**When** reviewer 对照本入口，**Then** 能判断它是 saga、projection、CQRS replay 或 command eventual consistency，而不是把 L3 等同 saga。
3. **Given** 一个 implementation task 想新增 Soft-only 规则，**When** reviewer 对照本入口，**Then** 能看到必须给出 Hard/Medium carrier 或拆成后续治理项。

---

### User Story 2 - 分层和运行时归属不倒置 (Priority: P1)

一致性 runtime 的实现者可以明确区分：`consistency` 是引擎纯态机和策略 trait，`eventexec` 是 runtime harness，`diport` 是 provider port，`adapters/*` 是真实 provider 实现，`bootstrap` / assembly 是拓扑选型和组合根，域 crate 只经 contract/generated 交互。

**Why this priority**: 分层倒置会破坏 RSS 的 domain-native 架构，特别是 `consistency` 依赖 service/provider、`generated` 依赖 runtime、或 domain 直接依赖 adapter 这几类错误。

**Independent Test**: 对任一计划任务做 layer mapping，必须能落到 `docs/rules/architecture.md` 的现有 crate 图规则，并给出 `cargo xtask layer-deps` 或类型系统载体。

**Acceptance Scenarios**:

1. **Given** 新增 consistency newtype、state machine 或策略 trait，**When** 选择 crate 归属，**Then** 它属于 `crates/consistency` 且不能依赖 DI-infra、服务、域或 adapter。
2. **Given** 新增 relay、consumer、saga executor、projection harness 或 reconcile loop，**When** 选择 runtime 归属，**Then** 它属于 `eventexec` 或组合根接线，不迁入 domain crate。
3. **Given** 新增 provider 可替换能力，**When** 设计接口和实现，**Then** trait 属于 `diport` 或现有服务边界，真实实现属于 `adapters/*`，组合根注入。

---

### User Story 3 - Tenant-aware failure modes 可审计 (Priority: P1)

安全 reviewer 可以从单一入口审查 tenant-aware consistency 的失败模式：outbox partition key 跨租户队头阻塞、broker tenant metadata 不可信、DLX payload 加密、consumer leaseLost hard-fence、reconcile leader 与 fencing 分离。

**Why this priority**: 一致性 runtime 的正确性不是只有“不丢消息”。在多租户和零信任部署下，错误的 tenant 边界会产生跨租户 liveness DoS、DLX 泄漏、旧 leader stale write 或重复副作用。

**Independent Test**: 每个 tenant-aware failure mode 都能映射到已有规则文件、Hard/Medium carrier 或后续验收任务；没有一条只依赖人工记忆。

**Acceptance Scenarios**:

1. **Given** ordered outbox delivery 使用 `partition_key`，**When** key 缺 tenant scope 且非全局唯一，**Then** 该设计不满足本 feature 验收。
2. **Given** consumer 写 app DLX，**When** broker metadata 中存在 tenant 字段但 tenant authority 缺失、过期或绑定不匹配，**Then** consumer 不信任该 tenant 并 fail-closed。
3. **Given** reconcile 多副本运行，**When** leader lease 丢失或旧 epoch 写入，**Then** 正确性靠 epoch/fencing CAS 和幂等，而不是靠 leader lease 本身。

---

### User Story 4 - 后续任务可从 SpecKit 入口派生 (Priority: P2)

计划维护者可以基于 `tasks.md` 生成后续 PBI/PR 级任务，且每个任务都有文件范围、依赖关系、并行性和验收命令，不把本 docs-only issue 误扩成 runtime 实施。

**Why this priority**: #1614 是规划入口。它必须让后续实施可分解、可并行、可 review，但不能提前实现 runtime 代码或改动治理规则正文。

**Independent Test**: `tasks.md` 使用 SpecKit checklist task 格式，所有任务都有 `T###`、可选 `[P]`、必要 `[USx]` 和明确文件路径；后续实施项与本 PR 的 docs-only 验收分离。

**Acceptance Scenarios**:

1. **Given** 一个任务被标记 `[P]`，**When** 分配给并行实施者，**Then** 它与同阶段其他 `[P]` 任务没有文件写冲突。
2. **Given** 一个任务属于 user story phase，**When** reviewer 检查格式，**Then** 它包含 `[USx]` label 和明确文件路径。
3. **Given** 本 #1614 PR 完成，**When** 查看 diff，**Then** 只出现 SpecKit 文档入口和 `.specify/feature.json` 指针更新，不包含 runtime/adapters/migration 代码。

### Edge Cases

- Existing specs already describe parts of eventing and runtime; this entry must cite those as context but not duplicate stale implementation claims as current rule.
- `specs` is a symlink to `docs/spec`; generated paths must be valid through both `docs/spec/consistency-runtime/**` and `specs/consistency-runtime/**`.
- This feature must not include old tenantless or actorless command/outbox snippets.
- L3 includes saga and projection/CQRS; wording must not imply saga is the only L3 mechanism.
- Reconcile is L4 desired-state convergence; wording must not model it as saga compensation or projection replay.
- Global event tables without `tenant_id` must be described with their existing tenant-aware safeguards and known follow-up boundaries, not as fully tenant-scoped storage.
- Open-source references are planning evidence only; RSS still follows its crate graph, native AFIT, tenant/fencing, and generated contract rules.

## Consistency Levels

RSS declares consistency level in `contract.toml` as `consistencyLevel`; `docs/rules/architecture.md` owns the architectural source, and `contracts/README.md` owns the manifest value set.

| Level | Manifest Value | Runtime Meaning | Primary Mechanisms |
|-------|----------------|-----------------|--------------------|
| L0 | `LocalOnly` | Local handler/domain path with zero business persistence, outbox, and direct publish; provider-owned read-path transactions are allowed and do not imply a PostgreSQL `READ ONLY` or stable-snapshot guarantee. | Newtypes, validation, authenticated reads, projections, idempotency decisions, tenant-scoped provider reads |
| L1 | `LocalTx` | Single-domain local transaction boundary; success is complete when the local store commits. | Repository transaction funnel, tenant-scoped `SET LOCAL`, rollback/commit tests |
| L2 | `OutboxFact` | Local transaction commits authoritative state and an outbox fact for at-least-once asynchronous delivery. | Outbox entry, relay, inbox claim, command dispatch, tenant authority, DLX |
| L3 | `WorkflowEventual` | Eventual workflow or projection semantics where completion may require replay, journal resume, compensation, or checkpoint advancement. | Saga, projection/CQRS, workflow journal, projection checkpoint |
| L4 | `DeviceLatent` / desired-state | Desired-state convergence across unreliable external/device boundaries; correctness depends on repeated observe-act loops, tenancy declaration, leader gating, fencing, and idempotency. | Reconcile loop, trigger, leader election, `FencedWriter`, epoch-aware command emission |

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a SpecKit feature directory at `docs/spec/consistency-runtime/` with `spec.md`, `plan.md`, `tasks.md`, and `checklists/requirements.md`.
- **FR-002**: System MUST update `.specify/feature.json` so SpecKit follow-up commands resolve this feature directory.
- **FR-003**: The specification MUST define L0 LocalOnly, L1 LocalTx, L2 OutboxFact, L3 WorkflowEventual, and L4 DeviceLatent / desired-state consistency in terms compatible with `docs/rules/architecture.md`.
- **FR-004**: The specification MUST cover outbox, inbox/idempotency, saga, projection/CQRS, reconcile, command dispatch, DLX, lease/fencing, and tenant-aware consistency boundaries.
- **FR-005**: The plan MUST state layer ownership for `consistency`, `eventexec`, `diport`, `adapters/*`, `bootstrap`/assembly, domain crates, `contracts/**`, and `generated`.
- **FR-006**: The plan MUST identify Hard or Medium carriers for constraints where the repo already has one, and MUST avoid introducing Soft-only rules.
- **FR-007**: The plan MUST include the three benchmark references: steno saga action, kube-rs controller, and cqrs-es command/query flow.
- **FR-008**: The tasks document MUST follow the SpecKit checklist task format: `- [ ] T### [P?] [US?] Description with file path`.
- **FR-009**: The tasks document MUST separate this docs-only entry work from future runtime implementation work.
- **FR-010**: This feature MUST NOT modify runtime code, adapter code, migrations, generated code, or `docs/rules/**` rule bodies.
- **FR-011**: The feature MUST pass `cargo xtask verify --fast`.
- **FR-012**: The quality checklist MUST have no remaining failed items or unresolved clarification markers.

### Key Entities

- **Consistency Level**: The L0-L4 classification that determines runtime semantics, contract metadata, and governance expectations.
- **Outbox Fact**: A durable fact written with local state and relayed at least once through a transport.
- **Inbox Claim**: Consumer-side idempotency state with lease token CAS, duplicate detection, and crash recovery.
- **Saga**: L3 finite workflow with forward steps, reverse compensation, journal, resume, and dead-letter handling.
- **Projection**: L3 materialized read model path that consumes ordered projection events and advances checkpoints.
- **Reconcile Loop**: L4 desired-state convergence loop with explicit tenancy, trigger, leader election, and fencing.
- **Tenant Authority**: Signed transport metadata that makes broker-delivered tenant scope trustworthy for consumer-side DLX decisions.
- **SpecKit Feature Artifact**: The spec, checklist, plan, and tasks files that serve as the single entry for this planning slice.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `docs/spec/consistency-runtime/spec.md`, `plan.md`, `tasks.md`, and `checklists/requirements.md` exist and contain no template placeholders.
- **SC-002**: `.specify/feature.json` points to `docs/spec/consistency-runtime`.
- **SC-003**: Every user story has priority, rationale, independent test, and acceptance scenarios.
- **SC-004**: Requirements cover all named mechanisms from the issue: L0-L4, outbox, inbox, saga, projection, reconcile, and tenant-aware consistency.
- **SC-005**: The plan contains a Constitution Check with explicit pass/fail reasoning for RSS layering, contract-only cross-domain communication, AI-HARD governance, and docs-only scope.
- **SC-006**: The task list contains dependency and parallel execution sections and all task rows follow the required SpecKit checkbox format.
- **SC-007**: `cargo xtask verify --fast` completes successfully after the documentation changes.
- **SC-008**: The PR diff contains no Rust source, migration, generated contract, or `docs/rules/**` body changes.

## Assumptions

- Azure Boards issue #1614 is the authoritative tracking item and remains a docs-only PBI.
- Existing `docs/rules/**` files remain the rule single source; this feature links to them instead of rewriting them.
- Optional SpecKit artifacts (`research.md`, `data-model.md`, `quickstart.md`, `contracts/`) are not generated because #1614 explicitly requests the spec/plan/tasks entry and does not define a runnable interface or data model.
- Follow-up implementation work will use this entry to create separate issues or PRs before changing runtime behavior.
