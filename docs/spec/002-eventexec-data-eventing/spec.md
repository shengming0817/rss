# Feature Specification: eventexec 数据持久化与事件处理

**Feature Branch**: `002-eventexec-data-eventing`

**Created**: 2026-06-23

**Status**: Draft

**Input**: User description: "eventexec 数据持久化与事件处理：兑现 consistency 引擎 body + eventexec runtime 驱动 + durable adapters（postgres/redis/amqp）+ topology-gated 接线，覆盖 inbox/outbox/saga/reconcile/cqrs-projection/command 七机制。拆成 12 个 ≤2000 行可执行 PR，挂 Azure Boards #1005。"

**Tracking**: Azure Boards Feature #1005（`[RW-W-eventexec]`）· Epic #991（GoCell→Rust 迁移 · W 宽扇出阶段）· #1100 折为 P8

---

## 背景与读者

本 feature 是 GoCell→Rust 迁移 Epic #991 W 阶段对 `consistency` 引擎 + `eventexec` 运行时 + 持久化 adapters 的 body 兑现。G0 阶段（#997）已**冻结全部 trait/type 签名**；默认只在冻结签名内填实现。

#1627 使用 pre-GA breaking window 收口 saga durable model：删除 `diport` 自有 `SagaId` / `JournalStatus` / `JournalEntry`，统一改用 `consistency::saga::{SagaId, SagaJournalStatus, SagaJournalRecord}`；旧类型不保留 alias/shim。#1632 将 saga durable state 切到 tenant-scoped `saga_instances` + `(tenant_id, saga_id, seq)` append-only `saga_journal`；journal 不持久化 step output。

「用户」= 两类框架消费者：

- **域 crate 作者**（identity / settings / audit / …）：需要 durable outbox 发事件、幂等消费、saga 编排、CQRS 投影、L4 收敛环、命令分发等一致性原语，且这些原语在编译期/启动期把错误用法变得不可表达。
- **平台运维**：需要至少一次投递、进程重启/崩溃不丢事件、跨副本不重复副作用、永久失败可观测（DLX）、多副本下单写者收敛（leader-elect + fencing）。

「demo 拓扑」= 进程内 in-mem（单进程 / 测试 / 样例）；「durable 拓扑」= postgres + amqp（生产事件传输；consumer 幂等走 PG inbox）。topology-gated resolver 在二者间选型，**缺生产配置即启动期 fail-closed，绝不静默降级回 in-mem**。

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - 一致性引擎类型可用（consistency body，L0–L4）(Priority: P1)

域 crate 作者引用 `consistency` 的 `IdemKey`/`EventTopic`/`EventEntry`/`StoredOutboxEntry`/`HandleResult`/`Disposition`/`EngineError`/`EntityId`/`Request`/`Outcome`/`Lsn` 以及 `vocab::StepName` 等类型时，构造器与访问器**真正可用**，且非法输入（空 key、非 canonical topic、空 entity id）在构造期被 fail-closed 拒绝。

**Why this priority**: 所有上层机制（outbox/saga/reconcile/projection/command）都消费这些类型。它们是纯计算、无 I/O、无外部依赖，是整个 feature 的临界路径地基；不落地则其余 11 个 PR 全部 `todo!()` panic。

**Independent Test**: 表驱动单测覆盖每个 newtype 的 parse 正常/边界/拒绝路径、每个穷尽 enum 的 label/message、EventEntry/StoredOutboxEntry/HandleResult funnel 构造与访问；`consistency` crate 覆盖率 ≥ 90%，无需任何 adapter 或运行时。

**Acceptance Scenarios**:

1. **Given** 一个非空 canonical dotted 字符串，**When** 调 `Topic::parse`，**Then** 返回 `Ok(Topic)` 且 `as_str` 回显原值。
2. **Given** 空字符串或非法标识符，**When** 调 `IdemKey::parse` / `StepName::parse` / `EntityId::parse`，**Then** 返回对应 `*Error`（fail-closed），不 panic。
3. **Given** `EngineErrorKind::{Transient,Permanent,Invariant}`，**When** 查 `is_transient`/`is_permanent`/`message`，**Then** 分类与 `&'static str` const message 正确，message 不含 runtime 数据（无 `format!`）。
4. **Given** topic+idem_key+payload，**When** `EventEntry::new` 再读 `topic()`/`idem_key()`/`payload()`，**Then** 回显一致；持久化回读只产生 `StoredOutboxEntry`，外部无法绕过 funnel 字面构造 `EventEntry`/`HandleResult`/`PermanentError`。

---

### User Story 2 - 业务事务与事件原子落库（outbox + relay + sweeper，L1/L2）(Priority: P1)

域 crate 作者在一个本地事务内同时写业务数据与 outbox entry；relay 后台环把已持久化 entry 可靠中继到 broker（CAS 标记已发），sweeper 周期兜底未发 entry。业务事务回滚时 entry 一并回滚（无孤立事件）；进程崩溃重启后未发 entry 仍会被中继（不丢事件）。

**Why this priority**: outbox 是 saga/projection/command 的持久化基础，也是 #1100 的核心。relay 的 at-least-once + CAS 是「事件不丢」的根。

**Independent Test**: postgres outbox 表 + OutboxStore 在事务内 append；relay 环用 fake/in-mem publisher 验证「发布成功→CAS 置 published」「发布失败→retry_after 延后」「永久失败→DLX」；业务事务回滚→outbox 无 entry（L1 原子性治理测试）；relay 重复发同一 entry→consumer 侧幂等拒第二次（L2）。

**Acceptance Scenarios**:

1. **Given** 业务操作 + outbox append 在同一事务，**When** 业务校验失败回滚，**Then** outbox 表无该 entry（原子性）。
2. **Given** 已持久化未发的 entry，**When** relay 环运行一轮且 publisher 成功，**Then** entry 状态经 CAS 置为 published，重复运行不再发。
3. **Given** publisher 返回瞬态错误，**When** relay 处理，**Then** entry 保持未发 + 设 `retry_after`；返回永久错误则进 DLX。
4. **Given** relay 进程在发布后、CAS 前崩溃，**When** 重启后 sweeper/relay 复扫，**Then** entry 被重投（至少一次），由消费侧幂等去重收口。

---

### User Story 3 - 消费幂等去重（idempotency / inbox，L0 + replaydeps）(Priority: P1)

消费方在执行副作用前以稳定 key（EventId / DispatchId）做 claim-or-skip：首见 `Fresh` 则执行，已见 `Duplicate` 则幂等短路。runtime durable event consumer 通过 PG `inbox_receipts` resource bundle 接入，不再经 Redis claimer。

**Why this priority**: at-least-once 投递必然有重投；没有消费幂等，relay/saga/projection/command 的重投会产生重复副作用。是所有消费链的正确性前提。

**Independent Test**: 表驱动覆盖 `Fresh`/`Duplicate` 状态转移；同一 key 连续 try_claim 3 次仅首次 `Fresh`；consumer group 名变更后去重失效（负向断言）；runtime e2e 证明 duplicate 命中 PG inbox 且 tracer 新事件正常消费。

**Acceptance Scenarios**:

1. **Given** 一个全新 idem key，**When** 首次 `try_claim`，**Then** 返回 `Fresh`；同 key 再次 `try_claim` 返回 `Duplicate`。
2. **Given** durable runtime consumer，**When** 同一 event_id + consumer_group 重复投递，**Then** 第二次命中 PG inbox `Duplicate`，handler 不重复执行。
3. **Given** durable runtime consumer，**When** tracer 使用新 event_id 投递，**Then** PG inbox 返回 `Fresh` 并最终 `done`。

---

### User Story 4 - 跨进程事件传输（amqp transport + eventtransport resolver）(Priority: P2)

durable 拓扑下，事件经 per-domain 隔离的 amqp broker 在进程间传输；demo 拓扑下经进程内 bus。eventtransport resolver 单源选型 publisher/subscriber；缺 broker 配置即 fail-closed。broker 凭据在日志中 redaction。

**Why this priority**: 真实多进程部署的事件主干。relay 必须把 entry 发到跨进程 broker 才能让独立部署的消费者收到。

**Independent Test**: amqp Publisher/Subscriber 对接本地 broker（集成测试 feature 门控）验证 publish→subscribe 闭环 + per-domain 队列隔离；resolver 在 demo/durable 拓扑分别解析出 in-mem bus / amqp，缺配置 fail-closed；凭据不进日志。

**Acceptance Scenarios**:

1. **Given** durable 拓扑 + per-domain broker URL，**When** relay 发布到某 domain topic，**Then** 该 domain 的订阅者收到，跨 domain 不串。
2. **Given** demo 拓扑，**When** resolver 解析 transport，**Then** publisher 与 subscriber 是同一进程内 bus 实例。
3. **Given** durable 拓扑缺 broker URL，**When** 启动，**Then** fail-closed 报错；broker 凭据不出现在任何日志行。

---

### User Story 5 - 通用消费框架与死信（ConsumerBase + DLX + 订阅注册，L2）(Priority: P2)

域 crate 经 `contract.toml` 声明订阅（单源），框架据此派生订阅注册 glue；ConsumerBase 统一 claim→handle→commit/release 循环，按 `HandleResult`（ack/requeue/reject）收口；瞬态失败退避重试，预算耗尽或永久失败进 DLX（dead-letter store），不静默丢消息。

**Why this priority**: saga executor / projection consumer / command handler 都建在 ConsumerBase 上。统一收口避免每个消费者重复实现重试/DLX/幂等接线。

**Independent Test**: ConsumerBase 用 fake claimer + fake handler 验证三 disposition 路径、退避预算耗尽→DLX、永久错误→DLX；active 订阅缺 handler 注册→治理测试/启动期失败；订阅注册 glue 与 contract.toml 同源。

**Acceptance Scenarios**:

1. **Given** handler 返回 `ack()`，**When** ConsumerBase 处理，**Then** broker ack + receipt commit + claimer mark done。
2. **Given** handler 持续 `requeue(err)` 直到预算耗尽，**When** ConsumerBase 处理，**Then** 自动降级写 DLX，记录尝试次数。
3. **Given** handler 返回 `reject(permanent)`，**When** ConsumerBase 处理，**Then** entry 直接进 DLX。
4. **Given** 某 active 事件契约无任何订阅 handler，**When** 治理校验/启动，**Then** 报错（死事件守卫）。

---

### User Story 6 - identity 登录事件 durable 闭环（#1100 集成，L2）(Priority: P1)

`LoginService::login` 不再直接 `Publisher.publish`，而是把 `session.created` 写 durable outbox entry（与会话创建同事务）；relay 中继到 broker；audit 消费侧以 EventId 幂等去重后 append 审计。替换 G1 的 in-mem 替身，端到端 journey 升级为可选 durable 拓扑。

**Why this priority**: 这是 durable outbox 第一条真实业务链路（#1100，已 Approved，P1），验证地基 PR 的集成正确性；也是 RW-G1 追踪弹的 durable 收尾。

**Independent Test**: L2 治理测试（outbox 原子性 + consumer 幂等）；relay 重投 session.created → audit 仅 append 一次；replay + 投影重建测试；journey 在 demo 与 durable 两拓扑均绿。

**Acceptance Scenarios**:

1. **Given** 登录成功，**When** 会话创建事务提交，**Then** outbox 含一条 `identity.session-created` entry，携带 EventId/trace/correlation/occurred_at envelope。
2. **Given** relay 因重启重投同一 session.created，**When** audit 消费，**Then** 第一次 append、第二次幂等短路（审计无重复）。
3. **Given** 会话创建事务回滚，**When** 检查 outbox，**Then** 无该 entry。

---

### User Story 7 - Saga 编排与逆序补偿（saga executor / tailer / journal，L3）(Priority: P3)

域 crate 声明 `kind: saga` 契约（非空 saga/retry block、≥1 step、完整 receipt/effect/idempotency/compensation/retry 语义、compensation order 仅 reverse、consistencyLevel=L3）；codegen 派生 sealed definition/step/receipt marker、typestate cursor、完整 definition identity 与闭合 retry policy；executor 逐步前向执行并 append journal，任一步永久失败或预算耗尽则**逆序**补偿同次 run 已完成步。instance 固定 contract/version/schema/action-generation 并 exact resume；durable receipt 与崩溃恢复分别由 #1924/#1925 提供，缺 receipt 时不得重算 action。

**Why this priority**: L3 高阶能力，依赖 outbox + ConsumerBase + 持久化 journal。是多步跨聚合一致性的载体，但非地基。

**Independent Test**: 3-step saga 全成→journal 顺序记录；step 2 返回失败→逆序补偿已完成前缀 step 1 journal 记录；从 step 2 checkpoint resume→跳过 step 1；kind:saga 契约 governance（xtask）正/负用例；forward retry success、forward timeout compensation、retry budget exhaustion、compensation retry success、compensation timeout DLX；background worker 注册 `saga_executor:<owner>__<contract_slug>` readyz probe，source/store infra error 降级，worker stop/panic 变 unhealthy。

**Acceptance Scenarios**:

1. **Given** 3 步 saga，**When** 全部成功，**Then** journal 按执行序记录 3 条 completed，saga 终态 succeeded。
2. **Given** 第 2 步返回失败，**When** executor 处理，**Then** 逆序 compensate 已完成前缀（step1），saga 终态 failed，补偿失败不静默吞（进 saga dead-letter）。
3. **Given** 非法 saga 契约（空 step / compensation 非 reverse / 负 timeout），**When** governance 校验，**Then** 报错拒绝。

---

### User Story 8 - CQRS 投影与断点续投（projection，L3）(Priority: P3)

投影器把事件（outbox entry / saga journal event，均实现 `ProjectionEvent`）apply 到读模型；从 checkpoint(Lsn) 断点续投，崩溃重启从 checkpoint 继续（不重做、不遗漏）；`projection_events` 表 append-only（DML DELETE/TRUNCATE 被 lint 拒）；从 offset 0 重放结果与增量更新一致。

**Why this priority**: L3 读模型构建，与 saga 正交、共享 checkpoint store。非地基。

**Independent Test**: 处理 100 事件、checkpoint=50、重启→续投 51–100；从头重放→读模型与增量一致；append-only lint 拒 DELETE projection_events（synthetic red case）；同 Lsn 重投 no-op。

**Acceptance Scenarios**:

1. **Given** 已处理至 checkpoint offset N，**When** 进程重启，**Then** 从 N+1 继续，无重复 apply、无遗漏。
2. **Given** 全新读模型，**When** 从 offset 0 重放全部事件，**Then** 结果与增量构建一致。
3. **Given** 含 `DELETE FROM projection_events` 的代码，**When** 跑 lint，**Then** 拒绝（append-only 守卫）。

---

### User Story 9 - L4 desired-state 收敛环（reconcile + leader-elect + fencing）(Priority: P3)

域 crate 经唯一 `reconcile::Builder`（必填 sealed Tenancy + Trigger）构造 Loop；level-triggered 周期/事件触发驱动 Reconciler 把 actual 收敛到 desired；`Request::default()`=resync 全量；瞬态错误 per-entity 指数退避。多副本下仅 leader dispatch，丢 lease 即 cancel 在途 reconcile；跨副本正确性靠单调 epoch 注入 FencedWriter（CAS）+ 消费幂等。

**Why this priority**: L4 最专精、依赖最多（Clock + 可选 LeaderElector + Tenancy）。与其他机制正交，可最后并行。

**Independent Test**: 状态机收敛路径用例；timeout→requeue_after；缺 Tenancy 参→编译错（Hard）；多副本 2 pod 并发 acquire lease→仅一成功，丢 lease→另一接管；epoch 单调，旧 epoch 写被拒。

**Acceptance Scenarios**:

1. **Given** 缺 Tenancy 参，**When** 编译 `reconcile::Builder`，**Then** 编译失败（必填 sealed 参）。
2. **Given** 多副本 + leader-elect，**When** 两 pod 同时 acquire lease，**Then** 仅一个 dispatch；持有者丢 lease 后另一 pod 接管。
3. **Given** epoch 1 已写，**When** 以 epoch 1 再写则拒、以 epoch 2 写则受，**Then** fencing 单调性成立。

---

### User Story 10 - 命令分发与双侧收口（command dispatch + codegen，L2/L3）(Priority: P3)

域 crate 经 `kind: command` 契约的显式 journal policy codegen 出互斥 producer wrapper 与 typed consumer registration；producer 经 `DirectCommandDispatcher` 或 `JournaledCommandDispatcher` 构造不可外部伪造的 reviewed DTO，再进入对应 store；DispatchId + claimer 两阶段幂等；命令 topic 稳定 dotted 命名。

**Why this priority**: L2/L3 命令面，依赖 outbox + ConsumerBase + codegen 管道。与 saga/projection 并行。

**Independent Test**: 新增 command 契约→codegen 产 emit/register wrapper；忘注册 handler→双侧对称治理失败；同 DispatchId 发两次→第二次 claimer 拒；codegen 完整性 xtask 校验（无手写 emit 出口）。

**Acceptance Scenarios**:

1. **Given** 一个 command 契约，**When** 跑 codegen，**Then** 生成 `emit_async` + `register_handler` wrapper，业务无法绕过裸调 runtime emit。
2. **Given** producer 以同一 DispatchId 重发，**When** consumer claim，**Then** 第二次被幂等拒。
3. **Given** command 有 emit 源但无 consumer handler，**When** 双侧对称治理，**Then** 报错。

---

### Edge Cases

- **relay 发布成功但 CAS 前崩溃**：entry 仍未标 published → 重启后重投 → 消费幂等去重收口（至少一次 + 幂等 = 有效一次）。
- **consumer group 名漂移**：重放时视为新消费者，去重失效 → 由 group name 稳定性（codegen 绑定）+ 负向治理用例守。
- **saga 补偿本身失败**：不静默吞 → 进 saga dead-letter，需人工/告警介入。
- **投影 schema 演化**：新增列后历史事件重放仍可处理（向后兼容 ADD/RENAME，无 DROP）。
- **多副本同时持 lease（脑裂）**：lease 不保证互斥正确性 → 靠 fencing epoch CAS 拒旧 writer。
- **DLX 自身写失败**：MUST `tracing::error!`（带 entry id + error + domain），该轮将 entry 置回 `requeue_after`（不丢失），并使 readyz 降级；MUST NOT panic、MUST NOT 静默忽略。
- **demo→durable 拓扑切换缺配置**：启动期 fail-closed，绝不静默降级（防生产误用 in-mem 丢事件）。

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `consistency` 的全部冻结类型（newtype/enum/struct funnel）与引擎策略 trait 关联的访问器 MUST 兑现真实 body，非法构造输入 MUST fail-closed 拒绝，不得 `todo!()` panic。
- **FR-002**: 引擎错误 message MUST 为 `&'static str` const literal（无 `format!` 拼 runtime 数据）；engine 类型 MUST NOT derive serde（ADR-004 C6）。
- **FR-003**: 系统 MUST 支持业务数据与 outbox entry 在同一本地事务内原子写入；业务回滚 MUST 连带 outbox 回滚（无孤立 entry）。
- **FR-004**: relay MUST 以 at-least-once 中继已持久化 entry，发布成功后经 CAS 标记 published；瞬态失败延后重试、永久失败进 DLX；MUST 不丢事件（崩溃重启后复投）。relay 后台 worker MUST 注册运行时操作 health probe `outbox_relay`（**无 `_ready` 后缀**——`_ready` 专属依赖可用性 probe，运行时操作 probe 不带，见 observability.md §Readyz Probe）；worker 异常退出 MUST 经该 probe 反映到 health（不静默假绿）。
- **FR-005**: sweeper MUST 周期兜底扫描未发 entry 触发重投，防中断导致 entry 永不发。sweeper 后台 worker MUST 注册运行时操作 health probe `outbox_sweeper`（**无 `_ready` 后缀**，同 observability.md §Readyz Probe 命名约定）；worker 异常退出 MUST 经该 probe 反映到 health（不静默假绿）。
- **FR-006**: 消费方 MUST 在副作用前以稳定 key claim-or-skip 幂等去重；重复投递 MUST 不产生重复副作用。
- **FR-007**: topology-gated resolver（eventtransport / replaydeps / sagaprojectiondeps）MUST 在 demo（in-mem）与 durable 拓扑间单源选型；eventtransport durable = AMQP + PostgreSQL inbox/DLX，saga durable = PostgreSQL tenant-scoped instance/journal + checkpoint/DLX + Redis runtime lock provider。durable 拓扑缺对应生产配置 MUST 启动期 fail-closed，MUST NOT 静默降级回 in-mem。
- **FR-008**: in-mem 原语（claimer / bus / saga instance+journal / checkpoint）MUST sealed，仅 resolver 的 demo 分支可达，生产代码 MUST 不可直接构造（类型层 Hard）。
- **FR-009**: 消费框架 MUST 经 `HandleResult` 三路（ack/requeue/reject）收口，瞬态退避有预算上限，耗尽或永久失败 MUST 进 DLX 并结构化记录（不静默丢消息）。DLX 写入 MUST 触发 `tracing::error!` 并带 span 定位字段（domain / contract_id / topic / num_attempts / error_summary，均无 PII）。
- **FR-010**: 订阅注册 MUST 与域 crate `contract.toml` 同源（codegen 派生 glue），active 事件契约 MUST 至少有一个订阅 handler（死事件守卫）。
- **FR-011**: `LoginService::login`（#1100）MUST 改为写 durable outbox entry 替换直接 publish；audit 消费 MUST 以 EventId 幂等去重；MUST 通过 L2 原子性 + 幂等治理测试与 replay/投影重建测试。
- **FR-012**: saga executor MUST 逐步前向执行并 append durable journal，action 返回失败、timeout 或重试预算耗尽 MUST 逆序补偿已完成步；补偿失败、timeout 或预算耗尽 MUST 上报（saga dead-letter）不静默吞；MUST 支持从 journal/checkpoint resume。background worker 形态 MUST 注册运行时操作 health probe `saga_executor:<owner>__<contract_slug>`（无 `_ready` 后缀），通过 tenant candidate source + tenant-scoped runnable listing 调用 `run` / `resume`；source/store/journal/DLX infra error MUST 降级，worker stop/panic MUST 反映为 unhealthy。
- **FR-013**: `kind: saga` 契约 governance MUST 校验：非空 saga/retry block、≥1 step、step name 合法标识符、每步完整 receipt/effect/idempotency/compensation/retry 声明、compensation order 仅 reverse、consistencyLevel=L3、attempt/time/backoff/jitter 良构；codegen MUST 派生 sealed markers、typed receipt、typestate cursor、完整 identity/policy/action generation，factory 未到 generated `End` MUST 无法 `finish()`。
- **FR-014**: 投影器 MUST 从 checkpoint(Lsn) 断点续投，崩溃重启 MUST 从 checkpoint 继续（不重做不遗漏）；从 offset 0 重放结果 MUST 与增量更新一致；`projection_events` MUST append-only（DML DELETE/TRUNCATE 被守卫拒）。
- **FR-015**: reconcile Loop MUST 仅经 `Builder`（必填 sealed Tenancy + Trigger）构造，缺 Tenancy MUST 编译错；level-triggered 触发、`Request::default()`=resync 全量、瞬态错误 per-entity 指数退避。
- **FR-016**: 多副本 reconcile MUST 仅 leader dispatch，丢 lease MUST cancel 在途 reconcile；跨副本正确性 MUST 靠单调 epoch FencedWriter（CAS，旧 epoch 写拒）+ 消费幂等，不靠 lease 本身。旧 epoch 写被 FencedWriter 拒绝时 MUST 产生可观测日志（`tracing::warn!`，带 key / epoch_attempted / current_epoch），便于运维发现脑裂。
- **FR-017**: 命令分发 MUST 经 policy-exclusive codegen wrapper → typed eventexec dispatcher → reviewed command DTO → provider store；外部 MUST NOT 能构造 `CommandSpec` 或 reviewed DTO；DispatchId + claimer 两阶段幂等；producer/consumer/wiring 同源 key。
- **FR-018**: 每个 PR MUST ≤ 2000 行净增删（特殊情况例外须在 PR 说明理由）；MUST 只在 G0/#997 冻结签名内兑现 body，不改公共接缝；破坏式 wire/API 变更走 pre-GA 窗口原地改 + 扇出闭环。#1627 的 saga durable model 收口是 intentional breaking API：`diport` 旧 saga journal 类型删除，消费方迁移到 `consistency::saga`。
- **FR-019**: 各一致性等级 MUST 配对应治理/测试：L0 表驱动、L1 事务完整性、L2 outbox 原子性+consumer 幂等、L3 replay+投影重建、L4 状态机+超时+fencing；新增治理机制 MUST ≥ Medium（严禁 Soft）。
- **FR-020**: outbox/event envelope 的 reserved key（trace/correlation/subjectId/principal/actor/occurredAt/tenantId/tenantAuthority）MUST 由受控构造注入，业务 MUST 不可经 metadata 伪造；broker 凭据 / PII MUST 不进 wire 与默认日志。`subjectId` 与 `actor` MUST 使用 typed opaque/newtype 入口写入 persisted metadata，MUST NOT 进入 AMQP header / MQTT user property；完整 `Principal` 或含 email/姓名/phone/token 等 PII 不得序列化进 envelope。

### Key Entities *(include if feature involves data)*

- **Stored Outbox Entry**：已持久化的待发事件——`StoredOutboxEntry` 的 topic + idem_key（EventId）+ 已编码 payload（`OutboxPayload`）+ envelope（transport-safe trace/correlation/tenant authority + persisted-only subject/actor）+ 投递状态（pending/publishing/published/dlx）+ retry 计数 + retry_after + lease/fencing token。
- **Idempotency / Inbox Record**：消费侧去重记录——idem key + consumer group + lease/done 状态 + 命名空间（per-domain）。
- **Dead Letter Record**：永久失败或预算耗尽的 entry——原始 entry 引用 + 错误摘要 + 尝试次数 + 首末尝试时间。
- **Saga Instance / Journal Entry**：saga instance 以 `(tenant_id, saga_id)` 标识并承载 status、lease token、epoch、expiry；journal entry 以 `(tenant_id, saga_id, seq)` 记录 step name + 状态（executing/completed/compensating/compensated/failed）+ 补偿失败安全摘要 + 时间；不持久化 step output。tailer 对 instance `Degraded`、replay / definition drift 返回 `Degraded`，不得把损坏 journal 伪装成 `Done`。
- **Checkpoint**：断点位点——owner + checkpoint id + offset(Lsn) + 版本（CAS）；saga 与 projection 共享存储。
- **Projection Event**：投影输入载体（outbox entry CDC / projection journal event）——topic + lsn + payload。
- **Reconcile Request / Outcome**：收敛单元——目标 entity（None=resync 全量）/ 收敛结果（settled / requeue_after）+ fencing epoch。
- **Command Dispatch**：命令载体——DispatchId（幂等 key）+ 命令 topic + Request payload；与 outbox entry 同表。
- **Topology Resolver 配置**：拓扑选型输入——transport（demo bus / amqp）、runtime consumer inbox（postgres `inbox_receipts`）、replay/其它 runtime 原语（in-mem / redis 等）、saga instance store/journal（mem paired store / postgres tenant-scoped tables + checkpoint/DLX）。

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 范围内全部冻结 `todo!()` body（consistency 全模块 + eventexec saga 接缝 + adapters 持久化）被兑现，`cargo build --workspace` 与 `cargo test --workspace` 全绿，工作区无残留 `todo!()`（命令分发/saga/projection/reconcile 范围内）。
- **SC-002**: 事件零丢失——relay 进程在「发布后 CAS 前」被杀，重启后该事件仍被消费方收到且仅生效一次（at-least-once + 幂等）。
- **SC-003**: 业务事务回滚时 outbox 无孤立 entry，原子性测试 100% 通过（L1）。
- **SC-004**: 同一事件/命令重复投递 N 次，副作用仅发生一次（消费幂等），L2 幂等治理测试通过。
- **SC-005**: durable 拓扑缺对应生产配置时，进程启动 fail-closed 报错，绝不以 in-mem 静默启动；eventtransport consumer 至少要求 broker + PG inbox/DLX，Redis 不再是该路径必需项（100% 的缺配置用例触发启动失败）。
- **SC-006**: saga 任一步返回失败时，已完成步按逆序 100% 被补偿（无跳过、无乱序），补偿失败写 saga dead-letter 时产生 `tracing::error!`（含 saga_id / step_name / error_summary）并可经 metric（如 `saga_dead_letters_total{domain}`）计数告警。
- **SC-007**: 投影从 checkpoint 续投在崩溃重启后无重复 apply、无遗漏；从 offset 0 重放结果与增量构建逐字段一致。
- **SC-008**: 多副本 reconcile 在任意时刻至多一个 leader dispatch；旧 epoch 写 100% 被 fencing 拒绝。
- **SC-009**: 引擎与基础 crate（consistency 等）覆盖率 ≥ 90%，新增/修改代码 ≥ 80%；`cargo clippy --workspace --all-targets -- -D warnings` 与 `cargo fmt --check` 干净。
- **SC-010**: feature 拆为 12 个 PR，每个净增删 ≤ 2000 行（例外有书面理由），全部挂 Azure Boards #1005 并形成 blocked-by DAG + wave 排序。

## Assumptions

- G0/#997 已冻结全部 trait/type 签名；本 feature 默认不改公共接缝，只填 body。#1627 例外使用 pre-GA breaking window 收口 saga durable model：旧 `diport` saga journal 类型删除，不保留源码兼容。
- **租户隔离立场**：当前 per-domain 队列/凭据隔离粒度为 domain，不分 tenant；outbox 持久化 `tenant_id`
  并按 `(tenant_id, domain, partition_key)` 执行有序投递 gate，避免跨租户 liveness coupling。inbox_receipts
  以 `(tenant_id, event_id, consumer_group)` 为 receipt key，claim 前必须完成 envelope schema 与 tenantAuthority
  验签，并由 `InboxReceiptContext` 固定 domain/topic/contract/schema 维度。
- `consistency` 引擎策略 trait 为 native AFIT + 泛型静态分发（不引 dynosaur/async-trait）；`diport` DI port 为 dynosaur dyn（ADR-003）。二者分工不变。
- demo 拓扑（in-mem，adapters/memory）已实现并保留为单进程/测试/样例路径；durable 拓扑按机制组合 postgres/amqp/redis，其中 runtime event consumer 使用 postgres inbox + amqp，不再经 Redis claimer。
- G1 追踪弹（identity→in-mem→audit）已绿，作为 #1100 durable 替换的起点与回归基线。
- reconcile Loop harness 的最终 crate 落位（eventexec vs 独立 home）与 saga/projection 共享 checkpoint store 的先后，由 `/speckit-plan` 阶段裁定（不阻塞拆解）。
- postgres 索引/migration 形态遵 rust-standards §数据库迁移（pre-GA 普通 `CREATE INDEX`，migration 只增不改）。
- 持久化测试经集成 feature 门控（`#[cfg(feature = "integration")]`），单测以 fake/in-mem 替身；CI 形态见 gocell-rust 的历史 CI 设计文档。
- 七机制依赖序：引擎类型(P1/P2)+postgres 基座(P3) → outbox(P4)/idempotency(P5)/amqp(P6) → ConsumerBase(P7) → #1100(P8) → saga(P9)/projection(P10)/reconcile(P11)/command(P12) 并行收尾。
