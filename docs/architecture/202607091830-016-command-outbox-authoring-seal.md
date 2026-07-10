# ADR-016: Command Outbox Authoring Seal

- Status: Accepted
- Date: 2026-07-09
- Scope: command/event outbox authoring boundary

## Context

Command topic 曾可借用 event outbox authoring API；公开 topic/entry 构造面意味着组合根之外的调用方也可能
拼出 command outbox 行。AST allowlist 能检查已知调用集合，却不能等价于编译期不可构造，因此不能承担
authoring seal。

## Decision

event 与 command 使用两条互不转换的写入路径：

- event producer 只持有 `EventTopic` 与 `EventEntry`；`EventTopic::parse` 类型化拒绝
  `*.commands.*` namespace。
- relay/readback 只 hydrate `StoredOutboxEntry`。该类型可读取持久行，但不能转换为 `EventEntry`，因此不能
  回流 producer authoring API。
- command contract 必须显式选择 `journal = "required" | "none"`。codegen 为两种 policy 分别只生成
  `journal_async` 或 `emit_async`，并生成 sealed per-command `Contract` marker；marker 通过 associated
  `Request + SPEC` 绑定 schema/routing，policy marker trait 固定可用 seam。
- `eventexec` 分别提供 `DirectCommandDispatcher<S: CommandDispatchStore>` 与
  `JournaledCommandDispatcher<S: CommandJournalStore>`。dispatcher 在 crate 内构造
  `ReviewedCommandDispatch` / `ReviewedCommandJournal`；外部无法构造 reviewed DTO。
- 分层图只增加精确 `eventexec → generated` 编译边，使 eventexec 能实现 generated seam；
  `command_generated_seam_allows` 不接受其它 Service→Generated、反向或同层变体。
- provider 只能通过 reviewed DTO 的只读 accessor 或消费式 `into_parts` 落库。event `OutboxEmitter` 不接受
  command authoring 类型。
- raw idempotency key 只能进入 eventexec-owned keyed blind-index keyring；provider 只收到 sealed
  current/previous alias probes，并在单事务 claim alias、生成随机 canonical command id、写 journal/outbox。

不保留旧 `Topic`、authoring `Entry`、alias、default、feature flag 或双路径。

## AI-HARD classification

以下约束是 Hard：event command namespace 隔离、per-command carrier、policy-exclusive wrapper、reviewed DTO
构造和 store 参数类型。它们由类型、可见性或 codegen golden 直接表达，错误用法无法编译或无法生成。

生产 provider impl/callsite 的 workspace 集合无法由单 crate 类型系统证明完整，保留
`COMMAND-IMPL-ALLOWLIST-01#provider-set` Medium 守卫。该守卫进入 verify，具有 alias/glob synthetic red、
真实 provider anti-vacuity，并明确只证明集合事实，不声称封闭 authoring API。

## Consequences

- command producer 必须经 generated policy wrapper 与对应 dispatcher；provider 不再接收 raw topic/payload。
- event producer、持久化 hydration 与 command authoring 三种能力无法相互转换。
- 新增 command policy 或 store 必须先扩展生成 seam 与 reviewed DTO；编译器会暴露所有迁移点。
- 完整 carrier/evidence/gate 由生成的
  [`Persistence Funnel AI-Robust Matrix`](202607091830-015-persistence-funnel-ai-robust-matrix.md) 派生展示。
