# Tasks: eventexec 数据持久化与事件处理

**Input**: specs/002-eventexec-data-eventing/{spec,plan,research,data-model}.md + contracts/
**Tracking**: Azure Boards Feature #1005 · Epic #991 · #1100 折为 P8（T008）
**粒度**: 任务 = PR。正好 12 个 PR（T001–T012 = P1–P12），每个 ≤2000 行净增删（例外书面理由）。

## 约定

- `[P]` = 该 PR 与**同 wave** 其他 PR 无文件交叉、无相互依赖，可并行开发。
- 每 PR 走 TDD：先写测试（FAIL）→ 在冻结签名内兑现 body → 治理/扇出闭环 → clippy/fmt 0 warning。
- 一致性等级测试：L0 表驱动 / L1 事务完整性 / L2 outbox 原子性+consumer 幂等 / L3 replay+投影重建 / L4 状态机+超时+fencing。
- 同文件归同 PR（resolver 在 bootstrap 下按 `replaydeps.rs`/`eventtransport.rs`/`sagaprojectiondeps.rs` 分文件，避免跨 PR 冲突）。

---

## Wave 1 — 引擎地基（critical path）

### T001 [P] [US1] P1 · consistency body L0–L2
**触及**: `crates/consistency/src/{error,idempotency,outbox}.rs` · **等级**: L0/L1/L2 · **blocked-by**: 无 · **并行**: 与 T003 并行（不同 crate）；T002 依赖本 PR。

- [ ] T001.1 [US1] 先写表驱动测试（rstest）：`IdemKey/Topic::parse` 正常/空/非 canonical；`Disposition::as_label`、`PermanentErrorKind/EngineErrorKind::message` const；`Entry/HandleResult/PermanentError` funnel 构造+访问；`EngineError::is_transient/is_permanent` —— 全 FAIL
- [ ] T001.2 [US1] 兑现 `crates/consistency/src/error.rs` body（EngineError new/kind/is_*、message const literal，无 format!）
- [ ] T001.3 [US1] 兑现 `crates/consistency/src/idempotency.rs` body（IdemKey parse/as_str；SeenState 已穷尽）
- [ ] T001.4 [US1] 兑现 `crates/consistency/src/outbox.rs` body（Topic parse/as_str、Disposition::as_label、PermanentError new/kind、HandleResult ack/requeue/reject/disposition、Entry new/topic/idem_key/payload）
- [ ] T001.5 [US1] 覆盖率 ≥90%；`cargo nextest run -p consistency`、`clippy -D warnings`、`fmt --check` 绿；移除已读字段的 `#[allow(dead_code)]`

### T002 [US1] P2 · consistency body L3–L4
**触及**: `crates/consistency/src/{saga,reconcile,projection}.rs` · **等级**: L3/L4 · **blocked-by**: T001（共用 error.rs/EngineError）· **并行**: 否（依赖 T001）。

- [ ] T002.1 [US1] 先写表驱动测试：`StepName::parse`（合法标识符/拒非法）、`EntityId::parse`（拒空）、`Lsn::new/get` 单调、`Request::default`=resync/`for_entity`/`entity`、`Outcome::settled/requeue_after/requeue_interval`、`ReconcileError::new/is_*`、`ProjectionEvent` 泛型消费 —— FAIL
- [ ] T002.2 [US1] 兑现 `saga.rs` body（StepName parse/as_str；SagaOutcome/CompensationOutcome 已穷尽）
- [ ] T002.3 [US1] 兑现 `reconcile.rs` body（EntityId、Request、Outcome、ReconcileError、Context opaque 访问器）
- [ ] T002.4 [US1] 兑现 `projection.rs` body（Lsn new/get；ProjectionEvent 默认/约束）
- [ ] T002.5 [US1] 覆盖率 ≥90%；nextest/clippy/fmt 绿

### T003 [P] [US1] P3 · postgres 基座
**触及**: `adapters/postgres/{Cargo.toml,src/lib.rs,src/{pool,tx,migrator}.rs,migrations/}` · **等级**: —（纯基础设施连接层，无业务一致性等级；安全/连通性由集成测试 + xtask verify 覆盖）· **blocked-by**: 无 · **并行**: 与 T001 并行。

- [ ] T003.1 [US1] 先写集成测试骨架（`#[cfg(feature="integration")]`）：Pool 连接、TxManager begin/commit/rollback、Migrator 应用空 migration —— FAIL
- [ ] T003.2 [US1] 加 sqlx 依赖；实现 `PgStore` Pool + `TxRunner`(diport, run_global_transaction) + Migrator(`sqlx::migrate!`) + `impl ManagedResource`（替换 todo!()）
- [ ] T003.3 [US1] 建 `migrations/README.md`（命名 `{序号}_{动词}_{对象}.sql`、只增不改、pre-GA 普通 CREATE INDEX）+ `0001_init_schema.sql` 占位
- [ ] T003.4 [US1] 交付 `docker/dev-stack.yml`（本地 postgres，T006 补 redis/rabbitmq）+ `.env.example`，使 quickstart 的 durable 集成测试可运行；并在该 crate `Cargo.toml` 定义 package-scoped `[features] integration = []`
- [ ] T003.5 [US1] 单测以 fake/sqlite 或 testcontainer；clippy/fmt 绿；`cargo xtask layer-deps` 绿（adapter 不被域依赖）

---

## Wave 2 — durable 主干（T004/T005 blocked-by W1；T006 仅依赖已有 diport，可与 W1 并行）

### T004 [US2] P4 · outbox durable store + relay + sweeper
**触及**: `adapters/postgres/src/outbox.rs`+`migrations/000x_create_outbox.sql` · `crates/eventexec/src/relay.rs` · **等级**: L1/L2 · **blocked-by**: T001,T003 · **并行**: 与 T005/T006 并行（不同文件）。

- [ ] T004.1 [US2] 先写测试：L1 事务回滚→outbox 无 entry（原子性）；relay 一轮：发布成功→CAS published、瞬态→retry_after、永久→DLX；崩溃重投 idempotent —— FAIL
- [ ] T004.2 [US2] migration 建 outbox 表（data-model §outbox：status 值集/lease_token/retry_after + 索引）
- [ ] T004.3 [US2] `OutboxStore.append`（事务内双写）+ `impl OutboxRelay`（consistency trait）
- [ ] T004.4 [US2] `eventexec/relay.rs`：relay CAS 循环（按 domain/status/retry_after 扫）+ sweeper worker。worker 实现 `ManagedResource`、经组合根 `ShutdownStack::register_with_token(|token| …)` 注入 root `CancellationToken`（token funnel），两阶段逆序关闭（`shutdown_within` budget，在途写不丢、先于 pool 关闭）——不裸用 JoinSet/CancellationToken（ADR-001 shutdown 逆序编排）
- [ ] T004.5 [US2] relay/sweeper 注册运行时操作 health probe `outbox_relay` / `outbox_sweeper`（**无 `_ready` 后缀**，遵 observability.md §Readyz Probe 命名），worker 异常退出经该 probe 反映 health（refs: FR-004/FR-005）
- [ ] T004.6 [US2] L1/L2 原子性治理 #[test]（OUTBOX-ATOMIC-IDEM-01，Medium）+ relay/sweeper 两阶段逆序 shutdown budget 测试（在途写不丢）；clippy/fmt/覆盖率绿

### T005 [P] [US3] P5 · idempotency/inbox 去重 + replaydeps resolver
**触及**: `adapters/postgres/src/inbox.rs`+migration · `adapters/redis/src/{claimer.rs,lib.rs}` · `crates/bootstrap/src/replaydeps.rs` · **等级**: L0 · **blocked-by**: T001,T003 · **并行**: 与 T004/T006 并行。

- [ ] T005.1 [US3] 先写测试：首见 Fresh/再见 Duplicate（pg INSERT ON CONFLICT、redis CAS）；consumer group 漂移→去重失效（负向）；replaydeps demo→in-mem、多副本缺 redis→fail-closed —— FAIL
- [ ] T005.2 [US3] postgres `inbox_dedup` 表 + `impl IdempotencyStore`（claim-or-skip）
- [ ] T005.3 [US3] redis claimer（`_runtime:{event_id}:{group}` namespace）+ `impl ManagedResource`
- [ ] T005.4 [US3] `bootstrap/replaydeps.rs` sealed resolver（demo in-mem claimer / 多副本 redis；fail-closed，TOPO-INMEM-SEAL-01 + TOPO-FAILCLOSED-01）
- [ ] T005.5 [US3] L0 表驱动 + resolver 单测；clippy/fmt 绿

### T006 [P] [US4] P6 · amqp transport + eventtransport resolver
**触及**: `adapters/amqp/src/{lib.rs,publisher.rs,subscriber.rs}` · `crates/bootstrap/src/eventtransport.rs` · **等级**: —（传输，纯基础设施/连通性，无业务一致性等级；安全/连通性由集成测试 + xtask verify 覆盖）· **blocked-by**: diport（已有）· **并行**: 仅依赖已有 diport crate，可与 T001/T003/T004/T005 并行开发，不 blocked-by W1。

- [ ] T006.1 [US4] 先写集成测试：publish→subscribe 闭环、per-domain 队列隔离、凭据不进日志；eventtransport demo→同进程 bus / durable→amqp、缺 broker→fail-closed —— FAIL
- [ ] T006.2 [US4] lapin `impl Publisher`/`impl Subscriber`（per-domain vhost/credential，redaction）+ `impl ManagedResource`（替换 todo!()）
- [ ] T006.3 [US4] `bootstrap/eventtransport.rs` sealed resolver（demo MemBus / durable amqp；fail-closed）
- [ ] T006.4 [US4] 集成测试 feature 门控（该 crate `Cargo.toml` 定义 package-scoped `[features] integration = []`）；向 `docker/dev-stack.yml` 补 redis/rabbitmq 服务；clippy/fmt 绿；`cargo xtask` 凭据 redaction 核查
- [ ] T006.5 [US4] **单测**（非 integration feature 门控）synthetic redaction 断言：mock tracing subscriber 验证 amqp URI 密码 part（`://<user>:<pass>@` userinfo）不出现在任何 span field（EVENTTRANSPORT-CRED-REDACT-01，Medium）

---

## Wave 3 — 消费框架 + #1100 集成

### T007 [US5] P7 · ConsumerBase + DLX + 订阅注册
**触及**: `crates/eventexec/src/consumer.rs` · `adapters/postgres/src/dead_letter.rs`+migration · `crates/diport/src/dead_letter_store.rs` · `crates/bootstrap`(订阅注册 glue) · **等级**: L2 · **blocked-by**: T004,T005 · **并行**: 否（W3 内 T008 依赖本 PR）。

- [ ] T007.1 [US5] 先写测试：ack→commit+mark done；requeue 预算耗尽→DLX；reject(permanent)→DLX；active 契约无 handler→治理失败 —— FAIL
- [ ] T007.2 [US5] `DeadLetterStore`(diport) + postgres dead_letter 表/impl
- [ ] T007.3 [US5] `eventexec/consumer.rs` ConsumerBase（claim→handle→commit/release，退避预算，DLX 收口；复用 run_dispatch 范式，认知复杂度 ≤15）
- [ ] T007.4 [US5] 订阅注册 glue 与 contract.toml 同源（generated）；active-subscriber 治理 #[test]（EVENT-ACTIVE-SUB-01，Medium）
- [ ] T007.5 [US5] DLX 写入结构化 tracing 测试：验证 `tracing::error!` span 字段（domain / contract_id / topic / num_attempts / error_summary）均存在（refs: FR-009）
- [ ] T007.6 [US5] clippy/fmt/覆盖率绿

### T008 [US6] P8 · #1100 identity.session-created durable 接线 + consumer 幂等
**触及**: `crates/identity/src/application.rs` · `crates/audit/src/application.rs` · `journeys/` · `contracts/event/identity/v1/contract.toml`(graduate) · **等级**: L2 · **blocked-by**: T004,T005,T007（T006 可选）· **并行**: 否。

- [ ] T008.1 [US6] 先写测试：会话创建+outbox 同事务原子性；relay 重投 session.created→audit 仅 append 一次（幂等）；replay+投影重建；journey demo+durable 双拓扑 —— FAIL
- [ ] T008.2 [US6] 重写 `LoginService::login`：直接 publish → 构造 `outbox::Entry`（envelope 注入）+ 事务内 append durable outbox
- [ ] T008.3 [US6] `audit` 消费侧以 EventId `IdempotencyStore::try_claim` 幂等去重后 append
- [ ] T008.4 [US6] journey 升级（in-mem 替身 → 可选 durable 拓扑）；contract lifecycle draft→active（subscriber+route group 经 bootstrap 验证）
- [ ] T008.5 [US6] L2 原子性+幂等治理 #[test]；扇出闭环（contract→generated→metadata→journey→docs）；clippy/fmt 绿

---

## Wave 4 — 高阶机制（W1+T007 后并行）

### T009 [P] [US7] P9 · saga executor + tailer + journal + 逆序补偿 + checkpoint store
**触及**: `crates/eventexec/src/saga.rs` · `adapters/postgres/src/{saga_journal,checkpoint}.rs`+migration · `crates/diport/src/checkpoint_store.rs` · `crates/bootstrap/src/sagaprojectiondeps.rs` · `contracts/saga/` · `xtask`(saga governance) · **等级**: L3 · **blocked-by**: T002,T003,T007 · **并行**: 与 T011/T012 并行（T010 依赖本 PR 的 checkpoint）。

- [ ] T009.1 [US7] 先写测试：3-step 全成→journal 顺序；step2 失败超预算→逆序 compensate step2/step1；从 step2 checkpoint resume→跳过 step1；kind:saga governance 正/负 —— FAIL
- [ ] T009.2 [US7] `OwnerCheckpointStore`(diport) + postgres checkpoint 表（CAS version）—— **P10 复用**
- [ ] T009.3 [US7] postgres saga_journal 表 + reader/append
- [ ] T009.4 [US7] `eventexec/saga.rs`：SagaId/SagaActionCtx body + SagaExecutor run/resume（前向 append + 失败逆序补偿，补偿失败→saga dead-letter）+ SagaTailer status
- [ ] T009.5 [US7] `bootstrap/sagaprojectiondeps.rs` resolver（demo mem / durable pg journal+checkpoint+tx+locker；fail-closed）
- [ ] T009.6 [US7] saga dead-letter observability 字段测试：验证补偿失败写 dead-letter 时 `tracing::error!` 含 saga_id / step_name / error_summary 非空，dead-letter 记录的 contract_id / domain 取 saga owner（refs: SC-006）
- [ ] T009.7 [US7] `contracts/saga/` kind + xtask SAGA-CONTRACT-01 governance（Medium，正/负用例）；clippy/fmt 绿

### T010 [US8] P10 · projection/CQRS + 断点续投
**触及**: `crates/eventexec/src/projection.rs` · `adapters/postgres/src/projection_events.rs`+migration · `lints/rss_projection_append_only/` · **等级**: L3 · **blocked-by**: T002,T003,T007,**T009(checkpoint 接缝)** · **并行**: 否（依赖 T009 checkpoint）。

- [ ] T010.1 [US8] 先写测试：处理 100 事件 checkpoint=50→重启续投 51-100（无重复/遗漏）；从 0 重放=增量一致；同 Lsn 重投 no-op；append-only dylint synthetic red case —— FAIL
- [ ] T010.2 [US8] postgres projection_events 表（append-only，migration REVOKE UPDATE/DELETE）
- [ ] T010.3 [US8] `eventexec/projection.rs`：投影 harness（apply<E: ProjectionEvent> + 复用 T009 checkpoint 续投 + TxRunner 同事务 CAS）
- [ ] T010.4 [US8] dylint `rss_projection_append_only`（AST 拒 DELETE/TRUNCATE projection_events，PROJECTION-APPEND-ONLY-01，Medium）+ 接入 `cargo dylint --all`
- [ ] T010.5 [US8] projection_events migration 补对应 down 脚本 `GRANT UPDATE, DELETE`（对应 up 脚本的 `REVOKE UPDATE, DELETE`）；在 `migrations/README.md` 约定 REVOKE/GRANT 必须配对（refs: docs/rules/eventbus.md §append-only，DB 引擎 REVOKE = Hard 主守卫）
- [ ] T010.6 [US8] L3 replay+投影重建 #[test]；clippy/fmt 绿

### T011 [P] [US9] P11 · reconcile 环 + leader-elect + fencing
**触及**: `crates/eventexec/src/reconcile.rs` · `crates/diport/src/{leader_elector,fenced_writer}.rs` · `adapters/{redis,postgres}`(impl) · **等级**: L4 · **blocked-by**: T002 · **并行**: 与 T009/T012 并行。

- [ ] T011.1 [US9] 先写测试：缺 Tenancy→编译错（trybuild）；2 副本并发 acquire lease→仅一成功、丢 lease→接管；epoch 单调（旧拒/新受）；timeout→requeue_after；resync 全量 —— FAIL
- [ ] T011.2 [US9] `LeaderElector`/`FencedWriter`(diport) + adapters/{redis,postgres} impl + test fake
- [ ] T011.3 [US9] `eventexec/reconcile.rs`：Loop harness + `Builder`（必填 sealed Tenancy + Trigger，RECONCILE-TENANCY-REQ-01 Hard）+ leader-gated dispatch + per-entity 退避 + panic→transient
- [ ] T011.4 [US9] L4 状态机/超时/fencing #[test]（RECONCILE-FENCE-MONO-01，Medium）；clippy/fmt 绿

### T012 [P] [US10] P12 · command dispatch + codegen
**触及**: `crates/eventexec/src/command.rs` · `contracts/command/` · `generated/`(codegen) · `xtask`(codegen 完整性+双侧对称) · **等级**: L2/L3 · **blocked-by**: T004,T007 · **并行**: 与 T009/T011 并行。

- [ ] T012.1 [US10] 先写测试：command 契约→codegen 产 emit/register wrapper；同 DispatchId 二次→claimer 拒；忘注册 handler→双侧对称治理失败；无裸 emit 出口 —— FAIL
- [ ] T012.2 [US10] `contracts/command/` kind + schema（consistencyLevel=OutboxFact/L3，topic=`<domain>.commands.<name>`）
- [ ] T012.3 [US10] `eventexec/command.rs` runtime `command::emit_async`（→ `outbox::Entry::new`）
- [ ] T012.4 [US10] generated codegen：`<cmd>::emit_async` + `register_handler` wrapper（triple funnel，禁裸调）
- [ ] T012.5 [US10] xtask COMMAND-SYMMETRY-01 governance（codegen 完整性 + 双侧对称，Medium，anti-vacuity）；扇出闭环；clippy/fmt 绿

---

## 依赖图

```
W1: T001(P1)[P] ─┬─→ T002(P2)
    T003(P3)[P] ─┘
W2:  T004(P4)[P] ┐  (T001,T003)
     T005(P5)[P] ┤  (T001,T003)
     T006(P6)[P] ┘  (diport 已有，无 W1 前置，可提前并行 W1)
         │
W3:  T007(P7) ──→ T008(P8=#1100)   (T004,T005 → T007 → T008)
         │
W4:  T009(P9)[P] ──→ T010(P10)     (T002,T003,T007;T010 另需 T009 checkpoint)
     T011(P11)[P]                  (T002)
     T012(P12)[P]                  (T004,T007)
```

## 并行机会（最大并行度）

- **W1**: T001 ∥ T003（2 路）；T002 待 T001。
- **W2**: T004 ∥ T005 ∥ T006（3 路）；T004/T005 blocked-by W1，**T006 无 W1 前置（仅依赖已有 diport），可提前与 W1 并行启动**。
- **W3**: T007 → T008（串行 2）。
- **W4**: T009 ∥ T011 ∥ T012（3 路）；T010 待 T009（checkpoint）。

## MVP 范围

最小可演示闭环 = **T001 + T003 + T004 + T005 + T007 + T008**（durable outbox 端到端 + #1100），覆盖 SC-002/003/004/005。saga/projection/reconcile/command（T009–T012）为增量高阶能力。

## 实施策略

按 wave 推进；每 wave 内 `[P]` PR 可并行开 worktree。每 PR 独立 TDD→PR→review→fix→merge。wave 滚动顺序最终以 epic #1005 `pm:epic-wave` 评论为准（见 issues 技能 Part A）。
