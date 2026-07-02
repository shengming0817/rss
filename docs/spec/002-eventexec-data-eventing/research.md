# Phase 0 Research: eventexec 数据持久化与事件处理

技术路径大体已由 G0 架构决策冻结。本文件汇总「已定决策 + 对标依据」并解决 plan 的两个 NEEDS-CLARIFICATION（开放项）。

## 已定决策（追溯 ADR / rules，非本 feature 重开）

### D1. 引擎策略 trait = native AFIT + 泛型静态分发
- **Decision**: `InboxStore`/`OutboxRelay`/`SagaStep`/`Reconciler`/`Projector` 一律 trait 内 `async fn` + 消费方 `fn run<S: Trait>(s:&S)`，非 object-safe，禁 `Box<dyn>`。
- **Rationale**: 零开销零 box；引擎是热路径策略接缝，不需 provider 运行时替换。
- **Alternatives**: async-trait（堆分配 BoxFuture）/ dynosaur（dyn）——均拒，留给 DI port。
- **ref**: ADR-004 C1；consistency/src/lib.rs:1-26。

### D2. DI port = dynosaur dyn（Send 变体）
- **Decision**: `Publisher`/`Subscriber`/`AuditSink`/`Signer`/`ManagedResource`/`LeaderElector`/`FencedWriter`/`OwnerCheckpointStore` 等可替换 provider 走 `#[trait_variant::make(_: Send)] + #[dynosaur(DynX=dyn(box) X, bridge(dyn))]`，组合根注入 `Box<DynX>`/`Arc<DynX>`。
- **Rationale**: provider 运行时可换（in-mem/redis/pg/amqp），需 dyn；Send 变体支持 tokio::spawn 隔离。
- **ref**: ADR-003；diport/src/lib.rs:7-46。

### D3. 持久化库选型
- **postgres** = `sqlx`（编译期查询校验 + `sqlx::migrate!` 命名空间；outbox/inbox/DLX）；**amqp** = `lapin`；**redis** = `redis`（distlock/CAS/历史 replaydeps 后端，不再作为 runtime event consumer claimer）。
- **ref**: gocell-rust-directory-structure §四 工具链清单；framework-comparison（omicron db 层 RLS / SET LOCAL；lapin AMQP）。

### D4. topology-gated resolver fail-closed
- **Decision**: resolver 在 demo(in-mem)/durable 间选型；eventtransport durable 使用 broker+PG inbox/DLX，Redis 只随需要它的 runtime 原语启用。durable 缺对应配置 → 启动期 `Err`，绝不回落 in-mem。in-mem 原语 sealed（`pub(crate)` + resolver 私有构造），生产代码类型层不可达。
- **Rationale**: 生产误用 in-mem = 跨进程/重启丢事件，必须编译期/启动期堵死。
- **ref**: docs/rules/eventbus.md §topology-gated；spec FR-007/FR-008。

### D5. 对标源码（已冻进接缝 rustdoc）
- watermill `message/router.go`@master：Disposition Ack/Requeue/Reject + handleMessage 决策（eventexec dispatch / ConsumerBase）。
- oxidecomputer/steno `src/saga_action_generic.rs`@main：`do_it`/`undo_it`/`name` + 逆序补偿（saga executor）；RSS 拒其 `Serialize` bound（C6）、用 native AFIT 替 BoxFuture。
- kube-rs `kube-runtime/src/controller/mod.rs`@main：`Action::requeue`/`await_change` level-triggered（reconcile Loop）。
- TiKV / openraft：fencing + leader election（FencedWriter / LeaderElector）。

## 开放项裁定（本 feature 新决策）

### R1. reconcile Loop harness 落 `eventexec`（决策见 plan §决策 1）
- **Decision**: Loop harness（Builder/Trigger/退避/leader-gated）入 `eventexec::reconcile`；`Reconciler` 引擎 trait 留 `consistency`；`LeaderElector`/`FencedWriter` 入 `diport` + adapter impl。
- **Rationale**: eventexec=runtime 单源；复用其 tokio 结构化并发与 leader/lease 接线；不新建第四运行时 home。
- **Alternatives**: (a) 独立 `reconcileloop` crate——拒（碎片化，1005 范围外）；(b) 放 consistency——拒（consistency 不依赖服务层、不做 I/O/spawn）。

### R2. checkpoint store 并入先落的 P9，P10 复用（决策见 plan §决策 2）
- **Decision**: `OwnerCheckpointStore`(diport) + postgres checkpoint 表 + sagaprojectiondeps 的 checkpoint 分支落 P9；P10 复用，blocked-by P9（仅 checkpoint 接缝）。
- **Rationale**: 避免 P9/P10 同文件冲突；checkpoint 贴 journal 语义、体量小。
- **Alternatives**: 单开 P9a checkpoint 前置 PR 使 P9/P10 全并行——拒（增 PR 数，收益小）。

## 治理载体定档（AI-robust，均 ≥ Medium）

| 约束 | 载体 | 档 | INVARIANT 草案 |
|------|------|----|---------------|
| in-mem 原语生产不可达 | sealed `pub(crate)` + resolver 私有构造（类型系统） | Hard | TOPO-INMEM-SEAL-01 |
| durable 缺配置 fail-closed | resolver 返 `Result` + bootstrap fail-fast | Medium | TOPO-FAILCLOSED-01 |
| Entry/HandleResult/PermanentError 受控构造 | 私有字段 funnel（类型系统） | Hard | （已冻结） |
| Tenancy 必填、Clock 位置参 | 构造器必填非 Option 参 | Hard | RECONCILE-TENANCY-REQ-01 |
| active 事件有 subscriber | xtask governance #[test] | Medium | EVENT-ACTIVE-SUB-01 |
| L2 outbox 原子性 + consumer 幂等 | xtask/集成 governance #[test] | Medium | OUTBOX-ATOMIC-IDEM-01 |
| kind:saga 契约合规 | xtask governance #[test] | Medium | SAGA-CONTRACT-01 |
| command 双侧对称 + 无裸 emit | codegen + xtask 完整性 #[test] | Medium | COMMAND-SYMMETRY-01 |
| projection_events append-only | DB 引擎 `REVOKE UPDATE, DELETE`（serving role，migration 内 GRANT 收紧）| Hard | PROJECTION-APPEND-ONLY-01（主守卫，refs: eventbus.md §append-only） |
| projection_events append-only | dylint `rss_projection_append_only`（AST） | Medium | PROJECTION-APPEND-ONLY-01（辅助早拦，与上行 Hard 主守卫并列） |
| fencing epoch 单调 | FencedWriter CAS（运行期）+ 测试 | Medium | RECONCILE-FENCE-MONO-01 |
| broker 凭据 redaction | mock tracing subscriber synthetic 负向测试：amqp URI 的 `://<user>:<pass>@` userinfo 不出现在任何 span field | Medium | EVENTTRANSPORT-CRED-REDACT-01 |

> 落地时 INVARIANT ID 与符号写入对应守卫 rustdoc / 测试头（不在 rules 文件维护实例清单）。

## 未决（留实施期，不阻塞拆解）
- 各 postgres 表的精确索引列与 retention/清理策略（pre-GA 普通 CREATE INDEX；data-model.md 给初版）。
- amqp per-domain vhost/credential 的环境变量命名最终形态（遵 eventbus.md §命名）。
- saga subsaga / projection schema 演化的细节（本 feature 只交付主干，演化按 api-versioning pre-GA 窗口）。
