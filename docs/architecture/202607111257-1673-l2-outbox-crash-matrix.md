# L2 OutboxFact crash matrix

`identity.session-created` 在契约中声明 `consistencyLevel = "OutboxFact"`（L2）。L2 的保证是：业务写与
outbox fact 同一本地事务提交；relay 以稳定 event/message ID 做 **at-least-once publish**；consumer 以
同一 ID 经 inbox 状态机幂等收口。它不保证 broker exactly-once publish。

ref: serverlesstechnology/cqrs src/cqrs.rs@b13692ce3db62b3b7fea19dddeec90a9d8af3180
ref: apalis packages/apalis-sql/migrations/postgres/20250307001101_add_job_priority.sql@49f90e1304f8f218eb08ce6ca0f1b4934f3ed011
ref: sqlxmq migrations/20220208120856_fix_concurrent_poll.up.sql@79cbd3091ab39178d5de65d14416dad6067ac067

上游 `cqrs-es` 在事件存储后同步 dispatch；RSS 为跨进程 broker 投递增加 durable outbox 的
typed atomic claim → publish → strict-deadline CAS settle，以及 consumer inbox claim → commit → ack。
Outbox claim 在单个数据库事务内确定性选取、写入 token/`lease_until`，并由
构造期绑定唯一 typed domain 的 `PgOutbox::claim_batch(limit)` 铸造 provider-owned opaque
`PgClaimedOutboxEntry`；调用方不能给 claim 路径传 raw domain。该类型只能按值交给同一
`PgOutbox` 的 relay 路径消费；lease 与 durable context 保持 provider-private，不是
`consistency` 可公开 hydrate 的引擎类型。settle 同时比对 token、精确 deadline 与 DB 当前时间。
CAS 不能消除 publish 已成功但结果尚未 settle 的不确定窗口。

relay 以 `max_in_flight` 同时限制 claim 数和 publish 并发数（`1..=64`），并在 claim 返回后即时并发
dispatch。同批对每个非空 `(tenant_id, domain, partition_key)` 只有 SQL gate 选出的唯一队头，所以并发不
放宽分区内顺序。每条 publish 前还须以 DB 当前时间验证 token/deadline 与剩余 lease budget；预算必须覆盖
完整 40s broker publish timeout，否则不发 broker 请求。timeout 或 confirm 丢失仍是 ambiguous outcome，
可能已经产生 delivery，必须以同一 event/message ID 重试。

## Crash matrix

| 故障窗口 | 崩溃后的 durable / broker 状态 | 恢复动作 | 重复风险 | Pass | Fail |
|---|---|---|---|---|---|
| DB transaction commit 前 | 业务写与 outbox row 一并回滚；无 delivery | 重试完整业务命令 | 无已提交 fact | 不出现孤立业务写或孤立 outbox row | 任一侧单独提交 |
| DB commit 后、relay claim 前 | outbox `pending` | 后续 `claim_batch` 取得 lease 并发布 | 无；尚未 publish | 稳定 fact 可被捞取并最终 `published` | 已提交 fact 永久不可见 |
| relay claim 后、publish preflight 前 | outbox `publishing`，broker 无 delivery | lease TTL 到期后重捞 | 无；尚未 publish | stale lease 可恢复且旧 holder 不能 settle | row 永久卡住或 stale writer 覆盖新 owner |
| publish preflight 发现剩余 lease budget 不足 | outbox 仍为 `publishing`，broker 无 delivery | 不调用 broker；lease 到期后以新 token 重捞 | 无；未发 publish | DB 时间、token 与精确 deadline 共同围栏预算 | 仍调用 broker，允许请求越过 lease deadline |
| broker publish 达到 40s timeout / confirm 结果丢失 | outbox 仍为 `publishing`；broker 可能已有 delivery | 按不确定结果处理；以稳定身份重发，再 CAS settle | **允许 broker duplicate** | 不把 timeout 当作“确定未发布”，身份不漂移 | timeout 后换 ID、丢 fact或错误地假定不会重复 |
| publish 成功后、settle 前 | outbox 仍为 `publishing`，broker 已有一次 delivery | lease TTL 到期后以相同身份重发，再 CAS settle | **允许 broker duplicate** | 两次 topic/payload/tenant/contract/message ID 相同，最终 `published`，consumer 副作用一次 | 换 ID、丢 fact、误改未过期对照行或副作用执行两次 |
| settle 后 | outbox `published` | 无；正常 claim 不再返回 | 无新增 relay 重发 | 已结清 row 不再进入待发批次 | `published` row 被正常 claim 重发 |
| consumer 收到 delivery、claim 前 | broker delivery 未 ack；inbox absent | broker redelivery 后重新 claim | delivery 可重复 | 首次 claim 为 `Fresh` | 未 claim 即 ack 导致消息丢失 |
| inbox claim 后、commit 前 | inbox `claimed`；delivery 未 ack | claim lease 到期后由新 token reclaim | handler 可能被重新调用；副作用必须位于受幂等/事务保护边界 | stale token 无法 commit，新 holder 可收敛 | stale holder commit 或 claim 永久阻塞 |
| inbox commit 后、broker ack 前 | inbox `done`；broker 仍可能 redeliver | redelivery claim 返回 `Duplicate` 并 ack | broker duplicate，业务副作用无重复 | handler 总副作用一次 | `done` delivery 再执行 handler |
| DLX 后、人工 redrive 前 | outbox/dead-letter 保留终态与脱敏摘要 | 经受审 redrive 恢复为可投递状态，保持原 fact 身份 | redrive 可再次投递 | 原 event/message ID 与 tenant scope 不漂移，最终由 inbox 去重 | 生成新身份、绕过 tenant scope 或静默丢弃 |

矩阵中的“一次”指 durable fact 最终只收敛到一个终态、consumer 业务副作用一次；不指 broker publish
调用一次。fixture 的 `expectedInvariant = "outbox-publish-settled-once"` 也按此解释。

## 可执行证据

默认 hermetic crash/restart 编排证据是 `crates/eventexec/tests/outbox_crash_matrix.rs`。测试直接解析
`fixtures/consistency/outbox/fixture-outbox-after-publish-before-settle.toml`，并要求其映射到闭枚举
`CrashFaultSpec::OutboxAfterPublishBeforeSettle`，因此不存在第二套自由字符串场景。它通过公共
`eventexec::relay_loop` 驱动内存 durable-state fake：provider 自身给出 domain；首个 worker 在记录 publish 后阻塞 settle，abort
模拟硬崩溃；只过期目标 lease 后重启，断言 fake 以同一身份重发、最终 settle、另一 tenant 的同 partition
未过期对照行不变。这个对照只证明恢复不会误改一个不符合 claim 条件的邻近行，不作为 PG tenant 隔离证据。
两次 delivery 再经过实际 `consistency::InboxState` claim/commit 状态机，第一次 `Fresh`
执行副作用并进入 `Done`，第二次 `Duplicate`，副作用总计一次。

生产 relay 的 broker identity 由 `adapters/postgres/src/outbox.rs` 中 `publish_request` 单源构造；真实
`PgOutbox::relay` 与 fault-matrix publish-before-settle 路径共同调用。默认 postgres 单测对同一 durable
`StoredOutboxEntry` 连续构造两次请求，锁定 `event_id`、topic 与 payload 均不漂移，避免 crash fake 自己预置
相同身份后形成自证。

```bash
cargo test -p eventexec --test outbox_crash_matrix
cargo test -p postgres relay_publish_request_reuses_durable_identity_on_every_attempt
cargo xtask consistency-fixtures
```

#1641 已落地的真实后端 journey 位于
`journeys-fault-matrix/tests/consistency_fault_matrix_journey.rs`，同一 fixture 被绑定到
`CrashRunner::PostgresRabbitmq` 和 `run_outbox_after_publish_before_settle`。它验证真实 PostgreSQL
lease/CAS 与 RabbitMQ delivery/ack 行为；属于 opt-in lane，不进入默认快测：

```bash
cargo xtask ci-integration --shard consistency-fault
```

## 证据边界

| 证据 | 能证明 | 不能证明 |
|---|---|---|
| 默认 hermetic 测试 | fixture/闭枚举及 status/domain/contract/runner 绑定；公共 relay loop 的 crash 中间态、显式 lease 恢复、fake 重发、最终 settle、未过期对照行保持不变；生产 `publish_request` 对同一 durable event 的 broker identity 不漂移；实际 inbox 纯状态机去重 | PostgreSQL SQL、RLS、真实 tenant/partition scope、真实时钟 TTL、AMQP confirm/channel redelivery、网络结果 |
| #1641 Postgres/RabbitMQ journey | 真实 PG durable row、lease/CAS 与 RabbitMQ publish/redelivery/ack 的既有集成证据 | 任意网络分区、进程被 SIGKILL 的所有时点、broker 集群灾难 |
| 尚未覆盖 | publish 请求已到 broker、client 在 confirm 前断线等所有 ambiguous outcome 组合；40s timeout 的每种 broker 结果；跨节点时钟/网络分区组合 | 不得据现有测试宣称已覆盖或 exactly-once；timeout 仍须保守按可能已 delivery 处理 |

因此运行期与文档统一采用 at-least-once 术语。任何依赖“CAS 使 broker 至多 publish 一次”的实现或运维
假设都不成立；稳定事件身份与 consumer inbox 幂等是 L2 闭环不可删减的组成部分。
