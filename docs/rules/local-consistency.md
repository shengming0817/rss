# 本地事务一致性规则

本文拥有组件本地事务 outcome、重试与 provider 证明边界。产品 route 的读写能力、认证、审计与
HTTP 接线由产品持有；本仓不提供 LocalOnly route/codegen adoption 或通用业务事务 registry。

## 能力与 owner

- `rss-transactional-messaging` 拥有 `LocalTxAttempt`、事务结算分类和消费者事务契约。
- `rss-transactional-messaging-runtime` 拥有消费执行、重试与有界结算算法。
- `rss-transactional-messaging-postgres` 拥有实际 PostgreSQL 事务与连接回收语义。
- `rss-transactional-messaging-testkit` 提供 provider-neutral conformance，真实 provider 测试进入
  `postgres-integration` 等组件 T2 package。
- 本地事务不证明跨系统 effect、消息投递、Saga 或 Reconcile 已完成。多个独立 port 调用不自动组成同一事务。

## Transaction outcome

- `LocalTxAttempt` 覆盖 committed、not-started、rolled-back、rollback-failed、commit-unknown 和
  fenced 六种状态；它报告 provider 事实，构造值本身不执行或证明数据库事务。retry class 与结算结果正交。
- 通用本地事务路径由 provider 返回 `LocalTxAttempt`，调用方通过穷尽 fold 消费结果。
  `ConsumerTx::execute` 则直接返回 `TransactionOutcome<Self::CommitProof>`，不经过该 fold 投影。
  消费者的 committed 分支需要消费 `ReceiptIntent` 并携带 provider commit proof；官方 PostgreSQL
  provider 仅在收到 commit ACK 后铸造私有 proof。缺失 commit ACK 为 commit-unknown，缺失 rollback ACK
  为 rollback-failed。
- 明确 commit/rollback ACK 才可正常回收 connection lease；取消、timeout、未结算或结算失败必须隔离或关闭。
- commit-unknown、rollback-failed 不能被当作 no-write，不能自动重放 handler；事务可能已经 durable。
- transient retry 仅在确认未开始 effect 或 rollback 完成后进行，重建整个 transaction，并沿用原总预算。
- CAS conflict 不因 handler 重试自动解决，调用方须依据最新版本重新决策。
- tenant scope 来自能力的受控上下文与类型；不能把 payload 字符串或未绑定租户的 raw pool 当作租户授权。

## 有界执行

- 一次 monotonic clock observation 确定 operation cutoff 和 settlement cutoff，跨 attempt 不重置预算。
- provider future 同时受算法 owner 的 deadline race 和 provider I/O 边界约束。
- execute race timeout 按 commit-unknown 处理；未来被取消不证明外部操作未发生。
- 结算与投递决定遵循[消息消费规则](event-delivery.md)，不能把数据库事务成功替代 broker settlement。

## 验证载体

- Hard：生产代码中的闭合 outcome、typed transaction 接口、private commit proof 与连接所有权边界。
- Medium：组件状态机测试、provider conformance，以及真实 PostgreSQL 原子性、租户隔离、fault/recovery 测试。
- trait 或公开构造器不能证明第三方 provider 的真实事务语义，必须由其实现和 T2 支持。
- 验证从实际 Cargo consumer 与 provider 推导，不维护 generated HTTP route、active journey 或手工 backend catalog。
- 文档和报告不是执行证据；公共 API 与持久化 identity 的变化遵循[版本规则](api-versioning.md)。
- 产品完整生产验收归产品 T3，组件本地事务不自动授权产品部署、迁移执行或生产运维建设。
