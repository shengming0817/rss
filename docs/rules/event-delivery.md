# Event Delivery 规则

本文拥有 consumer transaction、claim/lease、Disposition、settlement、ordering 与 dead-letter lifecycle。

## Consumer transaction

- 每次 delivery 在 tenant-scoped `ConsumerTx` 内完成 Inbox idempotency、handler effect 与 settlement intent。
- duplicate 必须返回既有 terminal result；不得再次执行 handler 或外部副作用。
- 应用 handler 只能取得 typed context/repositories，不得取得 raw broker acker、connection 或 transaction。
  可信 companion 基础设施可实现 PG-specific effect 并借用 SQLx connection；此能力不是恶意 SQL 沙箱。
- 唯一规范 outcome 是 `rss_transactional_messaging::transaction::TransactionOutcome<C>`；provider 用私有
  associated commit proof 绑定成功分支。禁止镜像枚举、转换桥、crate-root re-export 或生产 `()` proof。
- commit outcome unknown 不得 success-ack；由同 ID redelivery 与 Inbox state 收敛。
- `DeliverySource` 只交付字段私有的 `ManagedDeliveryStream`；stream item 携 typed envelope 与 move-only
  settlement，消费者不能拆出 raw stream 重新组合 lifecycle。topology 不进入 ingress port，未结算 delivery
  由 provider session 关闭后交 broker redelivery。
- ingress validator 必须消费 core-issued `IngressChallenge` 并返回 `VerifiedIngress`；pipeline 在 claim 前再次
  核对 subscription、tenant、message identity、contract 与 fingerprint，验证证据不得擦除为 `()`。

## Claim 与 lease

- claim token/epoch 私有铸造；extend/release 必须 CAS 匹配完整 lease identity；provider 事务内写 terminal receipt。
- lease lost 是 hard fence：停止后续 effect/settlement，取消在途可取消工作，并让 broker redeliver。
- 运行期可能在 TTL race 中重复执行，因此所有外部 side effect 必须幂等、可重入或由 fencing 保护。
- subscriber 只能铸造字段私有、move-only 的 managed delivery stream；stream 与 lifecycle token 必须同源，
  raw stream/token compose API 禁止。强制取消必须同时终止 handler 与 renewal，且不得 ACK、commit、写 DLQ、
  伪造 requeue 或释放无法证明 rollback-safe 的 claim；未结算 delivery 交由 broker redelivery。

## Disposition 与 settlement

`TransactionOutcome` 是闭值：committed、not-started、rolled-back、rollback-failed、commit-unknown、fenced。
自由字符串或 adapter-specific fallback 禁止。

- broker ACK/NACK/Reject 只能由 transaction outcome 产生；handler 不直接控制。
- success ACK 只能发生在 durable commit 明确成功之后。
- 只有 handler transient 进入本地 retry budget；infrastructure transient、commit unknown、rollback failed 与
  fenced 立即重投，不得写 application DLQ 或提交 Inbox done。Rejected 先回滚 effect savepoint，
  再在同一事务提交完整 terminal receipt；v0.1 不提供 application DLQ。
- 本地 retry loop 必须接收一个 `rss_transactional_messaging::policy::RetryPolicy`；尝试上限与指数 backoff 不得拆开传递或
  单独默认。标准值为三次总尝试、1 秒 base、60 秒 cap。
- TransactionalMessaging worker 构造必须显式接收 `rss_transactional_messaging::policy::ShutdownBudget`；标准值 45 秒，仅在 internal
  `ManagedResource` 边界投影为 `Duration`。
- claim、extend、handler transaction、retry delay、settle、release 与 abandon 都消费同一次 clock observation
  mint 的 operation/settlement absolute deadline。algorithm owner 必须通过唯一 `within` funnel race provider
  future；provider 同时消费该 cutoff 投影的 `OperationDeadline` 作为第二层 I/O watchdog，任一层不得重置预算。
- execute deadline elapsed 一律按 commit outcome unknown 处理，并在 settlement reserve 内尝试 abandon；
  release/settlement/abandon timeout 不得触发第二个或矛盾 broker decision。drop future 只请求取消，不证明
  provider effect 未发生。
- rollback success 才能按 retry disposition 结算；rollback failed/commit unknown 必须保守重投并保留诊断。
- settlement transport failure 不改变 durable outcome；以相同 message ID 重投并读取 Inbox result。

## Ordering

- 需要顺序的 contract 必须声明 typed partition key；consumer 同 partition 串行，不同 partition 可并发。
- DLQ 未 resolution 的 head 阻塞同 partition successor；不得因 retry、restart 或 rebalance 越过。
- 顺序保证不等于 exactly-once，也不替代业务 fencing。

## Dead letter

- v0.1 仅记录闭值 terminal disposition；application DLQ、replay/redrive/resolve、operator authorization
  与 audit 属于消费者，不提供仓内实现或隐式恢复入口。

## Carrier

- Hard：private lease/authorization types、managed delivery stream、closed Disposition、typed `ConsumerTx` 与
  no-raw-acker boundary，以及 typed retry/shutdown budget。
- Medium：provider conformance、transaction fault tests、tenant gates 与真实 broker/database integration。
