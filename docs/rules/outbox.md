# Outbox 规则

本文拥有 L2 producer/fact、outbox identity、relay、same-ID 窗口与恢复边界。

## Producer/fact closure

- OutboxFact HTTP producer 的每个 `emits` 必须指向同 domain 的存在 event；全 lifecycle 生效。
- active producer 只指向 active 且有 subscriber 的 fact，并经 concern-specific tenant transaction 一次性写业务行
  与 canonical outbox entry。
- generic entry、provider `.write()` 后补 append、publisher 补发和兼容双写均不得进入 active producer。
- carrier：typed contract/schema、generated fact provenance、contract validate 与 L2 assurance。

## 模式与 identity

- PostgreSQL v0.1 只有专属 schema 内的 mutable outbox；无 CDC ledger、fallback 或双写。
- 稳定字段相同为幂等，任一稳定字段不同为 typed conflict；唯一 fingerprint 算法由 core 拥有。
- event ID 是 at-least-once 幂等锚，不是 exactly-once 声明。事务外副作用仍需自己的 idem key/fencing。
- tenant 表必须 ENABLE/FORCE RLS；跨租 relay 仅通过专属 NOLOGIN/NOBYPASSRLS 函数角色和 Outbox
  显式 policy 获得最小权限，runtime 不得成为该角色成员。

## Relay

- publish success 后 settle 前崩溃允许 duplicate；ambiguous outcome 必须用原 event ID 重试。
- publish outcome 闭合为 `Confirmed | DefinitelyNotPublished(PublishFailure) | Ambiguous(PublishFailure)`；
  `PublishFailure` 只携 closed kind/stage/reason，禁止丢弃诊断或暴露 provider 文本。只有 definite permanent
  首投进入 terminal DLQ，ambiguous 固定复用原 `MessageId`。
- claim 在同一数据库语句生成 token/deadline；settle CAS 必须匹配 token 与 deadline，过期租约拒绝。
- 每次 publish 前按数据库当前时间检查 lease 与 absolute delivery budget；预算不足不得调用 broker。
  canonical `rss_transactional_messaging::policy::DeliveryBudget` 只公开 `Duration`，PostgreSQL 的整毫秒投影只能在 adapter 内完成。
- lease 尚未到期但不足以覆盖 publish+settle 时必须 settle 为 `Retry`；不得把短租约伪装为业务 deadline
  到期并永久 dead-letter。publish 与 settle 消费同一 attempt absolute deadline 的分阶段投影。
- relay claim、lease、extend、publish 与 settle provider future 全部经 algorithm-owner `within` race；provider
  继续以同一 cutoff 的 `OperationDeadline` 执行第二层 watchdog。publish race timeout 固定映射为
  `Ambiguous(DeadlineElapsed)`，只允许原 `MessageId` retry；settle timeout 不得伪造 durable disposition。
- provider 在构造期绑定 typed domain，调用方不得传 raw domain。

## Same-ID window

`INVARIANT: OUTBOX-SAME-ID-WINDOW-01`：automatic retry/safety 与 inbox retention policy 由数据库约束，
retention 必须严格覆盖投递窗口与安全余量；v0.1 不自动清理 receipt。

- 首次 claim 冻结 24 小时 automatic deadline；续租只延长 lease，不重置投递窗口。
- 只有数据库确认窗口过期才 DeadLetter；尚未过期但预算不足时 Retry，均不得 publish。
- provider 调用耗时从 lease/window 预算中扣除；无 publish 的结算只消费有效 lease 预算。
- v0.1 无 redrive、resolve、retention worker；Medium carrier 为统一 conformance 与真实 PostgreSQL T2，
  不使用源码 contains、文件数量或 SQL hash 正确性守卫。

## Partition order

`INVARIANT: OUTBOX-PARTITION-ORDER-01`：同 `(tenant, domain, partition_key)` 只允许 head-of-partition admission；
未 terminal settle/DLQ resolution 的 head 阻塞 successor。partition key 必须全局唯一或包含 tenant scope。

## Metadata funnel

`INVARIANT: OUTBOX-METADATA-FUNNEL-01`：reserved envelope 字段只能由 generated/adapter canonical writer
产生；业务 metadata 不得覆盖 tenant、schema、time、trace authority 或 wire identity。

## Recovery

- RSS 只处理外部系统完成 DB/broker restore 后的应用级不一致；不拥有备份、PITR、volume 或 orchestration。
- restore plan 固定 tenant、epoch、restore points、event set 与原 deadline；不得由 restore point 生成新 identity。
- broker-ahead 依赖 Inbox 幂等收敛；DB-ahead 只允许授权 same-ID republish，不绕过 deadline/policy。
- apply 必须消费新 epoch 的 drained fence并原子写 tenant-scoped durable receipt；缺失或不一致即 fail-closed。
- 本能力默认 T1/T2；不得自动注册普通 PR T3、dashboard 或 alert。
