# Outbox 规则

本文拥有 L2 producer/fact、outbox identity、relay、same-ID 窗口与恢复边界。

## Producer/fact closure

- OutboxFact HTTP producer 的每个 `emits` 必须指向同 domain 的存在 event；全 lifecycle 生效。
- active producer 只指向 active 且有 subscriber 的 fact，并经 concern-specific tenant transaction 一次性写业务行
  与 canonical outbox entry。
- generic entry、provider `.write()` 后补 append、publisher 补发和兼容双写均不得进入 active producer。
- carrier：typed contract/schema、generated fact provenance、contract validate 与 L2 assurance。

## 模式与 identity

- PostgreSQL 只有 mutable outbox 与显式 opt-in append-only CDC ledger；不得 fallback 或双写。
- 两模式共享稳定 fact identity；稳定字段相同为幂等，任一稳定字段不同为 typed conflict。
- event ID 是 at-least-once 幂等锚，不是 exactly-once 声明。事务外副作用仍需自己的 idem key/fencing。
- CDC tenant 表必须 ENABLE/FORCE RLS、最小授权并拒绝 serving UPDATE/DELETE。

## Relay

- publish success 后 settle 前崩溃允许 duplicate；ambiguous outcome 必须用原 event ID 重试。
- publish error 是 closed permanent/transient/ambiguous decision；只有 permanent 首投进入 terminal DLQ。
- claim 在同一数据库语句生成 token/deadline；settle CAS 必须匹配 token 与 deadline，过期租约拒绝。
- 每次 publish 前按数据库当前时间检查 lease 与 absolute delivery budget；预算不足不得调用 broker。
- provider 在构造期绑定 typed domain，调用方不得传 raw domain。

## Same-ID window

`INVARIANT: OUTBOX-SAME-ID-WINDOW-01`：retry/redrive/safety 与 inbox retention policy 由数据库约束，retention
必须严格覆盖全部窗口；runtime 只接受同一 revision/value。

- automatic/redrive absolute deadline 首次冻结，redrive 不延长或重算。
- deadline 到期不得 publish，只能进入唯一 terminal resolution。
- accepted gap 不携 evidence；compensated 必须引用同 tenant、已发布且 causation 匹配的 evidence。
- resolution append-only，serving role 无写权限。Medium carrier 为 `outbox-same-id-guard` 与真实 provider proof。

## Partition order

`INVARIANT: OUTBOX-PARTITION-ORDER-01`：同 `(domain, partition_key)` 只允许 head-of-partition admission；
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
