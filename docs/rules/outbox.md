# Outbox 规则

本文拥有 Outbox 事务写入、identity、relay、same-ID 窗口与恢复边界。

## Transactional admission

- 相关业务效果与 Outbox entry 必须在调用方的同一租户事务内原子提交或回滚；
  `OutboxWriter::append` 不提交调用方事务，事务结算遵循[本地事务规则](local-consistency.md)。
- PostgreSQL 官方 Rust writer 与 SQL 入口共用组件 prepare/append 函数，遵循相同的身份、分区与权限约束。
  事务提交后补 append、publisher 补发或兼容双写不能替代原子写入。
- carrier：core 的 typed transaction/writer 契约、PostgreSQL 组件函数与真实 T2 原子性测试。
  产品拥有业务组合与租户授权；接口类型本身不证明第三方 provider 的事务实现。

## 模式与 identity

- PostgreSQL v0.1 只有专属 schema 内的 mutable outbox；无 CDC ledger、fallback 或双写。
- 稳定字段相同为幂等，任一稳定字段不同为 typed conflict；唯一 fingerprint 算法由 core 拥有。
- event ID 是 at-least-once 幂等锚，不是 exactly-once 声明。事务外副作用仍需自己的 idem key/fencing。
- tenant 表必须 ENABLE/FORCE RLS；跨租 relay 仅通过专属 NOLOGIN/NOBYPASSRLS 函数角色和 Outbox
  显式 policy 获得最小权限，runtime 不得成为该角色成员。

## Companion transaction admission

`PgOutboxWriter::validate_transaction` 通过私有 runtime provenance 拒绝其它 runtime 的事务。
companion repository 在任何读写之前调用，包括不会追加消息的读取、幂等重放和无变化操作。
校验不执行 SQL、不提交事务，不要求构造 relay store 或 delivery budget；tenant 授权和业务组合仍归宿主。

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
- 基础组合不启用恢复；recovery 提供显式 redrive/resolve，但不提供 retention worker；Medium carrier 为统一 conformance 与真实 PostgreSQL T2，
  不使用源码 contains、文件数量或 SQL hash 正确性守卫。

## Partition order

`INVARIANT: OUTBOX-PARTITION-ORDER-01`：同 `(tenant, domain, partition_key)` 只允许 head-of-partition admission；
未 terminal settle/DLQ resolution 的 head 阻塞 successor。partition identity 包含 tenant 与 domain，key 可在不同作用域复用。

- PostgreSQL 由组件内 allocator 原子分配 `partition_seq`；`seq` 仅用于行身份和 DR 引用，不参与分区前序判定。
- 官方 Rust 与 SQL 写入共用 prepare/append 函数：一次完整非空分区声明先按精确身份排序取行锁，再分配序号，锁持有到事务结算；不得增量扩展集合。
- 数据库持有事务准备证明和唯一序号；runtime 不得直接 INSERT Outbox、改写排序字段或操作 allocator/底层序列。Recovery 只持有所需状态列更新权限。
- Rust 在失败或取消后阻断提交；consumer effect savepoint 回滚后关闭 Outbox 准入，保留合法 terminal receipt/DLQ 提交。
- 有序旧数据不按 `seq` 回填提交顺序；安装与权限切换归外部 migrator。序号不承诺连续，也不扩展为通用序列服务。
- Medium canonical proof 为真实 PostgreSQL T2：覆盖反序提交、回滚、多分区锁序、SQL 入口与权限拒绝、replay、lease/DLQ 和 DR。

## Metadata funnel

`INVARIANT: OUTBOX-METADATA-FUNNEL-01`：core 的私有字段与 typed constructors 隔离消息身份和业务
扩展属性，adapter 按 canonical wire contract 编解码；业务属性不得覆盖 tenant、schema、time、
trace authority 或 wire identity。metadata 构造不认证租户，可信身份与授权仍由消费方提供。

## Recovery

- RSS 只处理外部系统完成 DB/broker restore 后的应用级不一致；不拥有备份、PITR、volume 或 orchestration。
- restore plan 固定 tenant、epoch、restore points、event set 与原 deadline；不得由 restore point 生成新 identity。
- broker-ahead 依赖 Inbox 幂等收敛；DB-ahead 只允许授权 same-ID republish，不绕过 deadline/policy。
- apply 必须消费新 epoch 的 drained fence并原子写 tenant-scoped durable receipt；缺失或不一致即 fail-closed。
- 本能力默认 T1/T2；不得自动注册普通 PR T3、dashboard 或 alert。

## Explicit recovery

消息 recovery 拥有显式恢复请求；PostgreSQL adapter 在原消息 schema 和事务 owner 内落实。
未过期 dead_letter 可按原身份 redrive；过期头仅可通过带持久化回执的 resolved 处置解除分区阻塞。
resolved 不表示 published，发布事实查询必须区分两者。所有操作按租户、目标版本和稳定操作身份校验。

`INVARIANT: OUTBOX-SQL-MESSAGE-CONTRACT-01`: SQL writers consume the core-owned versioned
`message-wire-v1` byte contract. The database strictly decodes all authored facts and hashes the
exact bytes with SHA-256; callers cannot supply a fingerprint or a private durable projection.
The core encoder is shared with `MessageFingerprint::of`. Transport fields are separate and cannot
change authored identity. Medium proof owner is PostgreSQL `partition::wire_contract`: independent
SQL encoding, malformed inputs, digest parity, authored conflicts and transport-only idempotency.
