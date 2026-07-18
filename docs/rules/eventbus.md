# EventBus 规范

## 事件传输选型（topology-gated）

组合根（assembly / bin crate）经 `bootstrap::eventtransport::resolve(topo, cfg, required_domains)`
按 `Topology` 单源选型事件传输。**bootstrap 是服务层 crate**（`deny.toml` + `xtask layer-deps` +
cargo 依赖图三道门禁其依赖 `adapters/*`），故 resolver 是**纯策略函数**——做拓扑选型 + fail-closed
校验 + 凭据 redaction，返回**已校验决策** `ResolvedTransport::{Demo | Durable { per_domain }}`，
**不构造具体 adapter**；组合根 `match` 该决策再构造 `MemBus`（`adapters/memory`）/ amqp
（`adapters/amqp`）。`clk` 不入 eventtransport `resolve` 签名（传输决策不依赖时钟；replaydeps /
saga instance 依赖选型才需 ctx/clk）：

- `Topology::Demo`（demo / memory）→ `ResolvedTransport::Demo` → 组合根构造进程内 in-mem bus（Publisher == Subscriber 同实例）。
- `Topology::DurableShared`（共享 broker）→ `ResolvedTransport::Durable { per_domain }`：每个 required 域
  一条已校验 URL，per-domain（`RSS_<DOMAIN>_AMQP_URL`）缺则**回退**共享 `RSS_AMQP_URL`。
- `Topology::DurableIsolated`（per-domain 隔离 broker）→ `ResolvedTransport::Durable { per_domain }`：每域
  **必须**有 per-domain URL，**禁回退**共享；配置含 shared URL 即 `IsolatedFallbackForbidden` fail-closed
  （防误用共享凭据），缺 per-domain URL 即 `MissingBrokerUrl{domain}` fail-closed。shared vs isolated 是不同
  安全策略，由不同 `Topology` 变体类型编码（非运行期约定）——对应 §per-domain 隔离安全模型。

durable 缺 broker URL **resolve 即返 `Err`**、组合根 fail-fast 拒绝启动，**不静默降级回 in-memory**（relay
必须把已持久化 outbox entry 发到 broker，而非进程内 bus，否则跨进程/重启丢事件）。env 读取在组合根（读后填
typed `TransportConfig`，domain key 自动规范化大写），resolver 保持纯函数可测；`MissingBrokerUrl{domain}`
含 domain + 应设 env 名（可操作，domain 名非 PII）。INVARIANT: TOPO-FAILCLOSED-01（`Result` + bootstrap
fail-fast，Medium）。

in-memory bus **仅** demo 决策可达（INVARIANT: TOPO-INMEM-SEAL-01）——sealing 落**组合根**（bootstrap
命名不到 adapter 类型，无法在本层 sealing）：

- 生产 bin（`bins/server` / `bins/rss`）经 `deny.toml` 连 `memory` adapter 都依赖不到 ⇒ in-mem bus
  类型层不可命名（**Hard，比「bootstrap 内 sealing」更强**；这是 in-mem 生产不可达的**主守卫**）。
- dev 组合根（`journeys` / `examples`，合法依赖 `memory` + `amqp`）：in-mem 仅经
  `match ResolvedTransport::Demo` 臂构造——**决策绑定纪律（Medium）**，把构造收束到已校验决策；
  dev root 仍能直接 `MemBus::new()` 绕过（类型层未封闭，dev-only 可接受），非编译期 Hard。

扩展新 broker（mqtt）：给 `ResolvedTransport` 加变体 + 组合根 `match` 加分支 + 暴露选择 env，不在本约束外另开旁路。
权威语义见 `bootstrap::eventtransport` 模块的 rustdoc。

## per-domain AMQP vhost/credential 隔离

per-domain URL（`RSS_<DOMAIN>_AMQP_URL`，DOMAIN 大写，缺省回退 `RSS_AMQP_URL`）携带 per-domain
凭据（user:pass）和 vhost，是 per-domain 凭据/vhost 隔离的 **seam**。**目标安全模型**（split 拓扑）：operator
为每个域 crate provision 独立 vhost/AMQP user，使每个进程只持有访问自身 broker 资源所需凭据、无法跨域
发布或消费事件。凭据由 broker operator 外部配置（非 framework 派生，无 HKDF/派生层，原因：AMQP broker
用户是外部对象，不存在 framework 可控的 master key）。

在 **split/per-domain 隔离拓扑**下，per-domain URL（`RSS_<DOMAIN>_AMQP_URL`）缺失必须**启动期 fail-closed**，不静默降级回共享 `RSS_AMQP_URL` / 共享凭据；非隔离（共享 broker）拓扑才允许回退 `RSS_AMQP_URL`。URL 含 user:pass，凭据 non-leak
由 typed redaction funnel（Medium）守。权威语义见 `bootstrap::eventtransport` 模块的 rustdoc。

Broker ACL 必须和 domain 绑定：relay producer 凭据只允许 publish 该 domain 的 exchange / routing key；
consumer 凭据只允许 consume runtime 为其 declared 的 queue，并只能 bind contract registry 声明的 topic。
AMQP header / MQTT user property 中的 `tenantId` 不是授权凭据；消费侧写 app DLX 前只信任 relay 签发的
`tenantAuthority`，不能把 broker header tenant 当作 authority。

## 标准 Envelope Header

broker-visible delivery envelope header 的标准字段为：

- `tenantId`：canonical `vocab::TenantId`，缺失或非 canonical 时消费侧 typed header fail-closed。
- `schemaVersion`：契约版本（`v{N}`），由 generated `CONTRACT.version()` 同源写入 outbox
  `contract_version` 物理列；relay 以该列覆盖 metadata header 后发布，CDC 经 `outbox_log.contract_version`
  映射 header。
- `schemaHash`：声明 schema bundle 摘要（`sha256:<64 lowercase hex>`），由 generated
  `CONTRACT.schema_hash()` 同源写入 outbox `schema_hash` 物理列；relay 以该列覆盖 metadata header 后发布，
  CDC 经 `outbox_log.schema_hash` 映射 header。
- `occurredAt`：事件发生 unix 秒，producer 注入 `Clock` 后写入 sealed metadata；relay 从 metadata hydrate，
  CDC 经 DB generated column `outbox_log.occurred_at` 投影 header。
- `trace` / `correlation`：观测字段，缺失或畸形 fail-open，不阻断投递。
- `tenantAuthority`：relay 签发的租户权威 token；消费侧写 app DLX 前必须验签。CDC 不签发该 header。

`subjectId` / `actor` / `principal` / `causation_id` 与业务 free-form metadata 是 persisted-only，不进 AMQP header / MQTT
user property。业务写入口 `EnvelopeMetadata::try_insert` 对所有 reserved key fail-closed；adapter 只在
outbox relay/subscriber rehydrate 的受控路径调用 `insert_wire_pair`。

## Outbox 写入模式

PostgreSQL adapter 有两条显式 outbox 写入模式，二者不可 fallback / 双写兼容：

### L2 producer-fact domain closure

`kind=http && consistencyLevel=OutboxFact && capabilities.outbox.role=producer` 的每个 `emits`
必须引用存在的 `kind=event && consistencyLevel=OutboxFact` fact，且 fact `domain` 必须与 producer
`domain` 完全相等。该 authoring 约束覆盖 `draft`、`active`、`deprecated` 全 lifecycle：draft/deprecated
只是不进入 active runtime，不是跨域 emits 的兼容豁免。跨域流程必须在各域分别声明本域 producer/fact，
再由订阅和 workflow 组合，不允许 HTTP producer 直接把其他域 fact 伪装成本域事务输出。

active producer 在同域约束之上另加 runtime readiness：目标 fact 也必须 active 且至少声明一个
`[[subscriptions]]`。`cargo xtask contract validate` R22 对全 lifecycle 同域约束和 active-only readiness
分别 fail-closed；契约字段摘要只引用本节，不维护另一套例外规则。

### Outbox relay 投递语义（at-least-once）

Outbox relay transport 是 **at-least-once**：durable fact 使用稳定 event/message ID 发布；publish 成功、settle 前崩溃允许 broker duplicate，broker confirm 的 ambiguous outcome 也必须按可能已发布处理并重试，不能换 ID 或假定消息尚未到达。

`PublisherError` 的处置是闭合三态：`Permanent` 首投进入 DLX；`Transient` 与 `Ambiguous` 都在原
delivery deadline 内以原 event ID 重试。`Ambiguous` 专指 broker 可能已经接收但客户端无法确认的结果，
包括 AMQP `basic_publish` 已开始后的 connection/channel/confirm 丢失，以及 publish/confirm deadline；它
不是 exactly-once 证明。AMQP publisher 对这类结果必须退休整个 generation（专用 connection + confirm
channel），禁止在潜在已接收的旧 transport 上继续 admission；replacement 由 RSS 在一个绝对 recovery
deadline 内依次 drain、关闭旧 connection、重连并创建 fresh confirm channel。Lapin auto-recovery 不参与，
避免形成不可由 RSS deadline 取消的第二条恢复路径。

每个 outbox provider 在构造期绑定唯一 typed `DomainName`；relay 只能经 `claim_domain()` 观察该归属，
`claim_batch(limit)` 不接收调用方传入的 raw domain，`RelayConfig` 也不另存一份可与 publisher 错插的 domain。
`claim_batch` 在同一数据库语句内选取、铸造 token/deadline 并持久化。Postgres provider
只经 `PgOutbox::claim_batch` 铸造 provider-owned opaque `PgClaimedOutboxEntry`；调用方只能将它
按值交给同一 `PgOutbox` 的 relay 路径，无法构造、hydrate 或读取 provider-private 的
lease/durable context。`consistency::OutboxRelay::Claim` 只是 provider 关联类型接缝，不定义可
hydrate 的通用 claim 实体。settle CAS 同时匹配 token 与精确 deadline，且拒绝已过期
租约。这只围栏当前 lease holder 与 stale writer 的状态写回，不提供 broker
exactly-once，也不能撤销已经成功的 publish。duplicate 由 tenant-scoped `Inbox` / `ConsumerTx` 收口重复数据库副作用：
业务写、outgoing outbox 与 receipt done 在同一事务
提交，提交成功后才 broker Ack。

`RelayConfig::max_in_flight` 同时限制单轮 claim 数与 publish 并发数，构造期只接受 `1..=64`。claim
返回后同批 entry 立即并发 dispatch，不得整批串行等待；SQL head-of-partition gate 保证同批对每个非空
`(tenant_id, domain, partition_key)` 至多返回唯一队头，故不同 partition 与无序 entry 可并行而不破坏
分区内顺序。每条 broker publish 前，Postgres provider 必须以 DB 当前时间做 lease budget preflight：只有
当前 token/deadline 仍匹配且剩余租约严格大于 `publish + settle + safety` 才调用 broker。四项预算经
`RelayBudget` 单一 typed funnel 构造，默认 `lease=60s / publish=40s / settle=5s / safety=5s`；AMQP 的
`basic_publish` 与 confirm 共用同一个 publish deadline，Postgres 通用 publisher watchdog 为
`publish + safety`，所有 settle 完整操作受 settle deadline 约束。preflight 不足不得发 broker 请求，
timeout/confirm/settle 不确定结果仍按 at-least-once 语义以稳定身份重试，不能把本地超时解释为 broker
未收到。每个预算分量统一以 `86_400_000ms`（24h，含边界）为 operational ceiling；Rust typed funnel、
AMQP 二次构造校验与 claim/preflight SQL 入口都拒绝 `86_400_001ms`。预算 env 一旦存在但非法，runtime
启动失败，不回退默认值。

### 有界 same-ID 投递窗口

ref: Spring Modulith spring-modulith-events/spring-modulith-events-jdbc/src/main/java/org/springframework/modulith/events/jdbc/JdbcEventPublicationRepositoryV2.java@c75f173e5201208d8129b4cd8c112defb1158c67

Spring Modulith 的 JDBC publication repository 用同一 publication id 做完成与重新提交的原子状态转换；RSS
沿用稳定 id + 数据库原子状态转换，但明确偏离其时间语义：上游只有最小重提交 age，没有 maximum same-ID
horizon。RSS 由数据库 singleton `event_delivery_policy(policy_revision='same-id-delivery-v1')` 冻结本 release 的
自动重试 24h、operator redrive 24h、安全余量 24h 与 inbox receipt 7d，并由 CHECK 强制
`7d > 24h + 24h + 24h`，并对每个 interval 设置 10 年硬上界，阻止 interval/timestamp 溢出。runtime 启动时读取且只接受这一组精确值；revision、行数或值漂移均 fail-closed。
这些是正确性策略，不提供环境变量或调用方 override。

outbox 行的 `same_id_delivery_phase` 闭合于 `automatic|redrive`，并持久化两个绝对 deadline。首次 claim 只在
`automatic_retry_deadline` 为空时冻结为 claim 时刻 + 24h；首次进入 DLX 只在
`same_id_redrive_deadline` 为空时冻结，并同时受 automatic deadline + 24h 与 DLX settled-at + 24h 的较早者
约束。operator redrive 只切 phase 为 `redrive`、恢复 pending 并清 retry/lease/terminal 时间，不延长或重算
任一 deadline。

每次 broker publish 前，数据库 preflight 除 lease budget 外还检查当前 phase 的绝对 deadline。deadline 已到
时不调用 broker，relay 将同一行 settle 到 DLX，写安全失败摘要，并发射
`outbox_same_id_window_expired_total{domain,contract_id,tenant_id,phase}`；`phase` 仅为
`automatic|redrive`。operator 对已过 redrive deadline 的操作返回 typed `Expired`，不修改 outbox 行，
`dlq_redrive_total{kind="outbox_dlx_redrive",outcome="expired"}` 与 `dlq.maintenance` finish failure audit
共同留证。过期行不能再做 same-ID publish；它保持 DLX 并继续阻塞 partition，直到经唯一
`resolve-expired-outbox` terminal funnel 结清。该 funnel 只允许已过期的当前 tenant DLX，闭合策略为：

- `accepted_gap`：必须不携带 evidence event；
- `compensated`：必须引用同 tenant、已 `published`、且 `causation_id` 等于被阻塞 event ID 的 outbox evidence。

成功时原行进入显式 terminal `abandoned`并写 `abandoned_at`，使 partition successor 可继续 claim；
`outbox_expired_resolutions` 以 tenant、blocked event、resolution kind、change ticket、已验证 operator subject、
可选 evidence event 和 DB 时间形成 append-only durable evidence。change ticket/operator subject 在 typed API 与 DB
同时拒绝空值、首尾空白、控制字符和超长值。serving `rss_app` 对 resolution 表和函数均无权；
只有 NOLOGIN maintenance owner 持有精确函数权限。

稳定 event ID 是幂等锚，不是 exactly-once 保证。MDM 变更、设备命令、外部 API 等事务外副作用仍须透传稳定 idempotency key，或由 reconcile 闭环收敛；不得因 relay CAS 或 Inbox receipt 省略外部系统自己的幂等边界。

**事实同一性（OUTBOX-FACT-FUNNEL-01）**：mutable 与 CDC 模式共用
`rss-outbox-fact-v1` canonical identity。首次写入返回 `Inserted`；同 `event_id` 且稳定事实
完全相同返回 `SameFact`；任一稳定字段不同返回 typed `FactConflict`并在 commit
前退出。identity 包含 event/tenant/domain/topic/contract/schema/payload/partition/causation
与 persisted stable metadata；仅 `occurredAt` / `trace` / `correlation` 是可重试漂移的观测
字段而被排除。status/retry/lease/seq/行时间不属于事实。fingerprint 由类型化
identity 产生，DB 以 stored generated column 重算；任一边界不得记录 fingerprint 或原
材料。

- **relay mode**：默认 `PgInfraDeps::emitter(clock)` 与各域 `PgDomainDeps::*::outbox(...)` 写 mutable
  `outbox` 状态表。`PgOutbox` relay / backlog / sweeper / DLX redrive 只读取 `outbox` 与 `rss_outbox_*`
  SECURITY DEFINER 函数，不读取 `outbox_log`。
- **CDC mode**：显式 opt-in `PgInfraDeps::cdc_emitter(clock)` 写 `outbox_log` append-only ledger。该表面向
  logical decoding / CDC adapter，字段包含 `event_id`、`aggregate_type`、`aggregate_id`、contract
  id/version、`schema_hash`、`payload bytea`、`metadata jsonb`、`tenant_id`、`causation_id`，以及从
  `metadata` 派生的 generated columns `occurred_at`、`trace`、`correlation_id`。`aggregate_id`
  取 envelope `subject_id`；`partition_key` 只保留 relay 排序语义，不暴露到 CDC aggregate id。Debezium
  connector skeleton 由 `cargo xtask cdc-config debezium` 输出，操作步骤见
  `docs/runbooks/202607081921-1633-cdc-outbox.md`。

`outbox_log` 是 tenant-scoped append-only 表：迁移必须同时落 `ENABLE/FORCE RLS`、标准 `rss.tenant_id`
policy、`rss_app` 最小 `SELECT/INSERT` 授权与 `UPDATE/DELETE` revoke。tenant、contract version 与
schema hash 只来自 typed `TenantId` + generated `ContractBinding` 写入列和 metadata，不能从 payload 或
free-form metadata 反推。
CDC metadata projection 列必须是 DB generated columns，从 sealed `metadata` 单源派生；应用写路径不得额外赋值
`occurred_at`、`trace` 或 `correlation_id`。当前 Debezium EventRouter skeleton 只把强制非空的 `occurred_at`
发布为 broker header；nullable trace/correlation 保持 persisted-only，直到引入 reviewed null-stripping
SMT/等价机制。CDC deployment 使用 `pgoutput` 时要求 PostgreSQL 18+，并且 publication 必须设置
`publish_generated_columns = stored`；低于 PostgreSQL 18 的实例不得启用该 CDC skeleton。
`subjectId`、`actor`、`principal`、`causation_id`、
`aggregate_id`、`contract_id` 与业务 free-form metadata 保持 persisted-only，除非后续 reviewed 设计明确改变。

## 复用层选型（claimer / nonce，topology-gated）

组合根的 outbox 消费幂等 claimer + 内部 listener service-token nonce store 同样经
`bootstrap::replaydeps::resolve(ctx, clk, topo)` 按 `Topology` 单源选型：demo/single-pod → in-memory；
real multi-pod → Redis-backed（client 作 ManagedResource），缺 Redis 配置启动期 fail-closed。两个
组合根（`bins/server` + `examples/ssobff`）复用同一 crate，不各自接线 in-memory 原语。`idempotency::InMemClaimer::new`
/ `authn::InMemoryNonceStore::new` 在这两个 root 内**仅** `bootstrap::replaydeps::resolve` 的 demo 分支可达——用
sealed resolver + `pub(crate)` 构造器从类型层封闭（Hard，编译期不可达）。bus / claimer / nonce 三 funnel 合起来确保组合根内每个 in-memory
单 pod 原语只经 sealed resolver 可达。权威语义见 `bootstrap::replaydeps` 模块的 rustdoc。

## saga 实例资源选型（instance / journal / checkpoint / dead-letter / runtime lock，topology-gated）

L3 saga runtime 的 primitive API 是 direct `run` / `resume` / `status`；生产运行形态可把同一
executor 封装为 background `saga_executor:<owner>__<contract_slug>` worker，由 tenant candidate source +
tenant-scoped runnable listing 驱动。组合根注入的最小资源集合是 tenant-scoped `SagaInstanceStore` +
tenant-scoped append-only `SagaJournal` + `OwnerCheckpointStore` + `DeadLetterStore` + runtime lock provider：

- demo/memory → paired `MemSagaInstanceStore` / `MemSagaJournal`（共享 lease state）+
  `MemCheckpointStore` + `MemDeadLetterStore` + `MemLockStore`。
- postgres → `PgSagaInstanceStore` / `PgSagaJournal`，两者按操作只经 `PgTenantReadPool` / `PgTenantWritePool` 访问 tenant 表；
  `saga_instances` 承载 register/claim/extend/release/status CAS，`saga_journal` 承载 durable append-only
  step facts；runtime lock provider 必须来自 Redis，作为 `run` / `resume` 进入 Postgres lease 前的 multi-pod
  外层 gate。
- worker tenant discovery → `SagaTenantSource` 只返回候选 tenant id；真实 runnable instance 列表仍回到
  tenant-scoped `SagaInstanceStore::list_runnable`，且 `run` / `resume` 仍需 runtime lock + instance lease CAS。
- fail-closed：tenant scope 缺失、lease token/epoch/expiry 不匹配、或 `(tenant_id, saga_id, seq)` 内容冲突，
  必须返回 typed interrupted outcome，不触发补偿或 app DLX。
- runtime lock fail-closed：durable 拓扑缺 Redis URL 启动期 fail-closed；执行时 lock busy / lost /
  unavailable 必须返回 typed interrupted outcome，不注册新 instance、不触发补偿或 app DLX。Redis lock 不是最终
  fencing，Postgres instance lease + journal CAS 仍是最终写入围栏。

`saga_instances` 与 `saga_journal` 均为 tenant 表：迁移必须同时落 `ENABLE/FORCE RLS`、标准
`rss.tenant_id` policy 和 serving role 最小权限；`saga_journal` 仅 `SELECT/INSERT`，撤销 `UPDATE/DELETE`。
跨租户 worker discovery 只允许通过窄 `saga_worker_tenant_index` + fixed `SECURITY DEFINER` function 返回
tenant id；`rss_app` 不得直接读该 index。
checkpoint 表不改 schema，saga checkpoint id 必须包含 tenant，避免跨租户同 saga UUID 碰撞。

## ConsumerBase

所有 consumer 使用 `ConsumerBase` 的 preflight / claim / lease / broker-settle 语义。非 durable helper
可由 handler 返回 `outbox::HandleResult` 后再由 ConsumerBase commit receipt；**durable PG runtime 必须使用
ConsumerTx**：Fresh claim 后在同一 tenant-scoped PG transaction 内完成业务写、outgoing outbox append
（当前订阅无 outgoing 时允许空 append 集）和 `inbox_receipts` mark processed，commit 成功后才 broker Ack。
旧 non-tx ackable spawn 不是 durable runtime 受支持路径。

```rust
async fn handle(ctx: &Context, message: diport::Message) -> consistency::HandleResult {
    if permanent {
        // reject 接 PermanentError（kind: Permanent | Invariant，排除 Transient）
        return consistency::HandleResult::reject(consistency::PermanentError::new(perm_kind));
    }
    if transient {
        // requeue 接 EngineError（不同类型；kind message 进 error_summary 落 DLX）
        let engine_err: consistency::error::EngineError = /* 瞬态因由 */;
        return consistency::HandleResult::requeue(engine_err);
    }
    consistency::HandleResult::ack()
}
```

`HandleResult` 不用裸构造（无公开字段构造路径）；业务代码使用 `ack`、`requeue`、`reject`
构造器，不手写 struct literal。`reject`/`requeue` 携带的 error kind 经 `HandleResult::error_summary()`
（`&'static str` const，PII-safe）随结果流到 ConsumerBase 的 DLX funnel 落日志（#1125），不再在 HandleResult
边界静默丢弃；更丰富的 per-delivery 扩展信息仍走 `DeliveryOutcome`，不污染业务结果。

### Durable ConsumerTx

durable PG consumer 的 Fresh 成功路径固定为：

`verify envelope + tenantAuthority -> try_claim -> lease renewal race -> ConsumerTx handler -> PG commit -> broker Ack`。

ConsumerTx handler 由 postgres adapter 构造，runtime 只按 generated subscription 选择 handler；外部 crate
无法构造或逃逸 `TxCapability`。handler 在同一事务内先做业务写 / outbox append，再用同一个
`TxCapability` 执行 inbox `done` CAS；`LeaseOutcome::Lost`、SQL/commit unknown、handler transient failure
均不得 broker Ack。Duplicate delivery 不进入 tx handler，直接 Ack。
ConsumerTx outcome 使用 typed constructor 收口：`handler_transient` 可在当前投递内 bounded retry，但耗尽后仍只
broker `Requeue`，不写 app DLX、不提交 inbox `done`、不 `Ack`；`commit_unknown` / `LeaseLost` 立即 broker
`Requeue`；只有永久 `Reject` 可写 app DLX、提交 inbox `done` 后 broker `Ack`。

durable runtime 对 generated subscription fail closed：每条订阅在 `contract.toml` 声明 identity
（contract/topic/consumer/group）、闭枚举 `execution = "adapter-native" | "domain-effect"` 与逐订阅
`externalEffectPolicy = "transactional-only" | "idempotency-key" | "reconcile" | "compensated"`，再由 codegen 派生为
`SubscriptionSpec`，并从 `(contract id, version, consumer)` 同源生成闭枚举 `SubscriptionDispatchKey`。
runtime 必须对该 dispatch key 穷尽匹配并只绑定 `ConsumerTx` plan；新增订阅而未接线时编译失败，guard
只守穷尽 match 的结构，不维护订阅实例清单。`adapter-native` 禁止声明 `effect`；`domain-effect`
必须声明当前唯一闭值 `effect = "settings-config-version-refresh"`，仅用于必须捕获域内 singleton 的
settings cache refresh，并由 generated topology 的穷举 resolver 限制在 `settings.config-version-changed`。
当前完整语义矩阵只接受 `adapter-native + 无 effect + transactional-only`，或
`domain-effect + settings-config-version-refresh + reconcile`：四个 audit handler 的业务写与 Inbox Done
同属 ConsumerTx，settings refresh 则从持久化权威状态重建进程内 cache，允许重复并收敛。其它 policy 已冻结为
可扩展闭值，但必须与新增 effect/capability evidence 同步扩展矩阵后才可激活；不得用 `idempotency-key`
冒充未实现的稳定 key，也不得用 `compensated` 冒充未落地的补偿闭环。
新增订阅、execution/effect/policy 缺失或配对非法、声明与 generated marker 漂移时，解析或测试失败；
不得增加 wildcard、默认分支、通用 handler registry、平行映射清单或 fallback。payload decode / wire DTO 归属域 crate（域可依赖
`generated`），postgres adapter 只保留 PG transaction / TxCapability 职责，避免 adapter 维护第二套 event schema。

active L2 manifest 的 topic、delivery、consistency level、outbox role/atomicity/emits 以及 subscription
集合、consumer/group、topology、execution/effect/externalEffectPolicy 都是 wire 语义，受 `cargo xtask contract breaking`
跨版本门保护。`emits` 与 subscription 集合的排序不是语义，但元素任何增、删、替换都是
breaking；active 默认 deny（跨 LocalOnly 边界的 consistency review rule 固定 warn，但须精确
`Contract-Review-Ack` trailer）、deprecated warn、draft 跳过。
这里的 lifecycle 分级仅定义 breaking review 处置，不削弱 R22 的全 lifecycle producer/fact 同域约束。

`settings.config-version-changed` 的 `DomainEffect` 捕获 HTTP routes 使用的同一 `SettingsService`；成功路径必须
先刷新该 singleton cache，再由 ConsumerTx 提交 inbox `done`。refresh transient 不提交 inbox、走 `Requeue`，
permanent payload 错误走 `Reject`。否则 inbox done 后的重复投递会被 Duplicate 直接 Ack，无法修复 stale cache。

### 租约续租 + leaseLost hard-fence（#1213）

claim 是**带 TTL 的租约**：`InboxStore::try_claim(key, lease)` 由消费方经 `LeaseToken::mint()` 铸 uuid v4 token 传入，
claimed 行 stamp 该 token；**过期未续租**的 claim 可被新 token 重捞（修 crash-after-claim 时 key 永久
`Duplicate` 的丢消息——硬崩溃下 `release` 走不到）。长 handler 由 ConsumerBase 后台按 **`lease_ttl/3`**
（`LeaseConfig::from_ttl`，组合根由后端 claim TTL 派生注入）周期调 `extend(key, lease)` 续租，与 handler 执行
**同任务并发 race**（消费驱动 future `!Send`、跑专用线程，**不** `tokio::spawn`）。续租 `LeaseOutcome::Lost`
（claim 已被他人重捞）即 **cancel handler 执行上下文 + 终态降级 `Requeue`、不 commit**（**leaseLost hard-fence**，
对标 gocell ConsumerBase runWithRenewal）。`commit(key, lease)` 自身 CAS 守租约：返 `Lost` 同样立即
broker `Requeue`，不得进入当前 claim 的 handler 重试预算，也不得写 app DLX（覆盖「续租未及时探测、commit
时租约已失」的竞态窗口）。token CAS 是唯一正确围栏——时间窗口判定有 TOCTOU 竞态。

**并发安全要求**：在 claim TTL 到期与原消费者续租循环探测到 `Lost` 之间（窗口 ≤ `lease_ttl/3`），
同一消息可被第二个消费者重捞并启动 handler，形成并发双执行窗口。commit-side CAS 保证幂等键
`done` 标记仅写一次，但 handler 内**事务外的外部副作用**（邮件、外部 API 调用、DB 事务外的
余额变更等）在该窗口内可能各执行一次。因此，handler 内所有外部副作用须设计为**幂等且允许并发
重入**；不满足此要求的副作用在 TTL 窗口内存在双重执行风险，commit-side CAS 不提供此保证。

## Disposition

| Disposition | 语义 | 行为 |
|-------------|------|------|
| Ack | 成功 | broker ack + receipt commit |
| Requeue | 瞬态失败 | 退避重试，预算耗尽后 reject |
| Reject | 永久失败 | broker nack/reject，进入 DLX |

`PermanentError` 只是错误分类，不自动把 Requeue 改成 Reject。

## 投递顺序保证（seq + partition_key，#1211）

outbox 行带 `seq BIGINT GENERATED ALWAYS AS IDENTITY`（表级单调序，应用不可写/伪造、隐式 NOT NULL、允许
gap）+ 可空 `partition_key`，投递顺序按 `partition_key` 二分：

- **`partition_key IS NULL`（默认）= 无序并行**：不同 entry 投递顺序无保证，跨 worker 并行。消费方须幂等、
  不依赖跨 entry 顺序（靠 inbox 去重 + 实体状态收敛）。emit 默认 `None`，行为同分区前。
- **`partition_key` 设置 = 同 `(tenant_id, domain, partition_key)` 串行有序**：outbox 行持久化
  `tenant_id` 并启用 RLS；relay 经 provider-bound `claim_batch(limit)` 的
  **head-of-partition gating**——同 partition 仅放行 `min(seq)` 且尚未 `published` 的队头行（`NOT EXISTS`
  更早未结清 sibling），即使多 worker + `SKIP LOCKED` 也**永不乱序、至多一条 in-flight**；因此一个 claim
  batch 内每个非空 partition 至多一个唯一队头，可与其它 partition 的队头即时并发 publish。`partition_key` 是
  不透明聚合根路由键（= Debezium `aggregateid`），经 write 路径 `diport::OutboxEnvelopeParts::with_partition_key`
  → adapter 落库，不进 `consistency::StoredOutboxEntry`（relay 读侧无需透传，顺序由 SQL gating 承载）。
  tenant 是 outbox envelope 的必填 typed 输入，adapter 将其落为列；同一 business key 在不同 tenant 下不共享
  head-of-partition gate。

**dlx fail-closed**：队头进 dlx（永久错误 / 预算耗尽 / same-ID deadline 到期）会**阻塞**该 partition，且只在
redrive deadline 尚未到期时允许运维 re-drive（`eventexec::DlqRedriveRequest` → 当前 tenant scope 内
`outbox.status='pending', same_id_delivery_phase='redrive', retry_count=0, retry_after=NULL, lease_token=NULL, lease_until=NULL, published_at=NULL, dlx_at=NULL`；两个绝对 deadline 原值保留）
——这是与「串行有序」一致的唯一选择（放行未结清后继破坏 in-order 不变式）。deadline 过期后只能经上述
terminal resolution 把队头结清为 `abandoned`；claim blocker 只把 `published|abandoned` 视为 resolved。`outbox.status='dlx'` 仍是 relay
状态与 partition ordering gate；统一 DLQ 审计行写入 `dead_letter(source_kind='outbox_relay')`，不搬迁/删除
原 outbox 行；expired redrive 不修改行也不解除 partition gate，成功 redrive 清除 `dlx_at` 后，既往 DLX 历史
继续由 `dead_letter` hot row 留存，随后经 verified WORM archive-before-purge lifecycle 转入冷归档。代价有界且可观测：
dlx `error!` 日志 + hot/archive backlog 指标 +
backlog `oldest_age` 增长 + same-ID expiry counter。
**已知前提**：队头判据假设同 partition 行按 seq 序提交，成立于同 partition 写入由
聚合根并发控制串行化（partition = aggregate 标准契约）。**backlog 例外**：head-of-partition gate 是 claim-only，
被 gate 的后继仍计入 backlog depth（否则 stalled partition 对 SLO 失明）。INVARIANT: OUTBOX-PARTITION-ORDER-01。

> 机制本 PR 交付；哪些域事件 opt-in `partition_key` 仍是应用层决策，但决策必须前移到
> `contract.toml` 的 `[subscriptions.topology] partitionKey` 声明面。`partitionKey = "aggregate"` 表示 producer
> 须提供 tenant-scoped aggregate key；`partitionKey = "none"` 表示无序并行。generated topology registry 到 runtime
> consumer bundle/readiness 的桥接由 #1442/#1434 负责，不在本规则段实现。

## Acker / 投递结算 seam（at-least-once）

`Disposition` 表的「broker ack / nack」由 **ack seam** 落地（#1142）。纯逻辑驱动 `eventexec::run_consumer`
（消费 `diport::MessageStream`）只做幂等 + DLX bookkeeping、**不触达 broker**——配 in-mem bus / auto-ack 传输
即 at-most-once。要 **at-least-once**，consumer 走 ackable 变体：

- provider 实现 `diport::AckableSubscriber`（`subscribe_ackable` → `DeliveryStream`；AMQP `no_ack=false` +
  `basic_qos` prefetch 限 channel 上 unacked 上限），每条 `Delivery { message, acker }` 携一个 `diport::Acker`
  结算句柄。`Acker` 是**独立 seam**（`Delivery` 并置），**不挂** `Message`（冻结值类型）——即 §ConsumerBase
  所述 `DeliveryOutcome` 规约的落地（ADR-003 Amendment #1142）。
- `eventexec::run_consumer_ackable` 消费 `DeliveryStream`，每条消息**终态恰一次**调 `acker.settle(AckAction)`。
  `AckAction { Ack, Requeue, Reject }` 是 provider-agnostic broker 词汇（adapter 翻成 AMQP
  `basic_ack` / `basic_nack(requeue=true)` / `basic_nack(requeue=false)`，后者路由 broker 端 DLX/丢弃）。

终态 → `AckAction` 映射（引擎动作不变，settle 叠加）：

| 终态 | 引擎动作 | settle |
|------|---------|--------|
| handler `Ack` | commit key | `Ack` |
| `Reject` / `Requeue` 耗尽 → DLX 写成功 | commit key | `Ack`（引擎自持 DLX，broker 移除） |
| DLX 写失败 + release 成功 | release key | `Requeue`（broker 重投重试 DLX，防静默丢失） |
| DLX 写失败 + release 失败 | release 失败，发 `consumer_release_failed_total{domain}` | `Reject`（避免 claim TTL 窗口内重投被 Duplicate→Ack 吞掉） |
| 幂等 `try_claim` 瞬态 Err（`Transient`） | 不 commit | `Requeue`（退避重投） |
| 幂等 `try_claim` 永久 Err（`Permanent`/`Invariant`，如鉴权/协议配置错） | 不 commit | `Reject`（→DLX，不无限重投，#1354） |
| 租约丢失（续租或 commit CAS 返 `LeaseOutcome::Lost`，#1213） | cancel handler / 不 commit（hard-fence） | `Requeue`（claim 已被他人重捞，不双写 done） |
| `Duplicate` | 跳过（不调 handler/不 commit） | `Ack`（已处理，移除） |
| `IdemKey` parse 失败（malformed） | 不 commit（无法去重） | `Reject`（→broker DLX 留证，不无限重投） |
| 未知 `SeenState` | 不 commit/release（保守） | `Requeue` |

崩溃安全：消费者在 settle 前崩溃 / channel 关闭 → broker 自动 requeue 未 ack 投递（RabbitMQ channel close
语义）→ 重投经 idempotency `try_claim` 去重，达成 at-least-once。

**双端口拆分**：`Subscriber`+`MessageStream`（at-most-once：in-mem / MQTT QoS auto-ack / `run_dispatch`）与
`AckableSubscriber`+`DeliveryStream`（at-least-once：AMQP / `run_consumer_ackable`）按投递保证并存。MQTT
manual-ack（broker-native DLX 之外的 MQTT 特殊语义）见 #1265；consumer worker 生命周期 spawn（managed worker +
两阶段关闭 + probe）见 #1142 派生 follow-up。

## Service required deps

service 必填依赖走构造器**必填参数**（非 `Option`）——缺失即编译错误。可选依赖在构造器内或 builder 给默认值，
累加式 builder 在 `build()` 末尾 validate。

## 订阅注册

订阅单源是域 crate 的 `Cargo.toml [dependencies]`（+ `contract.toml` 订阅声明）。codegen
（build.rs / proc-macro）从 metadata 派生注册代码；业务不手写平行 registry。订阅必须同时绑定
`ContractId`、`DomainId`、consumer group。

webhook、grpc serve、event subscribe 遵循同一范式：声明在 metadata，派生到
`generated`（`generated/`），运行时 registration 只消费派生结果。

event consumer 运行时接线分两段：

- 域 crate 的 `Domain::init` 只从 per-contract generated `SPEC.subscriptions()` 读取声明并注册 handler。
- 组合根必须把 drained runtime bindings 交给 `runtime::event_transport::bridge_generated_subscriptions`
  桥接为 `BridgedSubscription`，再传给 consumer bundle；bridge 内部固定消费
  `generated::event::EVENTS` 根级 registry，不接受调用方传入平行 spec。bridge 必须双向校验
  generated spec 与 runtime binding 一对一精确匹配，任一侧缺项、重复消费或 group drift 都 fail-fast；
  `wire_event_transport` 不接受 raw `SubscriberBinding`。

`BridgedSubscription` 字段私有，topic / consumer group / consumer / readiness 等只能来自 generated
topology spec。生产代码不得在 sanctioned bridge/bundle 外直接调用 `spawn_consumer_ackable*`、
`spawn_consumer` / `pg.infra().inbox(...)`，durable runtime 还必须经 `spawn_consumer_ackable_tx_subscriber`
和 `consumer_tx_handler_for_subscription` 接线；`EVENT-TRANSPORT-PG-INBOX-01` 由 `cargo xtask verify` 中的
`event-transport-guard` 作 Medium 扫描补强。主路径 bridge-only 构造是类型/API 层约束；旁路扫描不声称 Hard。

## DLX 与幂等

- 永久错误进入 DLX。统一 hot 表为 `dead_letter`，`source_kind` 闭值集只有 `consumer` / `outbox_relay` /
  `saga` / `projection`。payload 与全部 persisted delivery metadata 必须一次封装为 `key-provider-v3` replay capsule；
  `tenantAuthority` 只在入站验证期存在，永不落入 capsule。tenant、来源、producer/consumer provenance、安全摘要与
  payload 长度保留为独立可查询安全列。`consumer` 来源必须记录 subscription `consumer_group`；`projection`
  来源必须记录 projection id。不存在旧 decoder、明文 shape、双写或 fallback；0062 migration 发现任何既有
  `dead_letter` 行直接 fail-fast。
- DLX lifecycle 固定为 `HOT → WORM 对象语义/校验和已验证 → VerifiedArchiveReceipt → bounded purge → COLD`。
  archive canonical envelope 使用独立 `RSS_DLX_ARCHIVE_KEY_NAME` 加密并写入独立 S3 bucket；该 bucket 必须启用
  versioning、默认 Object Lock `COMPLIANCE` 且默认留存严格长于 hot 的精确 30 天。provider 只有
  conditional put/get/head/verify，没有 delete/list；普通 DLQ API 不读取、检查或 replay cold archive。
  `AlreadyExists` 只能在解密既有对象并与 canonical record 语义相等后补 receipt，否则 Invariant fail-closed。
  S3 lifecycle 最终删除到期冷对象；RSS 只在 verified HEAD-missing 生成 `MissingArchiveProof` 后回收 receipt。
  `DlxLifecycleRepository` / `DlxArchiveStore` 是 `diport` 的两个 provider-neutral 静态 Send port；eventexec 以
  associated-type equality 绑定 sealed receipt/proof 与 typed object key。不存在第三个 archive cipher port：
  eventexec 私有 DLX crypto service 直接消费既有 `diport::KeyProvider`，不得增加 dyn wrapper、fallback 或 shim。
- durable runtime 必须配置 `RSS_DLX_PAYLOAD_KEY_NAME` 以及 Vault transit provider
  `RSS_VAULT_ADDR` / `RSS_VAULT_TRANSIT_MOUNT`，并分别提供 `RSS_DLX_HOT_VAULT_TOKEN` /
  `RSS_DLX_ARCHIVE_VAULT_TOKEN`；两枚 workload token 必须不同，archive token 不回退或复用通用
  `RSS_VAULT_TOKEN`。broker tenant authority 另必填
  `RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL`，可选 `RSS_TENANT_AUTHORITY_TTL_SECS`（默认 3600）和
  `RSS_TENANT_AUTHORITY_CLOCK_SKEW_SECS`（默认 60，上限 300）。`rss dlq replay-dead-letter`
  需要同一 DLX payload key provider；`list` / `inspect` / `redrive-outbox` / `resolve-expired-outbox` 是 payload-free 路径，不因
	  Vault/key provider 不可用而阻断。DLX list API 只返回 payload 长度与摘要元数据，
  不返回 payload 内容；返回 `DlqListResult { data, has_more, next_cursor }`，`next_cursor` 是
  `(last_attempt_epoch_secs DESC, kind, id)` keyset cursor，调用方必须用它稳定续页，不能用 offset 或假设一次
  `Vec` 即完整队列。
- Runtime 提供 tenant-scoped operator CLI：`rss dlq list` / `inspect` / `replay-dead-letter` /
  `redrive-outbox` 与 `resolve-expired-outbox`。所有命令必须带 `--operator-service-token`、`--operator-tenant`、`--tenant`；授权由
  service token PDP 验证（`jti` 经 Postgres 持久 replay guard 原子记录，跨 CLI 进程防重放）+
  `RSS_DLQ_OPERATOR_GRANTS=subject|action|tenant` 精确 grant 共同决定。`list` 支持 `--source` / `--domain` /
  `--contract-id` / `--cursor` 精确收窄，filter 集合覆盖 `OutboxPartitionBlocked{tenant_id,domain,contract_id}`
  告警标签。审计 kind 固定为
  `dlq.maintenance`，action 固定为 `dlq.<action>.start|finish`。v1 不提供 destructive `skip` 或旧命令别名；
  partition unblock 定义为 deadline 内 redrive outbox DLX 队头后让 relay 正常发布。CLI 经离线
  `PgRuntimeDeps::setup_maintenance` 使用 migrator/maintenance 连接；长期 serving role `rss_app` 被显式撤销
  `rss_outbox_redrive(text,uuid)` 或 `rss_outbox_resolve_expired(text,uuid,text,text,text,text)` EXECUTE，不能取得 mutation 权限。
- Consumer hot `dead_letter` replay 必须传 `OperatorDlqCapability`、typed `DeadLetterId` 与调用方提供的新
  `IdemKey`，由 hot `KeyProvider` 解密 v3 capsule 后插入一条新的 outbox 行；operator 路径不得删除原
  `dead_letter`，不得重置 `inbox_receipts done`，不得直接 broker replay。replay 从同一 v3 capsule 恢复 schema header
  并写入 outbox `contract_version` / `schema_hash` 物理列；缺失或非法 fail-closed。Outbox relay DLX redrive 同样必须传
  `OperatorDlqCapability`；deadline 内只恢复原 outbox 行为 `pending`、切换到 `redrive` phase 并保留两个绝对
  deadline，已过期则返回 typed `Expired` 且不 mutation。outbox DLX payload 副本保留在 `dead_letter`
  用于审计，不参与 redrive。Saga 与 projection `dead_letter` 只作审计与诊断，不支持 replay 成 outbox；
  projection poison `message_id` 固定为 `projection:<owner>:<projection_id>:<lsn>`，重复写入必须幂等。
  Projection read-model shadow replay 不从 DLQ 恢复，必须走 `rss projections replay`，输入源是
  `projection_events` 的 generated projection input binding 镜像。
	  `OperatorDlqCapability::issue_for_authorized_operator()`
	  只能在 admin/PDP 边界签发；runtime CLI 用精确 `issue_authorized_dlq_capability` wrapper，调用点由 dylint
	  `rss_dlq_operator_callsite` 守。不存在 plaintext fallback decoder；
  replay decrypt 只把 `KeyProviderErrorKind::Rejected` 映射成坏 payload，`Unavailable/Timeout` 与
  `Forbidden/NotFound` 保留为 operator 可区分的依赖/配置错误。
- PG outbox relay claim 原子写入 token + `lease_until`，settle 以二者和 DB 当前时间做严格 CAS；consumer inbox claim 同样写入 fencing token。inbox lease 带 TTL，过期可重捞（crash-recovery），长 handler 经 `extend` 续租（#1213）。outbox 不在本轮引入续租，batch 尾部超时时由新 claim 重投并依赖 inbox 幂等收口。
- crash-after-claim 后消息最多延迟 `INBOX_LEASE_TTL_SECONDS`（当前 60s）才被 TTL 重捞重跑（此前是永久静默丢失）；该上界当前不可按消费者配置，低延迟工作流需关注。
- handler 不接触 lease；ConsumerBase 后台续租 + 终态 CAS 透传，relay / subscriber write-back 同理（handler 只返 `HandleResult`）。
- consumer group 命名必须稳定，避免重放时变成新消费者。

## Command dispatch

命令 dispatch 通过 generated typed API 和 Claimer 两阶段去重。producer 侧 key、
consumer 侧 claim、组合根 wiring 必须同源；不得新增裸字符串 dispatch。

producer 与 consumer **双侧**都收口到 codegen typed API。command manifest 必须显式声明且仅声明
`[command] journal = "required" | "none"`；缺失、未知值或非 command 携带该段均拒绝。两条互斥 funnel：

```
journal="none"
  → generated::command::<cmd>::emit_async(DirectCommandDispatcher, typed Request, tenant, identity, key)
  → eventexec::DirectCommandDispatcher<CommandDispatchStore>
  → crate-private constructor → ReviewedCommandDispatch
  → provider `CommandDispatchStore::dispatch`

journal="required"
  → generated::command::<cmd>::journal_async(JournaledCommandDispatcher, typed Request, tenant, identity, key)
  → eventexec::JournaledCommandDispatcher<CommandJournalStore>
  → crate-private constructor → ReviewedCommandJournal
  → provider `CommandJournalStore::record_command`
```

**分层关键点**：`generated` 只可依赖基础 crate，不得依赖 `eventexec`（引擎/服务层）。
`CommandEmit` / `CommandJournal` / `CommandRegister` / sealed `TypedCommandSpec` seam 定义在 `generated` 内，使 wrapper 可
funneling 而无需反向依赖 runtime。每个 command module 只生成一个 sealed `Contract` marker；
`CommandContract::Request + SPEC` 把 payload schema 与 routing metadata 绑定，`DirectCommandContract` /
`JournaledCommandContract` 再在类型层固定 policy。公开 seam 只接受 carrier，不接受独立 `CommandSpec + R`；required
只生成 `journal_async`，none 只生成 `emit_async`。外部无法构造 marker 或 reviewed DTO，因此不能进入 RSS command outbox。

业务幂等键只在 `eventexec` 的独立 `CommandIdempotencyKeyring` 内使用：keyring 由 current + previous generations
组成，每把 key 至少 256 bit、drop zeroize，且不得复用 tenant-authority/audit key。runtime 用 keyed
`secure::BlindIndex` 对 `(tenant, topic, raw key)` 生成 sealed `CommandAliasProbeSet` 后立即丢弃 raw key；provider
只能看到 `(key_id, 256-bit digest)` probes。事务 provider 原子 claim current/previous aliases，并生成随机
`command:v2:<uuid>` canonical id；无业务 key 的 direct dispatch 直接生成随机 canonical id，不写 alias。
wrapper 锁 topic + contract + typed Request + tenant + subject_id + actor + idempotency key。`tenant` 是
`vocab::TenantId` typed scope，由 runtime 写入 reserved `tenantId`
envelope；`contract` 是 generated `vocab::ContractBinding`，由 runtime 写入 reserved
`schemaVersion` / `schemaHash` metadata 并同源落 outbox `contract_version` / `schema_hash` 列；`subject_id` 是 `diport::EnvelopeSubjectId`，`actor` 是
`diport::OutboxActor`。`subject_id` / `actor` 由 runtime
写入 persisted metadata，broker header / MQTT user property 不可见；dispatcher 只透传，不从 payload 重新派生。

event authoring 与 command authoring 完全分离：公开 event 写面只接受 `EventTopic` + `EventEntry`，
`EventTopic::parse` 拒绝 `*.commands.*` namespace；relay/readback 只得到 `StoredOutboxEntry`，其 hydration
类型不能转换回 event producer API。command provider 只消费 `ReviewedCommandDispatch` 或
`ReviewedCommandJournal` 的只读 accessor / `into_parts`，不存在公开 raw command entry 构造面。

consumer 侧对称：`generated::command::<cmd>::register_handler`（generic over
`CommandRegister` seam）→ runtime `eventexec::command::register_command_handler`，复用
`eventexec::run_consumer` + `consistency::InboxStore` claimer 做两阶段
去重（同 canonical command id 再入 → `SeenState::Duplicate` → 拒绝）。

**Guards**：manifest policy 与互斥 wrapper 由 `COMMAND-JOURNAL-GENERATED-01#manifest-policy`
codegen + golden + synthetic red/anti-vacuity（Hard）守；per-command carrier、reviewed DTO 与 alias probes 均不可伪造
（可见性/类型 Hard）。`COMMAND-IMPL-ALLOWLIST-01#provider-set` 只检查类型无法表达的生产 provider impl 与
callsite 集合（Medium AST，覆盖 alias/glob red case）；不再把 AST 扫描描述为 command authoring seal。
`kind=command ⇒ OutboxFact` 仍由 contract validate R15（Medium）守。符号、证据与 residual 见
[`Persistence Funnel AI-Robust Matrix`](../architecture/202607091830-015-persistence-funnel-ai-robust-matrix.md)
及 [ADR-016](../architecture/202607091830-016-command-outbox-authoring-seal.md)。

`consistencyLevel = OutboxFact`（R15 机器锁定）；command topic = `<domain>.commands.<name>`（稳定
dotted，broker routing key）。命令 emit 是 emit-only 单事实（非 co-tx）。

### Durable command journal

durable command（调用方需要幂等 claim、稳定结果回放、业务写与 command outbox append 同事务提交的命令）
必须走 command journal seam：`ReviewedCommandJournal`（eventexec provider-neutral reviewed DTO）负责
review tenant/topic/contract/fingerprint/payload 并携 keyed alias probes；request fingerprint 明确排除 raw key。
Postgres `PgCommandJournal` 在同一事务 claim aliases、生成 canonical id，并持久化 journal 与 outbox。public
`CommandJournalStore::record_command` 只表示 foundation 级 “journal + outbox enqueue” seam；需要本地业务写
共提交时，必须由 Postgres/domain-shaped UoW 在 crate 内经 `PgTenantWritePool` + crate-private `TxCapability`
封装业务写、journal claim、`append_outbox` 和终态更新，外部 handler/domain 不得拿 raw
`PgPool`/`PgConnection` 自行拼事务。重复同 fingerprint 只回放
`CommandJournalOutcome::AlreadyCompleted/AlreadyFailed` 等稳定 summary，不重执行业务写；同 key 不同
fingerprint 必须返回 conflict，不能静默吞 outbox conflict。commit result unknown 不作为普通 transient
自动重放整个 UoW，后续同 key 只能通过 journal/outbox 已持久化状态恢复。

纯请求内 L1 同步命令（不 durable、不入 outbox、不跨进程恢复）可以不使用 command journal；一旦命令需要
durable outbox / 幂等请求重放 / 本地业务写共提交，journal 是唯一 sanctioned path。不提供 dual-write、
旧字段 fallback、raw `PgPool` / `PgConnection` path，也不把完整 command worker、device ack/timeout 或
Temporal scheduler 塞进本 seam。

### Reconcile transactional command seam

durable reconcile scheduler 有一条专用 sanctioned path：domain reconciler 不拿 `OutboxEmitter` / publisher，
只拿 `AttemptScope`，并通过 generated per-command `reconcile_command(typed Request, tenant, subject, actor, key)`
构造 sealed `TypedCommandSpec`，再调用 `record_action_and_enqueue_command(action, typed_command)` 请求同事务写入。
`ReviewedCommand` 只保留 typed `from_spec` 与 provider accessor/`into_parts`，没有 raw topic/contract/payload
构造器或 `StableDispatchKey` 公共模型。durable scheduler 必填同一 `CommandIdempotencyKeyring`，只把 sealed
alias probes 交给 provider；最终 outbox `event_id` 是 provider 事务内生成的随机 canonical id，避免跨租户/topic
alias 碰撞并防 raw key 落库。Postgres
adapter 是唯一持久化实现：在同一 tenant-scoped transaction 内用 target-local `lease_token + epoch` CAS，
append action-local `reconcile_actions(result_label='recorded')`，再 append outbox row；outbox conflict 只在同
tenant/topic/contract/payload 一致时视为幂等。terminal attempt outcome 只写 `reconcile_attempt_results`。该路径不经过
production `generated::command::CommandEmit` bridge，也不新增真实 active command contract；首个真实 command contract
与 bridge 接线另行落地。

守卫：`RECONCILE-COMMAND-OUTBOX-SEAM-01` / `cargo xtask reconcile-outbox-command-guard` 禁止
`eventexec::reconcile` direct publisher/emitter/broker/裸 outbox append，并限制 postgres reconcile adapter 的
`append_outbox` 只能出现在 `record_action_and_enqueue_command` seam 的同一个 `PgTenantWritePool::write` transaction
closure 内，且顺序为 lease CAS → action insert → outbox append。

## Projection

projection consumer 必须 wire durable projection harness。投影事件载体使用
`consistency::ProjectionEvent` trait，包含 payload、topic、LSN 与持久化 envelope metadata。
retained journal、checkpoint、tailer、DLQ 的完整约束以对应 rustdoc 和 ADR 为准。

**串行有序门禁（fail-closed by absence，#1211）**：`ProjectionHarness::new` 必填 DLQ store 与一枚
`consistency::SerialInOrderGuarantor` witness——非串行投递路径拿不到 witness ⇒ **编译期**挂不上 projection
（投影 apply 须按序，乱序会损坏读模型）。witness 唯一经 `SerialInOrder::from_source(&S)` 铸造，`S` 须 impl
`consistency::PartitionSerialDelivery`（声明其 read/poll 路径串行有序，如 `PgProjectionEvents` 的
`ORDER BY id ASC`）。attach 门禁 + witness 类型封闭 = Hard（sealed）；witness 真实性（铸造源真串行）由 dylint
`rss_partition_serial_allowlist` 守（仅 allowlist adapter/组合根可 impl `PartitionSerialDelivery`，Medium）。
INVARIANT: PROJECTION-SERIAL-WITNESS-01 / PARTITION-SERIAL-IMPL-ALLOWLIST-01。

outbox 派生投影的 durable journal（`projection_events`）只由 outbox writer funnel 写入：
`append_outbox` 返回 `Inserted/AlreadyExists`，仅当 outbox 行新插入且 `(contract_id, version, schema_hash, topic)` 命中 generated
`generated::event::PROJECTION_INPUTS` 派生的 `ProjectionWriteRegistry` 时，才在同一事务内镜像到
`projection_events`。registry 只接受 `&'static [vocab::ProjectionInputBinding]`，不提供 raw string topic
注册 API；生产 projection binding 必须来自 contract metadata/codegen，非手写列表。DLQ replay 写 outbox 时也走
同一 funnel，duplicate replay 不重复写 projection journal。

`projection_events` 写/读只经固定 `SECURITY DEFINER` 函数：
`rss_append_projection_event(...)` / `rss_read_projection_events(...)`。`rss_app` 只拿函数 `EXECUTE`，不持
`projection_events` 表级 `SELECT/INSERT/UPDATE/DELETE`；函数 owner 为 NOLOGIN runtime role，表仍 `REVOKE UPDATE, DELETE`。
启动期 migrator 用 generated `PROJECTION_INPUTS` 刷新 DB 侧 `projection_input_bindings`，不授 `rss_app`
写权限；append 函数还要求参数与同事务可见 outbox row 完全匹配，且该 row 命中 DB registry，防止直接 SQL
绕过 Rust funnel 凭空写 projection journal。append 函数持 xact advisory lock 后插入，使 projection LSN identity 顺序跟随已提交 projection append 顺序。
0040 migration 是有意的 breaking cut：旧 `projection_events` 非空即 fail-fast，不 backfill、不保留裸 append shim。
`ProjectionEventSource::read_from(None, limit)` 表示从 source 起点读取；runner 不用 `Lsn(0)` 兼作起点前哨兵。
Postgres `projection_events` 的 identity 实际从 1 开始，`PgProjectionEvents` 内部才把 `None` 映射为 DB 固定函数的
exclusive `after=0`。
Projection harness 默认对 `Permanent` / `Invariant` / `OutOfOrder` 写 projection DLQ 后停当前 projection，不自动
skip；`Transient` 不写 DLQ；DLQ 写失败不推进 checkpoint。projection runner 仅在显式
`ProjectionPoisonPolicy::SkipPermanentAfterDlx` 下允许跳过 `Permanent` poison，且必须先写入 projection DLQ
成功，再用 checkpoint CAS 推进到该 poison LSN；`Invariant` / `OutOfOrder` 不允许 runner 自动 skip。
`PgCheckpointStore::save_checkpoint` 在 SQL update 路径拒绝 offset regression。
append-only 主守卫是 serving role 的 DB 引擎权限与固定函数面（Hard、不可绕）；
code-level `DELETE`/`TRUNCATE projection_events` 字面量与固定函数 direct callsite 另由 verify guard
（Medium，含 anti-vacuity + RED/GREEN fixture）守。
盲区/评级/符号以对应 rustdoc 为准。

## 命名与 payload

- stream / topic / command key 使用稳定 dotted 名称。
- event payload 是 JSON object，字段 camelCase。
- event metadata 的 trace、request、principal 信息由 outbox envelope 注入，业务
  不伪造 reserved metadata key。
