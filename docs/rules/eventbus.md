# EventBus 规范

本文件只写约束与失败语义。实现细节、默认值与语义证明属于对应 crate 的 rustdoc 与 ADR；
本文件不复述，也不作为任何机器门的 carrier。

## 事件传输选型（topology-gated）

- 组合根必须经 `bootstrap::eventtransport::resolve` 按 `Topology` 单源选型，该 resolver 是纯策略函数，
  返回已校验决策而不构造 adapter；具体 adapter 由组合根 `match` 决策后构造。
- `Topology::DurableShared` 允许 per-domain URL 缺失时回退共享 `RSS_AMQP_URL`；
  `Topology::DurableIsolated` 禁止回退，配置含 shared URL 即 fail-closed。
- durable 缺 broker URL 必须 resolve 返回 `Err` 并由组合根 fail-fast，不得静默降级回 in-memory。
- in-memory bus 只允许 demo 决策可达。生产 bin 经 `deny.toml` 依赖不到 memory adapter（Hard）；
  dev 组合根只允许在 `Demo` 分支构造。
- 扩展新 broker 必须加 `ResolvedTransport` 变体 + 组合根分支，不另开旁路。
- 载体：`INVARIANT: TOPO-FAILCLOSED-01` / `TOPO-INMEM-SEAL-01`；语义单源为 `bootstrap::eventtransport` rustdoc。

## per-domain AMQP vhost/credential 隔离

- per-domain URL 携带 per-domain 凭据与 vhost，凭据由 broker operator 外部配置，framework 不派生。
- split 拓扑下 per-domain URL 缺失必须启动期 fail-closed，不降级到共享凭据。
- Broker ACL 必须与 domain 绑定：producer 凭据只允许 publish 本域 exchange / routing key，
  consumer 凭据只允许 consume runtime 为其 declared 的 queue 并只 bind 契约声明的 topic。
- broker header / MQTT user property 中的 `tenantId` 不是授权凭据；消费侧写 app DLX 前只信任
  relay 签发的 `tenantAuthority`。

## Device MQTTS session 与认证边界

- MQTT production adapter 默认编译且只有一个 `MqttSession`：一枚稳定 RSS client identity、一个
  rumqttc eventloop/driver、一个 persistent broker session 和一个 typed exact topic policy。不存在明文
  `mqtt://`、随机 client ID、独立 publisher/subscriber driver、无 broker feature 时的 fallback，或 raw-topic port。
- 构造必须同时提供纯 authority `mqtts://host[:port]`、CA/client certificate/private key、与 client
  certificate CN 精确相等的稳定 client ID、broker assertion Ed25519 public key、非空设备 scope policy、
  `60s..=7d` session expiry 和严格递增 credential revision；任一缺失或非法均 fail-closed。连接固定
  `clean_start=false`，只有 `session_present=false` 才重建全部 exact QoS1 subscription。
- 每个设备 scope 只生成三条主题：
  `rss/v1/{tenant}/{device}/{generation}/downlink/identity.commands.apply-device-certificate`、
  `.../uplink/identity.device-command-acked` 和
  `.../uplink/identity.device-certificate-reported`。`tenant` / `device` 必须是 canonical UUID，generation
  必须大于零；policy 拒绝空集、同 tenant/device 重复项、wildcard 与调用方字符串拼接入口。Broker ACL
  与 subscription 必须从同一 exact policy 派生。
- 设备 client certificate 必须含唯一 URI SAN
  `urn:rss:mqtt-device:v1:{tenant}:{device}:{generation}`。正式 Mosquitto v5 message plugin 只从
  `mosquitto_client_certificate` 取得 peer certificate，校验 SAN 与 exact uplink topic，并拒绝 client
  自带的 `rss.authn.v1.*` user properties；随后用 broker-only Ed25519 private key 绑定 principal、topic、
  correlation data、SHA-256 payload digest、QoS 与 retain，签入 v1 assertion。RSS 只持 public verification
  key；payload、topic 或普通 user property 都不能构造、覆盖或降级 authenticated principal。
- 入站固定 manual ACK。只有 assertion 验签、当前 scope/generation 匹配并进入有界 delivery queue 后才产生
  不可复制的 `AuthenticatedDeviceDelivery`，且只有消费该 delivery 的一次性 capability 才能发 PUBACK。
  验签失败、scope 漂移、stale generation、队列饱和或 session degraded 均不得提前 PUBACK。
- adapter-private `DeliveryQueue` 是严格有界 short-lock `VecDeque` + `Notify` + closed：driver 单
  producer、ingress 单 consumer；`RECEIVE_MAXIMUM == DELIVERY_CAPACITY` 以 compile-time hard const
  锁定。invalidation 唯一 funnel：在 settlement 共享 short barrier 下做 checked atomic epoch bump，
  再同步 `clear` 尚未 pop 的旧代 pending（不 PUBACK），然后才允许任何 async disconnect / drain /
  backoff / connect；已 pop / in-flight delivery 只靠 epoch settle。settle 不是二次 load，而是与
  begin / invalidate 共享同一 barrier，把 current check + `try_ack` enqueue + 同代错误分类线性化：
  epoch mismatch → `MqttSessionError::StaleTransportEpoch`；同代失败 → `AckUnavailable`。pilot 仅对
  terminal settlement（durable post-commit 或 bounded unaddressable poison terminal）的
  `StaleTransportEpoch` 不关闭已恢复的新 session 并等待 broker 对同一 envelope 的
  persistent-session replay；`AckUnavailable`、receipt mismatch、commit failure 一律 fail-closed /
  shutdown。只有 `DeliverySaturated` 不撕裂健康 transport；`AssertionRejected` 是 trust-boundary
  failure，仍进入 recovery。本边界不扩 TLS / ACL / cert / sequence / redaction 证据面，也不新增
  metric label / dashboard / alert。
- 下行 `send_command` 返回的 `BrokerAccepted` 只证明 broker PUBACK，即 **BrokerAccepted**；它不是设备 ACK、
  durable RSS ingress 或 application receipt。durable commit 后的 application receipt 由 #1903 ingress
  transaction outcome 唯一产生，broker/session 与 ingress 的断连、饱和 join hazard 归 #1908，生产 assembly
  provider closure/readiness/drain 归 #1910。
- credential reload 只接受同一稳定 client ID、完整本地可验证 material 和更高 revision；在有界 deadline 内
  切换，candidate 失败则回滚 last-good credentials。`MqttReadiness` 只暴露闭合状态、`session_present` 与
  revision，不暴露 endpoint、certificate、private key 或 payload。
- MQTT T2 只使用 hermetic Docker fixture 构建正式 plugin image；不读取 `RSS_MQTT_TEST_URL`，也不接受外部
  URL 替代 fixture 的 PKI、ACL、persistence 或 assertion 证明。

## 标准 Envelope Header

broker-visible header 闭集：`tenantId`、`schemaVersion`、`schemaHash`、`occurredAt`、
`trace` / `correlation`、`tenantAuthority`。

- `tenantId` 缺失或非 canonical 时消费侧 typed header fail-closed。
- `schemaVersion` / `schemaHash` 由 generated `CONTRACT` 同源写入 outbox 物理列，relay 以列覆盖 header。
- `trace` / `correlation` 是观测字段，缺失或畸形 fail-open，不阻断投递。
- `tenantAuthority` 由 relay 签发并必须在写 app DLX 前验签；CDC 不签发该 header。
- `subjectId` / `actor` / `principal` / `causation_id` 与业务 free-form metadata 是 persisted-only，
  不进 broker header。业务写入口对所有 reserved key fail-closed。

## Outbox 写入模式

PostgreSQL adapter 只有两条显式模式，二者不得 fallback 或双写：mutable `outbox` 状态表（默认）与
显式 opt-in 的 `outbox_log` append-only CDC ledger。`outbox_log` 是 tenant 表，迁移必须落
`ENABLE/FORCE RLS` + 标准 tenant policy + 最小授权并 revoke `UPDATE/DELETE`。

### L2 producer-fact domain closure

- HTTP producer 的每个 `emits` 必须引用存在的 event fact，且 fact `domain` 必须与 producer `domain` 相等。
  该约束覆盖全 lifecycle，draft / deprecated 不是跨域 emits 的豁免。
- active producer 另要求目标 fact 也 active 且至少声明一个订阅。
- active HTTP producer 的持久化只有一个内核事务 funnel：私有
  `TenantDb<ServingWriteLane>::producer_tx` 铸造原始事务；生产调用方只经
  `identity_producer_tx` / `retry_config_producer_tx` 等 concern-specific runner 接收不可互换的 capability，
  写业务行并返回 typed outcome。内核校验 authorization、envelope contract 与 entry fact 后 canonical append。
  generic entry 构造不具 generated fact provenance，不得进入 active producer 的 emitted 分支。
- 不存在旧 producer co-transaction API、provider `.write()` + append、publisher 补发或兼容双写。
- 载体：`cargo xtask contract validate` R22；producer evidence 为 `generated/l2-assurance.json`。

### L2 provider conformance catalog

- provider-neutral 能力闭集：`identity / conflict / fencing / budget / commit-ack / ambiguity / archive-receipt`。
  provider 不得以 `unsupported`、空 runner 或 noop 测试冒充不适用能力。
- 每个 provider owner 只有一个 enrollment；宏在编译期拒绝缺失、重复、额外或重排能力。
- committed matrix 的 `enrolled` 只表示存在可执行 carrier，不表示测试已通过；通过状态只由对应 shard 回执证明。
- 测试 API 不提供 claim、archive receipt、AMQP channel/connection/generation 的构造或注入入口。
- 载体：`cargo xtask provider-capabilities --check` → `generated/provider-capability-matrix.json`。

### Outbox relay 投递语义

Outbox relay transport 是 **at-least-once**：durable fact 使用稳定 event ID 发布；publish 成功、settle 前
崩溃允许 broker duplicate，broker confirm 的 ambiguous outcome 必须按可能已发布处理并重试，
不得换 ID 或假定消息尚未到达。

- `PublisherError` 处置是闭合三态：`Permanent` 首投进入 DLX；`Transient` 与 `Ambiguous` 在原 deadline 内
  以原 event ID 重试。`Ambiguous` 不是 exactly-once 证明。
- AMQP publisher 遇 `Ambiguous` 必须退休整个 generation，不得在潜在已接收的旧 transport 上继续 admission。
  恢复由 RSS 在绝对 recovery deadline 内驱动；broker 客户端 auto-recovery 不参与。
- 每个 outbox provider 在构造期绑定唯一 typed `DomainName`；claim 不接收调用方传入的 raw domain。
- claim 必须在同一数据库语句内选取、铸造 token/deadline 并持久化；settle CAS 必须同时匹配 token 与
  精确 deadline，并拒绝已过期租约。
- 每次 broker publish 前必须以 DB 当前时间做 lease budget preflight，预算不足不得发 broker 请求。
  预算经单一 typed funnel 构造；env 存在但非法时 runtime 启动失败，不回退默认值。
- 稳定 event ID 是幂等锚，不是 exactly-once 保证。事务外副作用仍须透传自己的幂等 key 或由 reconcile 收敛。
- 事实同一性：mutable 与 CDC 模式共用 canonical identity；同 event 且稳定事实相同视为幂等，
  任一稳定字段不同必须 typed 冲突并在 commit 前退出。`occurredAt` / `trace` / `correlation` 是可漂移观测字段。
- 载体：`OUTBOX-FACT-FUNNEL-01`；实现语义见 `adapters/postgres` outbox rustdoc。

### 有界 same-ID 投递窗口

- 自动重试窗口、operator redrive 窗口、安全余量与 inbox receipt 保留期由数据库 singleton policy 冻结，
  并由 CHECK 强制保留期严格大于三者之和。runtime 启动只接受该组精确值；revision、行数或值漂移 fail-closed。
  这是正确性策略，不提供 env 或调用方 override。
- outbox 行的 phase 闭合于 `automatic | redrive`，两个绝对 deadline 只在首次冻结，operator redrive
  不延长或重算任一 deadline。
- publish preflight 必须检查当前 phase 的绝对 deadline；已到期不得调用 broker，直接 settle 到 DLX 并计数。
- 过期行只能经唯一 terminal resolution funnel 结清：`accepted_gap` 必须不携带 evidence；
  `compensated` 必须引用同 tenant、已发布且 causation 匹配的 evidence。结清后原行进入 `abandoned`，
  successor 方可继续 claim。
- resolution 表是 append-only durable evidence；serving role 对该表与函数均无权限。
- 载体：`INVARIANT: OUTBOX-SAME-ID-WINDOW-01` / `cargo xtask outbox-same-id-guard`。

### L2 非一致恢复点

- RSS 只处理 PostgreSQL 与 RabbitMQ 已由外部 delivery 系统恢复后形成的应用级非一致状态；备份、PITR、
  broker 数据卷恢复、Helm 与 Kubernetes 编排均不属于 RSS。真实后端 journey 构造与恢复结果等价的
  PostgreSQL/RabbitMQ 状态，不宣称验证外部恢复控制面。
- 恢复前应由外部 owner 暂停业务流量与 RSS serving，阻止新的 relay claim、consumer subscription 与应用写入，
  并冻结 exact tenant、recovery epoch、数据库与 broker restore point、选中的 durable event ID 以及原
  absolute deadline。这是 Soft/process 运维前置，不是本能力的机器 gate：当前 apply 路径不校验 pause
  evidence。进程内 pause/drain 与分阶段 resume 的后续闭环由 #2009 跟踪，不得把该 backlog 当作已具备能力。
- restore point 只作 operator 决策证据，不得反向生成、替换或扩展 event identity；两个 restore point 必须
  严格不等，相等时 plan 构造以 `equal_restore_points` fail-closed。
- broker ahead / PostgreSQL earlier 只允许原消息按 at-least-once 语义重新投递；计划中的 event set 是
  operator 冻结断言，不要求恢复后的 PostgreSQL outbox 存在对应行，也不得因此追加 outbox 存在性 SQL
  校验。不得清空或重置 Inbox，duplicate 必须由恢复后的 ConsumerTx/Inbox 状态收敛。PostgreSQL ahead /
  broker earlier 只允许经授权计划对选中 outbox row 做 same-ID republish，不得延长 absolute deadline 或
  绕过既有 external-effect policy。
- apply 成功必须原子形成 tenant-scoped、operator-authorized、append-only durable receipt；缺 receipt、
  receipt 与 frozen plan 不一致或任一 event 已过 deadline 时 fail-closed，并保持外部暂停直至核对完成。
  核对 receipt 后按 relay、consumer 的顺序恢复 admission（分阶段 resume 控制面见 #2009）。
- 本能力是 T1/T2 correctness proof；真实后端 target 只属于 `ReleaseCheck`，不进入普通 PR 的
  `integration-critical`、required selector 或 T3。它不新增 dashboard、alert 或 Prometheus counter。
- 运维顺序与失败处置见
  [`202608021938-1837-l2-dr-recovery.md`](../ops/202608021938-1837-l2-dr-recovery.md)。

## 复用层选型（claimer / workflow backend，topology-gated）

- outbox 消费幂等 claimer 经 `bootstrap::replaydeps::resolve` 按 `Topology` 单源选型；
  demo/single-pod 用 in-memory，multi-pod 用 Redis-backed，缺 Redis 配置启动期 fail-closed。
- service-token replay 不属于该 resolver：所有可用 HS256 operator 路径必须显式注入 Postgres durable store，
  不存在 serving、demo 或进程内 fallback。
- workflow definition lifecycle 与 assembly deployment activation 是两个维度。activation 单源是 assembly
  manifest v2 的 `workflowActivations`，由 AssemblyLock v2 绑定 repository definition，并原样进入
  RuntimePlan v2 `workflowPlans`；contract lifecycle、`Topology` 和 backend resolver 均不得提供 activation
  default 或把 omitted/disabled workflow 推断为 active。
- active Saga 的完整 requirement 集合为 typed actions + 单一 tenant-scoped `SagaDurableStore`
  （instance/lease、append-only journal cursor、protected receipt 的原子视图）+ dead-letter store +
  typed hydrate/probe/operator recovery + worker。该集合先由已验证的 assembly activation plan 派生，
  再由组合根闭合；`bootstrap::sagaprojectiondeps::resolve` 只在 requirements 已要求 Saga/Projection
  durable backend 后，按 `Topology` 选择同一个 memory 或 PostgreSQL durable-store provider。
  resolver 成功不代表 workflow 已激活，也不证明完整 requirement 集合已闭合；不得重新拆出
  instance/journal/receipt owner、Saga-specific checkpoint 或 runtime lock。
- `eventexec::WorkflowRuntimePlan` 是 production workflow activation 的唯一执行入口：它将 sealed
  RuntimePlan 与 generated definition、typed capability catalog 精确 join，并只向 PostgreSQL capture、
  operator/DLQ、Saga 与 runtime inventory 发放不可外部构造的借用视图。omitted/disabled 不得创建 registry、
  store、worker、route 或 probe；global definition catalog 只能由该 compiler 读取，不能直接驱动 production。
- saga fail-closed：tenant scope 缺失、lease token/epoch/expiry 不匹配、`(tenant, saga, seq)` 内容冲突、
  durable-store 不可用，都必须返回 typed interrupted outcome，不触发补偿或 app DLX。
- Postgres instance lease epoch/token + journal CAS 是最终写入围栏；不保留 Redis runtime-lock 旁路。
- saga 表是 tenant 表：迁移必须落 `ENABLE/FORCE RLS` + 标准 policy + 最小权限，journal 撤销 `UPDATE/DELETE`。
  跨租户 worker discovery 只允许经窄索引 + 固定 `SECURITY DEFINER` 函数返回 tenant id。

## ConsumerBase 与 ConsumerTx

- 所有 consumer 使用 `ConsumerBase` 的 preflight / claim / lease / broker-settle 语义。
- `HandleResult` 不得裸构造，只用 `ack` / `requeue` / `reject` 构造器。`reject` / `requeue` 携带的
  error kind 必须经 `HandleResult::as_settled()` → `Settled::{Reject,Requeue}{summary}` 流到 DLX funnel，
  不在结果边界静默丢弃（失败变体类型层必携摘要，#1285）。
- durable PG runtime 必须使用 ConsumerTx：Fresh claim 后在同一 tenant-scoped 事务内完成业务写、
  outgoing append 与 inbox mark processed，commit 成功后才 broker Ack。旧 non-tx ackable spawn 不受支持。
- ConsumerTx handler 由 postgres adapter 构造，外部 crate 不得构造或逃逸
  `ConsumerTx`，也不能取得 `TenantTx<ServingWriteLane>`、raw connection 或通用 executor。
  handler、outcome、runner 与 worker spawn 归 runtime assembly 私有。
- 长驻 `!Send` event worker 的 OS thread、current-thread Tokio runtime、driver、build failure、health 与
  completion 统一归 `eventexec` typed dedicated-runtime factory；assembly 只提供业务 future，确需保留
  组合根健康证据时仅注入窄 build-failure observer，不得直接构造 `tokio::runtime::Builder`。
- ackable 订阅生命周期唯一入口是 `eventexec::run_ackable_subscription_loop`：`subscribe_ackable` 失败与
  delivery stream 非取消终止均指数退避重入，直到 shutdown token 取消；成功订阅后重置 attempt，并以 CAS
  仅在 `starting` | `subscriber-unavailable` → Healthy（`mark_subscription_recovered`，不洗掉已证实的
  `dlx-write-error`）。失败/断流标 `subscriber-unavailable`（不覆盖 DLX/invariant）。默认
  `BackoffPolicy` 为 1s base / 60s cap（`base * 2^(attempts-1)` 封顶），经 spawn 注入（生产 default，
  测试可 tiny）。禁止 subscribe 失败后 one-shot `worker exiting`。载体：`CONSUMER-SUBSCRIBE-SUPERVISE-01`
  （Medium）。
- 结算规则：`handler_transient` 耗尽后只 broker `Requeue`，不写 app DLX、不提交 inbox done、不 Ack；
  `commit_unknown` / lease lost 立即 `Requeue`；只有永久 `Reject` 可写 app DLX 后 Ack。
  Duplicate delivery 不进入 tx handler，直接 Ack。活跃 claim 是 typed `InProgress`，不是 backend
  `Transient`；consumer 按同源 lease 周期做有上限延迟后 `Requeue`，不进入 handler，也不发 backend-health warn。
- 每条订阅必须在 `contract.toml` 声明 identity、闭枚举 `execution` 与逐订阅 `externalEffectPolicy`。
  唯一 Rust policy 类型是 `vocab::ExternalEffectPolicy`，codegen 直接写入 spec，不复制第二个枚举。
- runtime 必须对 dispatch key、generated policy 与注册 capability 穷尽匹配；新增订阅未接线时编译失败。
  不得增加 wildcard、默认分支、通用 handler registry、平行映射清单或 fallback。
- `adapter-native` 禁止声明 `effect`；`domain-effect` 必须声明当前唯一闭值，且由 generated topology
  的穷举 resolver 限制适用范围。未激活的 policy 必须 fail closed，不预建空 executor 框架。
- payload decode 与 wire DTO 归属域 crate；postgres adapter 只保留事务职责，不维护第二套 event schema。
- handler 内自行构造或间接取得 raw external port 由 `event-transport-guard`（Medium AST）补强扫描；
  该 guard 不等价于 rustc HIR，主防线仍是私有 handler/runner 与 exact owner activation。
- 载体：`EVENT-TRANSPORT-PG-INBOX-01`；订阅语义受 `cargo xtask contract breaking` 跨版本门保护。

### 租约续租与 leaseLost hard-fence

- claim 是带 TTL 的租约：claimed 行 stamp 消费方铸造的 token，过期未续租的 claim 可被新 token 重捞。
- 长 handler 由 ConsumerBase 后台按 `lease_ttl/3` 周期续租，与 handler 执行同任务并发。
- 续租或 commit CAS 返回 lease lost 必须 cancel handler 执行上下文并终态降级 `Requeue`，不 commit、
  不进入当前 claim 的重试预算、不写 app DLX。token CAS 是唯一正确围栏，时间窗口判定有 TOCTOU 竞态。
- **并发安全要求**：TTL 到期与续租探测到 lost 之间存在并发双执行窗口。commit-side CAS 只保证幂等键
  `done` 写一次，handler 内事务外的外部副作用可能各执行一次，因此这些副作用必须幂等且允许并发重入。

## Disposition

| Disposition | 语义 | 行为 |
|-------------|------|------|
| Ack | 成功 | broker ack + receipt commit |
| Requeue | 瞬态失败 | 退避重试，预算耗尽后 reject |
| Reject | 永久失败 | broker nack/reject，进入 DLX |

读路径用 `HandleResult::as_settled()` → 闭合枚举 `Settled`（禁 `#[non_exhaustive]`；
`Reject`/`Requeue` 变体必携 PII-safe summary）；`Disposition` 仅作无摘要标签 / metrics
（由 `as_settled` 派生，可 `#[non_exhaustive]`）。二者不是平行第二真源。

`PermanentError` 只是错误分类，不自动把 Requeue 改成 Reject。

## 投递顺序保证

outbox 行带表级单调 `seq`（应用不可写、允许 gap）+ 可空 `partition_key`，顺序语义二分：

- `partition_key IS NULL`（默认）= 无序并行。消费方须幂等，不依赖跨 entry 顺序。
- `partition_key` 设置 = 同 `(tenant_id, domain, partition_key)` 串行有序，由 relay claim 的
  head-of-partition gating 保证至多一条 in-flight；不同 partition 的队头可并发 publish。
- `partition_key` 是不透明聚合根路由键，经 write 路径落库，不进 relay 读侧类型。
  tenant 是 envelope 必填 typed 输入，同一 business key 在不同 tenant 下不共享 gate。
- **dlx fail-closed**：队头进 DLX 会阻塞该 partition，只在 redrive deadline 未到期时允许运维 redrive；
  过期后只能经 terminal resolution 结清为 `abandoned`。放行未结清后继会破坏 in-order 不变式，故不提供。
- **backlog 例外**：head-of-partition gate 是 claim-only，被 gate 的后继仍计入 backlog depth。
- 是否 opt-in `partition_key` 是应用层决策，但必须前移到 `contract.toml` 的 topology 声明面。
- 载体：`INVARIANT: OUTBOX-PARTITION-ORDER-01`。
- **已知前提**：队头判据假设同 partition 行按 seq 序提交，成立于聚合根并发控制串行化写入。

## Acker / 投递结算 seam

- 纯逻辑 consumer 只做幂等与 DLX bookkeeping、不触达 broker，配 auto-ack 传输即 at-most-once。
- at-least-once 必须走 ackable 变体：每条投递携带独立 `Acker` 结算句柄，终态恰一次 settle。
  `Acker` 是独立 seam，不挂在冻结的 `Message` 值类型上。
- `AckAction { Ack, Requeue, Reject }` 是 provider-agnostic broker 词汇，由 adapter 翻译。

终态到 settle 的映射：

| 终态 | 引擎动作 | settle |
|------|---------|--------|
| handler `Ack` | commit key | `Ack` |
| `Reject` / 预算耗尽且 DLX 写成功 | commit key | `Ack` |
| DLX 写失败 + release 成功 | release key | `Requeue` |
| DLX 写失败 + release 失败 | 发 release 失败指标 | `Reject` |
| claim 瞬态错误 | 不 commit | `Requeue` |
| active claim `InProgress` | 不 commit；lease-aware 有界延迟 | `Requeue` |
| claim 永久错误 | 不 commit | `Reject` |
| 租约丢失 | cancel handler，不 commit | `Requeue` |
| `Duplicate` | 跳过 handler | `Ack` |
| 幂等键 malformed | 不 commit | `Reject` |
| 未知状态 | 不 commit / 不 release | `Requeue` |

崩溃安全：settle 前崩溃由 broker 自动 requeue，重投经幂等 claim 去重，达成 at-least-once。

## 订阅注册

- 订阅单源是域 crate 的 `Cargo.toml [dependencies]` 加 `contract.toml` 声明；codegen 为每个 manifest
  subscription 派生不可外部实现的 marker 与唯一 typed `subscribe` wrapper，业务不手写平行 registry。
- `bootstrap::Registry` 只实现 generated `EventSubscribe`；调用方只提供 capability，contract、topic、schema、
  consumer、group、dispatch/readiness/execution/effect 均由 generated `SPEC` 固定。不存在公开的裸坐标注册入口。
- 域 crate 的 `Domain::init` 只能调用 per-subscription generated wrapper 注册 handler。
- 组合根必须经 sanctioned bridge 把 runtime binding 桥接为 `BridgedSubscription`，bridge 内部固定消费
  `generated::event::EVENTS` 根级 registry，不接受调用方传入平行 spec。
- bridge 必须双向校验 generated spec 与 runtime binding 一对一精确匹配，缺项、重复消费或 group drift fail-fast。
- `BridgedSubscription` 字段私有；生产代码不得在 sanctioned bridge/bundle 外直接 spawn consumer 或取 inbox。
- consumer group 命名必须稳定，避免重放时变成新消费者。

## DLX 与幂等

- 永久错误进入统一 hot 表 `dead_letter`，`source_kind` 是闭值集。payload 与全部 persisted delivery metadata
  必须一次封装为加密 replay capsule；`tenantAuthority` 只在入站验证期存在，永不落入 capsule。
- tenant、来源、provenance、安全摘要与 payload 长度保留为独立可查询安全列。不存在旧 decoder、明文 shape、
  双写或 fallback。
- DLX lifecycle 固定为 `HOT → 校验和已验证 → receipt → bounded purge → COLD`。archive 使用独立密钥与独立
  bucket，该 bucket 必须启用 versioning 与 Object Lock，默认留存严格长于 hot。
  archive provider 只有 conditional put/get/head/verify，没有 delete/list。
- durable runtime 必须分别提供 hot 与 archive 两枚不同的 workload token，archive token 不回退或复用通用 token。
- DLX list API 只返回 payload 长度与摘要元数据，不返回 payload 内容；分页必须用 keyset cursor，
  不得用 offset 或假定一次返回即完整队列。
- operator CLI 全部命令必须用 `--operator-service-token-stdin` 从标准输入读取 operator service token，并带
  operator tenant 与目标 tenant；授权由 PDP 验证 +
  typed maintenance caller + 精确 grant 共同决定，caller 不得由 grant 字符串选择。
  service token 的重放防护由 Postgres 单语句原子消费保证，raw 标识不落库，存储失败 fail-closed。
- 审计 kind 与 action 是固定闭值；v1 不提供 destructive `skip` 或旧命令别名。
- replay 必须传 operator capability、typed id 与调用方提供的新幂等键；不得删除原 `dead_letter` 行、
  不得重置 inbox done、不得直接 broker replay。replay 从同一 capsule 恢复 schema header，缺失或非法 fail-closed。
- saga 与 projection 的 `dead_letter` 只作审计与诊断，不支持 replay 成 outbox。
- serving role 必须被显式撤销 redrive / resolve 函数的 EXECUTE 权限。
- 不存在 plaintext fallback decoder；解密错误必须区分坏 payload 与依赖/配置错误。
- crash-after-claim 后消息最多延迟一个 inbox lease TTL 才被重捞重跑；该上界当前不可按消费者配置。
- handler 不接触 lease；续租与终态 CAS 由 ConsumerBase 透传。

## Command dispatch

- 命令 dispatch 经 generated typed API 与两阶段去重，producer key、consumer claim 与组合根 wiring 必须同源，
  不得新增裸字符串 dispatch。
- command manifest 必须显式且仅声明 `journal = "required" | "none"`；缺失、未知值或非 command 携带该段均拒绝。
  两条 funnel 互斥：`none` 只生成 emit 入口，`required` 只生成 journal 入口。
- **分层关键点**：`generated` 只可依赖基础 crate，不得依赖 `eventexec`。seam 定义在 `generated` 内，
  使 wrapper 可 funneling 而无需反向依赖 runtime。
- 每个 command module 只生成一个 sealed marker；外部无法构造 marker 或 reviewed DTO。
- 业务幂等键只在 keyring 内使用，每把 key 至少 256 bit 且 drop zeroize，不得复用 tenant-authority / audit key。
  runtime 用 keyed blind index 生成 probes 后立即丢弃 raw key，provider 只能看到 digest。
- canonical id 由事务 provider 随机生成；无业务 key 的 direct dispatch 不写 alias。
- event authoring 与 command authoring 完全分离：generated event wrapper 以 sealed `EventContract`/
  `EventEmit` 把 payload 与 contract/schema/topic 固定配对；`eventexec::ReviewedEvent` 的字段与构造私有，
  只可由 `GeneratedEventEncoder` 结合 tenant/subject/actor/envelope provenance 生成。production fact provider
  只接受 `ReviewedEvent`；普通 `EventEntry`、字符串 topic、手写 binding 或 relay 读回类型均不能转换回
  event producer API，公开 event 写面也拒绝 command namespace。
- `consistencyLevel = OutboxFact` 由 contract validate R15 机器锁定；command topic 使用稳定 dotted 名称。
- 载体：`COMMAND-JOURNAL-GENERATED-01` / `COMMAND-IMPL-ALLOWLIST-01`；
  设计单源见 [ADR-016](../architecture/202607091830-016-command-outbox-authoring-seal.md)。

### Durable command journal

- 需要幂等 claim、稳定结果回放或业务写与 command append 同事务提交的命令，必须走 command journal seam。
- 需要本地业务写共提交时必须由 Postgres/domain-shaped UoW 在 crate 内封装，外部 handler 不得拿 raw
  连接自行拼事务。
- 重复同 fingerprint 只回放稳定 summary，不重执行业务写；同 key 不同 fingerprint 必须返回 conflict。
- commit result unknown 不得作为普通 transient 自动重放整个 UoW。
- 纯请求内同步命令可以不使用 journal；一旦需要 durable outbox、幂等重放或共提交，journal 是唯一 sanctioned path。
- 不提供 dual-write、旧字段 fallback 或 raw 连接路径。

### Reconcile transactional command seam

- domain reconciler 不得持有 emitter 或 publisher，只拿 attempt scope，并经 generated per-command 入口
  构造 sealed spec 后请求同事务写入。
- durable scheduler 必填同一 keyring，只把 sealed probes 交给 provider；event id 由 provider 事务内随机生成。
- Postgres adapter 必须在同一 tenant-scoped 事务内按 lease CAS → action insert → outbox append 顺序执行；
  outbox conflict 只在同 tenant/topic/contract/payload 一致时视为幂等。
- 载体：`RECONCILE-COMMAND-OUTBOX-SEAM-01` / `cargo xtask reconcile-outbox-command-guard`。

## Projection

- projection consumer 必须 wire durable projection harness，投影事件载体使用统一 trait。
- **Target canonical owner**：`eventexec::ConformingProjectionTarget<S>` 是 sealed
  `ProjectionTarget` 的唯一实现形态；adapter 只能实现 `ProjectionTargetStore` 的单一原子 `apply` SPI。
  target 构造必须原子接收 definition contract（含 version/schema digest）、generated input generation 与
  exact binding set；这些 identity 随字段私有的 `ProjectionTargetDefinition` 进入 validated input。sealed
  assembly registry 在任何 store I/O 前逐项比较 definition、generation 与 binding，禁止从全局 catalog
  重建、fallback 或兼容旧的 projection-id-only 构造器。
  mutation 与 receipt 不得拆成两个调用，raw event 必须先经过 tenant、projection generation、source
  contract/version/schema/topic 的精确 binding 分类，再生成字段私有的 `ValidatedProjectionApply`、
  `ProjectionDedupeKey` 与稳定 fact digest。旧 target/projector/accessor 不保留兼容路径。
- exact binding 命中才调用 store；真正无关 contract 返回 `Filtered`，tenant 或已知 binding identity
  漂移必须 fail-closed。store 必须先查 receipt duplicate/conflict，再检查持久 high-water ordering，使
  checkpoint 丢失后的已提交旧事实返回 `Duplicate`，而未见过的低 LSN 返回 `OutOfOrder`。
- **Ordering 职责切分**：target store 守跨批、跨重启的 persistent ordering；harness 只守当前输入 batch
  的 LSN 升序及 checkpoint 前缀，二者不可互相替代。
- **串行有序门禁**：harness 构造必填 DLQ store 与一枚串行有序 witness，非串行投递路径拿不到 witness，
  编译期即挂不上 projection。witness 只能由声明串行有序的 source 铸造，铸造资格由 dylint allowlist 守。
- outbox 派生投影的 durable journal 只由 outbox writer funnel 写入，且仅当 outbox 行新插入并命中 generated
  projection registry 时才在同一事务内镜像。registry 不提供 raw string topic 注册 API。
- journal 读写只经固定 `SECURITY DEFINER` 函数；serving role 只有 append/probe EXECUTE，独立
  `rss_projection_reader` 只有 scoped read EXECUTE，两者都不持 raw table 权限。source scope 只能由 sealed
  assembly target 绑定 tenant 后铸造，并携带 projection id、definition version/schema digest、generated input
  generation；DB 在 payload 出界前再按完整 binding identity 过滤。append 函数要求参数与同事务可见 outbox
  row 完全匹配，防止直接 SQL 绕过 Rust funnel。
- source high-water 只经固定七参数函数 `rss_projection_source_high_water_scoped` 读取：operator 凭据先为
  sealed tenant/projection/definition version/schema digest/input generation scope 签发一次性 256-bit opaque
  capability，source-reader 凭据再把 capability 两个 UUID half 与该 scope 一并提交数据库。数据库只保存 token
  digest 与固定 30 秒 expiry，并在共享校验器中原子消费；过期 token 一律 `22023`，operator-only 零参数
  sweeper 每次最多回收 1000 个 orphan。reader 不能读取 capability catalog、调用 issuer 或自行选择未授权 tenant。
  scope 未命中完整静态 binding 集必须
  fail-closed；scope 有效但尚无已提交事件返回 `NULL`。函数对该 scope 的每个静态 binding 做一次 indexed tail
  seek，再合并 committed LSN；SQL 调用次数和 touched-buffer 预算不随历史事件数增长，真实 PostgreSQL 的
  100,000 行无关历史 + buffer regression 是 FR-013 的 T2 主证明，不是 T3 carrier。
- 全局 `rss.projection_events.append` transaction advisory lock 继续在 projection LSN 分配前串行化提交顺序；
  #1916 不以普通 sequence 替代 commit order，也不声明 exactly-once。checkpoint/target correctness 归 #1917。
  active swap 必须在同一数据库事务中先取得该 append lock，再锁定 exact binding、target generation、checkpoint、
  quarantine 和 typed active selection，读取 source high-water 后执行 fenced CAS；只有 generation high-water、
  checkpoint 与 source high-water 精确相等才可提交。失败保持旧 selection，不存在 high-water→pointer 的 TOCTOU
  窗口。lock wait、tenant fairness、throughput 与业务事务延迟容量阈值归 #1922；只有 #1922 的阈值证据触发后
  才可另立 X01 设计替换该锁。
- Projection 控制面必须使用独立 `rss_projection_operator` 凭据；它不持 checkpoint/CAS/DLX/audit 表权限，
  只可调用固定 status/replay/swap 所需函数并写强制审计。operator 不继承 source reader；需要 replay 的命令
  必须同时提供两个 file-only 凭据，且二者在启动时按 exact role/config/ACL/function set fail-closed。
  exact ACL 使用完整有效权限指纹，包含 PUBLIC 继承能力；迁移必须撤销 `public` functions 的 ambient
  PUBLIC EXECUTE，不能用“没有直接授给该角色”替代有效权限证明。
- **Settings 唯一 mutation funnel**：`settings.config-projection` 的 online serving 与 operator replay 都调用
  `PgSettingsProjectionApplyStore` 实现的同一个 `ProjectionTargetStore::apply`，最终只执行 migration 0093
  固定签名的 `SECURITY DEFINER` apply 函数。函数参数只包含 validated metadata，不接受 raw payload 或 config
  value；`rss_app` 与 `rss_projection_operator` 均无三张 Settings projection 表的 raw INSERT/UPDATE 权限，
  reader 无 apply 权限，PUBLIC 无 EXECUTE。函数 owner 必须 NOLOGIN、固定 `search_path`、显式设置并核验 tenant
  scope，再按 receipt duplicate/conflict → persistent order → generation/row/receipt/high-water 原子提交。
  Rust conversion 只在局部 decode raw payload，重复验证 Settings definition/input binding 与 selector、envelope、
  payload 三处 tenant；apply error 原子携带 closed typed reason，kind 只能由 reason 派生，禁止 kind+reason 双输入。
  Stop、DLQ summary 与 operator CLI 复用同一 snake_case reason；identity/tenant 漂移是 `Invariant`，合法 binding
  下的格式/数值错误和 version regression 是 `Permanent`。
- **Settings active generation 单源**：active selection 是 tenant-scoped typed record，绑定 generation、definition
  version/schema digest、input generation、promoted high-water 与 fencing token。它不是 generic
  `distributed_cas` value 或 JSON blob；pre-GA hard cut 删除旧 pointer 数据与读写函数，不保留 parser、backfill、
  alias、dual-read 或兼容 shim。登录角色没有 pointer 表 raw 权限，serving/operator 只能分别调用 fixed resolver/
  status/swap 函数。
- typed resolver 只接受已认证 tenant scope。Settings v3 query 在每个 request/unit-of-work 开始时解析一次，并把
  不可外部构造的 generation snapshot 固定到全部 projection reads；pointer 在请求中途切换时，旧 request 继续
  完整读取旧 generation，新 request 才观察新 generation。pointer unset、identity drift、跨 tenant 或 provider
  错误一律 fail-closed，不选择 latest、manifest target 或 Settings v4 fallback。
- active worker 对每个 tenant/batch 同样只解析一次 generation；batch 中途 swap 不改变当前 batch，下一 batch 从
  新 selection 对应的独立 checkpoint 继续。首次 selection 前只能由 assembly 声明的 bootstrap target 构建候选
  generation，不能 serving；rollback 前先 replay/catch-up 旧 generation，swap 后 worker 自动从旧 checkpoint 追尾，
  且不删除被切出的 generation rows、receipts 或 checkpoint。Settings v4 authoritative contract、handler、cache 与
  repository 数据路径从不读取 projection resolver。
  ref: serverlesstechnology/cqrs `src/query.rs`（query/read-model 分离的结构参考；typed selection、tenant fencing
  与原子 swap 为本仓库强化）。
- harness 对 `Applied` / `Duplicate` / `Filtered` 均可推进 checkpoint；任何错误均不越过失败事件。
  `Permanent` / `Invariant` 可写 DLQ 后停当前 projection，`Transient` 不写 DLQ；`CommitUnknown` 与
  `RollbackFailed` 明确禁止 poison DLQ、自动 skip 或 checkpoint 推进。DLQ 写失败不推进 checkpoint。
- 只有显式 poison policy 才允许跳过 `Permanent`，且必须先写 DLQ 成功再用 checkpoint CAS 推进；
  `Invariant` / `OutOfOrder` 不允许自动 skip。checkpoint 保存必须拒绝 offset regression。
- append-only 主守卫是 serving role 的引擎权限与固定函数面（Hard）；代码层字面量与直接 callsite
  另由 verify guard（Medium）补强。
- `testkit::projection_conformance` 是唯一 canonical suite owner，exact-set 固定 atomic apply、duplicate、
  conflict、persistent out-of-order、identity mismatch、confirmed rollback、commit-unknown replay、
  rollback-failed。typed/private input funnel、sealed target 与 macro exact-set 是 Hard；production AST
  enrollment 及真实事务/故障事实是 Medium。enrollment alone 不得授权 production activation 或作为 T3
  acceptance；lifecycle 与 production acceptance carrier 未闭合时，production activation 必须保持 disabled。
- reference carrier 只证明 canonical contract 与强制 enrollment 机制，不等同于 PostgreSQL production
  acceptance；真实 store 仍须用同一 conformance enrollment 证明其事务与故障事实。
- 载体：`INVARIANT: PROJECTION-SERIAL-WITNESS-01` / `PARTITION-SERIAL-IMPL-ALLOWLIST-01` /
  `PROJECTION-TARGET-CONFORMANCE-01`。

## 命名与 payload

- stream / topic / command key 使用稳定 dotted 名称。
- event payload 是 JSON object，字段 camelCase。
- event metadata 的 trace、request、principal 信息由 outbox envelope 注入，业务不伪造 reserved metadata key。
