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
- active HTTP producer 的持久化只有一个事务 funnel：业务 closure 经同一个 `&mut TxCapability` 写业务行
  并返回 typed outcome，由 funnel 校验 authorization、envelope contract 与 entry fact 后 canonical append。
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

## 复用层选型（claimer / workflow backend，topology-gated）

- outbox 消费幂等 claimer 经 `bootstrap::replaydeps::resolve` 按 `Topology` 单源选型；
  demo/single-pod 用 in-memory，multi-pod 用 Redis-backed，缺 Redis 配置启动期 fail-closed。
- service-token replay 不属于该 resolver：所有可用 HS256 operator 路径必须显式注入 Postgres durable store，
  不存在 serving、demo 或进程内 fallback。
- workflow definition lifecycle 与 assembly deployment activation 是两个维度。activation 单源是 assembly
  manifest v2 的 `workflowActivations`，由 AssemblyLock v2 绑定 repository definition，并原样进入
  RuntimePlan v2 `workflowPlans`；contract lifecycle、`Topology` 和 backend resolver 均不得提供 activation
  default 或把 omitted/disabled workflow 推断为 active。
- active Saga 的完整 requirement 集合为 typed actions + tenant-scoped instance store + append-only journal +
  receipt store + checkpoint store + dead-letter store + lock/fencing + worker + probe。该集合先由已验证的
  assembly activation plan 派生，再由组合根闭合；`bootstrap::sagaprojectiondeps::resolve` 只在 requirements
  已要求 Saga/Projection durable backend 后，按 `Topology` 选择 PostgreSQL instance/journal/checkpoint 与
  Redis runtime-lock backend。resolver 成功不代表 workflow 已激活，也不证明完整 requirement 集合已闭合。
- #1913 只建立 manifest/lock/RuntimePlan v2 协议载体；#1914 才把 production registry、DB capture、worker、
  route、serving 与 inventory 切换为消费该 plan。在切换完成前，不得把上述目标语义登记为已成立的 runtime
  `INVARIANT:`。
- saga fail-closed：tenant scope 缺失、lease token/epoch/expiry 不匹配、`(tenant, saga, seq)` 内容冲突、
  lock busy/lost/unavailable，都必须返回 typed interrupted outcome，不触发补偿或 app DLX。
- Redis lock 不是最终 fencing；Postgres instance lease + journal CAS 才是最终写入围栏。
- saga 表是 tenant 表：迁移必须落 `ENABLE/FORCE RLS` + 标准 policy + 最小权限，journal 撤销 `UPDATE/DELETE`。
  跨租户 worker discovery 只允许经窄索引 + 固定 `SECURITY DEFINER` 函数返回 tenant id。
- saga checkpoint id 必须包含 tenant，避免跨租户同 UUID 碰撞。

## ConsumerBase 与 ConsumerTx

- 所有 consumer 使用 `ConsumerBase` 的 preflight / claim / lease / broker-settle 语义。
- `HandleResult` 不得裸构造，只用 `ack` / `requeue` / `reject` 构造器。`reject` / `requeue` 携带的
  error kind 必须经 PII-safe summary 流到 DLX funnel，不在结果边界静默丢弃。
- durable PG runtime 必须使用 ConsumerTx：Fresh claim 后在同一 tenant-scoped 事务内完成业务写、
  outgoing append 与 inbox mark processed，commit 成功后才 broker Ack。旧 non-tx ackable spawn 不受支持。
- ConsumerTx handler 由 postgres adapter 构造，外部 crate 不得构造或逃逸 `TxCapability`。
  handler、outcome、runner 与 worker spawn 归 runtime assembly 私有。
- 结算规则：`handler_transient` 耗尽后只 broker `Requeue`，不写 app DLX、不提交 inbox done、不 Ack；
  `commit_unknown` / lease lost 立即 `Requeue`；只有永久 `Reject` 可写 app DLX 后 Ack。
  Duplicate delivery 不进入 tx handler，直接 Ack。
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
| claim 永久错误 | 不 commit | `Reject` |
| 租约丢失 | cancel handler，不 commit | `Requeue` |
| `Duplicate` | 跳过 handler | `Ack` |
| 幂等键 malformed | 不 commit | `Reject` |
| 未知状态 | 不 commit / 不 release | `Requeue` |

崩溃安全：settle 前崩溃由 broker 自动 requeue，重投经幂等 claim 去重，达成 at-least-once。

## 订阅注册

- 订阅单源是域 crate 的 `Cargo.toml [dependencies]` 加 `contract.toml` 声明；codegen 派生注册代码，
  业务不手写平行 registry。订阅必须同时绑定 `ContractId`、`DomainId` 与 consumer group。
- 域 crate 的 `Domain::init` 只从 per-contract generated `SPEC.subscriptions()` 读取声明并注册 handler。
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
- operator CLI 全部命令必须带 operator service token、operator tenant 与目标 tenant；授权由 PDP 验证 +
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
- event authoring 与 command authoring 完全分离：公开 event 写面拒绝 command namespace，
  relay 读回类型不能转换回 event producer API。
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
- **串行有序门禁**：harness 构造必填 DLQ store 与一枚串行有序 witness，非串行投递路径拿不到 witness，
  编译期即挂不上 projection。witness 只能由声明串行有序的 source 铸造，铸造资格由 dylint allowlist 守。
- outbox 派生投影的 durable journal 只由 outbox writer funnel 写入，且仅当 outbox 行新插入并命中 generated
  projection registry 时才在同一事务内镜像。registry 不提供 raw string topic 注册 API。
- journal 读写只经固定 `SECURITY DEFINER` 函数；serving role 只拿函数 EXECUTE，不持表级 DML 权限。
  append 函数要求参数与同事务可见 outbox row 完全匹配，防止直接 SQL 绕过 Rust funnel。
- harness 默认对 `Permanent` / `Invariant` / `OutOfOrder` 写 DLQ 后停当前 projection，不自动 skip；
  `Transient` 不写 DLQ；DLQ 写失败不推进 checkpoint。
- 只有显式 poison policy 才允许跳过 `Permanent`，且必须先写 DLQ 成功再用 checkpoint CAS 推进；
  `Invariant` / `OutOfOrder` 不允许自动 skip。checkpoint 保存必须拒绝 offset regression。
- append-only 主守卫是 serving role 的引擎权限与固定函数面（Hard）；代码层字面量与直接 callsite
  另由 verify guard（Medium）补强。
- 载体：`INVARIANT: PROJECTION-SERIAL-WITNESS-01` / `PARTITION-SERIAL-IMPL-ALLOWLIST-01`。

## 命名与 payload

- stream / topic / command key 使用稳定 dotted 名称。
- event payload 是 JSON object，字段 camelCase。
- event metadata 的 trace、request、principal 信息由 outbox envelope 注入，业务不伪造 reserved metadata key。
