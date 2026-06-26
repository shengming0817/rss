# 可观测性规范

## 日志

| Level | 使用场景 |
|-------|----------|
| Error | 正确性、安全或持久化失败 |
| Warn | 降级运行、重试预算耗尽 |
| Info | 生命周期、迁移、consumer 加入 |
| Debug | 本地诊断，生产默认关闭 |

日志使用 `tracing`（结构化字段 + span）。禁止 Debug dump 完整请求、响应或 payload。
错误日志必须带与当前上下文匹配的结构化定位字段，敏感值必须先清洗。
request、tenant、domain、correlation 在对应上下文存在时必须透传；启动期、
全局错误和工具路径使用 service、component、operation、error 等可定位字段。

## Redaction

errcode 的 Message、Public Details、Internal Details 三层分工见 `.claude/rules/rss/error-handling.md` §Message 与 PII。

trace span、tracing sink 和持久化 `last_error` 都必须 fail-closed redaction：

- span error 统一走 `secure::redact_error`。
- span string attribute 先按 key 判敏感，再做 free-form scrub。
- tracing subscriber 对敏感 field 做统一清洗。
- `last_error` 持久化走同一 `secure` crate（redaction 模块）。

没有业务 opt-out。需要原始诊断时走受控服务端日志，不写入 trace 或 wire。

## Readyz Probe

- 依赖可用性 probe 用 `_ready` 后缀。
- 运行时操作 probe 不带 `_ready`。
- probe 名是运维契约，改名必须同步运维文档、tests、dashboard、alert。
- 域 crate repo readiness 由域 crate 边界显式注册，禁止静默吞掉缺失 repo。
- remote peer readiness 只探测 resolved endpoint 的 TCP 可达性，不反向调用对端 `/readyz`。
- peer 不可达只影响 readiness，不影响 liveness。

verbose readyz 输出分 wire 响应、server log、trace、metrics 四通道。wire 必须裁剪敏感
error；server log 是主诊断通道；trace 默认跳过 health endpoint。

## Metrics Label

metric label 值集必须冻结或经 typed enum 入口。新增 label value 同步更新 schema、
tests 和运维文档。高 cardinality 输入不能直接进入 label。

### HTTP Metrics domain Label

HTTP Metrics `domain` Label 与 gRPC metrics 的 `domain` label 必须来自 assembly 声明的
closed set。缺失、未知、越界归 `_runtime` 或 fail-fast，具体由 sealed resolver 定义。
禁止业务代码手写裸 string label。

gRPC unary 和 stream 中间件（tower layer）顺序必须保证 domain attribution 在 metrics 和
access log 之前完成。

### Reconcile Metrics result Label

`reconcile_total{result}` 的 result 值集必须闭合；新增或改名必须同步 schema、
tests、dashboard、alert 与 emit site。

### HTTP Idempotency state Label

`idempotency_requests_total{state}` 的 state 值集必须闭合；新增或改名必须同步 schema、
tests、dashboard、alert 与 middleware emit site。

### Outbox Relay Metrics（#1209）

outbox relay/sampler 发射下列 metric（bare 名，emit site = `eventexec` 注入式 `OutboxMetrics` 端口，
生产实现 `MetricsOutboxMetrics` 经 `metrics` facade）：

| metric | 类型 | label | 语义 |
|--------|------|-------|------|
| `outbox_publish_total` | Counter | `domain`,`status` | relay 单条结算（status=ack/requeue/reject） |
| `outbox_dlx_total` | Counter | `domain` | 永久失败进 DLX（= status=reject） |
| `outbox_pending_depth` | Gauge | `domain` | pending 且到期行数（采样器） |
| `outbox_oldest_pending_age_seconds` | Gauge | `domain` | 最老 pending 龄；无 pending ⇒ 0（非缺失） |
| `outbox_relay_tick_duration_seconds` | Histogram | `phase` | relay tick 耗时（phase=poll/publish；settle 并入 publish，见 §settle 相说明） |

label 闭值集纪律：

- `status` 值集闭合于 `consistency::Disposition::as_label()`（`ack`/`requeue`/`reject`）；**不**经
  `observ::EventLabel`（其 `DispositionLabel` 为 `Ack`/`Nack`/`Requeue`，与 outbox 的 `Reject` 语义不符）。
  `phase` 闭合于 `eventexec::RelayPhase::as_label()`（`poll`/`publish`）。两者均 crate 自有 `as_label()`
  闭映射——单源、无副本可漂移。
- `domain` label 值来自 `RelayConfig` 构造期校验的 domain 集（数量 ≤64 + canonical 标识格式，
  非请求/租户派生），基数有界，是 §HTTP Metrics domain Label 同款「assembly/config 声明 closed set」的
  合法低基数用法。`eventexec`（Service 层）依层矩阵不能依赖 `observ`，故这些 label 暂不经 `observ`
  typed enum 入口；把 outbox label 收敛进 `observ` 词表（供 otel 映射统一）是 **#1076** 后续项。

新增或改名上述 metric / label 必须同步 schema、tests、dashboard、`docs/ops/outbox-relay-alerts.rules.yaml`
与 emit site。

### Consumer Settle Metrics（#1142）

at-least-once consumer（`eventexec::run_consumer_ackable`）每次向 broker 结算投递发射：

| metric | 类型 | label | 语义 |
|--------|------|-------|------|
| `consumer_settle_total` | Counter | `domain`,`action`,`outcome` | 单条 broker 结算（action=ack/requeue/reject；outcome=ok/error） |

label 闭值集纪律：

- `action` 闭合于 `diport::AckAction::as_label()`（`ack`/`requeue`/`reject`）；`outcome` 闭合于
  `ok`/`error`（settle 调用是否成功）——crate 自有闭映射，无副本可漂移。
- `domain` 来自 `eventexec::ConsumerMeta`（注册期绑定的 domain/contract/topic 三元组），非请求/租户派生，基数有界。
- emit site = `eventexec::consumer::settle`（minimal 直发 `metrics` facade，无 recorder 即 no-op）；告警面 =
  `outcome="error"`（结算失败）。注入式 `ConsumerMetrics` 端口（与 `OutboxMetrics` 同形、组合根注入、成功/失败
  统一）属重构，随 consumer worker 生命周期落地（**#1301**）。`run_consumer`（brokerless / auto-ack）无 broker
  结算 ⇒ 不发本 metric。

adapter、webhook、MQTT 等 metrics 也遵守同一 label 闭值集规则。

## Cross-domain Transport

跨域同步 HTTP contract 调用经 `distributed` 的 transport seam（`DomainTransport` trait）时，
必须记录：

- `transport_mode`：仅允许 `in_proc`、`remote`。
- `outcome`：每次分发都记录，不能只记录成功路径。

`transport_mode` 与 `outcome` 都必须通过 sealed typed value 表达。metric label 保持低基数；
超出闭值集的错误细节只写 trace span，不进入 metric label。

remote 调用的 metrics 和 tracer 必须同源注入。共享依赖里的 tracer 缺失（`Option::None`）时统一降级
NoopTracer——构造器以 typed 形态传入，从类型层杜绝 remote span start 边界裸判空。

## Redis Namespace

Redis key namespace 使用 owner 维度表达：domain、role、resource。禁止把 service token、
outbox、projection 等跨域 key 混入 `_runtime` 前缀而丢失所有权。

`_runtime` 只用于框架级、无 domain 上下文的 shared-infra 原语。当前允许：

- outbox 消费幂等 claimer（两阶段 lease/done）：`_runtime:{eventID}:lease|done`
- 通用幂等 claimer（`consistency::IdempotencyStore`，`adapters/redis`）：`_runtime:idem:<glen>:<group>:<idemKey>`——claimed value=lease token（带 TTL）/ done value=哨兵（无 TTL，永久去重）；`SET NX PX` claim + Lua CAS extend/commit/release。固定字面 `idem` 第二段与上下两条（第二段为 UUID 形 `{eventID}`/`<tenant>`）**结构互斥**。`ConsumerGroup`/`IdemKey` 均 opaque（允许冒号），故 **group 段以字节长度 `<glen>` 前缀单射封边**——杜绝 `(group,key)` 裸冒号拼接碰撞（#279 review F3；旧 `<group>:<idemKey>` 直接拼接不安全）
- HTTP 幂等 store：`_runtime:<tenant>:{key}:resp|lease|fp`

新增 shared-infra 原语若使用 `_runtime`，key 格式必须与既有格式结构性互斥，并在本节登记。
否则使用显式 role/resource namespace。

## Outbox Envelope

trace、correlation、principal、occurred_at 等 reserved envelope 字段由 **adapter 在受控构造点经
sealed metadata funnel 注入**（`occurred_at` 取注入的 `Clock`，producer 端事件发生时刻；同 crate 时间编码
单源）。`consistency::Entry` 只持业务三字段（topic / idem_key / payload），envelope 不落引擎类型（`Clock`
在 `diport`，`consistency` 不可依赖之）。当前 `occurred_at` 已接线；`trace` / `correlation` 的 **sealed 注入
路径已建**（`OutboxMetadata::with_trace` / `with_correlation` funnel 特权 setter，#1193），但注入**源**
（observ trace span / correlation 上下文）按 ADR-002 §D1 刻意不进 `runctx`，待 #1296 接线——故 setter 暂无
生产 caller；principal 为 typed-but-empty 接缝（待 authn principal 接线，#1296）。

envelope 的**契约归属**（`domain` + `contract_id` 路由列）由 **typed `vocab::ContractBinding`** 承载（#1193）：
两字段同源一份 `contract.toml`，经 `cargo xtask codegen` 派生为 `generated::event::{domain}_v1::CONTRACT`
（golden 字节锁）；producer 经 `OutboxEnvelopeParts::new(CONTRACT, subject)` 传入。domain + contract_id 收进
**单一绑定值**，故二者之间无法漂移；`OutboxEnvelopeParts` 字段私有（input-struct-field-exclusion，Hard）。

两类 Hard 保证：

- **producer 不可漏接** `occurred_at`：由 metadata funnel 的构造器 `OutboxMetadata::new(occurred_at)`
  **必填位置参**承载——「无 occurred_at 的 outbox metadata」类型层不可表达，新增 outbox producer 必须从注入
  `Clock` 提供（缺失即编译错误）。三条生产构造点（`PgEmitter` / `PgSessionLifecycle` / `PgConfigRepo`）同源。
- **业务不可伪造** reserved key：业务 free-form 写入路径（`OutboxMetadata::try_insert`）对 reserved key 集
  fail-closed 拒；reserved key（含 trace / correlation）只经 funnel 内 sealed setter 写入，不经任何业务可见
  入口（INVARIANT OUTBOX-METADATA-FUNNEL-01）。

契约归属（`CONTRACT-BINDING-FUNNEL-01`）是 **Medium，非 Hard**：golden 锁（`codegen --check`）只保证 generated
`CONTRACT` 常量正确、不漂移；`vocab::ContractBinding::from_static` 是普通 `pub` 构造器，业务 crate **仍可裸构造**
任意绑定（residual，跨 crate sealing 在 vocab 基础层不可 Hard 强制，同 `ContractOwner::of_domain` #1091）。「业务
只用 generated `CONTRACT`、不伪造」当前靠约定 + golden；统一机器守卫见 **#1327**。

## Audit

audit payload 中的 replayable PII 必须 hash 或 redaction。trace 反查复用 auditquery
标准分页入口，不新增后门 endpoint。审计字段写入位置由类型系统 / sealed 写入入口守卫，
规则文件只保留约束摘要。
