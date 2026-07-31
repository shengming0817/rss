# 可观测性规范

本文件只写约束与失败语义。metric / label / 字段的完整目录属于对应 crate 的 rustdoc 与
`docs/ops/*.rules.yaml`，本文件不复制，也不作为任何机器门的 carrier。

## 日志

| Level | 使用场景 |
|-------|----------|
| Error | 正确性、安全或持久化失败 |
| Warn | 降级运行、可恢复重试 / 重试预算耗尽 |
| Info | 生命周期、迁移、consumer 加入 |
| Debug | 本地诊断，生产默认关闭 |

- 日志使用 `tracing`，结构化字段 + span；禁止 Debug dump 完整请求、响应或 payload。
- 错误日志必须带与当前上下文匹配的结构化定位字段，敏感值必须先清洗。
- request / tenant / domain / correlation 在对应上下文存在时必须透传；启动期、全局错误与工具路径
  使用 service / component / operation / error 等可定位字段。

## Redaction

> **作用面 = observe-time**。本节只把明文挡在 Debug / 日志 / trace / `last_error` 等输出面之外，
> 不是静态存储加密。at-rest 字段加密是独立关注点，设计单源见 ADR-011。
> redaction ≠ encryption：脱敏过的值仍可能明文落库，加密的值在 Debug 面仍不解密。

- span error、span string attribute、tracing subscriber 敏感字段与持久化 `last_error` 都必须
  fail-closed redaction，且统一收口到 `secure` crate，不得存在第二条清洗路径。
- 带脱敏声明的值进入任何输出面前必须经 `secure` 的字段级输出入口按**声明的字段策略**渲染。
  字段声明优先于 key 猜测：值在变成字符串之前已脱敏，exporter 的 key-sweep 只是兜底。
- 输出通道必须显式区分受信进程内诊断与外部不可信 sink；后者对部分泄露 mode 必须塌缩为完全脱敏。
- `last_error` 只能经 sealed 安全载体构造——未经脱敏的 `last_error` 不可构造、不可持久化（类型层 Hard）。
- 敏感度必须逐字段显式声明且只能声明一个。字段缺标注、重复声明、未知取值、非 public 字段声明明文
  展示、或任意字段声明散列 mode，均为编译错误（Hard）。关联令牌必须显式传入 HMAC key。
- 没有业务 opt-out。需要原始诊断时走受控服务端日志，不写入 trace 或 wire。
- 跨边界 wire DTO 的字段策略不在消费侧手写：由 contract schema 的声明面经 `cargo xtask codegen` 派生。
  `contract validate` 对遗留声明、未知枚举、高风险字段未声明 fail-closed；`contract breaking`
  对既有字段策略漂移报错。
- observe 面的脱敏声明与 at-rest 的保护声明是两条正交声明面，不混用、不互相替代。
- errcode 的 Message / Public Details / Internal Details 三层分工见 `docs/rules/error-handling.md`。

## Readyz Probe

- 依赖可用性 probe 用 `_ready` 后缀；运行时操作 probe 不带 `_ready`。
- saga worker probe 是运行时操作 probe，禁止按 tenant / saga_id / step 生成高基数 probe。
- probe 名是运维契约，改名必须同步运维文档、tests、dashboard、alert。
- 域 crate repo readiness 由域 crate 边界显式注册，禁止静默吞掉缺失 repo。
- remote peer readiness 只探测 resolved endpoint 的 TCP 可达性，不反向调用对端 `/readyz`；
  peer 不可达只影响 readiness，不影响 liveness。
- verbose readyz 分 wire 响应、server log、trace、metrics 四通道：wire 必须裁剪敏感 error，
  server log 是主诊断通道，trace 默认跳过 health endpoint。

## Metrics Label

这是所有 metric 共同的纪律，各 metric 的具体值集以 emit 侧 crate 的闭枚举 `as_label()` 为单一事实源。

- 每个 label 的值集必须冻结或经 typed enum 入口产出；禁止业务代码手写裸 string label。
- 闭值集必须由 emit 侧 crate 自有的 `as_label()` 闭映射产生，不得在第二个 crate 复制副本。
  同名 label key 出现在不同 metric 时不共享值集，必须用 metric 名限定语义。
- 高基数输入不得进入 label：tenant 业务 id、实体 id、key、SQL、payload、错误文本、duration、
  timestamp、token 与任意请求输入一律禁止。需要定位具体实例时走受控日志或 store 查询。
- label 不得从 duration、error text 或 adapter 原因推导；必须由 typed outcome 直接映射。
- 新增或改名 metric / label 必须同步 schema、tests、dashboard、对应 `docs/ops/*.rules.yaml` 与 emit site。

已知的**有界例外**，不外推到其它 metric：

- HTTP / gRPC 的 `domain` label 与 outbox relay 的 `domain` label 来自 assembly 或 provider 在声明期
  绑定的 closed set，非请求派生，基数有界。缺失、未知、越界必须归入固定 fallback 或 fail-fast。
- outbox 可观测路由维度允许 `contract_id` 与 `tenant_id` 入 label，前提是二者分别经 canonical
  grammar 校验与 typed `vocab::TenantId` 取得。跨域 transport metric 不适用该例外。
- gRPC 中间件顺序必须保证 domain attribution 在 metrics 与 access log 之前完成。

正交性要求：

- retry-engine 指标与 contract-attributed 指标是两组正交信号，禁止从其中一组反推另一组的结算结果；
  同理不得从 deadline stage 反推 commit / rollback 结果。
- 未开始事务、未获得真实结算的 attempt 不得伪造终态；已观测到的真实结算不得被后续未结算 attempt 擦除。
- 强制不可重试的终态必须发 warn，普通 attempt 只发 debug。
- 连接隔离信号与事务结算正交：可能没有结算状态，但必须以私有闭阶段发射并结构化 WARN，
  且不得据此伪造 transaction final status。
- backlog gauge 查询失败必须写 `NaN` 并把 tick 记为 transient，不得把 stale sample 或缺失 series 当作 0。
  从未观测过的 scope 不造假 label。
- 每个 attempt 恰好发射一次终态 metric；success / error / panic 三条分支都必须经 typed 映射入口。

告警面纪律：

- 告警是运维响应面：transient 降级不得为了摘流被伪报为 Unhealthy。
- 只有需要人工核实真实数据库状态的终态才是 actionable page；诊断计数器保持 dashboard/trace 信号，
  不新增 paging alert，也不建立第二套 dashboard/runbook truth。

## Cross-domain Transport

- 跨域同步 contract 调用的 metric 由统一 instrumented seam 在每次 dispatch 结算时发射，
  成功与失败路径都必须记录 outcome；错误细节不进入 label。
- 目标 domain 与 `contract_id` 不入 transport metric label，只进 dispatch span。
- dispatch span 只记录路由元数据；path / headers / body 必须经字段策略脱敏，不得明文进入 Debug 或 span 字段。
- 契约身份经 typed `vocab::ContractBinding` 单源绑定。
- caller-supplied header 经 fail-closed 白名单（仅诊断 / trace-context 头），拒绝 `authorization`、
  `cookie`、`x-tenant-id` 等；认证、租户与服务凭据由 adapter 从已认证信道铸造，不经此 seam。
- remote adapter 只实现同一 transport trait，不另建一套指标标签。

## Redis Namespace

- Redis key namespace 使用 owner 维度表达：domain、role、resource。禁止把 service token、outbox、
  projection 等跨域 key 混入 `_runtime` 前缀而丢失所有权。
- `_runtime` 只用于框架级、无 domain 上下文的 shared-infra 原语。
- 新增 `_runtime` 原语时，key 格式必须与既有格式**结构性互斥**并在对应 adapter rustdoc 登记；
  否则使用显式 role/resource namespace。
- 任何 opaque 段（允许冒号的 tenant / group / key）必须以字节长度前缀单射封边，禁止裸冒号拼接。

## Outbox Envelope

- same-fact 冲突判定的 canonical fingerprint 只用于存储边界比较，不是诊断标识。fingerprint、payload、
  partition key、causation id 与 stable metadata 的值均不得进入 Debug/Display/error/log/trace/metrics；
  冲突只暴露低基数静态分类。
- `occurredAt` / `trace` / `correlation` 是可重试漂移的观测字段，不参与事实 fingerprint。
- reserved envelope 字段只由 adapter 在受控构造点经 sealed metadata funnel 注入：
  - `occurredAt` 取注入的 `Clock`，为 producer 端事件发生时刻。
  - `schemaVersion` / `schemaHash` 取 generated `CONTRACT` 并同源写入 outbox 物理列；
    relay 以物理列覆盖 metadata header，缺失或非法时 DB 约束与 typed header 转换 fail-closed。
  - `correlation` 走独立可读诊断信道（非授权信道）fail-open 读回。跨服务贯通要求调用方携带
    `X-Correlation-ID`（受限字符集、有长度上限）；缺失时服务生成 UUID 保底，但链路不贯通。
  - `trace` 从当前 span 导出 W3C traceparent，consumer 侧还原 remote parent。fail-open：
    无 otel 层、未采样或畸形 traceparent 一律省略，绝不阻投递。
- `subjectId` / `principal` / `actor` / `causation_id` 是 persisted-only。完整 `Principal`、email、姓名、
  token 等 PII 不得进入 metadata，也永不进入 broker header，不能作为 broker-visible auth source。
- broker-visible metadata 只能来自 transport header allowlist；persisted metadata 不回填 broker header。
- relay 在 provider 内部重建 envelope 后携入发布请求；lease、metadata 原值与 durable signing context
  保持 provider-private，跨 crate 调用方只能借出 typed metric subject。
- publish 前的 lease budget preflight、budget 上限与 deadline 语义见 `eventbus.md` §Outbox relay 投递语义。
  timeout / confirm / settle 的不确定结果仍可能已经 delivery，后续按稳定身份重试。
- timeout 与 publisher 失败日志只允许低基数 phase、预算值与闭值 reason；禁止 URL、payload、metadata、
  tenant authority、token 与原始错误链。日志不得据 ambiguous 结果宣称消息未送达。
- **Tenant authority token**：relay 发布前在 reserved metadata 写入签名 token，consumer 写 app DLX 前
  必须验签并校验 issuer/audience、TTL、topic、contract、message id 与 tenant 绑定；任一不匹配时
  不信任 metadata `tenantId`、不写 app DLX，释放 claim 后 broker `Reject` 并计数。
  不保留 unsigned metadata tenant 兼容路径。
- 契约归属由 typed `vocab::ContractBinding` 单源承载，四字段同源一份 `contract.toml` + declared schema
  bundle，经 codegen 派生并由 golden 锁字节。contract 归属、tenant scope、subject、actor 都不从裸 string
  或 payload 重新派生。
- `partition_key` 是同租户内的不透明 aggregate 路由键，落 outbox 列而非 metadata。
  它可能含凭据级标识，故 `Debug` 必须脱敏（仅 presence 可见）；定位 stalled partition 走受控 DB 查询。

两类 Hard 保证：

- **producer 不可漏接** `occurredAt` / `schemaVersion` / `schemaHash` / subject / actor：全部由 funnel
  构造器的必填位置参承载，新增 outbox producer 缺任一项即编译错误。
- **业务不可伪造 reserved key**：producer 侧与 wire 侧的业务写入路径都对 reserved key 集 fail-closed；
  reserved-capable 透传写面只允许 relay / subscriber 从已 sealed 来源 rehydrate，调用站点由 dylint 限制。
  真正的 Hard 锚点在 emit 层——域只经无 reserved 槽的 emitter 入参发事件，永不构造 wire envelope。
- 载体：`INVARIANT: OUTBOX-METADATA-FUNNEL-01` / `DIPORT-ENVELOPE-WIRE-WRITER-01`。
  契约归属 `CONTRACT-BINDING-FUNNEL-01` 是 Medium 而非 Hard：`from_static` 必须保持公开 const fn 供
  generated 跨 crate 发射常量，跨 crate sealing 在基础层不可 Hard 强制。

## Audit

- audit payload 中的 replayable PII 必须经 keyed HMAC 关联令牌或 redaction。
- trace 反查复用标准分页入口，不新增后门 endpoint。
- 审计字段写入位置由类型系统与 sealed 写入入口守卫。
