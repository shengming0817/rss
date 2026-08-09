# contracts/ — 跨边界契约声明源（格式冻结）

> 单一事实源：`docs/rules/architecture.md` §核心载体。本文件只**冻结目录布局 + 文件名 + 字段集**，
> 语义规则（鉴权 / 扇出）不在此复制，见 `docs/rules/contract-fanout.md`。
> 由后续 G1/W/Join 单元在此格式上增量加真实域契约；本单元（RW-G0.3）冻结格式并搭起 codegen 管道。

## 布局（冻结）

```
contracts/{kind}/{domain}/{version}/
  ├── contract.toml          # 元数据
  ├── request.schema.json    # http / command
  ├── response.schema.json   # http
  ├── payload.schema.json    # event / saga
  └── projection.schema.json # projection
```

- `kind` ∈ `http` | `event` | `command` | `saga` | `projection`
- `domain`：合法值 = 域 crate 名，或 `_` 前缀保留段（如 `_seed`）。**注意**：`domain` 是目录段，与契约归属无关。
- `owner`：合法值 = 域名（如 `identity`），或 `_framework` sentinel（provider-agnostic 中立契约，不绑定 domain 目录）。`_framework` 是 owner 字段的保留值，**不对应任何目录段**。
- `version` = `v{N}`

## contract.toml 字段（冻结，`#[serde(deny_unknown_fields)]`）

| 字段 | 取值 | 必填 |
|------|------|------|
| `id` | 点分小写名（段 `[a-z][a-z0-9-]*`，如 `seed.echo`、`config.entry-upserted`）；**跨契约全局唯一**（R12） | 是 |
| `kind` | `http`/`event`/`command`/`saga`/`projection` | 是 |
| `domain` | 域名或 `_` 前缀保留段 | 是 |
| `version` | `v{N}` | 是 |
| `owner` | 域名 或 `_framework`（provider-agnostic 中立契约归框架） | 是 |
| `consistencyLevel` | `LocalOnly`/`LocalTx`/`OutboxFact`/`WorkflowEventual`/`DeviceLatent`（L0–L4）；active HTTP codegen 同源派生为 `HttpSpec::consistency_level` | 是 |
| `lifecycle` | `draft`/`active`/`deprecated`（`active` 才需 assembly 接线，见 contract-fanout.md） | 是 |
| `[effectProfile]` | HTTP effect 声明 carrier：`effects = [...]`，闭值集为 `read`/`auth`/`projection`/`business-write`/`business-transaction`/`outbox`/`publish`/`workflow`/`saga`/`reconcile`/`worker`/`cross-tenant-audit`；未知字段、未知 effect 解析即拒。LocalOnly 仍只允许 `auth`/`read`/`projection`；business-qualified 名称只描述业务副作用，不排除 provider-owned read-path transaction | `kind=http` 必填（R22，不按 lifecycle 豁免）；非 HTTP 禁止；`effects` 必须非空且无重复 |
| `[capabilities.localTx]` | L1 本地事务证据：`boundary = "single-domain"`、`txModel` 为 `tenant-scoped-uow` 或 `repo-atomic-cas`、`retry = "bounded-transient"`、`commitUnknown = "not-retryable"` | `consistencyLevel=LocalTx` 必填（R22）；其它等级禁止 stray block；旧 boundary-only 形态不再接受。UoW 模型承载显式事务生命周期；repo CAS 模型由单次 repository mutation 原子比较并写入 |
| `[capabilities.outbox]` | L2 outbox 证据：`role = "fact"`（event）/`"command"`（command）/`"producer"`（http）。producer 还必须声明 `atomicity = "same-transaction"` 与非空 `emits = ["<event-contract-id>"]`；fact/command 禁止 producer-only `atomicity`/`emits` | `consistencyLevel=OutboxFact` 必填（R22）；HTTP producer 的每个 `emits` 在 **draft/active/deprecated 全 lifecycle** 都必须指向存在的同 domain L2 event，lifecycle 不构成跨域豁免；active HTTP producer 另要求目标 event 为 active 且声明 subscriber readiness。权威语义见 [`eventbus.md` §L2 producer-fact domain closure](../docs/rules/eventbus.md#l2-producer-fact-domain-closure) |
| `[capabilities.workflow]` | L3 workflow 证据：`mode = "saga"` 或 `"projection"`。`saga` 需 `kind=saga` 且有 `[saga]`，并禁止 projection-only 字段；`projection` 只能由 `kind=projection` 承载，须声明 `inputs`、`ordering`、`checkpoint`、`replay`，且 `inputs` 指向存在的 L2 event | `consistencyLevel=WorkflowEventual` 必填（R22）；`kind=projection` 与 `mode=projection` 双向绑定 |
| `[capabilities.deviceLatent]` | L4 通用 envelope：`loop = "reconcile"`；resource-specific metadata 进入 tagged `[capabilities.deviceLatent.profile]`，由 `resourceKind` 选择 profile。`device-certificate` profile 的四个 links 位于 `[capabilities.deviceLatent.profile.links]` | `consistencyLevel=DeviceLatent` 必填（R22）；其它等级禁止 stray block；typed profile parse 拒缺字段、未知字段和未知 resource kind，设备证书契约的精确 linked ID/lifecycle 闭包由 R25 强制 |
| `[reconcile]` | L4 reconcile block：`tenancy = "single-tenant"|"tenant-scoped"`、`trigger = "interval"`、`fencing = "required"|"single-process"`、`lateMessagePolicy = "idempotent"` | `consistencyLevel=DeviceLatent` 必填（R22）；非 L4 禁止声明 |
| `[schemas]` | `request`/`response`/`payload`/`projection` → schema 文件名；多响应 HTTP contract 使用 `[schemas.responses]` 以状态码映射 schema，且不得同时保留 legacy `response`。存在非成功状态时，codegen 派生每个 DTO 的 status binding、闭合业务错误 carrier、完整 response envelope、闭合 framework failure、`HandlerResult` 和 declared-response route marker；挂载点据此精确校验普通或 producer handler future 输出。固定错误 schema 仅暴露 request-id factory。breaking projection 以 `response:<status>` slot 跟踪。http 需 `request`+成功响应，event/saga 需 `payload`，command 需 `request`；projection **只能**声明单一 `projection` slot，禁止 request/response/payload/responses | 按 kind（R4） |
| `path` | http 业务路径（`/api/v{N}/{domain}/…` 约定，如 `/api/v1/_seed/echo`；形态安全由 R7 守：绝对、非 `//`、无 `..`/空白） | 按 kind（active http 必填，R8） |
| `method` | http 方法 `GET`/`POST`/`PUT`/`PATCH`/`DELETE`（闭值集，非法即解析 `Err`） | 按 kind（active http 必填，R8） |
| `[endpoints.http]` | HTTP wire 语义 carrier：`successStatus = <200..299>` 与 `idempotency = "idempotent" \| "non-idempotent"`；状态码由 typed `HttpSuccessStatus` 在 codegen/binding 漏斗中再校验，幂等性是闭枚举 | 所有 `kind=http` 必填，无默认值或兼容路径 |
| `[endpoints.http.auth]` | active http serving 鉴权声明：`mode = "permission"`（`permission` 必须精确匹配 `vocab::RoutePermissionId` 闭值集成员，禁止前后空白，且禁止 `reason`）或显式 opt-out `public`/`bootstrap`/`clientsOnly`/`serviceOwned`（需非空 `reason`，禁止 `permission`）。未知子键解析即拒 | active http 必填（R18；validate 与 codegen 均 fail-closed；catalog 规则见 `docs/rules/tenancy.md`） |
| `[endpoints.http.resourceSharing]` | HTTP resource sharing 声明：未声明等同 `mode = "tenantScoped"`；显式 `mode = "global"` 必须带非空 `reason` 且 endpoint 必须声明 `endpoints.http.resource`。`tenantScoped` 禁止 `reason`。未知子键解析即拒。global route 是 shared/global resource opt-out，不读全局 resource attribute 表，也不允许 dynamic `resource.*` policy 条件 | 按 endpoint（默认 tenant-scoped；global opt-out 由 R18 校验并进入 codegen） |
| `[endpoints.http.headers]` | HTTP header 声明；当前最小闭值集仅接受 `"X-Tenant-ID" = "populate-only"`（public/pre-auth 填充）或 `"service-token-tenant-bound"`（serviceOwned：exact-one challenger header；ambient tenant 来自 signed canonical `tenant_id` claim，名称保留但不再表示 MAC extension） | 按 endpoint（`identity.login` public serving 必填，serviceOwned 必填 tenant-bound，R18） |
| `[endpoints.http.projection]` | HTTP field projection 声明；`fields = [{ field = "auditActor", permission = "...", obligationKey = "...", responsePath = "data[].actor" }]`。`field` 是闭值集（当前 audit read + identity profile projection fields），`permission` 必须精确匹配 `vocab::RoutePermissionId` 闭值集成员、禁止前后空白；`permission` / `obligationKey` / `responsePath` 必须非空且不重复。active GET response 中的 `x-pii` 字段与 `tenantId` 字段必须由 `responsePath` 精确覆盖；codegen 派生 typed `HttpProjectionFieldSpec`，handler/authorizer 只消费 `vocab::ProjectionField` / `vocab::RoutePermissionId` | 按 endpoint（R23：protected read response field 必须 enrollment） |
| `topic` | event 或 command 稳定 dotted topic 名（event 如 `seed.thing-happened`，command 如 `device.commands.reboot`；点分小写形态由 R7 守，同 `id`） | 按 kind（active event 必填，R8；active command 必填，R8） |
| `delivery` | event 投递语义 `at-least-once`/`at-most-once`/`exactly-once`（闭值集）。**当前实现路径仅 `at-least-once`**（outbox + 幂等消费者）；`at-most-once`/`exactly-once` 为前瞻保留值（broker 链路无运行时保证），**active event 经 R11 机器拒**（仅放行 at-least-once），draft/deprecated 可表达前瞻设计 | 按 kind（active event 必填，R8；值由 R11 限） |
| `[saga]` + `[saga.retry]` | saga 专属 block（TOML 键名 **camelCase**）。每个有序 step 必填 `name`、`receiptSchema`、`effectScope`、`compensationEffectScope`、`idempotencyClass = "deterministic-key"`、`compensationInput = "receipt"`、`retryClass = "never" \| "transient"`；`compensationOrder = "reverse"`。retry block 必填 `maxAttempts`、`timeBudgetMillis`、`backoff = "fixed" \| "exponential"`、`initialBackoffMillis`、`maxBackoffMillis`、`jitter = "none" \| "full"`。codegen 派生 sealed definition/step/receipt marker、typestate cursor、typed receipt DTO、完整 policy 与 `ACTION_REGISTRY_GENERATION`；factory builder 不接收 raw spec，只有注册到 generated `End` 才能 `finish()`。无 optional/pure/legacy 分支 | **kind=saga 必填（R10，无条件、不论 lifecycle）**；良构 R10 |
| `[[subscriptions]]` + `[subscriptions.topology]` | event 订阅拓扑声明（#1120/#1438/#1822/#1824，TOML 数组）：每项须含 `consumer`、`group`、typed topology、`execution = "adapter-native" \| "domain-effect"` 与闭合 `externalEffectPolicy = "transactional-only" \| "idempotency-key" \| "reconcile" \| "compensated"`；无默认/alias。唯一 Rust policy 类型为 `vocab::ExternalEffectPolicy`，codegen 直接写入 `SubscriptionSpec`，generated 不复制/re-export 第二个枚举。当前可激活矩阵只接受 `adapter-native + 无 effect + transactional-only`，或 `domain-effect + settings-config-version-refresh + reconcile`；注册 capability、runtime plan、postgres handler 与 eventexec executor 必须携带同一 policy。`idempotency-key`/`compensated` 没有生产 capability/executor，active 声明必须 fail closed。 | **`lifecycle=active && kind=event` 必须非空（R14）**；声明 subscription 即必须声明 policy；同一 event 的全部 subscription 必须使用同一个 `partitionKey`；draft/deprecated 可通过不声明 subscription 保持未激活 |
| `[command]` | command 持久化策略，`journal` 闭值为 `required` 或 `none`。无默认值；codegen 分别只生成 `journal_async` 或 `emit_async`，两者不会同时出现。 | **所有 command 必填，所有非 command 禁止（R24）** |

校验规则（`cargo xtask contract validate`）：

<!-- @generated:contract-governance:start -->
校验规则由 `Contract Governance IR` 单向投影；编号是稳定身份，handler/owner/source 与文档在同一 catalog 条目绑定。

| ID | Rule | Owner | Source | 说明 |
|---|---|---|---|---|
| R1 | `SagaConsistency` | `contract` | `manifest` | Saga 契约的 consistencyLevel 必须为 WorkflowEventual |
| R15 | `CommandConsistency` | `contract` | `manifest` | 期望 kind=command 的 consistencyLevel=OutboxFact；拒绝任何使用其他 consistencyLevel 的 Command 契约 |
| R24 | `CommandPolicy` | `contract` | `manifest` | kind=command 当且仅当声明完整 [command] journal policy |
| R2 | `FrameworkKind` | `contract` | `manifest` | owner=_framework 仅可用于 framework 允许的契约 kind |
| R3 | `PathMismatch` | `contract` | `repository` | 磁盘 kind/domain/version/slug 必须与 manifest 身份精确一致 |
| R4 | `SchemaShape` | `contract` | `manifest` | 每种 contract kind 只能声明其闭合 schema slot 形状 |
| R5 | `MissingSchema` | `contract` | `schema` | 每个已声明 schema 文件必须存在于同一真实契约目录 |
| R6 | `UnsafeSchemaPath` | `contract` | `schema` | schema 文件名必须是安全的单路径段且不得逃逸契约目录 |
| R7 | `IdentSyntax` | `contract` | `manifest` | domain/id/version/topic 等 authoring 标识必须符合各自 canonical grammar |
| R8 | `PerKindActiveFields` | `contract` | `manifest` | 期望 active HTTP 有 path+method、active Event 有 topic+delivery、active Command 有 topic；拒绝任一 active 契约缺其发布接线字段 |
| R9 | `PerKindFieldScope` | `contract` | `manifest` | kind 专属字段只能出现在对应 kind，禁止跨 kind 残留 |
| R26 | `ManifestWireMetadata` | `contract` | `manifest` | HTTP success status、subscription identity/effect 与 wire metadata 必须闭合一致 |
| R18 | `HttpAuth` | `contract` | `manifest` | active HTTP 必须声明闭合授权模式及其 permission/scope 参数 |
| R19 | `HttpTenantSource` | `contract` | `schema` | HTTP tenant authority 只能来自认证上下文或声明式受保护 header |
| R23 | `HttpProjectionCoverage` | `contract` | `schema` | HTTP projection 声明字段必须由响应 schema 精确覆盖 |
| R10 | `SagaBlock` | `contract` | `manifest` | Saga 必须有非空 typed steps、唯一 StepName、完整 receipt/effect/retry/compensation policy |
| R11 | `ActiveDeliverySupported` | `contract` | `manifest` | active Event 仅允许 delivery=at-least-once |
| R13 | `SchemaTitle` | `contract` | `schema` | 期望每个 declared schema 的 root title 为 string、全部 title 为 PascalCase 且契约内唯一；拒绝缺 root title、非法 title 或契约内重复 |
| R27 | `IdentityAbacOperatorSsot` | `framework` | `schema` | active identity schema 的 operator 属性必须直接引用唯一 Common ABAC component，且 repository 必须存在至少一个 canonical consumer |
| R16 | `SchemaRedaction` | `contract` | `schema` | 敏感 schema 字段必须声明闭合 redaction policy |
| R17 | `SchemaProtection` | `contract` | `schema` | 敏感持久化字段必须声明闭合 at-rest protection policy |
| R14 | `ActiveSubscriber` | `contract` | `manifest` | active Event 必须至少声明一个完整 subscription consumer |
| R20 | `SlugSyntax` | `contract` | `repository` | 嵌套 contract slug 必须符合安全 canonical segment grammar |
| R12 | `DuplicateId` | `framework` | `repository` | 整个 repository 的 contract id 必须全局唯一 |
| R21 | `SlugMixing` | `framework` | `repository` | 同一 kind/domain/version 不得混用 flat 与 nested contract layout |
| R22 | `ConsistencyCapability` | `framework` | `rust-source` | consistency level、outbox/workflow/device capability 与生产 carrier 必须闭合 |
| R25 | `DeviceCertificateHttpClosure` | `framework` | `repository` | device certificate policy/status HTTP 与 command/event/reconcile 契约必须精确闭合 |
<!-- @generated:contract-governance:end -->

> 载体分档（AI-robust）：「坏值不可表达」尽量上移类型层（Hard，`manifest.rs` + codegen funnel）——`method`/`delivery`/`compensationOrder`/HTTP auth mode/header mode/resourceSharing mode/idempotency/subscription execution/effect/external-effect-policy/topology/`capabilities.*`/`[reconcile]`/`[effectProfile]` 使用闭枚举；subscription policy 由 canonical vocab enum、私有 registration capability 与 policy-bound handler 保留到 executor，HTTP success status 经 `HttpSuccessStatus` 限制为 2xx，嵌套结构 `#[serde(deny_unknown_fields)]` 拒未知子键。类型系统无法排除的 handler 内 raw port/cross-file helper 由 AST call-graph synthetic red 与 active-handler anti-vacuity 守卫（Medium）补齐；函数项/import alias、UFCS、chained HTTP、email/object-store/cloud、同 crate helper 与 declarative macro 是显式覆盖面，同名 helper 候选超限 fail closed。该扫描不声称 rustc HIR/trait resolution/proc-macro expansion 完备，动态分派和过程宏展开是 Medium residual，Hard 主防线仍是 sealed capability 与私有构造器；需读取 Git 历史的 wire diff 同样是 Medium。新增 enforcement 零 Soft。

## schema.json

- 每个 JSON Schema 的 root **必须声明 `title`**（缺则 typify 不生成根类型），且 `title`（含嵌套对象，如 seed 的 `SeedEchoData`）是生成的 Rust 类型名，必须 **PascalCase 且契约内唯一**；由 `cargo xtask contract validate` R13 机器校验。唯一性 scope = **契约内**——每契约独立 codegen module `{domain}_{version}`，跨契约同名类型天然不冲突。
- 跨契约共享 schema 只允许放在 `contracts/components/<domain>/<version>/<slug>.schema.json`，并声明与路径精确对应的 `$id = rss://component/<domain>/<version>/<slug>`。契约 schema 只能用该绝对本地 URI 引用；relative、network、`file:`、traversal、symlink、missing、孤儿、冲突与引用环均 fail-closed。component 无手工 catalog，引用图、snapshot、hash、validation、breaking、codegen 与 CI impact 共用同一 resolver；它不是远程 registry。
- component 的 root `title` 是稳定派生类型名；同一契约的多个 schema 引用同一 component 时，codegen 在该契约 `TypeSpace` 中只注册一次共享 definitions。派生 Rust 类型仍保留在各 contract module，禁止另建共享 DTO crate。
- 标准 Draft-07 `maxLength` 仍表示 Unicode 字符数。仅当 RSS runtime 必须按 UTF-8 bytes 闭合安全边界时，string schema 可在唯一 `maxLength` 旁声明 `"x-rss-length-unit": "utf8-bytes"`；不存在其他单位、alias 或 fallback。marker 缺少 `maxLength`、挂到非 string schema、值非法，或 marker / generated tuple / constructor rewrite 数量不一致时 codegen 直接失败。标记类型只把 maximum 改为 `str::len()`，不改变 `minLength`、`pattern` 等标准约束。
- **HTTP 响应 envelope**：成功响应顶层包一层 `data`（seed `response.schema.json` 即 `{"data": {...}}`，派生 `SeedEchoResponse { data: SeedEchoData }`）；列表响应顶层为 `data` / `nextCursor` / `hasMore`（见 `docs/rules/rust-standards.md` §API）。错误响应走统一 error schema（见 `docs/rules/error-handling.md`），不在此 envelope 内。
- camelCase 属性名（如 `thingId`）由 typify 生成为 snake_case Rust 字段 + `#[serde(rename)]`（wire camelCase / Rust snake，符合 RSS 命名）。
- `format: int64`/`format: int32` → typify 生成原生整数类型（`i64`/`i32`），无外部依赖，可用。
- 种子契约避免 `format: uuid`（引入 `uuid` crate）和 `format: date-time`（引入 `chrono` crate）——防 `generated/` 引入超出 `serde` 的额外依赖。其他 `format` 按 typify 映射处理。
- **字段级 redaction 策略（#1358）**：每个 property 可声明 `x-pii`（`generic|email|phone|name|address`）和 / 或
  `x-redaction`（`public|internal|secret|fixed|last4|email_mask|drop`）。未声明字段默认 `public`（安全
  `Debug` 中按 `Debug` 明文显示）。`x-pii` 默认使用 `secure::PiiKind::default_mode()`；若与 `x-redaction`
  同用，只允许 `fixed|last4|email_mask|drop` 作为 mode override。`hash` 已移除，关联令牌必须在运行时代码中
  通过显式 keyed HMAC API 生成。不再使用 `x-sensitive`。
- 高风险字段名必须显式声明 `x-pii` 或非 public 的 `x-redaction`：`password`/`passwd`/`secret`/`token`/
  `credential`/`apikey`/`api_key`/`key`/`authorization`/`cookie`/`jwt`/`session`/`bearer`/`salt`/`private`
  （包含匹配）以及 `subject`/`subjectId`/`principal`/`principalId`/`payload`/`metadata`/`actor`
  （精确匹配，大小写按 schema 字段名折叠）。由 R16 机器校验。
- **字段级 storage protection 策略（#1468，ADR-011）**：`x-redaction`（上一条）守 **observe 面**（Debug/日志/trace
  脱敏）；`x-protection` 守**正交的 at-rest storage 面**（落库加密声明），二者**不混用、不互相替代**（ADR-011 D1）。
  framework 底座只立**声明层**——`x-protection` 携加密元数据但**不触发真实加解密**（真实 AAD/AEAD-v2 类型 + KeyProvider
  归 #1465/#1466）。property 上的 `x-protection` 是 object：
  - `atRest`（必填）：`plain` | `encrypt`。
  - `mode`（选填，默认 `randomized`，仅 `encrypt` 有意义）：`randomized` | `deterministic` | `blindIndex`。
  - `keyScope`（`encrypt` 必填，非空 string）。
  - `aad`（`encrypt` 必填，非空数组）：维度 ∈ `tenant`/`configKey`/`field`/`schemaVersion`（ADR-011 D2 复合域坐标，**单源**）。
    `randomized` 须含**完整坐标** `tenant`+`configKey`+`field`+`schemaVersion`（D2 跨上下文绑定，含 schemaVersion → 跨版本密文不可解）；
    `deterministic`/`blindIndex` 须含稳定子集 `tenant`+`configKey`+`field` 且**不得**含 `schemaVersion`（D4——否则 schema 演进后等值查询静默失效）。
    `configKey` 是复合坐标的必备维度（防跨 entry replay），**非可选**——偏离须改 ADR-011 而非局部放宽。
  - `reason`（`deterministic`/`blindIndex` 必填，非空 string）：deterministic 暴露明文相等性（pattern leak），须文档化权衡（D4）。
  - `atRest:encrypt` 字段不得是 nullable schema（例如 `type:["string","null"]`、`type:"null"` 或 `oneOf`/`anyOf`
    null arm）——当前无显式 null-policy，允许 JSON null 会把「是否为空」作为明文存储状态泄漏；如需加密 null sentinel，
    必须另行设计新的机器门。
  - `mode:"blindIndex"` 只允许非 nullable scalar schema（`string`/`number`/`integer`/`boolean`），并且只承诺等值索引。
    当前 contract 没有 query metadata，故 range / prefix / LIKE / sort / regex 的禁止不靠文档假装成 gate；运行时硬载体是
    `secure::BlindIndexValue` 无 `Ord`/`PartialOrd`/`Eq`，仅暴露 `ct_eq`，且 `secure::BlindIndex` 没有 range/prefix API。
    未来若新增 contract query 声明面，必须同步新增闭值枚举 + Rxx 机器校验。
  - 另：schema 节点顶层可声明 `x-at-rest: true`（持久化 opt-in）。**递归传播**进整棵子树——一旦某节点 opt-in，
    其下（含嵌套对象 / 数组元素）每个高风险字段（同上字段名集）**必须**显式声明 `x-protection`（缺即 R17 拒
    「敏感持久化字段缺 storage policy」，fail-closed）；不需要保护的高风险命名字段显式声明 `{"atRest":"plain"}` 表态豁免。
  由 R17 `SchemaProtection` 机器校验；`contract breaking` 对既有字段 `x-protection`/`x-at-rest`（含 root opt-in 撤销）漂移报
  `PROTECTION_POLICY_CHANGED`（审查材料，防 wire 隐私语义静默漂移）。

  完整示例（`x-at-rest` 持久化 schema，三种 mode）：
  ```json
  {
    "title": "ConfigEntry", "type": "object", "x-at-rest": true,
    "properties": {
      "label":  { "type": "string" },
      "value":  { "type": "string",
        "x-protection": { "atRest": "encrypt", "keyScope": "tenant",
          "aad": ["tenant", "configKey", "field", "schemaVersion"] } },
      "ssnIdx": { "type": "string",
        "x-protection": { "atRest": "encrypt", "mode": "blindIndex", "keyScope": "tenant",
          "aad": ["tenant", "configKey", "field"], "reason": "ssn 去重等值查询" } },
      "note":   { "type": "string", "x-protection": { "atRest": "plain" } }
    }
  }
  ```

## 派生（committed，一等审查材料）

`cargo xtask codegen` 经 typify+prettyplease 把 wire `*.schema.json` 派生进 `generated/` crate（committed `generated/src/{kind}/{domain}_{version}.rs`）；projection schema 仅参与 definition digest，`generated/src/projection/**` 只发射 `CONTRACT_ID`/`CONTRACT`，不生成 HTTP route 或 DTO；
`cargo xtask codegen --check` 重生成并 diff 已提交文件，漂移即失败（CI 门）。**勿手改 `generated/src/**`**——派生 diff 是一等审查材料。

`cargo xtask verify` 是本地全量治理门（门集**单一事实源** = `README.md` §构建与本地验证 / `xtask/src/verify.rs`）：除全 workspace 的 fmt / build / clippy / nextest / deny / dylint 外，**契约相关**的 `contract validate`（元数据校验）、`contract breaking`（wire 破坏检测，见下）、`layer-deps`（分层依赖）、`codegen --check`（派生漂移门）也是其中的 in-process meta 步（亦含在 `--fast` 内），任一失败即停止。改契约后跑 `cargo xtask verify`（或 `--fast` 快检）即覆盖契约元数据 + wire 破坏 + 派生漂移校验；激活 forge=azure 无 CI ⇒ 此门是治理门的唯一实际 gate。

### wire 破坏式变更检测门（`contract breaking`，ADR-008）

`cargo xtask contract breaking [--against <git-ref>]`：对 **base ref ↔ working-tree** 的 manifest + `*.schema.json` 做 typed 跨版本 diff，检测 wire 破坏式变更（对标 Buf WIRE_JSON 规则分类）。与 `contract validate`（当前结构）、`cargo public-api`（轴 A Rust 符号）互补；本门守历史语义。

- **基准**：`--against` 默认 `origin/develop`（PR 基准）；本地可传 `HEAD~1`。ref 不可解析、Git 命令/对象读取失败、基线 TOML/JSON 损坏均 fail-closed；只有 Git 明确证明历史路径不存在时才按“新契约”处理。
- **比较面**：base ↔ working 按 (契约, logical slot：request/response/payload/projection/saga step) 取并集——删除整个 active/deprecated 契约、删除 schema slot、slot 改名丢字段均进入比较（base-only 字段报删除，对标 Buf FILE/MESSAGE_NO_DELETE）；两侧先经同一 component resolver 形成 self-contained schema，再递归比较对象 `properties` + 数组元素 `items`。因此等价 inline→component-ref 不产生 wire finding，而 component 约束收紧会扇出到每个 active consumer。
- **schema 规则**：`FIELD_NO_DELETE`、`REQUIRED_FIELD_ADDED`、`FIELD_TYPE_CHANGED`、`FIELD_FORMAT_CHANGED`、`STRING_LENGTH_UNIT_TIGHTENED`、`ENUM_VALUE_DELETED`、`ADDITIONAL_PROPS_TIGHTENED`、`NULLABLE_REMOVED`、`REDACTION_POLICY_CHANGED`、`PROTECTION_POLICY_CHANGED`。给既有 `maxLength` 新增 `x-rss-length-unit: utf8-bytes` 会收紧非 ASCII accepted-input set，必须进入精确 breaking authorization；该规则递归覆盖 `oneOf` 与 array items。
- **manifest 规则**：HTTP 比较 `successStatus`、`auth.mode + permission`（忽略说明性 `reason`）、`idempotency`；L2 比较 topic、delivery、consistency level、outbox role/atomicity/emits，以及 subscription 集合、consumer/group、topology、execution/effect/externalEffectPolicy。Saga 比较完整 retry policy 与有序 step 执行语义；任一变化都必须形成新的 action generation。`emits` 与 subscription 忽略排序，但任何增、删、替换或既有 policy 变化都是 breaking；重复 contract identity 直接拒绝。
- **repository 规则**：同一 contract ID/version 的 carrier kind 变化生成 `CONTRACT_KIND_CHANGED`，进入统一的 base lifecycle 分级与精确 authorization；active 默认 deny、deprecated warn、base draft 跳过。该规则不创建旧 kind shim 或永久 allowlist。
- **lifecycle 分级**：以 base lifecycle 决定处置，`active` 默认 deny。只有用户明确授权的 intentional breaking，才可携命令生成的精确 `Contract-Breaking-Authorization: sha256:<fingerprint>` commit trailer 原地实施；fingerprint 绑定 base commit 与全部 canonical deny findings，缺失、过期或部分匹配均 fail-closed。`LOCAL_ONLY_BOUNDARY_CHANGED`、`EFFECT_ADDED`、`EFFECT_REMOVED` 固定 warn，但仍须独立携带绑定 base + canonical review findings 的 `Contract-Review-Ack` trailer；两种载体互不替代。`deprecated` 恒 warn、`draft` 跳过；active 降级不能绕过门。Saga definition 删除是独立的 fail-closed 例外：任何 lifecycle 均拒绝，且不接受 retirement fallback；durable 跨副本 retirement proof carrier 落地前旧 definition 只能保留并 deprecated。

> 当前 3 个 draft HTTP（`seed.echo`、`identity.device-certificate-policy-put`、`identity.device-certificate-status-get`）声明 `successStatus = 200` 仅为非 serving 的契约元数据，不构成运行时状态码承诺；激活前必须按实际 handler 重新确认。Settings/Audit projection 已迁到独立 `kind=projection`，不会生成 HTTP route。

per-kind 扩展字段由冻结类型直接解析。command 的 `[command]` 是本次有意破坏式收口：旧 command manifest 不再解析为有效契约，必须显式选择 journal policy。

**codegen 消费面（例外）**：① event `topic` + topology 派生 per-event `SPEC: EventSpec` 与 active-only 根 `EVENTS`；② command `topic` + `[command].journal` 派生 sealed `CommandSpec` 与互斥 producer wrapper；③ HTTP metadata 派生 `HttpSpec`；④ saga block 派生 sealed definition/step/receipt marker、typestate cursor、完整 policy/identity 与 action generation；⑤ projection 仅派生 definition `CONTRACT` 并由 event root catalog 引用，不派生 HTTP/DTO。改 codegen 输入字段必须跑 `cargo xtask codegen --check` 并更新已提交 `generated/`。

### 字段级脱敏派生（codegen 单源，`INVARIANT: CONTRACT-REDACTION-POLICY-01`）

generated wire struct 统一由 codegen 派生 `#[derive(::secure::Redact)]`，并按 schema property 的
`x-pii` / `x-redaction` 注入字段级 `#[redact(...)]`。因此 DTO 仍可 `{:?}` 格式化，但输出经
`secure::redact_struct` 安全渲染；不再通过 `x-sensitive` 或“剥掉 Debug”表达隐私语义。脱敏单源在
contract schema，**勿手改 committed `generated/src/**`**；输出由 `cargo xtask codegen --check` 漂移门、
validate R16、breaking `REDACTION_POLICY_CHANGED` 与 generated `redaction_debug` 集成测试共同锁定。
