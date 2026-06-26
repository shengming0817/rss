# contracts/ — 跨边界契约声明源（格式冻结）

> 单一事实源：`docs/rules/architecture.md` §核心载体。本文件只**冻结目录布局 + 文件名 + 字段集**，
> 语义规则（鉴权 / 扇出 / 版本窗口）不在此复制，见 `.claude/rules/rss/`（contract-fanout·api-versioning）。
> 由后续 G1/W/Join 单元在此格式上增量加真实域契约；本单元（RW-G0.3）冻结格式并搭起 codegen 管道。

## 布局（冻结）

```
contracts/{kind}/{domain}/{version}/
  ├── contract.toml          # 元数据
  ├── request.schema.json    # http / command
  ├── response.schema.json   # http
  └── payload.schema.json    # event / saga
```

- `kind` ∈ `http` | `event` | `command` | `saga`
- `domain`：合法值 = 域 crate 名，或 `_` 前缀保留段（如 `_seed`）。**注意**：`domain` 是目录段，与契约归属无关。
- `owner`：合法值 = 域名（如 `identity`），或 `_framework` sentinel（provider-agnostic 中立契约，不绑定 domain 目录）。`_framework` 是 owner 字段的保留值，**不对应任何目录段**。
- `version` = `v{N}`

## contract.toml 字段（冻结，`#[serde(deny_unknown_fields)]`）

| 字段 | 取值 | 必填 |
|------|------|------|
| `id` | 点分小写名（段 `[a-z][a-z0-9-]*`，如 `seed.echo`、`config.entry-upserted`）；**跨契约全局唯一**（R12） | 是 |
| `kind` | `http`/`event`/`command`/`saga` | 是 |
| `domain` | 域名或 `_` 前缀保留段 | 是 |
| `version` | `v{N}` | 是 |
| `owner` | 域名 或 `_framework`（provider-agnostic 中立契约归框架） | 是 |
| `consistencyLevel` | `LocalOnly`/`LocalTx`/`OutboxFact`/`WorkflowEventual`/`DeviceLatent`（L0–L4） | 是 |
| `lifecycle` | `draft`/`active`/`deprecated`（`active` 才需 assembly 接线，见 contract-fanout.md） | 是 |
| `[schemas]` | `request`/`response`/`payload` → schema 文件名（http 需 `request`+`response`、event/saga 需 `payload`、**command 需 `request`**） | 按 kind（R4） |
| `path` | http 业务路径（`/api/v{N}/{domain}/…` 约定，如 `/api/v1/_seed/echo`；形态安全由 R7 守：绝对、非 `//`、无 `..`/空白） | 按 kind（active http 必填，R8） |
| `method` | http 方法 `GET`/`POST`/`PUT`/`PATCH`/`DELETE`（闭值集，非法即解析 `Err`） | 按 kind（active http 必填，R8） |
| `topic` | event 或 command 稳定 dotted topic 名（event 如 `seed.thing-happened`，command 如 `device.commands.reboot`；点分小写形态由 R7 守，同 `id`） | 按 kind（active event 必填，R8；active command 必填，R8） |
| `delivery` | event 投递语义 `at-least-once`/`at-most-once`/`exactly-once`（闭值集）。**当前实现路径仅 `at-least-once`**（outbox + 幂等消费者）；`at-most-once`/`exactly-once` 为前瞻保留值（broker 链路无运行时保证），**active event 经 R11 机器拒**（仅放行 at-least-once），draft/deprecated 可表达前瞻设计 | 按 kind（active event 必填，R8；值由 R11 限） |
| `[saga]` | saga 专属 block（TOML 键名 **camelCase**）：`steps`（`{ name, outputSchema }` 数组）+ `compensationOrder = "reverse"` + `retryMillis`/`timeoutMillis`（`u64` 毫秒，非负由类型保证）。完整示例见 `xtask` 解析测试 `VALID_SAGA` | **kind=saga 必填（R10，无条件、不论 lifecycle）**；良构 R10 |
| `[[subscriptions]]` | event 订阅声明（#1120，TOML 数组）：每项须含 `consumer`（消费者域 DomainId，如 `audit`）+ `group`（稳定 consumer group 名，如 `audit.session-created`，broker 消费位点唯一键）。未知子键由 `deny_unknown_fields` 拒。`#[serde(default)]` ⇒ 无此字段的既有契约仍解析（空数组）。codegen 由此派生 `SUBSCRIPTIONS: &[SubscriptionSpec]` 常量，bootstrap 消费接线。示例：`[[subscriptions]]\nconsumer="audit"\ngroup="audit.session-created"` | **`lifecycle=active && kind=event` 必须非空（R14，EVENT-ACTIVE-SUB-01）**；draft/deprecated 豁免 |

校验规则（`cargo xtask contract validate`，R1–R14 ↔ `Rule` 枚举）：

| 编号 | Rule 枚举名 | 描述 |
|------|-------------|------|
| R1 | `SagaConsistency` | `kind=saga` ⇒ `consistencyLevel=WorkflowEventual` |
| R2 | `FrameworkKind` | `owner=_framework` ⇒ `kind ∈ {http,event,command}`（command 是 provider-agnostic 分发机制，#1124 扩展） |
| R3 | `PathMismatch` | 磁盘路径段 `{kind}/{domain}/{version}` 须等于 manifest 字段 |
| R4 | `SchemaShape` | kind→schema 形态须一致（http 需 request+response、event/saga 需 payload、command 需 request） |
| R5 | `MissingSchema` | 声明的每个 schema 文件须存在于契约目录（含 saga step `outputSchema`） |
| R6 | `UnsafeSchemaPath` | schema 文件名须为纯文件名，不得含 `../`、绝对路径等路径分量（防逃逸；含 saga step `outputSchema`） |
| R7 | `IdentSyntax` | `domain`/`version`/`id`/`owner` + per-kind `path`/`topic`（若声明）先收口语法：`domain` 为安全段（`[a-z0-9_]+`，可 `_` 前缀保留段，无路径分量）、`version` = `v{N}`、`id`/`topic` 点分小写、`owner` 为合法域名（`[a-z][a-z0-9_]*`）或 `_framework`、`path` 为安全绝对路径（非 `//`、无 `..`/空白）——防坏值拼进派生 module 名 / 文件路径 / 鉴权挂载点 / wire routing key（与 codegen 写盘前防逃逸守卫互为表里） |
| R8 | `PerKindActiveFields` | `lifecycle=active` ⇒ 按 kind 必填 **active 发布接线**字段（http `path`+`method` / event `topic`+`delivery` / command `topic`）；draft/deprecated 豁免。字段值形态由 R7 守。**saga 不在此**——`[saga]` 是结构语义、无条件必填（R10） |
| R9 | `PerKindFieldScope` | per-kind 字段只允许出现在匹配 kind（`path`/`method` 仅 http、`topic`/`delivery` 仅 event 或 command（topic 允许 event ∪ command）、`[saga]` 仅 saga）——错配会被派生 silently-ignored，须拒 |
| R10 | `SagaBlock` | **`kind=saga` ⇒ 须有非空 `[saga]` block（无条件、不论 lifecycle，saga.md governance）**；block 存在即查良构：≥1 step、step `name` 合法非关键字 Rust 标识符（拒 raw `r#`）且唯一、`outputSchema` 非空。非-saga kind 误带 `[saga]` 由 R9 拒 |
| R11 | `ActiveDeliverySupported` | `lifecycle=active` 的 event 只能声明当前可兑现的投递语义（仅 `at-least-once`）；`at-most-once`/`exactly-once` broker 链路无运行时保证，能力落地前限 draft/deprecated（active 资源不得声明系统不能兑现的能力） |
| R12 | `DuplicateId` | contract `id` 须跨**全部**契约全局唯一（跨契约扫描）；id 是契约注册标识，api-versioning.md 要求破坏式 wire 变更新建版本目录 **且** 新 contract ID。同根因只报 1 条（subject=该 id，detail 列冲突契约路径） |
| R13 | `SchemaTitle` | 每个 declared schema（喂 codegen TypeSpace 的 `request`/`response`/`payload`，**不含** saga step `outputSchema`——后者不喂 typify）：root **必须有 string `title`**（缺则 typify `add_root_schema` 返回 `Ok(None)`、根类型静默丢失），且全部（含嵌套对象）title 须 PascalCase（`^[A-Z][A-Za-z0-9]*$`）+ **契约内**唯一（title→typify Rust 类型名；数字可在非首位，如 `SeedEchoData`/`EchoV2`）。坏 JSON / 缺文件 skip（由 codegen parse 门 / R5 兜底） |
| R14 | `ActiveSubscriber` | **`lifecycle=active && kind=event` ⇒ `[[subscriptions]]` 非空**（EVENT-ACTIVE-SUB-01，Medium）；active event 无 subscriber 即死事件，视为错误配置。draft/deprecated 豁免 |

> 载体分档（AI-robust）：「坏值不可表达」尽量上移类型层（Hard，`manifest.rs`）——`method`/`delivery`/`compensationOrder` 枚举解析拒非法 variant、`retryMillis`/`timeoutMillis` 用 `u64` 拒负、嵌套结构 `#[serde(deny_unknown_fields)]`。R8–R11 是依赖 lifecycle/kind/值 组合的条件化跨字段不变式，类型层无法免费表达，与 R1–R7 同属 Medium（CI 门 + synthetic red/anti-vacuity）。R12（跨契约 id 唯一）/ R13（schema title PascalCase + 契约内唯一）/ R14（active event 须有 subscriber，EVENT-ACTIVE-SUB-01）是跨/内契约内容扫描，类型层亦无法表达，同属 Medium；R13 契约内重复**未必**被 codegen typify 兜底（同 title 不同结构可能合并 / 产生类型歧义而非 compile error），本规则在 validate 阶段 fail-fast + 清晰诊断 + 守 PascalCase 形态（codegen 不拒非 PascalCase title）。

## schema.json

- 每个 JSON Schema 的 root **必须声明 `title`**（缺则 typify 不生成根类型），且 `title`（含嵌套对象，如 seed 的 `SeedEchoData`）是生成的 Rust 类型名，必须 **PascalCase 且契约内唯一**；由 `cargo xtask contract validate` R13 机器校验。唯一性 scope = **契约内**——每契约独立 codegen module `{domain}_{version}`，跨契约同名类型天然不冲突。
- **HTTP 响应 envelope**：成功响应顶层包一层 `data`（seed `response.schema.json` 即 `{"data": {...}}`，派生 `SeedEchoResponse { data: SeedEchoData }`）；列表响应顶层为 `data` / `nextCursor` / `hasMore`（见 `.claude/rules/rss/rust-standards.md` §API）。错误响应走统一 error schema（见 error-handling.md），不在此 envelope 内。
- camelCase 属性名（如 `thingId`）由 typify 生成为 snake_case Rust 字段 + `#[serde(rename)]`（wire camelCase / Rust snake，符合 RSS 命名）。
- `format: int64`/`format: int32` → typify 生成原生整数类型（`i64`/`i32`），无外部依赖，可用。
- 种子契约避免 `format: uuid`（引入 `uuid` crate）和 `format: date-time`（引入 `chrono` crate）——防 `generated/` 引入超出 `serde` 的额外依赖。其他 `format` 按 typify 映射处理。

## 派生（committed，一等审查材料）

`cargo xtask codegen` 经 typify+prettyplease 把 `*.schema.json` 派生进 `generated/` crate（committed `generated/src/{kind}/{domain}_{version}.rs`）；
`cargo xtask codegen --check` 重生成并 diff 已提交文件，漂移即失败（CI 门）。**勿手改 `generated/src/**`**——派生 diff 是一等审查材料。

`cargo xtask verify` 是本地全量治理门（门集**单一事实源** = `README.md` §构建与本地验证 / `xtask/src/verify.rs`）：除全 workspace 的 fmt / build / clippy / nextest / deny / dylint 外，**契约相关**的 `contract validate`（元数据校验）、`contract breaking`（wire 破坏检测，见下）、`layer-deps`（分层依赖）、`codegen --check`（派生漂移门）也是其中的 in-process meta 步（亦含在 `--fast` 内），任一失败即停止。改契约后跑 `cargo xtask verify`（或 `--fast` 快检）即覆盖契约元数据 + wire 破坏 + 派生漂移校验；激活 forge=azure 无 CI ⇒ 此门是治理门的唯一实际 gate。

### wire 破坏式变更检测门（`contract breaking`，ADR-008）

`cargo xtask contract breaking [--against <git-ref>] [--deny]`：对 `*.schema.json` 做 **base ref ↔ working-tree** 的跨版本 JSON-Schema 递归 diff，检测 wire 破坏式变更（对标 Buf WIRE_JSON 规则分类）。与 `contract validate`（R1–R15 = manifest 元数据 + schema 文件存在性 = **结构**）、`cargo public-api`（轴 A Rust 符号）互补无重叠——本门只校验 schema **内容跨版本 diff**（语义破坏）。规则与窗口分级单源见 `xtask/src/contract/breaking.rs`（INVARIANT WIRE-BREAKING-01 / WIRE-BREAKING-WINDOW-01）。

- **基准**：`--against` 默认 `origin/develop`（PR 基准）；本地可传 `HEAD~1`。base ref 不可解析（未 fetch）按模式分级：**warn 模式跳过整门（退出码 0）**；**deny 模式 fail-closed（退出码 1，无法读基准即无法判定破坏）**——提示 `git fetch <remote> <branch>` 或换 `--against <本地 ref>`。
- **比较面**：base ↔ working 按 (契约, logical slot：request/response/payload/saga step) 取并集——删除整个 active/deprecated 契约、删除 schema slot、slot 改名丢字段均进入比较（base-only 字段报删除，对标 Buf FILE/MESSAGE_NO_DELETE）；递归对象 `properties` + 数组元素 `items`（首版不下探 oneOf/anyOf/$ref，ADR §8 增量）。
- **首版 7 条规则**（schema 内字段）：`FIELD_NO_DELETE`、`REQUIRED_FIELD_ADDED`、`FIELD_TYPE_CHANGED`、`FIELD_FORMAT_CHANGED`、`ENUM_VALUE_DELETED`、`ADDITIONAL_PROPS_TIGHTENED`、`NULLABLE_REMOVED`。只报既有字段的删除 / 收紧；新增可选字段不报（向后兼容）。后 3 条 manifest 依赖规则（HTTP 状态码 / `auth.required` / 幂等）登记第三期（依赖扩 manifest schema）。
- **lifecycle 范围**：只对 `active` + `deprecated` 契约 diff；`draft`（seed / 前瞻原地演进）跳过。
- **窗口分级**（对齐 `api-versioning.md` §兼容窗口，**配置驱动、不读墙上时钟**）：默认 **warn**（pre-GA 至 2026-12-31，退出码 0，记录不阻断）；env `RSS_WIRE_BREAKING=deny` 或 `--deny` 升 **deny**——对 `active` 契约破坏 fail-closed（退出码 1），`deprecated` 恒 warn。窗口到期 / GA / 出现外部 wire 消费方时由人改 env/默认提前收紧。

per-kind 扩展字段（http 的 `path`/`method`、event 的 `topic`/`delivery`、saga 的 `[saga]` block、command 的 `topic`）已随 #1035 + #1124 落地（见上 §contract.toml 字段 + 校验规则 R8–R10 / R15）；属预期附加演进（新增 optional 字段不破坏既有契约解析），非破坏冻结。

**codegen 消费面（例外）**：多数 per-kind 字段 codegen **不**消费（只读 `*.schema.json`），故 `generated/` 不受影响——**但 command 的 `topic` 是 codegen 输入**：派生 `generated/src/command/{domain}_{version}.rs` 的 `pub const TOPIC`（broker routing key 烤入 wrapper），故改 command `topic` 必须跑 `cargo xtask codegen --check`（漂移门）并更新已提交 `generated/`。event 的 `topic`/`delivery` 等仍不入 codegen。

### 敏感字段脱敏（codegen 单源，`INVARIANT: CODEGEN-SENSITIVE-NODEBUG-01`）

含**凭据级字段名**（字段名小写后 `contains` 命中约定集 `password` / `passwd` / `secret` / `token` / `credential`）的
generated wire struct，codegen（`xtask/src/codegen.rs` 的 `strip_sensitive_debug`）**抑制其 `Debug` derive**——该类型
从类型层即**不可** `{:?}` 格式化，杜绝 `{:?}` 或未 `skip` 的 `#[tracing::instrument]` 把明文凭据打进日志（如
`IdentityLoginRequest { password, .. }`）。脱敏单源在 codegen，**勿手改 committed `generated/src/**`**；输出由
`cargo xtask codegen --check` 漂移门 + synthetic 单测 `sensitive_field_struct_drops_debug_derive` 锁定（该单测以非敏感
struct 保留 `Debug` 作 anti-vacuity 对照）。新增 / 调整敏感字段名约定须改 `strip_sensitive_debug` 的 `SENSITIVE` 常量集；
域侧实体（非 generated）的脱敏另由手写 redacted `Debug` + `#[instrument(skip ...)]` 承载，不在本约定内。
