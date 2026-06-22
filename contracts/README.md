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
| `id` | 点分小写名（段 `[a-z][a-z0-9-]*`，如 `seed.echo`、`config.entry-upserted`） | 是 |
| `kind` | `http`/`event`/`command`/`saga` | 是 |
| `domain` | 域名或 `_` 前缀保留段 | 是 |
| `version` | `v{N}` | 是 |
| `owner` | 域名 或 `_framework`（provider-agnostic 中立契约归框架） | 是 |
| `consistencyLevel` | `LocalOnly`/`LocalTx`/`OutboxFact`/`WorkflowEventual`/`DeviceLatent`（L0–L4） | 是 |
| `lifecycle` | `draft`/`active`/`deprecated`（`active` 才需 assembly 接线，见 contract-fanout.md） | 是 |
| `[schemas]` | `request`/`response`/`payload` → schema 文件名 | 按 kind |

校验规则（`cargo xtask contract validate`，R1–R6 ↔ `Rule` 枚举）：

| 编号 | Rule 枚举名 | 描述 |
|------|-------------|------|
| R1 | `SagaConsistency` | `kind=saga` ⇒ `consistencyLevel=WorkflowEventual` |
| R2 | `FrameworkKind` | `owner=_framework` ⇒ `kind ∈ {http,event}` |
| R3 | `PathMismatch` | 磁盘路径段 `{kind}/{domain}/{version}` 须等于 manifest 字段 |
| R4 | `SchemaShape` | kind→schema 形态须一致（http 需 request+response、event/saga 需 payload、command 需 request） |
| R5 | `MissingSchema` | 声明的每个 schema 文件须存在于契约目录 |
| R6 | `UnsafeSchemaPath` | schema 文件名须为纯文件名，不得含 `../`、绝对路径等路径分量（防逃逸） |
| R7 | `IdentSyntax` | `domain`/`version`/`id`/`owner` 先收口语法：`domain` 为安全段（`[a-z0-9_]+`，可 `_` 前缀保留段，无路径分量）、`version` = `v{N}`、`id` 点分小写、`owner` 为合法域名（`[a-z][a-z0-9_]*`）或 `_framework`——防坏标识符拼进派生 module 名 / 文件路径（与 codegen 写盘前防逃逸守卫互为表里） |

## schema.json

- 每个 JSON Schema 的 `title` 字段是生成的 Rust 类型名，必须**唯一且 PascalCase**（含嵌套对象，如 seed 的 `SeedEchoData`）。
- **HTTP 响应 envelope**：成功响应顶层包一层 `data`（seed `response.schema.json` 即 `{"data": {...}}`，派生 `SeedEchoResponse { data: SeedEchoData }`）；列表响应顶层为 `data` / `nextCursor` / `hasMore`（见 `.claude/rules/rss/rust-standards.md` §API）。错误响应走统一 error schema（见 error-handling.md），不在此 envelope 内。
- camelCase 属性名（如 `thingId`）由 typify 生成为 snake_case Rust 字段 + `#[serde(rename)]`（wire camelCase / Rust snake，符合 RSS 命名）。
- `format: int64`/`format: int32` → typify 生成原生整数类型（`i64`/`i32`），无外部依赖，可用。
- 种子契约避免 `format: uuid`（引入 `uuid` crate）和 `format: date-time`（引入 `chrono` crate）——防 `generated/` 引入超出 `serde` 的额外依赖。其他 `format` 按 typify 映射处理。

## 派生（committed，一等审查材料）

`cargo xtask codegen` 经 typify+prettyplease 把 `*.schema.json` 派生进 `generated/` crate（committed `generated/src/{kind}/{domain}_{version}.rs`）；
`cargo xtask codegen --check` 重生成并 diff 已提交文件，漂移即失败（CI 门）。**勿手改 `generated/src/**`**——派生 diff 是一等审查材料。

`cargo xtask verify`（= `contract validate` + `layer-deps` + `codegen --check`）是本地聚合治理门：依次跑元数据校验、分层依赖校验、漂移检测，任一失败即停止。在无 CI 环境（如 Azure 限流）时可用此命令本地自验。

per-kind 扩展字段（http 的 `path`/`method`、event 的 `topic`/`delivery`、saga 的专属 block）留各自后续单元，届时扩展 `ContractManifest`（属预期附加演进，非破坏冻结；backlog 跟踪）。
