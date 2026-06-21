# 架构概念 → Rust/Cargo 映射

> **归档** · GoCell→RSS 迁移指南(含 GoCell 对照),**非现行规则**。现行架构规则(纯 Rust-native)见 `docs/rules/architecture.md`。

> 本文件是 GoCell → RSS（Rust 重写）的架构映射**单一事实源**，并且是**扁平 workspace 结构树的唯一持有者**。
> 所有规则、CLAUDE.md、agent、skill 在涉及"目录 / crate / 层 / contract / 一致性等级 / 命名"时以本文件为准。

## 概念框架（保留什么、退场什么）

RSS 保留 GoCell 的 **domain-native 治理**（原 GoCell 称 cell-native，随单元更名一并改）——bounded context 之间只经
**contract** 通信、操作按 **L0–L4 一致性等级**分类、**journeys** 为验收单源；但**去掉 cell/slice 结构外壳**：不再有
`cell.yaml`/`slice.yaml`、不再有 `cell-{id}`/`slice-{id}` crate、不再有 `crates/cells/{cell}/slices/` 嵌套。

**命名（单源，全仓统一）**：

- **架构风格**称 **`domain-native`**（原 cell-native）：bounded context 只经 contract 通信 + L0–L4 分类 + journeys 验收。
- **单元一律叫「域 crate（domain）」**——一个 bounded context = 一个域 crate（identity/settings/audit/contractreg/syshealth），即原 GoCell 的 "Cell"。派生表述统一为 **跨域 / per-domain / `domain` metric label / `RSS_<DOMAIN>_*` env / `Domain*` 类型**。
- 原 "Slice" = 域 crate 内 **feature 模块**（`pub(crate)` 封装），不再是独立 crate；"Slice" 作为词一并退场。
- **全仓零 "cell"**——仅在引用 GoCell 旧系统（对标 / 被替代机制）或命名已删除旧物（`cell.yaml`、`cell-{id}` crate 等）时出现。

适配原则：**先问哪些 GoCell 手搓的治理机器能被 Cargo/rustc/官方工具链直接吃掉，剩下的才自己写**——
结果是目录大幅收缩成常规 Rust workspace（见 §扁平 workspace 结构、§Rust 原生强制）。

## 核心结论

| GoCell 概念 | Rust/Cargo 载体 | 说明 |
|------------|----------------|------|
| bounded context（原 GoCell "Cell"） | **域 crate**（library） | identity/settings/...；跨域只经 contract |
| 原 "Slice" | 域 crate 内 **feature 模块** | 不再是 crate；intra-crate 用 `pub(crate)` 封装 |
| Contract | `contracts/{kind}/{domain}/{version}/` 的 `contract.toml` + `*.schema.json` 声明源 | typify/xtask 派生 Rust 进 `generated/` crate；跨边界唯一 wire 载体 |
| Contract 归属 | `owner` = 域 crate 名 / `_framework`（sentinel） | provider-agnostic 中立契约归框架 |
| Assembly | `assemblies/{name}/` 的 `assembly.toml`（+ `bins/server` / bin crate） | 依赖闭包 = 物理打包 |
| 一致性等级 L0–L4 | `contract.toml` 的 `consistencyLevel` 字段 | 与 wire 语义同源（决策 #1）；不放域 crate manifest |
| 层 | 扁平 `crates/` 分组 + `deny.toml` 强制 | 见 §扁平 workspace 结构、§分层 |

一句话：cargo 的 **crate ≈ 域 / 服务 / adapter / contract 派生体**，**workspace ≈ assembly**；更关键的是——
Rust 的**类型系统 + crate 依赖图原生强制了 gocell 需要 archtest 才能守住的大部分静态架构约束**（见 §Rust 原生强制）。

## 扁平 workspace 结构（结构树唯一持有者）

```
rss/
├── Cargo.toml            # [workspace] members + [workspace.dependencies] 统一版本
├── deny.toml             # cargo-deny：分层禁依赖 + license + advisory（分层强制载体）
├── clippy.toml           # disallowed-methods/types/macros（clock/panic/import 纪律）
├── rust-toolchain.toml
├── .config/nextest.toml  # cargo-nextest（进程隔离 / 重试）
├── crates/               # 全部库 crate，扁平（Rust 惯例，非 Go 式分层目录）
│   ├── vocab/            # error(thiserror) / authz / tenant / query（基础词汇）
│   ├── ids/              # sealed newtype（私有字段 = 硬封）
│   ├── secure/           # redaction / aead / cookie / pathsafe
│   ├── support/          # http / pg / validation 杂项
│   ├── runctx/           # 请求上下文(tenant/principal)；可观测 ID 走 tracing span
│   ├── consistency/      # outbox / saga / reconcile / projection / idempotency（纯态机 + trait，L0–L4）
│   ├── primitives/       # clock / crypto / authplan / healthz / circuitbreaker / lifecycle
│   ├── httpserve/        # axum router / middleware / health
│   ├── authn/            # jwt / session / refresh / PDP / Principal
│   ├── bootstrap/        # composition / config / shutdown / worker
│   ├── eventexec/        # outbox relay / eventbus / saga executor·tailer / command
│   ├── deviceloop/       # cert lifecycle·signing（L4）
│   ├── observ/           # metrics / logging / grpc interceptor / audit / websocket
│   ├── distributed/      # distlock / cas / transport
│   ├── identity/         # 域：身份 / 会话 / RBAC / ABAC（原 accesscore）
│   ├── settings/         # 域：版本化配置 / flag（原 configcore，避开 config 重名）
│   ├── audit/            # 域：审计链（原 auditcore）
│   ├── contractreg/      # 域：运行时契约 submit / list（原 registrycore）
│   └── syshealth/        # 域：健康聚合（原 syscore）
├── adapters/             # 一 adapter 一 crate + feature 门控；裸后端名（adapters/ 路径消歧）
│   ├── postgres/ redis/ amqp/ mqtt/ s3/
│   ├── oidc/ grpc/ otel/ prometheus/ vault/
│   └── softca/ ratelimit/
├── bins/
│   ├── server/           # 部署二进制（原 corebundle）
│   └── rss/              # 薄 cli：只放 xtask/cargo 干不了的运行时命令（产品/二进制名仅此处保留）
├── contracts/            # ★ 跨边界单源：{kind}/{domain}/{version}/contract.toml + *.schema.json（typify 消费）
├── assemblies/           # ★ 物理打包（assembly.toml）
├── journeys/             # ★ 验收规格（*-journey.toml）+ status-board.toml
├── fixtures/             # ★ 测试夹具（fixture-*.toml）
├── examples/             # ssobff / todoorder / iotdevice / corebundlestarter
├── xtask/                # codegen + golden + 契约/一致性治理校验（替代 tools/ + hack/ + Makefile）
├── generated/            # 契约派生的 committed crate（一等审查材料）；其余 codegen 走 build.rs OUT_DIR + insta
└── actors.toml           # 外部 Actor 注册（参与 contract 但不属于域模型的系统）
```

命名规约：crate 名一律 **concat 无 dash、不加 `rss-` 前缀**——路径已表达分层与归属，产品名 `rss` 只保留在
`bins/rss` 一处。仅当扁平 `crates/` 里和外部依赖 crate 真重名又缺路径语境时才加限定：`httpserve`（避开
`http`）、`authn`（避开 `auth`）、`settings`（避开 `config`）；`adapters/` 下用裸后端名，与自身依赖同名的
（`redis`/`prometheus`）在 `Cargo.toml` 用 `package = "..."` 重命名外部依赖即可，不污染 crate 名。

## 旧→新映射（从嵌套 cell/slice 设计迁移）

| 旧引用（rss-* / 嵌套 / cell-slice） | 新扁平载体 |
|---|---|
| `rss-kernel`（Cell/Slice/Contract/Reconciler/EventBus trait + ConsistencyLevel + 治理原语） | 拆分：`consistency`(引擎态机+trait+L0–L4) + `vocab`(error/authz/tenant/query) + `primitives`(clock/crypto/authplan/healthz/circuitbreaker/lifecycle) + `ids`(sealed newtype)；**不再有单一 kernel crate** |
| `rss-runtime` http/router/middleware/health | `httpserve` |
| `rss-runtime` auth(jwt/session/PDP/Principal/RowScope 派生) | `authn`（auth plan 类型在 `primitives::authplan`） |
| `rss-runtime` composition/config/shutdown/worker | `bootstrap` |
| `rss-runtime` eventbus/relay/saga executor·tailer/command | `eventexec` |
| `rss-runtime` observability(metrics/logging/grpc interceptor/audit/websocket) | `observ` |
| `rss-runtime` transport/distlock/cas | `distributed` |
| `rss-errcode` | `vocab`（error，thiserror） |
| framework/pkg `ctx` / `httputil`·`validation`·pg / `query` | `runctx` / `support` / `vocab` |
| redaction/aead/cookie/pathsafe | `secure` |
| cert lifecycle·signing(L4) | `deviceloop` |
| `crates/cells/{cell}`（accesscore/configcore/auditcore/registrycore/syscore） | 域 crate `identity`/`settings`/`audit`/`contractreg`/`syshealth`；slice→域 crate 内 feature 模块 |
| `crates/cmd/{name}` | `bins/rss`(运行时 CLI) + `xtask`(治理/codegen 校验) + `bins/server`(部署) |
| `crates/adapters/{name}` / `adapter-*` 前缀 | `adapters/{name}`（根级，裸后端名，无前缀） |
| `crates/generated/` | `generated/`（根级 committed crate） |
| Contract = crate `contract-{kind}-{domain}-v{N}` | `contracts/{kind}/{domain}/{version}/contract.toml + *.schema.json` 声明源 → 派生进 `generated/` crate |
| 一致性级 = `impl Cell { const CONSISTENCY }` | `contract.toml` 的 `consistencyLevel` 字段（与 wire 同源，决策 #1） |
| 契约归属 `ownerCell: <id>` / `_framework` | `owner` = 域 crate 名 / `_framework`（cell 外壳退场，归属落到域 crate） |
| DTO 作用域 A/B（cells/{cell}/slices、cell-{id}-internal crate） | 域 crate 内 `pub(crate)` 模块类型（A/B 合一）；C 仍为 contract（`generated`） |
| `cell.yaml` / `slice.yaml` 声明源 | 删除；`contractUsages` ⇒ 域 crate 的 `Cargo.toml [dependencies]`；其余元数据 ⇒ `contract.toml` |

## 分层（crate 图 + deny.toml 编译期强制）

- **基础** `vocab`/`ids`/`secure`/`support`/`runctx`：仅 std + 外部 crate（serde/thiserror/uuid…），不依赖内部其它分组。
- **引擎/原语** `consistency`/`primitives`：依赖基础；不依赖服务/域/adapters。
- **服务** `httpserve`/`authn`/`bootstrap`/`eventexec`/`observ`/`distributed`/`deviceloop`：依赖基础+引擎；不依赖域/adapters。
- **域** `identity`/`settings`/`audit`/`contractreg`/`syshealth`：依赖基础+引擎+服务+`generated`（contract 派生）；
  **互不依赖**（跨域只经 contract）；不依赖 adapters。
- **adapters/**：实现基础/引擎/服务定义的 trait；**不被域依赖**（组合根注入）。
- **bins/**、**xtask/**、**assemblies/**：组合根，可依赖所有库 crate。
- **generated/**：contract 派生，被域依赖。
- 强制：cargo 拒绝循环依赖（分层无环天然成立）；`cargo-deny`(deny.toml) 表达禁依赖；`cargo-udeps` 抓多余/未声明；
  `cargo public-api` 守封装面。

> 关键：gocell 靠 archtest 守的 "cell 只经 contract 通信"，在 Rust 由 crate 依赖图**自动守住**——域 crate
> 没在 Cargo.toml 声明就 import 不到，且 `deny.toml` 禁止声明对兄弟域 crate 的依赖。

## Rust 原生强制（三档载体）

这是 "更好的兼容方案" 的核心：gocell 因 Go 类型系统弱，靠 archtest + governance rule + codegen funnel +
type marker + rustdoc 约定守约束。在 Rust 里很多约束**编译期免费成立**。

### 一档（Hard）· rustc/Cargo 直接吸收（整类 archtest 消失，写都不用写）

| gocell 手搓机制 | Cargo/rustc 原生 |
|---|---|
| 分层依赖治理（depguard + `CROSS-MODULE-IMPORT` archtest + go.work 多模块） | workspace 成员 + 依赖图：不在 Cargo.toml 声明就 import 不到 |
| required-deps codegen（`gocell:"required"`→`validateRequired`） | 非 `Option` 字段 + 构造器签名，缺了编不过——codegen 整个删 |
| sealed / marker / newtype funnel（几十个 + archtest 守） | 模块可见性 + 私有字段 + sealed trait |
| 值集冻结（HandleResult/Disposition/Status/result label） | `#[non_exhaustive]` enum + 穷尽 `match`，漏 case 编不过 |
| `MESSAGE-CONST-LITERAL` + error prefix golden | `thiserror` enum variant（本就不是格式化字符串） |
| 数据竞争（race detector 运行时抽查） | `Send`/`Sync` 编译期 |
| reflect schema freeze（冻结 wire struct 字段/tag） | serde derive 单源生成，无需冻结 |
| 进程隔离测试 harness | `cargo-nextest`（每测试独立进程，原生） |

### 二档（Medium）· Cargo 生态既有工具（配置 / 少量代码，不是重写）

| gocell 机制 | Rust 载体 |
|---|---|
| clock 注入强制 / 禁直调 `time` / 禁特定 import | `clippy.toml` 的 `disallowed-methods`/`disallowed-types` + `cargo clippy -D warnings` |
| panic 纪律（`panicregister`） | clippy `panic`/`unwrap_used`/`expect_used` deny + 行级 `#[allow]` carve-out |
| codegen funnel（contractgen/cellgen 模板 + 单一 Render 出口） | `build.rs` + `typify`/`prettyplease`（或 `xtask` 生成 committed crate） |
| golden 漂移（`VerifyInWorktree` 字节 diff） | `insta` 快照（`cargo insta review`） |
| Go API / authoring-schema SemVer（轴 A） | `cargo-semver-checks` + `cargo-public-api` |
| DB migration 命名空间 | `sqlx::migrate!` |
| depgraph / graph export | `cargo tree` / `cargo-depgraph` |
| mock（同模块）/ table-driven | `mockall` / `rstest` |
| 残留真要 AST 级的少数 funnel（某 callsite） | `dylint`（自写 clippy lint） |
| `hack/` + Makefile + `nogo` 自定义分析器 | `cargo` + `xtask/` |

### 三档 · Cargo 替不了，框架自建（RSS 真差异化）

| 机制 | 载体 | 评级 |
|---|---|---|
| contracts 跨边界单源 + 扇出闭环 | `xtask` 校验器 | Medium（CI 门） |
| L0–L4 一致性声明 + governance（拓扑/引用完整性/格式） | `xtask` | Medium（CI 门） |
| wire contract 版本目录（轴 B） | `xtask` | Medium（CI 门） |
| 组合根 DI 接线（SharedDeps / `module()`） | 手工 `main` + `bootstrap` crate | — |
| outbox/saga/reconcile/projection 引擎 + topology-gated resolver | tokio 自写（`consistency` 态机 + `eventexec` 执行 + 各 deps resolver） | — |

**残留运行期/CI 检查**（类型系统 / crate 图管不到）显式为 **Medium（xtask/CI 门），严禁 Soft**：active subscriber
存在性、contract 扇出完整性、migration 只增不改、覆盖率阈值、no-op 业务理由。AI-robust 规则集因此收缩，重心从
"archtest" 迁到 "crate-graph lint + clippy + 类型系统"（见 `.claude/rules/rss/ai-robust.md`）。

## 关键模式的 Rust 形态

- **组合根 / `module()`**：域 crate 暴露 `pub fn module() -> DomainModule`；adapter↔域绑定在 `bins/server` /
  assembly 用构造器注入完成（无独立 cellmodules 层）。GoCell 的 `cellmodules/{eventtransport,replaydeps,sagaprojectiondeps}`
  等 topology-gated resolver 内联为 `bootstrap` 子模块（按 `Topology` 单源选型 eventbus / claimer / nonce / saga 投影依赖）。
- **Init fail-fast**：`fn init(&self, reg: &mut Registry) -> Result<(), KernelError>`；必填依赖走构造器必填参数
  （编译期）；init 内不做 I/O、不 spawn task。
- **Adapter sealed marker**：newtype 包裹原始 client（`struct PgStore(PgPool)`）实现服务 trait，port trait 用
  sealed-trait 封闭，外部 crate 无法实现，raw 保持 `pub(crate)`。
- **DTO 作用域**：域内 = `pub(crate)` 模块类型（原 A/B 档合一）；跨域 wire = contract（`contracts/` 声明 →
  `generated/` crate，原 C 档）。
- **错误**：`vocab`(error) + `thiserror`（库错误枚举）；应用边界可 `anyhow`。错误码命名空间注册 + golden。
- **代码生成**：`build.rs` / proc-macro / `xtask` 作为 codegen funnel（比 go:generate 更强），产物入 `generated/`
  （committed，一等审查材料）或 `OUT_DIR` + `insta`。
