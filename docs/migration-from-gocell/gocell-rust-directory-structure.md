# GoCell 以 Rust 为主：Cargo 适配与精简 workspace 结构

> **归档·冻结** · 2026-06-21 GoCell→Rust 迁移评估快照（target 命名已对齐 RSS）· **非现行规则**。
> 现行架构单源见 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`；本批只读冻结，仅供迁移评估溯源。
>
> 生成日期：2026-06-21 · 以 Rust 社区规范为主、去除 cell/slice 外壳概念，按"能否被 Cargo 原生替代"适配（非 1:1 迁移）
> 配套文档：[gocell-package-overview.md](./gocell-package-overview.md) · [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) · [gocell-rewrite-sequence.md](./gocell-rewrite-sequence.md) · [gocell-rust-crate-mapping.md](./gocell-rust-crate-mapping.md) · [gocell-rust-ci-plan.md](./gocell-rust-ci-plan.md) · [gocell-rust-eval-checklist.md](./gocell-rust-eval-checklist.md)

## 适配原则

不是把 Go 包逐个翻成 crate，而是先问**哪些 GoCell 手搓的治理机器能被 Cargo / rustc / 官方工具链直接吃掉**，剩下的才自己写。结果是去掉 cell/slice 外壳后，目录大幅收缩成一个常规 Rust workspace。

命名规约：

- crate 名一律 **concat 无 dash**（对齐既有 `accesscore`/`configcore` id 规约），**不加 `rss-` 前缀**——路径已表达分层与归属，`rss` 只保留在 `bins/rss` 这一处产品/二进制名。
- 只有在扁平 `crates/` 里、和外部依赖 crate 真重名又缺路径语境的才加限定：`httpserve`（避开 `http`）、`authn`（避开 `auth`）、`settings`（避开 `config`）。
- `adapters/` 下用**裸后端名**（`postgres`/`redis`/`amqp`…）：adapter 是 Rust 通用概念，`adapters/` 路径已消歧；个别和自身依赖 crate 同名的（`redis`/`prometheus`）在 `Cargo.toml` 用 `package = "..."` 重命名外部依赖即可，不污染 crate 名。
- 分层不靠目录嵌套表达，靠 `deny.toml` + Cargo 依赖图强制（不声明就 import 不了）。

---

## 一、能否被 Cargo 替代：三档盘点

### 一档 · rustc / Cargo 直接吸收（写都不用写，整类 archtest 消失）

| GoCell 手搓机制 | Cargo/rustc 原生 |
|---|---|
| 分层依赖治理（depguard + `CROSS-MODULE-IMPORT` archtest + go.work 多模块） | workspace 成员 + 依赖图：不在 `Cargo.toml` 声明就 import 不了 |
| required-deps codegen（`gocell:"required"`→`validateRequired`） | 非 `Option` 字段 + 构造器签名，缺了编不过——codegen 整个删 |
| sealed / marker / newtype funnel（几十个 + archtest 守） | 模块可见性 + 私有字段 |
| 值集冻结（HandleResult/Disposition/Status/result label） | `#[non_exhaustive]` enum + 穷尽 `match`，漏 case 编不过 |
| `MESSAGE-CONST-LITERAL`（错误 message const literal） | `thiserror` enum variant（本就不是格式化字符串）；错误码前缀 golden / 所有权**不在此档**，仍需 Medium `cargo xtask` 治理 |
| 数据竞争（race detector 运行时抽查） | `Send`/`Sync` 编译期 |
| reflect schema freeze（冻结 wire struct 字段/tag） | derive 单源生成，无需冻结 |
| 进程隔离测试 harness | `cargo-nextest`（每测试独立进程，原生） |

### 二档 · 换成 Cargo 生态既有工具（配置 / 少量代码，不是重写）

| GoCell 机制 | Rust 载体 |
|---|---|
| clock 注入强制 / 禁直调 `time` / 禁特定 import | `clippy.toml` 的 `disallowed-methods`/`disallowed-types` + `cargo clippy -- -D warnings` |
| panic 纪律（`panicregister`） | clippy `panic`/`unwrap_used`/`expect_used` deny + 行级 `#[allow]` carve-out |
| codegen funnel（contractgen/cellgen 模板 + 单一 Render 出口） | `build.rs` + `typify`/`prettyplease`（或 `xtask` 生成 committed crate） |
| golden 漂移（`VerifyInWorktree` 字节 diff） | `insta` 快照（`cargo insta review`） |
| Go API / authoring-schema SemVer（api-versioning 轴 A） | `cargo-semver-checks` + `cargo-public-api`（原生检查破坏式公共 API） |
| DB migration 命名空间（`pkg/migration`） | `sqlx::migrate!` |
| depgraph / graph export | `cargo tree` / `cargo-depgraph` |
| mock（同包）/ table-driven | `mockall` / `rstest` |
| 残留真要 AST 级的少数 funnel（某 callsite） | `dylint`（自写 clippy lint） |
| `hack/` + Makefile + `nogo` 自定义分析器 | `cargo` + `xtask/` |

### 三档 · Cargo 替不了，框架自建（GoCell 真差异化，去掉 cell/slice 外壳后仍成立的内核）

| 机制 | 为什么 Cargo 管不了 |
|---|---|
| contracts 跨边界单源 + 扇出闭环 | 业务契约语义，语言无关 → `xtask` 校验器 |
| L0–L4 一致性声明 + governance（拓扑/引用完整性/格式） | 领域规则，非通用 lint → `xtask` |
| wire contract 版本目录（api-versioning 轴 B） | 业务 wire 兼容策略 → `xtask` |
| 组合根 DI 接线（SharedDeps / Module） | Cargo 不做 DI → 手工 `main` |
| outbox/saga/reconcile/projection 引擎 + topology-gated resolver | 运行时机制 → tokio 自写 |

**净账**：GoCell 治理表面积里，约一半进编译器（一档）、约三成换 cargo 生态现成工具（二档）、只剩约两成（契约 + 一致性，三档）是框架真要自己写的引擎。

---

## 二、精简 workspace 结构

> 下方为 2026-06-21 评估期结构快照；**现行权威结构树的唯一持有者 = `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`，以其为准（本文已冻结，不随之演进）。

```
rss/
├── Cargo.toml              # [workspace] members + [workspace.dependencies]
├── deny.toml               # cargo-deny：分层禁依赖 + license + advisory
├── clippy.toml             # disallowed-methods/types/macros（clock/panic/import 纪律）
├── rust-toolchain.toml
├── .config/
│   └── nextest.toml        # cargo-nextest（进程隔离 / 重试）
│
├── crates/                 # 全部库 crate，扁平（Rust 惯例，非 Go 式分层目录）
│   ├── vocab/              # error(thiserror) / authz / tenant / query
│   ├── ids/                # sealed newtype（私有字段 = 硬封）
│   ├── secure/             # redaction / aead / cookie / pathsafe
│   ├── support/            # http / pg / validation 杂项
│   ├── runctx/             # 请求上下文(tenant/principal)；可观测 ID 走 tracing span
│   ├── consistency/        # outbox / saga / reconcile / projection / idempotency（纯态机 + trait，L0–L4）
│   ├── primitives/         # clock / crypto / authplan / healthz / circuitbreaker / lifecycle
│   ├── httpserve/          # axum router / middleware / health
│   ├── authn/              # jwt / session / refresh / PDP
│   ├── bootstrap/          # composition / config / shutdown / worker（关闭逆序 await，无 async Drop）
│   ├── eventexec/          # outbox relay / eventbus / saga executor·tailer / command
│   ├── deviceloop/         # cert lifecycle·signing（L4）
│   ├── observ/             # metrics / logging / grpc interceptor / audit / websocket
│   ├── distributed/        # distlock / cas / transport
│   ├── identity/           # 域：身份 / 会话 / RBAC / ABAC（原 accesscore）
│   ├── settings/           # 域：版本化配置 / secret 引用（原 configcore，避开 config 重名）
│   ├── audit/              # 域：审计链（原 auditcore）
│   ├── contractreg/        # 域：运行时契约 submit / list（原 registrycore）
│   └── syshealth/          # 域：健康聚合（原 syscore）
│
├── adapters/               # 一 adapter 一 crate + Cargo feature 门控（二进制只编用到的）；adapter 是 Rust 通用概念，裸后端名靠 adapters/ 路径消歧
│   ├── postgres/  redis/  amqp/  mqtt/  s3/
│   ├── oidc/  grpc/  otel/  prometheus/  vault/
│   └── softca/  ratelimit/
│
├── bins/
│   ├── server/             # 部署二进制（原 corebundle）
│   └── rss/                # 薄 cli：只放 xtask/cargo 干不了的运行时命令（产品名仅此处保留）
│
├── contracts/              # ★ 跨边界单源：contract.toml（元数据）+ *.schema.json（schema 体，typify 直接消费）
│                           #   组织：{kind}/{domain}/{version}/contract.toml + request.schema.json ...
├── assemblies/             # ★ 物理打包（assembly.toml）
├── journeys/               # ★ 验收规格（*-journey.toml）+ status-board.toml
├── fixtures/               # ★ 测试夹具（fixture-*.toml）
│
├── examples/               # ssobff / todoorder / iotdevice / corebundlestarter
├── xtask/                  # 代码生成 + golden + 契约/一致性治理校验（替代 tools/ + hack/ + Makefile）
├── generated/              # 契约派生的 committed crate（一等审查材料）；其余 codegen 默认走 build.rs OUT_DIR + insta，不落盘
└── actors.toml             # 外部 Actor 注册（参与 contract 但不属于域模型的系统）
```

### 结构相对 Go 的收缩

- `cmd/gocell` 的 validate/generate/check **三大半蒸发**：validate→`cargo build`、generate→`build.rs`/`xtask`、check→`clippy` + `cargo-deny`。
- `tools/archtest`（~200）→ 个位数 `dylint` + `clippy.toml` + `deny.toml`；`tools/` / `hack/` / Makefile → `xtask/`。
- `corecells/` + `cellmodules/` 的 cell/slice 外壳消失：原平台 Cell 变普通域 crate（`identity`/`settings`/`audit`/`contractreg`/`syshealth`），slice 变 crate 内 feature 模块；组合根接线进 `bins/server` 的 `main` + `bootstrap` crate。
- `framework/{kernel,runtime}/` 的 Go 式三层嵌套铺平进 `crates/`，分层改由 `deny.toml` 表达。

---

## 三、契约：TOML 元数据 + JSON Schema 体

契约从 YAML 改 TOML，但**拆成两类文件**：

- `contract.toml` —— 元数据（id / kind / consistencyLevel / owner / endpoints / auth / permission / topic / delivery 等），扁平结构，TOML 友好，像 Cargo.toml。
- `*.schema.json` —— request / response / payload 的 JSONSchema 体。深层嵌套，TOML 表达笨重，且 `typify` 本就直接吃 `.json` 生成 Rust；保留 JSON Schema 形态最顺。

这样既满足"contracts 改 TOML"，又不和 codegen 打架。`xtask` 的契约校验器读 `contract.toml` 做扇出闭环 + 一致性级校验（三档里语言无关的那部分）。

---

## 四、工具链清单（落到 CI / 本地）

| 用途 | 工具 |
|---|---|
| 构建 / 分层强制 | `cargo build` + workspace 依赖图 |
| 禁依赖 / license / 漏洞 | `cargo-deny`（`deny.toml`） |
| lint / 纪律（clock/panic/import） | `cargo clippy -- -D warnings` + `clippy.toml` |
| 格式 | `cargo fmt`（rustfmt） |
| 测试（进程隔离） | `cargo-nextest` |
| golden / 快照 | `insta`（`cargo insta`） |
| 契约 codegen | `build.rs` + `typify` + `prettyplease` |
| DB migration | `sqlx::migrate!` |
| 公共 API SemVer（轴 A） | `cargo-semver-checks` + `cargo-public-api` |
| 残留 AST 级 funnel | `dylint` |
| mock / 参数化测试 | `mockall` / `rstest` |
| 编排（codegen + 治理校验） | `cargo xtask` |

---

## 五、参考项目对标

接 CLAUDE.md §参考框架 工作流（`ref: {project} {file}`；完整对标表见单一事实源 `docs/references/framework-comparison.md`），Rust 侧按关注点对标如下。

### 最该先读的 4 个整体参考

1. **Oxide `omicron`**（github.com/oxidecomputer/omicron）—— **最贴 GoCell**：本身是控制面（非数据面）；contract-first 全链 `dropshot`(代码→OpenAPI) + `progenitor`(OpenAPI→client) + `typify`(JSONSchema→Rust)；分布式 saga 用自家 **`steno`**(编排+补偿)；Postgres 重、大 workspace、强 newtype 纪律。
2. **`kube-rs`**（github.com/kube-rs/kube）—— CNCF，controller-runtime 的 Rust 实现：`Controller` + `reconcile`/`error_policy`、level-triggered、owner-ref 触发、强制幂等 → 对标 `consistency` 的 `reconcile`(L4)。
3. **`linkerd2-proxy`** —— CNCF 服务网格数据面，tower / tokio / rustls / mTLS 工业标杆 → 对标 `httpserve` + `distributed`(transport) + 跨域 mTLS，以及 tower Layer 栈统一 HTTP/gRPC。
4. **TiKV** —— CNCF 分布式 KV，raft / fencing / leader election → 对标 reconcile 的 FencedWriter 与 distlock。

### 按关注点对标表

| 关注点（我们的 crate） | GoCell 原对标（Go） | Rust 参考 |
|---|---|---|
| 整体控制面形态 | — | **Oxide omicron** |
| reconcile L4 收敛环（`consistency`/`eventexec`） | K8s controller-runtime | **kube-rs `kube-runtime` Controller** |
| saga L3 编排（`consistency`） | Temporal / Watermill | **Oxide `steno`**；`temporalio/sdk-core`(Rust) |
| 声明模型 + 校验（`xtask` 治理） | Kubernetes | kube-rs CRD derive；omicron `openapi/` 校验 |
| 组合根 DI（`bootstrap`） | Uber fx | **无 fx 等价**——手工 composition root（axum `AppState`/`with_state` + `Arc<dyn>`），读 omicron / RisingWave 的 `main` 接线 |
| HTTP + 中间件（`httpserve`） | Kratos | **axum** + **tower/tower-http**；Layer 栈范式看 linkerd2-proxy |
| gRPC（`observ`） | grpc-go | **tonic** + **prost/tonic-build** |
| 契约 codegen（`xtask`/`generated`） | go-zero goctl | **typify** / **progenitor** / **dropshot**；proto 走 **prost** |
| 错误模型（`vocab`） | errcode | **thiserror**/**anyhow**(dtolnay)；带 context 的 **snafu**(TiKV/GreptimeDB 在用) |
| 可观测性（`observ`/`runctx`） | slog + otel | **tracing** + **tracing-opentelemetry** + **opentelemetry-rust**；管道范式看 **Vector** |
| 配置热更新（`bootstrap`） | go-micro | **figment**/**config-rs** + **notify** + **arc-swap** |
| Postgres + RLS/事务（`adapters/postgres`） | pgx | **sqlx**(编译期查询校验)；RLS/SET LOCAL 读 omicron db 层 |
| 事件/消息（`eventexec`, adapters） | Watermill | **lapin**(AMQP)/**rdkafka**/**async-nats**；CQRS/ES 看 **cqrs-es** |
| MQTT L4（`adapters/mqtt`） | paho | **rumqtt**(`rumqttc` 客户端 + `rumqttd` broker) |
| 分布式锁/共识（`distributed`） | distlock | **openraft** / **raft-rs**(TiKV)；leader election 看 kube-rs |
| 状态机 FSM（`consistency`） | kernel/fsm | **statig**(分层状态机)、typestate 模式 |
| 授权 PDP / ABAC（`authn`） | 自写 PDP | **oso**(Polar 策略引擎)、**casbin-rs**、能力令牌 **biscuit** |
| 证书 / PKI L4（`deviceloop`,`adapters/softca`） | crypto/x509 | **rustls** + **rcgen** + **x509-cert/der**(RustCrypto)；ACME 用 **instant-acme**；SPIFFE 用 **spiffe** crate |
| 治理 / lint（替代 archtest） | archtest | **dylint**(自写 lint) + **clippy** `disallowed-*` + **cargo-deny**(Embark) |
| xtask / codegen 编排（替代 hack/Makefile） | tools/+hack/ | **rust-analyzer**(xtask + 自生成 + 内部 lint 最佳范本)、`matklad/cargo-xtask` |
| 大型 workspace 组织 | framework module | **RisingWave** / **Databend** / **GreptimeDB** / omicron / **Zed** |

> **DI 说明**：Rust 无 Uber fx 对应物——主流即手工 composition root（axum `AppState` + `with_state`，服务包 `Arc<dyn Trait>`），印证 `bootstrap` 手工接线 + 构造器返 `Result` fail-fast 的决定。

---

## 设计决策（已定）

1. **一致性级（L0–L4）落位**：放 `contract.toml` 的 `consistencyLevel` 字段（与 wire 语义同源），不放域 crate manifest。
2. **generated 形态**：默认 `build.rs` + `insta`（产物进 `OUT_DIR`、快照锁字节、目录全省）；仅契约派生这种高审查价值的产物落 `generated/` committed crate 作一等审查材料。
3. **全仓 YAML→TOML**：`contract.toml` / `assembly.toml` / `*-journey.toml` / `status-board.toml` / `fixture-*.toml`。唯一例外：request/response 的 **schema 体保持 JSON Schema `.json`**——非 YAML（不在转换范围），且 `typify` 直接消费 JSON 生成 Rust，转 TOML 会与 codegen 打架。fixtures 较深嵌套处用 TOML 内联表 / 数组表表达。
