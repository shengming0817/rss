# GoCell 以 Rust 为主：crate 映射与结构性调整

> **归档·冻结** · 2026-06-21 GoCell→Rust 迁移评估快照（target 命名已对齐 RSS）· **非现行规则**。
> 现行架构单源见 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`；本批只读冻结，仅供迁移评估溯源。
>
> 生成日期：2026-06-21 · 假设已选定 Rust 为主语言，给落地调整指南
> 配套文档：[gocell-package-overview.md](./gocell-package-overview.md) · [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) · [gocell-rewrite-sequence.md](./gocell-rewrite-sequence.md) · [gocell-rust-directory-structure.md](./gocell-rust-directory-structure.md) · [gocell-rust-ci-plan.md](./gocell-rust-ci-plan.md) · [gocell-rust-eval-checklist.md](./gocell-rust-eval-checklist.md)

以 Rust 为主，要调整的不只是「换库」，更多是 Rust 生态**强制/允许**的结构性变化。本文先给 crate 映射，再讲 8 处真正改架构的地方，最后是日常摩擦与净效应。

---

## 一、按关注点的 crate 映射（直接替换层）

| 关注点 | GoCell 现状 | Rust 主力 crate | 备注 |
|---|---|---|---|
| 异步运行时 | goroutine + `context` | **tokio** + `tokio-util`(CancellationToken) | context 见结构调整 #1 |
| HTTP | chi + 自写中间件 | **axum** + `tower`/`tower-http` | 中间件改 Layer 栈 |
| gRPC | grpc-go + interceptor | **tonic** + `prost` | interceptor = tower Layer，与 HTTP 同源 |
| 序列化/DTO | encoding/json + DTO | **serde** + `serde_json` | DTO = `#[derive(Serialize,Deserialize)]` |
| 契约 codegen | contractgen 模板 + golden | `typify`(JSONSchema→Rust) / `schemars` + `prettyplease` + `insta` | contract-first 保留，见 #5 |
| 错误 | errcode 三通道 | **thiserror**（库）/ `anyhow`（应用） | 见 #4 |
| Postgres | pgx/v5 | **sqlx**（编译期查询校验）+ `sqlx::migrate!` | RLS/SET LOCAL/savepoint 都支持，不用 ORM |
| Redis | go-redis | **fred** 或 `redis-rs` + `deadpool` | distlock 仍自写 |
| AMQP / MQTT | amqp091 / paho | **lapin** / **rumqttc** | 都是成熟 async 纯 Rust |
| 对象存储 | aws-sdk-go-v2 | `aws-sdk-s3`（官方）/ `rust-s3` | |
| OIDC / JWT | go-oidc / golang-jwt | `openidconnect` / **jsonwebtoken** | |
| 加密 / 证书 / TLS | crypto/x509 / crypto/tls | RustCrypto(`aes-gcm`/`hmac`/`hkdf`) + `rcgen`/`x509-cert` + **rustls** | 证书侧比 Go 碎，TLS 侧 rustls 更优 |
| 可观测性 | slog + otel + prometheus | **tracing** + `tracing-opentelemetry` + `metrics` facade | 见 #1 |
| 配置 | YAML+env+watch | `figment`（分层覆盖）+ `notify` + `arc-swap` | env 覆盖 yaml 天然 |
| newtype/sealed | 手写 + archtest 守 | **nutype**（带校验的 newtype）/ 私有字段 | 见 #7 |
| 测试 | table-driven + golden | `rstest` + `insta` + `mockall` | |

---

## 二、真正要改架构的 8 处（不只是换库）

### 1. `ctxkeys` 一分为二 —— 最关键
Go 用一个 `context` 同时装两类东西，Rust 必须拆开：
- **可观测性 ID**（trace/correlation/request/cell）→ 折进 **`tracing` span 字段**，自动传播 + 同时喂日志和 otel，省掉 GoCell 现在 slog+ctxkeys+otel 三套。
- **控制流值**（tenant / principal）→ **不能**进 tracing（那是诊断不是控制流），必须走显式 `RequestCtx`（**已决议**落 `runctx` crate，经 `task_local!` 传播，不再是开放二选一）。这是 Rust「context 最痛」的具体落点。

### 2. `tower` 统一 HTTP 中间件 + gRPC 拦截器
axum 和 tonic 都是 tower service → **同一个 Layer 栈**。GoCell 现在「interceptor 顺序必须同步 HTTP 中间件顺序」那条不变式（要 archtest 守）**结构上消失**——它们本就是同一栈。

### 3. 组合根改手工接线（无 fx）
`SharedDeps`/`CellModule`/`capability-provider` 这套部分是 Uber fx 的替身；Rust 惯例是 `main`/composition root 里**显式构造注入**，`SharedDeps` = 一个 `Arc<dyn …>` 的 struct。结果：组合层代码更啰嗦，但 capability-provider-funnel 那批 archtest **蒸发**（接线就是一处普通代码），缺依赖 fail-fast = 构造器返 `Result`，天然。

### 4. errcode 三通道 → thiserror enum + 单点 `Error→Response` 映射
PII 安全（5xx strip public details）收口到唯一的 `impl From<Error> for Response`；「Message 必须 const literal」因为 enum variant 本就如此而**自动成立**，`MESSAGE-CONST-LITERAL-01` 不再需要守。

### 5. 契约保持 contract-first，但 freeze 方式变
契约声明源仍是跨**域**单源（符合「契约是唯一通信源」）——`contract.toml` 元数据 + `*.schema.json`，用 `typify` 生成 Rust；**wire-schema-freeze 的反射冻结 → `insta` 快照测试**。codegen 载体**采用 `build.rs`**（默认，OUT_DIR + `insta`；易调试、产物可见），proc-macro 仅在确需折进编译期时局部用；高审查价值的契约派生体落 committed `generated/` crate，保留「生成物是一等审查材料」。

### 6. 生命周期/关闭：async Drop 不存在，关闭必须显式编排
Go 的 `ContextCloser`/`ManagedResource` LIFO 停止，在 Rust 里 **Drop 不能 async** → 异步 close 不能靠 RAII 自动跑，必须组合根显式按逆序 await。Drop 反序只帮**同步**释放（锁、fd）。这是要提前接受的硬约束。

### 7. archtest 大规模蒸发，残留改 dylint

现行持久化边界的强度与 carrier 不在本归档快照复制；请以
`Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`、cargo xtask archrules verify
与 [ArchRules typed catalog](../../xtask/src/archrules.rs) 为准；需要派生展示时运行
`cargo xtask archrules matrix`。
分层 → **crate 边界 + Cargo.toml 依赖图 + `cargo-deny`**（禁依赖）硬性保证；sealed 构造/newtype funnel → 私有字段 + `nutype`；少数真要 AST 级的（如某调用点 funnel）→ **`dylint`**（自写 clippy lint，Rust 版 archtest）。治理 YAML 校验是语言无关的，**保留**。净效：~200 archtest 砍到个位数。

### 8. 后台环与状态机
reconcile fan-out / relay / sweeper → `tokio::JoinSet` + `CancellationToken`（比 `go func()` 重，要预算）；saga/command 的状态枚举可选 **typestate 模式**（编译期非法转移不可表达），但动态状态多时仍用 `enum + match` 更实际——`kernel/fsm` 那套可达性检查部分被类型系统吸收。

---

## 三、要提前接受的日常摩擦

- **async + `dyn Trait`**：组合根重度 `Arc<dyn Authorizer/Signer/Store/Publisher>`，而 async fn in trait（AFIT，1.75 起稳定）**静态分发 OK、dyn 不行** → 这些 DI trait 仍需 `async-trait` 宏或 `trait-variant`。这是最高频的样板税。
- **otel-rust 生态动荡**（版本和 API 比 Go SDK 频繁变）。
- **proc-macro / 重 derive 编译慢 + 难调试**，直接拖累 AI 的 TDD 红→绿回路。

---

## 四、净效应：什么缩、什么涨

| 缩小 / 消失 | 涨大 / 变难 |
|---|---|
| pkg sealed 类型层（变 newtype） | 组合根显式接线 |
| ~200 archtest（进类型系统/crate） | context 控制流值的传播 |
| HTTP/gRPC 拦截器双份 | 后台环 ceremony（JoinSet/Token） |
| 错误三通道样板 | 关闭顺序显式编排（无 async Drop） |
| slog+ctxkeys+otel 三套 → 一套 tracing | DI trait 的 async+dyn 样板 |

**一句话**：Rust 让 GoCell 的「治理表面积」大幅收缩（类型系统接管），代价是「接线 + context + 异步生命周期」三处变成显式工程量。与 [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) 的结论一致——抬高安全地板，压低迭代天花板。
