# RSS 对标框架参考（framework-comparison）

> **入口单一事实源** · `explorer` / `developer` / `ship` / `fix` 查「当前模块对标哪个开源项目」的入口。
>
> 本文件是「当前模块对标哪个开源项目」的**单一事实源**：概念映射 + **repo 坐标 + 关键源码起点路径** + primary/secondary
> 优先级。`CLAUDE.md` §参考框架 只保留 `ref:` 工作流并指回本文件，不再持表。供 `WebFetch` 拉 raw 源码对比；新建 / 重构
> 层内模块前，explorer 按下表 step 1 确定 primary / secondary 对标。
> 路径列是**起点**，explorer 用 `WebSearch` 校准具体文件与行号（仓库布局会变）。

## 模块对标表

> 本表只列**读源码优先的 Rust 工业对标 + 生态 crate**：每格 `·` / `/` 分隔的引用按 **primary（加粗，读源码首选）→ secondary（参考，可偏离）** 排序。
> Go / Java / .NET 等架构范式 / 概念出处见文末「概念谱系」附录（优先级远低于本表，仅作设计意图参考）。
> 下文「按模块扩展对标」表用 `primary | secondary` 列表达同一套语义；「Rust 标准库参考」表等权强制遵循、不分 primary/secondary。

| RSS 模块 / 层 | Rust 工业对标 + 生态（owner/repo · 起点） |
|---------------|------------------------------------------|
| 域 crate 生命周期 / init + 契约校验（`bootstrap`） | **`kube-rs/kube`**（`kube-runtime/src/controller/mod.rs`）· `oxidecomputer/omicron`（`Cargo.toml` 组合根） |
| 域 crate 运行时 / 依赖注入（组合根 `assemblies` / `bins`） | 构造器注入 · **`oxidecomputer/omicron`** / `risingwavelabs/risingwave`（手工接线范本）· `AzureMarker/shaku` |
| 代码生成（`generated` / build.rs / proc-macro） | **`oxidecomputer/typify`**（`typify/src/lib.rs`）· `prettyplease` · `oxidecomputer/dropshot`(代码→OpenAPI) / `oxidecomputer/progenitor`(OpenAPI→client) |
| 中间件（`httpserve` tower 层） | **`tower-rs/tower`**（`tower/src/builder/`）/ `tower-http` · `linkerd/linkerd2-proxy`（Layer / mTLS 工业标杆） |
| HTTP server（`httpserve`） | **`tokio-rs/axum`**（`axum/src/routing/`）· `oxidecomputer/dropshot`（`dropshot/src/lib.rs`） |
| 事件驱动（`eventexec` / EventBus） | **`serverlesstechnology/cqrs`**（crate `cqrs-es`，`src/lib.rs`，CQRS/ES）· `oxidecomputer/steno`（`src/lib.rs`，saga 编排） |

raw 拉取 URL 形态：`https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}`
（branch 多为 `master` 或 `main`，404 时换分支重试；大文件先 `Grep`/`WebSearch` 定位行号再局部拉取）。
默认分支为 `master` 的：`AzureMarker/shaku` · `tikv/tikv` · `tikv/raft-rs` · `vectordotdev/vector` ·
`dtolnay/thiserror` · `shepmaster/snafu` · `rust-lang/rust-analyzer` · `casbin/casbin-rs`；其余多为 `main`。

## 按模块扩展对标（主表 6 行之外）

> 主「模块对标表」6 行之外的模块；以下 owner/repo 坐标只在本文件维护。`crate` 列是 RSS 侧归属。
> `primary` 列 = 读源码首选，`secondary` 列 = 参考、可偏离（与主表「加粗 = primary」同一套语义）。

| RSS 模块 / 关注点 | crate | primary 对标（owner/repo · 起点） | secondary |
|-------------------|-------|----------------------------------|-----------|
| reconcile L4 控制环 | `consistency`（引擎）· `deviceloop`（设备 L4 消费者） | `kube-rs/kube`（`kube-runtime/src/controller/mod.rs`） | `oxidecomputer/omicron` |
| saga L3 编排 | `consistency` / `eventexec` | `oxidecomputer/steno`（`src/lib.rs`） | `temporalio/sdk-rust`（`crates/sdk-core/src/lib.rs`） |
| 分布式锁 / fencing / 共识 | `distributed` | `tikv/tikv`（`Cargo.toml`，raft / fencing） | `databendlabs/openraft`（`openraft/src/lib.rs`）· `tikv/raft-rs`（`src/raft.rs`） |
| 证书 / PKI L4 | `deviceloop` | `rustls/rcgen`（`rcgen/src/lib.rs`）· `djc/instant-acme`（`src/lib.rs`） | `maxlambrecht/rust-spiffe`（`spiffe/src/lib.rs`）· cert-manager（概念，provider-agnostic 范式） |
| 可观测性 | `observ` | tokio `tracing` · `vectordotdev/vector`（`src/lib.rs`，管道范式） | `open-telemetry/opentelemetry-rust`（`opentelemetry/src/lib.rs`） |
| 授权 PDP / ABAC | `vocab` / `authn` | `casbin/casbin-rs`（`src/lib.rs`，RBAC/ABAC enforcer）· `eclipse-biscuit/biscuit-rust`（`biscuit-auth/src/lib.rs`，能力令牌） | `osohq/oso`（**已弃用**，Oso 转 SaaS；仅作 Polar / ABAC 概念参考，**勿读源码实现**） |
| 状态机 FSM | `consistency` / `deviceloop` | `mdeloof/statig`（`statig/src/lib.rs`） | typestate 模式 |
| workspace 组织 | （根 workspace） | `oxidecomputer/omicron`（`Cargo.toml`）· `risingwavelabs/risingwave`（`Cargo.toml`） | `zed-industries/zed`（`Cargo.toml`） |
| 错误模型 | `vocab` | `dtolnay/thiserror`（`src/lib.rs`，库错误枚举） | `shepmaster/snafu`（`src/lib.rs`，带 context，TiKV / GreptimeDB 在用） |
| xtask / 内部 codegen + lint 范本 | `xtask` | `rust-lang/rust-analyzer`（`xtask/src/main.rs`） | `matklad/cargo-xtask`（`README.md`，约定 spec） |
| redis adapter — 幂等 claimer / kv 去重（`IdempotencyStore` provider）+ 连接池 `ManagedResource` | `adapters/redis` | `redis-rs/redis-rs`（`redis/src/cmd.rs` — `cmd("SET").arg(..).arg("NX").arg("EX") + query_async`）· `deadpool-rs/deadpool`（`deadpool-redis/src/lib.rs` — `Pool`/`Config`/`Runtime`；`Pool::close` ⇒ `ManagedResource::shutdown`） | — |

## Rust 标准库参考

> `fix` 技能（标准库 / 核心生态优先）查此表：有既定做法时遵循，不自创。语言层细则见 `.claude/rules/rss/rust-standards.md`。

| 场景 | 标准库 / 核心生态做法 |
|------|----------------------|
| 错误类型 | `thiserror`（库错误枚举）/ `anyhow`（应用边界），见 `error-handling.md` |
| 时间 | `Clock` trait 注入（构造器位置参），禁止默认系统时钟 |
| 集合 / 迭代 | 入参优先 `&[T]` / `impl Iterator`，避免无谓 `clone` |
| 序列化 | 仅 contract / DTO derive `serde`，domain 类型不 derive |
| 并发 | tokio task + `CancellationToken`，资源 RAII 清理 |
| HTTP 测试 | `tower::ServiceExt::oneshot` + `axum::http` 驱动 handler |

## 概念谱系（设计范式出处 · 多生态）

> 各模块的**架构范式发源地**（跨 Go / Java / .NET 生态）。RSS 借其设计意图、用上「模块对标表」的 Rust 工业对标实现。
> 各行按范式**真实发源地**标注生态，不强求每行覆盖三生态（如 reconcile / codegen 范式主源自 Go，无同级 Java/.NET 锚点）。
> **本附录优先级远低于上「模块对标表」**——只作概念出处参考，故只列框架名、不带源码起点路径。

| RSS 模块 | 概念范式出处（Go / Java / .NET） | 借鉴的概念 |
|----------|----------------------------------|-----------|
| 域生命周期 / reconcile | `kubernetes/kubernetes`（Go） | 控制器 / desired-state 收敛环 |
| 依赖注入 / 组合根 | `uber-go/fx`（Go）· Spring / Spring Boot（Java）· ASP.NET Core DI（.NET） | DI 容器 + 生命周期（**Rust 无同级框架**，唯一概念锚点）|
| 代码生成 | `zeromicro/go-zero` goctl（Go） | API spec → code 工具链 |
| 中间件 | `go-kratos/kratos`（Go）· ASP.NET Core middleware pipeline（.NET） | 中间件链 / pipeline |
| 事件驱动 / saga | `ThreeDotsLabs/watermill`（Go）· Axon Framework（Java）· MassTransit（.NET） | 消息路由 / pubsub / CQRS-saga 编排 |

## 维护

模块新增 / 对标变更时**只改本文件**——本文件是对标的**单一事实源**（Rust 工业对标主表 + 完整 owner/repo + 起点路径 +
扩展模块 + primary/secondary 优先级 + 多生态概念谱系附录）。`CLAUDE.md` §参考框架 不持表、只留 `ref:` 工作流并指回本文件，故无第二份表
需同步（单源化消除了原「两表逐行同序」漂移面）。表中无匹配模块时，explorer 须
fail-loud（见 `.claude/agents/explorer.md` step 1），不静默吐空结论。
