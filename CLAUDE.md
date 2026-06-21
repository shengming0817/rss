# RSS 协作说明

> 架构：domain-native 治理（bounded context 只经 contract 通信 + L0–L4 一致性 + journeys 验收），惯用扁平 Rust
> workspace。
> 本文件是项目最高协作规范（无独立宪法文件）；完整 workspace 结构树 / 分层 / 架构单源见
> `docs/rules/architecture.md`，规则分布于 `docs/rules/`（architecture·eventbus·tenancy·observability·reconcile·saga）
> 与 `.claude/rules/rss/`（ai-robust·rust-standards·error-handling·contract-fanout·domain-patterns·api-versioning·runtime-api）。

domain-native 治理 + 惯用 Rust workspace 工程底座。只保留稳定的开发规则和架构约束。

## 工作方式

- 与用户的所有沟通默认使用中文（对话回复、方案讨论、PR / review 说明）
- 修改前先查看 README.md 与 docs/
- 提交信息遵循 Conventional Commits
- 涉及功能或行为变更时，同步更新对应文档
- 被 `.gitignore` 忽略的文件禁止 `git add -f`
- Review 和重构时不考虑向后兼容——当前只有 rss 自身，没有外部调用方
- 需求判断 / 方案设计 / review 默认考虑 MDM / 零信任治理与安全边界，不按隐含单租户 / 无设备场景推进

## 核心架构约束

### 分层结构（扁平 Cargo workspace）

> 完整扁平布局（全部库 crate + adapters/contracts/bins/xtask/generated）是单一事实源，只在
> `docs/rules/architecture.md` §扁平 workspace 结构 维护一份；此处不复制，避免漂移。

根级治理载体：

- `Cargo.toml` — `[workspace] members` + `[workspace.dependencies]` 统一版本
- `deny.toml` — cargo-deny：分层禁依赖 + license + advisory（**分层强制载体**：兄弟域 crate 互不可依赖）
- `clippy.toml` — `disallowed-methods`/`disallowed-types`（clock / panic / import 纪律）
- `rust-toolchain.toml` / `.config/nextest.toml` — 工具链固定 / 进程隔离测试

要点：库 crate 全部扁平在 `crates/`；域逻辑是普通 crate（identity / settings / audit / contractreg / syshealth），
feature 模块是域 crate 内的子单元；`adapters/`、`contracts/`、`bins/`、`xtask/`、`generated/` 在根级。分层不靠
目录嵌套，靠 `deny.toml` + Cargo 依赖图编译期强制（不声明就 import 不到）。

### 依赖规则（crate 图 + deny.toml 编译期强制）

- **基础**（`vocab`/`ids`/`secure`/`support`/`runctx`）只依赖 std + 外部 crate，不依赖内部其它分组。
- **引擎/原语**（`consistency`/`primitives`）依赖基础；不依赖服务 / 域 / adapters。
- **服务**（`httpserve`/`authn`/`bootstrap`/`eventexec`/`observ`/`distributed`/`deviceloop`）依赖基础 + 引擎；不依赖域 / adapters。
- **域**（`identity`/`settings`/…）依赖基础 + 引擎 + 服务 + `generated`；**互不依赖**（跨域只经 contract）；不依赖 adapters。
- **adapters/** 实现上层 trait，不被域依赖（经组合根注入）；**bins/** / **xtask/** / **assemblies/** 是组合根，可依赖所有库 crate。
- cargo 拒绝循环依赖 → 分层无环天然成立；`cargo-deny`(deny.toml) 表达禁依赖、`cargo-udeps` 抓多余/未声明、`cargo public-api` 守封装面。

> 关键：跨域只经 contract 通信，由 crate 依赖图**自动守住**——域 crate
> 没在 Cargo.toml 声明就 import 不到，且 `deny.toml` 禁止声明对兄弟域 crate 的依赖。详见
> `docs/rules/architecture.md` §分层 / §Rust 原生强制（三档载体）。

### 域 crate 开发规则

- 一个 bounded context = 一个**域 crate**；feature 模块是域 crate 内的子单元，不是独立 crate。
- 契约元数据落 `contract.toml`（id / kind / consistencyLevel / owner / endpoints / auth …），
  `contractUsages` ⇒ 域 crate 的 `Cargo.toml [dependencies]`（声明即约束，编译期强制）。
- 跨域只通过 **contract** 通信（crate 依赖图 + deny.toml 强制）；纯计算库 crate（L0）可被同一 assembly 内兄弟 crate 直接 path 依赖。
- 域内类型用 `pub(crate)` 封装；跨域 wire 类型只经 contract（`contracts/` 声明 → `generated/`）。

### 一致性等级（L0-L4）

| 级别 | 含义 | 场景 |
|------|------|------|
| L0 LocalOnly | 域 crate 内本地纯计算 | 纯计算、校验 |
| L1 LocalTx | 单域 crate 本地事务 | session 创建、审计写入 |
| L2 OutboxFact | 本地事务 + outbox 发布 | session.created 事件、config.entry-upserted 事件 |
| L3 WorkflowEventual | 跨域最终一致 | 查询投影、CQRS、Saga |
| L4 DeviceLatent | 设备长延迟闭环 | 命令回执、证书续期、状态收敛 |

等级声明在 `contract.toml` 的 `consistencyLevel` 字段（与 wire 语义同源，决策 #1），由 `cargo xtask` 校验；不放域 crate manifest。

## Rust 编码规范

- 错误用 `vocab`(error) + `thiserror`（库错误枚举），应用边界可 `anyhow`；新错误码命名空间须注册所有权并更新 golden，见 `.claude/rules/rss/error-handling.md`
- 日志 / 追踪用 `tracing`（结构化字段 + span）
- DB 字段 `snake_case`，JSON/Query/Path `camelCase`（serde rename）
- clippy 认知复杂度 ≤ 15（`clippy::cognitive_complexity`）
- 新增/修改代码覆盖率 ≥ 80%，引擎与基础 crate（`consistency` / `primitives` / `vocab` / `ids`）≥ 90%（表驱动 `#[test]` / `rstest`）
- `cargo fmt` + `cargo clippy -- -D warnings` 必须干净

## 修改代码前

1. 先 `Read` 目标文件，`Grep` 搜索已有实现
2. 改完 `cargo build --workspace`，涉及逻辑 `cargo test --workspace`，提交前 `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings`
3. 只改需要改的

## AI-robust 治理章程

主要实施者是 AI。新增/修改约束 enforcement 机制按 AI-robust 三档（Hard / Medium / Soft）评级；Soft 严禁立项。
Rust 重写优先级：**能用类型系统 / crate 依赖图 / clippy lint 静态强制的约束，不要退化成运行期治理测试**。
载体决策原则、review checklist 详见 `.claude/rules/rss/ai-robust.md`，静态强制清单见 `docs/rules/architecture.md` §Rust 原生强制（三档载体）。

## 参考框架

新建或重构层内模块时，先用 `WebFetch` 读对标源码，commit message 注明 `ref: {framework} {file}`。

| 模块 | 对标框架 | Rust 生态参考 |
|------|---------|--------------|
| 域 crate 生命周期 / init + 契约校验 | Kubernetes | kube-rs |
| 域 crate 运行时 / 依赖注入 | Uber fx | 构造器注入 / shaku |
| 代码生成 | go-zero goctl | proc-macro / build.rs |
| 中间件 | Kratos | tower |
| HTTP | — | axum |
| 事件驱动 | Watermill | — |

## Sandbox 提权

`git push/pull/fetch` 和 forge CLI（`gh` / `az` / `glab`）命令须用 `dangerouslyDisableSandbox: true`。

## 文档命名规则

格式：`yyyyMMddHHmm-编号-实际功能或问题.md`
示例：`202603281443-022-compliance-api-review.md`
