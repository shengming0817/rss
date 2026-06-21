# RSS 协作说明

> RSS 是 GoCell 的 Rust 重写：保留 Cell-native 架构与治理模型，语言载体换成 Rust/Cargo。
> 本文件是项目最高协作规范（无独立宪法文件）；Cell/Slice/contract/一致性等级如何落到 Rust 见
> `.claude/rules/rss/rust-mapping.md`（架构映射单一事实源），分层 / 语言 / 治理细则见 `.claude/rules/rss/`。

Cell-native Rust 工程底座。只保留稳定的开发规则和架构约束。

## 工作方式

- 与用户的所有沟通默认使用中文（对话回复、方案讨论、PR / review 说明）
- 修改前先查看 README.md 与 docs/
- 提交信息遵循 Conventional Commits
- 涉及功能或行为变更时，同步更新对应文档
- 被 `.gitignore` 忽略的文件禁止 `git add -f`
- Review 和重构时不考虑向后兼容——当前只有 rss 自身，没有外部调用方
- 需求判断 / 方案设计 / review 默认考虑 MDM / 零信任治理与安全边界，不按隐含单租户 / 无设备场景推进

## 核心架构约束

### 分层结构（Cargo workspace）

```
Cargo.toml                — [workspace] 根 + [workspace.dependencies] 统一版本
crates/framework/kernel/  — rss-kernel：Cell/Slice 运行时 + 治理原语（底座灵魂），仅依赖 std + serde + serde_yaml
crates/framework/runtime/ — rss-runtime：通用运行时（http(axum) / auth / worker / observability），子能力用 feature 切分
crates/framework/{errcode,ctx,httputil,query}/ — 共享工具 crate（纯）
crates/cells/{cell}/       — 平台 Cell：cell/（组合 crate，持 cell.yaml）+ slices/{slice}/（slice crate，持 slice.yaml）
crates/contracts/{kind}/{domain}/v{N}/ — 跨 Cell 边界契约 crate（纯类型 + served/client trait，按 wire 版本一个 crate）
crates/adapters/{name}/    — 外部系统适配（postgres / redis / rabbitmq / websocket / s3 / oidc），实现 kernel/runtime trait
crates/cmd/{name}/         — CLI 入口 bin crate（rss validate / scaffold / generate / check / verify）
crates/generated/          — 代码生成产物（build.rs / proc-macro），禁止手工编辑
assemblies/{name}/         — 物理打包：bin crate + assembly.yaml
journeys/                  — 平台 Journey 验收规格（J-*.yaml）+ status-board.yaml
fixtures/                  — 测试夹具（fixture-*.yaml）
examples/{name}/           — 示例 crate
actors.yaml                — 外部 Actor 注册
```

### 依赖规则（crate 图编译期强制）

- `rss-kernel` 不依赖 runtime / adapters / cells（只依赖 std + serde + serde_yaml）
- cell / slice crate 只依赖 `rss-*`(framework) + `contract-*` +（L0）兄弟 cell crate，**绝不依赖其它 Cell 的 crate**
- `rss-runtime` 可依赖 kernel + pkg crate，不依赖 cells / adapters
- `adapter-*` 实现 kernel / runtime 定义的 trait，不被 cell 直接依赖（经组合根注入）
- assembly / bin crate 是组合根，可依赖所有层（绑定 cell↔adapter）
- cargo 不允许循环依赖 → 分层无环天然成立；校验用 `cargo-deny` / `cargo-udeps`

> 关键：gocell 靠 archtest 守的 "Cell 只经 contract 通信"，在 Rust 由 crate 依赖图**自动守住**——
> cell crate 没在 Cargo.toml 声明就 import 不到。详见 `.claude/rules/rss/rust-mapping.md` §Rust 原生强制。

### Cell 开发规则

- 每个 Cell 必须有 cell.yaml（必填：id / type / consistencyLevel / owner / schema.primary / verify.smoke）
- 每个 Slice 必须有 slice.yaml（必填：id / belongsToCell / contractUsages / verify.unit / verify.contract / allowedFiles）
- Cell 之间只通过 contract 通信；L0 Cell（纯计算 crate）可被同一 assembly 内的兄弟 Cell 直接 path 依赖
- Slice = crate；`contractUsages` = 该 crate `Cargo.toml` 的 `[dependencies]`（声明即约束）

### 一致性等级（L0-L4）

| 级别 | 含义 | 场景 |
|------|------|------|
| L0 LocalOnly | 单 slice 内部本地处理 | 纯计算、校验 |
| L1 LocalTx | 单 cell 本地事务 | session 创建、审计写入 |
| L2 OutboxFact | 本地事务 + outbox 发布 | session.created 事件、config.entry-upserted 事件 |
| L3 WorkflowEventual | 跨 cell 最终一致 | 查询投影、CQRS、Saga |
| L4 DeviceLatent | 设备长延迟闭环 | 命令回执、证书续期、状态收敛 |

等级在 Rust 是类型级 marker：`impl Cell { const CONSISTENCY: ConsistencyLevel = ...; }`；cell.yaml 仍存供工具消费。

## Rust 编码规范

- 错误用 `rss-errcode` + `thiserror`（库错误枚举），应用边界可 `anyhow`；新错误码命名空间须注册所有权并更新 golden，见 `.claude/rules/rss/error-handling.md`
- 日志 / 追踪用 `tracing`（结构化字段 + span）
- DB 字段 `snake_case`，JSON/Query/Path `camelCase`（serde rename）
- clippy 认知复杂度 ≤ 15（`clippy::cognitive_complexity`）
- 新增/修改代码覆盖率 ≥ 80%，`rss-kernel` 层 ≥ 90%（表驱动 `#[test]` / `rstest`）
- `cargo fmt` + `cargo clippy -- -D warnings` 必须干净

## 修改代码前

1. 先 `Read` 目标文件，`Grep` 搜索已有实现
2. 改完 `cargo build --workspace`，涉及逻辑 `cargo test --workspace`，提交前 `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings`
3. 只改需要改的

## AI-robust 治理章程

主要实施者是 AI。新增/修改约束 enforcement 机制按 AI-robust 三档（Hard / Medium / Soft）评级；Soft 严禁立项。
Rust 重写优先级：**能用类型系统 / crate 依赖图 / clippy lint 静态强制的约束，不要退化成运行期 archtest**。
载体决策原则、review checklist 详见 `.claude/rules/rss/ai-robust.md`，静态强制清单见 `.claude/rules/rss/rust-mapping.md` §Rust 原生强制。

## 参考框架

新建或重构层内模块时，先用 `WebFetch` 读对标源码，commit message 注明 `ref: {framework} {file}`。

| 模块 | 对标框架 | Rust 生态参考 |
|------|---------|--------------|
| Cell/Slice 声明模型 + 生命周期 + 校验 | Kubernetes | kube-rs |
| Cell 运行时 / 依赖注入 | Uber fx | 构造器注入 / shaku |
| 代码生成 | go-zero goctl | proc-macro / build.rs |
| 中间件 | Kratos | tower |
| HTTP | — | axum |
| 事件驱动 | Watermill | — |

## Sandbox 提权

`git push/pull/fetch` 和 forge CLI（`gh` / `az` / `glab`）命令须用 `dangerouslyDisableSandbox: true`。

## 文档命名规则

格式：`yyyyMMddHHmm-编号-实际功能或问题.md`
示例：`202603281443-022-compliance-api-review.md`

适用范围：`docs/architecture/` (ADR)、`docs/plans/` (实施计划)、`docs/reviews/` 等时间序载体。
`docs/guides/` / `docs/ops/` 等长期参考文档按主题名命名，不需要时间戳前缀。
