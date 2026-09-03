# RSS 协作说明

> 架构：domain-native 治理（bounded context 只经 contract 通信 + L0–L4 一致性 + journeys 验收），惯用扁平 Rust
> workspace。
> 本文件是项目最高协作规范（无独立宪法文件）；项目能力边界读取
> [`docs/rules/project-scope.md`](docs/rules/project-scope.md)，其它稳定规则直接从 `docs/rules/*.md`
> 发现。需求判断、方案设计和 review 不得越过其中的 `Freeze` / `External` 边界。

domain-native 治理 + 惯用 Rust workspace 工程底座。只保留稳定的开发规则和架构约束。

## 工作方式

- 与用户的所有沟通默认使用中文（对话回复、方案讨论、PR / review 说明）
- 修改前先查看目标文件与相关 `docs/rules/*.md`
- 提交信息遵循 Conventional Commits
- 涉及功能或行为变更时，同步更新对应文档
- 被 `.gitignore` 忽略的文件禁止 `git add -f`
- Review 和重构时不考虑向后兼容——当前只有 rss 自身，没有外部调用方
- 需求判断 / 方案设计 / review 默认考虑 MDM / 零信任治理与安全边界，不按隐含单租户 / 无设备场景推进

## 核心架构约束

### 分层结构（扁平 Cargo workspace）

根级治理载体：

- `Cargo.toml` — `[workspace] members` + `[workspace.dependencies]` 统一版本
- `deny.toml` — cargo-deny：分层禁依赖 + license + advisory（**分层强制载体**：兄弟域 crate 互不可依赖）
- `clippy.toml` — `disallowed-methods`/`disallowed-types`（clock / panic / import 纪律）
- `rust-toolchain.toml` / `.config/nextest.toml` — 工具链固定 / 进程隔离测试

要点：库 crate 扁平放在 `crates/`；feature 是域 crate 内的子单元。精确 member、package kind 与层级只从
Cargo metadata 和 `xtask/src/layers.rs` 派生，不在协作文档复制。

### 依赖规则（crate 图 + typed policy）

- 稳定方向为 Foundation → Engine → DI-infra → Service → Domain → Adapter/Composition。
- 兄弟域互不依赖，跨域只经 contract；domain 不依赖 adapter。
- `SharedRuntimeDeps` 只含共享基础设施/provider value object，具体允许根由
  `xtask/runtime-deps-guard.toml` 与 `cargo xtask runtime-deps guard` 强制。
- Cargo/rustc、`deny.toml`、`cargo xtask layer-deps`、`cargo-udeps` 与 `cargo public-api` 是真实 carrier。

### 域 crate 开发规则

- 一个 bounded context = 一个**域 crate**；feature 模块是域 crate 内的子单元，不是独立 crate。
- 契约元数据落 `contract.toml`（id / kind / consistencyLevel / owner / endpoints / auth …），
  `contractUsages` ⇒ 域 crate 的 `Cargo.toml [dependencies]`（声明即约束，编译期强制）。
- 跨域只通过 **contract** 通信（crate 依赖图 + deny.toml 强制）；仅 validation/newtype 等纯计算库 crate 可被同一 assembly 内兄弟 crate 直接 path 依赖。该例外不因 route 标为 LocalOnly 而扩张到 provider I/O。
- 域内类型用 `pub(crate)` 封装；跨域 wire 类型只经 contract（`contracts/` 声明 → `generated/`）。

### 一致性等级（L0-L4）

等级由 `contract.toml` 的 closed `consistencyLevel`、generated types 与 contract validation 持有；本文不复制
枚举或行为矩阵。

## Rust 编码规范

- 错误用 `vocab` + `thiserror`，应用边界可 `anyhow`；新错误码命名空间须注册所有权并更新 golden
- 日志 / 追踪用 `tracing`（结构化字段 + span）
- DB 字段 `snake_case`，JSON/Query/Path `camelCase`（serde rename）
- clippy 认知复杂度 ≤ 15（`clippy::cognitive_complexity`）
- 新增/修改代码覆盖率 ≥ 80%，引擎与基础 crate（`consistency` / `primitives` / `vocab` / `ids`）≥ 90%（表驱动 `#[test]` / `rstest`）
- `cargo fmt` + `cargo clippy -- -D warnings` 必须干净

## 修改代码前

1. 先 `Read` 目标文件，`Grep` 搜索已有实现
2. 编辑循环按改动类型运行最小复现测试；收尾统一运行 `make ci CI_BASE=<remote>/develop`，它是 10 分钟有界 affected preflight，只选择反向依赖 check、直接影响包 test/clippy 与定向治理测试；feature/integration/workspace 全量重门交 develop/release 或显式 `ci full`。`make ci-full` 仅供人工诊断，不是 PR 默认完成条件
3. 只改需要改的

## AI-robust 治理章程

主要实施者是 AI。新增/修改约束 enforcement 机制按 AI-robust 三档（Hard / Medium / Soft）评级；Soft 严禁立项。
Rust 重写优先级：**能用类型系统 / crate 依赖图 / clippy lint 静态强制的约束，不要退化成运行期治理测试**。
载体选择直接以 Cargo/rustc、类型、schema/codegen、lint/gate 与真实 conformance 为证据，不引用规则文案。

## 参考框架

新建或重构层内模块时，先用 `WebFetch` 读对标源码，commit message 注明 `ref: {framework} {file}`。
读源码优先 Rust 工业对标；Go / Java / .NET 等框架仅作低优先级的架构范式或概念出处。

对标时按受影响模块直接选择 primary upstream 源码并记录可追溯 `ref:`；不以仓内说明文档代替源码证据。

## Sandbox 提权

`git push/pull/fetch` 和 forge CLI（`gh` / `az` / `glab`）命令须用 `dangerouslyDisableSandbox: true`。

## 文档命名规则

格式：`yyyyMMddHHmm-编号-实际功能或问题.md`
示例：`202603281443-022-compliance-api-review.md`
