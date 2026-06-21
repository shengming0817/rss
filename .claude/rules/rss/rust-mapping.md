# Cell/Slice 模型 → Rust/Cargo 映射

> 本文件是 GoCell → RSS（Rust 重写）的架构映射单一事实源。所有规则、CLAUDE.md、
> agent、skill 在涉及"层 / Cell / Slice / contract / 一致性等级"时以本文件为准。

## 核心结论

| GoCell 概念 | Rust/Cargo 载体 | 说明 |
|------------|----------------|------|
| **Slice** | **crate（library）** | 最精确的对应：crate 是编译 / 依赖 / 封装 / 测试的单元 |
| **Slice 的 `contractUsages`** | crate `Cargo.toml` 的 `[dependencies]` | 声明即约束，**编译器强制**——没声明的 contract 物理上 import 不到 |
| **Contract** | **crate（纯类型 + trait，按 wire 版本一个 crate）** | `contract-{kind}-{domain}-v{N}`，只放 DTO / event / command + served/client trait |
| **Cell** | **一组 slice crate + 一个 cell 组合 crate + `cell.yaml`** | 比单 crate 高一层；cell crate 是唯一知道全部 slice 的组合根 |
| **L0 Cell（纯计算）** | 普通 library crate，兄弟 Cell 可直接 path 依赖 | 对应 "L0 可被同 assembly 兄弟 Cell 直接 import" |
| **Assembly** | **binary crate（或 workspace）** | 依赖闭包就是物理打包；`assembly.yaml` 作为声明式清单驱动 scaffold |
| **一致性等级 L0–L4** | trait 关联常量 `const CONSISTENCY: ConsistencyLevel` | 类型级 marker（AI-robust Hard 载体），`cell.yaml` 仍存供工具消费 |
| **层（kernel/runtime/pkg/...）** | workspace 内的 crate 分组 | 见下方 crate 布局 |

**一句话**：cargo 的 **crate ≈ Slice/Contract/Adapter**，**workspace ≈ Assembly**，
**Cell** 是 crate 之上的一层薄约定。更关键的是——Rust 的**类型系统 + crate 依赖图原生强制了
gocell 需要 archtest 才能守住的大部分静态架构约束**（见 §Rust 原生强制）。

## Crate 布局（目标结构，本轮不落地代码）

```
Cargo.toml                       # [workspace] 根 + [workspace.dependencies] 统一版本
crates/
  framework/
    kernel/        → rss-kernel    Cell/Slice/Contract/Reconciler/EventBus trait + ConsistencyLevel + 治理原语；仅依赖 std + serde + serde_yaml
    runtime/       → rss-runtime   http(axum)/auth/worker/observability(tracing+otel)，子能力用 feature 切分
    errcode/       → rss-errcode   错误码命名空间（替代 framework/pkg/errcode）
    ctx/ httputil/ query/          framework/pkg/* 的其余共享工具，各自独立 crate（纯）
  contracts/
    {kind}/{domain}/v{N}/  → contract-{kind}-{domain}-v{N}   纯类型 + served/client trait，无业务逻辑
  cells/
    {cell}/
      cell/        → cell-{id}      组合 crate：依赖本 Cell 的 slice crate，暴露 pub fn module()，持 cell.yaml + smoke 测试
      internal/    → cell-{id}-internal  （可选）scope-B 跨 slice 共享类型，仅本 Cell 的兄弟 slice 可依赖
      slices/{slice}/ → slice-{id}  slice crate：持 slice.yaml + unit/contract 测试
  adapters/
    postgres/ redis/ rabbitmq/ websocket/ s3/ oidc/ → adapter-*   实现 kernel/runtime 定义的 trait，feature 选编
  cmd/{name}/      → bin crate（clap）  CLI：rss validate / scaffold / generate / check / verify
  generated/       → 代码生成产物（build.rs / proc-macro 产出），禁止手工编辑
assemblies/{name}/ → bin crate + assembly.yaml
journeys/          J-*.yaml + status-board.yaml（语言无关，原样保留）
fixtures/          fixture-*.yaml
examples/{name}/   示例 crate
actors.yaml        外部 Actor 注册
```

## 依赖规则（由 crate 图编译期强制）

- `rss-kernel` 只依赖 std + serde + serde_yaml，**不依赖** runtime / adapters / cells。
- cell / slice crate 的 `[dependencies]` 只能含 `rss-*`(framework)、`contract-*`、（L0）兄弟 cell crate；
  **绝不依赖其它 Cell 的 crate**——因为 Rust import 必须先在 Cargo.toml 声明，此规则**由依赖图自动守住**，
  替代 gocell 的 "cells 只经 contract 通信" archtest。
- `adapter-*` 实现 kernel/runtime 的 trait，不被 cell 直接依赖（经组合根注入）。
- cargo 不允许 crate 循环依赖 → 分层无环天然成立。
- 校验：`cargo-deny` / `cargo-udeps`（未声明 / 多余依赖）/ `cargo public-api`（封装面）。

## Rust 原生强制（替代 gocell 的治理 / archtest）

这是 "更好的兼容方案" 的核心：gocell 因 Go 类型系统弱，靠 archtest + governance rule + codegen
funnel + type marker + godoc 约定（AI-robust 三档载体）守约束。在 Rust 里很多约束**编译期免费成立**：

| gocell 治理（Go + archtest） | Rust 原生强制 |
|------------------------------|--------------|
| "Cell 只经 contract 通信"（import archtest） | crate 依赖图：cell crate 依赖不到其它 cell crate，只能依赖 `contract-*` |
| `contractUsages` 声明且与 import 一致 | Cargo `[dependencies]` 即声明；多余 / 未用经 `cargo-udeps` |
| 分层依赖规则（kernel ⊄ runtime…） | workspace crate 图 + `cargo-deny`；循环依赖 cargo 直接拒绝 |
| `allowedFiles` / slice 封装 | crate 边界 + `pub(crate)` 可见性 |
| sealed marker type（godoc + archtest） | sealed-trait 模式（编译器强制） |
| 一致性等级 marker | trait 关联常量 `const CONSISTENCY`（类型级） |
| "public Option 不收 raw infra 接口" | newtype + sealed port trait，raw 类型 `pub(crate)` |
| 必填 service 依赖（`gocell:"required"` + 生成 validate） | 构造器必填参数（非 `Option`）→ 缺失即编译错误 |
| "禁止把 domain entity 序列化到 wire" | 只在 contract crate 类型上 derive `Serialize`；domain 类型不 derive |

**仍需运行期治理 / CI 的**（类型系统管不到）：active subscriber 存在性、contract 扇出完整性、
migration 只增不改、覆盖率阈值、no-op 业务理由。AI-robust 规则集因此收缩，重心从 "archtest"
迁到 "crate-graph lint + clippy + 类型系统"。

## 关键模式的 Rust 形态

- **组合根 / `Module()`**：cell crate 暴露 `pub fn module() -> CellModule`；adapter↔cell 绑定在
  assembly / bin crate 用构造器注入完成（替代 `cellmodules` 层）。
- **Init fail-fast**：`fn init(&self, reg: &mut Registry) -> Result<(), KernelError>`；必填依赖走构造器参数
  （编译期）；init 内不做 I/O、不 spawn task。
- **Adapter sealed marker**：newtype 包裹原始 client（`struct PgStore(PgPool)`）实现 kernel trait，
  port trait 用 sealed-trait 封闭，外部 crate 无法实现。
- **DTO 作用域**：A=slice crate 内 `pub(crate)` / 私有；B=`cell-{id}-internal` crate；
  C=contract crate（跨 Cell 唯一 wire 载体）。
- **错误**：`rss-errcode` + `thiserror`（库错误枚举）；应用边界可 `anyhow`。错误码命名空间注册 + golden。
- **代码生成**：`build.rs` / proc-macro 作为 codegen funnel（比 go:generate 更强），产物入 `generated/`。
