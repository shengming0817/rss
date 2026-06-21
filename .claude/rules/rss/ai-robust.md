# AI-robust 治理章程

RSS 的治理机制默认面向 AI co-author。新增约束必须让错误尽量不可表达，
至少做到机器可判定；纯口头约定不是可接受的新增 enforcement。

> RSS 是 GoCell 的 Rust 重写。核心方向：GoCell 因 Go 类型系统弱，大量约束靠 archtest（Go 测试套件）
> + governance rule + rustdoc 约定守；Rust 重写后**优先把约束上移到编译期**
> ——crate 依赖图、`pub`/`pub(crate)` 可见性、sealed trait、trait 关联常量（类型 marker）、构造器必填参数、
> cargo-deny / cargo-udeps / clippy lint。能在编译期免费成立的约束，绝不退化成运行期治理测试。
> 哪些约束编译期天然成立见 `docs/rules/architecture.md` §Rust 原生强制（三档载体）。

## 适用范围

本章程适用于新增或修改下列机制：

- crate 依赖图 / 可见性约束（Cargo `[dependencies]`、`pub(crate)`、workspace 分层）
- clippy 自定义 lint / cargo-deny / cargo-udeps / cargo public-api 规则
- `cargo xtask` governance 校验（运行期治理测试，替代 gocell `validate` / `check` CLI）
- bootstrap / init fail-fast guard
- codegen funnel（build.rs / proc-macro）与 golden
- sealed trait、trait 关联常量 marker、newtype、serde derive 边界冻结
- 带 `INVARIANT:` 的 crate rustdoc 约束

不适用于普通业务开发、常规 clippy/test/build，也不把 bug 修复本身包装成新治理机制。

## 分级

| 级别 | 定义 | 典型载体 |
|------|------|----------|
| Hard | 违反不可表达或改动必触发编译失败 / golden / derive 冻结 | crate 依赖图、type system、sealed trait、构造器必填参数、codegen、serde 冻结 |
| Medium | 违反可表达，但 CI 中由 clippy lint / cargo-deny / type-aware scan 或 runtime guard 抓住 | clippy 自定义 lint、cargo-deny / cargo-udeps、governance 测试、bootstrap guard |
| Soft | 依赖人记住、注释、命名习惯或手工清单 | 禁止作为新增机制 |

新机制最低门槛是 Medium。若当前只能做到 Soft，必须换载体或缩小目标。

## 载体选择

优先级（Rust 重写后重排——越靠前越接近编译期、越免费）：

1. **类型系统 / crate 依赖图**：用 Cargo `[dependencies]`、`pub(crate)` 可见性、sealed trait、
   trait 关联常量（类型 marker）、newtype、构造器必填参数表达约束——违反即编译错误。
   域 crate 依赖不到其它域 crate、必填依赖非 `Option`、domain 类型不 derive `Serialize`
   都属此档（见 `docs/rules/architecture.md` §Rust 原生强制（三档载体））。
2. **schema / marker 单源派生代码（codegen funnel）**：build.rs / proc-macro 从声明源派生执行体，
   再用 golden 锁字节输出。
3. **clippy 自定义 lint / cargo-deny / cargo-udeps / cargo public-api**：crate-graph lint
   抓多余 / 未声明依赖、封闭外部 API 面、禁用 crate / license。
4. **运行期 governance 测试（`cargo xtask` / `consistency` 等 crate 内 `#[test]`）**：仅用于类型系统与 crate 图
   管不到的边界——active subscriber 存在性、contract 扇出完整性、migration 只增不改、覆盖率阈值、
   no-op 业务理由（均为 **Medium** CI 门，严禁 Soft）。
5. **metadata / YAML / Markdown 规则**：遍历内容文件校验，并配 synthetic red case。
6. **runtime guard**：只用于上述都不可表达的边界，错误必须 fail-fast。

禁止直接在规则文件中维护落地实例清单。实例、符号、盲区和评级证明写在对应静态守卫
（clippy lint 文档、cargo-deny 注释、治理 `#[test]` 模块 rustdoc）、ADR 或代码注释中。

## Hard 范本

- **crate 图隔离**：约束表达为 "A 依赖不到 B"——不在 Cargo.toml 声明就 import 不到（替代 import archtest）。
- **可见性封装**：raw / 内部类型 `pub(crate)`，仅经公开 façade 暴露。
- **sealed trait**：port trait 用 sealed-trait 模式封闭，外部 crate 无法实现 / 伪造。
- **trait 关联常量 marker**：稳定语义落到类型级关联常量，编译期固定（一致性级是例外——已迁到 `contract.toml`，见 `docs/rules/architecture.md` 决策 #1）。
- **构造器必填参数**：必填 service 依赖为非 `Option` 位置参，缺失即编译错误（替代生成 validate）。
- **typed function choice**：不同语义拆成不同 API / 不同类型。
- **newtype funnel**：字符串 / 原始值入口必须经单一 newtype 构造，独立语义不复用裸 `String`。
- **input struct field exclusion**：公开输入类型不暴露不该由业务传入的字段。
- **serde derive 冻结**：只在 contract / DTO 类型上 derive `Serialize`/`Deserialize`，domain 类型不 derive；
  wire struct 字段集、`#[serde(rename)]`、类型身份用 golden 精确冻结。
- **codegen funnel + golden**：声明源经 build.rs / proc-macro 派生执行体，输出 drift 由字节 diff 暴露。

新机制若不属于这些范本，先写 ADR 说明为何需要扩展范本。

## 静态守卫命名

GoCell 的 archtest 文件命名约定，在 RSS 改为对应 Rust 静态守卫的命名：

- **crate 图 / 依赖约束**：用 cargo-deny 规则（`deny.toml` 注释 ID）或 cargo-udeps，不需单独命名文件。
- **clippy 自定义 lint**：lint id 用 `rss_{rule}`（kebab/snake，与 lint 注册名一致）。
- **运行期治理 `#[test]`**：单条独立规则测试函数 `{rule}`；同主题三条及以上集中到
  `{theme}_invariants` 测试模块。
- **不变式 ID**：守卫的 rustdoc / 测试头必须列 `INVARIANT: <ID>`（格式：`<THEME>-<RULE>-NN`）。
- **内容扫描 / governance 规则**：必须有 synthetic red case 和 anti-vacuity（守卫不能恒真）。

CI、本地触发方式见 `xtask/`（`cargo xtask --help`）；规则文件不复制执行细节。

## 审查要求

涉及 enforcement 的 finding 必须给出 Hard / Medium / Soft 评级。

- Hard：保留，符号和证明写入对应 crate / 守卫 rustdoc。
- Medium：保留；若有低成本 Hard 化路径（尤其能上移到类型系统 / crate 图的），登记 GitHub Issue。
- Soft：新增时 reject；既有 Soft 修改优先升级到 Medium 或 Hard。

复审中尤其追问：该约束是否能从运行期治理测试上移到编译期（crate 图 / 可见性 / sealed trait /
trait 关联常量 / 构造器必填参数）？能则必须上移，不接受 "已有 archtest 等价物" 作为停留运行期的理由。

Funnel 类约束必须分别说明上游和下游强度。只锁 callsite 不是闭环 funnel。

ADR amendment 落地时，必须同步重评原 ADR 的威胁矩阵或安全模型；冲突段落在同一改动中重写。
