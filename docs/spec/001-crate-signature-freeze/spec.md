# Feature Specification: 全 crate trait/type 签名冻结（RW-G0.2 / #997）

**Feature Branch**: `001-crate-signature-freeze`（spec 目录名；本次未切分支）

**Created**: 2026-06-21

**Status**: Draft

**Input**: Epic #991 接缝冻结(G0) 子任务 #997 —— 为 RSS 扁平 workspace 全部库 crate 冻结 trait/type 公开签名（body=todo!() + stub + mockall），按分层拆成多个独立 PR，定义实施顺序与对 spike ADR-002(#994)/ADR-003(#995)/ADR-001(#996) 的依赖门。

## 背景与意图

RSS 是 GoCell(Go) 的 greenfield Rust 重写。迁移采用"最大并行"模型：**接缝冻结(G0) → 追踪弹(G1) → 宽扇出(W, ~15 单元) → 单点收敛(Join)**。本 feature 是 G0 的核心动作 #997：先把"谁向谁暴露什么 trait/type"这层接缝**冻结**下来，再放行 W 阶段 ~15 个实现单元并行填充 body。

冻结的价值在于**晚改接缝最贵**：W 阶段若并行的 15 个单元各自依赖一份未冻结、还在漂移的签名，任一签名变更都会引发跨单元返工。先一次性冻结签名、评审通过，才能让 W 真正无冲突并行。

"用户" = **下游 W 扇出的实现者**（人或 AI co-author）。他们消费冻结的签名作为契约：照着 trait 写 impl、照着 mockall mock 写测试，互不阻塞。

## User Scenarios & Testing *(mandatory)*

### User Story 1 - 基础+引擎层接缝冻结（Priority: P1）

下游实现者要为基础层（vocab/ids/secure/support/runctx）与引擎层（consistency/primitives）填 body 时，能拿到一份编译通过、mock 可构造的 trait/type 签名。这两层是**所有上层 crate 的依赖根**：错误词汇、ID newtype、请求上下文、一致性态机 trait、clock/lifecycle 原语——上层服务/域/adapters 的签名都引用它们，必须最先冻结。

**Why this priority**: 分层依赖根。基础+引擎签名不冻，服务/域/adapters 的签名无从引用（编译都过不了）。这是临界路径的最前段，且体量相对小、概念稳定，最适合先收口建立 conventions。

**Independent Test**: `cargo build -p vocab -p ids -p secure -p support -p runctx -p consistency -p primitives` 通过；每个 DI port trait 的 `MockXxx::new()` 可构造且 `Box/Arc<DynX>`（dynosaur wrapper）可持有（dyn-compatible 成立）；L0 引擎 trait 泛型静态分发编译过；不依赖任何上层 crate。

**Acceptance Scenarios**:

1. **Given** 基础+引擎 crate 仅有骨架 lib.rs，**When** 冻结其公开 trait/type 签名（body=todo!()），**Then** `cargo build` 这 7 个 crate 通过、无 `unused`/`dead_code` 报错。
2. **Given** 已冻结的 DI port trait（如 `Clock`，归属 diport 待拍板），**When** 测试构造对应 mockall mock 并装入 `Box<DynX>`/`Arc<DynX>`（dynosaur wrapper），**Then** 编译通过（证明 dyn-compatible + DI 可注入）。
3. **Given** 基础层 exported API，**When** 运行 `cargo xtask public-api internal --layer basis` 生成 baseline，**Then** 产出可 commit 的 internal signature 快照供后续 diff。

---

### User Story 2 - 服务层接缝冻结（Priority: P2）

下游实现者要填服务层（httpserve/authn/bootstrap/eventexec/observ/distributed/deviceloop）body 时，能拿到冻结的生命周期 / 中间件 / 事件总线 / 认证等 trait 签名。服务层定义被域 crate 与 adapters 实现的核心 port（如 bootstrap 的 `Domain`/`Registry`/`ManagedResource`、eventexec 的 `Publisher`/`Subscriber`、httpserve 的 route/listener 接缝）。

**Why this priority**: 服务层 trait 是域 crate 注册与 adapters 实现的目标接缝，必须先于域/adapters 冻结。但它依赖基础+引擎签名已定（P1），故排在 P1 之后。

**Independent Test**: `cargo build` 七个服务 crate 通过（依赖已冻结的 P1 层）；`bootstrap::Domain`、`eventexec::Publisher/Subscriber`、`primitives` lifecycle 等关键 trait 的 mock 可构造并可作为构造器必填参数注入。

**Acceptance Scenarios**:

1. **Given** P1 层签名已冻结，**When** 冻结服务层 trait/type 签名，**Then** 七个服务 crate `cargo build` 通过。
2. **Given** `bootstrap::Domain` trait 与 `Registry`，**When** 构造一个 stub Domain 调 `init(&mut Registry)` 返回 `Result`，**Then** 编译通过且签名遵循"init fail-fast 返回 Err、不 panic、不做 I/O"形态。
3. **Given** `eventexec::Subscriber` trait，**When** mock 其 `subscribe` 返回 `impl Stream`，**Then** Future 满足 `Send`（tokio multi-thread 可 spawn）。

---

### User Story 3 - 域+adapters 层接缝冻结（Priority: P3）

下游实现者要填域 crate（identity/settings/audit/contractreg/syshealth）与 12 个 adapters 的 body 时，能拿到冻结的域 port trait（仓储/领域服务）与 adapter sealed-marker 接缝。域 crate 引用 `generated`（契约派生 wire 类型）；adapters 以 **unit sealed-marker** native AFIT impl diport **已冻** DI port trait（`ManagedResource`/`Signer`/`Publisher`），raw client 字段延迟 W 阶段。

**Why this priority**: 最外层、扇出面最宽（5 域 + 12 adapter = 17 单元），且依赖 P1+P2 全部冻结、并软依赖 `generated` 契约类型（#998 产出）。放最后，且本层本身就是 W 扇出的主体，签名冻结后即逐单元放行。

**Independent Test**: 每个域 crate `cargo build` 通过（域间互不依赖，经 deny.toml 强制）；域内 `pub(crate)` port trait 的 mock 可构造；每个 adapter 的 unit sealed-marker（如 `struct PgStore;`）能 native AFIT `impl` 已冻 diport DI port trait（raw client 字段延迟 W、届时保持 `pub(crate)`）。

**Acceptance Scenarios**:

1. **Given** P1+P2 签名已冻结、`generated` 契约类型可用，**When** 冻结域 crate 的 `pub(crate)` 仓储/服务 trait 签名，**Then** 五个域 crate `cargo build` 通过且域间无 import（deny.toml 绿）。
2. **Given** 某 adapter（如 postgres），**When** 以 unit sealed-marker native AFIT impl 已冻 diport DI port trait 的 todo!() 骨架，**Then** 编译通过、不被任何域 crate 依赖（raw client 字段延迟 W、届时 `pub(crate)` 不泄漏）。
3. **Given** 全部 17 单元签名冻结，**When** 运行 `cargo build --workspace`，**Then** 整个 workspace 编译通过。

---

### Edge Cases

- **spike 未落地就冻签名**：ADR-002(#994 context) / ADR-003(#995 dynosaur 派发) 决定每个 trait 的方法签名与声明语法。三 ADR 均已落地（门已过）。注意 ADR-003 dynosaur **可行性待 diport 落地 spike 验证**；若实测不可接受回退 async-trait（ADR-003 §5），已冻 DI port 声明语法须返工——故 DI port 实质冻结门于 PR-diport（见 Dependencies / data-model 待决项）。
- **dynosaur 跨 crate sealing 不可行 × mockall**：ADR-003 §4.2——DI port trait 集中到 `diport` 后无法对独立 adapter crate sealing（不带 sealed supertrait）；deny.toml wrapper 收敛 `dynosaur`/`trait-variant` **宏依赖**（DI port 定义点单源，Medium，限**依赖**非 impl），**不**限定谁可 impl——port-trait impl-allowlist 当前未机器强制（Hard→尚无守卫），待 #1060/PR-5；mockall 在 native-AFIT/dynosaur 下的形态经 #1049 验证（signer.rs mockall smoke）。
- **覆盖率门误伤**：body=todo!() 不可达，覆盖率必然偏低。处理：签名冻结 PR 在说明中声明"覆盖率延迟到行为 PR"，避免 80% 门触发红。
- **域层引用未生成的 generated 类型**：若 #998 未产出 `generated`，域层签名无法引用具体 wire 类型。处理：域层 PR 软依赖 #998；可先用占位/最小类型冻结非 wire 部分，wire 引用部分待 #998。
- **adapters 无独立 trait 可冻**：adapters 实现上层 trait，自身通常不定义新 trait。处理：adapter 单元只冻 unit sealed-marker + native AFIT impl 已冻 diport trait 签名，不强造 trait。

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: 系统 MUST 为全部库 crate 的公开 trait/type 冻结签名，方法体一律 `todo!()`，不实现任何业务行为。
- **FR-002**: 每个 DI port trait MUST 配套可构造的 mockall mock（同 crate `#[cfg(test)]`，外部 trait 用 `mock!`）。注：dynosaur/native-AFIT 下 mockall 的具体形态待 diport 落地 spike 验证（data-model 待决项#6）。
- **FR-003**: 每个需被注入的 DI port trait MUST 是 **dyn-compatible**（经 dynosaur `#[dynosaur::dynosaur(DynX = dyn(box) X)]` wrapper）；其 mock MUST 能装入 `Box<DynX>`/`Arc<DynX>`（由编译期 PORT-SHAPE 测试证明）。
- **FR-004**: 签名冻结后 `cargo build --workspace` MUST 通过；`cargo clippy --workspace -- -D warnings` MUST 干净（含对骨架期 unused 的合理 `#[allow]` 或结构安排）。
- **FR-005**: 签名冻结 MUST 按分层拆成多个独立 PR（基础+引擎 / **diport DI port** / 服务 / 域 / adapters），同层无依赖单元可并行，跨层严格串行。
- **FR-006**: 第一个 PR MUST 先落地 **签名编写 conventions**（单源 ADR-004：dynosaur async/dyn 二分、mock、sealed/newtype、ctx 传播、必填依赖/Clock、serde 边界、unsafe 收敛、dynosaur 版本 pin、覆盖率豁免、对标 ref），作为后续各层签名的统一约定地基。
- **FR-007**: conventions 与受其影响的签名 MUST 在 spike ADR-002(#994 context)/ADR-003(#995 dynosaur 派发) 决议落地后再实施（均已落地）；ADR-001(#996 关闭逆序) MUST 在 lifecycle/bootstrap 相关签名前落地；**DI port trait MUST 门于 PR-diport（dynosaur 可行性验证 + crate 落地）**。
- **FR-008**: 域层签名 PR MUST 软依赖 #998（contract codegen 产出 `generated`）以引用 wire 类型；基础/引擎/服务层 PR 不依赖 #998。
- **FR-009**: 域 crate 之间 MUST 互不 import（由 deny.toml + crate 依赖图编译期强制）；adapters MUST 不被任何域 crate 依赖。
- **FR-010**: domain 类型 MUST NOT derive `Serialize`/`Deserialize`；只有 contract/DTO 类型可序列化到 wire（类型层杜绝实体直接上 wire）。
- **FR-011**: 必填 service 依赖 MUST 表达为构造器必填位置参（非 `Option`）；`Clock` MUST 为构造器位置参，不走 builder/Config、不默认系统时钟。
- **FR-012**: 每个签名冻结 PR MUST 在 PR body 标注对标 `ref:`（基于框架对标表）或声明"无需对标：<理由>"。
- **FR-013**: 全部签名冻结完成（全 18+ 单元 PR 合并、含 diport、`cargo build --workspace` 绿、签名 review 通过）MUST 作为放行 W 宽扇出（#1000–#1016）的门。

### Key Entities

- **签名冻结单元（freeze unit）**：一个或一组 crate 的公开接缝集合，是 PR 的粒度。属性：所属层、依赖的上游层、是否软依赖 #998、所需 spike 前置。
- **conventions 地基**：trait 写法 + mock + ctx + 覆盖率约定的单源（**ADR-004**），被所有签名单元引用。
- **DI port trait**：provider-可换、经 dynosaur `DynX` wrapper 注入的接缝（`Box/Arc<DynX>`）；归属二分（ADR-005）——provider-agnostic infra port → `diport`，**域形 repo/service port**（签名引域内实体）→ 所属域 crate `pub mod ports`；需 dyn-compatible + mockall mock。
- **diport crate**：**provider-agnostic** DI port trait + dynosaur wrapper 的 **DI-infra 层** crate（ADR-003，PR-diport #1049）。**无** forbid→deny 例外、**无** unsafe carve-out（#1049 实测 def-site hygiene 不触发 consumer forbid，推翻 §3 原设）；`dynosaur`/`trait-variant` 依赖经 deny.toml + layer-deps 收敛到白名单 = diport + 定义域形 port 的域 crate（ADR-005，DIPORT-MACRO-CONFINE-01′）。
- **sealed-marker newtype**：adapter 以 unit sealed-marker/native AFIT 实现 diport DI port trait 的范式（PR-5 冻 unit struct；raw client 字段在 W 阶段接后端时填入、保持 `pub(crate)`；crate 保持 forbid）。
- **spike 依赖门**：ADR-001/002/003 决议 + diport 落地门作为签名实施的前置条件（非规划前置）。

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 全部库 crate（19 crates/ + **diport** + 12 adapters）的公开接缝签名冻结完成，`cargo build --workspace` 一次通过、零编译错误。
- **SC-002**: 100% 的 DI port trait（diport，dynosaur）具备可构造 mock 且通过 dyn-compatible 编译期 PORT-SHAPE 测试（无一例外）。
- **SC-003**: 签名冻结被拆为 ≥7 个独立 PR（1 conventions + 基础+引擎 + **diport** + 服务 + 域 + adapters 分组），同层 PR 间零文件冲突可并行。
- **SC-004**: 跨层实施顺序零违反：任一层 PR 合并时，其依赖的上游层签名已全部合并（依赖门 100% 成立）。
- **SC-005**: 签名冻结完成后，W 阶段 15 个实现单元可在不再修改已冻接缝的前提下并行开工（冻结后接缝变更率趋零 = 冻结成功的衡量）。
- **SC-006**: 每个签名 PR 携带对标 `ref:` 或显式无对标理由，覆盖率豁免在 PR 说明中声明、CI 不因 todo!() 覆盖率红。

## Assumptions

- workspace 骨架（#993，Cargo.toml + 34 member + deny/clippy/toolchain）已就绪并合并（已 close）。
- 工具链 edition 2024 / rust 1.96，native AFIT 已稳定（1.75）但 `dyn` 仍不可用 → DI port 经 dynosaur wrapper。`dynosaur`(=0.3.x，diport 落地 PR pin) + `mockall` 在 `[workspace.dependencies]`；`async-trait` 仅作 ADR-003 §5 复评对照，非现行范式。
- 接缝**清单**（哪个 crate 暴露哪类 trait）以 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`；spike 改签名**写法语法**，**ADR-003 额外把 DI 注入 port 收敛进新 `diport` crate（改归属位置）**——故本拆解在计划层重排出 PR-diport 单元（建 diport + 回写 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` 由 PR-diport 落地）。
- "用户"是下游实现者（人/AI），非终端业务用户；本 feature 不产出运行时业务行为。
- 域层 wire 类型来自 #998 的 `generated`；若 #998 滞后，域层 PR 可先冻非 wire 接缝。
- spec 规划文档在 `specs/` 下产出；**本次 ship（PR-0）随同提交整理后的 spec + ADR-004 conventions + public-api 工具入口**；PR-1..PR-5 + PR-diport 为后续实现 PR（已建 backlog issue 跟踪）。
