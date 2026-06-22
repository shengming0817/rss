# Implementation Plan: 全 crate trait/type 签名冻结（#997 / RW-G0.2）

**Branch**: `001-crate-signature-freeze`（spec 目录；本次不切分支） | **Date**: 2026-06-21 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `docs/spec/001-crate-signature-freeze/spec.md`

## Summary

把 RSS 全部库 crate（19 `crates/` + **diport（新建）** + 12 `adapters/`）的公开 trait/type **签名冻结**（body=`todo!()` + stub + mockall），按**分层切成多个独立 PR**，定义实施顺序与对 spike ADR-002(#994)/ADR-003(#995)/ADR-001(#996) 的依赖门，使 W 阶段 ~15 个实现单元可无冲突并行。

技术路线（已由 explorer 实拉对标源码确证 + 对齐已落地 ADR）：

- **PR 边界 = 架构分层**；分层依赖图（cargo + deny.toml 编译期强制）天然给出严格串行的跨层序与同层并行性。
- **PR-0 conventions 地基**先行（单源 ADR-004）：统一 async/dyn 范式（**ADR-003 dynosaur**：DI 注入 port 用 native AFIT + `#[dynosaur::dynosaur(DynX = dyn(box) X)]`，L0 纯计算用 native AFIT + 泛型静态分发）、mock、sealed/newtype、ctx 传播（ADR-002）、unsafe 收敛、覆盖率豁免——消费已落地 spike ADR。
- **重排（ADR-003）**：DI 注入 port trait 收敛进新 `diport` crate（unsafe 收敛，§3）→ 新增 **PR-diport** 单元（PR-2 后、PR-3/4/5 前）。
- **签名形态对标**：bootstrap←kube-rs/fx、httpserve←tower/axum、eventexec←watermill、DI 派发←dynosaur（详见 research.md 的 `ref:`）。

## Technical Context

**Language/Version**: Rust edition 2024，rust-version 1.96（远超 async-fn-in-trait 稳定版 1.75）。

**Primary Dependencies**：`mockall`、`rstest`、`tokio`、`axum`、`tower`、`thiserror`、`serde`、`tracing` 已在 `[workspace.dependencies]` pin；`dynosaur`（=0.3.x，DI 派发，**diport 落地 PR 加入并 pin**）；`async-trait` 仅作 ADR-003 §5 复评对照、非现行范式。

**Storage**: N/A（签名冻结期不接持久化；adapters 的 raw client 仅作 sealed-marker newtype 字段类型出现，不连接）。

**Testing**: `cargo build --workspace`（编译即冻结成立的主信号）+ `cargo nextest`（进程隔离）+ mockall mock 可构造性测试 + `cargo public-api`（基础/引擎层封装面 baseline）。

**Target Platform**: Linux server（部署 bins/server）；本 feature 无运行时产物。

**Project Type**: 惯用扁平 Rust workspace（多 crate，library + 组合根 bins/xtask）。

**Performance Goals**: N/A（无行为）。冻结期唯一"性能"是 `cargo build --workspace` 可在合理时间编译通过。

**Constraints**:
- 接缝**清单**由 `docs/rules/architecture.md` §扁平 workspace 结构 为底；spike 改签名**写法语法**，**ADR-003 额外把 DI 注入 port 收敛进新 `diport` crate**（改归属位置，architecture.md 回写由 PR-diport 落地）。
- spike 依赖门是**实施**前置，非规划前置（本规划现在即可定稿）；DI port 实质冻结门于 PR-diport（dynosaur 可行性验证，ADR-003 §8）。
- 不实现业务行为；domain 类型不 derive `Serialize`/`Deserialize`；必填依赖走构造器必填位置参（`Box<DynX>`）；`Clock` 为构造器位置参。

**Scale/Scope**: 32 个库 crate（19 crates/ + diport + 12 adapters）+ generated（codegen 派生，不手写签名）。预计拆为 7 个 PR 组（1 conventions + 基础+引擎 + **diport** + 服务 + 域 + adapters×可能再分组）。

## Constitution Check

*GATE: 无 `.specify/memory/constitution.md`；RSS 宪法载体 = `CLAUDE.md` + `docs/rules/*` + `.claude/rules/rss/*`。逐条核对：*

| 治理门（RSS 宪法） | 本计划是否合规 | 说明 |
|---|---|---|
| 分层依赖隔离（crate 图 + deny.toml，Hard） | ✅ | PR 顺序 = 分层序；域间互不依赖、adapters 不被域依赖由 deny.toml 守，签名阶段即遵守 |
| AI-robust：约束上移编译期（Hard 优先） | ✅ | 签名冻结本身即"接缝以类型/可见性表达"；dynosaur dyn-compatible（Hard，编译器）、构造器必填参数、newtype 全为 Hard 载体 |
| unsafe 默认 forbid（rust-standards，Hard 默认） | ✓ 无例外（落地） | ADR-003 §3 原设「仅 `diport` forbid→deny + 目标 allow」被 PR-diport #1049 spike 推翻：def-site hygiene 不触发 consumer forbid → diport **无 forbid→deny 例外、无 carve-out**，全仓保持 forbid。dynosaur/trait-variant 依赖收敛守卫 = deny.toml wrappers（Medium） |
| 必填依赖非 Option + 构造器必填参数（Hard） | ✅ | FR-011；PORT-SHAPE-02 测试验证 mock 可作必填参数注入 |
| domain 不 derive Serialize（Hard，serde 边界冻结） | ✅ | FR-010 显式约束 |
| `Clock` 构造器位置参、禁默认系统时钟（Medium，clippy） | ✅ | conventions PR-0 固化 |
| 错误用 vocab+thiserror、message const literal（Hard/Medium） | ✅ | 错误类型签名在 vocab（基础层，P1）冻结 |
| 覆盖率门（新增/改 ≥80%，引擎/基础 ≥90%，Medium） | ⚠️ 例外 | todo!() 不可达→签名 PR 声明覆盖率延迟到行为 PR（见 Complexity Tracking） |
| 对标 ref（ship 阶段1 要求） | ✅ | research.md 已含真实 `ref:`；每 PR body 标注 |
| 契约扇出闭环（Medium） | ✅（部分） | 域层签名引用 generated wire 类型→软依赖 #998；非 wire 接缝可先冻 |
| pre-GA 不留兼容 shim | ✅ | 全新签名，无旧别名 |

**结论**：除覆盖率门的合理例外（todo!() 本质不可达，已在 Complexity Tracking 记录）外，全部治理门通过。无未 justified 违规，可进 Phase 0。

## Project Structure

### Documentation (this feature)

```text
docs/spec/001-crate-signature-freeze/
├── plan.md              # 本文件
├── research.md          # Phase 0：对标决策（dynosaur 派发、对标 ref、mock/测试策略）
├── data-model.md        # Phase 1：freeze unit / trait 分类 / conventions / diport 落地待决项
├── quickstart.md        # Phase 1：每层签名冻结的验证指南
├── contracts/           # Phase 1：每层 trait 接缝契约（签名形态规格）
│   ├── conventions.md   #   薄引用 ADR-004（签名编写约定单源）
│   ├── layer-basis-engine.md
│   ├── layer-diport.md  #   DI port 收敛单元（ADR-003 dynosaur）
│   ├── layer-services.md
│   └── layer-domains-adapters.md
└── tasks.md             # Phase 2：/speckit-tasks 产出（依赖序任务=未来 PR）
```

### Source Code (repository root) —— 本 feature 触碰的真实路径

```text
crates/
├── vocab/ ids/ secure/ support/ runctx/        # 基础层（P1 组）—— runctx ctx 范式依 ADR-002
├── consistency/ primitives/                      # 引擎层（P1 组）—— Clock/lifecycle 推荐迁 diport（待决项#2）
├── diport/                                        # DI-infra crate（PR-diport #1049）—— dynosaur；无 forbid→deny 例外（#1049 实测）
├── httpserve/ authn/ bootstrap/ eventexec/       # 服务层（P2 组，非 DI 接缝）—— bootstrap::shutdown 依 ADR-001
│   observ/ distributed/ deviceloop/
├── identity/ settings/ audit/ contractreg/ syshealth/   # 域层（P3 组，域内 DTO）—— 软依赖 #998 generated
adapters/
├── postgres/ redis/ amqp/ mqtt/ s3/ oidc/        # adapters 层（P3 组）—— sealed-marker newtype + native AFIT impl diport
│   grpc/ otel/ prometheus/ vault/ softca/ ratelimit/
generated/                                         # 不手写：契约派生（#998）
```

**Structure Decision**: 惯用扁平 Rust workspace。除 **PR-diport 新建 `crates/diport`**（ADR-003 §3：DI port + dynosaur wrapper + unsafe 收敛集中）外不新增目录结构——签名冻结在既有 34 member（+ diport）的 `src/` 内写公开 trait/type + `#[cfg(test)]` mock/shape 测试。每 crate 内部模块按 `domain-patterns.md`：`internal/ports`（域内非 DI 服务/值）、`internal/mem`（in-mem，本阶段仅签名占位）、`handler`/`application`/`domain`（域 crate DDD 分层）。DI 注入 port trait 集中 diport。**PR 粒度 = 层**（同层可再按 crate 子分组并行），跨层严格串行。

## 实施顺序与依赖门（计划核心）

```
PR-0  conventions 地基(ADR-004)  [门: ADR-002 + ADR-003 + ADR-001 三 ADR 已落地]
  └─→ PR-1  基础层 (5 crate)   [门: PR-0；runctx ctx 范式← ADR-002]   ┐
  └─→ PR-2  引擎层 (2 crate)   [门: PR-0 + PR-1；L0 静态分发]         ┘ 同层内并行
        └─→ PR-diport  DI port 收敛 [门: PR-1+PR-2；建 crate + dynosaur 可行性验证 ADR-003 §8]
              └─→ PR-3  服务层 (7 crate, 非 DI) [门: PR-diport；shutdown← ADR-001]
                    └─→ PR-4  域层 (5 crate, 域内) [门: PR-3；软门 #998 generated]   ┐ PR-4/PR-5
                    └─→ PR-5  adapters (12)       [门: PR-diport：DI port trait 已冻] ┘ 可并行(不同 crate)
                          └─→ [GATE] 全签名 review 通过 → 放行 W 宽扇出 (#1000–#1016)
```

- **横切硬门**：ADR-002(context)+ADR-003(dynosaur) gate 全部签名实施——决定每个 trait 方法签名与声明语法，先写后改=全量返工。均已落地。
- **DI port 门**：**PR-diport** 集中 DI 注入 port（dynosaur）+ 验证 ADR-003 §8 三开放风险 + 回写 architecture.md/deny.toml/rust-standards/domain-patterns，gate PR-3/4/5。
- **局部门**：ADR-001 gate `ManagedResource`（PR-2/PR-diport 待拍板）+ `bootstrap::shutdown`（PR-3）；#998 软 gate 域层 wire 引用（PR-4）。
- **同层并行**：PR-1 内 5 个基础 crate、PR-3 内 7 个服务 crate 互不依赖→可拆子 PR 并行；PR-4(域) 与 PR-5(adapters) 触不同 crate→可并行。
- **规划 vs 实施分离**：本计划现在产出（不阻塞），DI port 实施待 PR-diport 验证 dynosaur 可行性；若不可接受按 ADR-003 §5 回退 async-trait（spec 再 reconcile）。

## Complexity Tracking

| 违规（治理门） | 为何需要 | 拒绝的更简单替代 |
|---|---|---|
| 覆盖率门豁免（签名 PR <80%/90%） | body=`todo!()` 物理不可达，无行为可测；强测会逼出假测试 | 替代"在签名 PR 写真实现凑覆盖率"被拒：违反"只冻接缝不实现行为"，破坏并行冻结的全部价值。改为：签名 PR 声明豁免、覆盖率门移交对应行为 PR（W 阶段）兑现 |
| PR-0 引入 conventions"约定层" | 32 crate 签名若各写各的 dynosaur/mock 风格→W 阶段返工 + review 不可机判 | 替代"无 conventions、各 crate 自由发挥"被拒：AI co-author 易漂移，签名 review 无统一基准。conventions 是最小必要抽象（一份 ADR-004 文档，非代码框架） |
| PR-diport 引入 DI-infra crate（dynosaur 依赖收敛） | ADR-003：dynosaur/trait-variant 宏依赖须收敛到单 crate（DI port 集中）。§3 原设的 forbid→deny 例外被 #1049 spike 推翻——def-site hygiene 不触发 consumer forbid，diport 无 carve-out、全仓保持 forbid | 替代"DI port 留各域/服务 crate（async-trait）"= ADR-003 §5 已拒（成本模型）。收敛守卫 = deny.toml wrappers（Medium）。§8 三风险已在 PR-diport #1049 验证 |
