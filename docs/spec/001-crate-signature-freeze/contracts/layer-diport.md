# Contract: diport 层接缝（PR-diport）

> 范式见 conventions.md（单源 ADR-004）；决策单源 = **ADR-003**（`docs/architecture/202606212047-003-di-trait-async-dyn-dispatch-strategy.md`）。
>
> ADR-003 把可替换 provider 的 **DI 注入 port trait** 收敛进 **DI-infra 层** crate `diport`（基础/引擎之上、服务/域/adapter 之下，见 `docs/rules/architecture.md` §分层）。`dynosaur`/`trait-variant` 宏依赖经 `deny.toml` wrapper + `layer-deps` 收敛（DIPORT-MACRO-CONFINE-01**′**，Medium）。
>
> **ADR-005 修订（#1083）——归属二分**：本表只收 **provider-agnostic infra port**（签名只引基础/wire/自定义类型）。**域形 repo/service port**（`SessionRepo`/`ConfigRepo`/…，签名引用域内实体）**不归 diport**（否则 diport→域 反向依赖、层序倒置、deny 红），改归**所属域 crate `pub mod ports`**（Option 2）。dynosaur 宏收敛白名单随之扩到「diport + 定义自身 repo port 的域 crate」（-01′）。归属 category line 见 ADR-005 §2.1。
>
> **落地结论（PR-diport #1049 spike 实测，推翻 ADR-003 §3 原设的 forbid→deny 例外）**：dynosaur 0.3 生成的 `unsafe transmute` 经 def-site hygiene **不触发** consumer crate 的 `unsafe_code` lint——diport **无 forbid→deny 例外、无 unsafe carve-out**，与其它 crate 一致 `[lints] workspace = true`（仍继承 workspace `forbid`）。dynosaur→diport 收敛改由 deny.toml wrapper 守（DI port 集中，与 unsafe 无关）。本单元 = ADR-003 §8 推迟的「diport 落地 + dynosaur 可行性验证」单元，已落地。

## 冻结接缝（DI port trait 全集，dynosaur）

从 PR-2/PR-3/PR-4 收敛而来；具体清单与归属边界由本 PR 拍板（见 data-model 待决项）：

| 来源层 | DI port trait（举例） | 形态 |
|---|---|---|
| 引擎 | `Clock`（待决项#2 是否迁入）；`InboxStore`/`RetentionSweeper` 保持 `consistency` native AFIT，批量 `InboxBacklogSource` 保持 `eventexec` native AFIT，均不进入 diport | dynosaur `dyn(box)` wrapper |
| 服务 | `Publisher`/`Subscriber`（+ sync `SubscribeInitializer`）、`AuditSink`、`Pdp`、session/refresh store、`DistLock`、`Transport`、`Signer` | dynosaur（sync port 如 `SubscribeInitializer` 同 `Clock` 不需 dynosaur） |
| 生命周期 | `ManagedResource`（待决项#4 inter-ADR 冲突） | 暂遵 ADR-001（async_trait + `Arc<dyn>`）；PR-diport 统一→dynosaur 并同步重评 ADR-001 威胁矩阵 |
| ~~域~~ | ~~各域仓储/领域服务 repo port~~ → **移出本表（ADR-005 #1083）**：域形 repo port 归**所属域 crate `pub mod ports`**（签名引用域内实体，不得收敛 diport），非 diport | （域 crate；同款 dynosaur 范式） |

```rust
// crates/diport/Cargo.toml — 继承 workspace forbid，无 deny 覆盖、无 unsafe carve-out（落地结论）
// [lints] workspace = true

// crates/diport/src/<port>.rs — Send 变体 + dynosaur dyn(box) wrapper（static 零开销、dyn 才 box）
#[trait_variant::make(MyPort: Send)]                       // 生成 Send 变体 MyPort
#[dynosaur(pub DynMyPort = dyn(box) MyPort, bridge(dyn))]  // 据 Send 变体生成 dyn-compatible wrapper
#[allow(async_fn_in_trait)]                                // Send 由 trait_variant 变体 + dynosaur wrapper 承载
pub trait MyPortLocal {                            // 非 Send 基 trait，crate 根只 re-export Send 变体 + DynX
    async fn do_it(&self) -> Result<(), MyPortError>;   // native AFIT，无 #[async_trait]，body: todo!()
    async fn shutdown(&self) -> Result<(), MyPortError>; // 无 async Drop
}
```

## 落地门（ADR-003 §8 — PR-diport #1049 已验证 / 完成）

**三开放风险（dynosaur pre-1.0）落地结论**：

1. unsafe carve-out **不需要**：dynosaur 0.3 生成的 `unsafe transmute` 经 def-site hygiene 不触发 consumer forbid（`cargo build` 实测 + trybuild anti-vacuity 验证 forbid 对本 crate 手写 unsafe 仍生效）。无目标 `#[allow(unsafe_code)]`、无 ADR registry / lint 映射 carve-out。
2. 跨 crate sealing 不可行（§4.2）→ 采**方案 ②**：`deny.toml` wrapper 收敛 `dynosaur`/`trait-variant` **依赖**（只准 diport 依赖 ⇒ DI port 只在 diport 定义）。注意 cargo-deny 限「依赖」非「impl」——port-trait **impl-allowlist（限谁可 impl）当前未机器强制**，待 #1060 / PR-5。本 crate trait **不带** sealed supertrait。
3. dynosaur v0.3 API（`new_box`/`new_arc`）→ 已 pin `=0.3.0`；升级须复测 unsafe-hygiene 不变式 + 审 changelog。

**结构单源回写（PR-diport 已完成）**：`docs/rules/architecture.md` §扁平 workspace 结构树 + §分层、`Cargo.toml [workspace] members`（`crates/diport`）、`deny.toml` wrappers、`domain-patterns.md`（DI port 集中 + sealing 改 cargo-deny）。

**前置 follow-up**：`bootstrap` shutdown 框架（按注册逆序执行 `shutdown()`，把 ADR-003 §7 末条 Soft→Medium）须先于 port trait 大规模落地。

## 验证

- `cargo build -p diport` 绿；port trait 的 dyn-compatible compile-pass + compile-fail（`trybuild`，DIPORT-DYN-COMPAT-01 / DIPORT-UNSAFE-HYGIENE-01，Medium 回归锁）。
- `deny.toml` + layer-deps wrappers 绿：`dynosaur`/`trait-variant` **依赖**限白名单 = diport + 定义域形 port 的域 crate（DIPORT-MACRO-CONFINE-01′，ADR-005；限依赖非 impl；impl-allowlist 待 #1060）。
- diport 继承 workspace `forbid(unsafe_code)` 编译通过（无 deny 覆盖、无 carve-out）；adapter crate 保持 `forbid` 且不 invoke dynosaur 宏。
