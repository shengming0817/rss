# Contract: diport 层接缝（PR-diport）

> 范式见 conventions.md（单源 ADR-004）；决策单源 = **ADR-003**（`docs/architecture/202606212047-003-di-trait-async-dyn-dispatch-strategy.md`）。
>
> 计划重排引入的新单元：ADR-003 把可替换 provider 的 **DI 注入 port trait** 收敛进一个专用服务层 crate `diport`——因 dynosaur 宏展开注入 `unsafe transmute`，必须集中到单一 crate（forbid→deny 例外，§3）。本单元 = ADR-003 §8 推迟的「diport 落地 + dynosaur 可行性验证」单元。

## 冻结接缝（DI port trait 全集，dynosaur）

从 PR-2/PR-3/PR-4 收敛而来；具体清单与归属边界由本 PR 拍板（见 data-model 待决项）：

| 来源层 | DI port trait（举例） | 形态 |
|---|---|---|
| 引擎 | `Clock`（待决项#2 是否迁入）、`IdempotencyStore`（如需 dyn） | dynosaur `dyn(box)` wrapper |
| 服务 | `Publisher`/`Subscriber`、`Pdp`、session/refresh store、`DistLock`、`Transport`、`Signer` | dynosaur |
| 生命周期 | `ManagedResource`（待决项#4 inter-ADR 冲突） | 暂遵 ADR-001（async_trait + `Arc<dyn>`）；PR-diport 统一→dynosaur 并同步重评 ADR-001 威胁矩阵 |
| 域 | 各域仓储/领域服务 repo port（`SessionRepo`/`ConfigRepo`/…，`pub`） | dynosaur |

```rust
// crates/diport/src/lib.rs
#![deny(unsafe_code)] // crate 根：deny（非 forbid），仅本 crate；其余 crate 继承 workspace forbid

// crates/diport/src/store.rs — dynosaur 生成 dyn-compatible DynUserStore，static 零开销、dyn 才 box
#[dynosaur::dynosaur(DynUserStore = dyn(box) UserStore)]
pub trait UserStore: Send + Sync {                 // native AFIT，无 #[async_trait]
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError>;  // body: todo!()
    async fn shutdown(&self) -> Result<(), StoreError>;                  // 无 async Drop
}
```

## 落地门（ADR-003 §8 — 本 PR 验收前必须验证 / 完成）

**三开放风险（dynosaur pre-1.0）**：

1. 目标 `#[allow(unsafe_code)]` 可达性 + carve-out 登记（`cargo expand` 实测；按 error-handling.md §Carve-out 更新 ADR registry + lint 映射 + 展开点 `// SAFETY:`）。
2. 跨 crate sealing 不可行（§4.2）→ 二选一 ①（impl 收回 diport）/ ②（deny.toml wrappers 限定实现方，倾向 ②）。
3. dynosaur v0.3 API（`new_box`/`from_box`）破坏式演进 → pin `=0.3.x` + 升级审 changelog。

**结构单源回写（同 PR，三处一并改防漂移）**：`docs/rules/architecture.md` §扁平 workspace 结构树 + §分层、`Cargo.toml [workspace] members`（加 `crates/diport`）、`deny.toml` wrappers；并回写 `rust-standards.md §工程护栏`（diport forbid 例外）+ `domain-patterns.md`（DI port 集中 + sealing 改 cargo-deny）。

**前置 follow-up**：`bootstrap` shutdown 框架（按注册逆序执行 `shutdown()`，把 ADR-003 §7 末条 Soft→Medium）须先于 port trait 大规模落地。

**回退触发**：三风险任一不可接受 → 按 ADR-003 §5 以 async-trait 重评，spec 须再 reconcile。

## 验证

- `cargo build -p diport` 绿；首个 port trait 的 dyn-compatible compile-pass + compile-fail（`trybuild`，Medium 回归锁）。
- `deny.toml` wrappers 绿：`dynosaur` 依赖仅 diport；impl diport port trait 的 crate 集受限。
- adapter crate 保持 `#![forbid(unsafe_code)]` 编译通过（不 invoke dynosaur 宏）。
