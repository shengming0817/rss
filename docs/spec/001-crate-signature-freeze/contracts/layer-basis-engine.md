# Contract: 基础层 + 引擎层接缝（PR-1 / PR-2）

> 范式见 conventions.md（单源 ADR-004）。形态为骨架示意（todo!()），具体字段以实现 PR 为准；清单源自 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`。

## PR-1 基础层（vocab / ids / secure / support / runctx）

| crate | 冻结接缝（公开 type/trait） | 派发范式 |
|---|---|---|
| **vocab** | error 枚举（thiserror，message const）、authz/tenant/query 基础词汇 type、`ContractOwner`(sealed enum) | sync |
| **ids** | sealed newtype ID（私有字段：`pub struct UserId(Uuid);`），构造 funnel | sync |
| **secure** | redaction / aead / cookie / pathsafe 的 trait + 值类型 | 视情况（L0 纯计算 → 静态分发；如需 dyn provider 见 diport） |
| **support** | http / pg / validation 杂项 helper 签名 | sync |
| **runctx** | `RequestCtx<T,P>`（sealed struct + `task_local!`，**遵 ADR-002 D2**：私有字段、不 derive Deserialize、需 ctx 处显式传 `&RequestCtx`） | sync |

要点：基础层仅依赖 std + 外部 crate（serde/thiserror/uuid…），不依赖任何内部分组（deny.toml 守）。`cargo public-api` baseline 必产。

```rust
// vocab — 错误枚举范式（message const literal）
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum DomainError {
    #[error("resource not found")]
    NotFound,
    // ...
}

// ids — sealed newtype（私有字段=硬封）
pub struct UserId(uuid::Uuid);
impl UserId { pub fn new(_raw: uuid::Uuid) -> Self { todo!() } }
```

## PR-2 引擎层（consistency / primitives）

| crate | 冻结接缝 | 派发范式 | 门 |
|---|---|---|---|
| **consistency** | outbox / inbox / saga / reconcile / projection / idempotency 的**纯态机 + trait**（L0–L4），如 `InboxStore`、`OutboxRelay`、`Reconciler` | **L0 引擎策略：native AFIT + 泛型 `<S: Trait>`**（零开销，不引 dynosaur）；`InboxStore`/`RetentionSweeper` 不迁入 diport；runtime 批量 inbox 可观测接缝归 `eventexec::InboxBacklogSource` | — |
| **primitives** | crypto / authplan / healthz / circuitbreaker（纯计算/原语） | native/sync | — |
| **primitives::lifecycle / Clock**（**归属待 diport 拍板**） | `Clock`、`ManagedResource` | `Clock` 构造器位参、禁默认系统时钟；ADR-003 §2/§4.3 列 Clock 为 DI port → **推荐迁 diport**（dynosaur）。`ManagedResource` 见 ADR-001（inter-ADR 冲突，data-model 待决项#4） | ADR-001 / 待决项#2#4 |

要点：引擎依赖基础，不依赖服务/域/adapters。`Reconciler` 接缝对标 kube-rs（函数式而非 dyn，见 research.md D3）。`cargo public-api` baseline 必产（引擎 ≥90% 覆盖在行为 PR 兑现）。

```rust
// primitives — 纯计算引擎策略：native AFIT + 泛型静态分发（L0，零开销）
pub trait IdemCheck {
    async fn seen(&self, key: &IdemKey) -> Result<bool, EngineError>;  // body: todo!()
}

// Clock / ManagedResource（provider-可换 DI port）推荐归 diport（dynosaur），见 contracts/layer-diport.md。
// 在 diport 落地前，primitives 仅占位非 DI 纯计算接缝。
```
