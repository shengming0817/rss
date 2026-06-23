# Contract: 域层 + adapters 层接缝（PR-4 / PR-5）

> 范式见 conventions.md（单源 ADR-004）。域层软依赖 #998（generated wire 类型）。
>
> **重排（ADR-003 + ADR-005 #1083）**：DI port 归属二分——provider-agnostic **infra port** 收敛 `diport`（PR-diport，dynosaur）；**域形 repo/服务 port**（签名引用域内实体，不得收敛 diport）归**所属域 crate `pub mod ports`**（ADR-005 Option 2；trait + 最小签名实体集升 `pub`、字段私有 funnel；dynosaur 宏白名单扩到该域 crate，-01′）。`adapter→域` 经 DIP 内向边 impl 域形 port（`allows(Adapter,Domain)=true` + deny.toml 域 wrapper 加该 adapter）。PR-4 冻**域内 DTO + 非 DI 域逻辑 + 域形 repo port（代表性）**；PR-5 adapter 以 **native AFIT** impl diport infra port + 域形 repo port。

## PR-4 域层（identity / settings / audit / contractreg / syshealth）

域 crate = 一个 bounded context；feature 模块是其内子单元。冻**域内 DTO + 非 DI 域逻辑接缝 + 域形 repo/service DI port（`pub mod ports`，ADR-005）**，**不冻**跨域 wire 类型（contract/generated），**不冻** provider-agnostic infra DI port（在 diport）。

| crate | 冻结接缝（域内，非 DI） | 软门 |
|---|---|---|
| **identity** | 身份/会话/RBAC/ABAC 域内 DTO + 值对象 + 非 DI 域逻辑 | #998（会话/身份 wire 类型） |
| **settings** | 版本化配置/flag 域类型 | #998 |
| **audit** | 审计链域类型 | #998 |
| **contractreg** | 运行时契约域类型 | #998 |
| **syshealth** | 健康聚合域类型 | #998 |

要点：域间**互不 import**（deny.toml 编译期强制）；域依赖基础+引擎+服务+diport+generated（+ 域形 port 用 dynosaur/trait-variant，DIPORT-MACRO-CONFINE-01′ 白名单）。domain 类型**不 derive Serialize**（ADR-004 C6，Hard）。provider-agnostic infra DI port 见 diport；**域形 repo/service port 在本域 crate `pub mod ports`**（ADR-005）。

```rust
// identity — 域内 DTO / 值对象（不 derive Serialize；构造经 pub(crate) funnel）
pub(crate) struct SessionView { /* 域内只读投影，pub(crate) */ }

// identity::ports（ADR-005）— 域形 repo port 用 dynosaur，归本域 crate（签名引用域内实体 Session/SessionId）
pub use crate::domain::{IdentityError, Session, SessionId};   // 实体 façade：types pub、构造器 pub(crate)
pub use vocab::TenantId;                                      // typed tenant scope
#[trait_variant::make(SessionRepo: Send)]
#[dynosaur(pub DynSessionRepo = dyn(box) SessionRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait SessionRepoLocal {
    async fn find(&self, tenant: TenantId, id: SessionId) -> Result<Option<Session>, IdentityError>;  // body: todo!()
}
// adapter（postgres）依赖 identity、native AFIT impl SessionRepo（DIP 内向边，不 invoke dynosaur 宏）
```

## PR-5 adapters 层（12 crate）

adapters 实现 `diport` 定义的 DI port trait；**不被域依赖**（组合根注入），自身**不定义新 trait**——只冻 **unit sealed-marker**（raw client 字段延迟 W 阶段）+ native AFIT impl 已冻 diport trait 签名。

| 分组 | adapters | PR-5 impl 的**已冻** diport DI port trait |
|---|---|---|
| 全部 12 | postgres, redis, amqp, mqtt, s3, oidc, grpc, otel, prometheus, vault, softca, ratelimit | `ManagedResource`（生命周期 shutdown，普适） |
| 发布 | amqp, mqtt | 另 impl `Publisher` |
| 签名 | vault, softca | 另 impl `Signer` |
| 限流 | ratelimit | 另 impl `RateLimiter`（W 阶段 #1011 新定义于 diport；marker `RateLimiter`→`GovernorLimiter`） |

> 注：provider-agnostic 更专的 infra trait（设备 transport/证书签发/metrics/Subscriber…）diport 现**未冻**，待 W 阶段定义后再 impl。**W 阶段已落地**：`RateLimiter`（限流，#1011）按 ADR-005 category line 作为 provider-agnostic infra port 新增进 diport（async dynosaur，照 `signer.rs`），`ratelimit` 冻结 marker 随 body 落地由 `RateLimiter` 重命名为 provider 专名 `GovernorLimiter`（governor GCRA；冻结名仅示意、无外部消费方）。**域形 repo port（ADR-005）归域 crate `ports`**：本轮 `postgres` 已 impl 代表性 `identity::ports::RoleRepo`（adapter→域 DIP 边编译证明）；其余域 repo port 随 W 阶段逐域补 + 对应 adapter impl（按需把该 adapter 加入该域 deny.toml wrapper）。

要点：PR-5 冻 **unit sealed-marker**（`pub struct PgStore;`，无 raw client 字段——字段延迟 W 阶段接后端时填入、届时 `pub(crate)` 不泄漏），**native AFIT** impl 已冻 diport DI port trait body=todo!()。adapter crate **保持 `#![forbid(unsafe_code)]`**（只 import diport trait + `Dyn*`，自己不 invoke dynosaur 宏，ADR-003 §4.2）。adapters 本身不 mock（域 crate mock 的是 diport trait）。PR-5 与 PR-4 触不同 crate→可并行。

```rust
// adapters/postgres — unit sealed-marker（forbid(unsafe_code) 不变；raw client 字段延迟 W）
use diport::{ManagedResource, ShutdownError};               // diport infra port（不 invoke dynosaur 宏）
use identity::ports::{IdentityError, Role, RoleId, RoleRepo, TenantId}; // 域形 repo port（adapter→域 DIP 内向边，ADR-005）
pub struct PgStore;                            // W 阶段接后端时加 `pub(crate) sqlx::PgPool` 字段
impl ManagedResource for PgStore {             // native AFIT impl，无 #[async_trait]
    fn name(&self) -> &str { todo!() }
    async fn shutdown(&self) -> Result<(), ShutdownError> { todo!() }
}
impl RoleRepo for PgStore {                    // 域形 repo port impl（postgres 依赖 identity，DIP 内向）
    async fn find(&self, _tenant: TenantId, _id: RoleId) -> Result<Option<Role>, IdentityError> { todo!() }
    async fn save(&self, _tenant: TenantId, _role: Role) -> Result<(), IdentityError> { todo!() }
}
```
