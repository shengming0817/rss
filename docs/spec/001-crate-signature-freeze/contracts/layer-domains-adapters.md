# Contract: 域层 + adapters 层接缝（PR-4 / PR-5）

> 范式见 conventions.md（单源 ADR-004）。域层软依赖 #998（generated wire 类型）。
>
> **重排（ADR-003）**：域的仓储/领域服务 **DI port trait** 已收敛到 `diport`（PR-diport，dynosaur；`pub(crate)`→`pub` + deny.toml wrapper 收敛**宏依赖**（限**依赖**非 impl，§4.2 方案②）；port-trait impl-allowlist 待 #1060/PR-5）。PR-4 冻**域内 DTO + 非 DI 域逻辑**；PR-5 adapter 以 **native AFIT** impl diport 的 port trait。

## PR-4 域层（identity / settings / audit / contractreg / syshealth）

域 crate = 一个 bounded context；feature 模块是其内子单元。冻**域内 DTO + 非 DI 域逻辑接缝**，**不冻**跨域 wire 类型（contract/generated），**不冻** DI port trait（已迁 diport）。

| crate | 冻结接缝（域内，非 DI） | 软门 |
|---|---|---|
| **identity** | 身份/会话/RBAC/ABAC 域内 DTO + 值对象 + 非 DI 域逻辑 | #998（会话/身份 wire 类型） |
| **settings** | 版本化配置/flag 域类型 | #998 |
| **audit** | 审计链域类型 | #998 |
| **contractreg** | 运行时契约域类型 | #998 |
| **syshealth** | 健康聚合域类型 | #998 |

要点：域间**互不 import**（deny.toml 编译期强制）；域依赖基础+引擎+服务+diport+generated。domain 类型**不 derive Serialize**（ADR-004 C6，Hard）。仓储/服务 DI port 见 diport（dynosaur，非本文件）。

```rust
// identity — 域内 DTO / 值对象（不 derive Serialize；DI repo port 在 diport）
pub(crate) struct SessionView { /* 域内只读投影，pub(crate) */ }

// diport（PR-diport）— DI repo port 用 dynosaur，非本文件
// #[dynosaur::dynosaur(DynSessionRepo = dyn(box) SessionRepo)]
// pub trait SessionRepo: Send + Sync { async fn find(&self, id: SessionId) -> Result<Option<Session>, IdentityError>; }
```

## PR-5 adapters 层（12 crate）

adapters 实现 `diport` 定义的 DI port trait；**不被域依赖**（组合根注入），自身**不定义新 trait**——只冻 **unit sealed-marker**（raw client 字段延迟 W 阶段）+ native AFIT impl 已冻 diport trait 签名。

| 分组 | adapters | PR-5 impl 的**已冻** diport DI port trait |
|---|---|---|
| 全部 12 | postgres, redis, amqp, mqtt, s3, oidc, grpc, otel, prometheus, vault, softca, ratelimit | `ManagedResource`（生命周期 shutdown，普适） |
| 发布 | amqp, mqtt | 另 impl `Publisher` |
| 签名 | vault, softca | 另 impl `Signer` |

> 注：repo/store/设备 transport/证书签发/metrics/Subscriber 等更专的 trait diport 现**未冻**，待 W 阶段定义后再 impl；故 PR-5 仅 impl 已冻的 4 个 DI port trait。

要点：PR-5 冻 **unit sealed-marker**（`pub struct PgStore;`，无 raw client 字段——字段延迟 W 阶段接后端时填入、届时 `pub(crate)` 不泄漏），**native AFIT** impl 已冻 diport DI port trait body=todo!()。adapter crate **保持 `#![forbid(unsafe_code)]`**（只 import diport trait + `Dyn*`，自己不 invoke dynosaur 宏，ADR-003 §4.2）。adapters 本身不 mock（域 crate mock 的是 diport trait）。PR-5 与 PR-4 触不同 crate→可并行。

```rust
// adapters/postgres — unit sealed-marker（forbid(unsafe_code) 不变；raw client 字段延迟 W）
use diport::{ManagedResource, ShutdownError};  // import 已冻 diport trait（不 invoke dynosaur 宏）
pub struct PgStore;                            // W 阶段接后端时加 `pub(crate) sqlx::PgPool` 字段
impl ManagedResource for PgStore {             // native AFIT impl，无 #[async_trait]
    fn name(&self) -> &str { todo!() }
    async fn shutdown(&self) -> Result<(), ShutdownError> { todo!() }
}
```
