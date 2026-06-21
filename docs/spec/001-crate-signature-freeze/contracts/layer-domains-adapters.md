# Contract: 域层 + adapters 层接缝（PR-4 / PR-5）

> 范式见 conventions.md（单源 ADR-004）。域层软依赖 #998（generated wire 类型）。
>
> **重排（ADR-003）**：域的仓储/领域服务 **DI port trait** 已收敛到 `diport`（PR-diport，dynosaur；`pub(crate)`→`pub` + deny.toml wrappers 限定实现方，§4.2 方案②）。PR-4 冻**域内 DTO + 非 DI 域逻辑**；PR-5 adapter 以 **native AFIT** impl diport 的 port trait。

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

adapters 实现 `diport`（及引擎）定义的 trait；**不被域依赖**（组合根注入），自身**不定义新 trait**——只冻 sealed-marker newtype 骨架 + native AFIT impl 签名。

| 分组 | adapters | 实现的上层 trait（举例） |
|---|---|---|
| 核心存储/消息 | postgres, redis, amqp | diport: repo/store/Publisher/Subscriber |
| 设备 | mqtt, softca | diport: 设备 transport / 证书签发 |
| REST/外部 | s3, oidc, grpc, otel, prometheus, vault, ratelimit | diport: 对应 DI port |

要点：`pub struct PgStore(pub(crate) sqlx::PgPool);` raw client `pub(crate)`，外部无法触达；**native AFIT** impl diport trait body=todo!()。adapter crate **保持 `#![forbid(unsafe_code)]`**（只 import diport trait + `Dyn*`，自己不 invoke dynosaur 宏，ADR-003 §4.2）。adapters 本身不 mock（域 crate mock 的是 diport trait）。PR-5 与 PR-4 触不同 crate→可并行。

```rust
// adapters/postgres — sealed-marker newtype（forbid(unsafe_code) 不变）
use diport::SessionRepo;                       // import diport trait（不 invoke dynosaur 宏）
pub struct PgStore(pub(crate) sqlx::PgPool);    // raw client pub(crate)
impl SessionRepo for PgStore {                  // native AFIT impl，无 #[async_trait]
    async fn find(&self, _id: SessionId) -> Result<Option<Session>, IdentityError> { todo!() }
}
```
