//! diport —— DI 端口层（DI-infra）：可替换 provider 的依赖注入 port trait 单源。
//!
//! 分层位置：基础 / 引擎 **之上**、服务 / 域 / adapter **之下**（被它们消费）——`xtask`
//! `layers.rs` 的 `Layer::DiPort`。依赖基础 + 引擎；不依赖服务 / 域 / adapter（无 back-path）。
//! 跨域通信单源仍是 contract；DI infra port ≠ 跨域 wire，本 crate 不放 wire 类型（ADR-003 §6 偏离 2）。
//!
//! ## 派发策略（ADR-003）
//!
//! - **async DI port**（`Signer` / `KeyProvider` / `Publisher` / `Subscriber` / `AuditSink` / `RateLimiter` / `ObjectStore` / `Pdp` / `ManagedResource`）：native AFIT + dynosaur
//!   `#[dynosaur(DynX = dyn(box) X, bridge(dyn))]` 生成 dyn-compatible wrapper；static 路径零开销、
//!   dyn 路径才 box。组合根经 `Box<DynX>` / `Arc<DynX>` 注入（必填构造器位置参，缺失即编译错误）。
//!   - **Send**：dyn wrapper 的 boxed future 须 `Send`（ShutdownStack 经 `tokio::spawn` 隔离 panic）。
//!     由 `#[trait_variant::make(X: Send)]` 生成 Send 变体 + dynosaur `bridge(dyn)` 据此生成 Send 的
//!     `DynX`。本 crate 公开（`pub use`）的是 **Send 变体** `X` + `DynX`；非 Send 基 trait `XLocal`
//!     仅供静态分发的窄场景，不在 crate 根 re-export（避免方法解析歧义）。
//! - **sync DI port**（`Clock` / `SubscribeInitializer`）：sync trait 天然 dyn-compatible，经
//!   `Box<dyn _>` 注入，**不需** dynosaur（仅 async port 需要）。
//!
//! ## 注入形态（INVARIANT: DIPORT-ASYNC-ARC-SEND-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）
//!
//! async DI port 的 dynosaur Send 变体 `DynX` 是 **`Send` 但非 `Sync`**（`#[trait_variant::make(X: Send)]`
//! 只加 `Send`，内部 `dyn ErasedX` 无 `Sync`）。推论：`Box<DynX>: Send`（`Box<T>: Send ⟸ T: Send`）成立，
//! 但 `Arc<DynX>: Send` 需 `DynX: Send + Sync`，故 **`Arc<DynX>` 是 `!Send`**——无法被多次调用且在
//! `tokio::spawn` / Send `'static` future 中消费的 async 消费者（典型订阅 handler）持有。注入形态据此三分
//! （ADR-003 amendment §注入形态收口，#1095）：
//!
//! | 消费场景 | 注入形态 |
//! |----------|----------|
//! | 单 owner、非跨 Send-future（如 `ShutdownStack` 顺序关闭） | `Box<DynX>`（仅需 Send） |
//! | 多次调用 + 在 `tokio::spawn` / Send `'static` future 中消费 | **泛型静态分发** `<S: X + Send + Sync + 'static>` + `Arc<S>`（provider 经 trait bound 仍可互换，零运行期成本） |
//! | 单线程 / 不跨 Send-future 持有 | `Arc<DynX>`（窄场景） |
//!
//! 错误形态（`Arc<DynX>` 跨 Send future）**编译期不可表达**（Hard）；负例
//! `tests/ui/arc_dyn_ports_not_send.rs` 锁该事实（anti-vacuity：改 `Send + Sync` 即破）。泛型静态分发
//! 范例见 `audit::application::SessionCreatedAuditHandler`。Option A（改 `DynX: Send + Sync` 让 `Arc<DynX>`
//! 可 dyn 注入运行期多态）已评估 defer，见 ADR-003 amendment。
//!
//! ## 新增一个 async DI port（三步，照 `signer.rs` 抄）
//!
//! 1. 新建 `crates/diport/src/<port>.rs`，写基 trait（**非** Send，命名 `<Port>Local`），叠加两个属性宏：
//!    ```ignore
//!    #[trait_variant::make(MyPort: Send)]                       // 生成 Send 变体 `MyPort`
//!    #[dynosaur(pub DynMyPort = dyn(box) MyPort, bridge(dyn))]  // 据 Send 变体生成 dyn wrapper（pub 必加）
//!    #[allow(async_fn_in_trait)] // reason: Send 由 trait_variant 变体 + dynosaur wrapper 承载
//!    pub trait MyPortLocal { async fn do_it(&self) -> Result<(), MyPortError>; }
//!    ```
//! 2. 在本 `lib.rs` **只 re-export** Send 变体 `MyPort` + `DynMyPort` + 错误类型——**不**导出基 trait
//!    `MyPortLocal`（否则同名方法在 glob import 下解析歧义，见落地结论 / ADR-003）。
//! 3. `deny.toml` 的 dynosaur/trait-variant wrapper 已限定到本 crate，无需改；新外部宏依赖才需登记。
//!
//! **消费侧**（域 / 服务 / adapter）：`impl MyPort for ...`（Send 变体，**非** `MyPortLocal`）；组合根经
//! `DynMyPort::new_box(impl)` / `new_arc(impl)` 构造 `Box<DynMyPort>` / `Arc<DynMyPort>` 注入（必填构造器位置参）。
//!
//! ## key 标识选型（`KeyId` vs `KeyRef`，勿混用）
//!
//! 两个 port 的 key 标识语义不同，不可互替：
//! - [`signer::KeyId`]（签名 port）：**opaque 标识**，无版本语义，provider 内部据此选签名 key。
//! - [`key_provider::KeyRef`]（加解密 port）：**name + version 复合**，承载轮换语义（current-primary 写 /
//!   previous-read 解，ADR-011 §D3）；其 version [`key_provider::KeyVersion`] 严格定长常数时间匹配。
//!   加解密 adapter 用 `KeyRef`（**非** `KeyId`）；存储 token 经 `KeyRef::parse` ⇄ `to_token` 对称读写。
//!
//! ## sealing（ADR-003 §4.2 方案 ②）
//!
//! DI port trait 集中到独立 crate 后，sealed-trait（仅定义 crate 内封闭）无法对独立 adapter crate
//! sealing。本 crate trait **不带** sealed supertrait。
//!
//! `deny.toml` wrapper 收敛的是 **dynosaur/trait-variant 宏依赖**（只准 `diport` 依赖 ⇒ DI port
//! 只在 `diport` 定义，DIPORT-MACRO-CONFINE-01）——它**不**约束「谁可 **impl** port trait」：
//! cargo-deny 只能限依赖、不能限 impl 站点，且域 crate 也合法依赖 `diport`（为**消费**端口而非 impl）。
//! 故 impl-site allowlist（限 production impl 到 adapter / 组合根）改由 dylint 自写 lint
//! `rss_diport_impl_allowlist` 承载（AST 级，Medium，INVARIANT DIPORT-IMPL-ALLOWLIST-01）：非
//! adapter / 组合根路径下 impl 任一 diport port trait 即报。二者互补——cargo-deny 守**定义面**（port
//! 只在 `diport` 定义），dylint 守**impl 面**（port 只在 adapter / 组合根 impl）。#1060 闭环。
//!
//! ## INVARIANT: DIPORT-UNSAFE-HYGIENE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! ADR-003 §3 原设：dynosaur 宏注入 unsafe 到 consumer crate，须 `forbid`→`deny` 例外。**PR-diport
//! spike 实测推翻**：dynosaur 0.3 生成的 `unsafe transmute` 经 def-site hygiene **不触发** consumer
//! 的 `unsafe_code` lint——diport 即便 `forbid` 也编译通过（anti-vacuity 已验证 forbid 对本 crate
//! 手写 unsafe 仍生效）。故本 crate **无 forbid→deny 例外、无 unsafe carve-out**，与其它 crate 一致
//! `[lints] workspace = true`。dynosaur→diport 收敛改由 deny.toml wrapper 守（DI port 集中 + 单一
//! dyn-dispatch 依赖点），与 unsafe 无关。dynosaur exact-pin `=0.3.0`：升级须复测本不变式 + 审 changelog。

pub mod acker;
pub mod audit_sink;
pub mod cas_store;
pub mod checkpoint_store;
pub mod clock;
pub mod dead_letter_store;
pub mod envelope;
pub mod fenced_writer;
pub mod key_provider;
pub mod leader_elector;
pub mod lock_store;
pub mod managed_resource;
pub mod metrics_exporter;
pub mod object_store;
pub mod outbox_emitter;
pub mod pdp;
pub mod publisher;
pub mod rate_limiter;
// provider-error wrapper 共享脱敏 source 字段。`pub`（经下方 re-export 进公开 API 面）：`pub enum` 错误
// （`ObjectStoreError`）变体字段恒 public，须持 public 类型避免 privacy leak（#1120 merge：PR215 RedactedSource
// pub(crate) 与 PR214 pub-enum 错误不兼容）。
mod redacted;
// DTO 字节 payload 脱敏 newtype（`Debug`/`Display` 恒 `<redacted>`，经 `as_bytes`/`into_bytes` 受控访问）。
// `pub`（经下方 re-export 进公开 API 面）：pub struct DTO 的 pub 字节字段须持 public 类型避免 privacy leak。
mod redacted_bytes;
pub mod revocation_store;
pub mod saga_journal;
pub mod secret_resolver;
pub mod signer;
pub mod subscriber;

pub use acker::{
    AckAction, AckError, AckableSubscriber, Acker, Delivery, DeliveryStream, DynAckableSubscriber,
    DynAcker,
};
pub use audit_sink::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError, DynAuditSink};
pub use cas_store::{
    CasStore, CasStoreError, CasStoreKey, CasStoreOutcome, CasStoreRequest, DynCasStore,
};
pub use checkpoint_store::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    DynOwnerCheckpointStore, OwnerCheckpointStore, SaveOutcome,
};
pub use clock::Clock;
pub use dead_letter_store::{
    DeadLetterRecord, DeadLetterSource, DeadLetterStore, DeadLetterStoreError, DeadLetterSummary,
    DynDeadLetterStore, WritableDeadLetterSource,
};
pub use envelope::{
    EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL, KEY_SUBJECT_ID,
    KEY_TENANT_AUTHORITY, KEY_TENANT_ID, KEY_TRACE, MetadataError, RESERVED_METADATA_KEYS,
};
pub use fenced_writer::{
    DynFencedWriter, FencedWriteKey, FencedWriteRequest, FencedWriter, FencedWriterError,
    WriteOutcome,
};
pub use key_provider::{
    DynKeyProvider, EncryptOutput, KeyName, KeyParseError, KeyProvider, KeyProviderError, KeyRef,
    KeyVersion,
};
pub use leader_elector::{
    DynLeaderElector, LeaderElector, LeaderElectorError, LeaderId, LeaderIdError, LeaseToken,
};
pub use lock_store::{
    DynLockStore, LockAcquireOutcome, LockRenewOutcome, LockStore, LockStoreError, LockStoreKey,
};
pub use managed_resource::{
    DEFAULT_SHUTDOWN_TIMEOUT, DynManagedResource, ManagedResource, ShutdownError,
};
pub use metrics_exporter::MetricsExporter;
pub use object_store::{
    DynObjectStore, ObjectByteStream, ObjectKey, ObjectPayload, ObjectStore, ObjectStoreError,
};
pub use outbox_emitter::{DynOutboxEmitter, OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts};
pub use pdp::{
    CredentialScheme, DynPdp, Pdp, PdpError, RawCredential, SERVICE_TOKEN_TENANT_HEADER,
    SERVICE_TOKEN_TENANT_MAC_NAME, ServiceTokenTenantBinding, VerifiedClaims,
    service_token_mac_input,
};
pub use publisher::{
    DynPublisher, PublishErrorKind, PublishRequest, Publisher, PublisherError, Topic,
};
pub use rate_limiter::{
    DynRateLimiter, RateLimitDecision, RateLimitError, RateLimitKey, RateLimiter,
};
pub use redacted::RedactedSource;
pub use redacted_bytes::RedactedBytes;
pub use revocation_store::{
    CertScope, CertSerial, CertSerialError, DynRevocationStore, RevocationStore,
    RevocationStoreError,
};
pub use saga_journal::{
    DynSagaJournal, JournalEntry, JournalStatus, SagaId, SagaJournal, SagaJournalError,
};
pub use secret_resolver::{
    DynSecretResolver, SecretCoordinate, SecretMaterial, SecretResolver, SecretResolverError,
};
pub use signer::{DynSigner, KeyId, SignRequest, Signature, Signer, SignerError, SigningPurpose};
pub use subscriber::{
    DynSubscriber, Message, MessageId, MessageStream, SubscribeInitError, SubscribeInitializer,
    Subscriber, SubscriberError,
};
