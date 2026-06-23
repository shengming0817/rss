//! diport —— DI 端口层（DI-infra）：可替换 provider 的依赖注入 port trait 单源。
//!
//! 分层位置：基础 / 引擎 **之上**、服务 / 域 / adapter **之下**（被它们消费）——`xtask`
//! `layers.rs` 的 `Layer::DiPort`。依赖基础 + 引擎；不依赖服务 / 域 / adapter（无 back-path）。
//! 跨域通信单源仍是 contract；DI infra port ≠ 跨域 wire，本 crate 不放 wire 类型（ADR-003 §6 偏离 2）。
//!
//! ## 派发策略（ADR-003）
//!
//! - **async DI port**（`Signer` / `Publisher` / `Subscriber` / `AuditSink` / `ManagedResource`）：native AFIT + dynosaur
//!   `#[dynosaur(DynX = dyn(box) X, bridge(dyn))]` 生成 dyn-compatible wrapper；static 路径零开销、
//!   dyn 路径才 box。组合根经 `Box<DynX>` / `Arc<DynX>` 注入（必填构造器位置参，缺失即编译错误）。
//!   - **Send**：dyn wrapper 的 boxed future 须 `Send`（ShutdownStack 经 `tokio::spawn` 隔离 panic）。
//!     由 `#[trait_variant::make(X: Send)]` 生成 Send 变体 + dynosaur `bridge(dyn)` 据此生成 Send 的
//!     `DynX`。本 crate 公开（`pub use`）的是 **Send 变体** `X` + `DynX`；非 Send 基 trait `XLocal`
//!     仅供静态分发的窄场景，不在 crate 根 re-export（避免方法解析歧义）。
//! - **sync DI port**（`Clock` / `SubscribeInitializer`）：sync trait 天然 dyn-compatible，经
//!   `Box<dyn _>` 注入，**不需** dynosaur（仅 async port 需要）。
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
//! ## INVARIANT: DIPORT-UNSAFE-HYGIENE-01
//!
//! ADR-003 §3 原设：dynosaur 宏注入 unsafe 到 consumer crate，须 `forbid`→`deny` 例外。**PR-diport
//! spike 实测推翻**：dynosaur 0.3 生成的 `unsafe transmute` 经 def-site hygiene **不触发** consumer
//! 的 `unsafe_code` lint——diport 即便 `forbid` 也编译通过（anti-vacuity 已验证 forbid 对本 crate
//! 手写 unsafe 仍生效）。故本 crate **无 forbid→deny 例外、无 unsafe carve-out**，与其它 crate 一致
//! `[lints] workspace = true`。dynosaur→diport 收敛改由 deny.toml wrapper 守（DI port 集中 + 单一
//! dyn-dispatch 依赖点），与 unsafe 无关。dynosaur exact-pin `=0.3.0`：升级须复测本不变式 + 审 changelog。

pub mod audit_sink;
pub mod clock;
pub mod managed_resource;
pub mod publisher;
pub mod signer;
pub mod subscriber;

pub use audit_sink::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError, DynAuditSink};
pub use clock::Clock;
pub use managed_resource::{
    DEFAULT_SHUTDOWN_TIMEOUT, DynManagedResource, ManagedResource, ShutdownError,
};
pub use publisher::{DynPublisher, PublishRequest, Publisher, PublisherError, Topic};
pub use signer::{DynSigner, KeyId, SignRequest, Signature, Signer, SignerError, SigningPurpose};
pub use subscriber::{
    DynSubscriber, Message, MessageId, MessageMetadata, MessageStream, SubscribeInitError,
    SubscribeInitializer, Subscriber, SubscriberError,
};
