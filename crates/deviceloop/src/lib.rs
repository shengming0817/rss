//! deviceloop — L4 设备长延迟收敛模型。
//!
//! 对标：
//! - kube-rs `kube-runtime/src/controller/mod.rs`（`reconcile(obj, ctx) -> Result<Action, E>` +
//!   `error_policy`；`Action::requeue / await_change`）
//! - statig `statig/src/lib.rs`（显式 state/event transition；RSS 使用手写闭值集，不引入宏）
//! - rcgen `rcgen/src/lib.rs`（`CertificateParams` / `SanType` / `ExtendedKeyUsagePurpose`——
//!   RSS 用 provider-agnostic enum，不依赖 rcgen；实际签发经 `diport::Signer`）
//!
//! 分层：服务层（依赖基础 + 引擎 + `diport`；不依赖域 / adapters）。

pub mod command;
pub mod condition;
pub mod generation;
pub mod policy;

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

pub use command::{
    CommandProgressRestore, CommandProgressSnapshot, CommandRestoreCommon, CommandSnapshotCommon,
    CommandTransitionOutcome, CommandVersion, DeviceCommandError, DeviceCommandId,
    DeviceCommandRestore, DeviceCommandScope, DeviceCommandSnapshot, DeviceCommandSnapshotView,
    DeviceCommandState, DeviceCommandStatus, DeviceCommandTransition, DeviceCommandTransitionError,
};
pub use condition::{
    ConditionRestoreError, ConditionStatus, DegradedCondition, DegradedConditionRestore,
    DegradedConditionSnapshot, DegradedConditionState, DegradedReason, DeletingCondition,
    DeletingConditionRestore, DeletingConditionSnapshot, DeletingConditionState, DeletingReason,
    DeviceCondition, DeviceConditionKind, DeviceConditionRestore, DeviceConditionSnapshot,
    DeviceConditionState, NotReadyStatus, PendingDeviceCondition, PendingDeviceConditionRestore,
    PendingDeviceConditionSnapshot, PendingDeviceConditionState, PendingDeviceReason,
    QuarantinedCondition, QuarantinedConditionRestore, QuarantinedConditionSnapshot,
    QuarantinedConditionState, QuarantinedReason, ReadyCondition, ReadyConditionRestore,
    ReadyConditionSnapshot, ReadyConditionState, ReadyReason, ReconcilingCondition,
    ReconcilingConditionRestore, ReconcilingConditionSnapshot, ReconcilingConditionState,
    ReconcilingReason,
};
pub use generation::{
    CurrentFence, CurrentFenceReportRestore, DesiredAdvanceError, DesiredGeneration,
    FenceCoordinate, FenceEpoch, GenerationRestore, GenerationRestoreError, GenerationSnapshot,
    GenerationTracker, InvalidGenerationCoordinate, MatchingReportedState, NewerGeneration,
    ObservedGeneration, ObservedHighWaterRestore, ReportOutcome,
};
pub use policy::{
    CertificateKeyUsage, CertificatePolicy, CertificatePolicyDurations, CertificatePolicyError,
    CertificateRenewBeforeSeconds, CertificateSan, CertificateValiditySeconds,
};

// 证书生命周期 API 以 `diport::CertScope`（tenant + device）为第一等输入——租户边界 correct-by-construction
// 进入函数签名（F2，零信任）：reconcile / 签发 / 撤销 共用同一 scope，杜绝从 ambient ctx 二次查租户。
// CertScope 内含基础层 `ids::DeviceId`（uuid 背书），reconcile 实现期构造撤销 `CertScope` 零桥接。
use diport::{CertScope, DynRevocationStore, DynSigner, SignerError};

// ── CertLifecycleState ────────────────────────────────────────────────────────

/// 设备证书生命周期状态（L4 desired-state 收敛环）。
///
/// 状态机驱动 reconcile；`#[non_exhaustive]` 允许后续增态而不破坏 match 调用方。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertLifecycleState {
    /// 初始态：证书尚未申请。
    Uninit,
    /// 申请中。
    Pending { since: SystemTime },
    /// 有效态。
    Active { expires_at: SystemTime },
    /// 续期中（已进入续期窗口）。
    Renewing { since: SystemTime },
    /// 已撤销。
    Revoked,
    /// 签发失败，等待重试。
    Failed { retry_after: Duration },
}

// ── CertLifecycleEvent ────────────────────────────────────────────────────────

/// 驱动 `CertLifecycleState` 转换的事件。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CertLifecycleEvent {
    /// 签发成功。
    Issued { expires_at: SystemTime },
    /// 证书被撤销。
    Revoked,
    /// 进入续期窗口。
    RenewalWindowEntered,
    /// 签发失败。
    IssuanceFailed,
}

// ── CertAction ────────────────────────────────────────────────────────────────

/// reconcile 动作（对齐 kube-rs `Action::requeue` / `await_change`）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CertAction {
    /// 延迟后重新入队。
    RequeueAfter(Duration),
    /// 无需主动重试，等待外部事件。
    Idle,
}

// ── CertReconcileCtx ─────────────────────────────────────────────────────────

/// reconcile 上下文（私有字段；signer / revocation_store 等依赖经构造器注入）。
///
/// `DynSigner<'static>` / `DynRevocationStore<'static>`：provider 在 assembly 级别构造，生命周期 `'static`。
pub struct CertReconcileCtx {
    // reason: 签名冻结阶段 body = todo!()，ADR-004 C8 覆盖率豁免；字段将在实现阶段被 reconcile 逻辑读取。
    #[allow(dead_code)]
    signer: Box<DynSigner<'static>>,
    // reason: 同 signer——签名冻结阶段 body = todo!()；reconcile 实现阶段消费（撤销发起 + 收敛前查 is_revoked）。
    #[allow(dead_code)]
    revocation_store: Box<DynRevocationStore<'static>>,
}

impl CertReconcileCtx {
    /// 构造 reconcile 上下文（必填位置参，缺失即编译错误）。
    // reason: 签名冻结阶段 body = todo!() 阻止 Box 参数 move 入 struct，触发 boxed_local 误报（Box<DynX>
    // 是 DI port 注入约定形式、非多余 boxing）；该临时豁免由 ADR-004 C8 签名冻结覆盖，实现阶段 body 落地后移除。
    #[allow(clippy::boxed_local)]
    pub fn new(
        _signer: Box<DynSigner<'static>>,
        _revocation_store: Box<DynRevocationStore<'static>>,
    ) -> Self {
        todo!()
    }
}

// ── reconcile_cert / cert_error_policy ───────────────────────────────────────

/// L4 reconcile（对齐 kube-rs `reconcile fn`；不 spawn task，由驱动层提供并发）。
///
/// 入口承载 [`CertScope`]（tenant + device）——租户边界进入签名，sign / revoke / is_revoked 从同一 scope 派生。
pub async fn reconcile_cert(
    _scope: &CertScope,
    _ctx: &CertReconcileCtx,
) -> Result<CertAction, CertReconcileError> {
    todo!()
}

/// error policy（对齐 kube-rs `error_policy`）。
pub fn cert_error_policy(
    _scope: &CertScope,
    _error: &CertReconcileError,
    _ctx: &CertReconcileCtx,
) -> CertAction {
    todo!()
}

// ── CertSignRequest ───────────────────────────────────────────────────────────

/// 证书签发请求（provider-agnostic，对齐 rcgen 语义；实际签发经 `diport::Signer`）。
///
/// 字段集 pre-GA 可演进（algorithm / correlation）；不 derive `Serialize`（服务层类型不上 wire）。
#[derive(Debug, Clone)]
pub struct CertSignRequest {
    /// 目标证书作用域（tenant + device）——签发请求绑定租户边界（correct-by-construction）。
    pub scope: CertScope,
    /// 证书有效期。
    pub validity: Duration,
    /// 密钥用途。
    pub key_usages: Vec<CertKeyUsage>,
    /// Subject Alternative Names。
    pub sans: Vec<CertSan>,
}

/// 证书密钥用途（对齐 rcgen `ExtendedKeyUsagePurpose`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertKeyUsage {
    /// TLS 客户端认证（设备向服务端出示证书）。
    ClientAuth,
    /// TLS 服务端认证。
    ServerAuth,
}

/// Subject Alternative Name（对齐 rcgen `SanType`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertSan {
    /// DNS 域名。
    DnsName(String),
    /// IP 地址。
    IpAddress(IpAddr),
    /// URI（SPIFFE ID 等）。
    Uri(String),
}

// ── CertReconcileError ────────────────────────────────────────────────────────

/// reconcile 错误（thiserror；`#[error]` 静态字面量，不含 runtime 数据）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CertReconcileError {
    /// 签名 provider 返回错误。
    #[error("signing failed")]
    SigningFailed(#[from] SignerError),
    /// 证书参数非法。
    #[error("invalid cert params")]
    InvalidParams,
    /// 存储不可用。
    #[error("store unavailable")]
    StoreUnavailable,
}

// ── smoke tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    use super::{
        CertAction, CertKeyUsage, CertLifecycleEvent, CertLifecycleState, CertSan, CertSignRequest,
    };
    use diport::CertScope;
    use ids::DeviceId;

    fn _assert_send<T: Send>() {}

    // Finding#5（PORT-SHAPE）：锁 DynSigner + DynRevocationStore 注入形状——Noop impl Send 变体，
    // 验证 new_box 构造路径 + CertReconcileCtx::new 函数签名 + Box<DynX<'static>> 可 Send。
    struct NoopSigner;
    impl diport::Signer for NoopSigner {
        async fn sign(
            &self,
            _request: diport::SignRequest,
        ) -> Result<diport::Signature, diport::SignerError> {
            todo!()
        }
        async fn shutdown(&self) -> Result<(), diport::SignerError> {
            todo!()
        }
    }

    struct NoopRevocationStore;
    impl diport::RevocationStore for NoopRevocationStore {
        async fn revoke(
            &self,
            _serial: diport::CertSerial,
            _scope: diport::CertScope,
            _not_after: diport::CertNotAfter,
        ) -> Result<(), diport::RevocationStoreError> {
            todo!()
        }
        async fn is_revoked(
            &self,
            _serial: diport::CertSerial,
            _scope: diport::CertScope,
        ) -> Result<bool, diport::RevocationStoreError> {
            todo!()
        }
        async fn shutdown(&self) -> Result<(), diport::RevocationStoreError> {
            todo!()
        }
    }

    #[test]
    fn dyn_signer_injection_shape() {
        // 构造 Box<DynSigner / DynRevocationStore<'static>>（只构造不 await，body 为 todo!() 不影响类型检查）
        let _s: Box<diport::DynSigner<'static>> = diport::DynSigner::new_box(NoopSigner);
        let _r: Box<diport::DynRevocationStore<'static>> =
            diport::DynRevocationStore::new_box(NoopRevocationStore);
        // 绑定 CertReconcileCtx::new 函数指针——签名变更即编译失败（Hard：类型系统守）
        let _f: fn(
            Box<diport::DynSigner<'static>>,
            Box<diport::DynRevocationStore<'static>>,
        ) -> super::CertReconcileCtx = super::CertReconcileCtx::new;
        // Box<DynX<'static>> 可 Send（跨 tokio::spawn 安全）
        _assert_send::<Box<diport::DynSigner<'static>>>();
        _assert_send::<Box<diport::DynRevocationStore<'static>>>();
    }

    #[test]
    fn lifecycle_state_uninit_constructible() {
        let s = CertLifecycleState::Uninit;
        assert_eq!(s, CertLifecycleState::Uninit);
    }

    // Finding#6 & Finding#10：补全 CertLifecycleEvent / CertSan 所有变体 + 穷尽 match；
    // 同 crate 内 non_exhaustive 不强制 `_` 臂，直接列全变体即可，无需 allow(unreachable_patterns)。
    #[test]
    fn cert_lifecycle_event_all_variants() {
        use std::time::SystemTime;
        // 构造所有变体（body 为 todo!() 的签名冻结阶段不依赖运行时值；SystemTime::now() 仅构造用）
        let events = [
            CertLifecycleEvent::Issued {
                expires_at: SystemTime::UNIX_EPOCH,
            },
            CertLifecycleEvent::Revoked,
            CertLifecycleEvent::RenewalWindowEntered,
            CertLifecycleEvent::IssuanceFailed,
        ];
        for e in &events {
            // 穷尽 match（同 crate 内不需要 `_` 臂）
            match e {
                CertLifecycleEvent::Issued { .. } => {}
                CertLifecycleEvent::Revoked => {}
                CertLifecycleEvent::RenewalWindowEntered => {}
                CertLifecycleEvent::IssuanceFailed => {}
            }
        }
    }

    #[test]
    fn cert_san_all_variants() {
        use std::net::{IpAddr, Ipv4Addr};
        let sans = [
            CertSan::DnsName("device.example.com".to_string()),
            CertSan::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            CertSan::Uri("spiffe://example.com/device/1".to_string()),
        ];
        for s in &sans {
            // 穷尽 match（同 crate 内不需要 `_` 臂）
            match s {
                CertSan::DnsName(_) => {}
                CertSan::IpAddress(_) => {}
                CertSan::Uri(_) => {}
            }
        }
    }

    #[test]
    fn cert_action_idle_constructible() {
        let a = CertAction::Idle;
        // 穷尽 match（同 crate 内不需要 `_` 臂）
        match a {
            CertAction::RequeueAfter(_) => {}
            CertAction::Idle => {}
        }
    }

    #[test]
    fn cert_key_usage_client_auth_constructible() {
        let u = CertKeyUsage::ClientAuth;
        // 穷尽 match（同 crate 内不需要 `_` 臂）
        match u {
            CertKeyUsage::ClientAuth => {}
            CertKeyUsage::ServerAuth => {}
        }
    }

    #[test]
    fn reconcile_fns_bind_certscope_signature() {
        // F2 签名锁（Hard：类型系统守 typed tenancy 边界）——回退到裸 DeviceId / 去掉 scope 即编译失败。
        // cert_error_policy 是 sync，强制 typed fn 指针锁定首参为 &CertScope。
        let _policy: fn(
            &CertScope,
            &super::CertReconcileError,
            &super::CertReconcileCtx,
        ) -> CertAction = super::cert_error_policy;
        // reconcile_cert 是 async fn（返回 opaque future，不可裸 fn 指针）——type-annotated 闭包锁定首参 &CertScope；
        // 仅构造 future 不 poll，body 的 todo!() 不执行。
        let _reconcile = |scope: &CertScope, ctx: &super::CertReconcileCtx| {
            let _fut = super::reconcile_cert(scope, ctx);
        };
        let _ = (_policy, _reconcile);
    }

    #[test]
    fn cert_sign_request_is_send() {
        _assert_send::<CertSignRequest>();
    }

    #[test]
    fn device_id_smoke() {
        // 设备标识统一为 `ids::DeviceId`（与 diport::CertScope 同一类型）——构造 funnel 可见。
        let _: fn(&str) -> Result<DeviceId, ids::IdParseError> = DeviceId::parse;
    }
}
