//! deviceloop — L4 设备证书生命周期收敛环（签名冻结；所有函数体 = `todo!()`，ADR-004 C8 豁免）。
//!
//! 对标：
//! - kube-rs `kube-runtime/src/controller/mod.rs`（`reconcile(obj, ctx) -> Result<Action, E>` +
//!   `error_policy`；`Action::requeue / await_change`）
//! - rcgen `rcgen/src/lib.rs`（`CertificateParams` / `SanType` / `ExtendedKeyUsagePurpose`——
//!   RSS 用 provider-agnostic enum，不依赖 rcgen；实际签发经 `diport::Signer`）
//!
//! 分层：服务层（依赖基础 + 引擎 + `diport`；不依赖域 / adapters）。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use diport::{DynSigner, SignerError};

// ── DeviceId ──────────────────────────────────────────────────────────────────

/// 设备唯一标识（newtype funnel；私有字段，单一构造入口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId(String);

impl DeviceId {
    /// 由字符串构造设备 ID。
    pub fn new(_id: impl Into<String>) -> Self {
        todo!()
    }
    /// 借出底层标识。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

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

/// reconcile 上下文（私有字段；signer 等依赖经构造器注入）。
///
/// `DynSigner<'static>`：provider 在 assembly 级别构造，生命周期 `'static`。
pub struct CertReconcileCtx {
    // reason: 签名冻结阶段 body = todo!()，ADR-004 C8 覆盖率豁免；字段将在实现阶段被 reconcile 逻辑读取。
    #[allow(dead_code)]
    signer: Box<DynSigner<'static>>,
}

impl CertReconcileCtx {
    /// 构造 reconcile 上下文（必填位置参，缺失即编译错误）。
    // reason: 签名冻结阶段 body = todo!()，参数未 move 进 struct；实现阶段将移除本 allow。
    #[allow(clippy::boxed_local)]
    pub fn new(_signer: Box<DynSigner<'static>>) -> Self {
        todo!()
    }
}

// ── reconcile_cert / cert_error_policy ───────────────────────────────────────

/// L4 reconcile（对齐 kube-rs `reconcile fn`；不 spawn task，由驱动层提供并发）。
pub async fn reconcile_cert(
    _device_id: &DeviceId,
    _ctx: &CertReconcileCtx,
) -> Result<CertAction, CertReconcileError> {
    todo!()
}

/// error policy（对齐 kube-rs `error_policy`）。
pub fn cert_error_policy(
    _device_id: &DeviceId,
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
    /// 目标设备。
    pub device_id: DeviceId,
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
        DeviceId,
    };

    fn _assert_send<T: Send>() {}

    // Finding#5（PORT-SHAPE）：锁 DynSigner 注入形状——NoopSigner impl Signer（Send 变体），
    // 验证 new_box 构造路径 + CertReconcileCtx::new 函数签名 + Box<DynSigner<'static>> 可 Send。
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

    #[test]
    fn dyn_signer_injection_shape() {
        // 构造 Box<DynSigner<'static>>（只构造不 await，body 为 todo!() 不影响类型检查）
        let _s: Box<diport::DynSigner<'static>> = diport::DynSigner::new_box(NoopSigner);
        // 绑定 CertReconcileCtx::new 函数指针——签名变更即编译失败（Hard：类型系统守）
        let _f: fn(Box<diport::DynSigner<'static>>) -> super::CertReconcileCtx =
            super::CertReconcileCtx::new;
        // Box<DynSigner<'static>> 可 Send（跨 tokio::spawn 安全）
        _assert_send::<Box<diport::DynSigner<'static>>>();
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
    fn reconcile_fns_are_nameable() {
        // 绑定函数名（不调用——body 为 todo!()）；验证签名编译期可解析
        let _ = super::reconcile_cert;
        let _ = super::cert_error_policy;
    }

    #[test]
    fn cert_sign_request_is_send() {
        _assert_send::<CertSignRequest>();
    }

    #[test]
    fn device_id_smoke() {
        // 构造路径可见（不调用 new，body 为 todo!()——仅验证类型可见性）
        let _: fn(&DeviceId) -> &str = DeviceId::as_str;
    }
}
