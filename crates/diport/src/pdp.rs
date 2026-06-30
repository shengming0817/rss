//! `Pdp` —— 验签 / 凭据决策 provider DI port（可替换：prod JWKS+crypto / test in-mem）。
//!
//! 信任边界：authn 的 `verify→mint` bridge 经本 port 完成签名 / exp / MAC 校验，验签成功后才 seal 出
//! `VerifiedJwt` / `VerifiedServiceToken`（`AUTHN-VERIFIEDJWT-SEAL-01` 的**生产端**闭环，#1158）。
//! ADR-006 §3：保持内置 typed authplan + 预留本 `Pdp` 接缝；真实 crypto verifier adapter 留 #1109 W。
//! httpserve 生产挂载亦留 #1109（ADR-006 §5 验签空窗——本 PR 不接线生产可达认证路径）。

use dynosaur::dynosaur;
use vocab::tenant::TenantId;

/// service-token MAC 绑定的 HTTP header 名（wire 原始大小写）。
pub const SERVICE_TOKEN_TENANT_HEADER: &str = "X-Tenant-ID";
/// service-token MAC 输入使用的 canonical header 名（小写）。
pub const SERVICE_TOKEN_TENANT_MAC_NAME: &str = "x-tenant-id";

/// 验签失败分类（port-own 闭值集，`#[non_exhaustive]`）。
///
/// PII 边界：变体不携 runtime 数据，`Display` 仅 provider 无关的安全摘要常量——adapter 把内部错误
/// **归类**到这三种 taxonomy 变体（不经 `source` 透传原始错误，杜绝凭据 / 连接串泄漏）。消费侧据变体
/// 映射 HTTP 语义（authn `From<PdpError>`，#1229 / #1275 三路一一保真）：`InvalidSignature` →
/// `TokenInvalid`、`Untrusted` → `TokenUntrusted`、`Expired` → `TokenExpired`；三者 wire **均** 401
/// `invalid_token`（RFC 6750 §3.1，verify 层纯认证不发 403；独立变体仅供 deny 路 `authz.deny_reason` 告警
/// 分级，区分疑似攻击 vs 疑似配置错），403 留给 authz 层「已认证但无权」。
/// `Clone`：消费侧单测 stub 按预置结果重放。
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum PdpError {
    /// 凭据**结构 / 签名 / claim 完整性**不可用（taxonomy 压缩：oidc adapter 多个子情形归此一变体）：
    /// 签名 / MAC 校验失败；token 段数≠3 或 base64url 坏（`jws::parse` Malformed）；alg 不在白名单
    /// （`alg=none` / RS256 / 未知，`jws::parse` UnsupportedAlg）；payload JSON 畸形或缺必填 claim；
    /// 空 subject；Clock 早于 UNIX_EPOCH（fail-closed）。消费侧 → 401 `invalid_token`。
    #[error("credential signature invalid")]
    InvalidSignature,
    /// 凭据时间窗越界：`exp` 过期（now > exp + leeway）或 `nbf` 未生效（now < nbf − leeway）。
    #[error("credential expired")]
    Expired,
    /// 凭据来源 / 路径不受信（**非**结构损坏）：`iss` 不匹配配置签发者；`aud` 不含配置受众；
    /// alg-scheme 路径混淆（JWT 路径配 HS256 token / service-token 路径配 ES256 token，OIDC-ALG-KEYPATH-01）；
    /// 未知 credential scheme。消费侧 → 401 `invalid_token`（verify 层纯认证，不发 403）。
    #[error("credential issuer untrusted")]
    Untrusted,
}

/// service-token replay guard failure.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ServiceTokenReplayError {
    /// Token nonce/jti was already observed.
    #[error("service-token nonce replayed")]
    Replayed,
    /// Guard storage/check failed; callers must fail closed.
    #[error("service-token replay guard failed")]
    Guard,
}

/// Required seam for service-token `jti`/nonce replay protection.
pub trait ServiceTokenReplayGuard: Send + Sync + 'static {
    /// Atomically record a nonce if it has not been observed, retaining it at least until the
    /// already-validated service token expiry boundary.
    fn check_and_record(
        &self,
        nonce: &str,
        expires_at: std::time::SystemTime,
    ) -> Result<(), ServiceTokenReplayError>;
}

/// 凭据 scheme 标签——adapter 据此选验签路径（JWT 签名 vs service-token MAC）。闭值集，`#[non_exhaustive]`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialScheme {
    /// 标准 JWT（`header.payload.sig`）。
    Jwt,
    /// 服务间 access token。
    ServiceToken,
}

/// service-token 对 `X-Tenant-ID` header 的 MAC 绑定（闭合类型，非通用 signed-header bag）。
///
/// 只经 [`Self::new`] 从已解析 [`TenantId`] 构造，保证进入 verifier 的 tenant header 为 canonical form。
#[derive(Clone, secure::Redact)]
pub struct ServiceTokenTenantBinding(#[redact(sensitivity = pii)] String);

impl ServiceTokenTenantBinding {
    /// 从已验证 tenant id 构造 service-token header binding。
    pub fn new(tenant: TenantId) -> Self {
        Self(tenant.to_string())
    }

    /// canonical `X-Tenant-ID` 值，供 service-token MAC 输入使用。
    pub fn tenant_header_value(&self) -> &str {
        &self.0
    }
}

/// service-token HS256 MAC 输入：JWS signing input + canonical tenant header 绑定。
pub fn service_token_mac_input(
    signing_input: &[u8],
    binding: &ServiceTokenTenantBinding,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        signing_input.len()
            + 1
            + SERVICE_TOKEN_TENANT_MAC_NAME.len()
            + 1
            + binding.tenant_header_value().len(),
    );
    input.extend_from_slice(signing_input);
    input.extend_from_slice(b"\n");
    input.extend_from_slice(SERVICE_TOKEN_TENANT_MAC_NAME.as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(binding.tenant_header_value().as_bytes());
    input
}

/// 待验签原始凭据（零信任边界）：newtype funnel（私有字段，命名构造入口）。携带 scheme 标签 + 原始
/// token 串——adapter 据 scheme 选验签路径。本层**不 parse、不验签**，只受控装箱传给 provider。
#[derive(Clone, secure::Redact)]
pub struct RawCredential {
    #[redact(sensitivity = public)]
    scheme: CredentialScheme,
    #[redact(sensitivity = secret)]
    token: String,
    #[redact(sensitivity = secret)]
    service_token_tenant: Option<ServiceTokenTenantBinding>,
}

impl RawCredential {
    /// 由原始 JWT 串构造待验签凭据。
    pub fn jwt(raw: impl Into<String>) -> Self {
        Self {
            scheme: CredentialScheme::Jwt,
            token: raw.into(),
            service_token_tenant: None,
        }
    }
    /// 由原始 service-token 串构造待验签凭据。
    pub fn service_token(raw: impl Into<String>, binding: ServiceTokenTenantBinding) -> Self {
        Self {
            scheme: CredentialScheme::ServiceToken,
            token: raw.into(),
            service_token_tenant: Some(binding),
        }
    }
    /// 凭据 scheme（adapter 选验签路径）。
    pub fn scheme(&self) -> CredentialScheme {
        self.scheme
    }
    /// 借出原始 token 串（adapter 验签用）。
    pub fn token(&self) -> &str {
        &self.token
    }
    /// service-token 绑定的 canonical tenant header；JWT 路径恒为 `None`。
    pub fn service_token_tenant(&self) -> Option<&ServiceTokenTenantBinding> {
        self.service_token_tenant.as_ref()
    }
}

/// 验签成功后的可信 claims（port-own DTO；newtype funnel：私有字段 + 构造 / 访问 funnel）。
///
/// 信任语义：本值仅由验签 provider 在校验签名 / exp / MAC **成功后**构造，故其字段是「已验证」身份——
/// authn 据此 mint `Principal`（验签 = 信任原点，非 authn 旁路 re-parse）。
///
/// PII 边界：`subject` / `tenant` / `kind` 全部经 `#[derive(secure::Redact)]` 脱敏
/// （DIPORT-DTO-PII-DEBUG-REDACT-01）。
/// `kind` 是 adapter 透传的**未类型化、未校验** `Option<String>`——观测面不信任未校验输入，故一律脱敏，
/// 杜绝 adapter 误塞 PII（email / 设备指纹）经 `kind` 进日志。`kind`→`PrincipalKind` 的**策略**归 authn
/// （非本层，保 ADR-005 category line）。字段集随消费域细化（`scopes` 等待 authz 消费方落地再加，pre-GA 可演进）。
#[derive(Clone, secure::Redact)]
pub struct VerifiedClaims {
    #[redact(sensitivity = pii)]
    subject: String,
    #[redact(sensitivity = pii)]
    tenant: Option<String>,
    #[redact(sensitivity = pii)]
    kind: Option<String>,
}

impl VerifiedClaims {
    /// 由验签产物构造可信 claims（adapter 唯一构造入口）。
    pub fn new(subject: impl Into<String>, tenant: Option<String>, kind: Option<String>) -> Self {
        Self {
            subject: subject.into(),
            tenant,
            kind,
        }
    }
    /// 已验证 subject。
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// 已验证租户（跨租户主体为 `None`）。
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }
    /// 已验证 `kind` claim（authn 据此映射 `PrincipalKind`）。
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }
}

/// 验签 provider DI port（async）。
///
/// 公开 [`Pdp`] 是 **Send 变体**（adapters `impl Pdp for ...`），[`DynPdp`] 是其 dyn-compatible wrapper
/// （组合根经 `Box<DynPdp>` / `Arc<DynPdp>` 注入）。非 Send 基 trait `PdpLocal` 仅供静态分发窄场景，
/// 不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send。无
/// `shutdown`——纯验签 port 无 infra 资源；有 JWKS 刷新句柄 / 连接的 adapter 应**另** `impl ManagedResource`
/// 由 `bootstrap::ShutdownStack` 编排关闭（参 [`crate::ManagedResource`]）。
#[trait_variant::make(Pdp: Send)]
#[dynosaur(pub DynPdp = dyn(box) Pdp, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `Pdp` 变体 +
// dynosaur `DynPdp` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait PdpLocal {
    /// 验签原始凭据（签名 / exp / MAC），成功返回可信 [`VerifiedClaims`]；失败 fail-closed（[`PdpError`]）。
    ///
    /// I/O：生产实现可能查 JWKS / 调外置引擎（async）。本 trait 只定义接缝，真实 crypto adapter 留 #1109 W。
    async fn verify(&self, raw: &RawCredential) -> Result<VerifiedClaims, PdpError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async `Pdp` port 可 native AFIT impl + 经 `Box<DynPdp>` 动态注入 + 跨 spawn（Send）。
    use super::{DynPdp, Pdp, PdpError, RawCredential, VerifiedClaims};

    struct NoopPdp;
    impl Pdp for NoopPdp {
        async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
            Ok(VerifiedClaims::new("sub", None, None))
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn pdp_is_dyn_injectable() {
        let pdp: Box<DynPdp> = DynPdp::new_box(NoopPdp);
        let raw = RawCredential::jwt("h.e.s");
        let joined = tokio::spawn(async move { pdp.verify(&raw).await.is_ok() }).await;
        assert!(matches!(joined, Ok(true)));
    }
}

#[cfg(test)]
mod pii_debug {
    //! `RawCredential.token` / `VerifiedClaims.subject·tenant` Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（同 `signer.rs` 的 `pii_debug`）。
    use super::{CredentialScheme, RawCredential, ServiceTokenTenantBinding, VerifiedClaims};
    use vocab::tenant::TenantId;

    fn _assert_redact<T: secure::Redact>() {}

    #[test]
    fn pii_dtos_use_redact_derive_model() {
        _assert_redact::<RawCredential>();
        _assert_redact::<ServiceTokenTenantBinding>();
        _assert_redact::<VerifiedClaims>();
    }

    #[test]
    fn raw_credential_debug_redacts_token() {
        let cred = RawCredential::jwt("secret.jwt.token");
        assert_eq!(cred.scheme(), CredentialScheme::Jwt);
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("secret.jwt.token"), "原始 token 泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("Jwt"), "scheme 应可见: {dbg}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn service_token_tenant_binding_is_required_and_redacted() {
        let tenant =
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant");
        let binding = ServiceTokenTenantBinding::new(tenant);
        assert_eq!(
            binding.tenant_header_value(),
            "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        );
        let cred = RawCredential::service_token("secret.service.token", binding.clone());
        assert_eq!(cred.scheme(), CredentialScheme::ServiceToken);
        assert_eq!(
            cred.service_token_tenant()
                .expect("service-token has tenant binding")
                .tenant_header_value(),
            binding.tenant_header_value()
        );
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("secret.service.token"), "token 泄漏: {dbg}");
        assert!(
            !dbg.contains("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
            "tenant 泄漏: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }

    #[test]
    fn verified_claims_debug_redacts_all_identity_fields() {
        let vc = VerifiedClaims::new(
            "alice-secret",
            Some("tenant-secret".to_string()),
            Some("kind-secret".to_string()),
        );
        let dbg = format!("{vc:?}");
        assert!(!dbg.contains("alice-secret"), "subject 泄漏: {dbg}");
        assert!(!dbg.contains("tenant-secret"), "tenant 泄漏: {dbg}");
        // kind 亦脱敏：未类型化 adapter 输入不信任进观测面（防误塞 PII）。
        assert!(!dbg.contains("kind-secret"), "kind 泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }
}
