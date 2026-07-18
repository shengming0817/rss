//! `Pdp` —— 验签 / 凭据决策 provider DI port（可替换：prod JWKS+crypto / test in-mem）。
//!
//! 信任边界：authn 的 `verify→mint` bridge 经本 port 完成签名 / exp / MAC 校验，验签成功后才 seal 出
//! `VerifiedJwt` / `VerifiedServiceToken`（`AUTHN-VERIFIEDJWT-SEAL-01` 的**生产端**闭环，#1158）。
//! ADR-006 §3：保持内置 typed authplan + 预留本 `Pdp` 接缝；真实 crypto verifier adapter 留 #1109 W。
//! httpserve 生产挂载亦留 #1109（ADR-006 §5 验签空窗——本 PR 不接线生产可达认证路径）。

use dynosaur::dynosaur;
use sha2::{Digest as _, Sha256};
use std::future::Future;
use std::time::Duration;
use vocab::tenant::TenantId;

/// service-token MAC 绑定的 HTTP header 名（wire 原始大小写）。
pub const SERVICE_TOKEN_TENANT_HEADER: &str = "X-Tenant-ID";
/// service-token MAC 输入使用的 canonical header 名（小写）。
pub const SERVICE_TOKEN_TENANT_MAC_NAME: &str = "x-tenant-id";

/// 验签失败分类（port-own 闭值集，`#[non_exhaustive]`）。
///
/// PII 边界：变体不携 runtime 数据，`Display` 仅 provider 无关的安全摘要常量——adapter 把内部错误
/// **归类**到四种 taxonomy 变体（不经 `source` 透传原始错误，杜绝凭据 / 连接串泄漏）。消费侧据变体
/// 映射 HTTP 语义（authn `From<PdpError>`）：`InvalidSignature` → `TokenInvalid`、`Untrusted` →
/// `TokenUntrusted`、`Expired` → `TokenExpired`，三种凭据拒绝 wire 均为 401 `invalid_token`；
/// `ProviderUnavailable` 则保持基础设施故障语义并映射可重试 503。403 留给 authz 层「已认证但无权」。
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
    /// A required authentication provider could not complete the verification operation.
    ///
    /// This remains a data-free closed value: adapters must log only their own redacted,
    /// operator-facing diagnostics. Consumers map it to a retryable service-availability response,
    /// never to `invalid_token` or a signature-attack signal.
    #[error("authentication provider unavailable")]
    ProviderUnavailable,
}

const SERVICE_TOKEN_REPLAY_KEY_DOMAIN: &[u8] = b"rss.service-token-replay.v1";

/// Named, already-verified inputs for deriving one service-token replay identity.
///
/// The fields intentionally preserve their exact RFC case-sensitive bytes. Named fields prevent
/// four same-typed strings from being silently reordered at call sites.
pub struct ServiceTokenReplayScope<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub key_id: &'a str,
    pub token_id: &'a str,
}

/// Failure to frame a replay scope into the stable v1 digest protocol.
#[derive(Debug, thiserror::Error)]
pub enum ServiceTokenReplayKeyError {
    /// A component cannot be represented by the canonical unsigned 64-bit byte length.
    #[error("service-token replay scope component is too large")]
    ComponentTooLarge,
}

/// Opaque, fixed-width identity for one verified service-token replay scope.
///
/// INVARIANT: AUTHN-SERVICE-TOKEN-REPLAY-KEY-01 { level = "Hard", exec = "native-compile", source = "code", native = "private [u8; 32] field and named verified scope derivation" } — raw issuer/audience/kid/jti values cannot enter the replay store API. The v1 digest frames each
/// exact string as `u64::to_be_bytes(len) || bytes` beneath a fixed domain tag.
#[derive(Clone)]
pub struct ServiceTokenReplayKey([u8; 32]);

impl ServiceTokenReplayKey {
    /// Derive the canonical SHA-256 replay key from verified scope components.
    pub fn derive(scope: ServiceTokenReplayScope<'_>) -> Result<Self, ServiceTokenReplayKeyError> {
        let mut digest = Sha256::new();
        digest.update(SERVICE_TOKEN_REPLAY_KEY_DOMAIN);
        for component in [scope.issuer, scope.audience, scope.key_id, scope.token_id] {
            let length = u64::try_from(component.len())
                .map_err(|_| ServiceTokenReplayKeyError::ComponentTooLarge)?;
            digest.update(length.to_be_bytes());
            digest.update(component.as_bytes());
        }
        Ok(Self(digest.finalize().into()))
    }

    /// Borrow the fixed-width digest for a storage adapter.
    pub fn digest_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ServiceTokenReplayKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServiceTokenReplayKey([REDACTED])")
    }
}

/// Closed outcome of one atomic replay-key consume attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTokenReplayDisposition {
    /// This exact scoped key was recorded for the first time.
    Recorded,
    /// This exact scoped key was already recorded.
    Replayed,
}

/// Provider failure while atomically consuming a replay key.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ServiceTokenReplayStoreError {
    /// Durable replay storage is unavailable or rejected the request.
    #[error("service-token replay store unavailable")]
    Unavailable,
}

/// Construction or expiry failure for a service-token replay operation deadline.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ServiceTokenReplayDeadlineError {
    /// A zero budget would make the provider deterministically unavailable.
    #[error("service-token replay deadline budget must be non-zero")]
    ZeroBudget,
    /// The requested duration cannot be represented as a monotonic absolute deadline.
    #[error("service-token replay deadline overflow")]
    Overflow,
    /// The single absolute operation deadline has elapsed.
    #[error("service-token replay deadline elapsed")]
    Elapsed,
}

/// One absolute monotonic deadline shared by the complete replay-store operation.
///
/// The instant is private so adapters cannot reset the budget between pool acquire, transaction
/// setup, SQL execution, and commit. [`Self::run`] provides the client-side cancellation boundary;
/// [`Self::server_timeout_millis`] derives strictly-inner PostgreSQL statement/lock budgets from
/// the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceTokenReplayDeadline {
    operation: tokio::time::Instant,
}

impl ServiceTokenReplayDeadline {
    /// Mint one absolute deadline from an explicit non-zero caller budget.
    pub fn from_timeout(timeout: Duration) -> Result<Self, ServiceTokenReplayDeadlineError> {
        if timeout.is_zero() {
            return Err(ServiceTokenReplayDeadlineError::ZeroBudget);
        }
        #[allow(clippy::disallowed_methods)]
        let operation = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or(ServiceTokenReplayDeadlineError::Overflow)?;
        Ok(Self { operation })
    }

    /// Run the complete provider future beneath this single absolute deadline.
    pub async fn run<F: Future>(
        self,
        future: F,
    ) -> Result<F::Output, ServiceTokenReplayDeadlineError> {
        #[allow(clippy::disallowed_methods)]
        if tokio::time::Instant::now() >= self.operation {
            return Err(ServiceTokenReplayDeadlineError::Elapsed);
        }
        tokio::time::timeout_at(self.operation, future)
            .await
            .map_err(|_| ServiceTokenReplayDeadlineError::Elapsed)
    }

    /// Derive server-side statement and lock timeouts strictly inside the client deadline.
    pub fn server_timeout_millis(self) -> Result<(u64, u64), ServiceTokenReplayDeadlineError> {
        #[allow(clippy::disallowed_methods)]
        let remaining = self
            .operation
            .saturating_duration_since(tokio::time::Instant::now());
        let remaining_millis = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        let statement_millis = remaining_millis
            .checked_sub(2)
            .filter(|millis| *millis > 0)
            .ok_or(ServiceTokenReplayDeadlineError::Elapsed)?;
        let lock_millis = statement_millis.min(5_000);
        Ok((statement_millis, lock_millis))
    }
}

/// Required async seam for durable, scoped service-token replay protection.
#[trait_variant::make(ServiceTokenReplayStore: Send)]
#[dynosaur(
    pub DynServiceTokenReplayStore = dyn(box) ServiceTokenReplayStore,
    bridge(dyn)
)]
#[allow(async_fn_in_trait)]
pub trait ServiceTokenReplayStoreLocal: Send + Sync {
    /// Atomically record a scoped key if absent, retaining it at least until the already-validated
    /// service-token expiry boundary.
    async fn check_and_record(
        &self,
        key: &ServiceTokenReplayKey,
        expires_at: std::time::SystemTime,
        deadline: ServiceTokenReplayDeadline,
    ) -> Result<ServiceTokenReplayDisposition, ServiceTokenReplayStoreError>;
}

#[cfg(test)]
mod replay_key_tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::{
        DynServiceTokenReplayStore, ServiceTokenReplayDeadline, ServiceTokenReplayDeadlineError,
        ServiceTokenReplayDisposition, ServiceTokenReplayKey, ServiceTokenReplayScope,
        ServiceTokenReplayStore, ServiceTokenReplayStoreError,
    };

    #[allow(clippy::expect_used)]
    fn key(issuer: &str, audience: &str, key_id: &str, token_id: &str) -> ServiceTokenReplayKey {
        ServiceTokenReplayKey::derive(ServiceTokenReplayScope {
            issuer,
            audience,
            key_id,
            token_id,
        })
        .expect("test replay scope lengths fit u64")
    }

    #[test]
    fn replay_key_v1_golden_is_stable() {
        assert_eq!(
            key("https://issuer.example", "rss", "svc-2026", "nonce-123").digest_bytes(),
            &[
                0xe7, 0x6c, 0xbd, 0xad, 0x45, 0x7d, 0x11, 0xca, 0xe3, 0x73, 0xd3, 0x84, 0xee, 0x63,
                0xa1, 0xfe, 0x99, 0x4d, 0xbe, 0xca, 0x35, 0x15, 0x4a, 0x7a, 0x74, 0x3f, 0x40, 0x4a,
                0x96, 0x4d, 0x5f, 0xdd,
            ]
        );
    }

    #[test]
    fn every_verified_scope_component_changes_the_replay_key() {
        let keys = [
            key("iss-a", "aud-a", "kid-a", "jti-a"),
            key("iss-b", "aud-a", "kid-a", "jti-a"),
            key("iss-a", "aud-b", "kid-a", "jti-a"),
            key("iss-a", "aud-a", "kid-b", "jti-a"),
            key("iss-a", "aud-a", "kid-a", "jti-b"),
        ];
        assert_eq!(
            keys.iter()
                .map(|key| *key.digest_bytes())
                .collect::<HashSet<_>>()
                .len(),
            5
        );
    }

    #[test]
    fn length_prefixes_prevent_component_boundary_ambiguity() {
        assert_ne!(
            key("ab", "c", "kid", "jti").digest_bytes(),
            key("a", "bc", "kid", "jti").digest_bytes()
        );
    }

    #[test]
    fn replay_key_debug_never_exposes_scope_or_digest() {
        let replay_key = key(
            "issuer-marker",
            "audience-marker",
            "kid-marker",
            "jti-marker",
        );
        let rendered = format!("{replay_key:?}");
        assert_eq!(rendered, "ServiceTokenReplayKey([REDACTED])");
        for marker in [
            "issuer-marker",
            "audience-marker",
            "kid-marker",
            "jti-marker",
        ] {
            assert!(!rendered.contains(marker));
        }
    }

    #[test]
    fn replay_deadline_rejects_zero_budget() {
        assert_eq!(
            ServiceTokenReplayDeadline::from_timeout(std::time::Duration::ZERO),
            Err(ServiceTokenReplayDeadlineError::ZeroBudget)
        );
    }

    struct YieldingStore;

    impl ServiceTokenReplayStore for YieldingStore {
        async fn check_and_record(
            &self,
            _key: &ServiceTokenReplayKey,
            _expires_at: SystemTime,
            _deadline: ServiceTokenReplayDeadline,
        ) -> Result<ServiceTokenReplayDisposition, ServiceTokenReplayStoreError> {
            tokio::task::yield_now().await;
            Ok(ServiceTokenReplayDisposition::Recorded)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn replay_store_is_dyn_injectable_and_send_across_yield() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}

        let store: Arc<DynServiceTokenReplayStore<'static>> =
            DynServiceTokenReplayStore::new_arc(YieldingStore);
        assert_send_sync(&store);
        let result = tokio::spawn(async move {
            let deadline =
                match ServiceTokenReplayDeadline::from_timeout(std::time::Duration::from_secs(1)) {
                    Ok(deadline) => deadline,
                    Err(_) => return Err(ServiceTokenReplayStoreError::Unavailable),
                };
            store
                .check_and_record(
                    &key("iss", "aud", "kid", "jti"),
                    SystemTime::UNIX_EPOCH,
                    deadline,
                )
                .await
        })
        .await;
        assert!(matches!(
            result,
            Ok(Ok(ServiceTokenReplayDisposition::Recorded))
        ));
    }
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
/// 公开 [`Pdp`] 是 **Send + Sync 变体**（adapters `impl Pdp for ...`），[`DynPdp`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynPdp>` / `Arc<DynPdp>` 注入）。验签发生在多线程 HTTP
/// serving future 内，故 provider 与 wrapper 均须可跨请求共享；`PdpLocal` 仍不在 crate 根 re-export。
///
/// dyn-safe 约束（ADR-003 §4.6 + #1828 amendment）：方法 `&self`、参数 / 返回为具体类型、supertrait
/// `Send + Sync`。无
/// `shutdown`——纯验签 port 无 infra 资源；有 JWKS 刷新句柄 / 连接的 adapter 应**另** `impl ManagedResource`
/// 由 `bootstrap::ShutdownStack` 编排关闭（参 [`crate::ManagedResource`]）。
#[trait_variant::make(Pdp: Send)]
#[dynosaur(pub DynPdp = dyn(box) Pdp, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 的 Send+Sync 约束共享 provider；trait-variant 的 Send 只约束 async future，
// 避免无必要的 Future: Sync。dynosaur `DynPdp` 承载运行期可替换 provider（#1828）。
pub trait PdpLocal: Send + Sync {
    /// 验签原始凭据（签名 / exp / MAC），成功返回可信 [`VerifiedClaims`]；失败 fail-closed（[`PdpError`]）。
    ///
    /// I/O：生产实现可能查 JWKS / 调外置引擎（async）。本 trait 只定义接缝，真实 crypto adapter 留 #1109 W。
    async fn verify(&self, raw: &RawCredential) -> Result<VerifiedClaims, PdpError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async `Pdp` port 可 native AFIT impl + 经 `Arc<DynPdp>` 动态注入 + 跨 spawn。
    use std::sync::Arc;

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
        fn assert_send_sync<T: Send + Sync>(_: &T) {}

        let pdp: Arc<DynPdp> = DynPdp::new_arc(NoopPdp);
        assert_send_sync(&pdp);
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
