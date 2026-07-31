//! `Pdp` —— profile-typed 验签 / 凭据决策 provider DI port。
//!
//! [`TokenProfile`] 是 listener 信任边界固定的穷尽闭值集；sealed [`TokenProfileMarker`] 将同一策略带入
//! typed issuer 与 verifier。生产 runtime 以 exhaustive profile binding 同时选择
//! `OidcProvider<P>`、required auth scheme 与 authn verification funnel。Provider 在解析 token 前先比较
//! 可信 [`RawCredential::profile`] 与 marker，并在签名/MAC、时间窗、issuer/audience 以及 profile
//! claims 全部校验成功后才构造 [`VerifiedClaims`]。authn 随后才能 seal 已验证 token 并派生主体。

use dynosaur::dynosaur;
use ids::UserId;
use sha2::{Digest as _, Sha256};
use std::future::Future;
use std::time::Duration;
use vocab::{PrincipalKind, ServiceCallerDomain, tenant::TenantId};

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
    /// token profile / algorithm 路径混淆（access profile 配 HS256 token / service-token profile 配
    /// ES256 token，OIDC-ALG-KEYPATH-01）。消费侧 → 401 `invalid_token`（verify 层纯认证，不发 403）。
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
pub struct ServiceTokenReplayKey(sha2::digest::Output<Sha256>);

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
        Ok(Self(digest.finalize()))
    }

    /// Borrow the fixed-width digest for a storage adapter.
    pub fn digest_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
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

/// Token verification profile fixed by the listener trust boundary.
///
/// This enum is intentionally exhaustive: every verifier, runtime binding, and policy consumer
/// must handle all profiles explicitly when a new profile is introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenProfile {
    /// RSS-issued, durable-grant-bound User access token.
    RssAccess,
    /// Access token issued by an independently trusted federation.
    FederatedAccess,
    /// RSS service-to-service token bound to the canonical tenant header.
    ServiceToken,
    /// Projection maintenance operator token with a signed tenant and verifier-only JWKS trust.
    ProjectionOperator,
}

/// JOSE algorithm fixed by a [`TokenProfile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// HMAC using SHA-256.
    Hs256,
}

impl TokenAlgorithm {
    /// Exact, case-sensitive JOSE `alg` value.
    pub const fn jose_name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Hs256 => "HS256",
        }
    }
}

/// Immutable protocol policy for one token profile.
///
/// All fields stay private so callers cannot synthesize a weaker policy. The value is obtained
/// only from [`TokenProfile::policy`] or [`TokenProfileMarker::policy`]. RSS and federated access
/// require exact `typ=at+jwt`, `token_use=access`, ES256, and at most 900 seconds; service tokens
/// require exact `typ=rss-service+jwt`, `token_use=service`, HS256, and at most 300 seconds.
/// Encoded token/header/payload/signature limits are inclusive and shared by all profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenPolicy {
    jose_typ: &'static str,
    token_use: &'static str,
    algorithm: TokenAlgorithm,
    maximum_lifetime: Duration,
    maximum_token_length: usize,
    maximum_header_length: usize,
    maximum_payload_length: usize,
    maximum_signature_length: usize,
}

impl TokenPolicy {
    /// Exact, case-sensitive protected-header `typ`.
    pub const fn jose_typ(self) -> &'static str {
        self.jose_typ
    }

    /// Exact, case-sensitive private `token_use` claim.
    pub const fn token_use(self) -> &'static str {
        self.token_use
    }

    /// Only accepted JOSE algorithm.
    pub const fn algorithm(self) -> TokenAlgorithm {
        self.algorithm
    }

    /// Maximum allowed `exp - iat` duration.
    pub const fn maximum_lifetime(self) -> Duration {
        self.maximum_lifetime
    }

    /// Maximum encoded token length, in bytes.
    pub const fn maximum_token_length(self) -> usize {
        self.maximum_token_length
    }

    /// Maximum encoded protected-header segment length, in bytes.
    pub const fn maximum_header_length(self) -> usize {
        self.maximum_header_length
    }

    /// Maximum encoded payload segment length, in bytes.
    pub const fn maximum_payload_length(self) -> usize {
        self.maximum_payload_length
    }

    /// Maximum encoded signature segment length, in bytes.
    pub const fn maximum_signature_length(self) -> usize {
        self.maximum_signature_length
    }
}

const MAXIMUM_TOKEN_LENGTH: usize = 16 * 1024;
const MAXIMUM_HEADER_LENGTH: usize = 4 * 1024;
const MAXIMUM_PAYLOAD_LENGTH: usize = 12 * 1024;
const MAXIMUM_SIGNATURE_LENGTH: usize = 1024;

const RSS_ACCESS_POLICY: TokenPolicy = TokenPolicy {
    jose_typ: "at+jwt",
    token_use: "access",
    algorithm: TokenAlgorithm::Es256,
    maximum_lifetime: Duration::from_secs(900),
    maximum_token_length: MAXIMUM_TOKEN_LENGTH,
    maximum_header_length: MAXIMUM_HEADER_LENGTH,
    maximum_payload_length: MAXIMUM_PAYLOAD_LENGTH,
    maximum_signature_length: MAXIMUM_SIGNATURE_LENGTH,
};

const FEDERATED_ACCESS_POLICY: TokenPolicy = TokenPolicy {
    jose_typ: "at+jwt",
    token_use: "access",
    algorithm: TokenAlgorithm::Es256,
    maximum_lifetime: Duration::from_secs(900),
    maximum_token_length: MAXIMUM_TOKEN_LENGTH,
    maximum_header_length: MAXIMUM_HEADER_LENGTH,
    maximum_payload_length: MAXIMUM_PAYLOAD_LENGTH,
    maximum_signature_length: MAXIMUM_SIGNATURE_LENGTH,
};

const SERVICE_TOKEN_POLICY: TokenPolicy = TokenPolicy {
    jose_typ: "rss-service+jwt",
    token_use: "service",
    algorithm: TokenAlgorithm::Hs256,
    maximum_lifetime: Duration::from_secs(300),
    maximum_token_length: MAXIMUM_TOKEN_LENGTH,
    maximum_header_length: MAXIMUM_HEADER_LENGTH,
    maximum_payload_length: MAXIMUM_PAYLOAD_LENGTH,
    maximum_signature_length: MAXIMUM_SIGNATURE_LENGTH,
};

const PROJECTION_OPERATOR_TOKEN_POLICY: TokenPolicy = TokenPolicy {
    jose_typ: "rss-projection-operator+jwt",
    token_use: "projection-operator",
    algorithm: TokenAlgorithm::Es256,
    maximum_lifetime: Duration::from_secs(300),
    maximum_token_length: MAXIMUM_TOKEN_LENGTH,
    maximum_header_length: MAXIMUM_HEADER_LENGTH,
    maximum_payload_length: MAXIMUM_PAYLOAD_LENGTH,
    maximum_signature_length: MAXIMUM_SIGNATURE_LENGTH,
};

impl TokenProfile {
    /// Return the immutable policy fixed for this profile.
    pub const fn policy(self) -> TokenPolicy {
        match self {
            Self::RssAccess => RSS_ACCESS_POLICY,
            Self::FederatedAccess => FEDERATED_ACCESS_POLICY,
            Self::ServiceToken => SERVICE_TOKEN_POLICY,
            Self::ProjectionOperator => PROJECTION_OPERATOR_TOKEN_POLICY,
        }
    }
}

/// Marker for RSS-issued access tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssAccessProfile {}

/// Marker for independently federated access tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederatedAccessProfile {}

/// Marker for RSS service-to-service tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTokenProfile {}

/// Marker for verifier-only Projection maintenance operator tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionOperatorTokenProfile {}

mod token_profile_sealed {
    pub trait Sealed {}

    impl Sealed for super::RssAccessProfile {}
    impl Sealed for super::FederatedAccessProfile {}
    impl Sealed for super::ServiceTokenProfile {}
    impl Sealed for super::ProjectionOperatorTokenProfile {}
}

/// Sealed type-level token profile.
///
/// External crates may use the four marker types as generic arguments but cannot implement this
/// trait for another type, so a verifier or issuer cannot be instantiated with an invented policy.
pub trait TokenProfileMarker: token_profile_sealed::Sealed + Send + Sync + Copy + 'static {
    /// Runtime identity of this type-level profile.
    const PROFILE: TokenProfile;

    /// Immutable protocol policy of this type-level profile.
    fn policy() -> TokenPolicy {
        Self::PROFILE.policy()
    }
}

impl TokenProfileMarker for RssAccessProfile {
    const PROFILE: TokenProfile = TokenProfile::RssAccess;
}

impl TokenProfileMarker for FederatedAccessProfile {
    const PROFILE: TokenProfile = TokenProfile::FederatedAccess;
}

impl TokenProfileMarker for ServiceTokenProfile {
    const PROFILE: TokenProfile = TokenProfile::ServiceToken;
}

impl TokenProfileMarker for ProjectionOperatorTokenProfile {
    const PROFILE: TokenProfile = TokenProfile::ProjectionOperator;
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

/// 待验签原始凭据（零信任边界）：newtype funnel（私有字段，命名构造入口）。携带由可信 listener
/// 固定的 profile + 原始 token 串。本层**不 parse、不验签**，只受控装箱传给 provider。
#[derive(Clone, secure::Redact)]
pub struct RawCredential {
    #[redact(sensitivity = public)]
    profile: TokenProfile,
    #[redact(sensitivity = secret)]
    token: String,
    #[redact(sensitivity = secret)]
    service_token_tenant: Option<ServiceTokenTenantBinding>,
}

impl RawCredential {
    /// 由可信 RSS access listener 的原始 token 构造凭据。
    pub fn rss_access(raw: impl Into<String>) -> Self {
        Self {
            profile: TokenProfile::RssAccess,
            token: raw.into(),
            service_token_tenant: None,
        }
    }

    /// 由可信 federated access listener 的原始 token 构造凭据。
    pub fn federated_access(raw: impl Into<String>) -> Self {
        Self {
            profile: TokenProfile::FederatedAccess,
            token: raw.into(),
            service_token_tenant: None,
        }
    }

    /// 由原始 service-token 串构造待验签凭据。
    pub fn service_token(raw: impl Into<String>, binding: ServiceTokenTenantBinding) -> Self {
        Self {
            profile: TokenProfile::ServiceToken,
            token: raw.into(),
            service_token_tenant: Some(binding),
        }
    }

    /// Construct a Projection operator credential. Tenant authority is carried only in the
    /// signed token claims; no ambient header binding is accepted by this profile.
    pub fn projection_operator(raw: impl Into<String>) -> Self {
        Self {
            profile: TokenProfile::ProjectionOperator,
            token: raw.into(),
            service_token_tenant: None,
        }
    }

    /// 由可信 listener 固定的 token profile。
    pub fn profile(&self) -> TokenProfile {
        self.profile
    }
    /// 借出原始 token 串（adapter 验签用）。
    pub fn token(&self) -> &str {
        &self.token
    }
    /// service-token 绑定的 canonical tenant header；access profiles 恒为 `None`。
    pub fn service_token_tenant(&self) -> Option<&ServiceTokenTenantBinding> {
        self.service_token_tenant.as_ref()
    }
}

/// Validated RSS access-token grant facts.
///
/// Both identifiers must be lowercase canonical UUIDv4 strings. Time and epoch inputs use signed
/// integers at the JSON boundary so negative and overflowing values can be rejected before this
/// value exists.
#[derive(Clone, secure::Redact)]
pub struct VerifiedAccessGrantFacts {
    #[redact(sensitivity = secret)]
    session_id: ids::CanonicalUuidV4,
    #[redact(sensitivity = secret)]
    token_id: ids::CanonicalUuidV4,
    #[redact(sensitivity = secret)]
    auth_time_unix_secs: u64,
    #[redact(sensitivity = secret)]
    authn_epoch: u64,
}

impl VerifiedAccessGrantFacts {
    /// Validate the complete RSS grant-fact quartet as one indivisible shape.
    pub fn try_new(
        session_id: impl Into<String>,
        token_id: impl Into<String>,
        auth_time_unix_secs: i64,
        authn_epoch: i64,
    ) -> Result<Self, VerifiedClaimShapeError> {
        let session_id = ids::CanonicalUuidV4::parse(&session_id.into())
            .map_err(|_| VerifiedClaimShapeError::Invalid)?;
        let token_id = ids::CanonicalUuidV4::parse(&token_id.into())
            .map_err(|_| VerifiedClaimShapeError::Invalid)?;
        if auth_time_unix_secs < 0 || authn_epoch < 0 {
            return Err(VerifiedClaimShapeError::Invalid);
        }
        Ok(Self {
            session_id,
            token_id,
            auth_time_unix_secs: auth_time_unix_secs as u64,
            authn_epoch: authn_epoch as u64,
        })
    }

    pub fn session_id(&self) -> ids::CanonicalUuidV4 {
        self.session_id
    }

    pub fn token_id(&self) -> ids::CanonicalUuidV4 {
        self.token_id
    }

    pub fn auth_time_unix_secs(&self) -> u64 {
        self.auth_time_unix_secs
    }

    pub fn authn_epoch(&self) -> u64 {
        self.authn_epoch
    }
}

/// A profile shape failed validation. It carries no rejected runtime data.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum VerifiedClaimShapeError {
    #[error("verified claim shape is invalid")]
    Invalid,
}

#[derive(Clone)]
enum VerifiedClaimsProfile {
    RssUser {
        user_id: UserId,
        tenant: TenantId,
        grant: VerifiedAccessGrantFacts,
    },
    FederatedAccess {
        subject: String,
        tenant: Option<TenantId>,
        kind: PrincipalKind,
        permissions: VerifiedFederatedPermissions,
    },
    ServiceToken {
        caller: ServiceCallerDomain,
    },
    ProjectionOperator {
        caller: ServiceCallerDomain,
        tenant: TenantId,
    },
}

/// Borrowed exhaustive view of one verified profile shape.
///
/// The enum is public so consumers must handle every profile when the closed set evolves, while
/// all constructors and owned fields remain private to [`VerifiedClaims`].
pub enum VerifiedClaimsView<'a> {
    RssUser {
        user_id: UserId,
        tenant: TenantId,
        grant: &'a VerifiedAccessGrantFacts,
    },
    FederatedAccess {
        subject: &'a str,
        tenant: Option<TenantId>,
        kind: PrincipalKind,
        permissions: &'a VerifiedFederatedPermissions,
    },
    ServiceToken {
        caller: ServiceCallerDomain,
    },
    ProjectionOperator {
        caller: ServiceCallerDomain,
        tenant: TenantId,
    },
}

/// 验签成功后的可信 claims（port-own DTO；private closed profile shape）。
///
/// RSS evidence cannot exist without typed User/tenant identity and the complete grant quartet.
/// Federated and service evidence are disjoint variants and therefore cannot be upgraded to a
/// local grant receipt by filling similarly named extension claims.
#[derive(Clone, secure::Redact)]
pub struct VerifiedClaims {
    #[redact(sensitivity = secret)]
    profile: VerifiedClaimsProfile,
}

/// Non-empty, duplicate-free permissions carried by one verified federated token.
///
/// Raw strings never cross this boundary. The OIDC adapter must first parse every claim through
/// [`vocab::GrantPermission`], and the private owned fields prevent consumers from mutating the
/// verified set after the token has entered the authentication funnel.
#[derive(Clone)]
pub struct VerifiedFederatedPermissions {
    permissions: Box<[vocab::GrantPermission]>,
}

impl VerifiedFederatedPermissions {
    pub fn new(
        permissions: impl IntoIterator<Item = vocab::GrantPermission>,
    ) -> Result<Self, VerifiedClaimShapeError> {
        let mut seen = std::collections::HashSet::new();
        let mut verified = Vec::new();
        for permission in permissions {
            if !seen.insert(permission) {
                return Err(VerifiedClaimShapeError::Invalid);
            }
            verified.push(permission);
        }
        if verified.is_empty() {
            return Err(VerifiedClaimShapeError::Invalid);
        }
        Ok(Self {
            permissions: verified.into_boxed_slice(),
        })
    }

    pub fn allows_route(&self, permission: vocab::RoutePermissionId) -> bool {
        self.permissions
            .iter()
            .any(|grant| grant.matches_route(permission))
    }

    pub fn as_slice(&self) -> &[vocab::GrantPermission] {
        &self.permissions
    }
}

impl VerifiedClaims {
    pub fn rss_user(user_id: UserId, tenant: TenantId, grant: VerifiedAccessGrantFacts) -> Self {
        Self {
            profile: VerifiedClaimsProfile::RssUser {
                user_id,
                tenant,
                grant,
            },
        }
    }

    pub fn federated_access(
        subject: impl Into<String>,
        tenant: Option<TenantId>,
        kind: PrincipalKind,
        permissions: VerifiedFederatedPermissions,
    ) -> Result<Self, VerifiedClaimShapeError> {
        let subject = subject.into();
        let tenant_shape_valid = match kind {
            PrincipalKind::User | PrincipalKind::Device | PrincipalKind::Admin => tenant.is_some(),
            PrincipalKind::SuperAdmin => tenant.is_none(),
            PrincipalKind::Service | PrincipalKind::Anonymous => false,
            _ => false,
        };
        if subject.is_empty() || !tenant_shape_valid {
            return Err(VerifiedClaimShapeError::Invalid);
        }
        Ok(Self {
            profile: VerifiedClaimsProfile::FederatedAccess {
                subject,
                tenant,
                kind,
                permissions,
            },
        })
    }

    pub fn service_token(caller: ServiceCallerDomain) -> Self {
        Self {
            profile: VerifiedClaimsProfile::ServiceToken { caller },
        }
    }

    pub fn projection_operator(caller: ServiceCallerDomain, tenant: TenantId) -> Self {
        Self {
            profile: VerifiedClaimsProfile::ProjectionOperator { caller, tenant },
        }
    }

    pub fn view(&self) -> VerifiedClaimsView<'_> {
        match &self.profile {
            VerifiedClaimsProfile::RssUser {
                user_id,
                tenant,
                grant,
            } => VerifiedClaimsView::RssUser {
                user_id: *user_id,
                tenant: *tenant,
                grant,
            },
            VerifiedClaimsProfile::FederatedAccess {
                subject,
                tenant,
                kind,
                permissions,
            } => VerifiedClaimsView::FederatedAccess {
                subject,
                tenant: *tenant,
                kind: *kind,
                permissions,
            },
            VerifiedClaimsProfile::ServiceToken { caller } => {
                VerifiedClaimsView::ServiceToken { caller: *caller }
            }
            VerifiedClaimsProfile::ProjectionOperator { caller, tenant } => {
                VerifiedClaimsView::ProjectionOperator {
                    caller: *caller,
                    tenant: *tenant,
                }
            }
        }
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
    /// 验签原始凭据，成功返回可信 [`VerifiedClaims`]；失败 fail-closed（[`PdpError`]）。
    ///
    /// 生产 `OidcProvider<P>` 实现先做 profile 与输入边界检查，再做 exact key selection、
    /// 签名/tenant-bound MAC 和完整 profile claim 校验。JWKS key snapshot 与 service-token durable replay
    /// consume 使该接缝保持 async。
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
            Ok(VerifiedClaims::service_token(
                vocab::ServiceCallerDomain::MaintenanceOperator,
            ))
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn pdp_is_dyn_injectable() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}

        let pdp: Arc<DynPdp> = DynPdp::new_arc(NoopPdp);
        assert_send_sync(&pdp);
        let raw = RawCredential::rss_access("h.e.s");
        let joined = tokio::spawn(async move { pdp.verify(&raw).await.is_ok() }).await;
        assert!(matches!(joined, Ok(true)));
    }
}

#[cfg(test)]
mod token_profile_tests {
    use super::{
        FederatedAccessProfile, ProjectionOperatorTokenProfile, RssAccessProfile,
        ServiceTokenProfile, TokenAlgorithm, TokenProfile, TokenProfileMarker,
    };

    #[test]
    fn profiles_have_exact_protocol_policies() {
        let cases = [
            (
                TokenProfile::RssAccess,
                "at+jwt",
                "access",
                TokenAlgorithm::Es256,
                900,
            ),
            (
                TokenProfile::FederatedAccess,
                "at+jwt",
                "access",
                TokenAlgorithm::Es256,
                900,
            ),
            (
                TokenProfile::ServiceToken,
                "rss-service+jwt",
                "service",
                TokenAlgorithm::Hs256,
                300,
            ),
            (
                TokenProfile::ProjectionOperator,
                "rss-projection-operator+jwt",
                "projection-operator",
                TokenAlgorithm::Es256,
                300,
            ),
        ];

        for (profile, jose_typ, token_use, algorithm, maximum_lifetime_secs) in cases {
            let policy = profile.policy();
            assert_eq!(policy.jose_typ(), jose_typ);
            assert_eq!(policy.token_use(), token_use);
            assert_eq!(policy.algorithm(), algorithm);
            assert_eq!(
                policy.maximum_lifetime(),
                std::time::Duration::from_secs(maximum_lifetime_secs)
            );
            assert_eq!(policy.maximum_token_length(), 16 * 1024);
            assert_eq!(policy.maximum_header_length(), 4 * 1024);
            assert_eq!(policy.maximum_payload_length(), 12 * 1024);
            assert_eq!(policy.maximum_signature_length(), 1024);
        }
    }

    #[test]
    fn marker_profiles_resolve_to_the_closed_runtime_profiles() {
        assert_eq!(RssAccessProfile::PROFILE, TokenProfile::RssAccess);
        assert_eq!(
            FederatedAccessProfile::PROFILE,
            TokenProfile::FederatedAccess
        );
        assert_eq!(ServiceTokenProfile::PROFILE, TokenProfile::ServiceToken);
        assert_eq!(
            ProjectionOperatorTokenProfile::PROFILE,
            TokenProfile::ProjectionOperator
        );
        assert_eq!(RssAccessProfile::policy(), TokenProfile::RssAccess.policy());
    }

    #[test]
    fn jose_algorithm_names_are_exact_and_case_sensitive() {
        assert_eq!(TokenAlgorithm::Es256.jose_name(), "ES256");
        assert_eq!(TokenAlgorithm::Hs256.jose_name(), "HS256");
    }
}

#[cfg(test)]
mod pii_debug {
    //! `RawCredential.token` / `VerifiedClaims.subject·tenant` Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（同 `signer.rs` 的 `pii_debug`）。
    use super::{
        RawCredential, ServiceTokenTenantBinding, TokenProfile, VerifiedAccessGrantFacts,
        VerifiedClaims, VerifiedFederatedPermissions,
    };
    use vocab::tenant::TenantId;

    fn _assert_redact<T: secure::Redact>() {}

    #[test]
    fn pii_dtos_use_redact_derive_model() {
        _assert_redact::<RawCredential>();
        _assert_redact::<ServiceTokenTenantBinding>();
        _assert_redact::<VerifiedAccessGrantFacts>();
        _assert_redact::<VerifiedClaims>();
    }

    #[test]
    fn raw_credential_debug_redacts_token() {
        let cred = RawCredential::rss_access("secret.jwt.token");
        assert_eq!(cred.profile(), TokenProfile::RssAccess);
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("secret.jwt.token"), "原始 token 泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("RssAccess"), "profile 应可见: {dbg}");
    }

    #[test]
    fn access_constructors_fix_distinct_profiles_without_tenant_binding() {
        let rss = RawCredential::rss_access("rss.token");
        let federated = RawCredential::federated_access("federated.token");
        let projection = RawCredential::projection_operator("projection.token");
        assert_eq!(rss.profile(), TokenProfile::RssAccess);
        assert_eq!(federated.profile(), TokenProfile::FederatedAccess);
        assert_eq!(projection.profile(), TokenProfile::ProjectionOperator);
        assert!(rss.service_token_tenant().is_none());
        assert!(federated.service_token_tenant().is_none());
        assert!(projection.service_token_tenant().is_none());
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
        assert_eq!(cred.profile(), TokenProfile::ServiceToken);
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
    #[allow(clippy::expect_used)]
    fn verified_claims_debug_redacts_all_identity_fields() {
        let vc = VerifiedClaims::federated_access(
            "alice-secret",
            Some(
                TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant"),
            ),
            vocab::PrincipalKind::Admin,
            VerifiedFederatedPermissions::new([vocab::GrantPermission::route(
                vocab::RoutePermissionId::SettingsConfigPublish,
            )])
            .expect("literal permission set"),
        )
        .expect("federated claims");
        let dbg = format!("{vc:?}");
        assert!(!dbg.contains("alice-secret"), "subject 泄漏: {dbg}");
        assert!(!dbg.contains("f47ac10b"), "tenant 泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn rss_grant_facts_and_claims_debug_redact_the_complete_shape() {
        let session_id = "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8";
        let token_id = "d8dbe849-1d7e-49aa-b68a-a7b41ed252df";
        let facts = VerifiedAccessGrantFacts::try_new(session_id, token_id, 1_700_000_000, 73)
            .expect("grant facts");
        let facts_debug = format!("{facts:?}");
        for secret in [session_id, token_id, "1700000000", "73"] {
            assert!(!facts_debug.contains(secret), "grant fact leaked: {secret}");
        }

        let claims = VerifiedClaims::rss_user(
            ids::UserId::parse("550e8400-e29b-41d4-a716-446655440000").expect("user"),
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
            facts,
        );
        let claims_debug = format!("{claims:?}");
        for secret in [session_id, token_id, "550e8400", "f47ac10b"] {
            assert!(
                !claims_debug.contains(secret),
                "verified claim leaked: {secret}"
            );
        }
    }
}
