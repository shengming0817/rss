//! 已验签 payload 的 profile claim 校验与 [`diport::VerifiedClaims`] 映射。
//!
//! 调用前提：标准 JWS 签名已在 [`crate::verify`] 校验通过。本模块要求数值
//! `iat`/`exp`、字符串 `token_use`/`iss`/`sub` 和字符串或字符串数组 `aud`；然后用注入的
//! [`diport::Clock`] 校验 `iat <= exp`、未来 `iat`、profile 最大寿命、过期和 `nbf`。时间校验不读取
//! 系统时钟。失败仅记录闭值 reason 标签，不记录 token 或 claim 值。
//!
//! RSS access 只接受 canonical User/tenant 和完整 session-bound grant quartet。Federated access
//! 独立接受 allowlisted `user`/`device`/`admin`/`superAdmin` shape，即使出现同名 RSS extension
//! claims 也不会生成本地 grant evidence。Service token 必须是 `kind=service`、带非空 `jti` 与
//! canonical signed `tenant_id`；header equality 由 verifier 在 claims 映射之后执行。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use diport::{
    Clock, PdpError, TokenProfile, TokenProfileMarker, VerifiedAccessGrantFacts, VerifiedClaims,
};
use serde::Deserialize;

use crate::config::VerifierConfig;
use crate::verify::{TelemetryReason, log_claim_fail};

/// 验签后反序列化的 claims（私有 DTO，非域实体）。
///
/// `sub`/`iat`/`exp`/`token_use`/`iss`/`aud` 必填；`jti`/`nbf` 可选；其余（含可配置
/// tenant/kind claim）经 `flatten` 落 `extra`，按配置名取字符串值。
#[derive(Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
    token_use: String,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    nbf: Option<i64>,
    iss: String,
    aud: Audience,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// `aud` 可为单串或串数组（RFC 7519 §4.1.3）。`untagged`：先试 string、再试 array。
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(a) => a == expected,
            Self::Many(list) => list.iter().any(|a| a == expected),
        }
    }
}

/// 校验已验签 payload 的 claim 语义并映射到可信 [`VerifiedClaims`]。
///
/// 校验顺序：反序列化 → `iat`/`exp`/`nbf` 与 profile 最大寿命 → exact `token_use` → issuer →
/// audience → 非空 subject → profile-specific tenant/kind。任一失败 fail-closed 归类
/// [`PdpError`]，不记录 PII。
pub(crate) fn validate_and_map<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    clock: &dyn Clock,
    payload: &[u8],
) -> Result<VerifiedClaims, PdpError> {
    validate_claims(config, clock, payload).map(|(claims, _jti, _expires_at)| claims)
}

/// Service-token claim validation additionally requires a non-empty `jti` nonce.
pub(crate) fn validate_service_token_and_map<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    clock: &dyn Clock,
    payload: &[u8],
) -> Result<(VerifiedClaims, String, SystemTime), PdpError> {
    let (claims, jti, expires_at) = validate_claims(config, clock, payload)?;
    let Some(jti) = jti.filter(|s| !s.is_empty()) else {
        log_claim_fail(TelemetryReason::MissingJti);
        return Err(PdpError::InvalidSignature);
    };
    Ok((claims, jti, expires_at))
}

fn validate_claims<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    clock: &dyn Clock,
    payload: &[u8],
) -> Result<(VerifiedClaims, Option<String>, SystemTime), PdpError> {
    let claims: Claims = serde_json::from_slice(payload).map_err(|_| {
        // 缺必填 claim / JSON 畸形 → 不可用 token。不记 payload 字节。
        log_claim_fail(TelemetryReason::MalformedOrMissingClaim);
        PdpError::InvalidSignature
    })?;

    let now = now_unix_secs(clock).ok_or_else(|| {
        // Clock 早于 UNIX_EPOCH（不可能的系统态）→ fail-closed，不放行。
        log_claim_fail(TelemetryReason::ClockBeforeEpoch);
        PdpError::InvalidSignature
    })?;
    validate_time_window(
        &claims,
        now,
        config.leeway_secs(),
        P::policy().maximum_lifetime().as_secs(),
    )?;

    if claims.token_use != P::policy().token_use() {
        log_claim_fail(TelemetryReason::TokenUseProfileMismatch);
        return Err(PdpError::Untrusted);
    }

    if claims.iss != config.issuer() {
        log_claim_fail(TelemetryReason::UntrustedIssuer);
        return Err(PdpError::Untrusted);
    }
    if !claims.aud.contains(config.audience()) {
        log_claim_fail(TelemetryReason::UntrustedAudience);
        return Err(PdpError::Untrusted);
    }
    if claims.sub.is_empty() {
        // 空 sub 能过 required-claim 存在性，但匿名 token 在 authn 侧无法 mint Principal → 不可用（401）。
        log_claim_fail(TelemetryReason::EmptySubject);
        return Err(PdpError::InvalidSignature);
    }

    let expires_at = expiry_system_time(claims.exp, config.leeway_secs()).ok_or_else(|| {
        log_claim_fail(TelemetryReason::InvalidExpiryBoundary);
        PdpError::InvalidSignature
    })?;
    let verified = validate_profile_claims::<P>(config, &claims)?;
    Ok((verified, claims.jti, expires_at))
}

fn validate_profile_claims<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    claims: &Claims,
) -> Result<VerifiedClaims, PdpError> {
    let tenant_present = claims.extra.contains_key(config.tenant_claim());
    let tenant = string_claim(&claims.extra, config.tenant_claim());
    let kind = string_claim(&claims.extra, config.kind_claim());

    match P::PROFILE {
        TokenProfile::RssAccess => validate_rss_profile_claims(claims, tenant, kind),
        TokenProfile::FederatedAccess => {
            let Some(kind) = kind.filter(|kind| config.is_kind_trusted(kind)) else {
                log_claim_fail(TelemetryReason::KindMissingOrUntrusted);
                return Err(PdpError::InvalidSignature);
            };
            let (tenant, kind) = match kind.as_str() {
                "user" | "device" | "admin" => {
                    let tenant = canonical_tenant(tenant)?;
                    let kind = match kind.as_str() {
                        "user" => vocab::PrincipalKind::User,
                        "device" => vocab::PrincipalKind::Device,
                        "admin" => vocab::PrincipalKind::Admin,
                        _ => unreachable!(),
                    };
                    (Some(tenant), kind)
                }
                "superAdmin" if !tenant_present => (None, vocab::PrincipalKind::SuperAdmin),
                "superAdmin" => {
                    log_claim_fail(TelemetryReason::SuperAdminHasTenant);
                    return Err(PdpError::InvalidSignature);
                }
                _ => {
                    log_claim_fail(TelemetryReason::UnsupportedPrincipalKind);
                    return Err(PdpError::InvalidSignature);
                }
            };
            let permissions = validate_federated_permissions(config, claims)?;
            VerifiedClaims::federated_access(claims.sub.clone(), tenant, kind, permissions).map_err(
                |_| {
                    log_claim_fail(TelemetryReason::FederatedPermissionsInvalid);
                    PdpError::InvalidSignature
                },
            )
        }
        TokenProfile::ServiceToken => {
            if claims.permissions.is_some() {
                log_claim_fail(TelemetryReason::ServicePermissionsForbidden);
                return Err(PdpError::InvalidSignature);
            }
            if kind.as_deref() != Some("service") {
                log_claim_fail(TelemetryReason::ServiceKindInvalid);
                return Err(PdpError::InvalidSignature);
            }
            // Empty sub already rejected upstream as EmptySubject; non-empty unknown
            // callers are a distinct closed-set miss (not an empty subject).
            let caller =
                vocab::ServiceCallerDomain::from_subject(&claims.sub).ok_or_else(|| {
                    log_claim_fail(TelemetryReason::ServiceSubjectUnknown);
                    PdpError::InvalidSignature
                })?;
            let tenant = canonical_tenant(tenant)?;
            Ok(VerifiedClaims::service_token(caller, tenant))
        }
        TokenProfile::ProjectionOperator => {
            if claims.permissions.is_some() {
                log_claim_fail(TelemetryReason::ServicePermissionsForbidden);
                return Err(PdpError::InvalidSignature);
            }
            if kind.as_deref() != Some("service") {
                log_claim_fail(TelemetryReason::ServiceKindInvalid);
                return Err(PdpError::InvalidSignature);
            }
            let caller =
                vocab::ServiceCallerDomain::from_subject(&claims.sub).ok_or_else(|| {
                    log_claim_fail(TelemetryReason::ServiceSubjectUnknown);
                    PdpError::InvalidSignature
                })?;
            if caller != vocab::ServiceCallerDomain::MaintenanceOperator {
                log_claim_fail(TelemetryReason::ServiceSubjectUnknown);
                return Err(PdpError::InvalidSignature);
            }
            let tenant = canonical_tenant(tenant)?;
            Ok(VerifiedClaims::projection_operator(caller, tenant))
        }
    }
}

fn validate_federated_permissions<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    claims: &Claims,
) -> Result<diport::VerifiedFederatedPermissions, PdpError> {
    let raw_permissions = claims
        .permissions
        .as_ref()
        .filter(|values| !values.is_empty())
        .ok_or_else(|| {
            log_claim_fail(TelemetryReason::FederatedPermissionsInvalid);
            PdpError::InvalidSignature
        })?;
    let mut permissions = Vec::with_capacity(raw_permissions.len());
    for raw in raw_permissions {
        let permission = vocab::GrantPermission::parse(raw).map_err(|_| {
            log_claim_fail(TelemetryReason::FederatedPermissionsInvalid);
            PdpError::InvalidSignature
        })?;
        if permission.as_route().is_none() || !config.is_federated_permission_trusted(permission) {
            log_claim_fail(TelemetryReason::FederatedPermissionsInvalid);
            return Err(PdpError::Untrusted);
        }
        permissions.push(permission);
    }
    diport::VerifiedFederatedPermissions::new(permissions).map_err(|_| {
        log_claim_fail(TelemetryReason::FederatedPermissionsInvalid);
        PdpError::InvalidSignature
    })
}

fn validate_rss_profile_claims(
    claims: &Claims,
    tenant: Option<String>,
    kind: Option<String>,
) -> Result<VerifiedClaims, PdpError> {
    if claims.permissions.is_some() {
        log_claim_fail(TelemetryReason::RssGrantFactsInvalid);
        return Err(PdpError::InvalidSignature);
    }
    validate_rss_time_window(claims)?;
    if kind.as_deref() != Some("user") {
        log_claim_fail(TelemetryReason::RssKindInvalid);
        return Err(PdpError::InvalidSignature);
    }
    let user_id = ids::UserId::parse(&claims.sub).map_err(|_| {
        log_claim_fail(TelemetryReason::RssSubjectNotCanonical);
        PdpError::InvalidSignature
    })?;
    if user_id.as_uuid().hyphenated().to_string() != claims.sub {
        log_claim_fail(TelemetryReason::RssSubjectNotCanonical);
        return Err(PdpError::InvalidSignature);
    }
    let tenant = canonical_tenant(tenant)?;
    let Some(session_id) = string_claim(&claims.extra, "sid") else {
        log_claim_fail(TelemetryReason::RssGrantFactsInvalid);
        return Err(PdpError::InvalidSignature);
    };
    let Some(token_id) = claims.jti.clone().filter(|value| !value.is_empty()) else {
        log_claim_fail(TelemetryReason::RssGrantFactsInvalid);
        return Err(PdpError::InvalidSignature);
    };
    let Some(auth_time) = integer_claim(&claims.extra, "auth_time") else {
        log_claim_fail(TelemetryReason::RssGrantFactsInvalid);
        return Err(PdpError::InvalidSignature);
    };
    let Some(authn_epoch) = integer_claim(&claims.extra, "authn_epoch") else {
        log_claim_fail(TelemetryReason::RssGrantFactsInvalid);
        return Err(PdpError::InvalidSignature);
    };
    if auth_time > claims.iat {
        log_claim_fail(TelemetryReason::AuthTimeAfterIat);
        return Err(PdpError::InvalidSignature);
    }
    let grant = VerifiedAccessGrantFacts::try_new(session_id, token_id, auth_time, authn_epoch)
        .map_err(|_| {
            log_claim_fail(TelemetryReason::RssGrantFactsInvalid);
            PdpError::InvalidSignature
        })?;
    Ok(VerifiedClaims::rss_user(user_id, tenant, grant))
}

/// RSS grant evidence represents a usable access window, so unlike the shared
/// federated/service boundary it requires the strict RFC 9068 shape `iat < exp`.
fn validate_rss_time_window(claims: &Claims) -> Result<(), PdpError> {
    if claims.iat >= claims.exp {
        log_claim_fail(TelemetryReason::IatAfterExp);
        return Err(PdpError::InvalidSignature);
    }
    Ok(())
}

fn canonical_tenant(raw: Option<String>) -> Result<vocab::TenantId, PdpError> {
    let Some(raw) = raw else {
        log_claim_fail(TelemetryReason::ScopedPrincipalMissingTenant);
        return Err(PdpError::InvalidSignature);
    };
    let tenant = vocab::TenantId::parse(&raw).map_err(|_| {
        log_claim_fail(TelemetryReason::TenantNotCanonical);
        PdpError::InvalidSignature
    })?;
    if tenant.to_string() != raw {
        log_claim_fail(TelemetryReason::TenantNotCanonical);
        return Err(PdpError::InvalidSignature);
    }
    Ok(tenant)
}

fn integer_claim(extra: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<i64> {
    extra.get(name).and_then(serde_json::Value::as_i64)
}

/// iat/exp/nbf 越界判定（注入时钟 + leeway）。过期 / 未生效均 → [`PdpError::Expired`]。
/// `leeway` 以 u64 传入，经 `saturating_add_unsigned` / `saturating_sub_unsigned` 消除 u64→i64 截断。
fn validate_time_window(
    claims: &Claims,
    now: i64,
    leeway: u64,
    maximum_lifetime_secs: u64,
) -> Result<(), PdpError> {
    if claims.iat > claims.exp {
        log_claim_fail(TelemetryReason::IatAfterExp);
        return Err(PdpError::InvalidSignature);
    }
    if claims.iat > now.saturating_add_unsigned(leeway) {
        log_claim_fail(TelemetryReason::IatInFuture);
        return Err(PdpError::InvalidSignature);
    }
    let lifetime = claims.exp.saturating_sub(claims.iat);
    if u64::try_from(lifetime).map_or(true, |value| value > maximum_lifetime_secs) {
        log_claim_fail(TelemetryReason::MaximumLifetimeExceeded);
        return Err(PdpError::InvalidSignature);
    }
    // 过期：now > exp + leeway。saturating_add_unsigned 防 exp 极端值 + 大 leeway 溢出 panic。
    if now > claims.exp.saturating_add_unsigned(leeway) {
        log_claim_fail(TelemetryReason::Expired);
        return Err(PdpError::Expired);
    }
    // 未生效：now < nbf - leeway。
    if let Some(nbf) = claims.nbf
        && now < nbf.saturating_sub_unsigned(leeway)
    {
        log_claim_fail(TelemetryReason::NotYetValid);
        return Err(PdpError::Expired);
    }
    Ok(())
}

/// 注入时钟 → UNIX 秒（i64）。早于 epoch → None（fail-closed）；u64 秒溢出 i64 → None（不放行）。
fn now_unix_secs(clock: &dyn Clock) -> Option<i64> {
    clock
        .now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

fn expiry_system_time(exp: i64, leeway: u64) -> Option<SystemTime> {
    let expires_at = exp.saturating_add_unsigned(leeway);
    let secs = u64::try_from(expires_at).ok()?;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// 从 extra 取字符串型 claim（非字符串 / 缺失 → None，不强转、不 panic）。
fn string_claim(extra: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<String> {
    extra.get(name).and_then(|v| v.as_str()).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    //! 私有 helper 单测：`now_unix_secs` / `trusted_kind` / `validate_time_window` 边界覆盖。
    //! item-level `#[allow(clippy::expect_used)]` 按 error-handling.md §Carve-out 标注。

    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::config::{AccessStaticKeySource, VerifierConfigBuilder};
    use diport::VerifiedClaimsView;

    const NOW: i64 = 1_700_000_000;
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const CANON_USER: &str = "550e8400-e29b-41d4-a716-446655440000";
    const CANON_SID: &str = "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8";
    const CANON_JTI: &str = "d8dbe849-1d7e-49aa-b68a-a7b41ed252df";

    /// FixedClock 替身：返回固定 UNIX 秒（非系统时钟，确定性时间边界）。
    struct FixedClock(i64);
    impl diport::Clock for FixedClock {
        fn now(&self) -> SystemTime {
            if self.0 >= 0 {
                UNIX_EPOCH + Duration::from_secs(self.0 as u64)
            } else {
                // 负秒：早于 epoch（模拟 epoch 前时钟）。
                UNIX_EPOCH - Duration::from_secs(self.0.unsigned_abs())
            }
        }
    }

    /// 合法 ES256 SEC1 点（固定 fixture；永非生产 key）。
    #[allow(clippy::expect_used)]
    fn valid_es256_sec1() -> Vec<u8> {
        p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32])
            .expect("valid scalar")
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// 构造一个 claims.rs 可用的最小 VerifierConfig（仅需 issuer/aud/keys 字段）。
    #[allow(clippy::expect_used)]
    fn minimal_config() -> VerifierConfig<diport::RssAccessProfile> {
        VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(
                AccessStaticKeySource::builder()
                    .add_es256_sec1("test-es256", &valid_es256_sec1())
                    .expect("key")
                    .build(),
            )
            .build()
            .expect("valid config")
    }

    #[allow(clippy::expect_used)]
    fn minimal_federated_config() -> VerifierConfig<diport::FederatedAccessProfile> {
        let permissions =
            crate::FederatedPermissionUniverse::try_new([vocab::GrantPermission::route(
                vocab::RoutePermissionId::SettingsConfigPublish,
            )])
            .expect("permission universe");
        let mut builder = VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
            "https://iss",
            "aud",
            permissions,
        )
        .keys_static(
            AccessStaticKeySource::builder()
                .add_es256_sec1("test-es256", &valid_es256_sec1())
                .expect("key")
                .build(),
        );
        for kind in ["user", "device", "admin", "superAdmin"] {
            builder = builder.trust_kind(kind);
        }
        builder.build().expect("valid federated config")
    }

    fn valid_rss_payload() -> serde_json::Value {
        serde_json::json!({
            "sub": CANON_USER,
            "iss": "https://iss",
            "aud": "aud",
            "iat": NOW,
            "exp": NOW + 600,
            "token_use": "access",
            "kind": "user",
            "tenant_id": CANON_TENANT,
            "sid": CANON_SID,
            "jti": CANON_JTI,
            "auth_time": NOW - 30,
            "authn_epoch": 7,
        })
    }

    #[allow(clippy::expect_used)]
    fn validate_json<P: diport::TokenProfileMarker>(
        config: &VerifierConfig<P>,
        payload: &serde_json::Value,
    ) -> Result<VerifiedClaims, PdpError> {
        let encoded = serde_json::to_vec(payload).expect("encode claim fixture");
        validate_and_map(config, &FixedClock(NOW), &encoded)
    }

    #[allow(clippy::panic)]
    fn expect_rss_user(
        claims: &VerifiedClaims,
    ) -> (ids::UserId, vocab::TenantId, &VerifiedAccessGrantFacts) {
        match claims.view() {
            VerifiedClaimsView::RssUser {
                user_id,
                tenant,
                grant,
            } => (user_id, tenant, grant),
            VerifiedClaimsView::FederatedAccess { .. } => {
                panic!("expected RSS user claims, got federated access")
            }
            VerifiedClaimsView::ServiceToken { .. } => {
                panic!("expected RSS user claims, got service token")
            }
            VerifiedClaimsView::ProjectionOperator { .. } => {
                panic!("expected RSS user claims, got Projection operator")
            }
        }
    }

    #[allow(clippy::panic)]
    fn expect_federated(
        claims: &VerifiedClaims,
    ) -> (&str, Option<vocab::TenantId>, vocab::PrincipalKind) {
        match claims.view() {
            VerifiedClaimsView::FederatedAccess {
                subject,
                tenant,
                kind,
                ..
            } => (subject, tenant, kind),
            VerifiedClaimsView::RssUser { .. } => {
                panic!("expected federated access claims, got RSS user")
            }
            VerifiedClaimsView::ServiceToken { .. } => {
                panic!("expected federated access claims, got service token")
            }
            VerifiedClaimsView::ProjectionOperator { .. } => {
                panic!("expected federated access claims, got Projection operator")
            }
        }
    }

    // ── now_unix_secs ──────────────────────────────────────────────────────────

    #[test]
    fn now_unix_secs_normal_returns_some() {
        // 2023-11-14T22:13:20Z（固定值，非系统时钟）→ Some(正数)。
        let clock = FixedClock(1_700_000_000);
        let result = now_unix_secs(&clock);
        assert_eq!(result, Some(1_700_000_000));
    }

    #[test]
    fn now_unix_secs_before_epoch_returns_none() {
        // duration_since(UNIX_EPOCH) 返回 Err → None（fail-closed）。
        // 模拟：返回 UNIX_EPOCH - 1s（即 SystemTime::now() < UNIX_EPOCH）。
        struct BeforeEpochClock;
        impl diport::Clock for BeforeEpochClock {
            fn now(&self) -> SystemTime {
                UNIX_EPOCH - Duration::from_secs(1)
            }
        }
        let result = now_unix_secs(&BeforeEpochClock);
        assert_eq!(result, None);
    }

    // ── validate_time_window ──────────────────────────────────────────────────

    /// 构造最小 Claims 用于 validate_time_window。
    fn make_claims(exp: i64, nbf: Option<i64>) -> Claims {
        Claims {
            sub: "alice".to_string(),
            iat: exp.saturating_sub(600),
            exp,
            token_use: "access".to_string(),
            jti: None,
            nbf,
            iss: "https://iss".to_string(),
            aud: Audience::One("aud".to_string()),
            permissions: None,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn validate_time_window_not_expired_ok() {
        let claims = make_claims(1500, None);
        assert!(validate_time_window(&claims, 1000, 60, 900).is_ok());
    }

    #[test]
    fn validate_time_window_expired_err() {
        // now=2100, exp=2000, leeway=60 → now(2100) > exp+leeway(2060) true → Expired。
        let claims = make_claims(1800, None);
        assert!(matches!(
            validate_time_window(&claims, 1900, 60, 900),
            Err(PdpError::Expired)
        ));
    }

    #[test]
    fn validate_time_window_at_exp_plus_leeway_boundary_ok() {
        // now=2060, exp=2000, leeway=60 → now(2060) > exp+leeway(2060) false（不等）→ Ok。
        let claims = make_claims(1800, None);
        assert!(validate_time_window(&claims, 1860, 60, 900).is_ok());
    }

    #[test]
    fn validate_time_window_nbf_future_beyond_leeway_err() {
        // now=1000, nbf=1100, leeway=60 → now(1000) < nbf-leeway(1040) true → Expired。
        let claims = make_claims(1500, Some(1100));
        assert!(matches!(
            validate_time_window(&claims, 1000, 60, 900),
            Err(PdpError::Expired)
        ));
    }

    #[test]
    fn validate_time_window_nbf_within_leeway_ok() {
        // now=1000, nbf=1050, leeway=60 → now(1000) < nbf-leeway(990) false → Ok。
        let claims = make_claims(1500, Some(1050));
        assert!(validate_time_window(&claims, 1000, 60, 900).is_ok());
    }

    #[test]
    fn access_claims_reject_lifetime_over_900_seconds() {
        let config = minimal_config();
        let payload = br#"{
            "sub":"550e8400-e29b-41d4-a716-446655440000",
            "iss":"https://iss",
            "aud":"aud",
            "iat":1000,
            "exp":1901,
            "token_use":"access",
            "kind":"user",
            "tenant_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "sid":"7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8",
            "jti":"d8dbe849-1d7e-49aa-b68a-a7b41ed252df",
            "auth_time":1000,
            "authn_epoch":7
        }"#;

        assert!(
            validate_and_map(&config, &FixedClock(1000), payload).is_err(),
            "access token 的 exp-iat 超过 900 秒必须 fail-closed"
        );
    }

    enum QuartetMutation {
        Remove(&'static str),
        Replace(&'static str, serde_json::Value),
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn rss_grant_quartet_rejects_missing_null_type_empty_non_v4_negative_overflow_and_inversion() {
        use QuartetMutation::{Remove, Replace};

        let cases = vec![
            ("missing sid", Remove("sid")),
            ("missing jti", Remove("jti")),
            ("missing auth_time", Remove("auth_time")),
            ("missing authn_epoch", Remove("authn_epoch")),
            ("null sid", Replace("sid", serde_json::Value::Null)),
            ("null jti", Replace("jti", serde_json::Value::Null)),
            (
                "null auth_time",
                Replace("auth_time", serde_json::Value::Null),
            ),
            (
                "null authn_epoch",
                Replace("authn_epoch", serde_json::Value::Null),
            ),
            ("typed sid", Replace("sid", serde_json::json!(17))),
            ("typed jti", Replace("jti", serde_json::json!(true))),
            (
                "typed auth_time",
                Replace("auth_time", serde_json::json!([NOW])),
            ),
            (
                "typed authn_epoch",
                Replace("authn_epoch", serde_json::json!({"epoch": 7})),
            ),
            ("empty sid", Replace("sid", serde_json::json!(""))),
            ("empty jti", Replace("jti", serde_json::json!(""))),
            (
                "empty auth_time",
                Replace("auth_time", serde_json::json!("")),
            ),
            (
                "empty authn_epoch",
                Replace("authn_epoch", serde_json::json!("")),
            ),
            (
                "non-v4 sid",
                Replace(
                    "sid",
                    serde_json::json!("00000000-0000-1000-8000-000000000000"),
                ),
            ),
            (
                "non-v4 jti",
                Replace(
                    "jti",
                    serde_json::json!("00000000-0000-5000-8000-000000000000"),
                ),
            ),
            (
                "negative auth_time",
                Replace("auth_time", serde_json::json!(-1)),
            ),
            (
                "negative authn_epoch",
                Replace("authn_epoch", serde_json::json!(-1)),
            ),
            (
                "overflow auth_time",
                Replace("auth_time", serde_json::json!(u64::MAX)),
            ),
            (
                "overflow authn_epoch",
                Replace("authn_epoch", serde_json::json!(u64::MAX)),
            ),
            (
                "auth_time after iat",
                Replace("auth_time", serde_json::json!(NOW + 1)),
            ),
        ];
        let config = minimal_config();

        for (label, mutation) in cases {
            let mut payload = valid_rss_payload();
            let claims = payload.as_object_mut().expect("object fixture");
            match mutation {
                Remove(name) => {
                    claims.remove(name);
                }
                Replace(name, value) => {
                    claims.insert(name.to_owned(), value);
                }
            }
            let result = validate_json(&config, &payload);
            assert!(
                matches!(result, Err(PdpError::InvalidSignature)),
                "{label} must fail closed: {result:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn rss_subject_accepts_only_canonical_lowercase_hyphenated_uuid() {
        let config = minimal_config();
        let cases = [
            ("canonical", CANON_USER, true),
            ("invalid UUID", "not-a-uuid", false),
            (
                "uppercase UUID",
                "550E8400-E29B-41D4-A716-446655440000",
                false,
            ),
            ("compact UUID", "550e8400e29b41d4a716446655440000", false),
        ];

        for (label, subject, accepted) in cases {
            let mut payload = valid_rss_payload();
            payload["sub"] = serde_json::json!(subject);
            let result = validate_json(&config, &payload);

            if accepted {
                let claims = result.expect("canonical RSS subject must be accepted");
                let (user, _, _) = expect_rss_user(&claims);
                assert_eq!(user.as_uuid().hyphenated().to_string(), CANON_USER);
            } else {
                assert!(
                    matches!(result, Err(PdpError::InvalidSignature)),
                    "{label} must fail closed: {result:?}"
                );
            }
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn valid_rss_quartet_maps_as_one_typed_grant_shape() {
        let claims = validate_json(&minimal_config(), &valid_rss_payload()).expect("valid RSS");
        let (user, tenant, grant) = expect_rss_user(&claims);
        assert_eq!(user.as_uuid().hyphenated().to_string(), CANON_USER);
        assert_eq!(tenant.to_string(), CANON_TENANT);
        assert_eq!(grant.session_id().to_string(), CANON_SID);
        assert_eq!(grant.token_id().to_string(), CANON_JTI);
        assert_eq!(grant.auth_time_unix_secs(), (NOW - 30) as u64);
        assert_eq!(grant.authn_epoch(), 7);
    }

    #[test]
    fn rss_access_rejects_zero_lifetime_window() {
        let mut payload = valid_rss_payload();
        payload["exp"] = serde_json::json!(NOW);

        assert!(matches!(
            validate_json(&minimal_config(), &payload),
            Err(PdpError::InvalidSignature)
        ));
    }

    #[test]
    fn rss_access_rejects_every_non_user_principal_kind() {
        let config = minimal_config();
        for kind in ["device", "admin", "superAdmin", "service"] {
            let mut payload = valid_rss_payload();
            payload["kind"] = serde_json::json!(kind);
            let result = validate_json(&config, &payload);
            assert!(
                matches!(result, Err(PdpError::InvalidSignature)),
                "RSS kind {kind} must fail closed: {result:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn federated_kinds_accept_native_and_rss_extension_shapes_without_local_grant_evidence() {
        let config = minimal_federated_config();
        let cases = [
            ("user", vocab::PrincipalKind::User, true),
            ("device", vocab::PrincipalKind::Device, true),
            ("admin", vocab::PrincipalKind::Admin, true),
            ("superAdmin", vocab::PrincipalKind::SuperAdmin, false),
        ];

        for (kind_claim, expected_kind, scoped) in cases {
            for rss_extensions in [false, true] {
                let mut payload = valid_rss_payload();
                payload["sub"] = serde_json::json!(format!("external-{kind_claim}"));
                payload["kind"] = serde_json::json!(kind_claim);
                payload["permissions"] = serde_json::json!(["settings.config-publish"]);
                let fixture = payload.as_object_mut().expect("object fixture");
                if !scoped {
                    fixture.remove("tenant_id");
                }
                if !rss_extensions {
                    for name in ["sid", "jti", "auth_time", "authn_epoch"] {
                        fixture.remove(name);
                    }
                }

                let claims = validate_json(&config, &payload).expect("valid federated shape");
                let (subject, tenant, kind) = expect_federated(&claims);
                assert_eq!(subject, format!("external-{kind_claim}"));
                assert_eq!(kind, expected_kind);
                assert_eq!(tenant.is_some(), scoped);
                if let Some(tenant) = tenant {
                    assert_eq!(tenant.to_string(), CANON_TENANT);
                }
            }
        }
    }

    #[test]
    fn federated_permissions_reject_every_non_closed_shape() {
        let config = minimal_federated_config();
        let cases = [
            (None, PdpError::InvalidSignature),
            (Some(serde_json::json!([])), PdpError::InvalidSignature),
            (
                Some(serde_json::json!([
                    "settings.config-publish",
                    "settings.config-publish"
                ])),
                PdpError::InvalidSignature,
            ),
            (
                Some(serde_json::json!(["settings.unknown"])),
                PdpError::InvalidSignature,
            ),
            (
                Some(serde_json::json!(["runtime:inventory:read"])),
                PdpError::Untrusted,
            ),
            (
                Some(serde_json::json!([
                    "identity:policy:manage:settings.config-publish"
                ])),
                PdpError::Untrusted,
            ),
        ];
        for (permissions, expected) in cases {
            let mut payload = valid_rss_payload();
            payload["sub"] = serde_json::json!("external-user");
            payload["kind"] = serde_json::json!("user");
            for name in ["sid", "jti", "auth_time", "authn_epoch"] {
                payload
                    .as_object_mut()
                    .expect("object fixture")
                    .remove(name);
            }
            match permissions {
                Some(value) => payload["permissions"] = value,
                None => {
                    payload
                        .as_object_mut()
                        .expect("object fixture")
                        .remove("permissions");
                }
            }
            let error = validate_json(&config, &payload).expect_err("shape must fail closed");
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
        }
    }
}
