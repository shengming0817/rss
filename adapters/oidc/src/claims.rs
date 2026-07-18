//! 已验签 payload 的 profile claim 校验与 [`diport::VerifiedClaims`] 映射。
//!
//! 调用前提：签名或 tenant-bound MAC 已在 [`crate::verify`] 校验通过。本模块要求数值
//! `iat`/`exp`、字符串 `token_use`/`iss`/`sub` 和字符串或字符串数组 `aud`；然后用注入的
//! [`diport::Clock`] 校验 `iat <= exp`、未来 `iat`、profile 最大寿命、过期和 `nbf`。时间校验不读取
//! 系统时钟。失败仅记录闭值 reason 标签，不记录 token 或 claim 值。
//!
//! RSS 与 federated access 的 `user`/`device`/`admin` 必须携带 canonical tenant，
//! `superAdmin` 必须不带 tenant。Service token 必须是 `kind=service`、带非空 `jti`，且 tenant
//! claim 被禁止；其 tenant 只能来自 verifier 已纳入 MAC 的 canonical header binding。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use diport::{Clock, PdpError, TokenProfile, TokenProfileMarker, VerifiedClaims};
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
    let (tenant, kind) = validate_profile_claims::<P>(config, &claims.extra)?;
    Ok((
        VerifiedClaims::new(claims.sub, tenant, kind),
        claims.jti,
        expires_at,
    ))
}

fn validate_profile_claims<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Result<(Option<String>, Option<String>), PdpError> {
    let tenant_present = extra.contains_key(config.tenant_claim());
    let tenant = string_claim(extra, config.tenant_claim());
    let kind = string_claim(extra, config.kind_claim());

    match P::PROFILE {
        TokenProfile::RssAccess | TokenProfile::FederatedAccess => {
            let Some(kind) = kind.filter(|kind| config.is_kind_trusted(kind)) else {
                log_claim_fail(TelemetryReason::KindMissingOrUntrusted);
                return Err(PdpError::InvalidSignature);
            };
            match kind.as_str() {
                "user" | "device" | "admin" => {
                    let Some(raw_tenant) = tenant else {
                        log_claim_fail(TelemetryReason::ScopedPrincipalMissingTenant);
                        return Err(PdpError::InvalidSignature);
                    };
                    let canonical = vocab::tenant::TenantId::parse(&raw_tenant)
                        .map_err(|_| {
                            log_claim_fail(TelemetryReason::TenantNotCanonical);
                            PdpError::InvalidSignature
                        })?
                        .to_string();
                    Ok((Some(canonical), Some(kind)))
                }
                "superAdmin" if !tenant_present => Ok((None, Some(kind))),
                "superAdmin" => {
                    log_claim_fail(TelemetryReason::SuperAdminHasTenant);
                    Err(PdpError::InvalidSignature)
                }
                _ => {
                    log_claim_fail(TelemetryReason::UnsupportedPrincipalKind);
                    Err(PdpError::InvalidSignature)
                }
            }
        }
        TokenProfile::ServiceToken => {
            if kind.as_deref() != Some("service") {
                log_claim_fail(TelemetryReason::ServiceKindInvalid);
                return Err(PdpError::InvalidSignature);
            }
            if tenant_present {
                log_claim_fail(TelemetryReason::ServiceTenantClaimForbidden);
                return Err(PdpError::InvalidSignature);
            }
            Ok((None, Some("service".to_string())))
        }
    }
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
    fn minimal_config(trust_kinds: &[&str]) -> VerifierConfig<diport::RssAccessProfile> {
        let mut builder =
            VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
                .keys_static(
                    AccessStaticKeySource::builder()
                        .add_es256_sec1("test-es256", &valid_es256_sec1())
                        .expect("key")
                        .build(),
                );
        for k in trust_kinds {
            builder = builder.trust_kind(*k);
        }
        builder.build().expect("valid config")
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
        let config = minimal_config(&["user"]);
        let payload = br#"{
            "sub":"alice",
            "iss":"https://iss",
            "aud":"aud",
            "iat":1000,
            "exp":1901,
            "token_use":"access",
            "kind":"user",
            "tenant_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479"
        }"#;

        assert!(
            validate_and_map(&config, &FixedClock(1000), payload).is_err(),
            "access token 的 exp-iat 超过 900 秒必须 fail-closed"
        );
    }
}
