//! 已验签 payload → `diport::VerifiedClaims` 映射 + claim 校验（exp/nbf 经**注入** `diport::Clock`、iss/aud/sub）。
//!
//! 调用前提：签名/MAC **已**在 [`crate::verify`] 校验通过——本模块只校 claim 语义。PII 边界：失败只记 reason
//! 闭值标签（不记 token / claim 值）。`exp`/`iss`/`aud`/`sub` 为必填字段（缺失 → 反序列化失败 → 不可用 token →
//! `InvalidSignature`）；`exp` 必填即拒永久 token。时间一律取注入 `Clock`（**禁系统时钟**，rust-standards 护栏）。

use std::time::UNIX_EPOCH;

use diport::{Clock, PdpError, VerifiedClaims};
use serde::Deserialize;

use crate::config::VerifierConfig;
use crate::verify::LOG_TARGET;

/// 验签后反序列化的 claims（私有 DTO，非域实体）。`sub`/`exp`/`iss`/`aud` 必填；`nbf` 可选；其余（含可配置
/// tenant/kind claim）经 `flatten` 落 `extra`，按配置名取字符串值。
#[derive(Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
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

/// 校验已验签 payload 的 claim 语义并映射到可信 [`VerifiedClaims`]。校验序：反序列化 → exp/nbf（注入 Clock +
/// leeway）→ iss → aud → sub 非空 → tenant/kind 透传。任一失败 fail-closed 归类 [`PdpError`]，不记 PII。
pub(crate) fn validate_and_map(
    config: &VerifierConfig,
    clock: &dyn Clock,
    payload: &[u8],
) -> Result<VerifiedClaims, PdpError> {
    let claims: Claims = serde_json::from_slice(payload).map_err(|_| {
        // 缺必填 claim / JSON 畸形 → 不可用 token。不记 payload 字节。
        log_fail("malformed_or_missing_claim");
        PdpError::InvalidSignature
    })?;

    let now = now_unix_secs(clock).ok_or_else(|| {
        // Clock 早于 UNIX_EPOCH（不可能的系统态）→ fail-closed，不放行。
        log_fail("clock_before_epoch");
        PdpError::InvalidSignature
    })?;
    validate_time_window(&claims, now, config.leeway_secs())?;

    if claims.iss != config.issuer() {
        log_fail("untrusted_issuer");
        return Err(PdpError::Untrusted);
    }
    if !claims.aud.contains(config.audience()) {
        log_fail("untrusted_audience");
        return Err(PdpError::Untrusted);
    }
    if claims.sub.is_empty() {
        // 空 sub 能过 required-claim 存在性，但匿名 token 在 authn 侧无法 mint Principal → 不可用（401）。
        log_fail("empty_subject");
        return Err(PdpError::InvalidSignature);
    }

    let tenant = string_claim(&claims.extra, config.tenant_claim());
    let kind = trusted_kind(config, &claims.extra);
    Ok(VerifiedClaims::new(claims.sub, tenant, kind))
}

/// exp/nbf 越界判定（注入时钟 + leeway）。过期 / 未生效均 → [`PdpError::Expired`]。
/// `leeway` 以 u64 传入，经 `saturating_add_unsigned` / `saturating_sub_unsigned` 消除 u64→i64 截断。
fn validate_time_window(claims: &Claims, now: i64, leeway: u64) -> Result<(), PdpError> {
    // 过期：now > exp + leeway。saturating_add_unsigned 防 exp 极端值 + 大 leeway 溢出 panic。
    if now > claims.exp.saturating_add_unsigned(leeway) {
        log_fail("expired");
        return Err(PdpError::Expired);
    }
    // 未生效：now < nbf - leeway。
    if let Some(nbf) = claims.nbf
        && now < nbf.saturating_sub_unsigned(leeway)
    {
        log_fail("not_yet_valid");
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

/// 取 kind claim 并经 operator allowlist 过滤：值 ∈ 信任集 → 透传；存在但不信任 → 剥离 None + debug 记一笔
/// （安全可观测：外部 IdP 试图 assert 未授权 kind）；缺失 → None。**不**记 kind 原值。
fn trusted_kind(
    config: &VerifierConfig,
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    match string_claim(extra, config.kind_claim()) {
        Some(k) if config.is_kind_trusted(&k) => Some(k),
        Some(_) => {
            tracing::debug!(
                target: LOG_TARGET,
                resource = LOG_TARGET,
                reason = "kind_not_allowlisted",
                "oidc stripped untrusted kind claim"
            );
            None
        }
        None => None,
    }
}

/// 从 extra 取字符串型 claim（非字符串 / 缺失 → None，不强转、不 panic）。
fn string_claim(extra: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<String> {
    extra.get(name).and_then(|v| v.as_str()).map(str::to_owned)
}

/// 脱敏失败日志：只记 reason 闭值标签（**不**记 token / claim 值 / payload）。
fn log_fail(reason: &'static str) {
    tracing::warn!(
        target: LOG_TARGET,
        resource = LOG_TARGET,
        reason = reason,
        "oidc jwt claim validation failed"
    );
}

#[cfg(test)]
mod tests {
    //! 私有 helper 单测：`now_unix_secs` / `trusted_kind` / `validate_time_window` 边界覆盖。
    //! item-level `#[allow(clippy::expect_used)]` 按 error-handling.md §Carve-out 标注。

    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::config::{StaticKeySource, VerifierConfigBuilder};

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
    fn minimal_config(trust_kinds: &[&str]) -> VerifierConfig {
        let mut builder = VerifierConfigBuilder::new("https://iss", "aud").keys(
            StaticKeySource::builder()
                .add_es256_sec1(&valid_es256_sec1())
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

    // ── trusted_kind ──────────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn trusted_kind_in_allowlist_returns_some() {
        let config = minimal_config(&["user"]);
        let mut extra = serde_json::Map::new();
        extra.insert(
            "kind".to_string(),
            serde_json::Value::String("user".to_string()),
        );
        let result = trusted_kind(&config, &extra);
        assert_eq!(result, Some("user".to_string()));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn trusted_kind_not_in_allowlist_returns_none() {
        // kind 存在但不在信任集 → 剥离 None。
        let config = minimal_config(&["user"]);
        let mut extra = serde_json::Map::new();
        extra.insert(
            "kind".to_string(),
            serde_json::Value::String("superAdmin".to_string()),
        );
        let result = trusted_kind(&config, &extra);
        assert_eq!(result, None);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn trusted_kind_missing_returns_none() {
        // kind 不在 extra → None。
        let config = minimal_config(&["user"]);
        let extra = serde_json::Map::new();
        let result = trusted_kind(&config, &extra);
        assert_eq!(result, None);
    }

    // ── validate_time_window ──────────────────────────────────────────────────

    /// 构造最小 Claims 用于 validate_time_window。
    fn make_claims(exp: i64, nbf: Option<i64>) -> Claims {
        Claims {
            sub: "alice".to_string(),
            exp,
            nbf,
            iss: "https://iss".to_string(),
            aud: Audience::One("aud".to_string()),
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn validate_time_window_not_expired_ok() {
        // now=1000, exp=2000, leeway=60 → now(1000) > exp+leeway(2060) false → Ok。
        let claims = make_claims(2000, None);
        assert!(validate_time_window(&claims, 1000, 60).is_ok());
    }

    #[test]
    fn validate_time_window_expired_err() {
        // now=2100, exp=2000, leeway=60 → now(2100) > exp+leeway(2060) true → Expired。
        let claims = make_claims(2000, None);
        assert!(matches!(
            validate_time_window(&claims, 2100, 60),
            Err(PdpError::Expired)
        ));
    }

    #[test]
    fn validate_time_window_at_exp_plus_leeway_boundary_ok() {
        // now=2060, exp=2000, leeway=60 → now(2060) > exp+leeway(2060) false（不等）→ Ok。
        let claims = make_claims(2000, None);
        assert!(validate_time_window(&claims, 2060, 60).is_ok());
    }

    #[test]
    fn validate_time_window_nbf_future_beyond_leeway_err() {
        // now=1000, nbf=1100, leeway=60 → now(1000) < nbf-leeway(1040) true → Expired。
        let claims = make_claims(9999, Some(1100));
        assert!(matches!(
            validate_time_window(&claims, 1000, 60),
            Err(PdpError::Expired)
        ));
    }

    #[test]
    fn validate_time_window_nbf_within_leeway_ok() {
        // now=1000, nbf=1050, leeway=60 → now(1000) < nbf-leeway(990) false → Ok。
        let claims = make_claims(9999, Some(1050));
        assert!(validate_time_window(&claims, 1000, 60).is_ok());
    }
}
