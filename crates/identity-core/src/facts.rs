//! Shared source and observation semantics for authentication facts, not authentication proofs.
use crate::{ValidationError, federation::FederationError};
use serde::{Deserialize, Serialize};

/// Structural lifetime range; deployment freshness is selected at issuance.
pub fn valid_max_age(seconds: i64) -> bool {
    seconds > 0
}
pub fn valid_snapshot_window(observed_at: i64, expires_at: i64) -> bool {
    observed_at > 0
        && expires_at
            .checked_sub(observed_at)
            .is_some_and(valid_max_age)
}
pub fn acceptable_observation(observed_at: i64, now: i64, future_skew_seconds: u32) -> bool {
    observed_at > 0
        && now > 0
        && observed_at
            .checked_sub(now)
            .is_some_and(|ahead| ahead <= i64::from(future_skew_seconds))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactUnavailableReason {
    LocalIdentity,
    NotConfigured,
    ClaimMissing,
    NotYetValid,
}

/// A structurally valid observation source. Only a component-issued session can
/// attest that this metadata describes verified authentication.
/// ```compile_fail
/// let source = rss_identity_core::facts::FactSource {
///     provider_id: uuid::Uuid::nil(), issuer: "https://idp.test".into(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FactSourceInput")]
pub struct FactSource {
    provider_id: uuid::Uuid,
    issuer: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FactSourceInput {
    provider_id: uuid::Uuid,
    issuer: String,
}
impl FactSource {
    pub fn new(provider_id: uuid::Uuid, issuer: String) -> Result<Self, ValidationError> {
        if provider_id.is_nil() || !valid_issuer(&issuer) {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self {
            provider_id,
            issuer,
        })
    }
    pub fn provider_id(&self) -> uuid::Uuid {
        self.provider_id
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}
impl TryFrom<FactSourceInput> for FactSource {
    type Error = ValidationError;
    fn try_from(input: FactSourceInput) -> Result<Self, Self::Error> {
        Self::new(input.provider_id, input.issuer)
    }
}

fn valid_issuer(value: &str) -> bool {
    value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && url::Url::parse(value).is_ok_and(|u| {
            matches!(u.scheme(), "https" | "http")
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        })
}
pub(crate) fn expires_at(
    max_age: i64,
    issued_at: i64,
    expires_at: i64,
    now: i64,
    future_skew_seconds: u32,
) -> Result<i64, FederationError> {
    if !acceptable_observation(issued_at, now, future_skew_seconds)
        || expires_at <= issued_at
        || expires_at <= now
    {
        return Err(FederationError::Claims);
    }
    Ok(issued_at
        .checked_add(max_age)
        .ok_or(FederationError::Claims)?
        .min(expires_at))
}
