//! Bounded group observations. Values alone confer no authentication.
use crate::facts::{FactSource, FactUnavailableReason, valid_max_age, valid_snapshot_window};
use serde::{Deserialize, Serialize};
pub const VERSION: u32 = 1;
pub const MAX_VALUES: usize = 1024;
/// Only available contains values. Unknown states/fields fail deserialization;
/// consumers must also validate the explicit version and metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Groups {
    Available {
        version: u32,
        source: FactSource,
        snapshot_id: uuid::Uuid,
        provider_config_version: i64,
        observed_at: i64,
        expires_at: i64,
        values: Vec<String>,
    },
    Unavailable {
        version: u32,
        reason: FactUnavailableReason,
    },
    Expired {
        version: u32,
    },
}
impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Groups(<redacted>)")
    }
}
impl Groups {
    pub fn unavailable(reason: FactUnavailableReason) -> Self {
        Self::Unavailable {
            version: VERSION,
            reason,
        }
    }
    /// Structural and temporal validation, including an already expired available
    /// response that crossed its deadline in transport. Expiry preserves identity.
    pub fn structurally_valid_at(&self, now: i64) -> bool {
        match self {
            Self::Unavailable { version, .. } | Self::Expired { version } => *version == VERSION,
            Self::Available {
                version,
                source: _,
                snapshot_id,
                provider_config_version,
                observed_at,
                expires_at,
                values,
            } => {
                *version == VERSION
                    && !snapshot_id.is_nil()
                    && *provider_config_version > 0
                    && now > 0
                    && valid_snapshot_window(*observed_at, *expires_at)
                    && canonical_values(values)
            }
        }
    }
}
pub fn bounded_values(values: &[String]) -> bool {
    values.len() <= MAX_VALUES
        && values
            .iter()
            .all(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
}
pub fn canonical_values(values: &[String]) -> bool {
    bounded_values(values) && values.windows(2).all(|v| v[0] < v[1])
}

use crate::federation::FederationError;

/// Deployment policy. There is deliberately no implicit default constructor.
#[derive(Clone, Copy)]
pub struct GroupFactsMaxAge(i64);
impl GroupFactsMaxAge {
    pub fn new(seconds: i64) -> Result<Self, FederationError> {
        if !valid_max_age(seconds) {
            return Err(FederationError::Configuration);
        }
        Ok(Self(seconds))
    }
    /// Only signed iat/exp determine the fixed deadline. An already stale observation
    /// is valid authentication input, but cannot yield available groups.
    pub fn expires_at(
        self,
        issued_at: i64,
        expires_at: i64,
        now: i64,
        future_skew_seconds: u32,
    ) -> Result<i64, FederationError> {
        crate::facts::expires_at(self.0, issued_at, expires_at, now, future_skew_seconds)
    }
}

/// Exact claim presence; an absent claim never proves an empty membership set.
#[derive(Clone, PartialEq, Eq)]
pub enum UpstreamGroups {
    NotConfigured,
    Missing,
    Present(Vec<String>),
}
impl UpstreamGroups {
    pub fn present(mut values: Vec<String>) -> Result<Self, FederationError> {
        if !bounded_values(&values) {
            return Err(FederationError::Claims);
        }
        values.sort();
        values.dedup();
        Ok(Self::Present(values))
    }
    pub fn values(&self) -> Option<&[String]> {
        match self {
            Self::Present(values) => Some(values),
            Self::NotConfigured | Self::Missing => None,
        }
    }
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.values().is_some_and(|v| !canonical_values(v)) {
            return Err(FederationError::Claims);
        }
        Ok(())
    }
}
