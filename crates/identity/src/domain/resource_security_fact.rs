//! Closed, typed Resource Security Fact projection consumed by device authorization.
//!
//! The source and authoring lifecycle remain external. RSS stores only tenant/device-bound,
//! append-only revisions and deliberately exposes no domain mutation service.

use std::time::SystemTime;

use super::{AbacAttribute, AttributeKey, IdentityError, PolicyValue};

pub const RESOURCE_OWNER_KEY: &str = "resource.owner";
pub const RESOURCE_RISK_CLASS_KEY: &str = "resource.riskClass";
const FACT_TEXT_MAX_BYTES: usize = 256;

/// Exact External fact keys accepted by the device projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceSecurityFactKey {
    Owner,
    RiskClass,
}

/// Classification used to reject every non-synthetic `resource.*` policy key before #2115.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceSecurityFactPolicyKey {
    SyntheticResourceId,
    Fact(ResourceSecurityFactKey),
    Other,
}

impl ResourceSecurityFactPolicyKey {
    pub fn classify(key: &AttributeKey) -> Result<Self, ResourceSecurityFactError> {
        let raw = key.as_str();
        if raw == super::POLICY_ATTR_RESOURCE_ID {
            return Ok(Self::SyntheticResourceId);
        }
        if !raw.starts_with("resource.") {
            return Ok(Self::Other);
        }
        ResourceSecurityFactKey::parse(raw).map(Self::Fact)
    }

    pub const fn into_fact(self) -> Option<ResourceSecurityFactKey> {
        match self {
            Self::Fact(key) => Some(key),
            Self::SyntheticResourceId | Self::Other => None,
        }
    }
}

impl ResourceSecurityFactKey {
    /// Parse one of the two exact persisted key strings.
    pub fn parse(raw: &str) -> Result<Self, ResourceSecurityFactError> {
        match raw {
            RESOURCE_OWNER_KEY => Ok(Self::Owner),
            RESOURCE_RISK_CLASS_KEY => Ok(Self::RiskClass),
            _ => Err(ResourceSecurityFactError::UnknownKey),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => RESOURCE_OWNER_KEY,
            Self::RiskClass => RESOURCE_RISK_CLASS_KEY,
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceSecurityFactError {
    #[error("resource security fact key is not supported")]
    UnknownKey,
    #[error("resource security fact principal id is invalid")]
    InvalidPrincipalId,
    #[error("resource security fact source id is invalid")]
    InvalidSourceId,
    #[error("resource security fact risk class is invalid")]
    InvalidRiskClass,
    #[error("resource security fact device id is invalid")]
    InvalidDevice,
    #[error("resource security fact revision is invalid")]
    InvalidRevision,
    #[error("resource security fact freshness window is invalid")]
    InvalidFreshness,
}

fn valid_fact_text(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > FACT_TEXT_MAX_BYTES || raw.chars().any(char::is_control) {
        return false;
    }
    true
}

/// Opaque owner principal coordinate; Debug output is always redacted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ResourceFactPrincipalId(String);

impl ResourceFactPrincipalId {
    /// Parse a non-empty, control-free value of at most 256 UTF-8 bytes.
    pub fn parse(raw: &str) -> Result<Self, ResourceSecurityFactError> {
        if !valid_fact_text(raw) {
            return Err(ResourceSecurityFactError::InvalidPrincipalId);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ResourceFactPrincipalId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResourceFactPrincipalId(<redacted>)")
    }
}

/// Opaque External authority coordinate; Debug output is always redacted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ResourceFactSourceId(String);

impl ResourceFactSourceId {
    /// Parse a non-empty, control-free value of at most 256 UTF-8 bytes.
    pub fn parse(raw: &str) -> Result<Self, ResourceSecurityFactError> {
        if !valid_fact_text(raw) {
            return Err(ResourceSecurityFactError::InvalidSourceId);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ResourceFactSourceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResourceFactSourceId(<redacted>)")
    }
}

/// Closed device risk vocabulary supplied by the External authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceRiskClass {
    Normal,
    Restricted,
    Quarantined,
}

impl ResourceRiskClass {
    /// Parse `normal`, `restricted`, or `quarantined` exactly.
    pub fn parse(raw: &str) -> Result<Self, ResourceSecurityFactError> {
        match raw {
            "normal" => Ok(Self::Normal),
            "restricted" => Ok(Self::Restricted),
            "quarantined" => Ok(Self::Quarantined),
            _ => Err(ResourceSecurityFactError::InvalidRiskClass),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Restricted => "restricted",
            Self::Quarantined => "quarantined",
        }
    }
}

/// Keyed fact value; the enum variant uniquely derives the persisted key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceSecurityFactValue {
    Owner(ResourceFactPrincipalId),
    RiskClass(ResourceRiskClass),
}

impl ResourceSecurityFactValue {
    pub const fn key(&self) -> ResourceSecurityFactKey {
        match self {
            Self::Owner(_) => ResourceSecurityFactKey::Owner,
            Self::RiskClass(_) => ResourceSecurityFactKey::RiskClass,
        }
    }

    fn to_policy_value(&self) -> Result<PolicyValue, IdentityError> {
        match self {
            Self::Owner(principal) => PolicyValue::string(principal.as_str()),
            Self::RiskClass(class) => PolicyValue::string(class.as_str()),
        }
        .map_err(|_| IdentityError::InvalidPolicy)
    }
}

/// Positive, monotonically increasing External revision coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceSecurityFactRevision(u64);

impl ResourceSecurityFactRevision {
    /// Construct a non-zero revision.
    pub fn new(raw: u64) -> Result<Self, ResourceSecurityFactError> {
        if raw == 0 {
            return Err(ResourceSecurityFactError::InvalidRevision);
        }
        Ok(Self(raw))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One tenant/device-bound accepted revision with a mandatory freshness window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSecurityFact {
    tenant: rss_request_context::TenantId,
    device: ids::DeviceId,
    source: ResourceFactSourceId,
    value: ResourceSecurityFactValue,
    revision: ResourceSecurityFactRevision,
    observed_at: SystemTime,
    expires_at: SystemTime,
}

impl ResourceSecurityFact {
    /// Rebuild a validated revision; device must be non-nil and `observed_at < expires_at`.
    #[allow(clippy::too_many_arguments)]
    pub fn hydrate(
        tenant: rss_request_context::TenantId,
        device: ids::DeviceId,
        source: ResourceFactSourceId,
        value: ResourceSecurityFactValue,
        revision: u64,
        observed_at: SystemTime,
        expires_at: SystemTime,
    ) -> Result<Self, ResourceSecurityFactError> {
        if device.as_uuid().is_nil() {
            return Err(ResourceSecurityFactError::InvalidDevice);
        }
        if observed_at >= expires_at {
            return Err(ResourceSecurityFactError::InvalidFreshness);
        }
        Ok(Self {
            tenant,
            device,
            source,
            value,
            revision: ResourceSecurityFactRevision::new(revision)?,
            observed_at,
            expires_at,
        })
    }

    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    pub const fn device(&self) -> ids::DeviceId {
        self.device
    }

    pub fn source(&self) -> &ResourceFactSourceId {
        &self.source
    }

    pub const fn key(&self) -> ResourceSecurityFactKey {
        self.value.key()
    }

    pub fn value(&self) -> &ResourceSecurityFactValue {
        &self.value
    }

    pub const fn revision(&self) -> ResourceSecurityFactRevision {
        self.revision
    }

    pub const fn observed_at(&self) -> SystemTime {
        self.observed_at
    }

    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Return true exactly within `[observed_at, expires_at)`.
    pub fn is_fresh_at(&self, at: SystemTime) -> bool {
        self.observed_at <= at && at < self.expires_at
    }

    pub(crate) fn to_abac_attribute(&self) -> Result<AbacAttribute, IdentityError> {
        Ok(AbacAttribute::new(
            AttributeKey::new(self.key().as_str()),
            self.value.to_policy_value()?,
        ))
    }
}

/// Latest-revision lookup result; `Stale` never permits fallback to an older revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceSecurityFactResolution {
    Known(Vec<ResourceSecurityFact>),
    Missing(ResourceSecurityFactKey),
    Stale(ResourceSecurityFactKey),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn resource_security_fact_keys_are_an_exact_closed_set() {
        assert_eq!(
            ResourceSecurityFactKey::parse(RESOURCE_OWNER_KEY),
            Ok(ResourceSecurityFactKey::Owner)
        );
        assert_eq!(
            ResourceSecurityFactKey::parse(RESOURCE_RISK_CLASS_KEY),
            Ok(ResourceSecurityFactKey::RiskClass)
        );
        for rejected in [
            "resource.id",
            "resource.location",
            "resource.software",
            "resource.inventory.kind",
            "resource.fleet",
            "resource.owner.custom",
        ] {
            assert_eq!(
                ResourceSecurityFactKey::parse(rejected),
                Err(ResourceSecurityFactError::UnknownKey)
            );
        }
    }

    #[test]
    fn resource_security_fact_value_is_keyed_and_text_is_bounded() {
        let owner = ResourceSecurityFactValue::Owner(
            ResourceFactPrincipalId::parse("principal-1").expect("principal"),
        );
        let risk = ResourceSecurityFactValue::RiskClass(ResourceRiskClass::Quarantined);
        assert_eq!(owner.key(), ResourceSecurityFactKey::Owner);
        assert_eq!(risk.key(), ResourceSecurityFactKey::RiskClass);
        assert!(ResourceFactSourceId::parse("").is_err());
        assert!(ResourceFactSourceId::parse("bad\nsource").is_err());
        assert!(ResourceFactPrincipalId::parse(&"a".repeat(257)).is_err());
    }

    #[test]
    fn resource_security_fact_revision_and_freshness_are_fail_closed() {
        assert!(ResourceSecurityFactRevision::new(0).is_err());
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("tenant");
        let device = ids::DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device");
        let source = ResourceFactSourceId::parse("external-control-plane").expect("source");
        let observed = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let expires = observed + Duration::from_secs(10);
        let fact = ResourceSecurityFact::hydrate(
            tenant,
            device,
            source,
            ResourceSecurityFactValue::RiskClass(ResourceRiskClass::Normal),
            1,
            observed,
            expires,
        )
        .expect("fact");
        assert!(!fact.is_fresh_at(observed - Duration::from_secs(1)));
        assert!(fact.is_fresh_at(observed));
        assert!(!fact.is_fresh_at(expires));
    }
}
