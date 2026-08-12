//! Resource attributes for route ABAC resolution.
//!
//! Resource attributes are tenant-scoped PIP data used by the route authorizer before
//! baseline RBAC fallback. They deliberately only model dynamic `resource.*` keys;
//! synthetic route attributes such as `resource.id` remain owned by the route gate.

use std::time::SystemTime;

use super::{
    AbacAttribute, AttributeKey, AttributeKeyError, IdentityError, POLICY_ATTR_RESOURCE_ID,
    PolicyRouteScope, PolicyValue,
};

const RESOURCE_ATTR_PREFIX: &str = "resource.";

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceAttributeKeyError {
    #[error("resource attribute key is empty")]
    Empty,
    #[error("resource attribute key has invalid format")]
    Format,
    #[error("resource attribute key is reserved")]
    Reserved,
}

/// Dynamic resource attribute key.
///
/// Only `resource.*` keys are accepted, and `resource.id` is reserved for the
/// synthetic route resource id produced by `httpserve`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceAttributeKey(AttributeKey);

impl ResourceAttributeKey {
    pub fn parse(raw: &str) -> Result<Self, ResourceAttributeKeyError> {
        if raw.is_empty() {
            return Err(ResourceAttributeKeyError::Empty);
        }
        let key = AttributeKey::parse(raw).map_err(|err| match err {
            AttributeKeyError::Empty => ResourceAttributeKeyError::Empty,
            AttributeKeyError::Format => ResourceAttributeKeyError::Format,
        })?;
        if !raw.starts_with(RESOURCE_ATTR_PREFIX) || raw == POLICY_ATTR_RESOURCE_ID {
            return Err(ResourceAttributeKeyError::Reserved);
        }
        if raw[RESOURCE_ATTR_PREFIX.len()..].is_empty() {
            return Err(ResourceAttributeKeyError::Format);
        }
        Ok(Self(key))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn as_attribute_key(&self) -> &AttributeKey {
        &self.0
    }
}

/// Classification for policy attribute keys that may refer to route resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourcePolicyAttributeKey {
    SyntheticResourceId,
    Dynamic(ResourceAttributeKey),
    Other,
}

impl ResourcePolicyAttributeKey {
    pub fn classify(key: &AttributeKey) -> Result<Self, ResourceAttributeKeyError> {
        let raw = key.as_str();
        if raw == POLICY_ATTR_RESOURCE_ID {
            return Ok(Self::SyntheticResourceId);
        }
        if !raw.starts_with(RESOURCE_ATTR_PREFIX) {
            return Ok(Self::Other);
        }
        Ok(Self::Dynamic(ResourceAttributeKey::parse(raw)?))
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }

    pub fn into_dynamic(self) -> Option<ResourceAttributeKey> {
        match self {
            Self::Dynamic(key) => Some(key),
            Self::SyntheticResourceId | Self::Other => None,
        }
    }
}

/// Canonical UUID resource id used for resource-attribute lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceAttributeResourceId(String);

impl ResourceAttributeResourceId {
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        let uuid = uuid::Uuid::try_parse(raw).map_err(|_| IdentityError::InvalidPolicy)?;
        if uuid.is_nil() || uuid.hyphenated().to_string() != raw {
            return Err(IdentityError::InvalidPolicy);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceAttributeVersion(u32);

impl ResourceAttributeVersion {
    pub fn new(raw: u32) -> Result<Self, IdentityError> {
        if raw == 0 {
            return Err(IdentityError::InvalidPolicy);
        }
        Ok(Self(raw))
    }

    pub fn first() -> Self {
        Self(1)
    }

    pub fn get(self) -> u32 {
        self.0
    }

    pub fn next_checked(self) -> Result<Self, IdentityError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(IdentityError::VersionConflict)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAttribute {
    tenant: rss_request_context::TenantId,
    route_scope: PolicyRouteScope,
    resource_id: ResourceAttributeResourceId,
    key: ResourceAttributeKey,
    value: PolicyValue,
    version: ResourceAttributeVersion,
    effective_from: SystemTime,
    effective_until: Option<SystemTime>,
}

impl ResourceAttribute {
    #[allow(clippy::too_many_arguments)]
    pub fn hydrate(
        tenant: rss_request_context::TenantId,
        route_scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        key: ResourceAttributeKey,
        value: PolicyValue,
        version: u32,
        effective_from: SystemTime,
        effective_until: Option<SystemTime>,
    ) -> Result<Self, IdentityError> {
        if effective_until.is_some_and(|until| until <= effective_from) {
            return Err(IdentityError::InvalidPolicy);
        }
        Ok(Self {
            tenant,
            route_scope,
            resource_id,
            key,
            value,
            version: ResourceAttributeVersion::new(version)?,
            effective_from,
            effective_until,
        })
    }

    pub fn build(
        tenant: rss_request_context::TenantId,
        route_scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        key: ResourceAttributeKey,
        value: PolicyValue,
        effective_from: SystemTime,
        effective_until: Option<SystemTime>,
    ) -> Result<Self, IdentityError> {
        Self::hydrate(
            tenant,
            route_scope,
            resource_id,
            key,
            value,
            ResourceAttributeVersion::first().get(),
            effective_from,
            effective_until,
        )
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    pub fn route_scope(&self) -> &PolicyRouteScope {
        &self.route_scope
    }

    pub fn resource_id(&self) -> &ResourceAttributeResourceId {
        &self.resource_id
    }

    pub fn key(&self) -> &ResourceAttributeKey {
        &self.key
    }

    pub fn value(&self) -> &PolicyValue {
        &self.value
    }

    pub fn version(&self) -> ResourceAttributeVersion {
        self.version
    }

    pub fn effective_from(&self) -> SystemTime {
        self.effective_from
    }

    pub fn effective_until(&self) -> Option<SystemTime> {
        self.effective_until
    }

    pub fn is_effective_at(&self, at: SystemTime) -> bool {
        self.effective_from <= at && self.effective_until.is_none_or(|until| at < until)
    }

    pub(crate) fn to_abac_attribute(&self) -> AbacAttribute {
        AbacAttribute::new(self.key.as_attribute_key().clone(), self.value.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAttributeResolution {
    Known(Vec<ResourceAttribute>),
    Missing(ResourceAttributeKey),
    Stale(ResourceAttributeKey),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const RESOURCE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn tenant() -> rss_request_context::TenantId {
        #[allow(clippy::expect_used)]
        rss_request_context::TenantId::parse(TENANT).expect("tenant")
    }

    fn scope() -> PolicyRouteScope {
        #[allow(clippy::expect_used)]
        PolicyRouteScope::parse("identity.roles", "identity:role:read").expect("scope")
    }

    #[test]
    fn resource_attribute_key_accepts_only_dynamic_resource_keys() {
        assert!(ResourceAttributeKey::parse("resource.owner").is_ok());
        assert!(matches!(
            ResourceAttributeKey::parse("resource.id"),
            Err(ResourceAttributeKeyError::Reserved)
        ));
        assert!(matches!(
            ResourceAttributeKey::parse("principal.id"),
            Err(ResourceAttributeKeyError::Reserved)
        ));
        assert!(matches!(
            ResourceAttributeKey::parse("resource."),
            Err(ResourceAttributeKeyError::Format)
        ));
    }

    #[test]
    fn resource_policy_attribute_key_classifies_policy_refs() {
        let dynamic = AttributeKey::parse("resource.owner").expect("dynamic key");
        let synthetic = AttributeKey::parse("resource.id").expect("synthetic key");
        let other = AttributeKey::parse("principal.id").expect("other key");
        let malformed_resource = AttributeKey::parse("resource.").expect("malformed resource key");

        assert!(matches!(
            ResourcePolicyAttributeKey::classify(&dynamic),
            Ok(ResourcePolicyAttributeKey::Dynamic(_))
        ));
        assert_eq!(
            ResourcePolicyAttributeKey::classify(&synthetic).expect("synthetic classifies"),
            ResourcePolicyAttributeKey::SyntheticResourceId
        );
        assert_eq!(
            ResourcePolicyAttributeKey::classify(&other).expect("other classifies"),
            ResourcePolicyAttributeKey::Other
        );
        assert!(matches!(
            ResourcePolicyAttributeKey::classify(&malformed_resource),
            Err(ResourceAttributeKeyError::Format)
        ));
    }

    #[test]
    fn resource_attribute_resource_id_requires_canonical_uuid() {
        assert!(ResourceAttributeResourceId::parse(RESOURCE).is_ok());
        assert!(
            ResourceAttributeResourceId::parse("550E8400-E29B-41D4-A716-446655440000").is_err()
        );
        assert!(
            ResourceAttributeResourceId::parse("00000000-0000-0000-0000-000000000000").is_err()
        );
    }

    #[test]
    fn resource_attribute_hydrate_rejects_invalid_version_and_window() {
        let from = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let id = ResourceAttributeResourceId::parse(RESOURCE).expect("resource");
        let key = ResourceAttributeKey::parse("resource.owner").expect("key");
        assert!(matches!(
            ResourceAttribute::hydrate(
                tenant(),
                scope(),
                id.clone(),
                key.clone(),
                PolicyValue::new("owner"),
                0,
                from,
                None,
            ),
            Err(IdentityError::InvalidPolicy)
        ));
        assert!(matches!(
            ResourceAttribute::hydrate(
                tenant(),
                scope(),
                id,
                key,
                PolicyValue::new("owner"),
                1,
                from,
                Some(from),
            ),
            Err(IdentityError::InvalidPolicy)
        ));
    }
}
