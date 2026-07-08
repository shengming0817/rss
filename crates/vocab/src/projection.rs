//! Field-level projection vocabulary shared by route authorization and read-model rendering.
//!
//! The field set is closed and typed. Unknown/future fields must not become public by default.

/// Baseline audit read permission.
pub const AUDIT_READ_PERMISSION: &str = "audit:read";
/// Permission granting cleartext audit actor rendering.
pub const AUDIT_FIELD_ACTOR_PERMISSION: &str = "audit:field:actor";
/// Permission granting cleartext audit tenant id rendering.
pub const AUDIT_FIELD_TENANT_ID_PERMISSION: &str = "audit:field:tenant_id";
/// Permission granting cleartext audit resource id rendering.
pub const AUDIT_FIELD_RESOURCE_ID_PERMISSION: &str = "audit:field:resource_id";
/// Permission granting cleartext identity profile subject rendering.
pub const IDENTITY_PROFILE_FIELD_SUBJECT_PERMISSION: &str = "identity:profile:field:subject";
/// Permission granting cleartext identity profile tenant id rendering.
pub const IDENTITY_PROFILE_FIELD_TENANT_ID_PERMISSION: &str = "identity:profile:field:tenant_id";

/// Durable policy field-mask obligation key for audit actor.
pub const AUDIT_ACTOR_FIELD_OBLIGATION: &str = "audit.actor";
/// Durable policy field-mask obligation key for audit tenant id.
pub const AUDIT_TENANT_ID_FIELD_OBLIGATION: &str = "audit.tenant_id";
/// Durable policy field-mask obligation key for audit resource id.
pub const AUDIT_RESOURCE_ID_FIELD_OBLIGATION: &str = "audit.resource_id";
/// Durable policy field-mask obligation key for identity profile subject.
pub const IDENTITY_PROFILE_SUBJECT_FIELD_OBLIGATION: &str = "identity.profile.subject";
/// Durable policy field-mask obligation key for identity profile tenant id.
pub const IDENTITY_PROFILE_TENANT_ID_FIELD_OBLIGATION: &str = "identity.profile.tenant_id";

/// Closed set of field-level projection targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProjectionField {
    /// `AuditEntryView.actor`.
    AuditActor,
    /// `AuditEntryView.tenantId`.
    AuditTenantId,
    /// `AuditEntryView.resourceId`.
    AuditResourceId,
    /// `IdentityProfileData.subject`.
    IdentityProfileSubject,
    /// `IdentityProfileData.tenantId`.
    IdentityProfileTenantId,
}

impl ProjectionField {
    /// Stable durable-policy obligation key.
    pub fn obligation_key(self) -> &'static str {
        match self {
            ProjectionField::AuditActor => AUDIT_ACTOR_FIELD_OBLIGATION,
            ProjectionField::AuditTenantId => AUDIT_TENANT_ID_FIELD_OBLIGATION,
            ProjectionField::AuditResourceId => AUDIT_RESOURCE_ID_FIELD_OBLIGATION,
            ProjectionField::IdentityProfileSubject => IDENTITY_PROFILE_SUBJECT_FIELD_OBLIGATION,
            ProjectionField::IdentityProfileTenantId => IDENTITY_PROFILE_TENANT_ID_FIELD_OBLIGATION,
        }
    }

    /// Permission required to render this field in cleartext.
    pub fn permission(self) -> &'static str {
        match self {
            ProjectionField::AuditActor => AUDIT_FIELD_ACTOR_PERMISSION,
            ProjectionField::AuditTenantId => AUDIT_FIELD_TENANT_ID_PERMISSION,
            ProjectionField::AuditResourceId => AUDIT_FIELD_RESOURCE_ID_PERMISSION,
            ProjectionField::IdentityProfileSubject => IDENTITY_PROFILE_FIELD_SUBJECT_PERMISSION,
            ProjectionField::IdentityProfileTenantId => IDENTITY_PROFILE_FIELD_TENANT_ID_PERMISSION,
        }
    }

    /// Parse a durable-policy field-mask obligation key into a closed projection field.
    pub fn from_obligation_key(raw: &str) -> Option<Self> {
        match raw {
            AUDIT_ACTOR_FIELD_OBLIGATION => Some(Self::AuditActor),
            AUDIT_TENANT_ID_FIELD_OBLIGATION => Some(Self::AuditTenantId),
            AUDIT_RESOURCE_ID_FIELD_OBLIGATION => Some(Self::AuditResourceId),
            IDENTITY_PROFILE_SUBJECT_FIELD_OBLIGATION => Some(Self::IdentityProfileSubject),
            IDENTITY_PROFILE_TENANT_ID_FIELD_OBLIGATION => Some(Self::IdentityProfileTenantId),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_field_permissions_are_stable() {
        let cases = [
            (
                ProjectionField::AuditActor,
                AUDIT_ACTOR_FIELD_OBLIGATION,
                AUDIT_FIELD_ACTOR_PERMISSION,
            ),
            (
                ProjectionField::AuditTenantId,
                AUDIT_TENANT_ID_FIELD_OBLIGATION,
                AUDIT_FIELD_TENANT_ID_PERMISSION,
            ),
            (
                ProjectionField::AuditResourceId,
                AUDIT_RESOURCE_ID_FIELD_OBLIGATION,
                AUDIT_FIELD_RESOURCE_ID_PERMISSION,
            ),
            (
                ProjectionField::IdentityProfileSubject,
                IDENTITY_PROFILE_SUBJECT_FIELD_OBLIGATION,
                IDENTITY_PROFILE_FIELD_SUBJECT_PERMISSION,
            ),
            (
                ProjectionField::IdentityProfileTenantId,
                IDENTITY_PROFILE_TENANT_ID_FIELD_OBLIGATION,
                IDENTITY_PROFILE_FIELD_TENANT_ID_PERMISSION,
            ),
        ];
        for (field, obligation, permission) in cases {
            assert_eq!(field.obligation_key(), obligation);
            assert_eq!(field.permission(), permission);
            assert_eq!(
                ProjectionField::from_obligation_key(obligation),
                Some(field)
            );
        }
    }

    #[test]
    fn projection_field_rejects_unknown_obligation_key() {
        assert_eq!(ProjectionField::from_obligation_key("audit.*"), None);
        assert_eq!(ProjectionField::from_obligation_key("audit.email"), None);
        assert_eq!(ProjectionField::from_obligation_key(""), None);
    }
}
