//! Refresh-token family records bound to one [`AuthGrant`](super::AuthGrant).
//!
//! The bearer secret never enters this module. Persistence receives only a SHA-256 digest and a
//! record whose tenant, user, authentication epoch and grant identifier were derived from the
//! grant root. Rotation can only inherit that binding from the source record.
//!
//! INVARIANT: REFRESH-AUTH-GRANT-BINDING-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields plus grant-derived initial constructor and source-derived rotation" }.

use std::time::SystemTime;

use ids::UserId;
use rss_request_context::TenantId;

use authn::{AuthGrant, AuthGrantId, AuthGrantStatus, AuthnEpoch};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefreshTokenId(String);

impl RefreshTokenId {
    pub(crate) fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Rebuild an opaque identifier obtained from trusted persistence.
    pub fn hydrate(raw: impl Into<String>) -> Self {
        Self::new(raw)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RefreshTokenHash([u8; 32]);

impl std::fmt::Debug for RefreshTokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshTokenHash(<redacted>)")
    }
}

impl RefreshTokenHash {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Rebuild a digest obtained from trusted persistence.
    pub fn hydrate(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshStatus {
    Active,
    Consumed,
    Revoked,
}

impl RefreshStatus {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
        }
    }

    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "consumed" => Some(Self::Consumed),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct RefreshTokenRecord {
    id: RefreshTokenId,
    tenant: TenantId,
    auth_grant_id: AuthGrantId,
    user_id: UserId,
    authn_epoch_at_issue: AuthnEpoch,
    auth_grant_status: AuthGrantStatus,
    token_hash: RefreshTokenHash,
    parent_id: Option<RefreshTokenId>,
    lineage_id: RefreshTokenId,
    status: RefreshStatus,
    issued_at: SystemTime,
    expires_at: SystemTime,
}

/// Named persistence boundary for rebuilding a [`RefreshTokenRecord`].
///
/// The snapshot is freely constructible by adapters, but only [`RefreshTokenRecord::hydrate`]
/// can turn it into a domain record after validating time, lineage and AuthGrant-state coupling.
#[derive(Clone)]
pub struct RefreshTokenSnapshot {
    pub id: RefreshTokenId,
    pub tenant: TenantId,
    pub auth_grant_id: AuthGrantId,
    pub user_id: UserId,
    pub authn_epoch_at_issue: AuthnEpoch,
    pub auth_grant_status: AuthGrantStatus,
    pub token_hash: RefreshTokenHash,
    pub parent_id: Option<RefreshTokenId>,
    pub lineage_id: RefreshTokenId,
    pub status: RefreshStatus,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

impl std::fmt::Debug for RefreshTokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenRecord")
            .field("id", &self.id)
            .field("tenant", &self.tenant)
            .field("auth_grant_id", &self.auth_grant_id)
            .field("user_id", &"<redacted>")
            .field("authn_epoch_at_issue", &"<redacted>")
            .field("auth_grant_status", &self.auth_grant_status)
            .field("token_hash", &self.token_hash)
            .field("parent_id", &self.parent_id)
            .field("lineage_id", &self.lineage_id)
            .field("status", &self.status)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl RefreshTokenRecord {
    pub(crate) fn new_initial(
        grant: &AuthGrant,
        id: RefreshTokenId,
        token_hash: RefreshTokenHash,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> Option<Self> {
        if grant.status() != AuthGrantStatus::Active
            || issued_at >= expires_at
            || expires_at > grant.expires_at()
        {
            return None;
        }
        Some(Self {
            lineage_id: id.clone(),
            id,
            tenant: grant.tenant(),
            auth_grant_id: grant.id().clone(),
            user_id: grant.user_id(),
            authn_epoch_at_issue: grant.authn_epoch_at_issue(),
            auth_grant_status: AuthGrantStatus::Active,
            token_hash,
            parent_id: None,
            status: RefreshStatus::Active,
            issued_at,
            expires_at,
        })
    }

    pub fn hydrate(snapshot: RefreshTokenSnapshot) -> Option<Self> {
        if snapshot.issued_at >= snapshot.expires_at
            || (snapshot.parent_id.is_none() && snapshot.lineage_id != snapshot.id)
            || snapshot
                .parent_id
                .as_ref()
                .is_some_and(|parent| parent == &snapshot.id || snapshot.lineage_id == snapshot.id)
            || (snapshot.auth_grant_status != AuthGrantStatus::Active
                && snapshot.status != RefreshStatus::Revoked)
        {
            return None;
        }
        Some(Self {
            id: snapshot.id,
            tenant: snapshot.tenant,
            auth_grant_id: snapshot.auth_grant_id,
            user_id: snapshot.user_id,
            authn_epoch_at_issue: snapshot.authn_epoch_at_issue,
            auth_grant_status: snapshot.auth_grant_status,
            token_hash: snapshot.token_hash,
            parent_id: snapshot.parent_id,
            lineage_id: snapshot.lineage_id,
            status: snapshot.status,
            issued_at: snapshot.issued_at,
            expires_at: snapshot.expires_at,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_status(&self, status: RefreshStatus) -> Self {
        Self {
            status,
            ..self.clone()
        }
    }

    #[cfg(test)]
    pub(crate) fn with_grant_status(&self, auth_grant_status: AuthGrantStatus) -> Self {
        Self {
            auth_grant_status,
            ..self.clone()
        }
    }

    pub fn begin_rotation(
        &self,
        new_id: RefreshTokenId,
        new_hash: RefreshTokenHash,
        issued_at: SystemTime,
    ) -> Option<RefreshRotation> {
        if self.status != RefreshStatus::Active
            || self.auth_grant_status != AuthGrantStatus::Active
            || issued_at >= self.expires_at
        {
            return None;
        }
        let new = Self {
            id: new_id,
            tenant: self.tenant,
            auth_grant_id: self.auth_grant_id.clone(),
            user_id: self.user_id,
            authn_epoch_at_issue: self.authn_epoch_at_issue,
            auth_grant_status: self.auth_grant_status,
            token_hash: new_hash,
            parent_id: Some(self.id.clone()),
            lineage_id: self.lineage_id.clone(),
            status: RefreshStatus::Active,
            issued_at,
            // Refresh rotation is bounded by the original login grant. A family cannot silently
            // turn an absolute AuthGrant lifetime into a sliding lifetime.
            expires_at: self.expires_at,
        };
        Some(RefreshRotation {
            old_id: self.id.clone(),
            new,
        })
    }

    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }

    pub fn id(&self) -> &RefreshTokenId {
        &self.id
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn auth_grant_id(&self) -> &AuthGrantId {
        &self.auth_grant_id
    }

    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn issuance_epoch(&self) -> AuthnEpoch {
        self.authn_epoch_at_issue
    }

    pub fn auth_grant_status(&self) -> AuthGrantStatus {
        self.auth_grant_status
    }

    pub fn token_hash(&self) -> &RefreshTokenHash {
        &self.token_hash
    }

    pub fn parent_id(&self) -> Option<&RefreshTokenId> {
        self.parent_id.as_ref()
    }

    pub fn lineage_id(&self) -> &RefreshTokenId {
        &self.lineage_id
    }

    pub fn status(&self) -> RefreshStatus {
        self.status
    }

    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct RefreshRotation {
    old_id: RefreshTokenId,
    new: RefreshTokenRecord,
}

impl RefreshRotation {
    pub fn old_id(&self) -> &RefreshTokenId {
        &self.old_id
    }

    pub fn new_record(&self) -> &RefreshTokenRecord {
        &self.new
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tenant() -> TenantId {
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")
    }

    fn user() -> UserId {
        UserId::parse("550e8400-e29b-41d4-a716-446655440000").expect("user")
    }

    fn grant() -> AuthGrant {
        AuthGrant::new_active(
            tenant(),
            user(),
            SystemTime::UNIX_EPOCH,
            AuthnEpoch::ZERO,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_600),
            SystemTime::UNIX_EPOCH,
        )
        .expect("grant")
    }

    fn initial() -> RefreshTokenRecord {
        RefreshTokenRecord::new_initial(
            &grant(),
            RefreshTokenId::new("root"),
            RefreshTokenHash::new([7; 32]),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_secs(60),
        )
        .expect("initial")
    }

    #[test]
    fn initial_record_derives_exact_grant_binding() {
        let record = initial();
        assert_eq!(record.tenant(), tenant());
        assert_eq!(
            record.auth_grant_id().as_uuid().get_version(),
            Some(uuid::Version::Random)
        );
        assert_eq!(record.user_id(), user());
        assert_eq!(record.issuance_epoch(), AuthnEpoch::ZERO);
        assert_eq!(record.auth_grant_status(), AuthGrantStatus::Active);
        assert_eq!(record.lineage_id(), record.id());
    }

    #[test]
    fn initial_record_cannot_outlive_its_grant() {
        let grant = grant();
        assert!(
            RefreshTokenRecord::new_initial(
                &grant,
                RefreshTokenId::new("refresh-too-long"),
                RefreshTokenHash::new([8; 32]),
                SystemTime::UNIX_EPOCH,
                grant.expires_at() + Duration::from_secs(1),
            )
            .is_none(),
            "a refresh family cannot outlive its authorization root"
        );
    }

    #[test]
    fn rotation_inherits_exact_grant_binding() {
        let record = initial();
        let rotation = record
            .begin_rotation(
                RefreshTokenId::new("child"),
                RefreshTokenHash::new([9; 32]),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .expect("rotation");
        let child = rotation.new_record();
        assert_eq!(child.tenant(), record.tenant());
        assert_eq!(child.auth_grant_id(), record.auth_grant_id());
        assert_eq!(child.user_id(), record.user_id());
        assert_eq!(child.issuance_epoch(), record.issuance_epoch());
        assert_eq!(child.auth_grant_status(), AuthGrantStatus::Active);
        assert_eq!(
            child.expires_at(),
            record.expires_at(),
            "rotation must preserve the absolute family lifetime"
        );
        assert_eq!(child.parent_id(), Some(record.id()));
        assert_eq!(child.lineage_id(), record.lineage_id());
    }

    #[test]
    fn rotation_cannot_be_prepared_at_the_family_expiry_boundary() {
        let record = initial();
        assert!(
            record
                .begin_rotation(
                    RefreshTokenId::new("child-at-expiry"),
                    RefreshTokenHash::new([7; 32]),
                    record.expires_at(),
                )
                .is_none()
        );
    }

    #[test]
    fn terminal_refresh_cannot_prepare_a_rotation() {
        let record = initial();
        for status in [RefreshStatus::Consumed, RefreshStatus::Revoked] {
            assert!(
                record
                    .with_status(status)
                    .begin_rotation(
                        RefreshTokenId::new(format!("terminal-{status:?}")),
                        RefreshTokenHash::new([6; 32]),
                        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                    )
                    .is_none(),
                "a terminal refresh record must not authorize a child rotation"
            );
        }
    }

    #[test]
    fn debug_redacts_binding_and_hash() {
        let debug = format!("{:?}", initial());
        assert!(!debug.contains("grant-secret"));
        assert!(!debug.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(debug.contains("RefreshTokenHash(<redacted>)"));
    }
}
