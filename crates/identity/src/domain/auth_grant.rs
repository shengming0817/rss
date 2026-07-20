//! Server-side authentication grant root.
//!
//! An [`AuthGrant`] binds one authenticated user, tenant and authentication epoch to the refresh
//! family created by the same login. State and terminal metadata are validated at construction,
//! and closing an active grant yields a sealed [`AuthGrantCloseMutation`].
//!
//! INVARIANT: AUTH-GRANT-STATE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields plus validated constructors" }.
//! INVARIANT: AUTH-GRANT-CLOSE-MUTATION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields plus transition-only constructor" }.

use std::time::SystemTime;

use ids::UserId;
use vocab::TenantId;

use super::AuthnEpoch;

/// Stable server-side authentication-grant identifier.
#[derive(Clone, PartialEq, Eq, Hash, secure::Redact)]
pub struct AuthGrantId(#[redact(sensitivity = secret)] String);

impl AuthGrantId {
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Generate the unique identifier for a newly authenticated grant.
    pub(crate) fn generate() -> Self {
        Self::new(uuid::Uuid::new_v4().to_string())
    }

    /// Rebuild an opaque identifier obtained from a trusted persistence or authenticated wire edge.
    pub fn hydrate(raw: impl Into<String>) -> Self {
        Self::new(raw)
    }

    /// Opaque identifier used by persistence and the existing `sessionId` HTTP/event wire.
    ///
    /// Binding this identifier into the JWT `sid` claim belongs to #1840 and is not part of the
    /// current token contract.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authentication-grant lifecycle status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthGrantStatus {
    Active,
    Revoked,
    Compromised,
}

impl AuthGrantStatus {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Compromised => "compromised",
        }
    }

    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            "compromised" => Some(Self::Compromised),
            _ => None,
        }
    }
}

/// Closed set of reasons that terminate an authentication grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthGrantCloseReason {
    LogoutCurrent,
    LogoutAll,
    PasswordChanged,
    PasswordReset,
    AccountLocked,
    AccountSuspended,
    AccountDeactivated,
    RefreshReuseDetected,
    CredentialDeleted,
}

impl AuthGrantCloseReason {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::LogoutCurrent => "logout_current",
            Self::LogoutAll => "logout_all",
            Self::PasswordChanged => "password_changed",
            Self::PasswordReset => "password_reset",
            Self::AccountLocked => "account_locked",
            Self::AccountSuspended => "account_suspended",
            Self::AccountDeactivated => "account_deactivated",
            Self::RefreshReuseDetected => "refresh_reuse_detected",
            Self::CredentialDeleted => "credential_deleted",
        }
    }

    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "logout_current" => Some(Self::LogoutCurrent),
            "logout_all" => Some(Self::LogoutAll),
            "password_changed" => Some(Self::PasswordChanged),
            "password_reset" => Some(Self::PasswordReset),
            "account_locked" => Some(Self::AccountLocked),
            "account_suspended" => Some(Self::AccountSuspended),
            "account_deactivated" => Some(Self::AccountDeactivated),
            "refresh_reuse_detected" => Some(Self::RefreshReuseDetected),
            "credential_deleted" => Some(Self::CredentialDeleted),
            _ => None,
        }
    }

    fn terminal_status(self) -> AuthGrantStatus {
        if self == Self::RefreshReuseDetected {
            AuthGrantStatus::Compromised
        } else {
            AuthGrantStatus::Revoked
        }
    }
}

/// Invalid persisted or requested authentication-grant state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthGrantStateError {
    #[error("authentication grant timestamps are not ordered")]
    InvalidTimeOrder,
    #[error("active authentication grant has terminal metadata")]
    ActiveHasTerminalMetadata,
    #[error("closed authentication grant lacks terminal metadata")]
    TerminalMetadataMissing,
    #[error("authentication grant status and close reason disagree")]
    StatusReasonMismatch,
    #[error("authentication grant is already closed")]
    AlreadyClosed,
}

/// Durable server-side authentication grant.
#[derive(Clone)]
pub struct AuthGrant {
    id: AuthGrantId,
    tenant: TenantId,
    user_id: UserId,
    auth_time: SystemTime,
    authn_epoch_at_issue: AuthnEpoch,
    status: AuthGrantStatus,
    expires_at: SystemTime,
    created_at: SystemTime,
    closed_at: Option<SystemTime>,
    close_reason: Option<AuthGrantCloseReason>,
}

/// Named persistence boundary for rebuilding an [`AuthGrant`].
///
/// The fields are public so adapters can decode rows without a domain-to-adapter dependency.
/// [`AuthGrant::hydrate`] remains the validating funnel: constructing a snapshot does not
/// construct a grant or bypass any state invariant.
#[derive(Clone)]
pub struct AuthGrantSnapshot {
    pub id: AuthGrantId,
    pub tenant: TenantId,
    pub user_id: UserId,
    pub auth_time: SystemTime,
    pub authn_epoch_at_issue: AuthnEpoch,
    pub status: AuthGrantStatus,
    pub expires_at: SystemTime,
    pub created_at: SystemTime,
    pub closed_at: Option<SystemTime>,
    pub close_reason: Option<AuthGrantCloseReason>,
}

impl std::fmt::Debug for AuthGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthGrant")
            .field("id", &self.id)
            .field("tenant", &self.tenant)
            .field("user_id", &"<redacted>")
            .field("auth_time", &self.auth_time)
            .field("authn_epoch_at_issue", &"<redacted>")
            .field("status", &self.status)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("closed_at", &self.closed_at)
            .field("close_reason", &self.close_reason)
            .finish()
    }
}

impl AuthGrant {
    /// Create a new active grant from authenticated identity evidence.
    pub(crate) fn new_active(
        id: AuthGrantId,
        tenant: TenantId,
        user_id: UserId,
        auth_time: SystemTime,
        authn_epoch_at_issue: AuthnEpoch,
        expires_at: SystemTime,
        created_at: SystemTime,
    ) -> Result<Self, AuthGrantStateError> {
        Self::hydrate(AuthGrantSnapshot {
            id,
            tenant,
            user_id,
            auth_time,
            authn_epoch_at_issue,
            status: AuthGrantStatus::Active,
            expires_at,
            created_at,
            closed_at: None,
            close_reason: None,
        })
    }

    /// Rebuild a persisted grant while revalidating every state invariant.
    pub fn hydrate(snapshot: AuthGrantSnapshot) -> Result<Self, AuthGrantStateError> {
        if snapshot.auth_time > snapshot.created_at || snapshot.created_at >= snapshot.expires_at {
            return Err(AuthGrantStateError::InvalidTimeOrder);
        }
        if snapshot
            .closed_at
            .is_some_and(|closed| closed < snapshot.created_at)
        {
            return Err(AuthGrantStateError::InvalidTimeOrder);
        }
        match (snapshot.status, snapshot.closed_at, snapshot.close_reason) {
            (AuthGrantStatus::Active, None, None) => {}
            (AuthGrantStatus::Active, _, _) => {
                return Err(AuthGrantStateError::ActiveHasTerminalMetadata);
            }
            (_, None, _) | (_, _, None) => {
                return Err(AuthGrantStateError::TerminalMetadataMissing);
            }
            (
                AuthGrantStatus::Revoked,
                Some(_),
                Some(AuthGrantCloseReason::RefreshReuseDetected),
            )
            | (
                AuthGrantStatus::Compromised,
                Some(_),
                Some(
                    AuthGrantCloseReason::LogoutCurrent
                    | AuthGrantCloseReason::LogoutAll
                    | AuthGrantCloseReason::PasswordChanged
                    | AuthGrantCloseReason::PasswordReset
                    | AuthGrantCloseReason::AccountLocked
                    | AuthGrantCloseReason::AccountSuspended
                    | AuthGrantCloseReason::AccountDeactivated
                    | AuthGrantCloseReason::CredentialDeleted,
                ),
            ) => return Err(AuthGrantStateError::StatusReasonMismatch),
            _ => {}
        }
        Ok(Self {
            id: snapshot.id,
            tenant: snapshot.tenant,
            user_id: snapshot.user_id,
            auth_time: snapshot.auth_time,
            authn_epoch_at_issue: snapshot.authn_epoch_at_issue,
            status: snapshot.status,
            expires_at: snapshot.expires_at,
            created_at: snapshot.created_at,
            closed_at: snapshot.closed_at,
            close_reason: snapshot.close_reason,
        })
    }

    /// Close an active grant and return the only mutation accepted by the lifecycle port.
    pub fn close(
        self,
        reason: AuthGrantCloseReason,
        closed_at: SystemTime,
    ) -> Result<AuthGrantCloseMutation, AuthGrantStateError> {
        if self.status != AuthGrantStatus::Active {
            return Err(AuthGrantStateError::AlreadyClosed);
        }
        let next = Self::hydrate(AuthGrantSnapshot {
            id: self.id,
            tenant: self.tenant,
            user_id: self.user_id,
            auth_time: self.auth_time,
            authn_epoch_at_issue: self.authn_epoch_at_issue,
            status: reason.terminal_status(),
            expires_at: self.expires_at,
            created_at: self.created_at,
            closed_at: Some(closed_at),
            close_reason: Some(reason),
        })?;
        Ok(AuthGrantCloseMutation { next })
    }

    pub fn id(&self) -> &AuthGrantId {
        &self.id
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn auth_time(&self) -> SystemTime {
        self.auth_time
    }

    pub fn authn_epoch_at_issue(&self) -> AuthnEpoch {
        self.authn_epoch_at_issue
    }

    pub fn status(&self) -> AuthGrantStatus {
        self.status
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn closed_at(&self) -> Option<SystemTime> {
        self.closed_at
    }

    pub fn close_reason(&self) -> Option<AuthGrantCloseReason> {
        self.close_reason
    }
}

/// Sealed terminal transition consumed by an [`AuthGrantLifecycle`](crate::ports::AuthGrantLifecycle).
#[derive(Debug)]
pub struct AuthGrantCloseMutation {
    next: AuthGrant,
}

impl AuthGrantCloseMutation {
    pub fn next(&self) -> &AuthGrant {
        &self.next
    }

    pub fn into_next(self) -> AuthGrant {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthGrant, AuthGrantCloseReason, AuthGrantId, AuthGrantSnapshot, AuthGrantStateError,
        AuthGrantStatus,
    };
    use crate::domain::AuthnEpoch;
    use std::time::{Duration, SystemTime};

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")
    }

    #[allow(clippy::expect_used)]
    fn user() -> ids::UserId {
        ids::UserId::parse("550e8400-e29b-41d4-a716-446655440000").expect("user")
    }

    #[allow(clippy::expect_used)]
    fn active() -> AuthGrant {
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        AuthGrant::new_active(
            AuthGrantId::new("grant-secret"),
            tenant(),
            user(),
            created,
            AuthnEpoch::ZERO,
            created + Duration::from_secs(60),
            created,
        )
        .expect("valid active grant")
    }

    #[test]
    fn generated_ids_are_unique_canonical_uuids() {
        let first = AuthGrantId::generate();
        let second = AuthGrantId::generate();

        assert_ne!(first, second);
        assert!(uuid::Uuid::parse_str(first.as_str()).is_ok());
        assert!(uuid::Uuid::parse_str(second.as_str()).is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn invalid_time_order_is_rejected() {
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let cases = [
            (
                "auth time after creation",
                created + Duration::from_secs(1),
                created + Duration::from_secs(60),
                AuthGrantStatus::Active,
                None,
                None,
            ),
            (
                "creation at expiry",
                created,
                created,
                AuthGrantStatus::Active,
                None,
                None,
            ),
            (
                "close before creation",
                created,
                created + Duration::from_secs(60),
                AuthGrantStatus::Revoked,
                Some(created - Duration::from_secs(1)),
                Some(AuthGrantCloseReason::LogoutCurrent),
            ),
        ];

        for (label, auth_time, expires_at, status, closed_at, close_reason) in cases {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: AuthGrantId::new("grant-1"),
                    tenant: tenant(),
                    user_id: user(),
                    auth_time,
                    authn_epoch_at_issue: AuthnEpoch::ZERO,
                    status,
                    expires_at,
                    created_at: created,
                    closed_at,
                    close_reason,
                })
                .expect_err(label),
                AuthGrantStateError::InvalidTimeOrder,
                "{label}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn terminal_metadata_matrix_rejects_invalid_states() {
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let closed = created + Duration::from_secs(1);
        let active_cases = [
            (Some(closed), None),
            (None, Some(AuthGrantCloseReason::LogoutCurrent)),
            (Some(closed), Some(AuthGrantCloseReason::LogoutCurrent)),
        ];
        for (closed_at, close_reason) in active_cases {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: AuthGrantId::new("grant-active-invalid"),
                    tenant: tenant(),
                    user_id: user(),
                    auth_time: created,
                    authn_epoch_at_issue: AuthnEpoch::ZERO,
                    status: AuthGrantStatus::Active,
                    expires_at: created + Duration::from_secs(60),
                    created_at: created,
                    closed_at,
                    close_reason,
                })
                .expect_err("active grant with terminal metadata must fail"),
                AuthGrantStateError::ActiveHasTerminalMetadata
            );
        }

        let terminal_metadata_missing_cases = [
            (AuthGrantStatus::Revoked, None, None),
            (AuthGrantStatus::Revoked, Some(closed), None),
            (
                AuthGrantStatus::Revoked,
                None,
                Some(AuthGrantCloseReason::LogoutCurrent),
            ),
            (AuthGrantStatus::Compromised, None, None),
            (AuthGrantStatus::Compromised, Some(closed), None),
            (
                AuthGrantStatus::Compromised,
                None,
                Some(AuthGrantCloseReason::RefreshReuseDetected),
            ),
        ];
        for (status, closed_at, close_reason) in terminal_metadata_missing_cases {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: AuthGrantId::new("grant-terminal-incomplete"),
                    tenant: tenant(),
                    user_id: user(),
                    auth_time: created,
                    authn_epoch_at_issue: AuthnEpoch::ZERO,
                    status,
                    expires_at: created + Duration::from_secs(60),
                    created_at: created,
                    closed_at,
                    close_reason,
                })
                .expect_err("terminal grant without complete metadata must fail"),
                AuthGrantStateError::TerminalMetadataMissing
            );
        }

        assert_eq!(
            AuthGrant::hydrate(AuthGrantSnapshot {
                id: AuthGrantId::new("grant-1"),
                tenant: tenant(),
                user_id: user(),
                auth_time: created,
                authn_epoch_at_issue: AuthnEpoch::ZERO,
                status: AuthGrantStatus::Revoked,
                expires_at: created + Duration::from_secs(60),
                created_at: created,
                closed_at: Some(closed),
                close_reason: Some(AuthGrantCloseReason::RefreshReuseDetected),
            })
            .expect_err("revoked grant cannot use the refresh-reuse reason"),
            AuthGrantStateError::StatusReasonMismatch
        );

        for reason in [
            AuthGrantCloseReason::LogoutCurrent,
            AuthGrantCloseReason::LogoutAll,
            AuthGrantCloseReason::PasswordChanged,
            AuthGrantCloseReason::PasswordReset,
            AuthGrantCloseReason::AccountLocked,
            AuthGrantCloseReason::AccountSuspended,
            AuthGrantCloseReason::AccountDeactivated,
            AuthGrantCloseReason::CredentialDeleted,
        ] {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: AuthGrantId::new("grant-compromised-invalid"),
                    tenant: tenant(),
                    user_id: user(),
                    auth_time: created,
                    authn_epoch_at_issue: AuthnEpoch::ZERO,
                    status: AuthGrantStatus::Compromised,
                    expires_at: created + Duration::from_secs(60),
                    created_at: created,
                    closed_at: Some(closed),
                    close_reason: Some(reason),
                })
                .expect_err("compromised grant requires the refresh-reuse reason"),
                AuthGrantStateError::StatusReasonMismatch,
                "reason={reason:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn close_derives_status_and_seals_second_close() {
        let closed = active()
            .close(
                AuthGrantCloseReason::RefreshReuseDetected,
                SystemTime::UNIX_EPOCH + Duration::from_secs(11),
            )
            .expect("close")
            .into_next();
        assert_eq!(closed.status(), AuthGrantStatus::Compromised);
        assert_eq!(
            closed.close_reason(),
            Some(AuthGrantCloseReason::RefreshReuseDetected)
        );
        assert_eq!(
            closed
                .close(
                    AuthGrantCloseReason::LogoutCurrent,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(12),
                )
                .expect_err("closed grant cannot close twice"),
            AuthGrantStateError::AlreadyClosed
        );
    }

    #[test]
    fn debug_redacts_grant_and_user_ids() {
        let debug = format!("{:?}", active());
        assert!(!debug.contains("grant-secret"));
        assert!(!debug.contains("550e8400-e29b-41d4-a716-446655440000"));
    }
}
