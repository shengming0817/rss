//! Server-side authentication grant root and authentication-security vocabulary.
//!
//! An [`AuthGrant`] binds one authenticated user, tenant and authentication epoch to the refresh
//! family created by the same login. State and terminal metadata are validated at construction,
//! and closing an active grant yields a sealed [`AuthGrantCloseMutation`].
//!
//! INVARIANT: AUTH-GRANT-STATE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields plus validated constructors" }.
//! INVARIANT: AUTH-GRANT-CLOSE-MUTATION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields plus transition-only constructor" }.
//! INVARIANT: AUTH-GRANT-ACCESS-ISSUE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private grant-borrowing issue input with a sole AuthGrant producer" }.

use std::time::SystemTime;

use ids::UserId;
use rss_request_context::TenantId;

const MAX_PERSISTED_COUNTER: u64 = i64::MAX as u64;

/// Monotonic authentication epoch shared by account security and issued grants.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthnEpoch(u64);

impl AuthnEpoch {
    /// Initial account epoch.
    pub const ZERO: Self = Self(0);

    /// Rebuild a persisted epoch while preserving the PostgreSQL `BIGINT` boundary.
    pub fn hydrate(value: u64) -> Result<Self, AuthnEpochError> {
        if value > MAX_PERSISTED_COUNTER {
            return Err(AuthnEpochError::OutOfRange);
        }
        Ok(Self(value))
    }

    pub(crate) const fn from_verified(value: u64) -> Self {
        Self(value)
    }

    /// Numeric value for persistence and verified JWT evidence.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance the epoch without crossing the persistence boundary.
    pub fn checked_next(self) -> Result<Self, AuthnEpochError> {
        let next = self.0.checked_add(1).ok_or(AuthnEpochError::Overflow)?;
        if next > MAX_PERSISTED_COUNTER {
            return Err(AuthnEpochError::Overflow);
        }
        Ok(Self(next))
    }
}

impl std::fmt::Debug for AuthnEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthnEpoch(<redacted>)")
    }
}

/// Invalid authentication epoch.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthnEpochError {
    /// A persisted value cannot be represented by the shared signed/SQL boundary.
    #[error("authentication epoch is out of range")]
    OutOfRange,
    /// Advancing the epoch exceeded the shared signed/SQL boundary.
    #[error("authentication epoch overflowed")]
    Overflow,
}

/// Account-wide credential-security causes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountSecurityEventKind {
    PasswordChanged,
    PasswordReset,
    AccountLocked,
    AccountSuspended,
    AccountDeactivated,
    AccountReactivated,
    LogoutAll,
    CredentialDeleted,
}

/// Grant-local credential-security causes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantSecurityEventKind {
    LogoutCurrent,
    RefreshReuseDetected,
}

impl GrantSecurityEventKind {
    const fn terminal_status(self) -> AuthGrantStatus {
        match self {
            Self::LogoutCurrent => AuthGrantStatus::Revoked,
            Self::RefreshReuseDetected => AuthGrantStatus::Compromised,
        }
    }
}

/// The only credential-security cause model used by domain state and persistence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialSecurityEventKind {
    Account(AccountSecurityEventKind),
    Grant(GrantSecurityEventKind),
}

impl CredentialSecurityEventKind {
    /// Stable persistence representation retained by the existing database constraint.
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Account(AccountSecurityEventKind::PasswordChanged) => "password_changed",
            Self::Account(AccountSecurityEventKind::PasswordReset) => "password_reset",
            Self::Account(AccountSecurityEventKind::AccountLocked) => "account_locked",
            Self::Account(AccountSecurityEventKind::AccountSuspended) => "account_suspended",
            Self::Account(AccountSecurityEventKind::AccountDeactivated) => "account_deactivated",
            Self::Account(AccountSecurityEventKind::AccountReactivated) => "account_reactivated",
            Self::Account(AccountSecurityEventKind::LogoutAll) => "logout_all",
            Self::Account(AccountSecurityEventKind::CredentialDeleted) => "credential_deleted",
            Self::Grant(GrantSecurityEventKind::LogoutCurrent) => "logout_current",
            Self::Grant(GrantSecurityEventKind::RefreshReuseDetected) => "refresh_reuse_detected",
        }
    }

    /// Parse the stable persistence representation, rejecting values outside the closed set.
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "password_changed" => Some(Self::Account(AccountSecurityEventKind::PasswordChanged)),
            "password_reset" => Some(Self::Account(AccountSecurityEventKind::PasswordReset)),
            "account_locked" => Some(Self::Account(AccountSecurityEventKind::AccountLocked)),
            "account_suspended" => Some(Self::Account(AccountSecurityEventKind::AccountSuspended)),
            "account_deactivated" => {
                Some(Self::Account(AccountSecurityEventKind::AccountDeactivated))
            }
            "account_reactivated" => {
                Some(Self::Account(AccountSecurityEventKind::AccountReactivated))
            }
            "logout_all" => Some(Self::Account(AccountSecurityEventKind::LogoutAll)),
            "credential_deleted" => {
                Some(Self::Account(AccountSecurityEventKind::CredentialDeleted))
            }
            "logout_current" => Some(Self::Grant(GrantSecurityEventKind::LogoutCurrent)),
            "refresh_reuse_detected" => {
                Some(Self::Grant(GrantSecurityEventKind::RefreshReuseDetected))
            }
            _ => None,
        }
    }
}

/// Stable server-side authentication-grant identifier.
#[derive(Clone, PartialEq, Eq, Hash, secure::Redact)]
pub struct AuthGrantId(#[redact(sensitivity = secret)] ids::CanonicalUuidV4);

impl AuthGrantId {
    fn new(raw: &str) -> Result<Self, AuthGrantIdError> {
        ids::CanonicalUuidV4::parse(raw)
            .map(Self)
            .map_err(|_| AuthGrantIdError::Invalid)
    }

    /// Generate the unique identifier for a newly authenticated grant.
    fn generate() -> Self {
        Self(ids::CanonicalUuidV4::generate())
    }

    /// Rewrap an already-verified canonical UUIDv4 without reopening a text boundary.
    pub fn from_verified(value: ids::CanonicalUuidV4) -> Self {
        Self(value)
    }

    /// Parse a canonical UUIDv4 obtained from persistence or an authenticated wire edge.
    pub fn hydrate(raw: impl AsRef<str>) -> Result<Self, AuthGrantIdError> {
        Self::new(raw.as_ref())
    }

    /// Return the already-verified UUID without reopening the string trust boundary.
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0.as_uuid()
    }

    /// Return the exact validated carrier for trusted in-repository evidence propagation.
    pub fn as_verified(&self) -> ids::CanonicalUuidV4 {
        self.0
    }

    /// Materialize the canonical lowercase-hyphenated persistence/wire representation.
    pub fn to_wire(&self) -> String {
        self.0.to_string()
    }
}

/// Invalid authentication-grant identifier.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthGrantIdError {
    #[error("authentication grant id must be a canonical UUIDv4")]
    Invalid,
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
    #[error("authentication grant tenant does not match the command initiator")]
    TenantMismatch,
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
    close_reason: Option<CredentialSecurityEventKind>,
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
    pub close_reason: Option<CredentialSecurityEventKind>,
}

impl std::fmt::Debug for AuthGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthGrant(<redacted>)")
    }
}

impl AuthGrant {
    /// Create a new active grant from authenticated identity evidence.
    pub fn new_active(
        tenant: TenantId,
        user_id: UserId,
        auth_time: SystemTime,
        authn_epoch_at_issue: AuthnEpoch,
        expires_at: SystemTime,
        created_at: SystemTime,
    ) -> Result<Self, AuthGrantStateError> {
        Self::hydrate(AuthGrantSnapshot {
            id: AuthGrantId::generate(),
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
                Some(CredentialSecurityEventKind::Grant(
                    GrantSecurityEventKind::RefreshReuseDetected,
                )),
            )
            | (
                AuthGrantStatus::Compromised,
                Some(_),
                Some(
                    CredentialSecurityEventKind::Grant(GrantSecurityEventKind::LogoutCurrent)
                    | CredentialSecurityEventKind::Account(_),
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
        reason: GrantSecurityEventKind,
        closed_at: SystemTime,
    ) -> Result<AuthGrantCloseMutation, AuthGrantStateError> {
        let next_status = reason.terminal_status();
        let reason = CredentialSecurityEventKind::Grant(reason);
        let may_close = self.status == AuthGrantStatus::Active
            || (self.status == AuthGrantStatus::Revoked
                && next_status == AuthGrantStatus::Compromised);
        if !may_close {
            return Err(AuthGrantStateError::AlreadyClosed);
        }
        let expected = self.clone();
        let next = Self::hydrate(AuthGrantSnapshot {
            id: self.id,
            tenant: self.tenant,
            user_id: self.user_id,
            auth_time: self.auth_time,
            authn_epoch_at_issue: self.authn_epoch_at_issue,
            status: next_status,
            expires_at: self.expires_at,
            created_at: self.created_at,
            closed_at: Some(closed_at),
            close_reason: Some(reason),
        })?;
        Ok(AuthGrantCloseMutation { expected, next })
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

    pub fn close_reason(&self) -> Option<CredentialSecurityEventKind> {
        self.close_reason
    }

    /// Derive the sole RSS access-token issue input from this grant.
    ///
    /// The returned value borrows the complete grant and has private fields, so callers cannot
    /// substitute a subject, tenant, session id, authentication time, or epoch independently.
    pub fn access_issue_input(&self) -> Result<RssAccessIssueInput<'_>, AuthGrantIssueError> {
        if self.status != AuthGrantStatus::Active {
            return Err(AuthGrantIssueError::NotActive);
        }
        Ok(RssAccessIssueInput { grant: self })
    }

    /// Compare the complete optimistic-concurrency snapshot carried by a sealed mutation.
    ///
    /// Providers use this method before applying `next`; centralizing the comparison prevents
    /// in-memory substitutes from weakening the PostgreSQL CAS predicate when the aggregate grows.
    pub fn matches_snapshot(&self, current: &Self) -> bool {
        self.id == current.id
            && self.tenant == current.tenant
            && self.user_id == current.user_id
            && self.auth_time == current.auth_time
            && self.authn_epoch_at_issue == current.authn_epoch_at_issue
            && self.status == current.status
            && self.expires_at == current.expires_at
            && self.created_at == current.created_at
            && self.closed_at == current.closed_at
            && self.close_reason == current.close_reason
    }
}

/// Grant-derived RSS access issuance capability.
#[must_use]
pub struct RssAccessIssueInput<'a> {
    pub(crate) grant: &'a AuthGrant,
}

impl std::fmt::Debug for RssAccessIssueInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RssAccessIssueInput(<redacted>)")
    }
}

/// An authentication grant cannot currently authorize access-token issuance.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthGrantIssueError {
    #[error("authentication grant is not active")]
    NotActive,
}

/// Sealed terminal transition consumed by the identity lifecycle port.
#[derive(Debug)]
pub struct AuthGrantCloseMutation {
    expected: AuthGrant,
    next: AuthGrant,
}

impl AuthGrantCloseMutation {
    pub fn expected(&self) -> &AuthGrant {
        &self.expected
    }

    pub fn next(&self) -> &AuthGrant {
        &self.next
    }

    pub fn into_parts(self) -> (AuthGrant, AuthGrant) {
        (self.expected, self.next)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountSecurityEventKind, AuthGrant, AuthGrantId, AuthGrantSnapshot, AuthGrantStateError,
        AuthGrantStatus, AuthnEpoch, CredentialSecurityEventKind, GrantSecurityEventKind,
    };
    use std::time::{Duration, SystemTime};

    #[allow(clippy::expect_used)]
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("tenant")
    }

    #[allow(clippy::expect_used)]
    fn user() -> ids::UserId {
        ids::UserId::parse("550e8400-e29b-41d4-a716-446655440000").expect("user")
    }

    #[allow(clippy::expect_used)]
    fn active() -> AuthGrant {
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        AuthGrant::new_active(
            tenant(),
            user(),
            created,
            AuthnEpoch::ZERO,
            created + Duration::from_secs(60),
            created,
        )
        .expect("valid active grant")
    }

    #[allow(clippy::expect_used)]
    fn grant_id() -> AuthGrantId {
        AuthGrantId::hydrate("7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8").expect("grant id")
    }

    fn logout_current() -> CredentialSecurityEventKind {
        CredentialSecurityEventKind::Grant(GrantSecurityEventKind::LogoutCurrent)
    }

    fn refresh_reuse() -> CredentialSecurityEventKind {
        CredentialSecurityEventKind::Grant(GrantSecurityEventKind::RefreshReuseDetected)
    }

    #[test]
    fn generated_ids_are_unique_canonical_uuids() {
        let first = AuthGrantId::generate();
        let second = AuthGrantId::generate();

        assert_ne!(first, second);
        assert_eq!(first.to_wire(), first.as_uuid().hyphenated().to_string());
        assert_eq!(second.to_wire(), second.as_uuid().hyphenated().to_string());
    }

    #[test]
    fn hydration_accepts_only_lowercase_hyphenated_uuid_v4() -> Result<(), super::AuthGrantIdError>
    {
        let canonical = "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8";
        let hydrated = AuthGrantId::hydrate(canonical)?;
        assert_eq!(
            hydrated.as_uuid(),
            uuid::Uuid::from_u128(0x7d65e5f2_e716_4c4e_8e4c_6f7ab1754ef8)
        );
        assert_eq!(hydrated.to_wire(), canonical);
        for rejected in [
            "7D65E5F2-E716-4C4E-8E4C-6F7AB1754EF8",
            "7d65e5f2e7164c4e8e4c6f7ab1754ef8",
            "7d65e5f2-e716-1c4e-8e4c-6f7ab1754ef8",
            "grant-id",
            "",
        ] {
            assert_eq!(
                AuthGrantId::hydrate(rejected),
                Err(super::AuthGrantIdError::Invalid)
            );
        }
        Ok(())
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
                Some(logout_current()),
            ),
        ];

        for (label, auth_time, expires_at, status, closed_at, close_reason) in cases {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: grant_id(),
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
            (None, Some(logout_current())),
            (Some(closed), Some(logout_current())),
        ];
        for (closed_at, close_reason) in active_cases {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: grant_id(),
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
            (AuthGrantStatus::Revoked, None, Some(logout_current())),
            (AuthGrantStatus::Compromised, None, None),
            (AuthGrantStatus::Compromised, Some(closed), None),
            (AuthGrantStatus::Compromised, None, Some(refresh_reuse())),
        ];
        for (status, closed_at, close_reason) in terminal_metadata_missing_cases {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: grant_id(),
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
                id: grant_id(),
                tenant: tenant(),
                user_id: user(),
                auth_time: created,
                authn_epoch_at_issue: AuthnEpoch::ZERO,
                status: AuthGrantStatus::Revoked,
                expires_at: created + Duration::from_secs(60),
                created_at: created,
                closed_at: Some(closed),
                close_reason: Some(refresh_reuse()),
            })
            .expect_err("revoked grant cannot use the refresh-reuse reason"),
            AuthGrantStateError::StatusReasonMismatch
        );

        for reason in [
            logout_current(),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::LogoutAll),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordChanged),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordReset),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountLocked),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountSuspended),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountDeactivated),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountReactivated),
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::CredentialDeleted),
        ] {
            assert_eq!(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: grant_id(),
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
                GrantSecurityEventKind::RefreshReuseDetected,
                SystemTime::UNIX_EPOCH + Duration::from_secs(11),
            )
            .expect("close")
            .into_parts()
            .1;
        assert_eq!(closed.status(), AuthGrantStatus::Compromised);
        assert_eq!(closed.close_reason(), Some(refresh_reuse()));
        assert_eq!(
            closed
                .close(
                    GrantSecurityEventKind::LogoutCurrent,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(12),
                )
                .expect_err("closed grant cannot close twice"),
            AuthGrantStateError::AlreadyClosed
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn refresh_reuse_promotes_revoked_but_never_downgrades_compromised() {
        let revoked = active()
            .close(
                GrantSecurityEventKind::LogoutCurrent,
                SystemTime::UNIX_EPOCH + Duration::from_secs(11),
            )
            .expect("revoke")
            .into_parts()
            .1;
        let compromised = revoked
            .close(
                GrantSecurityEventKind::RefreshReuseDetected,
                SystemTime::UNIX_EPOCH + Duration::from_secs(12),
            )
            .expect("reuse promotes revoked")
            .into_parts()
            .1;

        assert_eq!(compromised.status(), AuthGrantStatus::Compromised);
        assert_eq!(compromised.close_reason(), Some(refresh_reuse()));
        assert_eq!(
            compromised
                .close(
                    GrantSecurityEventKind::LogoutCurrent,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(13),
                )
                .expect_err("compromised state cannot be downgraded"),
            AuthGrantStateError::AlreadyClosed
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn debug_redacts_grant_and_user_ids() {
        let grant = active();
        let id = grant.id().to_wire();
        let debug = format!("{grant:?}");
        assert_eq!(debug, "AuthGrant(<redacted>)");
        assert!(!debug.contains(&id));
        assert!(!format!("{:?}", grant.id()).contains(&id));
        assert_eq!(
            format!("{:?}", grant.authn_epoch_at_issue()),
            "AuthnEpoch(<redacted>)"
        );
        let input = grant.access_issue_input().expect("active grant");
        assert_eq!(format!("{input:?}"), "RssAccessIssueInput(<redacted>)");
    }
}
