//! Closed credential-security event protocol and sealed persistence commands.
//!
//! Event kind is the single source of truth for its executable state transition and stable
//! persistence representation. The account/grant constructors derive tenant and the closed target
//! from validated domain state, so callers cannot author a cross-tenant event or combine an event
//! with an unrelated mutation.
//!
//! INVARIANT: CREDENTIAL-SECURITY-KIND-01 { level = "Hard", exec = "native-compile", source = "code", native = "closed enums and exhaustive derivation" }.
//! INVARIANT: CREDENTIAL-SECURITY-COMMAND-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields and linear commit capability" }.

use std::time::SystemTime;

use ids::UserId;
use vocab::TenantId;

use authn::{
    AccountSecurityEventKind, AuthGrant, AuthGrantCloseMutation, AuthGrantId, AuthGrantStateError,
    CredentialSecurityEventKind, GrantSecurityEventKind,
};

use super::{
    AccountSecurityMutation, AccountSecurityState, AccountSecurityTransitionError, AccountStatus,
};

fn transition_account_security(
    kind: AccountSecurityEventKind,
    state: AccountSecurityState,
    occurred_at: SystemTime,
) -> Result<AccountSecurityMutation, AccountSecurityTransitionError> {
    match kind {
        AccountSecurityEventKind::AccountLocked => {
            state.transition(AccountStatus::Locked, occurred_at)
        }
        AccountSecurityEventKind::AccountSuspended => {
            state.transition(AccountStatus::Suspended, occurred_at)
        }
        AccountSecurityEventKind::AccountDeactivated => {
            state.transition(AccountStatus::Deactivated, occurred_at)
        }
        AccountSecurityEventKind::PasswordChanged
        | AccountSecurityEventKind::PasswordReset
        | AccountSecurityEventKind::LogoutAll
        | AccountSecurityEventKind::CredentialDeleted => state.invalidate(occurred_at),
    }
}

/// Closed target discriminator persisted beside an opaque wire reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialSecurityTargetKind {
    Subject,
    Grant,
}

/// Opaque, non-PII reference used by the active security-event wire contract.
#[derive(Clone, PartialEq, Eq, Hash, secure::Redact)]
pub struct CredentialSecurityTargetRef(#[redact(sensitivity = secret)] uuid::Uuid);

impl CredentialSecurityTargetRef {
    pub(crate) fn generate() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
enum CredentialSecurityTarget {
    Subject {
        user_id: UserId,
    },
    Grant {
        user_id: UserId,
        grant_id: AuthGrantId,
    },
}

impl CredentialSecurityTarget {
    const fn kind(&self) -> CredentialSecurityTargetKind {
        match self {
            Self::Subject { .. } => CredentialSecurityTargetKind::Subject,
            Self::Grant { .. } => CredentialSecurityTargetKind::Grant,
        }
    }

    const fn user_id(&self) -> UserId {
        match self {
            Self::Subject { user_id } | Self::Grant { user_id, .. } => *user_id,
        }
    }

    fn grant_id(&self) -> Option<&AuthGrantId> {
        match self {
            Self::Subject { .. } => None,
            Self::Grant { grant_id, .. } => Some(grant_id),
        }
    }
}

/// Unforgeable event identity derived together with a sealed persistence command.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSecurityEvent {
    kind: CredentialSecurityEventKind,
    tenant: TenantId,
    target: CredentialSecurityTarget,
    occurred_at: SystemTime,
}

impl CredentialSecurityEvent {
    fn from_account(
        state: &AccountSecurityState,
        kind: AccountSecurityEventKind,
        occurred_at: SystemTime,
    ) -> Self {
        Self {
            kind: CredentialSecurityEventKind::Account(kind),
            tenant: state.tenant(),
            target: CredentialSecurityTarget::Subject {
                user_id: state.user_id(),
            },
            occurred_at,
        }
    }

    fn from_grant(
        grant: &AuthGrant,
        kind: GrantSecurityEventKind,
        occurred_at: SystemTime,
    ) -> Self {
        Self {
            kind: CredentialSecurityEventKind::Grant(kind),
            tenant: grant.tenant(),
            target: CredentialSecurityTarget::Grant {
                user_id: grant.user_id(),
                grant_id: grant.id().clone(),
            },
            occurred_at,
        }
    }

    pub fn kind(&self) -> CredentialSecurityEventKind {
        self.kind
    }

    pub fn target_kind(&self) -> CredentialSecurityTargetKind {
        self.target.kind()
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Internal projection subject. The wire event builder deliberately omits this value.
    pub fn user_id(&self) -> UserId {
        self.target.user_id()
    }

    pub fn grant_id(&self) -> Option<&AuthGrantId> {
        self.target.grant_id()
    }

    pub fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }
}

impl std::fmt::Debug for CredentialSecurityEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSecurityEvent")
            .field("kind", &self.kind)
            .field("target_kind", &self.target_kind())
            .field("tenant", &self.tenant)
            .field("target", &"<redacted>")
            .field("occurred_at", &self.occurred_at)
            .finish()
    }
}

/// Account-wide CAS command. Private fields bind the event to its exact mutation.
pub struct AccountCredentialSecurityCommand {
    mutation: AccountSecurityMutation,
    event: CredentialSecurityEvent,
    pending: PendingCredentialSecurityCommit,
}

impl AccountCredentialSecurityCommand {
    pub(crate) fn new(
        state: AccountSecurityState,
        kind: AccountSecurityEventKind,
        occurred_at: SystemTime,
    ) -> Result<Self, AccountSecurityTransitionError> {
        let event = CredentialSecurityEvent::from_account(&state, kind, occurred_at);
        let mutation = transition_account_security(kind, state, occurred_at)?;
        Ok(Self {
            mutation,
            event,
            pending: PendingCredentialSecurityCommit(()),
        })
    }

    pub fn mutation(&self) -> &AccountSecurityMutation {
        &self.mutation
    }

    pub fn event(&self) -> &CredentialSecurityEvent {
        &self.event
    }

    pub fn into_parts(
        self,
    ) -> (
        AccountSecurityMutation,
        CredentialSecurityEvent,
        PendingCredentialSecurityCommit,
    ) {
        (self.mutation, self.event, self.pending)
    }
}

/// Grant-local CAS command. Private fields bind the event to its exact transition.
pub struct GrantCredentialSecurityCommand {
    mutation: AuthGrantCloseMutation,
    event: CredentialSecurityEvent,
    pending: PendingCredentialSecurityCommit,
}

impl GrantCredentialSecurityCommand {
    pub(crate) fn new(
        grant: AuthGrant,
        kind: GrantSecurityEventKind,
        occurred_at: SystemTime,
    ) -> Result<Self, AuthGrantStateError> {
        let event = CredentialSecurityEvent::from_grant(&grant, kind, occurred_at);
        let mutation = grant.close(kind, occurred_at)?;
        Ok(Self {
            mutation,
            event,
            pending: PendingCredentialSecurityCommit(()),
        })
    }

    pub fn mutation(&self) -> &AuthGrantCloseMutation {
        &self.mutation
    }

    pub fn event(&self) -> &CredentialSecurityEvent {
        &self.event
    }

    pub fn into_parts(
        self,
    ) -> (
        AuthGrantCloseMutation,
        CredentialSecurityEvent,
        PendingCredentialSecurityCommit,
    ) {
        (self.mutation, self.event, self.pending)
    }
}

/// Closed command family accepted by the credential-security lifecycle.
pub enum CredentialSecurityCommand {
    Account(AccountCredentialSecurityCommand),
    Grant(GrantCredentialSecurityCommand),
}

/// Sealed logout-current command. Its private inner value is always a grant-local
/// `LogoutCurrent` mutation and cannot be substituted with an account command.
pub struct LogoutCurrentCommand(CredentialSecurityCommand);

/// Sealed logout-all command. Its private inner value is always an account-wide
/// `LogoutAll` mutation and cannot be substituted with a grant command.
pub struct LogoutAllCommand(CredentialSecurityCommand);

impl CredentialSecurityCommand {
    pub(crate) fn logout_all(
        state: AccountSecurityState,
        occurred_at: SystemTime,
    ) -> Result<LogoutAllCommand, AccountSecurityTransitionError> {
        Self::account(state, AccountSecurityEventKind::LogoutAll, occurred_at).map(LogoutAllCommand)
    }

    pub(crate) fn logout_current(
        grant: AuthGrant,
        occurred_at: SystemTime,
    ) -> Result<LogoutCurrentCommand, AuthGrantStateError> {
        Self::grant(grant, GrantSecurityEventKind::LogoutCurrent, occurred_at)
            .map(LogoutCurrentCommand)
    }

    pub(crate) fn account(
        state: AccountSecurityState,
        kind: AccountSecurityEventKind,
        occurred_at: SystemTime,
    ) -> Result<Self, AccountSecurityTransitionError> {
        AccountCredentialSecurityCommand::new(state, kind, occurred_at).map(Self::Account)
    }

    pub(crate) fn grant(
        grant: AuthGrant,
        kind: GrantSecurityEventKind,
        occurred_at: SystemTime,
    ) -> Result<Self, AuthGrantStateError> {
        GrantCredentialSecurityCommand::new(grant, kind, occurred_at).map(Self::Grant)
    }

    pub fn event(&self) -> &CredentialSecurityEvent {
        match self {
            Self::Account(command) => command.event(),
            Self::Grant(command) => command.event(),
        }
    }
}

impl LogoutCurrentCommand {
    pub fn event(&self) -> &CredentialSecurityEvent {
        self.0.event()
    }

    pub fn into_security_command(self) -> CredentialSecurityCommand {
        self.0
    }
}

impl LogoutAllCommand {
    pub fn event(&self) -> &CredentialSecurityEvent {
        self.0.event()
    }

    pub fn into_security_command(self) -> CredentialSecurityCommand {
        self.0
    }
}

const _: fn(
    AccountSecurityState,
    AccountSecurityEventKind,
    SystemTime,
) -> Result<CredentialSecurityCommand, AccountSecurityTransitionError> =
    CredentialSecurityCommand::account;
const _: fn(
    AuthGrant,
    GrantSecurityEventKind,
    SystemTime,
) -> Result<CredentialSecurityCommand, AuthGrantStateError> = CredentialSecurityCommand::grant;

/// Linear proof awaiting provider commit confirmation.
#[must_use]
pub struct PendingCredentialSecurityCommit(());

impl PendingCredentialSecurityCommit {
    /// Mint a success receipt only after the provider confirms the transaction commit.
    pub fn confirm(self) -> CredentialSecurityReceipt {
        CredentialSecurityReceipt(())
    }
}

/// Unforgeable acknowledgement of a committed credential-security transaction.
#[must_use]
pub struct CredentialSecurityReceipt(());

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::{AccountSecuritySnapshot, AccountSecurityVersion};
    use authn::{AuthGrantId, AuthGrantSnapshot, AuthGrantStatus, AuthnEpoch};
    use std::time::Duration;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn tenant() -> TenantId {
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")
    }

    fn user() -> UserId {
        UserId::parse("11111111-2222-4333-8444-555555555555").expect("user")
    }

    #[test]
    fn nine_kinds_round_trip_their_stable_storage_representation() {
        let cases = [
            (
                CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordChanged),
                "password_changed",
            ),
            (
                CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordReset),
                "password_reset",
            ),
            (
                CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountLocked),
                "account_locked",
            ),
            (
                CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountSuspended),
                "account_suspended",
            ),
            (
                CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountDeactivated),
                "account_deactivated",
            ),
            (
                CredentialSecurityEventKind::Account(AccountSecurityEventKind::LogoutAll),
                "logout_all",
            ),
            (
                CredentialSecurityEventKind::Account(AccountSecurityEventKind::CredentialDeleted),
                "credential_deleted",
            ),
            (
                CredentialSecurityEventKind::Grant(GrantSecurityEventKind::LogoutCurrent),
                "logout_current",
            ),
            (
                CredentialSecurityEventKind::Grant(GrantSecurityEventKind::RefreshReuseDetected),
                "refresh_reuse_detected",
            ),
        ];

        for (kind, db) in cases {
            assert_eq!(kind.as_db_str(), db);
            assert_eq!(CredentialSecurityEventKind::from_db_str(db), Some(kind));
        }
        assert_eq!(CredentialSecurityEventKind::from_db_str("unknown"), None);
    }

    #[test]
    fn all_account_kinds_execute_their_only_transition() {
        let cases = [
            (
                AccountSecurityEventKind::PasswordChanged,
                AccountStatus::Active,
                false,
            ),
            (
                AccountSecurityEventKind::PasswordReset,
                AccountStatus::Active,
                false,
            ),
            (
                AccountSecurityEventKind::AccountLocked,
                AccountStatus::Locked,
                true,
            ),
            (
                AccountSecurityEventKind::AccountSuspended,
                AccountStatus::Suspended,
                true,
            ),
            (
                AccountSecurityEventKind::AccountDeactivated,
                AccountStatus::Deactivated,
                true,
            ),
            (
                AccountSecurityEventKind::LogoutAll,
                AccountStatus::Active,
                false,
            ),
            (
                AccountSecurityEventKind::CredentialDeleted,
                AccountStatus::Active,
                false,
            ),
        ];

        for (kind, expected_status, changes_status) in cases {
            let state = AccountSecurityState::try_from(AccountSecuritySnapshot {
                tenant: tenant(),
                user_id: user(),
                status: AccountStatus::Active,
                authn_epoch: AuthnEpoch::ZERO.get(),
                version: AccountSecurityVersion::INITIAL.get(),
                status_changed_at: at(10),
                updated_at: at(10),
            })
            .expect("state");
            let command =
                CredentialSecurityCommand::account(state, kind, at(20)).expect("account command");
            let CredentialSecurityCommand::Account(command) = command else {
                unreachable!()
            };

            assert_eq!(
                command.event().target_kind(),
                CredentialSecurityTargetKind::Subject
            );
            assert_eq!(command.event().tenant(), tenant());
            assert_eq!(command.event().user_id(), user());
            assert!(command.event().grant_id().is_none());
            assert_eq!(command.mutation().next().status(), expected_status);
            assert_eq!(command.mutation().next().authn_epoch().get(), 1);
            assert_eq!(command.mutation().next().version().get(), 2);
            assert_eq!(
                command.mutation().next().status_changed_at(),
                if changes_status { at(20) } else { at(10) }
            );
            assert_eq!(command.mutation().next().updated_at(), at(20));

            let (_mutation, _event, _pending) = command.into_parts();
        }
    }

    fn active_grant() -> AuthGrant {
        AuthGrant::hydrate(AuthGrantSnapshot {
            id: AuthGrantId::hydrate("7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8").expect("grant id"),
            tenant: tenant(),
            user_id: user(),
            auth_time: at(1),
            authn_epoch_at_issue: AuthnEpoch::ZERO,
            status: AuthGrantStatus::Active,
            expires_at: at(100),
            created_at: at(2),
            closed_at: None,
            close_reason: None,
        })
        .expect("active grant")
    }

    #[test]
    fn grant_kinds_execute_only_terminal_transition_and_keep_closed_target() {
        let cases = [
            (
                GrantSecurityEventKind::LogoutCurrent,
                AuthGrantStatus::Revoked,
            ),
            (
                GrantSecurityEventKind::RefreshReuseDetected,
                AuthGrantStatus::Compromised,
            ),
        ];

        for (kind, expected_status) in cases {
            let command = CredentialSecurityCommand::grant(active_grant(), kind, at(20))
                .expect("grant command");
            let CredentialSecurityCommand::Grant(command) = command else {
                unreachable!()
            };

            assert_eq!(
                command.event().target_kind(),
                CredentialSecurityTargetKind::Grant
            );
            assert_eq!(command.event().tenant(), tenant());
            assert_eq!(command.event().user_id(), user());
            assert_eq!(
                command.event().grant_id().map(AuthGrantId::as_str),
                Some("7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8")
            );
            assert_eq!(command.mutation().next().status(), expected_status);
            assert_eq!(command.mutation().next().closed_at(), Some(at(20)));
            assert_eq!(
                command.mutation().next().close_reason(),
                Some(CredentialSecurityEventKind::Grant(kind))
            );

            let (_mutation, _event, _pending) = command.into_parts();
        }
    }
}
