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
use rss_request_context::TenantId;

use authn::{
    AccountSecurityEventKind, AuthGrant, AuthGrantCloseMutation, AuthGrantId, AuthGrantStateError,
    CredentialSecurityEventKind, GrantSecurityEventKind,
};

use super::{
    AccountSecurityMutation, AccountSecurityState, AccountSecurityTransitionError, AccountStatus,
    Credential, RefreshTokenRecord,
};

const REFRESH_REUSE_DETECTOR_SUBJECT: &str = "identity.refresh-reuse-detector";

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
        AccountSecurityEventKind::AccountReactivated => {
            state.transition(AccountStatus::Active, occurred_at)
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

/// Opaque, keyed reference used by the active security-event wire contract.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialSecurityTargetRef(secure::PseudonymRef);

impl CredentialSecurityTargetRef {
    fn for_target(
        keys: &secure::PseudonymKeyRing,
        tenant: TenantId,
        target: &CredentialSecurityTarget,
    ) -> Result<Self, secure::PseudonymError> {
        match target {
            CredentialSecurityTarget::Subject { user_id } => keys
                .current(
                    tenant,
                    "identity.security-event/target/subject",
                    user_id.as_uuid().as_bytes(),
                )
                .map(Self),
            CredentialSecurityTarget::Grant { grant_id, .. } => keys
                .current(
                    tenant,
                    "identity.security-event/target/grant",
                    grant_id.as_uuid().as_bytes(),
                )
                .map(Self),
        }
    }

    pub fn as_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.0.as_bytes())
    }

    pub const fn key_id(&self) -> secure::PseudonymKeyId {
        self.0.key_id()
    }
}

impl std::fmt::Debug for CredentialSecurityTargetRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialSecurityTargetRef")
            .field("key_id", &self.key_id())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Authenticated or system initiator sealed into the security command before persistence.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSecurityInitiator {
    tenant: TenantId,
    kind: rss_request_context::PrincipalKind,
    subject: String,
}

impl CredentialSecurityInitiator {
    pub(crate) fn authenticated(
        tenant: TenantId,
        kind: rss_request_context::PrincipalKind,
        subject: impl Into<String>,
    ) -> Self {
        Self {
            tenant,
            kind,
            subject: subject.into(),
        }
    }

    pub(crate) fn refresh_reuse_detector(tenant: TenantId) -> Self {
        Self {
            tenant,
            kind: rss_request_context::PrincipalKind::Service,
            subject: REFRESH_REUSE_DETECTOR_SUBJECT.to_owned(),
        }
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn kind(&self) -> rss_request_context::PrincipalKind {
        self.kind
    }

    /// Tenant-scoped stable pseudonym used by durable metadata and event consumers.
    ///
    /// The authenticated subject is deliberately never exposed by this domain object.
    pub fn privacy_ref(
        &self,
        keys: &secure::PseudonymKeyRing,
    ) -> Result<secure::PseudonymRef, secure::PseudonymError> {
        let domain = match self.kind {
            rss_request_context::PrincipalKind::User => "identity.security-event/actor/user",
            rss_request_context::PrincipalKind::Device => "identity.security-event/actor/device",
            rss_request_context::PrincipalKind::Admin => "identity.security-event/actor/admin",
            rss_request_context::PrincipalKind::SuperAdmin => {
                "identity.security-event/actor/super-admin"
            }
            rss_request_context::PrincipalKind::Service => "identity.security-event/actor/service",
            rss_request_context::PrincipalKind::Anonymous => {
                "identity.security-event/actor/anonymous"
            }
        };
        keys.current(self.tenant, domain, self.subject.as_bytes())
    }
}

impl std::fmt::Debug for CredentialSecurityInitiator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialSecurityInitiator")
            .field("tenant", &self.tenant)
            .field("kind", &self.kind)
            .field("subject", &"<redacted>")
            .finish()
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
    initiator: CredentialSecurityInitiator,
    occurred_at: SystemTime,
}

impl CredentialSecurityEvent {
    fn from_account(
        state: &AccountSecurityState,
        kind: AccountSecurityEventKind,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Self {
        Self {
            kind: CredentialSecurityEventKind::Account(kind),
            tenant: state.tenant(),
            target: CredentialSecurityTarget::Subject {
                user_id: state.user_id(),
            },
            initiator,
            occurred_at,
        }
    }

    fn from_grant(
        grant: &AuthGrant,
        kind: GrantSecurityEventKind,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Self {
        Self {
            kind: CredentialSecurityEventKind::Grant(kind),
            tenant: grant.tenant(),
            target: CredentialSecurityTarget::Grant {
                user_id: grant.user_id(),
                grant_id: grant.id().clone(),
            },
            initiator,
            occurred_at,
        }
    }

    pub(crate) fn from_refresh_reuse(record: &RefreshTokenRecord, occurred_at: SystemTime) -> Self {
        Self {
            kind: CredentialSecurityEventKind::Grant(GrantSecurityEventKind::RefreshReuseDetected),
            tenant: record.tenant(),
            target: CredentialSecurityTarget::Grant {
                user_id: record.user_id(),
                grant_id: record.auth_grant_id().clone(),
            },
            initiator: CredentialSecurityInitiator::refresh_reuse_detector(record.tenant()),
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

    pub fn target_ref(
        &self,
        keys: &secure::PseudonymKeyRing,
    ) -> Result<CredentialSecurityTargetRef, secure::PseudonymError> {
        CredentialSecurityTargetRef::for_target(keys, self.tenant, &self.target)
    }

    pub fn initiator(&self) -> &CredentialSecurityInitiator {
        &self.initiator
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
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<Self, AccountSecurityTransitionError> {
        if initiator.tenant() != state.tenant() {
            return Err(AccountSecurityTransitionError::Illegal);
        }
        let event = CredentialSecurityEvent::from_account(&state, kind, initiator, occurred_at);
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
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<Self, AuthGrantStateError> {
        if initiator.tenant() != grant.tenant() {
            return Err(AuthGrantStateError::TenantMismatch);
        }
        let event = CredentialSecurityEvent::from_grant(&grant, kind, initiator, occurred_at);
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

/// Credential CAS bound to the exact account-wide PasswordChanged mutation.
pub struct PasswordChangeCommand {
    expected_credential: Credential,
    next_credential: Credential,
    security: AccountCredentialSecurityCommand,
}

/// Sealed desired account-status command.
pub struct AccountStatusSetCommand(CredentialSecurityCommand);

/// Sealed no-event reactivation mutation.
pub struct ReactivateAccountCommand(AccountSecurityMutation);

/// Password-change command construction failed before persistence.
#[derive(Debug, thiserror::Error)]
pub enum PasswordChangeCommandError {
    #[error("credential and account security state do not match")]
    IdentityMismatch,
    #[error("account is not active")]
    AccountInactive,
    #[error("password rotation failed")]
    Password(#[source] secure::PasswordError),
    #[error("account invalidation failed")]
    Account(#[source] AccountSecurityTransitionError),
}

impl CredentialSecurityCommand {
    pub(crate) fn logout_all(
        state: AccountSecurityState,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<LogoutAllCommand, AccountSecurityTransitionError> {
        Self::account(
            state,
            AccountSecurityEventKind::LogoutAll,
            initiator,
            occurred_at,
        )
        .map(LogoutAllCommand)
    }

    pub(crate) fn logout_current(
        grant: AuthGrant,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<LogoutCurrentCommand, AuthGrantStateError> {
        Self::grant(
            grant,
            GrantSecurityEventKind::LogoutCurrent,
            initiator,
            occurred_at,
        )
        .map(LogoutCurrentCommand)
    }

    pub(crate) fn account(
        state: AccountSecurityState,
        kind: AccountSecurityEventKind,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<Self, AccountSecurityTransitionError> {
        AccountCredentialSecurityCommand::new(state, kind, initiator, occurred_at)
            .map(Self::Account)
    }

    pub(crate) fn grant(
        grant: AuthGrant,
        kind: GrantSecurityEventKind,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<Self, AuthGrantStateError> {
        GrantCredentialSecurityCommand::new(grant, kind, initiator, occurred_at).map(Self::Grant)
    }

    pub fn event(&self) -> &CredentialSecurityEvent {
        match self {
            Self::Account(command) => command.event(),
            Self::Grant(command) => command.event(),
        }
    }
}

impl PasswordChangeCommand {
    pub(crate) fn new(
        credential: Credential,
        account: AccountSecurityState,
        password: secure::ValidatedPassword,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<Self, PasswordChangeCommandError> {
        if credential.tenant() != account.tenant() || credential.user_id() != account.user_id() {
            return Err(PasswordChangeCommandError::IdentityMismatch);
        }
        if account.status() != AccountStatus::Active {
            return Err(PasswordChangeCommandError::AccountInactive);
        }
        let next_credential = credential
            .rotate(password)
            .map_err(PasswordChangeCommandError::Password)?;
        let security = AccountCredentialSecurityCommand::new(
            account,
            AccountSecurityEventKind::PasswordChanged,
            initiator,
            occurred_at,
        )
        .map_err(PasswordChangeCommandError::Account)?;
        Ok(Self {
            expected_credential: credential,
            next_credential,
            security,
        })
    }

    pub fn event(&self) -> &CredentialSecurityEvent {
        self.security.event()
    }

    pub fn into_parts(self) -> (Credential, Credential, AccountCredentialSecurityCommand) {
        (
            self.expected_credential,
            self.next_credential,
            self.security,
        )
    }
}

impl AccountStatusSetCommand {
    pub(crate) fn new(
        state: AccountSecurityState,
        target: AccountStatus,
        initiator: CredentialSecurityInitiator,
        occurred_at: SystemTime,
    ) -> Result<Self, AccountSecurityTransitionError> {
        let kind = match target {
            AccountStatus::Suspended => AccountSecurityEventKind::AccountSuspended,
            AccountStatus::Locked => AccountSecurityEventKind::AccountLocked,
            AccountStatus::Deactivated => AccountSecurityEventKind::AccountDeactivated,
            AccountStatus::Active => AccountSecurityEventKind::AccountReactivated,
        };
        CredentialSecurityCommand::account(state, kind, initiator, occurred_at).map(Self)
    }

    pub fn event(&self) -> &CredentialSecurityEvent {
        self.0.event()
    }

    pub fn into_security_command(self) -> CredentialSecurityCommand {
        self.0
    }
}

impl ReactivateAccountCommand {
    pub(crate) fn new(
        state: AccountSecurityState,
        occurred_at: SystemTime,
    ) -> Result<Self, AccountSecurityTransitionError> {
        state
            .transition(AccountStatus::Active, occurred_at)
            .map(Self)
    }

    pub fn mutation(&self) -> &AccountSecurityMutation {
        &self.0
    }

    pub fn into_mutation(self) -> AccountSecurityMutation {
        self.0
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
    CredentialSecurityInitiator,
    SystemTime,
) -> Result<CredentialSecurityCommand, AccountSecurityTransitionError> =
    CredentialSecurityCommand::account;
const _: fn(
    AuthGrant,
    GrantSecurityEventKind,
    CredentialSecurityInitiator,
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
            let command = CredentialSecurityCommand::account(
                state,
                kind,
                CredentialSecurityInitiator::authenticated(
                    tenant(),
                    rss_request_context::PrincipalKind::User,
                    user().as_uuid().hyphenated().to_string(),
                ),
                at(20),
            )
            .expect("account command");
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
            let command = CredentialSecurityCommand::grant(
                active_grant(),
                kind,
                CredentialSecurityInitiator::authenticated(
                    tenant(),
                    rss_request_context::PrincipalKind::User,
                    user().as_uuid().hyphenated().to_string(),
                ),
                at(20),
            )
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
                command.event().grant_id().map(AuthGrantId::to_wire),
                Some("7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8".to_owned())
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

    #[test]
    #[allow(clippy::expect_used)]
    fn grant_command_rejects_cross_tenant_initiator() {
        let other = TenantId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("other tenant");
        let result = CredentialSecurityCommand::grant(
            active_grant(),
            GrantSecurityEventKind::LogoutCurrent,
            CredentialSecurityInitiator::authenticated(
                other,
                rss_request_context::PrincipalKind::User,
                "opaque-user",
            ),
            at(20),
        );
        assert!(
            matches!(result, Err(AuthGrantStateError::TenantMismatch)),
            "cross-tenant initiator must fail closed"
        );
    }
}
