//! Pure account policy; persistence and transaction locking belong to the adapter.
use super::Password;
use crate::PrincipalId;
use rss_request_context::TenantId;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountKey {
    pub tenant: TenantId,
    pub principal: PrincipalId,
}
/// Validated domain snapshot, never an authentication proof or PostgreSQL fencing token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    key: AccountKey,
    enabled: bool,
    member_active: bool,
    epoch: i64,
    has_local_password: bool,
    membership_epoch: i64,
}
#[derive(Debug)]
pub enum AccountChange {
    Enabled(bool),
    Membership(bool),
    Password(Password),
}
#[derive(Debug, Clone, Copy)]
pub enum LocalChange {
    Enabled(bool),
    Membership(bool),
    Password,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountRuleError {
    #[error("invalid account state")]
    InvalidState,
    #[error("account operation rejected")]
    Rejected,
    #[error("management operation denied")]
    InsufficientPrivilege,
    #[error("recent authentication required")]
    ReauthenticationRequired,
    #[error("local login already exists in this tenant")]
    AlreadyExists,
    #[error("account generation exhausted")]
    EpochExhausted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAction {
    Initialized,
    AccountCreated,
    AccountEnabled,
    AccountDisabled,
    MembershipEnabled,
    MembershipDisabled,
    PasswordChanged,
    PasswordRecovered,
}
impl SecurityAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialized => "initialized",
            Self::AccountCreated => "account_created",
            Self::AccountEnabled => "account_enabled",
            Self::AccountDisabled => "account_disabled",
            Self::MembershipEnabled => "membership_enabled",
            Self::MembershipDisabled => "membership_disabled",
            Self::PasswordChanged => "password_changed",
            Self::PasswordRecovered => "password_recovered",
        }
    }
}
impl AccountState {
    #[allow(clippy::too_many_arguments)] // The single persistence hydration boundary validates every generation.
    pub fn restore(
        key: AccountKey,
        enabled: bool,
        member_active: bool,
        epoch: i64,
        has_local_password: bool,
        membership_epoch: i64,
    ) -> Result<Self, AccountRuleError> {
        if epoch < 1 || membership_epoch < 1 {
            return Err(AccountRuleError::InvalidState);
        }
        Ok(Self {
            key,
            enabled,
            member_active,
            epoch,
            has_local_password,
            membership_epoch,
        })
    }
    pub fn new_local(key: AccountKey) -> Result<Self, AccountRuleError> {
        Self::restore(key, true, true, 1, true, 1)
    }
    pub fn key(self) -> AccountKey {
        self.key
    }
    pub fn enabled(self) -> bool {
        self.enabled
    }
    pub fn member_active(self) -> bool {
        self.member_active
    }
    pub fn epoch(self) -> i64 {
        self.epoch
    }
    pub fn has_local_password(self) -> bool {
        self.has_local_password
    }
    pub fn new_federated(key: AccountKey) -> Result<Self, AccountRuleError> {
        Self::restore(key, true, true, 1, false, 1)
    }
    pub fn membership_epoch(self) -> i64 {
        self.membership_epoch
    }
    /// Invalidate all authentication, including outstanding password candidates.
    pub fn revoke_sessions(self) -> Result<Self, AccountRuleError> {
        if !self.active() {
            return Err(AccountRuleError::Rejected);
        }
        let mut next = self;
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AccountRuleError::EpochExhausted)?;
        Ok(next)
    }
    pub fn active(self) -> bool {
        self.enabled && self.member_active
    }
    pub fn matches_verification(self, expected: Self) -> bool {
        self.active()
            && self.key == expected.key
            && self.epoch == expected.epoch
            && self.has_local_password == expected.has_local_password
            && self.membership_epoch == expected.membership_epoch
    }
    /// Pure transition; the application service separately verifies the actor and host policy.
    pub fn change(self, change: LocalChange) -> Result<(Self, SecurityAction), AccountRuleError> {
        self.transition(change)
    }
    pub(crate) fn transition(
        self,
        change: LocalChange,
    ) -> Result<(Self, SecurityAction), AccountRuleError> {
        if matches!(change, LocalChange::Password) && !self.has_local_password {
            return Err(AccountRuleError::Rejected);
        }
        let mut next = self;
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AccountRuleError::EpochExhausted)?;
        let action = match change {
            LocalChange::Enabled(v) => {
                next.enabled = v;
                if v {
                    SecurityAction::AccountEnabled
                } else {
                    SecurityAction::AccountDisabled
                }
            }
            LocalChange::Membership(v) => {
                if v != next.member_active {
                    next.membership_epoch = next
                        .membership_epoch
                        .checked_add(1)
                        .ok_or(AccountRuleError::EpochExhausted)?;
                }
                next.member_active = v;
                if v {
                    SecurityAction::MembershipEnabled
                } else {
                    SecurityAction::MembershipDisabled
                }
            }
            LocalChange::Password => SecurityAction::PasswordChanged,
        };
        Ok((next, action))
    }
    /// The adapter must verify maintenance authority before persisting this result.
    pub fn recover(self) -> Result<(Self, SecurityAction), AccountRuleError> {
        if !self.has_local_password {
            return Err(AccountRuleError::Rejected);
        }
        let mut next = self;
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AccountRuleError::EpochExhausted)?;
        Ok((next, SecurityAction::PasswordRecovered))
    }
}
