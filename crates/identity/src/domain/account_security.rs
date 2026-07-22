//! Durable account-security lifecycle and authentication epoch.
//!
//! The public state is a validated persistence entity. The security capability used by token
//! issuance is [`ActiveAccountSecurity`], whose constructor and fields stay crate-private.
//!
//! INVARIANT: ACCOUNT-SECURITY-ACTIVE-RECEIPT-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields plus crate-private active conversion" }.
//! INVARIANT: ACCOUNT-SECURITY-MUTATION-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "private mutation fields and transition-only constructor" }.

use std::time::SystemTime;

use authn::AuthnEpoch;

const MAX_PERSISTED_COUNTER: u64 = i64::MAX as u64;

/// Durable account lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// The account may authenticate and mint a new grant.
    Active,
    /// Administrative suspension.
    Suspended,
    /// Durable security lock, distinct from temporary brute-force throttling.
    Locked,
    /// Terminal account lifecycle state.
    Deactivated,
}

impl AccountStatus {
    fn can_transition_to(self, next: Self) -> bool {
        use AccountStatus::{Active, Deactivated, Locked, Suspended};
        matches!(
            (self, next),
            (Active, Suspended)
                | (Active, Locked)
                | (Active, Deactivated)
                | (Suspended, Active)
                | (Suspended, Deactivated)
                | (Locked, Active)
                | (Locked, Deactivated)
        )
    }
}

/// Optimistic-concurrency version for account-security state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountSecurityVersion(u64);

impl AccountSecurityVersion {
    /// Initial persisted version.
    pub const INITIAL: Self = Self(1);

    /// Validated persisted value.
    pub fn hydrate(value: u64) -> Result<Self, AccountSecurityHydrationError> {
        if value == 0 {
            return Err(AccountSecurityHydrationError::ZeroVersion);
        }
        if value > MAX_PERSISTED_COUNTER {
            return Err(AccountSecurityHydrationError::CounterOutOfRange);
        }
        Ok(Self(value))
    }

    /// Numeric value for persistence.
    pub fn get(self) -> u64 {
        self.0
    }

    fn checked_next(self) -> Result<Self, AccountSecurityTransitionError> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(AccountSecurityTransitionError::VersionOverflow)?;
        if next > MAX_PERSISTED_COUNTER {
            return Err(AccountSecurityTransitionError::VersionOverflow);
        }
        Ok(Self(next))
    }
}

/// Persisted account-security aggregate.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountSecurityState {
    tenant: vocab::TenantId,
    user_id: ids::UserId,
    status: AccountStatus,
    authn_epoch: AuthnEpoch,
    version: AccountSecurityVersion,
    status_changed_at: SystemTime,
    updated_at: SystemTime,
}

/// Named persistence snapshot for the account-security aggregate.
///
/// This is the only cross-crate hydration input. Named fields make epoch/version and the two
/// timestamps impossible to swap accidentally at call sites while still compiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSecuritySnapshot {
    pub tenant: vocab::TenantId,
    pub user_id: ids::UserId,
    pub status: AccountStatus,
    pub authn_epoch: u64,
    pub version: u64,
    pub status_changed_at: SystemTime,
    pub updated_at: SystemTime,
}

impl std::fmt::Debug for AccountSecurityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSecurityState")
            .field("tenant", &self.tenant)
            .field("user_id", &"<redacted>")
            .field("status", &self.status)
            .field("authn_epoch", &"<redacted>")
            .field("version", &self.version)
            .field("status_changed_at", &self.status_changed_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl AccountSecurityState {
    /// Initial state created alongside a new credential.
    #[allow(
        dead_code,
        reason = "in-memory seed adapter is feature-gated; production initialization is transactional SQL"
    )]
    pub(crate) fn initial(tenant: vocab::TenantId, user_id: ids::UserId, now: SystemTime) -> Self {
        Self {
            tenant,
            user_id,
            status: AccountStatus::Active,
            authn_epoch: AuthnEpoch::ZERO,
            version: AccountSecurityVersion::INITIAL,
            status_changed_at: now,
            updated_at: now,
        }
    }

    /// Tenant that owns the account.
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// Canonical account subject.
    pub fn user_id(&self) -> ids::UserId {
        self.user_id
    }

    /// Durable lifecycle status.
    pub fn status(&self) -> AccountStatus {
        self.status
    }

    /// Current authentication epoch.
    pub fn authn_epoch(&self) -> AuthnEpoch {
        self.authn_epoch
    }

    /// Current optimistic-concurrency version.
    pub fn version(&self) -> AccountSecurityVersion {
        self.version
    }

    /// Time at which status last changed.
    pub fn status_changed_at(&self) -> SystemTime {
        self.status_changed_at
    }

    /// Time at which the state row last changed.
    pub fn updated_at(&self) -> SystemTime {
        self.updated_at
    }

    /// Construct the only legal lifecycle mutation.
    pub fn transition(
        &self,
        next_status: AccountStatus,
        now: SystemTime,
    ) -> Result<AccountSecurityMutation, AccountSecurityTransitionError> {
        if !self.status.can_transition_to(next_status) {
            return Err(AccountSecurityTransitionError::Illegal);
        }
        if now < self.updated_at {
            return Err(AccountSecurityTransitionError::TimeRegression);
        }
        let authn_epoch = if next_status == AccountStatus::Active {
            self.authn_epoch
        } else {
            self.authn_epoch
                .checked_next()
                .map_err(|_| AccountSecurityTransitionError::EpochOverflow)?
        };
        let next = Self {
            tenant: self.tenant,
            user_id: self.user_id,
            status: next_status,
            authn_epoch,
            version: self.version.checked_next()?,
            status_changed_at: now,
            updated_at: now,
        };
        Ok(AccountSecurityMutation {
            expected: self.clone(),
            next,
        })
    }

    /// Invalidate every credential-derived session without changing the durable account status.
    ///
    /// This is intentionally crate-private: only a sealed account credential-security command may
    /// create this mutation. Both monotonic counters advance while `status_changed_at` remains the
    /// time of the last real lifecycle transition.
    pub(crate) fn invalidate(
        &self,
        now: SystemTime,
    ) -> Result<AccountSecurityMutation, AccountSecurityTransitionError> {
        if now < self.updated_at {
            return Err(AccountSecurityTransitionError::TimeRegression);
        }
        let next = Self {
            tenant: self.tenant,
            user_id: self.user_id,
            status: self.status,
            authn_epoch: self
                .authn_epoch
                .checked_next()
                .map_err(|_| AccountSecurityTransitionError::EpochOverflow)?,
            version: self.version.checked_next()?,
            status_changed_at: self.status_changed_at,
            updated_at: now,
        };
        Ok(AccountSecurityMutation {
            expected: self.clone(),
            next,
        })
    }

    pub(crate) fn try_into_active(self) -> Option<ActiveAccountSecurity> {
        if self.status != AccountStatus::Active {
            return None;
        }
        Some(ActiveAccountSecurity {
            tenant: self.tenant,
            user_id: self.user_id,
            authn_epoch: self.authn_epoch,
        })
    }
}

impl TryFrom<AccountSecuritySnapshot> for AccountSecurityState {
    type Error = AccountSecurityHydrationError;

    fn try_from(snapshot: AccountSecuritySnapshot) -> Result<Self, Self::Error> {
        if snapshot.updated_at < snapshot.status_changed_at {
            return Err(AccountSecurityHydrationError::TimeRegression);
        }
        Ok(Self {
            tenant: snapshot.tenant,
            user_id: snapshot.user_id,
            status: snapshot.status,
            authn_epoch: AuthnEpoch::hydrate(snapshot.authn_epoch)
                .map_err(|_| AccountSecurityHydrationError::CounterOutOfRange)?,
            version: AccountSecurityVersion::hydrate(snapshot.version)?,
            status_changed_at: snapshot.status_changed_at,
            updated_at: snapshot.updated_at,
        })
    }
}

/// Sealed optimistic-concurrency transition command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSecurityMutation {
    expected: AccountSecurityState,
    next: AccountSecurityState,
}

impl AccountSecurityMutation {
    /// Complete state that must still be current.
    ///
    /// Adapters must compare the tenant, user, status, authentication epoch, and version rather
    /// than treating the version as a sufficient identity for the row.
    pub fn expected(&self) -> &AccountSecurityState {
        &self.expected
    }

    /// Fully validated next state.
    pub fn next(&self) -> &AccountSecurityState {
        &self.next
    }

    /// Consume into persistence parts.
    pub fn into_parts(self) -> (AccountSecurityState, AccountSecurityState) {
        (self.expected, self.next)
    }
}

/// Active account proof consumed by the token issuance funnel.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ActiveAccountSecurity {
    tenant: vocab::TenantId,
    user_id: ids::UserId,
    authn_epoch: AuthnEpoch,
}

impl ActiveAccountSecurity {
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub(crate) fn user_id(&self) -> ids::UserId {
        self.user_id
    }

    pub(crate) fn authn_epoch(&self) -> AuthnEpoch {
        self.authn_epoch
    }
}

impl std::fmt::Debug for ActiveAccountSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveAccountSecurity")
            .field("tenant", &self.tenant)
            .field("user_id", &"<redacted>")
            .field("epoch", &"<redacted>")
            .finish()
    }
}

/// Persisted row failed validation.
#[derive(Debug, thiserror::Error)]
pub enum AccountSecurityHydrationError {
    /// Version zero is not a persisted state.
    #[error("account security version is invalid")]
    ZeroVersion,
    /// Counter cannot be represented by the PostgreSQL schema.
    #[error("account security counter is out of range")]
    CounterOutOfRange,
    /// Persisted timestamps move backwards.
    #[error("account security timestamps are invalid")]
    TimeRegression,
}

/// Lifecycle transition was rejected before persistence.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccountSecurityTransitionError {
    /// Transition is outside the closed state machine.
    #[error("account security transition is invalid")]
    Illegal,
    /// Authentication epoch cannot be incremented safely.
    #[error("account security epoch overflow")]
    EpochOverflow,
    /// Version cannot be incremented safely.
    #[error("account security version overflow")]
    VersionOverflow,
    /// Mutation time predates the current row.
    #[error("account security time regression")]
    TimeRegression,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        AccountSecuritySnapshot, AccountSecurityState, AccountSecurityTransitionError,
        AccountStatus, AuthnEpoch,
    };
    use std::time::{Duration, SystemTime};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const USER: &str = "11111111-2222-4333-8444-555555555555";

    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse(TENANT).expect("canonical tenant")
    }

    fn user() -> ids::UserId {
        ids::UserId::parse(USER).expect("canonical user")
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn initial_state_is_active_at_epoch_zero_and_version_one() {
        let state = AccountSecurityState::initial(tenant(), user(), at(10));
        assert_eq!(state.status(), AccountStatus::Active);
        assert_eq!(state.authn_epoch(), AuthnEpoch::ZERO);
        assert_eq!(state.version().get(), 1);
        assert!(state.clone().try_into_active().is_some());
    }

    #[test]
    fn non_active_transition_bumps_epoch_and_every_transition_bumps_version() {
        let active = AccountSecurityState::initial(tenant(), user(), at(10));
        let suspended = active
            .transition(AccountStatus::Suspended, at(20))
            .expect("active may suspend")
            .next()
            .clone();
        assert_eq!(suspended.authn_epoch().get(), 1);
        assert_eq!(suspended.version().get(), 2);
        assert!(suspended.clone().try_into_active().is_none());

        let restored = suspended
            .transition(AccountStatus::Active, at(30))
            .expect("suspended may activate")
            .next()
            .clone();
        assert_eq!(
            restored.authn_epoch().get(),
            1,
            "restore never lowers epoch"
        );
        assert_eq!(restored.version().get(), 3);
    }

    #[test]
    fn illegal_and_terminal_transitions_fail_closed() {
        let active = AccountSecurityState::initial(tenant(), user(), at(10));
        assert!(matches!(
            active.transition(AccountStatus::Active, at(20)),
            Err(AccountSecurityTransitionError::Illegal)
        ));

        let deactivated = active
            .transition(AccountStatus::Deactivated, at(20))
            .expect("active may deactivate")
            .next()
            .clone();
        assert!(matches!(
            deactivated.transition(AccountStatus::Active, at(30)),
            Err(AccountSecurityTransitionError::Illegal)
        ));
    }

    #[test]
    fn transition_table_is_closed_and_complete() {
        let statuses = [
            AccountStatus::Active,
            AccountStatus::Suspended,
            AccountStatus::Locked,
            AccountStatus::Deactivated,
        ];
        for from in statuses {
            for to in statuses {
                let state = AccountSecurityState::try_from(AccountSecuritySnapshot {
                    tenant: tenant(),
                    user_id: user(),
                    status: from,
                    authn_epoch: 3,
                    version: 7,
                    status_changed_at: at(10),
                    updated_at: at(10),
                })
                .expect("valid row");
                let allowed = matches!(
                    (from, to),
                    (
                        AccountStatus::Active,
                        AccountStatus::Suspended
                            | AccountStatus::Locked
                            | AccountStatus::Deactivated
                    ) | (
                        AccountStatus::Suspended | AccountStatus::Locked,
                        AccountStatus::Active | AccountStatus::Deactivated
                    )
                );
                assert_eq!(
                    state.transition(to, at(20)).is_ok(),
                    allowed,
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn transition_rejects_counter_overflow_and_time_regression() {
        let epoch_max = AccountSecurityState::try_from(AccountSecuritySnapshot {
            tenant: tenant(),
            user_id: user(),
            status: AccountStatus::Active,
            authn_epoch: i64::MAX as u64,
            version: 1,
            status_changed_at: at(10),
            updated_at: at(10),
        })
        .expect("max epoch row");
        assert!(matches!(
            epoch_max.transition(AccountStatus::Locked, at(20)),
            Err(AccountSecurityTransitionError::EpochOverflow)
        ));

        let version_max = AccountSecurityState::try_from(AccountSecuritySnapshot {
            tenant: tenant(),
            user_id: user(),
            status: AccountStatus::Suspended,
            authn_epoch: 1,
            version: i64::MAX as u64,
            status_changed_at: at(10),
            updated_at: at(10),
        })
        .expect("max version row");
        assert!(matches!(
            version_max.transition(AccountStatus::Active, at(20)),
            Err(AccountSecurityTransitionError::VersionOverflow)
        ));

        let active = AccountSecurityState::initial(tenant(), user(), at(10));
        assert!(matches!(
            active.transition(AccountStatus::Suspended, at(9)),
            Err(AccountSecurityTransitionError::TimeRegression)
        ));
    }

    #[test]
    fn active_receipt_debug_redacts_subject_and_epoch() {
        let receipt = AccountSecurityState::initial(tenant(), user(), at(10))
            .try_into_active()
            .expect("initial state is active");
        let debug = format!("{receipt:?}");
        assert!(!debug.contains(USER));
        assert!(!debug.contains("authn_epoch"));
        assert!(debug.contains("<redacted>"));
    }
}
