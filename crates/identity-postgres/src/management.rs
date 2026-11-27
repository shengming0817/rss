//! Host authorization is the only management authority. No product roles are stored here.
use crate::{GroupAccessError, VerifiedGroups, groups::GroupFacts, session_storage::Loaded};
use rss_identity_core::{
    InstanceId,
    account::{AccountKey, AccountRuleError},
    assurance::{Acr, Assurance},
    federation::ProviderId,
};
use std::time::{Duration, Instant};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementOperation {
    RegisterWebauthn,
    RemoveWebauthn,
    RecoverWebauthn,
    AuthorizeWebauthnRecovery,
    ReadProfileSources,
    ReadLocalProfile,
    UpdateLocalProfile,
    ReadLatestProfile,
    ListAccounts,
    ReadAccount,
    ReadLatestDepartments,
    CreateAccount,
    /// Restricted provisioner only; normal Authority never invokes this operation.
    ProvisionAccount(rss_request_context::TenantId),
    SetAccountEnabled(bool),
    SetMembership(bool),
    ResetPassword,
    ChangeOwnPassword,
    ListProviders,
    CreateProvider,
    UpdateProvider(ProviderId),
    SetProviderEnabled(ProviderId, bool),
    TestProvider(ProviderId),
}
#[derive(Debug, Clone, Copy)]
pub enum ReauthenticationRequirement {
    None,
    Recent(Duration),
    RecentMfa(Duration),
}
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("management denied by host")]
pub struct ManagementDenied;
/// Created only after the component has loaded authoritative state in this transaction.
pub struct ManagementContext<'a> {
    instance: InstanceId,
    actor: AccountKey,
    target: Option<AccountKey>,
    operation: ManagementOperation,
    assurance: &'a Assurance,
    groups: &'a GroupFacts,
    department_snapshot: &'a crate::department::DepartmentFacts,
    expires: Instant,
}
impl ManagementContext<'_> {
    pub fn check_live(&self) -> Result<(), ManagementDenied> {
        if Instant::now() < self.expires {
            Ok(())
        } else {
            Err(ManagementDenied)
        }
    }
    pub fn instance(&self) -> InstanceId {
        self.instance
    }
    pub fn actor(&self) -> AccountKey {
        self.actor
    }
    pub fn target(&self) -> Option<AccountKey> {
        self.target
    }
    pub fn operation(&self) -> ManagementOperation {
        self.operation
    }
    pub fn assurance(&self) -> &Assurance {
        self.assurance
    }
    pub fn department_snapshot(
        &self,
    ) -> Result<crate::VerifiedDepartmentSnapshot<'_>, crate::DepartmentAccessError> {
        self.department_snapshot
            .view(self.instance, self.actor, self.expires)
    }
    pub fn groups(&self) -> Result<VerifiedGroups<'_>, GroupAccessError> {
        self.groups.view(self.expires)
    }
}
/// Transaction-bound host policy. Borrow the existing connection; do not commit,
/// change tenant scope, block, or acquire another connection. The caller owns the deadline.
pub trait ManagementPolicy: Send + Sync {
    fn authorize<'a>(
        &'a self,
        context: &'a ManagementContext<'a>,
        connection: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<ReauthenticationRequirement, ManagementDenied>>;
}
pub(crate) struct DenyManagement;
impl ManagementPolicy for DenyManagement {
    fn authorize<'a>(
        &'a self,
        _: &'a ManagementContext<'a>,
        _connection: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<ReauthenticationRequirement, ManagementDenied>> {
        Box::pin(async move { Err(ManagementDenied) })
    }
}
pub(crate) async fn authorize(
    policy: &dyn ManagementPolicy,
    instance: InstanceId,
    loaded: &Loaded,
    operation: ManagementOperation,
    target: Option<AccountKey>,
    connection: &mut sqlx::PgConnection,
) -> Result<(), AccountRuleError> {
    if Instant::now() >= loaded.expires {
        return Err(AccountRuleError::InsufficientPrivilege);
    }
    if target.is_some_and(|t| t.tenant != loaded.state.key().tenant)
        && !matches!(operation, ManagementOperation::ProvisionAccount(_))
    {
        return Err(AccountRuleError::InsufficientPrivilege);
    }
    let requirement = policy
        .authorize(
            &ManagementContext {
                instance,
                actor: loaded.state.key(),
                target,
                operation,
                assurance: &loaded.assurance,
                groups: &loaded.groups,
                department_snapshot: &loaded.department_snapshot,
                expires: loaded.expires,
            },
            connection,
        )
        .await
        .map_err(|_| AccountRuleError::InsufficientPrivilege)?;
    if Instant::now() >= loaded.expires {
        return Err(AccountRuleError::InsufficientPrivilege);
    }
    let (max_age, mfa) = match requirement {
        ReauthenticationRequirement::None => return Ok(()),
        ReauthenticationRequirement::Recent(age) => (age, false),
        ReauthenticationRequirement::RecentMfa(age) => (age, true),
    };
    if !loaded.recently_authenticated(max_age) || (mfa && loaded.assurance.acr() != Acr::Mfa) {
        return Err(AccountRuleError::ReauthenticationRequired);
    }
    Ok(())
}
