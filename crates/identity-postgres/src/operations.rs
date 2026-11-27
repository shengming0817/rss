use crate::{storage::*, transaction::SecurityEvent, *};
use rss_identity_core::account::{LocalChange, SecurityAction};
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
};
use rss_transactional_messaging::policy::OperationDeadline;

impl Authority {
    /// Verify credentials and issue a session only after the atomic security event commits.
    pub async fn login_local(
        &self,
        binding: ExecutionBinding,
        login: LoginKey,
        password: Password,
        source: AttemptSource,
        replacement: Option<AuthenticatedSession>,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        let budget = Budget::new(deadline)?;
        let candidate =
            Box::pin(self.verify_password(binding, login, password, source, budget.remaining()))
                .await?;
        Box::pin(self.create_session(candidate, replacement, budget.remaining())).await
    }

    pub(crate) async fn verify_password(
        &self,
        binding: ExecutionBinding,
        login: LoginKey,
        password: Password,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<AuthenticationCandidate, AuthorityError> {
        self.require_runtime()?;
        let budget = Budget::new(deadline)?;
        let claim = self
            .claim_password(binding, &login, &source, budget.remaining())
            .await?;
        let outcome = self
            .check_password(binding, login, password, budget.remaining())
            .await;
        self.settle_password(claim, outcome, budget.remaining())
            .await
    }

    async fn check_password(
        &self,
        binding: ExecutionBinding,
        login: LoginKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AuthenticationCandidate, AuthorityError> {
        let tenant = binding.tenant();
        let budget = Budget::new(deadline)?;
        let authority = self.instance.as_uuid();
        let snapshot = self.read_sql(binding, budget.remaining(), move |c| Box::pin(async move {
            lock_tenant_scope(c, tenant).await?;
            let id: Option<uuid::Uuid> = sqlx::query_scalar(
                "SELECT principal_id FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND login_key=$2")
                .bind(tenant.to_string()).bind(login.as_str()).fetch_optional(&mut *c).await?;
            let Some(id) = id else { return Ok(None) };
            let key = AccountKey {tenant, principal: principal(&id.to_string())?};
            lock_account(c,key,false).await?;
            let encoding: String = sqlx::query_scalar(
                "SELECT password_hash FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND principal_id=$2 AND login_key=$3")
                .bind(tenant.to_string()).bind(id).bind(login.as_str()).fetch_one(&mut *c).await?;
            let hash = rss_identity_core::account::PasswordEncoding::from_storage(encoding)
                .map_err(|_| crate::transaction::corrupt())?;
            Ok(Some((account_state_locked(c,key).await?, hash, crate::session_storage::now(c).await?)))
        })).await?;
        let kdf = &self.kdf;
        let Some((state, hash, authenticated_at)) = snapshot else {
            budget.password(kdf.dummy(password)).await?;
            return Err(AuthorityError::Rejected);
        };
        let valid = budget.password(kdf.verify(password, hash)).await?;
        if !valid || !state.active() {
            return Err(AuthorityError::Rejected);
        }
        let candidate = AuthenticationCandidate {
            binding,
            state,
            authority,
            expires: budget.0.instant(),
            authenticated_at,
        };
        self.read(binding, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        current(c, &candidate).await?;
                        Ok(candidate)
                    })
                })
                .await
            })
        })
        .await
    }

    pub async fn create_local_account(
        &self,
        actor: AuthenticatedSession,
        login: LoginKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.shortened_to(actor.expires);

        let hash = budget.password(self.kdf.hash(password)).await?;
        let key = AccountKey {
            tenant: actor.key.tenant,
            principal: PrincipalId::generate(),
        };
        let policy = self.policy.clone();
        let instance = self.instance;
        self.write_sql(actor.binding, budget.remaining(), move |c| {
            Box::pin(async move {
                let loaded = crate::session_storage::recheck_collection(c, &actor).await?;
                crate::management::authorize(
                    policy.as_ref(),
                    instance,
                    &loaded,
                    ManagementOperation::CreateAccount,
                    Some(key),
                    c,
                )
                .await?;
                insert_account(c, key, login.as_str(), hash.as_str()).await?;
                let state = account_state_locked(c, key).await?;
                Ok((
                    state,
                    vec![SecurityEvent::account(
                        SecurityAction::AccountCreated,
                        state,
                        Some(actor.key),
                    )],
                ))
            })
        })
        .await
    }

    pub async fn set_account_enabled(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        enabled: bool,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.apply_account_change(
            actor,
            target,
            AccountChange::Enabled(enabled),
            None,
            deadline,
        )
        .await
    }
    pub async fn set_account_membership(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        active: bool,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.apply_account_change(
            actor,
            target,
            AccountChange::Membership(active),
            None,
            deadline,
        )
        .await
    }
    pub async fn reset_local_password(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        if actor.key == target {
            return Err(AuthorityError::InvalidInput);
        }
        self.apply_account_change(
            actor,
            target,
            AccountChange::Password(password),
            None,
            deadline,
        )
        .await
    }
    pub async fn change_own_password(
        &self,
        actor: AuthenticatedSession,
        current_password: Password,
        new_password: Password,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.shortened_to(actor.expires);
        let key = actor.key;
        let (actor, login) = self.local_login_key(actor, budget.remaining()).await?;
        let candidate = self
            .verify_password(
                actor.binding,
                login,
                current_password,
                source,
                budget.remaining(),
            )
            .await
            .map_err(|e| {
                if e == AuthorityError::Rejected {
                    AuthorityError::ReauthenticationFailed
                } else {
                    e
                }
            })?;
        if candidate.account() != key {
            return Err(AuthorityError::ReauthenticationFailed);
        }
        self.apply_account_change(
            actor,
            key,
            AccountChange::Password(new_password),
            Some(candidate),
            budget.remaining(),
        )
        .await
    }
    /// Password reauthentication rotates only the currently authenticated account's session.
    pub async fn reauthenticate_local(
        &self,
        actor: AuthenticatedSession,
        password: Password,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.shortened_to(actor.expires);
        let (actor, login) = self.local_login_key(actor, budget.remaining()).await?;
        Box::pin(self.login_local(
            actor.binding,
            login,
            password,
            source,
            Some(actor),
            budget.remaining(),
        ))
        .await
    }
    async fn local_login_key(
        &self,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<(AuthenticatedSession, LoginKey), AuthorityError> {
        let key = actor.key;
        let (actor, name) = self.read_sql(actor.binding, deadline, move |c|Box::pin(async move {
            crate::session_storage::recheck_for(c,&actor,crate::session_storage::SessionAccess::Inspect).await?;
            let name:Option<String> = sqlx::query_scalar("SELECT login_key FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND principal_id=$2")
                .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_optional(c).await?;
            Ok((actor,name))
        })).await?;
        let login = LoginKey::parse(&name.ok_or(AuthorityError::ReauthenticationFailed)?)?;
        Ok((actor, login))
    }
    async fn apply_account_change(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        change: AccountChange,
        reauthentication: Option<AuthenticationCandidate>,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        if actor.key.tenant != target.tenant {
            return Err(AuthorityError::Rejected);
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.shortened_to(actor.expires);
        if let Some(proof) = &reauthentication {
            budget.0 = budget.0.shortened_to(proof.expires);
        }
        let (change, hash) = match change {
            AccountChange::Password(password) => (
                LocalChange::Password,
                Some(budget.password(self.kdf.hash(password)).await?),
            ),
            AccountChange::Enabled(v) => (LocalChange::Enabled(v), None),
            AccountChange::Membership(v) => (LocalChange::Membership(v), None),
        };
        let policy = self.policy.clone();
        let instance = self.instance;
        let operation = match change {
            LocalChange::Password if reauthentication.is_some() => {
                ManagementOperation::ChangeOwnPassword
            }
            LocalChange::Password => ManagementOperation::ResetPassword,
            LocalChange::Enabled(v) => ManagementOperation::SetAccountEnabled(v),
            LocalChange::Membership(v) => ManagementOperation::SetMembership(v),
        };
        self.write_sql(actor.binding, budget.remaining(), move |c| Box::pin(async move {
            let loaded = crate::session_storage::recheck_for(c, &actor, crate::session_storage::SessionAccess::Account(target)).await?;
            if let Some(proof) = reauthentication {
                if proof.account() != actor.key || target != actor.key { return Err(crate::transaction::reject().into()); }
                current(c, &proof).await?;
            }
            crate::management::authorize(policy.as_ref(),instance,&loaded,operation,Some(target), c).await?;
            if hash.is_some() { lock_attempt_capacity(c,target.tenant).await?; }
            let old = account_state_locked(c, target).await?;
            let (next, action) = old.change(change)?;
            sqlx::query("UPDATE identity_authority.accounts SET enabled=$3,auth_epoch=$4 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(next.enabled()).bind(next.epoch()).execute(&mut *c).await?;
            if let Some(hash) = hash {
                sqlx::query("UPDATE identity_authority.local_credentials SET password_hash=$3 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                    .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(hash.as_str()).execute(&mut *c).await?;
                crate::password_attempts::clear(c, target).await?;
            }
            sqlx::query("UPDATE identity_authority.memberships SET active=$3,epoch=$4 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(next.member_active()).bind(next.membership_epoch()).execute(&mut *c).await?;
            Ok((next, vec![SecurityEvent::account(action, next, Some(actor.key))]))
        })).await
    }
}

#[derive(Debug, Clone)]
pub struct AccountView {
    pub principal_id: PrincipalId,
    pub login: Option<String>,
    pub enabled: bool,
    pub member_active: bool,
    pub has_local_password: bool,
}
impl AccountView {
    pub fn new(state: AccountState, login: Option<String>) -> Self {
        Self {
            principal_id: state.key().principal,
            login,
            enabled: state.enabled(),
            member_active: state.member_active(),
            has_local_password: state.has_local_password(),
        }
    }
}
