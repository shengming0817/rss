//! in-memory 仓储实现（域内 / 域形 DI port 的 test / seed-login 替身）。
//!
//! - [`InMemCredentialRepo`]：`CredentialRepo` 域形 DI port 的 in-mem 替身（哈希凭据 + 锁定态持久化），PR3。
//! - [`InMemAuthGrantStore`]：同一共享状态实现 grant 创建/读取、refresh 读取与安全 lifecycle，
//!   使认证授权根、刷新族和 reuse containment 在 test / seed-login 路径始终同源。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::domain::{
    AccountLockout, AccountSecurityState, AccountStatus, AuthOutcome, Credential, IdentityError,
    LoginIdentifier,
};
use crate::ports::{AccountSecurityReadRepo, CredentialRepo, TenantRepoScope};
#[cfg(test)]
use authn::{AuthGrant, AuthGrantId, AuthGrantStatus, GrantSecurityEventKind};
use rss_request_context::TenantId;

// 认证授权根 in-mem 替身在 test / seed-login 构建启用；单一 Mutex 是原子 login/refresh-security 的事务边界。
#[cfg(test)]
use crate::domain::{RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord};
#[cfg(test)]
use crate::ports::{
    AccountStatusSetCommand, AccountStatusSetProducerReceipt, AuthGrantLifecycle,
    CredentialSecurityReceipt, IdentitySecurityLifecycle, LoginGrantMutation, LogoutAllCommand,
    LogoutAllProducerReceipt, LogoutCurrentCommand, LogoutCurrentProducerReceipt,
    PasswordChangeCommand, PasswordChangeProducerReceipt, RefreshExecutionCommand,
    RefreshExecutionOutcome, RefreshProducerReceipt, RefreshTokenStore, SECURITY_EVENT_CONTRACT,
    SECURITY_EVENT_FACT,
};
#[cfg(test)]
use diport::OutboxEmitError;
#[cfg(test)]
use eventexec::event::ReviewedEvent;
#[cfg(test)]
fn authorize_entry<M>(
    receipt: httpserve::ProducerAssuranceReceipt<M>,
    event: &ReviewedEvent,
    expected_contract: vocab::ContractBinding,
) -> Option<httpserve::ProducerAuthorization<M>> {
    receipt.authorize(event.fact(), expected_contract)
}

// RBAC 角色仓储 + 绑定生命周期 in-mem 替身（`#[cfg(test)]` 门控，#1190）。
#[cfg(test)]
use crate::domain::{
    Policy, PolicyId, PolicyRouteScope, PolicyVersion, ResourceAttribute, ResourceAttributeKey,
    ResourceAttributeResolution, ResourceAttributeResourceId, ResourceAttributeVersion, Role,
    RoleBinding, RoleId,
};
#[cfg(test)]
use crate::ports::{
    PoliciesCreateProducerReceipt, PoliciesDeactivateProducerReceipt,
    PoliciesUpdateProducerReceipt, PolicyLifecycle, PolicyListResult, PolicyPage, PolicyRepo,
    ResourceAttributeReadRepo, ResourceAttributeWriteRepo, RoleBindingLifecycle,
    RoleBindingReadRepo, RoleDefinitionLifecycle, RoleMutationActor, RoleMutationOutcome,
    RoleReadRepo, RoleRevision, RolesAssignProducerReceipt, RolesRevokeProducerReceipt,
};
#[cfg(test)]
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// InMemCredentialRepo — CredentialRepo 域形 DI port 的 in-mem 替身（PR3）
// ---------------------------------------------------------------------------

/// `CredentialRepo` 的 in-memory 替身：`(tenant, login)` → 哈希凭据 / 锁定态。
///
/// 内部 `Mutex`（trait 方法 `&self`，需内部可变；锁仅同步持有、**不跨 `.await`** ⇒ future 仍 `Send`）。
/// 键含 `TenantId` ⇒ 跨租赁查找天然 fail-closed（`find(t ≠ 存入 tenant)` → `None`）。键的标识段是
/// [`LoginIdentifier`]（登录查找键，非 canonical user id，#1277 F1）。生产由 PostgreSQL provider 承载。
struct InMemCredentialState {
    creds: HashMap<(TenantId, LoginIdentifier), Credential>,
    lockouts: HashMap<(TenantId, LoginIdentifier), AccountLockout>,
    security: HashMap<(TenantId, ids::UserId), AccountSecurityState>,
}

#[derive(Clone)]
pub(crate) struct InMemCredentialRepo {
    inner: Arc<Mutex<InMemCredentialState>>,
}

/// 取锁并从毒化恢复（集中 poison 处理理由，避免散落各方法）。
// reason: in-mem 替身锁仅同步持有、不跨 await；唯一毒化来源是持锁线程 panic（测试断言失败）——此时
// into_inner 恢复 guard 让数据结构仍可读，不二次 panic 掩盖原始失败。生产 postgres adapter 无 Mutex，
// 不沿用此模式（该替身门控于 test/seed-login，不进生产构建）。
pub(crate) fn recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl InMemCredentialRepo {
    /// 空仓储。
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemCredentialState {
                creds: HashMap::new(),
                lockouts: HashMap::new(),
                security: HashMap::new(),
            })),
        }
    }

    /// 以单个种子凭据构造（密码经 test-support typed seam 哈希，**不存明文**；version 起 1）。
    /// 供 test / `seed-login`（PR4 真实登录种子）。`login` = 登录查找键，`user_id` = canonical actor
    /// subject（写 wire/audit；与 `login` 解耦，#1277 F1）。
    pub(crate) fn with_seed_credential(
        login: impl Into<String>,
        user_id: ids::UserId,
        plaintext: &str,
        tenant: TenantId,
    ) -> Result<Self, secure::PasswordError> {
        let hash = secure::PasswordHash::for_test(secure::RawPassword::new(plaintext.to_owned()))?;
        let credential = Credential::new(LoginIdentifier::new(login), user_id, tenant, hash, 1);
        let repo = Self::new();
        let mut inner = recover(&repo.inner);
        inner.security.insert(
            (tenant, user_id),
            AccountSecurityState::initial(tenant, user_id, SystemTime::UNIX_EPOCH),
        );
        inner.creds.insert(Self::cred_key(&credential), credential);
        drop(inner);
        Ok(repo)
    }

    /// store key 单源：派生自 credential 自身（tenant + login），消除外部 key 与存值错位（F2）。
    fn cred_key(credential: &Credential) -> (TenantId, LoginIdentifier) {
        (credential.tenant(), credential.login().clone())
    }

    /// 测试可见：当前 lockout 表条目数（F2 断言——未知主体登录失败不建锁、不撑大表）。
    #[cfg(test)]
    pub(crate) fn lockout_len(&self) -> usize {
        recover(&self.inner).lockouts.len()
    }

    /// Test-only fixture seam for installing a complete durable account-security snapshot.
    ///
    /// The key is derived from `state`; this deliberately provides no lifecycle transition or CAS
    /// compatibility behavior.
    #[cfg(test)]
    pub(crate) fn set_account_security_for_test(&self, state: AccountSecurityState) {
        recover(&self.inner)
            .security
            .insert((state.tenant(), state.user_id()), state);
    }
}

impl CredentialRepo for InMemCredentialRepo {
    async fn find_by_user_id(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError> {
        let tenant = scope.tenant();
        // creds 按 (tenant, login) 索引——按 canonical user_id 查须线性扫本 tenant 凭据匹配 user_id。
        // reason: in-mem 替身（test/seed-login 门控）规模小，O(n) 扫可接受；生产 PostgreSQL provider
        // 通过 `(tenant_id, user_id)` 唯一索引查找，不沿用扫描。
        Ok(recover(&self.inner)
            .creds
            .values()
            .find(|c| c.tenant() == tenant && c.user_id() == user_id)
            .cloned())
    }

    async fn authenticate(
        &self,
        scope: TenantRepoScope,
        login: LoginIdentifier,
        candidate: secure::RawPassword,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError> {
        let tenant = scope.tenant();
        let key = (tenant, login);
        let mut inner = recover(&self.inner);
        let found = inner.creds.get(&key).cloned();
        let verification =
            secure::verify_password(candidate, found.as_ref().map(Credential::password_hash))
                .map_err(|error| IdentityError::Storage(Box::new(error)))?;
        let Some(found) = found else {
            return match verification {
                secure::PasswordVerification::Invalid => Ok(AuthOutcome::RejectedUnknown),
                secure::PasswordVerification::Verified(_) => Err(IdentityError::Storage(Box::new(
                    std::io::Error::other("credential verification invariant violated"),
                ))),
            };
        };
        let security = inner
            .security
            .get(&(tenant, found.user_id()))
            .cloned()
            .ok_or_else(|| {
                IdentityError::Storage(Box::new(std::io::Error::other(
                    "credential is missing account security state",
                )))
            })?;
        if security.status() != AccountStatus::Active {
            return Ok(AuthOutcome::RejectedKnown);
        }
        if let Some(lockout) = inner.lockouts.get_mut(&key) {
            lockout.try_lazy_unlock(now);
            if lockout.is_locked(now) {
                return Ok(AuthOutcome::RejectedKnown);
            }
        }
        Ok(match verification {
            secure::PasswordVerification::Verified(receipt) => {
                let Some(current) = inner.creds.get_mut(&key) else {
                    return Err(IdentityError::VersionConflict);
                };
                let expected_hash = found.password_hash().clone();
                if let Some(replacement) = receipt.upgraded_hash() {
                    let replaced = current.replace_hash_if_unchanged(&expected_hash, replacement);
                    debug_assert!(replaced, "hash equality checked under the credential lock");
                }
                inner.lockouts.remove(&key);
                AuthOutcome::Authenticated(security)
            }
            secure::PasswordVerification::Invalid => {
                inner
                    .lockouts
                    .entry(key)
                    .or_insert_with(|| AccountLockout::new(now))
                    .record_failure(now);
                AuthOutcome::RejectedKnown
            }
        })
    }

    async fn insert(
        &self,
        scope: TenantRepoScope,
        credential: Credential,
    ) -> Result<(), IdentityError> {
        if scope.tenant() != credential.tenant() {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential insert tenant scope mismatch",
            ))));
        }
        let key = Self::cred_key(&credential);
        let mut inner = recover(&self.inner);
        if inner.creds.contains_key(&key) {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential already exists",
            ))));
        }
        if inner.creds.iter().any(|(existing_key, existing)| {
            existing_key != &key
                && existing.tenant() == credential.tenant()
                && existing.user_id() == credential.user_id()
        }) {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential user already has a different login",
            ))));
        }
        inner
            .security
            .entry((credential.tenant(), credential.user_id()))
            .or_insert_with(|| {
                AccountSecurityState::initial(
                    credential.tenant(),
                    credential.user_id(),
                    SystemTime::UNIX_EPOCH,
                )
            });
        let replaced = inner.creds.insert(key, credential);
        debug_assert!(replaced.is_none(), "duplicate credential rejected above");
        Ok(())
    }
}

impl AccountSecurityReadRepo for InMemCredentialRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<AccountSecurityState>, IdentityError> {
        Ok(recover(&self.inner)
            .security
            .get(&(scope.tenant(), user_id))
            .cloned())
    }
}

// ---------------------------------------------------------------------------
// InMemAuthGrantStore — unified grant/refresh reader + security lifecycle substitute
// ---------------------------------------------------------------------------

#[cfg(test)]
#[derive(Default)]
struct InMemAuthGrantState {
    grants: HashMap<AuthGrantId, AuthGrant>,
    refresh: HashMap<RefreshTokenId, RefreshTokenRecord>,
}

/// Test/seed provider whose one shared lock is the transaction boundary for grant roots and their
/// refresh families. Clones share both maps and can be injected through both ports without
/// producing lifecycle/refresh state drift.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct InMemAuthGrantStore {
    inner: Arc<Mutex<InMemAuthGrantState>>,
    writer_now: Arc<Mutex<SystemTime>>,
}

#[cfg(test)]
impl Default for InMemAuthGrantStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemAuthGrantState::default())),
            writer_now: Arc::new(Mutex::new(SystemTime::UNIX_EPOCH)),
        }
    }
}

#[cfg(test)]
impl InMemAuthGrantStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_writer_now(&self, now: SystemTime) {
        *recover(&self.writer_now) = now;
    }

    #[cfg(test)]
    pub(crate) fn refresh_len(&self) -> usize {
        recover(&self.inner).refresh.len()
    }

    pub(crate) fn grant_snapshot(&self, grant_id: &AuthGrantId) -> Option<AuthGrant> {
        recover(&self.inner).grants.get(grant_id).cloned()
    }

    pub(crate) fn refresh_family_snapshot(
        &self,
        grant_id: &AuthGrantId,
    ) -> Vec<RefreshTokenRecord> {
        recover(&self.inner)
            .refresh
            .values()
            .filter(|record| record.auth_grant_id() == grant_id)
            .cloned()
            .collect()
    }

    /// Seed an already-prepared login pair for refresh-service unit tests. This is intentionally
    /// absent from the production port: initial refresh insertion remains available only through
    /// `AuthGrantLifecycle::persist_login_grant`.
    #[cfg(test)]
    pub(crate) fn seed_login_pair(
        &self,
        grant: AuthGrant,
        refresh: RefreshTokenRecord,
    ) -> Result<(), IdentityError> {
        if !grant_binding_matches(&grant, &refresh)
            || refresh.parent_id().is_some()
            || refresh.lineage_id() != refresh.id()
        {
            return Err(storage_error("invalid test login pair"));
        }
        let mut state = recover(&self.inner);
        if state.grants.contains_key(grant.id())
            || state.refresh.contains_key(refresh.id())
            || state
                .refresh
                .values()
                .any(|stored| stored.token_hash() == refresh.token_hash())
        {
            return Err(storage_error("duplicate test login pair"));
        }
        state.refresh.insert(refresh.id().clone(), refresh);
        state.grants.insert(grant.id().clone(), grant);
        Ok(())
    }
}

#[cfg(test)]
fn grant_binding_matches(grant: &AuthGrant, refresh: &RefreshTokenRecord) -> bool {
    grant.status() == AuthGrantStatus::Active
        && refresh.auth_grant_status() == AuthGrantStatus::Active
        && refresh.status() == RefreshStatus::Active
        && refresh.tenant() == grant.tenant()
        && refresh.auth_grant_id() == grant.id()
        && refresh.user_id() == grant.user_id()
        && refresh.issuance_epoch() == grant.authn_epoch_at_issue()
        && refresh.expires_at() <= grant.expires_at()
}

#[cfg(test)]
fn storage_error(message: &'static str) -> IdentityError {
    IdentityError::Storage(Box::new(std::io::Error::other(message)))
}

#[cfg(test)]
impl AuthGrantLifecycle for InMemAuthGrantStore {
    async fn persist_login_grant(
        &self,
        receipt: crate::ports::LoginProducerReceipt,
        scope: TenantRepoScope,
        mutation: LoginGrantMutation,
        event: ReviewedEvent,
    ) -> Result<crate::ports::PersistedLoginGrantReceipt, OutboxEmitError> {
        let (grant, initial_refresh, persistence) = mutation.into_parts();
        if scope.tenant() != grant.tenant()
            || event.envelope().tenant() != grant.tenant()
            || !grant_binding_matches(&grant, &initial_refresh)
            || initial_refresh.parent_id().is_some()
            || initial_refresh.lineage_id() != initial_refresh.id()
        {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "login grant binding mismatch",
            )));
        }
        let _authorization = authorize_entry(
            receipt,
            &event,
            generated::event::identity_v1::session_created::SPEC.contract(),
        )
        .ok_or_else(|| {
            OutboxEmitError::new(std::io::Error::other(
                "login producer does not authorize session-created",
            ))
        })?;

        let mut state = recover(&self.inner);
        if state.grants.contains_key(grant.id())
            || state.refresh.contains_key(initial_refresh.id())
            || state.refresh.values().any(|record| {
                record.tenant() == initial_refresh.tenant()
                    && record.token_hash() == initial_refresh.token_hash()
            })
        {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "login grant already exists",
            )));
        }
        state
            .refresh
            .insert(initial_refresh.id().clone(), initial_refresh);
        state.grants.insert(grant.id().clone(), grant);
        Ok(persistence.confirm())
    }

    async fn find_active(
        &self,
        scope: TenantRepoScope,
        grant_id: AuthGrantId,
        observed_at: SystemTime,
    ) -> Result<Option<AuthGrant>, IdentityError> {
        Ok(recover(&self.inner)
            .grants
            .get(&grant_id)
            .filter(|grant| {
                grant.tenant() == scope.tenant()
                    && grant.status() == AuthGrantStatus::Active
                    && grant.expires_at() > observed_at
            })
            .cloned())
    }
}

#[cfg(test)]
fn refresh_binding_matches(left: &RefreshTokenRecord, right: &RefreshTokenRecord) -> bool {
    left.id() == right.id()
        && left.tenant() == right.tenant()
        && left.auth_grant_id() == right.auth_grant_id()
        && left.user_id() == right.user_id()
        && left.issuance_epoch() == right.issuance_epoch()
        && left.token_hash() == right.token_hash()
        && left.parent_id() == right.parent_id()
        && left.lineage_id() == right.lineage_id()
        && left.issued_at() == right.issued_at()
        && left.expires_at() == right.expires_at()
}

#[cfg(test)]
fn refresh_grant_binding_matches(refresh: &RefreshTokenRecord, grant: &AuthGrant) -> bool {
    refresh.tenant() == grant.tenant()
        && refresh.auth_grant_id() == grant.id()
        && refresh.user_id() == grant.user_id()
        && refresh.issuance_epoch() == grant.authn_epoch_at_issue()
        && refresh.expires_at() <= grant.expires_at()
}

#[cfg(test)]
impl IdentitySecurityLifecycle for InMemAuthGrantStore {
    async fn execute_refresh(
        &self,
        receipt: RefreshProducerReceipt,
        scope: TenantRepoScope,
        command: RefreshExecutionCommand,
    ) -> Result<RefreshExecutionOutcome, IdentityError> {
        let _authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| storage_error("refresh producer does not authorize security-event"))?;
        let (source, rotation, event, pending) = command.into_parts();
        if scope.tenant() != source.tenant()
            || event.kind()
                != authn::CredentialSecurityEventKind::Grant(
                    GrantSecurityEventKind::RefreshReuseDetected,
                )
            || event.tenant() != source.tenant()
            || event.user_id() != source.user_id()
            || event.grant_id() != Some(source.auth_grant_id())
        {
            return Ok(RefreshExecutionOutcome::Stale);
        }

        let mut state = recover(&self.inner);
        let Some(stored) = state.refresh.get(source.id()).cloned() else {
            return Ok(RefreshExecutionOutcome::Stale);
        };
        if !refresh_binding_matches(&stored, &source) {
            return Ok(RefreshExecutionOutcome::Stale);
        }
        let Some(grant) = state.grants.get(stored.auth_grant_id()).cloned() else {
            return Ok(RefreshExecutionOutcome::Stale);
        };
        if !refresh_grant_binding_matches(&stored, &grant) {
            return Ok(RefreshExecutionOutcome::Stale);
        }

        if stored.status() != RefreshStatus::Active {
            let already_contained = grant.status() == AuthGrantStatus::Compromised;
            let compromised = if already_contained {
                grant
            } else if matches!(
                grant.status(),
                AuthGrantStatus::Active | AuthGrantStatus::Revoked
            ) {
                let closed_at = event
                    .occurred_at()
                    .max(grant.closed_at().unwrap_or(grant.created_at()));
                grant
                    .close(GrantSecurityEventKind::RefreshReuseDetected, closed_at)
                    .map_err(|_| storage_error("refresh reuse grant transition rejected"))?
                    .next()
                    .clone()
            } else {
                return Ok(RefreshExecutionOutcome::Stale);
            };
            for record in state.refresh.values_mut().filter(|record| {
                record.tenant() == stored.tenant()
                    && record.auth_grant_id() == stored.auth_grant_id()
                    && record.lineage_id() == stored.lineage_id()
            }) {
                *record = record
                    .with_status(RefreshStatus::Revoked)
                    .with_grant_status(AuthGrantStatus::Compromised);
            }
            state.grants.insert(compromised.id().clone(), compromised);
            return Ok(if already_contained {
                RefreshExecutionOutcome::AlreadyContained
            } else {
                RefreshExecutionOutcome::ReuseContained
            });
        }

        let Some(rotation) = rotation else {
            return Ok(RefreshExecutionOutcome::Stale);
        };
        if source.status() != RefreshStatus::Active
            || source.auth_grant_status() != AuthGrantStatus::Active
            || grant.status() != AuthGrantStatus::Active
        {
            return Ok(RefreshExecutionOutcome::Stale);
        }
        let new = rotation.new_record().clone();
        if rotation.old_id() != stored.id()
            || new.parent_id() != Some(stored.id())
            || new.lineage_id() != stored.lineage_id()
            || !refresh_grant_binding_matches(&new, &grant)
            || new.auth_grant_status() != AuthGrantStatus::Active
        {
            return Ok(RefreshExecutionOutcome::Stale);
        }
        let decision_time = (*recover(&self.writer_now))
            .max(event.occurred_at())
            .max(new.issued_at());
        if stored.is_expired(decision_time)
            || grant.expires_at() <= decision_time
            || new.expires_at() > stored.expires_at()
        {
            return Ok(RefreshExecutionOutcome::Expired);
        }
        if state.refresh.contains_key(new.id())
            || state.refresh.values().any(|record| {
                record.tenant() == new.tenant() && record.token_hash() == new.token_hash()
            })
        {
            return Err(storage_error("refresh rotation target already exists"));
        }
        state.refresh.insert(
            stored.id().clone(),
            stored.with_status(RefreshStatus::Consumed),
        );
        state.refresh.insert(new.id().clone(), new);
        Ok(RefreshExecutionOutcome::Applied(pending.confirm(
            crate::ports::acknowledge_durable_refresh_commit(),
        )))
    }

    async fn execute_password_change(
        &self,
        _receipt: PasswordChangeProducerReceipt,
        _scope: TenantRepoScope,
        _command: PasswordChangeCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(storage_error(
            "memory grant store does not provide password-change lifecycle",
        ))
    }

    async fn execute_account_status_set(
        &self,
        _receipt: AccountStatusSetProducerReceipt,
        _scope: TenantRepoScope,
        _command: AccountStatusSetCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(storage_error(
            "memory grant store does not provide account-status lifecycle",
        ))
    }

    async fn execute_logout_current(
        &self,
        _receipt: LogoutCurrentProducerReceipt,
        _scope: TenantRepoScope,
        _command: LogoutCurrentCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(storage_error(
            "memory grant store does not provide logout-current lifecycle",
        ))
    }

    async fn execute_logout_all(
        &self,
        _receipt: LogoutAllProducerReceipt,
        _scope: TenantRepoScope,
        _command: LogoutAllCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(storage_error(
            "memory grant store does not provide logout-all lifecycle",
        ))
    }
}

// ---------------------------------------------------------------------------
// InMemPolicyRepo — durable ABAC policy store in-mem 替身（#1588）
// ---------------------------------------------------------------------------

#[cfg(test)]
type PolicyStoreKey = (String, String); // (tenant, policy_id)
#[cfg(test)]
struct StoredPolicy {
    version: PolicyVersion,
    active: Option<Policy>,
}
#[cfg(test)]
type PolicyStore = HashMap<PolicyStoreKey, StoredPolicy>;
#[cfg(test)]
type PolicyStoreGuard<'a> = std::sync::MutexGuard<'a, PolicyStore>;

#[cfg(test)]
impl StoredPolicy {
    fn active(policy: Policy) -> Self {
        Self {
            version: policy.version(),
            active: Some(policy),
        }
    }
}

/// `PolicyRepo` 的 in-memory 替身：仅 test 编译，生产无 allow-all fallback。
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct InMemPolicyRepo {
    policies: Arc<Mutex<PolicyStore>>, // (tenant, policy_id)
    emitted: Arc<Mutex<Vec<CapturedEvent>>>,
    fail_reads: bool,
    fail_writes: bool,
}

#[cfg(test)]
impl InMemPolicyRepo {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn failing_reads() -> Self {
        Self {
            fail_reads: true,
            ..Self::default()
        }
    }

    pub(crate) fn failing_writes() -> Self {
        Self {
            fail_writes: true,
            ..Self::default()
        }
    }

    pub(crate) fn with_policy(self, policy: Policy) -> Self {
        recover(&self.policies).insert(
            (
                policy.tenant().to_string(),
                policy.id().as_str().to_string(),
            ),
            StoredPolicy::active(policy),
        );
        self
    }

    fn key(tenant: TenantId, id: &PolicyId) -> (String, String) {
        (tenant.to_string(), id.as_str().to_string())
    }

    fn read_guard(&self) -> Result<PolicyStoreGuard<'_>, IdentityError> {
        if self.fail_reads {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-policy-read-fail",
            ))));
        }
        Ok(recover(&self.policies))
    }

    /// 已捕获的 policy-updated 事件序列（确定性快照）。
    pub(crate) fn emitted(&self) -> Vec<CapturedEvent> {
        recover(&self.emitted).clone()
    }
}

#[cfg(test)]
impl PolicyRepo for InMemPolicyRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: PolicyId,
    ) -> Result<Option<Policy>, IdentityError> {
        let tenant = scope.tenant();
        Ok(self
            .read_guard()?
            .get(&Self::key(tenant, &id))
            .and_then(|stored| stored.active.clone()))
    }

    async fn list_active(
        &self,
        scope: TenantRepoScope,
        page: PolicyPage,
    ) -> Result<PolicyListResult, IdentityError> {
        let tenant = scope.tenant();
        let limit = usize::from(page.limit.get());
        let after = page.after.as_ref().map(PolicyId::as_str);
        let mut policies = self
            .read_guard()?
            .values()
            .filter_map(|stored| stored.active.as_ref())
            .filter(|policy| {
                policy.tenant() == tenant && after.is_none_or(|a| policy.id().as_str() > a)
            })
            .cloned()
            .collect::<Vec<_>>();
        policies.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));
        let has_more = policies.len() > limit;
        policies.truncate(limit);
        Ok(PolicyListResult { policies, has_more })
    }

    async fn list_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        at: SystemTime,
    ) -> Result<Vec<Policy>, IdentityError> {
        let tenant = tenant_scope.tenant();
        let mut policies = self
            .read_guard()?
            .values()
            .filter_map(|stored| stored.active.as_ref())
            .filter(|policy| {
                policy.tenant() == tenant
                    && policy.route_scope() == &scope
                    && policy.is_effective_at(at)
            })
            .cloned()
            .collect::<Vec<_>>();
        policies.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));
        Ok(policies)
    }
}

#[cfg(test)]
impl PolicyLifecycle for InMemPolicyRepo {
    async fn create_and_emit(
        &self,
        receipt: PoliciesCreateProducerReceipt,
        scope: TenantRepoScope,
        policy: Policy,
        event: ReviewedEvent,
    ) -> Result<Policy, IdentityError> {
        let tenant = scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-policy-cotx-fail",
            ))));
        }
        if policy.tenant() != tenant
            || event.envelope().tenant() != tenant
            || policy.version() != PolicyVersion::first()
        {
            return Err(IdentityError::InvalidPolicy);
        }
        let key = Self::key(tenant, policy.id());
        let mut guard = recover(&self.policies);
        if guard.contains_key(&key) {
            return Err(IdentityError::PolicyAlreadyExists);
        }
        let _authorization = authorize_entry(
            receipt,
            &event,
            generated::event::identity_v1::policy_updated::SPEC.contract(),
        )
        .ok_or(IdentityError::InvalidPolicy)?;
        guard.insert(key, StoredPolicy::active(policy.clone()));
        recover(&self.emitted).push(CapturedEvent::of(&event));
        Ok(policy)
    }

    async fn update_and_emit(
        &self,
        receipt: PoliciesUpdateProducerReceipt,
        scope: TenantRepoScope,
        policy: Policy,
        expected: PolicyVersion,
        event: ReviewedEvent,
    ) -> Result<Policy, IdentityError> {
        let tenant = scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-policy-cotx-fail",
            ))));
        }
        if policy.tenant() != tenant || event.envelope().tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let key = Self::key(tenant, policy.id());
        let mut guard = recover(&self.policies);
        let Some(current) = guard.get_mut(&key) else {
            return Err(IdentityError::PolicyNotFound);
        };
        if current.active.is_none() {
            return Err(IdentityError::PolicyNotFound);
        }
        if current.version != expected {
            return Err(IdentityError::VersionConflict);
        }
        let _authorization = authorize_entry(
            receipt,
            &event,
            generated::event::identity_v1::policy_updated::SPEC.contract(),
        )
        .ok_or(IdentityError::InvalidPolicy)?;
        let next = policy.with_version(expected.next_checked()?);
        current.version = next.version();
        current.active = Some(next.clone());
        recover(&self.emitted).push(CapturedEvent::of(&event));
        Ok(next)
    }

    async fn deactivate_and_emit(
        &self,
        receipt: PoliciesDeactivateProducerReceipt,
        scope: TenantRepoScope,
        id: PolicyId,
        expected: PolicyVersion,
        event: ReviewedEvent,
    ) -> Result<bool, IdentityError> {
        let tenant = scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-policy-cotx-fail",
            ))));
        }
        if event.envelope().tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let key = Self::key(tenant, &id);
        let mut guard = recover(&self.policies);
        let Some(current) = guard.get_mut(&key) else {
            return Ok(false);
        };
        let Some(active) = current.active.as_ref() else {
            return Ok(false);
        };
        if active.version() != expected {
            return Err(IdentityError::VersionConflict);
        }
        let _authorization = authorize_entry(
            receipt,
            &event,
            generated::event::identity_v1::policy_updated::SPEC.contract(),
        )
        .ok_or(IdentityError::InvalidPolicy)?;
        current.version = expected.next_checked()?;
        current.active = None;
        recover(&self.emitted).push(CapturedEvent::of(&event));
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// InMemResourceAttributeRepo — durable resource attribute store / resolver 替身（#1590）
// ---------------------------------------------------------------------------

#[cfg(test)]
#[derive(Clone)]
struct StoredResourceAttribute {
    version: ResourceAttributeVersion,
    active: Option<ResourceAttribute>,
}

#[cfg(test)]
type ResourceAttributeStoreKey = (String, String, String, String, String);

#[cfg(test)]
impl StoredResourceAttribute {
    fn active(attribute: ResourceAttribute) -> Self {
        Self {
            version: attribute.version(),
            active: Some(attribute),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct InMemResourceAttributeRepo {
    attributes: Arc<Mutex<HashMap<ResourceAttributeStoreKey, StoredResourceAttribute>>>,
    fail_reads: bool,
    fail_writes: bool,
}

#[cfg(test)]
impl InMemResourceAttributeRepo {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn failing_reads() -> Self {
        Self {
            fail_reads: true,
            ..Self::default()
        }
    }

    pub(crate) fn failing_writes() -> Self {
        Self {
            fail_writes: true,
            ..Self::default()
        }
    }

    pub(crate) fn with_attribute(self, attribute: ResourceAttribute) -> Self {
        recover(&self.attributes).insert(
            Self::key_from_attribute(&attribute),
            StoredResourceAttribute::active(attribute),
        );
        self
    }

    fn key(
        tenant: TenantId,
        scope: &PolicyRouteScope,
        resource_id: &ResourceAttributeResourceId,
        key: &ResourceAttributeKey,
    ) -> ResourceAttributeStoreKey {
        (
            tenant.to_string(),
            scope.contract_id().to_string(),
            scope.permission().as_str().to_string(),
            resource_id.as_str().to_string(),
            key.as_str().to_string(),
        )
    }

    fn key_from_attribute(
        attribute: &ResourceAttribute,
    ) -> (String, String, String, String, String) {
        Self::key(
            attribute.tenant(),
            attribute.route_scope(),
            attribute.resource_id(),
            attribute.key(),
        )
    }

    fn rebuild_with_version(
        attribute: &ResourceAttribute,
        version: ResourceAttributeVersion,
    ) -> Result<ResourceAttribute, IdentityError> {
        ResourceAttribute::hydrate(
            attribute.tenant(),
            attribute.route_scope().clone(),
            attribute.resource_id().clone(),
            attribute.key().clone(),
            attribute.value().clone(),
            version.get(),
            attribute.effective_from(),
            attribute.effective_until(),
        )
    }
}

#[cfg(test)]
impl ResourceAttributeReadRepo for InMemResourceAttributeRepo {
    async fn resolve_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        required_keys: Vec<ResourceAttributeKey>,
        at: SystemTime,
    ) -> Result<ResourceAttributeResolution, IdentityError> {
        let tenant = tenant_scope.tenant();
        if self.fail_reads {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-resource-attribute-read-fail",
            ))));
        }
        let guard = recover(&self.attributes);
        let mut attrs = Vec::with_capacity(required_keys.len());
        for required in required_keys {
            let store_key = Self::key(tenant, &scope, &resource_id, &required);
            let Some(stored) = guard.get(&store_key) else {
                return Ok(ResourceAttributeResolution::Missing(required));
            };
            let Some(attribute) = stored.active.as_ref() else {
                return Ok(ResourceAttributeResolution::Missing(required));
            };
            if !attribute.is_effective_at(at) {
                return Ok(ResourceAttributeResolution::Stale(required));
            }
            attrs.push(attribute.clone());
        }
        Ok(ResourceAttributeResolution::Known(attrs))
    }
}

#[cfg(test)]
impl ResourceAttributeWriteRepo for InMemResourceAttributeRepo {
    async fn upsert(
        &self,
        scope: TenantRepoScope,
        attribute: ResourceAttribute,
        expected: Option<ResourceAttributeVersion>,
    ) -> Result<ResourceAttribute, IdentityError> {
        let tenant = scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-resource-attribute-write-fail",
            ))));
        }
        if attribute.tenant() != tenant {
            return Err(IdentityError::InvalidPolicy);
        }
        let key = Self::key_from_attribute(&attribute);
        let mut guard = recover(&self.attributes);
        match expected {
            None => {
                if guard.contains_key(&key)
                    || attribute.version() != ResourceAttributeVersion::first()
                {
                    return Err(IdentityError::VersionConflict);
                }
                guard.insert(key, StoredResourceAttribute::active(attribute.clone()));
                Ok(attribute)
            }
            Some(expected) => {
                let Some(stored) = guard.get_mut(&key) else {
                    return Err(IdentityError::VersionConflict);
                };
                let Some(active) = stored.active.as_ref() else {
                    return Err(IdentityError::VersionConflict);
                };
                if active.version() != expected {
                    return Err(IdentityError::VersionConflict);
                }
                let next = Self::rebuild_with_version(&attribute, expected.next_checked()?)?;
                stored.version = next.version();
                stored.active = Some(next.clone());
                Ok(next)
            }
        }
    }

    async fn expire(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        key: ResourceAttributeKey,
        expected: ResourceAttributeVersion,
    ) -> Result<bool, IdentityError> {
        let tenant = tenant_scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-resource-attribute-write-fail",
            ))));
        }
        let store_key = Self::key(tenant, &scope, &resource_id, &key);
        let mut guard = recover(&self.attributes);
        let Some(stored) = guard.get_mut(&store_key) else {
            return Ok(false);
        };
        let Some(active) = stored.active.as_ref() else {
            return Ok(false);
        };
        if active.version() != expected {
            return Err(IdentityError::VersionConflict);
        }
        stored.version = expected.next_checked()?;
        stored.active = None;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// InMemRoleRepo / InMemRoleBindingLifecycle — RBAC 角色仓储 + 绑定生命周期 in-mem 替身（#1190，US5）
// ---------------------------------------------------------------------------

/// `RoleReadRepo` 的 in-memory 替身：保存完整 [`Role`]，供 assign/revoke 校验与列表 handler 测试共用。
#[cfg(test)]
#[derive(Default)]
struct InMemRoleState {
    roles: HashMap<(String, String), Role>, // (tenant, role_id)
    revisions: HashMap<(String, String), u64>,
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct InMemRoleRepo {
    state: Arc<Mutex<InMemRoleState>>,
}

#[cfg(test)]
impl InMemRoleRepo {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 种子：标记 `(tenant, role_id)` 存在。
    pub(crate) fn with_role(self, tenant: TenantId, role_id: &RoleId) -> Self {
        let key = (tenant.to_string(), role_id.as_str().to_string());
        let mut state = recover(&self.state);
        state.roles.insert(
            key.clone(),
            Role::new(role_id.clone(), "seeded".to_string(), vec![]),
        );
        state.revisions.insert(key, 1);
        drop(state);
        self
    }

    /// 种子：保存完整 role（含权限），供 handler/authorizer 测试构造 RBAC baseline。
    pub(crate) fn with_role_entity(self, tenant: TenantId, role: Role) -> Self {
        let key = (tenant.to_string(), role.id().as_str().to_string());
        let mut state = recover(&self.state);
        state.roles.insert(key.clone(), role);
        state.revisions.insert(key, 1);
        drop(state);
        self
    }
}

#[cfg(test)]
impl RoleReadRepo for InMemRoleRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: RoleId,
    ) -> Result<Option<Role>, IdentityError> {
        let tenant = scope.tenant();
        Ok(recover(&self.state)
            .roles
            .get(&(tenant.to_string(), id.as_str().to_string()))
            .cloned())
    }

    async fn list(
        &self,
        scope: TenantRepoScope,
        page: crate::ports::RolePage,
    ) -> Result<crate::ports::RoleListResult, IdentityError> {
        let tenant = scope.tenant();
        let limit = usize::from(page.limit.get());
        let after = page.after.as_ref().map(RoleId::as_str);
        let mut roles = recover(&self.state)
            .roles
            .iter()
            .filter(|((t, id), _)| {
                t == &tenant.to_string() && after.is_none_or(|a| id.as_str() > a)
            })
            .map(|(_, role)| role.clone())
            .collect::<Vec<_>>();
        roles.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));
        let has_more = roles.len() > limit;
        roles.truncate(limit);
        Ok(crate::ports::RoleListResult { roles, has_more })
    }
}

#[cfg(test)]
impl RoleDefinitionLifecycle for InMemRoleRepo {
    async fn create_or_update(
        &self,
        scope: TenantRepoScope,
        actor: RoleMutationActor,
        role: Role,
    ) -> Result<RoleMutationOutcome, IdentityError> {
        if actor.tenant() != scope.tenant() {
            return Err(IdentityError::PermissionDenied);
        }
        let tenant = scope.tenant();
        let key = (tenant.to_string(), role.id().as_str().to_string());
        let mut permissions = role.permission_ids().collect::<Vec<_>>();
        permissions.sort();
        permissions.dedup();
        let canonical = Role::hydrate(role.id().as_str(), role.name(), &permissions)?;
        let mut state = recover(&self.state);
        let changed = state.roles.get(&key).is_none_or(|current| {
            let mut current_permissions = current.permission_ids().collect::<Vec<_>>();
            current_permissions.sort();
            current_permissions.dedup();
            current.name() != canonical.name() || current_permissions != permissions
        });
        let current_revision = state.revisions.get(&key).copied().unwrap_or(0);
        let revision = if changed {
            current_revision.checked_add(1).ok_or_else(|| {
                IdentityError::Storage(Box::new(std::io::Error::other("role revision overflow")))
            })?
        } else {
            current_revision
        };
        if changed {
            state.roles.insert(key.clone(), canonical);
            state.revisions.insert(key, revision);
        }
        let revision = RoleRevision::hydrate(
            i64::try_from(revision).map_err(|error| IdentityError::Storage(Box::new(error)))?,
        )?;
        Ok(RoleMutationOutcome::new(revision, changed))
    }
}

/// 捕获的一条已发事件：`entry`（topic + 幂等键 EventId + payload）+ `envelope`（contract_id / tenant /
/// subject_id）。捕获 `idem_key` 使测试可断言 EventId 独立性（非靠 payload 差异侧证）；捕获 envelope 三元
/// 使测试可断言 contract 绑定、租户 scope、以及 **envelope subject_id = actor opaque id**（非 target，F2）。
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct CapturedEvent {
    pub(crate) topic: String,
    pub(crate) idem_key: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) contract_id: String,
    pub(crate) env_tenant: String,
    pub(crate) subject_id: String,
}

#[cfg(test)]
impl CapturedEvent {
    fn of(event: &ReviewedEvent) -> Self {
        let entry = event.entry();
        let envelope = event.envelope();
        Self {
            topic: entry.topic().as_str().to_string(),
            idem_key: entry.idem_key().as_str().to_string(),
            payload: entry.payload().to_vec(),
            contract_id: envelope.contract().contract_id().to_string(),
            env_tenant: envelope.tenant().to_string(),
            subject_id: envelope.subject_id().as_str().to_string(),
        }
    }
}

/// `RoleBindingLifecycle` 的 in-memory 替身：binding 集合 `(tenant, role_id, subject)` + 捕获已发事件
/// [`CapturedEvent`]（供发布侧 producer 测试断言 emit 一致性）。`fail=true` 模拟 co-tx 写失败
/// （L2 原子性：emit 失败 ⇒ binding 不落、事件不记，both-or-neither）。
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct InMemRoleBindingLifecycle {
    bindings: Arc<Mutex<HashSet<(String, String, String)>>>,
    emitted: Arc<Mutex<Vec<CapturedEvent>>>,
    fail: bool,
}

#[cfg(test)]
impl InMemRoleBindingLifecycle {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 失败模式（模拟 co-tx 写失败，供 L2 原子性测试）。
    pub(crate) fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }

    /// 种子：标记一条 binding 存在（供 revoke 命中测试）。
    pub(crate) fn with_binding(self, tenant: TenantId, role_id: &RoleId, subject: &str) -> Self {
        recover(&self.bindings).insert((
            tenant.to_string(),
            role_id.as_str().to_string(),
            subject.to_string(),
        ));
        self
    }

    /// 当前是否存在该 binding。
    pub(crate) fn has_binding(&self, tenant: TenantId, role_id: &RoleId, subject: &str) -> bool {
        recover(&self.bindings).contains(&(
            tenant.to_string(),
            role_id.as_str().to_string(),
            subject.to_string(),
        ))
    }

    /// 已捕获事件序列 [`CapturedEvent`]（确定性快照）。
    pub(crate) fn emitted(&self) -> Vec<CapturedEvent> {
        recover(&self.emitted).clone()
    }
}

#[cfg(test)]
impl RoleBindingLifecycle for InMemRoleBindingLifecycle {
    async fn assign_and_emit(
        &self,
        receipt: RolesAssignProducerReceipt,
        scope: TenantRepoScope,
        binding: RoleBinding,
        event: ReviewedEvent,
    ) -> Result<(), OutboxEmitError> {
        if scope.tenant() != binding.tenant() {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding assign tenant scope mismatch",
            )));
        }
        if event.envelope().tenant() != scope.tenant() {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding assign envelope tenant scope mismatch",
            )));
        }
        if self.fail {
            // reason: 模拟 co-tx 写失败 ⇒ both-or-neither：binding 不落、事件不记（提前返回）。
            return Err(OutboxEmitError::new(std::io::Error::other(
                "inmem-rbac-cotx-fail",
            )));
        }
        let _authorization = authorize_entry(
            receipt,
            &event,
            generated::event::identity_v1::role_assigned::SPEC.contract(),
        )
        .ok_or_else(|| {
            OutboxEmitError::new(std::io::Error::other(
                "roles-assign producer does not authorize role-assigned",
            ))
        })?;
        recover(&self.bindings).insert((
            binding.tenant().to_string(),
            binding.role_id().as_str().to_string(),
            binding.subject().to_string(),
        ));
        recover(&self.emitted).push(CapturedEvent::of(&event));
        Ok(())
    }

    async fn revoke_and_emit(
        &self,
        receipt: RolesRevokeProducerReceipt,
        scope: TenantRepoScope,
        role_id: RoleId,
        subject: String,
        event: ReviewedEvent,
    ) -> Result<bool, OutboxEmitError> {
        let tenant = scope.tenant();
        if event.envelope().tenant() != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding revoke envelope tenant scope mismatch",
            )));
        }
        if self.fail {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "inmem-rbac-cotx-fail",
            )));
        }
        let key = (
            tenant.to_string(),
            role_id.as_str().to_string(),
            subject.clone(),
        );
        // 仅撤目标 binding；未命中（不存在 / 跨租）→ 不删、不发事件、返回 false（隐藏存在性 + 幂等）。
        let mut bindings = recover(&self.bindings);
        if !bindings.contains(&key) {
            return Ok(false);
        }
        let _authorization = authorize_entry(
            receipt,
            &event,
            generated::event::identity_v1::role_revoked::SPEC.contract(),
        )
        .ok_or_else(|| {
            OutboxEmitError::new(std::io::Error::other(
                "roles-revoke producer does not authorize role-revoked",
            ))
        })?;
        let removed = bindings.remove(&key);
        drop(bindings);
        if removed {
            recover(&self.emitted).push(CapturedEvent::of(&event));
        }
        Ok(removed)
    }
}

#[cfg(test)]
impl RoleBindingReadRepo for InMemRoleBindingLifecycle {
    async fn list_for_subject(
        &self,
        scope: TenantRepoScope,
        subject: String,
    ) -> Result<Vec<RoleBinding>, IdentityError> {
        let tenant = scope.tenant();
        recover(&self.bindings)
            .iter()
            .filter(|(t, _, s)| t == &tenant.to_string() && s == &subject)
            .map(|(_, role_id, s)| RoleBinding::hydrate(s.clone(), role_id, tenant))
            .collect()
    }
}

#[cfg(test)]
impl RefreshTokenStore for InMemAuthGrantStore {
    async fn find_by_hash(
        &self,
        scope: TenantRepoScope,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
        let tenant = scope.tenant();
        Ok(recover(&self.inner)
            .refresh
            .values()
            .find(|r| r.tenant() == tenant && r.token_hash() == &hash)
            .cloned())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        Credential, InMemAuthGrantStore, InMemCredentialRepo, InMemPolicyRepo,
        InMemResourceAttributeRepo, InMemRoleBindingLifecycle, InMemRoleRepo, TenantId, recover,
    };
    use crate::domain::{
        AccountSecurityState, AuthOutcome, IdentityError, LoginIdentifier, Policy, PolicyId,
        PolicyRouteScope, PolicyValue, PolicyVersion, RefreshStatus, RefreshTokenHash,
        RefreshTokenId, RefreshTokenRecord, ResourceAttribute, ResourceAttributeKey,
        ResourceAttributeResolution, ResourceAttributeResourceId, ResourceAttributeVersion, Role,
        RoleBinding, RoleId,
    };
    use crate::ports::{
        AccountSecurityReadRepo, AuthGrantLifecycle, CredentialRepo, IdentitySecurityLifecycle,
        LoginGrantMutation, PolicyLifecycle, PolicyRepo, RefreshExecutionCommand,
        RefreshExecutionOutcome, RefreshTokenStore, ResourceAttributeReadRepo,
        ResourceAttributeWriteRepo, RoleBindingLifecycle, RoleDefinitionLifecycle,
        RoleMutationActor, TenantRepoScope,
    };
    use authn::{
        AuthGrant, AuthGrantId, AuthGrantSnapshot, AuthGrantStatus, AuthnEpoch,
        GrantSecurityEventKind,
    };
    use consistency::IdemKey;
    use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor};
    use eventexec::event::ReviewedEvent;
    use generated::http::identity_v1::{
        login::PRODUCER as LOGIN_PRODUCER, policies_create::PRODUCER as POLICIES_CREATE_PRODUCER,
        policies_deactivate::PRODUCER as POLICIES_DEACTIVATE_PRODUCER,
        refresh::PRODUCER as REFRESH_PRODUCER, roles_assign::PRODUCER as ROLES_ASSIGN_PRODUCER,
        roles_revoke::PRODUCER as ROLES_REVOKE_PRODUCER,
    };
    use httpserve::ProducerMarker;
    use std::time::{Duration, SystemTime};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";
    // canonical user id（audit actor 形态；与登录标识 "alice" 解耦，#1277 F1）。
    const USER_ALICE: &str = "11111111-2222-4333-8444-555555555555";
    // 未种子化的 canonical user id（find_by_user_id 未知主体 → None，#1277 F2）。
    const USER_GHOST: &str = "99999999-8888-4777-8666-555544443333";
    const RESOURCE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant parses")
    }

    fn scope(tenant: TenantId) -> TenantRepoScope {
        TenantRepoScope::for_test(tenant)
    }

    #[tokio::test]
    async fn in_mem_role_identical_concurrent_writes_share_revision_one() {
        let tenant = tid(TENANT_A);
        let repo = InMemRoleRepo::new();
        let role = Role::hydrate(
            "concurrent-role",
            "Concurrent",
            &["identity:role:read".to_owned()],
        )
        .expect("valid role");
        let actor = || {
            RoleMutationActor::for_test_user(
                tenant,
                ids::UserId::parse(USER_ALICE).expect("canonical user"),
                rss_request_context::PrincipalKind::Admin,
            )
            .expect("user-backed actor")
        };

        let (left, right) = tokio::join!(
            repo.create_or_update(scope(tenant), actor(), role.clone()),
            repo.create_or_update(scope(tenant), actor(), role),
        );
        let left = left.expect("left write");
        let right = right.expect("right write");
        assert_eq!(left.revision().get(), 1);
        assert_eq!(right.revision().get(), 1);
        assert_ne!(left.changed(), right.changed());
    }

    fn grant_id(raw: impl AsRef<str>) -> AuthGrantId {
        let digest = secure::digest(raw.as_ref());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        AuthGrantId::hydrate(uuid::Uuid::from_bytes(bytes).hyphenated().to_string())
            .expect("test UUIDv4")
    }

    #[allow(clippy::panic)]
    fn authenticated_state(outcome: AuthOutcome) -> AccountSecurityState {
        match outcome {
            AuthOutcome::Authenticated(state) => state,
            other => panic!("expected authenticated outcome, got {other:?}"),
        }
    }

    fn login_receipt() -> crate::ports::LoginProducerReceipt {
        ProducerMarker::for_test(LOGIN_PRODUCER).into_receipt()
    }

    fn refresh_receipt() -> crate::ports::RefreshProducerReceipt {
        ProducerMarker::for_test(REFRESH_PRODUCER).into_receipt()
    }

    fn policy_create_receipt() -> crate::ports::PoliciesCreateProducerReceipt {
        ProducerMarker::for_test(POLICIES_CREATE_PRODUCER).into_receipt()
    }

    fn policy_deactivate_receipt() -> crate::ports::PoliciesDeactivateProducerReceipt {
        ProducerMarker::for_test(POLICIES_DEACTIVATE_PRODUCER).into_receipt()
    }

    fn role_assign_receipt() -> crate::ports::RolesAssignProducerReceipt {
        ProducerMarker::for_test(ROLES_ASSIGN_PRODUCER).into_receipt()
    }

    fn role_revoke_receipt() -> crate::ports::RolesRevokeProducerReceipt {
        ProducerMarker::for_test(ROLES_REVOKE_PRODUCER).into_receipt()
    }

    fn uid(raw: &str) -> ids::UserId {
        ids::UserId::parse(raw).expect("canonical user id parses")
    }

    fn lid(raw: &str) -> LoginIdentifier {
        LoginIdentifier::new(raw)
    }

    fn raw(password: &str) -> secure::RawPassword {
        secure::RawPassword::new(password.to_owned())
    }

    fn verifies(credential: &Credential, password: &str) -> bool {
        matches!(
            credential
                .verify_password(raw(password))
                .expect("stored test PHC is valid"),
            secure::PasswordVerification::Verified(_)
        )
    }

    fn cred(login: &str, user: &str, password: &str, version: u32, tenant: TenantId) -> Credential {
        Credential::new(
            LoginIdentifier::new(login),
            uid(user),
            tenant,
            secure::PasswordHash::for_test(secure::RawPassword::new(password.to_owned()))
                .expect("hash"),
            version,
        )
    }

    fn epoch(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn make_grant(id: &str, tenant: TenantId) -> AuthGrant {
        let now = epoch(1_000);
        AuthGrant::hydrate(AuthGrantSnapshot {
            id: grant_id(id),
            tenant,
            user_id: uid(USER_ALICE),
            auth_time: now,
            authn_epoch_at_issue: AuthnEpoch::ZERO,
            status: AuthGrantStatus::Active,
            expires_at: now + Duration::from_secs(3_600),
            created_at: now,
            closed_at: None,
            close_reason: None,
        })
        .expect("active grant")
    }

    fn make_initial(
        grant: &AuthGrant,
        id: &str,
        hash: [u8; 32],
        status: RefreshStatus,
    ) -> RefreshTokenRecord {
        let issued = epoch(1_000);
        let record = RefreshTokenRecord::new_initial(
            grant,
            RefreshTokenId::new(id),
            RefreshTokenHash::new(hash),
            issued,
            issued + Duration::from_secs(3_600),
        )
        .expect("initial refresh");
        record.with_status(status)
    }

    fn login_mutation(grant: AuthGrant, refresh: RefreshTokenRecord) -> LoginGrantMutation {
        LoginGrantMutation::new(grant, refresh)
    }

    fn rotation_command(
        source: RefreshTokenRecord,
        grant: AuthGrant,
        new_id: &str,
        new_hash: [u8; 32],
        now: SystemTime,
    ) -> RefreshExecutionCommand {
        let active =
            AccountSecurityState::initial(source.tenant(), source.user_id(), source.issued_at())
                .try_into_active()
                .expect("active account");
        let rotation = source
            .begin_rotation(
                RefreshTokenId::new(new_id),
                RefreshTokenHash::new(new_hash),
                now,
            )
            .expect("valid rotation");
        RefreshExecutionCommand::rotate(source, grant, active, rotation, now)
            .expect("valid refresh command")
    }

    fn policy_id(raw: &str) -> PolicyId {
        PolicyId::parse(raw).expect("valid policy id")
    }

    fn policy(raw: &str, tenant: TenantId) -> Policy {
        Policy::new(policy_id(raw), tenant, Vec::new())
    }

    fn resource_scope() -> PolicyRouteScope {
        PolicyRouteScope::parse("test.contract", "identity:policy:read").expect("resource scope")
    }

    fn resource_id() -> ResourceAttributeResourceId {
        ResourceAttributeResourceId::parse(RESOURCE_ID).expect("resource id")
    }

    fn resource_key(raw: &str) -> ResourceAttributeKey {
        ResourceAttributeKey::parse(raw).expect("resource key")
    }

    fn resource_attribute(
        tenant: TenantId,
        key: ResourceAttributeKey,
        from: u64,
        until: Option<u64>,
    ) -> ResourceAttribute {
        ResourceAttribute::build(
            tenant,
            resource_scope(),
            resource_id(),
            key,
            PolicyValue::new(USER_ALICE),
            epoch(from),
            until.map(epoch),
        )
        .expect("resource attribute")
    }

    async fn session_event_for(tenant: TenantId, event_id: &str) -> ReviewedEvent {
        let payload =
            generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
                occurred_at: 1,
                session_id: uuid::Uuid::from_u128(1),
                subject: USER_ALICE.parse().expect("subject uuid"),
                tenant_id: uuid::Uuid::from_bytes(tenant.octets()),
            };
        generated::event::identity_v1::session_created::emit(
            &eventexec::event::GeneratedEventEncoder,
            payload,
            tenant,
            EnvelopeSubjectId::from_opaque("subject-1").expect("subject"),
            OutboxActor::scoped(
                rss_request_context::PrincipalKind::User,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tenant,
                rss_request_context::RowScope::SelfOnly,
            ),
            IdemKey::parse(event_id).expect("idem key parses"),
        )
        .await
        .expect("test payload encodes")
    }

    async fn dummy_event() -> ReviewedEvent {
        session_event_for(tid(TENANT_A), "evt-1").await
    }

    async fn wrong_event() -> ReviewedEvent {
        let tenant = tid(TENANT_A);
        let payload = generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Published,
            key: "app.test".to_string(),
            occurred_at: 1,
            source_version: None,
            tenant_id: TENANT_A.to_string(),
            version: 1,
        };
        generated::event::settings_v1::emit(
            &eventexec::event::GeneratedEventEncoder,
            payload,
            tenant,
            EnvelopeSubjectId::from_opaque("subject-1").expect("subject"),
            OutboxActor::scoped(
                rss_request_context::PrincipalKind::User,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tenant,
                rss_request_context::RowScope::SelfOnly,
            ),
            IdemKey::parse("evt-wrong-fact").expect("idem key parses"),
        )
        .await
        .expect("test payload encodes")
    }

    async fn policy_event() -> ReviewedEvent {
        let tenant = tid(TENANT_A);
        let payload =
            generated::event::identity_v1::policy_updated::IdentityPolicyUpdatedPayload {
                actor_kind: generated::event::identity_v1::policy_updated::IdentityPolicyUpdatedPayloadActorKind::Admin,
                change_kind: generated::event::identity_v1::policy_updated::IdentityPolicyUpdatedPayloadChangeKind::Created,
                contract_id: "identity.login".to_string(),
                occurred_at: 1,
                permission: "identity:policy:write".to_string(),
                policy_id: "policy-tombstone".to_string(),
                tenant_id: TENANT_A.to_string(),
                updated_by: USER_ALICE.parse().expect("updated-by uuid"),
                version: std::num::NonZeroU32::MIN,
            };
        generated::event::identity_v1::policy_updated::emit(
            &eventexec::event::GeneratedEventEncoder,
            payload,
            tenant,
            EnvelopeSubjectId::from_opaque("policy-tombstone").expect("subject"),
            OutboxActor::scoped(
                rss_request_context::PrincipalKind::Admin,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tenant,
                rss_request_context::RowScope::Tenant,
            ),
            IdemKey::parse("evt-policy").expect("idem key parses"),
        )
        .await
        .expect("test payload encodes")
    }

    async fn role_assigned_event(tenant: TenantId) -> ReviewedEvent {
        let payload = generated::event::identity_v1::role_assigned::IdentityRoleAssignedPayload {
            actor_kind: generated::event::identity_v1::role_assigned::IdentityRoleAssignedPayloadActorKind::Admin,
            assigned_by: USER_ALICE.parse().expect("actor uuid"),
            occurred_at: 1,
            role_id: "role-admin".to_string(),
            subject: "user-1".to_string(),
            tenant_id: tenant.to_string(),
        };
        generated::event::identity_v1::role_assigned::emit(
            &eventexec::event::GeneratedEventEncoder,
            payload,
            tenant,
            EnvelopeSubjectId::from_opaque("actor-1").expect("subject"),
            OutboxActor::scoped(
                rss_request_context::PrincipalKind::Admin,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tenant,
                rss_request_context::RowScope::Tenant,
            ),
            IdemKey::parse("evt-role-assigned").expect("idem key"),
        )
        .await
        .expect("role-assigned event")
    }

    async fn role_revoked_event(tenant: TenantId) -> ReviewedEvent {
        let payload = generated::event::identity_v1::role_revoked::IdentityRoleRevokedPayload {
            actor_kind: generated::event::identity_v1::role_revoked::IdentityRoleRevokedPayloadActorKind::Admin,
            occurred_at: 1,
            revoked_by: USER_ALICE.parse().expect("actor uuid"),
            role_id: "role-admin".to_string(),
            subject: "user-1".to_string(),
            tenant_id: tenant.to_string(),
        };
        generated::event::identity_v1::role_revoked::emit(
            &eventexec::event::GeneratedEventEncoder,
            payload,
            tenant,
            EnvelopeSubjectId::from_opaque("actor-1").expect("subject"),
            OutboxActor::scoped(
                rss_request_context::PrincipalKind::Admin,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tenant,
                rss_request_context::RowScope::Tenant,
            ),
            IdemKey::parse("evt-role-revoked").expect("idem key"),
        )
        .await
        .expect("role-revoked event")
    }

    // ---------------------------------------------------------------------------
    // InMemCredentialRepo tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn insert_then_find_roundtrip() {
        let repo = InMemCredentialRepo::new();
        let t = tid(TENANT_A);
        // insert key 派生自 credential（F2，无独立 tenant 参）。
        repo.insert(scope(t), cred("alice", USER_ALICE, "pw", 1, t))
            .await
            .expect("insert");
        let found = repo
            .find_by_user_id(scope(t), uid(USER_ALICE))
            .await
            .expect("find")
            .expect("some");
        assert_eq!(found.version(), 1);
        assert_eq!(
            found.user_id(),
            uid(USER_ALICE),
            "canonical subject 随凭据存取"
        );
        assert!(
            repo.find_by_user_id(scope(t), uid(USER_GHOST))
                .await
                .expect("find")
                .is_none()
        );
    }

    #[tokio::test]
    async fn insert_rejects_tenant_scope_mismatch_without_mutating_state() {
        let repo = InMemCredentialRepo::new();
        let credential_tenant = tid(TENANT_A);

        assert!(matches!(
            repo.insert(
                scope(tid(TENANT_B)),
                cred("alice", USER_ALICE, "original", 1, credential_tenant),
            )
            .await,
            Err(IdentityError::Storage(_))
        ));

        let inner = recover(&repo.inner);
        assert!(inner.creds.is_empty());
        assert!(inner.security.is_empty());
    }

    #[tokio::test]
    async fn insert_rejects_second_login_for_same_user_without_mutating_state() {
        let repo = InMemCredentialRepo::new();
        let tenant = tid(TENANT_A);
        let user = uid(USER_ALICE);
        repo.insert(
            scope(tenant),
            cred("alice", USER_ALICE, "original", 1, tenant),
        )
        .await
        .expect("insert original");
        let before_security = AccountSecurityReadRepo::find(&repo, scope(tenant), user)
            .await
            .expect("read security")
            .expect("security");

        assert!(matches!(
            repo.insert(
                scope(tenant),
                cred("alice-alias", USER_ALICE, "replacement", 2, tenant),
            )
            .await,
            Err(IdentityError::Storage(_))
        ));

        let inner = recover(&repo.inner);
        assert_eq!(inner.creds.len(), 1, "failed insert adds no credential");
        let original = inner
            .creds
            .get(&(tenant, lid("alice")))
            .expect("original remains");
        assert!(verifies(original, "original"));
        assert!(!inner.creds.contains_key(&(tenant, lid("alice-alias"))));
        assert_eq!(
            inner.security.get(&(tenant, user)),
            Some(&before_security),
            "failed insert leaves account security unchanged"
        );
    }

    #[tokio::test]
    async fn insert_rejects_existing_tenant_login_without_mutating_state() {
        let repo = InMemCredentialRepo::new();
        let tenant = tid(TENANT_A);
        let original_user = uid(USER_ALICE);
        let rejected_user = uid(USER_GHOST);
        repo.insert(
            scope(tenant),
            cred("alice", USER_ALICE, "original", 1, tenant),
        )
        .await
        .expect("insert original");
        let before_security = AccountSecurityReadRepo::find(&repo, scope(tenant), original_user)
            .await
            .expect("read security")
            .expect("security");

        assert!(matches!(
            repo.insert(
                scope(tenant),
                cred("alice", USER_GHOST, "replacement", 2, tenant),
            )
            .await,
            Err(IdentityError::Storage(_))
        ));

        let inner = recover(&repo.inner);
        assert_eq!(inner.creds.len(), 1, "duplicate insert adds no credential");
        let original = inner
            .creds
            .get(&(tenant, lid("alice")))
            .expect("original remains");
        assert_eq!(original.user_id(), original_user);
        assert!(verifies(original, "original"));
        assert_eq!(
            inner.security.get(&(tenant, original_user)),
            Some(&before_security),
            "duplicate insert leaves original security state unchanged"
        );
        assert!(
            !inner.security.contains_key(&(tenant, rejected_user)),
            "duplicate insert must not initialize rejected user's security state"
        );
    }

    #[tokio::test]
    async fn authenticate_known_wrong_and_unknown_outcomes() {
        let repo = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(USER_ALICE),
            "correct",
            tid(TENANT_A),
        )
        .expect("seed");
        let t = tid(TENANT_A);
        let now = epoch(1_000);
        // 已知 + Active + 正确 → Authenticated(AccountSecurityState)。
        let authenticated = authenticated_state(
            repo.authenticate(scope(t), lid("alice"), raw("correct"), now)
                .await
                .expect("auth"),
        );
        assert_eq!(authenticated.user_id(), uid(USER_ALICE));
        // 已知 + 错 → RejectedKnown。
        assert_eq!(
            repo.authenticate(scope(t), lid("alice"), raw("wrong"), now)
                .await
                .expect("auth"),
            AuthOutcome::RejectedKnown
        );
        // 查无主体 → RejectedUnknown（当前档 KDF 仍跑，F3；不 panic）。
        assert_eq!(
            repo.authenticate(scope(t), lid("ghost"), raw("correct"), now)
                .await
                .expect("auth"),
            AuthOutcome::RejectedUnknown
        );
    }

    #[tokio::test]
    async fn authenticate_upgrades_weak_phc_without_bumping_credential_version() {
        let repo = InMemCredentialRepo::new();
        let tenant = tid(TENANT_A);
        let weak = secure::PasswordHash::for_test_with_params(raw("correct"), 1_024, 1, 1)
            .expect("weak test PHC");
        let before = weak.as_str().to_owned();
        repo.insert(
            scope(tenant),
            Credential::new(lid("alice"), uid(USER_ALICE), tenant, weak, 7),
        )
        .await
        .expect("insert weak credential");

        let authenticated = authenticated_state(
            repo.authenticate(scope(tenant), lid("alice"), raw("correct"), epoch(1_000))
                .await
                .expect("authenticate"),
        );
        assert_eq!(authenticated.user_id(), uid(USER_ALICE));
        let upgraded = repo
            .find_by_user_id(scope(tenant), uid(USER_ALICE))
            .await
            .expect("find")
            .expect("credential");
        assert_eq!(
            upgraded.version(),
            7,
            "transparent rehash is not a logical change"
        );
        assert_ne!(upgraded.password_hash().as_str(), before);
        assert!(!upgraded.password_hash().needs_rehash().expect("valid PHC"));
        assert!(verifies(&upgraded, "correct"));
    }

    #[tokio::test]
    async fn stale_rehash_replacement_is_rejected_without_changing_the_winner() {
        let repo = InMemCredentialRepo::new();
        let tenant = tid(TENANT_A);
        let weak = secure::PasswordHash::for_test_with_params(raw("correct"), 1_024, 1, 1)
            .expect("weak test PHC");
        let expected = weak.clone();
        repo.insert(
            scope(tenant),
            Credential::new(lid("alice"), uid(USER_ALICE), tenant, weak, 11),
        )
        .await
        .expect("insert weak credential");

        let first = secure::PasswordHash::for_test(raw("correct")).expect("first replacement");
        let winner = first.as_str().to_owned();
        let stale = secure::PasswordHash::for_test(raw("correct")).expect("stale replacement");
        {
            let mut inner = recover(&repo.inner);
            let current = inner
                .creds
                .get_mut(&(tenant, lid("alice")))
                .expect("stored credential");
            assert!(current.replace_hash_if_unchanged(&expected, first));
            assert!(!current.replace_hash_if_unchanged(&expected, stale));
        }

        let upgraded = repo
            .find_by_user_id(scope(tenant), uid(USER_ALICE))
            .await
            .expect("find")
            .expect("credential");
        assert_eq!(upgraded.version(), 11);
        assert_eq!(upgraded.password_hash().as_str(), winner);
        assert!(!upgraded.password_hash().needs_rehash().expect("valid PHC"));
        assert!(verifies(&upgraded, "correct"));
    }

    #[tokio::test]
    async fn authenticate_unknown_subject_does_not_create_lockout() {
        // F2：未知主体登录失败**不建** lockout 态——不可预置任意用户名锁定、不经枚举撑大 lockout 表。
        let repo = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(USER_ALICE),
            "correct",
            tid(TENANT_A),
        )
        .expect("seed");
        let t = tid(TENANT_A);
        let now = epoch(1_000);
        for i in 0..50 {
            assert_eq!(
                repo.authenticate(scope(t), lid(&format!("ghost-{i}")), raw("x"), now)
                    .await
                    .expect("auth"),
                AuthOutcome::RejectedUnknown
            );
        }
        assert_eq!(
            repo.lockout_len(),
            0,
            "未知主体失败不建锁定态（lockout 表不随枚举增长，F2）"
        );
        // 对比：已知主体失败才建恰一条。
        repo.authenticate(scope(t), lid("alice"), raw("wrong"), now)
            .await
            .expect("auth");
        assert_eq!(repo.lockout_len(), 1, "已知主体失败建恰一条 lockout 态");
    }

    #[tokio::test]
    async fn cross_tenant_find_authenticate_and_lockout_fail_closed() {
        let repo = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(USER_ALICE),
            "correct",
            tid(TENANT_A),
        )
        .expect("seed");
        let a = tid(TENANT_A);
        let other = tid(TENANT_B);
        let t0 = epoch(1_000);
        // 跨租赁查找 → None（不泄露存在性），authenticate → RejectedUnknown（跨租即未知，不建锁）。
        assert!(
            repo.find_by_user_id(scope(other), uid(USER_ALICE))
                .await
                .expect("find")
                .is_none()
        );
        assert_eq!(
            repo.authenticate(scope(other), lid("alice"), raw("correct"), t0)
                .await
                .expect("auth"),
            AuthOutcome::RejectedUnknown
        );
        assert_eq!(repo.lockout_len(), 0, "跨租未知主体失败不建锁（F2 + 隔离）");
        // 在 TENANT_A 把 alice 临时锁定；跨租仍按未知主体拒绝。
        for i in 1..=5 {
            repo.authenticate(
                scope(a),
                lid("alice"),
                raw("wrong"),
                t0 + Duration::from_secs(i),
            )
            .await
            .expect("auth");
        }
        assert_eq!(
            repo.authenticate(
                scope(a),
                lid("alice"),
                raw("correct"),
                t0 + Duration::from_secs(6),
            )
            .await
            .expect("locked auth"),
            AuthOutcome::RejectedKnown
        );
        assert_eq!(
            repo.authenticate(
                scope(other),
                lid("alice"),
                raw("correct"),
                t0 + Duration::from_secs(6),
            )
            .await
            .expect("cross-tenant auth"),
            AuthOutcome::RejectedUnknown
        );
    }

    #[tokio::test]
    async fn policy_delete_leaves_tombstone_and_rejects_recreate() {
        let repo = InMemPolicyRepo::new();
        let tenant = tid(TENANT_A);
        let id = policy_id("policy-tombstone");

        repo.create_and_emit(
            policy_create_receipt(),
            scope(tenant),
            policy("policy-tombstone", tenant),
            policy_event().await,
        )
        .await
        .expect("create policy");
        assert!(
            repo.deactivate_and_emit(
                policy_deactivate_receipt(),
                scope(tenant),
                id.clone(),
                PolicyVersion::first(),
                policy_event().await,
            )
            .await
            .expect("delete policy"),
            "first delete succeeds"
        );
        assert!(
            repo.find(scope(tenant), id.clone())
                .await
                .expect("find after delete")
                .is_none(),
            "tombstoned policy is not active"
        );

        let recreate = repo
            .create_and_emit(
                policy_create_receipt(),
                scope(tenant),
                policy("policy-tombstone", tenant),
                policy_event().await,
            )
            .await;
        assert!(
            matches!(recreate, Err(IdentityError::PolicyAlreadyExists)),
            "deleted policy id keeps tombstone and rejects recreate, got: {recreate:?}"
        );
        assert!(
            repo.find(scope(tenant), id)
                .await
                .expect("find after rejected recreate")
                .is_none(),
            "rejected recreate must not restore active policy"
        );
    }

    #[tokio::test]
    async fn resource_attribute_resolve_reports_missing_and_stale_explicitly() {
        let tenant = tid(TENANT_A);
        let stale_key = resource_key("resource.stale_owner");
        let repo = InMemResourceAttributeRepo::new().with_attribute(resource_attribute(
            tenant,
            stale_key.clone(),
            0,
            Some(500),
        ));

        let missing = repo
            .resolve_effective(
                scope(tenant),
                resource_scope(),
                resource_id(),
                vec![resource_key("resource.owner")],
                epoch(1_000),
            )
            .await
            .expect("resolve missing");
        assert!(
            matches!(missing, ResourceAttributeResolution::Missing(key) if key.as_str() == "resource.owner")
        );

        let stale = repo
            .resolve_effective(
                scope(tenant),
                resource_scope(),
                resource_id(),
                vec![stale_key],
                epoch(1_000),
            )
            .await
            .expect("resolve stale");
        assert!(
            matches!(stale, ResourceAttributeResolution::Stale(key) if key.as_str() == "resource.stale_owner")
        );
    }

    #[tokio::test]
    async fn resource_attribute_upsert_and_expire_use_cas_versions() {
        let tenant = tid(TENANT_A);
        let key = resource_key("resource.owner");
        let repo = InMemResourceAttributeRepo::new();

        let created = repo
            .upsert(
                scope(tenant),
                resource_attribute(tenant, key.clone(), 0, None),
                None,
            )
            .await
            .expect("create resource attribute");
        assert_eq!(created.version(), ResourceAttributeVersion::first());

        let conflict = repo
            .upsert(
                scope(tenant),
                resource_attribute(tenant, key.clone(), 0, None),
                Some(ResourceAttributeVersion::new(99).expect("version")),
            )
            .await;
        assert!(matches!(conflict, Err(IdentityError::VersionConflict)));

        let updated = repo
            .upsert(
                scope(tenant),
                resource_attribute(tenant, key.clone(), 0, None),
                Some(created.version()),
            )
            .await
            .expect("update resource attribute");
        assert_eq!(updated.version().get(), 2);

        let expired = repo
            .expire(
                scope(tenant),
                resource_scope(),
                resource_id(),
                key.clone(),
                updated.version(),
            )
            .await
            .expect("expire resource attribute");
        assert!(expired);

        let after_expire = repo
            .resolve_effective(
                scope(tenant),
                resource_scope(),
                resource_id(),
                vec![key],
                epoch(1),
            )
            .await
            .expect("resolve after expire");
        assert!(matches!(
            after_expire,
            ResourceAttributeResolution::Missing(_)
        ));

        let failed_write = InMemResourceAttributeRepo::failing_writes()
            .upsert(
                scope(tenant),
                resource_attribute(tenant, resource_key("resource.fail"), 0, None),
                None,
            )
            .await;
        assert!(matches!(failed_write, Err(IdentityError::Storage(_))));
    }

    #[tokio::test]
    async fn authenticate_missing_security_state_fails_storage_without_repair_or_lockout_effect() {
        let tenant = tid(TENANT_A);
        let user = uid(USER_ALICE);
        let repo = InMemCredentialRepo::with_seed_credential("alice", user, "correct", tenant)
            .expect("seed");
        recover(&repo.inner).security.remove(&(tenant, user));

        assert!(matches!(
            repo.authenticate(scope(tenant), lid("alice"), raw("correct"), epoch(1_000))
                .await,
            Err(IdentityError::Storage(_))
        ));
        assert_eq!(repo.lockout_len(), 0);
        assert!(
            AccountSecurityReadRepo::find(&repo, scope(tenant), user)
                .await
                .expect("read security")
                .is_none(),
            "authenticate must never auto-repair a missing durable state"
        );
    }

    #[tokio::test]
    async fn authenticate_wrong_password_accumulates_then_locks() {
        // 原子 RMW（F1）：连续 authenticate(错) 经仓储持久化累计——每次读已存计数（非外部 stale 副本）。
        let repo = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(USER_ALICE),
            "correct",
            tid(TENANT_A),
        )
        .expect("seed");
        let t = tid(TENANT_A);
        let t0 = epoch(1_000);
        for i in 1..5 {
            assert_eq!(
                repo.authenticate(
                    scope(t),
                    lid("alice"),
                    raw("wrong"),
                    t0 + Duration::from_secs(i)
                )
                .await
                .expect("auth"),
                AuthOutcome::RejectedKnown,
                "第 {i} 次失败"
            );
            assert_eq!(repo.lockout_len(), 1, "失败状态保持单行");
        }
        // 第 5 次（窗口内）→ 达阈值锁定。
        repo.authenticate(
            scope(t),
            lid("alice"),
            raw("wrong"),
            t0 + Duration::from_secs(5),
        )
        .await
        .expect("auth");
        assert_eq!(
            repo.authenticate(
                scope(t),
                lid("alice"),
                raw("correct"),
                t0 + Duration::from_secs(6),
            )
            .await
            .expect("locked auth"),
            AuthOutcome::RejectedKnown
        );
    }

    #[tokio::test]
    async fn lockout_lazy_unlocks_after_ttl() {
        let repo = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(USER_ALICE),
            "correct",
            tid(TENANT_A),
        )
        .expect("seed");
        let t = tid(TENANT_A);
        let t0 = epoch(1_000);
        for i in 1..=5 {
            repo.authenticate(
                scope(t),
                lid("alice"),
                raw("wrong"),
                t0 + Duration::from_secs(i),
            )
            .await
            .expect("auth");
        }
        let lock_at = t0 + Duration::from_secs(5);
        let lock_ttl = Duration::from_secs(15 * 60);
        // TTL 内即使密码正确也仍拒绝。
        assert_eq!(
            repo.authenticate(
                scope(t),
                lid("alice"),
                raw("correct"),
                lock_at + lock_ttl - Duration::from_secs(1),
            )
            .await
            .expect("locked auth"),
            AuthOutcome::RejectedKnown
        );
        // authenticate 在 TTL 后原子 lazy-unlock，正确密码可登录。
        let unlocked = authenticated_state(
            repo.authenticate(
                scope(t),
                lid("alice"),
                raw("correct"),
                lock_at + lock_ttl + Duration::from_secs(1),
            )
            .await
            .expect("unlocked auth"),
        );
        assert_eq!(unlocked.user_id(), uid(USER_ALICE));
        // 解锁后再失败从 1 重计（不沿用旧计数）→ RejectedKnown、未锁。
        let after = lock_at + lock_ttl + Duration::from_secs(2);
        assert_eq!(
            repo.authenticate(scope(t), lid("alice"), raw("wrong"), after)
                .await
                .expect("auth"),
            AuthOutcome::RejectedKnown
        );
        assert_eq!(repo.lockout_len(), 1);
    }

    #[tokio::test]
    async fn authenticate_success_clears_lockout() {
        // 成功登录原子清零该主体失败计数（authenticate 内折叠 clear——不再需独立 clear_lockout 端口）。
        let repo = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(USER_ALICE),
            "correct",
            tid(TENANT_A),
        )
        .expect("seed");
        let t = tid(TENANT_A);
        let t0 = epoch(1_000);
        // 4 次错（未达阈值 5，未锁）→ lockout 态存在。
        for i in 1..=4 {
            assert_eq!(
                repo.authenticate(
                    scope(t),
                    lid("alice"),
                    raw("wrong"),
                    t0 + Duration::from_secs(i)
                )
                .await
                .expect("auth"),
                AuthOutcome::RejectedKnown
            );
        }
        assert_eq!(repo.lockout_len(), 1, "失败累积建一条 lockout 态");
        // 正确密码 → Authenticated + 原子清除 lockout 态。
        let authenticated = authenticated_state(
            repo.authenticate(
                scope(t),
                lid("alice"),
                raw("correct"),
                t0 + Duration::from_secs(5),
            )
            .await
            .expect("auth"),
        );
        assert_eq!(authenticated.user_id(), uid(USER_ALICE));
        assert_eq!(
            repo.lockout_len(),
            0,
            "成功登录清除该主体 lockout 态（计数重置）"
        );
    }

    // ---------------------------------------------------------------------------
    // Unified AuthGrant/refresh store tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn auth_grant_store_rejects_wrong_reviewed_fact_before_mutation() {
        let tenant = tid(TENANT_A);
        for (suffix, event) in [("wrong", wrong_event().await)] {
            let repo = InMemAuthGrantStore::new();
            let grant_label = format!("grant-{suffix}-fact");
            let grant = make_grant(&grant_label, tenant);
            let refresh = make_initial(
                &grant,
                &format!("refresh-{suffix}"),
                [1; 32],
                RefreshStatus::Active,
            );
            let result = repo
                .persist_login_grant(
                    login_receipt(),
                    scope(tenant),
                    login_mutation(grant, refresh),
                    event,
                )
                .await;

            assert!(result.is_err(), "{suffix} generated fact must fail closed");
            assert!(
                repo.find_active(
                    scope(tenant),
                    grant_id(&grant_label),
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .expect("find")
                .is_none(),
                "{suffix} generated fact must fail before grant mutation"
            );
            assert_eq!(repo.refresh_len(), 0);
        }
    }

    #[tokio::test]
    async fn policy_lifecycle_rejects_wrong_reviewed_fact_before_mutation() {
        let tenant = tid(TENANT_A);
        for (suffix, event) in [("wrong", wrong_event().await)] {
            let repo = InMemPolicyRepo::new();
            let raw_id = format!("policy-{suffix}-fact");
            let id = policy_id(&raw_id);
            let result = repo
                .create_and_emit(
                    policy_create_receipt(),
                    scope(tenant),
                    policy(&raw_id, tenant),
                    event,
                )
                .await;

            assert!(result.is_err(), "{suffix} generated fact must fail closed");
            assert!(
                repo.find(scope(tenant), id).await.expect("find").is_none(),
                "{suffix} generated fact must fail before policy mutation"
            );
            assert!(
                repo.emitted().is_empty(),
                "{suffix} generated fact must fail before policy emit"
            );
        }
    }

    #[tokio::test]
    async fn role_binding_lifecycle_rejects_wrong_reviewed_fact_before_mutation() {
        let tenant = tid(TENANT_A);
        for (suffix, event) in [("wrong", wrong_event().await)] {
            let lifecycle = InMemRoleBindingLifecycle::new();
            let role_id = RoleId::parse(&format!("role-{suffix}-fact")).expect("role id");
            let result = lifecycle
                .assign_and_emit(
                    role_assign_receipt(),
                    scope(tenant),
                    RoleBinding::new("user-1", role_id.clone(), tenant),
                    event,
                )
                .await;

            assert!(result.is_err(), "{suffix} generated fact must fail closed");
            assert!(
                !lifecycle.has_binding(tenant, &role_id, "user-1"),
                "{suffix} generated fact must fail before binding mutation"
            );
            assert!(
                lifecycle.emitted().is_empty(),
                "{suffix} generated fact must fail before binding emit"
            );
        }
    }

    #[tokio::test]
    async fn lifecycle_persist_then_find_roundtrip() {
        let repo = InMemAuthGrantStore::new();
        let ta = tid(TENANT_A);
        let grant = make_grant("grant-001", ta);
        let refresh = make_initial(&grant, "refresh-001", [1; 32], RefreshStatus::Active);
        let _persisted = repo
            .persist_login_grant(
                login_receipt(),
                scope(ta),
                login_mutation(grant, refresh),
                dummy_event().await,
            )
            .await
            .expect("persist ok");
        let found = repo
            .find_active(scope(ta), grant_id("grant-001"), SystemTime::UNIX_EPOCH)
            .await
            .expect("find ok");
        assert!(found.is_some(), "persist 后应能找到 grant");
        assert_eq!(found.expect("some").id(), &grant_id("grant-001"));
        assert!(
            repo.find_by_hash(scope(ta), RefreshTokenHash::new([1; 32]))
                .await
                .expect("refresh find")
                .is_some()
        );
    }

    #[tokio::test]
    async fn lifecycle_cross_tenant_find_returns_none() {
        let repo = InMemAuthGrantStore::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        let grant = make_grant("grant-004", ta);
        let refresh = make_initial(&grant, "refresh-004", [4; 32], RefreshStatus::Active);
        let _persisted = repo
            .persist_login_grant(
                login_receipt(),
                scope(ta),
                login_mutation(grant, refresh),
                dummy_event().await,
            )
            .await
            .expect("persist ok");
        let found = repo
            .find_active(scope(tb), grant_id("grant-004"), SystemTime::UNIX_EPOCH)
            .await
            .expect("find ok");
        assert!(found.is_none(), "跨租查找应返回 None");
    }

    #[tokio::test]
    async fn role_binding_lifecycle_rejects_assign_envelope_tenant_mismatch() {
        let lifecycle = InMemRoleBindingLifecycle::default();
        let tenant = tid(TENANT_A);
        let role_id = RoleId::parse("role-admin").expect("role id");
        let result = lifecycle
            .assign_and_emit(
                role_assign_receipt(),
                scope(tenant),
                RoleBinding::new("user-1", role_id.clone(), tenant),
                role_assigned_event(tid(TENANT_B)).await,
            )
            .await;

        assert!(result.is_err(), "assign envelope mismatch must fail closed");
        assert!(
            !lifecycle.has_binding(tenant, &role_id, "user-1"),
            "mismatch must not mutate bindings"
        );
        assert!(lifecycle.emitted().is_empty(), "mismatch must not emit");
    }

    #[tokio::test]
    async fn role_binding_lifecycle_rejects_revoke_envelope_tenant_mismatch() {
        let tenant = tid(TENANT_A);
        let role_id = RoleId::parse("role-admin").expect("role id");
        let lifecycle =
            InMemRoleBindingLifecycle::default().with_binding(tenant, &role_id, "user-1");
        let result = lifecycle
            .revoke_and_emit(
                role_revoke_receipt(),
                scope(tenant),
                role_id.clone(),
                "user-1".to_string(),
                role_revoked_event(tid(TENANT_B)).await,
            )
            .await;

        assert!(result.is_err(), "revoke envelope mismatch must fail closed");
        assert!(
            lifecycle.has_binding(tenant, &role_id, "user-1"),
            "mismatch must leave existing binding intact"
        );
        assert!(lifecycle.emitted().is_empty(), "mismatch must not emit");
    }

    // ---------------------------------------------------------------------------
    // Unified refresh behavior
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn in_mem_refresh_rotation_then_reuse_is_contained_atomically() {
        let store = InMemAuthGrantStore::new();
        let ta = tid(TENANT_A);
        let old_hash = [0x11u8; 32];
        let new_hash = [0x12u8; 32];
        let old_id = "aaaaaaaa-0011-4000-8000-000000000011";
        let grant = make_grant("grant-rt-m1", ta);
        let old_rec = make_initial(&grant, old_id, old_hash, RefreshStatus::Active);
        let _persisted = store
            .persist_login_grant(
                login_receipt(),
                scope(ta),
                login_mutation(grant.clone(), old_rec.clone()),
                dummy_event().await,
            )
            .await
            .expect("persist");
        let issued = epoch(1_001);
        let first = rotation_command(
            old_rec.clone(),
            grant.clone(),
            "aaaaaaaa-0012-4000-8000-000000000011",
            [0x10; 32],
            issued,
        );
        let first_outcome = store
            .execute_refresh(refresh_receipt(), scope(ta), first)
            .await
            .expect("first rotate");
        assert!(matches!(first_outcome, RefreshExecutionOutcome::Applied(_)));
        let rotation = rotation_command(
            old_rec.clone(),
            grant,
            "aaaaaaaa-0012-4000-8000-000000000012",
            new_hash,
            issued,
        );
        let result = store
            .execute_refresh(refresh_receipt(), scope(ta), rotation)
            .await
            .expect("rotate ok");
        assert!(matches!(result, RefreshExecutionOutcome::ReuseContained));

        // The replay's proposed child is never written.
        let new_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(new_hash))
            .await
            .expect("find ok");
        assert!(new_found.is_none(), "CAS miss 时 new 不应写入");

        // The winning family and grant are fenced in the same critical section.
        let old_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(old_hash))
            .await
            .expect("find ok");
        assert_eq!(
            old_found.expect("old exists").status(),
            RefreshStatus::Revoked,
            "reuse containment revokes the whole family"
        );
        assert_eq!(
            store
                .grant_snapshot(&grant_id("grant-rt-m1"))
                .expect("grant")
                .status(),
            AuthGrantStatus::Compromised
        );
        assert!(
            store
                .refresh_family_snapshot(&grant_id("grant-rt-m1"))
                .iter()
                .all(|record| {
                    record.status() == RefreshStatus::Revoked
                        && record.auth_grant_status() == AuthGrantStatus::Compromised
                }),
            "reuse containment fences every record in the family"
        );
    }

    #[tokio::test]
    async fn in_mem_refresh_repeated_reuse_is_already_contained() {
        let store = InMemAuthGrantStore::new();
        let ta = tid(TENANT_A);
        let old_hash = [0x13u8; 32];
        let new_hash = [0x14u8; 32];
        let old_id = "aaaaaaaa-0013-4000-8000-000000000013";
        let issued = epoch(1_001);
        let grant = make_grant("grant-rt-m2", ta);
        let old_rec = make_initial(&grant, old_id, old_hash, RefreshStatus::Active);
        let _persisted = store
            .persist_login_grant(
                login_receipt(),
                scope(ta),
                login_mutation(grant.clone(), old_rec.clone()),
                dummy_event().await,
            )
            .await
            .expect("persist");

        // First rotation consumes the source and persists one child.
        let rotation1 = rotation_command(
            old_rec.clone(),
            grant.clone(),
            "aaaaaaaa-0014-4000-8000-000000000014",
            new_hash,
            issued,
        );
        assert!(matches!(
            store
                .execute_refresh(refresh_receipt(), scope(ta), rotation1)
                .await
                .expect("rotate ok"),
            RefreshExecutionOutcome::Applied(_)
        ));

        // Reuse contains once; subsequent evidence is idempotent.
        let rotation2 = rotation_command(
            old_rec.clone(),
            grant.clone(),
            "aaaaaaaa-0015-4000-8000-000000000015",
            [0x15u8; 32],
            issued,
        );
        assert!(matches!(
            store
                .execute_refresh(refresh_receipt(), scope(ta), rotation2)
                .await
                .expect("contain reuse"),
            RefreshExecutionOutcome::ReuseContained
        ));
        let repeated = RefreshExecutionCommand::contain_reuse(
            old_rec.with_status(RefreshStatus::Consumed),
            issued,
        )
        .expect("non-active reuse command");
        assert!(matches!(
            store
                .execute_refresh(refresh_receipt(), scope(ta), repeated)
                .await
                .expect("repeat containment"),
            RefreshExecutionOutcome::AlreadyContained
        ));

        // Neither reuse attempt persists its proposed child.
        let old_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(old_hash))
            .await
            .expect("find ok");
        assert_eq!(
            old_found.expect("old exists").status(),
            RefreshStatus::Revoked,
            "reuse containment revokes old"
        );
        let third_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new([0x15u8; 32]))
            .await
            .expect("find ok");
        assert!(third_found.is_none(), "二次 CAS miss 时 new 不应写入");
    }

    #[tokio::test]
    async fn in_mem_rotate_rechecks_expiry_at_the_writer_boundary() {
        let store = InMemAuthGrantStore::new();
        let tenant = tid(TENANT_A);
        let old_hash = [0x31; 32];
        let new_hash = [0x32; 32];
        let grant = make_grant("grant-writer-expiry", tenant);
        let old = make_initial(
            &grant,
            "aaaaaaaa-0031-4000-8000-000000000031",
            old_hash,
            RefreshStatus::Active,
        );
        let _persisted = store
            .persist_login_grant(
                login_receipt(),
                scope(tenant),
                login_mutation(grant.clone(), old.clone()),
                dummy_event().await,
            )
            .await
            .expect("persist");
        let rotation = rotation_command(
            old.clone(),
            grant.clone(),
            "aaaaaaaa-0032-4000-8000-000000000032",
            new_hash,
            epoch(1_001),
        );

        store.set_writer_now(grant.expires_at());
        assert!(matches!(
            store
                .execute_refresh(refresh_receipt(), scope(tenant), rotation)
                .await
                .expect("writer fence"),
            RefreshExecutionOutcome::Expired
        ));
        assert_eq!(
            store
                .find_by_hash(scope(tenant), RefreshTokenHash::new(old_hash))
                .await
                .expect("old lookup")
                .expect("old remains")
                .status(),
            RefreshStatus::Active,
            "expiry fence must not consume the old bearer"
        );
        assert!(
            store
                .find_by_hash(scope(tenant), RefreshTokenHash::new(new_hash))
                .await
                .expect("new lookup")
                .is_none(),
            "expiry fence must not persist a new bearer"
        );
    }

    #[tokio::test]
    async fn in_mem_refresh_reuse_promotes_revoked_grant_to_compromised() {
        let store = InMemAuthGrantStore::new();
        let ta = tid(TENANT_A);
        let hash_a = [0x15u8; 32];
        let lineage_str = "aaaaaaaa-0015-4000-8000-000000000015";

        let grant = make_grant("grant-rt-m3", ta);
        let rec_a = make_initial(&grant, lineage_str, hash_a, RefreshStatus::Active);
        let _persisted = store
            .persist_login_grant(
                login_receipt(),
                scope(ta),
                login_mutation(grant.clone(), rec_a.clone()),
                dummy_event().await,
            )
            .await
            .expect("persist");
        let revoked = grant
            .close(GrantSecurityEventKind::LogoutCurrent, epoch(1_001))
            .expect("revoke")
            .next()
            .clone();
        let revoked_refresh = rec_a
            .with_status(RefreshStatus::Revoked)
            .with_grant_status(AuthGrantStatus::Revoked);
        {
            let mut state = recover(&store.inner);
            state.grants.insert(revoked.id().clone(), revoked);
            state
                .refresh
                .insert(revoked_refresh.id().clone(), revoked_refresh.clone());
        }
        let command = RefreshExecutionCommand::contain_reuse(revoked_refresh, epoch(1_002))
            .expect("revoked refresh is reuse evidence");
        assert!(matches!(
            store
                .execute_refresh(refresh_receipt(), scope(ta), command)
                .await
                .expect("contain"),
            RefreshExecutionOutcome::ReuseContained
        ));
        assert_eq!(
            store
                .grant_snapshot(&grant_id("grant-rt-m3"))
                .expect("grant")
                .status(),
            AuthGrantStatus::Compromised
        );
        let found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(hash_a))
            .await
            .expect("find")
            .expect("refresh");
        assert_eq!(found.status(), RefreshStatus::Revoked);
        assert_eq!(found.auth_grant_status(), AuthGrantStatus::Compromised);
    }

    // ── RT M4：find_by_hash 跨租 → None（anti-vacuity：同租 → Some）────────────────

    #[tokio::test]
    async fn in_mem_find_by_hash_cross_tenant_returns_none() {
        let store = InMemAuthGrantStore::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        let hash_a = [0x16u8; 32];

        let grant = make_grant("grant-rt-m4", ta);
        let rec_a = make_initial(
            &grant,
            "aaaaaaaa-0016-4000-8000-000000000016",
            hash_a,
            RefreshStatus::Active,
        );
        let _persisted = store
            .persist_login_grant(
                login_receipt(),
                scope(ta),
                login_mutation(grant, rec_a),
                dummy_event().await,
            )
            .await
            .expect("persist");

        // anti-vacuity：tenant A 自查 → Some
        let found_a = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(hash_a))
            .await
            .expect("find ok");
        assert!(
            found_a.is_some(),
            "tenant A 应能查到自己的记录（anti-vacuity）"
        );

        // 跨租：tenant B 查 → None
        let found_b = store
            .find_by_hash(scope(tb), RefreshTokenHash::new(hash_a))
            .await
            .expect("find ok");
        assert!(found_b.is_none(), "跨租 find_by_hash 应返回 None");
    }
}
