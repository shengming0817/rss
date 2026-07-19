//! in-memory 仓储实现（域内 / 域形 DI port 的 test / seed-login 替身）。
//!
//! - [`InMemCredentialRepo`]：`CredentialRepo` 域形 DI port 的 in-mem 替身（哈希凭据 + 锁定态持久化），PR3。
//! - [`InMemSessionLifecycle`]：`SessionLifecycle` 域形 DI port 的 in-mem 替身（co-tx 创建即写 store + 软撤销
//!   标记 + 跨租隔离查询），合并原 `InMemSessionRepo`（#1278）；`#[cfg(test)]` 门控（见其文档）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::domain::{
    AccountLockout, AccountSecurityState, AccountStatus, AuthOutcome, Credential, IdentityError,
    LoginIdentifier,
};
use crate::ports::{
    AccountSecurityLifecycle, AccountSecurityMutation, AccountSecurityReadRepo, CredentialRepo,
    PasswordChangeMutation, TenantRepoScope,
};
use vocab::TenantId;

// 会话生命周期 in-mem 替身（[`InMemSessionLifecycle`]）仅 test 构建编译：with_seed_credential 改注入 lifecycle
// （不再自建空 session store），journeys 用 adapters/memory 的 `MemSessionLifecycle`——故 `seed-login` 非 test
// 构建无消费者（`#[cfg(test)]` 防 dead_code，#1278）。其依赖的 Arc / 会话实体 / 端口 / outbox 类型同门控。
#[cfg(test)]
use crate::domain::{Session, SessionId};
#[cfg(test)]
use crate::ports::{LoginProducerReceipt, SessionLifecycle, SessionLogoutMutation};
#[cfg(test)]
use consistency::EventEntry;
#[cfg(test)]
use diport::{OutboxEmitError, OutboxEnvelopeParts};
#[cfg(test)]
fn authorize_entry<M>(
    receipt: httpserve::ProducerAssuranceReceipt<M>,
    entry: &EventEntry,
    envelope: &OutboxEnvelopeParts,
    expected_contract: vocab::ContractBinding,
) -> Option<httpserve::ProducerAuthorization<M>> {
    let fact = entry.generated_fact()?;
    if *envelope.contract() != fact.contract() {
        return None;
    }
    receipt.authorize(fact, expected_contract)
}

// RefreshTokenStore in-mem 替身（test/seed-login 门控）：seed-login 供 journey/demo 登录首发 token 落库（#1252）。
#[cfg(any(test, feature = "seed-login"))]
use crate::domain::{RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord};
#[cfg(any(test, feature = "seed-login"))]
use crate::ports::RefreshTokenStore;

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
    RoleBindingReadRepo, RoleReadRepo, RoleWriteRepo, RolesAssignProducerReceipt,
    RolesRevokeProducerReceipt,
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

    async fn save(
        &self,
        scope: TenantRepoScope,
        credential: Credential,
    ) -> Result<(), IdentityError> {
        if scope.tenant() != credential.tenant() {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential save tenant scope mismatch",
            ))));
        }
        let key = Self::cred_key(&credential);
        let mut inner = recover(&self.inner);
        if let Some(existing) = inner.creds.get(&key)
            && existing.user_id() != credential.user_id()
        {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential identity rebind is forbidden",
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
        inner.creds.insert(key, credential);
        Ok(())
    }

    async fn apply_password_change(
        &self,
        scope: TenantRepoScope,
        mutation: PasswordChangeMutation,
    ) -> Result<(), IdentityError> {
        let (expected, next, _observation) = mutation.into_parts();
        if scope.tenant() != next.tenant() {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "credential bump tenant scope mismatch",
            ))));
        }
        // key 派生自 next（F2：错位不可表达，无需 debug_assert）。
        let key = Self::cred_key(&next);
        let mut inner = recover(&self.inner);
        match inner.creds.get(&key).map(Credential::version) {
            None => Err(IdentityError::CredentialNotFound),
            Some(v) if v != expected => Err(IdentityError::VersionConflict),
            Some(_) => {
                inner.creds.insert(key, next);
                Ok(())
            }
        }
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

impl AccountSecurityLifecycle for InMemCredentialRepo {
    async fn apply_transition(
        &self,
        scope: TenantRepoScope,
        mutation: AccountSecurityMutation,
    ) -> Result<AccountSecurityState, IdentityError> {
        let (expected, next) = mutation.into_parts();
        if scope.tenant() != next.tenant() {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "account security transition tenant scope mismatch",
            ))));
        }
        let mut inner = recover(&self.inner);
        let key = (scope.tenant(), next.user_id());
        match inner.security.get(&key) {
            Some(current) if current == &expected => {
                inner.security.insert(key, next.clone());
                Ok(next)
            }
            _ => Err(IdentityError::VersionConflict),
        }
    }
}

// ---------------------------------------------------------------------------
// InMemSessionLifecycle — SessionLifecycle 域形 DI port 的 in-mem 替身（合并原 InMemSessionRepo，#1278）
// ---------------------------------------------------------------------------

/// `SessionLifecycle` 的 in-memory 替身：单一 `Arc<Mutex<HashMap>>` store 承载**创建（co-tx）/ 查询 /
/// 软撤销**——合并原分立的 `InMemSessionRepo` + 注入式 UoW（#1278：login 写入 与 logout 撤销/查询同源，
/// 「两端口异 store」从类型层不可表达）。
///
/// - `persist_session_and_emit`（创建）：把 `session` 直插共享 store（`revoked = false`）。in-mem 无 durable
///   事务，`entry`/`envelope` 不落库（同 `adapters/memory` 的 `MemSessionLifecycle`：demo/test 无 outbox 持久化
///   载体，消费侧从 payload 解码；真实 co-tx both-or-neither 由 postgres `PgSessionLifecycle` 的
///   OUTBOX-COTX-SESSION-01 守）。
/// - `logout`（软撤销）：设 `revoked = true`，不删除记录（幂等：重复 / 未知 logout 仍 Ok）。
/// - 跨租隔离：`find` 过滤 `s.tenant() == tenant`（跨租 → None）；`logout` 跨租 no-op（不报错、不撤销）。
///
/// 内部 `Arc<Mutex<..>>`（`&self` + 内部可变；锁仅同步持有、**不跨 `.await`** ⇒ future 仍 `Send`）；
/// `Arc` ⇒ clone 共享同一存储——测试侧持一克隆、`LoginService` 持另一克隆，可观测经 service login 写入 →
/// logout 软撤销的**同源**效果（application.rs `CapturingSessionLifecycle` 即复用本类型承载 store）。
///
/// **`#[cfg(test)]`**：with_seed_credential 改注入 lifecycle（journeys 注 `MemSessionLifecycle`），故
/// `seed-login` 非 test 构建无本类型消费者——仅本 crate 单测 + application.rs 测试替身用（防 dead_code，#1278）。
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct InMemSessionLifecycle {
    // bool = revoked（软撤销标记）
    sessions: Arc<Mutex<HashMap<SessionId, (Session, bool)>>>,
}

#[cfg(test)]
impl InMemSessionLifecycle {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl SessionLifecycle for InMemSessionLifecycle {
    async fn persist_session_and_emit(
        &self,
        receipt: LoginProducerReceipt,
        scope: TenantRepoScope,
        session: Session,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        if scope.tenant() != session.tenant() {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "session persist tenant scope mismatch",
            )));
        }
        let _authorization = authorize_entry(
            receipt,
            &entry,
            &envelope,
            generated::event::identity_v1::session_created::SPEC.contract(),
        )
        .ok_or_else(|| {
            OutboxEmitError::new(std::io::Error::other(
                "login producer does not authorize session-created",
            ))
        })?;
        // reason: in-mem 替身无 durable 事务 / outbox 载体——创建即把 session 直插共享 store（revoked=false）；
        // entry/envelope 不落库（同 MemSessionLifecycle；真实 co-tx 原子性由 PgSessionLifecycle 守）。
        recover(&self.sessions).insert(session.id().clone(), (session, false));
        Ok(())
    }

    async fn find(
        &self,
        scope: TenantRepoScope,
        session_id: SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let tenant = scope.tenant();
        Ok(recover(&self.sessions)
            .get(&session_id)
            .filter(|(s, revoked)| !*revoked && s.tenant() == tenant) // 跨租/已撤销 → None
            .map(|(s, _)| s.clone()))
    }

    async fn logout(
        &self,
        scope: TenantRepoScope,
        mutation: SessionLogoutMutation,
    ) -> Result<(), IdentityError> {
        let (session_id, _observation) = mutation.into_parts();
        let tenant = scope.tenant();
        if let Some(entry) = recover(&self.sessions).get_mut(&session_id)
            && entry.0.tenant() == tenant
        {
            entry.1 = true; // 跨租 no-op；幂等
        }
        Ok(())
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
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError> {
        let tenant = scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-policy-cotx-fail",
            ))));
        }
        if policy.tenant() != tenant
            || envelope.tenant() != tenant
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
            &entry,
            &envelope,
            generated::event::identity_v1::policy_updated::SPEC.contract(),
        )
        .ok_or(IdentityError::InvalidPolicy)?;
        guard.insert(key, StoredPolicy::active(policy.clone()));
        recover(&self.emitted).push(CapturedEvent::of(&entry, &envelope));
        Ok(policy)
    }

    async fn update_and_emit(
        &self,
        receipt: PoliciesUpdateProducerReceipt,
        scope: TenantRepoScope,
        policy: Policy,
        expected: PolicyVersion,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError> {
        let tenant = scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-policy-cotx-fail",
            ))));
        }
        if policy.tenant() != tenant || envelope.tenant() != tenant {
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
            &entry,
            &envelope,
            generated::event::identity_v1::policy_updated::SPEC.contract(),
        )
        .ok_or(IdentityError::InvalidPolicy)?;
        let next = policy.with_version(expected.next_checked()?);
        current.version = next.version();
        current.active = Some(next.clone());
        recover(&self.emitted).push(CapturedEvent::of(&entry, &envelope));
        Ok(next)
    }

    async fn deactivate_and_emit(
        &self,
        receipt: PoliciesDeactivateProducerReceipt,
        scope: TenantRepoScope,
        id: PolicyId,
        expected: PolicyVersion,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, IdentityError> {
        let tenant = scope.tenant();
        if self.fail_writes {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "inmem-policy-cotx-fail",
            ))));
        }
        if envelope.tenant() != tenant {
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
            &entry,
            &envelope,
            generated::event::identity_v1::policy_updated::SPEC.contract(),
        )
        .ok_or(IdentityError::InvalidPolicy)?;
        current.version = expected.next_checked()?;
        current.active = None;
        recover(&self.emitted).push(CapturedEvent::of(&entry, &envelope));
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
#[derive(Clone, Default)]
pub(crate) struct InMemRoleRepo {
    roles: Arc<Mutex<HashMap<(String, String), Role>>>, // (tenant, role_id)
}

#[cfg(test)]
impl InMemRoleRepo {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 种子：标记 `(tenant, role_id)` 存在。
    pub(crate) fn with_role(self, tenant: TenantId, role_id: &RoleId) -> Self {
        recover(&self.roles).insert(
            (tenant.to_string(), role_id.as_str().to_string()),
            Role::new(role_id.clone(), "seeded".to_string(), vec![]),
        );
        self
    }

    /// 种子：保存完整 role（含权限），供 handler/authorizer 测试构造 RBAC baseline。
    pub(crate) fn with_role_entity(self, tenant: TenantId, role: Role) -> Self {
        recover(&self.roles).insert((tenant.to_string(), role.id().as_str().to_string()), role);
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
        Ok(recover(&self.roles)
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
        let mut roles = recover(&self.roles)
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
impl RoleWriteRepo for InMemRoleRepo {
    async fn save(&self, scope: TenantRepoScope, role: Role) -> Result<(), IdentityError> {
        let tenant = scope.tenant();
        recover(&self.roles).insert((tenant.to_string(), role.id().as_str().to_string()), role);
        Ok(())
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
    fn of(entry: &EventEntry, envelope: &OutboxEnvelopeParts) -> Self {
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
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        if scope.tenant() != binding.tenant() {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "role binding assign tenant scope mismatch",
            )));
        }
        if envelope.tenant() != scope.tenant() {
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
            &entry,
            &envelope,
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
        recover(&self.emitted).push(CapturedEvent::of(&entry, &envelope));
        Ok(())
    }

    async fn revoke_and_emit(
        &self,
        receipt: RolesRevokeProducerReceipt,
        scope: TenantRepoScope,
        role_id: RoleId,
        subject: String,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, OutboxEmitError> {
        let tenant = scope.tenant();
        if envelope.tenant() != tenant {
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
            &entry,
            &envelope,
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
            recover(&self.emitted).push(CapturedEvent::of(&entry, &envelope));
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

// ---------------------------------------------------------------------------
// InMemRefreshTokenStore — RefreshTokenStore 域形 DI port 的 in-mem 替身（#1325）
// ---------------------------------------------------------------------------

/// `RefreshTokenStore` 的 in-memory 替身：`Arc<Mutex<HashMap<RefreshTokenId, RefreshTokenRecord>>>`。
///
/// - `insert`：按 `record.id()` 插入。
/// - `find_by_hash`：线性扫描，匹配 `token_hash == hash && tenant == 入参 tenant`（跨租 fail-closed）。
/// - `rotate`（原子 CAS）：锁内查 `old_id`；若存在且 `status==Active && tenant` 匹配 ⇒ 标 `Consumed` + 插入
///   `new`，返回 [`RefreshRotationOutcome::Applied`]；否则返回
///   [`RefreshRotationOutcome::Replay`]（不写 new）。
/// - `revoke_lineage`：锁内把所有 `lineage_id()==入参 && tenant` 匹配的记录置 `Revoked`（幂等）。
///
/// 内部 `Arc<Mutex<..>>`（`&self` + 内部可变；锁仅同步持有、**不跨 `.await`** ⇒ future 仍 `Send`）；
/// `Arc` ⇒ clone 共享同一 store（`RefreshService` 测试中两个 service 实例共享）。
///
/// **`#[cfg(any(test, feature = "seed-login"))]`**：本 crate 单测 + journey/demo 登录首发 token 落库
/// 消费（#1252，经 [`crate::seed_refresh_service`]）；生产 postgres adapter 承载真实持久化（防 dead_code）。
#[cfg(any(test, feature = "seed-login"))]
#[derive(Clone, Default)]
pub(crate) struct InMemRefreshTokenStore {
    records: Arc<Mutex<std::collections::HashMap<RefreshTokenId, RefreshTokenRecord>>>,
}

#[cfg(any(test, feature = "seed-login"))]
impl InMemRefreshTokenStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        recover(&self.records).len()
    }
}

#[cfg(any(test, feature = "seed-login"))]
impl RefreshTokenStore for InMemRefreshTokenStore {
    async fn insert(
        &self,
        scope: TenantRepoScope,
        record: RefreshTokenRecord,
    ) -> Result<(), crate::domain::IdentityError> {
        if scope.tenant() != record.tenant() {
            return Err(crate::domain::IdentityError::Storage(Box::new(
                std::io::Error::other("refresh insert tenant scope mismatch"),
            )));
        }
        recover(&self.records).insert(record.id().clone(), record);
        Ok(())
    }

    async fn find_by_hash(
        &self,
        scope: TenantRepoScope,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, crate::domain::IdentityError> {
        let tenant = scope.tenant();
        // reason: in-mem 替身（test 门控）规模小，O(n) 扫可接受；生产 postgres adapter 须 btree 索引。
        Ok(recover(&self.records)
            .values()
            .find(|r| r.tenant() == tenant && r.token_hash() == &hash)
            .cloned())
    }

    async fn rotate(
        &self,
        scope: TenantRepoScope,
        mutation: crate::ports::RefreshRotationMutation,
    ) -> Result<crate::RefreshRotationOutcome, crate::domain::IdentityError> {
        let (rotation, _observation) = mutation.into_parts();
        // sealed 命令：tenant 从 new record 派生（= 源 record tenant），无独立 tenant 入参可错位（#284 F2）。
        let old_id = rotation.old_id().clone();
        let new = rotation.new_record().clone();
        let tenant = new.tenant();
        if scope.tenant() != tenant {
            return Err(crate::domain::IdentityError::Storage(Box::new(
                std::io::Error::other("refresh rotate tenant scope mismatch"),
            )));
        }
        let mut guard = recover(&self.records);
        // CAS：找 old_id，若 Active + tenant 匹配 ⇒ 消费 + 写 new；否则 false（不写 new）。
        match guard.get(&old_id) {
            Some(rec) if rec.status() == RefreshStatus::Active && rec.tenant() == tenant => {
                let consumed = rec.with_status(RefreshStatus::Consumed);
                guard.insert(old_id, consumed);
                guard.insert(new.id().clone(), new);
                Ok(crate::RefreshRotationOutcome::Applied)
            }
            _ => Ok(crate::RefreshRotationOutcome::Replay),
        }
    }

    async fn revoke_lineage(
        &self,
        scope: TenantRepoScope,
        lineage_id: RefreshTokenId,
    ) -> Result<(), crate::domain::IdentityError> {
        let tenant = scope.tenant();
        // 幂等：锁内把所有同 lineage_id + tenant 的记录置 Revoked。
        let mut guard = recover(&self.records);
        let to_revoke: Vec<RefreshTokenId> = guard
            .values()
            .filter(|r| r.lineage_id() == &lineage_id && r.tenant() == tenant)
            .map(|r| r.id().clone())
            .collect();
        for id in to_revoke {
            if let Some(rec) = guard.get(&id) {
                let revoked = rec.with_status(RefreshStatus::Revoked);
                guard.insert(id, revoked);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        Credential, InMemCredentialRepo, InMemPolicyRepo, InMemResourceAttributeRepo,
        InMemRoleBindingLifecycle, InMemSessionLifecycle, TenantId, recover,
    };
    use crate::domain::{
        AccountSecurityState, AccountStatus, AttributeValue, AuthOutcome, IdentityError,
        LoginIdentifier, Policy, PolicyId, PolicyRouteScope, PolicyVersion, ResourceAttribute,
        ResourceAttributeKey, ResourceAttributeResolution, ResourceAttributeResourceId,
        ResourceAttributeVersion, RoleBinding, RoleId, Session, SessionId,
    };
    use crate::ports::{
        AccountSecurityLifecycle, AccountSecurityReadRepo, CredentialRepo, PasswordChangeMutation,
        PolicyLifecycle, PolicyRepo, ResourceAttributeReadRepo, ResourceAttributeWriteRepo,
        RoleBindingLifecycle, SessionLifecycle, SessionLogoutMutation, TenantRepoScope,
    };
    use consistency::{EventEntry, EventTopic, IdemKey, OutboxPayload};
    use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEnvelopeParts};
    use generated::http::identity_v1::{
        login::PRODUCER as LOGIN_PRODUCER, policies_create::PRODUCER as POLICIES_CREATE_PRODUCER,
        policies_deactivate::PRODUCER as POLICIES_DEACTIVATE_PRODUCER,
        roles_assign::PRODUCER as ROLES_ASSIGN_PRODUCER,
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

    fn make_session(sid: &str, tenant: TenantId) -> Session {
        let now = epoch(1_000);
        // subject = canonical user id（与 F1 一致：session.subject 是 ids::UserId hyphenated UUID，非登录标识）。
        Session::new(
            SessionId::new(sid),
            USER_ALICE,
            tenant,
            now + Duration::from_secs(3_600),
            now,
        )
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
            AttributeValue::new(USER_ALICE),
            epoch(from),
            until.map(epoch),
        )
        .expect("resource attribute")
    }

    // co-tx generated entry fixture shared by the in-memory producer conformance tests.
    fn dummy_entry() -> EventEntry {
        let payload =
            generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
                occurred_at: 1,
                session_id: "session-test".to_string(),
                subject: USER_ALICE.parse().expect("subject uuid"),
                tenant_id: TENANT_A.to_string(),
            };
        EventEntry::from_generated_payload(
            &payload,
            IdemKey::parse("evt-1").expect("idem key parses"),
        )
        .expect("test payload encodes")
    }

    fn missing_fact_entry() -> EventEntry {
        EventEntry::new(
            EventTopic::parse("identity.session-created").expect("topic parses"),
            IdemKey::parse("evt-missing-fact").expect("idem key parses"),
            OutboxPayload::from_reviewed_event_bytes(b"{}".to_vec()),
        )
    }

    fn wrong_fact_entry() -> EventEntry {
        let payload = generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Published,
            key: "app.test".to_string(),
            occurred_at: 1,
            source_version: None,
            tenant_id: TENANT_A.to_string(),
            version: 1,
        };
        EventEntry::from_generated_payload(
            &payload,
            IdemKey::parse("evt-wrong-fact").expect("idem key parses"),
        )
        .expect("test payload encodes")
    }

    fn dummy_envelope() -> OutboxEnvelopeParts {
        dummy_envelope_for(tid(TENANT_A))
    }

    fn dummy_envelope_for(tenant: TenantId) -> OutboxEnvelopeParts {
        OutboxEnvelopeParts::new(
            generated::event::identity_v1::session_created::CONTRACT,
            tenant,
            EnvelopeSubjectId::from_opaque("subject-1").expect("subject"),
            OutboxActor::scoped(
                vocab::PrincipalKind::User,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tenant,
                vocab::ScopedTenant::SelfOnly,
            ),
        )
    }

    fn policy_entry() -> EventEntry {
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
        EventEntry::from_generated_payload(
            &payload,
            IdemKey::parse("evt-policy").expect("idem key parses"),
        )
        .expect("test payload encodes")
    }

    fn policy_envelope() -> OutboxEnvelopeParts {
        let tenant = tid(TENANT_A);
        OutboxEnvelopeParts::new(
            generated::event::identity_v1::policy_updated::CONTRACT,
            tenant,
            EnvelopeSubjectId::from_opaque("policy-tombstone").expect("subject"),
            OutboxActor::scoped(
                vocab::PrincipalKind::Admin,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tenant,
                vocab::ScopedTenant::Tenant,
            ),
        )
    }

    // ---------------------------------------------------------------------------
    // InMemCredentialRepo tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn save_then_find_roundtrip() {
        let repo = InMemCredentialRepo::new();
        let t = tid(TENANT_A);
        // save key 派生自 credential（F2，无独立 tenant 参）。
        repo.save(scope(t), cred("alice", USER_ALICE, "pw", 1, t))
            .await
            .expect("save");
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
    async fn save_rejects_second_login_for_same_user_without_mutating_state() {
        let repo = InMemCredentialRepo::new();
        let tenant = tid(TENANT_A);
        let user = uid(USER_ALICE);
        repo.save(
            scope(tenant),
            cred("alice", USER_ALICE, "original", 1, tenant),
        )
        .await
        .expect("save original");
        let before_security = AccountSecurityReadRepo::find(&repo, scope(tenant), user)
            .await
            .expect("read security")
            .expect("security");

        assert!(matches!(
            repo.save(
                scope(tenant),
                cred("alice-alias", USER_ALICE, "replacement", 2, tenant),
            )
            .await,
            Err(IdentityError::Storage(_))
        ));

        let inner = recover(&repo.inner);
        assert_eq!(inner.creds.len(), 1, "failed save adds no credential");
        let original = inner
            .creds
            .get(&(tenant, lid("alice")))
            .expect("original remains");
        assert!(verifies(original, "original"));
        assert!(!inner.creds.contains_key(&(tenant, lid("alice-alias"))));
        assert_eq!(
            inner.security.get(&(tenant, user)),
            Some(&before_security),
            "failed save leaves account security unchanged"
        );
    }

    #[tokio::test]
    async fn full_snapshot_cas_cannot_restore_a_deactivated_row_from_forged_hydration() {
        let tenant = tid(TENANT_A);
        let user = uid(USER_ALICE);
        let repo = InMemCredentialRepo::with_seed_credential("alice", user, "correct", tenant)
            .expect("seed");
        let active = AccountSecurityReadRepo::find(&repo, scope(tenant), user)
            .await
            .expect("read")
            .expect("state");
        let deactivated = AccountSecurityLifecycle::apply_transition(
            &repo,
            scope(tenant),
            active
                .transition(AccountStatus::Deactivated, epoch(10))
                .expect("deactivate"),
        )
        .await
        .expect("persist deactivation");

        // A caller can hydrate a state from storage-facing primitives, but cannot use a fabricated
        // non-terminal snapshot with the same version to recover the terminal durable row.
        let forged = AccountSecurityState::try_from(crate::AccountSecuritySnapshot {
            tenant,
            user_id: user,
            status: AccountStatus::Suspended,
            authn_epoch: deactivated.authn_epoch().get(),
            version: deactivated.version().get(),
            status_changed_at: deactivated.status_changed_at(),
            updated_at: deactivated.updated_at(),
        })
        .expect("syntactically valid forged row");
        let result = AccountSecurityLifecycle::apply_transition(
            &repo,
            scope(tenant),
            forged
                .transition(AccountStatus::Active, epoch(11))
                .expect("suspended may transition active"),
        )
        .await;
        assert!(matches!(result, Err(IdentityError::VersionConflict)));
        assert_eq!(
            AccountSecurityReadRepo::find(&repo, scope(tenant), user)
                .await
                .expect("read")
                .expect("state"),
            deactivated
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
        repo.save(
            scope(tenant),
            Credential::new(lid("alice"), uid(USER_ALICE), tenant, weak, 7),
        )
        .await
        .expect("save weak credential");

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
        repo.save(
            scope(tenant),
            Credential::new(lid("alice"), uid(USER_ALICE), tenant, weak, 11),
        )
        .await
        .expect("save weak credential");

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
    async fn cross_tenant_password_change_isolated() {
        let a = tid(TENANT_A);
        let other = tid(TENANT_B);
        let repo = InMemCredentialRepo::new();
        repo.save(scope(a), cred("alice", USER_ALICE, "pw", 1, a))
            .await
            .expect("save");
        // 跨租 bump：next 在 TENANT_B（key 派生自 next）→ 查无 → CredentialNotFound，不动 TENANT_A。
        let res = repo
            .apply_password_change(
                scope(other),
                PasswordChangeMutation::for_test(1, cred("alice", USER_ALICE, "pw2", 2, other)),
            )
            .await;
        assert!(matches!(res, Err(IdentityError::CredentialNotFound)));
        let still = repo
            .find_by_user_id(scope(a), uid(USER_ALICE))
            .await
            .expect("find")
            .expect("some");
        assert_eq!(still.version(), 1);
        assert!(verifies(&still, "pw"));
    }

    #[tokio::test]
    async fn password_change_cas_hit_miss_and_unknown() {
        let repo = InMemCredentialRepo::new();
        let t = tid(TENANT_A);
        repo.save(scope(t), cred("alice", USER_ALICE, "pw", 1, t))
            .await
            .expect("save");
        // 期望版本不匹配 → VersionConflict（key 派生自 next）。
        let conflict = repo
            .apply_password_change(
                scope(t),
                PasswordChangeMutation::for_test(99, cred("alice", USER_ALICE, "pw2", 2, t)),
            )
            .await;
        assert!(matches!(conflict, Err(IdentityError::VersionConflict)));
        // 期望版本命中 → 替换。
        repo.apply_password_change(
            scope(t),
            PasswordChangeMutation::for_test(1, cred("alice", USER_ALICE, "pw2", 2, t)),
        )
        .await
        .expect("cas hit");
        let found = repo
            .find_by_user_id(scope(t), uid(USER_ALICE))
            .await
            .expect("find")
            .expect("some");
        assert_eq!(found.version(), 2);
        assert!(verifies(&found, "pw2"));
        // 查无凭据 → CredentialNotFound。
        let missing = repo
            .apply_password_change(
                scope(t),
                PasswordChangeMutation::for_test(1, cred("ghost", USER_ALICE, "x", 1, t)),
            )
            .await;
        assert!(matches!(missing, Err(IdentityError::CredentialNotFound)));
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
            policy_entry(),
            policy_envelope(),
        )
        .await
        .expect("create policy");
        assert!(
            repo.deactivate_and_emit(
                policy_deactivate_receipt(),
                scope(tenant),
                id.clone(),
                PolicyVersion::first(),
                policy_entry(),
                policy_envelope(),
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
                policy_entry(),
                policy_envelope(),
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
    async fn authenticate_covers_every_durable_status_and_password_result_without_lockout_coupling()
    {
        for status in [
            AccountStatus::Active,
            AccountStatus::Suspended,
            AccountStatus::Locked,
            AccountStatus::Deactivated,
        ] {
            for (password, correct) in [("correct", true), ("wrong", false)] {
                let tenant = tid(TENANT_A);
                let user = uid(USER_ALICE);
                let repo =
                    InMemCredentialRepo::with_seed_credential("alice", user, "correct", tenant)
                        .expect("seed");
                if status != AccountStatus::Active {
                    let state = AccountSecurityReadRepo::find(&repo, scope(tenant), user)
                        .await
                        .expect("read security")
                        .expect("security state");
                    let mutation = state
                        .transition(status, epoch(1_001))
                        .expect("active may enter every non-active state");
                    AccountSecurityLifecycle::apply_transition(&repo, scope(tenant), mutation)
                        .await
                        .expect("persist lifecycle state");
                }

                let outcome = repo
                    .authenticate(scope(tenant), lid("alice"), raw(password), epoch(1_002))
                    .await
                    .expect("authenticate");
                if status == AccountStatus::Active && correct {
                    assert!(matches!(
                        outcome,
                        AuthOutcome::Authenticated(ref state)
                            if state.status() == AccountStatus::Active
                    ));
                    assert_eq!(repo.lockout_len(), 0);
                } else {
                    assert_eq!(outcome, AuthOutcome::RejectedKnown);
                    assert_eq!(
                        repo.lockout_len(),
                        usize::from(status == AccountStatus::Active),
                        "{status:?} with password result {correct} must not couple lifecycle to temporary lockout"
                    );
                }
            }
        }
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
    // InMemSessionLifecycle tests（创建经 persist_session_and_emit + 查询/软撤销 + 跨租隔离，#1278）
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn session_lifecycle_rejects_missing_and_wrong_entry_fact_before_mutation() {
        let tenant = tid(TENANT_A);
        for (suffix, entry) in [
            ("missing", missing_fact_entry()),
            ("wrong", wrong_fact_entry()),
        ] {
            let repo = InMemSessionLifecycle::new();
            let session_id = format!("sid-{suffix}-fact");
            let result = repo
                .persist_session_and_emit(
                    login_receipt(),
                    scope(tenant),
                    make_session(&session_id, tenant),
                    entry,
                    dummy_envelope(),
                )
                .await;

            assert!(result.is_err(), "{suffix} generated fact must fail closed");
            assert!(
                repo.find(scope(tenant), SessionId::new(&session_id))
                    .await
                    .expect("find")
                    .is_none(),
                "{suffix} generated fact must fail before session mutation"
            );
        }
    }

    #[tokio::test]
    async fn policy_lifecycle_rejects_missing_and_wrong_entry_fact_before_mutation() {
        let tenant = tid(TENANT_A);
        for (suffix, entry) in [
            ("missing", missing_fact_entry()),
            ("wrong", wrong_fact_entry()),
        ] {
            let repo = InMemPolicyRepo::new();
            let raw_id = format!("policy-{suffix}-fact");
            let id = policy_id(&raw_id);
            let result = repo
                .create_and_emit(
                    policy_create_receipt(),
                    scope(tenant),
                    policy(&raw_id, tenant),
                    entry,
                    dummy_envelope(),
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
    async fn role_binding_lifecycle_rejects_missing_and_wrong_entry_fact_before_mutation() {
        let tenant = tid(TENANT_A);
        for (suffix, entry) in [
            ("missing", missing_fact_entry()),
            ("wrong", wrong_fact_entry()),
        ] {
            let lifecycle = InMemRoleBindingLifecycle::new();
            let role_id = RoleId::parse(&format!("role-{suffix}-fact")).expect("role id");
            let result = lifecycle
                .assign_and_emit(
                    role_assign_receipt(),
                    scope(tenant),
                    RoleBinding::new("user-1", role_id.clone(), tenant),
                    entry,
                    dummy_envelope(),
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
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        repo.persist_session_and_emit(
            login_receipt(),
            scope(ta),
            make_session("sid-001", ta),
            dummy_entry(),
            dummy_envelope(),
        )
        .await
        .expect("persist ok");
        let found = repo
            .find(scope(ta), SessionId::new("sid-001"))
            .await
            .expect("find ok");
        assert!(found.is_some(), "persist 后应能找到会话");
        assert_eq!(found.expect("some").id().as_str(), "sid-001");
    }

    #[tokio::test]
    async fn lifecycle_revoke_then_find_returns_none() {
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        repo.persist_session_and_emit(
            login_receipt(),
            scope(ta),
            make_session("sid-002", ta),
            dummy_entry(),
            dummy_envelope(),
        )
        .await
        .expect("persist ok");
        repo.logout(
            scope(ta),
            SessionLogoutMutation::for_test(SessionId::new("sid-002")),
        )
        .await
        .expect("revoke ok");
        let found = repo
            .find(scope(ta), SessionId::new("sid-002"))
            .await
            .expect("find ok");
        assert!(found.is_none(), "已撤销会话 find 应返回 None");
    }

    #[tokio::test]
    async fn lifecycle_revoke_idempotent() {
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        repo.persist_session_and_emit(
            login_receipt(),
            scope(ta),
            make_session("sid-003", ta),
            dummy_entry(),
            dummy_envelope(),
        )
        .await
        .expect("persist ok");
        // 第一次 revoke
        repo.logout(
            scope(ta),
            SessionLogoutMutation::for_test(SessionId::new("sid-003")),
        )
        .await
        .expect("revoke 1");
        // 第二次 revoke（幂等，应仍 Ok）
        repo.logout(
            scope(ta),
            SessionLogoutMutation::for_test(SessionId::new("sid-003")),
        )
        .await
        .expect("revoke 2 idempotent");
        // 未知 session id（幂等，no-op）
        repo.logout(
            scope(ta),
            SessionLogoutMutation::for_test(SessionId::new("no-such-sid")),
        )
        .await
        .expect("revoke unknown idempotent");
    }

    #[tokio::test]
    async fn lifecycle_cross_tenant_find_returns_none() {
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        repo.persist_session_and_emit(
            login_receipt(),
            scope(ta),
            make_session("sid-004", ta),
            dummy_entry(),
            dummy_envelope(),
        )
        .await
        .expect("persist ok");
        // 用 TENANT_B 查 TENANT_A 的 session → None（不泄露存在性）。
        let found = repo
            .find(scope(tb), SessionId::new("sid-004"))
            .await
            .expect("find ok");
        assert!(found.is_none(), "跨租查找应返回 None");
    }

    #[tokio::test]
    async fn lifecycle_cross_tenant_revoke_noop_then_original_tenant_finds() {
        // TENANT_A 种入（persist）→ TENANT_B revoke（no-op）→ TENANT_A find 仍在。
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        repo.persist_session_and_emit(
            login_receipt(),
            scope(ta),
            make_session("sid-005", ta),
            dummy_entry(),
            dummy_envelope(),
        )
        .await
        .expect("persist ok");
        // 跨租 revoke：no-op，不影响 TENANT_A 的记录。
        repo.logout(
            scope(tb),
            SessionLogoutMutation::for_test(SessionId::new("sid-005")),
        )
        .await
        .expect("cross-tenant revoke");
        let found = repo
            .find(scope(ta), SessionId::new("sid-005"))
            .await
            .expect("find ok");
        assert!(found.is_some(), "TENANT_A 的会话不应被 TENANT_B 撤销");
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
                dummy_entry(),
                dummy_envelope_for(tid(TENANT_B)),
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
                dummy_entry(),
                dummy_envelope_for(tid(TENANT_B)),
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
    // InMemRefreshTokenStore 直接单测（F6）
    // ---------------------------------------------------------------------------

    use super::InMemRefreshTokenStore;
    use crate::domain::{RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord};
    use crate::ports::RefreshTokenStore;

    /// 构造用于 InMemRefreshTokenStore 测试的辅助记录（hydrate 公开接口）。
    fn make_rt_record(
        id: &str,
        tenant: TenantId,
        hash: [u8; 32],
        lineage_id: &str,
        status: RefreshStatus,
    ) -> RefreshTokenRecord {
        let issued = epoch(1_700_000_000);
        RefreshTokenRecord::hydrate(
            id,
            tenant,
            "rt-subj",
            vocab::PrincipalKind::User,
            hash,
            None,
            lineage_id,
            crate::AuthnEpoch::ZERO,
            status,
            issued,
            issued + Duration::from_secs(3_600),
        )
    }

    // ── RT M1：rotate CAS miss — old 状态非 Active → Replay，new 不写入 ──────────

    #[tokio::test]
    async fn in_mem_rotate_cas_miss_consumed_status_returns_replay_no_write() {
        let store = InMemRefreshTokenStore::new();
        let ta = tid(TENANT_A);
        let old_hash = [0x11u8; 32];
        let new_hash = [0x12u8; 32];
        let old_id = "aaaaaaaa-0011-4000-8000-000000000011";
        let lineage = old_id;

        // 插入 Consumed 记录（非 Active）
        let old_rec = make_rt_record(old_id, ta, old_hash, lineage, RefreshStatus::Consumed);
        store.insert(scope(ta), old_rec).await.expect("insert ok");

        // CAS：old status = Consumed → miss → false，new 不写入。
        // sealed 命令由源 record 派生（#284 F2）：源（Consumed）的 begin_rotation 生成新 hash 的子 record。
        let issued = epoch(1_700_000_000);
        let rotation = make_rt_record(old_id, ta, old_hash, lineage, RefreshStatus::Consumed)
            .begin_rotation(
                RefreshTokenId::new("aaaaaaaa-0012-4000-8000-000000000012"),
                RefreshTokenHash::new(new_hash),
                issued,
                issued + Duration::from_secs(3_600),
            );
        let result = store
            .rotate(
                scope(ta),
                crate::ports::RefreshRotationMutation::for_test(rotation),
            )
            .await
            .expect("rotate ok");
        assert_eq!(
            result,
            crate::RefreshRotationOutcome::Replay,
            "Consumed 状态 CAS miss 应返回 replay"
        );

        // new 不应写入
        let new_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(new_hash))
            .await
            .expect("find ok");
        assert!(new_found.is_none(), "CAS miss 时 new 不应写入");

        // old 仍 Consumed（不变）
        let old_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(old_hash))
            .await
            .expect("find ok");
        assert_eq!(
            old_found.expect("old exists").status(),
            RefreshStatus::Consumed,
            "old 状态不变"
        );
    }

    // ── RT M2：rotate 一次性 CAS — 同一 Active old 连 rotate 两次 → 首次 Applied、二次 Replay ──
    //
    // 注：sealed RefreshRotation（#284 F2）由源 record 派生 tenant，故「跨租 rotate」类型层不可表达
    // （rotation.new.tenant 恒 = 源 tenant）——跨租隔离已由 find_by_hash 跨租→None（见 in_mem_find...）+
    // 服务级 R6 覆盖。本测试改测 store 层一次性 CAS（首次消费旧 token 后二次必 miss）。

    #[tokio::test]
    async fn in_mem_rotate_is_one_time_second_rotate_misses() {
        let store = InMemRefreshTokenStore::new();
        let ta = tid(TENANT_A);
        let old_hash = [0x13u8; 32];
        let new_hash = [0x14u8; 32];
        let old_id = "aaaaaaaa-0013-4000-8000-000000000013";
        let lineage = old_id;
        let issued = epoch(1_700_000_000);

        let old_rec = make_rt_record(old_id, ta, old_hash, lineage, RefreshStatus::Active);
        store
            .insert(scope(ta), old_rec.clone())
            .await
            .expect("insert ok");

        // 首次 rotate：源 Active → CAS 命中 → Applied（old→Consumed，new 写入）
        let rotation1 = old_rec.begin_rotation(
            RefreshTokenId::new("aaaaaaaa-0014-4000-8000-000000000014"),
            RefreshTokenHash::new(new_hash),
            issued,
            issued + Duration::from_secs(3_600),
        );
        assert_eq!(
            store
                .rotate(
                    scope(ta),
                    crate::ports::RefreshRotationMutation::for_test(rotation1),
                )
                .await
                .expect("rotate ok"),
            crate::RefreshRotationOutcome::Applied,
            "首次 rotate 应命中 CAS"
        );

        // 二次 rotate 同一 old（现已 Consumed）→ CAS miss → Replay（一次性）
        let rotation2 = old_rec.begin_rotation(
            RefreshTokenId::new("aaaaaaaa-0015-4000-8000-000000000015"),
            RefreshTokenHash::new([0x15u8; 32]),
            issued,
            issued + Duration::from_secs(3_600),
        );
        assert_eq!(
            store
                .rotate(
                    scope(ta),
                    crate::ports::RefreshRotationMutation::for_test(rotation2),
                )
                .await
                .expect("rotate ok"),
            crate::RefreshRotationOutcome::Replay,
            "二次 rotate 同一 old 应 miss（一次性）"
        );

        // old 现为 Consumed；二次的 new（0x15）未写入
        let old_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(old_hash))
            .await
            .expect("find ok");
        assert_eq!(
            old_found.expect("old exists").status(),
            RefreshStatus::Consumed,
            "首次 rotate 后 old 应 Consumed"
        );
        let third_found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new([0x15u8; 32]))
            .await
            .expect("find ok");
        assert!(third_found.is_none(), "二次 CAS miss 时 new 不应写入");
    }

    // ── RT M3：revoke_lineage 跨租 no-op — tenant B 调用 → tenant A 记录不变 ─────

    #[tokio::test]
    async fn in_mem_revoke_lineage_cross_tenant_noop() {
        let store = InMemRefreshTokenStore::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        let hash_a = [0x15u8; 32];
        let lineage_str = "aaaaaaaa-0015-4000-8000-000000000015";

        let rec_a = make_rt_record(
            "aaaaaaaa-0015-4000-8000-000000000015",
            ta,
            hash_a,
            lineage_str,
            RefreshStatus::Active,
        );
        store.insert(scope(ta), rec_a).await.expect("insert ok");

        // tenant B 用相同 lineage_id 调 revoke_lineage → WHERE tenant 不匹配 → no-op
        store
            .revoke_lineage(scope(tb), RefreshTokenId::new(lineage_str))
            .await
            .expect("revoke_lineage ok");

        // tenant A 的记录仍 Active（未受影响）
        let found = store
            .find_by_hash(scope(ta), RefreshTokenHash::new(hash_a))
            .await
            .expect("find ok");
        assert_eq!(
            found.expect("A exists").status(),
            RefreshStatus::Active,
            "跨租 revoke_lineage 不影响 tenant A 的记录"
        );
    }

    // ── RT M4：find_by_hash 跨租 → None（anti-vacuity：同租 → Some）────────────────

    #[tokio::test]
    async fn in_mem_find_by_hash_cross_tenant_returns_none() {
        let store = InMemRefreshTokenStore::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        let hash_a = [0x16u8; 32];

        let rec_a = make_rt_record(
            "aaaaaaaa-0016-4000-8000-000000000016",
            ta,
            hash_a,
            "aaaaaaaa-0016-4000-8000-000000000016",
            RefreshStatus::Active,
        );
        store.insert(scope(ta), rec_a).await.expect("insert ok");

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
