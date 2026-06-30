//! in-memory 仓储实现（域内 / 域形 DI port 的 test / seed-login 替身）。生产持久化（postgres adapter）留 W。
//!
//! - [`InMemCredentialRepo`]：`CredentialRepo` 域形 DI port 的 in-mem 替身（哈希凭据 + 锁定态持久化），PR3。
//! - [`InMemSessionLifecycle`]：`SessionLifecycle` 域形 DI port 的 in-mem 替身（co-tx 创建即写 store + 软撤销
//!   标记 + 跨租隔离查询），合并原 `InMemSessionRepo`（#1278）；`#[cfg(test)]` 门控（见其文档）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::domain::{AccountLockout, AuthOutcome, Credential, IdentityError, LoginIdentifier};
use crate::ports::CredentialRepo;
use vocab::TenantId;

// 会话生命周期 in-mem 替身（[`InMemSessionLifecycle`]）仅 test 构建编译：with_seed_credential 改注入 lifecycle
// （不再自建空 session store），journeys 用 adapters/memory 的 `MemSessionLifecycle`——故 `seed-login` 非 test
// 构建无消费者（`#[cfg(test)]` 防 dead_code，#1278）。其依赖的 Arc / 会话实体 / 端口 / outbox 类型同门控。
#[cfg(test)]
use crate::domain::{Session, SessionId};
#[cfg(test)]
use crate::ports::SessionLifecycle;
#[cfg(test)]
use consistency::Entry;
#[cfg(test)]
use diport::{OutboxEmitError, OutboxEnvelopeParts};
// Arc 供 InMemSessionLifecycle（test）与 InMemRefreshTokenStore（test/seed-login）共享 store 句柄。
#[cfg(any(test, feature = "seed-login"))]
use std::sync::Arc;

// RefreshTokenStore in-mem 替身（test/seed-login 门控）：seed-login 供 journey/demo 登录首发 token 落库（#1252）。
#[cfg(any(test, feature = "seed-login"))]
use crate::domain::{RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord};
#[cfg(any(test, feature = "seed-login"))]
use crate::ports::RefreshTokenStore;

// RBAC 角色仓储 + 绑定生命周期 in-mem 替身（`#[cfg(test)]` 门控，#1190）。
#[cfg(test)]
use crate::domain::{Role, RoleBinding, RoleId};
#[cfg(test)]
use crate::ports::{RoleBindingLifecycle, RoleRepo};
#[cfg(test)]
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// InMemCredentialRepo — CredentialRepo 域形 DI port 的 in-mem 替身（PR3）
// ---------------------------------------------------------------------------

/// `CredentialRepo` 的 in-memory 替身：`(tenant, login)` → 哈希凭据 / 锁定态。
///
/// 内部 `Mutex`（trait 方法 `&self`，需内部可变；锁仅同步持有、**不跨 `.await`** ⇒ future 仍 `Send`）。
/// 键含 `TenantId` ⇒ 跨租赁查找天然 fail-closed（`find(t ≠ 存入 tenant)` → `None`）。键的标识段是
/// [`LoginIdentifier`]（登录查找键，非 canonical user id，#1277 F1）。生产 postgres impl 留 W。
pub(crate) struct InMemCredentialRepo {
    creds: Mutex<HashMap<(TenantId, LoginIdentifier), Credential>>,
    lockouts: Mutex<HashMap<(TenantId, LoginIdentifier), AccountLockout>>,
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
            creds: Mutex::new(HashMap::new()),
            lockouts: Mutex::new(HashMap::new()),
        }
    }

    /// 以单个种子凭据构造（密码经 `secure::hash_password` 哈希，**不存明文**；version 起 1）。
    /// 供 test / `seed-login`（PR4 真实登录种子）。`login` = 登录查找键，`user_id` = canonical actor
    /// subject（写 wire/audit；与 `login` 解耦，#1277 F1）。
    pub(crate) fn with_seed_credential(
        login: impl Into<String>,
        user_id: ids::UserId,
        plaintext: &str,
        tenant: TenantId,
    ) -> Result<Self, secure::PasswordError> {
        let hash = secure::hash_password(plaintext)?;
        let credential = Credential::new(LoginIdentifier::new(login), user_id, tenant, hash, 1);
        let repo = Self::new();
        // key 派生自 credential（与 save 同——身份错位不可表达，F2）。
        recover(&repo.creds).insert(Self::cred_key(&credential), credential);
        Ok(repo)
    }

    /// store key 单源：派生自 credential 自身（tenant + login），消除外部 key 与存值错位（F2）。
    fn cred_key(credential: &Credential) -> (TenantId, LoginIdentifier) {
        (credential.tenant(), credential.login().clone())
    }

    /// 测试可见：当前 lockout 表条目数（F2 断言——未知主体登录失败不建锁、不撑大表）。
    #[cfg(test)]
    pub(crate) fn lockout_len(&self) -> usize {
        recover(&self.lockouts).len()
    }
}

impl CredentialRepo for InMemCredentialRepo {
    async fn find_by_user_id(
        &self,
        tenant: TenantId,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError> {
        // creds 按 (tenant, login) 索引——按 canonical user_id 查须线性扫本 tenant 凭据匹配 user_id。
        // reason: in-mem 替身（test/seed-login 门控）规模小，O(n) 扫可接受；生产 postgres adapter（W #1258）
        // 须为 user_id 建二级索引（O(1) 查），不沿用扫描。
        Ok(recover(&self.creds)
            .values()
            .find(|c| c.tenant() == tenant && c.user_id() == user_id)
            .cloned())
    }

    async fn authenticate(
        &self,
        tenant: TenantId,
        login: LoginIdentifier,
        candidate: String,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError> {
        // 恒定成本验签（F3）：先克隆出 (hash, user_id) 释放 creds 锁，经 secure::verify_password_constant_time——
        // 查无凭据也跑等价 argon2 KDF，消登录枚举时序差。再据「已知/未知」+「验签成败」原子分流（F1+F2）。
        // INVARIANT: MEM-LOCK-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }— creds 锁与 lockouts 锁**不交叉持有**：creds guard 在下方 `.map()`
        // 临时表达式结束即析构释放，KDF 在两锁之外计算，之后才取 lockouts 锁。重构勿引入同时持两锁（防死锁）。
        let key = (tenant, login);
        let found = recover(&self.creds)
            .get(&key)
            .map(|c| (c.password_hash().clone(), c.user_id()));
        let ok = secure::verify_password_constant_time(&candidate, found.as_ref().map(|(h, _)| h));
        Ok(match (found, ok) {
            // 已知 + 正确：成功重置失败计数（原子清锁内 RMW），返回 canonical actor subject。
            (Some((_, user_id)), true) => {
                recover(&self.lockouts).remove(&key);
                AuthOutcome::Authenticated(user_id)
            }
            // 已知 + 错：原子推进 lockout（锁内 RMW，达阈值即锁）；对外仍 InvalidCredentials。
            (Some(_), false) => {
                recover(&self.lockouts)
                    .entry(key)
                    .or_insert_with(|| AccountLockout::new(now))
                    .record_failure(now);
                AuthOutcome::InvalidKnownUser
            }
            // 查无凭据：KDF 已跑（防枚举时序差），但**不建/不动** lockout 态（F2：未知主体不可预置锁定/不撑大表）。
            (None, _) => AuthOutcome::InvalidUnknown,
        })
    }

    async fn save(&self, credential: Credential) -> Result<(), IdentityError> {
        recover(&self.creds).insert(Self::cred_key(&credential), credential);
        Ok(())
    }

    async fn bump_version(&self, expected: u32, next: Credential) -> Result<(), IdentityError> {
        // key 派生自 next（F2：错位不可表达，无需 debug_assert）。
        let key = Self::cred_key(&next);
        let mut guard = recover(&self.creds);
        match guard.get(&key).map(Credential::version) {
            None => Err(IdentityError::CredentialNotFound),
            Some(v) if v != expected => Err(IdentityError::VersionConflict),
            Some(_) => {
                guard.insert(key, next);
                Ok(())
            }
        }
    }

    async fn lockout_status(
        &self,
        tenant: TenantId,
        login: LoginIdentifier,
        now: SystemTime,
    ) -> Result<bool, IdentityError> {
        // 原子 RMW（锁内，F1）：lazy-unlock（TTL 过则原地清）后返回 is_locked。查无锁定态 → 未锁定。
        let mut guard = recover(&self.lockouts);
        match guard.get_mut(&(tenant, login)) {
            Some(lockout) => {
                lockout.try_lazy_unlock(now);
                Ok(lockout.is_locked(now))
            }
            None => Ok(false),
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
/// - `revoke`（软撤销，logout）：设 `revoked = true`，不删除记录（幂等：重复 / 未知 revoke 仍 Ok）。
/// - 跨租隔离：`find` 过滤 `s.tenant() == tenant`（跨租 → None）；`revoke` 跨租 no-op（不报错、不撤销）。
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
        session: Session,
        _entry: Entry,
        _envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        // reason: in-mem 替身无 durable 事务 / outbox 载体——创建即把 session 直插共享 store（revoked=false）；
        // entry/envelope 不落库（同 MemSessionLifecycle；真实 co-tx 原子性由 PgSessionLifecycle 守）。
        recover(&self.sessions).insert(session.id().clone(), (session, false));
        Ok(())
    }

    async fn find(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        Ok(recover(&self.sessions)
            .get(&session_id)
            .filter(|(s, revoked)| !*revoked && s.tenant() == tenant) // 跨租/已撤销 → None
            .map(|(s, _)| s.clone()))
    }

    async fn revoke(&self, tenant: TenantId, session_id: SessionId) -> Result<(), IdentityError> {
        if let Some(entry) = recover(&self.sessions).get_mut(&session_id)
            && entry.0.tenant() == tenant
        {
            entry.1 = true; // 跨租 no-op；幂等
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemRoleRepo / InMemRoleBindingLifecycle — RBAC 角色仓储 + 绑定生命周期 in-mem 替身（#1190，US5）
// ---------------------------------------------------------------------------

/// `RoleRepo` 的 in-memory 替身：保存完整 [`Role`]，供 assign/revoke 校验与列表 handler 测试共用。
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
}

#[cfg(test)]
impl RoleRepo for InMemRoleRepo {
    async fn find(&self, tenant: TenantId, id: RoleId) -> Result<Option<Role>, IdentityError> {
        Ok(recover(&self.roles)
            .get(&(tenant.to_string(), id.as_str().to_string()))
            .cloned())
    }

    async fn save(&self, tenant: TenantId, role: Role) -> Result<(), IdentityError> {
        recover(&self.roles).insert((tenant.to_string(), role.id().as_str().to_string()), role);
        Ok(())
    }

    async fn list(
        &self,
        tenant: TenantId,
        page: crate::ports::RolePage,
    ) -> Result<crate::ports::RoleListResult, IdentityError> {
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
    fn of(entry: &Entry, envelope: &OutboxEnvelopeParts) -> Self {
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
        binding: RoleBinding,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        if self.fail {
            // reason: 模拟 co-tx 写失败 ⇒ both-or-neither：binding 不落、事件不记（提前返回）。
            return Err(OutboxEmitError::new(std::io::Error::other(
                "inmem-rbac-cotx-fail",
            )));
        }
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
        tenant: TenantId,
        role_id: RoleId,
        subject: String,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, OutboxEmitError> {
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
        let removed = recover(&self.bindings).remove(&key);
        if removed {
            recover(&self.emitted).push(CapturedEvent::of(&entry, &envelope));
        }
        Ok(removed)
    }

    async fn list_for_subject(
        &self,
        tenant: TenantId,
        subject: String,
    ) -> Result<Vec<RoleBinding>, IdentityError> {
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
///   `new`，返回 `Ok(true)`；否则 `Ok(false)`（不写 new）。
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
}

#[cfg(any(test, feature = "seed-login"))]
impl RefreshTokenStore for InMemRefreshTokenStore {
    async fn insert(&self, record: RefreshTokenRecord) -> Result<(), crate::domain::IdentityError> {
        recover(&self.records).insert(record.id().clone(), record);
        Ok(())
    }

    async fn find_by_hash(
        &self,
        tenant: vocab::TenantId,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, crate::domain::IdentityError> {
        // reason: in-mem 替身（test 门控）规模小，O(n) 扫可接受；生产 postgres adapter 须 btree 索引。
        Ok(recover(&self.records)
            .values()
            .find(|r| r.tenant() == tenant && r.token_hash() == &hash)
            .cloned())
    }

    async fn rotate(
        &self,
        rotation: crate::ports::RefreshRotation,
    ) -> Result<bool, crate::domain::IdentityError> {
        // sealed 命令：tenant 从 new record 派生（= 源 record tenant），无独立 tenant 入参可错位（#284 F2）。
        let old_id = rotation.old_id().clone();
        let new = rotation.new_record().clone();
        let tenant = new.tenant();
        let mut guard = recover(&self.records);
        // CAS：找 old_id，若 Active + tenant 匹配 ⇒ 消费 + 写 new；否则 false（不写 new）。
        match guard.get(&old_id) {
            Some(rec) if rec.status() == RefreshStatus::Active && rec.tenant() == tenant => {
                let consumed = rec.with_status(RefreshStatus::Consumed);
                guard.insert(old_id, consumed);
                guard.insert(new.id().clone(), new);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn revoke_lineage(
        &self,
        tenant: vocab::TenantId,
        lineage_id: RefreshTokenId,
    ) -> Result<(), crate::domain::IdentityError> {
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
    use super::{Credential, InMemCredentialRepo, InMemSessionLifecycle, TenantId};
    use crate::domain::{AuthOutcome, IdentityError, LoginIdentifier, Session, SessionId};
    use crate::ports::{CredentialRepo, SessionLifecycle};
    use consistency::{Entry, IdemKey, OutboxPayload, Topic};
    use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEnvelopeParts};
    use std::time::{Duration, SystemTime};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";
    // canonical user id（audit actor 形态；与登录标识 "alice" 解耦，#1277 F1）。
    const USER_ALICE: &str = "11111111-2222-4333-8444-555555555555";
    // 未种子化的 canonical user id（find_by_user_id 未知主体 → None，#1277 F2）。
    const USER_GHOST: &str = "99999999-8888-4777-8666-555544443333";

    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant parses")
    }

    fn uid(raw: &str) -> ids::UserId {
        ids::UserId::parse(raw).expect("canonical user id parses")
    }

    fn lid(raw: &str) -> LoginIdentifier {
        LoginIdentifier::new(raw)
    }

    fn cred(login: &str, user: &str, password: &str, version: u32, tenant: TenantId) -> Credential {
        Credential::new(
            LoginIdentifier::new(login),
            uid(user),
            tenant,
            secure::hash_password(password).expect("hash"),
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

    // co-tx 创建入参占位（InMemSessionLifecycle::persist_session_and_emit 忽略 entry/envelope，仅存 session）。
    fn dummy_entry() -> Entry {
        Entry::new(
            Topic::parse("identity.session-created").expect("topic parses"),
            IdemKey::parse("evt-1").expect("idem key parses"),
            OutboxPayload::from_reviewed_event_bytes(b"{}".to_vec()),
        )
    }

    fn dummy_envelope() -> OutboxEnvelopeParts {
        OutboxEnvelopeParts::new(
            generated::event::identity_v1::session_created::CONTRACT,
            tid(TENANT_A),
            EnvelopeSubjectId::from_opaque("subject-1").expect("subject"),
            OutboxActor::scoped(
                vocab::PrincipalKind::User,
                OpaqueActorId::from_opaque("actor-1").expect("actor"),
                tid(TENANT_A),
                vocab::ScopedTenant::SelfOnly,
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
        repo.save(cred("alice", USER_ALICE, "pw", 1, t))
            .await
            .expect("save");
        let found = repo
            .find_by_user_id(t, uid(USER_ALICE))
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
            repo.find_by_user_id(t, uid(USER_GHOST))
                .await
                .expect("find")
                .is_none()
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
        // 已知 + 正确 → Authenticated(canonical user id)。
        assert_eq!(
            repo.authenticate(t, lid("alice"), "correct".to_string(), now)
                .await
                .expect("auth"),
            AuthOutcome::Authenticated(uid(USER_ALICE))
        );
        // 已知 + 错 → InvalidKnownUser。
        assert_eq!(
            repo.authenticate(t, lid("alice"), "wrong".to_string(), now)
                .await
                .expect("auth"),
            AuthOutcome::InvalidKnownUser
        );
        // 查无主体 → InvalidUnknown（恒定成本 KDF 仍跑，F3；不 panic）。
        assert_eq!(
            repo.authenticate(t, lid("ghost"), "correct".to_string(), now)
                .await
                .expect("auth"),
            AuthOutcome::InvalidUnknown
        );
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
                repo.authenticate(t, lid(&format!("ghost-{i}")), "x".to_string(), now)
                    .await
                    .expect("auth"),
                AuthOutcome::InvalidUnknown
            );
        }
        assert_eq!(
            repo.lockout_len(),
            0,
            "未知主体失败不建锁定态（lockout 表不随枚举增长，F2）"
        );
        // 对比：已知主体失败才建恰一条。
        repo.authenticate(t, lid("alice"), "wrong".to_string(), now)
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
        // 跨租赁查找 → None（不泄露存在性），authenticate → InvalidUnknown（跨租即未知，不建锁）。
        assert!(
            repo.find_by_user_id(other, uid(USER_ALICE))
                .await
                .expect("find")
                .is_none()
        );
        assert_eq!(
            repo.authenticate(other, lid("alice"), "correct".to_string(), t0)
                .await
                .expect("auth"),
            AuthOutcome::InvalidUnknown
        );
        assert_eq!(repo.lockout_len(), 0, "跨租未知主体失败不建锁（F2 + 隔离）");
        // 在 TENANT_A 把 alice 锁定（5 次错密码），TENANT_B 视角 lockout_status 仍 false（隔离）。
        for i in 1..=5 {
            repo.authenticate(
                a,
                lid("alice"),
                "wrong".to_string(),
                t0 + Duration::from_secs(i),
            )
            .await
            .expect("auth");
        }
        assert!(
            repo.lockout_status(a, lid("alice"), t0 + Duration::from_secs(5))
                .await
                .expect("ls")
        );
        assert!(
            !repo
                .lockout_status(other, lid("alice"), t0 + Duration::from_secs(5))
                .await
                .expect("ls"),
            "TENANT_B 视角不应受 TENANT_A 锁定影响"
        );
    }

    #[tokio::test]
    async fn cross_tenant_bump_version_isolated() {
        let a = tid(TENANT_A);
        let other = tid(TENANT_B);
        let repo = InMemCredentialRepo::new();
        repo.save(cred("alice", USER_ALICE, "pw", 1, a))
            .await
            .expect("save");
        // 跨租 bump：next 在 TENANT_B（key 派生自 next）→ 查无 → CredentialNotFound，不动 TENANT_A。
        let res = repo
            .bump_version(1, cred("alice", USER_ALICE, "pw2", 2, other))
            .await;
        assert!(matches!(res, Err(IdentityError::CredentialNotFound)));
        let still = repo
            .find_by_user_id(a, uid(USER_ALICE))
            .await
            .expect("find")
            .expect("some");
        assert_eq!(still.version(), 1);
        assert!(still.verify_password("pw"));
    }

    #[tokio::test]
    async fn bump_version_cas_hit_miss_and_unknown() {
        let repo = InMemCredentialRepo::new();
        let t = tid(TENANT_A);
        repo.save(cred("alice", USER_ALICE, "pw", 1, t))
            .await
            .expect("save");
        // 期望版本不匹配 → VersionConflict（key 派生自 next）。
        let conflict = repo
            .bump_version(99, cred("alice", USER_ALICE, "pw2", 2, t))
            .await;
        assert!(matches!(conflict, Err(IdentityError::VersionConflict)));
        // 期望版本命中 → 替换。
        repo.bump_version(1, cred("alice", USER_ALICE, "pw2", 2, t))
            .await
            .expect("cas hit");
        let found = repo
            .find_by_user_id(t, uid(USER_ALICE))
            .await
            .expect("find")
            .expect("some");
        assert_eq!(found.version(), 2);
        assert!(found.verify_password("pw2"));
        // 查无凭据 → CredentialNotFound。
        let missing = repo
            .bump_version(1, cred("ghost", USER_ALICE, "x", 1, t))
            .await;
        assert!(matches!(missing, Err(IdentityError::CredentialNotFound)));
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
                    t,
                    lid("alice"),
                    "wrong".to_string(),
                    t0 + Duration::from_secs(i)
                )
                .await
                .expect("auth"),
                AuthOutcome::InvalidKnownUser,
                "第 {i} 次失败"
            );
            assert!(
                !repo
                    .lockout_status(t, lid("alice"), t0 + Duration::from_secs(i))
                    .await
                    .expect("ls"),
                "未达阈值仍未锁"
            );
        }
        // 第 5 次（窗口内）→ 达阈值锁定。
        repo.authenticate(
            t,
            lid("alice"),
            "wrong".to_string(),
            t0 + Duration::from_secs(5),
        )
        .await
        .expect("auth");
        assert!(
            repo.lockout_status(t, lid("alice"), t0 + Duration::from_secs(5))
                .await
                .expect("ls")
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
                t,
                lid("alice"),
                "wrong".to_string(),
                t0 + Duration::from_secs(i),
            )
            .await
            .expect("auth");
        }
        let lock_at = t0 + Duration::from_secs(5);
        let lock_ttl = Duration::from_secs(15 * 60);
        // TTL 内仍锁定。
        assert!(
            repo.lockout_status(t, lid("alice"), lock_at + lock_ttl - Duration::from_secs(1))
                .await
                .expect("ls")
        );
        // lockout_status 在 TTL 后原子 lazy-unlock → false（且持久化解锁）。
        assert!(
            !repo
                .lockout_status(t, lid("alice"), lock_at + lock_ttl + Duration::from_secs(1))
                .await
                .expect("ls")
        );
        // 解锁后再失败从 1 重计（不沿用旧计数）→ InvalidKnownUser、未锁。
        let after = lock_at + lock_ttl + Duration::from_secs(2);
        assert_eq!(
            repo.authenticate(t, lid("alice"), "wrong".to_string(), after)
                .await
                .expect("auth"),
            AuthOutcome::InvalidKnownUser
        );
        assert!(
            !repo
                .lockout_status(t, lid("alice"), after)
                .await
                .expect("ls")
        );
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
                    t,
                    lid("alice"),
                    "wrong".to_string(),
                    t0 + Duration::from_secs(i)
                )
                .await
                .expect("auth"),
                AuthOutcome::InvalidKnownUser
            );
        }
        assert_eq!(repo.lockout_len(), 1, "失败累积建一条 lockout 态");
        // 正确密码 → Authenticated + 原子清除 lockout 态。
        assert_eq!(
            repo.authenticate(
                t,
                lid("alice"),
                "correct".to_string(),
                t0 + Duration::from_secs(5)
            )
            .await
            .expect("auth"),
            AuthOutcome::Authenticated(uid(USER_ALICE))
        );
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
    async fn lifecycle_persist_then_find_roundtrip() {
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        repo.persist_session_and_emit(make_session("sid-001", ta), dummy_entry(), dummy_envelope())
            .await
            .expect("persist ok");
        let found = repo
            .find(ta, SessionId::new("sid-001"))
            .await
            .expect("find ok");
        assert!(found.is_some(), "persist 后应能找到会话");
        assert_eq!(found.expect("some").id().as_str(), "sid-001");
    }

    #[tokio::test]
    async fn lifecycle_revoke_then_find_returns_none() {
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        repo.persist_session_and_emit(make_session("sid-002", ta), dummy_entry(), dummy_envelope())
            .await
            .expect("persist ok");
        repo.revoke(ta, SessionId::new("sid-002"))
            .await
            .expect("revoke ok");
        let found = repo
            .find(ta, SessionId::new("sid-002"))
            .await
            .expect("find ok");
        assert!(found.is_none(), "已撤销会话 find 应返回 None");
    }

    #[tokio::test]
    async fn lifecycle_revoke_idempotent() {
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        repo.persist_session_and_emit(make_session("sid-003", ta), dummy_entry(), dummy_envelope())
            .await
            .expect("persist ok");
        // 第一次 revoke
        repo.revoke(ta, SessionId::new("sid-003"))
            .await
            .expect("revoke 1");
        // 第二次 revoke（幂等，应仍 Ok）
        repo.revoke(ta, SessionId::new("sid-003"))
            .await
            .expect("revoke 2 idempotent");
        // 未知 session id（幂等，no-op）
        repo.revoke(ta, SessionId::new("no-such-sid"))
            .await
            .expect("revoke unknown idempotent");
    }

    #[tokio::test]
    async fn lifecycle_cross_tenant_find_returns_none() {
        let repo = InMemSessionLifecycle::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        repo.persist_session_and_emit(make_session("sid-004", ta), dummy_entry(), dummy_envelope())
            .await
            .expect("persist ok");
        // 用 TENANT_B 查 TENANT_A 的 session → None（不泄露存在性）。
        let found = repo
            .find(tb, SessionId::new("sid-004"))
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
        repo.persist_session_and_emit(make_session("sid-005", ta), dummy_entry(), dummy_envelope())
            .await
            .expect("persist ok");
        // 跨租 revoke：no-op，不影响 TENANT_A 的记录。
        repo.revoke(tb, SessionId::new("sid-005"))
            .await
            .expect("cross-tenant revoke");
        let found = repo
            .find(ta, SessionId::new("sid-005"))
            .await
            .expect("find ok");
        assert!(found.is_some(), "TENANT_A 的会话不应被 TENANT_B 撤销");
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
            status,
            issued,
            issued + Duration::from_secs(3_600),
        )
    }

    // ── RT M1：rotate CAS miss — old 状态非 Active → Ok(false)，new 不写入 ──────────

    #[tokio::test]
    async fn in_mem_rotate_cas_miss_consumed_status_returns_false_no_write() {
        let store = InMemRefreshTokenStore::new();
        let ta = tid(TENANT_A);
        let old_hash = [0x11u8; 32];
        let new_hash = [0x12u8; 32];
        let old_id = "aaaaaaaa-0011-4000-8000-000000000011";
        let lineage = old_id;

        // 插入 Consumed 记录（非 Active）
        let old_rec = make_rt_record(old_id, ta, old_hash, lineage, RefreshStatus::Consumed);
        store.insert(old_rec).await.expect("insert ok");

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
        let result = store.rotate(rotation).await.expect("rotate ok");
        assert!(!result, "Consumed 状态 CAS miss 应返回 false");

        // new 不应写入
        let new_found = store
            .find_by_hash(ta, RefreshTokenHash::new(new_hash))
            .await
            .expect("find ok");
        assert!(new_found.is_none(), "CAS miss 时 new 不应写入");

        // old 仍 Consumed（不变）
        let old_found = store
            .find_by_hash(ta, RefreshTokenHash::new(old_hash))
            .await
            .expect("find ok");
        assert_eq!(
            old_found.expect("old exists").status(),
            RefreshStatus::Consumed,
            "old 状态不变"
        );
    }

    // ── RT M2：rotate 一次性 CAS — 同一 Active old 连 rotate 两次 → 首次 true、二次 false ──
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
        store.insert(old_rec.clone()).await.expect("insert ok");

        // 首次 rotate：源 Active → CAS 命中 → true（old→Consumed，new 写入）
        let rotation1 = old_rec.begin_rotation(
            RefreshTokenId::new("aaaaaaaa-0014-4000-8000-000000000014"),
            RefreshTokenHash::new(new_hash),
            issued,
            issued + Duration::from_secs(3_600),
        );
        assert!(
            store.rotate(rotation1).await.expect("rotate ok"),
            "首次 rotate 应命中 CAS"
        );

        // 二次 rotate 同一 old（现已 Consumed）→ CAS miss → false（一次性）
        let rotation2 = old_rec.begin_rotation(
            RefreshTokenId::new("aaaaaaaa-0015-4000-8000-000000000015"),
            RefreshTokenHash::new([0x15u8; 32]),
            issued,
            issued + Duration::from_secs(3_600),
        );
        assert!(
            !store.rotate(rotation2).await.expect("rotate ok"),
            "二次 rotate 同一 old 应 miss（一次性）"
        );

        // old 现为 Consumed；二次的 new（0x15）未写入
        let old_found = store
            .find_by_hash(ta, RefreshTokenHash::new(old_hash))
            .await
            .expect("find ok");
        assert_eq!(
            old_found.expect("old exists").status(),
            RefreshStatus::Consumed,
            "首次 rotate 后 old 应 Consumed"
        );
        let third_found = store
            .find_by_hash(ta, RefreshTokenHash::new([0x15u8; 32]))
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
        store.insert(rec_a).await.expect("insert ok");

        // tenant B 用相同 lineage_id 调 revoke_lineage → WHERE tenant 不匹配 → no-op
        store
            .revoke_lineage(tb, RefreshTokenId::new(lineage_str))
            .await
            .expect("revoke_lineage ok");

        // tenant A 的记录仍 Active（未受影响）
        let found = store
            .find_by_hash(ta, RefreshTokenHash::new(hash_a))
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
        store.insert(rec_a).await.expect("insert ok");

        // anti-vacuity：tenant A 自查 → Some
        let found_a = store
            .find_by_hash(ta, RefreshTokenHash::new(hash_a))
            .await
            .expect("find ok");
        assert!(
            found_a.is_some(),
            "tenant A 应能查到自己的记录（anti-vacuity）"
        );

        // 跨租：tenant B 查 → None
        let found_b = store
            .find_by_hash(tb, RefreshTokenHash::new(hash_a))
            .await
            .expect("find ok");
        assert!(found_b.is_none(), "跨租 find_by_hash 应返回 None");
    }
}
