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
#[cfg(test)]
use std::sync::Arc;

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
        // INVARIANT: MEM-LOCK-ORDER-01 — creds 锁与 lockouts 锁**不交叉持有**：creds guard 在下方 `.map()`
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{Credential, InMemCredentialRepo, InMemSessionLifecycle, TenantId};
    use crate::domain::{AuthOutcome, IdentityError, LoginIdentifier, Session, SessionId};
    use crate::ports::{CredentialRepo, SessionLifecycle};
    use consistency::{Entry, IdemKey, Topic};
    use diport::OutboxEnvelopeParts;
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
            b"{}".to_vec(),
        )
    }

    fn dummy_envelope() -> OutboxEnvelopeParts {
        OutboxEnvelopeParts::new(generated::event::identity_v1::CONTRACT, "subject-1")
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
}
