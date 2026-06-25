//! in-memory 仓储实现（域内 / 域形 DI port 的 test / seed-login 替身）。生产持久化（postgres adapter）留 W。
//!
//! - [`InMemCredentialRepo`]：`CredentialRepo` 域形 DI port 的 in-mem 替身（哈希凭据 + 锁定态持久化），PR3。
//! - [`InMemSessionRepo`]：`SessionRepo` 域形 DI port 的 in-mem 替身（软撤销标记），PR4 #1189。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::domain::{AccountLockout, AccountStatus, Credential, IdentityError, Session, SessionId};
use crate::ports::{CredentialRepo, SessionRepo};
use vocab::TenantId;

// ---------------------------------------------------------------------------
// InMemCredentialRepo — CredentialRepo 域形 DI port 的 in-mem 替身（PR3）
// ---------------------------------------------------------------------------

/// `CredentialRepo` 的 in-memory 替身：`(tenant, subject)` → 哈希凭据 / 锁定态。
///
/// 内部 `Mutex`（trait 方法 `&self`，需内部可变；锁仅同步持有、**不跨 `.await`** ⇒ future 仍 `Send`）。
/// 键含 `TenantId` ⇒ 跨租赁查找天然 fail-closed（`find(t ≠ 存入 tenant)` → `None`）。生产 postgres impl 留 W。
pub(crate) struct InMemCredentialRepo {
    creds: Mutex<HashMap<(TenantId, String), Credential>>,
    lockouts: Mutex<HashMap<(TenantId, String), AccountLockout>>,
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
    /// 供 test / `seed-login`（PR4 真实登录种子）。
    pub(crate) fn with_seed_credential(
        subject: impl Into<String>,
        plaintext: &str,
        tenant: TenantId,
    ) -> Result<Self, secure::PasswordError> {
        let hash = secure::hash_password(plaintext)?;
        let credential = Credential::new(subject, tenant, hash, 1);
        let repo = Self::new();
        // key 派生自 credential（与 save 同——身份错位不可表达，F2）。
        recover(&repo.creds).insert(Self::cred_key(&credential), credential);
        Ok(repo)
    }

    /// store key 单源：派生自 credential 自身（tenant + subject），消除外部 key 与存值错位（F2）。
    fn cred_key(credential: &Credential) -> (TenantId, String) {
        (credential.tenant(), credential.subject().to_string())
    }
}

impl CredentialRepo for InMemCredentialRepo {
    async fn find(
        &self,
        tenant: TenantId,
        subject: String,
    ) -> Result<Option<Credential>, IdentityError> {
        Ok(recover(&self.creds).get(&(tenant, subject)).cloned())
    }

    async fn verify_password(
        &self,
        tenant: TenantId,
        subject: String,
        candidate: String,
    ) -> Result<bool, IdentityError> {
        // 恒定成本验签（F3）：克隆出哈希释放锁后，经 secure::verify_password_constant_time——查无凭据也跑
        // 等价 argon2 KDF，消登录枚举时序差。fail-closed 不区分「无此凭据」与「密码错」（值 + 时延双不可分）。
        let stored = recover(&self.creds)
            .get(&(tenant, subject))
            .map(|c| c.password_hash().clone());
        Ok(secure::verify_password_constant_time(
            &candidate,
            stored.as_ref(),
        ))
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

    async fn record_failure(
        &self,
        tenant: TenantId,
        subject: String,
        now: SystemTime,
    ) -> Result<AccountStatus, IdentityError> {
        // 原子 RMW（锁内，F1）：读锁定态-or-新建 → record_failure → 持久化（entry 引用即原地写）。并发不丢更新。
        let mut guard = recover(&self.lockouts);
        let lockout = guard
            .entry((tenant, subject))
            .or_insert_with(|| AccountLockout::new(now));
        Ok(lockout.record_failure(now))
    }

    async fn lockout_status(
        &self,
        tenant: TenantId,
        subject: String,
        now: SystemTime,
    ) -> Result<bool, IdentityError> {
        // 原子 RMW（锁内，F1）：lazy-unlock（TTL 过则原地清）后返回 is_locked。查无锁定态 → 未锁定。
        let mut guard = recover(&self.lockouts);
        match guard.get_mut(&(tenant, subject)) {
            Some(lockout) => {
                lockout.try_lazy_unlock(now);
                Ok(lockout.is_locked(now))
            }
            None => Ok(false),
        }
    }

    async fn clear_lockout(&self, tenant: TenantId, subject: String) -> Result<(), IdentityError> {
        recover(&self.lockouts).remove(&(tenant, subject));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemSessionRepo — SessionRepo 域形 DI port 的 in-mem 替身（PR4 #1189）
// ---------------------------------------------------------------------------

/// `SessionRepo` 的 in-memory 替身：`SessionId` → `(Session, revoked_flag)`。
///
/// 软撤销（logout）：设 `revoked = true`，不删除记录（幂等：重复 revoke 仍 Ok）。
/// 跨租隔离：find 过滤 `s.tenant() == tenant`；revoke 跨租 no-op（不报错、不撤销）。
/// 内部 `Arc<Mutex<..>>`（`&self` + 内部可变；锁仅同步持有、**不跨 `.await`** ⇒ future 仍 `Send`）；
/// `Arc` ⇒ clone 共享同一存储——测试侧持一克隆、`LoginService` 持另一克隆，可观测经 service `logout`
/// 的软撤销效果（同 `CapturingSessionUoW` 共享状态范式）。
#[derive(Clone, Default)]
pub(crate) struct InMemSessionRepo {
    // bool = revoked（软撤销标记）
    sessions: Arc<Mutex<HashMap<SessionId, (Session, bool)>>>,
}

impl InMemSessionRepo {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 测试种子接缝：种入活动会话（生产经 SessionUnitOfWork co-tx 写库，本 fake 用此直插）。
    /// `#[cfg(test)]`：仅本 crate 单测用——`seed-login`（journey）路径只构造空 `InMemSessionRepo`、
    /// 经 UoW 写会话，不经 insert ⇒ 非 test 的 seed-login 构建里 insert 无消费者（dead_code）。
    #[cfg(test)]
    pub(crate) fn insert(&self, session: Session) {
        recover(&self.sessions).insert(session.id().clone(), (session, false));
    }
}

impl SessionRepo for InMemSessionRepo {
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
    use super::{Credential, InMemCredentialRepo, InMemSessionRepo, TenantId};
    use crate::domain::{AccountStatus, IdentityError, Session, SessionId};
    use crate::ports::{CredentialRepo, SessionRepo};
    use std::time::{Duration, SystemTime};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant parses")
    }

    fn cred(subject: &str, password: &str, version: u32, tenant: TenantId) -> Credential {
        Credential::new(
            subject,
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
        Session::new(
            SessionId::new(sid),
            "alice-subject",
            tenant,
            now + Duration::from_secs(3_600),
            now,
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
        repo.save(cred("alice", "pw", 1, t)).await.expect("save");
        let found = repo.find(t, "alice".to_string()).await.expect("find");
        assert!(found.is_some());
        assert_eq!(found.expect("some").version(), 1);
        assert!(
            repo.find(t, "nobody".to_string())
                .await
                .expect("find")
                .is_none()
        );
    }

    #[tokio::test]
    async fn verify_password_correct_wrong_and_unknown() {
        let repo = InMemCredentialRepo::with_seed_credential("alice", "correct", tid(TENANT_A))
            .expect("seed");
        let t = tid(TENANT_A);
        assert!(
            repo.verify_password(t, "alice".to_string(), "correct".to_string())
                .await
                .expect("v")
        );
        assert!(
            !repo
                .verify_password(t, "alice".to_string(), "wrong".to_string())
                .await
                .expect("v")
        );
        // 查无主体 → false（恒定成本路径仍跑 argon2，F3；不 panic）。
        assert!(
            !repo
                .verify_password(t, "ghost".to_string(), "correct".to_string())
                .await
                .expect("v")
        );
    }

    #[tokio::test]
    async fn cross_tenant_find_verify_and_lockout_fail_closed() {
        let repo = InMemCredentialRepo::with_seed_credential("alice", "correct", tid(TENANT_A))
            .expect("seed");
        let a = tid(TENANT_A);
        let other = tid(TENANT_B);
        // 跨租赁查找 → None（不泄露存在性），验签 → false。
        assert!(
            repo.find(other, "alice".to_string())
                .await
                .expect("find")
                .is_none()
        );
        assert!(
            !repo
                .verify_password(other, "alice".to_string(), "correct".to_string())
                .await
                .expect("v")
        );
        // 在 TENANT_A 把 alice 锁定，TENANT_B 视角 lockout_status 仍 false（隔离，不推进/不读到别租计数）。
        let t0 = epoch(1_000);
        for i in 1..=5 {
            repo.record_failure(a, "alice".to_string(), t0 + Duration::from_secs(i))
                .await
                .expect("rf");
        }
        assert!(
            repo.lockout_status(a, "alice".to_string(), t0 + Duration::from_secs(5))
                .await
                .expect("ls")
        );
        assert!(
            !repo
                .lockout_status(other, "alice".to_string(), t0 + Duration::from_secs(5))
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
        repo.save(cred("alice", "pw", 1, a)).await.expect("save");
        // 跨租 bump：next 在 TENANT_B（key 派生自 next）→ 查无 → CredentialNotFound，不动 TENANT_A。
        let res = repo.bump_version(1, cred("alice", "pw2", 2, other)).await;
        assert!(matches!(res, Err(IdentityError::CredentialNotFound)));
        let still = repo
            .find(a, "alice".to_string())
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
        repo.save(cred("alice", "pw", 1, t)).await.expect("save");
        // 期望版本不匹配 → VersionConflict（key 派生自 next）。
        let conflict = repo.bump_version(99, cred("alice", "pw2", 2, t)).await;
        assert!(matches!(conflict, Err(IdentityError::VersionConflict)));
        // 期望版本命中 → 替换。
        repo.bump_version(1, cred("alice", "pw2", 2, t))
            .await
            .expect("cas hit");
        let found = repo
            .find(t, "alice".to_string())
            .await
            .expect("find")
            .expect("some");
        assert_eq!(found.version(), 2);
        assert!(found.verify_password("pw2"));
        // 查无凭据 → CredentialNotFound。
        let missing = repo.bump_version(1, cred("ghost", "x", 1, t)).await;
        assert!(matches!(missing, Err(IdentityError::CredentialNotFound)));
    }

    #[tokio::test]
    async fn record_failure_accumulates_atomically_then_locks() {
        // 原子 RMW（F1）：连续 record_failure 经仓储持久化累计——每次读的是已存计数（非外部 stale 副本）。
        let repo = InMemCredentialRepo::new();
        let t = tid(TENANT_A);
        let t0 = epoch(1_000);
        for i in 1..5 {
            let st = repo
                .record_failure(t, "alice".to_string(), t0 + Duration::from_secs(i))
                .await
                .expect("rf");
            assert_eq!(st, AccountStatus::Active, "第 {i} 次失败仍 Active");
        }
        // 第 5 次（窗口内）→ Locked。
        let st = repo
            .record_failure(t, "alice".to_string(), t0 + Duration::from_secs(5))
            .await
            .expect("rf");
        assert_eq!(st, AccountStatus::Locked);
        assert!(
            repo.lockout_status(t, "alice".to_string(), t0 + Duration::from_secs(5))
                .await
                .expect("ls")
        );
    }

    #[tokio::test]
    async fn lockout_status_lazy_unlocks_and_clear_resets() {
        let repo = InMemCredentialRepo::new();
        let t = tid(TENANT_A);
        let t0 = epoch(1_000);
        for i in 1..=5 {
            repo.record_failure(t, "alice".to_string(), t0 + Duration::from_secs(i))
                .await
                .expect("rf");
        }
        let lock_at = t0 + Duration::from_secs(5);
        let lock_ttl = Duration::from_secs(15 * 60);
        // TTL 内仍锁定。
        assert!(
            repo.lockout_status(
                t,
                "alice".to_string(),
                lock_at + lock_ttl - Duration::from_secs(1)
            )
            .await
            .expect("ls")
        );
        // lockout_status 在 TTL 后原子 lazy-unlock → false（且持久化解锁）。
        assert!(
            !repo
                .lockout_status(
                    t,
                    "alice".to_string(),
                    lock_at + lock_ttl + Duration::from_secs(1)
                )
                .await
                .expect("ls")
        );
        // 解锁后再失败从 1 重计（不沿用旧计数）→ Active。
        let after = lock_at + lock_ttl + Duration::from_secs(2);
        assert_eq!(
            repo.record_failure(t, "alice".to_string(), after)
                .await
                .expect("rf"),
            AccountStatus::Active
        );
        // clear_lockout 重置：未知主体幂等 Ok；清除后 status false。
        repo.clear_lockout(t, "alice".to_string())
            .await
            .expect("clear");
        assert!(
            !repo
                .lockout_status(t, "alice".to_string(), after)
                .await
                .expect("ls")
        );
        repo.clear_lockout(t, "ghost".to_string())
            .await
            .expect("clear idempotent");
    }

    // ---------------------------------------------------------------------------
    // InMemSessionRepo tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn session_repo_insert_find_roundtrip() {
        let repo = InMemSessionRepo::new();
        let ta = tid(TENANT_A);
        let session = make_session("sid-001", ta);
        repo.insert(session.clone());
        let found = repo
            .find(ta, SessionId::new("sid-001"))
            .await
            .expect("find ok");
        assert!(found.is_some(), "应能找到刚插入的会话");
        assert_eq!(found.expect("some").id().as_str(), "sid-001");
    }

    #[tokio::test]
    async fn session_repo_revoke_then_find_returns_none() {
        let repo = InMemSessionRepo::new();
        let ta = tid(TENANT_A);
        repo.insert(make_session("sid-002", ta));
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
    async fn session_repo_revoke_idempotent() {
        let repo = InMemSessionRepo::new();
        let ta = tid(TENANT_A);
        repo.insert(make_session("sid-003", ta));
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
    async fn session_repo_cross_tenant_find_returns_none() {
        let repo = InMemSessionRepo::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        repo.insert(make_session("sid-004", ta));
        // 用 TENANT_B 查 TENANT_A 的 session → None（不泄露存在性）。
        let found = repo
            .find(tb, SessionId::new("sid-004"))
            .await
            .expect("find ok");
        assert!(found.is_none(), "跨租查找应返回 None");
    }

    #[tokio::test]
    async fn session_repo_cross_tenant_revoke_noop_then_original_tenant_finds() {
        // TENANT_A 种入 → TENANT_B revoke（no-op）→ TENANT_A find 仍在。
        let repo = InMemSessionRepo::new();
        let ta = tid(TENANT_A);
        let tb = tid(TENANT_B);
        repo.insert(make_session("sid-005", ta));
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
