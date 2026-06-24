//! identity::domain::account — 账号状态机 / 凭据 / 账户锁定（dylint rss_domain_no_serialize 守护区）。
//!
//! 子域类型（spec 003 US3，PR3 独占本文件）：
//! - [`AccountStatus`]：账号生命周期闭值集 + 合法迁移判定（fail-closed）。
//! - [`Credential`]：argon2 哈希凭据（经 `secure::password`）+ 版本 pin（CAS）+ constant-time 验签；
//!   明文永不存、`password_hash` 字段经 [`secure::PasswordHash`] 类型层脱敏（Debug 不泄）。
//! - [`AccountLockout`]：暴力破解防御——阈值 5 / 滑窗 15min / 锁定 TTL 15min + lazy-unlock；窗口 / TTL
//!   判定经**调用方注入的 `Clock` 读出的 `now`** 计算（域类型不持 `Clock`、不调 `SystemTime::now()`，
//!   rust-standards §工程护栏；测试构造 `SystemTime` 模拟 fake-clock 推进）。
//!
//! 锁定状态经 [`crate::ports::CredentialRepo`] 持久化（多实例部署下内存态无法共享，暴破防御失效）。
//!
//! ref: RustCrypto/argon2 argon2/src/lib.rs@master（密码哈希，经 `secure::password`）
//! ref: OWASP ASVS V2.2 / NIST 800-63B §5.2.2（失败计数 + 窗口 + 锁定 TTL + lazy-unlock，无后台 job）

use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// AccountStatus — 账号状态（fail-closed）+ 合法迁移
// ---------------------------------------------------------------------------

/// 账号状态（闭值集，fail-closed）。
///
/// `pub`（[`crate::ports::CredentialRepo::record_failure`] 返回类型，被独立 adapter / 组合根跨 crate 收发）。
/// `#[non_exhaustive]`：对外保留扩展窗口（外部 crate match 须带 `_` 兜底）；域内穷举 match 仍由编译器守
/// 完整性（lib.rs smoke）。
///
/// 合法迁移（[`AccountStatus::can_transition_to`]，其余皆拒，含同态自迁——非迁移）：
/// - `Active` → `Suspended`（管理员暂停）/ `Locked`（[`AccountLockout`] 阈值触发）/ `Deactivated`（注销）。
/// - `Suspended` → `Active`（恢复）/ `Deactivated`。
/// - `Locked` → `Active`（lazy-unlock / 管理员解锁）/ `Deactivated`。
/// - `Deactivated` → ∅（终态，不可逆）。
// reason: 迁移判定（can_transition_to）生产消费方（账户门控）待 PR4/PR5；当前仅 test / smoke 消费 ⇒
// 非 test 构建 dead（ADR-004 C8 遗留期）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccountStatus {
    /// 正常激活。
    Active,
    /// 暂停（可恢复）。
    Suspended,
    /// 锁定（lazy-unlock 或管理员解锁；如多次登录失败）。
    Locked,
    /// 已注销（终态，不可逆）。
    Deactivated,
}

// reason: 同 enum（迁移判定生产消费方待 PR4；当前仅 test 消费）。
#[allow(dead_code)]
impl AccountStatus {
    /// 合法状态迁移判定（fail-closed：白名单外一律 `false`，含 `Deactivated` 终态与同态自迁）。
    pub(crate) fn can_transition_to(self, next: AccountStatus) -> bool {
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

// ---------------------------------------------------------------------------
// Credential — argon2 哈希凭据 + 版本 pin
// ---------------------------------------------------------------------------

/// 主体凭据：argon2 哈希密码 + 版本 pin（CAS）。
///
/// `pub`（ADR-005 Option 2）：作 [`crate::ports::CredentialRepo`] 签名实体被独立 adapter crate 跨 crate
/// 命名/收发；字段私有、构造器 `pub(crate)` funnel——外部可命名但**不可伪造**（fail-closed）。明文密码
/// **永不进入本类型**（仅 [`secure::hash_password`] 入参，哈希后丢弃）。
///
/// `Debug` 手写脱敏：`password_hash` 经 [`secure::PasswordHash`] 类型层已脱敏，`subject` 亦脱敏——零信任
/// 下 subject（UPN/email 派生或主体标识）按准 PII 处理，不随结构体打印进日志（observability §redaction）。
/// `tenant`（[`vocab::TenantId`]）有意保留原值：tenant id 是 audit/tracing 合法可观测字段、非凭据
/// （见 `vocab::tenant` rustdoc），脱敏反而损可观测。
// reason: 类型作 ports 签名实体已被引用；pub(crate) 方法生产消费方（LoginService）待 PR4 ⇒ 非 test 构建
// dead（ADR-004 C8 遗留期）。
#[allow(dead_code)]
#[derive(Clone)]
pub struct Credential {
    subject: String,
    tenant: vocab::TenantId,
    password_hash: secure::PasswordHash,
    version: u32,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("subject", &"<redacted>")
            .field("tenant", &self.tenant)
            .field("password_hash", &self.password_hash)
            .field("version", &self.version)
            .finish()
    }
}

// reason: 同 struct（生产消费方待 PR4；当前仅 test / seed-login 消费）。
#[allow(dead_code)]
impl Credential {
    /// 构造凭据（由已哈希密码；funnel 边界 = `pub(crate)`）。`version` 是 CAS pin（密码变更时 +1）。
    pub(crate) fn new(
        subject: impl Into<String>,
        tenant: vocab::TenantId,
        password_hash: secure::PasswordHash,
        version: u32,
    ) -> Self {
        Self {
            subject: subject.into(),
            tenant,
            password_hash,
            version,
        }
    }

    /// constant-time 验签：经 `secure::verify_password`（argon2 再哈希 + 常时比对，fail-closed）。
    pub(crate) fn verify_password(&self, candidate: &str) -> bool {
        secure::verify_password(candidate, &self.password_hash)
    }

    /// 密码轮换：返回 `version + 1` 的新凭据（subject / tenant 不变），供密码变更 CAS（PR4 编排）。
    pub(crate) fn rotate(&self, new_hash: secure::PasswordHash) -> Credential {
        Credential {
            subject: self.subject.clone(),
            tenant: self.tenant,
            password_hash: new_hash,
            version: self.version.saturating_add(1),
        }
    }

    /// 主体标识（opaque subject，FR-020 无 PII）。
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    /// 租户（RLS scope）。
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 凭据版本（CAS pin）。
    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    /// 密码哈希引用（adapter 持久化 PHC——经 [`secure::PasswordHash::as_str`]）。
    pub(crate) fn password_hash(&self) -> &secure::PasswordHash {
        &self.password_hash
    }
}

// ---------------------------------------------------------------------------
// AccountLockout — 失败计数 + 滑窗 + 锁定 TTL + lazy-unlock
// ---------------------------------------------------------------------------

/// 连续失败阈值（达此次数触发锁定）。OWASP ASVS V2.2 节流方向；RSS 取 5（缺口 P1-12）。
// reason: 锁定逻辑生产消费方（LoginService）待 PR4；当前仅 test / seed-login 消费（ADR-004 C8）。
#[allow(dead_code)]
const MAX_FAILURES: u32 = 5;
/// 失败计数滑动窗口（窗口外失败 lazy-reset 计数）。NIST 800-63B §5.2.2 失败窗口方向；RSS 取 15min。
#[allow(dead_code)]
const WINDOW: Duration = Duration::from_secs(15 * 60);
/// 锁定 TTL（达阈值后锁定时长，lazy-unlock，无后台 job）。RSS 取 15min。
#[allow(dead_code)]
const LOCK_TTL: Duration = Duration::from_secs(15 * 60);

/// 账户锁定态：失败计数 + 滑窗起点 + 锁定截止时刻。
///
/// 域内纯逻辑值类型（`pub(crate)`，不在 port 签名——锁定推进经 `CredentialRepo` 的**原子方法**
/// `record_failure` / `lockout_status` / `clear_lockout` 间接承载，见 ports.rs）。窗口 / TTL 判定全经
/// **调用方注入 `Clock` 读出的 `now: SystemTime`** 计算——域类型不持 `Clock`、不调 `SystemTime::now()`
/// （rust-standards §工程护栏；`record_failure`/`lockout_status` 的 `now` 参亦经注入 `Clock`，调用方禁直调
/// `SystemTime::now()`——clippy `disallowed-methods` 静态守）。
///
/// **多实例持久化契约（PR4 #1189 消费方义务）**：失败计数 = 安全关键状态，须经 `CredentialRepo` 跨实例
/// 共享且**原子**推进（非外部读-改-写，F1），否则负载均衡下各实例独立计数 / 并发丢更新、暴破防御失效。PR4
/// `LoginService` 登录路径 MUST：验签前 `CredentialRepo::lockout_status(now)` 拒绝已锁账户；验签失败后
/// `record_failure(now)`（原子 RMW，返回是否锁定）；成功后 `clear_lockout`。PR3 交付机制 + 原子 port + 替身，
/// 编排接线随 PR4（spec 003 US3 addendum；缺失则多实例暴破防御静默失效）。
// reason: 类型 pub(crate)、方法生产消费方（LoginService / W postgres adapter）待 PR4 / #1258 ⇒ 非 test 构建
// dead（ADR-004 C8 遗留期）。
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AccountLockout {
    failure_count: u32,
    window_start: SystemTime,
    locked_until: Option<SystemTime>,
}

// reason: 同 struct（生产消费方待 PR4；当前仅 test / seed-login 消费）。
#[allow(dead_code)]
impl AccountLockout {
    /// 新建锁定态（零失败、未锁定；滑窗锚定 `now`）。`now` 由调用方注入 `Clock` 读出。
    pub(crate) fn new(now: SystemTime) -> Self {
        Self {
            failure_count: 0,
            window_start: now,
            locked_until: None,
        }
    }

    /// 从持久化字段重建（adapter 加载锁定态时）。
    pub(crate) fn from_parts(
        failure_count: u32,
        window_start: SystemTime,
        locked_until: Option<SystemTime>,
    ) -> Self {
        Self {
            failure_count,
            window_start,
            locked_until,
        }
    }

    /// 记录一次失败，返回结果账号状态（`Locked` 当且仅当达阈值）。
    ///
    /// 滑窗语义：窗口过期（`now ≥ window_start + WINDOW`）→ 重开滑窗（计数清零、锚定 `now`）；累加；
    /// 达 [`MAX_FAILURES`] → `locked_until = now + LOCK_TTL` 返回 `Locked`，否则 `Active`。窗口锚定于
    /// [`AccountLockout::new`] 创建时刻（首次失败不重锚）。「窗口恰好到期」（`now == window_start + WINDOW`）
    /// 按过期处理（计数重置，第 N 次失败不触发锁定）。时钟回拨（`now < window_start`）按过期 fail-safe 重锚。
    ///
    /// **边界安全语义**：窗口重锚不放宽锁定判定——当次失败仍记入新窗口第 1 次，攻击者精准踩窗口边界
    /// **不能**额外获益（重锚后仍需累计 `MAX_FAILURES` 次才锁定，「免费重置」只把计数清零、不增可用尝试）。
    pub(crate) fn record_failure(&mut self, now: SystemTime) -> AccountStatus {
        let window_expired = match now.duration_since(self.window_start) {
            Ok(elapsed) => elapsed >= WINDOW,
            // 时钟回拨：fail-safe 重锚滑窗（不沿用旧计数）。
            Err(_) => true,
        };
        if window_expired {
            self.window_start = now;
            self.failure_count = 0;
        }
        self.failure_count = self.failure_count.saturating_add(1);
        if self.failure_count >= MAX_FAILURES {
            self.locked_until = Some(now + LOCK_TTL);
            AccountStatus::Locked
        } else {
            AccountStatus::Active
        }
    }

    /// lazy-unlock：锁定 TTL 已过（`now ≥ locked_until`，含恰好到期）→ 清锁定 + 计数归零，返回 `true`；
    /// 未锁定 / 未到期 → `false`。无后台 job（OWASP/NIST lazy 模型）。
    pub(crate) fn try_lazy_unlock(&mut self, now: SystemTime) -> bool {
        match self.locked_until {
            // duration_since(until) 为 Ok ⇔ now ≥ until（含恰好到期）⇒ TTL 过期。
            Some(until) if now.duration_since(until).is_ok() => {
                self.locked_until = None;
                self.failure_count = 0;
                true
            }
            _ => false,
        }
    }

    /// 当前是否仍锁定（`locked_until` 存在且 `now < locked_until`；恰好到期视为未锁定，与 lazy-unlock 一致）。
    pub(crate) fn is_locked(&self, now: SystemTime) -> bool {
        match self.locked_until {
            // duration_since(until) 为 Err ⇔ now < until ⇒ 仍在锁定 TTL 内。
            Some(until) => now.duration_since(until).is_err(),
            None => false,
        }
    }

    /// 当前失败计数（持久化 / 测试断言）。
    pub(crate) fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// 滑窗起点（持久化）。
    pub(crate) fn window_start(&self) -> SystemTime {
        self.window_start
    }

    /// 锁定截止时刻（持久化；`None` = 未锁定）。
    pub(crate) fn locked_until(&self) -> Option<SystemTime> {
        self.locked_until
    }
}

// ---------------------------------------------------------------------------
// 测试（表驱动；状态机 / 验签 / 锁定 / lazy-unlock / 临界边界 / 脱敏）
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{AccountLockout, AccountStatus, Credential, LOCK_TTL, MAX_FAILURES, WINDOW};
    use std::time::{Duration, SystemTime};

    use rstest::rstest;

    // canonical UUID 种子租户（vocab::TenantId::parse 接受形态）。
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    fn tid(raw: &str) -> vocab::TenantId {
        vocab::TenantId::parse(raw).expect("canonical tenant parses")
    }

    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn credential(subject: &str, password: &str, version: u32) -> Credential {
        let hash = secure::hash_password(password).expect("hash ok");
        Credential::new(subject, tid(CANON_TENANT), hash, version)
    }

    // --- AccountStatus 合法迁移（表驱动，含同态自迁与终态 fail-closed） ---

    #[rstest]
    #[case::active_suspend(AccountStatus::Active, AccountStatus::Suspended, true)]
    #[case::active_lock(AccountStatus::Active, AccountStatus::Locked, true)]
    #[case::active_deactivate(AccountStatus::Active, AccountStatus::Deactivated, true)]
    #[case::suspend_resume(AccountStatus::Suspended, AccountStatus::Active, true)]
    #[case::suspend_deactivate(AccountStatus::Suspended, AccountStatus::Deactivated, true)]
    #[case::locked_unlock(AccountStatus::Locked, AccountStatus::Active, true)]
    #[case::locked_deactivate(AccountStatus::Locked, AccountStatus::Deactivated, true)]
    // fail-closed：非法边
    #[case::active_self(AccountStatus::Active, AccountStatus::Active, false)]
    #[case::suspend_lock(AccountStatus::Suspended, AccountStatus::Locked, false)]
    #[case::locked_suspend(AccountStatus::Locked, AccountStatus::Suspended, false)]
    #[case::deactivated_terminal(AccountStatus::Deactivated, AccountStatus::Active, false)]
    #[case::deactivated_self(AccountStatus::Deactivated, AccountStatus::Deactivated, false)]
    fn account_status_transition(
        #[case] from: AccountStatus,
        #[case] to: AccountStatus,
        #[case] allowed: bool,
    ) {
        assert_eq!(from.can_transition_to(to), allowed, "{from:?} → {to:?}");
    }

    // --- Credential 验签 + 版本 + 脱敏 ---

    #[test]
    fn credential_verify_correct_and_wrong() {
        let cred = credential("alice-subject", "correct-horse", 1);
        assert!(cred.verify_password("correct-horse"));
        assert!(!cred.verify_password("wrong"));
        assert_eq!(cred.subject(), "alice-subject");
        assert_eq!(cred.version(), 1);
        assert_eq!(cred.tenant(), tid(CANON_TENANT));
    }

    #[test]
    fn credential_debug_redacts_password_hash_and_subject() {
        let cred = credential("alice-subject", "s3cr3t-pw", 1);
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("<redacted>"), "password_hash 必须脱敏");
        assert!(!dbg.contains("s3cr3t-pw"), "Debug 不得泄明文");
        assert!(!dbg.contains("argon2"), "Debug 不得泄哈希摘要");
        assert!(
            !dbg.contains("alice-subject"),
            "Debug 不得泄 subject（准 PII，零信任脱敏）"
        );
        // tenant 有意可见（可观测标识、非凭据）。
        assert!(
            dbg.contains(CANON_TENANT),
            "tenant 应保留（audit/tracing 合法字段）"
        );
    }

    #[test]
    fn credential_rotate_bumps_version_and_swaps_hash() {
        let cred = credential("alice-subject", "old-pw", 3);
        let new_hash = secure::hash_password("new-pw").expect("hash ok");
        let rotated = cred.rotate(new_hash);
        assert_eq!(rotated.version(), 4, "rotate +1");
        assert_eq!(rotated.subject(), "alice-subject");
        assert!(rotated.verify_password("new-pw"));
        assert!(!rotated.verify_password("old-pw"), "旧密码失效");
    }

    // --- AccountLockout 计数 / 阈值 / 锁定 ---

    #[test]
    fn lockout_locks_after_threshold_failures_in_window() {
        let t0 = epoch_plus(1_000);
        let mut lk = AccountLockout::new(t0);
        // 前 4 次失败：仍 Active，未锁定。
        for i in 1..MAX_FAILURES {
            let st = lk.record_failure(t0 + Duration::from_secs(i.into()));
            assert_eq!(st, AccountStatus::Active, "第 {i} 次失败仍 Active");
            assert!(!lk.is_locked(t0 + Duration::from_secs(i.into())));
        }
        // 第 5 次（窗口内）：锁定。
        let st = lk.record_failure(t0 + Duration::from_secs(5));
        assert_eq!(st, AccountStatus::Locked);
        assert_eq!(lk.failure_count(), MAX_FAILURES);
        assert!(lk.is_locked(t0 + Duration::from_secs(5)));
        assert_eq!(
            lk.locked_until(),
            Some(t0 + Duration::from_secs(5) + LOCK_TTL)
        );
    }

    #[test]
    fn lockout_resets_count_when_window_expired() {
        let t0 = epoch_plus(1_000);
        let mut lk = AccountLockout::new(t0);
        // 4 次失败积累。
        for i in 1..MAX_FAILURES {
            lk.record_failure(t0 + Duration::from_secs(i.into()));
        }
        assert_eq!(lk.failure_count(), MAX_FAILURES - 1);
        // 下一次失败发生在窗口**之后** → lazy-reset，计数从 1 重新计。
        let after_window = t0 + WINDOW + Duration::from_secs(1);
        let st = lk.record_failure(after_window);
        assert_eq!(st, AccountStatus::Active, "窗口过期重置后单次失败不锁定");
        assert_eq!(lk.failure_count(), 1);
    }

    // --- 临界边界：窗口恰好到期 ---

    #[test]
    fn lockout_window_boundary_exact_expiry_resets() {
        let t0 = epoch_plus(1_000);
        let mut lk = AccountLockout::new(t0);
        // 4 次失败（锚定窗口于 t0）。
        for i in 1..MAX_FAILURES {
            lk.record_failure(t0 + Duration::from_secs(i.into()));
        }
        assert_eq!(lk.failure_count(), MAX_FAILURES - 1);
        // 第 5 次恰好在 window_start + WINDOW（边界按过期处理）→ 计数重置为 1，不锁定。
        let st = lk.record_failure(t0 + WINDOW);
        assert_eq!(
            st,
            AccountStatus::Active,
            "窗口恰好到期 → 重置，第 5 次不锁定"
        );
        assert_eq!(lk.failure_count(), 1);
        assert!(!lk.is_locked(t0 + WINDOW));
    }

    // --- lazy-unlock + 锁定 TTL 临界边界 ---

    #[test]
    fn lazy_unlock_after_ttl_resets_and_unlocks() {
        let t0 = epoch_plus(1_000);
        let mut lk = AccountLockout::new(t0);
        for i in 1..=MAX_FAILURES {
            lk.record_failure(t0 + Duration::from_secs(i.into()));
        }
        let lock_at = t0 + Duration::from_secs(MAX_FAILURES.into());
        assert!(lk.is_locked(lock_at));
        // TTL 内：仍锁定，lazy-unlock 不动作。
        let within = lock_at + LOCK_TTL - Duration::from_secs(1);
        assert!(!lk.try_lazy_unlock(within));
        assert!(lk.is_locked(within));
        // TTL 过后：lazy-unlock 解锁 + 计数归零。
        let after = lock_at + LOCK_TTL + Duration::from_secs(1);
        assert!(lk.try_lazy_unlock(after));
        assert!(!lk.is_locked(after));
        assert_eq!(lk.failure_count(), 0);
        assert_eq!(lk.locked_until(), None);
    }

    #[test]
    fn lazy_unlock_ttl_boundary_exact_expiry_unlocks() {
        let t0 = epoch_plus(1_000);
        let mut lk = AccountLockout::new(t0);
        for i in 1..=MAX_FAILURES {
            lk.record_failure(t0 + Duration::from_secs(i.into()));
        }
        let lock_at = t0 + Duration::from_secs(MAX_FAILURES.into());
        let until = lk.locked_until().expect("locked");
        assert_eq!(until, lock_at + LOCK_TTL);
        // 恰好到 locked_until：视为未锁定（与 try_lazy_unlock 一致）。
        assert!(!lk.is_locked(until), "TTL 恰好到期 → 未锁定");
        assert!(lk.try_lazy_unlock(until), "TTL 恰好到期 → lazy-unlock 成功");
    }

    #[test]
    fn lockout_clock_rollback_resets_window_and_does_not_lock() {
        // 时钟回拨（now < window_start）：record_failure 走 Err(_) fail-safe 重锚分支——
        // 计数清零后从 1 重新计，单次失败不锁定（不沿用回拨前累计）。
        let t0 = epoch_plus(1_000);
        let mut lk = AccountLockout::new(t0);
        for i in 1..MAX_FAILURES {
            lk.record_failure(t0 + Duration::from_secs(i.into()));
        }
        assert_eq!(lk.failure_count(), MAX_FAILURES - 1);
        let past = epoch_plus(500); // now < window_start ⇒ duration_since Err
        let st = lk.record_failure(past);
        assert_eq!(st, AccountStatus::Active, "回拨重锚后单次失败不锁定");
        assert_eq!(lk.failure_count(), 1);
        assert_eq!(lk.window_start(), past, "滑窗重锚到回拨时刻");
    }

    #[test]
    fn lockout_from_parts_roundtrips_fields_and_behavior() {
        let t0 = epoch_plus(2_000);
        let lk = AccountLockout::from_parts(3, t0, Some(t0 + LOCK_TTL));
        // 字段回读。
        assert_eq!(lk.failure_count(), 3);
        assert_eq!(lk.window_start(), t0);
        assert_eq!(lk.locked_until(), Some(t0 + LOCK_TTL));
        // 行为语义：重建的锁定态在 TTL 内仍锁定、恰好到期解锁。
        assert!(lk.is_locked(t0 + Duration::from_secs(1)), "TTL 内仍锁定");
        assert!(!lk.is_locked(t0 + LOCK_TTL), "TTL 恰好到期 → 未锁定");
    }
}
