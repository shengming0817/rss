//! identity::domain::account — 账号状态机 / 凭据 / 账户锁定（dylint rss_domain_no_serialize 守护区）。
//!
//! 子域类型（spec 003 US3，PR3 独占本文件；#1277 增 LoginIdentifier / AuthOutcome 分层）：
//! - [`AccountStatus`]：账号生命周期闭值集 + 合法迁移判定（fail-closed）。
//! - [`LoginIdentifier`]：登录标识 newtype（不透明查找键；与 canonical [`ids::UserId`] 类型层不可混淆，F1）。
//! - [`AuthOutcome`]：验签原子结果三态（`Authenticated(UserId)` / `InvalidKnownUser` / `InvalidUnknown`），
//!   provider 内「验签 + 仅对已知主体推进 lockout」单一出口（F1+F2）。
//! - [`Credential`]：[`LoginIdentifier`] 查找键 + canonical [`ids::UserId`] subject + argon2 哈希凭据（经
//!   `secure::password`）+ 版本 pin（CAS）+ constant-time digest 比较 / 有界 KDF 验签；明文永不存、`password_hash` 经
//!   [`secure::PasswordHash`] 类型层脱敏（Debug 不泄）。
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
/// `pub`（账户状态闭值集，被独立 adapter / 组合根跨 crate 收发）；账户门控生产消费方待 PR5/W，当前由
/// [`AccountLockout::record_failure`] 作推进结果返回（域内）。`#[non_exhaustive]`：对外保留扩展窗口
/// （外部 crate match 须带 `_` 兜底）；域内穷举 match 仍由编译器守完整性（lib.rs smoke）。
///
/// 合法迁移（[`AccountStatus::can_transition_to`]，其余皆拒，含同态自迁——非迁移）：
/// - `Active` → `Suspended`（管理员暂停）/ `Locked`（[`AccountLockout`] 阈值触发）/ `Deactivated`（注销）。
/// - `Suspended` → `Active`（恢复）/ `Deactivated`。
/// - `Locked` → `Active`（lazy-unlock / 管理员解锁）/ `Deactivated`。
/// - `Deactivated` → ∅（终态，不可逆）。
// reason: 迁移判定（can_transition_to）生产消费方（账户门控）待 PR5/W；当前仅 test / smoke 消费 ⇒
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

// reason: 同 enum（迁移判定生产消费方待 PR5/W 账户门控；当前仅 test 消费）。
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
// LoginIdentifier — 登录标识（opaque 查找键，与 canonical UserId 类型层不可混淆，#1277 F1）
// ---------------------------------------------------------------------------

/// 登录标识：用户输入的不透明凭据查找键（username / email / UPN）。
///
/// `pub`（ADR-005 Option 2）：作 [`crate::ports::CredentialRepo`] 签名实体被独立 adapter crate 跨 crate
/// 命名/收发（adapter 以 [`as_str`](LoginIdentifier::as_str) 做 `(tenant, login)` 查找键）；构造经 `pub(crate)`
/// funnel——只在域内（登录应用边界 `LoginIdentifier::new(request.username)`）铸造，外部可命名/读值但**不可伪造**。
///
/// **与 [`ids::UserId`] 的类型层分层（#1277 F1）**：登录标识 ≠ canonical actor subject。登录标识是攻击者
/// 可控的查找键（写不进 wire / audit）；canonical subject（[`Credential::user_id`]）才是写入
/// `IdentitySessionCreatedPayload.subject` / outbox / 审计 actor 的稳定 UUID。二者为不同类型 ⇒「把 username
/// 当 canonical subject 写进 wire」从类型层不可表达（AI-HARD：错位不可编译）。
///
/// `Debug` 手写脱敏：登录标识零信任下按准 PII 处理（可能为 email/UPN），不随结构体打印进日志。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LoginIdentifier(String);

impl std::fmt::Debug for LoginIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginIdentifier(<redacted>)")
    }
}

impl LoginIdentifier {
    /// 铸造登录标识（funnel 边界 = `pub(crate)`，仅域内构造）。登录标识是不透明查找键，无句法白名单——
    /// 任意用户输入（email/UPN/username）皆合法；空串亦可构造但永不匹配任何凭据（fail-closed，不额外校验、
    /// 不返回 `Result`：凭据查找失败已是统一 `InvalidCredentials` 出口）。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 取登录标识字符串引用（adapter 做 `(tenant, login)` 查找键）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// AuthOutcome — 验签原子结果（provider 内「验签 + 仅对已知主体推进 lockout」单一出口，#1277）
// ---------------------------------------------------------------------------

/// 验签结果（[`crate::ports::CredentialRepo::authenticate`] 返回；消费方据此分流，#1277 F1+F2）。
///
/// `pub`（adapter 跨 crate 构造/返回）。`#[non_exhaustive]` 保留扩展窗口。三态语义：
/// - [`Authenticated`](AuthOutcome::Authenticated)：已知主体 + 密码正确——携 canonical [`ids::UserId`]
///   （写 payload/envelope/session subject，audit 必可 `UserId::parse`）；provider 已原子清零失败计数。
/// - [`InvalidKnownUser`](AuthOutcome::InvalidKnownUser)：已知主体 + 密码错——provider 已**原子推进** lockout。
/// - [`InvalidUnknown`](AuthOutcome::InvalidUnknown)：查无凭据——当前 profile KDF 已跑（关闭零 KDF 快路径），但
///   **不建 / 不动 lockout 态**（#1277 F2：未知主体不可被预置锁定、不撑大 lockout 表）。
///
/// 消费方对 `InvalidKnownUser` / `InvalidUnknown` 一律对外返回 `InvalidCredentials`（不向客户端区分以防枚举）；
/// 二者之别只用于 provider 内 lockout 推进决策（已收进本 outcome，不外泄）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthOutcome {
    /// 已知主体 + 密码正确：canonical actor subject（写 wire / audit）。
    Authenticated(ids::UserId),
    /// 已知主体 + 密码错（provider 已推进 lockout）。
    InvalidKnownUser,
    /// 查无凭据（当前 profile KDF 已跑；不动 lockout 态）。
    InvalidUnknown,
}

// ---------------------------------------------------------------------------
// Credential — 登录标识 + canonical UserId + argon2 哈希凭据 + 版本 pin
// ---------------------------------------------------------------------------

/// 主体凭据：[`LoginIdentifier`] 查找键 + canonical [`ids::UserId`] subject + argon2 哈希密码 + 版本 pin（CAS）。
///
/// `pub`（ADR-005 Option 2）：作 [`crate::ports::CredentialRepo`] 签名实体被独立 adapter crate 跨 crate
/// 命名/收发；字段私有、构造器 `pub(crate)` funnel——外部可命名但**不可伪造**（fail-closed）。明文密码
/// **永不进入本类型**（仅 [`secure::PasswordHash`] 封装持久化 PHC）。
///
/// **登录标识 vs canonical subject（#1277 F1）**：`login` 是凭据查找键（攻击者可控的不透明输入）；`user_id`
/// 是稳定 canonical actor subject——登录成功后**仅** `user_id` 写入 session / `IdentitySessionCreatedPayload`
/// / outbox envelope（audit `ids::UserId::parse` 必通），`login`（准 PII）永不进 wire / broker metadata。
///
/// `Debug` 手写脱敏：`password_hash` 经 [`secure::PasswordHash`] 类型层已脱敏，`login`（[`LoginIdentifier`]）
/// 亦脱敏（准 PII）。`tenant` / `user_id` 有意保留原值：均为 audit/tracing 合法可观测标识、非凭据
/// （见 `vocab::tenant` rustdoc），脱敏反而损可观测。
// 类型作 ports 签名实体被独立 adapter crate 跨 crate 收发；数据访问器（login/user_id/tenant/password_hash/
// version）+ hydrate 受控重建经 #1316 `PgCredentialRepo` 跨 crate 消费（pub，公共 API）。`new` /
// verify_password / rotate 仍 `pub(crate)`（域内 seed-login / change_password 用，非 adapter 面）。
#[derive(Clone)]
pub struct Credential {
    login: LoginIdentifier,
    user_id: ids::UserId,
    tenant: vocab::TenantId,
    password_hash: secure::PasswordHash,
    version: u32,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("login", &self.login) // LoginIdentifier Debug 已脱敏
            .field("user_id", &self.user_id) // canonical UUID：可观测 actor 标识、非凭据
            .field("tenant", &self.tenant)
            .field("password_hash", &self.password_hash)
            .field("version", &self.version)
            .finish()
    }
}

// reason: verify_password / rotate 已被 LoginService::change_password 消费（prod）；数据访问器 + hydrate
// 升 `pub`（#1316 `PgCredentialRepo` 跨 crate 消费，公共 API）。仅 `new`（`pub(crate)`）非 test 构建无调用方
// （seed-login 门控）⇒ 保留 impl 级 allow 防其 non-test dead_code。
#[allow(dead_code)]
impl Credential {
    /// 构造凭据（由已哈希密码；funnel 边界 = `pub(crate)`）。`login` = 登录查找键，`user_id` = canonical
    /// actor subject，`version` 是 CAS pin（密码变更时 +1）。
    pub(crate) fn new(
        login: LoginIdentifier,
        user_id: ids::UserId,
        tenant: vocab::TenantId,
        password_hash: secure::PasswordHash,
        version: u32,
    ) -> Self {
        Self {
            login,
            user_id,
            tenant,
            password_hash,
            version,
        }
    }

    /// 由持久化值受控重建凭据（adapter 读路径 funnel；对标 [`crate::ports::Role`]`::hydrate`）。`login` 为存储的
    /// 登录查找键，`password_hash` 为 adapter 经 [`secure::PasswordHash::parse`] 校验回读的 PHC。字段私有不变
    /// ⇒ 外部经本 `pub` 入口可重建但**不可伪造任意内部表示**（funnel，#1316 `PgCredentialRepo::find_by_user_id`）。
    pub fn hydrate(
        login: &str,
        user_id: ids::UserId,
        tenant: vocab::TenantId,
        password_hash: secure::PasswordHash,
        version: u32,
    ) -> Credential {
        Credential {
            login: LoginIdentifier::new(login),
            user_id,
            tenant,
            password_hash,
            version,
        }
    }

    /// Typed bounded verification with a current-profile work floor. Success returns an
    /// unforgeable receipt owned by secure.
    pub(crate) fn verify_password(
        &self,
        candidate: secure::RawPassword,
    ) -> Result<secure::PasswordVerification, secure::PasswordError> {
        secure::verify_password(candidate, Some(&self.password_hash))
    }

    /// 密码轮换：只接受策略批准值，返回 `version + 1` 的新凭据供密码变更 CAS。
    pub(crate) fn rotate(
        &self,
        password: secure::ValidatedPassword,
    ) -> Result<Credential, secure::PasswordError> {
        let new_hash = secure::PasswordHash::from_validated(password)?;
        Ok(Credential {
            login: self.login.clone(),
            user_id: self.user_id,
            tenant: self.tenant,
            password_hash: new_hash,
            version: self.version.saturating_add(1),
        })
    }

    /// Replace a verified physical PHC encoding without changing the logical credential version.
    pub(crate) fn replace_hash_if_unchanged(
        &mut self,
        expected: &secure::PasswordHash,
        replacement: secure::PasswordHash,
    ) -> bool {
        if &self.password_hash != expected {
            return false;
        }
        self.password_hash = replacement;
        true
    }

    /// 登录标识（opaque 查找键；store key 派生用，FR-020 准 PII）。`pub`（#1316 adapter 取 `(tenant, login)` PK）。
    pub fn login(&self) -> &LoginIdentifier {
        &self.login
    }

    /// canonical actor subject（稳定 UUID；登录成功后写 payload/envelope/session subject，audit actor，#1277 F1）。
    /// `pub`（#1316 adapter 绑 `credentials.user_id` 列）。
    pub fn user_id(&self) -> ids::UserId {
        self.user_id
    }

    /// 租户（RLS scope）。`pub`（#1316 adapter 绑 `credentials.tenant_id` 列）。
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 凭据版本（CAS pin）。`pub`（#1316 adapter 绑 `credentials.version` 列）。
    pub fn version(&self) -> u32 {
        self.version
    }

    /// 密码哈希引用（adapter 持久化 PHC——经 [`secure::PasswordHash::as_str`]）。`pub`（#1316 adapter 绑
    /// `credentials.password_hash` 列）。
    pub fn password_hash(&self) -> &secure::PasswordHash {
        &self.password_hash
    }
}

// ---------------------------------------------------------------------------
// AccountLockout — 失败计数 + 滑窗 + 锁定 TTL + lazy-unlock
// ---------------------------------------------------------------------------

/// 连续失败阈值（达此次数触发锁定）。OWASP ASVS V2.2 节流方向；RSS 取 5（缺口 P1-12）。
/// 策略阈值域内单源——`record_failure` 据此判定锁定；adapter（#1316 `PgCredentialRepo`）仅持久化 I/O，
/// 不复刻阈值（避免域逻辑外泄进 adapter）。
const MAX_FAILURES: u32 = 5;
/// 失败计数滑动窗口（窗口外失败 lazy-reset 计数）。NIST 800-63B §5.2.2 失败窗口方向；RSS 取 15min。
const WINDOW: Duration = Duration::from_secs(15 * 60);
/// 锁定 TTL（达阈值后锁定时长，lazy-unlock，无后台 job）。RSS 取 15min。
const LOCK_TTL: Duration = Duration::from_secs(15 * 60);

/// 账户锁定态：失败计数 + 滑窗起点 + 锁定截止时刻。
///
/// **adapter-facing 辅助类型**（`pub`，经 `ports` facade re-export，#1316）：**不在任何 port 方法签名**——锁定推进
/// 经 `CredentialRepo::authenticate`/`lockout_status` 内部**原子**承载（#1277 折叠后无独立 `record_failure`/
/// `clear_lockout` port 方法，见 ports.rs）。升 `pub` 是 ADR-005「最小实体集」之外的**必要扩展**（区别于 port 签名
/// 实体 `Credential`/`LoginIdentifier`/`AuthOutcome`）：`PgCredentialRepo` 须在事务/行锁内 `from_parts` 重建 →
/// `record_failure`/`try_lazy_unlock` 推进 → 访问器回写持久化三列，策略阈值仍域内单源、字段私有不可伪造，无法收敛。
/// 窗口 / TTL 判定全经
/// **调用方注入 `Clock` 读出的 `now: SystemTime`** 计算——域类型不持 `Clock`、不调 `SystemTime::now()`
/// （rust-standards §工程护栏；`authenticate`/`lockout_status` 的 `now` 参亦经注入 `Clock`，调用方禁直调
/// `SystemTime::now()`——clippy `disallowed-methods` 静态守）。
///
/// **多实例持久化契约（#1189 + #1277 消费方义务）**：失败计数 = 安全关键状态，须经 `CredentialRepo` 跨实例
/// 共享且**原子**推进（非外部读-改-写，F1），否则负载均衡下各实例独立计数 / 并发丢更新、暴破防御失效。
/// `LoginService` 登录路径：验签前 `CredentialRepo::lockout_status(now)` 拒绝已锁账户；`authenticate(now)`
/// 内部据 `AuthOutcome` 原子完成「已知+错推进失败计数（达阈值即锁）/ 已知+正确清零 / 未知不动」——验签与
/// lockout 推进收进单一原子调用（不再外部分步 record/clear，#1277）。postgres adapter（W #1258）须在
/// 事务/行锁内等价实现该原子性；缺失则多实例暴破防御静默失效。
// AccountLockout 升 `pub` 公共 API（经 ports facade re-export，#1316）：`PgCredentialRepo` 在事务内
// `from_parts` 重建 → `record_failure`/`try_lazy_unlock` 推进 → 访问器回写三列；策略阈值（5/15min/15min）
// 域内单源、adapter 仅 I/O。锁定推进不在 port 签名（折叠进 `authenticate`/`lockout_status` 内部承载），但
// 类型本身跨 crate 收发。全方法 `pub` ⇒ 公共 API 可达，非 dead（无需 allow）。
#[derive(Debug, Clone)]
pub struct AccountLockout {
    failure_count: u32,
    window_start: SystemTime,
    locked_until: Option<SystemTime>,
}

impl AccountLockout {
    /// 新建锁定态（零失败、未锁定；滑窗锚定 `now`）。`now` 由调用方注入 `Clock` 读出。
    pub fn new(now: SystemTime) -> Self {
        Self {
            failure_count: 0,
            window_start: now,
            locked_until: None,
        }
    }

    /// 从持久化字段重建（adapter 加载锁定态时）。`pub`（#1316 `PgCredentialRepo` 在事务内由三列重建）。
    pub fn from_parts(
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
    pub fn record_failure(&mut self, now: SystemTime) -> AccountStatus {
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
    pub fn try_lazy_unlock(&mut self, now: SystemTime) -> bool {
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
    pub fn is_locked(&self, now: SystemTime) -> bool {
        match self.locked_until {
            // duration_since(until) 为 Err ⇔ now < until ⇒ 仍在锁定 TTL 内。
            Some(until) => now.duration_since(until).is_err(),
            None => false,
        }
    }

    /// 当前失败计数（持久化 / 测试断言）。`pub`（#1316 adapter 回写 `credentials.failure_count`）。
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// 滑窗起点（持久化）。`pub`（#1316 adapter 回写 `credentials.lockout_window_start`）。
    pub fn window_start(&self) -> SystemTime {
        self.window_start
    }

    /// 锁定截止时刻（持久化；`None` = 未锁定）。`pub`（#1316 adapter 回写 `credentials.locked_until`）。
    pub fn locked_until(&self) -> Option<SystemTime> {
        self.locked_until
    }
}

// ---------------------------------------------------------------------------
// 测试（表驱动；状态机 / 验签 / 锁定 / lazy-unlock / 临界边界 / 脱敏）
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        AccountLockout, AccountStatus, Credential, LOCK_TTL, LoginIdentifier, MAX_FAILURES, WINDOW,
    };
    use std::time::{Duration, SystemTime};

    use rstest::rstest;

    // canonical UUID 种子租户（vocab::TenantId::parse 接受形态）。
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    // canonical UUID 种子 user id（audit actor 形态；与登录标识 "alice-login" 解耦，#1277 F1）。
    const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";

    fn tid(raw: &str) -> vocab::TenantId {
        vocab::TenantId::parse(raw).expect("canonical tenant parses")
    }

    fn uid(raw: &str) -> ids::UserId {
        ids::UserId::parse(raw).expect("canonical user id parses")
    }

    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn validated(password: &str) -> secure::ValidatedPassword {
        secure::PasswordPolicy::for_test("passwordpassword", &[])
            .validate(secure::RawPassword::new(password.to_owned()))
            .expect("password satisfies test policy")
    }

    fn verifies(credential: &Credential, password: &str) -> bool {
        matches!(
            credential
                .verify_password(secure::RawPassword::new(password.to_owned()))
                .expect("stored test PHC is valid"),
            secure::PasswordVerification::Verified(_)
        )
    }

    fn credential(login: &str, user: &str, password: &str, version: u32) -> Credential {
        let hash = secure::PasswordHash::for_test(secure::RawPassword::new(password.to_owned()))
            .expect("hash ok");
        Credential::new(
            LoginIdentifier::new(login),
            uid(user),
            tid(CANON_TENANT),
            hash,
            version,
        )
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
        let cred = credential("alice-login", CANON_USER, "correct-horse", 1);
        assert!(verifies(&cred, "correct-horse"));
        assert!(!verifies(&cred, "wrong"));
        // 登录标识与 canonical actor subject 解耦（#1277 F1）。
        assert_eq!(cred.login().as_str(), "alice-login");
        assert_eq!(cred.user_id(), uid(CANON_USER));
        assert_eq!(cred.version(), 1);
        assert_eq!(cred.tenant(), tid(CANON_TENANT));
    }

    #[test]
    fn credential_debug_redacts_password_hash_and_login() {
        let cred = credential("alice-login", CANON_USER, "s3cr3t-pw", 1);
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("<redacted>"), "password_hash 必须脱敏");
        assert!(!dbg.contains("s3cr3t-pw"), "Debug 不得泄明文");
        assert!(!dbg.contains("argon2"), "Debug 不得泄哈希摘要");
        assert!(
            !dbg.contains("alice-login"),
            "Debug 不得泄登录标识（准 PII，零信任脱敏）"
        );
        // tenant / user_id 有意可见（可观测 actor 标识、非凭据）。
        assert!(
            dbg.contains(CANON_TENANT),
            "tenant 应保留（audit/tracing 合法字段）"
        );
        assert!(
            dbg.contains(CANON_USER),
            "user_id 应保留（canonical actor，audit/tracing 合法字段）"
        );
    }

    #[test]
    fn credential_rotate_bumps_version_and_swaps_hash() {
        let cred = credential("alice-login", CANON_USER, "old-pw", 3);
        let rotated = cred
            .rotate(validated("a-compliant-new-password"))
            .expect("hash validated password");
        assert_eq!(rotated.version(), 4, "rotate +1");
        // rotate 保持登录标识 + canonical subject 不变。
        assert_eq!(rotated.login().as_str(), "alice-login");
        assert_eq!(
            rotated.user_id(),
            uid(CANON_USER),
            "rotate 保持 canonical subject"
        );
        assert!(verifies(&rotated, "a-compliant-new-password"));
        assert!(!verifies(&rotated, "old-pw"), "旧密码失效");
    }

    #[test]
    fn credential_hydrate_roundtrips_persisted_fields() {
        // adapter 读路径 funnel（#1316）：hydrate(已校验 PHC + 类型化字段) → 访问器回读一致 + 验签仍真。
        let phc = secure::PasswordHash::for_test(secure::RawPassword::new("rebuilt-pw".to_owned()))
            .expect("hash ok");
        let cred = Credential::hydrate("alice-login", uid(CANON_USER), tid(CANON_TENANT), phc, 7);
        assert_eq!(cred.login().as_str(), "alice-login");
        assert_eq!(cred.user_id(), uid(CANON_USER));
        assert_eq!(cred.tenant(), tid(CANON_TENANT));
        assert_eq!(cred.version(), 7, "version 随重建保真");
        assert!(verifies(&cred, "rebuilt-pw"), "hydrate 回读 PHC 验签真");
        assert!(!verifies(&cred, "wrong"));
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
