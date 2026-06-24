//! identity::domain::account — 账号状态值类型（dylint rss_domain_no_serialize 守护区）。
//!
//! 当前只承载 `AccountStatus` 闭值集；账号锁定（lockout）/ 凭据 / 密码 CAS 行为留 PR3（spec 003 US3）。

// ---------------------------------------------------------------------------
// AccountStatus — 账号状态（fail-closed）
// ---------------------------------------------------------------------------

/// 账号状态（闭值集，fail-closed；`#[non_exhaustive]` 保留扩展窗口）。
///
/// 默认行为：未知状态视同 `Suspended`——fail-closed。
// reason: 签名冻结期枚举尚无调用方，dead_code 来自冻结期（ADR-004 C8）；行为消费待 PR3。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum AccountStatus {
    /// 正常激活。
    Active,
    /// 暂停（可恢复）。
    Suspended,
    /// 锁定（需管理员解锁，如多次登录失败）。
    Locked,
    /// 已注销（不可恢复）。
    Deactivated,
}
