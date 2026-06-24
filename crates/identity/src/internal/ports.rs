//! 域内仓储 port（非 DI-swappable provider，留域内——见 domain-patterns.md §internal 模块例外）。
//!
//! **G1 tracer（删除随 PR4 #1189）**：`UserAccount` + `UserRepo` 是 RW-G1 明文登录追踪弹。PR3 已落真实
//! `CredentialRepo`（域形 DI port，哈希凭据 + 锁定）+ in-mem 替身（`super::mem::InMemCredentialRepo`）；本 tracer
//! 的删除与 PR4 `LoginService` 重接线 `CredentialRepo`（消费 + `X-Tenant-ID`→tenant + username→subject 解析）
//! 原子完成（spec 003 T015 defer 到 PR4——PR3 删之即破坏 `application.rs` 登录编译）。

/// 已认证主体的最小账户视图（仓储查询结果）。
///
/// **TRACER-ONLY**：`password` 为明文、比对用 `==`（RW-G1 追踪弹只为打通登录接缝）。**禁止照抄进生产**——
/// 真实凭据走哈希 + 常时比对 + 凭据存储（PR3 已落 `Credential` / `CredentialRepo`，本 tracer 删除随 PR4 #1189）。
/// `Debug` 手写脱敏 password（防 PII 进日志，error-handling.md §PII）。
/// `tenant_id` 为 canonical UUID 字符串（登录时解析为 `vocab::TenantId`，fail-closed）。
#[derive(Clone)]
pub(crate) struct UserAccount {
    pub(crate) subject: String,
    pub(crate) tenant_id: String,
    pub(crate) password: String,
}

impl std::fmt::Debug for UserAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserAccount")
            .field("subject", &self.subject)
            .field("tenant_id", &self.tenant_id)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// 用户仓储 port（域内）。生产 impl（postgres adapter）留 W；本 crate 提供 in-mem 实现（[`super::mem`]）。
pub(crate) trait UserRepo: Send + Sync {
    /// 按用户名查账户；不存在返回 `None`。
    fn find(&self, username: &str) -> Option<UserAccount>;
}
