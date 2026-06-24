//! 认证主体类别词汇（基础层单一源）。
//!
//! `PrincipalKind` 是跨层共用的脱敏标量：`authn::Principal.kind`（认证派生）、`httpserve::Authenticated`
//! 证据 extension（每路由放行决策）、`audit` 的 `actor_kind`（审计分层）均消费同一枚举。落基础层 `vocab`
//! 以杜绝多处镜像枚举的双源漂移（与 `vocab::TenantId` 同属基础值词汇，ADR-002 §D3 精神：值词汇落 basis，
//! 认证 / 派生行为留 service）。

/// 认证主体类别（驱动 [`crate::RowScope`] 派生；闭值集，fail-closed）。
///
/// `Service` / `Anonymous` 派生为受限 RowScope（见 `docs/rules/tenancy.md`）。
///
/// 消费方（authn / httpserve / audit）`match` 应列全已知变体、**勿用 `_` 静默吞新变体**；新增 / 删除变体由本 crate
/// 内穷举守卫（PRINCIPALKIND-EXHAUSTIVE-01）于编译期捕获。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrincipalKind {
    /// 普通终端用户。
    User,
    /// 设备主体（MDM 管理设备，L4 场景）。
    Device,
    /// 管理员（域级）。
    Admin,
    /// 超管（跨租户，仅平台授权层可造）。
    SuperAdmin,
    /// 服务账号（内部服务间 token）。
    Service,
    /// 匿名访客（fail-closed：RowScope 受限，不得升级权限）。
    Anonymous,
}

#[cfg(test)]
mod tests {
    use super::PrincipalKind;

    /// 闭值集穷举守卫：定义 crate 内 `non_exhaustive` 仍可无 `_` 穷举——新增变体时本 match 编译失败，
    /// 强制同步全部消费方（authn 派生 / httpserve `Authenticated` 证据 / audit 分层）。
    /// INVARIANT: PRINCIPALKIND-EXHAUSTIVE-01（Hard，编译期；anti-vacuity：移除任一变体即编译错误）。
    #[test]
    fn principal_kind_is_exhaustive() {
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
            PrincipalKind::SuperAdmin,
            PrincipalKind::Service,
            PrincipalKind::Anonymous,
        ] {
            match kind {
                PrincipalKind::User
                | PrincipalKind::Device
                | PrincipalKind::Admin
                | PrincipalKind::SuperAdmin
                | PrincipalKind::Service
                | PrincipalKind::Anonymous => {}
            }
        }
    }
}
