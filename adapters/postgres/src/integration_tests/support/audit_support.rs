use super::*;

// read/write/admin traits 须在 scope 才能调用 append / list / verify_tail / verify_tenant 方法。
pub(in super::super) use audit::ports::{
    AuditAdminRepo as _, AuditReadRepo as _, AuditWriteRepo as _,
};

// base64::Engine::encode 须在 scope（URL_SAFE_NO_PAD.encode(...)）。
pub(in super::super) use base64::Engine as _;

/// 构造审计仓储（共享 pool，固定 0x5a key hasher）。
pub(in super::super) fn make_audit_repo(
    store: &PgStore,
) -> crate::PgAuditRepo<crate::audit_repo::test_support::TestVerifier> {
    crate::PgAuditRepo::from_unverified_for_test(
        store,
        crate::audit_repo::test_support::test_hasher(0x5a),
    )
}

/// 构造 audit admin 只读仓储（固定 0x5a key hasher）。
pub(in super::super) fn make_audit_admin_repo(
    store: &PgStore,
) -> crate::PgAuditAdminRepo<crate::audit_repo::test_support::TestVerifier> {
    crate::PgAuditAdminRepo::from_unverified_for_test(
        store,
        crate::audit_repo::test_support::test_hasher(0x5a),
    )
}

/// 构造审计记录（nanos 可变，其余字段固定；actor UUID 硬编码确定性 ID）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 helper——固定格式 UUID / action parse 不失败；item-level carve-out。
pub(in super::super) fn make_audit_record(
    tenant: vocab::TenantId,
    nanos: u32,
) -> audit::ports::AuditRecord {
    use std::time::{Duration, UNIX_EPOCH};
    audit::ports::AuditRecord {
        tenant,
        actor: ids::UserId::parse("11111111-2222-4333-8444-555555555555").unwrap(),
        actor_kind: vocab::PrincipalKind::User,
        action: vocab::Action::parse("audit:read").unwrap(),
        resource: audit::ports::ResourceRef::new("session", "sess-1"),
        outcome: audit::ports::AuditOutcome::Success,
        recorded_at: UNIX_EPOCH + Duration::new(1_700_000_000, nanos),
    }
}

/// 构造分页请求（limit ≤ 500 不失败）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 helper——limit 值由测试代码控制，均合法；item-level carve-out。
pub(in super::super) fn audit_page(
    limit: u16,
    cursor: Option<vocab::Cursor>,
) -> audit::ports::AuditPage {
    audit::ports::AuditPage {
        limit: vocab::Limit::new(limit).unwrap(),
        cursor,
    }
}
