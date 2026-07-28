//! identity — RSS 身份/RBAC/ABAC 域（值类型与纯逻辑签名冻结）。
//!
//! 本 crate 承载身份域的核心值类型、RBAC/ABAC 纯计算接缝、错误枚举与**域形 repo/service DI port**。
//! provider-agnostic 基建 DI port（`Clock`/`Signer`/`Publisher`/`AuditSink`…）归 `diport`（ADR-003）；
//! **域形** repo port（签名引用域内实体 `Role`/`RoleId`，无法收敛 diport）归本 crate `ports` 模块
//! （ADR-005 Option 2，category line 见 ADR-005 / domain-patterns.md）。
//! 所有域类型字段私有，只经显式构造 funnel 创建——外部不可伪造，fail-closed（ADR-001）。
//!
//! # 实现状态（部分写实）
//!
//! `domain` 子域分层推进（spec 003 wave 拆分）：
//! - **RBAC（`domain::rbac`）+ 共享 newtype funnel（`domain::mod`）已写实**（`authorize_rbac` subject+tenant
//!   匹配 + 表驱动测试；newtype 严格白名单 parse）——PR1。
//! - **ABAC（`domain::abac`：`evaluate_abac` / `Policy` / typed `Operator` + `PolicyEffect`）已写实**
//!   （deny-overrides + 租户门 + 重复 key / 类型不匹配 fail-closed + 表驱动测试）——PR2。
//! - **账号安全子域（`domain::account_security` + `domain::account`）已写实**：durable 四值 lifecycle、
//!   authn epoch/version/CAS、sealed active receipt/mutation，以及与 lifecycle 分轨的临时暴破阻断。
//!
//! `application`（登录生命周期：[`LoginService`] / [`IdentityDomain`]）**已写实**——哈希凭据使用
//! constant-time digest 比较与有界 KDF（未知/弱档至少支付当前档工作）+ lockout 门控/原子推进 + L2 co-tx
//! （AuthGrant + 初始 refresh + `identity.session-created` outbox 同一事务）+ 密码变更
//! CAS + AuthGrant 关闭；in-mem DI 替身覆盖单测/journey，生产由 PostgreSQL 原子认证漏斗与持久状态真源承载。
//! `application` 模块私有，只 re-export facade。
//!
//! # 对标
//!
//! ref: casbin/casbin-rs src/core_api.rs@master（enforce 元组求值）
//! ref: casbin/casbin-rs src/rbac/default_role_manager.rs@master（domain 多租隔离）
//! ref: eclipse-biscuit/biscuit-rust biscuit-auth/src/token/mod.rs@main（pub(crate) 字段 + funnel）

#![forbid(unsafe_code)]

/// 应用层：登录生命周期编排（验签 / lockout / co-tx / 密码变更 / logout）+ bootstrap 生命周期。私有——
/// 只经 facade re-export 暴露，不外泄内部实现（domain-patterns.md §序列化边界 / 封装）。
mod application;
pub(crate) mod domain;
mod internal;
pub mod ports;

pub use application::{
    AccessGrantValidationError, AuthGrantServices, AuthGrantValidationService, ChangePasswordError,
    CredentialSecurityService, CurrentAuthGrant, FederatedIdentityDomain,
    FederatedIdentityDomainDeps, IdentityDomain, IdentityDomainDeps, LoginError, LoginService,
    PolicyManageError, PolicyManageService, RbacAdminError, RbacAdminService, RefreshBundle,
    RefreshError, RefreshService, ValidatedAuthGrant,
};
/// Demo/journey 首发 token 装配（seed-login/test 门控；生产经组合根注入 vault `Signer`，#1252）。
#[cfg(any(test, feature = "seed-login"))]
pub use application::{SeedSigner, seed_auth_grant_services};
pub use domain::{
    AccountCredentialSecurityCommand, AccountSecurityHydrationError, AccountSecurityMutation,
    AccountSecuritySnapshot, AccountSecurityState, AccountSecurityTransitionError,
    AccountSecurityVersion, AccountStatus, CredentialSecurityCommand, CredentialSecurityEvent,
    CredentialSecurityReceipt, CredentialSecurityTargetKind, CredentialSecurityTargetRef,
    GrantCredentialSecurityCommand, LogoutAllCommand, LogoutCurrentCommand, RefreshRotationOutcome,
};
pub use ports::AuthGrantProvider;

/// 测试支撑——仅 `test-support` feature（test/dev 构建）启用，生产不编译（funnel seal 不变）。
///
/// 下游 adapter crate（postgres）集成测试需构造 [`authn::AuthGrant`] 驱动
/// `ports::AuthGrantLifecycle`，及 [`ports::LoginIdentifier`](crate::ports::LoginIdentifier) 驱动
/// `ports::CredentialRepo::authenticate`（#1316）。AuthGrant 自身由 canonical `authn` 类型的验证构造器
/// 建立；`LoginIdentifier::new` 仍为 `pub(crate)` funnel。本模块经 feature 门控暴露其余受控构造器——与
/// `authn::test_support` 同信任模型（生产构建不编译 ⇒ funnel seal 不变）。
#[cfg(feature = "test-support")]
pub mod test_support {
    use std::sync::Arc;
    use std::time::SystemTime;

    use vocab::TenantId;

    /// Mint the route-typed login producer receipt for adapter tests that bypass the HTTP router.
    pub fn login_producer_receipt() -> crate::ports::LoginProducerReceipt {
        httpserve::ProducerMarker::for_test(generated::http::identity_v1::login::PRODUCER)
            .into_receipt()
    }

    /// Parse a canonical user id for downstream adapter tests without adding a direct `ids` edge.
    #[allow(clippy::expect_used)]
    pub fn user_id(raw: &str) -> ids::UserId {
        ids::UserId::parse(raw).expect("test user id must be canonical")
    }

    use crate::domain::{
        AccountSecuritySnapshot, AccountSecurityState, CredentialSecurityCommand, LoginIdentifier,
        LogoutAllCommand, LogoutCurrentCommand, RefreshTokenHash, RefreshTokenId,
        RefreshTokenRecord,
    };
    use authn::{
        AccountSecurityEventKind, AuthGrant, AuthGrantId, AuthGrantSnapshot, AuthGrantStatus,
        AuthnEpoch, GrantSecurityEventKind,
    };

    /// Mount the production logout handler for downstream adapter integration tests.
    pub fn logout_router(
        service: Arc<crate::CredentialSecurityService>,
        evidence: crate::CurrentAuthGrant,
    ) -> axum::Router {
        crate::application::logout_router_for_test(service, evidence)
    }

    /// Construct opaque current-grant evidence for downstream integration tests.
    pub fn current_auth_grant(
        grant_id: &str,
        user_id: ids::UserId,
        tenant_id: TenantId,
        authn_epoch: u64,
    ) -> crate::CurrentAuthGrant {
        crate::CurrentAuthGrant::for_test(
            ids::CanonicalUuidV4::parse(grant_id).expect("test grant id must be canonical UUIDv4"),
            user_id,
            tenant_id,
            authn_epoch,
        )
    }

    /// 构造测试用 [`AuthGrant`]（经域 funnel；仅 test/dev 构建）。
    #[allow(clippy::expect_used)]
    pub fn auth_grant(
        grant_id: &str,
        user_id: ids::UserId,
        tenant: TenantId,
        auth_time: SystemTime,
        authn_epoch_at_issue: AuthnEpoch,
        expires_at: SystemTime,
        created_at: SystemTime,
    ) -> AuthGrant {
        AuthGrant::hydrate(AuthGrantSnapshot {
            id: AuthGrantId::hydrate(grant_id).expect("test auth grant id must be UUIDv4"),
            tenant,
            user_id,
            auth_time,
            authn_epoch_at_issue,
            status: AuthGrantStatus::Active,
            expires_at,
            created_at,
            closed_at: None,
            close_reason: None,
        })
        .expect("test auth grant must satisfy state invariants")
    }

    /// Hydrate a validated account-security state for downstream adapter integration tests.
    #[allow(clippy::expect_used)]
    pub fn account_security_state(snapshot: AccountSecuritySnapshot) -> AccountSecurityState {
        AccountSecurityState::try_from(snapshot)
            .expect("test account-security snapshot must satisfy state invariants")
    }

    /// Build an account-wide credential-security command through the sealed domain constructor.
    #[allow(clippy::expect_used)]
    pub fn account_credential_security_command(
        state: AccountSecurityState,
        kind: AccountSecurityEventKind,
        occurred_at: SystemTime,
    ) -> CredentialSecurityCommand {
        CredentialSecurityCommand::account(state, kind, occurred_at)
            .expect("test account credential-security command must satisfy state invariants")
    }

    /// Build a grant-local credential-security command through the sealed domain constructor.
    #[allow(clippy::expect_used)]
    pub fn grant_credential_security_command(
        grant: AuthGrant,
        kind: GrantSecurityEventKind,
        occurred_at: SystemTime,
    ) -> CredentialSecurityCommand {
        CredentialSecurityCommand::grant(grant, kind, occurred_at)
            .expect("test grant credential-security command must satisfy state invariants")
    }

    /// Build the route-specific logout-all command; the returned type cannot be passed to the
    /// logout-current lifecycle method.
    #[allow(clippy::expect_used)]
    pub fn logout_all_command(
        state: AccountSecurityState,
        occurred_at: SystemTime,
    ) -> LogoutAllCommand {
        CredentialSecurityCommand::logout_all(state, occurred_at)
            .expect("test logout-all command must satisfy state invariants")
    }

    /// Build the route-specific logout-current command; the returned type cannot be passed to the
    /// logout-all lifecycle method.
    #[allow(clippy::expect_used)]
    pub fn logout_current_command(
        grant: AuthGrant,
        occurred_at: SystemTime,
    ) -> LogoutCurrentCommand {
        CredentialSecurityCommand::logout_current(grant, occurred_at)
            .expect("test logout-current command must satisfy state invariants")
    }

    /// Construct an initial refresh record derived from the exact test AuthGrant binding.
    #[allow(clippy::expect_used)]
    pub fn initial_refresh(
        grant: &AuthGrant,
        refresh_id: &str,
        token_hash: [u8; 32],
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> RefreshTokenRecord {
        RefreshTokenRecord::new_initial(
            grant,
            RefreshTokenId::new(refresh_id),
            RefreshTokenHash::new(token_hash),
            issued_at,
            expires_at,
        )
        .expect("test initial refresh must satisfy grant and time invariants")
    }

    /// Derive a test rotation through the same source-bound domain funnel used in production.
    #[allow(clippy::expect_used)]
    pub fn refresh_rotation(
        source: &RefreshTokenRecord,
        refresh_id: &str,
        token_hash: [u8; 32],
        issued_at: SystemTime,
    ) -> crate::ports::RefreshRotation {
        source
            .begin_rotation(
                RefreshTokenId::new(refresh_id),
                RefreshTokenHash::new(token_hash),
                issued_at,
            )
            .expect("test rotation must satisfy source binding and time invariants")
    }

    /// Build the generated `identity.session-created` fact carried by a login-grant mutation.
    #[allow(clippy::expect_used)]
    pub fn session_created_entry(event_id: &str, grant: &AuthGrant) -> consistency::EventEntry {
        let payload =
            generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
                session_id: grant.id().as_str().to_owned(),
                subject: grant.user_id().as_uuid(),
                tenant_id: grant.tenant().to_string(),
                occurred_at: crate::application::unix_secs(grant.created_at()),
            };
        consistency::EventEntry::from_generated_payload(
            &payload,
            consistency::IdemKey::parse(event_id)
                .expect("test event id must satisfy idempotency-key shape"),
        )
        .expect("generated session-created payload must encode")
    }

    /// 构造测试用 [`LoginIdentifier`]（登录查找键；经域 funnel；仅 test/dev 构建）。下游 adapter 集成测试需
    /// 为任意 login（含未种子化的「未知主体」）构造查找键传入 `authenticate`——而 known
    /// 主体可经 `credential.login().clone()` 取得，故本入口主要服务 unknown / 跨租 fail-closed 用例（#1316 F2）。
    pub fn login_identifier(raw: &str) -> LoginIdentifier {
        LoginIdentifier::new(raw)
    }
}

/// `identity.login` 契约测试样板（#1136）——用 `testkit` harness 给 served HTTP 契约写 per-contract
/// 测试的模板（正常 schema / 参数错误 + 错误码）。鉴权边界 / path newtype 维度按层分裂，见模块 rustdoc。
#[cfg(test)]
mod login_contract;

// ---------------------------------------------------------------------------
// smoke test（绑函数指针锁签名 / 构造 Copy enum；行为正确性见子模块表驱动单测）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod smoke {
    //! build smoke：锁签名稳定（绑函数指针证明可被引用消费）+ 闭值集 enum 可构造 + Send 约束。
    //! 行为正确性由各子模块（`domain::{rbac,abac}`）的表驱动单测覆盖。

    use crate::domain::{
        AbacAttribute, AccountLockout, AccountStatus, AttributeKey, AttributeValue, Credential,
        IdentityError, Operator, Permission, PermissionId, Policy, PolicyCondition, PolicyEffect,
        PolicyId, PolicyObligations, PolicyRouteScope, PolicyRule, PolicyVersion,
        ResourceAttribute, ResourceAttributeKey, ResourceAttributeResourceId,
        ResourceAttributeVersion, ResourcePattern, Role, RoleBinding, RoleId, authorize_rbac,
        evaluate_abac,
    };
    use authn::{AuthGrant, AuthGrantId};

    // 证明主要类型是 Send（跨 await 点传播）。
    fn _assert_send<T: Send>() {}

    #[test]
    fn domain_types_are_send() {
        _assert_send::<RoleId>();
        _assert_send::<PermissionId>();
        _assert_send::<PolicyId>();
        _assert_send::<Role>();
        _assert_send::<Permission>();
        _assert_send::<ResourcePattern>();
        _assert_send::<RoleBinding>();
        _assert_send::<AbacAttribute>();
        _assert_send::<AttributeKey>();
        _assert_send::<AttributeValue>();
        _assert_send::<Policy>();
        _assert_send::<PolicyVersion>();
        _assert_send::<PolicyRouteScope>();
        _assert_send::<PolicyCondition>();
        _assert_send::<PolicyRule>();
        _assert_send::<PolicyObligations>();
        _assert_send::<ResourceAttributeKey>();
        _assert_send::<ResourceAttributeResourceId>();
        _assert_send::<ResourceAttributeVersion>();
        _assert_send::<ResourceAttribute>();
        _assert_send::<Credential>();
        _assert_send::<AccountLockout>();
        _assert_send::<AuthGrantId>();
        _assert_send::<AuthGrant>();
    }

    #[test]
    fn account_status_enum_is_constructable_and_exhaustive() {
        let _status: AccountStatus = AccountStatus::Active;

        // 穷尽 match（non_exhaustive crate 内合法穷举）
        match _status {
            AccountStatus::Active => {}
            AccountStatus::Suspended => {}
            AccountStatus::Locked => {}
            AccountStatus::Deactivated => {}
        }
    }

    #[test]
    fn identity_error_enum_is_exhaustive() {
        // 穷尽 match 证明 IdentityError variant 完整（crate 内）
        let e = IdentityError::RoleNotFound;
        match e {
            IdentityError::RoleNotFound => {}
            IdentityError::PolicyNotFound => {}
            IdentityError::PolicyAlreadyExists => {}
            IdentityError::PermissionDenied => {}
            IdentityError::InvalidPolicy => {}
            IdentityError::CredentialNotFound => {}
            IdentityError::VersionConflict => {}
            IdentityError::OutboxFactConflict(_) => {}
            IdentityError::SecurityFactBuild(_) => {}
            IdentityError::SecurityPayloadEncode(_) => {}
            IdentityError::ProviderUnavailable(_) => {}
            IdentityError::Storage(_) => {}
        }
    }

    #[test]
    fn newtype_fn_signatures_are_consumable() {
        // parse funnel：显式类型标注锁签名（不调用 → 不触 todo!()）
        let _: fn(&str) -> Result<RoleId, crate::domain::IdParseError> = RoleId::parse;
        let _: fn(&str) -> Result<PermissionId, crate::domain::IdParseError> = PermissionId::parse;
        let _: fn(&str) -> Result<PolicyId, crate::domain::IdParseError> = PolicyId::parse;
        let _: fn(&str) -> Result<AttributeKey, crate::domain::AttributeKeyError> =
            AttributeKey::parse;
        let _: fn(&str) -> Result<ResourcePattern, crate::domain::PatternError> =
            ResourcePattern::parse;

        // as_str accessor：显式类型标注锁签名（不调用）
        let _: fn(&RoleId) -> &str = RoleId::as_str;
        let _: fn(&PermissionId) -> &str = PermissionId::as_str;
        let _: fn(&PolicyId) -> &str = PolicyId::as_str;
        let _: fn(&ResourcePattern) -> &str = ResourcePattern::as_str;
        let _: fn(&AttributeKey) -> &str = AttributeKey::as_str;
        let _: fn(&AttributeValue) -> &str = AttributeValue::as_str;

        // Role accessor：显式类型标注锁签名
        let _: fn(&Role) -> &RoleId = Role::id;
        let _: fn(&Role) -> &str = Role::name;
        let _: fn(&Role) -> &[vocab::GrantPermission] = Role::permissions;

        // Permission accessor
        let _: fn(&Permission) -> &PermissionId = Permission::id;
        let _: fn(&Permission) -> &vocab::Action = Permission::action;
        let _: fn(&Permission) -> &ResourcePattern = Permission::resource_pattern;

        // RoleBinding accessor
        let _: fn(&RoleBinding) -> &str = RoleBinding::subject;
        let _: fn(&RoleBinding) -> &RoleId = RoleBinding::role_id;
        let _: fn(&RoleBinding) -> vocab::TenantId = RoleBinding::tenant;

        // Policy accessor
        let _: fn(&Policy) -> &PolicyId = Policy::id;
        let _: fn(&Policy) -> vocab::TenantId = Policy::tenant;
        let _: fn(&Policy) -> &[PolicyRule] = Policy::rules;

        // PolicyRule accessor
        let _: fn(&PolicyRule) -> &AttributeKey = PolicyRule::attribute_key;
        let _: fn(&PolicyRule) -> &Operator = PolicyRule::operator;
        let _: fn(&PolicyRule) -> PolicyEffect = PolicyRule::effect;

        // AbacAttribute accessor
        let _: fn(&AbacAttribute) -> &AttributeKey = AbacAttribute::key;
        let _: fn(&AbacAttribute) -> &AttributeValue = AbacAttribute::value;
    }

    #[test]
    fn pure_logic_fn_signatures_are_consumable() {
        // 绑定自由函数指针（不调用 → 不触 todo!()）
        let _: fn(&authn::Principal, &[RoleBinding], &[Role], &Permission) -> vocab::Decision =
            authorize_rbac;

        // evaluate_abac 新签名：_principal 位参使租户隔离由签名承载（Hard）
        let _: fn(&authn::Principal, &[AbacAttribute], &Policy) -> vocab::Decision = evaluate_abac;
    }

    #[test]
    fn constructor_signatures_are_consumable() {
        // Role / Permission / RoleBinding / Policy 构造器签名可绑定（impl Into<String> 泛型用 String 实例化）
        let _: fn(RoleId, String, Vec<vocab::GrantPermission>) -> Role = Role::new;
        let _: fn(PermissionId, vocab::Action, ResourcePattern) -> Permission = Permission::new;
        let _: fn(String, RoleId, vocab::TenantId) -> RoleBinding = RoleBinding::new;
        let _: fn(AttributeKey, AttributeValue) -> AbacAttribute = AbacAttribute::new;
        let _: fn(PolicyId, vocab::TenantId, Vec<PolicyRule>) -> Policy = Policy::new;
        let _: fn(AttributeKey, Operator, PolicyEffect) -> PolicyRule = PolicyRule::new;
        // AttributeValue::new：impl Into<String> 用 String 实例化
        let _: fn(String) -> AttributeValue = AttributeValue::new;
        // RoleId::new / PermissionId::new
        let _: fn(String) -> RoleId = RoleId::new;
        let _: fn(String) -> PermissionId = PermissionId::new;
    }
}
