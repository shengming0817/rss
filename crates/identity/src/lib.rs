//! identity — RSS 身份/RBAC/ABAC 域。
//!
//! 已写实：RBAC / ABAC 纯计算、账号安全与登录生命周期（验签 / lockout / L2 co-tx / refresh / 密码变更），
//! 以及**域形** repo/service DI port。本 crate 承载身份域核心值类型、错误枚举与端口；
//! provider-agnostic 基建 DI port（`Clock`/`Signer`/`Publisher`/`AuditSink`…）归 `diport`（ADR-003）；
//! **域形** repo port（签名引用域内实体 `Role`/`RoleId`，无法收敛 diport）归本 crate `ports` 模块
//! （ADR-005 Option 2，category line 见 ADR-005，并由 Rust visibility 限定）。
//! 所有域类型字段私有，只经显式构造 funnel 创建——外部不可伪造，fail-closed（ADR-001）。
//!
//! # 实现状态
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
/// 只经 facade re-export 暴露，不外泄内部实现（由 Rust visibility 限定）。
mod application;
mod cert_artifact;
mod device_certificate;
pub(crate) mod domain;
mod internal;
pub(crate) mod outbox_emit;
pub mod ports;

pub use application::{
    AccessGrantValidationError, AccountStatusChangeError, AuthGrantServices,
    AuthGrantValidationService, ChangePasswordError, CredentialSecurityService, CurrentAuthGrant,
    DeviceResourceFactPip, DeviceResourceFactPipError, FederatedIdentityDomain,
    FederatedIdentityDomainDeps, IdentityDomain, IdentityDomainDeps, LoginError, LoginService,
    PolicyManageError, PolicyManageService, RbacAdminError, RbacAdminService, RefreshBundle,
    RefreshError, RefreshService, ValidatedAuthGrant, build_contract_authorizer,
};
/// Demo/journey 首发 token 装配（seed-login/test 门控；生产经组合根注入 vault `Signer`，#1252）。
#[cfg(any(test, feature = "seed-login"))]
pub use application::{SeedSigner, seed_auth_grant_services};
pub use domain::{
    AccountCredentialSecurityCommand, AccountSecurityHydrationError, AccountSecurityMutation,
    AccountSecuritySnapshot, AccountSecurityState, AccountSecurityTransitionError,
    AccountSecurityVersion, AccountStatus, AccountStatusSetCommand, CredentialSecurityCommand,
    CredentialSecurityEvent, CredentialSecurityInitiator, CredentialSecurityReceipt,
    CredentialSecurityTargetKind, CredentialSecurityTargetRef, GrantCredentialSecurityCommand,
    LogoutAllCommand, LogoutCurrentCommand, PasswordChangeCommand, PasswordChangeCommandError,
    ReactivateAccountCommand,
};
pub use ports::{ATTR_VALUE_MAX_LEN, AuthGrantProvider};

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

    use rss_request_context::TenantId;

    /// Evaluate policies loaded by a downstream adapter through the same PDP function used by the
    /// production contract authorizer. This seam is test-only so persistence providers can prove
    /// that durable typed operators retain their authorization semantics after hydration.
    pub fn evaluate_policies_for_test(
        tenant: TenantId,
        attributes: &[crate::ports::AbacAttribute],
        policies: &[crate::ports::Policy],
    ) -> vocab::Decision {
        match crate::domain::evaluate_policies_for_tenant(Some(tenant), attributes, policies) {
            crate::domain::PolicyEvaluation::Allow(_) => vocab::Decision::Allow,
            crate::domain::PolicyEvaluation::NoMatch | crate::domain::PolicyEvaluation::Deny => {
                vocab::Decision::Deny
            }
        }
    }

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

    /// Mint the sealed tenant/device scope for downstream adapter conformance tests.
    pub fn device_certificate_scope(
        tenant: TenantId,
        device: ids::DeviceId,
    ) -> crate::ports::device_certificate::DeviceCertificateScope {
        crate::device_certificate::DeviceCertificateScope::from_authorized(tenant, device)
    }

    /// Mint a role-mutation actor from a canonical test identity.
    pub fn role_mutation_actor(
        tenant: rss_request_context::TenantId,
        user_id: ids::UserId,
        kind: rss_request_context::PrincipalKind,
    ) -> Result<crate::ports::RoleMutationActor, crate::ports::IdentityError> {
        crate::ports::RoleMutationActor::for_test_user(tenant, user_id, kind)
    }

    use crate::domain::{
        AccountSecuritySnapshot, AccountSecurityState, AccountStatus, AccountStatusSetCommand,
        Credential, CredentialSecurityCommand, CredentialSecurityInitiator, LoginIdentifier,
        LogoutAllCommand, LogoutCurrentCommand, PasswordChangeCommand, ReactivateAccountCommand,
        RefreshTokenHash, RefreshTokenId, RefreshTokenRecord,
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
    #[allow(clippy::expect_used)]
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
        let initiator = CredentialSecurityInitiator::authenticated(
            state.tenant(),
            rss_request_context::PrincipalKind::User,
            state.user_id().as_uuid().hyphenated().to_string(),
        );
        CredentialSecurityCommand::account(state, kind, initiator, occurred_at)
            .expect("test account credential-security command must satisfy state invariants")
    }

    /// Build a grant-local credential-security command through the sealed domain constructor.
    #[allow(clippy::expect_used)]
    pub fn grant_credential_security_command(
        grant: AuthGrant,
        kind: GrantSecurityEventKind,
        occurred_at: SystemTime,
    ) -> CredentialSecurityCommand {
        let initiator = CredentialSecurityInitiator::authenticated(
            grant.tenant(),
            rss_request_context::PrincipalKind::User,
            grant.user_id().as_uuid().hyphenated().to_string(),
        );
        CredentialSecurityCommand::grant(grant, kind, initiator, occurred_at)
            .expect("test grant credential-security command must satisfy state invariants")
    }

    /// Build the route-specific logout-all command; the returned type cannot be passed to the
    /// logout-current lifecycle method.
    #[allow(clippy::expect_used)]
    pub fn logout_all_command(
        state: AccountSecurityState,
        occurred_at: SystemTime,
    ) -> LogoutAllCommand {
        let initiator = CredentialSecurityInitiator::authenticated(
            state.tenant(),
            rss_request_context::PrincipalKind::User,
            state.user_id().as_uuid().hyphenated().to_string(),
        );
        CredentialSecurityCommand::logout_all(state, initiator, occurred_at)
            .expect("test logout-all command must satisfy state invariants")
    }

    /// Build the route-specific logout-current command; the returned type cannot be passed to the
    /// logout-all lifecycle method.
    #[allow(clippy::expect_used)]
    pub fn logout_current_command(
        grant: AuthGrant,
        occurred_at: SystemTime,
    ) -> LogoutCurrentCommand {
        let initiator = CredentialSecurityInitiator::authenticated(
            grant.tenant(),
            rss_request_context::PrincipalKind::User,
            grant.user_id().as_uuid().hyphenated().to_string(),
        );
        CredentialSecurityCommand::logout_current(grant, initiator, occurred_at)
            .expect("test logout-current command must satisfy state invariants")
    }

    /// Build the route-specific password command through its sealed constructor.
    #[allow(clippy::expect_used)]
    pub fn password_change_command(
        credential: Credential,
        account: AccountSecurityState,
        password: secure::ValidatedPassword,
        occurred_at: SystemTime,
    ) -> PasswordChangeCommand {
        let initiator = CredentialSecurityInitiator::authenticated(
            account.tenant(),
            rss_request_context::PrincipalKind::User,
            account.user_id().as_uuid().hyphenated().to_string(),
        );
        PasswordChangeCommand::new(credential, account, password, initiator, occurred_at)
            .expect("test password-change command must satisfy state invariants")
    }

    /// Build the route-specific desired account-status command through its sealed constructor.
    #[allow(clippy::expect_used)]
    pub fn account_status_set_command(
        state: AccountSecurityState,
        target: AccountStatus,
        occurred_at: SystemTime,
    ) -> AccountStatusSetCommand {
        let initiator = CredentialSecurityInitiator::authenticated(
            state.tenant(),
            rss_request_context::PrincipalKind::Admin,
            "test-admin",
        );
        AccountStatusSetCommand::new(state, target, initiator, occurred_at)
            .expect("test account-status command must satisfy state invariants")
    }

    /// Build the internal reactivation command through its sealed constructor.
    #[allow(clippy::expect_used)]
    pub fn reactivate_account_command(
        state: AccountSecurityState,
        occurred_at: SystemTime,
    ) -> ReactivateAccountCommand {
        ReactivateAccountCommand::new(state, occurred_at)
            .expect("test reactivation command must satisfy state invariants")
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

    /// Build a sealed rotation command for downstream adapter conformance tests.
    #[allow(clippy::expect_used)]
    pub fn refresh_rotation_command(
        source: RefreshTokenRecord,
        grant: AuthGrant,
        rotation: crate::ports::RefreshRotation,
        occurred_at: SystemTime,
    ) -> crate::ports::RefreshExecutionCommand {
        let account = AccountSecurityState::try_from(AccountSecuritySnapshot {
            tenant: source.tenant(),
            user_id: source.user_id(),
            status: AccountStatus::Active,
            authn_epoch: source.issuance_epoch().get(),
            version: 1,
            status_changed_at: occurred_at,
            updated_at: occurred_at,
        })
        .expect("test account observation must be valid")
        .try_into_active()
        .expect("test account observation must be active");
        crate::ports::RefreshExecutionCommand::rotate(source, grant, account, rotation, occurred_at)
            .expect("test refresh rotation command must preserve exact binding")
    }

    /// Build a sealed reuse-containment command for downstream adapter conformance tests.
    #[allow(clippy::expect_used)]
    pub fn refresh_reuse_command(
        source: RefreshTokenRecord,
        occurred_at: SystemTime,
    ) -> crate::ports::RefreshExecutionCommand {
        crate::ports::RefreshExecutionCommand::contain_reuse(source, occurred_at)
            .expect("test refresh reuse command requires non-active evidence")
    }

    /// Build the generated `identity.session-created` fact carried by a login-grant mutation.
    #[allow(clippy::expect_used)]
    pub async fn session_created_event(
        event_id: &str,
        grant: &AuthGrant,
    ) -> eventexec::event::ReviewedEvent {
        let payload =
            generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
                session_id: grant.id().as_uuid(),
                subject: grant.user_id().as_uuid(),
                tenant_id: uuid::Uuid::from_bytes(grant.tenant().octets()),
                occurred_at: rss_contract::Timepoint::saturating_from_system_time(
                    grant.created_at(),
                )
                .unix_seconds(),
            };
        let subject = grant.user_id();
        crate::outbox_emit::emit_session_created(
            payload,
            grant.tenant(),
            subject,
            consistency::IdemKey::parse(event_id)
                .expect("test event id must satisfy idempotency-key shape"),
        )
        .await
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
