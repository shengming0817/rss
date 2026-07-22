//! identity::ports — 身份域**专属** repo / 领域服务 DI port（Option 2 / ADR-005）。
//!
//! 归属（ADR-005 category line）：provider-agnostic 基建 port（`Clock`/`Signer`/`Publisher`/`AuditSink`…）
//! 在 `diport`；**域形** repo port——签名引用域内实体（`Role`/`RoleId`，域 crate `pub(crate)`/`pub` 类型）——
//! **无法**收敛 `diport`（否则 diport→域 反向依赖、层序倒置、deny 红），故归本域 crate `ports` 模块。
//! adapter（如 `postgres`）依赖 `identity`、以 native AFIT impl 本 port（DIP 内向边，`adapters→域` 单向）。
//! 派发与 diport DI port 同范式：`#[trait_variant::make(X: Send)]` Send 变体 + `#[dynosaur(...)]` `DynX`。
//! 需要跨 axum handler / subscriber future 共享的端口在基 trait 加 `Send + Sync`，经 `Arc<DynX>` 注入；
//! 单 owner 端口仍可用 `Box<DynX>`。
//!
//! 跨 crate 可见性：repo port 须 `pub`（独立 adapter crate impl）；签名实体 `Role`/`RoleId`/`IdentityError`
//! 经下方 `pub use` 暴露——字段私有 + 构造经 `pub(crate)` funnel，外部可命名/收发但**不可伪造**（fail-closed）。
//!
//! ref: oxidecomputer/omicron Cargo.toml@main（域 trait + 组合根注入范本，framework-comparison §域运行时/DI）
//! ref: Cockburn Hexagonal Ports&Adapters / Evans DDD Repository（repo 接口归域核心、adapter 经 DIP 实现）

use std::time::SystemTime;

use consistency::EventEntry;
use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEmitError, OutboxEnvelopeParts};
use dynosaur::dynosaur;
use generated::http::identity_v1::{
    logout::{LOCAL_TX as LOGOUT_LOCAL_TX, ROUTE as LOGOUT_ROUTE},
    password_change::{LOCAL_TX as PASSWORD_CHANGE_LOCAL_TX, ROUTE as PASSWORD_CHANGE_ROUTE},
    refresh::{LOCAL_TX as REFRESH_LOCAL_TX, ROUTE as REFRESH_ROUTE},
};

// Exact fact bindings cross the domain→adapter port as zero-copy re-exports. Adapters retain the
// normal Adapter→Domain dependency and cannot introduce an Adapter→Generated layer edge.
pub use generated::event::identity_v1::policy_updated::CONTRACT as POLICY_UPDATED_CONTRACT;
pub use generated::event::identity_v1::role_assigned::CONTRACT as ROLE_ASSIGNED_CONTRACT;
pub use generated::event::identity_v1::role_revoked::CONTRACT as ROLE_REVOKED_CONTRACT;
pub use generated::event::identity_v1::security_event::{
    CONTRACT as SECURITY_EVENT_CONTRACT, FACT as SECURITY_EVENT_FACT,
};
use generated::event::identity_v1::security_event::{
    IdentitySecurityEventPayload, IdentitySecurityEventPayloadKind as WireSecurityEventKind,
    IdentitySecurityEventPayloadTarget, IdentitySecurityEventPayloadTargetKind as WireTargetKind,
    SPEC as SECURITY_EVENT_SPEC,
};
pub use generated::event::identity_v1::session_created::CONTRACT as SESSION_CREATED_CONTRACT;

/// Exact generated payload admitted by the L2 fault-matrix seam.
///
/// The alias is absent from normal production builds. Downstream adapters can accept this
/// concrete generated DTO without adding an adapter→generated dependency edge.
#[cfg(feature = "fault-matrix-test-support")]
pub type FaultMatrixSessionCreatedPayload =
    generated::event::identity_v1::session_created::IdentitySessionCreatedPayload;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造器仍 `pub(crate)` funnel）。
// reason: account-security aggregate/mutation are current port entities used by the mandatory
// authentication and refresh gate. AccountLockout is not a port method entity, but PgCredentialRepo
// rebuilds and advances it inside the authentication transaction; its fields remain private.
pub use crate::domain::{
    AbacAttribute, AccountCredentialSecurityCommand, AccountLockout, AccountSecurityEventKind,
    AccountSecurityHydrationError, AccountSecurityMutation, AccountSecuritySnapshot,
    AccountSecurityState, AccountSecurityTransitionError, AccountSecurityVersion, AccountStatus,
    AttributeKey, AttributeValue, AuthGrant, AuthGrantCloseMutation, AuthGrantId,
    AuthGrantSnapshot, AuthGrantStateError, AuthGrantStatus, AuthOutcome, AuthnEpoch,
    BruteForceDecision, Credential, CredentialSecurityCommand, CredentialSecurityEvent,
    CredentialSecurityEventKind, CredentialSecurityFactAuthorization, CredentialSecurityReceipt,
    CredentialSecurityTargetHydrationError, CredentialSecurityTargetKind,
    CredentialSecurityTargetMapping, CredentialSecurityTargetRef, GlobPattern,
    GrantCredentialSecurityCommand, GrantSecurityEventKind, IdentityError, LoginIdentifier,
    Operator, POLICY_ATTR_CONTRACT_ID, POLICY_ATTR_PERMISSION, POLICY_ATTR_PRINCIPAL_ID,
    POLICY_ATTR_PRINCIPAL_KIND, POLICY_ATTR_RESOURCE_ID, POLICY_ATTR_TENANT_ID,
    PendingCredentialSecurityCommit, Policy, PolicyCondition, PolicyEffect, PolicyId,
    PolicyObligations, PolicyRouteScope, PolicyRule, PolicyVersion, RefreshRotation,
    RefreshRotationOutcome, RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord,
    RefreshTokenSnapshot, ResolvedCredentialSecurityTarget, ResourceAttribute,
    ResourceAttributeKey, ResourceAttributeKeyError, ResourceAttributeResolution,
    ResourceAttributeResourceId, ResourceAttributeVersion, Role, RoleBinding, RoleId,
};
pub use vocab::TenantId;

/// Closed generated fact and envelope pair for one credential-security command.
///
/// Private fields prevent an adapter from replacing the generated payload or contract binding
/// between command construction and the provider transaction.
pub struct CredentialSecurityFact {
    entry: EventEntry,
    envelope: OutboxEnvelopeParts,
    target_mapping: CredentialSecurityTargetMapping,
    authorization: CredentialSecurityFactAuthorization,
}

impl CredentialSecurityFact {
    pub fn into_parts(
        self,
    ) -> (
        EventEntry,
        OutboxEnvelopeParts,
        CredentialSecurityTargetMapping,
        CredentialSecurityFactAuthorization,
    ) {
        (
            self.entry,
            self.envelope,
            self.target_mapping,
            self.authorization,
        )
    }
}

/// Build the exact generated credential-security fact from an unforgeable domain event and its
/// move-only command authorization.
///
/// The wire payload intentionally excludes subject, grant, credential and token identifiers. Its
/// event id and target reference are independent opaque UUIDs. The target reference is used as the
/// non-PII envelope subject and the actor is a fixed service identity.
pub fn credential_security_fact(
    event: &CredentialSecurityEvent,
    authorization: CredentialSecurityFactAuthorization,
) -> Result<CredentialSecurityFact, IdentityError> {
    let kind = match event.kind() {
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordChanged) => {
            WireSecurityEventKind::PasswordChanged
        }
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordReset) => {
            WireSecurityEventKind::PasswordReset
        }
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountLocked) => {
            WireSecurityEventKind::AccountLocked
        }
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountSuspended) => {
            WireSecurityEventKind::AccountSuspended
        }
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountDeactivated) => {
            WireSecurityEventKind::AccountDeactivated
        }
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::LogoutAll) => {
            WireSecurityEventKind::LogoutAll
        }
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::CredentialDeleted) => {
            WireSecurityEventKind::CredentialDeleted
        }
        CredentialSecurityEventKind::Grant(GrantSecurityEventKind::LogoutCurrent) => {
            WireSecurityEventKind::LogoutCurrent
        }
        CredentialSecurityEventKind::Grant(GrantSecurityEventKind::RefreshReuseDetected) => {
            WireSecurityEventKind::RefreshReuseDetected
        }
    };
    let target_ref = CredentialSecurityTargetRef::generate();
    let target_kind = match event.target_kind() {
        CredentialSecurityTargetKind::Subject => WireTargetKind::Subject,
        CredentialSecurityTargetKind::Grant => WireTargetKind::Grant,
    };
    let occurred_at = event
        .occurred_at()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let payload = IdentitySecurityEventPayload {
        kind,
        occurred_at,
        target: IdentitySecurityEventPayloadTarget {
            kind: target_kind,
            ref_: target_ref.as_uuid(),
        },
        tenant_id: event.tenant().to_string(),
    };
    let event_id = uuid::Uuid::new_v4().to_string();
    let idem_key = consistency::IdemKey::parse(&event_id).map_err(security_fact_build)?;
    let entry =
        EventEntry::from_generated_payload(&payload, idem_key).map_err(security_payload_encode)?;
    let envelope = OutboxEnvelopeParts::new(
        SECURITY_EVENT_SPEC.contract(),
        event.tenant(),
        EnvelopeSubjectId::from_opaque(target_ref.as_uuid().to_string())
            .map_err(security_fact_build)?,
        OutboxActor::service(
            OpaqueActorId::from_opaque("identity-security-lifecycle".to_owned())
                .map_err(security_fact_build)?,
        ),
    );
    let target_mapping = event.target_mapping(target_ref);
    Ok(CredentialSecurityFact {
        entry,
        envelope,
        target_mapping,
        authorization,
    })
}

fn security_fact_build(error: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    IdentityError::SecurityFactBuild(Box::new(error))
}

fn security_payload_encode(error: serde_json::Error) -> IdentityError {
    IdentityError::SecurityPayloadEncode(error)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod credential_security_fact_tests {
    use super::*;
    use std::time::Duration;

    const CASES: [(CredentialSecurityEventKind, &str, &str); 9] = [
        (
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordChanged),
            "passwordChanged",
            "subject",
        ),
        (
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::PasswordReset),
            "passwordReset",
            "subject",
        ),
        (
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountLocked),
            "accountLocked",
            "subject",
        ),
        (
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountSuspended),
            "accountSuspended",
            "subject",
        ),
        (
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountDeactivated),
            "accountDeactivated",
            "subject",
        ),
        (
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::LogoutAll),
            "logoutAll",
            "subject",
        ),
        (
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::CredentialDeleted),
            "credentialDeleted",
            "subject",
        ),
        (
            CredentialSecurityEventKind::Grant(GrantSecurityEventKind::LogoutCurrent),
            "logoutCurrent",
            "grant",
        ),
        (
            CredentialSecurityEventKind::Grant(GrantSecurityEventKind::RefreshReuseDetected),
            "refreshReuseDetected",
            "grant",
        ),
    ];

    fn command(
        kind: CredentialSecurityEventKind,
        tenant: TenantId,
        user: ids::UserId,
        occurred_at: SystemTime,
    ) -> CredentialSecurityCommand {
        match kind {
            CredentialSecurityEventKind::Account(kind) => CredentialSecurityCommand::account(
                AccountSecurityState::initial(tenant, user, SystemTime::UNIX_EPOCH),
                kind,
                occurred_at,
            )
            .expect("account command"),
            CredentialSecurityEventKind::Grant(kind) => CredentialSecurityCommand::grant(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: AuthGrantId::hydrate("grant-sensitive-id"),
                    tenant,
                    user_id: user,
                    auth_time: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                    authn_epoch_at_issue: AuthnEpoch::ZERO,
                    status: AuthGrantStatus::Active,
                    expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(100),
                    created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(2),
                    closed_at: None,
                    close_reason: None,
                })
                .expect("active grant"),
                kind,
                occurred_at,
            )
            .expect("grant command"),
        }
    }

    #[test]
    #[allow(
        clippy::cognitive_complexity,
        reason = "one table-driven assertion intentionally checks the full nine-kind protocol matrix"
    )]
    fn security_event_commands_map_to_their_exact_wire_kind_and_opaque_target() {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let user = ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("user");
        let occurred_at = SystemTime::UNIX_EPOCH + Duration::from_secs(42);

        for (kind, wire_kind, wire_target_kind) in CASES {
            let command = command(kind, tenant, user, occurred_at);
            let (event, authorization) = match command {
                CredentialSecurityCommand::Account(command) => {
                    let (_mutation, event, _pending, authorization) = command.into_parts();
                    (event, authorization)
                }
                CredentialSecurityCommand::Grant(command) => {
                    let (_mutation, event, _pending, authorization) = command.into_parts();
                    (event, authorization)
                }
            };
            let fact = credential_security_fact(&event, authorization).expect("fact");
            let (entry, envelope, mapping, _authorization) = fact.into_parts();
            let payload: serde_json::Value =
                serde_json::from_slice(entry.payload()).expect("payload");
            let target_ref = payload["target"]["ref"]
                .as_str()
                .expect("target ref must be a string");
            assert_eq!(
                payload,
                serde_json::json!({
                    "kind": wire_kind,
                    "target": {
                        "kind": wire_target_kind,
                        "ref": target_ref,
                    },
                    "tenantId": tenant.to_string(),
                    "occurredAt": 42,
                }),
                "domain kind {kind:?} must retain its canonical wire mapping"
            );
            let encoded = String::from_utf8_lossy(entry.payload());
            assert!(!encoded.contains(&user.as_uuid().to_string()));
            assert!(!encoded.contains("grant-sensitive-id"));
            assert!(uuid::Uuid::parse_str(target_ref).is_ok());
            assert_eq!(entry.generated_fact(), Some(SECURITY_EVENT_FACT));
            assert!(uuid::Uuid::parse_str(entry.idem_key().as_str()).is_ok());
            assert_ne!(entry.idem_key().as_str(), target_ref);
            assert_eq!(envelope.contract(), &SECURITY_EVENT_CONTRACT);
            assert_eq!(envelope.tenant(), tenant);
            assert_eq!(envelope.subject_id().as_str(), target_ref);
            assert_eq!(envelope.actor().kind(), vocab::PrincipalKind::Service);
            assert_eq!(
                envelope.actor().actor_id().as_str(),
                "identity-security-lifecycle"
            );
            let (mapping_tenant, mapping_ref, resolved) = mapping.into_parts();
            assert_eq!(mapping_tenant, tenant);
            assert_eq!(mapping_ref.as_uuid().to_string(), target_ref);
            assert_eq!(resolved.tenant(), tenant);
            assert_eq!(resolved.target_ref().as_uuid().to_string(), target_ref);
            assert_eq!(resolved.user_id(), user);
            match kind {
                CredentialSecurityEventKind::Account(_) => {
                    assert_eq!(resolved.kind(), CredentialSecurityTargetKind::Subject);
                    assert!(resolved.grant_id().is_none());
                }
                CredentialSecurityEventKind::Grant(_) => {
                    assert_eq!(resolved.kind(), CredentialSecurityTargetKind::Grant);
                    assert_eq!(
                        resolved.grant_id().map(AuthGrantId::as_str),
                        Some("grant-sensitive-id")
                    );
                }
            }
        }
    }

    #[test]
    fn pre_transaction_fact_errors_are_not_classified_as_storage() {
        use std::error::Error as _;

        let build = security_fact_build(
            consistency::IdemKey::parse("").expect_err("empty idempotency key must fail"),
        );
        assert!(matches!(build, IdentityError::SecurityFactBuild(_)));
        assert!(build.source().is_some());

        let encode = security_payload_encode(
            serde_json::from_str::<serde_json::Value>("{")
                .expect_err("invalid JSON must provide a serde source"),
        );
        assert!(matches!(encode, IdentityError::SecurityPayloadEncode(_)));
        assert!(encode.source().is_some());
    }
}

/// Generated route marker retained by the logout LocalTx command.
pub type AuthGrantCloseRouteMarker = generated::http::identity_v1::logout::RouteMarker;
/// Generated route marker retained by the password-change LocalTx command.
pub type PasswordChangeRouteMarker = generated::http::identity_v1::password_change::RouteMarker;
/// Generated route marker retained by the refresh rotation LocalTx command.
pub type RefreshRotationRouteMarker = generated::http::identity_v1::refresh::RouteMarker;

/// `identity.login` request-scoped producer assurance carried into the AuthGrant co-tx funnel.
pub type LoginProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::login::RouteMarker>;
/// `identity.roles-assign` request-scoped producer assurance.
pub type RolesAssignProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::roles_assign::RouteMarker>;
/// `identity.roles-revoke` request-scoped producer assurance.
pub type RolesRevokeProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::roles_revoke::RouteMarker>;
/// `identity.policies-create` request-scoped producer assurance.
pub type PoliciesCreateProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::policies_create::RouteMarker>;
/// `identity.policies-update` request-scoped producer assurance.
pub type PoliciesUpdateProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::policies_update::RouteMarker>;
/// `identity.policies-deactivate` request-scoped producer assurance.
pub type PoliciesDeactivateProducerReceipt = httpserve::ProducerAssuranceReceipt<
    generated::http::identity_v1::policies_deactivate::RouteMarker,
>;

/// 密封的登录持久化 mutation。
///
/// 只携带 AuthGrant、初始 refresh 哈希记录和线性 persistence capability；不携带 bearer secret。
/// 构造器仅对 identity application 可见，adapter 只能消费。
pub struct LoginGrantMutation {
    grant: AuthGrant,
    initial_refresh: RefreshTokenRecord,
    persistence: PendingLoginGrantPersistence,
}

impl LoginGrantMutation {
    pub(crate) fn new(grant: AuthGrant, initial_refresh: RefreshTokenRecord) -> Self {
        Self {
            grant,
            initial_refresh,
            persistence: PendingLoginGrantPersistence(()),
        }
    }

    pub fn grant(&self) -> &AuthGrant {
        &self.grant
    }

    pub fn initial_refresh(&self) -> &RefreshTokenRecord {
        &self.initial_refresh
    }

    pub fn into_parts(self) -> (AuthGrant, RefreshTokenRecord, PendingLoginGrantPersistence) {
        (self.grant, self.initial_refresh, self.persistence)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(grant: AuthGrant, initial_refresh: RefreshTokenRecord) -> Self {
        Self::new(grant, initial_refresh)
    }
}

/// Linear capability carried only by a sealed login mutation.
#[must_use]
pub struct PendingLoginGrantPersistence(());

impl PendingLoginGrantPersistence {
    /// Confirm this capability after the provider persistence boundary succeeds.
    pub fn confirm(self) -> PersistedLoginGrantReceipt {
        PersistedLoginGrantReceipt(())
    }
}

/// Unforgeable proof that the login persistence boundary acknowledged success.
#[must_use]
pub struct PersistedLoginGrantReceipt(());

pub struct AuthGrantCloseCommand {
    mutation: AuthGrantCloseMutation,
    observation: observ::LocalTxObservation<AuthGrantCloseRouteMarker>,
}

impl AuthGrantCloseCommand {
    pub(crate) fn new(mutation: AuthGrantCloseMutation) -> Self {
        Self {
            mutation,
            observation: observ::LocalTxObservation::new(LOGOUT_ROUTE, LOGOUT_LOCAL_TX.boundary),
        }
    }

    /// Adapter 消费命令并取得 session key 与精确 route marker evidence。
    pub fn into_parts(
        self,
    ) -> (
        AuthGrantCloseMutation,
        observ::LocalTxObservation<AuthGrantCloseRouteMarker>,
    ) {
        (self.mutation, self.observation)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(mutation: AuthGrantCloseMutation) -> Self {
        Self::new(mutation)
    }
}

/// `identity.password-change` 的不可伪造 CAS 命令。
///
/// expected version、next credential 与 generated route marker observation 被绑定成一个 owned
/// mutation；adapter 不再分别接收可错配的业务参数和观测证据。
pub struct PasswordChangeMutation {
    expected: u32,
    next: Credential,
    observation: observ::LocalTxObservation<PasswordChangeRouteMarker>,
}

impl PasswordChangeMutation {
    pub(crate) fn new(expected: u32, next: Credential) -> Self {
        Self {
            expected,
            next,
            observation: observ::LocalTxObservation::new(
                PASSWORD_CHANGE_ROUTE,
                PASSWORD_CHANGE_LOCAL_TX.boundary,
            ),
        }
    }

    /// Adapter 消费命令并取得 CAS 参数与精确 route marker evidence。
    pub fn into_parts(
        self,
    ) -> (
        u32,
        Credential,
        observ::LocalTxObservation<PasswordChangeRouteMarker>,
    ) {
        (self.expected, self.next, self.observation)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(expected: u32, next: Credential) -> Self {
        Self::new(expected, next)
    }
}

/// `identity.refresh` 的不可伪造 CAS 轮换命令。
///
/// sealed rotation 与 generated route marker observation 同源封装；adapter 只能消费命令，不能把
/// refresh 业务参数接到其它 LocalTx contract 或 retry boundary。
pub struct RefreshRotationMutation {
    rotation: RefreshRotation,
    observation: observ::LocalTxObservation<RefreshRotationRouteMarker>,
}

impl RefreshRotationMutation {
    pub(crate) fn new(rotation: RefreshRotation) -> Self {
        Self {
            rotation,
            observation: observ::LocalTxObservation::new(REFRESH_ROUTE, REFRESH_LOCAL_TX.boundary),
        }
    }

    /// Adapter 消费命令并取得 sealed rotation 与精确 route marker evidence。
    pub fn into_parts(
        self,
    ) -> (
        RefreshRotation,
        observ::LocalTxObservation<RefreshRotationRouteMarker>,
    ) {
        (self.rotation, self.observation)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(rotation: RefreshRotation) -> Self {
        Self::new(rotation)
    }
}

/// Tenant-scoped repo capability for identity storage ports.
///
/// It is an opaque handle: external crates can read the tenant for adapter lowering, but cannot
/// construct it from a bare [`TenantId`] in production builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantRepoScope {
    tenant: TenantId,
    _seal: (),
}

impl TenantRepoScope {
    /// Domain-internal constructor from an already authenticated or authorized tenant claim.
    pub(crate) fn from_authenticated_tenant(tenant: TenantId) -> Self {
        Self { tenant, _seal: () }
    }

    /// Read the tenant carried by this repo capability.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Test/dev-only constructor for downstream adapter conformance tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(tenant: TenantId) -> Self {
        Self { tenant, _seal: () }
    }
}

/// Sealed lookup request for resolving one opaque credential-security target reference.
///
/// The tenant capability and expected target kind are captured together so a provider cannot
/// accidentally resolve a grant reference as a subject reference or cross tenant boundaries.
#[must_use]
pub struct CredentialSecurityTargetResolutionRequest {
    scope: TenantRepoScope,
    target_ref: CredentialSecurityTargetRef,
    expected_kind: CredentialSecurityTargetKind,
}

impl CredentialSecurityTargetResolutionRequest {
    pub(crate) fn new(
        scope: TenantRepoScope,
        target_ref: CredentialSecurityTargetRef,
        expected_kind: CredentialSecurityTargetKind,
    ) -> Self {
        Self {
            scope,
            target_ref,
            expected_kind,
        }
    }

    /// Borrow the sealed tenant capability for the provider query.
    pub fn scope(&self) -> &TenantRepoScope {
        &self.scope
    }

    /// Borrow the opaque reference for the provider query.
    pub fn target_ref(&self) -> &CredentialSecurityTargetRef {
        &self.target_ref
    }

    /// Validate one provider row against the sealed request and close its target shape.
    ///
    /// A row outside the requested tenant/reference/kind is indistinguishable from absence. A row
    /// with the right binding but a malformed subject/grant shape is a typed hydration error.
    pub fn resolve_provider_row(
        self,
        stored_tenant: TenantId,
        stored_ref: CredentialSecurityTargetRef,
        stored_kind: CredentialSecurityTargetKind,
        user_id: ids::UserId,
        grant_id: Option<AuthGrantId>,
    ) -> Result<Option<ResolvedCredentialSecurityTarget>, CredentialSecurityTargetHydrationError>
    {
        if self.scope.tenant() != stored_tenant
            || self.target_ref != stored_ref
            || self.expected_kind != stored_kind
        {
            return Ok(None);
        }
        ResolvedCredentialSecurityTarget::hydrate_provider_row(
            stored_tenant,
            stored_ref,
            stored_kind,
            user_id,
            grant_id,
        )
        .map(Some)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        scope: TenantRepoScope,
        target_ref: CredentialSecurityTargetRef,
        expected_kind: CredentialSecurityTargetKind,
    ) -> Self {
        Self::new(scope, target_ref, expected_kind)
    }
}

// The draft resolver request is intentionally minted only by the future authenticated consumer.
// Keep the sealed constructor type-checked without exposing a bare-tenant constructor to adapters.
const _: fn(
    TenantRepoScope,
    CredentialSecurityTargetRef,
    CredentialSecurityTargetKind,
) -> CredentialSecurityTargetResolutionRequest = CredentialSecurityTargetResolutionRequest::new;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod credential_security_target_resolution_tests {
    use super::*;

    fn tenant(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("tenant")
    }

    fn target_ref(raw: &str) -> CredentialSecurityTargetRef {
        CredentialSecurityTargetRef::parse(raw).expect("target ref")
    }

    fn user() -> ids::UserId {
        ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("user")
    }

    #[test]
    fn resolver_request_rejects_wrong_tenant_reference_and_kind() {
        let tenant_a = tenant("f47ac10b-58cc-4372-a567-0e02b2c3d479");
        let tenant_b = tenant("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let reference_a = target_ref("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        let reference_b = target_ref("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
        let scope = TenantRepoScope::for_test(tenant_a);

        let resolved = CredentialSecurityTargetResolutionRequest::for_test(
            scope,
            reference_a.clone(),
            CredentialSecurityTargetKind::Subject,
        )
        .resolve_provider_row(
            tenant_a,
            reference_a.clone(),
            CredentialSecurityTargetKind::Subject,
            user(),
            None,
        )
        .expect("valid subject shape")
        .expect("matching subject row");
        assert_eq!(resolved.kind(), CredentialSecurityTargetKind::Subject);

        assert!(
            CredentialSecurityTargetResolutionRequest::for_test(
                scope,
                reference_a.clone(),
                CredentialSecurityTargetKind::Subject,
            )
            .resolve_provider_row(
                tenant_b,
                reference_a.clone(),
                CredentialSecurityTargetKind::Subject,
                user(),
                None,
            )
            .expect("mismatched tenant is absence")
            .is_none()
        );
        assert!(
            CredentialSecurityTargetResolutionRequest::for_test(
                scope,
                reference_a.clone(),
                CredentialSecurityTargetKind::Subject,
            )
            .resolve_provider_row(
                tenant_a,
                reference_b,
                CredentialSecurityTargetKind::Subject,
                user(),
                None,
            )
            .expect("mismatched reference is absence")
            .is_none()
        );
        assert!(
            CredentialSecurityTargetResolutionRequest::for_test(
                scope,
                reference_a.clone(),
                CredentialSecurityTargetKind::Grant,
            )
            .resolve_provider_row(
                tenant_a,
                reference_a.clone(),
                CredentialSecurityTargetKind::Subject,
                user(),
                None,
            )
            .expect("mismatched expected kind is absence")
            .is_none()
        );
        assert!(
            CredentialSecurityTargetResolutionRequest::for_test(
                scope,
                reference_a.clone(),
                CredentialSecurityTargetKind::Subject,
            )
            .resolve_provider_row(
                tenant_a,
                reference_a,
                CredentialSecurityTargetKind::Grant,
                user(),
                Some(AuthGrantId::hydrate("grant-sensitive-id")),
            )
            .expect("mismatched expected kind is absence")
            .is_none()
        );
    }

    #[test]
    fn resolver_request_reports_malformed_matching_provider_shape() {
        let tenant = tenant("f47ac10b-58cc-4372-a567-0e02b2c3d479");
        let reference = target_ref("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        let scope = TenantRepoScope::for_test(tenant);

        let subject_with_grant = CredentialSecurityTargetResolutionRequest::for_test(
            scope,
            reference.clone(),
            CredentialSecurityTargetKind::Subject,
        )
        .resolve_provider_row(
            tenant,
            reference.clone(),
            CredentialSecurityTargetKind::Subject,
            user(),
            Some(AuthGrantId::hydrate("unexpected")),
        );
        assert_eq!(
            subject_with_grant.err(),
            Some(CredentialSecurityTargetHydrationError::UnexpectedGrantId)
        );

        let grant_without_id = CredentialSecurityTargetResolutionRequest::for_test(
            scope,
            reference.clone(),
            CredentialSecurityTargetKind::Grant,
        )
        .resolve_provider_row(
            tenant,
            reference,
            CredentialSecurityTargetKind::Grant,
            user(),
            None,
        );
        assert_eq!(
            grant_without_id.err(),
            Some(CredentialSecurityTargetHydrationError::MissingGrantId)
        );
    }
}

/// Non-cross-tenant row-scoped repo capability for identity rows.
///
/// It only accepts [`vocab::ScopedTenant`]-derived visibility, which keeps `RowScope::All` out of
/// ordinary row-scoped repositories at the type boundary.
pub struct RowRepoScope {
    visibility: vocab::RowVisibility,
    _seal: (),
}

impl RowRepoScope {
    #[allow(dead_code)]
    pub(crate) fn from_scoped_visibility(
        scope: vocab::ScopedTenant,
        tenant: TenantRepoScope,
    ) -> Self {
        Self {
            visibility: vocab::RowVisibility::new(scope, tenant.tenant()),
            _seal: (),
        }
    }

    pub fn visibility(&self) -> &vocab::RowVisibility {
        &self.visibility
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(scope: vocab::ScopedTenant, tenant: TenantRepoScope) -> Self {
        Self::from_scoped_visibility(scope, tenant)
    }
}

/// durable ABAC policy read repository DI port（tenant-scoped，domain-shaped）。
///
/// 本 port 只暴露读侧能力。管理写侧必须经 [`PolicyLifecycle`] 的 combined co-tx API，以类型边界避免
/// “先写 policy 再发事件”的两步调用。`list_effective` 是授权热路径读口：provider 必须按
/// `(tenant, route scope, effective window)` 收敛，任何存储 / decode / validation 错误由 caller fail-closed
/// 映射为 deny。
#[trait_variant::make(PolicyRepo: Send)]
#[dynosaur(pub DynPolicyRepo = dyn(box) PolicyRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait PolicyRepoLocal: Send + Sync {
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: PolicyId,
    ) -> Result<Option<Policy>, IdentityError>;

    async fn list_active(
        &self,
        scope: TenantRepoScope,
        page: PolicyPage,
    ) -> Result<PolicyListResult, IdentityError>;

    async fn list_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        at: SystemTime,
    ) -> Result<Vec<Policy>, IdentityError>;
}

/// 策略列表分页参数（handler 已完成 query/cursor 校验，repo 只接收 typed page）。
#[derive(Debug, Clone)]
pub struct PolicyPage {
    pub limit: vocab::Limit,
    pub after: Option<PolicyId>,
}

/// 策略列表分页结果（`has_more` 由 repo over-fetch 判定；`nextCursor` 由 handler 用末项 policy id 派生）。
#[derive(Debug)]
pub struct PolicyListResult {
    pub policies: Vec<Policy>,
    pub has_more: bool,
}

/// Tenant-scoped resource attribute resolver used by route ABAC.
///
/// The read port is deliberately separate from [`ResourceAttributeWriteRepo`], so a finalized
/// LocalOnly authorizer cannot retain resource-attribute mutation capability. Resolution failures
/// are explicit (`Missing` / `Stale`) and always fail closed.
#[trait_variant::make(ResourceAttributeReadRepo: Send)]
#[dynosaur(pub DynResourceAttributeReadRepo = dyn(box) ResourceAttributeReadRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait ResourceAttributeReadRepoLocal: Send + Sync {
    async fn resolve_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        required_keys: Vec<ResourceAttributeKey>,
        at: SystemTime,
    ) -> Result<ResourceAttributeResolution, IdentityError>;
}

/// Tenant-scoped resource attribute mutation port.
#[trait_variant::make(ResourceAttributeWriteRepo: Send)]
#[dynosaur(pub DynResourceAttributeWriteRepo = dyn(box) ResourceAttributeWriteRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait ResourceAttributeWriteRepoLocal: Send + Sync {
    async fn upsert(
        &self,
        scope: TenantRepoScope,
        attribute: ResourceAttribute,
        expected: Option<ResourceAttributeVersion>,
    ) -> Result<ResourceAttribute, IdentityError>;

    async fn expire(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        key: ResourceAttributeKey,
        expected: ResourceAttributeVersion,
    ) -> Result<bool, IdentityError>;
}

/// ABAC policy lifecycle DI port（domain-shaped）——policy mutation + `identity.policy-updated` outbox 的唯一写口。
#[trait_variant::make(PolicyLifecycle: Send)]
#[dynosaur(pub DynPolicyLifecycle = dyn(box) PolicyLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait PolicyLifecycleLocal: Send + Sync {
    async fn create_and_emit(
        &self,
        receipt: PoliciesCreateProducerReceipt,
        scope: TenantRepoScope,
        policy: Policy,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError>;

    async fn update_and_emit(
        &self,
        receipt: PoliciesUpdateProducerReceipt,
        scope: TenantRepoScope,
        policy: Policy,
        expected: PolicyVersion,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError>;

    async fn deactivate_and_emit(
        &self,
        receipt: PoliciesDeactivateProducerReceipt,
        scope: TenantRepoScope,
        id: PolicyId,
        expected: PolicyVersion,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, IdentityError>;
}

/// 角色只读仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`RoleReadRepo`] 是 **Send 变体**（adapter `impl RoleReadRepo for ...`），[`DynRoleReadRepo`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynRoleReadRepo>` 注入）。非 Send 基 trait [`RoleReadRepoLocal`] 仅供
/// 静态分发窄场景，不在 crate 根 re-export（同 diport `XLocal` 约定）。
///
/// dyn-safe（ADR-003 §4.6）：方法 `&self`、参数/返回为具体类型、supertrait 仅 Send。归属为域形 port
/// （签名引用 `Role`/`RoleId`）→ 本域 crate `ports`，非 diport（ADR-005 category line）。
///
/// **当前方法集 = 只读接缝（find / tenant-scoped list）；save 仅由独立 [`RoleWriteRepo`] 暴露。**
/// 安全 scope 由签名承载：`Role` 按租户内角色建模，repo 方法必须接收 [`TenantRepoScope`] 做 store scope
/// （pre-GA：显式 `WHERE tenant_id` + 写路径 `SET LOCAL`；DB 层 FORCE RLS 属**仓库范围 RLS infra 后续**，跨
/// roles/sessions/config 统一落地，见 `docs/rules/tenancy.md` §RLS）；若后续需要全局角色定义，须拆独立
/// `GlobalRoleRepo`，不得复用本租户内 repo 签名。
/// **生产 postgres impl 已由 postgres `PgRoleRepo` 承载**（roles 表 + tenant scope + `Role::hydrate` 受控重建，
/// #1250；PR5b 补齐 `list` 分页查询）——签名实体 accessor（`RoleId::as_str` / `Role::id|name|permission_ids`
/// / `Role::hydrate`）已按需升 `pub`（字段私有 + 构造经 funnel，外部可读不可伪造）。
/// **查询形态后续**：按业务补 `find_by_name` / `exists` 等惯用方法；列表查询继续强制分页（`limit≤500`）。
#[trait_variant::make(RoleReadRepo: Send)]
#[dynosaur(pub DynRoleReadRepo = dyn(box) RoleReadRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RoleReadRepo` 变体 + dynosaur
// `DynRoleReadRepo` 承载（DI 注入走 Send wrapper）。与 diport DI port 同范式（ADR-003/ADR-004 C1）。body=todo!()
// （签名冻结，ADR-004 C8）。
pub trait RoleReadRepoLocal: Send + Sync {
    /// 按 ID 查角色（不存在返回 `Ok(None)`）。
    async fn find(&self, scope: TenantRepoScope, id: RoleId)
    -> Result<Option<Role>, IdentityError>;

    /// 租户内分页列出角色（按 role id 升序稳定排序）。
    async fn list(
        &self,
        scope: TenantRepoScope,
        page: RolePage,
    ) -> Result<RoleListResult, IdentityError>;
}

/// 角色写仓储 DI port。与 [`RoleReadRepo`] 破坏式分离，使读路由类型系统排除写能力。
#[trait_variant::make(RoleWriteRepo: Send)]
#[dynosaur(pub DynRoleWriteRepo = dyn(box) RoleWriteRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait RoleWriteRepoLocal: Send + Sync {
    /// 持久化角色（upsert）。
    async fn save(&self, scope: TenantRepoScope, role: Role) -> Result<(), IdentityError>;
}

/// 角色列表分页参数（handler 已完成 query/cursor 校验，repo 只接收 typed page）。
#[derive(Debug, Clone)]
pub struct RolePage {
    pub limit: vocab::Limit,
    pub after: Option<RoleId>,
}

/// 角色列表分页结果（`has_more` 由 repo over-fetch 判定；`nextCursor` 由 handler 用末项 role id 派生）。
#[derive(Debug)]
pub struct RoleListResult {
    pub roles: Vec<Role>,
    pub has_more: bool,
}

/// 授权侧角色绑定只读 DI port。与 [`RoleBindingLifecycle`] 破坏式分离，确保 finalized LocalOnly
/// authorizer 在类型层不具备 binding mutation/outbox 能力。
#[trait_variant::make(RoleBindingReadRepo: Send)]
#[dynosaur(pub DynRoleBindingReadRepo = dyn(box) RoleBindingReadRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait RoleBindingReadRepoLocal: Send + Sync {
    async fn list_for_subject(
        &self,
        scope: TenantRepoScope,
        subject: String,
    ) -> Result<Vec<RoleBinding>, IdentityError>;
}

/// 角色绑定生命周期 DI port（域形；provider 可换：prod postgres / test in-mem）——RBAC 角色分配 / 撤销的
/// **L2 OutboxFact co-tx** 写口（#1190 US5）。
///
/// 公开 [`RoleBindingLifecycle`] 是 **Send 变体**（adapter `impl RoleBindingLifecycle for ...`），
/// [`DynRoleBindingLifecycle`] 是其 dyn-compatible wrapper（组合根经 `Arc<DynRoleBindingLifecycle>` 注入，
/// 供 [`crate::RbacAdminService`] 作 axum handler state 间接共享）。归属为域形 port（签名引用 [`RoleBinding`]
/// / [`RoleId`]）→ 本域 crate `ports`，非 diport（ADR-005 category line，同 [`AuthGrantLifecycle`]）。
///
/// **co-tx（L2，both-or-neither）**：binding 行写 / 删与 outbox(`identity.role-{assigned,revoked}`) 行须
/// **同一本地事务**原子落地——域构造 `entry`（事件语义归域：topic + opaque-UUID EventId + 编码 payload）
/// 与 `envelope`，adapter 在单事务内先注入 tenant scope（SET LOCAL）、写/删 binding、`append_outbox`，单
/// commit；任一步失败整体 rollback。**唯一 binding-写 API**（域无 `save`/`emit` 分调、无半开事务句柄；co-tx
/// 不可拆解在类型层成立，同 [`AuthGrantLifecycle`] 的 OUTBOX-COTX-SESSION-01）。
///
/// INVARIANT: OUTBOX-COTX-BINDING-API-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }— 域只暴露
/// combined-method funnel，调用方无法把 binding 行写/删与 role-event outbox append 拆成两个 port 调用。
/// INVARIANT: OUTBOX-COTX-BINDING-PG-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—
/// 生产 postgres `PgRoleBindingLifecycle` 在 PR5b 落地 same-tx 接线与集成 anti-vacuity（commit 两行皆在 ↔
/// rollback 两行皆无），同 OUTBOX-COTX-SESSION-01。
///
/// **租户隔离由签名承载（fail-closed）**：`assign_and_emit` 的 tenant 来自 `binding.tenant()`；
/// `revoke_and_emit` 接 [`TenantRepoScope`] 做 store scope——跨租 revoke → 幂等 `Ok(false)`（不撤、不发
/// 事件、不泄露存在性，IDENTITY-AUTHZ-TENANT-01）。失败通道经 [`OutboxEmitError`]（infra 错误，source 已
/// PII-redacted）冒泡。
///
/// **PR5b 状态**：port + `#[cfg(test)]` in-mem 替身 + 生产 `PgRoleBindingLifecycle` 已闭合 assign/revoke
/// 发布侧；role assigned/revoked event contract 仍为 draft，生产 audit consumer 延后（#1017）。
///
/// ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable）
/// ref: Cockburn Hexagonal Ports&Adapters（repo 归域核心，adapter DIP 实现）
#[trait_variant::make(RoleBindingLifecycle: Send)]
#[dynosaur(pub DynRoleBindingLifecycle = dyn(box) RoleBindingLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RoleBindingLifecycle` 变体 +
// dynosaur `DynRoleBindingLifecycle` 承载。`Send + Sync` supertrait 使 `Arc<DynRoleBindingLifecycle>` 可
// 被 RbacAdminService 跨 await 持有 / 作 handler state 共享（同 AuthGrantLifecycle）。
pub trait RoleBindingLifecycleLocal: Send + Sync {
    /// **分配（co-tx，L2）**：把 [`RoleBinding`] 行（upsert）与 outbox(`identity.role-assigned`) 行同一本地
    /// 事务原子写入。tenant scope 来自 `binding.tenant()`（无独立 tenant 入参可错位）。
    async fn assign_and_emit(
        &self,
        receipt: RolesAssignProducerReceipt,
        scope: TenantRepoScope,
        binding: RoleBinding,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError>;

    /// **撤销（co-tx，L2）**：仅撤目标 binding（`(tenant, role_id, subject)` 键），命中则同事务删 binding +
    /// 写 outbox(`identity.role-revoked`) 行、返回 `Ok(true)`；未命中（不存在 / 跨租）→ **不删、不写 outbox**、
    /// 返回 `Ok(false)`（幂等 + 跨租隐藏存在性）。`entry`/`envelope` 在未命中时被丢弃（其 EventId 独立 opaque）。
    async fn revoke_and_emit(
        &self,
        receipt: RolesRevokeProducerReceipt,
        scope: TenantRepoScope,
        role_id: RoleId,
        subject: String,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, OutboxEmitError>;
}

/// Tenant-scoped read-only account-security capability.
///
/// INVARIANT: ACCOUNT-SECURITY-READ-CAPABILITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "refresh receives read-only dyn port rather than lifecycle capability" }.
#[trait_variant::make(AccountSecurityReadRepo: Send)]
#[dynosaur(
    pub DynAccountSecurityReadRepo = dyn(box) AccountSecurityReadRepo,
    bridge(dyn)
)]
#[allow(async_fn_in_trait)]
pub trait AccountSecurityReadRepoLocal: Send + Sync {
    /// Find the durable state for a canonical subject inside the sealed tenant scope.
    async fn find(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<AccountSecurityState>, IdentityError>;
}

/// Tenant-scoped account-security lifecycle capability.
#[trait_variant::make(AccountSecurityLifecycle: Send)]
#[dynosaur(
    pub DynAccountSecurityLifecycle = dyn(box) AccountSecurityLifecycle,
    bridge(dyn)
)]
#[allow(async_fn_in_trait)]
pub trait AccountSecurityLifecycleLocal: Send + Sync {
    /// Apply a sealed optimistic-concurrency transition.
    async fn apply_transition(
        &self,
        scope: TenantRepoScope,
        mutation: AccountSecurityMutation,
    ) -> Result<AccountSecurityState, IdentityError>;
}

/// 凭据仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`CredentialRepo`] 是 **Send 变体**（adapter `impl CredentialRepo for ...`），[`DynCredentialRepo`]
/// 是其 dyn-compatible wrapper（组合根经 `Arc<DynCredentialRepo>` 注入，ADR-004 C1/C5）。归属为域形 port
/// （签名引用 `Credential`/`LoginIdentifier`/`AuthOutcome`）→ 本域 crate `ports`，非 diport（ADR-005 category line）。
/// 基 trait 带 `Send + Sync` supertrait：登录 handler 需 clone 共享同一 credential store，且
/// `LoginService::login().await` future 必须为 `Send`（axum handler 要求）。
///
/// **租户隔离由签名承载（fail-closed）**：所有方法接收 [`TenantRepoScope`] 做 RLS / store scope；跨租
/// 经 tenant-keyed 查找天然失败——`find(t ≠ cred.tenant)` → `None`，`authenticate` → `RejectedUnknown`，
/// 不创建会话、不推进锁定计数（spec 003 US3 跨租红用例）。
///
/// **与 `RoleReadRepo` 差异**：本 port 在 PR3 已有写实 in-mem 替身（[`crate::internal`]），非纯签名冻结——
/// 锁定态推进是多实例暴破防御的硬需求（内存态多实例不共享则失效），由**原子 port 方法**承载（见下）。
/// 生产 PostgreSQL adapter 与 in-memory 替身实现相同的 combined authentication contract；
/// `Credential` / `AccountLockout` 只经受控 hydrate/accessor 跨 crate 持久化。
///
/// **租户/主体一致性 = 类型层 Hard（F2）**：携带完整 `Credential` 的写方法（`save` / `apply_password_change`）**不收**
/// 独立 `tenant`/`login` 参，store key 直接派生自 `credential.tenant()` / `.login()`——错位组合不可表达
/// （零信任租户隔离不靠调用方约定 / debug_assert）。只持标识的方法 `authenticate` 收
/// [`TenantRepoScope`] + [`LoginIdentifier`]（登录路径，攻击者可控查找键）；`find_by_user_id` 收 [`TenantRepoScope`] +
/// `ids::UserId`（self-scoped 改密路径，认证主体锚点，#1277 F2）——二者皆经 tenant-keyed 查找天然 fail-closed。
///
/// **验签 + 锁定推进原子化（F1+F2，#1277）**：失败计数 = 安全关键状态，**禁**外部「读-改-写」（并发丢更新）。
/// `authenticate` 在 provider 内单次原子完成「有界 KDF 验签 + 据已知/未知主体分流推进 lockout」，返回
/// [`AuthOutcome`]——已知+正确清零、已知+错推进、未知不动；登录枚举防御（禁止未知主体零 KDF 快路径）与真实账号
/// lockout 推进收进**单一原子结果**，「对未知主体建锁」从此无 API 可表达（F2 Hard：未知主体不可预置锁定、
/// 不撑大 lockout 表）。durable state、lazy-unlock 与 KDF 不可拆分；in-mem = 单锁，
/// postgres = 同一 writer 事务内固定行锁顺序。
/// ref: kubernetes client-go RetryOnConflict（并发更新显式版本化）。
/// ref: keycloak DefaultBruteForceProtector.java@main（`failedLogin` 入参为已解析 `UserModel` +
/// `permanentUserLockOut` 的 `getUserById != null` guard：brute-force 计数仅对已知主体推进；RSS 以
/// `AuthOutcome` typed 分流强化为类型层 Hard——`RejectedUnknown` 变体在类型层即与计数路径隔离）。
///
/// **owned 参数**：与既有 DI port（diport / `RoleReadRepo`）一致——async dyn port 用 owned 参规避借用生命周期、简化
/// dynosaur `bridge(dyn)` 装配；消费方调用即弃，代价仅一次 `LoginIdentifier::new`。
#[trait_variant::make(CredentialRepo: Send)]
#[dynosaur(pub DynCredentialRepo = dyn(box) CredentialRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: 同 RoleReadRepo——base trait 非 Send native AFIT，Send 由 trait_variant `CredentialRepo` 变体 +
// dynosaur `DynCredentialRepo` 承载（ADR-003/ADR-004 C1）。`Send + Sync` supertrait 使
// `Arc<DynCredentialRepo>` 可被 axum handler state 间接共享。
pub trait CredentialRepoLocal: Send + Sync {
    /// 按 canonical user id 查凭据（tenant-scoped；不存在返回 `Ok(None)`）。self-scoped 操作（改密）的身份
    /// 锚点是**认证主体**的 `ids::UserId`，**非**请求可选择的登录标识——调用方不能传 login 串定位他人凭据
    /// （#1277 F2：self-scoped 端点身份锚点 = authenticated subject，类型层杜绝越权改他人密码）。
    async fn find_by_user_id(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError>;

    /// **有界 KDF 验签 + 原子锁定记账**（F1+F2+F3，#1277）：无论凭据是否存在，候选明文至少支付当前
    /// profile 的工作（经 typed `secure::verify_password`）——关闭「无此主体时跳过 KDF」的快速枚举路径；
    /// 弱档会额外验证 stored KDF，更强档在硬上限内验证，因此不宣称不同 PHC profile 严格等时。
    /// provider 内据 `(tenant, login)` 查得凭据与否，**原子**分流返回 [`AuthOutcome`]：
    /// - 已知 + Active + 密码正确 → `Authenticated(AccountSecurityState)`（含 scoped canonical
    ///   actor subject 与认证 epoch）+ 清零失败计数；
    /// - 已知 + 密码错 → `RejectedKnown` + 原子推进 lockout（达阈值即锁）；
    /// - 查无凭据 → `RejectedUnknown`，**不建/不动 lockout 态**（F2：未知主体不可被预置锁定、不撑大 lockout 表）。
    ///
    /// `now` 由调用方注入 `Clock` 读出（禁 `SystemTime::now()`，clippy 静态守）。消费方（`LoginService`）对
    /// `RejectedKnown` / `RejectedUnknown` 一律对外 `InvalidCredentials`（不向客户端区分以防枚举）。
    ///
    /// **provider 实现要求（postgres adapter W，#1258）**：① 验签 + lockout 推进须在**单次原子**（事务/行锁/
    /// 条件 upsert）内完成；② `RejectedKnown` 与 `RejectedUnknown` 的 RTT 差异 SHOULD 不超过 argon2 KDF 噪音
    /// 量级——即 lockout 写（仅已知主体路径有）不得引入主体枚举可观测时序差（必要时未知主体路径补等价空写
    /// 或已知主体路径异步推进）。in-mem 替身经 Mutex 内 KDF 主导，天然满足。
    async fn authenticate(
        &self,
        scope: TenantRepoScope,
        login: LoginIdentifier,
        candidate: secure::RawPassword,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError>;

    /// 持久化凭据（upsert）。store key 派生自 `credential`（F2：tenant/login 错位不可表达）。
    async fn save(
        &self,
        scope: TenantRepoScope,
        credential: Credential,
    ) -> Result<(), IdentityError>;

    /// 密码变更的**原子 CAS**：provider 在一个不可分割的写边界内，仅当存储版本
    /// == `expected` 时以 `next` 替换；版本不匹配 → `Err(VersionConflict)` 且零变更，查无凭据 →
    /// `Err(CredentialNotFound)`。单次 port 调用可按 provider 的既定策略重试 transient storage 错误；
    /// `VersionConflict` / CAS 冲突不自动重试。store key 派生自 `next`（F2）；消费方经
    /// `Credential::rotate`（保持 login/user_id/tenant、version + 1）构造 `next`。
    async fn apply_password_change(
        &self,
        scope: TenantRepoScope,
        mutation: PasswordChangeMutation,
    ) -> Result<(), IdentityError>;
}

/// AuthGrant 生命周期域端口：原子登录持久化、活跃根查询和原子关闭收敛到一个 provider。
///
/// `persist_login_grant` 是唯一的初始 refresh 写入口。其必填参数同时携带：
///
/// - 路由精确的 [`LoginProducerReceipt`]；
/// - 密封的 [`LoginGrantMutation`]（AuthGrant + 初始 refresh 哈希记录）；
/// - 精确 [`EventEntry`] 与 [`OutboxEnvelopeParts`]。
///
/// PostgreSQL provider 独占事务句柄，在同一 producer transaction 中提交根、refresh 与 outbox。业务层没有
/// `save_grant`、`insert_initial_refresh` 或裸事务句柄，因此 split transaction 从端口形状上不可表达。L2
/// producer assurance 静态检查 receipt → generated fact → authorization → transaction outcome 的完整能力链。
///
/// `close` 消费由根状态机产生的密封命令；provider 必须先撤销绑定 refresh 族，再关闭根，且两步同事务。
/// `find_active` 对缺失、终态及跨租户统一返回 `None`。单一 provider 同时实现 lifecycle 与 refresh port，
/// 避免测试/demo 中出现根与刷新族落入两个互不一致的 store。
///
/// 公开 [`AuthGrantLifecycle`] 是 Send 变体，[`DynAuthGrantLifecycle`] 是组合根使用的 dyn wrapper。
/// ref: ADR-019 AuthGrant root
/// ref: Cockburn Hexagonal Ports&Adapters
#[trait_variant::make(AuthGrantLifecycle: Send)]
#[dynosaur(pub DynAuthGrantLifecycle = dyn(box) AuthGrantLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `AuthGrantLifecycle` 变体 +
// dynosaur `DynAuthGrantLifecycle` 承载（DI 注入走 Send wrapper）。`Send + Sync` supertrait 使
// `Arc<DynAuthGrantLifecycle>` 可被 axum handler state 间接共享。
pub trait AuthGrantLifecycleLocal: Send + Sync {
    /// Persist the grant root, initial refresh record and `identity.session-created` outbox row in
    /// one provider-owned transaction. This is the only initial-refresh persistence API.
    async fn persist_login_grant(
        &self,
        receipt: LoginProducerReceipt,
        scope: TenantRepoScope,
        mutation: LoginGrantMutation,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError>;

    /// Find an active grant. Missing, terminal and cross-tenant rows are indistinguishable.
    async fn find_active(
        &self,
        scope: TenantRepoScope,
        grant_id: AuthGrantId,
        observed_at: SystemTime,
    ) -> Result<Option<AuthGrant>, IdentityError>;

    /// Revoke the full refresh family and close the grant atomically.
    async fn close(
        &self,
        scope: TenantRepoScope,
        command: AuthGrantCloseCommand,
    ) -> Result<(), IdentityError>;
}

/// Credential-security projection and OutboxFact lifecycle.
///
/// The sealed command binds a validated account/grant CAS mutation to its exact event and a
/// linear commit capability. A provider may return [`CredentialSecurityReceipt`] only after the
/// projection and generated `identity.security-event` outbox row commit together.
#[trait_variant::make(IdentitySecurityLifecycle: Send)]
#[dynosaur(pub DynIdentitySecurityLifecycle = dyn(box) IdentitySecurityLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait IdentitySecurityLifecycleLocal: Send + Sync {
    async fn execute(
        &self,
        scope: TenantRepoScope,
        command: CredentialSecurityCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError>;
}

/// Read-only provider for resolving opaque security-event targets inside a sealed tenant scope.
#[trait_variant::make(CredentialSecurityTargetResolver: Send)]
#[dynosaur(
    pub DynCredentialSecurityTargetResolver = dyn(box) CredentialSecurityTargetResolver,
    bridge(dyn)
)]
#[allow(async_fn_in_trait)]
pub trait CredentialSecurityTargetResolverLocal: Send + Sync {
    async fn resolve(
        &self,
        request: CredentialSecurityTargetResolutionRequest,
    ) -> Result<Option<ResolvedCredentialSecurityTarget>, IdentityError>;
}

/// refresh token 持久化 store DI port（域形；provider 可换：prod postgres / test in-mem）——#1325。
///
/// 公开 [`RefreshTokenStore`] 是 **Send 变体**（adapter `impl RefreshTokenStore for ...`），
/// [`DynRefreshTokenStore`] 是其 dyn-compatible wrapper（组合根经 `Box<DynRefreshTokenStore>` 注入，ADR-004 C1/C5）。
/// 归属为域形 port（签名引用 [`RefreshTokenRecord`]/[`RefreshTokenId`]/[`RefreshTokenHash`]）→ 本域 crate
/// `ports`，非 diport（ADR-005 category line，同 [`AuthGrantLifecycle`]）。
///
/// 基 trait 带 `Send + Sync` supertrait（同 `CredentialRepo`/`AuthGrantLifecycle`）：refresh / login handler 经
/// `Arc<RefreshService<S>>` 共享同一 store 作 axum handler state，且 `rotate().await` future 须为 `Send`
/// （axum handler 要求）——故 `Box<DynRefreshTokenStore>` 须 `Sync`（#1252 接线 refresh/login 端点）。
///
/// **哈希存储（不存明文）**：store 只持 secret 的 SHA-256 摘要（[`RefreshTokenHash`]）——攻陷 store 不泄露可用
/// refresh token（摘要不可逆）。secret 生成 / 摘要计算在 `secure::refresh`（base 层 crypto），编排在
/// `application::RefreshService`（域 / store 不做 crypto）。
///
/// **租户隔离由签名承载（fail-closed，同 `CredentialRepo`/`AuthGrantLifecycle`）**：所有方法接
/// [`TenantRepoScope`] 做 store scope；跨租 `find_by_hash`→`None`（不泄露存在性）、`rotate`→CAS miss、
/// `revoke`/`revoke_lineage`→幂等 no-op。
///
/// **reuse-detection（旧 refresh 一次性 + 失窃检测）**：rotation 经 [`rotate`](RefreshTokenStoreLocal::rotate)
/// 的**原子 CAS** 保证旧 token 一次性消费；命中已消费 / 已撤销 token（重放）由 application 经
/// [`revoke_lineage`](RefreshTokenStoreLocal::revoke_lineage) 级联撤销整条谱系（OAuth refresh rotation 标准）。
///
/// ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh rotation + graceful reuse-detection，概念谱系）
/// ref: Cockburn Hexagonal Ports&Adapters（repo 归域核心，adapter DIP 实现）
#[trait_variant::make(RefreshTokenStore: Send)]
#[dynosaur(pub DynRefreshTokenStore = dyn(box) RefreshTokenStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RefreshTokenStore` 变体 +
// dynosaur `DynRefreshTokenStore` 承载（DI 注入走 Send wrapper）。`Send + Sync` supertrait 使
// `Box<DynRefreshTokenStore>` 为 `Sync`、`RefreshService<S>` 可作共享 handler state（同 AuthGrantLifecycle，#1252）。
pub trait RefreshTokenStoreLocal: Send + Sync {
    /// 按 secret 摘要查找（不存在 / 跨租 → `Ok(None)`，不泄露存在性）。返回的记录含 status——application 据此
    /// 判活跃 / 重放（命中非 Active = 重放）。
    async fn find_by_hash(
        &self,
        scope: TenantRepoScope,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, IdentityError>;

    /// **原子 CAS 轮换**：仅当 `rotation.old_id()` 当前 `status == Active` 时，**同一事务**内标其 `Consumed`
    /// + 插入 `rotation.new_record()`。
    ///
    /// 入参是 sealed [`RefreshRotation`] 命令（由源 record `begin_rotation` 派生）——tenant / parent / lineage
    /// 已从源 record 派生，错位组合类型层不可表达（REFRESH-ROTATE-LINEAGE-01，#284 F2）。store 据
    /// `rotation.new_record().tenant()` 注入 scope（无独立 `tenant` 入参可错位）。
    ///
    /// 返回 [`RefreshRotationOutcome::Applied`] = CAS 命中（old 当时仍 Active，已消费 + 写入 new）；
    /// [`RefreshRotationOutcome::Replay`] = old 已非 Active（并发轮换 / 重放胜出者已消费它）——
    /// **不写 new**，由 application 据此触发 reuse-detection 级联撤销；
    /// [`RefreshRotationOutcome::AccountStale`] = 最终 writer 事务观察到账号非 Active 或签发 epoch 已过期；
    /// [`RefreshRotationOutcome::Expired`] = 最终 writer 事务观察到 old refresh 或其 AuthGrant 已过期。
    /// 两种 fence 结果都让 old 保持未消费且不写 new。
    /// 旧 refresh 一次性失效在类型层 + 事务 CAS 双重保证（杜绝 TOCTOU 双换）。
    async fn rotate(
        &self,
        scope: TenantRepoScope,
        mutation: RefreshRotationMutation,
    ) -> Result<RefreshRotationOutcome, IdentityError>;

    /// **级联撤销整条谱系**（reuse-detection + logout）：把 `lineage_id` 家族全部记录置 `Revoked`。幂等
    /// （未知 / 跨租 / 已撤销均 `Ok` 且 no-op）。
    ///
    /// logout 与 reuse-detection 共用谱系级撤销——logout 须使活跃 token 及其整条轮换链失效（否则已轮换出的
    /// 子 token 仍可用），故无独立单条 `revoke(id)`（YAGNI：单条撤销无消费方）。
    async fn revoke_lineage(
        &self,
        scope: TenantRepoScope,
        lineage_id: RefreshTokenId,
    ) -> Result<(), IdentityError>;
}

/// Consumed owner that yields the lifecycle and refresh capabilities of one AuthGrant backend.
///
/// Login composition accepts this owner instead of two independent ports. Implementations decide
/// how both views share one backing store; the production PostgreSQL implementation constructs
/// both from the same verified capability bundle.
pub trait AuthGrantProvider: Send + Sync + 'static {
    type Lifecycle: AuthGrantLifecycle + 'static;
    type RefreshStore: RefreshTokenStore + 'static;

    fn into_auth_grant_parts(self) -> (Self::Lifecycle, Self::RefreshStore);
}

impl<T> AuthGrantProvider for T
where
    T: AuthGrantLifecycle + RefreshTokenStore + Clone + 'static,
{
    type Lifecycle = T;
    type RefreshStore = T;

    fn into_auth_grant_parts(self) -> (Self::Lifecycle, Self::RefreshStore) {
        (self.clone(), self)
    }
}

impl<T> PolicyRepo for std::sync::Arc<T>
where
    T: PolicyRepo + ?Sized,
{
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: PolicyId,
    ) -> Result<Option<Policy>, IdentityError> {
        T::find(self, scope, id).await
    }

    async fn list_active(
        &self,
        scope: TenantRepoScope,
        page: PolicyPage,
    ) -> Result<PolicyListResult, IdentityError> {
        T::list_active(self, scope, page).await
    }

    async fn list_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        at: SystemTime,
    ) -> Result<Vec<Policy>, IdentityError> {
        T::list_effective(self, tenant_scope, scope, at).await
    }
}

impl<T> ResourceAttributeReadRepo for std::sync::Arc<T>
where
    T: ResourceAttributeReadRepo + ?Sized,
{
    async fn resolve_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        required_keys: Vec<ResourceAttributeKey>,
        at: SystemTime,
    ) -> Result<ResourceAttributeResolution, IdentityError> {
        T::resolve_effective(self, tenant_scope, scope, resource_id, required_keys, at).await
    }
}

impl<T> RoleReadRepo for std::sync::Arc<T>
where
    T: RoleReadRepo + ?Sized,
{
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: RoleId,
    ) -> Result<Option<Role>, IdentityError> {
        T::find(self, scope, id).await
    }

    async fn list(
        &self,
        scope: TenantRepoScope,
        page: RolePage,
    ) -> Result<RoleListResult, IdentityError> {
        T::list(self, scope, page).await
    }
}

impl<T> RoleBindingReadRepo for std::sync::Arc<T>
where
    T: RoleBindingReadRepo + ?Sized,
{
    async fn list_for_subject(
        &self,
        scope: TenantRepoScope,
        subject: String,
    ) -> Result<Vec<RoleBinding>, IdentityError> {
        T::list_for_subject(self, scope, subject).await
    }
}

mod identity_port_effect_sealed {
    pub trait Sealed {}
}

/// Closed, owner-defined effect classification for identity domain DI ports.
///
/// Only the canonical dyn wrappers owned by this module are classified. The private supertrait
/// prevents downstream crates from assigning an effect to another type or overriding one of these
/// assignments. [`Arc`](std::sync::Arc) and [`Box`] preserve the wrapped port's classification.
#[allow(private_bounds)]
pub trait IdentityPortEffect: identity_port_effect_sealed::Sealed {
    type Effect: diport::PortEffectClass;
    type Privilege: diport::PortPrivilegeClass;
}

macro_rules! classify_identity_ports {
    ($($port:ident => $effect:ty),+ $(,)?) => {
        $(
            impl<'a> identity_port_effect_sealed::Sealed for $port<'a> {}

            impl<'a> IdentityPortEffect for $port<'a> {
                type Effect = $effect;
                type Privilege = diport::LocalPrivilege;
            }
        )+

        const _: fn() = || {
            fn assert_effect<T, E>()
            where
                T: IdentityPortEffect<Effect = E, Privilege = diport::LocalPrivilege> + ?Sized,
                E: diport::PortEffectClass,
            {
            }

            $(assert_effect::<$port<'static>, $effect>();)+
        };
    };
}

classify_identity_ports! {
    DynPolicyRepo => diport::AuthEffect,
    DynResourceAttributeReadRepo => diport::AuthEffect,
    DynResourceAttributeWriteRepo => diport::BusinessWriteEffect,
    DynRoleBindingReadRepo => diport::AuthEffect,
    DynRoleReadRepo => diport::ReadEffect,
    DynRoleWriteRepo => diport::BusinessWriteEffect,
    DynAccountSecurityReadRepo => diport::AuthEffect,
    DynAccountSecurityLifecycle => diport::BusinessWriteEffect,
    DynCredentialRepo => diport::BusinessWriteEffect,
    DynRefreshTokenStore => diport::BusinessWriteEffect,
    DynPolicyLifecycle => diport::OutboxEffect,
    DynRoleBindingLifecycle => diport::OutboxEffect,
    DynAuthGrantLifecycle => diport::OutboxEffect,
    DynIdentitySecurityLifecycle => diport::OutboxEffect,
    DynCredentialSecurityTargetResolver => diport::ReadEffect,
}

impl<T> identity_port_effect_sealed::Sealed for std::sync::Arc<T> where
    T: identity_port_effect_sealed::Sealed + ?Sized
{
}

impl<T> IdentityPortEffect for std::sync::Arc<T>
where
    T: IdentityPortEffect + ?Sized,
{
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

impl<T> identity_port_effect_sealed::Sealed for Box<T> where
    T: identity_port_effect_sealed::Sealed + ?Sized
{
}

impl<T> IdentityPortEffect for Box<T>
where
    T: IdentityPortEffect + ?Sized,
{
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod identity_port_effect_registry_tests {
    use std::collections::BTreeSet;

    #[test]
    fn canonical_dyn_wrappers_and_effect_registry_are_an_exact_set() {
        let source = include_str!("ports.rs");
        let canonical = source
            .lines()
            .filter_map(|line| {
                let (_, suffix) = line.split_once("pub Dyn")?;
                let name = suffix
                    .chars()
                    .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                    .collect::<String>();
                (!name.is_empty()).then(|| format!("Dyn{name}"))
            })
            .collect::<BTreeSet<_>>();
        let registry_body = source
            .split_once("classify_identity_ports! {")
            .and_then(|(_, suffix)| suffix.split_once("\n}"))
            .map(|(body, _)| body)
            .expect("identity effect registry must remain present");
        let classified = registry_body
            .lines()
            .filter_map(|line| {
                let (name, _) = line.trim().split_once(" => ")?;
                name.starts_with("Dyn").then(|| name.to_owned())
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(
            canonical, classified,
            "every canonical Dyn wrapper must have exactly one owner-sealed effect classification"
        );
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：域形 async repo port 可 native-AFIT impl + mockall mock（非 `#[async_trait]`）均经
    //! `Box<DynRoleReadRepo>` 装入（PORT-SHAPE-01/02）。
    //!
    //! 与 diport `signer.rs` smoke 的差异：identity 域类型（`RoleId`/`Role`）构造器 **PR1 已写实**，但本 port
    //! 的 repo impl（`NoopRoleRepo` / mock）方法 body 仍 `todo!()`（真实 repo 接缝待 W，issue #1083），故本
    //! smoke **只构造 Dyn wrapper + 断言 `Send`，不 `.await`**（不触 repo `todo!()`）。async future 的 Send + 跨
    //! `tokio::spawn` 调度由 diport `signer.rs` `mockall_mock_loads_into_dyn_signer` 同范式已证（dynosaur Send 变体保证）。
    use super::{
        AuthGrant, AuthGrantCloseCommand, AuthGrantId, AuthGrantLifecycle, DynAuthGrantLifecycle,
        DynRoleReadRepo, EventEntry, IdentityError, LoginGrantMutation, LoginProducerReceipt,
        OutboxEmitError, OutboxEnvelopeParts, PersistedLoginGrantReceipt, Role, RoleId,
        RoleReadRepo, TenantRepoScope,
    };
    use std::sync::Arc;

    struct NoopRoleRepo;
    impl RoleReadRepo for NoopRoleRepo {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _id: RoleId,
        ) -> Result<Option<Role>, IdentityError> {
            todo!()
        }
        async fn list(
            &self,
            _scope: TenantRepoScope,
            _page: super::RolePage,
        ) -> Result<super::RoleListResult, IdentityError> {
            todo!()
        }
    }

    fn assert_send<T: Send>(_: &T) {}
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体
    // `DynRoleReadRepo` 且 wrapper `Send`（可跨 spawn 注入）。不调用方法 → 不触 `todo!()`。
    #[test]
    fn role_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynRoleReadRepo> = DynRoleReadRepo::new_box(NoopRoleRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynRoleReadRepo> = DynRoleReadRepo::new_box(MockTestRoleRepo::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——test-only service 把 `Box<DynRoleReadRepo>` 作必填
    // 位置参（非 Option），缺失即编译错误（ADR-004 C5）。impl/mock 各注入一次，证明域形 repo port 与
    // 既有 DI port 一致经 `Box<DynX>` 注入（不调用方法 → 不触 `todo!()`）。
    struct RoleService {
        _repo: Box<DynRoleReadRepo<'static>>,
    }
    impl RoleService {
        fn new(repo: Box<DynRoleReadRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn role_repo_is_required_ctor_injectable() {
        let from_impl = RoleService::new(DynRoleReadRepo::new_box(NoopRoleRepo));
        assert_send(&from_impl._repo);
        let from_mock = RoleService::new(DynRoleReadRepo::new_box(MockTestRoleRepo::new()));
        assert_send(&from_mock._repo);
    }

    // mock 是 native trait impl（`async fn` 直接声明，非 `#[async_trait]`），经 `new_box` 进 `DynRoleReadRepo`。
    mockall::mock! {
        TestRoleRepo {}
        impl RoleReadRepo for TestRoleRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                id: RoleId,
            ) -> Result<Option<Role>, IdentityError>;
            async fn list(
                &self,
                scope: TenantRepoScope,
                page: super::RolePage,
            ) -> Result<super::RoleListResult, IdentityError>;
        }
    }

    // ── AuthGrantLifecycle（原子 login + 查询 + 关闭，单一域形 port）PORT-SHAPE ────────────
    struct NoopAuthGrantLifecycle;
    impl AuthGrantLifecycle for NoopAuthGrantLifecycle {
        async fn persist_login_grant(
            &self,
            _receipt: LoginProducerReceipt,
            _scope: TenantRepoScope,
            _mutation: LoginGrantMutation,
            _entry: EventEntry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError> {
            todo!()
        }
        async fn find_active(
            &self,
            _scope: TenantRepoScope,
            _grant_id: AuthGrantId,
            _observed_at: std::time::SystemTime,
        ) -> Result<Option<AuthGrant>, IdentityError> {
            todo!()
        }
        async fn close(
            &self,
            _scope: TenantRepoScope,
            _command: AuthGrantCloseCommand,
        ) -> Result<(), IdentityError> {
            todo!()
        }
    }

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send+Sync 变体，
    // 可经 `Arc<DynAuthGrantLifecycle>` 共享给 axum handler。
    #[test]
    fn auth_grant_lifecycle_impls_load_into_dyn_wrapper() {
        let from_impl: Arc<DynAuthGrantLifecycle> =
            Arc::from(DynAuthGrantLifecycle::new_box(NoopAuthGrantLifecycle));
        assert_send_sync(&from_impl);
        let from_mock: Arc<DynAuthGrantLifecycle> = Arc::from(DynAuthGrantLifecycle::new_box(
            MockTestAuthGrantLifecycle::new(),
        ));
        assert_send_sync(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——`Arc<DynAuthGrantLifecycle>` 作必填位置参（非 Option），
    // 缺失即编译错误（ADR-004 C5；LoginService 即如此持有单一 lifecycle，见 application.rs）。
    struct AuthGrantService {
        _lifecycle: Arc<DynAuthGrantLifecycle<'static>>,
    }
    impl AuthGrantService {
        fn new(lifecycle: Arc<DynAuthGrantLifecycle<'static>>) -> Self {
            Self {
                _lifecycle: lifecycle,
            }
        }
    }

    #[test]
    fn auth_grant_lifecycle_is_required_ctor_injectable() {
        let from_impl = AuthGrantService::new(Arc::from(DynAuthGrantLifecycle::new_box(
            NoopAuthGrantLifecycle,
        )));
        assert_send_sync(&from_impl._lifecycle);
        let from_mock = AuthGrantService::new(Arc::from(DynAuthGrantLifecycle::new_box(
            MockTestAuthGrantLifecycle::new(),
        )));
        assert_send_sync(&from_mock._lifecycle);
    }

    mockall::mock! {
        TestAuthGrantLifecycle {}
        impl AuthGrantLifecycle for TestAuthGrantLifecycle {
            async fn persist_login_grant(
                &self,
                receipt: LoginProducerReceipt,
                scope: TenantRepoScope,
                mutation: LoginGrantMutation,
                entry: EventEntry,
                envelope: OutboxEnvelopeParts,
            ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError>;
            async fn find_active(
                &self,
                scope: TenantRepoScope,
                grant_id: AuthGrantId,
                observed_at: std::time::SystemTime,
            ) -> Result<Option<AuthGrant>, IdentityError>;
            async fn close(
                &self,
                scope: TenantRepoScope,
                command: AuthGrantCloseCommand,
            ) -> Result<(), IdentityError>;
        }
    }
}

#[cfg(test)]
mod smoke_credential {
    //! build smoke：`CredentialRepo` 域形 async port 同范式（PORT-SHAPE-01/02）——native-AFIT impl +
    //! mockall mock 均经 `Arc<DynCredentialRepo>` 装入 + `Send + Sync`。`NoopCredentialRepo` body `todo!()`，
    //! 故只构造 Dyn wrapper + 断言 `Send`，**不 `.await`**（真实行为由 `internal::mem::InMemCredentialRepo`
    //! round-trip 测试覆盖）。
    use super::{
        AuthOutcome, Credential, CredentialRepo, DynCredentialRepo, IdentityError, LoginIdentifier,
        PasswordChangeMutation, SystemTime, TenantRepoScope,
    };
    use std::sync::Arc;

    struct NoopCredentialRepo;
    impl CredentialRepo for NoopCredentialRepo {
        async fn find_by_user_id(
            &self,
            _scope: TenantRepoScope,
            _user_id: ids::UserId,
        ) -> Result<Option<Credential>, IdentityError> {
            todo!()
        }
        async fn authenticate(
            &self,
            _scope: TenantRepoScope,
            _login: LoginIdentifier,
            _candidate: secure::RawPassword,
            _now: SystemTime,
        ) -> Result<AuthOutcome, IdentityError> {
            todo!()
        }
        async fn save(
            &self,
            _scope: TenantRepoScope,
            _credential: Credential,
        ) -> Result<(), IdentityError> {
            todo!()
        }
        async fn apply_password_change(
            &self,
            _scope: TenantRepoScope,
            _mutation: PasswordChangeMutation,
        ) -> Result<(), IdentityError> {
            todo!()
        }
    }

    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    // PORT-SHAPE-01：impl + mock 均经 `new_box` 装入 dynosaur Send+Sync 变体，可经
    // `Arc<DynCredentialRepo>` 共享给 axum handler。
    #[test]
    fn credential_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Arc<DynCredentialRepo> =
            Arc::from(DynCredentialRepo::new_box(NoopCredentialRepo));
        assert_send_sync(&from_impl);
        let from_mock: Arc<DynCredentialRepo> =
            Arc::from(DynCredentialRepo::new_box(MockTestCredentialRepo::new()));
        assert_send_sync(&from_mock);
    }

    // PORT-SHAPE-02：消费侧构造器必填位置参注入（`Arc<DynCredentialRepo>` 非 Option，缺失即编译错误）。
    struct CredentialService {
        _repo: Arc<DynCredentialRepo<'static>>,
    }
    impl CredentialService {
        fn new(repo: Arc<DynCredentialRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn credential_repo_is_required_ctor_injectable() {
        let from_impl =
            CredentialService::new(Arc::from(DynCredentialRepo::new_box(NoopCredentialRepo)));
        assert_send_sync(&from_impl._repo);
        let from_mock = CredentialService::new(Arc::from(DynCredentialRepo::new_box(
            MockTestCredentialRepo::new(),
        )));
        assert_send_sync(&from_mock._repo);
    }

    mockall::mock! {
        TestCredentialRepo {}
        impl CredentialRepo for TestCredentialRepo {
            async fn find_by_user_id(&self, scope: TenantRepoScope, user_id: ids::UserId) -> Result<Option<Credential>, IdentityError>;
            async fn authenticate(&self, scope: TenantRepoScope, login: LoginIdentifier, candidate: secure::RawPassword, now: SystemTime) -> Result<AuthOutcome, IdentityError>;
            async fn save(&self, scope: TenantRepoScope, credential: Credential) -> Result<(), IdentityError>;
            async fn apply_password_change(&self, scope: TenantRepoScope, mutation: PasswordChangeMutation) -> Result<(), IdentityError>;
        }
    }
}

#[cfg(test)]
mod smoke_refresh {
    //! build smoke：`RefreshTokenStore` 域形 async port 同范式（PORT-SHAPE-01/02，#1325）——native-AFIT impl +
    //! mockall mock 均经 `Box<DynRefreshTokenStore>` 装入 + `Send + Sync`。`RefreshTokenStoreLocal` supertrait
    //! 为 `Send + Sync`（#1252 接线 refresh/login handler 共享 state 要求），故 `DynRefreshTokenStore` 亦
    //! `Send + Sync`；烟测断言升级为 `assert_send_sync`。`NoopRefreshTokenStore` body `todo!()`，
    //! 故只构造 Dyn wrapper + 断言 `Send + Sync`，**不 `.await`**（真实行为由 `internal::mem::InMemRefreshTokenStore`
    //! + `application::RefreshService` 集成测试覆盖）。
    use super::{
        DynRefreshTokenStore, IdentityError, RefreshRotationMutation, RefreshTokenHash,
        RefreshTokenId, RefreshTokenRecord, RefreshTokenStore, TenantRepoScope,
    };

    struct NoopRefreshTokenStore;
    impl RefreshTokenStore for NoopRefreshTokenStore {
        async fn find_by_hash(
            &self,
            _scope: TenantRepoScope,
            _hash: RefreshTokenHash,
        ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
            todo!()
        }
        async fn rotate(
            &self,
            _scope: TenantRepoScope,
            _mutation: RefreshRotationMutation,
        ) -> Result<crate::RefreshRotationOutcome, IdentityError> {
            todo!()
        }
        async fn revoke_lineage(
            &self,
            _scope: TenantRepoScope,
            _lineage_id: RefreshTokenId,
        ) -> Result<(), IdentityError> {
            todo!()
        }
    }

    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send+Sync 变体（#1252）。
    #[test]
    fn refresh_store_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynRefreshTokenStore> =
            DynRefreshTokenStore::new_box(NoopRefreshTokenStore);
        assert_send_sync(&from_impl);
        let from_mock: Box<DynRefreshTokenStore> =
            DynRefreshTokenStore::new_box(MockTestRefreshTokenStore::new());
        assert_send_sync(&from_mock);
    }

    // PORT-SHAPE-02：消費侧构造器必填位置参注入（`Box<DynRefreshTokenStore>` 非 Option，缺失即编译错误）。
    struct RefreshStoreService {
        _store: Box<DynRefreshTokenStore<'static>>,
    }
    impl RefreshStoreService {
        fn new(store: Box<DynRefreshTokenStore<'static>>) -> Self {
            Self { _store: store }
        }
    }

    #[test]
    fn refresh_store_is_required_ctor_injectable() {
        let from_impl =
            RefreshStoreService::new(DynRefreshTokenStore::new_box(NoopRefreshTokenStore));
        assert_send_sync(&from_impl._store);
        let from_mock = RefreshStoreService::new(DynRefreshTokenStore::new_box(
            MockTestRefreshTokenStore::new(),
        ));
        assert_send_sync(&from_mock._store);
    }

    mockall::mock! {
        TestRefreshTokenStore {}
        impl RefreshTokenStore for TestRefreshTokenStore {
            async fn find_by_hash(&self, scope: TenantRepoScope, hash: RefreshTokenHash) -> Result<Option<RefreshTokenRecord>, IdentityError>;
            async fn rotate(&self, scope: TenantRepoScope, mutation: RefreshRotationMutation) -> Result<crate::RefreshRotationOutcome, IdentityError>;
            async fn revoke_lineage(&self, scope: TenantRepoScope, lineage_id: RefreshTokenId) -> Result<(), IdentityError>;
        }
    }
}
