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

use crate::domain::ActiveAccountSecurity;
use authn::{
    AccessGrantValidationInput, AccountSecurityEventKind, AuthGrant, AuthGrantId, AuthGrantStatus,
    CredentialSecurityEventKind, GrantSecurityEventKind,
};
#[cfg(test)]
use authn::{AuthGrantSnapshot, AuthnEpoch};
use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEmitError};
use dynosaur::dynosaur;
use eventexec::event::{GeneratedEventEncoder, ReviewedEvent};

/// Narrow public façade for the identity-owned device-certificate persistence port.
///
/// The feature implementation remains private; adapters can name only the exact sealed inputs,
/// restored snapshots, closed outcomes, and repository traits required to implement the port.
pub mod device_certificate {
    pub use crate::device_certificate::{
        ArtifactDigest, ConditionStateBatch, ConditionUpsertOutcome, DesiredCasOutcome,
        DesiredStateCas, DesiredStateRestore, DesiredStateSnapshot, DeviceCertificateError,
        DeviceCertificateRepository, DeviceCertificateRepositoryError,
        DeviceCertificateRepositoryLocal, DeviceCertificateScope, DeviceCertificateStateSnapshot,
        DeviceSequence, DynDeviceCertificateRepository, ExpectedGeneration, PolicyHash,
        ReportEnvelopeId, ReportedStateHash, ReportedStateRestore, ReportedStateSnapshot,
        ReportedStateWrite, ReportedWriteOutcome,
    };
}

// Exact fact bindings cross the domain→adapter port as zero-copy re-exports. Adapters retain the
// normal Adapter→Domain dependency and cannot introduce an Adapter→Generated layer edge.
pub use generated::event::identity_v1::policy_updated::CONTRACT as POLICY_UPDATED_CONTRACT;
pub use generated::event::identity_v1::role_assigned::CONTRACT as ROLE_ASSIGNED_CONTRACT;
pub use generated::event::identity_v1::role_revoked::CONTRACT as ROLE_REVOKED_CONTRACT;
use generated::event::identity_v1::security_event::{
    self, IdentitySecurityEventPayload, IdentitySecurityEventPayloadActor,
    IdentitySecurityEventPayloadActorKind as WireActorKind,
    IdentitySecurityEventPayloadKind as WireSecurityEventKind, IdentitySecurityEventPayloadTarget,
    IdentitySecurityEventPayloadTargetKind as WireTargetKind,
};
pub use generated::event::identity_v1::security_event::{
    CONTRACT as SECURITY_EVENT_CONTRACT, FACT as SECURITY_EVENT_FACT,
};
pub use generated::event::identity_v1::session_created::{
    CONTRACT as SESSION_CREATED_CONTRACT, FACT as SESSION_CREATED_FACT,
};

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
    AbacAttribute, AccountCredentialSecurityCommand, AccountLockout, AccountSecurityHydrationError,
    AccountSecurityMutation, AccountSecuritySnapshot, AccountSecurityState,
    AccountSecurityTransitionError, AccountSecurityVersion, AccountStatus, AccountStatusSetCommand,
    AttributeKey, AttributeValue, AuthOutcome, BruteForceDecision, Credential,
    CredentialSecurityCommand, CredentialSecurityEvent, CredentialSecurityInitiator,
    CredentialSecurityReceipt, CredentialSecurityTargetKind, CredentialSecurityTargetRef,
    GlobPattern, GrantCredentialSecurityCommand, IdentityError, LoginIdentifier, LogoutAllCommand,
    LogoutCurrentCommand, Operator, POLICY_ATTR_CONTRACT_ID, POLICY_ATTR_PERMISSION,
    POLICY_ATTR_PRINCIPAL_ID, POLICY_ATTR_PRINCIPAL_KIND, POLICY_ATTR_RESOURCE_ID,
    POLICY_ATTR_TENANT_ID, PasswordChangeCommand, PendingCredentialSecurityCommit, Policy,
    PolicyCondition, PolicyEffect, PolicyId, PolicyObligations, PolicyRouteScope, PolicyRule,
    PolicyVersion, ReactivateAccountCommand, RefreshRotation, RefreshStatus, RefreshTokenHash,
    RefreshTokenId, RefreshTokenRecord, RefreshTokenSnapshot, ResourceAttribute,
    ResourceAttributeKey, ResourceAttributeKeyError, ResourceAttributeResolution,
    ResourceAttributeResourceId, ResourceAttributeVersion, Role, RoleBinding, RoleId,
};
pub use vocab::TenantId;

/// Closed generated fact and envelope pair for one credential-security command.
///
/// Private fields prevent an adapter from replacing the generated payload or contract binding
/// between command construction and the provider transaction.
pub struct CredentialSecurityFact {
    event: ReviewedEvent,
}

impl CredentialSecurityFact {
    pub fn event(&self) -> &ReviewedEvent {
        &self.event
    }
    pub fn into_event(self) -> ReviewedEvent {
        self.event
    }
}

/// Move-only logout-current emission. Its private inner carrier is constructed from the sealed
/// grant-local command, so the generated fact cannot be replaced independently of the mutation.
pub struct LogoutCurrentEmission(CredentialSecurityEmission);

/// Move-only logout-all emission. Its private inner carrier is constructed from the sealed
/// account-wide command, so the generated fact cannot be replaced independently of the mutation.
pub struct LogoutAllEmission(CredentialSecurityEmission);

/// Move-only desired account-status emission.
pub struct AccountStatusSetEmission(CredentialSecurityEmission);

/// Move-only password-change emission retaining the credential CAS command.
pub struct PasswordChangeEmission {
    command: PasswordChangeCommand,
    fact: CredentialSecurityFact,
}

/// Move-only refresh attempt plus the only security fact it may conditionally emit.
pub struct RefreshExecutionEmission {
    command: RefreshExecutionCommand,
    fact: CredentialSecurityFact,
}

struct CredentialSecurityEmission {
    command: CredentialSecurityCommand,
    fact: CredentialSecurityFact,
}

impl CredentialSecurityEmission {
    async fn new(
        command: CredentialSecurityCommand,
        pseudonym_keys: &secure::PseudonymKeyRing,
    ) -> Result<Self, IdentityError> {
        let fact = credential_security_fact(command.event(), pseudonym_keys).await?;
        Ok(Self { command, fact })
    }

    fn into_parts(self) -> CredentialSecurityEmissionParts {
        CredentialSecurityEmissionParts {
            command: self.command,
            event: self.fact.into_event(),
        }
    }
}

/// Owned pieces exposed to the provider only after a route-specific emission has been consumed.
/// The fields stay private; adapters can only consume the tuple returned by [`Self::into_parts`].
pub struct CredentialSecurityEmissionParts {
    command: CredentialSecurityCommand,
    event: ReviewedEvent,
}

impl CredentialSecurityEmissionParts {
    pub fn into_parts(self) -> (CredentialSecurityCommand, ReviewedEvent) {
        (self.command, self.event)
    }
}

impl LogoutCurrentEmission {
    pub fn into_parts(self) -> CredentialSecurityEmissionParts {
        self.0.into_parts()
    }
}

impl LogoutAllEmission {
    pub fn into_parts(self) -> CredentialSecurityEmissionParts {
        self.0.into_parts()
    }
}

impl AccountStatusSetEmission {
    pub fn into_parts(self) -> CredentialSecurityEmissionParts {
        self.0.into_parts()
    }
}

impl PasswordChangeEmission {
    pub fn into_parts(self) -> (PasswordChangeCommand, ReviewedEvent) {
        (self.command, self.fact.into_event())
    }
}

impl RefreshExecutionEmission {
    pub fn into_parts(self) -> (RefreshExecutionCommand, ReviewedEvent) {
        (self.command, self.fact.into_event())
    }
}

/// Consume the exact logout-current command into its only valid generated emission.
pub async fn logout_current_emission(
    command: LogoutCurrentCommand,
    pseudonym_keys: &secure::PseudonymKeyRing,
) -> Result<LogoutCurrentEmission, IdentityError> {
    CredentialSecurityEmission::new(command.into_security_command(), pseudonym_keys)
        .await
        .map(LogoutCurrentEmission)
}

/// Consume the exact logout-all command into its only valid generated emission.
pub async fn logout_all_emission(
    command: LogoutAllCommand,
    pseudonym_keys: &secure::PseudonymKeyRing,
) -> Result<LogoutAllEmission, IdentityError> {
    CredentialSecurityEmission::new(command.into_security_command(), pseudonym_keys)
        .await
        .map(LogoutAllEmission)
}

pub async fn account_status_set_emission(
    command: AccountStatusSetCommand,
    pseudonym_keys: &secure::PseudonymKeyRing,
) -> Result<AccountStatusSetEmission, IdentityError> {
    CredentialSecurityEmission::new(command.into_security_command(), pseudonym_keys)
        .await
        .map(AccountStatusSetEmission)
}

pub async fn password_change_emission(
    command: PasswordChangeCommand,
    pseudonym_keys: &secure::PseudonymKeyRing,
) -> Result<PasswordChangeEmission, IdentityError> {
    let fact = credential_security_fact(command.event(), pseudonym_keys).await?;
    Ok(PasswordChangeEmission { command, fact })
}

pub async fn refresh_execution_emission(
    command: RefreshExecutionCommand,
    pseudonym_keys: &secure::PseudonymKeyRing,
) -> Result<RefreshExecutionEmission, IdentityError> {
    let fact = credential_security_fact(command.event(), pseudonym_keys).await?;
    Ok(RefreshExecutionEmission { command, fact })
}

#[cfg(feature = "test-support")]
pub async fn credential_security_emission_for_test(
    command: CredentialSecurityCommand,
    pseudonym_keys: &secure::PseudonymKeyRing,
) -> Result<CredentialSecurityEmissionParts, IdentityError> {
    CredentialSecurityEmission::new(command, pseudonym_keys)
        .await
        .map(CredentialSecurityEmission::into_parts)
}

/// The wire payload intentionally excludes raw subject, grant, credential and token identifiers.
/// Target and actor references are stable tenant-scoped pseudonyms; the same actor projection is
/// used in the payload and persisted outbox metadata so durable consumers can attribute safely.
pub async fn credential_security_fact(
    event: &CredentialSecurityEvent,
    pseudonym_keys: &secure::PseudonymKeyRing,
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
        CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountReactivated) => {
            WireSecurityEventKind::AccountReactivated
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
    let target_ref = event
        .target_ref(pseudonym_keys)
        .map_err(security_fact_build)?;
    let target_kind = match event.target_kind() {
        CredentialSecurityTargetKind::Subject => WireTargetKind::Subject,
        CredentialSecurityTargetKind::Grant => WireTargetKind::Grant,
    };
    let actor_kind = match event.initiator().kind() {
        vocab::PrincipalKind::User => WireActorKind::User,
        vocab::PrincipalKind::Device => WireActorKind::Device,
        vocab::PrincipalKind::Admin => WireActorKind::Admin,
        vocab::PrincipalKind::SuperAdmin => WireActorKind::SuperAdmin,
        vocab::PrincipalKind::Service => WireActorKind::Service,
        vocab::PrincipalKind::Anonymous => {
            return Err(security_fact_build(std::io::Error::other(
                "anonymous credential-security initiator",
            )));
        }
        _ => {
            return Err(security_fact_build(std::io::Error::other(
                "unsupported credential-security initiator",
            )));
        }
    };
    let actor_ref = event
        .initiator()
        .privacy_ref(pseudonym_keys)
        .map_err(security_fact_build)?;
    let actor_uuid = uuid::Uuid::from_bytes(actor_ref.as_bytes());
    let occurred_at = vocab::UnixEpochSeconds::try_from(event.occurred_at())
        .map_err(security_fact_build)?
        .get();
    let payload = IdentitySecurityEventPayload {
        actor: IdentitySecurityEventPayloadActor {
            kind: actor_kind,
            key_id: wire_pseudonym_key_id(actor_ref.key_id()),
            ref_: actor_uuid,
        },
        kind,
        occurred_at,
        target: IdentitySecurityEventPayloadTarget {
            kind: target_kind,
            key_id: wire_pseudonym_key_id(target_ref.key_id()),
            ref_: target_ref.as_uuid(),
        },
        tenant_id: event.tenant().to_string(),
    };
    let event_id = uuid::Uuid::new_v4().to_string();
    let idem_key = consistency::IdemKey::parse(&event_id).map_err(security_fact_build)?;
    let subject_id = EnvelopeSubjectId::from_opaque(target_ref.as_uuid().to_string())
        .map_err(security_fact_build)?;
    let actor = OutboxActor::scoped(
        event.initiator().kind(),
        OpaqueActorId::from_opaque(actor_uuid.to_string()).map_err(security_fact_build)?,
        event.tenant(),
        vocab::ScopedTenant::SelfOnly,
    );
    let event = security_event::emit(
        &GeneratedEventEncoder,
        payload,
        event.tenant(),
        subject_id,
        actor,
        idem_key,
    )
    .await
    .map_err(security_fact_build)?;
    Ok(CredentialSecurityFact { event })
}

fn security_fact_build(error: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    IdentityError::SecurityFactBuild(Box::new(error))
}

fn wire_pseudonym_key_id(id: secure::PseudonymKeyId) -> std::num::NonZeroU64 {
    match std::num::NonZeroU64::new(u64::from(id.get())) {
        Some(id) => id,
        None => unreachable!("PseudonymKeyId is non-zero by construction"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod credential_security_fact_tests {
    use super::*;
    use std::time::Duration;

    const CASES: [(CredentialSecurityEventKind, &str, &str); 10] = [
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
            CredentialSecurityEventKind::Account(AccountSecurityEventKind::AccountReactivated),
            "accountReactivated",
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

    fn pseudonym_keys() -> secure::PseudonymKeyRing {
        let key =
            secure::RedactionHashKey::from_bytes(vec![0x42; 32]).expect("valid pseudonym key");
        secure::PseudonymKeyRing::new(
            secure::VersionedPseudonymKey::new(
                secure::PseudonymKeyId::new(std::num::NonZeroU16::MIN),
                key,
            ),
            Vec::new(),
        )
        .expect("valid pseudonym key ring")
    }

    fn command(
        kind: CredentialSecurityEventKind,
        tenant: TenantId,
        user: ids::UserId,
        occurred_at: SystemTime,
    ) -> CredentialSecurityCommand {
        match kind {
            CredentialSecurityEventKind::Account(kind) => {
                let state = if kind == AccountSecurityEventKind::AccountReactivated {
                    AccountSecurityState::try_from(AccountSecuritySnapshot {
                        tenant,
                        user_id: user,
                        status: AccountStatus::Suspended,
                        authn_epoch: 1,
                        version: 2,
                        status_changed_at: SystemTime::UNIX_EPOCH,
                        updated_at: SystemTime::UNIX_EPOCH,
                    })
                    .expect("suspended state")
                } else {
                    AccountSecurityState::initial(tenant, user, SystemTime::UNIX_EPOCH)
                };
                CredentialSecurityCommand::account(
                    state,
                    kind,
                    CredentialSecurityInitiator::authenticated(
                        tenant,
                        vocab::PrincipalKind::User,
                        user.as_uuid().hyphenated().to_string(),
                    ),
                    occurred_at,
                )
                .unwrap_or_else(|error| panic!("account command {kind:?}: {error:?}"))
            }
            CredentialSecurityEventKind::Grant(kind) => CredentialSecurityCommand::grant(
                AuthGrant::hydrate(AuthGrantSnapshot {
                    id: AuthGrantId::hydrate("7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8")
                        .expect("grant id"),
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
                CredentialSecurityInitiator::authenticated(
                    tenant,
                    vocab::PrincipalKind::User,
                    user.as_uuid().hyphenated().to_string(),
                ),
                occurred_at,
            )
            .expect("grant command"),
        }
    }

    #[tokio::test]
    #[allow(
        clippy::cognitive_complexity,
        reason = "one table-driven assertion intentionally checks the full nine-kind protocol matrix"
    )]
    async fn security_event_commands_bind_real_actor_and_stable_tenant_scoped_target() {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let user = ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("user");
        let occurred_at = SystemTime::UNIX_EPOCH + Duration::from_secs(42);
        let pseudonym_keys = pseudonym_keys();

        for (kind, wire_kind, wire_target_kind) in CASES {
            let command = command(kind, tenant, user, occurred_at);
            let event = match command {
                CredentialSecurityCommand::Account(command) => {
                    let (_mutation, event, _pending) = command.into_parts();
                    event
                }
                CredentialSecurityCommand::Grant(command) => {
                    let (_mutation, event, _pending) = command.into_parts();
                    event
                }
            };
            let repeat = credential_security_fact(&event, &pseudonym_keys)
                .await
                .expect("repeat fact");
            let (repeat_entry, _, _) = repeat.into_event().into_parts();
            let repeat_payload: serde_json::Value =
                serde_json::from_slice(repeat_entry.payload()).expect("repeat payload");
            let fact = credential_security_fact(&event, &pseudonym_keys)
                .await
                .expect("fact");
            assert_eq!(fact.event().fact(), SECURITY_EVENT_FACT);
            let (entry, envelope, _) = fact.into_event().into_parts();
            let payload: serde_json::Value =
                serde_json::from_slice(entry.payload()).expect("payload");
            let target_ref = payload["target"]["ref"]
                .as_str()
                .expect("target ref must be a string");
            let actor_ref = payload["actor"]["ref"]
                .as_str()
                .expect("actor ref must be a string");
            assert_eq!(
                payload,
                serde_json::json!({
                    "actor": {
                        "keyId": 1,
                        "kind": "user",
                        "ref": actor_ref,
                    },
                    "kind": wire_kind,
                    "target": {
                        "keyId": 1,
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
            assert_eq!(repeat_payload["target"]["ref"], target_ref);
            assert_eq!(repeat_payload["actor"]["ref"], actor_ref);
            assert!(uuid::Uuid::parse_str(entry.idem_key().as_str()).is_ok());
            assert_ne!(entry.idem_key().as_str(), target_ref);
            assert_eq!(envelope.contract(), &SECURITY_EVENT_CONTRACT);
            assert_eq!(envelope.tenant(), tenant);
            assert_eq!(envelope.subject_id().as_str(), target_ref);
            assert_eq!(envelope.actor().kind(), vocab::PrincipalKind::User);
            assert_eq!(envelope.actor().actor_id().as_str(), actor_ref);
            assert_eq!(envelope.actor().tenant(), Some(tenant));
        }

        let other_tenant =
            TenantId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("other tenant");
        let subject = user.as_uuid().hyphenated().to_string();
        let actor_ref = CredentialSecurityInitiator::authenticated(
            tenant,
            vocab::PrincipalKind::User,
            subject.clone(),
        )
        .privacy_ref(&pseudonym_keys)
        .expect("actor ref");
        let other_actor_ref = CredentialSecurityInitiator::authenticated(
            other_tenant,
            vocab::PrincipalKind::User,
            subject.clone(),
        )
        .privacy_ref(&pseudonym_keys)
        .expect("actor ref");
        assert_ne!(actor_ref, other_actor_ref);

        let publicly_recomputable_actor = uuid::Uuid::new_v5(
            &tenant.as_uuid(),
            format!("actor:user:{subject}").as_bytes(),
        );
        assert_ne!(
            uuid::Uuid::from_bytes(actor_ref.as_bytes()),
            publicly_recomputable_actor,
            "a public tenant UUID must not be sufficient to enumerate actor references"
        );
    }

    #[tokio::test]
    async fn security_event_actor_projection_preserves_typed_attribution_without_raw_subject() {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let user = ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("user");
        let pseudonym_keys = pseudonym_keys();
        for (kind, subject, wire_kind) in [
            (vocab::PrincipalKind::User, "opaque-user", "user"),
            (vocab::PrincipalKind::Admin, "opaque-admin", "admin"),
            (vocab::PrincipalKind::Service, "system-worker", "service"),
        ] {
            let command = CredentialSecurityCommand::account(
                AccountSecurityState::initial(tenant, user, SystemTime::UNIX_EPOCH),
                AccountSecurityEventKind::LogoutAll,
                CredentialSecurityInitiator::authenticated(tenant, kind, subject),
                SystemTime::UNIX_EPOCH,
            )
            .expect("account command");
            let CredentialSecurityCommand::Account(command) = command else {
                unreachable!("account command")
            };
            let (_, event, _) = command.into_parts();
            let (entry, envelope, _) = credential_security_fact(&event, &pseudonym_keys)
                .await
                .expect("security fact")
                .into_event()
                .into_parts();
            let payload: serde_json::Value =
                serde_json::from_slice(entry.payload()).expect("payload");
            let projected = payload["actor"]["ref"].as_str().expect("actor ref");
            assert_eq!(payload["actor"]["kind"], wire_kind);
            assert_eq!(envelope.actor().kind(), kind);
            assert_eq!(envelope.actor().actor_id().as_str(), projected);
            assert!(!String::from_utf8_lossy(entry.payload()).contains(subject));
        }
    }

    #[test]
    fn pre_transaction_fact_build_errors_are_not_classified_as_storage() {
        use std::error::Error as _;

        let build = security_fact_build(
            consistency::IdemKey::parse("").expect_err("empty idempotency key must fail"),
        );
        assert!(matches!(build, IdentityError::SecurityFactBuild(_)));
        assert!(build.source().is_some());
    }

    #[tokio::test]
    async fn security_fact_rejects_pre_epoch_time_instead_of_emitting_epoch_zero() {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let user = ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("user");
        let before_epoch = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        let command = CredentialSecurityCommand::account(
            AccountSecurityState::initial(tenant, user, before_epoch),
            AccountSecurityEventKind::LogoutAll,
            CredentialSecurityInitiator::authenticated(
                tenant,
                vocab::PrincipalKind::User,
                user.as_uuid().hyphenated().to_string(),
            ),
            before_epoch,
        )
        .expect("account command");

        assert!(matches!(
            credential_security_fact(command.event(), &pseudonym_keys()).await,
            Err(IdentityError::SecurityFactBuild(_))
        ));
    }
}

/// `identity.login` request-scoped producer assurance carried into the AuthGrant co-tx funnel.
pub type LoginProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::login::RouteMarker>;
pub type RefreshProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::refresh::RouteMarker>;
pub type PasswordChangeProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::password_change::RouteMarker>;
pub type AccountStatusSetProducerReceipt = httpserve::ProducerAssuranceReceipt<
    generated::http::identity_v1::account_status_set::RouteMarker,
>;
pub type LogoutCurrentProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::logout::RouteMarker>;
pub type LogoutCurrentRouteMarker = generated::http::identity_v1::logout::RouteMarker;
pub type LogoutAllProducerReceipt =
    httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::logout_all::RouteMarker>;
pub type LogoutAllRouteMarker = generated::http::identity_v1::logout_all::RouteMarker;
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

/// A sealed refresh attempt. The application can create it only after exact grant/account
/// observations, while the provider still rechecks the authoritative rows in its transaction.
pub struct RefreshExecutionCommand {
    source: RefreshTokenRecord,
    rotation: Option<RefreshRotation>,
    event: CredentialSecurityEvent,
    pending: PendingRefreshRotationCommit,
}

impl RefreshExecutionCommand {
    pub(crate) fn rotate(
        source: RefreshTokenRecord,
        grant: AuthGrant,
        account: ActiveAccountSecurity,
        rotation: RefreshRotation,
        occurred_at: SystemTime,
    ) -> Option<Self> {
        let child = rotation.new_record();
        if source.status() != RefreshStatus::Active
            || source.auth_grant_status() != AuthGrantStatus::Active
            || grant.status() != AuthGrantStatus::Active
            || source.tenant() != grant.tenant()
            || source.tenant() != account.tenant()
            || source.user_id() != grant.user_id()
            || source.user_id() != account.user_id()
            || source.auth_grant_id() != grant.id()
            || source.issuance_epoch() != grant.authn_epoch_at_issue()
            || source.issuance_epoch() != account.authn_epoch()
            || rotation.old_id() != source.id()
            || child.tenant() != source.tenant()
            || child.auth_grant_id() != source.auth_grant_id()
            || child.user_id() != source.user_id()
            || child.issuance_epoch() != source.issuance_epoch()
            || child.parent_id() != Some(source.id())
            || child.lineage_id() != source.lineage_id()
        {
            return None;
        }
        let event = CredentialSecurityEvent::from_refresh_reuse(&source, occurred_at);
        Some(Self {
            source,
            rotation: Some(rotation),
            event,
            pending: PendingRefreshRotationCommit(()),
        })
    }

    pub(crate) fn contain_reuse(
        source: RefreshTokenRecord,
        occurred_at: SystemTime,
    ) -> Option<Self> {
        if source.status() == RefreshStatus::Active {
            return None;
        }
        let event = CredentialSecurityEvent::from_refresh_reuse(&source, occurred_at);
        Some(Self {
            source,
            rotation: None,
            event,
            pending: PendingRefreshRotationCommit(()),
        })
    }

    pub fn event(&self) -> &CredentialSecurityEvent {
        &self.event
    }

    pub fn into_parts(
        self,
    ) -> (
        RefreshTokenRecord,
        Option<RefreshRotation>,
        CredentialSecurityEvent,
        PendingRefreshRotationCommit,
    ) {
        (self.source, self.rotation, self.event, self.pending)
    }
}

/// Linear capability held by a sealed refresh command until its transaction commits.
#[must_use]
pub struct PendingRefreshRotationCommit(());

impl PendingRefreshRotationCommit {
    /// Convert the pending rotation only when the storage settlement funnel supplies its opaque
    /// commit acknowledgement. Application control flow cannot construct that acknowledgement.
    pub fn confirm(
        self,
        _acknowledgement: RefreshCommitAcknowledgement,
    ) -> PersistedRefreshRotationReceipt {
        PersistedRefreshRotationReceipt(())
    }
}

/// Opaque evidence that the authoritative refresh storage boundary acknowledged its commit.
///
/// The constructor is private. Its production mint callsite is also held to an AST exact set by
/// `producer_assurance`; wrappers, alternate adapters, dead helpers and direct fakes are rejected.
#[must_use]
pub struct RefreshCommitAcknowledgement(());

/// Storage-settlement hook used only after a durable refresh commit has been acknowledged.
///
/// This is public solely because the PostgreSQL adapter lives in a separate crate. The production
/// callsite exact-set gate admits only the canonical PostgreSQL settlement carrier.
#[doc(hidden)]
pub fn acknowledge_durable_refresh_commit() -> RefreshCommitAcknowledgement {
    RefreshCommitAcknowledgement(())
}

/// Unforgeable acknowledgement that a refresh rotation committed.
#[must_use]
pub struct PersistedRefreshRotationReceipt(());

/// Closed outcome of the authoritative refresh producer transaction.
pub enum RefreshExecutionOutcome {
    Applied(PersistedRefreshRotationReceipt),
    ReuseContained,
    AlreadyContained,
    Stale,
    Expired,
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
        event: ReviewedEvent,
    ) -> Result<Policy, IdentityError>;

    async fn update_and_emit(
        &self,
        receipt: PoliciesUpdateProducerReceipt,
        scope: TenantRepoScope,
        policy: Policy,
        expected: PolicyVersion,
        event: ReviewedEvent,
    ) -> Result<Policy, IdentityError>;

    async fn deactivate_and_emit(
        &self,
        receipt: PoliciesDeactivateProducerReceipt,
        scope: TenantRepoScope,
        id: PolicyId,
        expected: PolicyVersion,
        event: ReviewedEvent,
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
        event: ReviewedEvent,
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
        event: ReviewedEvent,
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
/// **租户/主体一致性 = 类型层 Hard（F2）**：insert-only provisioning **不收**
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

    /// Insert an initial credential. Existing tenant/login or tenant/user rows fail closed.
    async fn insert(
        &self,
        scope: TenantRepoScope,
        credential: Credential,
    ) -> Result<(), IdentityError>;
}

/// AuthGrant 生命周期域端口：原子登录持久化与活跃根查询收敛到一个 provider。
///
/// `persist_login_grant` 是唯一的初始 refresh 写入口。其必填参数同时携带：
///
/// - 路由精确的 [`LoginProducerReceipt`]；
/// - 密封的 [`LoginGrantMutation`]（AuthGrant + 初始 refresh 哈希记录）；
/// - 经 generated sealed carrier 构造的精确 [`ReviewedEvent`]。
///
/// PostgreSQL provider 独占事务句柄，在同一 producer transaction 中提交根、refresh 与 outbox。业务层没有
/// `save_grant`、`insert_initial_refresh` 或裸事务句柄，因此 split transaction 从端口形状上不可表达。L2
/// producer assurance 静态检查 receipt → generated fact → authorization → transaction outcome 的完整能力链。
///
/// `find_active` 对缺失、终态及跨租户统一返回 `None`。所有终态安全 mutation
/// 只能进入 [`IdentitySecurityLifecycle`]；本端口不提供 close/revoke 写能力。单一 provider
/// 同时实现 lifecycle 与 refresh port，避免测试/demo 中出现根与刷新族落入两个
/// 互不一致的 store。
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
        event: ReviewedEvent,
    ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError>;

    /// Find an active grant. Missing, terminal and cross-tenant rows are indistinguishable.
    async fn find_active(
        &self,
        scope: TenantRepoScope,
        grant_id: AuthGrantId,
        observed_at: SystemTime,
    ) -> Result<Option<AuthGrant>, IdentityError>;
}

/// Read-only, single-query durable fence for an already cryptographically verified RSS access
/// token. The input can only be derived from [`authn::VerifiedGrantReceipt`]; there is no separate
/// tenant, subject or epoch parameter that a caller can substitute.
#[trait_variant::make(AuthGrantValidator: Send)]
#[dynosaur(pub DynAuthGrantValidator = dyn(box) AuthGrantValidator, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait AuthGrantValidatorLocal: Send + Sync {
    /// Return `true` only when the grant and account are current in one provider observation.
    /// Missing, terminal, expired or mismatched rows are all `Ok(false)`; storage failures remain
    /// errors so the request path can fail closed without falling back to JWT-only evidence.
    async fn is_current(
        &self,
        scope: TenantRepoScope,
        input: &AccessGrantValidationInput,
        observed_at: SystemTime,
    ) -> Result<bool, IdentityError>;
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
    async fn execute_refresh(
        &self,
        receipt: RefreshProducerReceipt,
        scope: TenantRepoScope,
        command: RefreshExecutionCommand,
    ) -> Result<RefreshExecutionOutcome, IdentityError>;

    async fn execute_password_change(
        &self,
        receipt: PasswordChangeProducerReceipt,
        scope: TenantRepoScope,
        command: PasswordChangeCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError>;

    async fn execute_account_status_set(
        &self,
        receipt: AccountStatusSetProducerReceipt,
        scope: TenantRepoScope,
        command: AccountStatusSetCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError>;

    async fn execute_logout_current(
        &self,
        receipt: LogoutCurrentProducerReceipt,
        scope: TenantRepoScope,
        command: LogoutCurrentCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError>;

    async fn execute_logout_all(
        &self,
        receipt: LogoutAllProducerReceipt,
        scope: TenantRepoScope,
        command: LogoutAllCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError>;
}

/// Narrow plain-write capability for internal account reactivation.
///
/// This port cannot consume a producer receipt or append a security fact. Keeping it separate from
/// [`IdentitySecurityLifecycle`] prevents a non-event write from being smuggled through the L2
/// producer capability and lets HTTP restoration use its own auditable OutboxFact command.
#[trait_variant::make(AccountReactivationLifecycle: Send)]
#[dynosaur(pub DynAccountReactivationLifecycle = dyn(box) AccountReactivationLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait AccountReactivationLifecycleLocal: Send + Sync {
    async fn execute_reactivation(
        &self,
        scope: TenantRepoScope,
        command: ReactivateAccountCommand,
    ) -> Result<AccountSecurityState, IdentityError>;
}

/// refresh token 只读 store DI port（域形；provider 可换：prod postgres / test in-mem）。
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
/// [`TenantRepoScope`] 做 store scope；跨租 `find_by_hash`→`None`（不泄露存在性）。
///
/// **写能力刻意排除**：rotation、reuse containment、grant terminalization 与 outbox append 只能经
/// [`IdentitySecurityLifecycle::execute_refresh`] 的 producer transaction 完成。reader 持有者在类型层
/// 无法消费 token、创建 child 或撤销 family。
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
}

/// Consumed owner that yields the lifecycle and refresh capabilities of one AuthGrant backend.
///
/// Login composition accepts this owner instead of two independent ports. Implementations decide
/// how both views share one backing store; the production PostgreSQL implementation constructs
/// both from the same verified capability bundle.
pub trait AuthGrantProvider: Send + Sync + 'static {
    type Lifecycle: AuthGrantLifecycle + 'static;
    type RefreshStore: RefreshTokenStore + 'static;
    type SecurityLifecycle: IdentitySecurityLifecycle + 'static;

    fn into_auth_grant_parts(
        self,
    ) -> (Self::Lifecycle, Self::RefreshStore, Self::SecurityLifecycle);
}

impl<T> AuthGrantProvider for T
where
    T: AuthGrantLifecycle + RefreshTokenStore + IdentitySecurityLifecycle + Clone + 'static,
{
    type Lifecycle = T;
    type RefreshStore = T;
    type SecurityLifecycle = T;

    fn into_auth_grant_parts(
        self,
    ) -> (Self::Lifecycle, Self::RefreshStore, Self::SecurityLifecycle) {
        (self.clone(), self.clone(), self)
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
    DynAuthGrantValidator => diport::AuthEffect,
    DynCredentialRepo => diport::BusinessWriteEffect,
    DynRefreshTokenStore => diport::AuthEffect,
    DynPolicyLifecycle => diport::OutboxEffect,
    DynRoleBindingLifecycle => diport::OutboxEffect,
    DynAuthGrantLifecycle => diport::OutboxEffect,
    DynIdentitySecurityLifecycle => diport::OutboxEffect,
    DynAccountReactivationLifecycle => diport::BusinessWriteEffect,
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
        AuthGrant, AuthGrantId, AuthGrantLifecycle, DynAuthGrantLifecycle, DynRoleReadRepo,
        IdentityError, LoginGrantMutation, LoginProducerReceipt, OutboxEmitError,
        PersistedLoginGrantReceipt, Role, RoleId, RoleReadRepo, TenantRepoScope,
    };
    use eventexec::event::ReviewedEvent;
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
            _event: ReviewedEvent,
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
                event: ReviewedEvent,
            ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError>;
            async fn find_active(
                &self,
                scope: TenantRepoScope,
                grant_id: AuthGrantId,
                observed_at: std::time::SystemTime,
            ) -> Result<Option<AuthGrant>, IdentityError>;
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
        SystemTime, TenantRepoScope,
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
        async fn insert(
            &self,
            _scope: TenantRepoScope,
            _credential: Credential,
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
            async fn insert(&self, scope: TenantRepoScope, credential: Credential) -> Result<(), IdentityError>;
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
        DynRefreshTokenStore, IdentityError, RefreshTokenHash, RefreshTokenRecord,
        RefreshTokenStore, TenantRepoScope,
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
        }
    }
}
