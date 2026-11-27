use crate::transaction::SecurityEvent;
use rss_audit_core::*;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_identity_core::InstanceId;
use rss_request_context::TenantId;
use serde_json::json;
use uuid::Uuid;

const fn contract(id: &'static str, major: u32, digest: &'static str) -> SourceContract {
    SourceContract::new(
        ContractId::from_static(id),
        ContractVersion::from_static_major(major),
        SchemaDigest::from_static(digest),
    )
}

static ACCOUNT: SourceContract = contract(
    "identity.account.security",
    3,
    "sha256:47f5e210bc21eb91e79ad51b6edc6892caee4766c61cbb68e022fe39e8cd4c0b",
);
static PROVISIONING: SourceContract = contract(
    "identity.account.provisioning",
    1,
    "sha256:5b6240b41bdd4b2d41f374eb9c3ab2065de4afd59a6d081d3df65f6d77e6129d",
);
static AUTHENTICATION: SourceContract = contract(
    "identity.authentication.security",
    1,
    "sha256:05e9bfba291ff0cea88e1ac9698599f79a5496b88d253629ad06126f0bca4fa4",
);
static PROFILE: SourceContract = contract(
    "identity.profile.security",
    1,
    "sha256:b1d85fd4945126c1d887dfd7b9166cbbfb2816ac0b3ebf3de68b3444671ec15b",
);
static SESSION: SourceContract = contract(
    "identity.session.security",
    1,
    "sha256:a5ffc6efdd2f2c0c275555cff44e47c3e5fb395a997bedc5ee07c4ea5750070e",
);
static FEDERATION: SourceContract = contract(
    "identity.federation.security",
    2,
    "sha256:618633921c9b816c89b0de6bd78fc1548b9288e3b8b77cd22f29269a5492579d",
);

#[derive(Debug, thiserror::Error)]
#[error("invalid identity audit event")]
pub(super) struct InvalidEvent;
fn require(ok: bool) -> Result<(), InvalidEvent> {
    if ok { Ok(()) } else { Err(InvalidEvent) }
}
pub(super) fn map_event(
    instance: InstanceId,
    tenant_id: TenantId,
    id: Uuid,
    occurred: Timepoint,
    event: &SecurityEvent,
) -> Result<AuditEventV1, InvalidEvent> {
    let tenant = tenant_id.to_string();
    require(event.tenant() == tenant)?;
    let mapped = match event {
        SecurityEvent::Authentication(e) => {
            require(e.tenant == tenant && !e.principal.is_nil())?;
            let action = match e.action {
                crate::step_up::AuthenticationAction::Registered => "registered",
                crate::step_up::AuthenticationAction::Removed => "removed",
                crate::step_up::AuthenticationAction::Recovered => "recovered",
                crate::step_up::AuthenticationAction::Verified => "verified",
            };
            (
                &AUTHENTICATION,
                format!("identity.authentication.{action}"),
                "principal",
                e.principal.to_string(),
                "authentication",
                e.principal.to_string(),
                Outcome::Succeeded,
                json!({}),
            )
        }
        SecurityEvent::Profile(e) => {
            require(
                e.changed_fields.len() <= 6
                    && e.changed_fields.iter().all(|v| {
                        matches!(
                            *v,
                            "displayName"
                                | "username"
                                | "email"
                                | "emailVerified"
                                | "extensions"
                                | "maxAgeSeconds"
                        )
                    }),
            )?;
            require(
                e.tenant == tenant
                    && !e.principal.is_nil()
                    && matches!(e.action, "observed" | "local_updated")
                    && e.revision.is_none_or(|v| v > 0),
            )?;
            require(
                (e.action == "observed") == e.snapshot_id.is_some()
                    && (e.action == "local_updated") == e.actor.is_some(),
            )?;
            (
                &PROFILE,
                format!("identity.profile.{}", e.action),
                "principal",
                e.actor.unwrap_or(e.principal).to_string(),
                "profile",
                e.principal.to_string(),
                Outcome::Succeeded,
                json!({"source":e.source,"snapshot_id":e.snapshot_id,"revision":e.revision,"changed_fields":e.changed_fields}),
            )
        }
        SecurityEvent::Provisioned(v) => {
            let e = &v.account;
            let actor = e.actor.ok_or(InvalidEvent)?;
            require(
                e.action == "account_created"
                    && v.actor_instance == instance.to_string()
                    && v.actor_tenant != e.tenant
                    && !actor.is_nil()
                    && !e.principal.is_nil()
                    && e.epoch > 0
                    && e.state.membership_epoch > 0,
            )?;
            rss_request_context::TenantId::parse(&v.actor_tenant).map_err(|_| InvalidEvent)?;
            (
                &PROVISIONING,
                "identity.account.provisioned".into(),
                "principal",
                format!("{}:{}", v.actor_tenant, actor),
                "account",
                e.principal.to_string(),
                Outcome::Succeeded,
                json!({"epoch":e.epoch,"state":e.state,"actor_instance":v.actor_instance,"actor_tenant":v.actor_tenant,"actor_principal":actor}),
            )
        }
        SecurityEvent::Account(e) => {
            require(e.tenant == tenant && e.epoch > 0 && e.state.membership_epoch > 0)?;
            require(matches!(
                e.action,
                "initialized"
                    | "account_created"
                    | "account_enabled"
                    | "account_disabled"
                    | "membership_enabled"
                    | "membership_disabled"
                    | "password_changed"
                    | "password_recovered"
            ))?;
            require(
                e.actor.is_some()
                    || matches!(
                        e.action,
                        "initialized" | "account_created" | "password_recovered"
                    ),
            )?;
            let (kind, actor) = e.actor.map_or(("maintenance", instance.to_string()), |a| {
                ("principal", a.to_string())
            });
            (
                &ACCOUNT,
                format!("identity.account.{}", e.action),
                kind,
                actor,
                "account",
                e.principal.to_string(),
                Outcome::Succeeded,
                json!({"epoch":e.epoch,"state":e.state}),
            )
        }
        SecurityEvent::Session(e) => {
            let action = match e.action {
                crate::sessions::SessionAction::Created => "created",
                crate::sessions::SessionAction::Refreshed => "refreshed",
                crate::sessions::SessionAction::Revoked => "revoked",
                crate::sessions::SessionAction::AllRevoked => "all_revoked",
            };
            require(e.tenant == tenant && e.epoch > 0)?;
            require(matches!(
                action,
                "created" | "refreshed" | "revoked" | "all_revoked"
            ))?;
            require(action == "created" || e.replaced_session_id.is_none())?;
            let (kind, id) = if action == "all_revoked" {
                ("account_sessions", e.principal.to_string())
            } else {
                ("session", e.session_id.to_string())
            };
            (
                &SESSION,
                format!("identity.session.{}", action),
                "principal",
                e.principal.to_string(),
                kind,
                id.to_string(),
                Outcome::Succeeded,
                json!({"epoch":e.epoch,"session_id":e.session_id,"replaced_session_id":e.replaced_session_id,"source":e.source}),
            )
        }
        SecurityEvent::Federation(e) => {
            let action = match e.action {
                crate::federation::Action::ProviderCreated => "provider_created",
                crate::federation::Action::ProviderUpdated => "provider_updated",
                crate::federation::Action::ProviderEnabled => "provider_enabled",
                crate::federation::Action::ProviderDisabled => "provider_disabled",
                crate::federation::Action::ProviderTested => "provider_tested",
                crate::federation::Action::ProviderTestFailed => "provider_test_failed",
                crate::federation::Action::JitCreated => "jit_created",
                crate::federation::Action::LoggedIn => "logged_in",
                crate::federation::Action::Linked => "linked",
                crate::federation::Action::AlreadyLinked => "already_linked",
                crate::federation::Action::Reauthenticated => "reauthenticated",
                crate::federation::Action::SteppedUp => "stepped_up",
            };
            require(e.tenant == tenant && e.config_version > 0)?;
            let provider_action = matches!(
                action,
                "provider_created"
                    | "provider_updated"
                    | "provider_enabled"
                    | "provider_disabled"
                    | "provider_tested"
                    | "provider_test_failed"
            );
            require(
                provider_action
                    || matches!(
                        action,
                        "jit_created"
                            | "logged_in"
                            | "linked"
                            | "already_linked"
                            | "reauthenticated"
                            | "stepped_up"
                    ),
            )?;
            require(e.principal.is_some() || action == "provider_updated")?;
            require(e.diagnostic.is_some() == (action == "provider_test_failed"))?;
            let (kind, actor) = e.principal.map_or(("system", instance.to_string()), |p| {
                ("principal", p.to_string())
            });
            let (resource, id) = if provider_action {
                ("provider", e.provider_id.to_string())
            } else {
                (
                    "federated_principal",
                    e.principal.ok_or(InvalidEvent)?.to_string(),
                )
            };
            (
                &FEDERATION,
                format!("identity.federation.{}", action),
                kind,
                actor,
                resource,
                id.to_string(),
                if action == "provider_test_failed" {
                    Outcome::Failed
                } else {
                    Outcome::Succeeded
                },
                json!({"provider_id":e.provider_id,"config_version":e.config_version,"diagnostic":e.diagnostic}),
            )
        }
    };
    let (contract, action, actor_kind, actor_id, resource_kind, resource_id, outcome, payload) =
        mapped;
    let build = || -> Result<_, rss_audit_core::Error> {
        Ok(AuditEventV1::new(
            RecordIdentity::new(
                tenant_id,
                SourceIdentity::new(
                    SourceId::parse(&format!("identity.{instance}"))?,
                    contract.clone(),
                ),
                EventId::parse(&id.to_string())?,
            ),
            EventFacts::new(
                ActorRef::new(ActorKind::parse(actor_kind)?, ActorId::parse(&actor_id)?),
                Action::parse(&action)?,
                ResourceRef::new(
                    ResourceKind::parse(resource_kind)?,
                    ResourceId::parse(&resource_id)?,
                ),
                outcome,
                occurred,
            ),
            EventContext::new(
                Coordinates::new(None, None, None),
                AuditPayload::new(
                    serde_json::to_vec(&payload)
                        .map_err(|_| rss_audit_core::Error::MalformedEncoding)?,
                )?,
            ),
        ))
    };
    build().map_err(|_| InvalidEvent)
}
