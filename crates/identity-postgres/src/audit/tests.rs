use super::mapping::map_event;
use crate::{
    federation::{Action, FederationEvent},
    profiles::{ProfileEvent, ProfileSource},
    sessions::{SessionAction, SessionEvent},
    step_up::{AuthenticationAction, AuthenticationEvent},
    transaction::{AccountEvent, EventState, ProvisioningEvent, SecurityEvent},
};
use rss_contract::Timepoint;
use rss_identity_core::{
    InstanceId, SessionId, federation::ProviderId, session::AuthenticationSource,
};
use rss_request_context::TenantId;
use uuid::Uuid;

struct Case {
    event: SecurityEvent,
    id: &'static str,
    major: u32,
    schema: &'static [u8],
}

const INSTANCE: &str = "11111111-1111-4111-8111-111111111111";
const TENANT: &str = "22222222-2222-4222-8222-222222222222";

fn cases() -> [Case; 6] {
    let principal = Uuid::from_u128(3);
    let actor = Uuid::from_u128(4);
    let account = || AccountEvent {
        action: "account_created",
        tenant: TENANT.into(),
        principal,
        actor: Some(actor),
        epoch: 9,
        state: EventState {
            enabled: true,
            member_active: true,
            membership_epoch: 2,
        },
    };
    [
        Case {
            event: SecurityEvent::Account(account()),
            id: "identity.account.security",
            major: 3,
            schema: include_bytes!("../security-event-v3.json"),
        },
        Case {
            event: SecurityEvent::Provisioned(ProvisioningEvent {
                account: account(),
                actor_tenant: "33333333-3333-4333-8333-333333333333".into(),
                actor_instance: INSTANCE.into(),
            }),
            id: "identity.account.provisioning",
            major: 1,
            schema: include_bytes!("../account-provisioning-v1.json"),
        },
        Case {
            event: SecurityEvent::Authentication(AuthenticationEvent {
                tenant: TENANT.into(),
                principal,
                action: AuthenticationAction::Verified,
            }),
            id: "identity.authentication.security",
            major: 1,
            schema: include_bytes!("../authentication-security-event-v1.json"),
        },
        Case {
            event: SecurityEvent::Profile(ProfileEvent {
                tenant: TENANT.into(),
                principal,
                actor: Some(actor),
                action: "local_updated",
                source: ProfileSource::IdentityLocal,
                snapshot_id: None,
                revision: Some(5),
                changed_fields: vec!["email"],
            }),
            id: "identity.profile.security",
            major: 1,
            schema: include_bytes!("../profile-security-event-v1.json"),
        },
        Case {
            event: SecurityEvent::Session(SessionEvent {
                tenant: TENANT.into(),
                principal,
                action: SessionAction::Created,
                session_id: SessionId::parse("44444444-4444-4444-8444-444444444444").unwrap(),
                replaced_session_id: None,
                source: AuthenticationSource::LocalPassword,
                epoch: 3,
            }),
            id: "identity.session.security",
            major: 1,
            schema: include_bytes!("../session-security-event-v1.json"),
        },
        Case {
            event: SecurityEvent::Federation(FederationEvent {
                tenant: TENANT.into(),
                principal: Some(principal),
                action: Action::Linked,
                provider_id: ProviderId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
                config_version: 7,
                diagnostic: None,
            }),
            id: "identity.federation.security",
            major: 2,
            schema: include_bytes!("../federation-security-event-v2.json"),
        },
    ]
}

impl Case {
    fn record(&self) -> rss_audit_core::PreparedAuditV1 {
        let instance = InstanceId::parse(INSTANCE).unwrap();
        let tenant = TenantId::parse(TENANT).unwrap();
        let occurred = Timepoint::try_from(100_i64).unwrap();
        let recorded = Timepoint::try_from(105_i64).unwrap();
        let event = map_event(instance, tenant, Uuid::from_u128(6), occurred, &self.event).unwrap();
        rss_audit_core::prepare(event, recorded).unwrap()
    }
}

// The canonical records were captured with the original mapper and these fixed inputs.
#[test]
fn static_contracts_match_schema_bytes_and_canonical_records_across_batches() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, sync::Barrier, thread};

    let cases = cases();
    let golden: BTreeMap<&str, &str> =
        serde_json::from_str(include_str!("canonical-records.json")).unwrap();
    assert_eq!(golden.len(), cases.len());
    let expected = cases.each_ref().map(|case| {
        let bytes = STANDARD.decode(golden[case.id]).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(case.schema));
        (bytes, digest)
    });

    let start = Barrier::new(2);
    let check_batch = |batch: [usize; 8]| {
        start.wait();
        for i in batch {
            let case = &cases[i];
            let record = case.record();
            let contract = record.identity().source().contract();
            assert_eq!(contract.id().as_str(), case.id);
            assert_eq!(contract.version().major(), case.major);
            assert_eq!(contract.schema_digest().as_str(), expected[i].1);
            assert_eq!(record.canonical_bytes(), expected[i].0, "{}", case.id);
        }
    };
    thread::scope(|threads| {
        threads.spawn(|| check_batch([0; 8]));
        threads.spawn(|| check_batch([0, 1, 2, 3, 4, 5, 0, 1]));
    });
}
