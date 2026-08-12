#![allow(clippy::expect_used)]

use deviceloop::{
    DesiredGeneration, DeviceCommandId, DeviceIngressDisposition, DeviceIngressEnvelopeId,
    DeviceIngressEvidence, DeviceIngressFingerprint, DeviceIngressReceipt, DeviceSequence,
    FenceCoordinate, FenceEpoch,
};
use identity::ports::device_certificate::{
    DeviceIngressContract, DeviceIngressDelivery, DeviceIngressPreparation,
    UnaddressableDeviceIngressReason, application_receipt, prepare_device_ingress,
};
use std::time::SystemTime;

struct Delivery {
    correlation: Option<Vec<u8>>,
}

impl DeviceIngressDelivery for Delivery {
    fn tenant(&self) -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001")
            .expect("tenant")
    }

    fn device(&self) -> ids::DeviceId {
        ids::DeviceId::parse("00000000-0000-4000-8000-000000000002").expect("device")
    }

    fn credential_generation(&self) -> u64 {
        1
    }

    fn contract(&self) -> DeviceIngressContract {
        DeviceIngressContract::CommandAcked
    }

    fn correlation_data(&self) -> Option<&[u8]> {
        self.correlation.as_deref()
    }

    fn payload(&self) -> &[u8] {
        br#"{"deviceId":"00000000-0000-4000-8000-000000000002","commandId":"command-1","desiredGeneration":1,"fenceEpoch":2,"deviceSequence":3,"result":"received","reason":"None","observedAt":10}"#
    }
}

fn receipt(evidence: DeviceIngressEvidence) -> DeviceIngressReceipt {
    DeviceIngressReceipt::restore(
        evidence,
        DeviceIngressDisposition::Advanced,
        SystemTime::UNIX_EPOCH,
        SystemTime::UNIX_EPOCH,
    )
    .expect("receipt")
}

fn accepted(delivery: &Delivery) -> identity::ports::device_certificate::PreparedDeviceIngress {
    match prepare_device_ingress(delivery) {
        DeviceIngressPreparation::Accepted(prepared) => Some(prepared),
        DeviceIngressPreparation::Rejected(_)
        | DeviceIngressPreparation::UnaddressablePoison(_) => None,
    }
    .expect("expected accepted ingress")
}

#[test]
fn prepared_ingress_can_verify_domain_outcome_without_authorizing_settlement() {
    let prepared = accepted(&Delivery {
        correlation: Some(b"ingress-1".to_vec()),
    });
    let expected = prepared.write().evidence().clone();
    let (write, pending) = prepared.into_parts();
    assert_eq!(write.evidence(), &expected);

    let outcome = pending
        .verify_receipt(receipt(expected))
        .expect("exact receipt");
    assert_eq!(outcome.ingress_event_id(), "ingress-1");
    assert_eq!(
        outcome.receipt().evidence().envelope_id().as_str(),
        "ingress-1"
    );
}

#[test]
fn mismatched_or_missing_durable_identity_is_rejected() {
    let prepared = accepted(&Delivery {
        correlation: Some(b"ingress-1".to_vec()),
    });
    let (_, pending) = prepared.into_parts();
    let mismatch = DeviceIngressEvidence::ack_received(
        DeviceIngressEnvelopeId::parse("different-event").expect("event"),
        DeviceCommandId::parse("command-1").expect("command"),
        FenceCoordinate::new(
            DesiredGeneration::try_new(1).expect("generation"),
            FenceEpoch::try_new(2).expect("epoch"),
        ),
        DeviceSequence::try_new(3).expect("sequence"),
        DeviceIngressFingerprint::from_bytes([9; 32]),
    );
    assert!(pending.verify_receipt(receipt(mismatch)).is_err());

    let poison = match prepare_device_ingress(&Delivery { correlation: None }) {
        DeviceIngressPreparation::UnaddressablePoison(poison) => Some(poison),
        DeviceIngressPreparation::Accepted(_) | DeviceIngressPreparation::Rejected(_) => None,
    }
    .expect("missing envelope must enter poison terminal");
    assert_eq!(
        poison.reason(),
        UnaddressableDeviceIngressReason::MissingEnvelopeIdentity
    );
}

#[test]
fn malformed_payload_with_stable_envelope_becomes_durable_protocol_violation() {
    struct MalformedDelivery;
    impl DeviceIngressDelivery for MalformedDelivery {
        fn tenant(&self) -> rss_request_context::TenantId {
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001")
                .expect("tenant")
        }
        fn device(&self) -> ids::DeviceId {
            ids::DeviceId::parse("00000000-0000-4000-8000-000000000002").expect("device")
        }
        fn credential_generation(&self) -> u64 {
            7
        }
        fn contract(&self) -> DeviceIngressContract {
            DeviceIngressContract::CommandAcked
        }
        fn correlation_data(&self) -> Option<&[u8]> {
            Some(b"stable-malformed-1")
        }
        fn payload(&self) -> &[u8] {
            b"not-json"
        }
    }

    let prepared = match prepare_device_ingress(&MalformedDelivery) {
        DeviceIngressPreparation::Rejected(prepared) => Some(prepared),
        DeviceIngressPreparation::Accepted(_)
        | DeviceIngressPreparation::UnaddressablePoison(_) => None,
    }
    .expect("stable malformed ingress must be durably rejected");
    assert_eq!(
        prepared.write().evidence().kind_label(),
        "protocol_violation"
    );
    assert_eq!(prepared.write().credential_generation(), 7);
    let scope = prepared.write().scope();
    let evidence = prepared.write().evidence().clone();
    let rejected = DeviceIngressReceipt::restore(
        evidence,
        DeviceIngressDisposition::Rejected,
        SystemTime::UNIX_EPOCH,
        SystemTime::UNIX_EPOCH,
    )
    .expect("rejected receipt");
    let public = application_receipt(scope, &rejected).expect("public rejection");
    let payload = match public.payload() {
        generated::event::identity_v1::device_ingress_receipted::IdentityDeviceIngressReceiptedPayload::RejectedPayload(payload) => {
            Some(payload)
        }
        _ => None,
    }
    .expect("protocol violation must remain rejected on the public contract");
    assert_eq!(
        payload.reason,
        generated::event::identity_v1::device_ingress_receipted::IdentityDeviceIngressRejectedPayloadReason::ProtocolViolation
    );
}
