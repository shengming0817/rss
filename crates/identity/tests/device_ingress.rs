#![allow(clippy::expect_used)]

use deviceloop::{
    DesiredGeneration, DeviceCommandId, DeviceIngressDisposition, DeviceIngressEnvelopeId,
    DeviceIngressEvidence, DeviceIngressFingerprint, DeviceIngressReceipt, DeviceSequence,
    FenceCoordinate, FenceEpoch,
};
use identity::ports::device_certificate::{
    DeviceIngressContract, DeviceIngressDelivery, DeviceIngressPrepareError, prepare_device_ingress,
};
use std::time::SystemTime;

struct Delivery {
    correlation: Option<Vec<u8>>,
}

impl DeviceIngressDelivery for Delivery {
    fn tenant(&self) -> vocab::TenantId {
        vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").expect("tenant")
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

#[test]
fn prepared_ingress_can_verify_domain_outcome_without_authorizing_settlement() {
    let prepared = prepare_device_ingress(&Delivery {
        correlation: Some(b"ingress-1".to_vec()),
    })
    .expect("prepared ingress");
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
    let prepared = prepare_device_ingress(&Delivery {
        correlation: Some(b"ingress-1".to_vec()),
    })
    .expect("prepared ingress");
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

    assert!(matches!(
        prepare_device_ingress(&Delivery { correlation: None }),
        Err(DeviceIngressPrepareError::MissingEnvelopeIdentity)
    ));
}
