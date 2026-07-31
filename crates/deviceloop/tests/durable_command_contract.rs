#![allow(clippy::expect_used, clippy::panic)]

use std::time::{Duration, SystemTime};

use deviceloop::{
    CommandIntentDigest, CreateDeviceCommand, DesiredGeneration, DeviceCommandDeadline,
    DeviceCommandId, DeviceCommandMutation, DeviceCommandScope, DeviceCommandSnapshotView,
    DeviceCommandState, DeviceIngressEnvelopeId, DeviceIngressEvidence, DeviceIngressEvidenceView,
    DeviceIngressFingerprint, DeviceSequence, FenceEpoch, GenerationTracker, ObservedGeneration,
};
use ids::DeviceId;
use vocab::TenantId;

fn time(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn tracker() -> GenerationTracker<&'static str> {
    GenerationTracker::new(
        DeviceCommandScope::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device"),
        ),
        DesiredGeneration::try_new(7).expect("generation"),
        "desired",
        FenceEpoch::try_new(11).expect("epoch"),
    )
}

#[test]
fn intent_digest_is_mandatory_redacted_and_roundtrips() {
    let authority = tracker();
    let digest = CommandIntentDigest::from_bytes([0x5a; 32]);
    assert_eq!(format!("{digest:?}"), "CommandIntentDigest(<sha256>)");

    let command = DeviceCommandState::queue(
        DeviceCommandId::parse("command-1897").expect("command id"),
        digest,
        authority.current_fence(),
        time(10),
        time(20),
    )
    .expect("queue");
    let snapshot = command.snapshot();
    let common = match snapshot.view() {
        DeviceCommandSnapshotView::Queued { common } => common,
        other => panic!("expected queued snapshot, got {other:?}"),
    };
    assert_eq!(common.intent_digest(), digest);
    assert_eq!(
        DeviceCommandState::restore(snapshot.clone().into())
            .expect("restore")
            .snapshot(),
        snapshot
    );
}

#[test]
fn durable_inputs_exclude_server_owned_state_version_and_time() {
    let authority = tracker();
    let create = CreateDeviceCommand::new(
        DeviceCommandId::parse("command-1897").expect("command id"),
        CommandIntentDigest::from_bytes([0x11; 32]),
        authority.current_fence(),
        DeviceCommandDeadline::try_new(time(20)).expect("canonical deadline"),
    );
    assert_eq!(
        create.deadline().system_time().expect("deadline time"),
        time(20)
    );
    assert!(
        DeviceCommandDeadline::try_new(SystemTime::UNIX_EPOCH + Duration::from_nanos(20_000_001))
            .is_err()
    );

    let mutation = DeviceCommandMutation::publish(authority.current_fence());
    assert_eq!(mutation.as_label(), "publish");
}

#[test]
fn ingress_evidence_is_kind_specific_and_bounded() {
    let authority = tracker();
    let event_id = DeviceIngressEnvelopeId::parse("event-1897").expect("event id");
    let sequence = DeviceSequence::try_new(1).expect("sequence");
    let fingerprint = DeviceIngressFingerprint::from_bytes([0x22; 32]);
    let command_id = DeviceCommandId::parse("command-1897").expect("command id");

    let ack = DeviceIngressEvidence::ack_received(
        event_id.clone(),
        command_id,
        authority.fence_coordinate(),
        sequence,
        fingerprint,
    );
    assert_eq!(ack.kind_label(), "ack_received");
    assert_eq!(ack.envelope_id(), &event_id);
    assert_eq!(
        format!("{fingerprint:?}"),
        "DeviceIngressFingerprint(<sha256>)"
    );

    assert!(DeviceIngressEnvelopeId::parse("").is_err());
    assert!(DeviceIngressEnvelopeId::parse(&"x".repeat(257)).is_err());
    assert_eq!(
        DeviceSequence::try_new(0)
            .expect("zero is the first valid device sequence")
            .get(),
        0
    );

    let report = DeviceIngressEvidence::report(
        DeviceIngressEnvelopeId::parse("report-1897").expect("report id"),
        ObservedGeneration::try_new(7).expect("observed generation"),
        FenceEpoch::try_new(11).expect("fence epoch"),
        sequence,
        fingerprint,
    );
    assert!(matches!(
        report.view(),
        DeviceIngressEvidenceView::Report {
            observed_generation,
            fence_epoch,
            sequence: restored,
        } if observed_generation.get() == 7 && fence_epoch.get() == 11 && restored == sequence
    ));
}
