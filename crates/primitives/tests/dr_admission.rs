#![allow(clippy::expect_used)]

use std::time::Duration;

use primitives::{AdmissionEpochId, AdmissionError, prepare_dr_admission_controls};
use uuid::Uuid;

fn epoch(fill: u8) -> AdmissionEpochId {
    AdmissionEpochId::new(Uuid::from_bytes([fill; 16])).expect("non-nil admission epoch")
}

#[test]
fn admission_epoch_requires_non_nil_canonical_uuid() {
    let value = Uuid::from_bytes([0xab; 16]);
    let canonical = value.hyphenated().to_string();
    assert_eq!(
        AdmissionEpochId::new(Uuid::nil()),
        Err(AdmissionError::InvalidEpoch)
    );
    assert_eq!(
        AdmissionEpochId::parse("not-a-uuid"),
        Err(AdmissionError::InvalidEpoch)
    );
    assert_eq!(
        AdmissionEpochId::parse(&canonical.to_uppercase()),
        Err(AdmissionError::InvalidEpoch)
    );
    assert_eq!(
        AdmissionEpochId::parse(&canonical)
            .expect("canonical")
            .as_uuid(),
        value
    );
}

#[tokio::test]
async fn admission_pause_is_linearized_and_drain_waits_for_move_only_permits() {
    let prepared = prepare_dr_admission_controls();
    let (control, relay, consumer, writes) = prepared.into_parts();

    assert!(matches!(relay.try_enter(), Err(AdmissionError::Paused)));
    assert!(matches!(consumer.try_enter(), Err(AdmissionError::Paused)));
    assert!(matches!(writes.try_enter(), Err(AdmissionError::Paused)));
    control.start_running().expect("durable lineage is clear");

    let relay_permit = relay.try_enter().expect("relay starts open");
    let consumer_permit = consumer.try_enter().expect("consumer starts open");
    let write_permit = writes.try_enter().expect("writes start open");

    control.pause_all(epoch(1)).expect("pause active epoch");
    assert!(matches!(relay.try_enter(), Err(AdmissionError::Paused)));
    assert!(matches!(consumer.try_enter(), Err(AdmissionError::Paused)));
    assert!(matches!(writes.try_enter(), Err(AdmissionError::Paused)));

    let drain = tokio::time::timeout(Duration::from_millis(20), control.wait_drained());
    assert!(drain.await.is_err(), "in-flight permits must block drain");

    drop((relay_permit, consumer_permit, write_permit));
    tokio::time::timeout(Duration::from_secs(1), control.wait_drained())
        .await
        .expect("drain observation must be bounded")
        .expect("paused lanes drain");

    control.resume_relay(epoch(1)).expect("relay resumes first");
    assert!(relay.try_enter().is_ok());
    assert!(matches!(consumer.try_enter(), Err(AdmissionError::Paused)));
    assert!(matches!(writes.try_enter(), Err(AdmissionError::Paused)));

    control
        .resume_consumer(epoch(1))
        .expect("consumer resumes second");
    assert!(consumer.try_enter().is_ok());
    assert!(matches!(writes.try_enter(), Err(AdmissionError::Paused)));

    control.resume_writes(epoch(1)).expect("writes resume last");
    assert!(writes.try_enter().is_ok());
}

#[tokio::test]
async fn admission_rejects_stale_resume_and_stopped_is_terminal() {
    let prepared = prepare_dr_admission_controls();
    let (control, relay, _consumer, _writes) = prepared.into_parts();
    control.pause_all(epoch(2)).expect("pause");

    assert_eq!(
        control.resume_relay(epoch(1)),
        Err(AdmissionError::EpochConflict)
    );

    control.stop();
    assert!(matches!(relay.try_enter(), Err(AdmissionError::Stopped)));
    assert_eq!(control.resume_relay(epoch(2)), Err(AdmissionError::Stopped));
}

#[tokio::test]
async fn admission_new_epoch_repauses_every_lane_after_partial_resume() {
    let prepared = prepare_dr_admission_controls();
    let (control, relay, consumer, writes) = prepared.into_parts();
    control.pause_all(epoch(3)).expect("pause");
    control.resume_relay(epoch(3)).expect("partial resume");
    assert!(relay.try_enter().is_ok());

    control.pause_all(epoch(4)).expect("new epoch re-pause");
    assert!(matches!(relay.try_enter(), Err(AdmissionError::Paused)));
    assert!(matches!(consumer.try_enter(), Err(AdmissionError::Paused)));
    assert!(matches!(writes.try_enter(), Err(AdmissionError::Paused)));
}

#[tokio::test]
async fn admission_rejects_out_of_order_and_undrained_transitions() {
    let (control, relay, _consumer, _writes) = prepare_dr_admission_controls().into_parts();
    assert_eq!(
        control.resume_relay(epoch(1)),
        Err(AdmissionError::EpochConflict)
    );
    control.start_running().expect("start");
    assert_eq!(
        control.start_running(),
        Err(AdmissionError::InvalidTransition)
    );
    let permit = relay.try_enter().expect("relay permit");
    control.pause_all(epoch(1)).expect("pause");
    assert_eq!(
        control.resume_relay(epoch(1)),
        Err(AdmissionError::NotDrained)
    );
    drop(permit);
    control.wait_drained().await.expect("drained");
    assert_eq!(
        control.resume_consumer(epoch(1)),
        Err(AdmissionError::InvalidTransition)
    );
    control.resume_relay(epoch(1)).expect("relay");
    assert_eq!(
        control.resume_writes(epoch(1)),
        Err(AdmissionError::InvalidTransition)
    );
}

#[tokio::test]
async fn admission_waiters_observe_open_closed_and_terminal_stop() {
    let (control, relay, _consumer, _writes) = prepare_dr_admission_controls().into_parts();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), relay.wait_open())
            .await
            .is_err()
    );
    control.start_running().expect("start");
    relay.wait_open().await.expect("open");
    assert!(
        tokio::time::timeout(Duration::from_millis(10), relay.wait_closed())
            .await
            .is_err()
    );
    control.pause_all(epoch(5)).expect("pause");
    relay.wait_closed().await.expect("closed");
    control.stop();
    assert_eq!(relay.wait_open().await, Err(AdmissionError::Stopped));
    assert_eq!(relay.wait_closed().await, Err(AdmissionError::Stopped));
    assert_eq!(control.wait_drained().await, Err(AdmissionError::Stopped));
    assert_eq!(control.pause_all(epoch(6)), Err(AdmissionError::Stopped));
    assert_eq!(
        control.fail_closed_initializing(),
        Err(AdmissionError::Stopped)
    );
}

#[test]
fn admission_snapshot_tracks_counts_reset_and_terminal_state() {
    let (control, relay, consumer, writes) = prepare_dr_admission_controls().into_parts();
    let initial = control.snapshot();
    assert_eq!(initial.active_epoch(), None);
    assert_eq!(
        initial.phase(),
        primitives::LocalAdmissionPhase::Initializing
    );
    assert_eq!(initial.in_flight(), [0, 0, 0]);
    assert!(!initial.is_stopped());

    control.start_running().expect("start");
    let relay_permit = relay.try_enter().expect("relay");
    let consumer_permit = consumer.try_enter().expect("consumer");
    let write_permit = writes.try_enter().expect("write");
    assert_eq!(control.snapshot().in_flight(), [1, 1, 1]);
    drop((relay_permit, consumer_permit, write_permit));
    assert_eq!(control.snapshot().in_flight(), [0, 0, 0]);

    control.fail_closed_initializing().expect("reset");
    assert_eq!(
        control.snapshot().phase(),
        primitives::LocalAdmissionPhase::Initializing
    );
    control.stop();
    assert!(control.snapshot().is_stopped());
    assert_eq!(control.start_running(), Err(AdmissionError::Stopped));
}
