use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use deviceloop::{
    DeviceAck, DeviceAckId, DeviceCommandDecision, DeviceCommandId, DeviceCommandScope,
    DeviceCommandSnapshot, DeviceCommandState, DeviceDispatchIntent, DevicePresence,
};
use metrics_exporter_prometheus::PrometheusBuilder;

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const DEVICE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn tenant() -> Result<vocab::TenantId> {
    Ok(vocab::TenantId::parse(TENANT)?)
}

fn device_id() -> Result<ids::DeviceId> {
    Ok(ids::DeviceId::parse(DEVICE)?)
}

fn scope() -> Result<DeviceCommandScope> {
    Ok(DeviceCommandScope::new(tenant()?, device_id()?))
}

fn command_id(raw: &str) -> Result<DeviceCommandId> {
    Ok(DeviceCommandId::parse(raw)?)
}

fn ack_id(raw: &str) -> Result<DeviceAckId> {
    Ok(DeviceAckId::parse(raw)?)
}

fn dispatch_intent(state: &DeviceCommandState, now: SystemTime) -> Result<DeviceDispatchIntent> {
    state
        .reconcile(DevicePresence::Online, now)
        .into_dispatch_intent()
        .context("expected dispatch intent")
}

#[test]
fn device_command_ack_success_reaches_acked() -> Result<()> {
    let scope = scope()?;
    let pending = DeviceCommandState::pending(scope, command_id("cmd-ack")?, t(10));
    let intent = dispatch_intent(&pending, t(11))?;

    assert_eq!(intent.scope(), scope);
    assert_eq!(intent.command_id().as_str(), "cmd-ack");
    assert!(
        intent.stable_dispatch_key().contains("cmd-ack"),
        "dispatch intent must preserve the command id in the stable key"
    );

    let sent = pending.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;
    let ack = DeviceAck::new(scope, command_id("cmd-ack")?, ack_id("ack-1")?, t(17));
    let acked = sent.observe_ack(ack)?;

    assert_eq!(
        acked.decision(),
        &DeviceCommandDecision::Acked {
            lag: Duration::from_secs(7)
        }
    );
    assert!(matches!(
        acked.state(),
        DeviceCommandSnapshot::Acked {
            scope: observed_scope,
            command_id,
            ack_id,
            convergence_lag,
            ..
        } if observed_scope == scope
            && command_id.as_str() == "cmd-ack"
            && ack_id.as_str() == "ack-1"
            && convergence_lag == Duration::from_secs(7)
    ));
    Ok(())
}

#[test]
fn device_command_timeout_duplicate_ack_and_offline_reconcile() -> Result<()> {
    let scope = scope()?;
    let pending = DeviceCommandState::pending(scope, command_id("cmd-timeout")?, t(10));
    let offline = pending.reconcile(DevicePresence::Offline, t(11));
    assert_eq!(offline.decision(), &DeviceCommandDecision::AwaitOnline);

    let offline_state = offline.finalize();
    let online_intent = offline_state
        .reconcile(DevicePresence::Online, t(12))
        .into_dispatch_intent()
        .context("expected online dispatch")?;
    let sent = pending.mark_dispatched(&online_intent, t(12), Duration::from_secs(20))?;
    assert_eq!(
        sent.reconcile(DevicePresence::Online, t(31)).decision(),
        &DeviceCommandDecision::AwaitAck
    );

    let timeout = sent.reconcile(DevicePresence::Online, t(33));
    assert_eq!(
        timeout.decision(),
        &DeviceCommandDecision::TimedOut {
            lag: Duration::from_secs(23)
        }
    );
    let offline_timeout = sent.reconcile(DevicePresence::Offline, t(33));
    assert_eq!(offline_timeout.decision(), timeout.decision());

    let acked = sent.observe_ack(DeviceAck::new(
        scope,
        command_id("cmd-timeout")?,
        ack_id("late-but-before-timeout-copy")?,
        t(20),
    ))?;
    let late_ack = sent.observe_ack(DeviceAck::new(
        scope,
        command_id("cmd-timeout")?,
        ack_id("ack-after-deadline")?,
        t(33),
    ))?;
    assert_eq!(late_ack.decision(), timeout.decision());
    let acked_state = acked.finalize();
    let duplicate = acked_state.observe_ack(DeviceAck::new(
        scope,
        command_id("cmd-timeout")?,
        ack_id("ack-duplicate")?,
        t(21),
    ))?;
    assert_eq!(duplicate.decision(), &DeviceCommandDecision::DuplicateAck);
    assert_eq!(duplicate.state(), acked_state.snapshot());
    Ok(())
}

#[test]
fn device_command_convergence_lag_metric_exposes_no_high_cardinality_ids() -> Result<()> {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let pending = DeviceCommandState::pending(scope()?, command_id("cmd-timeout")?, t(10));
    let intent = pending
        .reconcile(DevicePresence::Online, t(12))
        .into_dispatch_intent()
        .context("expected dispatch intent")?;
    let sent = pending.mark_dispatched(&intent, t(12), Duration::from_secs(20))?;
    let timeout = sent.reconcile(DevicePresence::Online, t(33));

    metrics::with_local_recorder(&recorder, || {
        let _state = timeout.finalize();
    });

    let rendered = handle.render();
    if !rendered.contains("device_command_convergence_lag_seconds") {
        bail!("metric name missing: {rendered}");
    }
    assert!(rendered.contains("result=\"timed_out\""), "{rendered}");
    assert!(!rendered.contains(TENANT), "{rendered}");
    assert!(!rendered.contains(DEVICE), "{rendered}");
    assert!(!rendered.contains("cmd-timeout"), "{rendered}");
    Ok(())
}
