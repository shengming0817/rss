use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use deviceloop::{
    DesiredGeneration, DeviceCommandId, DeviceCommandScope, DeviceCommandState, FenceEpoch,
    GenerationTracker, ObservedGeneration,
};

fn main() -> Result<()> {
    let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let device = ids::DeviceId::parse("550e8400-e29b-41d4-a716-446655440000")?;
    let scope = DeviceCommandScope::new(tenant, device);
    let queued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut tracker = GenerationTracker::new(
        scope,
        DesiredGeneration::try_new(1).context("desired generation")?,
        "certificate-v2",
        FenceEpoch::try_new(1).context("fence epoch")?,
    );
    let queued = DeviceCommandState::queue(
        DeviceCommandId::parse("rotate-cert")?,
        tracker.current_fence(),
        queued_at,
        queued_at + Duration::from_secs(30),
    )?;
    let published = queued
        .publish(tracker.current_fence(), queued_at + Duration::from_secs(1))?
        .into_state();
    let received = published
        .ack_received(tracker.current_fence(), queued_at + Duration::from_secs(2))?
        .into_state();
    let received_label = received.status().as_label();

    let matching = tracker
        .report(
            ObservedGeneration::try_new(1).context("observed generation")?,
            FenceEpoch::try_new(1).context("reported fence epoch")?,
            "certificate-v2",
        )
        .into_matching()
        .context("reported state must match desired state")?;
    let applied = received
        .apply(matching, queued_at + Duration::from_secs(3))?
        .into_state();

    println!(
        "queued -> published -> {received_label} -> {}; ACK stops at Received, matching report applies",
        applied.status().as_label()
    );
    Ok(())
}
