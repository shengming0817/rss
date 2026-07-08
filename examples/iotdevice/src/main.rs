use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use deviceloop::{DeviceCommandId, DeviceCommandScope, DeviceCommandState, DevicePresence};

fn main() -> Result<()> {
    let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let device = ids::DeviceId::parse("550e8400-e29b-41d4-a716-446655440000")?;
    let scope = DeviceCommandScope::new(tenant, device);
    let queued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let command =
        DeviceCommandState::pending(scope, DeviceCommandId::parse("rotate-cert")?, queued_at);
    let transition = command.reconcile(
        DevicePresence::Online,
        SystemTime::UNIX_EPOCH + Duration::from_secs(11),
    );
    let intent = transition
        .into_dispatch_intent()
        .context("device should be online and dispatchable")?;

    println!("{}", intent.stable_dispatch_key());
    Ok(())
}
