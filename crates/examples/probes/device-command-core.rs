use rss_device_command::*;
fn main() -> anyhow::Result<()> {
    anyhow::ensure!(Coordinate::new(0, 1).is_err(), "zero generation accepted");
    anyhow::ensure!(Coordinate::new(1, 0).is_err(), "zero epoch accepted");
    anyhow::ensure!(BatchLimit::new(1024)?.get() == 1024, "recovery capacity");
    let before = Coordinate::new(1, 1)?;
    let handoff = Coordinate::new(1, 2)?;
    anyhow::ensure!(before != handoff, "authority epoch ignored");
    let scope = Scope::new(
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440000")?,
    );
    let spec = CommandSpec::new(
        scope,
        CommandId::parse("direct")?,
        before,
        StateDigest::from_bytes([0; 32]),
        100,
    );
    let mut cmd = Command::queue(
        spec,
        Delivery::Direct {
            content_digest: ContentDigest::from_bytes([1; 32]),
        },
        1,
    )?;
    let id = ClaimId::parse("0d9cdad2-218d-4b7e-b095-ec6bea72aa6e")?;
    anyhow::ensure!(cmd.transition(Event::Claim(id), before, 2)? == Outcome::Advanced);
    anyhow::ensure!(cmd.status() == Status::Claimed && cmd.record().claim_id == Some(id));
    Ok(())
}
