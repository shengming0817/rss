use rss_projection::*;
fn main() -> anyhow::Result<()> {
    let scope = SourceScope::new(
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        "example",
    )?;
    let position = Position::new(1)?;
    let event = Event::new(scope, position, "event", vec![1])?;
    anyhow::ensure!(
        event.position() == position && event.payload() == [1],
        "event identity changed"
    );
    anyhow::ensure!(BatchLimit::new(0).is_err(), "unbounded batch accepted");
    Ok(())
}
