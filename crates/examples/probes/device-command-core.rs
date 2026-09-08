use rss_device_command::*;
fn main() -> anyhow::Result<()> {
    anyhow::ensure!(Coordinate::new(0, 1).is_err(), "zero generation accepted");
    anyhow::ensure!(Coordinate::new(1, 0).is_err(), "zero epoch accepted");
    let before = Coordinate::new(1, 1)?;
    let handoff = Coordinate::new(1, 2)?;
    anyhow::ensure!(before != handoff, "authority epoch ignored");
    Ok(())
}
