//! Fixture credentials arrive through bounded stdin, not process arguments.
fn main() -> anyhow::Result<()> {
    let input = rss_examples::pg::read()?;
    tokio::runtime::Runtime::new()?.block_on(rss_examples::outbox_writer::run(input))
}
