//! Runs the public device-command scenario against an explicitly provisioned temporary backend.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let input = rss_examples::pg::read()?;
    tokio::time::timeout(
        std::time::Duration::from_secs(45),
        rss_examples::device_command::run(input),
    )
    .await??;
    Ok(())
}
