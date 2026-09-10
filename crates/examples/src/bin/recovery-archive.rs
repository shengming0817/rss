//! Execute the single-object candidate archive scenario.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        rss_examples::recovery_archive::run(rss_examples::pg::read()?),
    )
    .await??;
    Ok(())
}
