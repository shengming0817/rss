//! Independently resolved public consumer; fixture input arrives over stdin.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        rss_examples::recovery::run(rss_examples::pg::read()?),
    )
    .await??;
    Ok(())
}
