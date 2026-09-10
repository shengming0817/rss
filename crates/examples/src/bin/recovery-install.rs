//! Install and seed through candidate-owned schema and encoding.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(45),
        rss_examples::recovery::install(rss_examples::pg::read()?),
    )
    .await??;
    Ok(())
}
