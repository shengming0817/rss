//! Independent public consumer; fixture secrets arrive only over stdin.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        rss_examples::webhook::run(rss_examples::pg::read()?),
    )
    .await??;
    Ok(())
}
