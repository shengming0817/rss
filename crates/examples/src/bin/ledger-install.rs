//! Install the candidate-owned schema under the fixture migration owner.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(45),
        rss_examples::ledger::install(rss_examples::pg::read()?),
    )
    .await??;
    Ok(())
}
