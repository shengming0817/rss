#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(45),
        rss_examples::timeseries_pg::install(rss_examples::pg::read()?),
    )
    .await??;
    Ok(())
}
