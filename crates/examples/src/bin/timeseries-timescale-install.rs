#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        rss_examples::timeseries_timescale::install(rss_examples::pg::read()?),
    )
    .await??;
    Ok(())
}
