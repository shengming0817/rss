mod admission;
mod fixture;
mod process;
mod scenarios;
mod upgrade;
use fixture::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_handoff() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(180), async {
        let f = Fixture::new(false).await?;
        scenarios::composition(&f).await?;
        scenarios::ordered_visibility(&f).await?;
        scenarios::references_and_isolation(&f).await?;
        process::crash(&f).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_way_upgrade() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(90), upgrade::run()).await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_rows_keep_safe_coordinates_and_settlement() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        let f = Fixture::new(false).await?;
        scenarios::restore_diagnostics(&f).await
    })
    .await?
}
