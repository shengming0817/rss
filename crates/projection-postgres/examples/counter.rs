//! Application-owned runnable composition; see README for provisioning.
#[path = "counter/model.rs"]
mod model;
use rss_projection_postgres::PgStore;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::str::FromStr;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("DATABASE_URL")?)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let store = PgStore::new(
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?,
    )
    .await?;
    model::demo(&store).await?;
    let clock = model::Clock::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_projection::Control::new(&clock, std::time::Duration::from_secs(5), &cancel);
    anyhow::ensure!(
        store.close(&control).await == rss_projection_postgres::CloseOutcome::Drained,
        "pool drain interrupted"
    );
    Ok(())
}
