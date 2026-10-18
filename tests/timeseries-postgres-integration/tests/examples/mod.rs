use super::*;
#[tokio::test]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(100), run()).await??;
    Ok(())
}
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("ts-example").await?;
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "ts-example",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let p = pg.params();
    let mut input = testkit::example_process::pg_input(&pg, &p.username, TENANT);
    input["password"] = serde_json::json!(p.password);
    let admin = serde_json::from_value::<rss_examples::pg::Input>(input)?
        .pool()
        .await?;
    sqlx::raw_sql(ROLES).execute(&admin).await?;
    let input = testkit::example_process::pg_input(&pg, "ts_migrator", TENANT);
    match std::env::var("RSS_TIMESERIES_INSTALL") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(45)).await?
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::timeseries_pg::install(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    sqlx::raw_sql(GRANTS).execute(&admin).await?;
    let mut input = testkit::example_process::pg_input(&pg, "ts_runtime", TENANT);
    input["cursor_key"] = serde_json::to_value([17; 32])?;
    match std::env::var("RSS_TIMESERIES_EXAMPLE") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(45)).await?
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::timeseries_pg::run(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.samples")
        .fetch_one(&admin)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}
