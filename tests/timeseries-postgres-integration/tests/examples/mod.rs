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
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(45)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
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
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(45)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::timeseries_pg::run(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.samples")
        .fetch_one(&admin)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
async fn timescale_shared_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), timescale_run(false)).await??;
    Ok(())
}
#[tokio::test]
async fn timescale_native_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), timescale_run(true)).await??;
    Ok(())
}
async fn timescale_run(native: bool) -> anyhow::Result<()> {
    let network = testkit::bridge_network("ts-native-example").await?;
    let pg = testkit::timescaledb_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "ts-native-example",
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
    sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
        .execute(&admin)
        .await?;
    let deployment = if native {
        serde_json::json!({"profile":"dedicated","maintenance":testkit::example_process::pg_input(&pg,"ts_migrator",TENANT)})
    } else {
        serde_json::json!({"profile":"shared"})
    };
    let mut input = testkit::example_process::pg_input(&pg, "ts_migrator", TENANT);
    input["cursor_key"] = serde_json::to_value([17; 32])?;
    input["deployment"] = deployment.clone();
    match std::env::var("RSS_TIMESERIES_INSTALL") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(60)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::timeseries_timescale::install(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_timeseries TO ts_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_timeseries TO ts_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_timeseries TO ts_runtime; REVOKE EXECUTE ON FUNCTION rss_timeseries.integer_now() FROM ts_runtime").execute(&admin).await?;
    if native {
        sqlx::raw_sql("REVOKE EXECUTE ON FUNCTION rss_timeseries.project_gauge() FROM ts_runtime")
            .execute(&admin)
            .await?;
    }
    let mut input = testkit::example_process::pg_input(&pg, "ts_runtime", TENANT);
    input["cursor_key"] = serde_json::to_value([17; 32])?;
    input["deployment"] = deployment;
    match std::env::var("RSS_TIMESERIES_EXAMPLE") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(60)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::timeseries_timescale::run(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.samples")
        .fetch_one(&admin)
        .await?;
    assert_eq!(remaining, 0);
    Ok(())
}
