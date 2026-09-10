//! Provision roles only; the independent installer must provide both candidate schemas.
use std::time::Duration;
#[path = "../../../../crates/examples/src/observation/install.rs"]
mod installer;
#[tokio::test]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), run()).await??;
    Ok(())
}
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("observation-example").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "observation-example",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let params = fixture.params();
    let mut admin_input =
        testkit::example_process::pg_input(&fixture, &params.username, super::fixture::TENANT);
    admin_input["password"] = serde_json::json!(params.password);
    let admin: rss_examples::pg::Input = serde_json::from_value(admin_input)?;
    let admin = admin.pool().await?;
    sqlx::raw_sql("CREATE ROLE handoff_owner LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE handoff_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO handoff_owner; GRANT CREATE ON SCHEMA public TO handoff_owner;").execute(&admin).await?;
    let install =
        testkit::example_process::pg_input(&fixture, "handoff_owner", super::fixture::TENANT);
    match std::env::var("RSS_OBSERVATION_INSTALL") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &install, Duration::from_secs(45))
                .await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            let input: rss_examples::pg::Input = serde_json::from_value(install)?;
            let pool = input.pool().await?;
            let mut c = pool.acquire().await?;
            installer::install(&mut c).await?;
            drop(c);
            pool.close().await;
        }
        Err(e) => return Err(e.into()),
    }
    let input =
        testkit::example_process::pg_input(&fixture, "handoff_runtime", super::fixture::TENANT);
    match std::env::var("RSS_OBSERVATION_EXAMPLE") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(60)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::observation::run(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    let facts: i64 = sqlx::query_scalar("SELECT count(*) FROM public.observation_facts")
        .fetch_one(&admin)
        .await?;
    anyhow::ensure!(
        facts == 0,
        "recovery snapshot did not clear projected facts"
    );
    let batches: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_observation.batches")
        .fetch_one(&admin)
        .await?;
    anyhow::ensure!(
        batches == 4,
        "consumer did not durably receive all four batches"
    );
    admin.close().await;
    Ok(())
}
