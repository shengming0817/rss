//! The component owns provisioning and post-run durable assertions.
use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        let network = testkit::bridge_network("projection-example").await?;
        let fixture = testkit::postgres_tls(testkit::NetworkAttachment {network:network.name(),dns_name:"projection-example"},testkit::PgTlsServerIdentity::MatchingHost).await?;
        let p = fixture.params();
        let owner = PgPoolOptions::new().max_connections(3).connect_with(PgConnectOptions::new()
            .host(&p.host).port(p.port).database(&p.database).username(&p.username).password(&p.password)
            .ssl_mode(PgSslMode::VerifyFull).ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec())).await?;
        sqlx::raw_sql("CREATE ROLE projection_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE projection_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO projection_owner;").execute(&owner).await?;
        let mut migration = owner.acquire().await?;
        sqlx::raw_sql("SET ROLE projection_owner").execute(&mut *migration).await?;
        sqlx::raw_sql(MIGRATION_SQL).execute(&mut *migration).await?;
        sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_projection TO projection_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_projection TO projection_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_projection TO projection_runtime;").execute(&mut *migration).await?;
        drop(migration);
        sqlx::raw_sql(rss_examples::projection::FIXTURE_SQL).execute(&owner).await?;
        let input = testkit::example_process::pg_input(&fixture, "projection_runtime", "f47ac10b-58cc-4372-a567-0e02b2c3d479");
        match std::env::var("RSS_PROJECTION_EXAMPLE") {
            Ok(binary) => {
                anyhow::ensure!(!binary.is_empty(), "empty external example selection");
                testkit::example_process::run_binary(&binary, &input, Duration::from_secs(60)).await?;
                eprintln!("external-provider-consumer PASS {binary}");
            }
            Err(std::env::VarError::NotPresent) => {
                rss_examples::projection::run(serde_json::from_value(input)?).await?;
            }
            Err(error) => return Err(error.into()),
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.projection_demo_counts WHERE total=2").fetch_one(&owner).await?;
        anyhow::ensure!(count == 2, "durable example result missing");
        owner.close().await;
        Ok::<(), anyhow::Error>(())
    }).await??;
    Ok(())
}
