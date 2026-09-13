//! Exact candidate schemas and consumer-owned transaction behavior under non-owner roles.
use super::fence_fixture as fence;
use std::time::Duration;
#[tokio::test]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), run()).await??;
    Ok(())
}
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("ledger-example").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "ledger-example",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let p = fixture.params();
    let mut input = testkit::example_process::pg_input(&fixture, &p.username, super::TENANT);
    input["password"] = serde_json::json!(p.password);
    let admin = serde_json::from_value::<rss_examples::pg::Input>(input)?
        .pool()
        .await?;
    sqlx::raw_sql("CREATE ROLE ledger_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE ledger_migrator LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT ledger_owner TO ledger_migrator; CREATE ROLE ledger_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; GRANT rss_tmsg_relay TO ledger_owner; GRANT CREATE ON DATABASE rss_test TO ledger_owner;").execute(&admin).await?;
    let messaging = std::env::var("RSS_LEDGER_MESSAGING").map_or(true, |v| v == "1");
    let input = testkit::example_process::pg_input(&fixture, "ledger_migrator", super::TENANT);
    match std::env::var("RSS_LEDGER_INSTALL") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(45)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::ledger::install(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_ledger TO ledger_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_ledger TO ledger_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger TO ledger_runtime;").execute(&admin).await?;
    if messaging {
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO ledger_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO ledger_runtime; GRANT SELECT ON rss_transactional_messaging.outbox TO ledger_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea) TO ledger_runtime;").execute(&admin).await?;
        anyhow::ensure!(
            fence::binding().storage()
                == rss_transactional_messaging::fence::StorageIdentity::new([1; 16], [2; 16])?,
            "example storage authority drift"
        );
        fence::provision(&admin).await?;
    }
    let mut input = testkit::example_process::pg_input(&fixture, "ledger_runtime", super::TENANT);
    use ring::rand::SecureRandom as _;
    let mut key = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| anyhow::anyhow!("fixture key generation failed"))?;
    input["ledger_key_id"] = serde_json::json!("ledger-fixture");
    input["ledger_key"] = serde_json::json!(key);
    match std::env::var("RSS_LEDGER_EXAMPLE") {
        Ok(binary) => {
            testkit::example_process::run_binary(&binary, &input, Duration::from_secs(60)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::ledger::run(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    verify(&admin, messaging).await?;
    admin.close().await;
    Ok(())
}

async fn verify(admin: &sqlx::PgPool, messaging: bool) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ledger.entries")
        .fetch_one(admin)
        .await?;
    anyhow::ensure!(
        count == if messaging { 2 } else { 1 },
        "ledger consumer durable results missing"
    );
    if messaging {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT message_id FROM rss_transactional_messaging.outbox ORDER BY message_id",
        )
        .fetch_all(admin)
        .await?;
        anyhow::ensure!(
            ids == ["commit"],
            "message/ledger transaction did not commit and roll back together"
        );
    }
    Ok(())
}
