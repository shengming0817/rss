//! The component owns provisioning and post-run durable assertions.
use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        let network = testkit::bridge_network("saga-example").await?;
        let fixture = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: "saga-example",
            },
            testkit::PgTlsServerIdentity::MatchingHost,
        )
        .await?;
        let (owner, pool) = provision(&fixture).await?;
        pool.close().await;
        let input = testkit::example_process::pg_input(
            &fixture,
            "saga_runtime",
            "11111111-2222-4333-8444-555555555555",
        );
        match std::env::var("RSS_SAGA_EXAMPLE") {
            Ok(binary) => {
                anyhow::ensure!(!binary.is_empty(), "empty external example selection");
                testkit::example_process::run_binary(&binary, &input, Duration::from_secs(60))
                    .await?;
                eprintln!("external-provider-consumer PASS {binary}");
            }
            Err(std::env::VarError::NotPresent) => {
                rss_examples::saga::run(serde_json::from_value(input)?).await?;
            }
            Err(error) => return Err(error.into()),
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_saga.step_receipts")
            .fetch_one(&owner)
            .await?;
        anyhow::ensure!(count == 2, "durable example result missing");
        owner.close().await;
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}
