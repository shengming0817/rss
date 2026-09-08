//! The component owns provisioning and post-run durable assertions.
use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        let network = testkit::bridge_network("device-command-example").await?;
        let fixture = testkit::postgres_tls(testkit::NetworkAttachment {network:network.name(),dns_name:"device-command-example"},testkit::PgTlsServerIdentity::MatchingHost).await?;
        let setup = setup(&fixture).await?;
        let owner = &setup.owner;
        let mut input = testkit::example_process::pg_input(&fixture, "device_runtime", "f47ac10b-58cc-4372-a567-0e02b2c3d479");
        input["target"] = serde_json::json!(([1u8;16]));
        input["lineage"] = serde_json::json!(([2u8;16]));
        input["epoch"] = serde_json::json!(1);
        match std::env::var("RSS_DEVICE_COMMAND_EXAMPLE") {
            Ok(binary) => {
                anyhow::ensure!(!binary.is_empty(), "empty external example selection");
                testkit::example_process::run_binary(&binary, &input, Duration::from_secs(60)).await?;
                eprintln!("external-provider-consumer PASS {binary}");
            }
            Err(std::env::VarError::NotPresent) => {
                rss_examples::device_command::run(serde_json::from_value(input)?).await?;
            }
            Err(error) => return Err(error.into()),
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_device_command.commands WHERE command_id='example' AND status='applied'").fetch_one(owner).await?;
        anyhow::ensure!(count == 1, "durable example result missing");
        setup.runtime.close().await;
        owner.close().await;
        Ok::<(), anyhow::Error>(())
    }).await??;
    Ok(())
}
