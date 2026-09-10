//! Fixture owner checks external consumer's actual durable handoff.
#[tokio::test]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(90), run()).await??;
    Ok(())
}
async fn run() -> anyhow::Result<()> {
    let fixture = testkit::exclusive_mqtt_tls(true).await?;
    let directory = tempfile::tempdir()?;
    let input = serde_json::json!({"port":fixture.port(),"username":fixture.username(),"password":fixture.password(),"ca":fixture.ca_pem(),"certificate":fixture.client_cert_pem(),"key":fixture.client_key_pem(),"directory":directory.path(),"id":format!("artifact-{}",std::process::id())});
    match std::env::var("RSS_MQTT_EXAMPLE") {
        Ok(binary) => {
            testkit::example_process::run_binary(
                &binary,
                &input,
                std::time::Duration::from_secs(60),
            )
            .await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
        Err(std::env::VarError::NotPresent) => {
            rss_examples::mqtt::run(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    anyhow::ensure!(
        tokio::fs::read(directory.path().join("handoff")).await? == [1, 2, 3],
        "consumer durable handoff missing"
    );
    Ok(())
}
