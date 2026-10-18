use super::{postgres::Database, support::*};
#[tokio::test]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(90), run()).await?
}
async fn run() -> anyhow::Result<()> {
    let database = Database::new().await?;
    let mut receiver = Receiver::new(response(204)).await?;
    let input = database.input(&receiver, "independent-webhook");
    match std::env::var("RSS_WEBHOOK_EXAMPLE") {
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
            rss_examples::webhook::run(serde_json::from_value(input)?).await?
        }
        Err(error) => return Err(error.into()),
    }
    let record = receiver.received().await?;
    record.verify(&receiver.endpoint.secret)?;
    assert_eq!(
        record.body,
        message("independent-webhook")?
            .envelope()
            .payload()
            .as_slice()
    );
    assert_eq!(database.status("independent-webhook").await?, "published");
    receiver.stop().await?;
    database.close().await;
    Ok(())
}
