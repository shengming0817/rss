//! Real redrive consumer, with an independent durable receipt assertion.
#[path = "../../../fixtures/recovery_example.rs"]
mod fixture;
#[tokio::test]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(120),async {
        let network=testkit::bridge_network("redrive-example").await?;
        let f=fixture::Fixture::new(&network).await?;
        let input=f.input("recovery_operator");
        match std::env::var("RSS_RECOVERY_EXAMPLE") {
            Ok(binary)=>{testkit::example_process::run_binary(&binary,&input,std::time::Duration::from_secs(60)).await?;eprintln!("external-provider-consumer PASS {binary}");},
            Err(std::env::VarError::NotPresent)=>rss_examples::recovery::run(serde_json::from_value(input)?).await?,
            Err(e)=>return Err(e.into()),
        }
        let status:String=sqlx::query_scalar("SELECT status FROM rss_transactional_messaging.outbox WHERE message_id='redrive-example'").fetch_one(&f.admin).await?;
        anyhow::ensure!(status=="pending","redrive did not restore pending delivery");
        let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.recovery_operations").fetch_one(&f.admin).await?;
        anyhow::ensure!(receipts==1,"exact redrive receipt missing or duplicated");
        f.admin.close().await;
        Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}
