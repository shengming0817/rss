//! One-object candidate archive; the full fault matrix remains in archive.rs.
#[path = "../../../fixtures/recovery_example.rs"]
mod fixture;
#[tokio::test]
async fn example_consumer() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(180), run()).await??;
    Ok(())
}
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("archive-example").await?;
    let minio = testkit::minio_tls_archive(testkit::NetworkAttachment {
        network: network.name(),
        dns_name: "archive-example-s3",
    })
    .await?;
    let f = fixture::Fixture::new(&network).await?;
    let mut input = f.input("archive_worker");
    let credentials = minio.workload();
    input["endpoint"] = serde_json::json!(credentials.endpoint_url());
    input["access_key"] = serde_json::json!(credentials.access_key_id());
    input["secret_key"] = serde_json::json!(credentials.secret_access_key());
    input["s3_ca"] = serde_json::json!(minio.ca_pem());
    input["bucket"] = serde_json::json!(minio.archive_bucket());
    match std::env::var("RSS_ARCHIVE_EXAMPLE") {
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
            rss_examples::recovery_archive::run(serde_json::from_value(input)?).await?
        }
        Err(e) => return Err(e.into()),
    }
    let purged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.archive_jobs WHERE purged",
    )
    .fetch_one(&f.admin)
    .await?;
    let hot:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.consumer_dead_letter WHERE capsule IS NOT NULL").fetch_one(&f.admin).await?;
    anyhow::ensure!(
        purged == 1 && hot == 0,
        "archive durable transition missing"
    );
    let json:serde_json::Value=sqlx::query_scalar("SELECT object FROM rss_transactional_messaging.archive_objects WHERE verified AND prepared IS NULL").fetch_one(&f.admin).await?;
    let object: rss_transactional_messaging_recovery::archive::Object =
        serde_json::from_value(json)?;
    minio
        .assert_admin_cannot_delete_retained_version(
            &object.key,
            object
                .version
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("immutable version missing"))?,
        )
        .await?;
    f.admin.close().await;
    Ok(())
}
