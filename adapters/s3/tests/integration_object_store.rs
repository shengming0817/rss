#![cfg(feature = "integration")]

use aws_sdk_s3::config::{Credentials, Region};
use aws_smithy_http_client::{
    Builder,
    tls::{self, rustls_provider::CryptoMode},
};
use diport::{ObjectKey, ObjectStore};
use s3::S3Store;
use secure::PlaintextEndpointPolicy;

fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let value = std::env::var(name).map_err(|_| format!("missing required env var: {name}"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{name} must not be empty").into());
    }
    Ok(trimmed.to_string())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires live MinIO/S3 endpoint via RSS_S3_TEST_* env"]
async fn live_minio_object_store_roundtrip() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let endpoint = secure::S3Endpoint::parse(
        required_env("RSS_S3_TEST_ENDPOINT")?,
        PlaintextEndpointPolicy::AllowLoopback,
    )?;
    let bucket = required_env("RSS_S3_TEST_BUCKET")?;
    let access_key = required_env("RSS_S3_TEST_ACCESS_KEY")?;
    let secret_key = required_env("RSS_S3_TEST_SECRET_KEY")?;
    let region = std::env::var("RSS_S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let http_client = if endpoint.is_plaintext() {
        Builder::new().build_http()
    } else {
        Builder::new()
            .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
            .build_https()
    };
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(Region::new(region))
        .credentials_provider(Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "rss-s3-live-test",
        ))
        .endpoint_url(endpoint.expose())
        .force_path_style(true)
        .http_client(http_client)
        .build();
    let store = S3Store::new(aws_sdk_s3::Client::from_conf(config), bucket)?;
    let key = ObjectKey::new(format!("rss-live-minio/{}.txt", uuid::Uuid::new_v4()));

    store
        .put_object(key.clone(), b"rss-live-minio".to_vec())
        .await?;
    let payload = store
        .get_object(key.clone())
        .await?
        .ok_or("live object missing after put")?;
    let bytes = payload.collect_limited(1024).await?;
    assert_eq!(bytes, b"rss-live-minio");
    store.delete_object(key.clone()).await?;
    assert!(store.get_object(key).await?.is_none());
    Ok(())
}
