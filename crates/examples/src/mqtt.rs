//! Real broker publication with caller-owned durable handoff and explicit TLS/session inputs.
use rss_mqtt::{MqttConfig, MqttOutboxPlan, MqttOutboxPublisher, MqttOutboxTopic};
use rss_request_context::{Clock, Deadline, TenantId};
use rss_transactional_messaging::{
    message::{MessageRoute, MessagingDomain},
    policy::OperationDeadline,
    transport::{PublishOutcome, Publisher},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{sync::Arc, time::Duration};
#[path = "mqtt/logging.rs"]
mod logging;
#[path = "mqtt/store.rs"]
mod store;
#[derive(serde::Deserialize)]
pub struct Input {
    pub port: u16,
    pub ca: String,
    pub certificate: String,
    pub key: String,
    pub directory: std::path::PathBuf,
    pub id: String,
}
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: explicit example host clock.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
fn deadline() -> anyhow::Result<OperationDeadline> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&Timer, Duration::from_secs(10))?,
        &Timer,
    ))
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(logging::filter())
        .try_init()
        .map_err(|_| anyhow::anyhow!("example logger initialization failed"))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(input.ca.as_bytes()) {
        roots.add(cert?)?;
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_client_auth_cert(
        CertificateDer::pem_slice_iter(input.certificate.as_bytes())
            .collect::<Result<Vec<_>, _>>()?,
        PrivateKeyDer::from_pem_slice(input.key.as_bytes())?,
    )?;
    let topic = format!("example/{}", input.id);
    let config = MqttConfig::new(
        "localhost",
        input.port,
        &input.id,
        "artifact-example",
        Arc::new(tls),
        rss_mqtt::Limits::new(8, 8, 8, 65536)?,
    )?
    .credentials("mqtt", b"fixture-only".to_vec())?
    .subscriptions(vec![topic.clone()])?;
    let (publisher, mut receiver, resource) = rss_mqtt::connect(
        config,
        Arc::new(Timer),
        Arc::new(store::FileStore::new(input.directory.join("session"))?),
    )?;
    publisher.wait_ready(Duration::from_secs(10)).await?;
    let plan = MqttOutboxPlan::new(
        MessagingDomain::parse("writer-example")?,
        [(
            MessageRoute::parse("created")?,
            MqttOutboxTopic::new(topic)?,
        )],
    )?;
    let outbox = MqttOutboxPublisher::new(publisher, plan);
    let pending = crate::sample_message::message(
        TenantId::parse("00000000-0000-0000-0000-000000000001")?,
        &input.id,
    )?;
    let message = pending.envelope();
    anyhow::ensure!(
        matches!(
            outbox.publish(message, deadline()?).await,
            PublishOutcome::Confirmed(())
        ),
        "MQTT publication was not confirmed"
    );
    let delivery = tokio::time::timeout(Duration::from_secs(10), receiver.next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("MQTT delivery missing"))?;
    anyhow::ensure!(
        delivery.payload() == message.payload(),
        "MQTT payload mismatch"
    );
    // The example's explicit durable handoff is a file, not a claim about a product database.
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(input.directory.join("handoff")).await?;
    file.write_all(delivery.payload()).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::File::open(&input.directory)
        .await?
        .sync_all()
        .await?;
    delivery
        .into_parts()
        .1
        .ack_after_durable_handoff(deadline()?)
        .await?;
    resource.shutdown(Duration::from_secs(10)).await?;
    Ok(())
}
