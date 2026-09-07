use rdkafka::{
    ClientConfig, ClientContext, Message,
    consumer::{BaseConsumer, Consumer},
    message::{Headers, OwnedMessage},
    topic_partition_list::{Offset, TopicPartitionList},
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::{message::*, policy::*};
use rss_transactional_messaging_kafka::*;
use std::{collections::BTreeMap, time::Duration};
pub struct Timer;
impl Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: injected test clock owns its real monotonic source.
    pub fn new() -> Self {
        Self
    }
}
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete injected clock reads its monotonic source.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, end: Deadline) {
        tokio::task::unconstrained(async move {
            tokio::time::sleep(end.remaining(self.now()).unwrap_or_default()).await;
        })
        .await;
    }
}
pub fn deadline(duration: Duration) -> anyhow::Result<OperationDeadline> {
    let clock = Timer::new();
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&clock, duration)?,
        &clock,
    ))
}
pub fn message(id: &str) -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    Ok(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                TenantId::parse("00000000-0000-0000-0000-000000000001")?,
                Timepoint::try_from(1_700_000_000)?,
                MessagingDomain::parse("events")?,
                MessageRoute::parse("event:v1")?,
                ContractIdentity::new(
                    ContractId::parse("events.changed")?,
                    ContractVersion::parse("v1")?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::new(
                None,
                Some(PartitionKey::parse("tenant:key")?),
                None,
                BTreeMap::from([("messageId".into(), "authored-value".into())]),
            ),
        ),
        vec![0, 255, 128],
    ))
}
pub fn config(f: &testkit::KafkaTlsFixture) -> anyhow::Result<KafkaConfig> {
    Ok(KafkaConfig::new(
        KafkaClientId::parse(f.topic())?,
        f.brokers().into(),
        f.ca_pem().into(),
        KafkaCredentials::mutual_tls(f.client_certificate_pem().into(), f.client_key_pem().into())?,
        MessagingDomain::parse("events")?,
        [(MessageRoute::parse("event:v1")?, f.topic().into())],
        KafkaLimits::new(1, 1, 4096, Duration::from_secs(2))?,
    )?)
}
struct Quiet;
impl rdkafka::consumer::ConsumerContext for Quiet {}
impl ClientContext for Quiet {
    fn log(&self, _: rdkafka::config::RDKafkaLogLevel, _: &str, _: &str) { /* reason: fixture credentials must never enter native logs. */
    }
    fn error(&self, _: rdkafka::error::KafkaError, _: &str) { /* reason: poll returns test failures without forwarding native text. */
    }
}
pub async fn read_records(
    f: &testkit::KafkaTlsFixture,
    id: &str,
    count: usize,
) -> anyhow::Result<Vec<OwnedMessage>> {
    let mut c = ClientConfig::new();
    c.set("bootstrap.servers", f.brokers())
        // Fixture ports are allocated via Docker IPv4, while DNS is retained for SAN verification.
        .set("broker.address.family", "v4")
        .set("group.id", f.topic())
        .set("enable.auto.commit", "false")
        .set("security.protocol", "ssl")
        .set("ssl.ca.pem", f.ca_pem())
        .set("ssl.certificate.pem", f.client_certificate_pem())
        .set("ssl.key.pem", f.client_key_pem());
    let topic = f.topic().to_owned();
    let id = id.to_owned();
    tokio::task::spawn_blocking(move || {
        let consumer: BaseConsumer<Quiet> = c.create_with_context(Quiet)?;
        let mut assignments = TopicPartitionList::new();
        assignments.add_partition_offset(&topic, 0, Offset::Beginning)?;
        consumer.assign(&assignments)?;
        let timer = Timer::new();
        let mut records = Vec::new();
        let end = Deadline::from_timeout(&timer, Duration::from_secs(8))?;
        while !end.remaining(timer.now()).unwrap_or_default().is_zero() {
            if let Some(record) = consumer.poll(Duration::from_millis(100)) {
                let record = record?;
                if record.headers().is_some_and(|hs| {
                    hs.iter()
                        .any(|h| h.key == "messageId" && h.value == Some(id.as_bytes()))
                }) {
                    if count == 0 {
                        anyhow::bail!("a refused record was observed at the broker");
                    }
                    records.push(record.detach());
                    if records.len() == count {
                        return Ok(records);
                    }
                }
            }
        }
        if count == 0 {
            return Ok(records);
        }
        anyhow::bail!(
            "broker did not expose the expected record count: {} of {count}",
            records.len()
        )
    })
    .await?
}
pub async fn drained(p: &KafkaPublisher) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while p.pending_for_test() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
pub fn assert_record(record: &OwnedMessage, id: &str) {
    assert_eq!(record.payload(), Some([0u8, 255, 128].as_slice()));
    assert_eq!(record.key(), Some(b"tenant:key".as_slice()));
    let headers: BTreeMap<_, _> = record
        .headers()
        .into_iter()
        .flat_map(Headers::iter)
        .map(|h| (h.key, h.value))
        .collect();
    assert_eq!(headers.get("messageId"), Some(&Some(id.as_bytes())));
    assert_eq!(
        headers.get("attribute.messageId"),
        Some(&Some(b"authored-value".as_slice()))
    );
    assert_eq!(headers.get("schemaVersion"), Some(&Some(b"v1".as_slice())));
    assert_eq!(
        headers.get("occurredAt"),
        Some(&Some(b"1700000000".as_slice()))
    );
}
