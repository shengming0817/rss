use super::*;
use crate::{
    engine::{self, Command, Shared},
    record::Record,
};
use rdkafka::message::Headers;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_request_context::{Clock, Deadline};
use rss_transactional_messaging::{message::*, policy::*, transport::*};
use std::{
    collections::BTreeMap,
    sync::{Arc, mpsc},
    time::Duration,
};

fn config() -> anyhow::Result<KafkaConfig> {
    Ok(KafkaConfig::new(
        KafkaClientId::parse("rss-fixture-publisher")?,
        "127.0.0.1:1".into(),
        "invalid-pem".into(),
        KafkaCredentials::scram_sha512("fixture".into(), "SECRET_BAIT".into())?,
        MessagingDomain::parse("events")?,
        [(MessageRoute::parse("event:v1")?, "events-v1".into())],
        KafkaLimits::new(1, 1, 4096, Duration::from_millis(100))?,
    )?)
}
fn message() -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    Ok(MessageEnvelope::new(
        MessageId::parse("original-id")?,
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
                Some(rss_diag_context::CorrelationId::parse("correlation-id")?),
                Some(PartitionKey::parse("tenant:key")?),
                Some(MessageId::parse("cause-id")?),
                BTreeMap::from([("messageId".into(), "must-not-shadow".into())]),
            ),
        ),
        vec![0, 255, 128],
    )
    .with_transport_context(TransportContext::new(
        Some("trace-value".into()),
        Some("authority-value".into()),
    )))
}
#[test]
fn projection_preserves_authored_bytes_and_reserved_headers() -> anyhow::Result<()> {
    let c = config()?;
    let m = message()?;
    let r = Record::encode(&m, &c.plan).ok_or_else(|| anyhow::anyhow!("encode"))?;
    assert_eq!(r.payload, m.payload().as_slice());
    assert_eq!(r.key.as_deref(), Some("tenant:key"));
    assert_eq!(r.topic, "events-v1");
    let pairs: BTreeMap<_, _> = (0..r.headers.count())
        .map(|i| {
            let h = r.headers.get(i);
            (h.key.to_owned(), h.value.unwrap_or_default().to_vec())
        })
        .collect();
    let expected: BTreeMap<String, Vec<u8>> = [
        ("messageId", "original-id".to_owned()),
        (
            "tenantId",
            "00000000-0000-0000-0000-000000000001".to_owned(),
        ),
        ("domain", "events".to_owned()),
        ("route", "event:v1".to_owned()),
        ("contractId", "events.changed".to_owned()),
        ("schemaVersion", "v1".to_owned()),
        ("schemaHash", format!("sha256:{}", "a".repeat(64))),
        ("occurredAt", "1700000000".to_owned()),
        ("partitionKey", "tenant:key".to_owned()),
        ("correlation", "correlation-id".to_owned()),
        ("causationId", "cause-id".to_owned()),
        ("trace", "trace-value".to_owned()),
        ("tenantAuthority", "authority-value".to_owned()),
        ("attribute.messageId", "must-not-shadow".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.into_bytes()))
    .collect();
    assert_eq!(pairs, expected);
    Ok(())
}
#[test]
fn record_limits_include_metadata_and_route_validation() -> anyhow::Result<()> {
    let mut c = config()?;
    let m = message()?;
    c.plan.limits = KafkaLimits::new(1, 1, 20, Duration::from_secs(1))?;
    assert!(Record::encode(&m, &c.plan).is_none());
    c = config()?;
    c.plan.domain = MessagingDomain::parse("other")?;
    assert!(Record::encode(&m, &c.plan).is_none());
    for topic in ["", ".", "..", "bad:topic", "bad/topic"] {
        assert!(
            KafkaConfig::new(
                KafkaClientId::parse("rss-fixture-publisher")?,
                "broker".into(),
                "pem".into(),
                KafkaCredentials::scram_sha512("u".into(), "p".into())?,
                MessagingDomain::parse("events")?,
                [(MessageRoute::parse("route")?, topic.into())],
                c.plan.limits
            )
            .is_err()
        );
    }
    Ok(())
}
#[test]
fn reliable_configuration_cannot_be_overridden_and_debug_is_safe() -> anyhow::Result<()> {
    let c = config()?;
    let native = c.client();
    assert_eq!(native.get("client.id"), Some("rss-fixture-publisher"));
    for (key, value) in [
        ("acks", "all"),
        ("enable.idempotence", "true"),
        ("max.in.flight.requests.per.connection", "5"),
        ("enable.ssl.certificate.verification", "true"),
        ("ssl.endpoint.identification.algorithm", "https"),
        ("security.protocol", "sasl_ssl"),
    ] {
        assert_eq!(native.get(key), Some(value));
    }
    assert!(!format!("{c:?}").contains("SECRET_BAIT"));
    assert!(
        !format!(
            "{:?}",
            KafkaCredentials::scram_sha512("u".into(), "SECRET_BAIT".into())?
        )
        .contains("SECRET_BAIT")
    );
    Ok(())
}
struct Timer;
impl Clock for Timer {
    fn now(&self) -> std::time::Instant {
        {
            #[allow(
                clippy::disallowed_methods,
                reason = "the fixed injected test clock owns its epoch"
            )]
            fn epoch() -> std::time::Instant {
                std::time::Instant::now()
            }
            static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            *ORIGIN.get_or_init(epoch)
        }
    }
}
fn deadline(duration: Duration) -> anyhow::Result<OperationDeadline> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&Timer, duration)?,
        &Timer,
    ))
}
fn isolated() -> anyhow::Result<(
    KafkaPublisher,
    KafkaPublisherResource,
    mpsc::Receiver<Command>,
)> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let shared = Arc::new(Shared::new(sender));
    Ok((
        publisher::KafkaPublisher::for_unit_test(
            shared.clone(),
            Arc::new(config()?.into_parts().0),
        ),
        publisher::KafkaPublisherResource::for_unit_test(shared),
        receiver,
    ))
}
#[tokio::test]
async fn enqueue_is_not_confirmation_and_cancellation_keeps_owned_command() -> anyhow::Result<()> {
    let (p, owner, receiver) = isolated()?;
    let m = message()?;
    let outcome = p.publish(&m, deadline(Duration::from_millis(10))?).await;
    assert!(matches!(outcome, PublishOutcome::Ambiguous(_)));
    let command = receiver.try_recv()?;
    assert!(command.reply.is_closed());
    assert_eq!(command.record.payload, m.payload().as_slice());
    drop(owner);
    Ok(())
}
#[tokio::test]
async fn full_queue_and_closed_owner_are_definite_and_shutdown_seals_unpolled() -> anyhow::Result<()>
{
    let (p, owner, _receiver) = isolated()?;
    let m = message()?;
    assert!(
        p.publish(&m, deadline(Duration::from_millis(1))?)
            .await
            .is_ambiguous()
    );
    assert!(matches!(
        p.publish(&m, deadline(Duration::from_secs(1))?).await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    let closing = owner.shutdown(Duration::from_secs(1));
    assert!(matches!(
        p.publish(&m, deadline(Duration::from_secs(1))?).await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    drop(closing);
    Ok(())
}
#[tokio::test]
async fn invalid_native_initialization_has_safe_error() -> anyhow::Result<()> {
    let result = KafkaPublisher::create(config()?, Duration::from_secs(2)).await;
    assert_eq!(result.err(), Some(KafkaError::Initialization));
    Ok(())
}
#[test]
fn pending_senders_are_reclaimed_without_any_delivery_report() {
    engine::assert_cleanup_for_unit_test();
}

#[tokio::test]
async fn invalid_lifecycle_budget_is_not_a_record_limit_error() -> anyhow::Result<()> {
    assert_eq!(
        KafkaPublisher::create(config()?, Duration::ZERO)
            .await
            .err(),
        Some(KafkaError::InvalidLifecycleTimeout)
    );
    let (_, resource, _) = isolated()?;
    assert_eq!(
        resource.shutdown(Duration::MAX).await,
        Err(KafkaError::InvalidLifecycleTimeout)
    );
    Ok(())
}

#[test]
fn host_runtime_does_not_wait_for_detached_owner_completion() -> anyhow::Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let shared = Arc::new(Shared::new(sender));
    let (done, completion) = tokio::sync::oneshot::channel();
    let host = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    host.block_on(async {
        let resource =
            publisher::KafkaPublisherResource::with_completion_for_unit_test(shared, completion);
        assert_eq!(
            resource.shutdown(Duration::from_millis(10)).await,
            Err(KafkaError::DeadlineElapsed)
        );
    });
    // The owner is deliberately still alive. Dropping the host must not wait for its completion.
    drop(host);
    drop(done);
    drop(receiver);
    Ok(())
}

#[test]
fn absent_extensions_do_not_create_keys_or_headers() -> anyhow::Result<()> {
    let template = message()?;
    let m = template.metadata();
    let bare = MessageEnvelope::new(
        template.id().clone(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                m.tenant_id(),
                m.occurred_at(),
                m.domain().clone(),
                m.route().clone(),
                m.contract().clone(),
            ),
            MessageMetadataExtensions::default(),
        ),
        Vec::new(),
    );
    let config = config()?;
    let record =
        Record::encode(&bare, &config.plan).ok_or_else(|| anyhow::anyhow!("bare encode"))?;
    assert!(record.key.is_none());
    assert!(record.payload.is_empty());
    let actual: std::collections::BTreeSet<_> =
        record.headers.iter().map(|header| header.key).collect();
    assert_eq!(
        actual,
        [
            "messageId",
            "tenantId",
            "domain",
            "route",
            "contractId",
            "schemaVersion",
            "schemaHash",
            "occurredAt"
        ]
        .into_iter()
        .collect()
    );
    Ok(())
}
