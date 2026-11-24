use super::*;
use crate::{
    engine::{self, Command, QueuedCommand, Shared},
    record::Record,
};
use anyhow::Context;
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
        KafkaLimits::new(
            1,
            1,
            4096,
            1_048_576,
            crate::KafkaTimeouts::low_latency(Duration::from_millis(100))?,
        )?,
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
    c.plan.limits = KafkaLimits::new(
        1,
        1,
        20,
        1_048_576,
        crate::KafkaTimeouts::low_latency(Duration::from_secs(1))?,
    )?;
    assert!(Record::encode(&m, &c.plan).is_none());
    c = config()?;
    let header_heavy = MessageEnvelope::new(m.id().clone(), m.metadata().clone(), Vec::new())
        .with_transport_context(TransportContext::new(Some("x".repeat(4096)), None));
    assert!(Record::encode(&header_heavy, &c.plan).is_none());
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
    let native = c.client().create_native_config()?;
    assert_eq!(native.get("client.id")?, "rss-fixture-publisher");
    for (key, value) in [
        ("acks", "-1"),
        ("enable.idempotence", "true"),
        ("max.in.flight.requests.per.connection", "5"),
        ("enable.ssl.certificate.verification", "true"),
        ("ssl.endpoint.identification.algorithm", "https"),
        ("security.protocol", "sasl_ssl"),
    ] {
        assert_eq!(native.get(key)?, value);
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
    mpsc::Receiver<QueuedCommand>,
)> {
    let (shared, receiver) = Shared::channel(1);
    let shared = Arc::new(shared);
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
    let command = receiver.try_recv()?.dequeue();
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
fn definite_refusal(
    result: Result<tokio::sync::oneshot::Receiver<engine::Outcome>, engine::Outcome>,
) -> anyhow::Result<PublishFailure> {
    match result {
        Err(PublishOutcome::DefinitelyNotPublished(failure)) => Ok(failure),
        _ => anyhow::bail!("expected a definite pre-enqueue refusal"),
    }
}
#[test]
fn parallel_reservations_do_not_delay_sealing_or_hold_a_sender() -> anyhow::Result<()> {
    let (shared, receiver) = Shared::channel(2);
    let plan = config()?.into_parts().0;
    let m = message()?;
    let end = engine::now() + Duration::from_secs(5);
    std::thread::scope(|scope| -> anyhow::Result<()> {
        let (entered, encoding) = mpsc::channel();
        let mut releases = Vec::new();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let (release, wait) = mpsc::channel();
            releases.push(release);
            let entered = entered.clone();
            let (shared, m, plan) = (&shared, &m, &plan);
            workers.push(scope.spawn(move || {
                shared.enqueue(end, || {
                    entered.send(()).ok()?;
                    wait.recv_timeout(Duration::from_secs(5)).ok()?;
                    Record::encode(m, plan)
                })
            }));
        }
        for _ in 0..2 {
            encoding.recv_timeout(Duration::from_secs(5))?;
        }
        let mut encode_calls = 0;
        let refused = definite_refusal(shared.enqueue(end, || {
            encode_calls += 1;
            Record::encode(&m, &plan)
        }))?;
        assert_eq!(Some(refused), engine::unavailable().failure());
        assert_eq!(encode_calls, 0);
        shared.close(end);
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        for release in releases {
            release.send(())?;
        }
        for worker in workers {
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!("encoder thread panicked"))?;
            assert_eq!(
                Some(definite_refusal(result)?),
                engine::unavailable().failure()
            );
        }
        // Both slots have returned. Only the closed semaphore can skip this encoder now.
        let fresh_deadline = engine::now() + Duration::from_secs(5);
        let refused = definite_refusal(shared.enqueue(fresh_deadline, || {
            encode_calls += 1;
            Record::encode(&m, &plan)
        }))?;
        assert_eq!(Some(refused), engine::unavailable().failure());
        assert_eq!(encode_calls, 0);
        Ok(())
    })
}

#[test]
fn abandoned_expired_and_dequeued_records_return_capacity() -> anyhow::Result<()> {
    let (shared, queue) = Shared::channel(1);
    let plan = config()?.into_parts().0;
    let m = message()?;
    let end = engine::now() + Duration::from_secs(5);
    assert_eq!(
        definite_refusal(shared.enqueue(end, || None))?.stage(),
        PublishFailureStage::Encode
    );
    let cutoff = engine::now() + Duration::from_millis(100);
    let mut encoded = false;
    let expired = definite_refusal(shared.enqueue(cutoff, || {
        let record = Record::encode(&m, &plan);
        encoded = true;
        std::thread::sleep(cutoff.saturating_duration_since(engine::now()));
        record
    }))?;
    assert!(encoded);
    assert_eq!(Some(expired), engine::expired().failure());
    assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
    let reply = shared
        .enqueue(end, || Record::encode(&m, &plan))
        .ok()
        .context("expected capacity after expiry")?;
    drop(reply);
    let mut encode_calls = 0;
    for _ in 0..128 {
        // Even a cancelled caller's queued record still owns one slot.
        let refused = definite_refusal(shared.enqueue(end, || {
            encode_calls += 1;
            Record::encode(&m, &plan)
        }))?;
        assert_eq!(Some(refused), engine::unavailable().failure());
    }
    assert_eq!(encode_calls, 0);
    let command = queue.try_recv()?.dequeue();
    assert!(command.reply.is_closed());
    assert!(shared.enqueue(end, || Record::encode(&m, &plan)).is_ok());
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
    let (shared, receiver) = Shared::channel(1);
    let shared = Arc::new(shared);
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

#[test]
fn finite_limits_replace_policy_ceilings_and_check_aggregate_budget() -> anyhow::Result<()> {
    let timeouts = KafkaTimeouts::low_latency(Duration::from_secs(1))?;
    for (queued, in_flight, record, budget) in [
        (100_001, 1, 1024, 1_000_000_000),
        (1, 100_001, 1024, 1_000_000_000),
        (1, 1, 100_000_001, 1_000_000_000),
        (1, 21, 100_000_000, 3_000_000_000),
    ] {
        let mut c = config()?;
        c.plan.limits = KafkaLimits::new(queued, in_flight, record, budget, timeouts)?;
        // Conf setters validate without allocating queue slots, payloads or a producer.
        let native = c.client().create_native_config()?;
        assert_eq!(
            native.get("queue.buffering.max.messages")?,
            in_flight.to_string()
        );
        assert_eq!(
            native.get("queue.buffering.max.kbytes")?,
            (in_flight * record).div_ceil(1024).to_string()
        );
        assert_eq!(
            native.get("message.max.bytes")?,
            (record + 36).max(1000).to_string()
        );
    }
    for (queued, in_flight, record, budget) in [
        (0, 1, 1024, usize::MAX),
        (1, 0, 1024, usize::MAX),
        (1, 1, 0, usize::MAX),
        (1, 1, 1024, 0),
        (usize::MAX, 1, 1024, usize::MAX),
        (1, i32::MAX as usize + 1, 1024, usize::MAX),
        (1, 1, usize::MAX, usize::MAX),
        (1, 1, 1_000_000_000 - 35, usize::MAX),
        (1, 3_000_000, 999_999_000, usize::MAX),
    ] {
        assert!(matches!(
            KafkaLimits::new(queued, in_flight, record, budget, timeouts),
            Err(KafkaError::InvalidLimits)
        ));
    }
    let channel_slot = std::mem::size_of::<(std::sync::atomic::AtomicUsize, QueuedCommand)>();
    let largest_channel = isize::MAX as usize / channel_slot;
    // Only validate the layouts; allocating even the representable neighbour is unnecessary.
    assert!(KafkaLimits::new(largest_channel, 1, 1, usize::MAX, timeouts).is_ok());
    assert!(matches!(
        KafkaLimits::new(largest_channel + 1, 1, 1, usize::MAX, timeouts),
        Err(KafkaError::InvalidLimits)
    ));
    for (queued, record) in [(1, 1023usize), (2, 1024), (64, 1025)] {
        let rounded_native = record.div_ceil(1024) * 1024;
        let required = (2 * queued + 1) * record
            + rounded_native
            + queued * (channel_slot + std::mem::size_of::<QueuedCommand>())
            + std::mem::size_of::<Command>()
            + engine::pending_entry_bytes();
        assert!(KafkaLimits::new(queued, 1, record, required, timeouts).is_ok());
        assert!(KafkaLimits::new(queued, 1, record, required - 1, timeouts).is_err());
        let mut c = config()?;
        c.plan.limits = KafkaLimits::new(queued, 1, record, required, timeouts)?;
        assert_eq!(
            c.client()
                .create_native_config()?
                .get("queue.buffering.max.kbytes")?,
            record.div_ceil(1024).to_string()
        );
    }
    Ok(())
}

#[test]
fn transport_timeouts_preserve_native_units_ranges_and_independence() -> anyhow::Result<()> {
    let ms = Duration::from_millis;
    for (socket, request, linger, delivery) in [
        (ms(9), ms(1), Duration::ZERO, ms(1)),
        (ms(300_001), ms(1), Duration::ZERO, ms(1)),
        (ms(10), Duration::ZERO, Duration::ZERO, ms(1)),
        (ms(10), ms(900_001), Duration::ZERO, ms(1)),
        (ms(10), ms(1), Duration::ZERO, Duration::ZERO),
        (ms(10), ms(1), Duration::ZERO, ms(i32::MAX as u64 + 1)),
        (ms(10), ms(1), ms(1), ms(1)),
        (ms(10), ms(1), ms(2), ms(1)),
        (
            ms(10),
            ms(1),
            Duration::from_micros(900_000_001),
            ms(900_001),
        ),
        (ms(10), ms(1), Duration::from_nanos(1), ms(1)),
        (Duration::from_micros(10_001), ms(1), Duration::ZERO, ms(1)),
        (ms(10), Duration::from_micros(1001), Duration::ZERO, ms(1)),
        (ms(10), ms(1), Duration::ZERO, Duration::from_micros(1001)),
    ] {
        assert!(matches!(
            KafkaTimeouts::new(socket, request, linger, delivery),
            Err(KafkaError::InvalidTimeouts)
        ));
    }
    // Deliberately request > delivery: librdkafka does not enforce Java's summed relation.
    let mut c = config()?;
    c.plan.limits = KafkaLimits::new(
        1,
        1,
        1024,
        1_048_576,
        KafkaTimeouts::new(ms(300_000), ms(900_000), Duration::ZERO, ms(1))?,
    )?;
    let native = c.client().create_native_config()?;
    assert_eq!(native.get("socket.timeout.ms")?, "300000");
    assert_eq!(native.get("request.timeout.ms")?, "900000");
    assert_eq!(native.get("message.timeout.ms")?, "1");
    for micros in [0, 1, 1001, 999_999, 900_000_000] {
        let timeouts = KafkaTimeouts::new(
            ms(15_000),
            ms(20_000),
            Duration::from_micros(micros),
            ms(i32::MAX as u64),
        )?;
        let mut c = config()?;
        c.plan.limits = KafkaLimits::new(1, 1, 1024, 1_048_576, timeouts)?;
        let client = c.client();
        let encoded = client
            .get("linger.ms")
            .ok_or_else(|| anyhow::anyhow!("linger mapping"))?
            .parse::<f64>()?;
        // Mirrors the pinned native double-ms -> integer-us conversion, including 1001us rounding.
        assert_eq!((encoded * 1000.0) as u64, micros);
        let native = client.create_native_config()?;
        assert_eq!(native.get("socket.timeout.ms")?, "15000");
        assert_eq!(native.get("request.timeout.ms")?, "20000");
        assert_eq!(native.get("message.timeout.ms")?, i32::MAX.to_string());
        assert!((native.get("linger.ms")?.parse::<f64>()? * 1000.0 - micros as f64).abs() < 0.01);
    }
    Ok(())
}
