#![allow(clippy::new_ret_no_self)]

//! amqp adapter 集成测试——publish→subscribe 闭环 / 同-vhost topic 隔离 / 跨-vhost 隔离 / 凭据不进错误面 /
//! broker-confirmed 取消终止流 / **at-least-once**（manual-ack ack/requeue/崩溃重投）。
//!
//! 独立 `amqp-integration` package 直接启用 adapter integration feature，并由 Cargo 反向依赖图选择。
//! broker 经 `testkit::env_or_rabbitmq()` self-provision（testcontainers，#1137）——无需手工预置、不再 `#[ignore]`；
//! 设 `RSS_AMQP_TEST_URL` 则对接长存外部 broker（其 vhost 须预建）。需 docker（容器路径）。
//! 连不上即失败（fail-loud）。测试名 `integration_` 前缀 → nextest 串行 group（`test(/integration/)`）。
//! 本地：`cargo nextest run -p amqp --features integration`（docker 在场自起容器）。
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use amqp::{
    AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint, AmqpRuntimeDeps, AmqpSubscriber,
    AmqpSubscriberEndpoint,
};
use anyhow::anyhow;
use diport::{
    AckAction, AckableSubscriber, Acker, EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT,
    KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_SUBJECT_ID, KEY_TENANT_ID, ManagedResource, MessageId,
    PublishRequest as DiPublishRequest, Publisher, Topic,
};
use eventing::delivery::PublishErrorKind;
use futures::StreamExt;
use testkit::FixtureError;
use tokio_util::sync::CancellationToken;

const TEST_PUBLISH_TIMEOUT: Duration = Duration::from_secs(40);
const NEUTRAL_TOPIC: &str = "rss.event.v1";
const TEST_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TEST_SCHEMA_HASH: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Test-only constructor that keeps broker-behavior fixtures on a valid typed envelope.
struct PublishRequest;

struct NoopEventingEmitter;

impl eventing::observability::EventingEmitter for NoopEventingEmitter {
    fn emit(&self, _observation: eventing::observability::EventingObservation) {}
}

impl PublishRequest {
    fn new(topic: Topic, event_id: MessageId, payload: Vec<u8>) -> DiPublishRequest {
        let mut metadata = EnvelopeMetadata::empty();
        metadata.insert_wire_pair(KEY_TENANT_ID, TEST_TENANT);
        metadata.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        metadata.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        metadata.insert_wire_pair(KEY_SCHEMA_HASH, TEST_SCHEMA_HASH);
        DiPublishRequest::new(topic, event_id, payload).with_metadata(metadata)
    }
}

struct ForcedCancelInbox {
    claims: AtomicU32,
    commits: AtomicU32,
    releases: AtomicU32,
}

impl consistency::InboxStore for ForcedCancelInbox {
    async fn try_claim(
        &self,
        _ctx: &consistency::InboxReceiptContext,
        _key: &consistency::IdemKey,
        _lease: &consistency::LeaseToken,
    ) -> Result<consistency::SeenState, consistency::EngineError> {
        self.claims.fetch_add(1, Ordering::AcqRel);
        Ok(consistency::SeenState::Fresh)
    }

    async fn extend(
        &self,
        _ctx: &consistency::InboxReceiptContext,
        _key: &consistency::IdemKey,
        _lease: &consistency::LeaseToken,
    ) -> Result<consistency::LeaseOutcome, consistency::EngineError> {
        Ok(consistency::LeaseOutcome::Held)
    }

    async fn commit(
        &self,
        _ctx: &consistency::InboxReceiptContext,
        _key: &consistency::IdemKey,
        _lease: &consistency::LeaseToken,
    ) -> Result<consistency::LeaseOutcome, consistency::EngineError> {
        self.commits.fetch_add(1, Ordering::AcqRel);
        Ok(consistency::LeaseOutcome::Held)
    }

    async fn release(
        &self,
        _ctx: &consistency::InboxReceiptContext,
        _key: &consistency::IdemKey,
        _lease: &consistency::LeaseToken,
    ) -> Result<(), consistency::EngineError> {
        self.releases.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

struct NoopDeadLetter;

impl diport::DeadLetterStore for NoopDeadLetter {
    async fn write_dead_letter(
        &self,
        _record: diport::DeadLetterRecord,
    ) -> Result<(), diport::DeadLetterStoreError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::DeadLetterStoreError> {
        Ok(())
    }
}

struct TestMac;

impl primitives::MacVerifier for TestMac {
    fn sign(
        &self,
        _key: &primitives::MacKey,
        _algorithm: primitives::MacAlgorithm,
        _message: &[u8],
    ) -> primitives::Mac {
        primitives::Mac::from_bytes(vec![0x5a; 32])
    }

    fn verify(
        &self,
        key: &primitives::MacKey,
        algorithm: primitives::MacAlgorithm,
        message: &[u8],
        tag: &primitives::Mac,
    ) -> bool {
        primitives::constant_time_eq(
            self.sign(key, algorithm, message).as_bytes(),
            tag.as_bytes(),
        )
    }
}

fn forced_cancel_consumer_contract(
    topic: &Topic,
    message_id: &str,
) -> anyhow::Result<(eventexec::ConsumerMeta, EnvelopeMetadata)> {
    let authority = Arc::new(eventexec::TenantAuthority::new(
        Arc::new(TestMac),
        primitives::MacKey::from_bytes(vec![0x42; 32]),
        3_600,
        60,
        Arc::new(|| 1_000),
    )?);
    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let tenant = rss_request_context::TenantId::parse(TENANT)?;
    let token = authority.sign(eventexec::TenantAuthorityBinding::new(
        tenant,
        "amqp",
        "amqp-forced-cancel",
        topic.as_str(),
        message_id,
    ))?;
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(diport::KEY_TENANT_ID, TENANT);
    metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
    metadata.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
    metadata.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
    metadata.insert_wire_pair(
        KEY_SCHEMA_HASH,
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    Ok((
        eventexec::ConsumerMeta::new(
            "amqp",
            "amqp",
            "amqp-forced-cancel",
            topic.as_str(),
            "amqp-forced-cancel-group",
            authority,
            Arc::new(NoopEventingEmitter),
        ),
        metadata,
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_explicit_private_ca_accepts_matching_broker_and_rejects_wrong_ca()
-> anyhow::Result<()> {
    let network = testkit::bridge_network("rss-amqp-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::rabbitmq_tls(
        NEUTRAL_TOPIC,
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: &dns_name,
        },
    )
    .await?;
    let publisher_endpoint = AmqpPublisherEndpoint::new(secure::AmqpEndpoint::parse(
        fixture.publisher_url(),
        secure::PlaintextEndpointPolicy::Deny,
    )?);
    let subscriber_endpoint = AmqpSubscriberEndpoint::new(secure::AmqpEndpoint::parse(
        fixture.subscriber_url(),
        secure::PlaintextEndpointPolicy::Deny,
    )?);
    let good_ca = AmqpPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?;
    let deps = AmqpRuntimeDeps::connect_with_private_ca(
        &publisher_endpoint,
        &subscriber_endpoint,
        good_ca,
        "amqp-private-ca-it",
        TEST_PUBLISH_TIMEOUT,
    )
    .await?;
    assert_eq!(deps.runtime_resources().len(), 2);

    assert!(
        AmqpRuntimeDeps::connect_with_webpki_for_test(
            &secure::AmqpEndpoint::parse(
                fixture.publisher_url(),
                secure::PlaintextEndpointPolicy::Deny,
            )?,
            "amqp-default-roots-private-ca-it",
            TEST_PUBLISH_TIMEOUT,
        )
        .await
        .is_err(),
        "the default WebPKI roots must not authenticate the private-CA broker"
    );

    let publisher = deps.publisher_for_integration_test();
    publisher.inject_post_send_connection_close_once();
    let error = publisher
        .publish(PublishRequest::new(
            Topic::new(NEUTRAL_TOPIC),
            MessageId::new("evt-private-ca-recovery-1"),
            b"force-private-ca-recovery".to_vec(),
        ))
        .await
        .err()
        .ok_or_else(|| anyhow!("forced post-send connection close must be ambiguous"))?;
    assert!(error.is_ambiguous());
    assert!(
        publisher.wait_until_publish_ready_for_test().await,
        "replacement generation must reconnect with the same exclusive private CA"
    );

    let wrong_ca = AmqpPrivateCa::from_pem(fixture.wrong_ca_pem().as_bytes().to_vec())?;
    assert!(
        AmqpRuntimeDeps::connect_with_private_ca(
            &publisher_endpoint,
            &subscriber_endpoint,
            wrong_ca,
            "amqp-wrong-private-ca-it",
            TEST_PUBLISH_TIMEOUT,
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_tls_identities_enforce_publish_subscribe_acl() -> anyhow::Result<()> {
    let network = testkit::bridge_network("rss-amqp-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::rabbitmq_tls(
        NEUTRAL_TOPIC,
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: &dns_name,
        },
    )
    .await?;
    let ca = AmqpPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?;
    let topic = Topic::new(NEUTRAL_TOPIC);
    let token = CancellationToken::new();

    assert!(
        fixture.publisher_permissions_are_exact().await?,
        "publisher broker permissions must allow only the generated key on the topic exchange"
    );
    assert!(
        fixture.subscriber_permissions_are_exact().await?,
        "subscriber permissions must declare source/DLQ but read only the generated source queue"
    );

    let publisher_raw = secure::AmqpEndpoint::parse(
        fixture.publisher_url(),
        secure::PlaintextEndpointPolicy::Deny,
    )?;
    let subscriber_raw = secure::AmqpEndpoint::parse(
        fixture.subscriber_url(),
        secure::PlaintextEndpointPolicy::Deny,
    )?;
    let publisher_endpoint = AmqpPublisherEndpoint::new(publisher_raw.clone());
    let subscriber_endpoint = AmqpSubscriberEndpoint::new(subscriber_raw.clone());
    let deps = AmqpRuntimeDeps::connect_with_private_ca(
        &publisher_endpoint,
        &subscriber_endpoint,
        ca.clone(),
        "amqp-private-ca-acl",
        TEST_PUBLISH_TIMEOUT,
    )
    .await?;
    let infra = deps.infra();
    let subscriber = infra.subscriber();
    let publisher = infra.publisher();
    assert!(
        deps.subscriber_for_integration_test()
            .default_exchange_publish_is_denied_for_test(&Topic::new(format!(
                "{}.adjacent",
                NEUTRAL_TOPIC
            )))
            .await?,
        "subscriber credential must not publish through the default exchange"
    );
    let mut stream = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-private-ca-acl-1"),
            b"acl-roundtrip".to_vec(),
        ))
        .await?;
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("private-CA ACL stream closed without a delivery"))?;
    assert_eq!(delivery.message.payload().as_bytes(), b"acl-roundtrip");
    delivery.acker.settle(AckAction::Reject).await?;
    assert!(
        deps.subscriber_for_integration_test()
            .take_broker_dead_letter_for_test(&topic)
            .await
            .is_err(),
        "runtime subscriber identity must not consume or replay broker quarantine"
    );
    let shared_raw =
        secure::AmqpEndpoint::parse(fixture.shared_url(), secure::PlaintextEndpointPolicy::Deny)?;
    let observer = AmqpRuntimeDeps::connect_with_private_ca(
        &AmqpPublisherEndpoint::new(shared_raw.clone()),
        &AmqpSubscriberEndpoint::new(shared_raw),
        ca.clone(),
        "amqp-private-ca-dlq-observer",
        TEST_PUBLISH_TIMEOUT,
    )
    .await?;
    testkit::await_map(Duration::from_secs(5), async || {
        (observer
            .subscriber_for_integration_test()
            .broker_dead_letter_depth_for_test(&topic)
            .await
            .ok()
            == Some(1))
        .then_some(())
    })
    .await
    .map_err(|_| anyhow!("restricted broker Reject did not reach its exact DLQ routing key"))?;
    let dead_letter = observer
        .subscriber_for_integration_test()
        .take_broker_dead_letter_for_test(&topic)
        .await?
        .ok_or_else(|| anyhow!("shared observer found no broker dead-letter"))?;
    assert_eq!(dead_letter.message_id(), Some("evt-private-ca-acl-1"));
    assert_eq!(dead_letter.death_reason(), "rejected");
    assert!(
        publisher
            .publish(PublishRequest::new(
                Topic::new(format!("{}.adjacent", NEUTRAL_TOPIC)),
                MessageId::new("evt-private-ca-adjacent-denied"),
                b"must-not-route-adjacent".to_vec(),
            ))
            .await
            .is_err(),
        "publisher identity must not publish an adjacent contract routing key"
    );

    let publisher_only = AmqpRuntimeDeps::connect_with_private_ca(
        &publisher_endpoint,
        &AmqpSubscriberEndpoint::new(publisher_raw),
        ca.clone(),
        "amqp-private-ca-publisher-only",
        TEST_PUBLISH_TIMEOUT,
    )
    .await?;
    assert!(
        publisher_only
            .infra()
            .subscriber()
            .subscribe_ackable(topic.clone(), CancellationToken::new())
            .await
            .is_err(),
        "publisher identity must not declare/consume a queue"
    );
    let subscriber_only = AmqpRuntimeDeps::connect_with_private_ca(
        &AmqpPublisherEndpoint::new(subscriber_raw),
        &subscriber_endpoint,
        ca,
        "amqp-private-ca-subscriber-only",
        TEST_PUBLISH_TIMEOUT,
    )
    .await?;
    assert!(
        subscriber_only
            .infra()
            .publisher()
            .publish(PublishRequest::new(
                topic,
                MessageId::new("evt-private-ca-acl-denied"),
                b"must-not-publish".to_vec(),
            ))
            .await
            .is_err(),
        "subscriber identity must not publish"
    );
    assert!(
        subscriber_only
            .infra()
            .subscriber()
            .subscribe_ackable(
                Topic::new(format!("{}.adjacent", NEUTRAL_TOPIC)),
                CancellationToken::new(),
            )
            .await
            .is_err(),
        "subscriber identity must not declare an adjacent queue"
    );

    token.cancel();
    AckableSubscriber::shutdown(observer.subscriber_for_integration_test()).await?;
    Publisher::shutdown(observer.publisher_for_integration_test()).await?;
    publisher.shutdown().await?;
    subscriber.shutdown().await?;
    Ok(())
}

fn amqp_endpoint(url: &str) -> anyhow::Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

async fn connect_publisher(url: &str, name: &str) -> anyhow::Result<AmqpPublisher> {
    let endpoint = amqp_endpoint(url)?;
    Ok(AmqpPublisher::connect_with_webpki_for_test(&endpoint, name, TEST_PUBLISH_TIMEOUT).await?)
}

async fn connect_subscriber(url: &str, name: &str) -> anyhow::Result<AmqpSubscriber> {
    let endpoint = amqp_endpoint(url)?;
    Ok(AmqpSubscriber::connect_with_webpki_for_test(&endpoint, name).await?)
}

async fn connect_subscriber_with_dlq_ttl(
    url: &str,
    name: &str,
    ttl: Duration,
) -> anyhow::Result<AmqpSubscriber> {
    connect_subscriber_with_queue_limits(url, name, ttl, 256 * 1024 * 1024, 256 * 1024 * 1024).await
}

async fn connect_subscriber_with_queue_limits(
    url: &str,
    name: &str,
    ttl: Duration,
    source_max_bytes: u32,
    dead_letter_max_bytes: u32,
) -> anyhow::Result<AmqpSubscriber> {
    let endpoint = amqp_endpoint(url)?;
    let ttl_ms = u32::try_from(ttl.as_millis())?;
    let ttl_ms = std::num::NonZeroU32::new(ttl_ms)
        .ok_or_else(|| anyhow!("broker DLQ test TTL must be non-zero"))?;
    let source_max_bytes = std::num::NonZeroU32::new(source_max_bytes)
        .ok_or_else(|| anyhow!("source queue test byte limit must be non-zero"))?;
    let dead_letter_max_bytes = std::num::NonZeroU32::new(dead_letter_max_bytes)
        .ok_or_else(|| anyhow!("broker DLQ test byte limit must be non-zero"))?;
    Ok(AmqpSubscriber::connect_with_broker_queue_limits_for_test(
        &endpoint,
        name,
        ttl_ms,
        source_max_bytes,
        dead_letter_max_bytes,
    )
    .await?)
}

async fn connect_runtime_deps(url: &str, name: &str) -> anyhow::Result<AmqpRuntimeDeps> {
    let endpoint = amqp_endpoint(url)?;
    Ok(
        AmqpRuntimeDeps::connect_with_webpki_for_test(&endpoint, name, TEST_PUBLISH_TIMEOUT)
            .await?,
    )
}

async fn assert_queue_limit_backpressures(
    publisher: &AmqpPublisher,
    topic: &Topic,
    message_id_prefix: &str,
) -> anyhow::Result<()> {
    let payload = vec![b'x'; 32 * 1024];
    for index in 0..64 {
        match publisher
            .publish(PublishRequest::new(
                topic.clone(),
                MessageId::new(format!("{message_id_prefix}-{index}")),
                payload.clone(),
            ))
            .await
        {
            Ok(()) => {}
            Err(error) if error.kind() == PublishErrorKind::Transient => return Ok(()),
            Err(error) => return Err(anyhow!("unexpected queue-limit publish error: {error}")),
        }
    }
    Err(anyhow!(
        "queue accepted 2 MiB despite its fixed 64 KiB byte limit"
    ))
}

/// 连接失败：错误面安全（Display 是常量，无 URL/凭据）+ source 保留。**无需 broker**（连不可达端口）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn integration_connect_failure_returns_safe_error() {
    // 不可达端口（连接拒绝）；URL 含凭据，断言不泄进错误 Display（AmqpPublisher 不 derive Debug，故 match）。
    match connect_publisher("amqp://user:secretpass@127.0.0.1:1/%2f", "amqp-it").await {
        Ok(_) => panic!("connect to closed port must fail"),
        Err(err) => {
            assert_eq!(err.to_string(), "amqp connect failed");
            // `AmqpUrl` redaction contract：Display 与 Debug 均不得含 user:pass。
            let display = err.to_string();
            let debug = format!("{err:?}");
            for rendered in [&display, &debug] {
                assert!(
                    !rendered.contains("secretpass"),
                    "password leaked in {rendered}"
                );
                assert!(!rendered.contains("user"), "username leaked in {rendered}");
            }
            assert!(
                err.chain().nth(1).is_some(),
                "lapin error preserved as internal source"
            );
        }
    }
}

/// 非法 timeout 必须在触达 endpoint 前 fail-closed，且错误面不得泄漏 URL userinfo。
#[tokio::test]
// reason: fixture 必须解析；无 Debug 的成功值必须显式 match 断言错误路径。
#[allow(clippy::expect_used, clippy::panic)]
async fn integration_invalid_publish_timeout_rejected_before_connect() {
    let endpoint = amqp_endpoint("amqp://user:secretpass@127.0.0.1:1/%2f")
        .expect("fixture endpoint must parse");
    match AmqpPublisher::connect_with_webpki_for_test(
        &endpoint,
        "amqp-invalid-timeout",
        Duration::ZERO,
    )
    .await
    {
        Ok(_) => panic!("zero publish timeout must be rejected"),
        Err(err) => {
            assert_eq!(err.to_string(), "amqp connect failed");
            let source = std::error::Error::source(&err)
                .expect("typed timeout source must be preserved")
                .to_string();
            assert_eq!(source, "invalid amqp publisher timeout");
            assert!(!source.contains("user"));
            assert!(!source.contains("secretpass"));
        }
    }
}

/// review #278 F1：发布到**尚无绑定 queue** 的 topic（publish-before-subscribe / 队列声明竞态）→ broker
/// `mandatory` 退回 unroutable → 分类为 **transient**（非 permanent）：outbox 可退避重试等订阅完成 / 拓扑收敛，
/// 不首投即 DLX（保 L2 最终送达）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn integration_publish_unroutable_is_transient() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_unroutable").await?;
    // 不订阅 ⇒ 无 queue 绑定该 topic；mandatory=true ⇒ broker 退回（durable publish-ok 检测为失败）。
    let publisher = connect_publisher(&url, "amqp-it-unroutable").await?;
    match publisher
        .publish(PublishRequest::new(
            Topic::new("rss.it.no.queue.bound"),
            MessageId::new("evt-unroutable-1"),
            b"orphan".to_vec(),
        ))
        .await
    {
        Ok(()) => panic!("publish to unbound queue must fail (mandatory return)"),
        Err(err) => assert_eq!(
            err.kind(),
            PublishErrorKind::Transient,
            "unroutable (no bound queue yet) must be transient for L2 retry, not permanent DLX"
        ),
    }

    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// 同-vhost topic 隔离：订 A + B 两条流，发到 B → **B 收到、A 在超时内无投递**（同 vhost 内 routing 隔离，
/// review F8）。跨 **domain** 的硬隔离 seam 是 per-domain vhost——见 `integration_cross_vhost_isolation`。
/// 使用 `subscribe_ackable`（at-least-once）——AMQP 唯一投递路径（Durable 拓扑）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_topic_isolation_same_vhost() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_topic_iso").await?;
    let token = CancellationToken::new();
    let subscriber = connect_subscriber(&url, "amqp-it-sub").await?;
    let mut stream_a = subscriber
        .subscribe_ackable(Topic::new("rss.it.iso-a"), token.clone())
        .await?;
    let mut stream_b = subscriber
        .subscribe_ackable(Topic::new("rss.it.iso-b"), token.clone())
        .await?;

    let publisher = connect_publisher(&url, "amqp-it-pub").await?;
    publisher
        .publish(PublishRequest::new(
            Topic::new("rss.it.iso-b"),
            MessageId::new("evt-iso-b"),
            b"to-b".to_vec(),
        ))
        .await?;

    // 正向：B 收到该消息。
    let delivery_b = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
        .await?
        .ok_or_else(|| anyhow!("b stream closed without a message"))?;
    assert_eq!(delivery_b.message.payload().as_bytes(), b"to-b");
    // 负向：A 在短超时内无投递（隔离——B 的消息没串到 A）。timeout Err = 无消息。
    // 1s 余量（原 500ms 在 CI 高负载下偶发 flaky；正向已先成功，负向只需等隔离窗口）。
    let a_result = tokio::time::timeout(Duration::from_secs(1), stream_a.next()).await;
    assert!(
        a_result.is_err(),
        "topic A must not receive topic B's message"
    );

    token.cancel();
    Ok(())
}

/// (F4/C4) 每订阅独立 channel：同 subscriber 订 A(tokenA) + B(tokenB)，cancel **tokenA** → 流 A 终止，但
/// 流 B **仍能收到**后续发到 B 的消息——取消单订阅只 basic.cancel 本 consumer，不连带停掉其它 topic
/// consumer（review #274 F4：原 `self.channel` 共享，任一 cancel 关 channel 会连带终止同实例其它订阅）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_per_subscription_cancel_does_not_stop_others() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_persub_cancel").await?;
    let token_a = CancellationToken::new();
    let token_b = CancellationToken::new();
    let subscriber = connect_subscriber(&url, "amqp-it-persub").await?;
    let mut stream_a = subscriber
        .subscribe_ackable(Topic::new("rss.it.persub-a"), token_a.clone())
        .await?;
    let mut stream_b = subscriber
        .subscribe_ackable(Topic::new("rss.it.persub-b"), token_b.clone())
        .await?;

    // 取消 A 的 token：仅等待 A consumer 的 basic.cancel-ok。
    token_a.cancel();
    let ended_a = tokio::time::timeout(Duration::from_secs(5), stream_a.next()).await?;
    assert!(ended_a.is_none(), "A 流取消后须终止（Ok(None)）");

    // A 取消后发到 B → B 仍能收到（B 的 channel/consumer 未被 A 的 cancel 连带关闭——回归守卫）。
    let publisher = connect_publisher(&url, "amqp-it-persub-pub").await?;
    publisher
        .publish(PublishRequest::new(
            Topic::new("rss.it.persub-b"),
            MessageId::new("evt-persub-b"),
            b"to-b-after-a-cancel".to_vec(),
        ))
        .await?;
    let delivery_b = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
        .await?
        .ok_or_else(|| anyhow!("B 流在 A 取消后关闭（回归：共享 channel 被连带关闭）"))?;
    assert_eq!(
        delivery_b.message.payload().as_bytes(),
        b"to-b-after-a-cancel"
    );
    delivery_b
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle ack failed: {e}"))?;

    token_b.cancel();
    Publisher::shutdown(&publisher).await?;
    AckableSubscriber::shutdown(&subscriber).await?;
    Ok(())
}

/// 跨-vhost 隔离（per-domain vhost 硬命名空间边界，#1137）：同容器建两个 vhost，发到 vhost-a → vhost-a
/// 订阅者收到、vhost-b 订阅者在超时内无投递（vhost 是 AMQP 硬边界，跨 vhost 不路由）。这是跨域真隔离 seam。
#[tokio::test(flavor = "multi_thread")]
async fn integration_cross_vhost_isolation() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url_a = rmq.vhost_url("rss_vhost_a").await?;
    let url_b = rmq.vhost_url("rss_vhost_b").await?;
    let topic = Topic::new("rss.it.crossvhost");
    let token = CancellationToken::new();

    // 同 topic 名，分属两 vhost：vhost-a 订阅者 + vhost-b 订阅者。使用 subscribe_ackable（at-least-once）。
    let sub_a = connect_subscriber(&url_a, "xvhost-sub-a").await?;
    let mut stream_a = sub_a
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    let sub_b = connect_subscriber(&url_b, "xvhost-sub-b").await?;
    let mut stream_b = sub_b
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;

    // 发到 vhost-a。
    let pub_a = connect_publisher(&url_a, "xvhost-pub-a").await?;
    pub_a
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-xvhost-a"),
            b"only-a".to_vec(),
        ))
        .await?;

    // 正向：vhost-a 订阅者收到。
    let delivery_a = tokio::time::timeout(Duration::from_secs(5), stream_a.next())
        .await?
        .ok_or_else(|| anyhow!("vhost-a stream closed without a message"))?;
    assert_eq!(delivery_a.message.payload().as_bytes(), b"only-a");
    // 负向：vhost-b 订阅者超时内无投递（vhost 硬命名空间边界——跨 vhost 不路由）。
    // 1s 余量（原 500ms 在 CI 高负载下偶发 flaky；正向已先成功，负向只需等隔离窗口）。
    let b_result = tokio::time::timeout(Duration::from_secs(1), stream_b.next()).await;
    assert!(
        b_result.is_err(),
        "vhost-b must not receive vhost-a's message (per-domain vhost isolation)"
    );

    token.cancel();
    Ok(())
}

/// 取消即流终止（take_until token + broker-confirmed basic.cancel）。
/// cancel 后流须在超时内关闭（有界等待，防 broker 异常时挂死——对齐其他 broker 断言）。
/// 使用 `subscribe_ackable`（at-least-once）——token cancel 触发并等待 basic.cancel-ok。
#[tokio::test(flavor = "multi_thread")]
async fn integration_cancel_terminates_stream() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_cancel").await?;
    let token = CancellationToken::new();
    let subscriber = connect_subscriber(&url, "amqp-it-sub").await?;
    let mut stream = subscriber
        .subscribe_ackable(Topic::new("rss.it.cancel"), token.clone())
        .await?;
    token.cancel();
    let ended = tokio::time::timeout(Duration::from_secs(5), stream.next()).await?;
    assert!(ended.is_none(), "cancel 后流须在超时内终止（Ok(None)）");
    Ok(())
}

// ── at-least-once manual-ack 测试（a/b/c）──────────────────────────────────

/// (a) manual-ack Ack：publish → `subscribe_ackable` 收一条 → `settle(Ack)` → 消息移出队列。
/// 验证：ack 后重新订阅（新 consumer）在超时内无投递——broker 已移除该消息。
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_ack_removes_message() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_a").await?;
    let topic = Topic::new("rss.it.ack-a");

    // 先订阅（声明 queue），再发布，再消费。
    let sub1 = connect_subscriber(&url, "amqp-it-ack-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = connect_publisher(&url, "amqp-it-ack-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-ack-a"),
            b"ack-payload".to_vec(),
        ))
        .await?;

    // 收到一条投递，ack 结算。
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for ackable delivery"))?
        .ok_or_else(|| anyhow!("stream closed without delivery"))?;
    assert_eq!(delivery.message.payload().as_bytes(), b"ack-payload");
    delivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle failed: {e}"))?;
    assert_eq!(
        sub1.broker_dead_letter_depth_for_test(&topic).await?,
        0,
        "Ack must not copy the message into the broker quarantine"
    );

    // 关闭第一个 consumer。
    token1.cancel();
    AckableSubscriber::shutdown(&sub1).await?;

    // 重新订阅——broker 已 ack 移除，新 consumer 在超时内无投递。
    let sub2 = connect_subscriber(&url, "amqp-it-ack-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let no_msg = tokio::time::timeout(Duration::from_secs(2), stream2.next()).await;
    assert!(no_msg.is_err(), "ack 后队列应为空，不应再有投递");

    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// Manual Reject is a transport quarantine action: RabbitMQ dead-letters the original payload and
/// message-id as one dead-lettered message, and records the broker-owned rejection receipt in
/// `x-death`; this does not strengthen the transport delivery guarantee.
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_reject_enters_broker_dead_letter_queue() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_reject").await?;
    let topic = Topic::new("rss.it.ack-reject");
    let subscriber = connect_subscriber(&url, "amqp-it-reject-sub").await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;
    let token = CancellationToken::new();
    let mut stream = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    let publisher = connect_publisher(&url, "amqp-it-reject-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-reject-dlx"),
            b"reject-payload".to_vec(),
        ))
        .await?;

    let delivery = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for reject delivery"))?
        .ok_or_else(|| anyhow!("reject delivery stream closed"))?;
    delivery.acker.settle(AckAction::Reject).await?;

    testkit::await_map(Duration::from_secs(5), async || {
        (subscriber
            .broker_dead_letter_depth_for_test(&topic)
            .await
            .ok()
            == Some(1))
        .then_some(())
    })
    .await
    .map_err(|_| anyhow!("timeout waiting for broker dead-letter"))?;
    let dead_letter = subscriber
        .take_broker_dead_letter_for_test(&topic)
        .await?
        .ok_or_else(|| anyhow!("broker dead-letter queue was empty"))?;
    assert_eq!(dead_letter.message_id(), Some("evt-reject-dlx"));
    assert_eq!(dead_letter.payload(), b"reject-payload");
    assert_eq!(dead_letter.death_reason(), "rejected");
    assert_eq!(dead_letter.death_count(), 1);
    assert_eq!(dead_letter.source_queue(), topic.as_str());
    assert_eq!(dead_letter.source_exchange(), "amq.topic");

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// Quorum `at-least-once` dead lettering retains a rejected message in the source while the target
/// queue is absent. The normal Reject test separately proves delivery when that target is present.
#[tokio::test(flavor = "multi_thread")]
async fn integration_broker_dead_letter_target_unavailable_retains_in_source()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let vhost = "rss_ack_dlx_target_restore";
    let url = rmq.vhost_url(vhost).await?;
    let topic = Topic::new("rss.it.ack-dlx-target-restore");
    let subscriber = connect_subscriber(&url, "amqp-it-dlx-target-restore-sub").await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;
    let token = CancellationToken::new();
    let mut stream = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    subscriber
        .delete_broker_dead_letter_for_test(&topic)
        .await?;

    let publisher = connect_publisher(&url, "amqp-it-dlx-target-restore-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-dlx-target-restored"),
            b"retained-while-target-absent".to_vec(),
        ))
        .await?;
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for target-absence delivery"))?
        .ok_or_else(|| anyhow!("target-absence delivery stream closed"))?;
    delivery.acker.settle(AckAction::Reject).await?;

    testkit::await_map(Duration::from_secs(10), async || {
        (rmq.broker_queue_total_depth(vhost, topic.as_str())
            .await
            .ok()
            == Some(1))
        .then_some(())
    })
    .await
    .map_err(|_| anyhow!("missing DLQ target caused the rejected message to be lost"))?;

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// Both source and plaintext quarantine reject new publishes once their fixed byte budgets are
/// exhausted. Publisher confirms surface the pressure as transient so the outbox relay retries.
#[tokio::test(flavor = "multi_thread")]
async fn integration_broker_source_and_dead_letter_byte_limits_backpressure_publishers()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_dlx_byte_limits").await?;
    let topic = Topic::new("rss.it.ack-dlx-byte-limits");
    let subscriber = connect_subscriber_with_queue_limits(
        &url,
        "amqp-it-dlx-byte-limits-sub",
        Duration::from_secs(60),
        64 * 1024,
        64 * 1024,
    )
    .await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;

    let source_publisher = connect_publisher(&url, "amqp-it-source-byte-limit-pub").await?;
    assert_queue_limit_backpressures(&source_publisher, &topic, "evt-source-limit").await?;
    Publisher::shutdown(&source_publisher).await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;

    let dead_letter_publisher = connect_publisher(&url, "amqp-it-dlq-byte-limit-pub").await?;
    let dead_letter_topic = Topic::new(format!("{}.dlq", topic.as_str()));
    assert_queue_limit_backpressures(&dead_letter_publisher, &dead_letter_topic, "evt-dlq-limit")
        .await?;
    Publisher::shutdown(&dead_letter_publisher).await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;
    AckableSubscriber::shutdown(&subscriber).await?;
    Ok(())
}

/// Observation must never destroy malformed quarantine evidence. A direct message deliberately
/// lacks `x-death`; parsing fails, the manual-get channel closes, and RabbitMQ requeues it.
#[tokio::test(flavor = "multi_thread")]
async fn integration_malformed_broker_dead_letter_observation_requeues_evidence()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_dlx_observation").await?;
    let topic = Topic::new("rss.it.ack-dlx-observation");
    let subscriber = connect_subscriber(&url, "amqp-it-dlx-observation-sub").await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;
    let publisher = connect_publisher(&url, "amqp-it-dlx-observation-pub").await?;
    publisher
        .publish(PublishRequest::new(
            Topic::new(format!("{}.dlq", topic.as_str())),
            MessageId::new("evt-malformed-dlq-evidence"),
            b"malformed-dlq-evidence".to_vec(),
        ))
        .await?;
    testkit::await_map(Duration::from_secs(5), async || {
        (subscriber
            .broker_dead_letter_depth_for_test(&topic)
            .await
            .ok()
            == Some(1))
        .then_some(())
    })
    .await
    .map_err(|_| anyhow!("malformed DLQ evidence was not routed"))?;

    assert!(
        subscriber
            .take_broker_dead_letter_for_test(&topic)
            .await
            .is_err(),
        "missing x-death must fail typed observation"
    );
    testkit::await_map(Duration::from_secs(5), async || {
        (subscriber
            .broker_dead_letter_depth_for_test(&topic)
            .await
            .ok()
            == Some(1))
        .then_some(())
    })
    .await
    .map_err(|_| anyhow!("malformed DLQ evidence was destroyed instead of requeued"))?;

    subscriber.purge_durable_queue_for_test(&topic).await?;
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// Production always uses the fixed 24h quarantine TTL. The integration-only constructor varies
/// only that value so the same declaration path can prove RabbitMQ actually expires quarantined
/// messages without turning retention into production configuration.
#[tokio::test(flavor = "multi_thread")]
async fn integration_broker_dead_letter_ttl_expires_quarantined_message() -> Result<(), FixtureError>
{
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_dlx_ttl").await?;
    let topic = Topic::new("rss.it.ack-dlx-ttl");
    let subscriber =
        connect_subscriber_with_dlq_ttl(&url, "amqp-it-dlx-ttl-sub", Duration::from_millis(250))
            .await?;
    subscriber.purge_durable_queue_for_test(&topic).await?;
    let token = CancellationToken::new();
    let mut stream = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    let publisher = connect_publisher(&url, "amqp-it-dlx-ttl-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-reject-expiring"),
            b"expiring-quarantine".to_vec(),
        ))
        .await?;
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for expiring reject delivery"))?
        .ok_or_else(|| anyhow!("expiring reject delivery stream closed"))?;
    delivery.acker.settle(AckAction::Reject).await?;

    testkit::await_map(Duration::from_secs(5), async || {
        (subscriber
            .broker_dead_letter_depth_for_test(&topic)
            .await
            .ok()
            == Some(1))
        .then_some(())
    })
    .await
    .map_err(|_| anyhow!("quarantined message never became observable"))?;
    testkit::await_map(Duration::from_secs(5), async || {
        (subscriber
            .broker_dead_letter_depth_for_test(&topic)
            .await
            .ok()
            == Some(0))
        .then_some(())
    })
    .await
    .map_err(|_| anyhow!("broker dead-letter TTL did not expire the message"))?;

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// Durable queue arguments are application-owned. A queue created with different retention must
/// make a later production declaration fail loudly instead of accepting legacy topology or
/// silently dropping Rejects.
#[tokio::test(flavor = "multi_thread")]
async fn integration_broker_dead_letter_topology_drift_fails_loudly() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_dlx_drift").await?;
    let topic = Topic::new("rss.it.ack-dlx-drift");
    let drifted = connect_subscriber_with_dlq_ttl(
        &url,
        "amqp-it-dlx-drift-setup",
        Duration::from_millis(250),
    )
    .await?;
    drifted.purge_durable_queue_for_test(&topic).await?;
    AckableSubscriber::shutdown(&drifted).await?;

    let production = connect_subscriber(&url, "amqp-it-dlx-drift-production").await?;
    let result = production
        .subscribe_ackable(topic, CancellationToken::new())
        .await;
    assert!(
        result.is_err(),
        "production topology must reject an existing queue with different immutable arguments"
    );
    AckableSubscriber::shutdown(&production).await?;
    Ok(())
}

/// (b) manual-ack Requeue：publish → consume → `settle(Requeue)` → 消息被 broker 重入队 →
/// 第二个 consumer 能再次收到该消息（redelivered）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_requeue_redelivers_message() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_b").await?;
    let topic = Topic::new("rss.it.ack-b");

    let sub1 = connect_subscriber(&url, "amqp-it-rq-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = connect_publisher(&url, "amqp-it-rq-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-requeue-b"),
            b"requeue-payload".to_vec(),
        ))
        .await?;

    // 第一个 consumer 收到，nack(requeue=true)。
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for first delivery"))?
        .ok_or_else(|| anyhow!("stream closed"))?;
    delivery
        .acker
        .settle(AckAction::Requeue)
        .await
        .map_err(|e| anyhow!("settle requeue failed: {e}"))?;

    // 关闭第一个 consumer。
    token1.cancel();
    AckableSubscriber::shutdown(&sub1).await?;

    // 第二个 consumer：消息已被 requeue，应再次收到（at-least-once 重投）。
    let sub2 = connect_subscriber(&url, "amqp-it-rq-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for redelivery"))?
        .ok_or_else(|| anyhow!("redelivery stream closed without message"))?;
    assert_eq!(redelivery.message.payload().as_bytes(), b"requeue-payload");
    // ack 清理，避免残留影响后续测试。
    redelivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle ack failed: {e}"))?;
    assert_eq!(
        sub2.broker_dead_letter_depth_for_test(&topic).await?,
        0,
        "Requeue and the final Ack must not enter broker quarantine"
    );

    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// A long-lived broker can retain a durable, unacked delivery from an interrupted prior run.
/// The integration-only typed seam must purge that queue before the next run consumes anything.
#[tokio::test(flavor = "multi_thread")]
async fn integration_test_queue_purge_removes_requeued_prior_run_delivery()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_purge").await?;
    let topic = Topic::new("rss.it.ack-purge");

    let first_subscriber = connect_subscriber(&url, "amqp-it-purge-sub1").await?;
    first_subscriber
        .purge_durable_queue_for_test(&topic)
        .await?;
    let first_token = CancellationToken::new();
    let mut first_stream = first_subscriber
        .subscribe_ackable(topic.clone(), first_token.clone())
        .await?;
    let publisher = connect_publisher(&url, "amqp-it-purge-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-prior-run"),
            b"prior-run".to_vec(),
        ))
        .await?;

    let prior = tokio::time::timeout(Duration::from_secs(5), first_stream.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for prior-run delivery"))?
        .ok_or_else(|| anyhow!("prior-run delivery stream closed"))?;
    assert_eq!(prior.message.id().as_str(), "evt-prior-run");
    drop(prior);
    first_token.cancel();
    AckableSubscriber::shutdown(&first_subscriber).await?;

    let next_subscriber = connect_subscriber(&url, "amqp-it-purge-sub2").await?;
    let purged = next_subscriber.purge_durable_queue_for_test(&topic).await?;
    assert_eq!(
        purged, 1,
        "the interrupted prior-run delivery must be purged"
    );

    let next_token = CancellationToken::new();
    let mut next_stream = next_subscriber
        .subscribe_ackable(topic.clone(), next_token.clone())
        .await?;
    let stale = tokio::time::timeout(Duration::from_secs(1), next_stream.next()).await;
    assert!(stale.is_err(), "purged prior-run delivery was redelivered");

    publisher
        .publish(PublishRequest::new(
            topic,
            MessageId::new("evt-current-run"),
            b"current-run".to_vec(),
        ))
        .await?;
    let current = tokio::time::timeout(Duration::from_secs(5), next_stream.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for current-run delivery"))?
        .ok_or_else(|| anyhow!("current-run delivery stream closed"))?;
    assert_eq!(current.message.id().as_str(), "evt-current-run");
    current.acker.settle(AckAction::Ack).await?;

    next_token.cancel();
    AckableSubscriber::shutdown(&next_subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// (c) at-least-once 核心：consume 一条后**不 settle，直接 drop 流 / 断 channel**（模拟消费者崩溃）→
/// 新 consumer 能再次收到该消息（未 ack 的在途消息 broker channel-close 后自动 requeue）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_crash_without_settle_redelivers() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_c").await?;
    let topic = Topic::new("rss.it.ack-c");

    // 第一个 consumer：收到消息但不 settle，然后 shutdown channel（模拟崩溃）。
    let sub1 = connect_subscriber(&url, "amqp-it-crash-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = connect_publisher(&url, "amqp-it-crash-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-crash-c"),
            b"crash-payload".to_vec(),
        ))
        .await?;

    // 收到投递，取出 acker（消费 struct），但**不 settle**（模拟在途崩溃）。
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for delivery"))?
        .ok_or_else(|| anyhow!("stream closed"))?;
    // 取出 acker 但不调用（drop 时 broker 仍会在 channel close 后 requeue）。
    let _acker = delivery.acker;
    drop(stream1);
    // 关闭 channel（模拟崩溃丢 channel）；broker 对未 ack 消息自动 requeue。
    AckableSubscriber::shutdown(&sub1).await?;

    // 第二个 consumer：应能再次收到该消息（broker 重投）。
    let sub2 = connect_subscriber(&url, "amqp-it-crash-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for crash-redelivery (at-least-once)"))?
        .ok_or_else(|| anyhow!("crash-redelivery stream closed without message"))?;
    assert_eq!(redelivery.message.payload().as_bytes(), b"crash-payload");
    // ack 清理。
    redelivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle ack failed: {e}"))?;

    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// token cancel 必须等待 broker 确认 `basic.cancel`，停止新投递但保留 channel，
/// 使取消前已在途的 delivery 仍能 settle；后续消息只由替代 consumer 获取。
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_token_cancel_drains_inflight_before_shutdown()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_d").await?;
    let topic = Topic::new("rss.it.ack-d");

    let sub1 = connect_subscriber(&url, "amqp-it-cancel-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = connect_publisher(&url, "amqp-it-cancel-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-cancel-d"),
            b"cancel-payload".to_vec(),
        ))
        .await?;
    // Queue the successor before cancellation. With prefetch=1 it must remain broker-owned while
    // the first delivery is in flight, proving the cancel barrier prevents a second delivery.
    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new("evt-after-cancel-d"),
            b"after-cancel".to_vec(),
        ))
        .await?;

    // 先保留一条在途投递，然后仅取消 token（不 shutdown）。
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for delivery"))?
        .ok_or_else(|| anyhow!("stream closed"))?;
    // ConsumerTx owns the current delivery when shutdown requests cancellation. Settlement starts
    // immediately after that synchronous request: the adapter must prioritize broker-confirmed
    // basic.cancel without relying on task scheduling or a sleep, then allow this Ack to proceed.
    token1.cancel();
    let ack_result = tokio::time::timeout(
        Duration::from_secs(5),
        delivery.acker.settle(AckAction::Ack),
    )
    .await
    .map_err(|_| anyhow!("inflight Ack hung behind basic.cancel"))?;
    ack_result.map_err(|e| anyhow!("settle inflight after basic.cancel failed: {e}"))?;
    let ended = tokio::time::timeout(Duration::from_secs(5), stream1.next()).await?;
    assert!(ended.is_none(), "basic.cancel 确认后 ackable 流应终止");
    AckableSubscriber::shutdown(&sub1).await?;

    // 替代 consumer 收到取消前已排队的第二条；已 Ack 的在途消息不重投。
    let sub2 = connect_subscriber(&url, "amqp-it-cancel-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let next_delivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for post-cancel delivery"))?
        .ok_or_else(|| anyhow!("replacement consumer stream closed"))?;
    assert_eq!(next_delivery.message.id().as_str(), "evt-after-cancel-d");
    next_delivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle ack failed: {e}"))?;

    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// Forced lifecycle cancellation leaves the current delivery unsettled. Closing the old session
/// must therefore return that exact delivery to the broker for a replacement consumer.
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_forced_cancel_unsettled_delivery_redelivers()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_forced_cancel").await?;
    let topic = Topic::new("rss.it.ack-forced-cancel");
    let sub1 = connect_subscriber(&url, "amqp-it-forced-cancel-sub1").await?;
    let token1 = CancellationToken::new();
    let publisher = connect_publisher(&url, "amqp-it-forced-cancel-pub").await?;
    let message_id = "evt-forced-cancel";
    let (meta, metadata) = forced_cancel_consumer_contract(&topic, message_id)?;

    let store = Arc::new(ForcedCancelInbox {
        claims: AtomicU32::new(0),
        commits: AtomicU32::new(0),
        releases: AtomicU32::new(0),
    });
    let dlx = diport::DynDeadLetterStore::new_box(NoopDeadLetter);
    let handler_started = Arc::new(tokio::sync::Notify::new());
    let handler_started_run = Arc::clone(&handler_started);
    let handler = move |_message| {
        let handler_started_run = Arc::clone(&handler_started_run);
        Box::pin(async move {
            handler_started_run.notify_one();
            std::future::pending::<consistency::HandleResult>().await
        }) as futures::future::BoxFuture<'static, consistency::HandleResult>
    };
    let (admission_control, _, admission, _) =
        primitives::prepare_dr_admission_controls().into_parts();
    admission_control.start_running()?;
    let health = Arc::new(eventexec::WorkerHealth::starting());
    let subscription_health = Arc::clone(&health);
    let worker = eventexec::spawn_consumer_ackable_subscriber(
        "amqp-it-forced-cancel-worker".to_owned(),
        diport::DynAckableSubscriber::new_box(sub1),
        topic.clone(),
        Arc::clone(&store),
        dlx,
        meta,
        handler,
        eventexec::LeaseConfig::from_ttl(Duration::from_secs(60)),
        token1,
        health,
        eventing::lifecycle::RetryPolicy::new(
            std::num::NonZeroU32::MIN.saturating_add(2),
            Duration::from_millis(1),
            Duration::from_millis(4),
        )?,
        admission,
        eventing::lifecycle::ShutdownBudget::STANDARD,
    );
    while subscription_health.status() != primitives::healthz::HealthStatus::Healthy {
        tokio::task::yield_now().await;
    }
    let handler_notified = handler_started.notified();
    publisher
        .publish(
            PublishRequest::new(
                topic.clone(),
                MessageId::new(message_id),
                b"forced-cancel-payload".to_vec(),
            )
            .with_metadata(metadata),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(5), handler_notified)
        .await
        .map_err(|_| anyhow!("timeout waiting for managed handler"))?;
    tokio::time::timeout(
        Duration::from_secs(5),
        diport::ManagedResource::shutdown(&worker),
    )
    .await
    .map_err(|_| anyhow!("managed consumer did not stop after owner shutdown"))??;
    assert_eq!(store.claims.load(Ordering::Acquire), 1);
    assert_eq!(store.commits.load(Ordering::Acquire), 0);
    assert_eq!(store.releases.load(Ordering::Acquire), 0);

    let sub2 = connect_subscriber(&url, "amqp-it-forced-cancel-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2.subscribe_ackable(topic, token2.clone()).await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for forced-cancel redelivery"))?
        .ok_or_else(|| anyhow!("replacement stream closed"))?;
    assert_eq!(redelivery.message.id().as_str(), message_id);
    redelivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|error| anyhow!("settle redelivery failed: {error}"))?;

    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

/// envelope header 双向贯通：publish 携 occurred_at + subjectId + correlation →
/// subscriber 端只 rehydrate broker-visible metadata；subjectId 保持 persisted-only。
#[tokio::test(flavor = "multi_thread")]
async fn integration_envelope_header_roundtrip() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_envelope_hdr").await?;
    let topic = Topic::new("rss.it.envelope-header");
    let token = CancellationToken::new();

    let subscriber = connect_subscriber(&url, "amqp-it-env-sub").await?;
    let mut stream = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;

    let publisher = connect_publisher(&url, "amqp-it-env-pub").await?;

    // 构造携 envelope metadata 的 PublishRequest。
    let mut md = EnvelopeMetadata::empty();
    md.insert_wire_pair(KEY_TENANT_ID, TEST_TENANT);
    md.insert_wire_pair(KEY_OCCURRED_AT, "1700000001");
    md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
    md.insert_wire_pair(KEY_SCHEMA_HASH, TEST_SCHEMA_HASH);
    md.insert_wire_pair(KEY_CORRELATION, "corr-42");
    md.insert_wire_pair(KEY_SUBJECT_ID, "user-7");

    publisher
        .publish(
            PublishRequest::new(
                topic,
                MessageId::new("evt-env-hdr-1"),
                b"env-payload".to_vec(),
            )
            .with_metadata(md),
        )
        .await?;

    let delivery = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("stream closed without yielding a message"))?;

    // metadata 保真验证。
    assert_eq!(
        delivery.message.metadata().get(KEY_OCCURRED_AT),
        Some("1700000001"),
        "occurred_at 应经 AMQP timestamp 字段透传"
    );
    assert_eq!(
        delivery.message.metadata().get(KEY_CORRELATION),
        Some("corr-42"),
        "correlation 应经 AMQP FieldTable LongString 透传"
    );
    assert_eq!(
        delivery.message.metadata().get(KEY_SUBJECT_ID),
        None,
        "subjectId 是 persisted-only metadata，不应经 AMQP FieldTable LongString 透传"
    );

    delivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle failed: {e}"))?;

    token.cancel();
    Publisher::shutdown(&publisher).await?;
    AckableSubscriber::shutdown(&subscriber).await?;
    Ok(())
}

/// #1498 test-only WebPKI bundle 装配出口打开一个域 vhost 的 publisher + subscriber，经 `infra()`
/// 派发 DI-ready port 句柄跑 publish→subscribe 闭环；`runtime_resources()` 单源派生 publisher-guard +
/// subscriber-guard（各关其 connection），经 guard 关停干净收敛（D5 单源 rollback）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_bundle_dispatch_and_single_source_resources() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_bundle").await?;
    let topic = Topic::new("rss.it.bundle");
    let token = CancellationToken::new();

    let deps = connect_runtime_deps(&url, "amqp-it-bundle").await?;
    assert!(deps.publisher_readiness().is_ready());
    assert!(
        !deps.subscriber_readiness().is_ready(),
        "subscriber readiness requires an activated subscription channel"
    );

    // 经 bundle 派发的 port 句柄跑闭环（证明 dispatch 共享 bundle conn、port 可用）。
    let subscriber = deps.infra().subscriber();
    let mut stream = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    assert!(deps.subscriber_readiness().is_ready());
    let publisher = deps.infra().publisher();
    publisher
        .publish(PublishRequest::new(
            topic,
            MessageId::new("evt-bundle-1"),
            b"hello-bundle".to_vec(),
        ))
        .await?;

    let delivery = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("bundle stream closed without yielding a message"))?;
    assert_eq!(delivery.message.payload().as_bytes(), b"hello-bundle");
    delivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle failed: {e}"))?;

    // 单源 runtime_resources：恰两条受管连接（publisher-guard + subscriber-guard），名带 -pub / -sub 后缀。
    let resources = deps.runtime_resources();
    assert_eq!(
        resources.len(),
        2,
        "bundle 单源派生 publisher-guard + subscriber-guard"
    );
    assert_eq!(resources[0].name(), "amqp-it-bundle-pub");
    assert_eq!(resources[1].name(), "amqp-it-bundle-sub");

    token.cancel();
    // publisher port-local shutdown 关 channel；subscriber shared port 不拥有 connection；guard 单源关 connection。
    Publisher::shutdown(publisher.as_ref()).await?;
    AckableSubscriber::shutdown(subscriber.as_ref()).await?;
    for resource in resources {
        resource
            .shutdown()
            .await
            .map_err(|e| anyhow!("bundle resource shutdown failed: {e}"))?;
    }
    assert!(!deps.publisher_readiness().is_ready());
    assert!(!deps.subscriber_readiness().is_ready());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_broker_roundtrip_preserves_message_identity() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_publisher_identity_roundtrip").await?;
    let endpoint =
        secure::AmqpEndpoint::parse(&url, secure::PlaintextEndpointPolicy::AllowLoopback)?;
    let publisher = AmqpPublisher::connect_with_webpki_for_test(
        &endpoint,
        "amqp-it-identity-pub",
        Duration::from_secs(6),
    )
    .await?;
    let subscriber =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint, "amqp-it-identity-sub").await?;
    let topic = Topic::new("rss.it.publisher.identity");
    let token = CancellationToken::new();
    let mut deliveries = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    let event_id = MessageId::new("evt-publisher-identity-roundtrip-1");

    publisher
        .publish(PublishRequest::new(
            topic,
            event_id.clone(),
            b"identity-roundtrip".to_vec(),
        ))
        .await?;
    let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
        .await?
        .ok_or_else(|| anyhow!("identity roundtrip delivery missing"))?;
    assert_eq!(delivery.message.id(), &event_id);
    delivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|error| anyhow!("identity roundtrip ack failed: {error}"))?;

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    ManagedResource::shutdown(&publisher).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_post_send_close_is_ambiguous_and_allows_same_id_retry()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_confirm_rotation").await?;
    let endpoint =
        secure::AmqpEndpoint::parse(&url, secure::PlaintextEndpointPolicy::AllowLoopback)?;
    let publisher = AmqpPublisher::connect_with_webpki_for_test(
        &endpoint,
        "amqp-it-rotation",
        Duration::from_secs(6),
    )
    .await?;
    let subscriber =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint, "amqp-it-rotation-sub").await?;
    let topic = Topic::new("rss.it.confirm.rotation");
    let token = CancellationToken::new();
    let mut deliveries = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    let event_id = MessageId::new("evt-confirm-timeout-retry-1");

    publisher.inject_post_send_connection_close_once();
    let error = publisher
        .publish(PublishRequest::new(
            topic.clone(),
            event_id.clone(),
            b"same-id".to_vec(),
        ))
        .await
        .err()
        .ok_or_else(|| anyhow!("post-send barrier must return an ambiguous outcome"))?;
    assert!(error.is_ambiguous());
    assert!(
        publisher.wait_until_publish_ready_for_test().await,
        "publisher must install a fresh transport before retry"
    );

    publisher
        .publish(PublishRequest::new(
            topic,
            event_id.clone(),
            b"same-id".to_vec(),
        ))
        .await?;
    for _ in 0..2 {
        let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
            .await?
            .ok_or_else(|| anyhow!("same-ID retry delivery missing"))?;
        assert_eq!(delivery.message.id(), &event_id);
        delivery
            .acker
            .settle(AckAction::Ack)
            .await
            .map_err(|error| anyhow!("same-ID delivery ack failed: {error}"))?;
    }

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    ManagedResource::shutdown(&publisher).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_broker_forced_close_reconnects_fresh_transport() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let vhost = "rss_forced_transport_close";
    let url = rmq.vhost_url(vhost).await?;
    let endpoint =
        secure::AmqpEndpoint::parse(&url, secure::PlaintextEndpointPolicy::AllowLoopback)?;
    let topic = Topic::new("rss.it.forced.transport.close");

    // Declare the durable queue before the fault, then remove the setup connection so the broker's
    // bounded close targets the publisher rather than an arbitrary subscriber connection.
    let setup_subscriber =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint, "amqp-it-forced-close-setup")
            .await?;
    let setup_token = CancellationToken::new();
    let setup_deliveries = setup_subscriber
        .subscribe_ackable(topic.clone(), setup_token.clone())
        .await?;
    setup_token.cancel();
    drop(setup_deliveries);
    AckableSubscriber::shutdown(&setup_subscriber).await?;

    let publisher = AmqpPublisher::connect_with_webpki_for_test(
        &endpoint,
        "amqp-it-forced-close",
        Duration::from_secs(6),
    )
    .await?;

    rmq.broker_force_close_one_connection(vhost, "rss integration forced close")
        .await?;
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    let mut observed_transient = false;
    for attempt in 0..250 {
        ticker.tick().await;
        let result = publisher
            .publish(PublishRequest::new(
                topic.clone(),
                MessageId::new(format!("evt-forced-close-probe-{attempt}")),
                b"must-not-send".to_vec(),
            ))
            .await;
        if result.is_err_and(|error| {
            error.kind() == PublishErrorKind::Transient && !error.is_ambiguous()
        }) {
            observed_transient = true;
            break;
        }
    }
    assert!(
        observed_transient,
        "forced close must retire the stale transport"
    );
    assert!(
        publisher.wait_until_publish_ready_for_test().await,
        "forced close must install a fresh transport"
    );

    let subscriber =
        AmqpSubscriber::connect_with_webpki_for_test(&endpoint, "amqp-it-forced-close-sub").await?;
    let token = CancellationToken::new();
    let mut deliveries = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    publisher
        .publish(PublishRequest::new(
            topic,
            MessageId::new("evt-forced-close-retry"),
            b"fresh-transport".to_vec(),
        ))
        .await?;
    let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
        .await?
        .ok_or_else(|| anyhow!("fresh transport delivery missing"))?;
    assert_eq!(delivery.message.id().as_str(), "evt-forced-close-retry");
    delivery.acker.settle(AckAction::Ack).await?;

    token.cancel();
    AckableSubscriber::shutdown(&subscriber).await?;
    Publisher::shutdown(&publisher).await?;
    ManagedResource::shutdown(&publisher).await?;
    Ok(())
}
