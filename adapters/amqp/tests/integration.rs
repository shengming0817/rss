//! amqp adapter 集成测试——publish→subscribe 闭环 / 同-vhost topic 隔离 / 跨-vhost 隔离 / 凭据不进错误面 /
//! broker-confirmed 取消终止流 / **at-least-once**（manual-ack ack/requeue/崩溃重投）。
//!
//! Cargo `[[test]] required-features = ["integration"]` 是 eligibility 唯一 owner；默认 build / `cargo xtask verify` 不编译本 target。
//! broker 经 `testkit::env_or_rabbitmq()` self-provision（testcontainers，#1137）——无需手工预置、不再 `#[ignore]`；
//! 设 `RSS_AMQP_TEST_URL` 则对接长存外部 broker（其 vhost 须预建）。需 docker（容器路径）。
//! 连不上即失败（fail-loud）。测试名 `integration_` 前缀 → nextest 串行 group（`test(/integration/)`）。
//! 本地：`cargo nextest run -p amqp --features integration`（docker 在场自起容器）。
use std::time::Duration;

use amqp::{
    AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint, AmqpRuntimeDeps, AmqpSubscriber,
    AmqpSubscriberEndpoint,
};
use anyhow::anyhow;
use diport::{
    AckAction, AckableSubscriber, Acker, EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT,
    KEY_SUBJECT_ID, ManagedResource, MessageId, PublishErrorKind, PublishRequest, Publisher, Topic,
};
use futures::StreamExt;
use testkit::FixtureError;
use tokio_util::sync::CancellationToken;

const TEST_PUBLISH_TIMEOUT: Duration = Duration::from_secs(40);

#[tokio::test(flavor = "multi_thread")]
async fn integration_explicit_private_ca_accepts_matching_broker_and_rejects_wrong_ca()
-> anyhow::Result<()> {
    let network = testkit::bridge_network("rss-amqp-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::rabbitmq_tls(
        generated::event::settings_v1::TOPIC,
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
        AmqpRuntimeDeps::connect(
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
            Topic::new(generated::event::settings_v1::TOPIC),
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
        generated::event::settings_v1::TOPIC,
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: &dns_name,
        },
    )
    .await?;
    let ca = AmqpPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?;
    let topic = Topic::new(generated::event::settings_v1::TOPIC);
    let token = CancellationToken::new();

    assert!(
        fixture.publisher_permissions_are_exact().await?,
        "publisher broker permissions must allow only the generated key on the topic exchange"
    );
    assert!(
        fixture.subscriber_permissions_are_exact().await?,
        "subscriber broker permissions must allow only configure/read on the generated queue"
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
    assert_eq!(delivery.message.payload.as_bytes(), b"acl-roundtrip");
    delivery.acker.settle(AckAction::Ack).await?;
    assert!(
        publisher
            .publish(PublishRequest::new(
                Topic::new(format!("{}.adjacent", generated::event::settings_v1::TOPIC)),
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
                Topic::new(format!("{}.adjacent", generated::event::settings_v1::TOPIC)),
                CancellationToken::new(),
            )
            .await
            .is_err(),
        "subscriber identity must not declare an adjacent queue"
    );

    token.cancel();
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
    Ok(AmqpPublisher::connect(&endpoint, name, TEST_PUBLISH_TIMEOUT).await?)
}

async fn connect_subscriber(url: &str, name: &str) -> anyhow::Result<AmqpSubscriber> {
    let endpoint = amqp_endpoint(url)?;
    Ok(AmqpSubscriber::connect(&endpoint, name).await?)
}

async fn connect_runtime_deps(url: &str, name: &str) -> anyhow::Result<AmqpRuntimeDeps> {
    let endpoint = amqp_endpoint(url)?;
    Ok(AmqpRuntimeDeps::connect(&endpoint, name, TEST_PUBLISH_TIMEOUT).await?)
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
            // 凭据 non-leak：Display 与 Debug 均不得含 user:pass（FR-020）。
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
    match AmqpPublisher::connect(&endpoint, "amqp-invalid-timeout", Duration::ZERO).await {
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
    assert_eq!(delivery_b.message.payload.as_bytes(), b"to-b");
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
        delivery_b.message.payload.as_bytes(),
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
    assert_eq!(delivery_a.message.payload.as_bytes(), b"only-a");
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
    assert_eq!(delivery.message.payload.as_bytes(), b"ack-payload");
    delivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle failed: {e}"))?;

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
    assert_eq!(redelivery.message.payload.as_bytes(), b"requeue-payload");
    // ack 清理，避免残留影响后续测试。
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
    assert_eq!(prior.message.id.as_str(), "evt-prior-run");
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
    assert_eq!(current.message.id.as_str(), "evt-current-run");
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
    assert_eq!(redelivery.message.payload.as_bytes(), b"crash-payload");
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
    assert_eq!(next_delivery.message.id.as_str(), "evt-after-cancel-d");
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
    md.insert_wire_pair(KEY_OCCURRED_AT, "1700000001");
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
        delivery.message.metadata.occurred_at_secs(),
        Some(1_700_000_001_i64),
        "occurred_at 应经 AMQP timestamp 字段透传"
    );
    assert_eq!(
        delivery.message.metadata.get(KEY_CORRELATION),
        Some("corr-42"),
        "correlation 应经 AMQP FieldTable LongString 透传"
    );
    assert_eq!(
        delivery.message.metadata.get(KEY_SUBJECT_ID),
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

/// #1498 bundle 装配出口：`AmqpRuntimeDeps::connect` 打开一个域 vhost 的 publisher + subscriber，经
/// `infra()` 派发 DI-ready port 句柄跑 publish→subscribe 闭环；`runtime_resources()` 单源派生
/// publisher-guard + subscriber-guard（各关其 connection），经 guard 关停干净收敛（D5 单源 rollback）。
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
    assert_eq!(delivery.message.payload.as_bytes(), b"hello-bundle");
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
