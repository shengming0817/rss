//! amqp adapter 集成测试——publish→subscribe 闭环 / 同-vhost topic 隔离 / 跨-vhost 隔离 / 凭据不进错误面 /
//! 取消终止流。
//!
//! `#![cfg(feature = "integration")]`：默认 build / `cargo xtask verify` 不编译本文件。
//! broker 经 `testkit::env_or_rabbitmq()` self-provision（testcontainers，#1137）——无需手工预置、不再 `#[ignore]`；
//! 设 `RSS_AMQP_TEST_URL` 则对接长存外部 broker（其 vhost 须预建）。需 docker（容器路径）。
//! 连不上即失败（fail-loud）。测试名 `integration_` 前缀 → nextest 串行 group（`test(/integration/)`）。
//! 本地：`cargo nextest run -p amqp --features integration`（docker 在场自起容器）。
#![cfg(feature = "integration")]

use std::time::Duration;

use amqp::{AmqpPublisher, AmqpSubscriber};
use anyhow::anyhow;
use diport::{MessageId, PublishRequest, Publisher, Subscriber, Topic};
use futures::StreamExt;
use testkit::FixtureError;
use tokio_util::sync::CancellationToken;

/// 连接失败：错误面安全（Display 是常量，无 URL/凭据）+ source 保留。**无需 broker**（连不可达端口）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn integration_connect_failure_returns_safe_error() {
    // 不可达端口（连接拒绝）；URL 含凭据，断言不泄进错误 Display（AmqpPublisher 不 derive Debug，故 match）。
    match AmqpPublisher::connect("amqp://user:secretpass@127.0.0.1:1/%2f", "amqp-it").await {
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
                std::error::Error::source(&err).is_some(),
                "lapin error preserved as internal source"
            );
        }
    }
}

/// publish → subscribe 闭环：同 vhost / 同 topic，subscriber 收到 publisher 发的 payload。
#[tokio::test(flavor = "multi_thread")]
async fn integration_publish_subscribe_roundtrip() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_roundtrip").await?;
    let topic = Topic::new("rss.it.roundtrip");
    let token = CancellationToken::new();

    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub").await?;
    // 订阅须先于发布（先声明 queue + consumer）。
    let mut stream = subscriber.subscribe(topic.clone(), token.clone()).await?;

    let publisher = AmqpPublisher::connect(&url, "amqp-it-pub").await?;
    publisher
        .publish(PublishRequest {
            topic,
            event_id: MessageId::new("evt-amqp-1"),
            payload: b"hello-amqp".to_vec(),
        })
        .await?;

    // 有界等待，防 broker 异常时挂死。
    let msg = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("stream closed without yielding a message"))?;
    assert_eq!(msg.payload, b"hello-amqp".to_vec());
    // EventId 跨 broker 传播：message_id 经 envelope 流回 Message.id（消费侧幂等键源）。
    assert_eq!(
        msg.id.as_str(),
        "evt-amqp-1",
        "event_id 应经 broker message_id 传播到 Message.id"
    );

    token.cancel();
    publisher.shutdown().await?;
    subscriber.shutdown().await?;
    Ok(())
}

/// 同-vhost topic 隔离：订 A + B 两条流，发到 B → **B 收到、A 在超时内无投递**（同 vhost 内 routing 隔离，
/// review F8）。跨 **domain** 的硬隔离 seam 是 per-domain vhost——见 `integration_cross_vhost_isolation`。
#[tokio::test(flavor = "multi_thread")]
async fn integration_topic_isolation_same_vhost() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_topic_iso").await?;
    let token = CancellationToken::new();
    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub").await?;
    let mut stream_a = subscriber
        .subscribe(Topic::new("rss.it.iso-a"), token.clone())
        .await?;
    let mut stream_b = subscriber
        .subscribe(Topic::new("rss.it.iso-b"), token.clone())
        .await?;

    let publisher = AmqpPublisher::connect(&url, "amqp-it-pub").await?;
    publisher
        .publish(PublishRequest {
            topic: Topic::new("rss.it.iso-b"),
            event_id: MessageId::new("evt-iso-b"),
            payload: b"to-b".to_vec(),
        })
        .await?;

    // 正向：B 收到该消息。
    let msg_b = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
        .await?
        .ok_or_else(|| anyhow!("b stream closed without a message"))?;
    assert_eq!(msg_b.payload, b"to-b".to_vec());
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

/// 跨-vhost 隔离（per-domain vhost 硬命名空间边界，#1137）：同容器建两个 vhost，发到 vhost-a → vhost-a
/// 订阅者收到、vhost-b 订阅者在超时内无投递（vhost 是 AMQP 硬边界，跨 vhost 不路由）。这是跨域真隔离 seam。
#[tokio::test(flavor = "multi_thread")]
async fn integration_cross_vhost_isolation() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url_a = rmq.vhost_url("rss_vhost_a").await?;
    let url_b = rmq.vhost_url("rss_vhost_b").await?;
    let topic = Topic::new("rss.it.crossvhost");
    let token = CancellationToken::new();

    // 同 topic 名，分属两 vhost：vhost-a 订阅者 + vhost-b 订阅者。
    let sub_a = AmqpSubscriber::connect(&url_a, "xvhost-sub-a").await?;
    let mut stream_a = sub_a.subscribe(topic.clone(), token.clone()).await?;
    let sub_b = AmqpSubscriber::connect(&url_b, "xvhost-sub-b").await?;
    let mut stream_b = sub_b.subscribe(topic.clone(), token.clone()).await?;

    // 发到 vhost-a。
    let pub_a = AmqpPublisher::connect(&url_a, "xvhost-pub-a").await?;
    pub_a
        .publish(PublishRequest {
            topic: topic.clone(),
            event_id: MessageId::new("evt-xvhost-a"),
            payload: b"only-a".to_vec(),
        })
        .await?;

    // 正向：vhost-a 订阅者收到。
    let msg_a = tokio::time::timeout(Duration::from_secs(5), stream_a.next())
        .await?
        .ok_or_else(|| anyhow!("vhost-a stream closed without a message"))?;
    assert_eq!(msg_a.payload, b"only-a".to_vec());
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

/// 取消即流终止（take_until token + basic_cancel）。
/// cancel 后流须在超时内关闭（有界等待，防 broker 异常时挂死——对齐其他 broker 断言）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_cancel_terminates_stream() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_cancel").await?;
    let token = CancellationToken::new();
    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub").await?;
    let mut stream = subscriber
        .subscribe(Topic::new("rss.it.cancel"), token.clone())
        .await?;
    token.cancel();
    let ended = tokio::time::timeout(Duration::from_secs(5), stream.next()).await?;
    assert!(ended.is_none(), "cancel 后流须在超时内终止（Ok(None)）");
    Ok(())
}
