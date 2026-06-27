//! mqtt adapter 集成测试——connect 失败错误面安全 / publish→subscribe 闭环（含 event_id 经
//! correlation_data 传播）/ 同连接 topic 隔离 / 取消终止流。
//!
//! `#![cfg(feature = "integration")]`：默认 build / `cargo xtask verify` 不编译本文件。
//! broker 经 `testkit::env_or_mosquitto()` self-provision（testcontainers eclipse-mosquitto，#1137）——
//! 无需手工预置；设 `RSS_MQTT_TEST_URL` 则对接长存外部 broker。需 docker（容器路径）；连不上即失败（fail-loud）。
//! 测试名 `integration_` 前缀 → nextest 串行 group（`test(/integration/)`）。
//! 本地：`cargo nextest run -p mqtt --features integration`（docker 在场自起容器）。
//! 注：`integration_connect_failure_returns_safe_error` 连不可达端口，**无需 broker / docker**。
#![cfg(feature = "integration")]

use std::time::Duration;

use anyhow::anyhow;
use diport::{
    EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_SUBJECT_ID, MessageId, PublishRequest,
    Publisher, Subscriber, Topic,
};
use futures::StreamExt;
use mqtt::{MqttPublisher, MqttSubscriber};
use testkit::FixtureError;
use tokio_util::sync::CancellationToken;

/// 明文 mqtt:// 携凭据 fail-closed（F4）：错误面安全（Display 常量，不泄 user:pass）。**无需 broker**。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn integration_plaintext_credentials_rejected_safely() {
    // 明文 URL 含凭据 → fail-closed 拒绝（凭据须 mqtts://）；断言不泄进错误 Display/Debug（手写 Debug）。
    match MqttPublisher::connect("mqtt://user:secretpass@127.0.0.1:1", "mqtt-it").await {
        Ok(_) => panic!("plaintext mqtt:// with credentials must be rejected"),
        Err(err) => {
            assert_eq!(err.to_string(), "mqtt connect failed");
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
                "url error preserved as internal source"
            );
        }
    }
}

/// 连接失败（不可达端口，无凭据）：错误面安全（Display 常量）+ source 保留。**无需 broker**。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn integration_connect_failure_returns_safe_error() {
    match MqttPublisher::connect("mqtt://127.0.0.1:1", "mqtt-it").await {
        Ok(_) => panic!("connect to closed port must fail"),
        Err(err) => {
            assert_eq!(err.to_string(), "mqtt connect failed");
            assert!(
                std::error::Error::source(&err).is_some(),
                "rumqttc error preserved as internal source"
            );
        }
    }
}

/// publish → subscribe 闭环：subscriber 收到 publisher 发的 payload，且 event_id 经 v5 correlation_data
/// 传播回 `Message.id`（跨进程幂等键源）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_publish_subscribe_roundtrip() -> Result<(), FixtureError> {
    let broker = testkit::env_or_mosquitto().await?;
    let url = broker.url();
    let topic = Topic::new("rss/it/roundtrip");
    let token = CancellationToken::new();

    let subscriber = MqttSubscriber::connect(url, "mqtt-it-sub").await?;
    // 订阅须先于发布（先 SUBACK 再 publish，否则 broker 不投递历史消息）。
    let mut stream = subscriber.subscribe(topic.clone(), token.clone()).await?;

    let publisher = MqttPublisher::connect(url, "mqtt-it-pub").await?;
    publisher
        .publish(PublishRequest::new(
            topic,
            MessageId::new("evt-mqtt-1"),
            b"hello-mqtt".to_vec(),
        ))
        .await?;

    // 有界等待，防 broker 异常时挂死。
    let msg = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("stream closed without yielding a message"))?;
    assert_eq!(msg.payload.as_bytes(), b"hello-mqtt");
    // event_id 跨 broker 传播：correlation_data 经 envelope 流回 Message.id（消费侧幂等键源）。
    assert_eq!(
        msg.id.as_str(),
        "evt-mqtt-1",
        "event_id 应经 broker correlation_data 传播到 Message.id"
    );

    token.cancel();
    publisher.shutdown().await?;
    subscriber.shutdown().await?;
    Ok(())
}

/// 同连接 topic 隔离：订 A + B 两条流，发到 B → **B 收到、A 在超时内无投递**（精确 topic 路由隔离）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_topic_isolation_same_connection() -> Result<(), FixtureError> {
    let broker = testkit::env_or_mosquitto().await?;
    let url = broker.url();
    let token = CancellationToken::new();
    let subscriber = MqttSubscriber::connect(url, "mqtt-it-sub").await?;
    let mut stream_a = subscriber
        .subscribe(Topic::new("rss/it/iso-a"), token.clone())
        .await?;
    let mut stream_b = subscriber
        .subscribe(Topic::new("rss/it/iso-b"), token.clone())
        .await?;

    let publisher = MqttPublisher::connect(url, "mqtt-it-pub").await?;
    publisher
        .publish(PublishRequest::new(
            Topic::new("rss/it/iso-b"),
            MessageId::new("evt-iso-b"),
            b"to-b".to_vec(),
        ))
        .await?;

    // 正向：B 收到该消息。
    let msg_b = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
        .await?
        .ok_or_else(|| anyhow!("b stream closed without a message"))?;
    assert_eq!(msg_b.payload.as_bytes(), b"to-b");
    // 负向：A 在短超时内无投递（精确 topic 路由——B 的消息没串到 A）。timeout Err = 无消息。
    let a_result = tokio::time::timeout(Duration::from_secs(1), stream_a.next()).await;
    assert!(
        a_result.is_err(),
        "topic A must not receive topic B's message"
    );

    token.cancel();
    publisher.shutdown().await?;
    subscriber.shutdown().await?;
    Ok(())
}

/// 取消即流终止（take_until token + unsubscribe）。cancel 后流须在超时内关闭（有界等待，防挂死）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_cancel_terminates_stream() -> Result<(), FixtureError> {
    let broker = testkit::env_or_mosquitto().await?;
    let url = broker.url();
    let token = CancellationToken::new();
    let subscriber = MqttSubscriber::connect(url, "mqtt-it-sub").await?;
    let mut stream = subscriber
        .subscribe(Topic::new("rss/it/cancel"), token.clone())
        .await?;
    token.cancel();
    let ended = tokio::time::timeout(Duration::from_secs(5), stream.next()).await?;
    assert!(ended.is_none(), "cancel 后流须在超时内终止（Ok(None)）");
    subscriber.shutdown().await?;
    Ok(())
}

/// envelope user_properties 双向贯通：publish 携 occurred_at + subjectId + correlation →
/// subscriber 端 `Message.metadata` 保真（MQTT v5 user_properties 透传验证）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_envelope_header_roundtrip() -> Result<(), FixtureError> {
    let broker = testkit::env_or_mosquitto().await?;
    let url = broker.url();
    let topic = Topic::new("rss/it/envelope-user-props");
    let token = CancellationToken::new();

    let subscriber = MqttSubscriber::connect(url, "mqtt-it-env-sub").await?;
    let mut stream = subscriber.subscribe(topic.clone(), token.clone()).await?;

    let publisher = MqttPublisher::connect(url, "mqtt-it-env-pub").await?;

    // 构造携 envelope metadata 的 PublishRequest。
    let mut md = EnvelopeMetadata::empty();
    md.insert_wire_pair(KEY_OCCURRED_AT, "1700000002");
    md.insert_wire_pair(KEY_CORRELATION, "corr-mqtt-7");
    md.insert_wire_pair(KEY_SUBJECT_ID, "user-mqtt-1");

    publisher
        .publish(
            PublishRequest::new(
                topic,
                MessageId::new("evt-env-mqtt-1"),
                b"mqtt-env-payload".to_vec(),
            )
            .with_metadata(md),
        )
        .await?;

    let msg = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("stream closed without yielding a message"))?;

    // metadata 保真验证。
    assert_eq!(
        msg.metadata.occurred_at_secs(),
        Some(1_700_000_002_i64),
        "occurred_at 应经 MQTT user_properties 透传"
    );
    assert_eq!(
        msg.metadata.get(KEY_CORRELATION),
        Some("corr-mqtt-7"),
        "correlation 应经 MQTT user_properties 透传"
    );
    assert_eq!(
        msg.metadata.get(KEY_SUBJECT_ID),
        Some("user-mqtt-1"),
        "subjectId 应经 MQTT user_properties 透传"
    );

    token.cancel();
    publisher.shutdown().await?;
    subscriber.shutdown().await?;
    Ok(())
}
