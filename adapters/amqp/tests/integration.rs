//! amqp adapter 集成测试——publish→subscribe 闭环 / 队列隔离 / 凭据不进错误面 / 取消终止流。
//!
//! `#![cfg(feature = "integration")]`：默认 build / `cargo xtask verify` 不编译本文件。
//! 对接真实 broker 的用例标 `#[ignore]`（默认不跑、计为 ignored 非 green-pass）；一旦显式 `--ignored`
//! 调起就**必须**设 `RSS_AMQP_TEST_URL`，否则 **fail-closed**（panic，非静默 skip——杜绝无 broker 假绿，
//! review F5）。本 PR 不引 testcontainers（自动起容器的必跑 CI lane = follow-up，需 docker/CI 基建）。本地：
//! `docker run -p 5672:5672 rabbitmq:3` + `RSS_AMQP_TEST_URL=... cargo test -p amqp --features integration -- --ignored`。
#![cfg(feature = "integration")]

use amqp::{AmqpPublisher, AmqpSubscriber};
use diport::{PublishRequest, Publisher, Subscriber, Topic};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

/// 取真实 broker URL；缺 `RSS_AMQP_TEST_URL` 即 **panic（fail-closed）**——`#[ignore]` broker 用例被显式
/// `--ignored` 调起即是要验真实 broker 行为，无 broker 配置必须失败、不得静默跳过（review F5）。
#[allow(clippy::expect_used)] // fail-closed 前置条件断言：item-level carve-out（workspace lints 约定）
fn broker_url() -> String {
    std::env::var("RSS_AMQP_TEST_URL")
        .expect("RSS_AMQP_TEST_URL must be set to run #[ignore] amqp broker integration tests")
}

/// 连接失败：错误面安全（Display 是常量，无 URL/凭据）+ source 保留。无需 broker。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn connect_failure_returns_safe_error() {
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
/// `#[ignore]`：需真实 broker——默认 `cargo test --features integration` 标 **ignored**（非 green-pass，
/// 杜绝假绿，review F5）；显式 `--ignored` + `RSS_AMQP_TEST_URL` 才跑（testcontainers CI lane = follow-up）。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires RSS_AMQP_TEST_URL + a running RabbitMQ broker"]
#[allow(clippy::expect_used)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn publish_subscribe_roundtrip() {
    let url = broker_url();
    let topic = Topic::new("rss.it.roundtrip");
    let token = CancellationToken::new();

    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub")
        .await
        .expect("subscriber connect");
    // 订阅须先于发布（先声明 queue + consumer）。
    let mut stream = subscriber
        .subscribe(topic.clone(), token.clone())
        .await
        .expect("subscribe");

    let publisher = AmqpPublisher::connect(&url, "amqp-it-pub")
        .await
        .expect("publisher connect");
    publisher
        .publish(PublishRequest {
            topic,
            payload: b"hello-amqp".to_vec(),
        })
        .await
        .expect("publish");

    // 有界等待，防 broker 异常时挂死。
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("delivery within timeout")
        .expect("stream yielded a message");
    assert_eq!(msg.payload, b"hello-amqp".to_vec());

    token.cancel();
    publisher.shutdown().await.expect("publisher shutdown");
    subscriber.shutdown().await.expect("subscriber shutdown");
}

/// topic 隔离：订 A + B 两条流，发到 B → **B 收到、A 在超时内无投递**（真正证明隔离，而非仅取消终止，
/// review F8）。A/B 各自 queue（B 已声明 ⇒ mandatory publish 可路由）。
/// 注：跨 **domain** 的真隔离 seam 是 per-domain vhost/credential（独立 URL）；此处验同 vhost 内 routing 隔离。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires RSS_AMQP_TEST_URL + a running RabbitMQ broker"]
#[allow(clippy::expect_used)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn topic_b_not_delivered_to_a() {
    let url = broker_url();
    let token = CancellationToken::new();
    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub")
        .await
        .expect("subscriber connect");
    let mut stream_a = subscriber
        .subscribe(Topic::new("rss.it.iso-a"), token.clone())
        .await
        .expect("subscribe a");
    let mut stream_b = subscriber
        .subscribe(Topic::new("rss.it.iso-b"), token.clone())
        .await
        .expect("subscribe b");

    let publisher = AmqpPublisher::connect(&url, "amqp-it-pub")
        .await
        .expect("publisher connect");
    publisher
        .publish(PublishRequest {
            topic: Topic::new("rss.it.iso-b"),
            payload: b"to-b".to_vec(),
        })
        .await
        .expect("publish b");

    // 正向：B 收到该消息。
    let msg_b = tokio::time::timeout(std::time::Duration::from_secs(5), stream_b.next())
        .await
        .expect("b delivery within timeout")
        .expect("b stream yielded a message");
    assert_eq!(msg_b.payload, b"to-b".to_vec());
    // 负向：A 在短超时内无投递（隔离——B 的消息没串到 A）。timeout Err = 无消息。
    let a_result =
        tokio::time::timeout(std::time::Duration::from_millis(500), stream_a.next()).await;
    assert!(
        a_result.is_err(),
        "topic A must not receive topic B's message"
    );

    token.cancel();
}

/// 取消即流终止（take_until token + basic_cancel）。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires RSS_AMQP_TEST_URL + a running RabbitMQ broker"]
#[allow(clippy::expect_used)] // 集成测试断言：item-level carve-out（workspace lints 约定）
async fn cancel_terminates_stream() {
    let url = broker_url();
    let token = CancellationToken::new();
    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub")
        .await
        .expect("subscriber connect");
    let mut stream = subscriber
        .subscribe(Topic::new("rss.it.cancel"), token.clone())
        .await
        .expect("subscribe");
    token.cancel();
    assert!(stream.next().await.is_none());
}
