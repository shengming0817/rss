//! amqp adapter 集成测试——publish→subscribe 闭环 / 同-vhost topic 隔离 / 跨-vhost 隔离 / 凭据不进错误面 /
//! 取消终止流 / **at-least-once**（manual-ack ack/requeue/崩溃重投三 case）。
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
use diport::{AckAction, AckableSubscriber, Acker, MessageId, PublishRequest, Publisher, Topic};
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
/// 使用 `subscribe_ackable`（at-least-once）——AMQP 唯一投递路径（Durable 拓扑）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_publish_subscribe_roundtrip() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_roundtrip").await?;
    let topic = Topic::new("rss.it.roundtrip");
    let token = CancellationToken::new();

    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub").await?;
    // 订阅须先于发布（先声明 queue + consumer）。
    let mut stream = subscriber
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;

    let publisher = AmqpPublisher::connect(&url, "amqp-it-pub").await?;
    publisher
        .publish(PublishRequest {
            topic,
            event_id: MessageId::new("evt-amqp-1"),
            payload: b"hello-amqp".to_vec(),
        })
        .await?;

    // 有界等待，防 broker 异常时挂死。
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("stream closed without yielding a message"))?;
    assert_eq!(delivery.message.payload, b"hello-amqp".to_vec());
    // EventId 跨 broker 传播：message_id 经 envelope 流回 Message.id（消费侧幂等键源）。
    assert_eq!(
        delivery.message.id.as_str(),
        "evt-amqp-1",
        "event_id 应经 broker message_id 传播到 Message.id"
    );

    token.cancel();
    Publisher::shutdown(&publisher).await?;
    AckableSubscriber::shutdown(&subscriber).await?;
    Ok(())
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
    let publisher = AmqpPublisher::connect(&url, "amqp-it-unroutable").await?;
    match publisher
        .publish(PublishRequest {
            topic: Topic::new("rss.it.no.queue.bound"),
            event_id: MessageId::new("evt-unroutable-1"),
            payload: b"orphan".to_vec(),
        })
        .await
    {
        Ok(()) => panic!("publish to unbound queue must fail (mandatory return)"),
        Err(err) => assert!(
            err.is_transient(),
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
    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub").await?;
    let mut stream_a = subscriber
        .subscribe_ackable(Topic::new("rss.it.iso-a"), token.clone())
        .await?;
    let mut stream_b = subscriber
        .subscribe_ackable(Topic::new("rss.it.iso-b"), token.clone())
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
    let delivery_b = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
        .await?
        .ok_or_else(|| anyhow!("b stream closed without a message"))?;
    assert_eq!(delivery_b.message.payload, b"to-b".to_vec());
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
/// 流 B **仍能收到**后续发到 B 的消息——取消单订阅只关本订阅 channel，不连带关闭共享 channel 停掉其它 topic
/// consumer（review #274 F4：原 `self.channel` 共享，任一 cancel 关 channel 会连带终止同实例其它订阅）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_per_subscription_cancel_does_not_stop_others() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_persub_cancel").await?;
    let token_a = CancellationToken::new();
    let token_b = CancellationToken::new();
    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-persub").await?;
    let mut stream_a = subscriber
        .subscribe_ackable(Topic::new("rss.it.persub-a"), token_a.clone())
        .await?;
    let mut stream_b = subscriber
        .subscribe_ackable(Topic::new("rss.it.persub-b"), token_b.clone())
        .await?;

    // 取消 A 的 token：仅关 A 的 channel。
    token_a.cancel();
    let ended_a = tokio::time::timeout(Duration::from_secs(5), stream_a.next()).await?;
    assert!(ended_a.is_none(), "A 流取消后须终止（Ok(None)）");

    // A 取消后发到 B → B 仍能收到（B 的 channel/consumer 未被 A 的 cancel 连带关闭——回归守卫）。
    let publisher = AmqpPublisher::connect(&url, "amqp-it-persub-pub").await?;
    publisher
        .publish(PublishRequest {
            topic: Topic::new("rss.it.persub-b"),
            event_id: MessageId::new("evt-persub-b"),
            payload: b"to-b-after-a-cancel".to_vec(),
        })
        .await?;
    let delivery_b = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
        .await?
        .ok_or_else(|| anyhow!("B 流在 A 取消后关闭（回归：共享 channel 被连带关闭）"))?;
    assert_eq!(delivery_b.message.payload, b"to-b-after-a-cancel".to_vec());
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
    let sub_a = AmqpSubscriber::connect(&url_a, "xvhost-sub-a").await?;
    let mut stream_a = sub_a
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;
    let sub_b = AmqpSubscriber::connect(&url_b, "xvhost-sub-b").await?;
    let mut stream_b = sub_b
        .subscribe_ackable(topic.clone(), token.clone())
        .await?;

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
    let delivery_a = tokio::time::timeout(Duration::from_secs(5), stream_a.next())
        .await?
        .ok_or_else(|| anyhow!("vhost-a stream closed without a message"))?;
    assert_eq!(delivery_a.message.payload, b"only-a".to_vec());
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

/// 取消即流终止（take_until token + channel close）。
/// cancel 后流须在超时内关闭（有界等待，防 broker 异常时挂死——对齐其他 broker 断言）。
/// 使用 `subscribe_ackable`（at-least-once）——token cancel 触发 cancel_ackable_on_token 关 channel。
#[tokio::test(flavor = "multi_thread")]
async fn integration_cancel_terminates_stream() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_cancel").await?;
    let token = CancellationToken::new();
    let subscriber = AmqpSubscriber::connect(&url, "amqp-it-sub").await?;
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
    let sub1 = AmqpSubscriber::connect(&url, "amqp-it-ack-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = AmqpPublisher::connect(&url, "amqp-it-ack-pub").await?;
    publisher
        .publish(PublishRequest {
            topic: topic.clone(),
            event_id: MessageId::new("evt-ack-a"),
            payload: b"ack-payload".to_vec(),
        })
        .await?;

    // 收到一条投递，ack 结算。
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for ackable delivery"))?
        .ok_or_else(|| anyhow!("stream closed without delivery"))?;
    assert_eq!(delivery.message.payload, b"ack-payload".to_vec());
    delivery
        .acker
        .settle(AckAction::Ack)
        .await
        .map_err(|e| anyhow!("settle failed: {e}"))?;

    // 关闭第一个 consumer。
    token1.cancel();
    AckableSubscriber::shutdown(&sub1).await?;

    // 重新订阅——broker 已 ack 移除，新 consumer 在超时内无投递。
    let sub2 = AmqpSubscriber::connect(&url, "amqp-it-ack-sub2").await?;
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

    let sub1 = AmqpSubscriber::connect(&url, "amqp-it-rq-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = AmqpPublisher::connect(&url, "amqp-it-rq-pub").await?;
    publisher
        .publish(PublishRequest {
            topic: topic.clone(),
            event_id: MessageId::new("evt-requeue-b"),
            payload: b"requeue-payload".to_vec(),
        })
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
    let sub2 = AmqpSubscriber::connect(&url, "amqp-it-rq-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for redelivery"))?
        .ok_or_else(|| anyhow!("redelivery stream closed without message"))?;
    assert_eq!(redelivery.message.payload, b"requeue-payload".to_vec());
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

/// (c) at-least-once 核心：consume 一条后**不 settle，直接 drop 流 / 断 channel**（模拟消费者崩溃）→
/// 新 consumer 能再次收到该消息（未 ack 的在途消息 broker channel-close 后自动 requeue）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_crash_without_settle_redelivers() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_c").await?;
    let topic = Topic::new("rss.it.ack-c");

    // 第一个 consumer：收到消息但不 settle，然后 shutdown channel（模拟崩溃）。
    let sub1 = AmqpSubscriber::connect(&url, "amqp-it-crash-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = AmqpPublisher::connect(&url, "amqp-it-crash-pub").await?;
    publisher
        .publish(PublishRequest {
            topic: topic.clone(),
            event_id: MessageId::new("evt-crash-c"),
            payload: b"crash-payload".to_vec(),
        })
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
    let sub2 = AmqpSubscriber::connect(&url, "amqp-it-crash-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for crash-redelivery (at-least-once)"))?
        .ok_or_else(|| anyhow!("crash-redelivery stream closed without message"))?;
    assert_eq!(redelivery.message.payload, b"crash-payload".to_vec());
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

/// (d) F2/C2：**token cancel（非 shutdown）** 后，未 settle 的 in-flight 投递经 `cancel_ackable_on_token`
/// 关 channel 被 broker 自动 requeue → 新 consumer 能再次收到。守 ackable 取消语义（区别于 auto-ack 仅 basic_cancel）。
#[tokio::test(flavor = "multi_thread")]
async fn integration_ackable_token_cancel_requeues_inflight() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_ack_d").await?;
    let topic = Topic::new("rss.it.ack-d");

    let sub1 = AmqpSubscriber::connect(&url, "amqp-it-cancel-sub1").await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;

    let publisher = AmqpPublisher::connect(&url, "amqp-it-cancel-pub").await?;
    publisher
        .publish(PublishRequest {
            topic: topic.clone(),
            event_id: MessageId::new("evt-cancel-d"),
            payload: b"cancel-payload".to_vec(),
        })
        .await?;

    // 收到投递但**不 settle**，然后仅 token cancel（不 shutdown）——触发 cancel_ackable_on_token 关 channel。
    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for delivery"))?
        .ok_or_else(|| anyhow!("stream closed"))?;
    let _unsettled = delivery.acker; // 故意不 settle（in-flight unacked）
    token1.cancel();
    let ended = tokio::time::timeout(Duration::from_secs(5), stream1.next()).await?;
    assert!(ended.is_none(), "token cancel 后 ackable 流应终止");

    // 新 consumer：未 settle 的 in-flight 已被 channel close requeue，应能再次收到（取消即可重投）。
    let sub2 = AmqpSubscriber::connect(&url, "amqp-it-cancel-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .map_err(|_| anyhow!("timeout waiting for token-cancel redelivery"))?
        .ok_or_else(|| anyhow!("token-cancel redelivery stream closed"))?;
    assert_eq!(redelivery.message.payload, b"cancel-payload".to_vec());
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
