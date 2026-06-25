//! #1171 §6 journey：`eventexec::run_consumer_ackable`（ConsumerBase 驱动）+ **真实 AMQP** broker
//! settlement 的 at-least-once 端到端——闭合 issue #1171 本体（「手工 ack runtime 兑现」）。
//!
//! 与 demo 拓扑 journey（`identity_login_audit_journey.rs`，MemBus + `run_consumer`，经 `ConsumerWorker`
//! 受监督 worker）互补：本 journey 把 `run_consumer_ackable` 接到 `AmqpSubscriber::subscribe_ackable` +
//! `AmqpAcker::settle`（→ lapin `basic_ack`/`basic_nack`），证 ConsumerBase 的 `Disposition` 终态真正驱动
//! broker settlement（at-least-once）。adapter 级 settle / requeue / crash 三场景见
//! `adapters/amqp/tests/integration.rs`；本 journey 的增量 = `run_consumer_ackable` 作为 driver 的真 broker 贯通。
//!
//! 并发形态：`run_consumer_ackable` future 持 `&DynAcker`/`&DynDeadLetterStore`（Send-非-Sync）跨 await ⇒
//! `!Send`，**与 AMQP 连接同 runtime** 经 `tokio::join!` 同任务驱动（不跨线程；`ConsumerWorker` 的专用线程
//! 驱动 + 两阶段关闭由 demo journey + eventexec 单测覆盖，真 broker 下的 worker 化随 bins 落地 #1017）。
//!
//! `#![cfg(feature = "integration")]`：broker 经 `testkit::env_or_rabbitmq()` self-provision（testcontainers，
//! #1137；设 `RSS_AMQP_TEST_URL` 则对接长存外部 broker，其 vhost 由 testkit 预建）。需 docker（容器路径）。
//! 本地运行：`cargo nextest run -p journeys --features integration`（docker 在场自起容器）。
//!
//! ref: rabbitmq docs/confirms（manual ack：basic.ack/nack + requeue 标志）
//!      lapin message::Delivery.acker（settle-once 生命周期）

#![cfg(feature = "integration")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use amqp::{AmqpPublisher, AmqpSubscriber};
use anyhow::anyhow;
use consistency::{ConsumerGroup, HandleResult};
use diport::{
    AckableSubscriber, DynDeadLetterStore, Message, MessageId, PublishRequest, Publisher, Topic,
};
use eventexec::{ConsumerMeta, run_consumer_ackable};
use futures::StreamExt;
use futures::future::BoxFuture;
use memory::{InMemClaimer, MemDeadLetterStore};
use testkit::FixtureError;
use tokio_util::sync::CancellationToken;

/// 消费 topic（subscribe_ackable 据此声明 durable queue）。
const TOPIC: &str = "rss.it.consumer-alo";
/// 去重锚点 EventId（两次发布同此 id 验幂等）。
const EVENT_ID: &str = "evt-consumer-alo";

/// `run_consumer_ackable` 驱动真实 AMQP：publish 同一 EventId 两次 → ConsumerBase 首条 Fresh（handler +
/// commit + settle Ack）、次条 Duplicate（短路 + settle Ack）→ handler 恰一次 + 两条均 broker Ack（队列空）。
#[tokio::test(flavor = "multi_thread")]
async fn run_consumer_ackable_drives_amqp_at_least_once() -> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_consumer_alo").await?;
    let topic = Topic::new(TOPIC);

    // 先订阅（声明 durable queue，token 与 stream 同源），再发布——run_consumer_ackable 与连接同 runtime。
    let sub = AmqpSubscriber::connect(&url, "alo-sub").await?;
    let token = CancellationToken::new();
    let stream = sub.subscribe_ackable(topic.clone(), token.clone()).await?;
    let publisher = AmqpPublisher::connect(&url, "alo-pub").await?;

    // 消费侧：InMemClaimer 幂等 + MemDeadLetterStore；handler 记录被消费的 message id（计数 + 内容）。
    let group =
        ConsumerGroup::parse("audit.consumer-alo").map_err(|_| anyhow!("consumer group parse"))?;
    let claimer = Arc::new(InMemClaimer::new(group));
    let consumed = Arc::new(Mutex::new(Vec::<String>::new()));
    let consumed_for_handler = consumed.clone();
    let handler = move |message: Message| -> BoxFuture<'static, HandleResult> {
        let consumed = consumed_for_handler.clone();
        Box::pin(async move {
            consumed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(message.id.as_str().to_string());
            HandleResult::ack()
        })
    };
    let meta = ConsumerMeta::new("audit", TOPIC, TOPIC);

    let drive = async {
        // 同一 EventId 发两次（模拟 broker 重投 / 生产重复）：次条经 ConsumerBase 幂等 Duplicate 短路。
        for _ in 0..2 {
            publisher
                .publish(PublishRequest {
                    topic: topic.clone(),
                    event_id: MessageId::new(EVENT_ID),
                    payload: b"alo-payload".to_vec(),
                })
                .await?;
        }
        // 等首条被 handler 消费（broker 投递 + run_consumer_ackable 驱动）。
        tokio::time::timeout(Duration::from_secs(10), async {
            while consumed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| anyhow!("timeout waiting for first consume"))?;
        // 等次条被消费并去重短路 + 两条均 settle Ack 落 broker。
        tokio::time::sleep(Duration::from_millis(500)).await;
        token.cancel();
        anyhow::Ok(())
    };

    // !Send consume future 与 drive 同任务并发（与 AMQP 连接同 runtime）。
    let (_, driven) = tokio::join!(
        run_consumer_ackable(
            stream,
            claimer,
            DynDeadLetterStore::new_box(MemDeadLetterStore::new()),
            meta,
            handler,
        ),
        drive,
    );
    driven?;
    AckableSubscriber::shutdown(&sub).await?;

    // ConsumerBase 幂等：handler 恰一次（次条同 EventId 被 Duplicate 短路）。
    {
        let c = consumed.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            c.len(),
            1,
            "同 EventId 重投经 ConsumerBase 幂等仅消费一次: {c:?}"
        );
        assert_eq!(
            c[0], EVENT_ID,
            "消费的 message id = EventId（broker message_id 贯穿）"
        );
    }

    // at-least-once Ack 兑现：两条投递均被 run_consumer_ackable settle(Ack)（首条 handler-Ack、次条
    // Duplicate-Ack）→ broker 队列空。新 consumer 在超时内无投递（证 settle 真落 broker，非仅本地状态机）。
    let sub2 = AmqpSubscriber::connect(&url, "alo-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let leftover = tokio::time::timeout(Duration::from_secs(2), stream2.next()).await;
    assert!(
        leftover.is_err(),
        "两条投递均被 run_consumer_ackable Ack，队列应空（broker settlement 兑现）"
    );

    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}
