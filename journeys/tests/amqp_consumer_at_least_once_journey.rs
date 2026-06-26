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
use bootstrap::replaydeps::resolve;
use bootstrap::{IdempotencyConfig, ResolvedIdempotency, Topology};
use consistency::{ConsumerGroup, HandleResult};
use diport::{
    AckableSubscriber, DynDeadLetterStore, Message, MessageId, PublishRequest, Publisher, Topic,
};
use eventexec::{ConsumerMeta, LeaseConfig, run_consumer_ackable};
use futures::StreamExt;
use futures::future::BoxFuture;
use memory::{InMemClaimer, MemDeadLetterStore};
use testkit::FixtureError;
use tokio_util::sync::CancellationToken;

/// 消费 topic（subscribe_ackable 据此声明 durable queue）。
const TOPIC: &str = "rss.it.consumer-alo";
/// 去重锚点 EventId（两次发布同此 id 验幂等）。
const EVENT_ID: &str = "evt-consumer-alo";

/// dev-root 决策绑定构造 demo in-mem claimer（TOPO-INMEM-SEAL-01 dev-root discipline）：经
/// `bootstrap::replaydeps::resolve(Topology::Demo, ..)` 决策臂构造，**不**直接 raw-new——把 in-mem 构造收束到
/// 已校验的拓扑决策（review #274 F6/C6：本 AMQP journey 原直接 `InMemClaimer::new` 旁路了 resolve 决策绑定）。
fn demo_claimer(group: ConsumerGroup) -> anyhow::Result<InMemClaimer> {
    match resolve(Topology::Demo, IdempotencyConfig::default())? {
        ResolvedIdempotency::Demo => Ok(InMemClaimer::new(group)),
        other => Err(anyhow!(
            "demo journey 须解析为 Demo 幂等决策，实得 {other:?}"
        )),
    }
}

/// `run_consumer_ackable` 消费一条真 broker 消息并 settle Ack（at-least-once 终态兑现）。
///
/// 发布单条消息 → ConsumerBase Fresh（handler + commit + settle Ack）→ broker 队列空
/// （新 consumer 超时无投递，证 settle Ack 真落 broker）。
/// 幂等去重由 demo journey（`identity_login_audit_journey.rs` `relay_redelivery_audits_once`）
/// + `consumer.rs` 单测覆盖；本 journey 聚焦 broker settlement 贯通。
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

    // 消费侧：InMemClaimer 幂等 + MemDeadLetterStore；handler 记录被消费的 message id。
    let group =
        ConsumerGroup::parse("audit.consumer-alo").map_err(|_| anyhow!("consumer group parse"))?;
    // 决策绑定（F6/C6）：经 resolve(Topology::Demo) 决策臂构造 in-mem claimer，不直接 raw-new。
    let claimer = Arc::new(demo_claimer(group)?);
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
        // 发布单条消息。
        publisher
            .publish(PublishRequest::new(
                topic.clone(),
                MessageId::new(EVENT_ID),
                b"alo-payload".to_vec(),
            ))
            .await?;
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
        .map_err(|_| anyhow!("timeout waiting for consume"))?;
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
            // reason: demo InMemClaimer 无后端 TTL；占位续租间隔（生产 wiring 用 store.lease_ttl() 派生，#1213 review #3）。
            LeaseConfig::from_ttl(std::time::Duration::from_secs(60)),
        ),
        drive,
    );
    driven?;
    AckableSubscriber::shutdown(&sub).await?;

    // 单条消费断言。
    {
        let c = consumed.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(c.len(), 1, "一条消息被消费: {c:?}");
        assert_eq!(
            c[0], EVENT_ID,
            "消费的 message id = EventId（broker message_id 贯穿）"
        );
    }

    // at-least-once Ack 兑现：消息被 run_consumer_ackable settle(Ack) → broker 队列空。
    // 新 consumer 超时无投递（证 settle 真落 broker，非仅本地状态机）。
    let sub2 = AmqpSubscriber::connect(&url, "alo-sub2").await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2
        .subscribe_ackable(topic.clone(), token2.clone())
        .await?;
    let leftover = tokio::time::timeout(Duration::from_secs(2), stream2.next()).await;
    assert!(
        leftover.is_err(),
        "消息被 run_consumer_ackable Ack，队列应空（broker settlement 兑现）"
    );

    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}
