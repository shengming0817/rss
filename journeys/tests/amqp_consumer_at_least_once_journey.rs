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
//! 驱动 + 两阶段关闭由 demo journey + eventexec 单测覆盖，真 broker 下的 worker 化由 ManagedBlockingWorker 覆盖）。
//!
//! Cargo `[[test]] required-features = ["integration"]`：broker 经 `testkit::env_or_rabbitmq()` self-provision（testcontainers，
//! #1137；设 `RSS_AMQP_TEST_URL` 则对接长存外部 broker，其 vhost 由 testkit 预建）。需 docker（容器路径）。
//! 本地运行：`cargo nextest run -p journeys --features integration`（docker 在场自起容器）。
//!
//! ref: rabbitmq docs/confirms（manual ack：basic.ack/nack + requeue 标志）
//!      lapin message::Delivery.acker（settle-once 生命周期）

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use amqp::{AmqpPublisher, AmqpSubscriber};
use anyhow::{Context as _, anyhow};
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
use testkit::await_map;
use tokio_util::sync::CancellationToken;

/// 消费 topic（subscribe_ackable 据此声明 durable queue）。
const TOPIC: &str = "rss.it.consumer-alo";
const REJECT_TOPIC: &str = "rss.it.consumer-alo-reject";
/// 去重锚点 EventId（两次发布同此 id 验幂等）。
const EVENT_ID: &str = "evt-consumer-alo";
const TEST_PUBLISH_TIMEOUT: Duration = Duration::from_secs(40);

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

fn consumer_admission() -> anyhow::Result<primitives::ConsumerAdmission> {
    let (control, _, consumer, _) = primitives::prepare_dr_admission_controls().into_parts();
    control
        .start_running()
        .context("start AMQP journey consumer admission")?;
    Ok(consumer)
}

/// dev-root 决策绑定构造 demo in-mem claimer（TOPO-INMEM-SEAL-01 dev-root discipline）：经
/// `bootstrap::replaydeps::resolve(Topology::Demo, ..)` 决策臂构造，**不**直接 raw-new——把 in-mem 构造收束到
/// 已校验的拓扑决策（review #274 F6/C6：本 AMQP journey 原直接 `InMemClaimer::new` 旁路了 resolve 决策绑定）。
fn demo_claimer() -> anyhow::Result<InMemClaimer> {
    match resolve(Topology::Demo, IdempotencyConfig::default())? {
        ResolvedIdempotency::Demo => Ok(InMemClaimer::new()),
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
    let sub = connect_subscriber(&url, "alo-sub").await?;
    let token = CancellationToken::new();
    let stream = sub.subscribe_ackable(topic.clone(), token.clone()).await?;
    let publisher = connect_publisher(&url, "alo-pub").await?;

    // 消费侧：InMemClaimer 幂等 + MemDeadLetterStore；handler 记录被消费的 message id。
    let group =
        ConsumerGroup::parse("audit.consumer-alo").map_err(|_| anyhow!("consumer group parse"))?;
    // 决策绑定（F6/C6）：经 resolve(Topology::Demo) 决策臂构造 in-mem claimer，不直接 raw-new。
    let claimer = Arc::new(demo_claimer()?);
    let consumed = Arc::new(Mutex::new(Vec::<String>::new()));
    let consumed_for_handler = consumed.clone();
    let handler = move |message: Message| -> BoxFuture<'static, HandleResult> {
        let consumed = consumed_for_handler.clone();
        Box::pin(async move {
            consumed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(message.id().as_str().to_string());
            HandleResult::ack()
        })
    };
    let meta = ConsumerMeta::new(
        "audit",
        TOPIC.split('.').next().unwrap_or(TOPIC),
        TOPIC,
        TOPIC,
        group.as_str(),
        common::tenant_authority(),
    );

    let drive = async {
        // 发布单条消息。
        publisher
            .publish(
                PublishRequest::new(
                    topic.clone(),
                    MessageId::new(EVENT_ID),
                    b"alo-payload".to_vec(),
                )
                .with_metadata(common::signed_metadata(
                    TOPIC.split('.').next().unwrap_or(TOPIC),
                    TOPIC,
                    TOPIC,
                    EVENT_ID,
                )?),
            )
            .await?;
        // 等首条被 handler 消费（broker 投递 + run_consumer_ackable 驱动）。
        await_map(Duration::from_secs(10), async || {
            (!consumed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty())
            .then_some(())
        })
        .await
        .map_err(|_| anyhow!("timeout waiting for consume"))?;
        token.cancel();
        anyhow::Ok(())
    };

    // !Send consume future 与 drive 同任务并发（与 AMQP 连接同 runtime）。
    // Owner must outlive the join! consume future (E0597 if declared inside the block).
    let dlx = DynDeadLetterStore::new_box(MemDeadLetterStore::new());
    let admission = consumer_admission()?;
    let (_, driven) = tokio::join!(
        eventexec::run_managed_delivery_stream_harness(
            stream,
            token.child_token(),
            async |stream| {
                run_consumer_ackable(
                    stream,
                    claimer,
                    dlx.as_ref(),
                    &meta,
                    &handler,
                    // reason: demo InMemClaimer 无后端 TTL；占位续租间隔（生产 wiring 用 store.lease_ttl() 派生，#1213 review #3）。
                    LeaseConfig::from_ttl(std::time::Duration::from_secs(60)),
                    admission,
                )
                .await;
            },
        ),
        drive,
    );
    driven?;
    assert_eq!(
        sub.broker_dead_letter_depth_for_test(&topic).await?,
        0,
        "ConsumerBase Ack must not enter broker quarantine"
    );
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
    let sub2 = connect_subscriber(&url, "alo-sub2").await?;
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

/// A message without the trusted transport envelope is rejected before the handler. This is a
/// legal ConsumerBase fail-closed path and proves the complete
/// `ConsumerBase -> AmqpAcker -> RabbitMQ DLQ` settlement chain without changing the application
/// `HandleResult::reject` contract (which remains app-DLX + broker Ack).
#[tokio::test(flavor = "multi_thread")]
async fn run_consumer_ackable_quarantines_untrusted_envelope_in_broker_dlq()
-> Result<(), FixtureError> {
    let rmq = testkit::env_or_rabbitmq().await?;
    let url = rmq.vhost_url("rss_consumer_alo_reject").await?;
    let topic = Topic::new(REJECT_TOPIC);
    let sub = connect_subscriber(&url, "alo-reject-sub").await?;
    sub.purge_durable_queue_for_test(&topic).await?;
    let token = CancellationToken::new();
    let stream = sub.subscribe_ackable(topic.clone(), token.clone()).await?;
    let publisher = connect_publisher(&url, "alo-reject-pub").await?;

    let group = ConsumerGroup::parse("audit.consumer-alo-reject")
        .map_err(|_| anyhow!("consumer group parse"))?;
    let claimer = Arc::new(demo_claimer()?);
    let handler_calls = Arc::new(Mutex::new(0_u32));
    let calls_for_handler = Arc::clone(&handler_calls);
    let handler = move |_message: Message| -> BoxFuture<'static, HandleResult> {
        let calls = Arc::clone(&calls_for_handler);
        Box::pin(async move {
            *calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            HandleResult::ack()
        })
    };
    let meta = ConsumerMeta::new(
        "audit",
        REJECT_TOPIC.split('.').next().unwrap_or(REJECT_TOPIC),
        REJECT_TOPIC,
        REJECT_TOPIC,
        group.as_str(),
        common::tenant_authority(),
    );
    let drive = async {
        publisher
            .publish(PublishRequest::new(
                topic.clone(),
                MessageId::new("evt-consumer-alo-untrusted"),
                b"untrusted-envelope".to_vec(),
            ))
            .await?;
        await_map(Duration::from_secs(10), async || {
            (sub.broker_dead_letter_depth_for_test(&topic).await.ok() == Some(1)).then_some(())
        })
        .await
        .map_err(|_| anyhow!("timeout waiting for ConsumerBase broker quarantine"))?;
        token.cancel();
        anyhow::Ok(())
    };
    let dlx = DynDeadLetterStore::new_box(MemDeadLetterStore::new());
    let admission = consumer_admission()?;
    let (_, driven) = tokio::join!(
        eventexec::run_managed_delivery_stream_harness(
            stream,
            token.child_token(),
            async |stream| {
                run_consumer_ackable(
                    stream,
                    claimer,
                    dlx.as_ref(),
                    &meta,
                    &handler,
                    LeaseConfig::from_ttl(Duration::from_secs(60)),
                    admission,
                )
                .await;
            },
        ),
        drive,
    );
    driven?;
    assert_eq!(
        *handler_calls.lock().unwrap_or_else(|e| e.into_inner()),
        0,
        "untrusted envelope must be rejected before handler invocation"
    );
    let dead_letter = sub
        .take_broker_dead_letter_for_test(&topic)
        .await?
        .ok_or_else(|| anyhow!("ConsumerBase broker quarantine was empty"))?;
    assert_eq!(dead_letter.message_id(), Some("evt-consumer-alo-untrusted"));
    assert_eq!(dead_letter.death_reason(), "rejected");
    assert_eq!(dead_letter.death_count(), 1);

    AckableSubscriber::shutdown(&sub).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}
