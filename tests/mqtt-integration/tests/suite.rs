mod support;
#[tokio::test]
async fn shared_mqtt_broker_smoke() -> anyhow::Result<()> {
    let fixture = testkit::shared_mqtt_tls().await?;
    let clock = std::sync::Arc::new(support::Timer::new());
    let store = std::sync::Arc::new(support::FileStore::new()?);
    let config = support::config(&fixture, "smoke", vec!["smoke/events".into()])?;
    let (publisher, mut receiver, resource) = rss_mqtt::connect(config, clock.clone(), store)?;
    publisher
        .wait_ready(std::time::Duration::from_secs(5))
        .await?;
    let outcome = publisher
        .publish(
            rss_mqtt::PublishRequest::new("smoke/events", b"test".to_vec())?,
            support::deadline(&*clock),
        )
        .await;
    assert!(matches!(
        outcome,
        rss_transactional_messaging::transport::PublishOutcome::Confirmed(())
    ));
    let delivery = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("delivery missing"))?;
    assert_eq!(delivery.payload(), b"test");
    delivery
        .into_parts()
        .1
        .ack_after_durable_handoff(support::deadline(&*clock))
        .await?;
    resource.shutdown(std::time::Duration::from_secs(5)).await?;
    Ok(())
}

#[path = "scenarios/protocol.rs"]
mod protocol;

#[path = "scenarios/broker.rs"]
mod broker;
#[path = "scenarios/outbox.rs"]
mod outbox;

#[path = "scenarios/logging.rs"]
mod logging;
