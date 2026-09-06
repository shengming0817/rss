use super::support::{self, FileStore, Timer};
use rss_mqtt::{ConnectionState, PublishRequest, RejectReason};
use rss_transactional_messaging::transport::PublishOutcome;
use std::{sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread")]
async fn persistent_receive_settlement_and_reconstruction() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fixture = testkit::mqtt_tls(true).await?;
        let clock = Arc::new(Timer::new());
        let store = Arc::new(FileStore::new()?);
        let (publisher, mut receiver, resource) = rss_mqtt::connect(
            support::config(&fixture, "recovery", vec!["recovery/events".into()])?,
            clock.clone(),
            store.clone(),
        )?;
        publisher.wait_ready(Duration::from_secs(5)).await?;
        for (body, reject) in [("acked", false), ("rejected", true)] {
            assert!(matches!(
                publisher
                    .publish(
                        PublishRequest::new("recovery/events", body.as_bytes().to_vec())?
                            .message_expiry_interval(60)
                            .correlation_data(b"correlation".to_vec()),
                        support::deadline(&*clock)
                    )
                    .await,
                PublishOutcome::Confirmed(())
            ));
            let delivery = receiver
                .next()
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing delivery"))?;
            assert_eq!(delivery.payload(), body.as_bytes());
            assert_eq!(
                delivery
                    .properties()
                    .and_then(|p| p.correlation_data.as_deref()),
                Some(&b"correlation"[..])
            );
            let settlement = delivery.into_parts().1;
            if reject {
                settlement
                    .reject_terminal(RejectReason::Unspecified, support::deadline(&*clock))
                    .await?;
            } else {
                settlement
                    .ack_after_durable_handoff(support::deadline(&*clock))
                    .await?;
            }
        }
        assert!(matches!(
            publisher
                .publish(
                    PublishRequest::new("recovery/events", b"unsettled".to_vec())?,
                    support::deadline(&*clock)
                )
                .await,
            PublishOutcome::Confirmed(())
        ));
        let delivery = receiver
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing unsettled"))?;
        let stale = delivery.into_parts().1;
        let mut status = publisher.connection_state();
        drop(resource);
        status.wait_for(|v| *v == ConnectionState::Closed).await?;
        drop(receiver);
        let (publisher, mut receiver, resource) = rss_mqtt::connect(
            support::config(&fixture, "recovery", vec!["recovery/events".into()])?,
            clock.clone(),
            store,
        )?;
        assert!(matches!(
            publisher.wait_ready(Duration::from_secs(5)).await?,
            ConnectionState::Ready {
                session_present: true,
                ..
            }
        ));
        assert!(
            stale
                .ack_after_durable_handoff(support::deadline(&*clock))
                .await
                .is_err()
        );
        let redelivered = receiver
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing replay"))?;
        assert_eq!(redelivered.payload(), b"unsettled");
        redelivered.into_parts().1.abandon();
        let replay = receiver
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing abandoned replay"))?;
        assert_eq!(replay.payload(), b"unsettled");
        replay
            .into_parts()
            .1
            .ack_after_durable_handoff(support::deadline(&*clock))
            .await?;
        let mut recovered = publisher.connection_state();
        let before = match *recovered.borrow() {
            ConnectionState::Ready { generation, .. } => generation,
            _ => 0,
        };
        fixture.restart().await?;
        tokio::time::timeout(
            Duration::from_secs(5),
            recovered.wait_for(
                |s| matches!(s,ConnectionState::Ready{generation,..} if *generation>before),
            ),
        )
        .await??;
        assert!(matches!(
            publisher
                .publish(
                    PublishRequest::new("recovery/events", b"barrier".to_vec())?,
                    support::deadline(&*clock)
                )
                .await,
            PublishOutcome::Confirmed(())
        ));
        let barrier = receiver
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing barrier"))?;
        assert_eq!(
            barrier.payload(),
            b"barrier",
            "ACK and negative PUBACK prevent prior delivery replay"
        );
        barrier
            .into_parts()
            .1
            .ack_after_durable_handoff(support::deadline(&*clock))
            .await?;
        resource.shutdown(Duration::from_secs(5)).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_and_credentials_fail_closed() -> anyhow::Result<()> {
    let fixture = testkit::mqtt_tls(true).await?;
    for (id, wrong_ca, client_auth, password) in [
        ("wrong-ca", true, true, "fixture-only"),
        ("no-cert", false, false, "fixture-only"),
        ("wrong-password", false, true, "incorrect"),
    ] {
        let config = rss_mqtt::MqttConfig::new(
            "localhost",
            fixture.port(),
            id,
            "tls",
            support::tls(&fixture, wrong_ca, client_auth)?,
            rss_mqtt::Limits::new(2, 2, 2, 1024)?,
        )?
        .credentials("mqtt", password.as_bytes().to_vec())?;
        let (publisher, _receiver, resource) =
            rss_mqtt::connect(config, Arc::new(Timer::new()), Arc::new(FileStore::new()?))?;
        let error = publisher
            .wait_ready(Duration::from_secs(2))
            .await
            .err()
            .ok_or_else(|| anyhow::anyhow!("invalid TLS/auth accepted"))?;
        assert!(!format!("{error:?} {error}").contains(password));
        drop(resource);
    }
    let wrong_host = testkit::mqtt_tls(false).await?;
    let (publisher, _receiver, resource) = rss_mqtt::connect(
        support::config(&wrong_host, "wrong-host", vec![])?,
        Arc::new(Timer::new()),
        Arc::new(FileStore::new()?),
    )?;
    assert!(publisher.wait_ready(Duration::from_secs(2)).await.is_err());
    drop(resource);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_maximum_applies_to_deliveries_held_by_the_caller() -> anyhow::Result<()> {
    let fixture = testkit::mqtt_tls(true).await?;
    let clock = Arc::new(Timer::new());
    let config = rss_mqtt::MqttConfig::new(
        "localhost",
        fixture.port(),
        "backpressure",
        "integration",
        support::tls(&fixture, false, true)?,
        rss_mqtt::Limits::new(4, 1, 4, 4096)?,
    )?
    .credentials("mqtt", b"fixture-only".to_vec())?
    .subscriptions(vec!["pressure".into()])?;
    let (publisher, mut receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(5)).await?;
    for body in [b"one", b"two"] {
        assert!(matches!(
            publisher
                .publish(
                    PublishRequest::new("pressure", body.to_vec())?,
                    support::deadline(&*clock)
                )
                .await,
            PublishOutcome::Confirmed(())
        ));
    }
    let first = receiver
        .next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("first"))?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver.next())
            .await
            .is_err()
    );
    first
        .into_parts()
        .1
        .ack_after_durable_handoff(support::deadline(&*clock))
        .await?;
    let second = tokio::time::timeout(Duration::from_secs(3), receiver.next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("second"))?;
    assert_eq!(second.payload(), b"two");
    second
        .into_parts()
        .1
        .ack_after_durable_handoff(support::deadline(&*clock))
        .await?;
    resource.shutdown(Duration::from_secs(3)).await?;
    Ok(())
}
