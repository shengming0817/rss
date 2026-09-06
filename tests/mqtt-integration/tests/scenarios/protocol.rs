use super::support::{self, FileStore, Timer, wire::Peer};
use rss_mqtt::{MqttError, PublishRequest};
use rss_transactional_messaging::transport::{PublishFailureKind, PublishOutcome};
use rumqttc::mqttbytes::v5::{Packet, PubAckReason, Publish};
use std::{sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread")]
async fn out_of_order_pubacks_keep_their_request_identity() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("out-of-order")?;
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let first = wire.publish().await?;
        let second = wire.publish().await?;
        for p in [second, first] {
            wire.ack(
                p.pkid,
                if p.payload.as_ref() == b"accepted" {
                    PubAckReason::Success
                } else {
                    PubAckReason::QuotaExceeded
                },
            )
            .await?;
        }
        anyhow::ensure!(
            matches!(wire.read().await?, Packet::Disconnect(_)),
            "expected disconnect"
        );
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    let (a, b) = tokio::join!(
        publisher.publish(
            PublishRequest::new("events", b"accepted".to_vec())?,
            support::deadline(&*clock)
        ),
        publisher.publish(
            PublishRequest::new("events", b"quota".to_vec())?,
            support::deadline(&*clock)
        )
    );
    assert!(matches!(a, PublishOutcome::Confirmed(())));
    assert!(
        matches!(b, PublishOutcome::DefinitelyNotPublished(f) if f.kind() == PublishFailureKind::Transient)
    );
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn session_loss_is_ambiguous_and_same_content_can_retry() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("session-loss")?;
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let first = wire.publish().await?;
        drop(wire);
        let mut wire = peer.accept(false).await?;
        let retry = wire.publish().await?;
        assert_eq!(first.topic, retry.topic);
        assert_eq!(first.payload, retry.payload);
        assert_eq!(first.properties, retry.properties);
        wire.ack(retry.pkid, PubAckReason::Success).await?;
        let _ = wire.read().await?;
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    let request = PublishRequest::new("events", b"immutable".to_vec())?
        .user_properties(vec![("message-id".into(), "original".into())]);
    assert!(
        publisher
            .publish(request.clone(), support::deadline(&*clock))
            .await
            .is_ambiguous()
    );
    publisher.wait_ready(Duration::from_secs(3)).await?;
    assert!(matches!(
        publisher.publish(request, support::deadline(&*clock)).await,
        PublishOutcome::Confirmed(())
    ));
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_publish_keeps_protocol_progress() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("cancel")?;
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let first = wire.publish().await?;
        let _ = seen_tx.send(());
        let _ = release_rx.await;
        wire.ack(first.pkid, PubAckReason::Success).await?;
        let next = wire.publish().await?;
        assert_eq!(next.payload.as_ref(), b"barrier");
        wire.ack(next.pkid, PubAckReason::Success).await?;
        anyhow::ensure!(
            matches!(wire.read().await?, Packet::Disconnect(_)),
            "normal shutdown after cancellation"
        );
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    let sending = tokio::spawn({
        let p = publisher.clone();
        let c = clock.clone();
        async move {
            p.publish(
                PublishRequest::new("events", Vec::new())?,
                support::deadline(&*c),
            )
            .await;
            Ok::<_, anyhow::Error>(())
        }
    });
    seen_rx.await?;
    sending.abort();
    let _ = sending.await;
    let _ = release_tx.send(());
    assert!(matches!(
        publisher
            .publish(
                PublishRequest::new("events", b"barrier".to_vec())?,
                support::deadline(&*clock)
            )
            .await,
        PublishOutcome::Confirmed(())
    ));
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn old_epoch_cannot_ack_a_reused_packet_id() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("epochs")?;
    let (break_tx, break_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let mut p = Publish::new("events", rumqttc::QoS::AtLeastOnce, b"old".to_vec(), None);
        p.pkid = 9;
        wire.write(Packet::Publish(p)).await?;
        let _ = break_rx.await;
        drop(wire);
        let mut wire = peer.accept(true).await?;
        let mut p = Publish::new("events", rumqttc::QoS::AtLeastOnce, b"new".to_vec(), None);
        p.pkid = 9;
        p.dup = true;
        wire.write(Packet::Publish(p)).await?;
        anyhow::ensure!(
            matches!(wire.read().await?, Packet::PubAck(a) if a.pkid == 9),
            "new delivery must be acknowledged"
        );
        let _ = wire.read().await?;
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let (publisher, mut receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    let old = tokio::time::timeout(Duration::from_secs(3), receiver.next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("missing old"))?;
    let _ = break_tx.send(());
    let new = tokio::time::timeout(Duration::from_secs(3), receiver.next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("missing new"))?;
    assert_eq!(new.payload(), b"new");
    assert_eq!(
        old.into_parts()
            .1
            .ack_after_durable_handoff(support::deadline(&*clock))
            .await,
        Err(MqttError::StaleDelivery)
    );
    new.into_parts()
        .1
        .ack_after_durable_handoff(support::deadline(&*clock))
        .await?;
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn recreated_eventloop_restores_inflight_publish_from_checkpoint() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let first_config = peer.config("restart-publish")?;
    let next_config = peer.config("restart-publish")?;
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (replayed_tx, replayed_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let first = wire.publish().await?;
        let _ = seen_tx.send(());
        anyhow::ensure!(
            wire.read().await.is_err(),
            "old process must disconnect without PUBACK"
        );
        drop(wire);
        let mut wire = peer.accept(true).await?;
        let replay = wire.publish().await?;
        assert_eq!(replay.pkid, first.pkid);
        assert_eq!(replay.payload, first.payload);
        assert_eq!(replay.properties, first.properties);
        wire.ack(replay.pkid, PubAckReason::Success).await?;
        let _ = replayed_tx.send(());
        let next = wire.publish().await?;
        assert_eq!(next.payload.as_ref(), b"next");
        wire.ack(next.pkid, PubAckReason::Success).await?;
        let _ = wire.read().await?;
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let store = Arc::new(FileStore::new()?);
    let (publisher, receiver, resource) =
        rss_mqtt::connect(first_config, clock.clone(), store.clone())?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    let sending = tokio::spawn({
        let p = publisher.clone();
        let c = clock.clone();
        async move {
            p.publish(
                PublishRequest::new("events", b"durable-inflight".to_vec())?,
                support::deadline(&*c),
            )
            .await;
            Ok::<_, anyhow::Error>(())
        }
    });
    seen_rx.await?;
    let mut state = publisher.connection_state();
    drop(resource);
    state
        .wait_for(|v| *v == rss_mqtt::ConnectionState::Closed)
        .await?;
    drop(receiver);
    sending.abort();
    let _ = sending.await;
    let (publisher, _receiver, resource) = rss_mqtt::connect(next_config, clock.clone(), store)?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    replayed_rx.await?;
    assert!(matches!(
        publisher
            .publish(
                PublishRequest::new("events", b"next".to_vec())?,
                support::deadline(&*clock)
            )
            .await,
        PublishOutcome::Confirmed(())
    ));
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[tokio::test]
async fn broker_only_resume_is_rejected_without_silent_reset() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("missing-local-state")?;
    let server = tokio::spawn(async move {
        let _wire = peer.accept(true).await?;
        Ok::<_, anyhow::Error>(())
    });
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, Arc::new(Timer::new()), Arc::new(FileStore::new()?))?;
    assert_eq!(
        publisher.wait_ready(Duration::from_secs(3)).await,
        Err(MqttError::SessionState)
    );
    drop(resource);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn qos_zero_never_receives_reliable_settlement_authority() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("unsupported-qos")?;
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        wire.write(Packet::Publish(Publish::new(
            "events",
            rumqttc::QoS::AtMostOnce,
            b"unreliable".to_vec(),
            None,
        )))
        .await?;
        let _ = wire.read().await;
        Ok::<_, anyhow::Error>(())
    });
    let (_publisher, mut receiver, resource) =
        rss_mqtt::connect(config, Arc::new(Timer::new()), Arc::new(FileStore::new()?))?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), receiver.next()).await?,
        Err(MqttError::UnsupportedQos)
    ));
    drop(resource);
    server.await??;
    Ok(())
}

#[derive(Debug)]
struct FailingStore;
impl rumqttc::SessionStore for FailingStore {
    fn load<'a>(
        &'a self,
        _: &'a rumqttc::SessionStoreKey,
    ) -> support::SessionStoreFuture<'a, Option<rumqttc::PersistedSession>> {
        Box::pin(async { Err(std::io::Error::other("sensitive-store-location").into()) })
    }
    fn save<'a>(
        &'a self,
        _: &'a rumqttc::SessionStoreKey,
        _: &'a rumqttc::PersistedSession,
    ) -> support::SessionStoreFuture<'a, ()> {
        Box::pin(async { Err(std::io::Error::other("sensitive-store-location").into()) })
    }
    fn clear<'a>(&'a self, _: &'a rumqttc::SessionStoreKey) -> support::SessionStoreFuture<'a, ()> {
        Box::pin(async { Err(std::io::Error::other("sensitive-store-location").into()) })
    }
}
#[tokio::test]
async fn session_store_errors_are_terminal_and_redacted() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let (publisher, _receiver, resource) = rss_mqtt::connect(
        peer.config("store-error")?,
        Arc::new(Timer::new()),
        Arc::new(FailingStore),
    )?;
    assert_eq!(
        publisher.wait_ready(Duration::from_secs(3)).await,
        Err(MqttError::SessionStore)
    );
    assert!(!format!("{:?}", *publisher.connection_state().borrow()).contains("sensitive"));
    drop(resource);
    Ok(())
}

#[derive(Debug)]
struct BlockedStore {
    entered: tokio::sync::Notify,
}
impl rumqttc::SessionStore for BlockedStore {
    fn load<'a>(
        &'a self,
        _: &'a rumqttc::SessionStoreKey,
    ) -> support::SessionStoreFuture<'a, Option<rumqttc::PersistedSession>> {
        Box::pin(async move {
            self.entered.notify_one();
            std::future::pending().await
        })
    }
    fn save<'a>(
        &'a self,
        _: &'a rumqttc::SessionStoreKey,
        _: &'a rumqttc::PersistedSession,
    ) -> support::SessionStoreFuture<'a, ()> {
        Box::pin(std::future::pending())
    }
    fn clear<'a>(&'a self, _: &'a rumqttc::SessionStoreKey) -> support::SessionStoreFuture<'a, ()> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test]
async fn shutdown_bounds_blocked_storage_and_closes_admission() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let store = Arc::new(BlockedStore {
        entered: tokio::sync::Notify::new(),
    });
    let clock = Arc::new(Timer::new());
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(peer.config("blocked-store")?, clock.clone(), store.clone())?;
    tokio::time::timeout(Duration::from_secs(3), store.entered.notified()).await?;
    let mut status = publisher.connection_state();
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        resource.shutdown(Duration::from_millis(30)),
    )
    .await?;
    tokio::time::timeout(
        Duration::from_secs(1),
        status.wait_for(|v| *v == rss_mqtt::ConnectionState::Closed),
    )
    .await??;
    assert!(matches!(
        publisher
            .publish(
                PublishRequest::new("events", Vec::new())?,
                support::deadline(&*clock)
            )
            .await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_suback_does_not_complete_current_subscription() -> anyhow::Result<()> {
    use rumqttc::mqttbytes::v5::{SubAck, SubscribeReasonCode};
    let peer = Peer::new().await?;
    let config = peer
        .config("suback-owner")?
        .subscriptions(vec!["events".into()])?;
    let next_config = peer
        .config("suback-owner")?
        .subscriptions(vec!["events".into()])?;
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let Packet::Subscribe(old) = wire.read().await? else {
            anyhow::bail!("subscribe missing")
        };
        let _ = seen_tx.send(());
        let _ = wire.read().await;
        drop(wire);
        let mut wire = peer.accept(true).await?;
        let Packet::Subscribe(replay) = wire.read().await? else {
            anyhow::bail!("replay missing")
        };
        let Packet::Subscribe(current) = wire.read().await? else {
            anyhow::bail!("current subscribe missing")
        };
        assert_eq!(replay.pkid, old.pkid);
        assert_ne!(replay.pkid, current.pkid);
        wire.write(Packet::SubAck(SubAck {
            pkid: replay.pkid,
            return_codes: vec![SubscribeReasonCode::Success(rumqttc::QoS::AtLeastOnce)],
            properties: None,
        }))
        .await?;
        let mut probe = Publish::new("events", rumqttc::QoS::AtLeastOnce, b"probe".to_vec(), None);
        probe.pkid = 17;
        wire.write(Packet::Publish(probe)).await?;
        let _ = finish_rx.await;
        wire.write(Packet::SubAck(SubAck {
            pkid: current.pkid,
            return_codes: vec![SubscribeReasonCode::NotAuthorized],
            properties: None,
        }))
        .await?;
        let _ = wire.read().await;
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let store = Arc::new(FileStore::new()?);
    let (publisher, receiver, resource) = rss_mqtt::connect(config, clock.clone(), store.clone())?;
    seen_rx.await?;
    let mut state = publisher.connection_state();
    drop(resource);
    state
        .wait_for(|s| *s == rss_mqtt::ConnectionState::Closed)
        .await?;
    drop(receiver);
    let (publisher, mut receiver, resource) = rss_mqtt::connect(next_config, clock, store)?;
    let probe = tokio::time::timeout(Duration::from_secs(3), receiver.next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("probe missing"))?;
    assert!(!matches!(
        *publisher.connection_state().borrow(),
        rss_mqtt::ConnectionState::Ready { .. }
    ));
    let _ = finish_tx.send(());
    assert_eq!(
        publisher.wait_ready(Duration::from_secs(3)).await,
        Err(MqttError::SubscriptionRejected)
    );
    drop(probe);
    drop(resource);
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transient_connack_exposes_cause_and_recovers() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("busy")?;
    let (retry_tx, retry_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        drop(
            peer.accept_code(false, rumqttc::mqttbytes::v5::ConnectReturnCode::ServerBusy)
                .await?,
        );
        let _ = retry_rx.await;
        let mut wire = peer.accept(false).await?;
        let _ = wire.read().await?;
        Ok::<_, anyhow::Error>(())
    });
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, Arc::new(Timer::new()), Arc::new(FileStore::new()?))?;
    let mut state = publisher.connection_state();
    tokio::time::timeout(
        Duration::from_secs(3),
        state.wait_for(|s| {
            matches!(
                s,
                rss_mqtt::ConnectionState::Reconnecting {
                    cause: MqttError::BrokerBusy,
                    ..
                }
            )
        }),
    )
    .await??;
    let _ = retry_tx.send(());
    publisher.wait_ready(Duration::from_secs(3)).await?;
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transient_suback_retries_the_current_subscription() -> anyhow::Result<()> {
    use rumqttc::mqttbytes::v5::{SubAck, SubscribeReasonCode};
    let peer = Peer::new().await?;
    let config = peer
        .config("subscribe-busy")?
        .subscriptions(vec!["events".into()])?;
    let server = tokio::spawn(async move {
        for (resumed, reason) in [
            (false, SubscribeReasonCode::QuotaExceeded),
            (
                true,
                SubscribeReasonCode::Success(rumqttc::QoS::AtLeastOnce),
            ),
        ] {
            let mut wire = peer.accept(resumed).await?;
            let Packet::Subscribe(sub) = wire.read().await? else {
                anyhow::bail!("missing subscribe")
            };
            wire.write(Packet::SubAck(SubAck {
                pkid: sub.pkid,
                return_codes: vec![reason],
                properties: None,
            }))
            .await?;
            let _ = wire.read().await;
        }
        Ok::<_, anyhow::Error>(())
    });
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, Arc::new(Timer::new()), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    resource.shutdown(Duration::from_secs(3)).await?;
    server.await??;
    Ok(())
}

#[derive(Debug)]
struct SwitchStore {
    inner: FileStore,
    fail: std::sync::atomic::AtomicBool,
}
impl rumqttc::SessionStore for SwitchStore {
    fn load<'a>(
        &'a self,
        key: &'a rumqttc::SessionStoreKey,
    ) -> support::SessionStoreFuture<'a, Option<rumqttc::PersistedSession>> {
        self.inner.load(key)
    }
    fn save<'a>(
        &'a self,
        key: &'a rumqttc::SessionStoreKey,
        session: &'a rumqttc::PersistedSession,
    ) -> support::SessionStoreFuture<'a, ()> {
        Box::pin(async move {
            if self.fail.load(std::sync::atomic::Ordering::Acquire) {
                return Err(std::io::Error::other("private-store-error").into());
            }
            self.inner.save(key, session).await
        })
    }
    fn clear<'a>(
        &'a self,
        key: &'a rumqttc::SessionStoreKey,
    ) -> support::SessionStoreFuture<'a, ()> {
        self.inner.clear(key)
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_preserves_the_session_store_failure_cause() -> anyhow::Result<()> {
    let peer = Peer::new().await?;
    let config = peer.config("shutdown-store")?;
    let server = tokio::spawn(async move {
        let mut wire = peer.accept(false).await?;
        let _ = wire.read().await;
        Ok::<_, anyhow::Error>(())
    });
    let store = Arc::new(SwitchStore {
        inner: FileStore::new()?,
        fail: std::sync::atomic::AtomicBool::new(false),
    });
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, Arc::new(Timer::new()), store.clone())?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    store.fail.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        resource.shutdown(Duration::from_secs(3)).await,
        Err(MqttError::SessionStore)
    );
    assert_eq!(
        *publisher.connection_state().borrow(),
        rss_mqtt::ConnectionState::Failed(MqttError::SessionStore)
    );
    server.await??;
    Ok(())
}
