//! Regression for the explicitly accepted consumer-owned logging restriction (#2308).
#[path = "../../../../crates/mqtt/examples/support/logging.rs"]
mod consumer_logging;
use super::support::{self, FileStore, Timer, wire::Peer};
use rumqttc::mqttbytes::v5::{ConnectReturnCode, Packet, Subscribe, SubscribeFilter};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("capture poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn consumer_filter_blocks_upstream_wire_data_but_keeps_application_logs() -> anyhow::Result<()>
{
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_env_filter(consumer_logging::filter())
        .with_ansi(false)
        .with_writer(capture.clone())
        .try_init()
        .map_err(|e| anyhow::anyhow!("logger setup: {e}"))?;
    log::warn!(target:"mqtt_app","application-control");
    let peer = Peer::new().await?;
    let config = peer.config("logging")?;
    let (attack_tx, attack_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        // MQTT v5 CONNACK property 0x25 advertises Retain Available = 0.
        let Packet::ConnAck(ack) = Packet::read(
            &mut bytes::BytesMut::from(&[0x20, 5, 0, 0, 2, 0x25, 0][..]),
            None,
        )?
        else {
            anyhow::bail!("bad fixture CONNACK")
        };
        let mut wire = peer
            .accept_properties(false, ConnectReturnCode::Success, ack.properties)
            .await?;
        let _ = attack_rx.await;
        let mut illegal = Subscribe::new(
            SubscribeFilter::new("secret-inbound", rumqttc::QoS::AtLeastOnce),
            None,
        );
        illegal.pkid = 9;
        wire.write(Packet::Subscribe(illegal)).await?;
        let _ = wire.read().await;
        Ok::<_, anyhow::Error>(())
    });
    let clock = Arc::new(Timer::new());
    let (publisher, _receiver, resource) =
        rss_mqtt::connect(config, clock.clone(), Arc::new(FileStore::new()?))?;
    publisher.wait_ready(Duration::from_secs(3)).await?;
    let request = rss_mqtt::PublishRequest::new("secret-topic", b"secret-body".to_vec())?
        .retain(true)
        .correlation_data(b"secret-correlation".to_vec())
        .user_properties(vec![("key".into(), "secret-attribute".into())]);
    assert!(matches!(
        publisher.publish(request, support::deadline(&*clock)).await,
        rss_transactional_messaging::transport::PublishOutcome::DefinitelyNotPublished(_)
    ));
    let mut state = publisher.connection_state();
    let _ = attack_tx.send(());
    tokio::time::timeout(
        Duration::from_secs(3),
        state.wait_for(|s| {
            matches!(
                s,
                rss_mqtt::ConnectionState::Failed(rss_mqtt::MqttError::Protocol)
            )
        }),
    )
    .await??;
    drop(resource);
    server.await??;
    let output = String::from_utf8(
        capture
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("capture poisoned"))?
            .clone(),
    )?;
    assert!(
        output.contains("application-control"),
        "must not globally disable logging"
    );
    for secret in [
        "secret-topic",
        "secret-body",
        "secret-correlation",
        "secret-attribute",
        "secret-inbound",
    ] {
        assert!(
            !output.contains(secret),
            "upstream wire data escaped consumer filter"
        );
    }
    Ok(())
}
