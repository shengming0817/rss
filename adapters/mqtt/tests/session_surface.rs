use diport::{ManagedResource, MessageId, Publisher, Subscriber};
use mqtt::{
    AuthenticatedDeviceDelivery, BrokerAccepted, MqttReadiness, MqttSession, MqttSessionError,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_impl_all!(MqttSession: ManagedResource, Send, Sync);
assert_not_impl_any!(MqttSession: Publisher, Subscriber, Clone);
assert_not_impl_any!(AuthenticatedDeviceDelivery: Clone, Copy);
assert_not_impl_any!(BrokerAccepted: Clone, Copy);

fn application_receipt_publish_is_transport_only<'a>(
    session: &'a MqttSession,
    tenant: vocab::TenantId,
    device: ids::DeviceId,
    message_id: &'a MessageId,
    payload: Vec<u8>,
) -> impl Future<Output = Result<BrokerAccepted, MqttSessionError>> + 'a {
    session.send_application_receipt(tenant, device, message_id, payload)
}

#[test]
fn application_receipt_publish_returns_only_broker_acceptance() {
    let _ = application_receipt_publish_is_transport_only;
}

/// ```compile_fail
/// # async fn bypass(delivery: mqtt::AuthenticatedDeviceDelivery) {
/// delivery.ack().await.unwrap();
/// # }
/// ```
pub struct DirectAckMustNotCompile;

/// A generic repository receipt is domain data, not authority to settle a transport delivery.
///
/// ```compile_fail
/// # async fn bypass<D, R>(delivery: D, repository: &R) {
/// let _ = identity::ports::device_certificate::run_device_ingress(delivery, repository).await;
/// # }
/// ```
pub struct GenericRepositoryCannotAuthorizePuback;

/// ```compile_fail
/// # fn bypass(delivery: &mqtt::AuthenticatedDeviceDelivery) {
/// let _ = delivery.to_message("event-1");
/// # }
/// ```
pub struct GenericMessageEscapeMustNotCompile;

#[test]
fn readiness_is_a_closed_non_sensitive_state() {
    let states = [
        MqttReadiness::Starting,
        MqttReadiness::Ready {
            session_present: false,
            credential_revision: 1,
        },
        MqttReadiness::Ready {
            session_present: true,
            credential_revision: 2,
        },
        MqttReadiness::Reloading {
            from_revision: 1,
            to_revision: 2,
        },
        MqttReadiness::Degraded {
            credential_revision: 2,
        },
        MqttReadiness::Stopped,
    ];
    for state in states {
        let rendered = format!("{state:?}");
        assert!(!rendered.contains("BEGIN CERTIFICATE"));
        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains("mqtts://"));
    }
}

#[test]
fn stale_transport_epoch_is_distinct_from_ack_unavailable() {
    assert_ne!(
        MqttSessionError::StaleTransportEpoch,
        MqttSessionError::AckUnavailable
    );
    for error in [
        MqttSessionError::StaleTransportEpoch,
        MqttSessionError::AckUnavailable,
    ] {
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("BEGIN CERTIFICATE"));
        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains("mqtts://"));
    }
}

/// Uplink saturation probe is test-support only and must not compile on the shipped surface.
///
/// ```compile_fail
/// # fn probe(session: &mqtt::MqttSession) {
/// let _ = session.uplink_queue_is_saturated_for_test();
/// # }
/// ```
pub struct UplinkSaturationProbeRequiresTestSupport;

#[cfg(feature = "broker-tests")]
mod inplace_reconnect {
    use std::time::Duration;

    use anyhow::Context;
    use diport::SecretMaterial;
    use ids::DeviceId;
    use mqtt::*;
    use testkit::MqttMtlsFixture;
    use vocab::TenantId;

    fn material(credential: &testkit::MqttCredential) -> MqttTlsMaterial {
        let tls = credential.tls();
        MqttTlsMaterial::new(
            SecretMaterial::new(tls.ca_pem().as_bytes().to_vec()),
            SecretMaterial::new(tls.certificate_pem().expect("c").as_bytes().to_vec()),
            SecretMaterial::new(tls.private_key_pem().expect("k").as_bytes().to_vec()),
        )
    }

    fn config(fixture: &MqttMtlsFixture) -> MqttSessionConfig {
        let credential = fixture.rss_a();
        MqttSessionConfig::new(
            MqttsEndpoint::parse(fixture.url()).expect("endpoint"),
            credential.stable_client_id(),
            material(credential),
            BrokerAssertionVerifier::new(*fixture.broker_assertion_public_key()).expect("key"),
            MqttTopicPolicy::new(vec![DeviceScope::new(
                TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                DeviceId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                CredentialGeneration::new(2).unwrap(),
            )])
            .unwrap(),
            SessionExpiry::new(Duration::from_secs(3600)).unwrap(),
            CredentialRevision::new(credential.revision()).unwrap(),
        )
        .unwrap()
    }

    async fn wait_ready(session: &MqttSession, want_present: Option<bool>) -> MqttReadiness {
        let mut rx = session.readiness_changes();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let ready = *rx.borrow();
                match (ready, want_present) {
                    (
                        MqttReadiness::Ready {
                            session_present, ..
                        },
                        Some(want),
                    ) if session_present == want => return ready,
                    (MqttReadiness::Ready { .. }, None) => return ready,
                    _ => {}
                }
                rx.changed().await.expect("readiness watch");
            }
        })
        .await
        .expect("mqtt readiness")
    }

    /// Stable published ports: pause/unpause proves in-place reconnect restores Ready + session_present.
    #[tokio::test]
    async fn inplace_reconnect_restores_ready_session_present() -> anyhow::Result<()> {
        let mut fixture = testkit::mosquitto_mtls().await?;
        let session = MqttSession::connect(config(&fixture)).await?;
        assert!(matches!(
            session.readiness(),
            MqttReadiness::Ready {
                session_present: false,
                ..
            }
        ));
        fixture.pause().await?;
        // Keepalive (30s) must expire under a frozen broker before the driver reconnects.
        tokio::time::timeout(Duration::from_secs(60), async {
            let mut rx = session.readiness_changes();
            loop {
                if matches!(*rx.borrow(), MqttReadiness::Degraded { .. }) {
                    return Ok::<(), anyhow::Error>(());
                }
                if rx.changed().await.is_err() {
                    anyhow::bail!("readiness watch closed before degraded");
                }
            }
        })
        .await
        .context("degraded after broker pause")??;
        fixture.unpause().await?;
        let ready = wait_ready(&session, Some(true)).await;
        assert!(
            matches!(
                ready,
                MqttReadiness::Ready {
                    session_present: true,
                    ..
                }
            ),
            "in-place reconnect must restore session_present; got {ready:?}"
        );
        session.shutdown().await?;
        Ok(())
    }
}
