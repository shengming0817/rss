//! Hermetic Mosquitto mTLS + assertion + ACL + session T2 for #1902.
#![allow(clippy::expect_used, clippy::unwrap_used)] // reason: broker T2 fixtures fail loudly.

use std::sync::Arc;
use std::time::Duration;

use diport::{MessageId, SecretMaterial};
use ids::DeviceId;
use mqtt::{
    BrokerAssertionVerifier, CredentialGeneration, CredentialRevision, DeviceScope, MqttReadiness,
    MqttSession, MqttSessionConfig, MqttSessionError, MqttTlsMaterial, MqttTopicPolicy,
    MqttsEndpoint, NegativeAckPollBarrier, SessionExpiry,
};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Filter, Packet, PublishProperties};
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::{TlsConfiguration, Transport};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use testkit::{MqttAssertionFault, MqttCredential, MqttMtlsFixture};
use vocab::TenantId;

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const CROSS_TENANT: &str = "33333333-3333-4333-8333-333333333333";
const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
const CURRENT_GENERATION: u64 = 2;

fn scope(tenant: &str, generation: u64) -> DeviceScope {
    DeviceScope::new(
        TenantId::parse(tenant).expect("tenant"),
        DeviceId::parse(DEVICE).expect("device"),
        CredentialGeneration::new(generation).expect("generation"),
    )
}

fn policy_current() -> MqttTopicPolicy {
    MqttTopicPolicy::new(vec![scope(TENANT, CURRENT_GENERATION)]).expect("policy")
}

fn mqtt_material(credential: &MqttCredential) -> MqttTlsMaterial {
    let tls = credential.tls();
    MqttTlsMaterial::new(
        SecretMaterial::new(tls.ca_pem().as_bytes().to_vec()),
        SecretMaterial::new(
            tls.certificate_pem()
                .expect("certificate required")
                .as_bytes()
                .to_vec(),
        ),
        SecretMaterial::new(
            tls.private_key_pem()
                .expect("private key required")
                .as_bytes()
                .to_vec(),
        ),
    )
}

fn session_config(
    fixture: &MqttMtlsFixture,
    credential: &MqttCredential,
    expiry_secs: u64,
) -> MqttSessionConfig {
    MqttSessionConfig::new(
        MqttsEndpoint::parse(fixture.url()).expect("mqtts endpoint"),
        credential.stable_client_id(),
        mqtt_material(credential),
        BrokerAssertionVerifier::new(*fixture.broker_assertion_public_key())
            .expect("assertion key"),
        policy_current(),
        SessionExpiry::new(Duration::from_secs(expiry_secs)).expect("expiry"),
        CredentialRevision::new(credential.revision()).expect("revision"),
    )
    .expect("session config")
}

fn rustls_client(credential: &MqttCredential) -> Arc<ClientConfig> {
    let tls = credential.tls();
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(tls.ca_pem().as_bytes()) {
        roots.add(cert.expect("ca")).expect("add ca");
    }
    let certificates =
        CertificateDer::pem_slice_iter(tls.certificate_pem().expect("cert").as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("certs");
    let key =
        PrivateKeyDer::from_pem_slice(tls.private_key_pem().expect("key").as_bytes()).expect("key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, key)
            .expect("client auth"),
    )
}

fn device_client(
    fixture: &MqttMtlsFixture,
    credential: &MqttCredential,
) -> (AsyncClient, EventLoop) {
    let endpoint = url::Url::parse(fixture.url()).expect("url");
    let mut options = MqttOptions::new(
        credential.stable_client_id(),
        endpoint.host_str().expect("host"),
        endpoint.port().expect("port"),
    );
    options
        .set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
            rustls_client(credential),
        )))
        .set_keep_alive(Duration::from_secs(30))
        .set_clean_start(true)
        .set_manual_acks(true);
    AsyncClient::new(options, 16)
}

fn persistent_device_client(
    fixture: &MqttMtlsFixture,
    credential: &MqttCredential,
    clean_start: bool,
) -> (AsyncClient, EventLoop) {
    let endpoint = url::Url::parse(fixture.url()).expect("url");
    let mut options = MqttOptions::new(
        credential.stable_client_id(),
        endpoint.host_str().expect("host"),
        endpoint.port().expect("port"),
    );
    options
        .set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
            rustls_client(credential),
        )))
        .set_keep_alive(Duration::from_secs(30))
        .set_clean_start(clean_start)
        .set_session_expiry_interval(Some(3_600))
        .set_manual_acks(true);
    AsyncClient::new(options, 16)
}

async fn wait_connack(eventloop: &mut EventLoop) -> bool {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match eventloop.poll().await.expect("poll") {
                Event::Incoming(rumqttc::v5::mqttbytes::v5::Packet::ConnAck(ack)) => {
                    return matches!(
                        ack.code,
                        rumqttc::v5::mqttbytes::v5::ConnectReturnCode::Success
                    );
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn connect_session(fixture: &MqttMtlsFixture, credential: &MqttCredential) -> MqttSession {
    let session = MqttSession::connect(session_config(fixture, credential, 3600))
        .await
        .expect("connect");
    assert!(matches!(session.readiness(), MqttReadiness::Ready { .. }));
    session
}

#[tokio::test]
async fn valid_mtls_session_is_ready_and_redacted() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let rendered = format!("{session:?}");
    assert!(!rendered.contains("BEGIN"));
    assert!(!rendered.contains(fixture.url()));
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn missing_or_wrong_credentials_fail_closed() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let no_cert = fixture.device_no_certificate();
    let no_cert_config = MqttSessionConfig::new(
        MqttsEndpoint::parse(fixture.url()).expect("mqtts endpoint"),
        no_cert.stable_client_id(),
        MqttTlsMaterial::new(
            SecretMaterial::new(no_cert.tls().ca_pem().as_bytes().to_vec()),
            SecretMaterial::new(Vec::new()),
            SecretMaterial::new(Vec::new()),
        ),
        BrokerAssertionVerifier::new(*fixture.broker_assertion_public_key())
            .expect("assertion key"),
        policy_current(),
        SessionExpiry::new(Duration::from_secs(3600)).expect("expiry"),
        CredentialRevision::new(no_cert.revision()).expect("revision"),
    );
    assert!(
        no_cert_config.is_err(),
        "empty cert material must fail closed"
    );
    assert!(
        MqttSession::connect(session_config(&fixture, fixture.device_wrong_ca(), 3600))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn device_uplink_yields_sealed_principal_and_rejects_override() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let policy = policy_current();
    let topic = policy
        .command_acked_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("topic");

    let (device, mut device_loop) = device_client(&fixture, fixture.device_current());
    assert!(
        wait_connack(&mut device_loop).await,
        "device mTLS must succeed"
    );
    let device_pump = tokio::spawn(async move {
        loop {
            if device_loop.poll().await.is_err() {
                break;
            }
        }
    });
    let mut properties = PublishProperties::default();
    properties.correlation_data = Some(b"corr-1".to_vec().into());
    // Payload/metadata may claim another device; sealed principal must still follow the cert SAN.
    properties.user_properties =
        vec![("claim.device".into(), format!("impersonate:{CROSS_TENANT}"))];
    device
        .publish_with_properties(
            topic.as_str(),
            QoS::AtLeastOnce,
            false,
            br#"{"claim":"other-device"}"#.to_vec(),
            properties,
        )
        .await
        .expect("device publish queued");

    let delivery = tokio::time::timeout(Duration::from_secs(10), session.next_uplink())
        .await
        .expect("uplink timeout")
        .expect("uplink");
    assert_eq!(delivery.scope(), &scope(TENANT, CURRENT_GENERATION));
    assert_eq!(
        delivery.scope().principal_urn(),
        scope(TENANT, CURRENT_GENERATION).principal_urn()
    );
    assert!(!delivery.scope().principal_urn().contains(CROSS_TENANT));
    assert_eq!(delivery.payload(), br#"{"claim":"other-device"}"#);

    // Wire metadata / payload claims cannot mint MQTT identity. Authenticated delivery no longer
    // exposes a conversion into provider-agnostic Message.
    let mut forged = diport::Message::new("evt-2", br#"{"claim":"other-device"}"#.to_vec());
    let forged_claim = scope(CROSS_TENANT, CURRENT_GENERATION).principal_urn();
    forged
        .metadata
        .insert_wire_pair(diport::KEY_PRINCIPAL, &forged_claim);
    assert_eq!(
        forged.metadata.get(diport::KEY_PRINCIPAL),
        Some(forged_claim.as_str()),
        "wire KEY_PRINCIPAL remains forgeable text and must not be treated as sealed identity"
    );
    // Delivery scope is unchanged by forged Message metadata.
    assert_eq!(delivery.scope(), &scope(TENANT, CURRENT_GENERATION));

    // This transport test intentionally cannot settle the delivery. A broker-only fixture has no
    // PostgreSQL commit proof and therefore must not claim to prove durable ingress or mint PUBACK.
    drop(delivery);
    device_pump.abort();
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn persistent_assertion_poison_is_negatively_acked_without_reconnect() -> anyhow::Result<()> {
    let fixture =
        testkit::mosquitto_mtls_with_assertion_fault(MqttAssertionFault::CorruptFirstSignature)
            .await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let topic = policy_current()
        .command_acked_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("topic");
    let (device, mut device_loop) = device_client(&fixture, fixture.device_current());
    assert!(wait_connack(&mut device_loop).await);
    let device_pump = tokio::spawn(async move { while device_loop.poll().await.is_ok() {} });

    for (correlation, payload) in [
        (b"poison-1".as_slice(), b"rejected".as_slice()),
        (b"valid-2".as_slice(), b"accepted".as_slice()),
    ] {
        let mut properties = PublishProperties::default();
        properties.correlation_data = Some(correlation.to_vec().into());
        device
            .publish_with_properties(
                topic.as_str(),
                QoS::AtLeastOnce,
                false,
                payload.to_vec(),
                properties,
            )
            .await
            .expect("uplink queued");
    }

    let delivery = tokio::time::timeout(Duration::from_secs(10), session.next_uplink())
        .await
        .expect("valid uplink timeout")
        .expect("valid uplink");
    assert_eq!(delivery.payload(), b"accepted");
    assert_eq!(delivery.correlation_data(), Some(b"valid-2".as_slice()));
    assert!(matches!(
        session.readiness(),
        MqttReadiness::Ready {
            session_present: false,
            credential_revision: 1,
        }
    ));
    drop(delivery);
    session.shutdown().await?;

    // The valid delivery was deliberately left unacknowledged. A persistent reconnect must replay
    // that envelope, proving the broker session was restored, while the negatively acknowledged
    // poison must be absent from the same broker queue.
    let restored = connect_session(&fixture, fixture.rss_a()).await;
    assert!(matches!(
        restored.readiness(),
        MqttReadiness::Ready {
            session_present: true,
            credential_revision: 1,
        }
    ));
    let replay = tokio::time::timeout(Duration::from_secs(10), restored.next_uplink())
        .await
        .expect("persistent replay timeout")
        .expect("persistent replay");
    assert_eq!(replay.payload(), b"accepted");
    assert_eq!(replay.correlation_data(), Some(b"valid-2".as_slice()));
    assert!(
        tokio::time::timeout(Duration::from_millis(750), restored.next_uplink())
            .await
            .is_err(),
        "negative PUBACK must remove poison while preserving unrelated unacknowledged delivery"
    );

    drop(replay);
    device_pump.abort();
    restored.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn qos0_uplink_is_rejected_without_poisoning_the_session() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let topic = policy_current()
        .command_acked_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("topic");
    let (device, mut device_loop) = device_client(&fixture, fixture.device_current());
    assert!(wait_connack(&mut device_loop).await);
    let device_pump = tokio::spawn(async move { while device_loop.poll().await.is_ok() {} });

    device
        .publish(topic.as_str(), QoS::AtMostOnce, false, b"qos0".to_vec())
        .await
        .expect("qos0 queued");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), session.next_uplink())
            .await
            .is_err(),
        "broker-rejected qos0 must not mint authenticated delivery"
    );

    device
        .publish(topic.as_str(), QoS::AtLeastOnce, false, b"qos1".to_vec())
        .await
        .expect("qos1 queued");
    let delivery = tokio::time::timeout(Duration::from_secs(10), session.next_uplink())
        .await
        .expect("qos1 timeout")
        .expect("qos1 delivery");
    assert_eq!(delivery.payload(), b"qos1");
    assert!(matches!(session.readiness(), MqttReadiness::Ready { .. }));

    drop(delivery);
    device_pump.abort();
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn negative_puback_write_failure_stops_without_reconnect() -> anyhow::Result<()> {
    let mut fixture =
        testkit::mosquitto_mtls_with_assertion_fault(MqttAssertionFault::CorruptFirstSignature)
            .await?;
    let barrier = NegativeAckPollBarrier::new();
    let session = MqttSession::connect(
        session_config(&fixture, fixture.rss_a(), 3600)
            .with_negative_ack_poll_barrier(barrier.clone()),
    )
    .await
    .expect("connect");
    let topic = policy_current()
        .command_acked_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("topic");
    let (device, mut device_loop) = device_client(&fixture, fixture.device_current());
    assert!(wait_connack(&mut device_loop).await);
    let device_pump = tokio::spawn(async move { while device_loop.poll().await.is_ok() {} });

    device
        .publish(topic.as_str(), QoS::AtLeastOnce, false, b"poison".to_vec())
        .await
        .expect("poison queued");
    tokio::time::timeout(Duration::from_secs(10), barrier.wait_until_reached())
        .await
        .expect("negative ack was not queued");
    fixture.stop().await?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    barrier.release();

    let mut readiness = session.readiness_changes();
    tokio::time::timeout(Duration::from_secs(10), async {
        while *readiness.borrow_and_update() != MqttReadiness::Stopped {
            readiness.changed().await.expect("readiness sender");
        }
    })
    .await
    .expect("negative ack outcome unknown must stop");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(session.readiness(), MqttReadiness::Stopped);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), session.next_uplink())
            .await
            .expect("closed delivery queue")
            .is_err(),
        "poison must not mint authenticated delivery"
    );

    device_pump.abort();
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cross_tenant_device_cannot_write_primary_topics() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let policy = policy_current();
    let topic = policy
        .command_acked_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("topic");
    let (device, mut device_loop) = device_client(&fixture, fixture.device_cross_tenant());
    assert!(wait_connack(&mut device_loop).await);
    let _ = device
        .publish(topic.as_str(), QoS::AtLeastOnce, false, b"{}".to_vec())
        .await;
    let _ = tokio::time::timeout(Duration::from_millis(800), device_loop.poll()).await;

    let uplink = tokio::time::timeout(Duration::from_secs(2), session.next_uplink()).await;
    assert!(uplink.is_err(), "cross-tenant write must not deliver");
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn stale_generation_uplink_is_dropped() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let current_topic = policy_current()
        .command_acked_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("current generation uplink topic");
    let (device, mut device_loop) = device_client(&fixture, fixture.device_stale());
    assert!(wait_connack(&mut device_loop).await);
    let _ = device
        .publish(
            current_topic.as_str(),
            QoS::AtLeastOnce,
            false,
            b"{}".to_vec(),
        )
        .await;
    let _ = tokio::time::timeout(Duration::from_millis(800), device_loop.poll()).await;
    let uplink = tokio::time::timeout(Duration::from_secs(2), session.next_uplink()).await;
    assert!(
        uplink.is_err(),
        "stale generation must not authenticate on current uplink"
    );
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn credential_reload_and_revocation() -> anyhow::Result<()> {
    let mut fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    session
        .reload_credentials(
            mqtt_material(fixture.rss_b()),
            CredentialRevision::new(fixture.rss_b().revision()).expect("rev"),
        )
        .await
        .expect("reload to rss_b");
    assert!(matches!(
        session.readiness(),
        MqttReadiness::Ready {
            credential_revision: 2,
            ..
        }
    ));

    // Invalid non-increasing revision rolls back / fails closed.
    assert!(
        session
            .reload_credentials(
                mqtt_material(fixture.rss_b()),
                CredentialRevision::new(2).expect("rev"),
            )
            .await
            .is_err()
    );

    session.shutdown().await?;

    fixture = fixture.revoke_device_current_and_rebind().await?;
    assert!(
        MqttSession::connect(session_config(&fixture, fixture.device_current(), 3600))
            .await
            .is_err(),
        "revoked device cert must fail handshake"
    );
    let still_ok = connect_session(&fixture, fixture.rss_b()).await;
    still_ok.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn credential_reload_keeps_last_good_on_unusable_tls() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    assert!(matches!(
        session.readiness(),
        MqttReadiness::Ready {
            credential_revision: 1,
            ..
        }
    ));

    // Valid leaf identity for the live client_id, but an unrelated CA that cannot trust the broker.
    // prepare_tls succeeds so reload enters the broker handshake path, then last-good rolls back.
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let wrong_ca = rcgen::CertifiedIssuer::self_signed(
        ca_params,
        rcgen::KeyPair::generate().expect("wrong ca key"),
    )
    .expect("wrong ca");
    let unusable = MqttTlsMaterial::new(
        SecretMaterial::new(wrong_ca.pem().into_bytes()),
        SecretMaterial::new(
            fixture
                .rss_a()
                .tls()
                .certificate_pem()
                .expect("rss_a cert")
                .as_bytes()
                .to_vec(),
        ),
        SecretMaterial::new(
            fixture
                .rss_a()
                .tls()
                .private_key_pem()
                .expect("rss_a key")
                .as_bytes()
                .to_vec(),
        ),
    );
    assert!(
        session
            .reload_credentials(unusable, CredentialRevision::new(2).expect("rev"))
            .await
            .is_err(),
        "unusable TLS material must fail reload"
    );
    assert!(
        matches!(
            session.readiness(),
            MqttReadiness::Ready {
                credential_revision: 1,
                ..
            }
        ),
        "last-good rss_a revision must remain ready after failed reload"
    );
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn broker_restart_restores_ready_session() -> anyhow::Result<()> {
    let mut fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    assert!(matches!(
        session.readiness(),
        MqttReadiness::Ready {
            session_present: false,
            ..
        }
    ));
    // Disconnect with session expiry so the broker keeps the persistent session across restart.
    session.shutdown().await?;
    fixture.restart().await?;

    let restored = connect_session(&fixture, fixture.rss_a()).await;
    assert!(
        matches!(
            restored.readiness(),
            MqttReadiness::Ready {
                session_present: true,
                ..
            }
        ),
        "reconnect after true broker restart must restore session_present"
    );
    restored.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn offline_persistent_device_receives_broker_accepted_downlink_after_reconnect()
-> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let topic = policy_current()
        .command_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("command topic");
    let (device, mut device_loop) =
        persistent_device_client(&fixture, fixture.device_current(), true);
    assert!(
        wait_connack(&mut device_loop).await,
        "device mTLS must succeed"
    );
    device
        .subscribe_many([Filter::new(topic.as_str(), QoS::AtLeastOnce)])
        .await
        .expect("persistent subscribe queued");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                device_loop.poll().await.expect("prime poll"),
                Event::Incoming(Packet::SubAck(_))
            ) {
                break;
            }
        }
    })
    .await
    .expect("persistent subscription accepted");
    device.disconnect().await.expect("disconnect queued");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                device_loop.poll().await.expect("disconnect poll"),
                Event::Outgoing(rumqttc::Outgoing::Disconnect)
            ) {
                break;
            }
        }
    })
    .await
    .expect("device disconnected with persistent expiry");
    drop(device);
    drop(device_loop);

    let session = connect_session(&fixture, fixture.rss_a()).await;
    session
        .send_command(
            TenantId::parse(TENANT)?,
            DeviceId::parse(DEVICE)?,
            &MessageId::new("offline-command-1"),
            br#"{"op":"apply"}"#.to_vec(),
        )
        .await
        .expect("broker accepted offline command");

    let (_restored, mut restored_loop) =
        persistent_device_client(&fixture, fixture.device_current(), false);
    let session_present = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match restored_loop.poll().await.expect("restore poll") {
                Event::Incoming(Packet::ConnAck(ack)) => return ack.session_present,
                Event::Incoming(_) | Event::Outgoing(_) => {}
            }
        }
    })
    .await
    .expect("reconnect CONNACK");
    assert!(session_present, "broker must restore the primed session");
    let received = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match restored_loop.poll().await.expect("queued delivery poll") {
                Event::Incoming(Packet::Publish(publish)) => return publish.payload.to_vec(),
                Event::Incoming(_) | Event::Outgoing(_) => {}
            }
        }
    })
    .await
    .expect("queued downlink restored");
    assert_eq!(received, br#"{"op":"apply"}"#);
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn downlink_resolves_session_scope_and_returns_transport_only_puback() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let accepted = session
        .send_command(
            vocab::TenantId::parse(TENANT)?,
            ids::DeviceId::parse(DEVICE)?,
            &MessageId::new("cmd-1"),
            br#"{"op":"apply"}"#.to_vec(),
        )
        .await
        .expect("broker accepted");
    assert_eq!(format!("{accepted:?}"), "BrokerAccepted");
    session.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn downlink_unknown_device_returns_publish_invalid_without_delivery() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let topic = policy_current()
        .command_topic(&scope(TENANT, CURRENT_GENERATION))
        .expect("command topic");
    let (device, mut device_loop) = device_client(&fixture, fixture.device_current());
    assert!(
        wait_connack(&mut device_loop).await,
        "device mTLS must succeed"
    );
    device
        .subscribe_many([Filter::new(topic.as_str(), QoS::AtLeastOnce)])
        .await
        .expect("subscribe queued");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                device_loop.poll().await.expect("suback poll"),
                Event::Incoming(Packet::SubAck(_))
            ) {
                break;
            }
        }
    })
    .await
    .expect("subscription accepted");

    let session = connect_session(&fixture, fixture.rss_a()).await;
    let unknown = DeviceId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")?;
    let err = session
        .send_command(
            TenantId::parse(TENANT)?,
            unknown,
            &MessageId::new("cmd-unknown-device"),
            br#"{"op":"apply"}"#.to_vec(),
        )
        .await;
    assert!(
        matches!(err, Err(MqttSessionError::PublishInvalid)),
        "unknown device must fail closed as PublishInvalid: {err:?}"
    );

    let leaked = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match device_loop.poll().await.expect("idle poll") {
                Event::Incoming(Packet::Publish(publish)) => return Some(publish.payload.to_vec()),
                Event::Incoming(_) | Event::Outgoing(_) => {}
            }
        }
    })
    .await;
    assert!(
        leaked.is_err(),
        "unknown-device publish must not deliver downlink"
    );

    session.shutdown().await?;
    Ok(())
}
