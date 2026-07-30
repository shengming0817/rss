#![cfg(feature = "broker-tests")]
//! Hermetic Mosquitto mTLS + assertion + ACL + session T2 for #1902.
#![allow(clippy::expect_used, clippy::unwrap_used)] // reason: broker T2 fixtures fail loudly.

use std::sync::Arc;
use std::time::Duration;

use diport::{MessageId, SecretMaterial};
use ids::DeviceId;
use mqtt::{
    BrokerAssertionVerifier, CredentialGeneration, CredentialRevision, DeviceScope, MqttReadiness,
    MqttSession, MqttSessionConfig, MqttTlsMaterial, MqttTopicPolicy, MqttsEndpoint, SessionExpiry,
};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::PublishProperties;
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::{TlsConfiguration, Transport};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use testkit::{MqttCredential, MqttMtlsFixture};
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

    // Wire metadata / payload claims cannot mint MQTT identity: sealed principal lives only on
    // AuthenticatedDeviceDelivery, not on provider-agnostic Message.
    let message = delivery.to_message("evt-1");
    assert_eq!(message.payload.as_bytes(), br#"{"claim":"other-device"}"#);
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

    delivery.ack().await.expect("puback");
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
async fn downlink_puback_is_transport_only_capability() -> anyhow::Result<()> {
    let fixture = testkit::mosquitto_mtls().await?;
    let session = connect_session(&fixture, fixture.rss_a()).await;
    let accepted = session
        .send_command(
            &scope(TENANT, CURRENT_GENERATION),
            &MessageId::new("cmd-1"),
            br#"{"op":"apply"}"#.to_vec(),
        )
        .await
        .expect("broker accepted");
    assert_eq!(format!("{accepted:?}"), "BrokerAccepted");
    session.shutdown().await?;
    Ok(())
}
