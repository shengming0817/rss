#![allow(clippy::expect_used)] // reason: deterministic PKI fixture construction fails loudly.

use std::time::Duration;

use diport::SecretMaterial;
use ids::DeviceId;
use mqtt::{
    BrokerAssertionVerifier, CredentialGeneration, CredentialRevision, DeviceScope,
    MqttSessionConfig, MqttTlsMaterial, MqttTopicPolicy, MqttsEndpoint, SessionExpiry,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use vocab::TenantId;

const CLIENT_ID: &str = "rss-control-plane-01";

struct Pki {
    ca: String,
    cert: String,
    key: String,
    other_key: String,
}

fn pki(client_id: &str, client_auth: bool) -> Pki {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().expect("CA key"))
        .expect("self-signed CA");

    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, client_id);
    if client_auth {
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    }
    let cert = params.signed_by(&key, &ca).expect("client certificate");
    Pki {
        ca: ca.pem(),
        cert: cert.pem(),
        key: key.serialize_pem(),
        other_key: KeyPair::generate().expect("other key").serialize_pem(),
    }
}

fn policy() -> MqttTopicPolicy {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant");
    let device = DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("canonical device");
    let generation = CredentialGeneration::new(3).expect("positive generation");
    MqttTopicPolicy::new(vec![DeviceScope::new(tenant, device, generation)]).expect("one scope")
}

fn material(pki: &Pki, key: &str) -> MqttTlsMaterial {
    MqttTlsMaterial::new(
        SecretMaterial::new(pki.ca.as_bytes().to_vec()),
        SecretMaterial::new(pki.cert.as_bytes().to_vec()),
        SecretMaterial::new(key.as_bytes().to_vec()),
    )
}

fn config_with(
    pki: &Pki,
    client_id: &str,
    key: &str,
) -> Result<MqttSessionConfig, mqtt::MqttConfigError> {
    MqttSessionConfig::new(
        MqttsEndpoint::parse("mqtts://broker.example.com:8883").expect("endpoint"),
        client_id,
        material(pki, key),
        BrokerAssertionVerifier::new([7; 32]).expect("nonzero public key"),
        policy(),
        SessionExpiry::new(Duration::from_secs(3600)).expect("bounded expiry"),
        CredentialRevision::new(1).expect("positive revision"),
    )
}

#[test]
fn session_expiry_is_explicit_and_bounded() {
    assert!(SessionExpiry::new(Duration::from_secs(60)).is_ok());
    assert!(SessionExpiry::new(Duration::from_secs(7 * 24 * 60 * 60)).is_ok());
    assert!(SessionExpiry::new(Duration::ZERO).is_err());
    assert!(SessionExpiry::new(Duration::from_secs(59)).is_err());
    assert!(SessionExpiry::new(Duration::from_secs(7 * 24 * 60 * 60 + 1)).is_err());
}

#[test]
fn valid_owned_tls_material_builds_an_explicit_client_config() {
    let pki = pki(CLIENT_ID, true);
    assert!(config_with(&pki, CLIENT_ID, &pki.key).is_ok());
}

#[test]
fn client_identity_key_and_eku_are_fail_closed() {
    let valid = pki(CLIENT_ID, true);
    assert!(config_with(&valid, "different-client", &valid.key).is_err());
    assert!(config_with(&valid, CLIENT_ID, &valid.other_key).is_err());

    let no_client_auth = pki(CLIENT_ID, false);
    assert!(config_with(&no_client_auth, CLIENT_ID, &no_client_auth.key).is_err());
}

#[test]
fn secret_material_config_and_errors_are_opaque() {
    let pki = pki(CLIENT_ID, true);
    let tls = material(&pki, &pki.key);
    let rendered = format!("{tls:?}");
    assert_eq!(rendered, "MqttTlsMaterial(<redacted>)");
    assert!(!rendered.contains("PRIVATE KEY"));
    assert!(!rendered.contains("CERTIFICATE"));

    let error = config_with(&pki, "different-client", &pki.key).expect_err("CN mismatch must fail");
    assert_eq!(error, mqtt::MqttConfigError::ClientIdMismatch);
    assert_eq!(
        error.to_string(),
        "mqtt client id does not match certificate"
    );
    assert_eq!(format!("{error:?}"), "ClientIdMismatch");
}
