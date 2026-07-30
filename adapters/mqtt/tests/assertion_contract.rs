#![allow(clippy::expect_used)] // reason: deterministic cryptographic test fixtures fail loudly.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mqtt::{
    BrokerAssertionVerifier, BrokerPublishFrame, CredentialGeneration, DeviceScope, MqttTopicPolicy,
};
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const DEVICE: &str = "550e8400-e29b-41d4-a716-446655440000";
const PRINCIPAL: &str = concat!(
    "urn:rss:mqtt-device:v1:",
    "f47ac10b-58cc-4372-a567-0e02b2c3d479:",
    "550e8400-e29b-41d4-a716-446655440000:7"
);
const VERSION_KEY: &str = "rss.authn.v1.version";
const PRINCIPAL_KEY: &str = "rss.authn.v1.principal";
const SIGNATURE_KEY: &str = "rss.authn.v1.signature";

fn policy() -> MqttTopicPolicy {
    let tenant = vocab::TenantId::parse(TENANT).expect("canonical tenant");
    let device = ids::DeviceId::parse(DEVICE).expect("canonical device");
    let generation = CredentialGeneration::new(7).expect("positive generation");
    MqttTopicPolicy::new(vec![DeviceScope::new(tenant, device, generation)])
        .expect("one exact device scope")
}

fn command_acked_topic() -> String {
    let tenant = vocab::TenantId::parse(TENANT).expect("canonical tenant");
    let device = ids::DeviceId::parse(DEVICE).expect("canonical device");
    let generation = CredentialGeneration::new(7).expect("positive generation");
    let scope = DeviceScope::new(tenant, device, generation);
    policy()
        .command_acked_topic(&scope)
        .expect("policy mints command-acked topic")
        .as_str()
        .to_owned()
}

fn certificate_reported_topic() -> String {
    let tenant = vocab::TenantId::parse(TENANT).expect("canonical tenant");
    let device = ids::DeviceId::parse(DEVICE).expect("canonical device");
    let generation = CredentialGeneration::new(7).expect("positive generation");
    let scope = DeviceScope::new(tenant, device, generation);
    policy()
        .certificate_reported_topic(&scope)
        .expect("policy mints certificate-reported topic")
        .as_str()
        .to_owned()
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("test field fits u32");
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(value);
}

fn canonical(
    principal: &str,
    topic: &str,
    payload: &[u8],
    correlation: Option<&[u8]>,
    qos: u8,
    retain: bool,
) -> Vec<u8> {
    let mut bytes = b"rss.mqtt.authn.v1\0".to_vec();
    append_field(&mut bytes, b"1");
    append_field(&mut bytes, principal.as_bytes());
    append_field(&mut bytes, topic.as_bytes());
    append_field(&mut bytes, correlation.unwrap_or_default());
    append_field(&mut bytes, digest(&SHA256, payload).as_ref());
    append_field(&mut bytes, &[qos]);
    append_field(&mut bytes, &[u8::from(retain)]);
    bytes
}

fn signed_properties(
    key: &Ed25519KeyPair,
    principal: &str,
    topic: &str,
    payload: &[u8],
    correlation: Option<&[u8]>,
    qos: u8,
    retain: bool,
) -> Vec<(String, String)> {
    let signature = key.sign(&canonical(
        principal,
        topic,
        payload,
        correlation,
        qos,
        retain,
    ));
    vec![
        (VERSION_KEY.into(), "1".into()),
        (PRINCIPAL_KEY.into(), principal.into()),
        (
            SIGNATURE_KEY.into(),
            URL_SAFE_NO_PAD.encode(signature.as_ref()),
        ),
    ]
}

fn verifier_and_key() -> (BrokerAssertionVerifier, Ed25519KeyPair) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate test key");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse generated key");
    let public_key: [u8; 32] = pair
        .public_key()
        .as_ref()
        .try_into()
        .expect("Ed25519 public key is 32 bytes");
    (
        BrokerAssertionVerifier::new(public_key).expect("valid public key"),
        pair,
    )
}

#[test]
fn valid_assertion_mints_verified_principal() {
    let payload = br#"{"result":"accepted"}"#;
    let correlation = Some(b"command-42".as_slice());
    let topic = command_acked_topic();
    let (verifier, key) = verifier_and_key();
    let properties = signed_properties(&key, PRINCIPAL, &topic, payload, correlation, 1, false);
    let frame = BrokerPublishFrame::new(&topic, payload, correlation, 1, false, &properties);

    let verified = verifier
        .verify(&policy(), &frame)
        .expect("valid broker assertion");
    assert_eq!(verified.tenant().to_string(), TENANT);
    assert_eq!(verified.device().as_uuid().hyphenated().to_string(), DEVICE);
    assert_eq!(verified.generation().get(), 7);
}

#[test]
fn every_signed_coordinate_is_bound_and_fail_closed() {
    let payload = b"payload-v1";
    let correlation = Some(b"corr-v1".as_slice());
    let topic = command_acked_topic();
    let wrong_topic = certificate_reported_topic();
    let (verifier, key) = verifier_and_key();
    let properties = signed_properties(&key, PRINCIPAL, &topic, payload, correlation, 1, false);

    let cases = [
        BrokerPublishFrame::new(&topic, b"payload-v2", correlation, 1, false, &properties),
        BrokerPublishFrame::new(&wrong_topic, payload, correlation, 1, false, &properties),
        BrokerPublishFrame::new(&topic, payload, Some(b"corr-v2"), 1, false, &properties),
        BrokerPublishFrame::new(&topic, payload, correlation, 0, false, &properties),
        BrokerPublishFrame::new(&topic, payload, correlation, 1, true, &properties),
    ];

    for frame in cases {
        let error = verifier
            .verify(&policy(), &frame)
            .expect_err("tampered signed coordinate must fail");
        assert_eq!(error.to_string(), "mqtt broker assertion rejected");
    }
}

#[test]
fn missing_duplicate_malformed_and_stale_assertions_are_rejected() {
    let payload = b"payload";
    let topic = command_acked_topic();
    let (verifier, key) = verifier_and_key();
    let valid = signed_properties(&key, PRINCIPAL, &topic, payload, None, 1, false);

    let missing = valid[..2].to_vec();
    let mut duplicate = valid.clone();
    duplicate.push((SIGNATURE_KEY.into(), valid[2].1.clone()));
    let mut malformed = valid.clone();
    malformed[2].1 = "not-base64url".into();
    let stale_principal = PRINCIPAL.replace(":7", ":6");
    let stale = signed_properties(&key, &stale_principal, &topic, payload, None, 1, false);

    for properties in [missing, duplicate, malformed, stale] {
        let frame = BrokerPublishFrame::new(&topic, payload, None, 1, false, &properties);
        assert!(
            verifier.verify(&policy(), &frame).is_err(),
            "invalid assertion form must fail closed"
        );
    }
}

#[test]
fn client_supplied_reserved_property_family_is_rejected() {
    let payload = b"payload";
    let topic = command_acked_topic();
    let (verifier, key) = verifier_and_key();
    let mut properties = signed_properties(&key, PRINCIPAL, &topic, payload, None, 1, false);
    properties.push(("rss.authn.v1.attacker".into(), "spoof".into()));
    let frame = BrokerPublishFrame::new(&topic, payload, None, 1, false, &properties);
    assert!(verifier.verify(&policy(), &frame).is_err());
}
