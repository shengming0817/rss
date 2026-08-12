use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::topic::{CredentialGeneration, DeviceScope, MqttTopicPolicy, parse_generation};

const ASSERTION_DOMAIN: &[u8] = b"rss.mqtt.authn.v1\0";
const RESERVED_PREFIX: &str = "rss.authn.v1.";
const VERSION_KEY: &str = "rss.authn.v1.version";
const PRINCIPAL_KEY: &str = "rss.authn.v1.principal";
const SIGNATURE_KEY: &str = "rss.authn.v1.signature";
const VERSION: &str = "1";

/// Borrowed MQTT v5 publish fields covered by the broker assertion.
pub struct BrokerPublishFrame<'a> {
    topic: &'a str,
    payload: &'a [u8],
    correlation: Option<&'a [u8]>,
    qos: u8,
    retain: bool,
    properties: &'a [(String, String)],
}

impl<'a> BrokerPublishFrame<'a> {
    pub fn new(
        topic: &'a str,
        payload: &'a [u8],
        correlation: Option<&'a [u8]>,
        qos: u8,
        retain: bool,
        properties: &'a [(String, String)],
    ) -> Self {
        Self {
            topic,
            payload,
            correlation,
            qos,
            retain,
            properties,
        }
    }
}

/// Ed25519 broker assertion verifier. It owns only public material.
pub struct BrokerAssertionVerifier {
    public_key: [u8; 32],
}

impl std::fmt::Debug for BrokerAssertionVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrokerAssertionVerifier(<public-key>)")
    }
}

impl BrokerAssertionVerifier {
    pub fn new(public_key: [u8; 32]) -> Result<Self, BrokerAssertionError> {
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(BrokerAssertionError);
        }
        Ok(Self { public_key })
    }

    pub fn verify(
        &self,
        policy: &MqttTopicPolicy,
        frame: &BrokerPublishFrame<'_>,
    ) -> Result<VerifiedBrokerAssertion, BrokerAssertionError> {
        if frame.qos != 1 {
            return Err(BrokerAssertionError);
        }
        let assertion = assertion_properties(frame.properties)?;
        let (scope, _) = policy
            .resolve_uplink(frame.topic)
            .ok_or(BrokerAssertionError)?;
        let principal = parse_principal(assertion.principal)?;
        if &principal != scope {
            return Err(BrokerAssertionError);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(assertion.signature)
            .map_err(|_| BrokerAssertionError)?;
        if signature.len() != 64 {
            return Err(BrokerAssertionError);
        }
        let signed = canonical_bytes(assertion.principal, frame)?;
        UnparsedPublicKey::new(&ED25519, self.public_key)
            .verify(&signed, &signature)
            .map_err(|_| BrokerAssertionError)?;
        Ok(VerifiedBrokerAssertion { principal })
    }
}

struct AssertionProperties<'a> {
    principal: &'a str,
    signature: &'a str,
}

fn assertion_properties(
    properties: &[(String, String)],
) -> Result<AssertionProperties<'_>, BrokerAssertionError> {
    let mut version = None;
    let mut principal = None;
    let mut signature = None;
    for (key, value) in properties {
        if !key.starts_with(RESERVED_PREFIX) {
            continue;
        }
        let slot = match key.as_str() {
            VERSION_KEY => &mut version,
            PRINCIPAL_KEY => &mut principal,
            SIGNATURE_KEY => &mut signature,
            _ => return Err(BrokerAssertionError),
        };
        if slot.replace(value.as_str()).is_some() {
            return Err(BrokerAssertionError);
        }
    }
    if version != Some(VERSION) {
        return Err(BrokerAssertionError);
    }
    Ok(AssertionProperties {
        principal: principal.ok_or(BrokerAssertionError)?,
        signature: signature.ok_or(BrokerAssertionError)?,
    })
}

fn parse_principal(raw: &str) -> Result<DeviceScope, BrokerAssertionError> {
    let mut parts = raw.split(':');
    if parts.next() != Some("urn")
        || parts.next() != Some("rss")
        || parts.next() != Some("mqtt-device")
        || parts.next() != Some("v1")
    {
        return Err(BrokerAssertionError);
    }
    let tenant_raw = parts.next().ok_or(BrokerAssertionError)?;
    let device_raw = parts.next().ok_or(BrokerAssertionError)?;
    let generation_raw = parts.next().ok_or(BrokerAssertionError)?;
    if parts.next().is_some() {
        return Err(BrokerAssertionError);
    }
    let tenant =
        rss_request_context::TenantId::parse(tenant_raw).map_err(|_| BrokerAssertionError)?;
    let device = ids::DeviceId::parse(device_raw).map_err(|_| BrokerAssertionError)?;
    if device.as_uuid().hyphenated().to_string() != device_raw {
        return Err(BrokerAssertionError);
    }
    let generation =
        CredentialGeneration::new(parse_generation(generation_raw).ok_or(BrokerAssertionError)?)
            .map_err(|_| BrokerAssertionError)?;
    Ok(DeviceScope::new(tenant, device, generation))
}

pub(crate) fn canonical_bytes(
    principal: &str,
    frame: &BrokerPublishFrame<'_>,
) -> Result<Vec<u8>, BrokerAssertionError> {
    let mut bytes = ASSERTION_DOMAIN.to_vec();
    append_field(&mut bytes, VERSION.as_bytes())?;
    append_field(&mut bytes, principal.as_bytes())?;
    append_field(&mut bytes, frame.topic.as_bytes())?;
    append_field(&mut bytes, frame.correlation.unwrap_or_default())?;
    append_field(&mut bytes, digest(&SHA256, frame.payload).as_ref())?;
    append_field(&mut bytes, &[frame.qos])?;
    append_field(&mut bytes, &[u8::from(frame.retain)])?;
    Ok(bytes)
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) -> Result<(), BrokerAssertionError> {
    let len = u32::try_from(value.len()).map_err(|_| BrokerAssertionError)?;
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

/// Proof that the broker assertion was valid for the current exact policy.
pub struct VerifiedBrokerAssertion {
    principal: DeviceScope,
}

impl std::fmt::Debug for VerifiedBrokerAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedBrokerAssertion(<verified>)")
    }
}

impl VerifiedBrokerAssertion {
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.principal.tenant()
    }

    pub fn device(&self) -> ids::DeviceId {
        self.principal.device()
    }

    pub fn generation(&self) -> CredentialGeneration {
        self.principal.generation()
    }

    pub(crate) fn into_scope(self) -> DeviceScope {
        self.principal
    }
}

#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("mqtt broker assertion rejected")]
pub struct BrokerAssertionError;

impl std::fmt::Debug for BrokerAssertionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrokerAssertionError(\"mqtt broker assertion rejected\")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_ed25519_public_key_is_rejected() {
        assert!(BrokerAssertionVerifier::new([0; 32]).is_err());
    }

    #[test]
    fn principal_generation_rejects_leading_zeros() {
        let principal = concat!(
            "urn:rss:mqtt-device:v1:",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479:",
            "550e8400-e29b-41d4-a716-446655440000:01"
        );
        assert!(parse_principal(principal).is_err());
    }

    #[test]
    fn parse_generation_rejects_leading_zero_forms() {
        assert!(parse_generation("01").is_none());
        assert!(parse_generation("0").is_none());
        assert!(parse_generation("7").is_some());
        assert!(parse_generation("10").is_some());
    }
}
