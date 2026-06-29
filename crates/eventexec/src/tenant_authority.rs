//! Tenant authority token for broker-delivered event envelopes.
//!
//! The outbox relay signs the tenant/topic binding before publishing to broker. Consumers verify
//! the token before using `tenantId` for DLX RLS scope, so broker headers are not trusted by
//! themselves.
//!
//! ref: RustCrypto/MACs hmac/README.md@master (HMAC-SHA256 sign/verify primitive)

use std::sync::Arc;

use base64::Engine as _;
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use serde::{Deserialize, Serialize};

const TOKEN_VERSION: &str = "v1";
const ISSUER: &str = "rss-outbox-relay";
const AUDIENCE: &str = "rss-event-consumer";
const HMAC_KEY_MIN_BYTES: usize = 32;
const CLOCK_SKEW_MAX_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TenantAuthorityConfigError {
    #[error("tenant authority HMAC key must be at least 32 bytes")]
    WeakKey,
    #[error("tenant authority ttl must be greater than zero")]
    InvalidTtl,
    #[error("tenant authority clock skew must be at most 300 seconds")]
    InvalidClockSkew,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TenantAuthoritySignError {
    #[error("tenant authority payload serialization failed")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TenantAuthorityError {
    #[error("tenant authority token is missing")]
    Missing,
    #[error("tenant metadata is missing or invalid")]
    TenantMissing,
    #[error("tenant authority token is malformed")]
    Malformed,
    #[error("tenant authority token MAC is invalid")]
    BadMac,
    #[error("tenant authority token is expired or not yet valid")]
    Expired,
    #[error("tenant authority token binding mismatch")]
    BindingMismatch,
}

impl TenantAuthorityError {
    pub const fn skip_reason(self) -> &'static str {
        match self {
            Self::Missing => "tenant_authority_missing",
            Self::TenantMissing => "tenant_authority_missing",
            Self::Malformed | Self::BadMac => "tenant_authority_invalid",
            Self::Expired => "tenant_authority_expired",
            Self::BindingMismatch => "tenant_authority_binding_mismatch",
        }
    }
}

#[derive(Clone)]
pub struct TenantAuthority {
    mac: Arc<dyn MacVerifier + Send + Sync>,
    key: MacKey,
    ttl_secs: u64,
    clock_skew_secs: u64,
    now_epoch_secs: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl std::fmt::Debug for TenantAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantAuthority")
            .field("mac", &"<provider>")
            .field("key", &"<redacted>")
            .field("ttl_secs", &self.ttl_secs)
            .field("clock_skew_secs", &self.clock_skew_secs)
            .finish_non_exhaustive()
    }
}

impl TenantAuthority {
    pub fn new(
        mac: Arc<dyn MacVerifier + Send + Sync>,
        key: MacKey,
        ttl_secs: u64,
        clock_skew_secs: u64,
        now_epoch_secs: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, TenantAuthorityConfigError> {
        if key.as_bytes().len() < HMAC_KEY_MIN_BYTES {
            return Err(TenantAuthorityConfigError::WeakKey);
        }
        if ttl_secs == 0 {
            return Err(TenantAuthorityConfigError::InvalidTtl);
        }
        if clock_skew_secs > CLOCK_SKEW_MAX_SECS {
            return Err(TenantAuthorityConfigError::InvalidClockSkew);
        }
        Ok(Self {
            mac,
            key,
            ttl_secs,
            clock_skew_secs,
            now_epoch_secs,
        })
    }

    pub fn sign(
        &self,
        binding: TenantAuthorityBinding<'_>,
    ) -> Result<String, TenantAuthoritySignError> {
        let iat = (self.now_epoch_secs)();
        self.sign_at(binding, iat)
    }

    pub fn sign_at(
        &self,
        binding: TenantAuthorityBinding<'_>,
        iat: i64,
    ) -> Result<String, TenantAuthoritySignError> {
        let exp = iat.saturating_add(i64::try_from(self.ttl_secs).unwrap_or(i64::MAX));
        let payload = TenantAuthorityPayload::from_binding(binding, iat, exp);
        let payload_json = serde_json::to_vec(&payload)?;
        let payload_b64 = b64().encode(payload_json);
        let tag = self.mac.sign(
            &self.key,
            MacAlgorithm::HmacSha256,
            &canonical_input(&payload),
        );
        Ok(format!(
            "{TOKEN_VERSION}.{payload_b64}.{}",
            b64().encode(tag.as_bytes())
        ))
    }

    pub fn verify(
        &self,
        binding: TenantAuthorityBinding<'_>,
        metadata: &diport::EnvelopeMetadata,
    ) -> Result<vocab::TenantId, TenantAuthorityError> {
        let metadata_tenant = metadata
            .tenant_id()
            .ok_or(TenantAuthorityError::TenantMissing)?;
        let token = metadata
            .get(diport::KEY_TENANT_AUTHORITY)
            .ok_or(TenantAuthorityError::Missing)?;
        let payload = self.verify_token(token)?;
        let signed_tenant = vocab::TenantId::parse(&payload.tenant_id)
            .map_err(|_| TenantAuthorityError::Malformed)?;
        if signed_tenant != binding.tenant || metadata_tenant != binding.tenant {
            return Err(TenantAuthorityError::BindingMismatch);
        }
        if payload.issuer() != ISSUER
            || payload.audience() != AUDIENCE
            || payload.domain != binding.domain
            || payload.contract_id != binding.contract_id
            || payload.topic != binding.topic
            || payload.message_id != binding.message_id
        {
            return Err(TenantAuthorityError::BindingMismatch);
        }
        let now = (self.now_epoch_secs)();
        let skew = i64::try_from(self.clock_skew_secs).unwrap_or(i64::MAX);
        let max_lifetime = i64::try_from(self.ttl_secs).unwrap_or(i64::MAX);
        let token_lifetime = payload
            .exp
            .checked_sub(payload.iat)
            .ok_or(TenantAuthorityError::Expired)?;
        if token_lifetime <= 0 || token_lifetime > max_lifetime {
            return Err(TenantAuthorityError::Expired);
        }
        if payload.iat > now.saturating_add(skew) || now > payload.exp.saturating_add(skew) {
            return Err(TenantAuthorityError::Expired);
        }
        Ok(signed_tenant)
    }

    fn verify_token(&self, token: &str) -> Result<TenantAuthorityPayload, TenantAuthorityError> {
        let mut parts = token.split('.');
        let Some(version) = parts.next() else {
            return Err(TenantAuthorityError::Malformed);
        };
        let Some(payload_part) = parts.next() else {
            return Err(TenantAuthorityError::Malformed);
        };
        let Some(tag_part) = parts.next() else {
            return Err(TenantAuthorityError::Malformed);
        };
        if parts.next().is_some() || version != TOKEN_VERSION {
            return Err(TenantAuthorityError::Malformed);
        }
        let payload_bytes = b64()
            .decode(payload_part)
            .map_err(|_| TenantAuthorityError::Malformed)?;
        let payload: TenantAuthorityPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| TenantAuthorityError::Malformed)?;
        let tag = Mac::from_bytes(
            b64()
                .decode(tag_part)
                .map_err(|_| TenantAuthorityError::Malformed)?,
        );
        if !self.mac.verify(
            &self.key,
            MacAlgorithm::HmacSha256,
            &canonical_input(&payload),
            &tag,
        ) {
            return Err(TenantAuthorityError::BadMac);
        }
        Ok(payload)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TenantAuthorityBinding<'a> {
    tenant: vocab::TenantId,
    domain: &'a str,
    contract_id: &'a str,
    topic: &'a str,
    message_id: &'a str,
}

impl<'a> TenantAuthorityBinding<'a> {
    pub fn new(
        tenant: vocab::TenantId,
        domain: &'a str,
        contract_id: &'a str,
        topic: &'a str,
        message_id: &'a str,
    ) -> Self {
        Self {
            tenant,
            domain,
            contract_id,
            topic,
            message_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
struct TenantAuthorityPayload {
    iss: String,
    aud: String,
    tenant_id: String,
    domain: String,
    contract_id: String,
    topic: String,
    message_id: String,
    iat: i64,
    exp: i64,
}

impl TenantAuthorityPayload {
    fn from_binding(binding: TenantAuthorityBinding<'_>, iat: i64, exp: i64) -> Self {
        Self {
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            tenant_id: binding.tenant.to_string(),
            domain: binding.domain.to_string(),
            contract_id: binding.contract_id.to_string(),
            topic: binding.topic.to_string(),
            message_id: binding.message_id.to_string(),
            iat,
            exp,
        }
    }

    fn issuer(&self) -> &str {
        &self.iss
    }

    fn audience(&self) -> &str {
        &self.aud
    }
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn canonical_input(payload: &TenantAuthorityPayload) -> Vec<u8> {
    let mut out = Vec::new();
    append_str(&mut out, "v", TOKEN_VERSION);
    append_str(&mut out, "iss", payload.issuer());
    append_str(&mut out, "aud", payload.audience());
    append_str(&mut out, "tenantId", &payload.tenant_id);
    append_str(&mut out, "domain", &payload.domain);
    append_str(&mut out, "contractId", &payload.contract_id);
    append_str(&mut out, "topic", &payload.topic);
    append_str(&mut out, "messageId", &payload.message_id);
    append_i64(&mut out, "iat", payload.iat);
    append_i64(&mut out, "exp", payload.exp);
    out
}

fn append_str(out: &mut Vec<u8>, key: &str, value: &str) {
    out.extend_from_slice(key.as_bytes());
    out.push(b':');
    out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(b'\n');
}

fn append_i64(out: &mut Vec<u8>, key: &str, value: i64) {
    out.extend_from_slice(key.as_bytes());
    out.push(b':');
    out.extend_from_slice(&8u32.to_be_bytes());
    out.extend_from_slice(&value.to_be_bytes());
    out.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::{Mac, MacAlgorithm};

    #[derive(Debug)]
    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut tag = Vec::from(key.as_bytes());
            tag.extend_from_slice(message);
            Mac::from_bytes(tag)
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn authority(now: i64) -> TenantAuthority {
        TenantAuthority::new(
            Arc::new(TestMac),
            MacKey::from_bytes(vec![0x42; 32]),
            60,
            5,
            Arc::new(move || now),
        )
        .expect("valid authority")
    }

    fn binding<'a>(message_id: &'a str) -> TenantAuthorityBinding<'a> {
        TenantAuthorityBinding::new(
            tenant(),
            "identity",
            "contract-session",
            "identity.session-created",
            message_id,
        )
    }

    fn metadata(token: String) -> diport::EnvelopeMetadata {
        let mut md = diport::EnvelopeMetadata::empty();
        md.insert_wire_pair(diport::KEY_TENANT_ID, tenant().to_string());
        md.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
        md
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn sign_verify_round_trip() {
        let auth = authority(1_700_000_000);
        let token = auth.sign(binding("msg-1")).expect("signed");
        let md = metadata(token);
        let verified = auth.verify(binding("msg-1"), &md).expect("verified");
        assert_eq!(verified, tenant());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn verify_rejects_tampered_binding() {
        let auth = authority(1_700_000_000);
        let md = metadata(auth.sign(binding("msg-1")).expect("signed"));
        let err = auth
            .verify(binding("msg-2"), &md)
            .expect_err("message binding mismatch must fail");
        assert_eq!(err, TenantAuthorityError::BindingMismatch);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn verify_rejects_expired_token() {
        let signer = authority(1_700_000_000);
        let verifier = authority(1_700_000_066);
        let md = metadata(signer.sign(binding("msg-1")).expect("signed"));
        let err = verifier
            .verify(binding("msg-1"), &md)
            .expect_err("expired token must fail");
        assert_eq!(err, TenantAuthorityError::Expired);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn verify_accepts_bounded_clock_skew() {
        let signer = authority(1_700_000_000);
        let verifier = authority(1_700_000_064);
        let md = metadata(signer.sign(binding("msg-1")).expect("signed"));
        let verified = verifier.verify(binding("msg-1"), &md).expect("verified");
        assert_eq!(verified, tenant());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn verify_rejects_token_lifetime_above_local_policy() {
        let signer = TenantAuthority::new(
            Arc::new(TestMac),
            MacKey::from_bytes(vec![0x42; 32]),
            600,
            5,
            Arc::new(|| 1_700_000_000),
        )
        .expect("valid signer");
        let verifier = authority(1_700_000_010);
        let md = metadata(signer.sign(binding("msg-1")).expect("signed"));
        let err = verifier
            .verify(binding("msg-1"), &md)
            .expect_err("verifier ttl policy must cap token lifetime");
        assert_eq!(err, TenantAuthorityError::Expired);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn verify_rejects_tampered_tag() {
        let auth = authority(1_700_000_000);
        let mut token = auth.sign(binding("msg-1")).expect("signed");
        token.push('x');
        let md = metadata(token);
        let err = auth
            .verify(binding("msg-1"), &md)
            .expect_err("tampered token must fail");
        assert!(matches!(
            err,
            TenantAuthorityError::Malformed | TenantAuthorityError::BadMac
        ));
    }
}
