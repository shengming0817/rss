use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::diagnostics::{Diagnostic, DiagnosticCode, DiagnosticsSnapshot, VerifyError};
use crate::identity::TenantId;

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SEGMENT_BYTES: usize = 12 * 1024;
const MAX_LIFETIME_SECS: i64 = 900;
const MAX_LEEWAY_SECS: u64 = 300;

pub struct AccessToken(Box<str>);

impl AccessToken {
    pub fn parse(value: &str) -> Result<Self, VerifyError> {
        if value.is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(invalid());
        }
        Ok(Self(value.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrincipalKind {
    User,
    Device,
    Admin,
    SuperAdmin,
}

/// Closed verification policy for profile-specific access-token claim names and clock skew.
pub struct VerificationPolicy {
    kind_claim: Box<str>,
    tenant_claim: Box<str>,
    leeway_secs: u64,
}

impl VerificationPolicy {
    pub fn new(
        kind_claim: &str,
        tenant_claim: &str,
        leeway_secs: u64,
    ) -> Result<Self, crate::BuildError> {
        if kind_claim.is_empty()
            || tenant_claim.is_empty()
            || kind_claim == tenant_claim
            || leeway_secs > MAX_LEEWAY_SECS
        {
            return Err(build_invalid());
        }
        Ok(Self {
            kind_claim: kind_claim.into(),
            tenant_claim: tenant_claim.into(),
            leeway_secs,
        })
    }
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            kind_claim: "kind".into(),
            tenant_claim: "tenant_id".into(),
            leeway_secs: 0,
        }
    }
}

pub struct VerifiedAccess {
    pub(crate) subject: Box<str>,
    pub(crate) tenant: Option<TenantId>,
    pub(crate) kind: PrincipalKind,
    permissions: Box<[Box<str>]>,
    issuer: Box<str>,
    audience: Box<str>,
    key_id: Box<str>,
    key_point: Box<[u8]>,
    valid_from: i64,
    valid_until: i64,
}

impl VerifiedAccess {
    pub fn principal_kind(&self) -> PrincipalKind {
        self.kind
    }
    pub fn tenant(&self) -> Option<&TenantId> {
        self.tenant.as_ref()
    }
    pub fn matches_subject(&self, candidate: &str) -> bool {
        self.subject.as_ref() == candidate
    }
    pub fn allows_permission(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|candidate| candidate.as_ref() == permission)
    }
}

pub struct TrustedIssuer {
    issuer: Box<str>,
    audience: Box<str>,
    keys: HashMap<Box<str>, TrustedKey>,
}

struct TrustedKey {
    verifying: VerifyingKey,
    point: Box<[u8]>,
}

impl TrustedIssuer {
    pub fn from_jwks_json(
        issuer: &str,
        audience: &str,
        jwks_json: &str,
    ) -> Result<Self, crate::BuildError> {
        if issuer.is_empty() || audience.is_empty() || jwks_json.len() > 256 * 1024 {
            return Err(build_invalid());
        }
        let document: Jwks = serde_json::from_str(jwks_json).map_err(|_| build_invalid())?;
        let mut keys = HashMap::new();
        for key in document.keys {
            if key.kty != "EC"
                || key.crv != "P-256"
                || key.alg != "ES256"
                || key.use_ != "sig"
                || key.kid.is_empty()
            {
                return Err(build_invalid());
            }
            let x = decode_coordinate(&key.x).ok_or_else(build_invalid)?;
            let y = decode_coordinate(&key.y).ok_or_else(build_invalid)?;
            let mut point = [0_u8; 65];
            point[0] = 4;
            point[1..33].copy_from_slice(&x);
            point[33..].copy_from_slice(&y);
            let verifying = VerifyingKey::from_sec1_bytes(&point).map_err(|_| build_invalid())?;
            let trusted = TrustedKey {
                verifying,
                point: point.into(),
            };
            if keys.insert(key.kid.into_boxed_str(), trusted).is_some() {
                return Err(build_invalid());
            }
        }
        if keys.is_empty() {
            return Err(build_invalid());
        }
        Ok(Self {
            issuer: issuer.into(),
            audience: audience.into(),
            keys,
        })
    }

    /// Verify one access token against this immutable trust snapshot.
    ///
    /// [`crate::Dispatcher::verify`] is the application-kernel funnel. This lower-level entry is
    /// also the single algorithm owner consumed by the repository's dynamic OIDC integration.
    pub fn verify(
        &self,
        token: &AccessToken,
        now: SystemTime,
    ) -> Result<VerifiedAccess, VerifyError> {
        self.verify_with_policy(token, now, &VerificationPolicy::default())
    }

    /// Verify with an immutable, bounded profile policy while retaining this issuer as the
    /// signature and claims-decision owner.
    pub fn verify_with_policy(
        &self,
        token: &AccessToken,
        now: SystemTime,
        policy: &VerificationPolicy,
    ) -> Result<VerifiedAccess, VerifyError> {
        let mut segments = token.as_str().split('.');
        let header_segment = segments.next().ok_or_else(invalid)?;
        let payload_segment = segments.next().ok_or_else(invalid)?;
        let signature_segment = segments.next().ok_or_else(invalid)?;
        if segments.next().is_some()
            || header_segment.len() > MAX_SEGMENT_BYTES
            || payload_segment.len() > MAX_SEGMENT_BYTES
            || signature_segment.len() > MAX_SEGMENT_BYTES
        {
            return Err(invalid());
        }
        let header_bytes = decode_segment(header_segment)?;
        let payload = decode_segment(payload_segment)?;
        let signature_bytes = decode_segment(signature_segment)?;
        let header_value: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| invalid())?;
        if header_value
            .as_object()
            .is_none_or(|header| header.contains_key("crit"))
        {
            return Err(invalid());
        }
        let header: Header = serde_json::from_value(header_value).map_err(|_| invalid())?;
        if header.alg != "ES256" || header.typ != "at+jwt" || header.kid.is_empty() {
            return Err(invalid());
        }
        let key = self.keys.get(header.kid.as_str()).ok_or_else(invalid)?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| invalid())?;
        let signing_input = format!("{header_segment}.{payload_segment}");
        key.verifying
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| invalid())?;

        let claims: Claims = serde_json::from_slice(&payload).map_err(|_| invalid())?;
        let now = unix_seconds(now)?;
        let valid_from = claims
            .nbf
            .unwrap_or(claims.iat)
            .max(claims.iat)
            .saturating_sub_unsigned(policy.leeway_secs);
        let valid_until = claims.exp.saturating_add_unsigned(policy.leeway_secs);
        if claims.iss != self.issuer.as_ref()
            || !claims.aud.contains(self.audience.as_ref())
            || claims.sub.is_empty()
            || claims.token_use != "access"
            || claims.iat > claims.exp
            || claims.exp - claims.iat > MAX_LIFETIME_SECS
            || now > valid_until
            || now < valid_from
        {
            return Err(invalid());
        }

        let (kind, tenant) = verified_identity(&claims, policy)?;
        let permissions = verified_permissions(claims.permissions)?;
        Ok(VerifiedAccess {
            subject: claims.sub.into_boxed_str(),
            tenant,
            kind,
            permissions,
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            key_id: header.kid.into_boxed_str(),
            key_point: key.point.clone(),
            valid_from,
            valid_until,
        })
    }

    pub(crate) fn accepts(&self, access: &VerifiedAccess) -> bool {
        access.issuer == self.issuer
            && access.audience == self.audience
            && self
                .keys
                .get(access.key_id.as_ref())
                .is_some_and(|key| key.point.as_ref() == access.key_point.as_ref())
    }
}

impl VerifiedAccess {
    pub(crate) fn is_fresh_at(&self, now: SystemTime) -> bool {
        unix_seconds(now).is_ok_and(|now| now >= self.valid_from && now <= self.valid_until)
    }
}

fn unix_seconds(now: SystemTime) -> Result<i64, VerifyError> {
    let elapsed = now.duration_since(UNIX_EPOCH).map_err(|_| invalid())?;
    i64::try_from(elapsed.as_secs()).map_err(|_| invalid())
}

fn decode_segment(value: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())
}

fn decode_coordinate(value: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    bytes.try_into().ok()
}

fn verified_identity(
    claims: &Claims,
    policy: &VerificationPolicy,
) -> Result<(PrincipalKind, Option<TenantId>), VerifyError> {
    let kind = string_claim(&claims.extra, &policy.kind_claim).ok_or_else(invalid)?;
    match kind {
        "user" => Ok((PrincipalKind::User, Some(required_tenant(claims, policy)?))),
        "device" => Ok((
            PrincipalKind::Device,
            Some(required_tenant(claims, policy)?),
        )),
        "admin" => Ok((PrincipalKind::Admin, Some(required_tenant(claims, policy)?))),
        "superAdmin" if !claims.extra.contains_key(policy.tenant_claim.as_ref()) => {
            Ok((PrincipalKind::SuperAdmin, None))
        }
        _ => Err(invalid()),
    }
}

fn required_tenant(claims: &Claims, policy: &VerificationPolicy) -> Result<TenantId, VerifyError> {
    TenantId::parse(string_claim(&claims.extra, &policy.tenant_claim).ok_or_else(invalid)?)
        .map_err(|_| invalid())
}

fn string_claim<'a>(extra: &'a HashMap<String, serde_json::Value>, name: &str) -> Option<&'a str> {
    extra.get(name).and_then(serde_json::Value::as_str)
}

fn verified_permissions(raw: Vec<String>) -> Result<Box<[Box<str>]>, VerifyError> {
    if raw.is_empty() {
        return Err(invalid());
    }
    let mut unique = HashSet::new();
    let mut permissions = Vec::with_capacity(raw.len());
    for permission in raw {
        if permission.is_empty()
            || permission.len() > 128
            || !permission.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b':' | b'-' | b'.' | b'_')
            })
            || !unique.insert(permission.clone())
        {
            return Err(invalid());
        }
        permissions.push(permission.into_boxed_str());
    }
    Ok(permissions.into_boxed_slice())
}

fn invalid() -> VerifyError {
    VerifyError::new(DiagnosticsSnapshot::one(Diagnostic::new(
        DiagnosticCode::InvalidCredential,
    )))
}

fn build_invalid() -> crate::BuildError {
    crate::BuildError::new(DiagnosticsSnapshot::one(Diagnostic::new(
        DiagnosticCode::InvalidTrustedIssuer,
    )))
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    use_: String,
    kid: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    token_use: String,
    iss: String,
    aud: Audience,
    permissions: Vec<String>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}
