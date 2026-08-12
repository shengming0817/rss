//! Profile-typed JWT signing for RSS access and service tokens.
//!
//! The token profile is a sealed type parameter owned by `diport`. Algorithm, protected-header
//! `typ`, private `token_use`, and maximum lifetime all come from that single policy. RSS access
//! and service-token issuers expose disjoint issue methods; federated access has no mint
//! constructor because RSS only verifies tokens from that trust domain.
//!
//! ref: RFC 7515 §7.1 (JWS Compact Serialization), RFC 7519 (registered claims), RFC 8725
//! §3.11–§3.12 (explicit typing and mutually exclusive validation rules), RFC 9068 §2.1
//! (`at+jwt` access-token type).

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use diport::{RssAccessProfile, ServiceTokenProfile, TokenProfileMarker as _};
use vocab::ServiceCallerDomain;

use super::{KIND_SERVICE, KIND_USER, RssAccessIssueInput, SigningKeyRing};

const B64_URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Configuration for exactly one type-level token profile.
///
/// Fields are private so callers cannot substitute an algorithm or token marker. There is no
/// constructor for `JwtIssuerConfig<FederatedAccessProfile>`. Mint always uses
/// [`SigningKeyRing::active`] — next/retiring keys are never selected for signing
/// (INVARIANT: AUTHN-SIGNING-KEYRING-01 { level = "Hard", exec = "native-compile", source = "code", native = "typed single active field; no next/retiring sign API" }).
#[derive(Clone)]
pub struct JwtIssuerConfig<P: diport::TokenProfileMarker> {
    binding: diport::JwtSigningBinding<P>,
    issuer: String,
    audience: String,
    ttl: Duration,
}

impl JwtIssuerConfig<RssAccessProfile> {
    /// Configure an RSS access-token issuer. Validation occurs in [`JwtIssuer::new`].
    pub fn rss_access(
        key_ring: SigningKeyRing,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        Self::from_parts(
            diport::JwtSigningBinding::rss_access(key_ring.active().clone()),
            issuer.into(),
            audience.into(),
            ttl,
        )
    }
}

impl JwtIssuerConfig<ServiceTokenProfile> {
    /// Configure an RSS service-token issuer. Validation occurs in [`JwtIssuer::new`].
    pub fn service_token(
        key_ring: SigningKeyRing,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        Self::from_parts(
            diport::JwtSigningBinding::service_token(key_ring.active().clone()),
            issuer.into(),
            audience.into(),
            ttl,
        )
    }
}

impl<P: diport::TokenProfileMarker> JwtIssuerConfig<P> {
    fn from_parts(
        binding: diport::JwtSigningBinding<P>,
        issuer: String,
        audience: String,
        ttl: Duration,
    ) -> Self {
        Self {
            binding,
            issuer,
            audience,
            ttl,
        }
    }

    /// Borrow the canonical profile/key/purpose binding shared with the signer provider.
    pub fn signing_binding(&self) -> &diport::JwtSigningBinding<P> {
        &self.binding
    }

    /// Configured lifetime, already bounded by the selected profile at issuer construction.
    pub fn lifetime(&self) -> Duration {
        self.ttl
    }
}

/// A signed compact JWS with its authoritative `exp` value.
pub struct MintedJwt {
    raw: String,
    expires_at: i64,
}

impl std::fmt::Debug for MintedJwt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MintedJwt(<redacted>)")
    }
}

impl MintedJwt {
    fn new(raw: String, expires_at: i64) -> Self {
        Self { raw, expires_at }
    }

    /// Borrow the compact JWS.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Return the JWT `exp` value in UNIX epoch seconds.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Fail-closed JWT issue errors. Messages contain no token, subject, tenant, key, or token id.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwtIssueError {
    /// Issuer, audience, key id, purpose, or TTL violates the selected profile.
    #[error("jwt issuer config is invalid")]
    InvalidConfig,
    /// The grant is expired or its authentication time is later than issuance.
    #[error("authentication grant has no valid access-token window")]
    InvalidGrantWindow,
    /// The injected clock is before the UNIX epoch.
    #[error("clock is before unix epoch")]
    ClockBeforeEpoch,
    /// Timestamp conversion or expiry arithmetic overflowed.
    #[error("jwt expiry computation overflowed")]
    ExpiryOverflow,
    /// Protected header or claims encoding failed.
    #[error("jwt claims serialization failed")]
    ClaimsEncode(#[source] serde_json::Error),
    /// The injected signer rejected the operation.
    #[error("jwt signing failed")]
    Sign(#[source] diport::SignerError),
}

#[derive(serde::Serialize)]
struct JoseHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
}

/// RSS access claims are always bound to one durable User authentication grant.
struct AccessClaims<'a> {
    sub: String,
    tenant_id: String,
    kind: &'static str,
    sid: String,
    jti: String,
    auth_time: i64,
    authn_epoch: u64,
    token_use: &'static str,
    iat: i64,
    exp: i64,
    iss: &'a str,
    aud: &'a str,
}

impl serde::Serialize for AccessClaims<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap as _;
        let policy = RssAccessProfile::policy();
        let mut map = serializer.serialize_map(Some(12))?;
        map.serialize_entry("sub", &self.sub)?;
        map.serialize_entry(policy.tenant_claim_name(), &self.tenant_id)?;
        map.serialize_entry(policy.kind_claim_name(), &self.kind)?;
        map.serialize_entry("sid", &self.sid)?;
        map.serialize_entry("jti", &self.jti)?;
        map.serialize_entry("auth_time", &self.auth_time)?;
        map.serialize_entry("authn_epoch", &self.authn_epoch)?;
        map.serialize_entry("token_use", &self.token_use)?;
        map.serialize_entry("iat", &self.iat)?;
        map.serialize_entry("exp", &self.exp)?;
        map.serialize_entry("iss", &self.iss)?;
        map.serialize_entry("aud", &self.aud)?;
        map.end()
    }
}

/// Service claims carry the signed canonical tenant authority for the request challenger.
struct ServiceClaims<'a> {
    sub: &'a str,
    tenant_id: String,
    jti: String,
    kind: &'static str,
    token_use: &'static str,
    iat: i64,
    exp: i64,
    iss: &'a str,
    aud: &'a str,
}

impl serde::Serialize for ServiceClaims<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap as _;
        let policy = ServiceTokenProfile::policy();
        let mut map = serializer.serialize_map(Some(9))?;
        map.serialize_entry("sub", &self.sub)?;
        map.serialize_entry(policy.tenant_claim_name(), &self.tenant_id)?;
        map.serialize_entry("jti", &self.jti)?;
        map.serialize_entry(policy.kind_claim_name(), &self.kind)?;
        map.serialize_entry("token_use", &self.token_use)?;
        map.serialize_entry("iat", &self.iat)?;
        map.serialize_entry("exp", &self.exp)?;
        map.serialize_entry("iss", &self.iss)?;
        map.serialize_entry("aud", &self.aud)?;
        map.end()
    }
}

/// A JWT issuer whose public capabilities are fixed by the sealed profile marker.
///
/// INVARIANT: AUTHN-TOKEN-PROFILE-MINT-01 { level = "Hard", exec = "native-compile", source = "code", native = "sealed profile marker and disjoint inherent impls" }
pub struct JwtIssuer<P: diport::TokenProfileMarker, S> {
    signer: Arc<S>,
    clock: Box<dyn diport::Clock>,
    config: JwtIssuerConfig<P>,
}

impl<S: diport::Signer + Send + Sync + 'static> JwtIssuer<RssAccessProfile, S> {
    /// Construct an RSS access issuer. `0 < ttl <= 900s` is enforced before issuance.
    pub fn new(
        signer: Arc<S>,
        clock: Box<dyn diport::Clock>,
        config: JwtIssuerConfig<RssAccessProfile>,
    ) -> Result<Self, JwtIssueError> {
        Self::validated_new(signer, clock, config)
    }

    /// Sign an RSS access token with exact `typ=at+jwt`, `token_use=access`, and ES256.
    pub async fn issue_access(
        &self,
        input: RssAccessIssueInput<'_>,
    ) -> Result<MintedJwt, JwtIssueError> {
        let grant = input.grant;
        let (iat, configured_exp) = self.time_claims()?;
        let auth_time = unix_time(grant.auth_time())?;
        let grant_exp = unix_time(grant.expires_at())?;
        let exp = configured_exp.min(grant_exp);
        if auth_time > iat || iat >= exp {
            return Err(JwtIssueError::InvalidGrantWindow);
        }
        let claims = AccessClaims {
            sub: grant.user_id().as_uuid().hyphenated().to_string(),
            tenant_id: grant.tenant().to_string(),
            kind: KIND_USER,
            sid: grant.id().to_wire(),
            jti: uuid::Uuid::new_v4().to_string(),
            auth_time,
            authn_epoch: grant.authn_epoch_at_issue().get(),
            token_use: RssAccessProfile::policy().token_use(),
            iat,
            exp,
            iss: &self.config.issuer,
            aud: &self.config.audience,
        };
        self.sign_claims(&claims, exp).await
    }
}

fn unix_time(value: std::time::SystemTime) -> Result<i64, JwtIssueError> {
    let seconds = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JwtIssueError::InvalidGrantWindow)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| JwtIssueError::ExpiryOverflow)
}

impl<S: diport::Signer + Send + Sync + 'static> JwtIssuer<ServiceTokenProfile, S> {
    /// Construct a service-token issuer. `0 < ttl <= 300s` is enforced before issuance.
    pub fn new(
        signer: Arc<S>,
        clock: Box<dyn diport::Clock>,
        config: JwtIssuerConfig<ServiceTokenProfile>,
    ) -> Result<Self, JwtIssueError> {
        Self::validated_new(signer, clock, config)
    }

    /// Sign a service token with exact service profile markers and signed canonical tenant_id.
    pub async fn issue_service_token(
        &self,
        caller: ServiceCallerDomain,
        tenant: rss_request_context::TenantId,
    ) -> Result<MintedJwt, JwtIssueError> {
        let subject = caller.as_str();
        let (iat, exp) = self.time_claims()?;
        let claims = ServiceClaims {
            sub: subject,
            tenant_id: tenant.to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            kind: KIND_SERVICE,
            token_use: ServiceTokenProfile::policy().token_use(),
            iat,
            exp,
            iss: &self.config.issuer,
            aud: &self.config.audience,
        };
        self.sign_claims(&claims, exp).await
    }
}

impl<P, S> JwtIssuer<P, S>
where
    P: diport::TokenProfileMarker,
    S: diport::Signer + Send + Sync + 'static,
{
    fn validated_new(
        signer: Arc<S>,
        clock: Box<dyn diport::Clock>,
        config: JwtIssuerConfig<P>,
    ) -> Result<Self, JwtIssueError> {
        let policy = P::policy();
        // `SigningKeyRing` constructors already reject empty active; re-check as defense in depth.
        if config.issuer.is_empty()
            || config.audience.is_empty()
            || config.binding.active_key().as_str().is_empty()
            || config.binding.purpose().as_str().is_empty()
            || config.ttl.is_zero()
            || config.ttl > policy.maximum_lifetime()
        {
            return Err(JwtIssueError::InvalidConfig);
        }
        Ok(Self {
            signer,
            clock,
            config,
        })
    }

    fn time_claims(&self) -> Result<(i64, i64), JwtIssueError> {
        let now = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtIssueError::ClockBeforeEpoch)?
            .as_secs();
        let iat = i64::try_from(now).map_err(|_| JwtIssueError::ExpiryOverflow)?;
        let ttl =
            i64::try_from(self.config.ttl.as_secs()).map_err(|_| JwtIssueError::ExpiryOverflow)?;
        let exp = iat.checked_add(ttl).ok_or(JwtIssueError::ExpiryOverflow)?;
        Ok((iat, exp))
    }

    async fn sign_claims<C: serde::Serialize>(
        &self,
        claims: &C,
        expires_at: i64,
    ) -> Result<MintedJwt, JwtIssueError> {
        let policy = P::policy();
        let binding = &self.config.binding;
        let header = JoseHeader {
            alg: binding.algorithm().jose_name(),
            kid: binding.active_key().as_str(),
            typ: policy.jose_typ(),
        };
        let header_b64 =
            B64_URL.encode(serde_json::to_vec(&header).map_err(JwtIssueError::ClaimsEncode)?);
        let payload_b64 =
            B64_URL.encode(serde_json::to_vec(claims).map_err(JwtIssueError::ClaimsEncode)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self
            .signer
            .sign(binding.sign_request(signing_input.as_bytes().to_vec()))
            .await
            .map_err(JwtIssueError::Sign)?;
        let signature_b64 = B64_URL.encode(signature.as_bytes());
        Ok(MintedJwt::new(
            format!("{signing_input}.{signature_b64}"),
            expires_at,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthGrant, AuthnEpoch, GrantSecurityEventKind};
    use diport::{KeyId, SignRequest, Signature, Signer, SignerError};
    use ids::UserId;
    use rss_request_context::TenantId;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const NOW_SECS: u64 = 1_700_000_000;
    const SIG_BYTES: &[u8] = b"deterministic-signature";

    #[derive(Clone)]
    struct RecordingSigner {
        captured: Arc<Mutex<Option<SignRequest>>>,
        fail: bool,
    }

    impl RecordingSigner {
        fn ok() -> Self {
            Self {
                captured: Arc::new(Mutex::new(None)),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::ok()
            }
        }

        fn captured(&self) -> Option<SignRequest> {
            self.captured
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    impl Signer for RecordingSigner {
        async fn sign(&self, request: SignRequest) -> Result<Signature, SignerError> {
            *self
                .captured
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(request);
            if self.fail {
                return Err(SignerError::new(std::io::Error::other("test failure")));
            }
            Ok(Signature::new(SIG_BYTES.to_vec()))
        }

        async fn shutdown(&self) -> Result<(), SignerError> {
            Ok(())
        }
    }

    struct TestClock(SystemTime);

    impl diport::Clock for TestClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn now_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS)
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON_TENANT).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn user() -> UserId {
        UserId::parse("550e8400-e29b-41d4-a716-446655440000").expect("canonical user")
    }

    #[allow(clippy::expect_used)]
    fn grant(expires_at: SystemTime) -> AuthGrant {
        AuthGrant::new_active(
            tenant(),
            user(),
            now_time() - Duration::from_secs(30),
            AuthnEpoch::hydrate(7).expect("epoch"),
            expires_at,
            now_time() - Duration::from_secs(30),
        )
        .expect("grant")
    }

    #[allow(clippy::expect_used)]
    fn rss_config(ttl: Duration) -> JwtIssuerConfig<RssAccessProfile> {
        JwtIssuerConfig::rss_access(
            SigningKeyRing::single(KeyId::new("rss-kid")).expect("non-empty kid"),
            "https://rss.example",
            "rss-api",
            ttl,
        )
    }

    #[allow(clippy::expect_used)]
    fn service_config(ttl: Duration) -> JwtIssuerConfig<ServiceTokenProfile> {
        JwtIssuerConfig::service_token(
            SigningKeyRing::single(KeyId::new("service-kid")).expect("non-empty kid"),
            "https://service.rss.example",
            "rss-internal",
            ttl,
        )
    }

    #[allow(clippy::expect_used)]
    fn rss_issuer(
        signer: RecordingSigner,
        clock: SystemTime,
        ttl: Duration,
    ) -> JwtIssuer<RssAccessProfile, RecordingSigner> {
        JwtIssuer::<RssAccessProfile, _>::new(
            Arc::new(signer),
            Box::new(TestClock(clock)),
            rss_config(ttl),
        )
        .expect("valid RSS issuer")
    }

    #[allow(clippy::expect_used)]
    fn service_issuer(
        signer: RecordingSigner,
        ttl: Duration,
    ) -> JwtIssuer<ServiceTokenProfile, RecordingSigner> {
        JwtIssuer::<ServiceTokenProfile, _>::new(
            Arc::new(signer),
            Box::new(TestClock(now_time())),
            service_config(ttl),
        )
        .expect("valid service issuer")
    }

    #[allow(clippy::expect_used)]
    fn decode_segment(segment: &str) -> serde_json::Value {
        let bytes = B64_URL.decode(segment).expect("base64url segment");
        serde_json::from_slice(&bytes).expect("JSON segment")
    }

    fn segments(jwt: &MintedJwt) -> Vec<&str> {
        jwt.as_str().split('.').collect()
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rss_access_emits_exact_profile_markers_and_tenant() {
        let grant = grant(now_time() + Duration::from_secs(3_600));
        let signer = RecordingSigner::ok();
        let jwt = rss_issuer(signer.clone(), now_time(), Duration::from_secs(900))
            .issue_access(grant.access_issue_input().expect("active grant"))
            .await
            .expect("issue access");
        let parts = segments(&jwt);
        assert_eq!(parts.len(), 3);
        let header = decode_segment(parts[0]);
        let claims = decode_segment(parts[1]);
        assert_eq!(
            (
                header["alg"].as_str(),
                header["typ"].as_str(),
                header["kid"].as_str()
            ),
            (Some("ES256"), Some("at+jwt"), Some("rss-kid"))
        );
        assert_eq!(claims["token_use"], "access");
        assert_eq!(claims["kind"], "user");
        assert_eq!(claims["sub"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(claims["tenant_id"], CANON_TENANT);
        assert_eq!(claims["sid"], grant.id().to_wire());
        assert_eq!(claims["auth_time"].as_u64(), Some(NOW_SECS - 30));
        assert_eq!(claims["authn_epoch"].as_u64(), Some(7));
        let jti = claims["jti"].as_str().expect("jti");
        assert_eq!(
            uuid::Uuid::parse_str(jti).expect("uuid").get_version_num(),
            4
        );
        assert_eq!(claims["iat"].as_u64(), Some(NOW_SECS));
        assert_eq!(claims["exp"].as_u64(), Some(NOW_SECS + 900));
        assert_eq!(jwt.expires_at(), (NOW_SECS + 900) as i64);
        assert_eq!(parts[2], B64_URL.encode(SIG_BYTES));
        let captured = signer.captured().expect("signer called");
        assert_eq!(captured.key.as_str(), "rss-kid");
        assert_eq!(captured.purpose.as_str(), "auth.rss-access");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn same_grant_keeps_sid_auth_time_epoch_but_rotates_jti() {
        let grant = grant(now_time() + Duration::from_secs(3_600));
        let issuer = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(60));
        let first = issuer
            .issue_access(grant.access_issue_input().expect("active grant"))
            .await
            .expect("first");
        let second = issuer
            .issue_access(grant.access_issue_input().expect("active grant"))
            .await
            .expect("second");
        let first = decode_segment(segments(&first)[1]);
        let second = decode_segment(segments(&second)[1]);
        for claim in ["sid", "auth_time", "authn_epoch"] {
            assert_eq!(first[claim], second[claim]);
        }
        assert_ne!(first["jti"], second["jti"]);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn service_token_emits_exact_markers_jti_and_canonical_tenant_claim() {
        let signer = RecordingSigner::ok();
        let jwt = service_issuer(signer.clone(), Duration::from_secs(300))
            .issue_service_token(vocab::ServiceCallerDomain::MaintenanceOperator, tenant())
            .await
            .expect("issue service token");
        let parts = segments(&jwt);
        let header = decode_segment(parts[0]);
        let claims = decode_segment(parts[1]);
        assert_eq!(
            (
                header["alg"].as_str(),
                header["typ"].as_str(),
                header["kid"].as_str()
            ),
            (Some("HS256"), Some("rss-service+jwt"), Some("service-kid"))
        );
        assert_eq!(claims["token_use"], "service");
        assert_eq!(claims["kind"], "service");
        assert!(
            claims["jti"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(claims["tenant_id"], CANON_TENANT);

        // RFC 7515 signing input is exactly base64url(header).base64url(payload).
        let expected_signing_input = format!("{}.{}", parts[0], parts[1]);
        let captured = signer.captured().expect("signer called");
        assert_eq!(
            captured.message.as_bytes(),
            expected_signing_input.as_bytes(),
            "service-token signer message must be exact header.payload with no private MAC suffix"
        );
        assert_eq!(captured.key.as_str(), "service-kid");
        assert_eq!(captured.purpose.as_str(), "auth.service-token");
    }

    #[test]
    fn profile_ttl_boundaries_fail_closed_at_construction() {
        for ttl in [Duration::ZERO, Duration::from_secs(901)] {
            assert!(matches!(
                JwtIssuer::<RssAccessProfile, _>::new(
                    Arc::new(RecordingSigner::ok()),
                    Box::new(TestClock(now_time())),
                    rss_config(ttl),
                ),
                Err(JwtIssueError::InvalidConfig)
            ));
        }
        for ttl in [Duration::ZERO, Duration::from_secs(301)] {
            assert!(matches!(
                JwtIssuer::<ServiceTokenProfile, _>::new(
                    Arc::new(RecordingSigner::ok()),
                    Box::new(TestClock(now_time())),
                    service_config(ttl),
                ),
                Err(JwtIssueError::InvalidConfig)
            ));
        }
        assert!(
            JwtIssuer::<RssAccessProfile, _>::new(
                Arc::new(RecordingSigner::ok()),
                Box::new(TestClock(now_time())),
                rss_config(Duration::from_secs(900)),
            )
            .is_ok()
        );
        assert!(
            JwtIssuer::<ServiceTokenProfile, _>::new(
                Arc::new(RecordingSigner::ok()),
                Box::new(TestClock(now_time())),
                service_config(Duration::from_secs(300)),
            )
            .is_ok()
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_profile_config_values_are_rejected() {
        let rss_cases = [
            JwtIssuerConfig::rss_access(
                SigningKeyRing::single(KeyId::new("kid")).expect("non-empty kid"),
                "",
                "aud",
                Duration::from_secs(1),
            ),
            JwtIssuerConfig::rss_access(
                SigningKeyRing::single(KeyId::new("kid")).expect("non-empty kid"),
                "iss",
                "",
                Duration::from_secs(1),
            ),
        ];
        for config in rss_cases {
            assert!(matches!(
                JwtIssuer::<RssAccessProfile, _>::new(
                    Arc::new(RecordingSigner::ok()),
                    Box::new(TestClock(now_time())),
                    config,
                ),
                Err(JwtIssueError::InvalidConfig)
            ));
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn mint_uses_ring_active_kid_not_next_or_retiring() {
        let ring = SigningKeyRing::with_rotation(
            KeyId::new("active-kid"),
            Some(KeyId::new("next-kid")),
            vec![(KeyId::new("retiring-kid"), NOW_SECS as i64 + 10_000)],
        )
        .expect("disjoint kids");
        let signer = RecordingSigner::ok();
        let issuer = JwtIssuer::<RssAccessProfile, _>::new(
            Arc::new(signer.clone()),
            Box::new(TestClock(now_time())),
            JwtIssuerConfig::rss_access(
                ring,
                "https://rss.example",
                "rss-api",
                Duration::from_secs(60),
            ),
        )
        .expect("valid issuer");
        let grant = grant(now_time() + Duration::from_secs(3_600));
        let jwt = issuer
            .issue_access(grant.access_issue_input().expect("active grant"))
            .await
            .expect("issue");
        let header = decode_segment(segments(&jwt)[0]);
        assert_eq!(header["kid"].as_str(), Some("active-kid"));
        let captured = signer.captured().expect("signer called");
        assert_eq!(captured.key.as_str(), "active-kid");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn invalid_grant_windows_short_circuit_before_signer() {
        let signer = RecordingSigner::ok();
        let expired = grant(now_time());
        let expired_result = rss_issuer(signer.clone(), now_time(), Duration::from_secs(1))
            .issue_access(expired.access_issue_input().expect("active grant"))
            .await;
        assert!(matches!(
            expired_result,
            Err(JwtIssueError::InvalidGrantWindow)
        ));
        assert!(signer.captured().is_none());

        let future_auth = AuthGrant::new_active(
            tenant(),
            user(),
            now_time() + Duration::from_secs(1),
            AuthnEpoch::ZERO,
            now_time() + Duration::from_secs(60),
            now_time() + Duration::from_secs(1),
        )
        .expect("future grant");
        let future_result = rss_issuer(signer.clone(), now_time(), Duration::from_secs(1))
            .issue_access(future_auth.access_issue_input().expect("active grant"))
            .await;
        assert!(matches!(
            future_result,
            Err(JwtIssueError::InvalidGrantWindow)
        ));
        assert!(signer.captured().is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn signer_failures_propagate_without_token_output() {
        let grant = grant(now_time() + Duration::from_secs(60));
        let sign_error = rss_issuer(
            RecordingSigner::failing(),
            now_time(),
            Duration::from_secs(1),
        )
        .issue_access(grant.access_issue_input().expect("active grant"))
        .await;
        assert!(matches!(sign_error, Err(JwtIssueError::Sign(_))));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn expiry_is_capped_by_grant_and_terminal_grant_cannot_form_input() {
        let grant = grant(now_time() + Duration::from_secs(10));
        let jwt = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(900))
            .issue_access(grant.access_issue_input().expect("active grant"))
            .await
            .expect("issue");
        assert_eq!(jwt.expires_at(), (NOW_SECS + 10) as i64);

        let closed = grant
            .close(GrantSecurityEventKind::LogoutCurrent, now_time())
            .expect("close")
            .next()
            .clone();
        assert!(closed.access_issue_input().is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn typed_issuer_and_issue_future_are_send_sync() {
        fn assert_send<T: Send>(_: T) {}
        fn assert_send_sync<T: Send + Sync>(_: &T) {}

        let issuer = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(1));
        assert_send_sync(&issuer);
        let grant = grant(now_time() + Duration::from_secs(60));
        assert_send(issuer.issue_access(grant.access_issue_input().expect("active grant")));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn debug_and_errors_do_not_expose_secrets() {
        let grant = grant(now_time() + Duration::from_secs(60));
        let jwt = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(1))
            .issue_access(grant.access_issue_input().expect("active grant"))
            .await
            .expect("issue access");
        assert_eq!(format!("{jwt:?}"), "MintedJwt(<redacted>)");
        assert!(!format!("{jwt:?}").contains(jwt.as_str()));
        assert_eq!(
            JwtIssueError::InvalidConfig.to_string(),
            "jwt issuer config is invalid"
        );
        assert_eq!(
            JwtIssueError::InvalidGrantWindow.to_string(),
            "authentication grant has no valid access-token window"
        );
    }
}
