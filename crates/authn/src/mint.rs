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

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use diport::{RssAccessProfile, ServiceTokenProfile, TokenProfileMarker as _};
use vocab::ServiceCallerDomain;
use vocab::tenant::TenantId;

use super::{KIND_ADMIN, KIND_DEVICE, KIND_SERVICE, KIND_SUPER_ADMIN, KIND_USER, SigningKeyRing};

const B64_URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Configuration for exactly one type-level token profile.
///
/// Fields are private so callers cannot substitute an algorithm or token marker. There is no
/// constructor for `JwtIssuerConfig<FederatedAccessProfile>`. Mint always uses
/// [`SigningKeyRing::active`] — next/retiring keys are never selected for signing
/// (INVARIANT: AUTHN-SIGNING-KEYRING-01 { level = "Hard", exec = "native-compile", source = "code", native = "typed single active field; no next/retiring sign API" }).
pub struct JwtIssuerConfig<P: diport::TokenProfileMarker> {
    key_ring: SigningKeyRing,
    purpose: diport::SigningPurpose,
    issuer: String,
    audience: String,
    ttl: Duration,
    _profile: PhantomData<fn() -> P>,
}

impl JwtIssuerConfig<RssAccessProfile> {
    /// Configure an RSS access-token issuer. Validation occurs in [`JwtIssuer::new`].
    pub fn rss_access(
        key_ring: SigningKeyRing,
        purpose: diport::SigningPurpose,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        Self::from_parts(key_ring, purpose, issuer.into(), audience.into(), ttl)
    }
}

impl JwtIssuerConfig<ServiceTokenProfile> {
    /// Configure an RSS service-token issuer. Validation occurs in [`JwtIssuer::new`].
    pub fn service_token(
        key_ring: SigningKeyRing,
        purpose: diport::SigningPurpose,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        Self::from_parts(key_ring, purpose, issuer.into(), audience.into(), ttl)
    }
}

impl<P: diport::TokenProfileMarker> JwtIssuerConfig<P> {
    fn from_parts(
        key_ring: SigningKeyRing,
        purpose: diport::SigningPurpose,
        issuer: String,
        audience: String,
        ttl: Duration,
    ) -> Self {
        Self {
            key_ring,
            purpose,
            issuer,
            audience,
            ttl,
            _profile: PhantomData,
        }
    }
}

/// A tenant-aware principal that may be minted as an RSS access token.
///
/// User, device, and admin variants require a tenant at construction. Super-admin deliberately
/// has no tenant field, so an ambient tenant claim cannot be attached to it.
///
/// INVARIANT: JWT-ACCESS-PRINCIPAL-TYPED-01 { level = "Hard", exec = "native-compile", source = "code", native = "typed function choice / input field exclusion" }
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum JwtAccessPrincipal<'a> {
    /// Tenant-scoped user.
    User { subject: &'a str, tenant: TenantId },
    /// Tenant-scoped device.
    Device { subject: &'a str, tenant: TenantId },
    /// Tenant-scoped administrator.
    Admin { subject: &'a str, tenant: TenantId },
    /// Cross-tenant super-administrator.
    SuperAdmin { subject: &'a str },
}

impl std::fmt::Debug for JwtAccessPrincipal<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User { tenant, .. } => formatter
                .debug_struct("User")
                .field("subject", &"<redacted>")
                .field("tenant", tenant)
                .finish(),
            Self::Device { tenant, .. } => formatter
                .debug_struct("Device")
                .field("subject", &"<redacted>")
                .field("tenant", tenant)
                .finish(),
            Self::Admin { tenant, .. } => formatter
                .debug_struct("Admin")
                .field("subject", &"<redacted>")
                .field("tenant", tenant)
                .finish(),
            Self::SuperAdmin { .. } => formatter
                .debug_struct("SuperAdmin")
                .field("subject", &"<redacted>")
                .finish(),
        }
    }
}

impl<'a> JwtAccessPrincipal<'a> {
    fn subject(self) -> &'a str {
        match self {
            Self::User { subject, .. }
            | Self::Device { subject, .. }
            | Self::Admin { subject, .. }
            | Self::SuperAdmin { subject } => subject,
        }
    }

    fn tenant(self) -> Option<TenantId> {
        match self {
            Self::User { tenant, .. }
            | Self::Device { tenant, .. }
            | Self::Admin { tenant, .. } => Some(tenant),
            Self::SuperAdmin { .. } => None,
        }
    }

    fn kind_claim(self) -> &'static str {
        match self {
            Self::User { .. } => KIND_USER,
            Self::Device { .. } => KIND_DEVICE,
            Self::Admin { .. } => KIND_ADMIN,
            Self::SuperAdmin { .. } => KIND_SUPER_ADMIN,
        }
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
    /// An empty subject cannot be signed.
    #[error("jwt subject must not be empty")]
    EmptySubject,
    /// A dynamically loaded principal kind cannot be represented by [`JwtAccessPrincipal`].
    #[error("principal kind is not issuable as an access token")]
    KindNotIssuable,
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

/// Access claims include a tenant only for the three tenant-scoped variants.
#[derive(serde::Serialize)]
struct AccessClaims<'a> {
    sub: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    kind: &'static str,
    token_use: &'static str,
    iat: i64,
    exp: i64,
    iss: &'a str,
    aud: &'a str,
}

/// Service claims intentionally have no tenant field; tenant context is only in the MAC input.
#[derive(serde::Serialize)]
struct ServiceClaims<'a> {
    sub: &'a str,
    jti: String,
    kind: &'static str,
    token_use: &'static str,
    iat: i64,
    exp: i64,
    iss: &'a str,
    aud: &'a str,
}

enum MessageBinding<'a> {
    Access,
    Service(&'a diport::ServiceTokenTenantBinding),
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
        principal: JwtAccessPrincipal<'_>,
    ) -> Result<MintedJwt, JwtIssueError> {
        let subject = principal.subject();
        if subject.is_empty() {
            return Err(JwtIssueError::EmptySubject);
        }
        let (iat, exp) = self.time_claims()?;
        let claims = AccessClaims {
            sub: subject,
            tenant_id: principal.tenant().map(|tenant| tenant.to_string()),
            kind: principal.kind_claim(),
            token_use: RssAccessProfile::policy().token_use(),
            iat,
            exp,
            iss: &self.config.issuer,
            aud: &self.config.audience,
        };
        self.sign_claims(&claims, exp, MessageBinding::Access).await
    }
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

    /// Sign a tenant-header-bound service token with exact service profile markers.
    pub async fn issue_service_token(
        &self,
        caller: ServiceCallerDomain,
        binding: diport::ServiceTokenTenantBinding,
    ) -> Result<MintedJwt, JwtIssueError> {
        let subject = caller.as_str();
        let (iat, exp) = self.time_claims()?;
        let claims = ServiceClaims {
            sub: subject,
            jti: uuid::Uuid::new_v4().to_string(),
            kind: KIND_SERVICE,
            token_use: ServiceTokenProfile::policy().token_use(),
            iat,
            exp,
            iss: &self.config.issuer,
            aud: &self.config.audience,
        };
        self.sign_claims(&claims, exp, MessageBinding::Service(&binding))
            .await
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
            || config.key_ring.active().as_str().is_empty()
            || config.purpose.as_str().is_empty()
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
        binding: MessageBinding<'_>,
    ) -> Result<MintedJwt, JwtIssueError> {
        let policy = P::policy();
        // Mint only with Active — next/retiring are not selectable (AUTHN-SIGNING-KEYRING-01).
        let active = self.config.key_ring.active();
        let header = JoseHeader {
            alg: policy.algorithm().jose_name(),
            kid: active.as_str(),
            typ: policy.jose_typ(),
        };
        let header_b64 =
            B64_URL.encode(serde_json::to_vec(&header).map_err(JwtIssueError::ClaimsEncode)?);
        let payload_b64 =
            B64_URL.encode(serde_json::to_vec(claims).map_err(JwtIssueError::ClaimsEncode)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let message = match binding {
            MessageBinding::Access => signing_input.as_bytes().to_vec(),
            MessageBinding::Service(binding) => {
                diport::service_token_mac_input(signing_input.as_bytes(), binding)
            }
        };
        let signature = self
            .signer
            .sign(diport::SignRequest {
                key: active.clone(),
                purpose: self.config.purpose.clone(),
                message: message.into(),
            })
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
    use diport::{KeyId, SignRequest, Signature, Signer, SignerError, SigningPurpose};
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

    fn tenant_binding() -> diport::ServiceTokenTenantBinding {
        diport::ServiceTokenTenantBinding::new(tenant())
    }

    fn rss_config(ttl: Duration) -> JwtIssuerConfig<RssAccessProfile> {
        JwtIssuerConfig::rss_access(
            SigningKeyRing::single(KeyId::new("rss-kid")).expect("non-empty kid"),
            SigningPurpose::new("auth.rss-access"),
            "https://rss.example",
            "rss-api",
            ttl,
        )
    }

    fn service_config(ttl: Duration) -> JwtIssuerConfig<ServiceTokenProfile> {
        JwtIssuerConfig::service_token(
            SigningKeyRing::single(KeyId::new("service-kid")).expect("non-empty kid"),
            SigningPurpose::new("auth.service-token"),
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
        let jwt = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(900))
            .issue_access(JwtAccessPrincipal::User {
                subject: "user-123",
                tenant: tenant(),
            })
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
        assert_eq!(claims["tenant_id"], CANON_TENANT);
        assert_eq!(claims["iat"].as_u64(), Some(NOW_SECS));
        assert_eq!(claims["exp"].as_u64(), Some(NOW_SECS + 900));
        assert_eq!(jwt.expires_at(), (NOW_SECS + 900) as i64);
        assert_eq!(parts[2], B64_URL.encode(SIG_BYTES));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn scoped_access_kinds_require_tenant_and_super_admin_omits_it() {
        for (principal, expected_kind, expects_tenant) in [
            (
                JwtAccessPrincipal::User {
                    subject: "u",
                    tenant: tenant(),
                },
                "user",
                true,
            ),
            (
                JwtAccessPrincipal::Device {
                    subject: "d",
                    tenant: tenant(),
                },
                "device",
                true,
            ),
            (
                JwtAccessPrincipal::Admin {
                    subject: "a",
                    tenant: tenant(),
                },
                "admin",
                true,
            ),
            (
                JwtAccessPrincipal::SuperAdmin { subject: "root" },
                "superAdmin",
                false,
            ),
        ] {
            let jwt = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(1))
                .issue_access(principal)
                .await
                .expect("issue access");
            let claims = decode_segment(segments(&jwt)[1]);
            assert_eq!(claims["kind"], expected_kind);
            assert_eq!(claims.get("tenant_id").is_some(), expects_tenant);
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn service_token_emits_exact_markers_jti_and_no_tenant_claim() {
        let signer = RecordingSigner::ok();
        let jwt = service_issuer(signer.clone(), Duration::from_secs(300))
            .issue_service_token(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                tenant_binding(),
            )
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
        assert!(claims.get("tenant_id").is_none());

        let expected_signing_input = format!("{}.{}", parts[0], parts[1]);
        let expected_message = format!("{expected_signing_input}\nx-tenant-id:{CANON_TENANT}");
        let captured = signer.captured().expect("signer called");
        assert_eq!(captured.message.as_bytes(), expected_message.as_bytes());
        assert_eq!(captured.key.as_str(), "service-kid");
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
    fn empty_profile_config_values_are_rejected() {
        let rss_cases = [
            JwtIssuerConfig::rss_access(
                SigningKeyRing::single(KeyId::new("kid")).expect("non-empty kid"),
                SigningPurpose::new(""),
                "iss",
                "aud",
                Duration::from_secs(1),
            ),
            JwtIssuerConfig::rss_access(
                SigningKeyRing::single(KeyId::new("kid")).expect("non-empty kid"),
                SigningPurpose::new("purpose"),
                "",
                "aud",
                Duration::from_secs(1),
            ),
            JwtIssuerConfig::rss_access(
                SigningKeyRing::single(KeyId::new("kid")).expect("non-empty kid"),
                SigningPurpose::new("purpose"),
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
                SigningPurpose::new("auth.rss-access"),
                "https://rss.example",
                "rss-api",
                Duration::from_secs(60),
            ),
        )
        .expect("valid issuer");
        let jwt = issuer
            .issue_access(JwtAccessPrincipal::SuperAdmin { subject: "root" })
            .await
            .expect("issue");
        let header = decode_segment(segments(&jwt)[0]);
        assert_eq!(header["kid"].as_str(), Some("active-kid"));
        let captured = signer.captured().expect("signer called");
        assert_eq!(captured.key.as_str(), "active-kid");
    }

    #[tokio::test]
    async fn failures_short_circuit_or_propagate_without_token_output() {
        let signer = RecordingSigner::ok();
        let empty_subject = rss_issuer(signer.clone(), now_time(), Duration::from_secs(1))
            .issue_access(JwtAccessPrincipal::SuperAdmin { subject: "" })
            .await;
        assert!(matches!(empty_subject, Err(JwtIssueError::EmptySubject)));
        assert!(signer.captured().is_none());

        let before_epoch = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        let clock_error = rss_issuer(signer.clone(), before_epoch, Duration::from_secs(1))
            .issue_access(JwtAccessPrincipal::SuperAdmin { subject: "root" })
            .await;
        assert!(matches!(clock_error, Err(JwtIssueError::ClockBeforeEpoch)));
        assert!(signer.captured().is_none());

        let sign_error = rss_issuer(
            RecordingSigner::failing(),
            now_time(),
            Duration::from_secs(1),
        )
        .issue_access(JwtAccessPrincipal::SuperAdmin { subject: "root" })
        .await;
        assert!(matches!(sign_error, Err(JwtIssueError::Sign(_))));
    }

    #[test]
    fn typed_issuer_and_issue_future_are_send_sync() {
        fn assert_send<T: Send>(_: T) {}
        fn assert_send_sync<T: Send + Sync>(_: &T) {}

        let issuer = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(1));
        assert_send_sync(&issuer);
        assert_send(issuer.issue_access(JwtAccessPrincipal::SuperAdmin { subject: "root" }));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn debug_and_errors_do_not_expose_secrets() {
        let jwt = rss_issuer(RecordingSigner::ok(), now_time(), Duration::from_secs(1))
            .issue_access(JwtAccessPrincipal::SuperAdmin {
                subject: "secret-subject",
            })
            .await
            .expect("issue access");
        assert_eq!(format!("{jwt:?}"), "MintedJwt(<redacted>)");
        assert!(!format!("{jwt:?}").contains(jwt.as_str()));
        assert_eq!(
            JwtIssueError::InvalidConfig.to_string(),
            "jwt issuer config is invalid"
        );
        assert_eq!(
            JwtIssueError::EmptySubject.to_string(),
            "jwt subject must not be empty"
        );
        assert_eq!(
            JwtIssueError::KindNotIssuable.to_string(),
            "principal kind is not issuable as an access token"
        );
    }
}
