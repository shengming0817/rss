//! Fixed ES256 assertion signing for Keycloak's supported JWT authorization grant.
//! ref: keycloak 26.7.3 JWTAuthorizationGrantType.java and AbstractBaseJWTValidator.java.
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rss_identity_core::enterprise::{EnterpriseClaims, EnterpriseSigner};
use zeroize::Zeroizing;

/// Deployment supplies a dedicated P-256 PKCS#8 private key; never reuse cookie/state keys.
pub struct Es256EnterpriseSigner {
    key: EncodingKey,
    kid: String,
}
impl Es256EnterpriseSigner {
    /// Load a dedicated ES256 signing key and public key identifier.
    pub fn new(kid: String, pem: &[u8]) -> Result<Self, &'static str> {
        if kid.is_empty()
            || kid.len() > 255
            || !kid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err("invalid signing key identifier");
        }
        let key = EncodingKey::from_ec_pem(pem).map_err(|_| "invalid enterprise signing key")?;
        Ok(Self { key, kid })
    }
}
impl EnterpriseSigner for Es256EnterpriseSigner {
    fn sign(&self, claims: &EnterpriseClaims) -> Result<Zeroizing<String>, &'static str> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.key)
            .map(Zeroizing::new)
            .map_err(|_| "enterprise signing failed")
    }
}

/// Verified provider token, retained only by the authorized RP backend.
pub struct EnterpriseAccess {
    token: Zeroizing<String>,
    subject: String,
    expires_at: i64,
}
impl EnterpriseAccess {
    /// Expose only to the RP's server-side protocol adapter.
    pub fn expose(&self) -> &str {
        &self.token
    }
    /// Stable Keycloak subject verified against the host's explicit account mapping.
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Signed token deadline; it does not imply an active browser session.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
}
#[derive(serde::Deserialize)]
struct AccessClaims {
    sub: String,
    azp: String,
    exp: i64,
}
/// Fixed backend exchange inputs. No field is taken from an untrusted browser request.
pub struct EnterpriseExchange<'a> {
    /// Host-bound provider identity, settings and credentials.
    pub provider: rss_identity_core::federation::BoundProvider,
    /// Fixed registered RP target.
    pub target: &'a rss_identity_core::enterprise::EnterpriseTarget,
    /// Authority-issued, one-use JWT assertion.
    pub assertion: &'a str,
    /// Original authority-issued deadline, never extended by the exchange.
    pub assertion_expires_at: i64,
    /// Stable provisioned Keycloak subject.
    pub expected_subject: &'a str,
}
impl crate::HttpOidc {
    /// Exchange a one-use backend assertion through the existing bounded, vetted transport.
    /// `expected_subject` comes from the host's provisioned stable IdP mapping, never browser JSON.
    /// Register the snapshot at authoritative installation; the host rechecks the current version before using the result.
    /// No retries: a network failure may follow successful upstream assertion consumption.
    pub async fn exchange_enterprise(
        &self,
        input: EnterpriseExchange<'_>,
        deadline: rss_request_context::Deadline,
    ) -> Result<EnterpriseAccess, rss_identity_core::federation::FederationError> {
        let EnterpriseExchange {
            provider: bound,
            target,
            assertion,
            assertion_expires_at,
            expected_subject,
        } = input;
        use rss_identity_core::federation::FederationError;
        let (provider, credentials) = (bound.settings(), bound.credentials());
        target
            .validate()
            .map_err(|_| FederationError::Configuration)?;
        if target.client_id != provider.client_id().as_str()
            || assertion.is_empty()
            || assertion.len() > 16384
            || expected_subject.is_empty()
            || expected_subject.len() > 512
        {
            return Err(FederationError::Configuration);
        }
        let (metadata, doc, transport) = self.discover(bound.clone(), deadline).await?;
        let endpoint = metadata.bound_token_endpoint(&target.token_endpoint)?;
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
            .append_pair("client_id", &target.client_id)
            .append_pair("client_secret", credentials.client_secret())
            .append_pair(
                "scope",
                &target.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
            )
            .append_pair("assertion", assertion)
            .finish();
        let request = http::Request::builder()
            .method("POST")
            .uri(endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form.into_bytes())
            .map_err(|_| FederationError::Configuration)?;
        let response = transport
            .call(
                rss_identity_core::federation::ProviderStage::Exchange,
                request,
            )
            .await?;
        if !response.status().is_success() {
            return Err(FederationError::Rejected);
        }
        let token: TokenResponse =
            serde_json::from_slice(response.body()).map_err(|_| FederationError::Claims)?;
        if !token.token_type.eq_ignore_ascii_case("bearer")
            || token.refresh_token.is_some()
            || token.access_token.len() > 16384
        {
            return Err(FederationError::Claims);
        }
        let header = jsonwebtoken::decode_header(&token.access_token)
            .map_err(|_| FederationError::Claims)?;
        if header.alg != Algorithm::RS256 {
            return Err(FederationError::Claims);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or(FederationError::Claims)?;
        let keys = self.signing_keys(&doc, &transport, Some(kid)).await?;
        let key =
            crate::profile_token::signing_key(&header, Some(&keys), credentials.client_secret())?;
        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.set_audience(&[&target.client_id]);
        validation.set_issuer(&[provider.issuer().as_str()]);
        validation.leeway = 0;
        let claims = jsonwebtoken::decode::<AccessClaims>(&token.access_token, &key, &validation)
            .map_err(|_| FederationError::Claims)?
            .claims;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| FederationError::Unavailable)?
            .as_secs() as i64;
        if claims.sub != expected_subject
            || claims.azp != target.client_id
            || claims.exp <= now
            || claims.exp > now + 30
            || claims.exp > assertion_expires_at
        {
            return Err(FederationError::Claims);
        }
        transport.channel.check()?;
        crate::remaining(deadline)?;
        Ok(EnterpriseAccess {
            token: Zeroizing::new(token.access_token),
            subject: claims.sub,
            expires_at: claims.exp,
        })
    }
}
