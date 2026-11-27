pub mod callback;
mod credentials;
mod revisions;
pub use credentials::ProviderCredentials;
pub use revisions::{BoundProvider, InstalledRevision, ProviderRevisions};
/// Maximum admitted providers in one tenant directory.
pub const MAX_PROVIDERS: u16 = 1024;
// Federation values and narrow upstream port. Values are not authentication proofs.
// ref: RustCrypto/MACs hmac/src/lib.rs @ hmac-v0.12.1.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};

use rand_core::{OsRng, RngCore};

use rss_request_context::TenantId;

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

use std::{future::Future, pin::Pin};

use uuid::Uuid;

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ProviderId(Uuid);

impl ProviderId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse(value: &str) -> Result<Self, FederationError> {
        let id = Uuid::parse_str(value).map_err(|_| FederationError::Configuration)?;

        if id.is_nil() {
            return Err(FederationError::Configuration);
        }

        Ok(Self(id))
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimMapping {
    pub subject: crate::entra::SubjectMapping,
    pub profile: crate::profile::ProfileSettings,
    pub groups: Option<String>,
    pub department_snapshot: Option<crate::department::DepartmentSnapshotClaim>,
}

/// Untrusted configuration input. Convert before entering the domain or restoring storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSettingsInput {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub claims: ClaimMapping,
    pub jit: bool,
}

impl ProviderSettingsInput {
    fn validate(&self) -> Result<(), FederationError> {
        if let crate::entra::SubjectMapping::Entra { tenant } = &self.claims.subject
            && (tenant.is_nil()
                || self.issuer != format!("https://login.microsoftonline.com/{tenant}/v2.0")
                || !self.scopes.iter().any(|s| s == "profile"))
        {
            return Err(FederationError::Configuration);
        }
        for (s, max) in [
            (&self.issuer, 2048),
            (&self.client_id, 256),
            (&self.redirect_uri, 2048),
        ] {
            if s.is_empty() || s.len() > max || s.trim() != s || s.chars().any(char::is_control) {
                return Err(FederationError::Configuration);
            }
        }

        for value in [&self.issuer, &self.redirect_uri] {
            let url = url::Url::parse(value).map_err(|_| FederationError::Configuration)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(FederationError::Configuration);
            }
        }
        if self.scopes.is_empty()
            || self.scopes.len() > 16
            || !self.scopes.iter().any(|s| s == "openid")
        {
            return Err(FederationError::Configuration);
        }

        self.claims
            .profile
            .validate()
            .map_err(|_| FederationError::Configuration)?;
        let mut seen = std::collections::BTreeSet::new();

        for s in &self.scopes {
            if s.len() > 128
                || s.is_empty()
                || !s
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
                || s == "offline_access"
                || !seen.insert(s)
            {
                return Err(FederationError::Configuration);
            }
        }

        if let Some(department) = &self.claims.department_snapshot
            && [&self.claims.profile.extensions_claim, &self.claims.groups]
                .into_iter()
                .flatten()
                .any(|claim| claim == department.claim())
        {
            return Err(FederationError::Configuration);
        }

        for s in [&self.claims.profile.extensions_claim, &self.claims.groups]
            .into_iter()
            .flatten()
        {
            if s.is_empty()
                || s.len() > 255
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || ["sub", "iss", "aud", "nonce", "azp"].contains(&s.as_str())
            {
                return Err(FederationError::Configuration);
            }
        }

        Ok(())
    }
}

/// Validated immutable domain configuration; serde restoration uses the same constructor.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProviderSettings {
    issuer: crate::IssuerId,
    client_id: crate::ClientId,
    redirect_uri: String,
    scopes: Vec<String>,
    claims: ClaimMapping,
    jit: bool,
}
impl TryFrom<ProviderSettingsInput> for ProviderSettings {
    type Error = FederationError;
    fn try_from(input: ProviderSettingsInput) -> Result<Self, Self::Error> {
        input.validate()?;
        Ok(Self {
            issuer: crate::IssuerId::parse(&input.issuer)
                .map_err(|_| FederationError::Configuration)?,
            client_id: crate::ClientId::parse(&input.client_id)
                .map_err(|_| FederationError::Configuration)?,
            redirect_uri: input.redirect_uri,
            scopes: input.scopes,
            claims: input.claims,
            jit: input.jit,
        })
    }
}
impl<'de> Deserialize<'de> for ProviderSettings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::try_from(ProviderSettingsInput::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
impl ProviderSettings {
    pub fn issuer(&self) -> &crate::IssuerId {
        &self.issuer
    }
    pub fn client_id(&self) -> &crate::ClientId {
        &self.client_id
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn claims(&self) -> &ClaimMapping {
        &self.claims
    }
    pub fn jit(&self) -> bool {
        self.jit
    }
    pub fn input(&self) -> ProviderSettingsInput {
        ProviderSettingsInput {
            issuer: self.issuer.as_str().into(),
            client_id: self.client_id.as_str().into(),
            redirect_uri: self.redirect_uri.clone(),
            scopes: self.scopes.clone(),
            claims: self.claims.clone(),
            jit: self.jit,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderView {
    pub id: ProviderId,
    pub version: i64,
    pub enabled: bool,
    pub revocation_epoch: i64,
    pub settings: ProviderSettings,
    pub assurance_profile: [u8; 32],
    pub credential_version: i64,
}

/// Authoritative identity of a provider configuration. The host advances the version
/// whenever it replaces settings or credentials, including when restoring earlier values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderRevision {
    pub instance: crate::InstanceId,
    pub tenant: TenantId,
    pub provider: ProviderId,
    pub version: i64,
}

impl ProviderView {
    pub fn revision(&self, instance: crate::InstanceId, tenant: TenantId) -> ProviderRevision {
        ProviderRevision {
            instance,
            tenant,
            provider: self.id,
            version: self.version,
        }
    }
}

pub fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

pub fn random_secret() -> Result<Zeroizing<String>, FederationError> {
    let mut bytes = [0; 32];

    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| FederationError::Unavailable)?;

    Ok(Zeroizing::new(B64.encode(bytes)))
}

/// Secret protocol material deliberately has no Debug/Serialize implementation.
pub struct ProtocolMaterial {
    pub state: Zeroizing<String>,
    pub nonce: Zeroizing<String>,
    pub verifier: Zeroizing<String>,
}

impl ProtocolMaterial {
    pub fn new(state: String) -> Result<Self, FederationError> {
        Ok(Self {
            state: Zeroizing::new(state),
            nonce: random_secret()?,
            verifier: random_secret()?,
        })
    }
}

/// Output of the trusted upstream adapter. Not a principal, session, or deserializable proof.
#[derive(Clone)]
pub struct UpstreamClaims {
    pub issuer: String,
    pub subject: crate::entra::ExternalSubject,
    pub profile: crate::profile::Profile,
    pub groups: crate::groups::UpstreamGroups,
    pub department_snapshot: crate::department::UpstreamDepartmentSnapshot,
    pub issued_at: i64,
    pub expires_at: i64,
    pub assurance: crate::assurance::Assurance,
}

impl UpstreamClaims {
    pub fn validate(&self) -> Result<(), FederationError> {
        self.subject.validate()?;
        self.groups.validate()?;
        if self.issued_at <= 0 || self.expires_at <= self.issued_at {
            return Err(FederationError::Claims);
        }
        self.profile
            .validate()
            .map_err(|_| FederationError::Claims)?;

        Ok(())
    }
}

pub type UpstreamFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, FederationError>> + Send + 'a>>;

/// One deployment-approved interpretation and its supported authentication intent.
/// The fingerprint retains its persisted identity; this descriptor is not browser authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssuranceProfile {
    pub fingerprint: [u8; 32],
    pub supports_step_up: bool,
}

/// Installed by trusted composition once. Tenant identity comes from the persisted flow.
pub trait UpstreamOidc: Send + Sync {
    /// Identifies the host-approved interpretation of verified ACR/AMR, never provider admission.
    fn assurance_profile(&self, tenant: TenantId, config: &ProviderSettings) -> AssuranceProfile;
    fn validate(
        &self,
        tenant: TenantId,
        config: &ProviderSettings,
        credentials: &ProviderCredentials,
    ) -> Result<(), FederationError>;
    /// Registry shared by authoritative configuration reads and committed changes.
    fn revisions(&self) -> &ProviderRevisions;
    fn prepare<'a>(
        &'a self,
        provider: BoundProvider,
        material: &'a ProtocolMaterial,
        mode: crate::assurance::AuthenticationMode,
        deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, String>;
    fn exchange<'a>(
        &'a self,
        provider: BoundProvider,
        material: ProtocolMaterial,
        code: Zeroizing<String>,
        deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, UpstreamClaims>;
    fn test<'a>(
        &'a self,
        provider: BoundProvider,
        deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, ConnectionReport>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStage {
    Binding,
    Discovery,
    Jwks,
    Exchange,
    Claims,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReason {
    InvalidTrustAnchor,
    EgressDenied,
    TlsRejected,
    Unavailable,
    Timeout,
    InvalidResponse,
    IssuerMismatch,
    IssuerResponseUnsupported,
    CodeRejected,
    InvalidToken,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("provider {stage:?}: {reason:?}")]
pub struct ProviderFailure {
    pub stage: ProviderStage,
    pub reason: ProviderReason,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionReport {
    pub checks: Vec<ProviderStage>,
    pub tls_verified: bool,
    pub authorization_response_issuer: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FederationError {
    #[error("invalid federation input")]
    Configuration,
    #[error("federation transaction rejected")]
    Rejected,
    #[error("identity linking conflict")]
    Conflict,
    #[error("federation configuration changed")]
    StaleConfiguration,
    #[error("federation provider limit reached")]
    ProviderLimitReached,
    #[error("federation provider unavailable")]
    Unavailable,
    #[error("federation claims rejected")]
    Claims,
    #[error(transparent)]
    Provider(#[from] ProviderFailure),
}
impl FederationError {
    pub fn provider(stage: ProviderStage, reason: ProviderReason) -> Self {
        Self::Provider(ProviderFailure { stage, reason })
    }
    pub fn diagnostic(self) -> ProviderFailure {
        match self {
            Self::Provider(f) => f,
            Self::Claims => ProviderFailure {
                stage: ProviderStage::Claims,
                reason: ProviderReason::InvalidToken,
            },
            Self::Unavailable => ProviderFailure {
                stage: ProviderStage::Discovery,
                reason: ProviderReason::Timeout,
            },
            _ => ProviderFailure {
                stage: ProviderStage::Binding,
                reason: ProviderReason::InvalidResponse,
            },
        }
    }
}
