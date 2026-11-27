//! Entra personnel identity shared by browser federation and native enrollment.
//! Device authorization remains with the consuming product.
use crate::federation::{FederationError, UpstreamFuture};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Explicit subject interpretation. An Entra provider never falls back to `sub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubjectMapping {
    Oidc,
    Entra { tenant: Uuid },
}

/// Canonical external subject, not authentication evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExternalSubject {
    Oidc(String),
    Entra { tenant: Uuid, user: Uuid },
}
impl ExternalSubject {
    pub fn validate(&self) -> Result<(), FederationError> {
        match self {
            Self::Oidc(v)
                if !v.is_empty() && v.len() <= 255 && !v.chars().any(char::is_control) =>
            {
                Ok(())
            }
            Self::Entra { tenant, user } if !tenant.is_nil() && !user.is_nil() => Ok(()),
            _ => Err(FederationError::Claims),
        }
    }
    /// One unambiguous storage identity; raw Entra pairwise sub is never retained.
    pub fn storage_key(&self) -> String {
        match self {
            Self::Oidc(v) => format!("oidc:{v}"),
            Self::Entra { tenant, user } => format!("entra:{tenant}:{user}"),
        }
    }
    pub fn matches(&self, mapping: &SubjectMapping) -> bool {
        matches!((self, mapping), (Self::Oidc(_), SubjectMapping::Oidc))
            || matches!((self, mapping), (Self::Entra { tenant: a, .. }, SubjectMapping::Entra { tenant: b }) if a == b)
    }
}

/// Deployment-approved MDM resource contract. Request input cannot choose its issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntraTokenProfile {
    pub tenant: Uuid,
    pub app_id: Uuid,
    pub authorized_clients: Vec<Uuid>,
    pub required_scopes: Vec<String>,
    pub device_claim: String,
}
impl EntraTokenProfile {
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.tenant.is_nil()
            || self.app_id.is_nil()
            || self.authorized_clients.is_empty()
            || self.authorized_clients.len() > 16
            || self.authorized_clients.iter().any(Uuid::is_nil)
            || self
                .authorized_clients
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.authorized_clients.len()
            || self.required_scopes.len() > 16
            || self
                .required_scopes
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_whitespace))
            || self.device_claim.is_empty()
            || self.device_claim.len() > 64
            || !self
                .device_claim
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || [
                "iss", "aud", "tid", "oid", "sub", "idtyp", "ver", "azp", "exp", "nbf", "iat",
                "scp",
            ]
            .contains(&self.device_claim.as_str())
        {
            return Err(FederationError::Configuration);
        }
        Ok(())
    }
    pub fn issuer(&self) -> String {
        format!("https://login.microsoftonline.com/{}/v2.0", self.tenant)
    }
}

/// Trusted adapter output only. Postgres constructs the actual proof privately.
#[derive(Clone)]
pub struct EntraTokenClaims {
    pub tenant: Uuid,
    pub user: Uuid,
    pub device: Option<Uuid>,
    pub issued_at: i64,
    pub expires_at: i64,
}
impl EntraTokenClaims {
    pub fn subject(&self) -> ExternalSubject {
        ExternalSubject::Entra {
            tenant: self.tenant,
            user: self.user,
        }
    }
    pub fn validate(&self, profile: &EntraTokenProfile) -> Result<(), FederationError> {
        profile.validate()?;
        self.subject().validate()?;
        if self.tenant != profile.tenant
            || self.device.is_some_and(|d| d.is_nil())
            || self.issued_at <= 0
            || self.expires_at <= self.issued_at
        {
            return Err(FederationError::Claims);
        }
        Ok(())
    }
}

/// Installed by trusted composition; never a public authentication candidate API.
pub trait EntraTokenVerifier: Send + Sync {
    fn verify<'a>(
        &'a self,
        profile: &'a EntraTokenProfile,
        token: Zeroizing<String>,
        deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, EntraTokenClaims>;
}
