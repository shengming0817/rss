//! Narrow enterprise assertion contract, not an OAuth authorization server.
//! ref: keycloak 26.7.3 JWTAuthorizationGrantType.java.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Installed by trusted host composition. Browsers select no issuer, key or scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseTarget {
    pub id: String,
    pub issuer: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub scopes: BTreeSet<String>,
}
impl EnterpriseTarget {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.is_empty()
            || self.id.len() > 255
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || self.scopes.is_empty()
            || self.scopes.len() > 16
            || self.scopes.iter().any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
            })
        {
            return Err("invalid enterprise target");
        }
        for raw in [&self.issuer, &self.token_endpoint] {
            let u = url::Url::parse(raw).map_err(|_| "invalid enterprise URL")?;
            if raw.len() > 2048
                || u.scheme() != "https"
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.fragment().is_some()
                || u.query().is_some()
            {
                return Err("invalid enterprise URL");
            }
        }
        Ok(())
    }
}
/// All fields are supplied by the authority after current-state verification.
#[derive(Serialize)]
pub struct EnterpriseClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub scope: String,
    pub client_id: String,
    pub rp: String,
    pub auth_time: Option<i64>,
    pub user_presence: bool,
    pub user_verification: bool,
    pub key_possession: bool,
}
/// Locally loaded signer; implementations must not perform network calls or block on I/O.
pub trait EnterpriseSigner: Send + Sync {
    fn sign(&self, claims: &EnterpriseClaims) -> Result<zeroize::Zeroizing<String>, &'static str>;
}
