//! Transient credentials supplied to one OIDC operation, never part of public provider settings.
use super::FederationError;
use zeroize::Zeroizing;

pub struct ProviderCredentials {
    secret: Zeroizing<String>,
    ca: Option<String>,
}
impl ProviderCredentials {
    pub fn new(secret: String, ca: Option<String>) -> Result<Self, FederationError> {
        let secret = Zeroizing::new(secret);
        if secret.is_empty()
            || secret.len() > 4096
            || secret.contains('\0')
            || ca.as_ref().is_some_and(|v| v.is_empty() || v.len() > 16384)
        {
            return Err(FederationError::Configuration);
        }
        Ok(Self { secret, ca })
    }
    pub fn client_secret(&self) -> &str {
        self.secret.as_str()
    }
    pub fn ca_pem(&self) -> Option<&str> {
        self.ca.as_deref()
    }
}
impl std::fmt::Debug for ProviderCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderCredentials(<redacted>)")
    }
}
