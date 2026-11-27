//! Host-authorized RP assertions share platform challenge settlement and session ownership.
use super::*;
use rss_identity_core::enterprise::{EnterpriseClaims, EnterpriseSigner, EnterpriseTarget};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "purpose",
    content = "target",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PlatformPurpose {
    BrowserLogin,
    EnterpriseRp(String),
}
#[derive(Clone)]
pub struct EnterpriseConfig {
    pub(crate) targets: BTreeMap<String, EnterpriseTarget>,
    pub(crate) signer: Arc<dyn EnterpriseSigner>,
}
impl EnterpriseConfig {
    pub fn new(
        targets: Vec<EnterpriseTarget>,
        signer: Arc<dyn EnterpriseSigner>,
    ) -> Result<Self, AuthorityError> {
        if targets.is_empty() || targets.len() > 1024 {
            return Err(AuthorityError::Configuration);
        }
        let mut map = BTreeMap::new();
        let mut issuers = std::collections::BTreeSet::new();
        for target in targets {
            target
                .validate()
                .map_err(|_| AuthorityError::Configuration)?;
            // A client may only use its own issuer trust configuration in the selected IdP.
            if !issuers.insert(target.issuer.clone())
                || map.insert(target.id.clone(), target).is_some()
            {
                return Err(AuthorityError::Configuration);
            }
        }
        Ok(Self {
            targets: map,
            signer,
        })
    }
    pub(crate) fn target(
        &self,
        purpose: &PlatformPurpose,
    ) -> Result<Option<EnterpriseTarget>, AuthorityError> {
        match purpose {
            PlatformPurpose::BrowserLogin => Ok(None),
            PlatformPurpose::EnterpriseRp(id) => self
                .targets
                .get(id)
                .cloned()
                .map(Some)
                .ok_or(AuthorityError::Rejected),
        }
    }
}
/// Backend-only credential. Intentionally neither serializable nor Debug.
pub struct EnterpriseAssertion {
    pub target: EnterpriseTarget,
    pub expires_at: i64,
    value: Zeroizing<String>,
}
impl EnterpriseAssertion {
    pub fn expose(&self) -> &str {
        &self.value
    }
}
/// Only released by confirmed commit. HTTP adapters must never serialize the assertion.
pub struct PlatformLogin {
    pub session: IssuedSession,
    pub assertion: Option<EnterpriseAssertion>,
}
pub(crate) fn issue(
    config: &EnterpriseConfig,
    target: EnterpriseTarget,
    stored: &PlatformAuthentication,
    now: i64,
    session_expiry: i64,
) -> Result<EnterpriseAssertion, transaction::MutationError> {
    let expires_at = (now + 30).min(session_expiry);
    let claims = EnterpriseClaims {
        iss: target.issuer.clone(),
        sub: format!(
            "{}/{}/{}",
            stored.binding.instance,
            stored.binding.account.tenant,
            stored.binding.account.principal.as_uuid()
        ),
        aud: target.token_endpoint.clone(),
        jti: Uuid::new_v4().to_string(),
        iat: now,
        exp: expires_at,
        scope: target.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
        client_id: target.client_id.clone(),
        rp: target.id.clone(),
        auth_time: stored.authenticated_at,
        user_presence: stored.user_presence,
        user_verification: stored.user_verification,
        key_possession: true,
    };
    let value = config
        .signer
        .sign(&claims)
        .map_err(|_| failure(PlatformError::Unavailable))?;
    if value.is_empty() || value.len() > 16384 {
        return Err(corrupt().into());
    }
    Ok(EnterpriseAssertion {
        target,
        expires_at,
        value,
    })
}
