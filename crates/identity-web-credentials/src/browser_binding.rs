//! Browser correlation and operation proofs are separate from the session credential.
use crate::{
    CredentialError,
    cookie::{named_cookie, secret_header},
    cookie_presentation,
};
use http::{HeaderMap, HeaderValue};
use rss_identity_core::federation::random_secret;
use rss_identity_postgres::{AuthorityError, StepUpGrant};
use std::time::{SystemTime, UNIX_EPOCH};

const BROWSER: &str = "__Host-identity-oidc-browser";
const GRANT: &str = "__Host-identity-operation";

pub struct BrowserBinding {
    pub value: String,
    pub set_cookie: Option<HeaderValue>,
}
impl BrowserBinding {
    fn existing(headers: &HeaderMap) -> Result<Option<&str>, CredentialError> {
        cookie_presentation(headers)?;
        match named_cookie(headers, BROWSER)? {
            Some(v)
                if v.len() == 43
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
            {
                Ok(Some(v))
            }
            None => Ok(None),
            Some(_) => Err(CredentialError::Invalid),
        }
    }
    pub fn start(headers: &HeaderMap) -> Result<Self, CredentialError> {
        if let Some(v) = Self::existing(headers)? {
            return Ok(Self {
                value: v.into(),
                set_cookie: None,
            });
        }
        let value = random_secret().map_err(AuthorityError::from)?.to_string();
        let set_cookie = Some(secret_header(format!(
            "{BROWSER}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"
        ))?);
        Ok(Self { value, set_cookie })
    }
    pub fn require(headers: &HeaderMap) -> Result<String, CredentialError> {
        Self::existing(headers)?
            .map(str::to_owned)
            .ok_or(CredentialError::Invalid)
    }
}

pub fn operation_cookie(grant: &StepUpGrant) -> Result<HeaderValue, CredentialError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
        .ok_or(CredentialError::Deadline)?;
    let age = grant
        .expires_at
        .checked_sub(now)
        .filter(|age| *age > 0)
        .ok_or(AuthorityError::InteractionRequired)?;
    secret_header(format!(
        "{GRANT}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={age}",
        grant.expose()
    ))
}
pub fn read_operation_cookie(headers: &HeaderMap) -> Result<Option<String>, CredentialError> {
    cookie_presentation(headers)?;
    Ok(named_cookie(headers, GRANT)?.map(str::to_owned))
}
pub fn clear_operation_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-identity-operation=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
    )
}
