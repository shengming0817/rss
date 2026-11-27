use crate::CredentialError;
use http::{HeaderMap, HeaderValue, header};
use rss_identity_core::session::{CredentialKind, SessionSecret};
use rss_identity_postgres::{AuthorityError, IssuedSession};

pub(crate) const SESSION_COOKIE_NAME: &str = "__Host-identity-session";
pub fn cookie_presentation(headers: &HeaderMap) -> Result<(), CredentialError> {
    if headers.contains_key(header::AUTHORIZATION) || headers.contains_key("x-api-key") {
        return Err(CredentialError::Malformed);
    }
    Ok(())
}
pub fn cookie(headers: &HeaderMap) -> Result<Option<SessionSecret>, CredentialError> {
    cookie_presentation(headers)?;
    cookie_value(headers)?
        .map(|value| SessionSecret::parse(value.into()).map_err(|_| CredentialError::Invalid))
        .transpose()
}
/// A damaged single value cannot prevent password recovery; ambiguous headers still fail.
pub fn login_cookie(headers: &HeaderMap) -> Result<Option<SessionSecret>, CredentialError> {
    cookie_presentation(headers)?;
    Ok(cookie_value(headers)?.and_then(|value| SessionSecret::parse(value.into()).ok()))
}
fn cookie_value(headers: &HeaderMap) -> Result<Option<&str>, CredentialError> {
    named_cookie(headers, SESSION_COOKIE_NAME)
}
pub(crate) fn named_cookie<'a>(
    headers: &'a HeaderMap,
    name_expected: &str,
) -> Result<Option<&'a str>, CredentialError> {
    let mut found = None;
    let mut size = 0;
    for value in headers.get_all(header::COOKIE) {
        size += value.as_bytes().len();
        if size > 8192 {
            return Err(CredentialError::Malformed);
        }
        for part in value
            .to_str()
            .map_err(|_| CredentialError::Malformed)?
            .split(';')
        {
            let Some((name, value)) = part.trim().split_once('=') else {
                return Err(CredentialError::Malformed);
            };
            if name == name_expected {
                if found.is_some() {
                    return Err(CredentialError::Malformed);
                }
                found = Some(value);
            }
        }
    }
    Ok(found)
}

/// Two presentations derived from a single committed browser session. The header is sensitive.
pub struct IssuedCookie {
    pub header: HeaderValue,
    pub csrf_token: String,
}
pub fn issued_cookie(issued: &IssuedSession) -> Result<IssuedCookie, CredentialError> {
    let age = issued.cookie_max_age();
    if age == 0 || issued.view().credential_kind != CredentialKind::Cookie {
        return Err(AuthorityError::Unavailable.into());
    }
    let header = secret_header(format!(
        "{SESSION_COOKIE_NAME}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={age}",
        issued.secret().expose()
    ))?;
    Ok(IssuedCookie {
        header,
        csrf_token: issued.secret().csrf(),
    })
}
pub(crate) fn secret_header(value: String) -> Result<HeaderValue, CredentialError> {
    let mut header = HeaderValue::from_str(&value).map_err(|_| AuthorityError::Unavailable)?;
    header.set_sensitive(true);
    Ok(header)
}
pub fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-identity-session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
    )
}
