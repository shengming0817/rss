//! In-process presentation of instance-local web credentials.
mod bearer;
mod browser_binding;
mod cookie;
mod origin;
mod session;

pub use bearer::{authenticate_bearer_request, bearer_credential, bearer_presentation};
pub use browser_binding::{
    BrowserBinding, clear_operation_cookie, operation_cookie, read_operation_cookie,
};
pub use cookie::{
    IssuedCookie, clear_session_cookie, cookie, cookie_presentation, issued_cookie, login_cookie,
};
pub use origin::{HttpConfig, HttpConfigError, csrf, request_marker, same_origin};
use rss_identity_postgres::AuthorityError;
pub use session::{SessionActivity, authenticate_request};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("malformed credential presentation")]
    Malformed,
    #[error("invalid credential")]
    Invalid,
    #[error("browser request rejected")]
    Forbidden,
    #[error("request deadline elapsed")]
    Deadline,
    #[error(transparent)]
    Authority(#[from] AuthorityError),
}

fn unique<'a>(
    headers: &'a http::HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, CredentialError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .map(|v| v.to_str().map_err(|_| CredentialError::Malformed))
        .transpose()?;
    if values.next().is_some() {
        return Err(CredentialError::Malformed);
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_origin_configuration_is_explicit_and_canonical() {
        assert!(
            HttpConfig::new(
                "https://identity.example.test",
                std::time::Duration::from_secs(10)
            )
            .is_ok()
        );
        for bad in [
            "http://identity.example.test",
            "https://identity.example.test/",
            "https://user@identity.example.test",
            "https://identity.example.test/path",
            "https://identity.example.test?x=1",
            "https://identity.example.test#fragment",
        ] {
            assert!(HttpConfig::new(bad, std::time::Duration::from_secs(10)).is_err());
        }
    }
    #[test]
    fn session_cookie_and_csrf_are_strict() {
        let secret = rss_identity_core::session::SessionSecret::generate().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "cookie",
            format!("__Host-identity-session={}", secret.expose())
                .parse()
                .unwrap(),
        );
        headers.insert("x-csrf-token", secret.csrf().parse().unwrap());
        assert!(csrf(&headers, &cookie(&headers).unwrap().unwrap()).is_ok());
        headers.append(
            "cookie",
            format!("__Host-identity-session={}", secret.expose())
                .parse()
                .unwrap(),
        );
        assert!(cookie(&headers).is_err());
    }
}
