use crate::cookie::{SESSION_COOKIE_NAME, named_cookie};
use crate::{CredentialError, HttpConfig, session::cutoff, unique};
use http::HeaderMap;
use rss_identity_core::session::BearerSecret;
use rss_identity_postgres::{AuthenticatedSession, Authority};
use rss_transactional_messaging::{fence::ExecutionBinding, policy::OperationDeadline};

pub fn bearer_presentation(headers: &HeaderMap) -> Result<(), CredentialError> {
    if named_cookie(headers, SESSION_COOKIE_NAME)?.is_some() || headers.contains_key("x-api-key") {
        return Err(CredentialError::Malformed);
    }
    Ok(())
}
pub fn bearer_credential(headers: &HeaderMap) -> Result<BearerSecret, CredentialError> {
    bearer_presentation(headers)?;
    let value = unique(headers, "authorization")?.ok_or(CredentialError::Invalid)?;
    let (scheme, secret) = value.split_once(' ').ok_or(CredentialError::Invalid)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(CredentialError::Invalid);
    }
    BearerSecret::parse(secret.into()).map_err(|_| CredentialError::Invalid)
}

/// Revalidate the bearer and record activity. The retained credential is request-local.
pub async fn authenticate_bearer_request(
    authority: &Authority,
    config: &HttpConfig,
    binding: ExecutionBinding,
    headers: &HeaderMap,
    deadline: OperationDeadline,
) -> Result<(AuthenticatedSession, BearerSecret), CredentialError> {
    let end = cutoff(config, deadline)?;
    let retained = bearer_credential(headers)?;
    let secret =
        BearerSecret::parse(retained.expose().into()).map_err(|_| CredentialError::Invalid)?;
    let proof = authority
        .authenticate_bearer(
            binding,
            secret,
            OperationDeadline::from_remaining(
                end.saturating_duration_since(std::time::Instant::now()),
            ),
        )
        .await?;
    Ok((proof, retained))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bearer_presentation_rejects_duplicates_mixed_and_malformed_credentials() {
        let token = "a".repeat(64);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert_eq!(bearer_credential(&headers).unwrap().expose(), token);
        for (name, value) in [
            ("authorization", format!("Bearer {token}")),
            ("x-api-key", "key".into()),
            ("cookie", "__Host-identity-session=broken".into()),
        ] {
            let mut mixed = headers.clone();
            mixed.append(name, value.parse().unwrap());
            assert!(bearer_credential(&mixed).is_err());
        }
        for value in [
            "Basic secret",
            "Bearer ",
            "Bearer abc",
            "Bearer  ",
            "Bearer a,b",
        ] {
            headers.insert("authorization", value.parse().unwrap());
            assert!(bearer_credential(&headers).is_err());
        }
        assert!(!format!("{:?}", BearerSecret::parse(token.clone()).unwrap()).contains(&token));
    }
}
