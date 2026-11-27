use crate::{CredentialError, HttpConfig, cookie, csrf, request_marker, same_origin};
use http::HeaderMap;
use rss_identity_core::session::SessionSecret;
use rss_identity_postgres::{AuthenticatedSession, Authority};
use rss_transactional_messaging::{fence::ExecutionBinding, policy::OperationDeadline};
use std::time::Instant;

pub(crate) fn cutoff(
    config: &HttpConfig,
    deadline: OperationDeadline,
) -> Result<Instant, CredentialError> {
    let remaining = deadline.timeout().min(config.timeout());
    if remaining.is_zero() {
        return Err(CredentialError::Deadline);
    }
    Instant::now()
        .checked_add(remaining)
        .ok_or(CredentialError::Deadline)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionActivity {
    Passive,
    Active,
}

/// Active calls verify browser intent before touching idle expiry. Passive reads only inspect.
/// Both return a request-local proof and a zeroizing credential for protocol continuation.
pub async fn authenticate_request(
    authority: &Authority,
    config: &HttpConfig,
    binding: ExecutionBinding,
    headers: &HeaderMap,
    activity: SessionActivity,
    deadline: OperationDeadline,
) -> Result<(AuthenticatedSession, SessionSecret), CredentialError> {
    let end = cutoff(config, deadline)?;
    authority.require_runtime()?;
    crate::cookie_presentation(headers)?;
    if activity == SessionActivity::Active {
        same_origin(headers, config)?;
        if !request_marker(headers)? {
            return Err(CredentialError::Forbidden);
        }
    }
    let secret = cookie(headers)?.ok_or(CredentialError::Invalid)?;
    if activity == SessionActivity::Active {
        csrf(headers, &secret)?;
    }
    let retained =
        SessionSecret::parse(secret.expose().into()).map_err(|_| CredentialError::Invalid)?;
    let remaining =
        OperationDeadline::from_remaining(end.saturating_duration_since(Instant::now()));
    let proof = match activity {
        SessionActivity::Passive => {
            authority
                .inspect_session(binding, secret, remaining)
                .await?
        }
        SessionActivity::Active => {
            authority
                .authenticate_session(binding, secret, remaining)
                .await?
        }
    };
    Ok((proof, retained))
}
