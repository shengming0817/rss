use crate::{CredentialError, HttpConfig, cookie, csrf, request_marker, same_origin};
use http::HeaderMap;
use rss_identity_core::session::SessionSecret;
use rss_identity_postgres::{AuthenticatedSession, Authority};
use rss_request_context::Deadline;
use rss_transactional_messaging::fence::ExecutionBinding;
pub(crate) fn cutoff(
    authority: &Authority,
    config: &HttpConfig,
    deadline: Deadline,
) -> Result<Deadline, CredentialError> {
    use rss_request_context::Clock;
    let clock = authority.execution_timer();
    let cutoff = deadline.capped(clock, config.timeout());
    if cutoff.is_expired(clock.now()) {
        return Err(CredentialError::Deadline);
    }
    Ok(cutoff)
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
    deadline: Deadline,
) -> Result<(AuthenticatedSession, SessionSecret), CredentialError> {
    let end = cutoff(authority, config, deadline)?;
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
    let proof = match activity {
        SessionActivity::Passive => authority.inspect_session(binding, secret, end).await?,
        SessionActivity::Active => authority.authenticate_session(binding, secret, end).await?,
    };
    Ok((proof, retained))
}
