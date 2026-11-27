use crate::support::*;
use http::HeaderMap;
use rss_identity_web_credentials::{
    CredentialError, HttpConfig, SessionActivity, authenticate_request, issued_cookie,
};
use std::time::Duration;

pub async fn run(f: &Fixture) -> anyhow::Result<()> {
    let issued = f.login().await?;
    let config = HttpConfig::new("https://host.example.test", Duration::from_secs(10))?;
    let cookie = issued_cookie(&issued)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        cookie
            .header
            .to_str()?
            .split(';')
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing session cookie"))?
            .parse()?,
    );
    // Shorten persisted idle expiry so renewal is observable without relying on a wall-clock tick.
    let idle = issued.view().issued_at + 240;
    sqlx::query("UPDATE identity_authority.sessions SET idle_expires_at=$2 WHERE session_id=$1")
        .bind(issued.view().id.as_uuid())
        .bind(idle)
        .execute(&f.owner)
        .await?;
    let scope = binding(f.key.tenant);
    let passive = authenticate_request(
        &f.store,
        &config,
        scope,
        &headers,
        SessionActivity::Passive,
        deadline(),
    )
    .await?;
    assert_eq!(passive.0.view().idle_expires_at, idle);
    headers.insert("origin", "https://host.example.test".parse()?);
    headers.insert("x-identity-request", "1".parse()?);
    headers.insert("x-csrf-token", "wrong".parse()?);
    assert!(matches!(
        authenticate_request(
            &f.store,
            &config,
            scope,
            &headers,
            SessionActivity::Active,
            deadline()
        )
        .await,
        Err(CredentialError::Forbidden)
    ));
    let still_idle = authenticate_request(
        &f.store,
        &config,
        scope,
        &headers,
        SessionActivity::Passive,
        deadline(),
    )
    .await?;
    assert_eq!(still_idle.0.view().idle_expires_at, idle);
    headers.insert("x-csrf-token", cookie.csrf_token.parse()?);
    let (active, _) = authenticate_request(
        &f.store,
        &config,
        scope,
        &headers,
        SessionActivity::Active,
        deadline(),
    )
    .await?;
    assert!(active.view().idle_expires_at > idle);
    f.store.revoke_current_session(active, deadline()).await?;
    assert!(
        authenticate_request(
            &f.store,
            &config,
            scope,
            &headers,
            SessionActivity::Passive,
            deadline()
        )
        .await
        .is_err()
    );
    Ok(())
}
