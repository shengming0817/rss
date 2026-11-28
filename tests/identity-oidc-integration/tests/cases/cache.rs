//! Real HTTP discovery revalidation with deterministic coordination of concurrent callers.
use super::jwks_rotation::measured;
use crate::support::*;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use rss_identity_core::{assurance::AuthenticationMode, federation::*};
use rss_identity_oidc::{
    HttpOidc,
    test_support::{fixture_install, fixture_provider, reuse_counts, reuse_policy},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use tokio::sync::Semaphore;

#[tokio::test]
async fn conditional_refresh_and_generation_isolation() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(20), run()).await?
}
#[allow(
    clippy::cognitive_complexity,
    reason = "observe cache validation, cancellation and retirement on a single live endpoint"
)]
async fn run() -> anyhow::Result<()> {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let issuer = format!("http://{}/realm", socket.local_addr()?);
    let meta = serde_json::json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/auth"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/keys"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]});
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let routes = Router::new().route(
        "/realm/.well-known/openid-configuration",
        get({
            let (entered, release, requests) = (entered.clone(), release.clone(), requests.clone());
            move |headers: HeaderMap| {
                let (entered, release, requests, meta) = (
                    entered.clone(),
                    release.clone(),
                    requests.clone(),
                    meta.clone(),
                );
                async move {
                    let n = requests.fetch_add(1, SeqCst);
                    if n > 0 {
                        entered.add_permits(1);
                        if let Ok(permit) = release.acquire().await {
                            permit.forget();
                        }
                    }
                    if headers.contains_key("if-none-match") {
                        (
                            StatusCode::NOT_MODIFIED,
                            [
                                (
                                    "cache-control",
                                    if n == 1 { "max-age=0" } else { "no-store" },
                                ),
                                ("etag", "\"rev\""),
                            ],
                        )
                            .into_response()
                    } else {
                        (
                            [
                                (
                                    "cache-control",
                                    if n == 0 { "max-age=0" } else { "no-store" },
                                ),
                                ("etag", "\"rev\""),
                            ],
                            Json(meta),
                        )
                            .into_response()
                    }
                }
            }
        }),
    );
    let server = tokio::spawn(axum::serve(socket, routes).into_future());
    let adapter = HttpOidc::for_loopback_test(
        crate::fixture_clock::clock(),
        vec![],
        policy()?,
        rss_identity_oidc::ReusePolicy {
            max_refreshes: 1,
            ..reuse_policy()
        },
    )?;
    let c = settings(&issuer)?;
    let creds = ProviderCredentials::new("fixture-secret".into(), None)?;
    let bound = fixture_provider(&adapter, tenant()?, &c, &creds);
    let material = ProtocolMaterial::new("state".into())?;
    let prepare = |bound| adapter.prepare(bound, &material, AuthenticationMode::Login, deadline());
    prepare(bound.clone()).await?;
    let cold = reuse_counts(&adapter);
    let shared = async { tokio::try_join!(prepare(bound.clone()), prepare(bound.clone())) };
    let release_one = async {
        entered.acquire().await?.forget();
        release.add_permits(1);
        Ok::<_, anyhow::Error>(())
    };
    let (result, released) =
        tokio::join!(measured("shared conditional refresh", shared), release_one);
    released?;
    result?;
    assert_eq!(requests.load(SeqCst), 2);
    assert_eq!(reuse_counts(&adapter), cold);
    println!(
        "OIDC shared conditional refresh: GET=1 public_decodes=0 resident_bytes={}",
        cold.2
    );
    let concurrent = async { tokio::try_join!(prepare(bound.clone()), prepare(bound.clone())) };
    let unblock = async {
        entered.acquire().await.map(|p| p.forget())?;
        release.add_permits(2);
        Ok::<_, anyhow::Error>(())
    };
    let (result, released) = tokio::join!(measured("concurrent refresh", concurrent), unblock);
    released?;
    result?;
    let after = reuse_counts(&adapter);
    // One caller consumed the checked 304, the other fetched its private no-store response.
    assert_eq!(requests.load(SeqCst), 4);
    assert_eq!((after.0, after.2), (cold.0 + 1, 0));
    println!(
        "OIDC concurrent refresh: GET=2 public_decodes=1 resident_bytes={}",
        after.2
    );
    entered.acquire().await?.forget();
    let mut pending = prepare(bound.clone());
    tokio::select! {result=&mut pending=>anyhow::bail!("unexpected early result {result:?}"), permit=entered.acquire()=>permit?.forget()}
    drop(pending);
    release.add_permits(2);
    prepare(bound.clone()).await?;
    assert_eq!(requests.load(SeqCst), 6);
    adapter.revisions().retire(bound.revision());
    assert!(prepare(bound.clone()).await.is_err());
    let fresh = fixture_install(
        &adapter,
        ProviderRevision {
            version: 2,
            ..bound.revision()
        },
        &c,
        &creds,
    )?;
    release.add_permits(1);
    prepare(fresh).await?;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn retired_refresh_and_same_version_reinstallation() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), same_version()).await?
}

async fn same_version() -> anyhow::Result<()> {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let issuer = format!("http://{}/realm", socket.local_addr()?);
    let hits = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let endpoint = {
        let (hits, entered, release, issuer) = (
            hits.clone(),
            entered.clone(),
            release.clone(),
            issuer.clone(),
        );
        move |headers: HeaderMap| {
            let (hits, entered, release, issuer) = (
                hits.clone(),
                entered.clone(),
                release.clone(),
                issuer.clone(),
            );
            async move {
                let n = hits.fetch_add(1, SeqCst);
                assert_eq!(
                    headers.get("if-none-match").and_then(|v| v.to_str().ok()),
                    (n == 1).then_some("\"old\"")
                );
                if n == 1 {
                    entered.add_permits(1);
                    if let Ok(permit) = release.acquire().await {
                        permit.forget();
                    }
                }
                let auth = if n < 2 { "old-auth" } else { "new-auth" };
                (
                    [
                        ("etag", if n < 2 { "\"old\"" } else { "\"new\"" }),
                        ("cache-control", "max-age=0"),
                    ],
                    Json(
                        serde_json::json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/{auth}"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/keys"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}),
                    ),
                )
            }
        }
    };
    let routes = Router::new().route("/realm/.well-known/openid-configuration", get(endpoint));
    let server = tokio::spawn(axum::serve(socket, routes).into_future());
    let adapter = HttpOidc::for_loopback_test(
        crate::fixture_clock::clock(),
        vec![],
        policy()?,
        reuse_policy(),
    )?;
    let c = settings(&issuer)?;
    let creds = ProviderCredentials::new("fixture-secret".into(), None)?;
    let old = fixture_provider(&adapter, tenant()?, &c, &creds);
    let material = ProtocolMaterial::new("state".into())?;
    let prepare = |bound| adapter.prepare(bound, &material, AuthenticationMode::Login, deadline());
    assert!(prepare(old.clone()).await?.contains("/old-auth?"));
    let mut flight = prepare(old.clone());
    tokio::select! {r=&mut flight=>anyhow::bail!("old refresh ended before retirement {r:?}"), permit=entered.acquire()=>permit?.forget()}
    adapter.revisions().retire(old.revision());
    let reinstalled = fixture_install(&adapter, old.revision(), &c, &creds)?;
    let (old_result, new_result) = tokio::join!(flight, prepare(reinstalled));
    assert_eq!(old_result.err(), Some(FederationError::StaleConfiguration));
    assert!(new_result?.contains("/new-auth?"));
    assert_eq!(hits.load(SeqCst), 3);
    release.add_permits(1);
    server.abort();
    Ok(())
}
