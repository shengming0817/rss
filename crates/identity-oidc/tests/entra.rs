//! Real loopback JWKS HTTP and RSA signatures. These are synthetic claims, not Entra T3.
#![cfg(feature = "test-support")]
use axum::{Json, Router, routing::get};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rss_identity_core::entra::*;
use rss_identity_oidc::entra::HttpEntra;
use serde_json::{Value, json};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

#[allow(
    clippy::unwrap_used,
    reason = "Fixed test inputs and immediate fixture assertions"
)]
fn jwt(claims: &Value, kid: Option<&str>, key: &[u8]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    encode(&header, claims, &EncodingKey::from_rsa_der(key)).unwrap()
}
#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "Fixed test inputs and immediate fixture assertions"
)]
async fn signed_entra_resource_tokens() -> anyhow::Result<()> {
    let key_a = include_bytes!("fixtures/entra-a.der");
    let key_b = include_bytes!("fixtures/entra-b.der");
    let jwk: Value = serde_json::from_str(include_str!("fixtures/entra-a.json"))?;
    let document = Arc::new(RwLock::new(json!({"keys":[jwk]})));
    let blocked = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let response = document.clone();
    let gate = (blocked.clone(), entered.clone(), resume.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/keys", listener.local_addr()?);
    let app = Router::new().route(
        "/keys",
        get(move || {
            let response = response.clone();
            let (blocked, entered, resume) = gate.clone();
            async move {
                if blocked.load(Ordering::SeqCst) {
                    entered.notify_one();
                    resume.notified().await;
                }
                Json(response.read().unwrap().clone())
            }
        }),
    );
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown.await;
            })
            .await
            .unwrap();
    });
    let p = EntraTokenProfile {
        tenant: Uuid::new_v4(),
        app_id: Uuid::new_v4(),
        authorized_clients: vec![Uuid::new_v4()],
        required_scopes: vec!["mdm.enroll".into()],
        device_claim: "deviceid".into(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let claims = json!({"iss":p.issuer(),"aud":p.app_id,"ver":"2.0","idtyp":"user","tid":p.tenant,"oid":user,"azp":p.authorized_clients[0],"iat":now-1,"nbf":now-1,"exp":now+300,"scp":"mdm.enroll other","deviceid":device});
    let verifier = Arc::new(HttpEntra::for_loopback_test(
        endpoint.clone(),
        transport_policy(),
        32768,
        cache_policy(),
    )?);
    let result = verifier
        .verify(
            &p,
            Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)),
            upstream_deadline(),
        )
        .await?;
    assert_eq!(result.user, user);
    assert_eq!(result.device, Some(device));
    let mut tou = claims.clone();
    tou.as_object_mut().unwrap().remove("deviceid");
    assert!(
        verifier
            .verify(
                &p,
                Zeroizing::new(jwt(&tou, Some("entra-a"), key_a)),
                upstream_deadline()
            )
            .await?
            .device
            .is_none()
    );
    for (field, value) in [
        (
            "iss",
            json!("https://login.microsoftonline.com/common/v2.0"),
        ),
        ("aud", json!(format!("api://{}", p.app_id))),
        ("aud", json!([p.app_id])),
        ("ver", json!("1.0")),
        ("idtyp", json!("app")),
        ("tid", json!(Uuid::new_v4())),
        ("oid", json!(Uuid::nil())),
        ("azp", json!(Uuid::new_v4())),
        ("scp", json!("other")),
        ("exp", json!(now - 1)),
        ("nbf", json!(now + 60)),
        ("iat", json!(now + 60)),
        ("deviceid", json!("invalid-device")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        assert!(
            verifier
                .verify(
                    &p,
                    Zeroizing::new(jwt(&invalid, Some("entra-a"), key_a)),
                    upstream_deadline()
                )
                .await
                .is_err(),
            "field {field}"
        );
    }
    for field in [
        "idtyp", "oid", "tid", "azp", "exp", "nbf", "iss", "aud", "ver",
    ] {
        let mut invalid = claims.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            verifier
                .verify(
                    &p,
                    Zeroizing::new(jwt(&invalid, Some("entra-a"), key_a)),
                    upstream_deadline()
                )
                .await
                .is_err(),
            "missing {field}"
        );
    }
    for (kid, key) in [
        (None, key_a.as_slice()),
        (Some("unknown"), key_a.as_slice()),
        (Some("entra-a"), key_b.as_slice()),
    ] {
        assert!(
            verifier
                .verify(
                    &p,
                    Zeroizing::new(jwt(&claims, kid, key)),
                    upstream_deadline()
                )
                .await
                .is_err()
        );
    }
    // A slow miss from another tenant must not block this tenant's hot cache.
    blocked.store(true, Ordering::SeqCst);
    let mut other = p.clone();
    other.tenant = Uuid::new_v4();
    let mut other_claims = claims.clone();
    other_claims["tid"] = json!(other.tenant);
    other_claims["iss"] = json!(other.issuer());
    let pending = {
        let verifier = verifier.clone();
        tokio::spawn(async move {
            verifier
                .verify(
                    &other,
                    Zeroizing::new(jwt(&other_claims, Some("entra-a"), key_a)),
                    upstream_deadline(),
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    let hot = tokio::time::timeout(
        Duration::from_millis(500),
        verifier.verify(
            &p,
            Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)),
            upstream_deadline(),
        ),
    )
    .await;
    blocked.store(false, Ordering::SeqCst);
    resume.notify_one();
    pending.await??;
    assert!(hot??.user == user);
    // The same still-valid cache refreshes once for a rotated unknown key.
    *document.write().unwrap() =
        json!({"keys":[serde_json::from_str::<Value>(include_str!("fixtures/entra-b.json"))?]});
    tokio::time::sleep(Duration::from_millis(30)).await;
    let rotated = verifier.clone();
    assert!(
        rotated
            .verify(
                &p,
                Zeroizing::new(jwt(&claims, Some("entra-b"), key_b)),
                upstream_deadline()
            )
            .await
            .is_ok()
    );
    assert!(
        rotated
            .verify(
                &p,
                Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)),
                upstream_deadline()
            )
            .await
            .is_err()
    );
    let a: Value = serde_json::from_str(include_str!("fixtures/entra-a.json"))?;
    *document.write().unwrap() = json!({"keys":[a,a]});
    assert!(
        HttpEntra::for_loopback_test(endpoint, transport_policy(), 32768, cache_policy())?
            .verify(
                &p,
                Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)),
                upstream_deadline()
            )
            .await
            .is_err()
    );
    let _ = stop.send(());
    server.await?;
    Ok(())
}

#[allow(
    clippy::unwrap_used,
    reason = "Fixed test inputs and immediate fixture assertions"
)]
fn transport_policy() -> rss_identity_oidc::TransportPolicy {
    rss_identity_oidc::TransportPolicy::new(
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(3),
        1024 * 1024,
        128,
    )
    .unwrap()
}

#[allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "Fixed test inputs and immediate fixture assertions"
)]
fn upstream_deadline() -> rss_request_context::Deadline {
    rss_request_context::Deadline::at(
        std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(30))
            .unwrap(),
    )
}

#[allow(
    clippy::unwrap_used,
    reason = "Fixed test inputs and immediate fixture assertions"
)]
fn cache_policy() -> rss_identity_oidc::entra::JwksCachePolicy {
    rss_identity_oidc::entra::JwksCachePolicy::new(
        Duration::from_secs(60),
        std::num::NonZeroUsize::new(1024).unwrap(),
        Duration::from_millis(20),
    )
    .unwrap()
}

#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "Fixed test inputs and immediate fixture assertions"
)]
async fn jwks_refresh_cooldown_expiry_and_capacity() -> anyhow::Result<()> {
    use axum::{http::StatusCode, response::IntoResponse};
    use rss_identity_oidc::entra::JwksCachePolicy;
    use std::num::NonZeroUsize;
    use std::sync::atomic::AtomicUsize;
    let key_a = include_bytes!("fixtures/entra-a.der");
    let key_b = include_bytes!("fixtures/entra-b.der");
    let document = Arc::new(RwLock::new(
        json!({"keys":[serde_json::from_str::<Value>(include_str!("fixtures/entra-a.json"))?]}),
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let blocked = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let handler = (
        document.clone(),
        calls.clone(),
        failed.clone(),
        blocked.clone(),
        entered.clone(),
        resume.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/keys", listener.local_addr()?);
    let app = Router::new().route(
        "/keys",
        get(move || {
            let (document, calls, failed, blocked, entered, resume) = handler.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if blocked.load(Ordering::SeqCst) {
                    entered.notify_one();
                    resume.notified().await;
                }
                if failed.load(Ordering::SeqCst) {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                Json(document.read().unwrap().clone()).into_response()
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let p = EntraTokenProfile {
        tenant: Uuid::new_v4(),
        app_id: Uuid::new_v4(),
        authorized_clients: vec![Uuid::new_v4()],
        required_scopes: vec!["read".into()],
        device_claim: "deviceid".into(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"iss":p.issuer(),"aud":p.app_id,"ver":"2.0","idtyp":"user","tid":p.tenant,"oid":Uuid::new_v4(),"azp":p.authorized_clients[0],"iat":now-1,"nbf":now-1,"exp":now+300,"scp":"read"});
    let selected = JwksCachePolicy::new(
        Duration::from_millis(400),
        NonZeroUsize::new(2).unwrap(),
        Duration::from_millis(100),
    )?;
    let verifier = Arc::new(HttpEntra::for_loopback_test(
        endpoint.clone(),
        transport_policy(),
        32768,
        selected,
    )?);
    verifier
        .verify(
            &p,
            Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)),
            upstream_deadline(),
        )
        .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    *document.write().unwrap() =
        json!({"keys":[serde_json::from_str::<Value>(include_str!("fixtures/entra-b.json"))?]});
    tokio::time::sleep(Duration::from_millis(110)).await;
    let token = jwt(&claims, Some("entra-b"), key_b);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (v, p, t) = (verifier.clone(), p.clone(), token.clone());
        tasks.push(tokio::spawn(async move {
            v.verify(&p, Zeroizing::new(t), upstream_deadline()).await
        }));
    }
    for task in tasks {
        task.await??;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    for i in 0..8 {
        assert!(
            verifier
                .verify(
                    &p,
                    Zeroizing::new(jwt(&claims, Some(&format!("unknown-{i}")), key_b)),
                    upstream_deadline()
                )
                .await
                .is_err()
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "random kids share one tenant cooldown"
    );
    tokio::time::sleep(Duration::from_millis(110)).await;
    failed.store(true, Ordering::SeqCst);
    let unknown = jwt(&claims, Some("missing"), key_b);
    assert!(
        verifier
            .verify(&p, Zeroizing::new(unknown.clone()), upstream_deadline())
            .await
            .is_err()
    );
    assert!(
        verifier
            .verify(&p, Zeroizing::new(unknown.clone()), upstream_deadline())
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    verifier
        .verify(&p, Zeroizing::new(token.clone()), upstream_deadline())
        .await?;
    tokio::time::sleep(Duration::from_millis(110)).await;
    failed.store(false, Ordering::SeqCst);
    blocked.store(true, Ordering::SeqCst);
    let pending = {
        let (v, p, t) = (verifier.clone(), p.clone(), unknown.clone());
        tokio::spawn(async move { v.verify(&p, Zeroizing::new(t), upstream_deadline()).await })
    };
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    pending.abort();
    let _ = pending.await;
    blocked.store(false, Ordering::SeqCst);
    resume.notify_one();
    assert!(
        verifier
            .verify(&p, Zeroizing::new(unknown), upstream_deadline())
            .await
            .is_err()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "cancelled fetch keeps cooldown"
    );
    tokio::time::sleep(Duration::from_millis(450)).await;
    verifier
        .verify(&p, Zeroizing::new(token), upstream_deadline())
        .await?;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "expired cache is fetched again"
    );
    let mut other = p.clone();
    other.tenant = Uuid::new_v4();
    let mut other_claims = claims.clone();
    other_claims["tid"] = json!(other.tenant);
    other_claims["iss"] = json!(other.issuer());
    verifier
        .verify(
            &other,
            Zeroizing::new(jwt(&other_claims, Some("entra-b"), key_b)),
            upstream_deadline(),
        )
        .await?;
    other.tenant = Uuid::new_v4();
    other_claims["tid"] = json!(other.tenant);
    other_claims["iss"] = json!(other.issuer());
    assert!(
        verifier
            .verify(
                &other,
                Zeroizing::new(jwt(&other_claims, Some("entra-b"), key_b)),
                upstream_deadline()
            )
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    tokio::time::sleep(Duration::from_millis(450)).await;
    verifier
        .verify(
            &other,
            Zeroizing::new(jwt(&other_claims, Some("entra-b"), key_b)),
            upstream_deadline(),
        )
        .await?;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        7,
        "expired entries free directory capacity"
    );
    let capacity = HttpEntra::for_loopback_test(
        endpoint,
        transport_policy(),
        32768,
        JwksCachePolicy::new(
            Duration::from_secs(60),
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_millis(100),
        )?,
    )?;
    for _ in 0..1024 {
        other.tenant = Uuid::new_v4();
        other_claims["tid"] = json!(other.tenant);
        other_claims["iss"] = json!(other.issuer());
        capacity
            .verify(
                &other,
                Zeroizing::new(jwt(&other_claims, Some("entra-b"), key_b)),
                upstream_deadline(),
            )
            .await?;
    }
    other.tenant = Uuid::new_v4();
    other_claims["tid"] = json!(other.tenant);
    other_claims["iss"] = json!(other.issuer());
    assert!(
        capacity
            .verify(
                &other,
                Zeroizing::new(jwt(&other_claims, Some("entra-b"), key_b)),
                upstream_deadline()
            )
            .await
            .is_err()
    );
    server.abort();
    let _ = server.await;
    Ok(())
}
