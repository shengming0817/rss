use crate::support::*;
use axum::{Json, Router, routing::get};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rss_identity_core::entra::{EntraTokenProfile, EntraTokenVerifier};
use rss_identity_oidc::entra::{HttpEntra, JwksCachePolicy};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "the fixture owns the issuer clock and request deadline"
)]
async fn entra_refreshes_rotated_keys_and_stops_at_the_host_deadline() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let keys = format!("http://{}/keys", listener.local_addr()?);
    let calls = Arc::new(AtomicUsize::new(0));
    let responses = calls.clone();
    let a = serde_json::from_str::<Value>(JWK_A)?;
    let b = serde_json::from_str::<Value>(JWK_B)?;
    let app = Router::new().route(
        "/keys",
        get(move || {
            let index = responses.fetch_add(1, Ordering::SeqCst);
            let key = if index == 0 { a.clone() } else { b.clone() };
            async move {
                if index >= 2 {
                    std::future::pending::<()>().await;
                }
                Json(json!({"keys":[key]}))
            }
        }),
    );
    let server = tokio::spawn(axum::serve(listener, app).into_future());
    let verifier = HttpEntra::for_loopback_test(
        crate::fixture_clock::clock(),
        keys,
        policy()?,
        32768,
        JwksCachePolicy::new(
            Duration::from_secs(60),
            std::num::NonZeroUsize::MIN,
            Duration::from_nanos(1),
        )?,
    )?;
    let p = EntraTokenProfile {
        tenant: "11111111-1111-4111-8111-111111111111".parse()?,
        app_id: "22222222-2222-4222-8222-222222222222".parse()?,
        authorized_clients: vec!["33333333-3333-4333-8333-333333333333".parse()?],
        required_scopes: vec!["read".into()],
        device_claim: "deviceid".into(),
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = json!({"iss":p.issuer(),"aud":p.app_id,"ver":"2.0","idtyp":"user","tid":p.tenant,"oid":p.tenant,"azp":p.authorized_clients[0],"iat":now-1,"nbf":now-1,"exp":now+300,"scp":"read"});
    let sign = |kid: &str, key: &[u8]| {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_rsa_der(key))
    };
    for (kid, key, reads) in [
        ("entra-a", KEY_A, 1),
        ("entra-a", KEY_A, 1),
        ("entra-b", KEY_B, 2),
    ] {
        let claims = verifier
            .verify(&p, sign(kid, key)?.into(), deadline())
            .await?;
        assert_eq!(claims.user, p.tenant);
        assert_eq!(calls.load(Ordering::SeqCst), reads);
    }
    let cutoff =
        rss_request_context::Deadline::at(std::time::Instant::now() + Duration::from_millis(150));
    let pending = verifier.verify(&p, sign("next", KEY_B)?.into(), cutoff);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), pending)
            .await?
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    server.abort();
    Ok(())
}
