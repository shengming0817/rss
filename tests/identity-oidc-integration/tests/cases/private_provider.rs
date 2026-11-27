use crate::support::*;
#[path = "../support/form.rs"]
mod form;
use rss_identity_core::{assurance::AuthenticationMode, federation::*};
use rss_identity_oidc::{
    HttpOidc, PrivateProviderAccess,
    test_support::{fixture_install, fixture_provider, reuse_policy},
};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use url::Url;

fn private_host() -> anyhow::Result<Ipv4Addr> {
    if let Some(value) = std::env::var_os("IDENTITY_TEST_PRIVATE_HOST") {
        let address: Ipv4Addr = value
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid IDENTITY_TEST_PRIVATE_HOST"))?
            .parse()?;
        anyhow::ensure!(
            address.is_private(),
            "Keycloak published endpoint must be RFC1918"
        );
        return Ok(address);
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    // Route lookup only. No datagram is transmitted.
    socket.connect(("10.255.255.255", 9))?;
    let SocketAddr::V4(addr) = socket.local_addr()? else {
        anyhow::bail!("IPv4 host required")
    };
    anyhow::ensure!(
        addr.ip().is_private(),
        "an owned RFC1918 host address is required"
    );
    Ok(*addr.ip())
}
#[tokio::test]
async fn private_keycloak_login() -> anyhow::Result<()> {
    let host = private_host()?;
    let keycloak = testkit::keycloak_tls(
        host,
        std::env::var_os("IDENTITY_TEST_PRIVATE_HOST").is_some(),
        include_bytes!("../support/realm.json"),
    )
    .await?;
    let issuer = format!("{}/realms/identity", keycloak.origin);
    let ca = &keycloak.ca_pem;
    let c = settings(&issuer)?;
    let allowed = HttpOidc::new(
        crate::fixture_clock::clock(),
        vec![],
        vec![PrivateProviderAccess {
            tenant: tenant()?,
            issuer: issuer.clone(),
            client_id: "identity-test".into(),
            cidrs: vec![format!("{host}/32").parse()?],
        }],
        policy()?,
        reuse_policy(),
    )?;
    let trusted = ProviderCredentials::new("fixture-secret".into(), Some(ca.clone()))?;
    let mut internal_return = c.input();
    internal_return.redirect_uri = "https://192.168.1.7/callback".into();
    allowed.validate(tenant()?, &internal_return.try_into()?, &trusted)?;
    let denied = HttpOidc::new(
        crate::fixture_clock::clock(),
        vec![],
        vec![],
        policy()?,
        reuse_policy(),
    )?;
    anyhow::ensure!(denied.validate(tenant()?, &c, &trusted).is_err());
    anyhow::ensure!(
        denied
            .validate(tenant()?, &settings("https://127.0.0.1")?, &trusted)
            .is_err()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local = settings(&format!(
        "https://localhost:{}",
        listener.local_addr()?.port()
    ))?;
    let attempt = denied
        .test(
            fixture_provider(&denied, tenant()?, &local, &trusted),
            deadline(),
        )
        .await;
    assert!(
        matches!(attempt,Err(FederationError::Provider(f)) if f.reason==ProviderReason::EgressDenied)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let bound = fixture_provider(&allowed, tenant()?, &c, &trusted);
    anyhow::ensure!(allowed.test(bound.clone(), deadline()).await?.tls_verified);
    let revision = bound.revision();
    let untrusted = ProviderCredentials::new("fixture-secret".into(), None)?;
    let no_ca = fixture_install(
        &allowed,
        ProviderRevision {
            version: 2,
            ..revision
        },
        &c,
        &untrusted,
    )?;
    anyhow::ensure!(
        matches!(allowed.test(no_ca,deadline()).await,Err(FederationError::Provider(f)) if f.reason == ProviderReason::TlsRejected)
    );
    let bound = fixture_install(
        &allowed,
        ProviderRevision {
            version: 3,
            ..revision
        },
        &c,
        &trusted,
    )?;
    let material = ProtocolMaterial::new(random_secret()?.to_string())?;
    let auth = allowed
        .prepare(
            bound.clone(),
            &material,
            AuthenticationMode::Login,
            deadline(),
        )
        .await?;
    let browser = reqwest::Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes())?)
        .build()?;
    let page = browser
        .get(auth)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let action = Url::parse(&form::action(&page)?)?;
    anyhow::ensure!(
        action.origin() == Url::parse(&issuer)?.origin(),
        "unexpected form origin"
    );
    let reply = browser
        .post(action)
        .form(&[("username", "alice"), ("password", "fixture-password")])
        .send()
        .await?;
    anyhow::ensure!(reply.status().is_redirection(), "login failed");
    let callback = Url::parse(
        reply
            .headers()
            .get("location")
            .ok_or_else(|| anyhow::anyhow!("callback missing"))?
            .to_str()?,
    )?;
    let query: std::collections::HashMap<_, _> = callback.query_pairs().into_owned().collect();
    anyhow::ensure!(
        query.get("state").map(String::as_str) == Some(material.state.as_str()),
        "state mismatch"
    );
    let code = query
        .get("code")
        .ok_or_else(|| anyhow::anyhow!("code missing"))?;
    let claims = allowed
        .exchange(bound, material, code.clone().into(), deadline())
        .await?;
    assert_eq!(claims.issuer, issuer);
    claims.subject.validate()?;
    Ok(())
}
