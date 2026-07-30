#![cfg(feature = "containers")]

use std::fmt::Debug;

fn assert_debug_is_pem_free(label: &str, value: &impl Debug) {
    let rendered = format!("{value:?}");
    for forbidden in [
        "-----BEGIN",
        "PRIVATE KEY",
        "CERTIFICATE-----",
        "rss-test-private-ca",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "{label} Debug leaked PEM or private material via {forbidden:?}: {rendered}"
        );
    }
}

#[tokio::test]
async fn hermetic_mqtts_fixture_exposes_closed_credentials_and_lifecycle() -> anyhow::Result<()> {
    let mut fixture = testkit::mosquitto_mtls().await?;

    let endpoint = url::Url::parse(fixture.url())?;
    assert_eq!(endpoint.scheme(), "mqtts");
    assert!(endpoint.host().is_some(), "fixture URL must contain a host");
    assert!(endpoint.port().is_some(), "fixture URL must contain a port");
    assert!(
        endpoint.username().is_empty() && endpoint.password().is_none(),
        "mTLS fixture URL must not embed credentials"
    );

    let rss_a = fixture.rss_a();
    let rss_b = fixture.rss_b();
    assert_eq!(rss_a.revision(), 1);
    assert_eq!(rss_b.revision(), 2);
    assert_eq!(rss_a.stable_client_id(), rss_b.stable_client_id());
    assert!(
        !rss_a.stable_client_id().is_empty(),
        "RSS session identity must be stable and non-empty"
    );

    let device_current = fixture.device_current();
    let device_stale = fixture.device_stale();
    let device_cross = fixture.device_cross_tenant();
    let device_wrong_ca = fixture.device_wrong_ca();
    let device_no_certificate = fixture.device_no_certificate();

    assert!(device_current.tls().certificate_pem().is_some());
    assert!(device_current.tls().private_key_pem().is_some());
    assert!(device_stale.tls().certificate_pem().is_some());
    assert!(device_cross.tls().certificate_pem().is_some());
    assert!(device_wrong_ca.tls().certificate_pem().is_some());
    assert!(device_no_certificate.tls().certificate_pem().is_none());
    assert!(device_no_certificate.tls().private_key_pem().is_none());

    for (label, credential) in [
        ("rss-a", rss_a),
        ("rss-b", rss_b),
        ("device-current", device_current),
        ("device-stale", device_stale),
        ("device-cross-tenant", device_cross),
        ("device-wrong-ca", device_wrong_ca),
        ("device-no-certificate", device_no_certificate),
    ] {
        assert_debug_is_pem_free(label, credential);
        assert_debug_is_pem_free(label, credential.tls());
    }

    let assertion_public_key: &[u8; 32] = fixture.broker_assertion_public_key();
    assert_eq!(assertion_public_key.len(), 32);

    fixture.stop().await?;
    fixture.start().await?;
    fixture.restart().await?;

    let stable_before = fixture.rss_b().stable_client_id().to_owned();
    let fixture = fixture.revoke_device_current_and_rebind().await?;
    assert!(fixture.url().starts_with("mqtts://"));
    assert_eq!(fixture.rss_b().stable_client_id(), stable_before);
    assert!(
        fixture.device_current().tls().certificate_pem().is_some(),
        "revoked fixture still exposes the revoked identity material for negative handshake proofs"
    );

    Ok(())
}
