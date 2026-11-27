#[path = "support/policy.rs"]
mod policy;
use rss_identity_core::federation::*;
use rss_identity_oidc::ReusePolicy;
use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
fn input() -> ProviderSettingsInput {
    ProviderSettingsInput {
        issuer: "https://idp.example.test".into(),
        client_id: "client".into(),
        redirect_uri: "https://identity.example.test/api/v1/identity/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            department_snapshot: None,
            profile: rss_identity_core::profile::ProfileSettings::default(),
            groups: None,
        },
        jit: false,
    }
}
fn credentials() -> ProviderCredentials {
    ProviderCredentials::new("fixture-secret".into(), None).unwrap()
}
#[test]
fn self_service_rejects_special_network_destinations() {
    let adapter =
        HttpOidc::new(vec![], vec![], transport_policy(), policy::reuse_policy()).unwrap();
    for issuer in ["https://idp.example.test", "https://8.8.8.8"] {
        let mut c = input();
        c.issuer = issuer.into();
        assert!(
            adapter
                .validate(tenant(), &c.try_into().unwrap(), &credentials())
                .is_ok()
        );
    }
    for issuer in [
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://10.0.0.1",
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        "https://2130706433",
        "http://idp.example.test",
        "not a url",
        "https://user:secret@idp.example.test",
        "https://idp.example.test/#fragment",
    ] {
        let mut c = input();
        c.issuer = issuer.into();
        assert!(
            ProviderSettings::try_from(c)
                .and_then(|c| adapter.validate(tenant(), &c, &credentials()))
                .is_err()
        );
    }
    let c: ProviderSettings = input().try_into().unwrap();
    assert!(
        adapter
            .validate(
                tenant(),
                &c,
                &ProviderCredentials::new(
                    "fixture-secret".into(),
                    Some("invalid certificate".into())
                )
                .unwrap()
            )
            .is_err()
    );
}
#[test]
fn trusted_assurance_is_independent_and_exactly_scoped() {
    let c: ProviderSettings = input().try_into().unwrap();
    let weak = HttpOidc::new(vec![], vec![], transport_policy(), policy::reuse_policy()).unwrap();
    let trusted = HttpOidc::new(
        vec![TrustedAssuranceProfile {
            tenant: tenant(),
            issuer: c.issuer().as_str().into(),
            client_id: c.client_id().as_str().into(),
            keycloak_totp: true,
        }],
        vec![],
        transport_policy(),
        policy::reuse_policy(),
    )
    .unwrap();
    let approved = trusted.assurance_profile(tenant(), &c);
    assert!(approved.supports_step_up);
    assert_eq!(
        approved.fingerprint,
        digest("keycloak-26.7.3/password-totp/acr-2/v1")
    );
    let unapproved = weak.assurance_profile(tenant(), &c);
    assert!(!unapproved.supports_step_up);
    assert_eq!(unapproved.fingerprint, digest("unspecified/v1"));
    assert!(
        !trusted
            .assurance_profile(
                TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                &c
            )
            .supports_step_up
    );
    assert_ne!(
        weak.assurance_profile(tenant(), &c),
        trusted.assurance_profile(tenant(), &c)
    );
    let other = TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    assert_eq!(
        weak.assurance_profile(other, &c),
        trusted.assurance_profile(other, &c)
    );
    assert!(trusted.validate(other, &c, &credentials()).is_ok());
}

fn transport_policy() -> rss_identity_oidc::TransportPolicy {
    rss_identity_oidc::TransportPolicy::new(
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(3),
        1024 * 1024,
        128,
    )
    .unwrap()
}

#[test]
fn transport_policy_validates_finite_resource_selections() {
    use rss_identity_oidc::TransportPolicy;
    use std::time::Duration;
    assert!(
        TransportPolicy::new(
            Duration::from_secs(120),
            Duration::from_secs(30),
            2 * 1024 * 1024,
            1024
        )
        .is_ok()
    );
    for timeout in [Duration::ZERO, Duration::MAX] {
        assert!(TransportPolicy::new(timeout, Duration::from_secs(3), 1024, 128).is_err());
    }
    assert!(TransportPolicy::new(Duration::from_secs(5), Duration::from_secs(3), 0, 128).is_err());
}
