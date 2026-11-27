#[path = "support/policy.rs"]
mod policy;
use rss_identity_core::federation::*;
use rss_identity_oidc::ReusePolicy;
use rss_identity_oidc::{HttpOidc, PrivateProviderAccess};
use rss_request_context::TenantId;

fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
fn grant(issuer: &str, cidrs: &[&str]) -> PrivateProviderAccess {
    PrivateProviderAccess {
        tenant: tenant(),
        issuer: issuer.into(),
        client_id: "client".into(),
        cidrs: cidrs.iter().map(|value| value.parse().unwrap()).collect(),
    }
}
fn settings(issuer: &str, client: &str) -> ProviderSettings {
    ProviderSettingsInput {
        issuer: issuer.into(),
        client_id: client.into(),
        redirect_uri: "https://reference.example.test/api/v1/identity/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            profile: rss_identity_core::profile::ProfileSettings::default(),
            groups: None,
            department_snapshot: None,
        },
        jit: false,
    }
    .try_into()
    .unwrap()
}
#[test]
fn private_grants_are_exact_and_do_not_grant_mfa() {
    let issuer = "https://10.42.0.9:8443/realms/reference";
    let adapter = HttpOidc::new(
        vec![],
        vec![grant(issuer, &["10.42.0.9/32"])],
        transport_policy(),
        policy::reuse_policy(),
    )
    .unwrap();
    let credentials = ProviderCredentials::new("private-test-secret".into(), None).unwrap();
    let provider = settings(issuer, "client");
    assert!(adapter.validate(tenant(), &provider, &credentials).is_ok());
    assert!(
        !adapter
            .assurance_profile(tenant(), &provider)
            .supports_step_up
    );
    for (owner, config) in [
        (tenant(), settings(issuer, "other")),
        (
            tenant(),
            settings("https://10.42.0.9:8443/realms/other", "client"),
        ),
        (
            tenant(),
            settings("https://10.42.0.10:8443/realms/reference", "client"),
        ),
        (
            TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            provider,
        ),
    ] {
        assert!(adapter.validate(owner, &config, &credentials).is_err());
    }
}
#[test]
fn only_bounded_canonical_private_networks_are_authorizable() {
    for cidrs in [
        vec![],
        vec!["0.0.0.0/0"],
        vec!["127.0.0.1/32"],
        vec!["169.254.169.254/32"],
        vec!["100.64.0.0/10"],
        vec!["::/0"],
        vec!["::1/128"],
        vec!["fe80::/10"],
        vec!["::ffff:10.42.0.9/128"],
        vec!["10.42.0.9/24"],
        vec!["10.42.0.0/24", "10.42.0.0/24"],
    ] {
        assert!(
            HttpOidc::new(
                vec![],
                vec![grant("https://idp.example.test/realm", &cidrs)],
                transport_policy(),
                policy::reuse_policy()
            )
            .is_err(),
            "{cidrs:?}"
        );
    }
    for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"] {
        assert!(
            HttpOidc::new(
                vec![],
                vec![grant("https://idp.example.test/realm", &[cidr])],
                transport_policy(),
                policy::reuse_policy()
            )
            .is_ok()
        );
    }
    let duplicate = || grant("https://idp.example.test/realm", &["10.0.0.0/8"]);
    assert!(
        HttpOidc::new(
            vec![],
            vec![duplicate(), duplicate()],
            transport_policy(),
            policy::reuse_policy()
        )
        .is_err()
    );
    assert!(
        HttpOidc::new(
            vec![],
            (0..1025)
                .map(|i| grant(&format!("https://idp{i}.example.test"), &["10.0.0.0/8"]))
                .collect(),
            transport_policy(),
            policy::reuse_policy()
        )
        .is_err()
    );
    assert!(
        HttpOidc::new(
            vec![],
            vec![grant("http://idp.example.test", &["10.0.0.0/8"])],
            transport_policy(),
            policy::reuse_policy()
        )
        .is_err()
    );
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
