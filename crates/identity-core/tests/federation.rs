use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountState, LocalChange},
};

#[test]
fn federated_accounts_are_members_without_local_credentials() {
    let key = AccountKey {
        tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
            .unwrap(),
        principal: PrincipalId::generate(),
    };
    let member = AccountState::new_federated(key).unwrap();
    assert!(member.active());
    assert!(!member.has_local_password());
    assert!(
        !member
            .change(LocalChange::Enabled(false))
            .unwrap()
            .0
            .enabled()
    );
    assert!(member.change(LocalChange::Password).is_err());
    assert!(member.recover().is_err());
}

#[test]
fn provider_settings_are_validated_at_every_deserialization_boundary() {
    use rss_identity_core::federation::*;
    let valid = serde_json::json!({"issuer":"https://idp.example.test","client_id":"client","redirect_uri":"https://identity.example.test/callback","scopes":["openid"],"claims":{"subject":{"kind":"oidc"},"profile":{"extensionsClaim":null,"maxAgeSeconds":14400},"groups":null},"jit":false});
    let checked: ProviderSettings = serde_json::from_value(valid.clone()).unwrap();
    assert!(!checked.jit());
    assert_eq!(checked.issuer().as_str(), "https://idp.example.test");
    for (key, value) in [
        (
            "issuer",
            serde_json::json!("https://user:password@idp.test"),
        ),
        ("client_id", serde_json::json!("")),
        ("scopes", serde_json::json!(["openid", "offline_access"])),
        (
            "claims",
            serde_json::json!({"profile":{"extensionsClaim":"sub","maxAgeSeconds":14400},"groups":null}),
        ),
    ] {
        let mut invalid = valid.clone();
        invalid[key] = value;
        assert!(serde_json::from_value::<ProviderSettings>(invalid).is_err());
    }
    let mut edited = checked.input();
    edited.issuer = "not-url".into();
    assert!(ProviderSettings::try_from(edited).is_err());
}
