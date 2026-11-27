use rss_identity_core::{entra::*, federation::*};
use serde_json::json;
use uuid::Uuid;
#[test]
fn subject_strategy_is_explicit_and_namespaces_do_not_collide() {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let entra = ExternalSubject::Entra { tenant, user };
    let oidc = ExternalSubject::Oidc(entra.storage_key());
    assert_ne!(entra.storage_key(), oidc.storage_key());
    assert!(entra.matches(&SubjectMapping::Entra { tenant }));
    assert!(!entra.matches(&SubjectMapping::Oidc));
    assert!(
        serde_json::from_value::<ClaimMapping>(
            json!({"profile":{"extensionsClaim":null,"maxAgeSeconds":14400},"groups":null})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<SubjectMapping>(
            json!({"kind":"entra","tenant":tenant,"fallback":"sub"})
        )
        .is_err()
    );
    let mut input: ProviderSettingsInput = serde_json::from_value(json!({"issuer":format!("https://login.microsoftonline.com/{tenant}/v2.0"),"client_id":"browser","redirect_uri":"https://host.test/callback","scopes":["openid"],"claims":{"subject":{"kind":"entra","tenant":tenant},"profile":{"extensionsClaim":null,"maxAgeSeconds":14400},"groups":null},"jit":false})).unwrap();
    assert!(ProviderSettings::try_from(input.clone()).is_err());
    input.scopes.push("profile".into());
    assert!(ProviderSettings::try_from(input.clone()).is_ok());
    input.issuer = "https://login.microsoftonline.com/common/v2.0".into();
    assert!(ProviderSettings::try_from(input).is_err());
}
