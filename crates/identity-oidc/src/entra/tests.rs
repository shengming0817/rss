use super::*;
use jsonwebtoken::{EncodingKey, Header};
use serde_json::{Value, json};

#[test]
#[allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::cognitive_complexity,
    reason = "signed claim fixtures"
)]
fn signed_user_claims_are_bound_to_the_resource_profile() -> anyhow::Result<()> {
    let p = EntraTokenProfile {
        tenant: Uuid::new_v4(),
        app_id: Uuid::new_v4(),
        authorized_clients: vec![Uuid::new_v4()],
        required_scopes: vec!["mdm.enroll".into()],
        device_claim: "deviceid".into(),
    };
    let now = 10_000;
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let claims = json!({"iss":p.issuer(),"aud":p.app_id,"ver":"2.0","idtyp":"user","tid":p.tenant,"oid":user,"azp":p.authorized_clients[0],"iat":now-1,"nbf":now-1,"exp":now+300,"scp":"mdm.enroll other","deviceid":device});

    let time = std::time::UNIX_EPOCH + Duration::from_secs(now);
    let jwk: Value = serde_json::from_str(include_str!("../../tests/fixtures/entra-a.json"))?;
    let key = select_key(std::slice::from_ref(&jwk), &p, "entra-a")?.unwrap();
    let sign = |claims: &Value| {
        jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            claims,
            &EncodingKey::from_rsa_der(include_bytes!("../../tests/fixtures/entra-a.der")),
        )
    };
    let valid = verify_signed_claims(&p, &sign(&claims)?, &key, time)?;
    assert_eq!((valid.user, valid.device), (user, Some(device)));
    let mut no_device = claims.clone();
    no_device.as_object_mut().unwrap().remove("deviceid");
    assert!(
        verify_signed_claims(&p, &sign(&no_device)?, &key, time)?
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
            verify_signed_claims(&p, &sign(&invalid)?, &key, time).is_err(),
            "field {field}"
        );
    }
    for field in [
        "idtyp", "oid", "tid", "azp", "exp", "nbf", "iss", "aud", "ver",
    ] {
        let mut invalid = claims.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            verify_signed_claims(&p, &sign(&invalid)?, &key, time).is_err(),
            "missing {field}"
        );
    }
    assert!(select_key(&[jwk.clone(), jwk], &p, "entra-a").is_err());
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "test controls every cache observation"
)]
async fn capacity_retains_active_tenants_and_releases_expired_cooldown() -> anyhow::Result<()> {
    let start = Instant::now();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let cap = std::num::NonZeroUsize::MIN;
    let mut tenants = BTreeMap::new();
    let slot = select_tenant(&mut tenants, first, start, cap)?;
    slot.lock().await.next_fetch_at = start + Duration::from_secs(2);
    assert!(select_tenant(&mut tenants, second, start, cap).is_err());
    drop(slot);
    assert!(select_tenant(&mut tenants, second, start + Duration::from_secs(1), cap).is_err());
    let _second = select_tenant(&mut tenants, second, start + Duration::from_secs(2), cap)?;
    assert!(!tenants.contains_key(&first));
    Ok(())
}
