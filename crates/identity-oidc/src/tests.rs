use super::*;
use serde_json::json;

#[allow(clippy::unwrap_used, reason = "test fixture")]
fn token_metadata() -> (Metadata, discovery::Jwks) {
    let metadata = serde_json::from_value(json!({"issuer":"https://issuer.test","authorization_endpoint":"https://issuer.test/auth","jwks_uri":"https://issuer.test/keys","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]})).unwrap();
    let jwks = serde_json::from_value(json!({"keys":[serde_json::from_str::<serde_json::Value>(include_str!("../tests/fixtures/entra-a.json")).unwrap()]})).unwrap();
    (metadata, jwks)
}
#[allow(
    clippy::disallowed_methods,
    reason = "test issuer supplies verifier wall time"
)]
fn verify(
    raw: &str,
    fixture: &(Metadata, discovery::Jwks),
    nonce: &str,
    client: &str,
    secret: &str,
    skew: u32,
) -> Result<profile_token::Claims, FederationError> {
    let header = profile_token::approved_header(raw, &fixture.0)?;
    let key = profile_token::signing_key(&header, Some(&fixture.1), secret)?;
    profile_token::verify(
        raw,
        header.alg,
        &key,
        &fixture.0,
        nonce,
        client,
        skew,
        std::time::SystemTime::now(),
    )
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
fn signed_token(claims: &serde_json::Value, valid_key: bool) -> String {
    let key = if valid_key {
        include_bytes!("../tests/fixtures/entra-a.der").as_slice()
    } else {
        include_bytes!("../tests/fixtures/entra-b.der").as_slice()
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("entra-a".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(key),
    )
    .unwrap()
}
#[test]
fn signed_claims_bind_authorized_party_issuer_audience_and_expiry() {
    let metadata = token_metadata();
    for (field, value, valid) in [
        ("azp", json!(null), true),
        ("azp", json!("client"), true),
        ("azp", json!("other"), false),
        ("iss", json!("https://other.test"), false),
        ("aud", json!(["other"]), false),
        ("aud", json!(["client", "other"]), false),
        ("nonce", json!("wrong"), false),
        ("exp", json!(1), false),
        ("iat", json!(4102444800_i64), false),
    ] {
        let mut claims = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce"});
        claims[field] = value;
        for key in [true, false] {
            assert_eq!(
                verify(
                    &signed_token(&claims, key),
                    &metadata,
                    "nonce",
                    "client",
                    "fixture-secret",
                    30
                )
                .is_ok(),
                valid && key,
                "{field}"
            );
        }
    }
}

#[test]
#[allow(clippy::unwrap_used, reason = "test fixture")]
fn signed_group_claim_presence_and_exact_values_are_distinct() {
    use rss_identity_core::groups::UpstreamGroups;
    use serde_json::json;
    assert!(matches!(
        mapped_groups(None, &json!({"groups":["ignored"]})).unwrap(),
        UpstreamGroups::NotConfigured
    ));
    for claims in [json!({}), json!({"groups":null})] {
        assert!(matches!(
            mapped_groups(Some("groups"), &claims).unwrap(),
            UpstreamGroups::Missing
        ));
    }
    assert_eq!(
        mapped_groups(Some("groups"), &json!({"groups":[]}))
            .unwrap()
            .values(),
        Some([].as_slice())
    );
    assert_eq!(
        mapped_groups(Some("groups"), &json!({"groups":["/a/b"," a ","/a/b"]}))
            .unwrap()
            .values(),
        Some([" a ".to_string(), "/a/b".to_string()].as_slice())
    );
    for value in [json!("group"), json!([null]), json!([1]), json!(["bad\n"])] {
        assert!(mapped_groups(Some("groups"), &json!({"groups":value})).is_err());
    }
}

fn department_assertion() -> serde_json::Value {
    json!({"version":1,"sourceRevision":"r1","nodes":[{"id":"dept-01","displayName":"Engineering","parentId":null}],"memberships":["dept-01"]})
}
#[test]
fn department_mapping_withholds_missing_or_invalid_assertions() {
    use rss_identity_core::department::UpstreamDepartmentSnapshot;
    assert_eq!(
        mapped_department(None, &json!({"organization":"ignored"})),
        UpstreamDepartmentSnapshot::NotConfigured
    );
    assert_eq!(
        mapped_department(Some("organization"), &json!({})),
        UpstreamDepartmentSnapshot::Missing
    );
    for value in [
        json!(null),
        json!("dept-01"),
        json!([]),
        json!({}),
        json!(1),
        json!(true),
    ] {
        assert_eq!(
            mapped_department(Some("organization"), &json!({"organization":value})),
            UpstreamDepartmentSnapshot::Invalid
        );
    }
    for members in [json!(["dept-01"]), json!([])] {
        let mut value = department_assertion();
        value["memberships"] = members;
        assert!(matches!(
            mapped_department(Some("organization"), &json!({"organization":value})),
            UpstreamDepartmentSnapshot::Present(_)
        ));
    }
}

#[test]
#[allow(clippy::unwrap_used, reason = "test fixture")]
fn signed_snapshot_withholds_invalid_fact_but_never_bypasses_token_verification() {
    let metadata = token_metadata();
    for value in [json!(null), department_assertion(), json!([])] {
        for (field, bad, accepted) in [
            ("unused", json!(true), true),
            ("iss", json!("https://other.test"), false),
            ("aud", json!(["other"]), false),
            ("nonce", json!("other"), false),
            ("exp", json!(1), false),
        ] {
            let mut raw = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce","organization_snapshot":value});
            raw[field] = bad;
            for key in [true, false] {
                let verified = verify(
                    &signed_token(&raw, key),
                    &metadata,
                    "nonce",
                    "client",
                    "fixture-secret",
                    30,
                );
                assert_eq!(verified.is_ok(), accepted && key);
                if let Ok(claims) = verified {
                    assert_eq!(
                        matches!(
                            mapped_department(
                                Some("organization_snapshot"),
                                &serde_json::to_value(claims).unwrap()
                            ),
                            rss_identity_core::department::UpstreamDepartmentSnapshot::Present(_)
                        ),
                        value.is_object()
                    );
                }
            }
        }
    }
}
#[test]
#[allow(clippy::unwrap_used, reason = "test fixture")]
fn malformed_profile_is_independent_of_verified_security_claims() {
    let metadata = token_metadata();
    let raw = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce","email":42,"name":false,"email_verified":"true","attributes":{"mfa":true,"number":0,"remote":false}});
    let claims = verify(
        &signed_token(&raw, true),
        &metadata,
        "nonce",
        "client",
        "fixture-secret",
        30,
    )
    .unwrap();
    let settings = rss_identity_core::profile::ProfileSettings {
        extensions_claim: Some("attributes".into()),
        max_age_seconds: 14400,
    };
    let profile = rss_identity_core::profile::Profile::from_claims(&claims.ordinary, &settings);
    assert!(matches!(
        profile.email,
        rss_identity_core::profile::Attribute::Invalid
    ));
    assert!(matches!(
        profile.email_verified,
        rss_identity_core::profile::Attribute::Invalid
    ));
    assert_eq!(
        profile.extensions.value().unwrap().object()["remote"],
        false
    );
    assert!(
        verify(
            &signed_token(&raw, false),
            &metadata,
            "nonce",
            "client",
            "fixture-secret",
            30
        )
        .is_err()
    );
}

#[test]
#[allow(clippy::unwrap_used, reason = "test fixture")]
fn entra_browser_requires_canonical_subject_without_fallback() {
    use rss_identity_core::entra::{ExternalSubject, SubjectMapping};
    let tenant = uuid::Uuid::new_v4();
    let user = uuid::Uuid::new_v4();
    let mapping = SubjectMapping::Entra { tenant };
    let claims = serde_json::json!({"tid":tenant,"oid":user,"email":"same@example.test"});
    let expected = ExternalSubject::Entra { tenant, user };
    assert_eq!(
        super::mapped_subject(&mapping, "pairwise-one", &claims).unwrap(),
        expected
    );
    assert_eq!(
        super::mapped_subject(&mapping, "pairwise-two", &claims).unwrap(),
        expected
    );
    for invalid in [
        serde_json::json!({"tid":tenant,"email":"same@example.test"}),
        serde_json::json!({"oid":user}),
        serde_json::json!({"tid":uuid::Uuid::new_v4(),"oid":user}),
        serde_json::json!({"tid":tenant,"oid":uuid::Uuid::nil()}),
    ] {
        assert!(super::mapped_subject(&mapping, "valid-pairwise-sub", &invalid).is_err());
    }
}

#[test]
fn id_token_rejects_unadvertised_algorithm_and_ambiguous_key() {
    let claims = json!({"iss":"https://issuer.test","sub":"subject","aud":"client","iat":1,"exp":4102444800_i64,"nonce":"nonce"});
    let raw = signed_token(&claims, true);
    let mut metadata = token_metadata();
    metadata.0.id_token_signing_alg_values_supported = vec!["HS256".into()];
    assert!(verify(&raw, &metadata, "nonce", "client", "fixture-secret", 30).is_err());
    let mut metadata = token_metadata();
    metadata.1.keys.push(metadata.1.keys[0].clone());
    assert!(verify(&raw, &metadata, "nonce", "client", "fixture-secret", 30).is_err());
}
