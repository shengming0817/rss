use rss_identity_core::{
    facts::{
        FactSource, FactUnavailableReason, acceptable_observation, valid_max_age,
        valid_snapshot_window,
    },
    groups::{Groups, VERSION},
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn source_construction_and_restore_share_the_same_closed_validation() {
    let provider = Uuid::new_v4();
    let source = FactSource::new(provider, "https://idp.test/issuer".into()).unwrap();
    assert_eq!(source.provider_id(), provider);
    assert_eq!(source.issuer(), "https://idp.test/issuer");
    let wire = json!({"provider_id":provider,"issuer":"https://idp.test/issuer"});
    assert_eq!(serde_json::to_value(&source).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<FactSource>(wire.clone()).unwrap(),
        source
    );
    assert!(FactSource::new(Uuid::nil(), "https://idp.test".into()).is_err());
    for issuer in [
        "".into(),
        "https://idp.test ".into(),
        "https://user@idp.test".into(),
        "https://idp.test?x=1".into(),
        "https://idp.test#fragment".into(),
        "file:///issuer".into(),
        "https://idp.test/\n".into(),
        "x".repeat(2049),
    ] {
        assert!(FactSource::new(provider, issuer.clone()).is_err());
        assert!(
            serde_json::from_value::<FactSource>(json!({"provider_id":provider,"issuer":issuer}))
                .is_err()
        );
    }
    let mut unknown = wire;
    unknown["department"] = json!("unexpected");
    assert!(serde_json::from_value::<FactSource>(unknown).is_err());
    assert!(serde_json::from_value::<FactSource>(json!({"issuer":"https://idp.test"})).is_err());
}

#[test]
fn shared_observation_contract_keeps_existing_wire_and_time_semantics() {
    for (reason, wire) in [
        (FactUnavailableReason::LocalIdentity, "local_identity"),
        (FactUnavailableReason::NotConfigured, "not_configured"),
        (FactUnavailableReason::ClaimMissing, "claim_missing"),
        (FactUnavailableReason::NotYetValid, "not_yet_valid"),
    ] {
        assert_eq!(
            serde_json::to_value(Groups::unavailable(reason)).unwrap(),
            json!({"version":VERSION,"status":"unavailable","reason":wire})
        );
    }
    for seconds in [1, 3600] {
        assert!(valid_max_age(seconds));
        assert!(valid_snapshot_window(1000, 1000 + seconds));
    }
    for seconds in [0, -1] {
        assert!(!valid_max_age(seconds));
    }
    assert!(acceptable_observation(1030, 1000, 30));
    assert!(!acceptable_observation(1031, 1000, 30));
    assert!(!valid_snapshot_window(0, 1));
    assert!(!valid_snapshot_window(i64::MAX, 1));
}
