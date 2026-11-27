use rss_identity_core::assurance::{Acr, Amr, Assurance, AuthenticationMode};
#[test]
fn normalized_facts_enforce_time_strength_and_method_invariants() {
    let facts = Assurance::new(Some(100), Acr::Mfa, vec![Amr::Otp]).unwrap();
    assert!(
        facts
            .check(AuthenticationMode::StepUp, 100, 101, 30)
            .is_ok()
    );
    for time in [69, 132] {
        assert!(
            Assurance::new(Some(time), Acr::Mfa, vec![])
                .unwrap()
                .check(AuthenticationMode::StepUp, 100, 101, 30)
                .is_err()
        );
    }
    for (time, acr, methods) in [
        (None, Acr::Mfa, vec![]),
        (Some(0), Acr::Unspecified, vec![]),
        (Some(100), Acr::Mfa, vec![Amr::Otp, Amr::Otp]),
    ] {
        assert!(Assurance::new(time, acr, methods).is_err());
    }
    assert_eq!(
        serde_json::from_str::<Assurance>(&serde_json::to_string(&facts).unwrap()).unwrap(),
        facts
    );
    assert!(
        serde_json::from_str::<Assurance>(
            r#"{"auth_time":100,"acr":"mfa","amr":[],"trusted":true}"#
        )
        .is_err()
    );
}
