use rss_identity_core::groups::{GroupFactsMaxAge, UpstreamGroups};

#[test]
fn group_policy_bounds_signed_observation_without_callback_extension() {
    for seconds in [0, -1] {
        assert!(GroupFactsMaxAge::new(seconds).is_err());
    }
    let policy = GroupFactsMaxAge::new(300).unwrap();
    assert_eq!(policy.expires_at(1000, 1100, 1050, 30).unwrap(), 1100);
    assert_eq!(policy.expires_at(1000, 2000, 1500, 30).unwrap(), 1300);
    assert_eq!(
        GroupFactsMaxAge::new(1)
            .unwrap()
            .expires_at(1000, 2000, 1000, 30)
            .unwrap(),
        1001
    );
    for (iat, exp, now) in [
        (0, 100, 1),
        (100, 100, 100),
        (131, 200, 100),
        (100, 200, 200),
        (i64::MAX - 1, i64::MAX, i64::MAX - 1),
    ] {
        assert!(policy.expires_at(iat, exp, now, 30).is_err());
    }
}

#[test]
fn group_values_are_exact_bounded_sets_and_missing_is_not_empty() {
    let groups = UpstreamGroups::present(vec![
        "/team/child".into(),
        " group ".into(),
        "/team/child".into(),
    ])
    .unwrap();
    assert_eq!(
        groups.values(),
        Some([" group ".to_string(), "/team/child".to_string()].as_slice())
    );
    assert_eq!(UpstreamGroups::NotConfigured.values(), None);
    assert_eq!(UpstreamGroups::Missing.values(), None);
    assert_eq!(
        UpstreamGroups::present(vec![]).unwrap().values(),
        Some([].as_slice())
    );
    for values in [
        vec!["".into()],
        vec!["\n".into()],
        vec!["x".repeat(257)],
        vec!["x".into(); 1025],
    ] {
        assert!(UpstreamGroups::present(values).is_err());
    }
    assert!(
        UpstreamGroups::present(
            (0..1024)
                .map(|i| format!("{i:04}{}", "x".repeat(252)))
                .collect()
        )
        .is_ok()
    );
}

#[test]
fn signed_observation_tolerates_bounded_skew_without_extending_deadline() {
    let policy = GroupFactsMaxAge::new(10).unwrap();
    for ahead in [1, 30] {
        assert_eq!(
            policy.expires_at(1000 + ahead, 2000, 1000, 30).unwrap(),
            1010 + ahead
        );
    }
    assert!(policy.expires_at(1031, 2000, 1000, 30).is_err());
}
