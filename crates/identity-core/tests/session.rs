use rss_identity_core::session::{SessionLifetime, SessionPolicy, SessionSecret};

#[test]
fn session_expiry_and_activity_are_bounded() {
    let mut ordinary =
        SessionLifetime::new(1_000, SessionPolicy::new(1800, 28800).unwrap()).unwrap();
    assert_eq!(ordinary.idle_expires_at(), 2_800);
    assert_eq!(ordinary.absolute_expires_at(), 29_800);
    assert!(ordinary.renew(2_799).is_ok());
    assert_eq!(ordinary.idle_expires_at(), 4_599);
    assert!(ordinary.renew(4_599).is_err());
    let mut admin = SessionLifetime::new(1_000, SessionPolicy::new(900, 14400).unwrap()).unwrap();
    assert_eq!(admin.idle_expires_at(), 1_900);
    assert_eq!(admin.absolute_expires_at(), 15_400);
    for now in (1_800..15_400).step_by(800) {
        admin.renew(now).unwrap();
    }
    assert_eq!(admin.idle_expires_at(), 15_400);
    assert!(admin.renew(15_400).is_err());
    assert!(SessionLifetime::new(i64::MAX, SessionPolicy::new(1800, 28800).unwrap()).is_err());
    assert!(
        SessionLifetime::restore(
            1_000,
            2_000,
            40_000,
            SessionPolicy::new(1800, 28800).unwrap()
        )
        .is_err()
    );
    assert!(
        SessionLifetime::new(1_000, SessionPolicy::new(1800, 28800).unwrap())
            .unwrap()
            .renew(999)
            .is_err()
    );
}

#[test]
fn session_secret_is_canonical_redacted_and_csrf_is_separated() {
    let a = SessionSecret::generate().unwrap();
    let b = SessionSecret::generate().unwrap();
    assert_eq!(a.expose().len(), 64);
    assert_ne!(a.digest(), b.digest());
    assert_eq!(
        SessionSecret::parse(a.expose().into()).unwrap().digest(),
        a.digest()
    );
    assert!(!format!("{a:?}").contains(a.expose()));
    assert!(a.check_csrf(&a.csrf()));
    assert!(!a.check_csrf(&b.csrf()));
    assert!(!a.check_csrf(a.expose()));
    assert!(SessionSecret::parse("a".repeat(63)).is_err());
    assert!(SessionSecret::parse("A".repeat(64)).is_err());
}

#[test]
fn session_id_wire_boundary_rejects_nil_and_round_trips() {
    use rss_identity_core::SessionId;
    let id = SessionId::generate();
    let wire = serde_json::to_string(&id).unwrap();
    assert_eq!(serde_json::from_str::<SessionId>(&wire).unwrap(), id);
    for value in ["00000000-0000-0000-0000-000000000000", "bad"] {
        assert!(serde_json::from_str::<SessionId>(&format!("\"{value}\"")).is_err());
    }
}

#[test]
fn restored_session_preserves_selected_renewal_window() {
    let mut admin = SessionLifetime::new(1_000, SessionPolicy::new(900, 14400).unwrap()).unwrap();
    admin.renew(1_800).unwrap();
    assert_eq!(admin.idle_expires_at(), 2_700);
    let mut restored = SessionLifetime::restore(
        1_000,
        1_900,
        15_400,
        SessionPolicy::new(900, 14400).unwrap(),
    )
    .unwrap();
    restored.renew(1_800).unwrap();
    assert_eq!(restored.idle_expires_at(), 2_700);
    assert!(
        SessionLifetime::restore(
            1_000,
            1_900,
            15_400,
            SessionPolicy::new(1800, 7200).unwrap()
        )
        .is_err()
    );
    let mut ordinary =
        SessionLifetime::new(1_000, SessionPolicy::new(1800, 28800).unwrap()).unwrap();
    ordinary.renew(1_800).unwrap();
    assert_eq!(ordinary.idle_expires_at(), 3_600);
}
