use rss_identity_core::{
    InstanceId, PrincipalId,
    account::{AccountKey, AccountState, LocalChange},
    session::{SessionLifetime, SessionPolicy},
};

#[test]
fn explicit_session_policy_preserves_absolute_expiry() {
    let policy = SessionPolicy::new(900, 14_400).unwrap();
    let mut session = SessionLifetime::new(1_000, policy).unwrap();
    assert_eq!(session.idle_expires_at(), 1_900);
    assert_eq!(session.absolute_expires_at(), 15_400);
    for now in (1_800..15_400).step_by(800) {
        session.renew(now).unwrap();
    }
    assert_eq!(session.idle_expires_at(), 15_400);
    assert!(session.renew(15_400).is_err());
    assert!(SessionPolicy::new(0, 1).is_err());
    assert!(SessionPolicy::new(901, 900).is_err());
    assert!(SessionLifetime::restore(1_000, 1_900, 15_401, policy).is_err());
}

#[test]
fn authentication_state_has_no_product_role_requirement() {
    let key = AccountKey {
        tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
            .unwrap(),
        principal: PrincipalId::generate(),
    };
    let account = AccountState::new_local(key).unwrap();
    let (disabled, _) = account.change(LocalChange::Enabled(false)).unwrap();
    assert!(!disabled.active());
    let (recovered, _) = disabled.recover().unwrap();
    assert!(!recovered.active());
    assert_eq!(recovered.epoch(), 3);
    assert_eq!(recovered.membership_epoch(), account.membership_epoch());
}

#[test]
fn instance_identity_is_non_nil_and_exact() {
    let first = InstanceId::generate();
    assert_ne!(first, InstanceId::generate());
    assert_eq!(
        InstanceId::parse(&first.as_uuid().to_string()).unwrap(),
        first
    );
    assert!(InstanceId::parse("00000000-0000-0000-0000-000000000000").is_err());
}
