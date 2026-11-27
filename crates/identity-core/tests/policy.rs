use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountRuleError, AccountState, LocalChange},
};
fn key() -> AccountKey {
    AccountKey {
        tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
            .unwrap(),
        principal: PrincipalId::generate(),
    }
}
#[test]
fn core_owns_role_free_transitions_and_epochs() {
    let account = AccountState::new_local(key()).unwrap();
    let (disabled, _) = account.change(LocalChange::Enabled(false)).unwrap();
    assert!(!disabled.enabled());
    assert_eq!(disabled.epoch(), 2);
    let (recovered, _) = disabled.recover().unwrap();
    assert!(!recovered.enabled());
    assert_eq!(recovered.epoch(), 3);
    assert!(AccountState::restore(key(), true, true, 0, true, 1).is_err());
    let max = AccountState::restore(key(), true, true, i64::MAX, true, 1).unwrap();
    assert_eq!(max.recover().unwrap_err(), AccountRuleError::EpochExhausted);
}
#[test]
fn actions_preserve_transition_direction() {
    let account = AccountState::new_local(key()).unwrap();
    for (change, action) in [
        (LocalChange::Enabled(true), "account_enabled"),
        (LocalChange::Enabled(false), "account_disabled"),
        (LocalChange::Membership(true), "membership_enabled"),
        (LocalChange::Membership(false), "membership_disabled"),
        (LocalChange::Password, "password_changed"),
    ] {
        let (next, actual) = account.change(change).unwrap();
        assert_eq!(actual.as_str(), action);
        assert_eq!(next.epoch(), account.epoch() + 1);
        assert!(!next.matches_verification(account));
    }
}
#[test]
fn membership_and_local_credential_are_independent() {
    let account = AccountState::new_local(key()).unwrap();
    let (inactive, _) = account.change(LocalChange::Membership(false)).unwrap();
    assert!(!inactive.active());
    assert_eq!(inactive.membership_epoch(), 2);
    let (active, _) = inactive.change(LocalChange::Membership(true)).unwrap();
    assert!(active.active());
    assert_eq!(active.membership_epoch(), 3);
    let federated = AccountState::new_federated(key()).unwrap();
    assert!(federated.change(LocalChange::Password).is_err());
    assert!(federated.recover().is_err());
}
