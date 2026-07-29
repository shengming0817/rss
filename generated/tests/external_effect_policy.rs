use generated::event::{EVENTS, SubscriptionEffect, SubscriptionExecution};
use vocab::ExternalEffectPolicy;

#[test]
fn active_l2_subscriptions_close_execution_effect_policy_matrix() {
    let mut subscription_count = 0;
    for event in EVENTS {
        for subscription in event.subscriptions() {
            subscription_count += 1;
            let actual = (
                subscription.execution(),
                subscription.effect(),
                subscription.external_effect_policy(),
            );
            assert!(
                matches!(
                    actual,
                    (
                        SubscriptionExecution::AdapterNative,
                        None,
                        ExternalEffectPolicy::TransactionalOnly,
                    ) | (
                        SubscriptionExecution::DomainEffect,
                        Some(SubscriptionEffect::SettingsConfigVersionRefresh),
                        ExternalEffectPolicy::Reconcile,
                    )
                ),
                "subscription {}:{} has invalid execution/effect/external policy relation: {actual:?}",
                event.contract_id(),
                subscription.consumer()
            );
        }
    }
    assert!(
        subscription_count > 0,
        "active subscriptions must not be empty"
    );
}

#[test]
fn settings_refresh_keeps_reconcile_policy() {
    let subscription = generated::event::settings_v1::SPEC.subscriptions()[0];
    assert_eq!(
        subscription.execution(),
        SubscriptionExecution::DomainEffect
    );
    assert_eq!(
        subscription.effect(),
        Some(SubscriptionEffect::SettingsConfigVersionRefresh)
    );
    assert_eq!(
        subscription.external_effect_policy(),
        ExternalEffectPolicy::Reconcile
    );
}

#[test]
fn security_audit_keeps_transactional_only_policy() {
    let subscription = generated::event::identity_v1::security_event::SPEC.subscriptions()[0];
    assert_eq!(
        subscription.execution(),
        SubscriptionExecution::AdapterNative
    );
    assert_eq!(subscription.effect(), None);
    assert_eq!(
        subscription.external_effect_policy(),
        ExternalEffectPolicy::TransactionalOnly
    );
}
