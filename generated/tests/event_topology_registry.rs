use std::collections::BTreeSet;

use generated::event::{
    EVENTS, EventSpec, PartitionKeyStrategy, SubscriberReadiness, SubscriptionDispatchKey,
    SubscriptionEffect, SubscriptionExecution, identity_v1, settings_v1,
};

fn assert_contract_binding(event: EventSpec) {
    let contract = event.contract();
    assert_eq!(event.contract_id(), contract.contract_id());
    assert_eq!(event.schema_version(), contract.version());
    assert_eq!(event.schema_hash(), contract.schema_hash());
    assert!(!event.topic().is_empty());
    assert_eq!(event.partition_key(), PartitionKeyStrategy::None);
    assert!(
        !event.subscriptions().is_empty(),
        "active event {} must have a subscription",
        event.contract_id()
    );
}

fn assert_unique_subscriptions(
    event: EventSpec,
    subscription_ids: &mut BTreeSet<(&'static str, &'static str, &'static str)>,
    dispatches: &mut Vec<SubscriptionDispatchKey>,
) {
    for subscription in event.subscriptions() {
        assert!(!subscription.consumer().is_empty());
        assert!(!subscription.group().is_empty());
        assert_eq!(subscription.readiness(), SubscriberReadiness::Required);
        assert!(
            subscription_ids.insert((
                event.contract_id(),
                subscription.consumer(),
                subscription.group(),
            )),
            "generated subscription identities must be globally unique"
        );
        assert!(
            !dispatches.contains(&subscription.dispatch()),
            "generated subscription dispatch keys must be globally unique"
        );
        dispatches.push(subscription.dispatch());
    }
}

#[test]
fn active_event_registry_exposes_closed_unique_topology() {
    assert!(
        !EVENTS.is_empty(),
        "active event registry must not be empty"
    );

    let event_ids = EVENTS
        .iter()
        .map(|event| event.contract_id())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        event_ids.len(),
        EVENTS.len(),
        "generated event contract IDs must be unique"
    );

    let mut subscription_ids = BTreeSet::new();
    let mut dispatches = Vec::new();
    for event in EVENTS {
        assert_contract_binding(*event);
        assert_unique_subscriptions(*event, &mut subscription_ids, &mut dispatches);
    }
}

#[test]
fn security_event_keeps_required_audit_subscription() {
    let event = identity_v1::security_event::SPEC;
    assert!(EVENTS.contains(&event));
    assert_eq!(event.subscriptions().len(), 1);
    let subscription = event.subscriptions()[0];
    assert_eq!(subscription.consumer(), "audit");
    assert_eq!(subscription.group(), "audit.security-event");
    assert_eq!(subscription.readiness(), SubscriberReadiness::Required);
    assert_eq!(
        subscription.execution(),
        SubscriptionExecution::AdapterNative
    );
    assert_eq!(subscription.effect(), None);
}

#[test]
fn settings_event_keeps_domain_effect_binding() {
    let event = settings_v1::SPEC;
    assert!(EVENTS.contains(&event));
    assert_eq!(event.subscriptions().len(), 1);
    let subscription = event.subscriptions()[0];
    assert_eq!(subscription.consumer(), "settings");
    assert_eq!(subscription.group(), "settings.config-version-changed");
    assert_eq!(
        subscription.execution(),
        SubscriptionExecution::DomainEffect
    );
    assert_eq!(
        subscription.effect(),
        Some(SubscriptionEffect::SettingsConfigVersionRefresh)
    );
}
