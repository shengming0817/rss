use generated::event::{
    EVENTS, PartitionKeyStrategy, SubscriberReadiness, SubscriptionEffect, SubscriptionExecution,
    identity_v1, settings_v1,
};

fn assert_unique_dispatch_keys() {
    let mut dispatches = Vec::new();
    for subscription in EVENTS.iter().flat_map(|event| event.subscriptions()) {
        assert!(
            !dispatches.contains(&subscription.dispatch()),
            "generated subscription dispatch keys must be globally unique"
        );
        dispatches.push(subscription.dispatch());
    }
    assert_eq!(
        dispatches.len(),
        EVENTS
            .iter()
            .map(|event| event.subscriptions().len())
            .sum::<usize>()
    );
}

#[test]
fn active_event_registry_exposes_complete_single_source_topology() {
    let expected = [
        identity_v1::policy_updated::SPEC,
        identity_v1::role_assigned::SPEC,
        identity_v1::role_revoked::SPEC,
        identity_v1::session_created::SPEC,
        settings_v1::SPEC,
    ];

    assert_eq!(EVENTS, expected);
    assert_unique_dispatch_keys();
    for event in EVENTS {
        let contract = event.contract();
        assert_eq!(event.contract_id(), contract.contract_id());
        assert_eq!(event.schema_version(), contract.version());
        assert_eq!(event.schema_hash(), contract.schema_hash());
        assert!(!event.topic().is_empty());
        assert_eq!(event.partition_key(), PartitionKeyStrategy::None);

        let subscriptions = event.subscriptions();
        assert_eq!(subscriptions.len(), 1);
        let [subscription] = subscriptions else {
            continue;
        };
        assert!(!subscription.consumer().is_empty());
        assert!(!subscription.group().is_empty());
        assert_eq!(subscription.readiness(), SubscriberReadiness::Required);
        let expected_execution = if event.contract_id() == "settings.config-version-changed" {
            (
                SubscriptionExecution::DomainEffect,
                Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            )
        } else {
            (SubscriptionExecution::AdapterNative, None)
        };
        assert_eq!(
            (subscription.execution(), subscription.effect()),
            expected_execution
        );
    }
}
