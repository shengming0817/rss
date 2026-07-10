use generated::event::{
    EVENTS, PartitionKeyStrategy, SubscriberReadiness, identity_v1, settings_v1,
};

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
    }
}
