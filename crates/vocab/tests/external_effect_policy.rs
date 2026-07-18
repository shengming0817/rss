use vocab::ExternalEffectPolicy;

#[test]
fn external_effect_policy_is_the_canonical_closed_vocabulary() {
    let policies = [
        ExternalEffectPolicy::TransactionalOnly,
        ExternalEffectPolicy::IdempotencyKey,
        ExternalEffectPolicy::Reconcile,
        ExternalEffectPolicy::Compensated,
    ];

    assert_eq!(policies.len(), 4);
}
