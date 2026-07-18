use std::collections::BTreeMap;

use generated::event::{EVENTS, ExternalEffectPolicy};

fn policy_wire(policy: ExternalEffectPolicy) -> &'static str {
    match policy {
        ExternalEffectPolicy::TransactionalOnly => "transactional-only",
        ExternalEffectPolicy::IdempotencyKey => "idempotency-key",
        ExternalEffectPolicy::Reconcile => "reconcile",
        ExternalEffectPolicy::Compensated => "compensated",
    }
}

#[test]
fn active_l2_subscriptions_expose_exact_external_effect_policies() {
    let actual = EVENTS
        .iter()
        .flat_map(|event| {
            event.subscriptions().iter().map(|subscription| {
                (
                    (
                        event.contract_id(),
                        subscription.consumer(),
                        subscription.group(),
                    ),
                    policy_wire(subscription.external_effect_policy()),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let expected = BTreeMap::from([
        (
            ("identity.policy-updated", "audit", "audit.policy-updated"),
            "transactional-only",
        ),
        (
            ("identity.role-assigned", "audit", "audit.role-assigned"),
            "transactional-only",
        ),
        (
            ("identity.role-revoked", "audit", "audit.role-revoked"),
            "transactional-only",
        ),
        (
            ("identity.session-created", "audit", "audit.session-created"),
            "transactional-only",
        ),
        (
            (
                "settings.config-version-changed",
                "settings",
                "settings.config-version-changed",
            ),
            "reconcile",
        ),
    ]);

    assert_eq!(actual, expected);
}
