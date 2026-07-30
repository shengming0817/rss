use generated::event::identity_v1::policy_updated;

struct ForgedSubscription;

impl generated::event::EventSubscription for ForgedSubscription {
    type Contract = policy_updated::Contract;
    const SPEC: generated::event::SubscriptionSpec = policy_updated::AUDIT_SUBSCRIPTION;
}

fn main() {}
