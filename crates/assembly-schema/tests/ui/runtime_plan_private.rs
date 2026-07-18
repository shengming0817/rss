use assembly_schema::{
    AssemblyDomain, AssemblyFingerprint, DomainLifecyclePhase, DomainPlan, LifecycleChannel,
    ListenerAuth, ListenerPlan, PlacementPlan, ProviderConstructor, ProviderPlan, RuntimePlan,
    RuntimePlanFingerprint,
};

fn forge(
    assembly_fingerprint: AssemblyFingerprint,
    runtime_plan_fingerprint: RuntimePlanFingerprint,
) -> RuntimePlan {
    RuntimePlan {
        schema_version: 1,
        assembly_fingerprint,
        runtime_plan_fingerprint,
        provider_plans: vec![ProviderPlan {
            id: "pdp".to_owned(),
            constructor: ProviderConstructor::OidcProvider,
            outputs: vec![LifecycleChannel::Resources],
        }],
        listener_plans: vec![ListenerPlan {
            id: "primary-main".to_owned(),
            kind: assembly_schema::AssemblyListenerKind::Primary,
            auth: ListenerAuth::RssAccessToken,
            domains: vec![AssemblyDomain::Identity],
        }],
        domain_plans: vec![DomainPlan {
            id: AssemblyDomain::Identity,
            lifecycle: vec![
                DomainLifecyclePhase::Construct,
                DomainLifecyclePhase::Ready,
                DomainLifecyclePhase::Shutdown,
            ],
        }],
        placement_plans: vec![PlacementPlan {
            domain: AssemblyDomain::Identity,
            workload: "runtime".to_owned(),
        }],
    }
}

fn main() {}
