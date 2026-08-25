use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, DomainLifecyclePhase, ListenerAuth, RuntimePlanKind,
    RuntimePlanV4Input,
};

fn main() {
    let mut input = RuntimePlanV4Input::new(RuntimePlanKind::generic());
    input.listener(
        "primary-main",
        AssemblyListenerKind::Primary,
        ListenerAuth::RssAccessToken,
        vec![AssemblyDomain::Identity],
    );
    input.domain(
        AssemblyDomain::Identity,
        vec![
            DomainLifecyclePhase::Construct,
            DomainLifecyclePhase::Ready,
            DomainLifecyclePhase::Shutdown,
        ],
    );
}
