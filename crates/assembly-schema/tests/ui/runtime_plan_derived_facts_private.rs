use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, DomainLifecyclePhase, ListenerAuth, RuntimePlanV1Input,
};

fn main() {
    let mut input = RuntimePlanV1Input::new();
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
