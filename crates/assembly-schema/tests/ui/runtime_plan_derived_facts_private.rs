use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, DomainLifecyclePhase, ListenerAuth, RuntimePlanV3Input,
};

fn main() {
    let mut input = RuntimePlanV3Input::new();
    input.listener(
        "primary-main",
        AssemblyListenerKind::Primary,
        ListenerAuth::RssAccessToken,
        vec![AssemblyDomain::Runtime],
    );
    input.domain(
        AssemblyDomain::Runtime,
        vec![
            DomainLifecyclePhase::Construct,
            DomainLifecyclePhase::Ready,
            DomainLifecyclePhase::Shutdown,
        ],
    );
}
