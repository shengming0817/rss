fn retarget_to_another_plan(
    permit: eventexec::SagaActivationPermit,
) -> eventexec::SagaActivationPermit {
    eventexec::SagaActivationPermit {
        source_runtime_plan_fingerprint: "sha256:other-plan".to_owned(),
        ..permit
    }
}

fn main() {}
