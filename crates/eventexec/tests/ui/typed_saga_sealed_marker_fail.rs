struct Forged;

impl generated::saga::StepMarker for Forged {
    type Receipt = generated::saga::test_support::test_v1::primary::SagaConformancePrepareReceipt;
    const BINDING: vocab::SagaStepBinding =
        generated::saga::test_support::test_v1::primary::STEP_0;
}

fn main() {}
