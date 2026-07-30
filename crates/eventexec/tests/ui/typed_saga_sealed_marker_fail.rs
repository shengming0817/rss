struct Forged;

impl generated::saga::StepMarker for Forged {
    type Receipt = generated::saga::billing_v1::BillingReserveFundsReceipt;
    const BINDING: vocab::SagaStepBinding = generated::saga::billing_v1::STEP_0;
}

fn main() {}
